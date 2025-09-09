#!/usr/bin/env python3
#-- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/agent/cmdrsp/multiple-usm-users.py

"""
snmpv3 agent + kms integration + trap/inform receiver — aes-128 (slave kms only)
- POST /kms {"user","key_ID"} -> fetch dec_key from Slave KMS exactly once per key_ID and rotate USM
- GET  /kms/ready?key_ID=...  -> {"applied": true/false, "processed": true/false}
- no /qkd fallback.

usm user: usr-sha-aes128 (auth=SHA, priv=AES-128)
snmpv3 on 0.0.0.0:50161; http on :8080
env configuration:
  SLAVE_KMS_BASE (default: http://10.250.1.2)
  SLAVE_APP_ID   (default: bbbc7de9-5826-11ef-8057-9b39f247bbb)
  SNMP_LISTEN    (default: 0.0.0.0)
  SNMP_PORT      (default: 50161)
  HTTP_PORT      (default: 8080)
  QKD_USER_DEFAULT (default: usr-sha-aes128)
"""

import base64
import gzip
import hashlib
import json
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import requests
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context, ntfrcv
from pysnmp.hlapi import usmHMACSHAAuthProtocol, usmAesCfb128Protocol

#logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)

#config
LISTEN_ADDR = os.getenv("SNMP_LISTEN", "0.0.0.0")
SNMP_PORT   = int(os.getenv("SNMP_PORT", "50161"))
HTTP_PORT   = int(os.getenv("HTTP_PORT", "8080"))
QKD_USER_DEFAULT = os.getenv("QKD_USER_DEFAULT", "usr-sha-aes128")

SLAVE_KMS_BASE = os.getenv("SLAVE_KMS_BASE", "http://10.250.1.2")
SLAVE_APP_ID   = os.getenv("SLAVE_APP_ID",   "bbbc7de9-5826-11ef-8057-9b39f247bbb")

DEC_TIMEOUT_SEC   = 3
DEC_RETRIES       = 6
DEC_RETRY_DELAY_S = 0.7

#state
in_flight     = set()
processed_ids = set()   # ok/gone
applied_ids   = set()   # truly rotated/active key
lock = threading.Lock()

#snmp-engine
snmpEngine = engine.SnmpEngine()
config.addTransport(
    snmpEngine, udp.domainName,
    udp.UdpTransport().openServerMode((LISTEN_ADDR, SNMP_PORT))
)

def _derive_aes128(key_bytes: bytes) -> bytes:
    return key_bytes if len(key_bytes) == 16 else hashlib.sha256(key_bytes).digest()[:16]

def ensure_user(user: str, priv_key_bytes: bytes):
    try:
        config.addV3User(
            snmpEngine, user,
            usmHMACSHAAuthProtocol, "authkey1",
            usmAesCfb128Protocol, _derive_aes128(priv_key_bytes)
        )
        config.addVacmUser(snmpEngine, 3, user, 'authPriv', (1,3,6,1,2,1), (1,3,6,1,2,1))
        logging.info("usm set/rotated: %s (sha + aes-128)", user)
    except Exception as e:
        logging.warning("usm setup failed: %s", e)

#initial placeholder (rotated when first key arrives)
ensure_user(QKD_USER_DEFAULT, b"\x00"*16)

#responders + trap/inform receiver
snmpContext = context.SnmpContext(snmpEngine)
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

def _notif_cb(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    try:
        pairs = "; ".join(f"{n.prettyPrint()}={v.prettyPrint()}" for n, v in varBinds)
        logging.info("received trap/inform: %s", pairs)
    except Exception as e:
        logging.warning("notification callback error: %s", e)

ntfrcv.NotificationReceiver(snmpEngine, _notif_cb)

#slave-kms
def fetch_dec_key_from_slave(key_id: str):
    """
    POST /api/v1/keys/{app}/dec_keys with {"key_IDs":[{"key_ID": "<key_id>"}]}
    expects: {"keys":[{"key":"<base64>"}]}
    returns: ("ok", bytes) | ("gone", None) | ("error", None)
    """
    url = f"{SLAVE_KMS_BASE}/api/v1/keys/{SLAVE_APP_ID}/dec_keys"
    payload = {"key_IDs": [{"key_ID": key_id}]}
    try:
        r = requests.post(
            url, json=payload, timeout=DEC_TIMEOUT_SEC, stream=True,
            headers={"Accept":"application/json","Accept-Encoding":"identity","Content-Type":"application/json"},
            proxies={"http": None, "https": None},
        )
    except Exception as e:
        logging.warning("dec_keys transport error: %s", e)
        return "error", None

    if r.status_code == 200:
        try:
            r.raw.decode_content = False
        except Exception:
            pass
        raw = r.raw.read()
        enc = (r.headers.get("Content-Encoding") or "").lower()
        if "gzip" in enc and raw[:2] == b"\x1f\x8b":
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass
        try:
            data = json.loads(raw.decode("utf-8","replace"))
            items = data.get("keys") or []
            if not items:
                return "error", None
            b64 = (items[0].get("key") or "").strip()
            key_bytes = base64.b64decode(b64)
            return "ok", key_bytes
        except Exception as e:
            logging.warning("dec_keys json/base64 error: %s", e)
            return "error", None

    text = ""
    try:
        try:
            r.raw.decode_content = False
        except Exception:
            pass
        text = r.raw.read(512).decode("utf-8","replace")
    except Exception:
        pass

    if r.status_code in (404,410) or (r.status_code == 400 and "key not found" in (text or "").lower()):
        return "gone", None

    logging.warning("dec_keys unexpected status=%s body=%r", r.status_code, (text or "")[:160])
    return "error", None

def process_key_id_async(user: str, key_id: str):
    logging.info("kms notification: user=%s key_ID=%s", user, key_id)
    try:
        for _ in range(DEC_RETRIES):
            status, kb = fetch_dec_key_from_slave(key_id)
            logging.info("dec_keys for key_ID=%s → %s", key_id, status)
            if status == "ok" and kb:
                ensure_user(user, kb)
                with lock:
                    processed_ids.add(key_id)
                    applied_ids.add(key_id)
                break
            if status == "gone":
                with lock:
                    processed_ids.add(key_id)
                break
            time.sleep(DEC_RETRY_DELAY_S)
        else:
            logging.info("slave kms did not return key in time (user=%s, key_ID=%s)", user, key_id)
    finally:
        with lock:
            in_flight.discard(key_id)

#http-handler
class QKDHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): return

    def _send_json(self, code: int, obj: dict):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, code: int, text: str):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/kms/ready":
            qs = parse_qs(p.query or "")
            key_id = (qs.get("key_ID") or [""])[0]
            with lock:
                applied = key_id in applied_ids
                processed = key_id in processed_ids
            return self._send_json(200, {"applied": applied, "processed": processed, "key_ID": key_id})
        return self._send_text(404, "Not found")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except Exception:
            length = 0
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except Exception:
            return self._send_text(400, "Invalid JSON")

        if path == "/kms":
            user   = data.get("user") or QKD_USER_DEFAULT
            key_id = data.get("key_ID")
            if not key_id:
                return self._send_text(400, "Missing 'key_ID'")

            with lock:
                if key_id in applied_ids:
                    return self._send_json(200, {"status": "already-applied"})
                if key_id in processed_ids or key_id in in_flight:
                    return self._send_json(200, {"status": "in-flight"})
                in_flight.add(key_id)

            threading.Thread(target=process_key_id_async, args=(user, key_id), daemon=True).start()
            logging.info("kms notification queued: user=%s key_ID=%s", user, key_id)
            return self._send_json(200, {"status": "queued"})

        return self._send_text(404, "Not found")

#start
def start_http_server():
    httpd = HTTPServer(("0.0.0.0", HTTP_PORT), QKDHandler)
    logging.info("qkd/kms endpoint listening on :%d", HTTP_PORT)
    httpd.serve_forever()

def start_snmp_agent():
    def _loop():
        snmpEngine.transportDispatcher.jobStarted(1)
        logging.info("snmp agent listening on %s:%d", LISTEN_ADDR, SNMP_PORT)
        try:
            snmpEngine.transportDispatcher.runDispatcher()
        finally:
            snmpEngine.transportDispatcher.closeDispatcher()
    threading.Thread(target=_loop, daemon=True).start()

def main():
    threading.Thread(target=start_http_server, daemon=True).start()
    start_snmp_agent()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        logging.info("server stopping...")

if __name__ == "__main__":
    main()
