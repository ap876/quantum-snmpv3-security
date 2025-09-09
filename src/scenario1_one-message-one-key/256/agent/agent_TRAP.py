#!/usr/bin/env python3
#-- coding: utf-8 --
#original code basis: https://github.com/etingof/pysnmp
#file path: examples/hlapi/asyncore/ntfrcv/v3-notification-receiver.py
#adapted and extended for scenario 1 ("one message – one key") with kms integration, trap receiver

"""
snmpv3 agent + kms integration (trap/inform receiver)
policy (scenario 1: one message – one key):
- /kms accepts {"user","key_ID"} and fetches dec_key from slave kms at most once per key_ID
- duplicates of the same key_ID are ignored (idempotent)
- /kms/status?key_ID=... returns {"status": "queued"|"in-flight"|"processed"|"not-seen"}-style states to help the client sync
- usm user rotates to the delivered key (auth=SHA, priv=aes-256 if available, otherwise aes-128)
- snmp listens on 0.0.0.0:50161, http on :8080

note: this build prefers aes-256 privacy -> if not available in pysnmp, it falls back to aes-128.
"""

import base64
import hashlib
import json
import logging
import os
import threading
import time
import gzip
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import requests
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context, ntfrcv
from pysnmp.hlapi import usmHMACSHAAuthProtocol, usmAesCfb128Protocol

#try aes-256 first-> fall back to aes-128 if unavailable
try:
    from pysnmp.hlapi import usmAesCfb256Protocol
    PRIV_PROTO = usmAesCfb256Protocol
    PRIV_BITS = 256
except Exception:
    PRIV_PROTO = usmAesCfb128Protocol
    PRIV_BITS = 128

#logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.info("snmp privacy (agent): aes-%d (aes-128 indicates pysnmp lacks aes-256)", PRIV_BITS)

#config
LISTEN_ADDR = os.getenv("AGENT_LISTEN", "0.0.0.0")
SNMP_PORT   = int(os.getenv("SNMP_PORT", "50161"))
HTTP_PORT   = int(os.getenv("HTTP_PORT", "8080"))
QKD_USER_DEFAULT = os.getenv("USM_USER", "usr-sha-aes")

SLAVE_KMS_BASE = os.getenv("SLAVE_KMS_BASE", "http://10.250.1.2")
SLAVE_APP_ID   = os.getenv("SLAVE_APP_ID",   "bbbc7de9-5826-11ef-8057-9b39f247bbb")

DEC_TIMEOUT_SEC   = 3
DEC_RETRIES       = 6
DEC_RETRY_DELAY_S = 0.7

in_flight = set()
processed_ids = set()

#snmp engine
snmpEngine = engine.SnmpEngine()
config.addTransport(snmpEngine, udp.domainName, udp.UdpTransport().openServerMode((LISTEN_ADDR, SNMP_PORT)))

def _derive_priv_key(key_bytes: bytes) -> bytes:
    need = 32 if PRIV_BITS == 256 else 16
    if len(key_bytes) == need:
        return key_bytes
    return hashlib.sha256(key_bytes).digest()[:need]

def ensure_usm_user(user: str, priv_key_bytes: bytes):
    try:
        config.addV3User(
            snmpEngine, user,
            usmHMACSHAAuthProtocol, "authkey1",
            PRIV_PROTO, _derive_priv_key(priv_key_bytes)
        )
        config.addVacmUser(snmpEngine, 3, user, 'authPriv', (1,3,6,1,2,1), (1,3,6,1,2,1))
        logging.info("usm configured: user=%s auth=SHA priv=AES-%d", user, PRIV_BITS)
    except Exception as e:
        logging.warning("usm user setup failed: %s", e)

#placeholder key (rotated after /kms)
ensure_usm_user(QKD_USER_DEFAULT, b'\x00' * (32 if PRIV_BITS == 256 else 16))

#responders and trap/inform receiver
snmpContext = context.SnmpContext(snmpEngine)
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

def _notif_cb(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    try:
        pairs = "; ".join(f"{n.prettyPrint()}={v.prettyPrint()}" for n, v in varBinds)
        logging.info("received TRAP/INFORM (ctx=%s): %s", contextName.prettyPrint(), pairs)
    except Exception as e:
        logging.warning("notification callback error: %s", e)

ntfrcv.NotificationReceiver(snmpEngine, _notif_cb)

#kms helpers
def fetch_dec_key_from_slave(slave_base: str, app_id: str, key_id: str, timeout=DEC_TIMEOUT_SEC):
    url = f"{slave_base}/api/v1/keys/{app_id}/dec_keys"
    payload = {"key_IDs": [{"key_ID": key_id}]}
    try:
        r = requests.post(
            url, json=payload, timeout=timeout, stream=True,
            headers={"Accept":"application/json","Accept-Encoding":"identity","Content-Type":"application/json"},
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
            data = json.loads(raw.decode("utf-8", "replace"))
            items = data.get("keys") or []
            if not items:
                return "error", None
            b64 = (items[0].get("key") or "").strip()
            key_bytes = base64.b64decode(b64)
            return "ok", key_bytes
        except Exception as e:
            logging.warning("dec_keys parse/base64 error: %s", e)
            return "error", None

    body = ""
    try:
        try:
            r.raw.decode_content = False
        except Exception:
            pass
        body = r.raw.read(512).decode("utf-8", "replace")
    except Exception:
        pass
    if r.status_code in (404, 410) or (r.status_code == 400 and "key not found" in (body or "").lower()):
        return "gone", None
    logging.warning("dec_keys unexpected status=%s body=%r", r.status_code, (body or "")[:200])
    return "error", None

def process_key_id_async(user: str, key_id: str):
    logging.info("kms notification: user=%s key_ID=%s (fetching dec_key)", user, key_id)
    try:
        for _ in range(DEC_RETRIES):
            status, key_bytes = fetch_dec_key_from_slave(SLAVE_KMS_BASE, SLAVE_APP_ID, key_id)
            logging.info("dec_keys for key_ID=%s → %s", key_id, status)
            if status == "ok" and key_bytes:
                ensure_usm_user(user, key_bytes)  # rotate priv key
                processed_ids.add(key_id)
                break
            if status == "gone":
                processed_ids.add(key_id)
                break
            time.sleep(DEC_RETRY_DELAY_S)
        else:
            logging.info("slave kms did not return a key in time (user=%s, key_ID=%s)", user, key_id)
    finally:
        in_flight.discard(key_id)

#http handler
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
        path = urlparse(self.path)
        if path.path == "/kms/status":
            q = parse_qs(path.query or "")
            key_id = (q.get("key_ID") or [""])[0]
            if not key_id:
                return self._send_json(400, {"error":"missing key_ID"})
            if key_id in processed_ids:
                return self._send_json(200, {"status":"processed"})
            if key_id in in_flight:
                return self._send_json(200, {"status":"in-flight"})
            return self._send_json(200, {"status":"not-seen"})
        return self._send_text(404, "not found")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except Exception:
            length = 0
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except Exception:
            return self._send_text(400, "invalid json")

        if path == "/kms":
            user   = data.get("user") or QKD_USER_DEFAULT
            key_id = data.get("key_ID")
            if not key_id:
                return self._send_text(400, "missing 'key_ID'")

            if key_id in processed_ids:
                return self._send_json(200, {"status":"already-processed"})
            if key_id in in_flight:
                return self._send_json(200, {"status":"in-flight"})

            in_flight.add(key_id)
            threading.Thread(target=process_key_id_async, args=(user, key_id), daemon=True).start()
            logging.info("kms notification queued: user=%s key_ID=%s", user, key_id)
            return self._send_json(200, {"status":"queued"})

        return self._send_text(404, "not found")

#startup
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
