#!/usr/bin/env python3
#-- coding: utf-8 --
#original code basis: https://github.com/etingof/pysnmp
#file paths: examples/v3arch/asyncore/agent/cmdrsp/multiple-usm-users.py; examples/v3arch/asyncore/ntfrcv/ntfrcv-v3.py
#adapted and extended for scenario 1 ("one message – one key") with kms integration; inform-ready aes-256 agent

"""
snmpv3 agent + kms integration + trap/inform receiver — strict aes-256

policy (scenario 1: one message – one key):
- manager fetches a fresh enc_key and notifies the agent via POST /kms {"user","key_ID"}
- agent fetches the dec_key from slave kms and rotates the usm priv key for that user (aes-256)
- duplicate key_ID notifications are handled idempotently (already processed / in-flight)
- /kms/ready?key_ID=... returns {"applied": true|false} so clients can poll before sending
- usm user: usr-sha-aes256 (auth=SHA, priv=AES-256)

snmpv3 listens on 0.0.0.0:50161, http control on :8080
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
from pysnmp.hlapi import usmHMACSHAAuthProtocol

#strict aes-256 (fail fast if unavailable)
try:
    from pysnmp.hlapi import usmAesCfb256Protocol
except Exception as e:
    raise RuntimeError("pysnmp build does not include AES-256 (usmAesCfb256Protocol).") from e

#logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.info("SNMP privacy (agent): AES-256")

#config
LISTEN_ADDR = os.getenv("SNMP_LISTEN", "0.0.0.0")
SNMP_PORT   = int(os.getenv("SNMP_PORT", "50161"))
HTTP_PORT   = int(os.getenv("HTTP_PORT", "8080"))
QKD_USER_DEFAULT = os.getenv("QKD_USER_DEFAULT", "usr-sha-aes256")

SLAVE_KMS_BASE = os.getenv("SLAVE_KMS_BASE", "http://10.250.1.2")
SLAVE_APP_ID   = os.getenv("SLAVE_APP_ID",   "bbbc7de9-5826-11ef-8057-9b39f247bbb")

DEC_TIMEOUT_SEC   = 3
DEC_RETRIES       = 6
DEC_RETRY_DELAY_S = 0.7

in_flight     = set()
processed_ids = set()   #processed ok or terminally gone
applied_ids   = set()   #usm rotation actually applied
lock = threading.Lock()

#snmp Engine
snmpEngine = engine.SnmpEngine()
config.addTransport(snmpEngine, udp.domainName, udp.UdpTransport().openServerMode((LISTEN_ADDR, SNMP_PORT)))

def _derive_aes256(key_bytes: bytes) -> bytes:
    return key_bytes if len(key_bytes) == 32 else hashlib.sha256(key_bytes).digest()

def ensure_usm_user(user: str, priv_key_bytes: bytes):
    #set/rotate usm user with SHA + AES-256
    try:
        config.addV3User(
            snmpEngine, user,
            usmHMACSHAAuthProtocol, "authkey1",
            usmAesCfb256Protocol, _derive_aes256(priv_key_bytes)
        )
        config.addVacmUser(snmpEngine, 3, user, 'authPriv', (1,3,6,1,2,1), (1,3,6,1,2,1))
        logging.info("USM set: user=%s (auth=SHA, priv=AES-256)", user)
    except Exception as e:
        logging.warning("USM setup failed: %s", e)

#initial placeholder key (rotated via /kms)
ensure_usm_user(QKD_USER_DEFAULT, b'\x00' * 32)

#snmp responders + trap/inform receiver
snmpContext = context.SnmpContext(snmpEngine)
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

def _notif_cb(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    try:
        pairs = "; ".join(f"{n.prettyPrint()}={v.prettyPrint()}" for n, v in varBinds)
        logging.info("Received TRAP/INFORM (ctx=%s): %s", contextName.prettyPrint(), pairs)
    except Exception as e:
        logging.warning("Notification callback error: %s", e)

ntfrcv.NotificationReceiver(snmpEngine, _notif_cb)

def fetch_dec_key_from_slave(slave_base: str, app_id: str, key_id: str, timeout=DEC_TIMEOUT_SEC):
    """
    POST /api/v1/keys/{app_id}/dec_keys with {"key_IDs":[{"key_ID":"..."}]}
    expects: {"keys":[{"key":"<base64>","key_ID":"..."}]}
    returns: ("ok", key_bytes) | ("gone", None) | ("error", None)
    """
    url = f"{slave_base}/api/v1/keys/{app_id}/dec_keys"
    payload = {"key_IDs": [{"key_ID": key_id}]}
    try:
        r = requests.post(
            url, json=payload, timeout=timeout, stream=True,
            headers={"Accept": "application/json", "Accept-Encoding": "identity", "Content-Type": "application/json"}
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

    #non-200 → try to read short body
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
    logging.info("KMS notification: user=%s key_ID=%s (fetching dec_key)", user, key_id)
    try:
        for _ in range(DEC_RETRIES):
            status, key_bytes = fetch_dec_key_from_slave(SLAVE_KMS_BASE, SLAVE_APP_ID, key_id)
            logging.info("dec_keys for key_ID=%s → %s", key_id, status)
            if status == "ok" and key_bytes:
                ensure_usm_user(user, key_bytes)  #rotate to aes-256
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
            logging.info("slave kms did not return a key in time (user=%s, key_ID=%s)", user, key_id)
    finally:
        with lock:
            in_flight.discard(key_id)

#http handler
class QKDHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        #quiet http.server
        return

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
        #/kms/ready?key_ID=...
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
            logging.info("KMS notification queued: user=%s key_ID=%s", user, key_id)
            return self._send_json(200, {"status": "queued"})

        return self._send_text(404, "Not found")
      
def start_http_server():
    httpd = HTTPServer(("0.0.0.0", HTTP_PORT), QKDHandler)
    logging.info("QKD/KMS endpoint listening on :%d", HTTP_PORT)
    httpd.serve_forever()

def start_snmp_agent():
    def _loop():
        snmpEngine.transportDispatcher.jobStarted(1)
        logging.info("SNMP agent listening on %s:%d", LISTEN_ADDR, SNMP_PORT)
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
        logging.info("Server stopping...")

if __name__ == "__main__":
    main()
