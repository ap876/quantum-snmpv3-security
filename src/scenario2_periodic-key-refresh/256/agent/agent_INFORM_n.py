#!/usr/bin/env python3
#-- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/agent/cmdrsp/multiple-usm-users.py

"""
snmpv3 agent + kms integration + trap/inform receiver — strictly aes-256

- POST /kms {user,key_ID} -> fetches dec_key from slave kms once per key_ID and rotates usm (sha+aes-256)
- GET /kms/ready?key_ID=... -> {"applied": true/false, "processed": true/false}
- usm user: usr-sha-aes256 (auth=sha, priv=aes-256)
- snmpv3 on --host:--port (default 0.0.0.0:50161), http on :--http-port (default :8080)
"""

import argparse
import base64
import gzip
import hashlib
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import requests
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context, ntfrcv
from pysnmp.hlapi import usmHMACSHAAuthProtocol

#strict aes-256
try:
    from pysnmp.hlapi import usmAesCfb256Protocol
except Exception as e:
    raise RuntimeError("pysnmp installation lacks AES-256 (usmAesCfb256Protocol)") from e

def parse_args():
    p = argparse.ArgumentParser(description="snmpv3 agent (aes-256 trap/inform) + slave kms integration")
    p.add_argument("--host", default="0.0.0.0", help="snmp listen host (default 0.0.0.0)")
    p.add_argument("--port", type=int, default=50161, help="snmp listen port (default 50161)")
    p.add_argument("--http-port", type=int, default=8080, help="http port for /kms and /kms/ready (default 8080)")
    p.add_argument("--user", default="usr-sha-aes256", help="usm username (default usr-sha-aes256)")
    p.add_argument("--slave-kms-base", default="http://10.250.1.2", help="slave kms base url")
    p.add_argument("--slave-app-id", default="bbbc7de9-5826-11ef-8057-9b39f247bbb", help="slave kms app_id")
    p.add_argument("--dec-timeout", type=int, default=3, help="dec_keys http timeout (s)")
    p.add_argument("--dec-retries", type=int, default=6, help="number of attempts to slave kms")
    p.add_argument("--dec-delay", type=float, default=0.7, help="delay between attempts (s)")
    return p.parse_args()

args = parse_args()

#log
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.info("snmp privacy (agent): AES-256")

#state
snmpEngine = engine.SnmpEngine()
SLAVE_KMS_BASE = args.slave_kms_base.rstrip("/")
SLAVE_APP_ID   = args.slave_app_id
DEC_TIMEOUT    = args.dec_timeout
DEC_RETRIES    = args.dec_retries
DEC_DELAY      = args.dec_delay
USM_USER       = args.user

in_flight     = set()
processed_ids = set()   # finished (ok or gone/error)
applied_ids   = set()   # key actually applied to usm
lock          = threading.Lock()

#snmp engine
config.addTransport(
    snmpEngine, udp.domainName,
    udp.UdpTransport().openServerMode((args.host, args.port))
)

def _derive_aes256(k: bytes) -> bytes:
    return k if len(k) == 32 else hashlib.sha256(k).digest()

def ensure_usm_user(user: str, priv_key_bytes: bytes):
    """add/rotate usm user sha+aes-256 and vacm rights"""
    config.addV3User(
        snmpEngine, user,
        usmHMACSHAAuthProtocol, "authkey1",
        usmAesCfb256Protocol, _derive_aes256(priv_key_bytes)
    )
    #vacm: full access to mib-2 (example)
    try:
        config.addVacmUser(snmpEngine, 3, user, 'authPriv', (1,3,6,1,2,1), (1,3,6,1,2,1))
    except Exception:
        pass
    logging.info("usm set/rotated: %s (sha + aes-256)", user)

#initial placeholder (will rotate after /kms)
ensure_usm_user(USM_USER, b"\x00" * 32)

snmpContext = context.SnmpContext(snmpEngine)
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

def _notif_cb(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    try:
        pairs = "; ".join(f"{n.prettyPrint()}={v.prettyPrint()}" for n, v in varBinds)
        logging.info("received TRAP/INFORM: %s", pairs)
    except Exception as e:
        logging.warning("notification callback error: %s", e)

ntfrcv.NotificationReceiver(snmpEngine, _notif_cb)

#kms helper
def fetch_dec_key_from_slave(key_id: str):
    """
    POST {"key_IDs":[{"key_ID": key_id}]} -> {"keys":[{"key":"<b64>","key_ID":"..."}]}
    returns ("ok", bytes) | ("gone", None) | ("error", None)
    """
    url = f"{SLAVE_KMS_BASE}/api/v1/keys/{SLAVE_APP_ID}/dec_keys"
    payload = {"key_IDs": [{"key_ID": key_id}]}
    try:
        r = requests.post(
            url, json=payload, timeout=DEC_TIMEOUT, stream=True,
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
        enc = (r.headers.get("Content-Encoding") or "").lower().strip()
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
            kb  = base64.b64decode(b64)
            return "ok", kb
        except Exception as e:
            logging.warning("dec_keys parse/base64 error: %s", e)
            return "error", None

    #non-200: read a small body for diagnostics
    body = ""
    try:
        try: r.raw.decode_content = False
        except Exception: pass
        body = r.raw.read(512).decode("utf-8", "replace")
    except Exception:
        pass
    if r.status_code in (404, 410) or (r.status_code == 400 and "key not found" in (body or "").lower()):
        return "gone", None
    logging.warning("dec_keys unexpected status=%s body=%r", r.status_code, (body or "")[:200])
    return "error", None

def process_key_id_async(user: str, key_id: str):
    logging.info("kms notification: user=%s key_ID=%s", user, key_id)
    try:
        for _ in range(DEC_RETRIES):
            status, key_bytes = fetch_dec_key_from_slave(key_id)
            logging.info("dec_keys for key_ID=%s -> %s", key_id, status)
            if status == "ok" and key_bytes:
                ensure_usm_user(user, key_bytes)
                with lock:
                    processed_ids.add(key_id)
                    applied_ids.add(key_id)
                break
            if status == "gone":
                with lock:
                    processed_ids.add(key_id)
                break
            time.sleep(DEC_DELAY)
        else:
            logging.info("slave kms did not return the key in time (user=%s, key_ID=%s)", user, key_id)
    finally:
        with lock:
            in_flight.discard(key_id)

#http handler
class QKDHandler(BaseHTTPRequestHandler):
    def log_message(self, *args, **kw):  #silence default http log
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
        p = urlparse(self.path)
        if p.path == "/kms/ready":
            qs = parse_qs(p.query or "")
            key_id = (qs.get("key_ID") or [""])[0]
            with lock:
                applied   = key_id in applied_ids
                processed = key_id in processed_ids
            return self._send_json(200, {"applied": applied, "processed": processed, "key_ID": key_id})
        return self._send_text(404, "Not found")

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/kms":
            return self._send_text(404, "Not found")
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except Exception:
            length = 0
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except Exception:
            return self._send_text(400, "Invalid JSON")

        user   = data.get("user") or USM_USER
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

#startup
def start_http():
    httpd = HTTPServer(("0.0.0.0", args.http_port), QKDHandler)
    logging.info("qkd/kms endpoint listening on :%d", args.http_port)
    httpd.serve_forever()

def start_snmp():
    def _loop():
        snmpEngine.transportDispatcher.jobStarted(1)
        logging.info("snmp agent listening on %s:%d", args.host, args.port)
        try:
            snmpEngine.transportDispatcher.runDispatcher()
        finally:
            snmpEngine.transportDispatcher.closeDispatcher()
    threading.Thread(target=_loop, daemon=True).start()

def main():
    threading.Thread(target=start_http, daemon=True).start()
    start_snmp()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        logging.info("server stopping...")

if __name__ == "__main__":
    main()
