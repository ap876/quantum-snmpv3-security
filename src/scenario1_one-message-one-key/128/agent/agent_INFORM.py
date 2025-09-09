#!/usr/bin/env python3
# -- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/agent/cmdrsp/multiple-usm-users.py
# adapted and extended for scenario 1 ("one message – one key") with kms integration, inform-ready variant (aes-256)

"""
snmpv3 agent (usm) with kms integration
idempotent dec_key retrieval and /kms/ready probe

policy (scenario 1: one message – one key):
- for each snmp message, the manager fetches a fresh enc_key and posts key_ID to the agent (/kms)
- the agent fetches the matching dec_key from slave kms and rotates the usm key for the given user
- duplicate key_ID notifications are handled idempotently (already processed/in-flight)
- /kms/ready?key_ID=... returns {"applied": true} once rotation completes, else false/404
- after rotation, the next snmp request is served with the freshly applied key

snmpv3 listens on LISTEN_ADDR:SNMP_PORT
http rest control on :HTTP_PORT
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
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.hlapi import (
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmDESPrivProtocol,
)

#try to import aes-256 ->fail fast if unavailable
try:
    from pysnmp.hlapi import usmAesCfb256Protocol
except Exception as e:
    raise RuntimeError("pysnmp build does not include AES-256 (usmAesCfb256Protocol).") from e

#logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)

#config
LISTEN_ADDR = "0.0.0.0"
SNMP_PORT   = 50161
HTTP_PORT   = 8080
QKD_USER_DEFAULT = "usr-sha-aes256"

#slave kms
SLAVE_KMS_BASE = os.getenv("SLAVE_KMS_BASE", "http://10.250.1.2")
SLAVE_APP_ID   = os.getenv("SLAVE_APP_ID",   "bbbc7de9-5826-11ef-8057-9b39f247bbb")

#dec_keys retry/timing
DEC_TIMEOUT_SEC   = 3
DEC_RETRIES       = 6
DEC_RETRY_DELAY_S = 0.7  #~4s total window

#dedup and state
in_flight = set()       #key_ID currently being processed
processed_ids = set()   #key_ID processed (either applied or terminally gone)
applied_ids = set()     #key_ID for which USM rotation actually applied

#snmp engine
snmpEngine = engine.SnmpEngine()

config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTransport().openServerMode((LISTEN_ADDR, SNMP_PORT))
)

#initial usm users (demo compatibility)
config.addV3User(snmpEngine, "usr-md5-des",
                 usmHMACMD5AuthProtocol, "authkey1",
                 usmDESPrivProtocol,     "privkey1")

config.addV3User(snmpEngine, "usr-sha-none",
                 usmHMACSHAAuthProtocol, "authkey1")

#primary aes-256 user (priv will be rotated via /kms); placeholder 32B
config.addV3User(snmpEngine, "usr-sha-aes256",
                 usmHMACSHAAuthProtocol, "authkey1",
                 usmAesCfb256Protocol,   b"\x00" * 32)

config.addVacmUser(snmpEngine, 3, "usr-md5-des",    "authPriv",  (1,3,6,1,2,1), (1,3,6,1,2,1))
config.addVacmUser(snmpEngine, 3, "usr-sha-none",   "authNoPriv",(1,3,6,1,2,1), (1,3,6,1,2,1))
config.addVacmUser(snmpEngine, 3, "usr-sha-aes256", "authPriv",  (1,3,6,1,2,1), (1,3,6,1,2,1))

snmpContext = context.SnmpContext(snmpEngine)
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

#helpers
def _derive_aes256(key_bytes: bytes) -> bytes:
    #return exactly 32B; if not, sha256 digest (32B)
    return key_bytes if len(key_bytes) == 32 else hashlib.sha256(key_bytes).digest()

def rotate_usm_keys(user: str, new_priv_key_bytes: bytes, also_rotate_auth: bool = False):
    #rotate usm keys; by default only priv (aes-256)
    try:
        priv_key_256 = _derive_aes256(new_priv_key_bytes)
        if not also_rotate_auth:
            config.addV3User(
                snmpEngine, user,
                usmHMACSHAAuthProtocol, "authkey1",
                usmAesCfb256Protocol,   priv_key_256
            )
        else:
            auth_key = hashlib.sha256(new_priv_key_bytes).digest()
            config.addV3User(
                snmpEngine, user,
                usmHMACSHAAuthProtocol, auth_key,
                usmAesCfb256Protocol,   priv_key_256
            )
        logging.info("usm keys rotated for user=%s (auth=SHA, priv=AES-256)", user)
        return True
    except Exception as e:
        logging.warning("usm key rotation failed: %s", e)
        return False

def fetch_dec_key_from_slave(slave_base: str, app_id: str, key_id: str, timeout=DEC_TIMEOUT_SEC):
    """
    fetch one decrypt key from slave kms for a given key_ID
    request: POST /api/v1/keys/{app_id}/dec_keys with {"key_IDs":[{"key_ID":"..."}]}
    returns: ("ok", key_bytes) | ("gone", None) | ("error", None)
    """
    url = f"{slave_base}/api/v1/keys/{app_id}/dec_keys"
    payload = {"key_IDs": [{"key_ID": key_id}]}

    try:
        r = requests.post(
            url,
            json=payload,
            timeout=timeout,
            stream=True,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Content-Type": "application/json",
            },
        )
    except Exception as e:
        logging.warning("dec_keys transport error: %s", e)
        return "error", None

    status = r.status_code

    if status == 200:
        try:
            r.raw.decode_content = False
        except Exception:
            pass
        try:
            raw_bytes = r.raw.read()
        except Exception as e:
            logging.warning("dec_keys: failed reading raw body: %s", e)
            return "error", None

        enc = (r.headers.get("Content-Encoding") or "").lower().strip()
        if "gzip" in enc and raw_bytes[:2] == b"\x1f\x8b":
            try:
                raw_bytes = gzip.decompress(raw_bytes)
            except Exception as e:
                logging.warning("dec_keys: gzip decompress failed: %s; falling back to plain json", e)

        body = raw_bytes.decode("utf-8", "replace")

        try:
            data = json.loads(body)
            items = data.get("keys") or []
            if not items:
                logging.warning("dec_keys: missing 'keys' in body=%r", body[:200])
                return "error", None

            b64 = (items[0].get("key") or "").strip()
            if not b64:
                logging.warning("dec_keys: missing 'key' in body=%r", body[:200])
                return "error", None

            try:
                key_bytes = base64.b64decode(b64)
                return "ok", key_bytes
            except Exception as e:
                logging.warning("dec_keys: base64 decode failed: %s; key(prefix)=%r", e, b64[:30])
                return "error", None

        except Exception as e:
            logging.warning("dec_keys: json parse error: %s; body=%r", e, body[:200])
            return "error", None

    #non-200 path
    text = ""
    try:
        try:
            r.raw.decode_content = False
        except Exception:
            pass
        text = r.raw.read(512).decode("utf-8", "replace")
    except Exception:
        pass

    if status in (404, 410):
        return "gone", None
    if status == 400 and "key not found" in (text or "").lower():
        return "gone", None

    logging.warning("dec_keys: unexpected status=%s body=%r", status, text[:200])
    return "error", None

def process_key_id_async(user: str, key_id: str):
    #background worker: fetch dec_key and rotate usm; records applied status
    logging.info("kms notification received: user=%s key_ID=%s (fetching from slave kms)", user, key_id)
    try:
        for _ in range(DEC_RETRIES):
            status, key_bytes = fetch_dec_key_from_slave(SLAVE_KMS_BASE, SLAVE_APP_ID, key_id)
            logging.info("dec_keys for key_ID=%s → %s", key_id, status)

            if status == "ok" and key_bytes:
                ok = rotate_usm_keys(user, key_bytes, also_rotate_auth=False)
                processed_ids.add(key_id)
                if ok:
                    applied_ids.add(key_id)
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
    def log_message(self, fmt, *args):
        #quiet http server
        return

    def _send_text(self, code: int, text: str):
        try:
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(text.encode("utf-8"))
        except Exception:
            pass

    def _send_json(self, code: int, obj: dict):
        try:
            body = json.dumps(obj)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
        except Exception:
            pass

    def do_GET(self):
        #implement /kms/ready?key_ID=... to allow inform-clients to poll readiness
        parsed = urlparse(self.path)
        if parsed.path == "/kms/ready":
            qs = parse_qs(parsed.query or "")
            key_id = (qs.get("key_ID") or qs.get("key_id") or [None])[0]
            if not key_id:
                return self._send_json(400, {"error": "missing key_ID"})
            if key_id in applied_ids:
                return self._send_json(200, {"applied": True, "key_ID": key_id})
            if key_id in processed_ids or key_id in in_flight:
                return self._send_json(200, {"applied": False, "key_ID": key_id})
            return self._send_json(404, {"applied": False, "key_ID": key_id, "error": "unknown key_ID"})
        return self._send_text(404, "not found")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            data = json.loads(raw or "{}")
        except Exception:
            return self._send_text(400, "invalid json")

        #optional raw key injection for testing
        if path == "/qkd":
            user = data.get("user") or QKD_USER_DEFAULT
            b64  = data.get("key")
            if not b64:
                return self._send_text(400, "missing 'key'")
            try:
                key_bytes = base64.b64decode(b64, validate=True)
                ok = rotate_usm_keys(user, key_bytes, also_rotate_auth=False)
                #simulate applied if rotation succeeded (no key_ID context here)
                return self._send_text(200, f"ok: rotated keys for {user}, applied={ok}")
            except Exception as e:
                logging.info("qkd /qkd error: %s", e)
                return self._send_text(500, "error")

        #main entry point -> manager notifies which key_ID to fetch
        if path == "/kms":
            user   = data.get("user") or QKD_USER_DEFAULT
            key_id = data.get("key_ID")
            if not key_id:
                return self._send_text(400, "missing 'key_ID'")

            if key_id in processed_ids:
                logging.info("duplicate key_ID=%s (already processed) – idempotent 200", key_id)
                return self._send_json(200, {"status": "already-processed", "user": user, "key_ID": key_id})

            if key_id in in_flight:
                logging.info("duplicate key_ID=%s (in flight) – idempotent 200", key_id)
                return self._send_json(200, {"status": "in-flight", "user": user, "key_ID": key_id})

            in_flight.add(key_id)
            threading.Thread(target=process_key_id_async, args=(user, key_id), daemon=True).start()
            logging.info("kms notification queued: user=%s key_ID=%s", user, key_id)
            return self._send_json(200, {"status": "queued", "user": user, "key_ID": key_id})

        return self._send_text(404, "not found")

#start functions
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
        except Exception as e:
            logging.error("snmp dispatcher error: %s", e)
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
