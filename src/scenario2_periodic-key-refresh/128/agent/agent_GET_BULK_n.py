#!/usr/bin/env python3
# -- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/agent/cmdrsp/multiple-usm-users.py

"""
SNMPv3 agent (multiple USM users) + KMS integration (Slave KMS) + traffic logger

Endpoints:
- POST /kms accepts {"user","key_ID"} and, exactly once per key_ID, calls Slave KMS /dec_keys (idempotent)
- GET/SET/NEXT/BULK responders are enabled.

Telemetry:
- Measures the size of every response the agent sends (TX = client's RX) and logs to traffic_getbulk60.csv
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

import requests
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.hlapi import (
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmDESPrivProtocol,
    usmAesCfb128Protocol,
)

#logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)

#config
LISTEN_ADDR = "0.0.0.0"
SNMP_PORT   = 50161
HTTP_PORT   = 8080
QKD_USER_DEFAULT = "usr-sha-aes128"

#slave kms 
SLAVE_KMS_BASE = os.getenv("SLAVE_KMS_BASE", "http://10.250.1.2")
SLAVE_APP_ID   = os.getenv("SLAVE_APP_ID",   "bbbc7de9-5826-11ef-8057-9b39f247bbb")

#dec_keys retry/timing
DEC_TIMEOUT_SEC   = 6
DEC_RETRIES       = 10
DEC_RETRY_DELAY_S = 1.2

#deduplication
in_flight = set()
processed_ids = set()

#traffic log (agent)
RUN_ID        = os.getenv("RUN_ID", f"run_{int(time.time())}")
REKEY_MODE    = os.getenv("REKEY_MODE", "time_based")
REKEY_PERIOD  = os.getenv("REKEY_PERIOD", "N/A")

traffic_log = logging.getLogger("traffic")
traffic_log.setLevel(logging.INFO)
try:
    _fh = logging.FileHandler("traffic_getbulk60.csv", mode="a", encoding="utf-8")
except Exception:
    _fh = logging.FileHandler("traffic_getbulk60.csv", mode="a")
_f = logging.Formatter("%(message)s")
_fh.setFormatter(_f)
traffic_log.addHandler(_fh)
try:
    if _fh.stream.tell() == 0:
        traffic_log.info("ts,pkt_dir,role,op,rekey_mode,rekey_period,varbinds,snmp_bytes,wire_bytes_ipv4,run_id,event")
except Exception:
    pass

#snmp engine
snmpEngine = engine.SnmpEngine()
config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTransport().openServerMode((LISTEN_ADDR, SNMP_PORT))
)

#usm users (initial values)
config.addV3User(snmpEngine, "usr-md5-des",
                 usmHMACMD5AuthProtocol, "authkey1",
                 usmDESPrivProtocol,     "privkey1")

config.addV3User(snmpEngine, "usr-sha-none",
                 usmHMACSHAAuthProtocol, "authkey1")

config.addV3User(snmpEngine, "usr-sha-aes128",
                 usmHMACSHAAuthProtocol, "authkey1",
                 usmAesCfb128Protocol,   "privkey1")

config.addVacmUser(snmpEngine, 3, "usr-md5-des",    "authPriv",  (1,3,6,1,2,1), (1,3,6,1,2,1))
config.addVacmUser(snmpEngine, 3, "usr-sha-none",   "authNoPriv",(1,3,6,1,2,1), (1,3,6,1,2,1))
config.addVacmUser(snmpEngine, 3, "usr-sha-aes128", "authPriv",  (1,3,6,1,2,1), (1,3,6,1,2,1))

snmpContext = context.SnmpContext(snmpEngine)
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

#spy -> measure the size of every SNMP message the server sends (TX = client's RX)
_orig_send_srv = udp.UdpTransport.sendMessage

def _spy_send_srv(self, *args, **kwargs):
    message = None
    transportAddress = None
    transportDomain = None

    if len(args) == 2:
        message = args[0]
        transportAddress = args[1]
    elif len(args) == 3:
        transportDomain = args[0]
        transportAddress = args[1]
        message = args[2]
    else:
        message = kwargs.get("message")
        transportAddress = kwargs.get("transportAddress")
        transportDomain = kwargs.get("transportDomain")

    try:
        n = len(message) if message is not None else 0
        traffic_log.info(
            f"{time.time():.6f},TX,server,GET-BULK,{REKEY_MODE},{REKEY_PERIOD},,"
            f"{n},{n+28},{RUN_ID},"
        )
    except Exception:
        pass

    return _orig_send_srv(self, *args, **kwargs)

udp.UdpTransport.sendMessage = _spy_send_srv

#helpers
def _derive_aes128(key_bytes: bytes) -> bytes:
    if len(key_bytes) == 16:
        return key_bytes
    return hashlib.sha256(key_bytes).digest()[:16]

def rotate_usm_keys(user: str, new_priv_key_bytes: bytes, also_rotate_auth: bool = False):
    try:
        priv_key_128 = _derive_aes128(new_priv_key_bytes)
        if not also_rotate_auth:
            config.addV3User(
                snmpEngine, user,
                usmHMACSHAAuthProtocol, "authkey1",
                usmAesCfb128Protocol,   priv_key_128
            )
        else:
            auth_key = hashlib.sha256(new_priv_key_bytes).digest()
            config.addV3User(
                snmpEngine, user,
                usmHMACSHAAuthProtocol, auth_key,
                usmAesCfb128Protocol,   priv_key_128
            )
        logging.info("USM keys rotated for user=%s (auth=SHA, priv=AES-128)", user)
        try:
            traffic_log.info(f"{time.time():.6f},EVT,server,KMS_APPLY,{REKEY_MODE},{REKEY_PERIOD},,"
                             f"0,0,{RUN_ID},kms_apply")
        except Exception:
            pass
    except Exception as e:
        logging.warning("USM key rotation failed: %s", e)

def fetch_dec_key_from_slave(slave_base: str, app_id: str, key_id: str, timeout=DEC_TIMEOUT_SEC):
    """
    POST /api/v1/keys/{app_id}/dec_keys  { "key_IDs":[{"key_ID": "<key_id>"}] }
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
                logging.warning("dec_keys: gzip decompress failed: %s; falling back to plain JSON", e)

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
            logging.warning("dec_keys: JSON parse error: %s; body=%r", e, body[:200])
            return "error", None

    #non-200: try to read brief message
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
    logging.info("KMS notification received: user=%s key_ID=%s (fetching from Slave KMS)", user, key_id)
    try:
        for _ in range(DEC_RETRIES):
            status, key_bytes = fetch_dec_key_from_slave(SLAVE_KMS_BASE, SLAVE_APP_ID, key_id)
            logging.info("dec_keys for key_ID=%s → %s", key_id, status)

            if status == "ok" and key_bytes:
                rotate_usm_keys(user, key_bytes, also_rotate_auth=False)
                processed_ids.add(key_id)
                break

            if status == "gone":
                processed_ids.add(key_id)
                break

            time.sleep(DEC_RETRY_DELAY_S)
        else:
            logging.info("Slave KMS did not return the key on time (user=%s, key_ID=%s)", user, key_id)
    finally:
        in_flight.discard(key_id)

#http handler
class QKDHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
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

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            data = json.loads(raw or "{}")
        except Exception:
            return self._send_text(400, "Invalid JSON")

        if path == "/qkd":
            user = data.get("user") or QKD_USER_DEFAULT
            b64  = data.get("key")
            if not b64:
                return self._send_text(400, "Missing 'key'")
            try:
                key_bytes = base64.b64decode(b64, validate=True)
                rotate_usm_keys(user, key_bytes, also_rotate_auth=False)
                return self._send_text(200, f"OK: rotated keys for {user}")
            except Exception as e:
                logging.info("QKD /qkd error: %s", e)
                return self._send_text(500, "ERROR")

        if path == "/kms":
            user   = data.get("user") or QKD_USER_DEFAULT
            key_id = data.get("key_ID")
            if not key_id:
                return self._send_text(400, "Missing 'key_ID'")

            if key_id in processed_ids:
                logging.info("duplicate key_ID=%s (already processed) — idempotent 200", key_id)
                return self._send_json(200, {"status": "already-processed", "user": user, "key_ID": key_id})

            if key_id in in_flight:
                logging.info("duplicate key_ID=%s (processing) — idempotent 200", key_id)
                return self._send_json(200, {"status": "in-flight", "user": user, "key_ID": key_id})

            in_flight.add(key_id)
            threading.Thread(target=process_key_id_async, args=(user, key_id), daemon=True).start()
            logging.info("KMS notification queued: user=%s key_ID=%s", user, key_id)
            return self._send_json(200, {"status": "queued", "user": user, "key_ID": key_id})

        return self._send_text(404, "Not found")

#start functions
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
        except Exception as e:
            logging.error("SNMP dispatcher error: %s", e)
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
