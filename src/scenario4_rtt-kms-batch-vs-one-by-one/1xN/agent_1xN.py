#!/usr/bin/env python3
# -- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/agent/cmdrsp/multiple-usm-users.py
#snmpv3 agent+kms proxy with csv timing

import base64, hashlib, json, logging, os, threading, time, gzip
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests


from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.hlapi import (
    usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
    usmDESPrivProtocol, usmAesCfb128Protocol, usmAesCfb256Protocol,
)


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)


import csv
def _csv_init(path: str, header: list[str]):
    #ensure header once
    need = not os.path.exists(path) or os.path.getsize(path) == 0
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if need:
        with open(path, "w", newline="") as f:
            csv.writer(f).writerow(header)

def _csv_row(path: str, values: list):
    #append a row
    with open(path, "a", newline="") as f:
        csv.writer(f).writerow(values)

DEC_TIMES_CSV = "kms_dec_times.csv"
_csv_init(DEC_TIMES_CSV, [
    "ts","key_ID","req_bytes","resp_bytes","http_ms","rotate_ms","status"
])


LISTEN_ADDR = "0.0.0.0"
SNMP_PORT   = 50161
HTTP_PORT   = 8080
QKD_USER_DEFAULT = "usr-sha-aes128"

#slave kms endpoints
SLAVE_KMS_BASE = os.getenv("SLAVE_KMS_BASE", "http://10.250.1.2")
SLAVE_APP_ID   = os.getenv("SLAVE_APP_ID",   "bbbc7de9-5826-11ef-8057-9b39f247bbb")

#retry policy
DEC_TIMEOUT_SEC   = 3
DEC_RETRIES       = 6
DEC_RETRY_DELAY_S = 0.7

#state
in_flight = set()
processed_ids = set()
key_state = {}  #key_ID->{"status":str,"applied_ts":float,"bits":128/256}

#snmp engine front
snmpEngine = engine.SnmpEngine()
config.addTransport(snmpEngine, udp.domainName, udp.UdpTransport().openServerMode((LISTEN_ADDR, SNMP_PORT)))
config.addV3User(snmpEngine, "usr-md5-des",    usmHMACMD5AuthProtocol, "authkey1", usmDESPrivProtocol,   "privkey1")
config.addV3User(snmpEngine, "usr-sha-none",   usmHMACSHAAuthProtocol, "authkey1")
config.addV3User(snmpEngine, "usr-sha-aes128", usmHMACSHAAuthProtocol, "authkey1", usmAesCfb128Protocol, "privkey1")
config.addVacmUser(snmpEngine, 3, "usr-md5-des",    "authPriv",  (1,3,6,1,2,1), (1,3,6,1,2,1))
config.addVacmUser(snmpEngine, 3, "usr-sha-none",   "authNoPriv",(1,3,6,1,2,1), (1,3,6,1,2,1))
config.addVacmUser(snmpEngine, 3, "usr-sha-aes128", "authPriv",  (1,3,6,1,2,1), (1,3,6,1,2,1))
snmpContext = context.SnmpContext(snmpEngine)
cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

#key derivation
def _derive_key_for_bits(key_bytes: bytes, bits: int) -> bytes:
    want = 16 if bits == 128 else 32
    return hashlib.sha256(key_bytes).digest()[:want] if len(key_bytes) != want else key_bytes

#rotate usm and time it
def rotate_usm_keys(user: str, new_priv_key_bytes: bytes, also_rotate_auth: bool = False) -> float:
    """return rotation time(ms) for csv"""
    t0 = time.perf_counter()
    try:
        if len(new_priv_key_bytes) >= 32:
            bits = 256; priv_proto = usmAesCfb256Protocol
        else:
            bits = 128; priv_proto = usmAesCfb128Protocol
        priv_key = _derive_key_for_bits(new_priv_key_bytes, bits)
        if not also_rotate_auth:
            config.addV3User(snmpEngine, user, usmHMACSHAAuthProtocol, "authkey1", priv_proto, priv_key)
        else:
            auth_key = hashlib.sha256(new_priv_key_bytes).digest()
            config.addV3User(snmpEngine, user, usmHMACSHAAuthProtocol, auth_key, priv_proto, priv_key)
        logging.info("USM keys rotated for user=%s (auth=SHA, priv=AES-%d)", user, bits)
    except Exception as e:
        logging.warning("key rotation failed: %s", e)
    return (time.perf_counter() - t0) * 1000.0

#pull dec_key from slave
def fetch_dec_key_from_slave(slave_base: str, app_id: str, key_id: str, timeout=DEC_TIMEOUT_SEC):
    url = f"{slave_base}/api/v1/keys/{app_id}/dec_keys"
    payload = {"key_IDs": [{"key_ID": key_id}]}
    body_bytes = json.dumps(payload).encode("utf-8")
    req_len = len(body_bytes)

    t0 = time.perf_counter()
    logging.info("dec_keys REQUEST → %s (key_ID=%s, req_payload=%d B)", url, key_id, req_len)
    try:
        r = requests.post(url, json=payload, timeout=timeout, stream=True,
                          headers={"Accept":"application/json","Accept-Encoding":"identity","Content-Type":"application/json"})
    except Exception as e:
        http_ms = (time.perf_counter()-t0)*1000
        logging.warning("dec_keys transport error after %.1f ms: %s", http_ms, e); return "error", None, req_len, 0, http_ms

    http_ms = (time.perf_counter()-t0)*1000
    #read raw body for exact bytes
    try:
        r.raw.decode_content = False
        raw_bytes = r.raw.read()
        resp_len = len(raw_bytes)
        enc = (r.headers.get("Content-Encoding") or "").lower().strip()
        if "gzip" in enc and raw_bytes[:2]==b"\x1f\x8b":
            try:
                raw_bytes = gzip.decompress(raw_bytes)
            except Exception:
                pass
        logging.info("dec_keys RESPONSE ← HTTP %s (%.1f ms, resp_payload=%d B, key_ID=%s)",
                     r.status_code, http_ms, resp_len, key_id)
    except Exception:
        raw_bytes = b""
        resp_len = 0

    if r.status_code == 200:
        try:
            data = json.loads(raw_bytes.decode("utf-8","replace"))
            b64 = (data.get("keys") or [{}])[0].get("key") or ""
            kb = base64.b64decode(b64)
            logging.info("dec_keys OK: key_ID=%s, key_len=%d B", key_id, len(kb))
            return "ok", kb, req_len, resp_len, http_ms
        except Exception as e:
            logging.warning("dec_keys parsing error: %s", e); return "error", None, req_len, resp_len, http_ms

    #non-200 handling
    try:
        tail = raw_bytes[:256].decode("utf-8","replace")
    except Exception:
        tail = ""
    if r.status_code in (404,410): return "gone", None, req_len, resp_len, http_ms
    if r.status_code==400 and "key not found" in (tail or "").lower(): return "gone", None, req_len, resp_len, http_ms
    logging.warning("dec_keys unexpected: HTTP %s body_prefix=%r", r.status_code, tail[:120])
    return "error", None, req_len, resp_len, http_ms

#async processor per key_ID
def process_key_id_async(user: str, key_id: str):
    logging.info("KMS notification: user=%s key_ID=%s (fetching dec_key)", user, key_id)
    try:
        for _ in range(DEC_RETRIES):
            status, key_bytes, req_len, resp_len, http_ms = fetch_dec_key_from_slave(SLAVE_KMS_BASE, SLAVE_APP_ID, key_id)
            logging.info("dec_keys attempt for key_ID=%s → %s", key_id, status)
            rotate_ms = 0.0
            if status == "ok" and key_bytes:
                rotate_ms = rotate_usm_keys(user, key_bytes, also_rotate_auth=False)
                bits = 256 if len(key_bytes) >= 32 else 128
                processed_ids.add(key_id); key_state[key_id]={"status":"applied","applied_ts":time.time(),"bits":bits}
                _csv_row(DEC_TIMES_CSV, [int(time.time()), key_id, req_len, resp_len, f"{http_ms:.3f}", f"{rotate_ms:.3f}", "applied"])
                break
            if status == "gone":
                processed_ids.add(key_id); key_state[key_id]={"status":"gone","applied_ts":time.time(),"bits":None}
                _csv_row(DEC_TIMES_CSV, [int(time.time()), key_id, req_len, resp_len, f"{http_ms:.3f}", f"{rotate_ms:.3f}", "gone"])
                break
            _csv_row(DEC_TIMES_CSV, [int(time.time()), key_id, req_len, resp_len, f"{http_ms:.3f}", f"{rotate_ms:.3f}", status])
            time.sleep(DEC_RETRY_DELAY_S)
        else:
            key_state[key_id]={"status":"timeout","applied_ts":time.time(),"bits":None}
            _csv_row(DEC_TIMES_CSV, [int(time.time()), key_id, 0, 0, f"{0.000:.3f}", f"{0.000:.3f}", "timeout"])
    finally:
        in_flight.discard(key_id)

#http handler
class QKDHandler(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs): return
    def _send_json(self, code:int, obj:dict):
        try:
            body=json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass
    def _send_text(self, code:int, text:str):
        try:
            body=text.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type","text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass
    def do_POST(self):
        path=self.path.split("?",1)[0]
        length=int(self.headers.get("Content-Length","0") or "0")
        try:
            raw = self.rfile.read(length) if length else b""
            data=json.loads(raw.decode("utf-8") if raw else "{}")
        except Exception:
            return self._send_text(400,"Invalid JSON")

        if path=="/kms":
            #kms key notification
            user=data.get("user") or QKD_USER_DEFAULT
            key_id=data.get("key_ID")
            if not key_id: return self._send_text(400,"Missing 'key_ID'")
            if key_id in processed_ids:
                resp={"status":"already-processed","user":user,"key_ID":key_id}
                logging.info("/kms req=%d B resp=%d B (already-processed key_ID=%s)",
                             length, len(json.dumps(resp).encode()), key_id)
                return self._send_json(200, resp)
            if key_id in in_flight:
                resp={"status":"in-flight","user":user,"key_ID":key_id}
                logging.info("/kms req=%d B resp=%d B (in-flight key_ID=%s)",
                             length, len(json.dumps(resp).encode()), key_id)
                return self._send_json(200, resp)

            in_flight.add(key_id)
            threading.Thread(target=process_key_id_async, args=(user,key_id), daemon=True).start()
            logging.info("Queued key_ID=%s (/kms req_payload=%d B)", key_id, length)
            resp={"status":"queued","user":user,"key_ID":key_id}
            logging.info("/kms resp_payload=%d B", len(json.dumps(resp).encode()))
            return self._send_json(200, resp)

        if path=="/qkd":
            #manual key rotate via raw key
            user=data.get("user") or QKD_USER_DEFAULT
            b64=data.get("key")
            if not b64: return self._send_text(400,"Missing 'key'")
            try:
                rotate_ms = rotate_usm_keys(user, base64.b64decode(b64, validate=True), also_rotate_auth=False)
                _csv_row(DEC_TIMES_CSV, [int(time.time()), "(manual)", 0, 0, f"{0.000:.3f}", f"{rotate_ms:.3f}", "manual-rotate"])
                return self._send_text(200,f"OK: rotated for {user}")
            except Exception:
                return self._send_text(500,"ERROR")
        return self._send_text(404,"Not found")

    def do_GET(self):
        path,_,query=self.path.partition("?")
        if path=="/kms/ready":
            #poll applied status
            from urllib.parse import parse_qs
            key_id=(parse_qs(query).get("key_ID") or [""])[0]
            if not key_id: return self._send_json(400,{"error":"missing key_ID"})
            st=key_state.get(key_id) or {}
            inprog=key_id in in_flight
            applied=(st.get("status")=="applied")
            return self._send_json(200,{
                "key_ID":key_id,"in_progress":inprog,"applied":applied,
                "status":st.get("status"),"bits":st.get("bits"),"applied_ts":st.get("applied_ts")
            })
        return self._send_text(404,"Not found")

#http server
def start_http_server():
    httpd=HTTPServer(("0.0.0.0", HTTP_PORT), QKDHandler)
    logging.info("QKD/KMS endpoint listening on :%d", HTTP_PORT)
    httpd.serve_forever()

#snmp server loop
def start_snmp_agent():
    def _loop():
        snmpEngine.transportDispatcher.jobStarted(1)
        logging.info("SNMP agent listening on %s:%d", LISTEN_ADDR, SNMP_PORT)
        try:
            snmpEngine.transportDispatcher.runDispatcher()
        finally:
            snmpEngine.transportDispatcher.closeDispatcher()
    threading.Thread(target=_loop, daemon=True).start()

#entrypoint
def main():
    threading.Thread(target=start_http_server, daemon=True).start()
    start_snmp_agent()
    try:
        while True: time.sleep(3600)
    except KeyboardInterrupt:
        logging.info("Server stopping...")

if __name__=="__main__":
    main()
