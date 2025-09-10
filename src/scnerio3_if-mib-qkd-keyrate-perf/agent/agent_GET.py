# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/agent/cmdrsp/multiple-usm-users.py
#!/usr/bin/env python3
#-- coding: utf-8 --

"""
snmpv3 agent (usm) + qkd/kms integration + proxy to net-snmpd (v2c public on 127.0.0.1:161)

front:
 - listens on snmpv3 0.0.0.0:50161 (user usr-sha-aes128, auth=sha, priv=aes-128)
 - /kms and /qkd rotate the usm privKey (qkd/kms integration)

proxy:
 - forwards get/get-next/get-bulk to local net-snmpd backend (v2c 'public' @ 127.0.0.1:161)
 - returns backend values to the client (transparent)
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
from typing import List, Tuple
import requests

#pysnmp: front (v3)
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context

#pysnmp: backend manager (v2c -> net-snmpd)
from pysnmp.hlapi import (
    SnmpEngine as ManagerEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, getCmd, nextCmd, bulkCmd
)
from pysnmp.hlapi import (
    usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol, usmDESPrivProtocol, usmAesCfb128Protocol,
)
from pysnmp.proto.rfc1902 import ObjectSyntax, ObjectName
from pysnmp.smi import instrum, builder

#logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)

#config
LISTEN_ADDR = "0.0.0.0"
SNMP_PORT   = 50161
HTTP_PORT   = 8080
QKD_USER_DEFAULT = "usr-sha-aes128"

#config(backend snmpd)
BACKEND_HOST      = os.getenv("BACKEND_HOST", "127.0.0.1")
BACKEND_PORT      = int(os.getenv("BACKEND_PORT", "161"))
BACKEND_COMMUNITY = os.getenv("BACKEND_COMMUNITY", "public")
BACKEND_TIMEOUT   = float(os.getenv("BACKEND_TIMEOUT", "1.0"))
BACKEND_RETRIES   = int(os.getenv("BACKEND_RETRIES", "1"))

#slave kms (append :8080 if needed)
SLAVE_KMS_BASE = os.getenv("SLAVE_KMS_BASE", "http://10.250.1.2")
SLAVE_APP_ID   = os.getenv("SLAVE_APP_ID", "bbbc7de9-5826-11ef-8057-9b39f247bbb")

#retry policy
DEC_TIMEOUT_SEC    = 5
DEC_RETRIES        = 10
DEC_RETRY_DELAY_S  = 1.0

#dedup key_ID
in_flight     = set()
processed_ids = set()

#snmp engine
snmpEngine = engine.SnmpEngine()
config.addTransport(snmpEngine, udp.domainName, udp.UdpTransport().openServerMode((LISTEN_ADDR, SNMP_PORT)))

#usm users (initial; privKey will rotate via /kms /qkd)
config.addV3User(snmpEngine, "usr-md5-des",    usmHMACMD5AuthProtocol, "authkey1", usmDESPrivProtocol,   "privkey1")
config.addV3User(snmpEngine, "usr-sha-none",   usmHMACSHAAuthProtocol, "authkey1")  #authNoPriv(for discovery)
config.addV3User(snmpEngine, "usr-sha-aes128", usmHMACSHAAuthProtocol, "authkey1", usmAesCfb128Protocol, "privkey1")

#vacm: allow access to mib-2 (includes if-mib subtree and ifX 1.3.6.1.2.1.31)
config.addVacmUser(snmpEngine, 3, "usr-md5-des",    "authPriv",  (1,3,6,1,2,1), (1,3,6,1,2,1))
config.addVacmUser(snmpEngine, 3, "usr-sha-none",   "authNoPriv",(1,3,6,1,2,1), (1,3,6,1,2,1))
config.addVacmUser(snmpEngine, 3, "usr-sha-aes128", "authPriv",  (1,3,6,1,2,1), (1,3,6,1,2,1))

#backend manager engine
mgrEngine    = ManagerEngine()
mgrCommunity = CommunityData(BACKEND_COMMUNITY, mpModel=1)  #v2c
mgrTarget    = UdpTransportTarget((BACKEND_HOST, BACKEND_PORT), timeout=BACKEND_TIMEOUT, retries=BACKEND_RETRIES)
mgrContext   = ContextData()

#proxy mib instrument
class BackendProxyInstrum(instrum.MibInstrumController):
    def __init__(self):
        super().__init__(builder.MibBuilder())  #dummy builder

    @staticmethod
    def _to_oid_tuple(x) -> Tuple[int, ...]:
        if isinstance(x, ObjectName): return tuple(x)
        if isinstance(x, (tuple, list)): return tuple(int(i) for i in x)
        if isinstance(x, str): return tuple(int(i) for i in x.strip('.').split('.'))
        return tuple(x)

    #correct signatures(acInfo is required)
    def readVars(self, varBinds: List[Tuple[ObjectName, ObjectSyntax]], acInfo):
        req = [ObjectType(ObjectIdentity(self._to_oid_tuple(oid))) for (oid, _v) in varBinds]
        errorInd, errorStat, errorIdx, binds = next(getCmd(mgrEngine, mgrCommunity, mgrTarget, mgrContext, *req))
        if errorInd:  raise RuntimeError(f"backend GET error: {errorInd}")
        if errorStat: raise RuntimeError(f"backend GET status: {errorStat.prettyPrint()} at {errorIdx}")
        return [(ObjectName(name), val) for (name, val) in binds]

    def readNextVars(self, varBinds: List[Tuple[ObjectName, ObjectSyntax]], acInfo):
        results = []
        for (oid, _v) in varBinds:
            start = ObjectType(ObjectIdentity(self._to_oid_tuple(oid)))
            g = nextCmd(mgrEngine, mgrCommunity, mgrTarget, mgrContext, start, lexicographicMode=False)
            try:
                errorInd, errorStat, errorIdx, binds = next(g)
            except StopIteration:
                raise RuntimeError("backend NEXT exhausted")
            if errorInd:  raise RuntimeError(f"backend NEXT error: {errorInd}")
            if errorStat: raise RuntimeError(f"backend NEXT status: {errorStat.prettyPrint()} at {errorIdx}")
            name, val = binds[0]
            results.append((ObjectName(name), val))
        return results

    def readBulkVars(self, nonRepeaters: int, maxRepetitions: int, varBinds: List[Tuple[ObjectName, ObjectSyntax]], acInfo):
        req = [ObjectType(ObjectIdentity(self._to_oid_tuple(oid))) for (oid, _v) in varBinds]
        out = []
        g = bulkCmd(mgrEngine, mgrCommunity, mgrTarget, mgrContext, nonRepeaters, maxRepetitions, *req, lexicographicMode=False)
        try:
            errorInd, errorStat, errorIdx, binds = next(g)
        except StopIteration:
            return out
        if errorInd:  raise RuntimeError(f"backend BULK error: {errorInd}")
        if errorStat: raise RuntimeError(f"backend BULK status: {errorStat.prettyPrint()} at {errorIdx}")
        for (name, val) in binds:
            out.append((ObjectName(name), val))
        return out

#register context and replace default instrument
snmpContext = context.SnmpContext(snmpEngine)
try:
    snmpContext.unregisterContextName('')
except Exception:
    pass
snmpContext.registerContextName('', BackendProxyInstrum())

#responders
cmdrsp.GetCommandResponder(snmpEngine,  snmpContext)
cmdrsp.SetCommandResponder(snmpEngine,  snmpContext)   #set will fail(backend is RO)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

#qkd/kms rotation
def _derive_aes128(key_bytes: bytes) -> bytes:
    if len(key_bytes) == 16: return key_bytes
    return hashlib.sha256(key_bytes).digest()[:16]

def rotate_usm_keys(user: str, new_priv_key_bytes: bytes, also_rotate_auth: bool = False):
    try:
        priv_key_128 = _derive_aes128(new_priv_key_bytes)
        if not also_rotate_auth:
            config.addV3User(snmpEngine, user, usmHMACSHAAuthProtocol, "authkey1", usmAesCfb128Protocol, priv_key_128)
        else:
            auth_key = hashlib.sha256(new_priv_key_bytes).digest()
            config.addV3User(snmpEngine, user, usmHMACSHAAuthProtocol, auth_key, usmAesCfb128Protocol, priv_key_128)
        logging.info("usm keys rotated for user=%s (auth=sha, priv=aes-128)", user)
    except Exception as e:
        logging.warning("usm key rotation failed: %s", e)

def fetch_dec_key_from_slave(slave_base: str, app_id: str, key_id: str, timeout=5):
    url = f"{slave_base}/api/v1/keys/{app_id}/dec_keys"
    payload = {"key_IDs": [{"key_ID": key_id}]}
    try:
        r = requests.post(url, json=payload, timeout=timeout, stream=True,
                          headers={"Accept":"application/json","Accept-Encoding":"identity","Content-Type":"application/json"})
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
                logging.warning("dec_keys: gzip decompress failed: %s", e)
        body = raw_bytes.decode("utf-8","replace")
        try:
            data = json.loads(body)
            items = data.get("keys") or []
            if not items: return "error", None
            b64 = (items[0].get("key") or "").strip()
            if not b64: return "error", None
            try:
                key_bytes = base64.b64decode(b64)
                return "ok", key_bytes
            except Exception as e:
                logging.warning("dec_keys: base64 decode failed: %s", e); return "error", None
        except Exception as e:
            logging.warning("dec_keys: json parse error: %s", e); return "error", None

    txt = ""
    try:
        try:
            r.raw.decode_content = False
        except Exception:
            pass
        txt = r.raw.read(512).decode("utf-8","replace")
    except Exception:
        pass
    if status in (404, 410): return "gone", None
    if status == 400 and "key not found" in (txt or "").lower(): return "gone", None
    logging.warning("dec_keys: unexpected status=%s body=%r", status, txt[:200])
    return "error", None

def process_key_id_async(user: str, key_id: str):
    logging.info("kms notification received: user=%s key_ID=%s (fetching from slave kms)", user, key_id)
    try:
        for attempt in range(1, DEC_RETRIES+1):
            status, key_bytes = fetch_dec_key_from_slave(SLAVE_KMS_BASE, SLAVE_APP_ID, key_id)
            logging.info("dec_keys attempt %d for key_ID=%s -> %s", attempt, key_id, status)
            if status == "ok" and key_bytes:
                rotate_usm_keys(user, key_bytes, also_rotate_auth=False)
                processed_ids.add(key_id); break
            if status == "gone":
                processed_ids.add(key_id); break
            time.sleep(DEC_RETRY_DELAY_S)
        else:
            logging.info("slave kms did not return a key in time (user=%s, key_ID=%s)", user, key_id)
    finally:
        in_flight.discard(key_id)

#http handler
class QKDHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): return

    def _send_text(self, code: int, text: str):
        try:
            self.send_response(code); self.send_header("Content-Type","text/plain; charset=utf-8")
            self.end_headers(); self.wfile.write(text.encode("utf-8"))
        except Exception: pass

    def _send_json(self, code: int, obj: dict):
        try:
            body = json.dumps(obj); self.send_response(code); self.send_header("Content-Type","application/json")
            self.end_headers(); self.wfile.write(body.encode("utf-8"))
        except Exception: pass

    def do_POST(self):
        path = self.path.split("?",1)[0]
        length = int(self.headers.get("Content-Length","0") or "0")
        try:
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            data = json.loads(raw or "{}")
        except Exception:
            return self._send_text(400, "Invalid JSON")

        if path == "/qkd":
            user = data.get("user") or QKD_USER_DEFAULT
            b64  = data.get("key")
            if not b64: return self._send_text(400, "Missing 'key'")
            try:
                key_bytes = base64.b64decode(b64, validate=True)
                rotate_usm_keys(user, key_bytes, also_rotate_auth=False)
                return self._send_text(200, f"OK: rotated keys for {user}")
            except Exception as e:
                logging.info("qkd /qkd error: %s", e); return self._send_text(500, "ERROR")

        if path == "/kms":
            user   = data.get("user") or QKD_USER_DEFAULT
            key_id = data.get("key_ID")
            if not key_id: return self._send_text(400, "Missing 'key_ID'")
            if key_id in processed_ids:
                logging.info("duplicate key_ID=%s (already processed) – 200", key_id)
                return self._send_json(200, {"status":"already-processed","user":user,"key_ID":key_id})
            if key_id in in_flight:
                logging.info("duplicate key_ID=%s (processing) – 200", key_id)
                return self._send_json(200, {"status":"in-flight","user":user,"key_ID":key_id})

            in_flight.add(key_id)
            threading.Thread(target=process_key_id_async, args=(user, key_id), daemon=True).start()
            logging.info("kms notification queued: user=%s key_ID=%s", user, key_id)
            return self._send_json(200, {"status":"queued","user":user,"key_ID":key_id})

        return self._send_text(404, "Not found")

#start helpers
def start_http_server():
    httpd = HTTPServer(("0.0.0.0", HTTP_PORT), QKDHandler)
    logging.info("qkd/kms endpoint listening on :%d", HTTP_PORT)
    httpd.serve_forever()

def start_snmp_agent():
    def _loop():
        snmpEngine.transportDispatcher.jobStarted(1)
        logging.info("snmp agent(proxy front) listening on %s:%d", LISTEN_ADDR, SNMP_PORT)
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
