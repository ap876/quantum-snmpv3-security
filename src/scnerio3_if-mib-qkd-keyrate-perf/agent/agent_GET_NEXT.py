#!/usr/bin/env python3
#--coding:utf-8--
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/agent/cmdrsp/multiple-usm-users.py
"""
SNMPv3 agent (USM) + QKD KMS integracija + PROXY ka net-snmpd (v2c public na 127.0.0.1:161)
Front na :50161, HTTP /kms na :8080. Podržava GET / NEXT / BULK i prosljeđuje ka lokalnom snmpd-u.
"""


import base64, hashlib, json, logging, os, threading, time, gzip
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List, Tuple
import requests
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.hlapi import (
    SnmpEngine as ManagerEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, getCmd, nextCmd, bulkCmd
)
from pysnmp.hlapi import (
    usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol, usmDESPrivProtocol, usmAesCfb128Protocol,
)
from pysnmp.proto.rfc1902 import ObjectSyntax, ObjectName
from pysnmp.smi import instrum, builder


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)

LISTEN_ADDR = "0.0.0.0"
SNMP_PORT   = 50161
HTTP_PORT   = 8080
QKD_USER_DEFAULT = "usr-sha-aes128"

 
BACKEND_HOST      = os.getenv("BACKEND_HOST", "127.0.0.1")
BACKEND_PORT      = int(os.getenv("BACKEND_PORT", "161"))
BACKEND_COMMUNITY = os.getenv("BACKEND_COMMUNITY", "public")
BACKEND_TIMEOUT   = float(os.getenv("BACKEND_TIMEOUT", "1.0"))
BACKEND_RETRIES   = int(os.getenv("BACKEND_RETRIES", "1"))

#kms slave
SLAVE_KMS_BASE = os.getenv("SLAVE_KMS_BASE", "http://10.250.1.2")
SLAVE_APP_ID   = os.getenv("SLAVE_APP_ID", "bbbc7de9-5826-11ef-8057-9b39f247bbb")

#snmp engine(front)
snmpEngine = engine.SnmpEngine()
config.addTransport(snmpEngine, udp.domainName, udp.UdpTransport().openServerMode((LISTEN_ADDR, SNMP_PORT)))

#usm users
config.addV3User(snmpEngine, "usr-md5-des",    usmHMACMD5AuthProtocol, "authkey1", usmDESPrivProtocol,   "privkey1")
config.addV3User(snmpEngine, "usr-sha-none",   usmHMACSHAAuthProtocol, "authkey1")  #authnopriv
config.addV3User(snmpEngine, "usr-sha-aes128", usmHMACSHAAuthProtocol, "authkey1", usmAesCfb128Protocol, "privkey1")

#vacm 
config.addVacmUser(snmpEngine, 3, "usr-md5-des",    "authPriv",  (1,3,6,1,2,1), (1,3,6,1,2,1))
config.addVacmUser(snmpEngine, 3, "usr-sha-none",   "authNoPriv",(1,3,6,1,2,1), (1,3,6,1,2,1))
config.addVacmUser(snmpEngine, 3, "usr-sha-aes128", "authPriv",  (1,3,6,1,2,1), (1,3,6,1,2,1))


mgrEngine    = ManagerEngine()
mgrCommunity = CommunityData(BACKEND_COMMUNITY, mpModel=1)
mgrTarget    = UdpTransportTarget((BACKEND_HOST, BACKEND_PORT), timeout=BACKEND_TIMEOUT, retries=BACKEND_RETRIES)
mgrContext   = ContextData()

class BackendProxyInstrum(instrum.MibInstrumController):
    def __init__(self):
        super().__init__(builder.MibBuilder())

    @staticmethod
    def _to_oid_tuple(x) -> Tuple[int, ...]:
        if isinstance(x, ObjectName): return tuple(x)
        if isinstance(x, (tuple, list)): return tuple(int(i) for i in x)
        if isinstance(x, str): return tuple(int(i) for i in x.strip('.').split('.'))
        return tuple(x)

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
                if errorInd or errorStat:
                    from pysnmp.proto.rfc1905 import endOfMibView
                    results.append((ObjectName(oid), endOfMibView)); continue
                name, val = binds[0]
                results.append((ObjectName(name), val))
            except Exception:
                from pysnmp.proto.rfc1905 import endOfMibView
                results.append((ObjectName(oid), endOfMibView))
        return results

    #bulk forward
    def readBulkVars(self, nonRepeaters: int, maxRepetitions: int,
                     varBinds: List[Tuple[ObjectName, ObjectSyntax]], acInfo):
        req = [ObjectType(ObjectIdentity(self._to_oid_tuple(oid))) for (oid, _v) in varBinds]
        out = []
        g = bulkCmd(mgrEngine, mgrCommunity, mgrTarget, mgrContext,
                    nonRepeaters, maxRepetitions, *req, lexicographicMode=False)
        try:
            errorInd, errorStat, errorIdx, binds = next(g)
        except StopIteration:
            return out
        if errorInd:  raise RuntimeError(f"backend BULK error: {errorInd}")
        if errorStat: raise RuntimeError(f"backend BULK status: {errorStat.prettyPrint()} at {errorIdx}")
        for (name, val) in binds:
            out.append((ObjectName(name), val))
        return out

#snmp context
snmpContext = context.SnmpContext(snmpEngine)
try: snmpContext.unregisterContextName('')
except Exception: pass
snmpContext.registerContextName('', BackendProxyInstrum())

#responders
cmdrsp.GetCommandResponder(snmpEngine,  snmpContext)
cmdrsp.SetCommandResponder(snmpEngine,  snmpContext)   #set will fail(read-only backend)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)

#key derive(aes128)
def _derive_aes128(key_bytes: bytes) -> bytes:
    return key_bytes if len(key_bytes) == 16 else hashlib.sha256(key_bytes).digest()[:16]

#rotate usm(priv only)
def rotate_usm_keys(user: str, new_priv_key_bytes: bytes):
    try:
        priv_key_128 = _derive_aes128(new_priv_key_bytes)
        config.addV3User(snmpEngine, user, usmHMACSHAAuthProtocol, "authkey1", usmAesCfb128Protocol, priv_key_128)
        logging.info("USM keys rotated for user=%s (auth=SHA, priv=AES-128)", user)
    except Exception as e:
        logging.warning("rotacija usm ključa nije uspjela: %s", e)

#fetch dec key(from slave kms)
def fetch_dec_key_from_slave(slave_base: str, app_id: str, key_id: str, timeout=5):
    url = f"{slave_base}/api/v1/keys/{app_id}/dec_keys"
    payload = {"key_IDs": [{"key_ID": key_id}]}
    try:
        r = requests.post(url, json=payload, timeout=timeout, stream=True,
                          headers={"Accept":"application/json","Accept-Encoding":"identity","Content-Type":"application/json"})
    except Exception as e:
        logging.warning("dec_keys transport error: %s", e); return "error", None

    if r.status_code == 200:
        try:
            r.raw.decode_content = False
            raw_bytes = r.raw.read()
            enc = (r.headers.get("Content-Encoding") or "").lower().strip()
            if "gzip" in enc and raw_bytes[:2] == b"\x1f\x8b":
                raw_bytes = gzip.decompress(raw_bytes)
            body = raw_bytes.decode("utf-8","replace")
            data = json.loads(body)
            items = data.get("keys") or []
            if not items: return "error", None
            b64 = (items[0].get("key") or "").strip()
            return ("ok", base64.b64decode(b64)) if b64 else ("error", None)
        except Exception as e:
            logging.warning("dec_keys parse/decode failed: %s", e); return "error", None

    txt = ""
    try:
        r.raw.decode_content = False
        txt = r.raw.read(512).decode("utf-8","replace")
    except Exception:
        pass
    if r.status_code in (404, 410): return "gone", None
    if r.status_code == 400 and "key not found" in (txt or "").lower(): return "gone", None
    logging.warning("dec_keys unexpected status=%s body=%r", r.status_code, txt[:200])
    return "error", None

#process key id(async)
def process_key_id_async(user: str, key_id: str):
    logging.info("kms notification: user=%s key_ID=%s", user, key_id)
    for _ in range(10):
        status, key_bytes = fetch_dec_key_from_slave(SLAVE_KMS_BASE, SLAVE_APP_ID, key_id, timeout=5)
        logging.info("dec_keys attempt→%s", status)
        if status == "ok" and key_bytes:
            rotate_usm_keys(user, key_bytes); break
        if status == "gone":
            break
        time.sleep(1.0)

#http handler
class QKDHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): return
    def _send_text(self, code: int, text: str):
        self.send_response(code); self.send_header("Content-Type","text/plain; charset=utf-8")
        self.end_headers(); self.wfile.write(text.encode("utf-8"))
    def _send_json(self, code: int, obj: dict):
        self.send_response(code); self.send_header("Content-Type","application/json")
        self.end_headers(); self.wfile.write(json.dumps(obj).encode("utf-8"))

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
                rotate_usm_keys(user, base64.b64decode(b64, validate=True))
                return self._send_text(200, f"OK: rotated keys for {user}")
            except Exception as e:
                logging.info("qkd error: %s", e); return self._send_text(500, "ERROR")

        if path == "/kms":
            user   = data.get("user") or QKD_USER_DEFAULT
            key_id = data.get("key_ID")
            if not key_id: return self._send_text(400, "Missing 'key_ID'")
            threading.Thread(target=process_key_id_async, args=(user, key_id), daemon=True).start()
            return self._send_json(200, {"status":"queued","user":user,"key_ID":key_id})

        return self._send_text(404, "Not found")

#start http
def start_http_server():
    httpd = HTTPServer(("0.0.0.0", HTTP_PORT), QKDHandler)
    logging.info("QKD/KMS endpoint listening on :%d", HTTP_PORT)
    httpd.serve_forever()

#start snmp
def start_snmp_agent():
    def _loop():
        snmpEngine.transportDispatcher.jobStarted(1)
        logging.info("SNMP agent(proxy front) listening on %s:%d", LISTEN_ADDR, SNMP_PORT)
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
        while True: time.sleep(3600)
    except KeyboardInterrupt:
        logging.info("server stopping...")

if __name__ == "__main__":
    main()
