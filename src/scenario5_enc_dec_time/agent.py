#!/usr/bin/env python3
#-- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/agent/cmdrsp/multiple-usm-users.py
"""
snmpv3 agent (multiple usm users) + kms integration (idempotent)
+ micro-benchmark aes-cfb (enc/dec) when key arrives from slave kms.
env:
  AES_KEY_SIZE=128|256
  CRYPTO_REPEATS=100
  CRYPTO_PAYLOAD_LEN=256
  CRYPTO_CSV=...csv   #if unset -> crypto_times_<TS>_server.csv
  SLAVE_KMS_BASE=http://10.250.1.2
  SLAVE_APP_ID=bbbc7de9-5826-11ef-8057-9b39f247bbb
"""

import base64, hashlib, json, logging, os, threading, time, gzip, csv, statistics, secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.hlapi import (
    usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
    usmDESPrivProtocol,
    usmAesCfb128Protocol, usmAesCfb256Protocol,
)
from Crypto.Cipher import AES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)

LISTEN_ADDR = "0.0.0.0"
SNMP_PORT   = 50161
HTTP_PORT   = 8080
QKD_USER_DEFAULT = "usr-sha-aes128"

SLAVE_KMS_BASE = os.getenv("SLAVE_KMS_BASE", "http://10.250.1.2")
SLAVE_APP_ID   = os.getenv("SLAVE_APP_ID",   "bbbc7de9-5826-11ef-8057-9b39f247bbb")

DEC_TIMEOUT_SEC   = 3
DEC_RETRIES       = 6
DEC_RETRY_DELAY_S = 0.7

in_flight = set()
processed_ids = set()

#env params
AES_KEY_SIZE = int(os.getenv("AES_KEY_SIZE", "128"))
CRYPTO_REPEATS = int(os.getenv("CRYPTO_REPEATS", "10"))
CRYPTO_PAYLOAD_LEN = int(os.getenv("CRYPTO_PAYLOAD_LEN", "256"))
if os.getenv("CRYPTO_CSV"):
    CRYPTO_CSV = os.getenv("CRYPTO_CSV")
else:
    CRYPTO_CSV = f"crypto_times_{time.strftime('%Y%m%d_%H%M%S')}_server.csv"

snmpEngine = engine.SnmpEngine()
config.addTransport(snmpEngine, udp.domainName, udp.UdpTransport().openServerMode((LISTEN_ADDR, SNMP_PORT)))

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

def _normalize_key_for_aes(key_bytes: bytes, bits: int) -> bytes:
    if bits == 128:
        return key_bytes if len(key_bytes) == 16 else hashlib.sha256(key_bytes).digest()[:16]
    if bits == 256:
        return key_bytes if len(key_bytes) == 32 else hashlib.sha256(key_bytes).digest()
    raise ValueError("AES_KEY_SIZE must be 128 or 256")

def _pick_priv_protocol_and_key(key_bytes: bytes):
    if AES_KEY_SIZE == 128:
        return usmAesCfb128Protocol, _normalize_key_for_aes(key_bytes, 128)
    if AES_KEY_SIZE == 256:
        return usmAesCfb256Protocol, _normalize_key_for_aes(key_bytes, 256)
    raise ValueError("AES_KEY_SIZE must be 128 or 256")

def rotate_usm_keys(user: str, new_priv_key_bytes: bytes):
    try:
        priv_proto, priv_key = _pick_priv_protocol_and_key(new_priv_key_bytes)
        config.addV3User(snmpEngine, user, usmHMACSHAAuthProtocol, "authkey1", priv_proto, priv_key)
        bits = 8 * len(priv_key)
        logging.info("USM keys rotated for user=%s (auth=SHA, priv=AES-%d)", user, bits)
    except Exception as e:
        logging.warning("Rotacija USM ključa nije uspjela: %s", e)

def append_crypto_csv(path: str, row: dict):
    new = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "ts_iso","run","side","key_size_bits","op","bytes","mean_ms","sd_ms","n","key_id"])
        if new:
            w.writeheader()
        w.writerow(row)

def bench_crypto_aes_cfb(key_bytes: bytes, payload_len: int, repeats: int):
    if len(key_bytes) not in (16, 32):
        raise ValueError("key must be 16/32 bytes")
    pt = secrets.token_bytes(payload_len)
    iv = secrets.token_bytes(16)
    enc, dec = [], []
    for _ in range(repeats):
        t0 = time.perf_counter()
        c = AES.new(key_bytes, AES.MODE_CFB, iv=iv)
        ct = c.encrypt(pt)
        t1 = time.perf_counter()
        enc.append((t1 - t0) * 1000.0)

        t2 = time.perf_counter()
        d = AES.new(key_bytes, AES.MODE_CFB, iv=iv)
        _ = d.decrypt(ct)
        t3 = time.perf_counter()
        dec.append((t3 - t2) * 1000.0)
    em = statistics.mean(enc); esd = statistics.pstdev(enc) if len(enc)>1 else 0.0
    dm = statistics.mean(dec); dsd = statistics.pstdev(dec) if len(dec)>1 else 0.0
    return em, esd, dm, dsd, len(enc)

def fetch_dec_key_from_slave(slave_base: str, app_id: str, key_id: str, timeout=DEC_TIMEOUT_SEC):
    """
    POST /api/v1/keys/{app_id}/dec_keys with {"key_IDs":[{"key_ID":"..."}]}
    expects {"keys":[{"key_ID":"...","key":"<base64>"}]}
    """
    url = f"{slave_base}/api/v1/keys/{app_id}/dec_keys"
    payload = {"key_IDs": [{"key_ID": key_id}]}
    try:
        r = requests.post(url, json=payload, timeout=timeout, stream=True,
                          headers={"Accept":"application/json","Accept-Encoding":"identity","Content-Type":"application/json"})
    except Exception as e:
        logging.warning("dec_keys transport error: %s", e)
        return "error", None

    if r.status_code == 200:
        try:
            r.raw.decode_content = False
        except Exception:
            pass
        try:
            raw_bytes = r.raw.read()
        except Exception as e:
            logging.warning("dec_keys: read body failed: %s", e)
            return "error", None
        enc = (r.headers.get("Content-Encoding") or "").lower().strip()
        if "gzip" in enc and raw_bytes[:2] == b"\x1f\x8b":
            try:
                raw_bytes = gzip.decompress(raw_bytes)
            except Exception:
                pass
        body = raw_bytes.decode("utf-8","replace")
        try:
            data = json.loads(body)
            items = data.get("keys") or []
            if not items:
                return "error", None
            b64 = (items[0].get("key") or "").strip()
            key_bytes = base64.b64decode(b64)
            key_norm = _normalize_key_for_aes(key_bytes, AES_KEY_SIZE)
            return "ok", key_norm
        except Exception as e:
            logging.warning("dec_keys: JSON/base64 error: %s", e)
            return "error", None

    text = ""
    try:
        try: r.raw.decode_content = False
        except Exception: pass
        text = r.raw.read(512).decode("utf-8","replace")
    except Exception: pass

    if r.status_code in (404, 410): return "gone", None
    if r.status_code == 400 and "key not found" in (text or "").lower(): return "gone", None
    logging.warning("dec_keys: unexpected status=%s body=%r", r.status_code, text[:200])
    return "error", None

def process_key_id_async(user: str, key_id: str, run_no: int):
    try:
        for attempt in range(1, DEC_RETRIES + 1):
            status, key_bytes = fetch_dec_key_from_slave(SLAVE_KMS_BASE, SLAVE_APP_ID, key_id)
            logging.info("dec_keys for key_ID=%s \u2192 %s", key_id, status)

            if status == "ok" and key_bytes:
                rotate_usm_keys(user, key_bytes)
                processed_ids.add(key_id)

                #server-side micro-benchmark
                em, esd, dm, dsd, n = bench_crypto_aes_cfb(key_bytes, CRYPTO_PAYLOAD_LEN, CRYPTO_REPEATS)
                ts = time.strftime("%Y-%m-%dT%H:%M:%S")
                bits = 8 * len(key_bytes)
                append_crypto_csv(CRYPTO_CSV, {
                    "ts_iso": ts, "run": run_no, "side": "server",
                    "key_size_bits": bits, "op": "ENC", "bytes": CRYPTO_PAYLOAD_LEN,
                    "mean_ms": f"{em:.6f}", "sd_ms": f"{esd:.6f}", "n": n, "key_id": key_id
                })
                append_crypto_csv(CRYPTO_CSV, {
                    "ts_iso": ts, "run": run_no, "side": "server",
                    "key_size_bits": bits, "op": "DEC", "bytes": CRYPTO_PAYLOAD_LEN,
                    "mean_ms": f"{dm:.6f}", "sd_ms": f"{dsd:.6f}", "n": n, "key_id": key_id
                })
                logging.info("CRYPTO(server,AES-%d) ENC=%.3f ms (sd=%.3f) | DEC=%.3f ms (sd=%.3f)  n=%d, payload=%dB",
                             bits, em, esd, dm, dsd, n, CRYPTO_PAYLOAD_LEN)
                break

            if status == "gone":
                processed_ids.add(key_id)
                break

            time.sleep(DEC_RETRY_DELAY_S)
        else:
            logging.info("Slave KMS nije vratio ključ u roku (user=%s, key_ID=%s)", user, key_id)
    finally:
        in_flight.discard(key_id)

class QKDHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): return

    def _send_text(self, code: int, text: str):
        try:
            self.send_response(code)
            self.send_header("Content-Type","text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(text.encode("utf-8"))
        except Exception: pass

    def _send_json(self, code: int, obj: dict):
        try:
            body = json.dumps(obj)
            self.send_response(code)
            self.send_header("Content-Type","application/json")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
        except Exception: pass

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            raw = self.rfile.read(length).decode("utf-8") if length else "{}"
            data = json.loads(raw or "{}")
        except Exception:
            return self._send_text(400, "Invalid JSON")

        if path == "/kms":
            user   = data.get("user") or QKD_USER_DEFAULT
            key_id = data.get("key_ID")
            run_no = int(data.get("run", 0))

            if not key_id:
                return self._send_text(400, "Missing 'key_ID'")

            if key_id in processed_ids:
                logging.info("Duplikat key_ID=%s (već obrađen) – idempotent 200", key_id)
                return self._send_json(200, {"status":"already-processed","user":user,"key_ID":key_id})
            if key_id in in_flight:
                logging.info("Duplikat key_ID=%s (obrada u toku) – idempotent 200", key_id)
                return self._send_json(200, {"status":"in-flight","user":user,"key_ID":key_id})

            logging.info("KMS notification received: user=%s key_ID=%s (fetching from Slave KMS)", user, key_id)
            in_flight.add(key_id)
            threading.Thread(target=process_key_id_async, args=(user, key_id, run_no), daemon=True).start()
            logging.info("KMS notification queued: user=%s key_ID=%s", user, key_id)
            return self._send_json(200, {"status":"queued","user":user,"key_ID":key_id})

        return self._send_text(404, "Not found")

def start_http_server():
    httpd = HTTPServer(("0.0.0.0", HTTP_PORT), QKDHandler)
    logging.info("KMS endpoint listening on :%d", HTTP_PORT)
    httpd.serve_forever()

def start_snmp_agent():
    def _loop():
        snmpEngine.transportDispatcher.jobStarted(1)
        logging.info("SNMP agent listening on %s:%d", LISTEN_ADDR, SNMP_PORT)
        try:
            snmpEngine.transportDispatcher.runDispatcher()
        except Exception as e:
            logging.error("SNMP dispatcher greška: %s", e)
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
