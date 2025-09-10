#!/usr/bin/env python3
# -- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/manager/cmdgen/usm-sha-aes128.py
"""
snmpv3 client (authPriv: SHA + AES-128/256) with kms integration
+ micro-benchmark aes-cfb (enc/dec) for the fetched key.

env:
  AES_KEY_SIZE=128|256          # default 128
  CRYPTO_REPEATS=100            # number of enc/dec repeats per key
  CRYPTO_PAYLOAD_LEN=256        # test message length in bytes
  CRYPTO_CSV=...csv             # output csv; if unset -> crypto_times_<TS>_client.csv
"""


import base64, hashlib, json, logging, time, subprocess, requests, os, csv, statistics, secrets
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.hlapi import usmHMACSHAAuthProtocol, usmAesCfb128Protocol, usmAesCfb256Protocol
from Crypto.Cipher import AES


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.WARNING)

AGENT_HOST = "127.0.0.1"
AGENT_PORT = 50161
HTTP_PORT  = 8080
USERNAME   = "usr-sha-aes128"
AUTH_PASS  = "authkey1"
OID_STR    = "1.3.6.1.2.1.1.1.0"  #sysDescr.0

#kms endpoints
MASTER_KMS_BASE = "http://10.250.0.2"
MASTER_APP_ID   = "aaac7de9-5826-11ef-8057-9b39f247aaa"
KMS_URL_TO_AGENT = f"http://{AGENT_HOST}:{HTTP_PORT}/kms"

#env params
AES_KEY_SIZE = int(os.getenv("AES_KEY_SIZE", "128"))
CRYPTO_REPEATS = int(os.getenv("CRYPTO_REPEATS", "10"))
CRYPTO_PAYLOAD_LEN = int(os.getenv("CRYPTO_PAYLOAD_LEN", "256"))
if os.getenv("CRYPTO_CSV"):
    CRYPTO_CSV = os.getenv("CRYPTO_CSV")
else:
    CRYPTO_CSV = f"crypto_times_{time.strftime('%Y%m%d_%H%M%S')}_client.csv"

#helpers
def _trim_to_json(raw: str) -> str:
    i = raw.find("{")
    return raw[i:] if i >= 0 else raw

#key-normalize
def _normalize_key_for_aes(key_bytes: bytes, bits: int) -> bytes:
    """return exactly 16B(128) or 32B(256) deterministically"""
    if bits == 128:
        return key_bytes if len(key_bytes) == 16 else hashlib.sha256(key_bytes).digest()[:16]
    if bits == 256:
        return key_bytes if len(key_bytes) == 32 else hashlib.sha256(key_bytes).digest()
    raise ValueError("AES_KEY_SIZE must be 128 or 256")

#snmp-priv-select
def _pick_priv_protocol_and_key(key_bytes: bytes):
    if AES_KEY_SIZE == 128:
        return usmAesCfb128Protocol, _normalize_key_for_aes(key_bytes, 128)
    if AES_KEY_SIZE == 256:
        return usmAesCfb256Protocol, _normalize_key_for_aes(key_bytes, 256)
    raise ValueError("AES_KEY_SIZE must be 128 or 256")

#kms-get
def get_enc_key_from_kms(master_base: str, app_id: str, n_keys=1, size_bits=128):
    """
    return (key_norm, key_b64, key_ID) or (None, None, None)
    """
    url = f"{master_base}/api/v1/keys/{app_id}/enc_keys/number/{n_keys}/size/{size_bits}"
    logging.info("STEP 1 – GET from master kms: %s", url)
    raw = None
    try:
        r = requests.get(url, timeout=10,headers={"Accept":"application/json","Accept-Encoding":"identity","User-Agent":"Wget/1.21"})
        if r.status_code == 200:
            raw = r.text
        elif r.status_code == 400:
            return None, None, None
    except Exception:
        raw = None
    if raw is None:
        try:
            raw = subprocess.check_output(["curl","--fail","--silent","--show-error","-H","Accept: application/json",url],stderr=subprocess.STDOUT, timeout=10).decode("utf-8","replace")
        except Exception:
            return None, None, None
    try:
        data = json.loads(_trim_to_json(raw))
        item = data["keys"][0]
        key_b64 = item["key"].strip()
        key_id  = item.get("key_ID") or item.get("id") or item.get("key_id")
        key_bytes = base64.b64decode(key_b64)
        key_norm = _normalize_key_for_aes(key_bytes, AES_KEY_SIZE)
        logging.info("STEP 1 done: enc_key len=%dB(from kms), key_ID=%s", len(key_bytes), key_id)
        return key_norm, key_b64, key_id
    except Exception:
        return None, None, None

#notify-agent
def post_key_id_to_agent(url: str, user: str, key_id: str, run_no: int, key_b64: str, timeout_sec: int = 5) -> bool:
    payload = {"user": user, "key_ID": key_id, "run": run_no, "key": key_b64}  #include key(lab inline)
    logging.info("STEP 2 – POST to /kms, payload=%s", payload)
    try:
        resp = requests.post(url, json=payload, timeout=timeout_sec,
                             headers={"Content-Type":"application/json","Accept":"application/json"})
        if resp.status_code == 200:
            logging.info("STEP 2 done: /kms accepted")
            return True
        logging.warning("STEP 2 failed: status=%s body=%s", resp.status_code, resp.text.strip())
        return False
    except Exception as e:
        logging.warning("STEP 2 exception: %s", e)
        return False

#snmp-get
def run_snmp_get(agent_host: str, agent_port: int, user: str, auth_pass: str, priv_key_bytes: bytes, oid_str: str):
    logging.info("STEP 4 – SNMP GET %s (AES-%d)", oid_str, AES_KEY_SIZE)
    snmpEngine = engine.SnmpEngine()
    config.addTransport(snmpEngine, udp.domainName, udp.UdpTransport().openClientMode())
    priv_proto, priv_key = _pick_priv_protocol_and_key(priv_key_bytes)
    config.addV3User(snmpEngine, user, usmHMACSHAAuthProtocol, auth_pass, priv_proto, priv_key)
    config.addTargetParams(snmpEngine, 'my-creds', user, 'authPriv')
    config.addTargetAddr(snmpEngine, 'target', udp.domainName, (agent_host, agent_port), 'my-creds')

    def cbFun(snmpEngine, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
        if errorIndication:
            logging.error("snmp error: %s", errorIndication)
        elif errorStatus:
            logging.error("snmp error: %s at %s",
                          errorStatus.prettyPrint(),
                          errorIndex and varBinds[int(errorIndex)-1][0] or '?')
        else:
            for oid, val in varBinds:
                logging.info("snmp get ok: %s = %s", oid.prettyPrint(), val.prettyPrint())

    oid_tuple = tuple(int(x) for x in oid_str.split('.'))
    cmdgen.GetCommandGenerator().sendVarBinds(snmpEngine, 'target', None, '', [((oid_tuple), None)], cbFun)
    snmpEngine.transportDispatcher.runDispatcher()

def bench_crypto_aes_cfb(key_bytes: bytes, payload_len: int, repeats: int):
    """
    measure raw aes-cfb encrypt()/decrypt() with 16/32B key
    return:(enc_mean_ms, enc_sd_ms, dec_mean_ms, dec_sd_ms, n)
    """
    if len(key_bytes) not in (16, 32):
        raise ValueError("key must be 16(aes-128) or 32(aes-256) bytes")
    pt = secrets.token_bytes(payload_len)
    iv = secrets.token_bytes(16)

    enc_times, dec_times = [], []
    for _ in range(repeats):
        t0 = time.perf_counter()
        c = AES.new(key_bytes, AES.MODE_CFB, iv=iv)
        ct = c.encrypt(pt)
        t1 = time.perf_counter()
        enc_times.append((t1 - t0) * 1000.0)

        t2 = time.perf_counter()
        d = AES.new(key_bytes, AES.MODE_CFB, iv=iv)
        _ = d.decrypt(ct)
        t3 = time.perf_counter()
        dec_times.append((t3 - t2) * 1000.0)

    def stats(xs):
        m = statistics.mean(xs)
        sd = statistics.pstdev(xs) if len(xs) > 1 else 0.0
        return m, sd

    em, esd = stats(enc_times)
    dm, dsd = stats(dec_times)
    return em, esd, dm, dsd, repeats

def append_crypto_csv(path: str, row: dict):
    new_file = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "ts_iso","run","side","key_size_bits","op","bytes","mean_ms","sd_ms","n","key_id"
        ])
        if new_file:
            w.writeheader()
        w.writerow(row)

def main():
    last_key_id = None
    used_ids = set()
    run_counter = 0
    kms_request_bits = AES_KEY_SIZE

    while True:
        #kms-get
        key_bytes, key_b64, key_id = get_enc_key_from_kms(MASTER_KMS_BASE, MASTER_APP_ID, size_bits=kms_request_bits)
        if not key_id:
            logging.info("KMS još nema dovoljno materijala, čekam 5s…")
            time.sleep(5)
            continue

        #dedup
        if key_id == last_key_id or key_id in used_ids:
            logging.info("nema novog key_ID (posljednji=%s). već viđen=%s, čekam 5s…",
                         last_key_id, key_id in used_ids)
            time.sleep(5)
            continue

        #notify
        run_counter += 1
        ok_kms = post_key_id_to_agent(KMS_URL_TO_AGENT, USERNAME, key_id, run_counter, key_b64, timeout_sec=5)
        if not ok_kms:
            logging.error("agent nije prihvatio /kms. ponavljam za 5s.")
            time.sleep(5)
            continue

        used_ids.add(key_id)
        last_key_id = key_id

        enc_mean, enc_sd, dec_mean, dec_sd, n = bench_crypto_aes_cfb(
            key_bytes, payload_len=CRYPTO_PAYLOAD_LEN, repeats=CRYPTO_REPEATS
        )
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        bits = 8 * len(key_bytes)
        append_crypto_csv(CRYPTO_CSV, {
            "ts_iso": ts, "run": run_counter, "side": "client",
            "key_size_bits": bits, "op": "ENC", "bytes": CRYPTO_PAYLOAD_LEN,
            "mean_ms": f"{enc_mean:.6f}", "sd_ms": f"{enc_sd:.6f}", "n": n, "key_id": key_id
        })
        append_crypto_csv(CRYPTO_CSV, {
            "ts_iso": ts, "run": run_counter, "side": "client",
            "key_size_bits": bits, "op": "DEC", "bytes": CRYPTO_PAYLOAD_LEN,
            "mean_ms": f"{dec_mean:.6f}", "sd_ms": f"{dec_sd:.6f}", "n": n, "key_id": key_id
        })
        logging.info("CRYPTO(client,AES-%d) ENC=%.3f ms (sd=%.3f) | DEC=%.3f ms (sd=%.3f)  n=%d, payload=%dB",
                     bits, enc_mean, enc_sd, dec_mean, dec_sd, n, CRYPTO_PAYLOAD_LEN)
        try:
            run_snmp_get(AGENT_HOST, AGENT_PORT, USERNAME, AUTH_PASS, key_bytes, OID_STR)
        except Exception as e:
            logging.warning("SNMP GET nije uspio: %s", e)

        time.sleep(1.0)

if __name__ == "__main__":
    main()
