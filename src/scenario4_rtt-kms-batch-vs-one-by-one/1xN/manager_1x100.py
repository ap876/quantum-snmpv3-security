#!/usr/bin/env python3
#--coding:utf-8--
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/manager/cmdgen/usm-sha-aes128.py
"""
Scenario 1×N (e.g., 1×100 with a 20-per-call limit):
  - Multiple GET sub-batches (max-per-request); measures RTT (total) and payload for each sub-batch
  - Logs HDR_RTT (time to status+headers) in 'note'
  - Writes overall GET_TOTAL (sum of all sub-batches)
  - For each key: POST /kms → RTT + request/response bytes
  - (optional) /kms/ready and SNMP (left commented out)
"""


#std
import argparse, base64, csv, hashlib, json, logging, os, time, math, gzip
from datetime import datetime
from typing import List, Tuple

#net+mem
import requests, tracemalloc

#rss helpers
try:
    import psutil
    def rss_bytes():
        return psutil.Process(os.getpid()).memory_info().rss
    RSS_BACKEND = "psutil"
except Exception:
    import resource
    def rss_bytes():
        try:
            return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024
        except Exception:
            return 0
    RSS_BACKEND = "resource"

#snmp deps
from pysnmp.hlapi import (
    SnmpEngine, UdpTransportTarget, ContextData, UsmUserData,
    ObjectType, ObjectIdentity, getCmd,
    usmHMACSHAAuthProtocol, usmAesCfb128Protocol, usmAesCfb256Protocol
)


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.WARNING)

def _csv_init(path: str, header: list[str]):
    need = not os.path.exists(path) or os.path.getsize(path) == 0
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if need:
        with open(path, "w", newline="") as f:
            csv.writer(f).writerow(header)

def _csv_row(path: str, values: list):
    with open(path, "a", newline="") as f:
        csv.writer(f).writerow(values)

PHASES_CSV = "client_phases.csv"
_csv_init(PHASES_CSV, ["run","mode","op","seq","n_keys","get_hdr_ms","get_total_ms","resp_bytes","store_ms"])

def write_csv_op(path: str, run: int, mode: str, key_size: int, op: str, seq: int, key_id: str,
                 ms: float, req_bytes: int = 0, resp_bytes: int = 0, note: str = ""):
    header = ["run", "mode", "key_size", "op", "seq", "key_id", "ms", "req_bytes", "resp_bytes", "note"]
    file_exists = os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header)
        if not file_exists:
            w.writeheader()
        w.writerow({
            "run": run, "mode": mode, "key_size": key_size, "op": op, "seq": seq, "key_id": key_id or "",
            "ms": f"{ms:.3f}", "req_bytes": req_bytes, "resp_bytes": resp_bytes, "note": note
        })

#helpers
def _derive_key(priv_key_bytes: bytes, bits: int) -> bytes:
    want = 16 if bits == 128 else 32
    return hashlib.sha256(priv_key_bytes).digest()[:want] if len(priv_key_bytes) != want else priv_key_bytes

def _trim_to_json(raw: str) -> str:
    i = raw.find("{")
    return raw[i:] if i >= 0 else raw

#kms batch get
def get_enc_keys_batch(master_base: str, app_id: str, n_keys=20, size_bits=256, timeout=15) -> Tuple[List[bytes], List[str], float, int, str, float]:
    url = f"{master_base}/api/v1/keys/{app_id}/enc_keys/number/{n_keys}/size/{size_bits}"
    note_parts = [f"url={url}"]
    resp_payload_bytes = 0
    hdr_ms = 0.0

    t0 = time.perf_counter()
    try:
        r = requests.get(
            url, timeout=timeout, stream=True,
            headers={"Accept":"application/json","Accept-Encoding":"identity","User-Agent":"Wget/1.21"}
        )
        hdr_ms = (time.perf_counter() - t0) * 1000.0
        note_parts.append(f"HTTP={r.status_code}")

        #read body to measure total rtt
        r.raw.decode_content = False
        raw_bytes = r.raw.read()
        t_total = (time.perf_counter() - t0) * 1000.0

        resp_payload_bytes = len(raw_bytes)
        enc = (r.headers.get("Content-Encoding") or "").lower().strip()
        note_parts += [f"enc={enc or 'none'}", f"HDR_RTT={hdr_ms:.3f}ms", f"respB={resp_payload_bytes}"]

        if r.status_code != 200:
            return [], [], t_total, resp_payload_bytes, "; ".join(note_parts), hdr_ms

        if "gzip" in enc and raw_bytes[:2] == b"\x1f\x8b":
            try:
                raw_bytes = gzip.decompress(raw_bytes)
                note_parts.append("gz=ok")
            except Exception as e:
                note_parts.append(f"gz=fail:{type(e).__name__}")

        raw = raw_bytes.decode("utf-8", "replace")
        data = json.loads(_trim_to_json(raw))
        items = data.get("keys") or []

        key_bytes_list: List[bytes] = []
        key_ids: List[str] = []
        for it in items:
            b64 = (it.get("key") or "").strip()
            kid = it.get("key_ID") or it.get("id") or it.get("key_id")
            if not b64 or not kid:
                continue
            try:
                key_bytes_list.append(base64.b64decode(b64))
                key_ids.append(kid)
            except Exception:
                continue

        if not key_ids:
            note_parts.append("parse=0_items")

        return key_bytes_list, key_ids, t_total, resp_payload_bytes, "; ".join(note_parts), hdr_ms

    except Exception as e:
        t_total = (time.perf_counter() - t0) * 1000.0
        note_parts.append(f"requests_err={type(e).__name__}({e})")
        return [], [], t_total, resp_payload_bytes, "; ".join(note_parts), hdr_ms

#agent post
def post_key_id_to_agent(url: str, user: str, key_id: str, timeout_sec: int = 5):
    payload = {"user": user, "key_ID": key_id}
    req_body = json.dumps(payload).encode("utf-8")
    t0 = time.perf_counter()
    note = ""
    try:
        r = requests.post(url, json=payload, timeout=timeout_sec,
                          headers={"Content-Type":"application/json","Accept":"application/json"})
        ok = (r.status_code == 200)
        resp_body = r.content or b""
        if not ok:
            note = f"HTTP={r.status_code}; body_prefix={(resp_body[:120].decode('utf-8','replace'))!r}"
    except Exception as e:
        ok = False
        resp_body = b""
        note = f"requests_err={e!r}"
    ms = (time.perf_counter()-t0)*1000.0
    return ok, ms, len(req_body), len(resp_body), note

#agent ready poll
def wait_ready(kms_ready_base: str, key_id: str, timeout_sec: float = 3.0, interval: float = 0.2) -> bool:
    deadline = time.time() + timeout_sec
    url = f"{kms_ready_base}?key_ID={key_id}"
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=1.0)
            if r.status_code == 200 and (r.json().get("applied") is True):
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False

#snmp single get
def snmp_get_once(agent_host: str, agent_port: int, user: str, auth_pass: str,
                  priv_key_bytes: bytes, key_bits: int, oid_str: str, timeout_sec: float = 2.0):
    t0 = time.perf_counter()
    priv_proto = usmAesCfb256Protocol if key_bits == 256 else usmAesCfb128Protocol
    usm = UsmUserData(userName=user, authKey=auth_pass,
                      privKey=_derive_key(priv_key_bytes, key_bits),
                      authProtocol=usmHMACSHAAuthProtocol, privProtocol=priv_proto)
    target = UdpTransportTarget((agent_host, agent_port), timeout=timeout_sec, retries=0)
    try:
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(), usm, target, ContextData(), ObjectType(ObjectIdentity(oid_str))))
        ok = (errorIndication is None) and (not errorStatus)
    except Exception:
        ok = False
    return ok, (time.perf_counter() - t0) * 1000.0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-host", default="127.0.0.1")
    ap.add_argument("--agent-port", type=int, default=50161)
    ap.add_argument("--kms-url", default="http://127.0.0.1:8080/kms")
    ap.add_argument("--kms-ready-url", default="http://127.0.0.1:8080/kms/ready")
    ap.add_argument("--wait-ready", action="store_true")
    ap.add_argument("--master-kms-base", default="http://10.250.0.2")
    ap.add_argument("--master-app-id", default="aaac7de9-5826-11ef-8057-9b39f247aaa")
    ap.add_argument("--user", default="usr-sha-aes128")
    ap.add_argument("--auth-pass", default="authkey1")
    ap.add_argument("--oid", default="1.3.6.1.2.1.1.1.0")
    ap.add_argument("--kms-key-bits", type=int, choices=[128, 256], default=256)

    #1×N params
    ap.add_argument("--want-keys", type=int, default=100)
    ap.add_argument("--max-per-request", type=int, default=20)

    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--snmp-retries", type=int, default=5)
    ap.add_argument("--snmp-timeout", type=float, default=1.0)
    ap.add_argument("--sleep-between", type=float, default=0.25)
    ap.add_argument("--outfile", default=f"batch1xN_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    args = ap.parse_args()

    mode = f"batch-1x{args.want_keys}-by-{args.max_per_request}"
    logging.info("CSV: %s", args.outfile)

    rss_before = rss_bytes()
    tracemalloc.start()

    for run in range(1, args.count + 1):
        total_get_ms = 0.0
        key_bytes_all: List[bytes] = []
        key_ids_all: List[str] = []

        remaining = max(0, args.want_keys)
        num_calls = math.ceil(remaining / max(1, args.max_per_request))

        #1.sub-batch gets
        for call_idx in range(1, num_calls + 1):
            n = min(args.max_per_request, remaining)
            if n <= 0:
                break

            kbl, kids, t_ms, respB, note, hdr_ms = get_enc_keys_batch(
                args.master_kms_base, args.master_app_id, n_keys=n, size_bits=args.kms_key_bits
            )
            total_get_ms += t_ms

            #csv original(get rtt+payload)
            write_csv_op(args.outfile, run, mode, args.kms_key_bits, "GET", call_idx,
                         f"BATCH_CALL_{call_idx}_N{n}", t_ms, req_bytes=0, resp_bytes=respB, note=note)

            t_store0 = time.perf_counter()
            if kids:
                key_bytes_all.extend(kbl)
                key_ids_all.extend(kids)
            store_ms = (time.perf_counter() - t_store0) * 1000.0

            _csv_row(PHASES_CSV, [run, mode, "GET_SUBBATCH", call_idx, n,
                                  f"{hdr_ms:.3f}", f"{t_ms:.3f}", respB, f"{store_ms:.3f}"])

            if not kids:
                logging.warning("run #%d: BATCH_CALL_%d (N=%d) vratio 0 ključeva", run, call_idx, n)

            remaining -= n
            time.sleep(args.sleep_between)

        #2.get total sum
        write_csv_op(args.outfile, run, mode, args.kms_key_bits, "GET_TOTAL", 0,
                     f"BATCH_TOTAL_{len(key_ids_all)}", total_get_ms, req_bytes=0, resp_bytes=0)

        if len(key_ids_all) == 0:
            logging.error("run #%d: nijedan ključ nije vraćen u batchu", run)
            continue

        logging.info("run #%d: batch GET ukupno %d ključeva (%.1f ms)", run, len(key_ids_all), total_get_ms)

        #3.post each key
        for idx, kid in enumerate(key_ids_all, start=1):
            ok_post, t_post_ms, req_b, resp_post_b, post_note = post_key_id_to_agent(
                args.kms_url, args.user, kid, timeout_sec=5
            )
            write_csv_op(args.outfile, run, mode, args.kms_key_bits, "POST", idx, kid,
                         t_post_ms, req_bytes=req_b, resp_bytes=resp_post_b, note=post_note)
            if not ok_post:
                logging.error("run #%d key#%d: POST fail (key_ID=%s) %s", run, idx, kid, post_note)
            time.sleep(0.05)

        #4.snmp per key
        #for idx, (kbytes, kid) in enumerate(zip(key_bytes_all, key_ids_all), start=1):
        #    if args.wait_ready:
        #        _ = wait_ready(args.kms_ready_url, kid, timeout_sec=max(1.0, args.snmp_retries*0.5), interval=0.15)
        #    ok, t_snmp_ms = snmp_get_once(args.agent_host, args.agent_port, args.user, args.auth_pass,
        #                                  kbytes, args.kms_key_bits, args.oid, timeout_sec=args.snmp_timeout)
        #    write_csv_op(args.outfile, run, mode, args.kms_key_bits, "SNMP", idx, kid, t_snmp_ms)

        time.sleep(args.sleep_between)

    #mem stats
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_after = rss_bytes()
    write_csv_op(args.outfile, 0, mode, args.kms_key_bits, "MEM", 0, "RUN_MEM", 0.0,
                 note=f"rss_delta={rss_after - rss_before}; py_peak={peak}; rss_backend={RSS_BACKEND}")

if __name__ == "__main__":
    main()
