#!/usr/bin/env python3
# -- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/manager/cmdgen/usm-sha-aes128.py

"""
Scenario 100×1 (one-by-one):
- GET 1 key → measure to headers (get_hdr_ms) and to body (get_total_ms) + resp_bytes
- POST key_ID → RTT + req/resp bytes
- optional: /kms/ready and SNMP
"""

import argparse, base64, csv, hashlib, json, logging, os, time, gzip
from datetime import datetime
import requests, tracemalloc

#psutil-fallback
try:
    import psutil
    def rss_bytes():
        return psutil.Process(os.getpid()).memory_info().rss
    RSS_BACKEND = "psutil"
except Exception:
    import resource
    def rss_bytes():
        try:
            v = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            return int(v) * 1024
        except Exception:
            return 0
    RSS_BACKEND = "resource"

from pysnmp.hlapi import (
    SnmpEngine, UdpTransportTarget, ContextData, UsmUserData,
    ObjectType, ObjectIdentity, getCmd,
    usmHMACSHAAuthProtocol, usmAesCfb128Protocol, usmAesCfb256Protocol
)


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.WARNING)

def _csv_init(path: str, header: list[str]):
    abs_path = os.path.abspath(path)
    need = not os.path.exists(abs_path) or os.path.getsize(abs_path) == 0
    os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
    if need:
        with open(abs_path, "w", newline="") as f:
            csv.writer(f).writerow(header)
    logging.info("phases.csv path: %s", abs_path)

def _csv_row(path: str, values: list):
    abs_path = os.path.abspath(path)
    with open(abs_path, "a", newline="") as f:
        csv.writer(f).writerow(values)

PHASES_CSV = "oneby_phases.csv"
_csv_init(PHASES_CSV, ["run","mode","op","seq","n_keys","get_hdr_ms","get_total_ms","resp_bytes","store_ms"])

def write_csv_op(path: str, run: int, mode: str, key_size: int, op: str, seq: int, key_id: str,
                 ms: float, req_bytes: int = 0, resp_bytes: int = 0, note: str = ""):
    header = ["run", "mode", "key_size", "op", "seq", "key_id", "ms", "req_bytes", "resp_bytes", "note"]
    file_exists = os.path.exists(path)
    if note is None: note = ""
    note = note.replace("\r"," ").replace("\n"," ").strip()
    if len(note) > 600: note = note[:600] + "…"
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header)
        if not file_exists: w.writeheader()
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

#kms-get-one
def get_enc_key_from_kms(master_base: str, app_id: str, size_bits=128, timeout=10):
    """
    GET /api/v1/keys/{app_id}/enc_keys/number/1/size/{size_bits}
    returns:(key_bytes, key_ID, total_ms, resp_payload_bytes, content_length_hdr, note, hdr_ms)
    """
    url = f"{master_base}/api/v1/keys/{app_id}/enc_keys/number/1/size/{size_bits}"
    resp_payload_bytes = 0
    content_length_hdr = -1
    note_parts = [f"url={url}"]

    t0 = time.perf_counter()
    try:
        r = requests.get(
            url, timeout=timeout, stream=True,
            headers={"Accept":"application/json","Accept-Encoding":"identity","User-Agent":"Wget/1.21"}
        )
        hdr_ms = (time.perf_counter() - t0) * 1000.0  #to-headers

        #read-body->total
        r.raw.decode_content = False
        raw_bytes = r.raw.read()
        total_ms = (time.perf_counter() - t0) * 1000.0

        resp_payload_bytes = len(raw_bytes)
        clh = r.headers.get("Content-Length")
        if clh and clh.isdigit(): content_length_hdr = int(clh)

        enc = (r.headers.get("Content-Encoding") or "").lower().strip()
        note_parts += [f"HTTP={r.status_code}", f"enc={enc or 'none'}",
                       f"respB={resp_payload_bytes}", f"CL={content_length_hdr if content_length_hdr!=-1 else 'n/a'}"]

        if r.status_code != 200:
            return None, None, total_ms, resp_payload_bytes, content_length_hdr, "; ".join(note_parts), hdr_ms

        if "gzip" in enc and raw_bytes[:2] == b"\x1f\x8b":
            try:
                raw_bytes = gzip.decompress(raw_bytes)
                note_parts.append("gz=ok")
            except Exception as e:
                note_parts.append(f"gz=fail:{type(e).__name__}")

        raw = raw_bytes.decode("utf-8","replace")

    except Exception as e:
        total_ms = (time.perf_counter() - t0) * 1000.0
        note_parts.append(f"requests_err={type(e).__name__}({e})")
        return None, None, total_ms, resp_payload_bytes, content_length_hdr, "; ".join(note_parts), 0.0
    try:
        data = json.loads(_trim_to_json(raw))
        item = (data.get("keys") or [None])[0]
        if not item:
            note_parts.append("parse=0_items")
            return None, None, total_ms, resp_payload_bytes, content_length_hdr, "; ".join(note_parts), hdr_ms
        key_b64 = (item.get("key") or "").strip()
        key_id  = item.get("key_ID") or item.get("id") or item.get("key_id")
        if not key_b64 or not key_id:
            note_parts.append("parse=missing_fields")
            return None, None, total_ms, resp_payload_bytes, content_length_hdr, "; ".join(note_parts), hdr_ms

        key_bytes = base64.b64decode(key_b64)
        return key_bytes, key_id, total_ms, resp_payload_bytes, content_length_hdr, "; ".join(note_parts), hdr_ms

    except Exception as e:
        note_parts.append(f"json_err={type(e).__name__}")
        return None, None, total_ms, resp_payload_bytes, content_length_hdr, "; ".join(note_parts), hdr_ms

#kms-post
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
        ok = False; resp_body = b""; note = f"requests_err={e!r}"
    ms = (time.perf_counter()-t0)*1000.0
    return ok, ms, len(req_body), len(resp_body), note

#kms-ready-poll
def wait_ready(kms_ready_base: str, key_id: str, timeout_sec: float = 3.0, interval: float = 0.2):
    deadline = time.time() + timeout_sec
    url = f"{kms_ready_base}?key_ID={key_id}"
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=1.0)
            if r.status_code == 200 and (r.json().get("applied") is True):
                return True
        except Exception: pass
        time.sleep(interval)
    return False

#snmp-test
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
    ap.add_argument("--kms-key-bits", type=int, choices=[128, 256], default=128)
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--snmp-retries", type=int, default=5)
    ap.add_argument("--snmp-timeout", type=float, default=1.0)
    ap.add_argument("--sleep-between", type=float, default=0.35)
    ap.add_argument("--outfile", default=f"onebyone_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    args = ap.parse_args()

    mode = "one-by-one"
    logging.info("CSV: %s", args.outfile)

    rss_before = rss_bytes()
    tracemalloc.start()

    backoff_base = 0.25

    for run in range(1, args.count + 1):
        #step1-get-one-key
        key_bytes, key_id, t_kms_ms, resp_b, cl_hdr, note, hdr_ms = get_enc_key_from_kms(
            args.master_kms_base, args.master_app_id, size_bits=args.kms_key_bits
        )

        #record-phases
        store_ms = 0.0
        if key_bytes and key_id:
            t_store0 = time.perf_counter()
            _ = (key_bytes, key_id)  #placeholder-store
            store_ms = (time.perf_counter() - t_store0) * 1000.0
        _csv_row(PHASES_CSV, [run, mode, "GET_ONE", 1, 1,
                              f"{hdr_ms:.3f}", f"{t_kms_ms:.3f}", resp_b, f"{store_ms:.3f}"])

        if not key_bytes or not key_id:
            write_csv_op(args.outfile, run, mode, args.kms_key_bits, "GET", 1, key_id, t_kms_ms,
                         req_bytes=0, resp_bytes=resp_b, note=note)
            logging.error("run #%d: KMS GET fail (%s)", run, note)
            time.sleep(max(args.sleep_between, backoff_base))
            backoff_base = min(2.0, backoff_base * 2)
            continue

        backoff_base = 0.25
        write_csv_op(args.outfile, run, mode, args.kms_key_bits, "GET", 1, key_id, t_kms_ms,
                     req_bytes=0, resp_bytes=resp_b, note=note)

        #step2-post-kms
        ok_post, t_post_ms, req_b, resp_post_b, post_note = post_key_id_to_agent(
            args.kms_url, args.user, key_id, timeout_sec=5
        )
        write_csv_op(args.outfile, run, mode, args.kms_key_bits, "POST", 2, key_id, t_post_ms,
                     req_bytes=req_b, resp_bytes=resp_post_b, note=post_note)
        if not ok_post:
            logging.error("run #%d: POST /kms fail (%s)", run, post_note)
            time.sleep(args.sleep_between)
            continue

        #step3-ready-optional
        if args.wait_ready:
            _ = wait_ready(args.kms_ready_url, key_id, timeout_sec=max(1.0, args.snmp_retries * 0.5), interval=0.2)
        time.sleep(args.sleep_between)

    #mem-stats
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_after = rss_bytes()
    write_csv_op(args.outfile, 0, mode, args.kms_key_bits, "MEM", 0, "RUN_MEM", 0.0,
                 note=f"rss_delta={rss_after - rss_before}; py_peak={peak}; rss_backend={RSS_BACKEND}")

if __name__ == "__main__":
    main()
