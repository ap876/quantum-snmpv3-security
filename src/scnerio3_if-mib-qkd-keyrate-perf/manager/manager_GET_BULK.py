# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/manager/cmdgen/usm-sha-aes128.py
#!/usr/bin/env python3
#-- coding: utf-8 --
"""
snmpv3 GET-BULK client (authPriv: SHA + AES-128) with KMS rotation and three spend policies:
  --kms-per-message:
      0 = one key for the ENTIRE walk
      1 = one key per CHUNK of columns (default)
      2 = one key for EVERY GET-BULK PDU

discovery(v2c): ifTable/ifXTable columns only(no scalars)
transfer: multi-round GET-BULK per chunk(cols-per-pdu columns, rows-per-pdu rows/PDU)
report: #encrypted PDU, #keys, QKD bits, optional CSV
"""

import argparse, base64, hashlib, json, logging, time, subprocess, csv
from collections import deque
from typing import List, Dict, Tuple

import requests

#v2c discovery(local net-snmpd)
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, nextCmd
)

#v3 GET-BULK toward proxy/agent
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.hlapi import usmHMACSHAAuthProtocol, usmAesCfb128Protocol

#qkd usage logger
try:
    from snmp_qkd_logger import init_logger, set_key, log_tx, log_note
except Exception:
    def init_logger(*a, **k): pass
    def set_key(*a, **k): pass
    def log_tx(*a, **k): pass
    def log_note(*a, **k): pass

#if-mib:columns only(ifEntry/ifXEntry)
IFMIB_ROOTS = [
    "1.3.6.1.2.1.2.2.1",       # ifTable columns (ifEntry)
    "1.3.6.1.2.1.31.1.1.1"     # ifXTable columns (ifXEntry)
]

END_OF_MIB_TEXT = "No more variables left in this MIB View"

def _derive_aes128(key_bytes: bytes) -> bytes:
    return key_bytes if len(key_bytes) == 16 else hashlib.sha256(key_bytes).digest()[:16]

def _trim_to_json(raw: str) -> str:
    i = raw.find("{"); return raw[i:] if i >= 0 else raw

def _pp_oid(name) -> str:
    try: return name.prettyPrint()
    except Exception: return str(name)

def _pp_val(val) -> str:
    try: return val.prettyPrint()
    except Exception:
        if isinstance(val, bytes):
            try: return val.decode("utf-8","replace")
            except Exception: return val.hex()
        return str(val)

def get_enc_key_from_kms(master_base: str, app_id: str, n_keys=1, size_bits=128, timeout=10):
    url = f"{master_base}/api/v1/keys/{app_id}/enc_keys/number/{n_keys}/size/{size_bits}"
    logging.debug("KMS GET: %s", url)
    raw = None
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"Accept":"application/json","Accept-Encoding":"identity","User-Agent":"KMS-BULK-Client/1.0"})
        if r.status_code == 200: raw = r.text
    except Exception:
        raw = None

    if raw is None:
        try:
            raw = subprocess.check_output(
                ["curl","--fail","--silent","--show-error","-H","Accept: application/json", url],
                stderr=subprocess.STDOUT, timeout=timeout).decode("utf-8","replace")
        except Exception:
            return None, None, None

    try:
        data = json.loads(_trim_to_json(raw)); item = data["keys"][0]
        key_b64 = (item.get("key") or "").strip()
        key_id  = item.get("key_ID") or item.get("id") or item.get("key_id")
        if not key_b64 or not key_id: return None, None, None
        key_bytes = base64.b64decode(key_b64)
        if len(key_bytes) not in (16,24,32): return None, None, None
        return key_bytes, key_b64, key_id
    except Exception:
        return None, None, None

def post_key_id_to_agent(url: str, user: str, key_id: str, timeout_sec: int = 8) -> bool:
    try:
        resp = requests.post(url, json={"user": user, "key_ID": key_id}, timeout=timeout_sec,
                             headers={"Content-Type":"application/json","Accept":"application/json"})
        return resp.status_code == 200
    except Exception:
        return False

def _mk_snmp_engine_for_key(user: str, auth_pass: str, priv_key_bytes: bytes, agent_host: str, agent_port: int):
    snmpEngineV3 = engine.SnmpEngine()
    config.addTransport(snmpEngineV3, udp.domainName, udp.UdpTransport().openClientMode())
    config.addV3User(snmpEngineV3, user, usmHMACSHAAuthProtocol, auth_pass,
                     usmAesCfb128Protocol, _derive_aes128(priv_key_bytes))
    config.addTargetParams(snmpEngineV3, 'my-creds', user, 'authPriv')
    config.addTargetAddr(snmpEngineV3, 'target', udp.domainName, (agent_host, agent_port), 'my-creds')
    return snmpEngineV3

def chunk(lst: List[str], n: int) -> List[List[str]]:
    return [lst[i:i+n] for i in range(0, len(lst), n)]

def to_column_oids(instance_oids: List[str]) -> List[str]:
  cols = set()
    for s in instance_oids:
        s = s.strip('.')
        if not s: continue
        parts = s.split('.')
        if parts[-1] == '0':
            continue
        cols.add('.'.join(parts[:-1]))
    return sorted(cols, key=lambda t: tuple(map(int, t.split('.'))))

#discovery(v2c)
def discover_if_mib_oids(backend_host: str, backend_port: int, community: str, timeout: float, retries: int) -> List[str]:
    """walk IF-MIB columns(ifTable/ifXTable); return list of *instance* leaf OIDs"""
    oids: List[str] = []
    mgrEngine = SnmpEngine()
    community = CommunityData(community, mpModel=1)   # v2c
    target    = UdpTransportTarget((backend_host, backend_port), timeout=timeout, retries=retries)
    ctx       = ContextData()

    for root in IFMIB_ROOTS:
        root_dot = str(root).rstrip('.')
        for (errInd, errStat, errIdx, binds) in nextCmd(
                mgrEngine, community, target, ctx,
                ObjectType(ObjectIdentity(root_dot)),
                lexicographicMode=True):
            if errInd:
                logging.warning("NEXT error @%s: %s", root_dot, errInd); break
            if errStat:
                logging.warning("NEXT status @%s: %s", root_dot, errStat.prettyPrint()); break
            if not binds:
                break
            vb0 = binds[0]
            try:
                name, val = vb0
            except Exception:
                logging.warning("NEXT varBind shape @%s: %r", root_dot, vb0); break

            name_str = str(name)
            if not name_str.startswith(root_dot + ".") and name_str != root_dot:
                break
            if _pp_val(val) == END_OF_MIB_TEXT:
                continue
            oids.append(name_str)

    oids = [s for s in oids if not s.strip().endswith(".0")]
    oids = sorted(set(oids), key=lambda s: tuple(map(int, s.strip('.').split('.'))))
    logging.info("DISCOVERY: leaf OIDs in IF-MIB=%d", len(oids))
    return oids

#bulk round(multi PDU until rows exhausted)
def _flatten_varbinds(varBinds) -> List[Tuple[str, str]]:
    flat: List[Tuple[str, str]] = []
    def acc(n, v):
        v_pp = _pp_val(v)
        if v_pp == END_OF_MIB_TEXT: return
        flat.append((_pp_oid(n), v_pp))
    for row in varBinds:
        if isinstance(row, (list, tuple)) and row and isinstance(row[0], (list, tuple)):
            for pair in row:
                if len(pair) >= 2: acc(pair[0], pair[1])
        elif isinstance(row, (list, tuple)) and len(row) >= 2:
            acc(row[0], row[1])
    return flat

def bulk_once(user: str, auth_pass: str, priv_key_bytes: bytes,
              agent_host: str, agent_port: int,
              start_oids: List[str], nonRepeaters: int, maxRepetitions: int) -> List[Tuple[str, str]]:
    try:
        sample = ",".join(start_oids[:4]) + ("..." if len(start_oids)>4 else "")
        log_tx("GET-BULK", extra=f"nR={nonRepeaters} maxRep={maxRepetitions} oids={sample}")
    except Exception:
        pass

    vb = [((tuple(int(x) for x in oid.split("."))), None) for oid in start_oids]
    snmpEngineV3 = _mk_snmp_engine_for_key(user, auth_pass, priv_key_bytes, agent_host, agent_port)

    out_flat: List[Tuple[str, str]] = []
    def cbFun(snmpEngineV3, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
        nonlocal out_flat
        if errorIndication or errorStatus:
            return
        out_flat = _flatten_varbinds(varBinds)

    cmdgen.BulkCommandGenerator().sendVarBinds(
        snmpEngineV3, 'target', None, '',
        nonRepeaters, maxRepetitions, vb, cbFun
    )
    snmpEngineV3.transportDispatcher.runDispatcher()
    return out_flat

def advance_columns(cols: List[str], resp_pairs: List[Tuple[str, str]]) -> Tuple[List[str], int]:
    """from response decide new start OIDs (last valid in each subtree) and how many finished"""
    if not resp_pairs:
        return [], len(cols)
    ncols = len(cols)
    per_col: List[List[str]] = [[] for _ in range(ncols)]
    for idx, (oid_str, _val) in enumerate(resp_pairs):
        per_col[idx % ncols].append(oid_str)

    new_starts: List[str] = []
    finished = 0
    for c, col_root in enumerate(cols):
        seq = [s for s in per_col[c] if s.startswith(col_root + ".")]
        if not seq:
            finished += 1
            continue
        new_starts.append(seq[-1])
    return new_starts, finished

def main():
    ap = argparse.ArgumentParser(description="SNMPv3 GET-BULK client(multi-round IF-MIB) with KMS rotation policies")
    ap.add_argument("--agent-host", default="127.0.0.1")
    ap.add_argument("--agent-port", type=int, default=50161)
    ap.add_argument("--qkd-port",   type=int, default=8080)
    ap.add_argument("--user", default="usr-sha-aes128")
    ap.add_argument("--auth-pass", default="authkey1")

    ap.add_argument("--backend-host", default="127.0.0.1")
    ap.add_argument("--backend-port", type=int, default=161)
    ap.add_argument("--backend-comm", default="public")
    ap.add_argument("--backend-timeout", type=float, default=1.0)
    ap.add_argument("--backend-retries", type=int, default=1)

    ap.add_argument("--master-kms-base", default="http://10.250.0.2")
    ap.add_argument("--master-app-id", default="aaac7de9-5826-11ef-8057-9b39f247aaa")
    ap.add_argument("--kms-key-bits", type=int, choices=[128,256], default=128,
                    help="key size requested from KMS(bits)")
    ap.add_argument("--kms-per-message", type=int, choices=[0,1,2], default=1,
                    help="0=per-walk, 1=per-chunk, 2=per-PDU")

    ap.add_argument("--cols-per-pdu", type=int, default=4, help="columns per PDU")
    ap.add_argument("--rows-per-pdu", type=int, default=10, help="maxRepetitions(rows per column per PDU)")
    ap.add_argument("--non-repeaters", type=int, default=0)
    ap.add_argument("--max-rounds", type=int, default=200, help="safety cap rounds per chunk")

    ap.add_argument("--per-message-sleep-apply", type=float, default=0.7, help="sleep after /kms before send(s)")
    ap.add_argument("--pause-between-batches", type=float, default=0.3, help="sleep between chunks(s)")

    ap.add_argument("--stats-csv", default="ifmib_getbulk_stats.csv")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    logging.getLogger("requests").setLevel(logging.WARNING)

    run_id   = time.strftime("%Y%m%d_%H%M%S")
    log_path = f"qkd_usage_{run_id}.log"
    init_logger(log_path)
    print(f"[LOGGER] writing to: {log_path}")
    log_note("client GET-BULK(multiround IF-MIB) start")

    #discovery(instance OIDs)
    instance_oids = discover_if_mib_oids(args.backend_host, args.backend_port,
                                         args.backend_comm, args.backend_timeout, args.backend_retries)
    if not instance_oids:
        logging.error("discovery returned no OIDs. exit.")
        log_note("client stop: discovery empty"); return

    #instances -> columns
    all_cols = to_column_oids(instance_oids)
    logging.info("columns at start=%d", len(all_cols))

    batches = chunk(all_cols, args.cols_per_pdu)
    logging.info("chunks=%d(cols-per-pdu=%d)", len(batches), args.cols_per_pdu)

    sent_pdu_total = 0
    keys_used = 0
    qkd_bits_consumed = 0

    recent_ids = deque(maxlen=2000); recent_set = set()
    kms_url_to_agent = f"http://{args.agent_host}:{args.qkd_port}/kms"

    def kms_rotate(bits: int) -> Tuple[bytes, str]:
        nonlocal keys_used, qkd_bits_consumed, recent_ids, recent_set
        key_bytes, _b64, key_id = get_enc_key_from_kms(args.master_kms_base, args.master_app_id, size_bits=bits)
        if not key_id:
            logging.info("KMS has no key, sleeping 2s…"); time.sleep(2); return None, None
        if key_id in recent_set:
            logging.info("duplicate key_ID=%s, sleeping 1s…", key_id); time.sleep(1); return None, None
        try: set_key(key_id, bits)
        except Exception: pass
        if not post_key_id_to_agent(kms_url_to_agent, args.user, key_id):
            logging.warning("agent rejected /kms"); return None, None
        time.sleep(args.per_message_sleep_apply)
        keys_used += 1
        qkd_bits_consumed += bits
        if len(recent_ids) == recent_ids.maxlen:
            old = recent_ids.popleft(); recent_set.discard(old)
        recent_ids.append(key_id); recent_set.add(key_id)
        return key_bytes, key_id

    try:
        if args.kms_per_message == 0:
            #one key for the entire walk
            key_bytes, key_id = kms_rotate(args.kms_key_bits)
            if not key_id:
                logging.error("KMS did not return a key. exit."); return

            for batch_idx, cols in enumerate(batches, 1):
                active_starts = list(cols)
                pdu_count_this_chunk = 0
                for round_idx in range(1, args.max_rounds + 1):
                    resp_pairs = bulk_once(args.user, args.auth_pass, key_bytes,
                                           args.agent_host, args.agent_port,
                                           active_starts, args.non_repeaters, args.rows_per_pdu)
                    sent_pdu_total += 1; pdu_count_this_chunk += 1
                    next_starts, finished = advance_columns(active_starts, resp_pairs)
                    logging.info("chunk %d: round %d → finished_cols=%d, remaining=%d",
                                 batch_idx, round_idx, finished, len(next_starts))
                    if not next_starts or next_starts == active_starts: break
                    active_starts = next_starts
                logging.info("chunk %d: GET-BULK PDUs=%d", batch_idx, pdu_count_this_chunk)
                time.sleep(args.pause_between_batches)

        elif args.kms_per_message == 1:
            #one key per chunk
            for batch_idx, cols in enumerate(batches, 1):
                key_bytes, key_id = kms_rotate(args.kms_key_bits)
                if not key_id:
                    logging.info("skipping chunk %d – no key", batch_idx); continue

                active_starts = list(cols)
                pdu_count_this_chunk = 0
                for round_idx in range(1, args.max_rounds + 1):
                    resp_pairs = bulk_once(args.user, args.auth_pass, key_bytes,
                                           args.agent_host, args.agent_port,
                                           active_starts, args.non_repeaters, args.rows_per_pdu)
                    sent_pdu_total += 1; pdu_count_this_chunk += 1
                    next_starts, finished = advance_columns(active_starts, resp_pairs)
                    logging.info("chunk %d: round %d → finished_cols=%d, remaining=%d",
                                 batch_idx, round_idx, finished, len(next_starts))
                    if not next_starts or next_starts == active_starts: break
                    active_starts = next_starts
                logging.info("chunk %d: GET-BULK PDUs=%d", batch_idx, pdu_count_this_chunk)
                time.sleep(args.pause_between_batches)

        else:
            #one key per every PDU
            for batch_idx, cols in enumerate(batches, 1):
                active_starts = list(cols)
                pdu_count_this_chunk = 0
                for round_idx in range(1, args.max_rounds + 1):
                    key_bytes, key_id = kms_rotate(args.kms_key_bits)
                    if not key_id:
                        logging.info("skipping PDU(chunk %d, round %d) – no key", batch_idx, round_idx)
                        break
                    resp_pairs = bulk_once(args.user, args.auth_pass, key_bytes,
                                           args.agent_host, args.agent_port,
                                           active_starts, args.non_repeaters, args.rows_per_pdu)
                    sent_pdu_total += 1; pdu_count_this_chunk += 1
                    next_starts, finished = advance_columns(active_starts, resp_pairs)
                    logging.info("chunk %d: round %d → finished_cols=%d, remaining=%d",
                                 batch_idx, round_idx, finished, len(next_starts))
                    if not next_starts or next_starts == active_starts: break
                    active_starts = next_starts
                logging.info("chunk %d: GET-BULK PDUs=%d", batch_idx, pdu_count_this_chunk)
                time.sleep(args.pause_between_batches)

        logging.info("done: total encrypted GET-BULK PDUs=%d", sent_pdu_total)
        logging.info("kms keys used=%d", keys_used)
        logging.info("qkd bits consumed(estimate)=%d", qkd_bits_consumed)

        try:
            with open(args.stats_csv, "a", newline="") as f:
                w = csv.writer(f)
                try:
                    f.seek(0, 2)
                    if f.tell() == 0:
                        w.writerow(["ts","kms_mode","cols_per_pdu","rows_per_pdu","v3_pdu","kms_keys","qkd_bits"])
                except Exception:
                    pass
                w.writerow([time.strftime("%Y-%m-%dT%H:%M:%S"),
                            {0:"per_walk",1:"per_chunk",2:"per_pdu"}[args.kms_per_message],
                            args.cols_per_pdu, args.rows_per_pdu,
                            sent_pdu_total, keys_used, qkd_bits_consumed])
            logging.info("stats csv:%s", args.stats_c‍sv if 'stats_c‍sv' in locals() else args.stats_csv)
        except Exception as e:
            logging.warning("csv not written:%s", e)

    except KeyboardInterrupt:
        logging.info("user interrupt. GET-BULK PDUs so far:%d", sent_pdu_total)
    finally:
        log_note("client GET-BULK(multiround IF-MIB) stop")

if __name__ == "__main__":
    main()
