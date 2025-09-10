#!/usr/bin/env python3
# -- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/manager/cmdgen/usm-sha-aes128.py
"""
SNMPv3 GET-NEXT client (authPriv: SHA + AES-128) + KMS rotation, FULL IF-MIB WALK

Features:
- v2c discovery: collect all INSTANCES from full IF-MIB (scalars + tables)
- generate START OIDs for GET-NEXT:
  * scalar-base (no .0) -> GET-NEXT yields ...0
  * column-base (no index) -> GET-NEXT yields first instance
- full WALK: loop GET-NEXT until prefixes are left (endOfMibView)
- KMS: by default fetch a new key for EVERY message and push key_ID to agent via /kms
- stats: number of v3 messages (encrypted), keys used, and estimated QKD bits

"""

import argparse
import base64
import csv
import hashlib
import json
import logging
import time
import subprocess
from typing import List, Dict, Tuple

import requests

#v2c discovery (local net-snmpd)
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, nextCmd
)

#v3 GET-NEXT to proxy
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.hlapi import usmHMACSHAAuthProtocol, usmAesCfb128Protocol

try:
    from snmp_qkd_logger import init_logger, set_key, log_tx, log_note
except Exception:
    def init_logger(*a, **k): pass
    def set_key(*a, **k): pass
    def log_tx(*a, **k): pass
    def log_note(*a, **k): pass

#---IF-MIB roots (full)
IFMIB_ROOTS = [
    "1.3.6.1.2.1.2",   #interfaces
    "1.3.6.1.2.1.31"   #ifMIB
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

def _is_prefix_of(prefix: str, oid: str) -> bool:
    return oid.startswith(prefix + ".") or oid == prefix
#kms
def get_enc_key_from_kms(master_base: str, app_id: str, n_keys=1, size_bits=128, timeout=10):
    url = f"{master_base}/api/v1/keys/{app_id}/enc_keys/number/{n_keys}/size/{size_bits}"
    logging.debug("KMS GET: %s", url)
    raw = None
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"Accept":"application/json","Accept-Encoding":"identity","User-Agent":"KMS-RTT-Client/1.0"})
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
        logging.debug("KMS OK: len=%dB key_ID=%s", len(key_bytes), key_id)
        return key_bytes, key_b64, key_id
    except Exception:
        return None, None, None

def post_key_id_to_agent(url: str, user: str, key_id: str, timeout_sec: int = 8) -> bool:
    payload = {"user": user, "key_ID": key_id}
    logging.debug("POST /kms: %s", payload)
    try:
        resp = requests.post(url, json=payload, timeout=timeout_sec,
                             headers={"Content-Type":"application/json","Accept":"application/json"})
        return resp.status_code == 200
    except Exception:
        return False
      
def _mk_snmp_engine_for_key(user: str, auth_pass: str, priv_key_bytes: bytes,
                            agent_host: str, agent_port: int):
    snmpEngineV3 = engine.SnmpEngine()
    config.addTransport(snmpEngineV3, udp.domainName, udp.UdpTransport().openClientMode())
    config.addV3User(snmpEngineV3, user, usmHMACSHAAuthProtocol, auth_pass,
                     usmAesCfb128Protocol, _derive_aes128(priv_key_bytes))
    config.addTargetParams(snmpEngineV3, 'my-creds', user, 'authPriv')
    config.addTargetAddr(snmpEngineV3, 'target', udp.domainName, (agent_host, agent_port), 'my-creds')
    return snmpEngineV3

#discovery v2c
def discover_if_mib_instances(backend_host: str, backend_port: int, community: str,
                              timeout: float, retries: int) -> List[str]:
    oids: List[str] = []
    mgrEngine = SnmpEngine()
    comm   = CommunityData(community, mpModel=1)   #v2c
    target = UdpTransportTarget((backend_host, backend_port), timeout=timeout, retries=retries)
    ctx    = ContextData()

    for root in IFMIB_ROOTS:
        root_dot = str(root).rstrip('.')
        for (errInd, errStat, errIdx, binds) in nextCmd(
                mgrEngine, comm, target, ctx,
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
            v = _pp_val(val)
            if v == END_OF_MIB_TEXT:
                continue
            oids.append(name_str)

    oids = sorted(set(oids), key=lambda s: tuple(map(int, s.strip('.').split('.'))))
    logging.info("DISCOVERY: IF-MIB instances (scalar+tabular): %d", len(oids))
    return oids

def build_start_oids_for_full_ifmib(instance_oids: List[str]) -> List[str]:
    scalar_bases = set()
    column_bases = set()
    for s in instance_oids:
        s = s.strip('.')
        if not s:
            continue
        parts = s.split('.')
        if parts[-1] == '0':
            scalar_bases.add('.'.join(parts[:-1]))
        else:
            column_bases.add('.'.join(parts[:-1]))
    start = scalar_bases | column_bases
    return sorted(start, key=lambda t: tuple(map(int, t.split('.'))))

def walk_getnext_full(user: str, auth_pass: str, key_bytes: bytes,
                      agent_host: str, agent_port: int,
                      start_oids: List[str],
                      cols_per_pdu: int) -> Tuple[int, Dict[str, str]]:
    values: Dict[str, str] = {}
    total_msgs = 0

    #split start heads into PDU groups
    def chunk(lst: List[str], n: int) -> List[List[str]]:
        return [lst[i:i+n] for i in range(0, len(lst), n)]

    groups = chunk(start_oids, cols_per_pdu)

    for group in groups:
        heads = list(group)
        snmpEngineV3 = _mk_snmp_engine_for_key(user, auth_pass, key_bytes, agent_host, agent_port)
        gen = cmdgen.NextCommandGenerator()

        while heads:
            vb = [((tuple(int(x) for x in h.split("."))), None) for h in heads]
            next_heads: List[str] = []

            def cbFun(snmpEngineV3, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
                nonlocal next_heads, values
                if errorIndication or errorStatus:
                    return
                #varBinds yields one next var for each input OID
                i = 0
                for row in varBinds:
                    pairs = row if (isinstance(row, (list, tuple)) and row and isinstance(row[0], (list, tuple))) else [row]
                    for pair in pairs:
                        if len(pair) < 2:
                            i += 1; continue
                        name, val = pair[0], pair[1]
                        n, v = _pp_oid(name), _pp_val(val)
                        if v == END_OF_MIB_TEXT:
                            i += 1; continue
                        values[n] = v
                        logging.debug("SNMP WALK: %s = %s", n, v)
                        start = heads[i]
                        #continue only within the same prefix (column or scalar base)
                        if _is_prefix_of(start, n):
                            next_heads.append(n)
                        i += 1

            gen.sendVarBinds(snmpEngineV3, 'target', None, '', vb, cbFun)
            snmpEngineV3.transportDispatcher.runDispatcher()
            total_msgs += 1
            heads = sorted(set(next_heads), key=lambda s: tuple(map(int, s.split("."))))

    return total_msgs, values

def main():
    ap = argparse.ArgumentParser(description="SNMPv3 GET-NEXT client (FULL IF-MIB WALK) with KMS rotation")
    #v3 proxy(front)
    ap.add_argument("--agent-host", default="127.0.0.1")
    ap.add_argument("--agent-port", type=int, default=50161)
    ap.add_argument("--qkd-port",   type=int, default=8080)
    ap.add_argument("--user", default="usr-sha-aes128")
    ap.add_argument("--auth-pass", default="authkey1")

    #backend(for discovery)
    ap.add_argument("--backend-host", default="127.0.0.1")
    ap.add_argument("--backend-port", type=int, default=161)
    ap.add_argument("--backend-comm", default="public")
    ap.add_argument("--backend-timeout", type=float, default=1.0)
    ap.add_argument("--backend-retries", type=int, default=1)

    #KMS
    ap.add_argument("--master-kms-base", default="http://10.250.0.2")
    ap.add_argument("--master-app-id", default="aaac7de9-5826-11ef-8057-9b39f247aaa")
    ap.add_argument("--kms-key-bits", type=int, choices=[128,256], default=128,
                    help="key size to request from KMS")
    ap.add_argument("--kms-per-message", type=int, default=1,
                    help="1=new key per v3 message; 0=one key for the whole walk")

    #sending
    ap.add_argument("--cols-per-pdu", type=int, default=10)
    ap.add_argument("--per-message-sleep-apply", type=float, default=0.7,
                    help="sleep after /kms before sending (s)")
    ap.add_argument("--pause-between-batches", type=float, default=0.2)

    #report
    ap.add_argument("--stats-csv", default="ifmib_walk_stats.csv")

    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    logging.getLogger("requests").setLevel(logging.WARNING)

    run_id = time.strftime("%Y%m%d_%H%M%S")
    log_path = f"qkd_usage_{run_id}.log"
    init_logger(log_path)
    print(f"[LOGGER] writing to: {log_path}")
    log_note("client GET-NEXT(full IF-MIB) start")

    #1.discovery(v2c)
    instances = discover_if_mib_instances(args.backend_host, args.backend_port,
                                          args.backend_comm, args.backend_timeout, args.backend_retries)
    if not instances:
        logging.error("Discovery returned no OIDs. Exit.")
        log_note("client stop: discovery empty")
        return

    #2. instance->start OID(scalar-base+column-base)
    start_oids = build_start_oids_for_full_ifmib(instances)
    logging.info("Start OIDs(FULL IF-MIB): %d", len(start_oids))

    kms_url_to_agent = f"http://{args.agent_host}:{args.qkd_port}/kms"

    #3. walk
    total_msgs = 0
    keys_used = 0
    qkd_bits_consumed = 0

    if args.kms_per_message:
        #each message->new key
        #send per-group
        #rotate KMS key before every v3 send
        def chunk(lst: List[str], n: int) -> List[List[str]]:
            return [lst[i:i+n] for i in range(0, len(lst), n)]

        groups = chunk(start_oids, args.cols_per_pdu)
        values: Dict[str, str] = {}

        for group in groups:
            heads = list(group)
            while heads:
                #KMS rotation for this message
                key_bytes, _k_b64, key_id = get_enc_key_from_kms(
                    args.master_kms_base, args.master_app_id, n_keys=1, size_bits=args.kms_key_bits)
                if not key_id:
                    logging.info("KMS has no key, waiting 2s…"); time.sleep(2); continue
                try: set_key(key_id, args.kms_key_bits)
                except Exception: pass
                ok_post = post_key_id_to_agent(kms_url_to_agent, args.user, key_id)
                if not ok_post:
                    logging.warning("Agent didn't accept /kms, retry…"); time.sleep(1); continue
                keys_used += 1
                qkd_bits_consumed += args.kms_key_bits

                time.sleep(args.per_message_sleep_apply)

                #send one v3 message with current heads
                snmpEngineV3 = _mk_snmp_engine_for_key(args.user, args.auth_pass, key_bytes,
                                                       args.agent_host, args.agent_port)
                gen = cmdgen.NextCommandGenerator()
                vb = [((tuple(int(x) for x in h.split("."))), None) for h in heads]
                next_heads: List[str] = []

                def cbFun(snmpEngineV3, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
                    nonlocal next_heads, values
                    if errorIndication or errorStatus:
                        return
                    i = 0
                    for row in varBinds:
                        pairs = row if (isinstance(row, (list, tuple)) and row and isinstance(row[0], (list, tuple))) else [row]
                        for pair in pairs:
                            if len(pair) < 2: i += 1; continue
                            name, val = pair[0], pair[1]
                            n, v = _pp_oid(name), _pp_val(val)
                            if v == END_OF_MIB_TEXT:
                                i += 1; continue
                            values[n] = v
                            start = heads[i]
                            if _is_prefix_of(start, n):
                                next_heads.append(n)
                            i += 1

                log_tx("GET-NEXT", extra=f"heads={','.join(heads[:4])}{'...' if len(heads)>4 else ''}")
                gen.sendVarBinds(snmpEngineV3, 'target', None, '', vb, cbFun)
                snmpEngineV3.transportDispatcher.runDispatcher()
                total_msgs += 1

                #prepare next step
                heads = sorted(set(next_heads), key=lambda s: tuple(map(int, s.split("."))))
                time.sleep(args.pause_between_batches)

        walked_values = values

    else:
        #one key for the whole walk
        key_bytes, _k_b64, key_id = get_enc_key_from_kms(
            args.master_kms_base, args.master_app_id, n_keys=1, size_bits=args.kms_key_bits)
        if not key_id:
            logging.error("KMS didn't return a key. Exit."); return
        try: set_key(key_id, args.kms_key_bits)
        except Exception: pass
        if not post_key_id_to_agent(kms_url_to_agent, args.user, key_id):
            logging.error("Agent didn't accept /kms. Exit."); return
        keys_used = 1
        qkd_bits_consumed = args.kms_key_bits
        time.sleep(args.per_message_sleep_apply)

        total_msgs, walked_values = walk_getnext_full(
            args.user, args.auth_pass, key_bytes,
            args.agent_host, args.agent_port,
            start_oids, args.cols_per_pdu
        )

    #report
    logging.info("WALK done. Encrypted v3 messages: %d", total_msgs)
    logging.info("KMS keys used: %d", keys_used)
    logging.info("QKD bits consumed(estimate): %d", qkd_bits_consumed)

    try:
        with open(args.stats_csv, "a", newline="") as f:
            w = csv.writer(f)
            #header if file empty
            try:
                f.seek(0, 2)
                if f.tell() == 0:
                    w.writerow(["ts","mode","cols_per_pdu","v3_msgs","kms_keys","qkd_bits"])
            except Exception:
                pass
            w.writerow([time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "per_msg" if args.kms_per_message else "per_walk",
                        args.cols_per_pdu, total_msgs, keys_used, qkd_bits_consumed])
        logging.info("Stats CSV: %s", args.stats_csv)
    except Exception as e:
        logging.warning("CSV not written: %s", e)

    log_note(f"client stop: v3_msgs={total_msgs}, kms_keys={keys_used}, qkd_bits={qkd_bits_consumed}")

if __name__ == "__main__":
    main()
