# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/manager/cmdgen/usm-sha-aes128.py
#!/usr/bin/env python3
#-- coding: utf-8 --

"""
snmpv3 client (authPriv: SHA + AES-128) – discovery via GET-NEXT (v2c) across the whole IF-MIB,
then data transfer using plain GET PDUs.

supports:
- --kms-per-message 1  -> fresh KMS key for every GET (max QKD bit usage)
- --kms-per-message 0  -> one KMS key for the entire GET "walk" (min usage)
- report: number of encrypted v3 messages and estimated QKD bits consumed
"""

import argparse
import base64
import csv
import hashlib
import json
import logging
import subprocess
import time
from collections import deque
from typing import List, Dict

import requests

#v2c discovery (local net-snmpd)
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, nextCmd
)

#v3 GET via proxy
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.hlapi import usmHMACSHAAuthProtocol, usmAesCfb128Protocol

#qkd usage logger (optional)
try:
    from snmp_qkd_logger import init_logger, set_key, log_tx, log_note
except Exception:
    def init_logger(*a, **k): pass
    def set_key(*a, **k): pass
    def log_tx(*a, **k): pass
    def log_note(*a, **k): pass

END_OF_MIB_TEXT = "No more variables left in this MIB View"
IFMIB_ROOTS = [
    "1.3.6.1.2.1.2",      #interfaces subtree
    "1.3.6.1.2.1.31.1"    #ifX subtree
]

#helpers
def _derive_aes128(key_bytes: bytes) -> bytes:
    return key_bytes if len(key_bytes) == 16 else hashlib.sha256(key_bytes).digest()[:16]

def _trim_to_json(raw: str) -> str:
    i = raw.find("{"); return raw[i:] if i >= 0 else raw

def get_enc_key_from_kms(master_base: str, app_id: str, n_keys=1, size_bits=128, timeout=10):
    url = f"{master_base}/api/v1/keys/{app_id}/enc_keys/number/{n_keys}/size/{size_bits}"
    logging.debug("kms get: %s", url)
    raw = None
    try:
        r = requests.get(
            url,
            timeout=timeout,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "User-Agent": "KMS-GET-Client/1.0",
            },
        )
        if r.status_code == 200:
            raw = r.text
    except Exception:
        raw = None

    if raw is None:
        try:
            raw = subprocess.check_output(
                ["curl", "--fail", "--silent", "--show-error", "-H", "Accept: application/json", url],
                stderr=subprocess.STDOUT,
                timeout=timeout,
            ).decode("utf-8", "replace")
        except Exception:
            return None, None, None

    try:
        data = json.loads(_trim_to_json(raw)); item = data["keys"][0]
        key_b64 = (item.get("key") or "").strip()
        key_id  = item.get("key_ID") or item.get("id") or item.get("key_id")
        if not key_b64 or not key_id:
            return None, None, None
        key_bytes = base64.b64decode(key_b64)
        if len(key_bytes) not in (16, 24, 32):
            return None, None, None
        return key_bytes, key_b64, key_id
    except Exception:
        return None, None, None

def post_key_id_to_agent(url: str, user: str, key_id: str, timeout_sec: int = 8) -> bool:
    try:
        resp = requests.post(
            url,
            json={"user": user, "key_ID": key_id},
            timeout=timeout_sec,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        return resp.status_code == 200
    except Exception:
        return False

def _mk_snmp_engine_for_key(user: str, auth_pass: str, priv_key_bytes: bytes,
                            agent_host: str, agent_port: int):
    snmpEngineV3 = engine.SnmpEngine()
    config.addTransport(snmpEngineV3, udp.domainName, udp.UdpTransport().openClientMode())
    config.addV3User(
        snmpEngineV3,
        user,
        usmHMACSHAAuthProtocol,
        auth_pass,
        usmAesCfb128Protocol,
        _derive_aes128(priv_key_bytes),
    )
    config.addTargetParams(snmpEngineV3, 'my-creds', user, 'authPriv')
    config.addTargetAddr(snmpEngineV3, 'target', udp.domainName, (agent_host, agent_port), 'my-creds')
    return snmpEngineV3

def do_one_get(user: str, auth_pass: str, priv_key_bytes: bytes,
               agent_host: str, agent_port: int, oids: List[str]) -> Dict[str, str]:
    """exactly one GET with provided OIDs (v3 authPriv)."""
    try:
        sample = ",".join(oids[:4]) + ("..." if len(oids) > 4 else "")
        log_tx("GET", extra=f"oids={sample}")
    except Exception:
        pass

    out: Dict[str, str] = {}

    def cbFun(snmpEngineV3, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
        nonlocal out
        if errorIndication:
            logging.error("snmp error: %s", errorIndication); return
        if errorStatus:
            logging.error("snmp error: %s at %s",
                          errorStatus.prettyPrint(),
                          errorIndex and varBinds[int(errorIndex)-1][0] or '?'); return
        for vb in varBinds:
            if isinstance(vb, (tuple, list)) and len(vb) >= 2:
                name, val = vb[0], vb[1]
                out[name.prettyPrint()] = val.prettyPrint()
                logging.info("snmp get: %s = %s", name.prettyPrint(), val.prettyPrint())

    vb = [((tuple(int(x) for x in oid.split("."))), None) for oid in oids]
    snmpEngineV3 = _mk_snmp_engine_for_key(user, auth_pass, priv_key_bytes, agent_host, agent_port)
    cmdgen.GetCommandGenerator().sendVarBinds(snmpEngineV3, 'target', None, '', vb, cbFun)
    snmpEngineV3.transportDispatcher.runDispatcher()
    return out

def chunk(lst: List[str], n: int) -> List[List[str]]:
    return [lst[i:i+n] for i in range(0, len(lst), n)]

#discovery (v2c) – full IF-MIB
def discover_if_mib_instances(backend_host: str, backend_port: int, community: str,
                              timeout: float, retries: int) -> List[str]:
    oids: List[str] = []
    mgrEngine = SnmpEngine()
    comm   = CommunityData(community, mpModel=1)
    target = UdpTransportTarget((backend_host, backend_port), timeout=timeout, retries=retries)
    ctx    = ContextData()

    for root in IFMIB_ROOTS:
        root_dot = str(root).rstrip('.')
        for (errInd, errStat, errIdx, binds) in nextCmd(
            mgrEngine, comm, target, ctx,
            ObjectType(ObjectIdentity(root_dot)),
            lexicographicMode=True
        ):
            if errInd:
                logging.warning("next error @%s: %s", root_dot, errInd); break
            if errStat:
                logging.warning("next status @%s: %s", root_dot, errStat.prettyPrint()); break
            if not binds:
                break
            vb0 = binds[0]
            try:
                name, val = vb0
            except Exception:
                logging.warning("next varBind shape @%s: %r", root_dot, vb0); break

            name_str = str(name)
            if not name_str.startswith(root_dot + ".") and name_str != root_dot:
                break

            v = val.prettyPrint() if hasattr(val, "prettyPrint") else str(val)
            if v == END_OF_MIB_TEXT:
                continue
            oids.append(name_str)

    oids = sorted(set(oids), key=lambda s: tuple(map(int, s.strip('.').split('.'))))
    logging.info("discovery: found IF-MIB instances (scalar + tabular): %d", len(oids))
    return oids

#main
def main():
    ap = argparse.ArgumentParser(description="snmpv3 GET client (full IF-MIB) with KMS/QKD accounting")
    #v3 proxy (front)
    ap.add_argument("--agent-host", default="127.0.0.1")
    ap.add_argument("--agent-port", type=int, default=50161)
    ap.add_argument("--qkd-port",   type=int, default=8080)
    ap.add_argument("--user", default="usr-sha-aes128")
    ap.add_argument("--auth-pass", default="authkey1")

    #backend (discovery v2c)
    ap.add_argument("--backend-host", default="127.0.0.1")
    ap.add_argument("--backend-port", type=int, default=161)
    ap.add_argument("--backend-comm", default="public")
    ap.add_argument("--backend-timeout", type=float, default=1.0)
    ap.add_argument("--backend-retries", type=int, default=1)

    #kms
    ap.add_argument("--master-kms-base", default="http://10.250.0.2")
    ap.add_argument("--master-app-id", default="aaac7de9-5826-11ef-8057-9b39f247aaa")
    ap.add_argument("--kms-key-bits", type=int, choices=[128, 256], default=128,
                    help="size of enc key to request from KMS (bits)")
    ap.add_argument("--kms-per-message", type=int, choices=[0, 1], default=1,
                    help="1 = fresh key per GET; 0 = single key for entire walk")

    #batching / timing
    ap.add_argument("--get-batch-size", type=int, default=10)
    ap.add_argument("--per-message-sleep-apply", type=float, default=0.7,
                    help="wait after /kms before sending GET (s)")
    ap.add_argument("--pause-between-batches", type=float, default=0.3)

    #report
    ap.add_argument("--stats-csv", default="ifmib_get_stats.csv")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    logging.getLogger("requests").setLevel(logging.WARNING)

    run_id   = time.strftime("%Y%m%d_%H%M%S")
    log_path = f"qkd_usage_{run_id}.log"
    init_logger(log_path)
    print(f"[logger] writing to: {log_path}")
    log_note("client GET(full IF-MIB) start")

    #1) discovery
    all_oids = discover_if_mib_instances(
        args.backend_host, args.backend_port,
        args.backend_comm, args.backend_timeout, args.backend_retries
    )
    if not all_oids:
        logging.error("discovery returned no OIDs. exiting.")
        log_note("client stop: discovery empty")
        return

    batches = chunk(all_oids, args.get_batch_size)
    logging.info("total OIDs: %d, number of GET messages: %d (batch=%d)",
                 len(all_oids), len(batches), args.get_batch_size)

    kms_url_to_agent = f"http://{args.agent_host}:{args.qkd_port}/kms"

    #2) kms policy
    total_msgs = 0
    keys_used = 0
    qkd_bits_consumed = 0

    if args.kms_per_message == 0:
        #one key for the entire walk
        key_bytes, _kb64, key_id = get_enc_key_from_kms(
            args.master_kms_base, args.master_app_id, n_keys=1, size_bits=args.kms_key_bits
        )
        if not key_id:
            logging.error("kms did not return a key. exiting.")
            return
        try: set_key(key_id, args.kms_key_bits)
        except Exception: pass
        if not post_key_id_to_agent(kms_url_to_agent, args.user, key_id):
            logging.error("agent did not accept /kms. exiting.")
            return
        keys_used = 1
        qkd_bits_consumed = args.kms_key_bits
        time.sleep(args.per_message_sleep_apply)

        for batch in batches:
            _ = do_one_get(args.user, args.auth_pass, key_bytes,
                           args.agent_host, args.agent_port, batch)
            total_msgs += 1
            time.sleep(args.pause_between_batches)

    else:
        #fresh key for every GET message
        recent_ids = deque(maxlen=2000); recent_set = set()
        for batch in batches:
            key_bytes, _kb64, key_id = get_enc_key_from_kms(
                args.master_kms_base, args.master_app_id, n_keys=1, size_bits=args.kms_key_bits
            )
            if not key_id:
                logging.info("kms has no key yet, sleeping 2s…")
                time.sleep(2); continue
            if key_id in recent_set:
                logging.info("duplicate key_ID=%s, sleeping 1s…", key_id)
                time.sleep(1); continue
            try: set_key(key_id, args.kms_key_bits)
            except Exception: pass
            if not post_key_id_to_agent(kms_url_to_agent, args.user, key_id):
                logging.warning("agent did not accept /kms, skipping this batch…")
                time.sleep(1); continue

            time.sleep(args.per_message_sleep_apply)
            _ = do_one_get(args.user, args.auth_pass, key_bytes,
                           args.agent_host, args.agent_port, batch)
            total_msgs += 1
            keys_used  += 1
            qkd_bits_consumed += args.kms_key_bits

            if len(recent_ids) == recent_ids.maxlen:
                old = recent_ids.popleft(); recent_set.discard(old)
            recent_ids.append(key_id); recent_set.add(key_id)

            time.sleep(args.pause_between_batches)

    #3) report
    logging.info("done: sent GET messages (encrypted) = %d", total_msgs)
    logging.info("kms keys used = %d", keys_used)
    logging.info("qkd bits consumed (estimate) = %d", qkd_bits_consumed)

    #csv
    try:
        with open(args.stats_csv, "a", newline="") as f:
            w = csv.writer(f)
            try:
                f.seek(0, 2)
                if f.tell() == 0:
                    w.writerow(["ts","mode","batch_size","v3_msgs","kms_keys","qkd_bits"])
            except Exception:
                pass
            w.writerow([
                time.strftime("%Y-%m-%dT%H:%M:%S"),
                "per_msg" if args.kms_per_message else "per_walk",
                args.get_batch_size, total_msgs, keys_used, qkd_bits_consumed
            ])
        logging.info("stats csv: %s", args.stats_csv)
    except Exception as e:
        logging.warning("csv not written: %s", e)

    log_note(f"client GET stop: v3_msgs={total_msgs}, kms_keys={keys_used}, qkd_bits={qkd_bits_consumed}")

if __name__ == "__main__":
    main()
