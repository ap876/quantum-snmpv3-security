#!/usr/bin/env python3
# -- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/manager/cmdgen/usm-sha-aes128.py

"""
snmpv3 client (authPriv: SHA + AES-256) with KMS integration

mode: GET_BULK — time-based rekey (rotate key every N seconds)
"""

import argparse
import base64
import hashlib
import json
import logging
import time
import subprocess
import requests
from collections import deque

from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.hlapi import usmHMACSHAAuthProtocol

#try to load AES-256 privacy protocol
try:
    from pysnmp.hlapi import usmAesCfb256Protocol
except Exception as e:
    raise RuntimeError("This pysnmp build lacks AES-256 (usmAesCfb256Protocol).") from e

#logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.WARNING)

#helpers
def _derive_aes256(key_bytes: bytes) -> bytes:
    return key_bytes if len(key_bytes) == 32 else hashlib.sha256(key_bytes).digest()

def _trim_to_json(raw: str) -> str:
    i = raw.find("{")
    return raw[i:] if i >= 0 else raw

def get_enc_key_from_kms(master_base: str, app_id: str, n_keys=1, size_bits=256):
    url = f"{master_base}/api/v1/keys/{app_id}/enc_keys/number/{n_keys}/size/{size_bits}"
    logging.info("STEP 1 – GET from Master KMS: %s", url)
    raw = None
    try:
        r = requests.get(
            url, timeout=10,
            headers={"Accept": "application/json", "Accept-Encoding": "identity", "User-Agent": "Wget/1.21"},
        )
        if r.status_code == 200:
            raw = r.text
        elif r.status_code == 400:
            return None, None, None
    except Exception:
        raw = None

    if raw is None:
        try:
            raw = subprocess.check_output(
                ["curl", "--fail", "--silent", "--show-error", "-H", "Accept: application/json", url],
                stderr=subprocess.STDOUT, timeout=10,
            ).decode("utf-8", "replace")
        except Exception:
            return None, None, None

    try:
        data = json.loads(_trim_to_json(raw))
        item = data["keys"][0]
        key_b64 = item["key"].strip()
        key_id  = item.get("key_ID") or item.get("id") or item.get("key_id")
        key_bytes = base64.b64decode(key_b64)
        if len(key_bytes) not in (16, 24, 32):
            return None, None, None
        logging.info("STEP 1 done: enc_key len=%dB, key_ID=%s", len(key_bytes), key_id)
        return key_bytes, key_b64, key_id
    except Exception:
        return None, None, None

def post_key_id_to_agent(url: str, user: str, key_id: str, timeout_sec: int = 5) -> bool:
    payload = {"user": user, "key_ID": key_id}
    logging.info("STEP 2 – POST to /kms, payload=%s", payload)
    try:
        resp = requests.post(
            url, json=payload, timeout=timeout_sec,
            headers={"Content-Type": "application/json", "Accept": "application/json"}
        )
        if resp.status_code == 200:
            logging.info("STEP 2 done: /kms accepted")
            return True
        logging.warning("STEP 2 failed: status=%s body=%s", resp.status_code, (resp.text or "").strip()[:200])
        return False
    except Exception as e:
        logging.warning("STEP 2 exception: %s", e)
        return False

def run_snmp_getbulk(agent_host: str,
                     agent_port: int,
                     user: str,
                     auth_pass: str,
                     priv_key_bytes: bytes,
                     root_oid: str,
                     non_repeaters: int = 0,
                     max_repetitions: int = 10):
    logging.info("STEP 3 – SNMP GETBULK root=%s (N=%d, M=%d) — time-based rekey",
                 root_oid, non_repeaters, max_repetitions)

    snmpEngine = engine.SnmpEngine()
    config.addTransport(snmpEngine, udp.domainName, udp.UdpTransport().openClientMode())

    #usm user with privacy key derived from KMS (AES-256)
    config.addV3User(
        snmpEngine, user,
        usmHMACSHAAuthProtocol, auth_pass,
        usmAesCfb256Protocol, _derive_aes256(priv_key_bytes)
    )
    config.addTargetParams(snmpEngine, 'my-creds', user, 'authPriv')
    config.addTargetAddr(snmpEngine, 'target', udp.domainName, (agent_host, agent_port), 'my-creds')

    def cbFun(snmpEngine, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBindTable, cbCtx):
        if errorIndication:
            logging.error("SNMP error: %s", errorIndication)
        elif errorStatus:
            logging.error("SNMP error: %s at %s",
                          errorStatus.prettyPrint(),
                          errorIndex and varBindTable[int(errorIndex)-1][0] or '?')
        else:
            row_no = 0
            for row in varBindTable:
                row_no += 1
                for oid, val in row:
                    logging.info("BULK[%02d]: %s = %s", row_no, oid.prettyPrint(), val.prettyPrint())

    oid_tuple = tuple(int(x) for x in root_oid.split('.'))

    cmdgen.BulkCommandGenerator().sendVarBinds(
        snmpEngine,
        'target',
        None, '',                      #contextEngineId, contextName (empty)
        non_repeaters,
        max_repetitions,
        [((oid_tuple), None)],
        cbFun
    )

    snmpEngine.transportDispatcher.runDispatcher()

#time-based rekey client
class TimeRekeyClient:
    def __init__(self, *,
                 master_kms_base: str,
                 master_app_id: str,
                 agent_kms_url: str,
                 user: str,
                 rekey_interval_s: int = 30,
                 insufficient_policy: str = "reuse",
                 wait_retry_s: float = 0.5,
                 wait_timeout_s: float = 5.0,
                 apply_sleep_s: float = 0.8):
        self.master_kms_base = master_kms_base
        self.master_app_id = master_app_id
        self.agent_kms_url = agent_kms_url
        self.user = user
        self.rekey_interval_s = int(rekey_interval_s)
        self.insufficient_policy = insufficient_policy  #reuse | wait | abort
        self.wait_retry_s = wait_retry_s
        self.wait_timeout_s = wait_timeout_s
        self.apply_sleep_s = apply_sleep_s
        self.active_key_bytes = None
        self.active_key_id = None
        self.next_rekey_at = 0.0
        self.recent_ids = deque(maxlen=2000)
        self.recent_set = set()

    def _try_fetch_and_apply(self):
        key_bytes, _key_b64, key_id = get_enc_key_from_kms(self.master_kms_base, self.master_app_id, size_bits=256)
        if not key_id:
            return False, "kms_no_bits"

        if key_id in self.recent_set:
            return False, "duplicate_key_id"

        ok_kms = post_key_id_to_agent(self.agent_kms_url, self.user, key_id, timeout_sec=5)
        if not ok_kms:
            return False, "agent_reject"

        if len(self.recent_ids) == self.recent_ids.maxlen:
            old = self.recent_ids.popleft()
            self.recent_set.discard(old)
        self.recent_ids.append(key_id)
        self.recent_set.add(key_id)

        time.sleep(self.apply_sleep_s)  #allow agent to apply

        self.active_key_bytes = key_bytes
        self.active_key_id = key_id
        self.next_rekey_at = time.time() + self.rekey_interval_s
        logging.info("REKEY OK (AES-256): key_ID=%s (valid until %.0fs)", key_id, self.next_rekey_at)
        return True, ""

    def ensure_key(self):
        now = time.time()
        if (self.active_key_bytes is None) or (now >= self.next_rekey_at):
            ok, reason = self._try_fetch_and_apply()
            if ok:
                return True, "fresh", True

            if self.insufficient_policy == "wait":
                t0 = time.time()
                while time.time() - t0 < self.wait_timeout_s:
                    time.sleep(self.wait_retry_s)
                    ok, reason = self._try_fetch_and_apply()
                    if ok:
                        return True, "fresh_after_wait", True
                if self.active_key_bytes is not None:
                    logging.warning("REKEY WAIT timeout — continuing with OLD key (reuse).")
                    return True, "reuse_after_wait_timeout", False
                else:
                    logging.error("REKEY WAIT timeout — no key available (abort).")
                    return False, "no_key_after_wait", False

            if self.insufficient_policy == "reuse":
                if self.active_key_bytes is not None:
                    logging.warning("REKEY failed (%s) — using OLD key (reuse).", reason)
                    return True, "reuse", False
                else:
                    logging.error("REKEY failed (%s) — no old key exists (abort).", reason)
                    return False, "no_key_reuse_fail", False

            logging.error("REKEY failed (%s) — policy 'abort', not sending.", reason)
            return False, "abort", False

        return True, "reused", False


def build_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-host", default="127.0.0.1")
    ap.add_argument("--agent-port", type=int, default=50161)
    ap.add_argument("--qkd-port", type=int, default=8080)
    ap.add_argument("--username", default="usr-sha-aes256")
    ap.add_argument("--auth-pass", default="authkey1")

    #GETBULK parameters
    ap.add_argument("--bulk-root-oid", default="1.3.6.1.2.1")  #MIB-2 subtree
    ap.add_argument("--bulk-non-repeaters", type=int, default=0)
    ap.add_argument("--bulk-max-repetitions", type=int, default=10)

    #master kms
    ap.add_argument("--master-kms-base", default="http://10.250.0.2")
    ap.add_argument("--master-app-id", default="aaac7de9-5826-11ef-8057-9b39f247aaa")

    #time-based rekey
    ap.add_argument("--rekey-interval", type=int, default=30)  #e.g., 30 or 60
    ap.add_argument("--insufficient-policy", choices=["reuse","wait","abort"], default="reuse")
    ap.add_argument("--wait-timeout", type=float, default=5.0)
    ap.add_argument("--wait-retry", type=float, default=0.5)
    ap.add_argument("--apply-sleep", type=float, default=0.8)

    #send cadence
    ap.add_argument("--pause", type=float, default=1.0, help="pause between GETBULK requests (s)")
    return ap.parse_args()

def main():
    args = build_args()

    AGENT_HOST = args.agent_host
    AGENT_PORT = args.agent_port
    QKD_PORT   = args.qkd_port
    USERNAME   = args.username
    AUTH_PASS  = args.auth_pass

    BULK_ROOT_OID = args.bulk_root_oid
    BULK_NON_REPEATERS = args.bulk_non_repeaters
    BULK_MAX_REPETITIONS = args.bulk_max_repetitions

    MASTER_KMS_BASE = args.master_kms_base
    MASTER_APP_ID   = args.master_app_id
    KMS_URL_TO_AGENT = f"http://{AGENT_HOST}:{QKD_PORT}/kms"

    rekey = TimeRekeyClient(
        master_kms_base=MASTER_KMS_BASE,
        master_app_id=MASTER_APP_ID,
        agent_kms_url=KMS_URL_TO_AGENT,
        user=USERNAME,
        rekey_interval_s=args.rekey_interval,
        insufficient_policy=args.insufficient_policy,
        wait_retry_s=args.wait_retry,
        wait_timeout_s=args.wait_timeout,
        apply_sleep_s=args.apply_sleep
    )

    sent_count = 0
    try:
        while True:
            can_send, reason, fresh = rekey.ensure_key()
            if not can_send:
                time.sleep(args.pause)
                continue

            run_snmp_getbulk(
                AGENT_HOST, AGENT_PORT,
                USERNAME, AUTH_PASS,
                rekey.active_key_bytes,
                BULK_ROOT_OID,
                BULK_NON_REPEATERS,
                BULK_MAX_REPETITIONS
            )
            sent_count += 1
            logging.info("GET_BULK sent (fresh_key=%s, key_ID=%s). Total: %d",
                         fresh, rekey.active_key_id, sent_count)

            time.sleep(args.pause)

    except KeyboardInterrupt:
        logging.info("Interrupted. Total GET_BULK messages sent: %d", sent_count)

if __name__ == "__main__":
    main()
