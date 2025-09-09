#!/usr/bin/env python3
# -- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/manager/cmdgen/usm-sha-aes128.py
# adapted and extended for scenario 1 ("one message – one key") with KMS integration, aes-256 variant

"""
snmpv3 client (authPriv: SHA + AES-256) with kms integration
policy: one snmp GET message = one fresh encryption key

loop runs indefinitely:
  1) fetch enc_key from master kms  --> (key_ID, key_bytes)
  2) post key_ID to agent /kms      --> agent pulls dec_key from slave kms and rotates usm
  3) wait briefly and send exactly one snmp GET
  4) pause and repeat
"""

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

#try to import aes-256 -> fail fast if unavailable
try:
    from pysnmp.hlapi import usmAesCfb256Protocol
except Exception as e:
    raise RuntimeError("pysnmp build does not include AES-256 (usmAesCfb256Protocol).") from e

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.WARNING)

#parameters
AGENT_HOST = "127.0.0.1"
AGENT_PORT = 50161
QKD_PORT   = 8080

USERNAME   = "usr-sha-aes256"
AUTH_PASS  = "authkey1"  # keep secrets outside the repo in real deployments
OID_STR    = "1.3.6.1.2.1.1.1.0"  # sysDescr.0

#master kms
MASTER_KMS_BASE = "http://10.250.0.2"
MASTER_APP_ID   = "aaac7de9-5826-11ef-8057-9b39f247aaa"

KMS_URL_TO_AGENT = f"http://{AGENT_HOST}:{QKD_PORT}/kms"

#POLICY: 1 key for 1 message
#gives agent time to fetch/apply key before GET
PER_MESSAGE_SLEEP_APPLY = 1.0   
#short pause between cycles
PAUSE_BETWEEN_MESSAGES  = 1.0 

#sliding window for deduplicating recently used key_IDs -> to avoid accidental reuse
DEDUP_WINDOW = 2000


def _derive_aes256(key_bytes: bytes) -> bytes:
    if len(key_bytes) == 32:
        return key_bytes
    return hashlib.sha256(key_bytes).digest()

def _trim_to_json(raw: str) -> str:
    i = raw.find("{")
    return raw[i:] if i >= 0 else raw


def get_enc_key_from_kms(master_base: str, app_id: str, n_keys: int = 1, size_bits: int = 256):
    url = f"{master_base}/api/v1/keys/{app_id}/enc_keys/number/{n_keys}/size/{size_bits}"
    logging.info("step 1 – GET from master kms: %s", url)
    raw = None

    try:
        r = requests.get(
            url,
            timeout=10,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "User-Agent": "Wget/1.21",
            },
        )
        if r.status_code == 200:
            raw = r.text
        elif r.status_code == 400:
            return None, None, None
    except Exception:
        raw = None

    #simple fallback via curl for lab setups that behave better with it
    if raw is None:
        try:
            raw = subprocess.check_output(
                ["curl", "--fail", "--silent", "--show-error",
                 "-H", "Accept: application/json",
                 url],
                stderr=subprocess.STDOUT,
                timeout=10,
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
            logging.warning("unexpected key length from kms: %dB", len(key_bytes))
            return None, None, None

        logging.info("step 1 done: enc_key len=%dB, key_ID=%s", len(key_bytes), key_id)
        return key_bytes, key_b64, key_id
    except Exception as e:
        logging.warning("failed to parse kms response: %s", e)
        return None, None, None


def post_key_id_to_agent(url: str, user: str, key_id: str, timeout_sec: int = 5) -> bool:
    payload = {"user": user, "key_ID": key_id}
    logging.info("step 2 – POST /kms, payload=%s", payload)
    try:
        resp = requests.post(
            url, json=payload, timeout=timeout_sec,
            headers={"Content-Type": "application/json", "Accept": "application/json"}
        )
        if resp.status_code == 200:
            logging.info("step 2 done: /kms accepted")
            return True
        logging.warning("step 2 failed: status=%s body=%s", resp.status_code, resp.text.strip())
        return False
    except Exception as e:
        logging.warning("step 2 exception: %s", e)
        return False


def run_snmp_get(agent_host: str, agent_port: int, user: str, auth_pass: str, priv_key_bytes: bytes, oid_str: str):
    logging.info("step 3 – SNMP GET %s (1 message = 1 key)", oid_str)

    snmpEngine = engine.SnmpEngine()
    config.addTransport(snmpEngine, udp.domainName, udp.UdpTransport().openClientMode())

    #register usm user credentials — auth: sha (string), priv: aes-256 (bytes)
    config.addV3User(
        snmpEngine, user,
        usmHMACSHAAuthProtocol, auth_pass,
        usmAesCfb256Protocol, _derive_aes256(priv_key_bytes)
    )
    config.addTargetParams(snmpEngine, 'my-creds', user, 'authPriv')
    config.addTargetAddr(snmpEngine, 'target', udp.domainName, (agent_host, agent_port), 'my-creds')

    def cbFun(snmpEngine, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
        if errorIndication:
            logging.error("snmp error: %s", errorIndication)
        elif errorStatus:
            logging.error(
                "snmp error: %s at %s",
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex)-1][0] or '?'
            )
        else:
            for oid, val in varBinds:
                logging.info("snmp GET ok: %s = %s", oid.prettyPrint(), val.prettyPrint())

    oid_tuple = tuple(int(x) for x in oid_str.split('.'))
    cmdgen.GetCommandGenerator().sendVarBinds(snmpEngine, 'target', None, '', [((oid_tuple), None)], cbFun)
    snmpEngine.transportDispatcher.runDispatcher()


def main():
    recent_ids = deque(maxlen=DEDUP_WINDOW)
    recent_set = set()
    sent_count = 0

    try:
        while True:
            key_bytes, key_b64, key_id = get_enc_key_from_kms(MASTER_KMS_BASE, MASTER_APP_ID, size_bits=256)
            if not key_id:
                logging.info("kms does not have enough material yet, sleeping 3s…")
                time.sleep(3)
                continue

            #avoid reusing the same key_ID if kms re-serves it
            if key_id in recent_set:
                logging.info("duplicate key_ID=%s received, sleeping 2s and retry…", key_id)
                time.sleep(2)
                continue

            ok_kms = post_key_id_to_agent(KMS_URL_TO_AGENT, USERNAME, key_id, timeout_sec=5)
            if not ok_kms:
                logging.error("agent did not accept /kms, sleeping 2s")
                time.sleep(2)
                continue

            #update dedup structures
            if len(recent_ids) == recent_ids.maxlen:
                old = recent_ids.popleft()
                recent_set.discard(old)
            recent_ids.append(key_id)
            recent_set.add(key_id)

            #give agent time to apply key
            time.sleep(PER_MESSAGE_SLEEP_APPLY)

            #send exactly one GET using the fresh key
            run_snmp_get(AGENT_HOST, AGENT_PORT, USERNAME, AUTH_PASS, key_bytes, OID_STR)
            sent_count += 1
            logging.info("total GET messages sent: %d", sent_count)

            time.sleep(PAUSE_BETWEEN_MESSAGES)

    except KeyboardInterrupt:
        logging.info("interrupted by user, total GET messages sent: %d", sent_count)


if __name__ == "__main__":
    main()
