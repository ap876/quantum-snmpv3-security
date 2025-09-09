#!/usr/bin/env python3
# -- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/manager/cmdgen/usm-sha-aes128.py
# adapted and extended for scenario 1 ("one message – one key") with KMS integration, get-bulk variant

"""
snmpv3 client (authPriv: SHA + AES-128) with kms integration, GETBULK mode

policy (scenario 1: one message – one key):
- for each snmp message, the manager fetches a fresh enc_key from master kms (key_ID, key_bytes)
- the manager notifies the agent at /kms with key_ID
- the agent pulls dec_key from slave kms and rotates usm
- the manager waits briefly and sends exactly one snmp GETBULK using that fresh key
- keys are not reused, a short pause follows before the next cycle
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
from pysnmp.hlapi import usmHMACSHAAuthProtocol, usmAesCfb128Protocol

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.WARNING)

#parameters
AGENT_HOST = "127.0.0.1"
AGENT_PORT = 50161
QKD_PORT   = 8080

USERNAME   = "usr-sha-aes128"
AUTH_PASS  = "authkey1"

#bulk root oid and params
BULK_ROOT_OID        = "1.3.6.1.2.1"  #MIB-2 subtree
BULK_NON_REPEATERS   = 0
BULK_MAX_REPETITIONS = 10

#master kms
MASTER_KMS_BASE = "http://10.250.0.2"
MASTER_APP_ID   = "aaac7de9-5826-11ef-8057-9b39f247aaa"
KMS_URL_TO_AGENT = f"http://{AGENT_HOST}:{QKD_PORT}/kms"

#POLICY: 1 key for 1 message
PER_MESSAGE_SLEEP_APPLY = 1.0   #give agent time to apply key
PAUSE_BETWEEN_MESSAGES  = 1.0   #rhythm (seconds)

#dedup window
DEDUP_WINDOW = 2000

def _derive_aes128(key_bytes: bytes) -> bytes:
    #normalize to 16 bytes for aes-128
    if len(key_bytes) == 16:
        return key_bytes
    return hashlib.sha256(key_bytes).digest()[:16]

def _trim_to_json(raw: str) -> str:
    #some proxies prepend text -> cut from first '{'
    i = raw.find("{")
    return raw[i:] if i >= 0 else raw

def get_enc_key_from_kms(master_base: str, app_id: str, n_keys: int = 1, size_bits: int = 128):
    #fetch one enc key from master kms
    #returns (key_bytes, key_b64, key_ID) or (None, None, None)
    url = f"{master_base}/api/v1/keys/{app_id}/enc_keys/number/{n_keys}/size/{size_bits}"
    logging.info("STEP 1 – GET sa Master KMS-a: %s", url)
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

    #fallback via curl if requests path fails
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
            return None, None, None
        logging.info("STEP 1 završeno: enc_key len=%dB, key_ID=%s", len(key_bytes), key_id)
        return key_bytes, key_b64, key_id
    except Exception:
        return None, None, None

def post_key_id_to_agent(url: str, user: str, key_id: str, timeout_sec: int = 5) -> bool:
    #tell agent which key_ID to pull from slave kms
    payload = {"user": user, "key_ID": key_id}
    logging.info("STEP 2 – POST na /kms, payload=%s", payload)
    try:
        resp = requests.post(
            url, json=payload, timeout=timeout_sec,
            headers={"Content-Type": "application/json", "Accept": "application/json"}
        )
        if resp.status_code == 200:
            logging.info("STEP 2 završeno: /kms prihvatio zahtjev")
            return True
        logging.warning("STEP 2 nije uspio: status=%s body=%s", resp.status_code, resp.text.strip())
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
    #send exactly one GETBULK with the fresh key
    logging.info("STEP 3 – SNMP GETBULK root=%s (N=%d, M=%d) — 1 poruka = 1 ključ",
                 root_oid, non_repeaters, max_repetitions)

    snmpEngine = engine.SnmpEngine()
    config.addTransport(snmpEngine, udp.domainName, udp.UdpTransport().openClientMode())

    #usm user with priv key derived from kms
    config.addV3User(
        snmpEngine, user,
        usmHMACSHAAuthProtocol, auth_pass,
        usmAesCfb128Protocol, _derive_aes128(priv_key_bytes)
    )
    config.addTargetParams(snmpEngine, 'my-creds', user, 'authPriv')
    config.addTargetAddr(snmpEngine, 'target', udp.domainName, (agent_host, agent_port), 'my-creds')

    def cbFun(snmpEngine, sendRequestHandle, errorIndication, errorStatus, errorIndex, varBindTable, cbCtx):
        if errorIndication:
            logging.error("SNMP greška: %s", errorIndication)
        elif errorStatus:
            logging.error("SNMP greška: %s at %s",
                          errorStatus.prettyPrint(),
                          errorIndex and varBindTable[int(errorIndex)-1][0] or '?')
        else:
            row_no = 0
            for row in varBindTable:
                row_no += 1
                for oid, val in row:
                    logging.info("BULK[%02d]: %s = %s", row_no, oid.prettyPrint(), val.prettyPrint())

    #prepare root oid
    oid_tuple = tuple(int(x) for x in root_oid.split('.'))

    #contextEngineId=None, contextName='' before N/M per pysnmp cmdgen signature
    cmdgen.BulkCommandGenerator().sendVarBinds(
        snmpEngine,
        'target',
        None, '',
        non_repeaters,
        max_repetitions,
        [((oid_tuple), None)],
        cbFun
    )

    snmpEngine.transportDispatcher.runDispatcher()

def main():
    #dedup tracking
    recent_ids = deque(maxlen=DEDUP_WINDOW)
    recent_set = set()
    sent_count = 0

    try:
        while True:
            key_bytes, key_b64, key_id = get_enc_key_from_kms(MASTER_KMS_BASE, MASTER_APP_ID)
            if not key_id:
                logging.info("KMS još nema dovoljno materijala, čekam 3s…")
                time.sleep(3)
                continue

            if key_id in recent_set:
                logging.info("Dobijen već korišten key_ID=%s, čekam 2s i tražim ponovo…", key_id)
                time.sleep(2)
                continue

            ok_kms = post_key_id_to_agent(KMS_URL_TO_AGENT, USERNAME, key_id, timeout_sec=5)
            if not ok_kms:
                logging.error("Agent nije prihvatio /kms. Pauza 2s.")
                time.sleep(2)
                continue

            #update dedup window
            if len(recent_ids) == recent_ids.maxlen:
                old = recent_ids.popleft()
                recent_set.discard(old)
            recent_ids.append(key_id)
            recent_set.add(key_id)

            #give agent time to rotate usm
            time.sleep(PER_MESSAGE_SLEEP_APPLY)

            #exactly one GETBULK
            run_snmp_getbulk(
                AGENT_HOST, AGENT_PORT,
                USERNAME, AUTH_PASS,
                key_bytes,
                BULK_ROOT_OID,
                BULK_NON_REPEATERS,
                BULK_MAX_REPETITIONS
            )
            sent_count += 1
            logging.info("Poslato GET_BULK poruka ukupno: %d", sent_count)

            time.sleep(PAUSE_BETWEEN_MESSAGES)

    except KeyboardInterrupt:
        logging.info("Prekinuto od strane korisnika. Ukupno poslanih GET_BULK poruka: %d", sent_count)

if __name__ == "__main__":
    main()
