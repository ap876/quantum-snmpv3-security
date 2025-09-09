#!/usr/bin/env python3
# -- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/hlapi/asyncore/ntforg/v3-inform.py
# adapted and extended for scenario 1 ("one message – one key") with kms integration, inform variant

"""
snmpv3 client (authPriv: SHA + AES-128) with kms integration — INFORM variant

policy (scenario 1: one message – one key):
  1) fetch enc_key from master kms  -> (key_ID, key_bytes)
  2) post key_ID to agent /kms      -> agent pulls dec_key from slave kms and rotates usm
  3) poll /kms/ready?key_ID=...     -> wait until the agent applied the key (or timeout)
  4) send exactly one snmp INFORM using that fresh key
  5) repeat

runs indefinitely until interrupted (Ctrl+C). requires aes-128 (priv) support on both sides.
"""

import base64
import hashlib
import json
import logging
import time
import subprocess
import requests
from typing import Optional, Tuple

from pysnmp.hlapi import (
    SnmpEngine, UdpTransportTarget, ContextData,
    UsmUserData, ObjectIdentity, NotificationType, sendNotification,
    usmHMACSHAAuthProtocol, usmAesCfb128Protocol
)

#logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.WARNING)

#parameters
AGENT_HOST = "127.0.0.1"
AGENT_PORT = 50161
QKD_PORT   = 8080

USERNAME   = "usr-sha-aes128"
AUTH_PASS  = "authkey1"  #keep real secrets out of the repo

#master kms
MASTER_KMS_BASE = "http://10.250.0.2"
MASTER_APP_ID   = "aaac7de9-5826-11ef-8057-9b39f247aaa"

KMS_URL_TO_AGENT = f"http://{AGENT_HOST}:{QKD_PORT}/kms"
KMS_READY_URL    = f"http://{AGENT_HOST}:{QKD_PORT}/kms/ready"

START_TIME = time.time()

def _derive_aes128(key_bytes: bytes) -> bytes:
    #return 16B key; if not 16B, derive via sha256 and take first 16B
    if len(key_bytes) == 16:
        return key_bytes
    return hashlib.sha256(key_bytes).digest()[:16]

def _trim_to_json(raw: str) -> str:
    #strip any proxy banners before the first '{'
    i = raw.find("{")
    return raw[i:] if i >= 0 else raw

def get_enc_key_from_kms(master_base: str, app_id: str, n_keys: int = 1, size_bits: int = 128) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    #fetch one enc key from master kms; returns (key_bytes, key_b64, key_ID) or (None, None, None)
    url = f"{master_base}/api/v1/keys/{app_id}/enc_keys/number/{n_keys}/size/{size_bits}"
    logging.info("step 1 – GET from master kms: %s", url)
    raw: Optional[str] = None

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

    #fallback via curl for quirky lab setups
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
    except Exception:
        return None, None, None

def post_key_id_to_agent(url: str, user: str, key_id: str, timeout_sec: int = 5) -> bool:
    #notify the agent which key_ID to pull from slave kms
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

def wait_key_applied(agent_host: str, key_id: str, max_wait_s: float = 6.0) -> bool:
    #poll /kms/ready?key_ID=... until {"applied": true} or timeout
    deadline = time.time() + max_wait_s
    url = f"http://{agent_host}:{QKD_PORT}/kms/ready?key_ID={key_id}"
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=1.0)
            if r.status_code == 200:
                j = r.json()
                if j.get("applied"):
                    logging.info("step 2.5 – agent applied key (key_ID=%s)", key_id)
                    return True
        except Exception:
            pass
        time.sleep(0.3)
    logging.warning("step 2.5 – agent did not apply key in time (key_ID=%s)", key_id)
    return False

def run_snmp_inform(agent_host: str, agent_port: int, user: str, auth_pass: str, priv_key_bytes: bytes) -> bool:
    #send a single snmpv3 INFORM (coldStart) with authPriv (sha + aes-128)
    logging.info("step 3 – SNMP INFORM — 1 message = 1 key")

    authData = UsmUserData(
        userName=user,
        authKey=auth_pass, authProtocol=usmHMACSHAAuthProtocol,
        privKey=_derive_aes128(priv_key_bytes), privProtocol=usmAesCfb128Protocol
    )
    transport = UdpTransportTarget((agent_host, agent_port), timeout=2, retries=0)
    ctx = ContextData()

    #use a standard notification (coldStart) so hlapi adds sysUpTime.0 & snmpTrapOID.0
    ntf = NotificationType(ObjectIdentity('1.3.6.1.6.3.1.1.5.1'))

    try:
        ei, es, ei2, vbs = next(sendNotification(
            SnmpEngine(), authData, transport, ctx,
            'inform', ntf
        ))
        if ei:
            logging.warning("inform ei: %s", ei)
            return False
        if es:
            logging.warning("inform es: %s", es.prettyPrint())
            return False
        logging.info("inform acknowledged by agent")
        return True
    except StopIteration:
        logging.warning("inform iterator StopIteration without result")
        return False
    except Exception as e:
        logging.warning("inform exception: %s", e)
        return False

def main():
    used_ids = set()
    last_key_id = None

    while True:
        #1. get fresh key
        key_bytes, key_b64, key_id = get_enc_key_from_kms(MASTER_KMS_BASE, MASTER_APP_ID)
        if not key_id:
            logging.info("kms has no material yet, sleeping 3s…")
            time.sleep(3)
            continue
        if key_id == last_key_id or key_id in used_ids:
            logging.info("no new key_ID (last=%s). seen=%s, sleeping 2s…",
                         last_key_id, key_id in used_ids)
            time.sleep(2)
            continue

        #2. tell agent which key to fetch
        if not post_key_id_to_agent(KMS_URL_TO_AGENT, USERNAME, key_id, timeout_sec=5):
            time.sleep(2)
            continue

        #2.5. wait until agent applies the key
        if not wait_key_applied(AGENT_HOST, key_id, max_wait_s=6.0):
            #skip this key_ID to avoid sending an undecipherable INFORM
            used_ids.add(key_id)
            last_key_id = key_id
            time.sleep(1)
            continue

        #3. send exactly one INFORM with that key
        ok = run_snmp_inform(AGENT_HOST, AGENT_PORT, USERNAME, AUTH_PASS, key_bytes)
        used_ids.add(key_id)
        last_key_id = key_id

        #short breather
        time.sleep(1.0)

if __name__ == "__main__":
    main()
