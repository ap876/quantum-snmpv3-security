#!/usr/bin/env python3
#-- coding: utf-8 --
#original code basis: https://github.com/etingof/pysnmp
#file path: examples/hlapi/asyncore/ntforg/v3-trap.py
#adapted and extended for scenario 1 ("one message – one key") with kms integration, trap variant

"""
snmpv3 hlapi client (trap) with kms integration
policy: 1 TRAP = 1 key
- step 1: fetch enc_key (256-bit) from master kms
- step 2: post key_ID to agent /kms
- step 2.5: poll /kms/status?key_ID=... until agent applies the key
- step 3: send TRAP (hlapi) with callback

if pysnmp lacks AES-256 support, it falls back to AES-128.
"""

import base64
import hashlib
import json
import logging
import time
import subprocess
import requests

from pysnmp.hlapi import usmHMACSHAAuthProtocol, usmAesCfb128Protocol
from pysnmp.hlapi.asyncore import (
    SnmpEngine, UdpTransportTarget, ContextData, UsmUserData,
    sendNotification, NotificationType, ObjectIdentity
)
from pysnmp.proto import rfc1902

#try AES-256 first -> fall back to AES-128 if unavailable
try:
    from pysnmp.hlapi import usmAesCfb256Protocol
    PRIV_PROTO = usmAesCfb256Protocol
    PRIV_BITS = 256
except Exception:
    PRIV_PROTO = usmAesCfb128Protocol
    PRIV_BITS = 128

#logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.info("snmp privacy (client): AES-%d", PRIV_BITS)

#parameters
AGENT_HOST = "127.0.0.1"
AGENT_PORT = 50161
QKD_PORT   = 8080
USERNAME   = "usr-sha-aes"
AUTH_PASS  = "authkey1"

#master kms
MASTER_KMS_BASE = "http://10.250.0.2"
MASTER_APP_ID   = "aaac7de9-5826-11ef-8057-9b39f247aaa"

KMS_URL_TO_AGENT    = f"http://{AGENT_HOST}:{QKD_PORT}/kms"
KMS_STATUS_TO_AGENT = f"http://{AGENT_HOST}:{QKD_PORT}/kms/status"

def _derive_priv(key_bytes: bytes) -> bytes:
    #ensure exact key length for chosen privacy (32B for AES-256, 16B for AES-128)
    need = 32 if PRIV_BITS == 256 else 16
    if len(key_bytes) == need:
        return key_bytes
    return hashlib.sha256(key_bytes).digest()[:need]

def _trim_to_json(raw: str) -> str:
    #strip any proxy/banner noise before the first '{'
    i = raw.find("{")
    return raw[i:] if i >= 0 else raw

def get_enc_key_from_kms(master_base: str, app_id: str, n_keys: int = 1, size_bits: int = 256):
    #return (key_bytes, key_b64, key_ID) or (None, None, None)
    url = f"{master_base}/api/v1/keys/{app_id}/enc_keys/number/{n_keys}/size/{size_bits}"
    logging.info("step 1 – GET from master kms: %s", url)
    raw = None
    try:
        r = requests.get(
            url, timeout=10,
            headers={"Accept":"application/json","Accept-Encoding":"identity","User-Agent":"Wget/1.21","Connection":"close"},
        )
        if r.status_code == 200:
            raw = r.text
        elif r.status_code == 400:
            return None, None, None
    except Exception:
        raw = None

    #simple curl fallback for quirky lab setups
    if raw is None:
        try:
            raw = subprocess.check_output(
                ["curl","--fail","--silent","--show-error","--max-time","10",
                 "-H","Accept: application/json","-H","Accept-Encoding: identity","-H","Connection: close",url],
                stderr=subprocess.STDOUT, timeout=12
            ).decode("utf-8","replace")
        except Exception:
            return None, None, None

    try:
        data = json.loads(_trim_to_json(raw))
        item = data["keys"][0]
        key_b64 = item["key"].strip()
        key_id  = item.get("key_ID") or item.get("id") or item.get("key_id")
        key_bytes = base64.b64decode(key_b64)
        if len(key_bytes) not in (16,24,32):
            return None, None, None
        logging.info("step 1 done: enc_key len=%dB, key_ID=%s", len(key_bytes), key_id)
        return key_bytes, key_b64, key_id
    except Exception:
        return None, None, None

def post_key_id_to_agent(url: str, user: str, key_id: str, timeout_sec: int = 5) -> bool:
    #notify agent which key_ID to fetch from slave kms
    payload = {"user": user, "key_ID": key_id}
    logging.info("step 2 – POST /kms, payload=%s", payload)
    try:
        resp = requests.post(url, json=payload, timeout=timeout_sec,
                             headers={"Content-Type":"application/json","Accept":"application/json","Connection":"close"})
        if resp.status_code == 200:
            logging.info("step 2 done: /kms accepted")
            return True
        logging.warning("step 2 failed: status=%s body=%s", resp.status_code, resp.text.strip())
        return False
    except Exception as e:
        logging.warning("step 2 exception: %s", e)
        return False

def wait_agent_applied(status_url: str, key_id: str, attempts: int = 20, delay: float = 0.2) -> bool:
    #poll /kms/status until {"status":"processed"} or timeout
    for _ in range(attempts):
        try:
            r = requests.get(status_url, params={"key_ID": key_id}, timeout=2)
            if r.status_code == 200:
                st = (r.json() or {}).get("status")
                if st == "processed":
                    logging.info("step 2.5 – agent applied key (key_ID=%s)", key_id)
                    return True
                if st == "in-flight":
                    time.sleep(delay); continue
        except Exception:
            pass
        time.sleep(delay)
    logging.warning("step 2.5 – agent did not confirm 'processed' in time (key_ID=%s)", key_id)
    return False

def run_snmp_trap(agent_host: str, agent_port: int, user: str, auth_pass: str, priv_key_bytes: bytes):
    #send one snmpv3 TRAP (coldStart) with sha + aes-128/256 (authPriv), using async hlapi
    logging.info("step 3 – SNMP TRAP (HLAPI) — 1 message = 1 key")

    snmpEngine = SnmpEngine()
    user_data = UsmUserData(
        user,
        authKey=auth_pass,
        authProtocol=usmHMACSHAAuthProtocol,
        privKey=_derive_priv(priv_key_bytes),
        privProtocol=PRIV_PROTO
    )
    transport = UdpTransportTarget((agent_host, agent_port))
    context   = ContextData()

    def _cb(sendRequestHandle, errorIndication, errorStatus, errorIndex, varBinds, cbCtx):
        if errorIndication:
            logging.error("trap send failed: %s", errorIndication)
        else:
            logging.info("trap sent ok (handle=%s)", sendRequestHandle)

    #coldStart + one extra varbind for visibility
    sendNotification(
        snmpEngine, user_data, transport, context,
        'trap',
        NotificationType(ObjectIdentity('1.3.6.1.6.3.1.1.5.1')).addVarBinds(
            ((1,3,6,1,2,1,1,1,0), rfc1902.OctetString('TRAP test (AES-%d)' % PRIV_BITS)),
        ),
        cbFun=_cb,
    )

    #let async dispatcher flush the packet
    snmpEngine.transportDispatcher.runDispatcher(timeout=1.0)

def main():
    used_ids = set()
    while True:
        key_bytes, key_b64, key_id = get_enc_key_from_kms(MASTER_KMS_BASE, MASTER_APP_ID, size_bits=256)
        if not key_id:
            logging.info("kms has no material yet, sleeping 3s…")
            time.sleep(3); continue
        if key_id in used_ids:
            time.sleep(1); continue

        if not post_key_id_to_agent(KMS_URL_TO_AGENT, USERNAME, key_id, timeout_sec=5):
            time.sleep(2); continue

        wait_agent_applied(KMS_STATUS_TO_AGENT, key_id, attempts=30, delay=0.2)

        try:
            run_snmp_trap(AGENT_HOST, AGENT_PORT, USERNAME, AUTH_PASS, key_bytes)
        except Exception as e:
            logging.warning("trap exception: %s", e)

        used_ids.add(key_id)
        time.sleep(1)

if __name__ == "__main__":
    main()
