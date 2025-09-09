#!/usr/bin/env python3
#-- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/manager/cmdgen/usm-sha-aes128.py

"""
snmpv3 hlapi client (inform) with kms integration — aes-128
mode:
  - every --rekey-interval seconds fetch a NEW key (master kms -> 128-bit enc_key)
  - post key_ID to the agent at /kms
  - wait on /kms/ready?key_ID=... up to --ready-timeout seconds (default = rekey-interval)
  - send informs every --send-interval seconds until the next rekey
strictly no /qkd fallback.
"""

import argparse
import base64
import hashlib
import json
import logging
import subprocess
import time
from typing import Optional, Tuple

import requests
from pysnmp.hlapi import (
    SnmpEngine, UdpTransportTarget, ContextData,
    UsmUserData, ObjectIdentity, NotificationType, sendNotification,
    usmHMACSHAAuthProtocol, usmAesCfb128Protocol
)

#logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.WARNING)

#defaults
AGENT_HOST = "127.0.0.1"
AGENT_PORT = 50161
HTTP_PORT  = 8080
USERNAME   = "usr-sha-aes128"
AUTH_PASS  = "authkey1"

MASTER_KMS_BASE = "http://10.250.0.2"
MASTER_APP_ID   = "aaac7de9-5826-11ef-8057-9b39f247aaa"

def _derive_aes128(key_bytes: bytes) -> bytes:
    #return 16B key; if not 16B, derive via sha256 and take first 16B
    return key_bytes if len(key_bytes) == 16 else hashlib.sha256(key_bytes).digest()[:16]

def _trim_to_json(raw: str) -> str:
    #strip any banners before the first '{'
    i = raw.find("{")
    return raw[i:] if i >= 0 else raw

def get_enc_key_from_kms(master_base: str, app_id: str, size_bits=128) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    #prefer requests (no proxy); fallback to curl with --noproxy '*'
    url = f"{master_base}/api/v1/keys/{app_id}/enc_keys/number/1/size/{size_bits}"
    logging.info("step 1 – kms get: %s", url)

    raw = None
    try:
        r = requests.get(
            url, timeout=10,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "User-Agent": "Wget/1.21",
                "Connection": "close",
            },
            proxies={"http": None, "https": None},
        )
        if r.status_code == 200:
            raw = r.text
        elif r.status_code == 400:
            return None, None, None
    except Exception as e:
        logging.warning("kms get transport error (requests): %s", e)
        raw = None

    if raw is None:
        try:
            raw = subprocess.check_output(
                ["curl","--fail","--silent","--show-error","--max-time","10",
                 "--noproxy","*",
                 "-H","Accept: application/json",
                 "-H","Accept-Encoding: identity",
                 "-H","Connection: close",
                 url],
                stderr=subprocess.STDOUT, timeout=12
            ).decode("utf-8","replace")
        except Exception as e:
            logging.warning("kms get transport error (curl): %s", e)
            return None, None, None

    try:
        data = json.loads(_trim_to_json(raw))
        item = data["keys"][0]
        key_b64 = item["key"].strip()
        key_id  = item.get("key_ID") or item.get("id") or item.get("key_id")
        key_bytes = base64.b64decode(key_b64)
        if len(key_bytes) not in (16, 24, 32):
            return None, None, None
        logging.info("step 1 ok – key_ID=%s len=%dB", key_id, len(key_bytes))
        return key_bytes, key_b64, key_id
    except Exception:
        return None, None, None

def post_key_id_to_agent(agent_host: str, http_port: int, user: str, key_id: str, timeout_sec: int = 5) -> bool:
    #tell the agent which key_ID to pull and apply
    url = f"http://{agent_host}:{http_port}/kms"
    payload = {"user": user, "key_ID": key_id}
    logging.info("step 2 – post %s payload=%s", url, payload)
    try:
        resp = requests.post(
            url, json=payload, timeout=timeout_sec,
            headers={"Content-Type":"application/json","Accept":"application/json","Connection":"close"},
            proxies={"http": None, "https": None},
        )
        if resp.status_code == 200:
            logging.info("step 2 ok – agent accepted key_ID")
            return True
        logging.warning("step 2 failed: status=%s body=%s", resp.status_code, resp.text.strip())
        return False
    except Exception as e:
        logging.warning("/kms transport error: %s", e)
        return False

def wait_ready(agent_host: str, http_port: int, key_id: str, max_wait_s: float) -> bool:
    #poll /kms/ready?key_ID=... until {"applied": true} or timeout
    url = f"http://{agent_host}:{http_port}/kms/ready?key_ID={key_id}"
    deadline = time.time() + max_wait_s
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=1.0, proxies={"http": None, "https": None})
            if r.status_code == 200:
                j = r.json()
                if j.get("applied"):
                    logging.info("step 2.5 – agent applied key (key_ID=%s)", key_id)
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    logging.warning("step 2.5 – agent did not apply key in time (key_ID=%s)", key_id)
    return False

def send_inform(agent_host: str, agent_port: int, user: str, auth_pass: str, priv_key_bytes: bytes) -> bool:
    #send a single snmpv3 inform (coldStart) with sha+aes-128 (authPriv)
    authData = UsmUserData(
        userName=user,
        authKey=auth_pass, authProtocol=usmHMACSHAAuthProtocol,
        privKey=_derive_aes128(priv_key_bytes), privProtocol=usmAesCfb128Protocol
    )
    transport = UdpTransportTarget((agent_host, agent_port), timeout=2, retries=0)
    ctx = ContextData()
    ntf = NotificationType(ObjectIdentity('1.3.6.1.6.3.1.1.5.1'))  #coldStart
    try:
        ei, es, ei2, vbs = next(sendNotification(SnmpEngine(), authData, transport, ctx, 'inform', ntf))
        if ei:
            logging.warning("inform ei: %s", ei);  return False
        if es:
            logging.warning("inform es: %s", es.prettyPrint());  return False
        logging.info("inform acknowledged by agent")
        return True
    except Exception as e:
        logging.warning("inform exception: %s", e)
        return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=AGENT_HOST)
    ap.add_argument("--snmp-port", type=int, default=AGENT_PORT)
    ap.add_argument("--http-port", type=int, default=HTTP_PORT)
    ap.add_argument("--rekey-interval", type=int, default=30)
    ap.add_argument("--send-interval", type=float, default=1.0)
    ap.add_argument("--ready-timeout", type=float, default=None,
                    help="if not set, defaults to --rekey-interval")
    args = ap.parse_args()

    ready_timeout = args.ready_timeout if args.ready_timeout is not None else float(args.rekey_interval)

    logging.info("client start — host=%s:%d  rekey=%ss  send=%.1fs  ready-timeout=%.1fs",
                 args.host, args.snmp_port, args.rekey_interval, args.send_interval, ready_timeout)

    current_key_bytes = None
    current_key_id = None
    next_rekey_at = 0.0

    while True:
        now = time.time()
        if now >= next_rekey_at or not current_key_bytes:
            #1. fetch fresh key from master kms
            kb, kb64, kid = get_enc_key_from_kms(MASTER_KMS_BASE, MASTER_APP_ID, size_bits=128)
            if not kid:
                time.sleep(3); continue

            #2. announce key_ID to agent
            if not post_key_id_to_agent(args.host, args.http_port, USERNAME, kid, timeout_sec=5):
                time.sleep(2); continue

            #2.5. wait until agent applies the key
            if not wait_ready(args.host, args.http_port, kid, max_wait_s=ready_timeout):
                #skip this key and try the next one
                time.sleep(1); continue

            current_key_bytes = kb
            current_key_id = kid
            next_rekey_at = now + args.rekey_interval

        #3. send inform at the configured rate until rekey time
        send_inform(args.host, args.snmp_port, USERNAME, AUTH_PASS, current_key_bytes)
        time.sleep(args.send_interval)

if __name__ == "__main__":
    main()
