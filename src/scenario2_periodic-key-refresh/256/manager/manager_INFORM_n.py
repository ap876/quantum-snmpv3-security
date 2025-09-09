#!/usr/bin/env python3
#-- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/manager/cmdgen/usm-sha-aes128.py

"""
snmpv3 hlapi client (inform) with kms integration — strictly aes-256

flow:
- maintains an "active key" until it expires (--rekey-interval seconds)
- when renewal is due: GET enc_key (256-bit) from master kms -> POST key_ID to agent /kms -> POLL /kms/ready -> if applied=true, activate the key
- sends one snmp INFORM (coldStart) with sha+aes-256 (authPriv) every --send-interval seconds

robust kms GET:
- prefers requests (Accept-Encoding: identity), with a curl fallback for odd servers/responses
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
    usmHMACSHAAuthProtocol
)

try:
    from pysnmp.hlapi import usmAesCfb256Protocol
except Exception as e:
    raise RuntimeError("pysnmp installation lacks AES-256 (usmAesCfb256Protocol)") from e

def parse_args():
    p = argparse.ArgumentParser(description="snmpv3 INFORM client (aes-256) + master kms integration")
    p.add_argument("--agent-host", default="127.0.0.1", help="snmp agent host (default 127.0.0.1)")
    p.add_argument("--agent-port", type=int, default=50161, help="snmp agent port (default 50161)")
    p.add_argument("--http-port", type=int, default=8080, help="agent http port for /kms and /kms/ready (default 8080)")
    p.add_argument("--user", default="usr-sha-aes256", help="usm username (default usr-sha-aes256)")
    p.add_argument("--auth-pass", default="authkey1", help="usm auth password (SHA)")
    p.add_argument("--master-kms-base", default="http://10.250.0.2", help="master kms base url")
    p.add_argument("--master-app-id", default="aaac7de9-5826-11ef-8057-9b39f247aaa", help="master kms app_id")
    p.add_argument("--rekey-interval", type=int, default=30, help="seconds to reuse active key (default 30)")
    p.add_argument("--send-interval", type=float, default=1.0, help="seconds between INFORM messages (default 1.0)")
    p.add_argument("--ready-timeout", type=float, default=8.0, help="max wait for agent to apply key (s)")
    return p.parse_args()

args = parse_args()

#log
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.info("client start — host=%s:%d  rekey=%ss  send=%.1fs",
             args.agent_host, args.agent_port, args.rekey_interval, args.send_interval)

#kms-urls
KMS_URL_TO_AGENT = f"http://{args.agent_host}:{args.http_port}/kms"
KMS_READY_URL    = f"http://{args.agent_host}:{args.http_port}/kms/ready"

def _derive_aes256(k: bytes) -> bytes:
    return k if len(k) == 32 else hashlib.sha256(k).digest()

def _trim_to_json(raw: str) -> str:
    i = raw.find("{")
    return raw[i:] if i >= 0 else raw

def get_enc_key_from_kms(master_base: str, app_id: str, size_bits=256) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    """
    returns (key_bytes, key_b64, key_ID) or (None, None, None)
    tries requests first (Accept-Encoding: identity); falls back to curl if headers/parsing fail
    """
    url = f"{master_base.rstrip('/')}/api/v1/keys/{app_id}/enc_keys/number/1/size/{size_bits}"
    logging.info("step 1 – kms GET: %s", url)

    #requests-first
    try:
        r = requests.get(
            url, timeout=10,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "User-Agent": "Wget/1.21",
                "Connection": "close"
            }
        )
        if r.status_code == 200:
            try:
                data = json.loads(_trim_to_json(r.text))
                item = data["keys"][0]
                key_b64 = item["key"].strip()
                key_id  = item.get("key_ID") or item.get("id") or item.get("key_id")
                key_bytes = base64.b64decode(key_b64)
                if len(key_bytes) not in (16, 24, 32):
                    return None, None, None
                logging.info("step 1 ok – key_ID=%s len=%dB", key_id, len(key_bytes))
                return key_bytes, key_b64, key_id
            except Exception as e:
                logging.warning("step 1 parse error (requests): %s", e)
        else:
            logging.warning("step 1 status=%s (requests)", r.status_code)
    except Exception as e:
        logging.warning("kms GET transport error (requests): %s", e)

    #curl-fallback
    try:
        raw = subprocess.check_output(
            ["curl","--fail","--silent","--show-error","--max-time","10",
             "-H","Accept: application/json",
             "-H","Accept-Encoding: identity",
             "-H","Connection: close",
             url],
            stderr=subprocess.STDOUT, timeout=12
        ).decode("utf-8","replace")
        data = json.loads(_trim_to_json(raw))
        item = data["keys"][0]
        key_b64 = item["key"].strip()
        key_id  = item.get("key_ID") or item.get("id") or item.get("key_id")
        key_bytes = base64.b64decode(key_b64)
        if len(key_bytes) not in (16, 24, 32):
            return None, None, None
        logging.info("step 1 ok (curl) – key_ID=%s len=%dB", key_id, len(key_bytes))
        return key_bytes, key_b64, key_id
    except Exception as e:
        logging.warning("step 1 curl failed: %s", e)
        return None, None, None

def post_key_id_to_agent(url: str, user: str, key_id: str, timeout_sec: int = 5) -> bool:
    payload = {"user": user, "key_ID": key_id}
    logging.info("step 2 – POST %s payload=%s", url, payload)
    try:
        resp = requests.post(
            url, json=payload, timeout=timeout_sec,
            headers={"Content-Type":"application/json","Accept":"application/json","Connection":"close"}
        )
        if resp.status_code == 200:
            logging.info("step 2 ok – agent accepted key_ID")
            return True
        logging.warning("step 2 status=%s body=%s", resp.status_code, (resp.text or "").strip())
        return False
    except Exception as e:
        logging.warning("/kms transport error: %s", e)
        return False

def wait_ready(agent_host: str, http_port: int, key_id: str, max_wait_s: float) -> bool:
    url = f"http://{agent_host}:{http_port}/kms/ready?key_ID={key_id}"
    deadline = time.time() + max_wait_s
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=1.2)
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

def send_inform(user: str, auth_pass: str, priv_key: bytes) -> bool:
    """send one snmpv3 INFORM (coldStart) with sha+aes-256."""
    authData = UsmUserData(
        userName=user,
        authKey=auth_pass, authProtocol=usmHMACSHAAuthProtocol,
        privKey=_derive_aes256(priv_key), privProtocol=usmAesCfb256Protocol
    )
    transport = UdpTransportTarget((args.agent_host, args.agent_port), timeout=2, retries=0)
    ctx = ContextData()
    ntf = NotificationType(ObjectIdentity('1.3.6.1.6.3.1.1.5.1'))  #coldStart

    try:
        ei, es, ei2, vbs = next(sendNotification(SnmpEngine(), authData, transport, ctx, 'inform', ntf))
        if ei:
            logging.warning("inform EI: %s", ei)
            return False
        if es:
            logging.warning("inform ES: %s", es.prettyPrint())
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
    current_key: Optional[bytes] = None
    current_key_id: Optional[str] = None
    key_expire_at = 0.0

    while True:
        now = time.time()
        #renew key if missing or expired
        if (current_key is None) or (now >= key_expire_at):
            key_bytes, _, key_id = get_enc_key_from_kms(args.master_kms_base, args.master_app_id, size_bits=256)
            if not key_id:
                time.sleep(2)
                continue
            if not post_key_id_to_agent(KMS_URL_TO_AGENT, args.user, key_id, timeout_sec=5):
                time.sleep(2)
                continue
            if not wait_ready(args.agent_host, args.http_port, key_id, max_wait_s=args.ready_timeout):
                #do not activate this key_id to avoid sending undecipherable INFORMs
                time.sleep(1)
                continue
            #activate
            current_key     = key_bytes
            current_key_id  = key_id
            key_expire_at   = time.time() + max(1, int(args.rekey_interval))

        #send one INFORM
        send_inform(args.user, args.auth_pass, current_key)
        time.sleep(max(0.1, float(args.send_interval)))

if __name__ == "__main__":
    main()
