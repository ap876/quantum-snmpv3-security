#!/usr/bin/env python3
#-- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/manager/cmdgen/usm-sha-aes128.py

"""
snmpv3 hlapi client (trap) + kms — strictly aes-256 (cfb) with a key reuse window.
flow for each new key:
  1) get enc_key(256) from master kms -> (key_ID, key)
  2) post key_ID to agent at /kms -> agent pulls dec_key from slave kms
  3) poll /kms/ready?key_ID=... -> wait until agent applies the key (applied=true)
  4) for --rekey-interval seconds send traps every --send-interval using the same key
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
from pysnmp.hlapi.asyncore import (
    SnmpEngine, UdpTransportTarget, ContextData, UsmUserData,
    sendNotification, NotificationType, ObjectIdentity
)
from pysnmp.hlapi import usmHMACSHAAuthProtocol

#strictly require aes-256
try:
    from pysnmp.hlapi import usmAesCfb256Protocol
except Exception as e:
    raise RuntimeError("this pysnmp build lacks AES-256 (usmAesCfb256Protocol). install a build with AES-256.") from e

#logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.WARNING)

def _derive_aes256(key_bytes: bytes) -> bytes:
    return key_bytes if len(key_bytes) == 32 else hashlib.sha256(key_bytes).digest()

def _trim_to_json(raw: str) -> str:
    i = raw.find("{")
    return raw[i:] if i >= 0 else raw

def kms_get_enc_key(master_base: str, app_id: str, n_keys=1, size_bits=256) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    url = f"{master_base}/api/v1/keys/{app_id}/enc_keys/number/{n_keys}/size/{size_bits}"
    logging.info("step 1 – kms get: %s", url)

    raw = None
    try:
        r = requests.get(
            url,
            timeout=10,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Connection": "close",
                "User-Agent": "Wget/1.21",
            },
        )
        if r.status_code == 200:
            raw = r.text
        elif r.status_code == 400:
            return None, None, None
    except Exception as e:
        logging.warning("kms get (requests) error: %r", e)
        raw = None

    if raw is None:
        try:
            out = subprocess.check_output(
                [
                    "curl", "--fail", "--silent", "--show-error", "--max-time", "10",
                    "-H", "Accept: application/json",
                    "-H", "Accept-Encoding: identity",
                    "-H", "Connection: close",
                    url,
                ],
                stderr=subprocess.STDOUT,
                timeout=12,
            ).decode("utf-8", "replace")
            raw = out
            logging.info("step 1 ok (curl fallback)")
        except Exception as e:
            logging.warning("step 1 curl failed: %s", e)
            return None, None, None

    try:
        data = json.loads(_trim_to_json(raw))
        item = data["keys"][0]
        key_b64 = item["key"].strip()
        key_id = item.get("key_ID") or item.get("id") or item.get("key_id")
        key_bytes = base64.b64decode(key_b64)
        if len(key_bytes) not in (16, 24, 32):
            return None, None, None
        logging.info("step 1 ok – key_ID=%s len=%dB", key_id, len(key_bytes))
        return key_bytes, key_b64, key_id
    except Exception:
        return None, None, None

def agent_post_key_id(agent_host: str, qkd_port: int, user: str, key_id: str, timeout_sec=5) -> bool:
    url = f"http://{agent_host}:{qkd_port}/kms"
    payload = {"user": user, "key_ID": key_id}
    logging.info("step 2 – post %s payload=%s", url, payload)
    try:
        r = requests.post(
            url,
            json=payload,
            timeout=timeout_sec,
            headers={"Content-Type": "application/json", "Accept": "application/json", "Connection": "close"},
        )
        if r.status_code == 200:
            logging.info("step 2 ok – agent accepted key_ID")
            return True
        logging.warning("step 2 failed: status=%s body=%s", r.status_code, r.text.strip())
        return False
    except Exception as e:
        logging.warning("step 2 exception: %s", e)
        return False

def wait_applied(agent_host: str, qkd_port: int, key_id: str, max_wait_s: float) -> bool:
    """poll /kms/ready?key_ID=... until applied=true or timeout."""
    url = f"http://{agent_host}:{qkd_port}/kms/ready?key_ID={key_id}"
    deadline = time.time() + max_wait_s
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                j = r.json()
                if j.get("applied"):
                    logging.info("step 2.5 – agent applied key (key_ID=%s)", key_id)
                    return True
        except Exception:
            pass
        time.sleep(0.3)
    logging.warning("step 2.5 – agent did not confirm 'applied' in time (key_ID=%s)", key_id)
    return False

def send_trap_once(agent_host: str, agent_port: int, user: str, auth_pass: str, priv_key: bytes):
    snmpEngine = SnmpEngine()
    user_data = UsmUserData(
        userName=user,
        authKey=auth_pass, authProtocol=usmHMACSHAAuthProtocol,
        privKey=_derive_aes256(priv_key), privProtocol=usmAesCfb256Protocol,
    )
    transport = UdpTransportTarget((agent_host, agent_port), timeout=2, retries=0)
    ctx = ContextData()

    def _cb(h, ei, es, ei2, vbs, ctx2):
        if ei:
            logging.error("trap send error: %s", ei)
        elif es:
            logging.error("trap local ES: %s", es.prettyPrint())
        else:
            logging.info("trap sent (callback)")

    sendNotification(
        snmpEngine,
        user_data,
        transport,
        ctx,
        'trap',
        NotificationType(ObjectIdentity('1.3.6.1.6.3.1.1.5.1')),  # coldStart
        cbFun=_cb,
    )

    snmpEngine.transportDispatcher.runDispatcher(timeout=1.0)
    logging.info("trap sent (from send_trap_once)")

def main():
    ap = argparse.ArgumentParser(description="snmpv3 trap client (aes-256) + kms")
    ap.add_argument("--agent-host", default="127.0.0.1")
    ap.add_argument("--agent-port", type=int, default=50161)
    ap.add_argument("--qkd-port", type=int, default=8080)
    ap.add_argument("--user", default="usr-sha-aes256")
    ap.add_argument("--auth-pass", default="authkey1")
    ap.add_argument("--master-kms", default="http://10.250.0.2")
    ap.add_argument("--app-id", default="aaac7de9-5826-11ef-8057-9b39f247aaa")
    ap.add_argument("--rekey-interval", type=int, default=30, help="seconds a key remains active (reuse window)")
    ap.add_argument("--send-interval", type=float, default=1.0, help="seconds between traps while key is active")
    ap.add_argument("--apply-timeout", type=float, default=6.0, help="max wait for agent to apply key")
    args = ap.parse_args()

    logging.info(
        "client start — host=%s:%d  rekey=%ss  send=%.1fs  aes-256",
        args.agent_host, args.agent_port, args.rekey_interval, args.send_interval,
    )

    while True:
        key_bytes, _, key_id = kms_get_enc_key(args.master_kms, args.app_id, size_bits=256)
        if not key_id:
            logging.info("kms has no fresh material yet, sleeping 3s...")
            time.sleep(3)
            continue

        if not agent_post_key_id(args.agent_host, args.qkd_port, args.user, key_id, timeout_sec=5):
            time.sleep(2)
            continue

        if not wait_applied(args.agent_host, args.qkd_port, key_id, max_wait_s=args.apply_timeout):
            time.sleep(1)
            continue

        valid_until = time.time() + args.rekey_interval
        logging.info(
            "active key key_ID=%s until %s (+%ss)",
            key_id, time.strftime("%H:%M:%S", time.localtime(valid_until)), args.rekey_interval,
        )

        while time.time() < valid_until:
            try:
                send_trap_once(args.agent_host, args.agent_port, args.user, args.auth_pass, key_bytes)
            except Exception as e:
                logging.warning("trap exception: %s", e)
            time.sleep(args.send_interval)

if __name__ == "__main__":
    main()
