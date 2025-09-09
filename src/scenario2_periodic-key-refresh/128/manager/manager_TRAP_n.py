#!/usr/bin/env python3
#-- coding: utf-8 --
# original code basis: https://github.com/etingof/pysnmp
# file path: examples/v3arch/asyncore/manager/cmdgen/usm-sha-aes128.py

"""
snmpv3 client (authpriv: sha + aes-128) — trap variant with key lifetime (rekey interval)

flow:
 1) if the key is expired or missing: get enc_key (aes-128) from master kms → (key_ID, key)
 2) post key_ID to the agent at /kms → the agent fetches dec_key from slave kms
 3) poll /kms/ready?key_ID=... until the agent applies the key (or timeout)
 4) until the rekey interval expires: send snmp traps at --send-interval cadence
 5) go back to (1)

notes:
- trap is non-ack, so we only log local errors
- fallback to curl if kms responds with a wrong 'content-encoding: gzip'
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

def _derive_aes128(key_bytes: bytes) -> bytes:
  return key_bytes if len(key_bytes) == 16 else hashlib.sha256(key_bytes).digest()[:16]

def _trim_to_json(raw: str) -> str:
    i = raw.find("{")
    return raw[i:] if i >= 0 else raw

def get_enc_key_from_kms(master_base: str, app_id: str, n_keys=1, size_bits=128) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    url = f"{master_base}/api/v1/keys/{app_id}/enc_keys/number/{n_keys}/size/{size_bits}"
    logging.info("STEP 1 – KMS GET: %s", url)

    raw = None
    try:
        r = requests.get(
            url, timeout=10,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",  # request plain
                "User-Agent": "Wget/1.21",
                "Connection": "close",
            },
        )
        if r.status_code == 200:
            raw = r.text
        else:
            logging.warning("kms get http status=%s; trying curl…", r.status_code)
            raw = None
    except Exception as e:
        logging.warning("kms get transport error (requests): %r", e)
        raw = None

    if raw is None:
        #curl fallback (more robust to odd headers)
        try:
            raw = subprocess.check_output(
                ["curl","--fail","--silent","--show-error","--max-time","10",
                 "-H","Accept: application/json",
                 "-H","Accept-Encoding: identity",
                 "-H","Connection: close",
                 url],
                stderr=subprocess.STDOUT, timeout=12
            ).decode("utf-8","replace")
            logging.info("STEP 1 ok (curl)")
        except subprocess.CalledProcessError as e:
            logging.warning("STEP 1 curl fail: %s", e)
            return None, None, None
        except Exception:
            return None, None, None

    try:
        data = json.loads(_trim_to_json(raw))
        item = data["keys"][0]
        key_b64 = item["key"].strip()
        key_id  = item.get("key_ID") or item.get("id") or item.get("key_id")
        key_bytes = base64.b64decode(key_b64)
        if len(key_bytes) not in (16, 24, 32):
            logging.warning("unsupported key length: %dB", len(key_bytes))
            return None, None, None
        logging.info("STEP 1 ok – key_ID=%s len=%dB", key_id, len(key_bytes))
        return key_bytes, key_b64, key_id
    except Exception as e:
        logging.warning("STEP 1 parse/base64 error: %s", e)
        return None, None, None

def post_key_id_to_agent(url: str, user: str, key_id: str, timeout_sec: int = 5) -> bool:
    payload = {"user": user, "key_ID": key_id}
    logging.info("STEP 2 – POST %s payload=%s", url, payload)
    try:
        resp = requests.post(
            url, json=payload, timeout=timeout_sec,
            headers={"Content-Type": "application/json", "Accept": "application/json", "Connection": "close"}
        )
        if resp.status_code == 200:
            logging.info("STEP 2 ok – agent accepted key_ID")
            return True
        logging.warning("STEP 2 failed: status=%s body=%s", resp.status_code, resp.text.strip())
        return False
    except Exception as e:
        logging.warning("/kms transport error: %s", e)
        return False

def wait_key_applied(agent_host: str, agent_port_http: int, key_id: str, max_wait_s: float = 6.0) -> bool:
    """
    poll /kms/ready?key_ID=... until 'applied': true or timeout
    """
    deadline = time.time() + max_wait_s
    url = f"http://{agent_host}:{agent_port_http}/kms/ready?key_ID={key_id}"
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=1.0)
            if r.status_code == 200:
                j = r.json()
                if j.get("applied"):
                    logging.info("STEP 2.5 – agent applied key (key_ID=%s)", key_id)
                    return True
        except Exception:
            pass
        time.sleep(0.3)
    logging.warning("STEP 2.5 – agent did not apply the key in time (key_ID=%s)", key_id)
    return False

def send_trap(agent_host: str, agent_port_snmp: int, user: str, auth_pass: str, priv_key_bytes: bytes) -> bool:
    authData = UsmUserData(
        userName=user,
        authKey=auth_pass, authProtocol=usmHMACSHAAuthProtocol,
        privKey=_derive_aes128(priv_key_bytes), privProtocol=usmAesCfb128Protocol
    )
    transport = UdpTransportTarget((agent_host, agent_port_snmp), timeout=2, retries=0)
    ctx = ContextData()
    ntf = NotificationType(ObjectIdentity('1.3.6.1.6.3.1.1.5.1'))  # coldStart
    try:
        ei, es, _, _ = next(sendNotification(SnmpEngine(), authData, transport, ctx, 'trap', ntf))
        if ei:
            logging.warning("trap ei: %s", ei)
            return False
        if es:
            logging.warning("trap es: %s", es.prettyPrint())
            return False
        logging.info("trap sent (no ack).")
        return True
    except StopIteration:
        logging.warning("trap iterator StopIteration without result")
        return False
    except Exception as e:
        logging.warning("trap exception: %s", e)
        return False

def main():
    ap = argparse.ArgumentParser(description="snmpv3 trap aes-128 client with kms and rekey interval")
    ap.add_argument("--host", default="127.0.0.1", help="snmp agent host (default: 127.0.0.1)")
    ap.add_argument("--snmp-port", type=int, default=50161, help="snmp agent port (default: 50161)")
    ap.add_argument("--http-port", type=int, default=8080, help="agent http port (default: 8080)")
    ap.add_argument("--user", default="usr-sha-aes128", help="snmpv3 usm user")
    ap.add_argument("--auth-pass", default="authkey1", help="snmpv3 auth password (sha)")
    ap.add_argument("--master-kms", default="http://10.250.0.2", help="master kms base url")
    ap.add_argument("--master-app-id", default="aaac7de9-5826-11ef-8057-9b39f247aaa", help="master kms app_id")
    ap.add_argument("--rekey-interval", type=int, default=30, help="lifetime (seconds) of one key before rekey")
    ap.add_argument("--send-interval", type=float, default=1.0, help="interval between traps in seconds")
    args = ap.parse_args()

    logging.info("client start — host=%s:%d  rekey=%ss  send=%.1fs",
                 args.host, args.snmp_port, args.rekey_interval, args.send_interval)

    kms_to_agent_url = f"http://{args.host}:{args.http_port}/kms"

    current_key: Optional[bytes] = None
    current_key_id: Optional[str] = None
    key_expire_at: float = 0.0

    while True:
        now = time.time()
        need_new_key = current_key is None or now >= key_expire_at

        if need_new_key:
            #1.get fresh key
            key_bytes, _, key_id = get_enc_key_from_kms(args.master_kms, args.master_app_id, size_bits=128)
            if not key_id:
                logging.info("kms does not have enough material yet, sleeping 3s…")
                time.sleep(3)
                continue

            #2.announce key_ID to agent
            if not post_key_id_to_agent(kms_to_agent_url, args.user, key_id, timeout_sec=5):
                time.sleep(2)
                continue

            #3.)wait for agent to apply the key
            if not wait_key_applied(args.host, args.http_port, key_id, max_wait_s=30.0):
                #don't send trap with unapplied key — try again
                time.sleep(1)
                continue

            #activate locally
            current_key = key_bytes
            current_key_id = key_id
            key_expire_at = time.time() + args.rekey_interval
            logging.info("active key key_ID=%s until %s (%.0fs)",
                         current_key_id, time.strftime("%H:%M:%S", time.localtime(key_expire_at)), args.rekey_interval)

        #4.send trap at the configured rate until the window expires
        _ = send_trap(args.host, args.snmp_port, args.user, args.auth_pass, current_key)
        time.sleep(args.send_interval)
        #when window expires, next loop iteration will rekey

if __name__ == "__main__":
    main()
