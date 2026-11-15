#!/usr/bin/env python3
"""End-to-end demo of the TrapKey loop, no external deps.

    python3 demo/demo.py

Starts the server on a throwaway data dir, then:
  create product -> issue key -> activate -> verify offline -> revoke -> denied
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "cli"))

PORT = int(os.environ.get("DEMO_PORT", "7199"))
BASE = f"http://127.0.0.1:{PORT}"
HWID = "c0ffee00c0ffee00c0ffee00c0ffee00"


def call(method: str, path: str, body: dict | None = None, admin_key: str | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("content-type", "application/json")
    if admin_key:
        req.add_header("x-admin-key", admin_key)
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            return res.status, json.loads(res.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def wait_health(timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _ = call("GET", "/health")
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(0.15)
    return False


def verify_locally(token: str, n: str, e: str) -> dict:
    """Independent offline check, exactly what the C++ SDK does."""
    import base64

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    body_b64, sig_b64 = token.split(".")
    modulus = int.from_bytes(base64.urlsafe_b64decode(n + "=" * (-len(n) % 4)), "big")
    pub = rsa.RSAPublicNumbers(int(e, 16), modulus).public_key()
    sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    pub.verify(sig, body_b64.encode(), padding.PKCS1v15(), hashes.SHA256())
    claims = json.loads(base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4)))
    return claims


def main() -> int:
    data_dir = Path(tempfile.mkdtemp(prefix="trapkey-demo-"))
    env = {**os.environ, "PORT": str(PORT), "TRAPKEY_DATA": str(data_dir / "data.json")}

    print(f"starting server on {BASE} (data: {data_dir})")
    server = subprocess.Popen(
        ["node", str(ROOT / "server" / "src" / "index.js")],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    try:
        if not wait_health():
            print("server did not start", file=sys.stderr)
            return 1

        admin_key = (data_dir / "admin.key").read_text().strip()

        status, res = call("POST", "/v1/products", {"name": "Demo Desktop App"}, admin_key)
        product = res["data"]
        print(f"\n1. product      : {product['id']} ({product['name']})")
        print(f"   embed in app : n={product['verifyKey']['n'][:24]}…  e={product['verifyKey']['e']}")

        status, res = call(
            "POST",
            "/v1/keys",
            {"productId": product["id"], "days": 365, "seats": 1, "features": ["pro"]},
            admin_key,
        )
        key = res["data"]["created"][0]
        print(f"2. issued key   : {key}")

        status, res = call("POST", "/v1/activate", {"key": key, "productId": product["id"], "hwid": HWID})
        assert status == 200, res
        token = res["data"]["license"]
        print(f"3. activated    : token {len(token)} bytes, expires {res['data']['claims']['exp']}")

        claims = verify_locally(token, product["verifyKey"]["n"], product["verifyKey"]["e"])
        print(f"4. offline check: signature OK, hwid match = {claims['hwid'] == HWID}, features={claims['feat']}")

        status, res = call("POST", "/v1/activate", {"key": key, "productId": product["id"], "hwid": "ffff" * 8})
        print(f"5. seat limit   : HTTP {status} {res['error']['code']}")

        status, res = call("POST", f"/v1/keys/{key}/revoke", {"reason": "demo"}, admin_key)
        print(f"6. revoked      : status={res['data']['status']}")

        status, res = call("POST", "/v1/validate", {"license": token, "hwid": HWID})
        print(f"7. after revoke : validate -> valid={res['data']['valid']} reason={res['data'].get('reason')}")

        status, res = call("POST", "/v1/activate", {"key": key, "productId": product["id"], "hwid": HWID})
        print(f"8. reactivate   : HTTP {status} {res['error']['code']}")

        print("\ndone. every step above is real HTTP against the real server.")
        return 0
    finally:
        server.send_signal(signal.SIGTERM)
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
        shutil.rmtree(data_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
