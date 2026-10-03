#!/usr/bin/env python3
"""F5-gateway: camino canal attest -> session -> echo contra gateway vivo.

Uso: python3 matrix_f5_gateway.py [base_url]
Requiere el gateway en vivo (p.ej. run_f5.py en :18791, DEV_ATTEST=1).

Prueba lo que los unit tests no cubren: el servidor REAL deriva la MISMA
clave que un cliente X25519 externo (re-derivación independiente con el
transcript exacto de attest_server.session), session_id cuadra por hash,
y el eco cifrado ida+vuelta abre con la clave derivada.
"""
import base64
import hashlib
import json
import sys
import urllib.request

sys.path.insert(0, "/opt/data/hermetik/gateway")
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from attest_server import INFO, SESSION_KEY_BYTES, expected_report_data
from channel import Channel

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18791"
PASS = FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print(f"  ✓ {msg}")


def ko(msg):
    global FAIL
    FAIL += 1
    print(f"  ✗ {msg}")


def get(path, headers=None):
    req = urllib.request.Request(BASE + path, headers=headers or {})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, json.load(r)


def post(path, body, headers=None):
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(
        BASE + path, data=json.dumps(body).encode(), headers=h
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, json.load(r)


print("== F5-G1 health nunca oculta atestación ==")
st, h = get("/health")
if st == 200 and h.get("attestation_state") == "dev-unattested":
    ok("health 200 + dev-unattested visible")
else:
    ko(f"health inesperado: {st} {h}")

print("== F5-G2 attest emite quote ligado ==")
import secrets

nonce = secrets.token_hex(32)
st, q = get(f"/v1/attest?nonce={nonce}")
spub_b64 = q.get("session_pub", "")
if (
    st == 200
    and q.get("quote", "").startswith("dev-unattested:")
    and len(base64.b64decode(spub_b64)) == 32
):
    ok("quote dev + session_pub 32B")
else:
    ko(f"attest inesperado: {q}")

print("== F5-G3 session deriva clave ligada (re-derivación independiente) ==")
spub = base64.b64decode(spub_b64)
priv = X25519PrivateKey.generate()
cpub = priv.public_key().public_bytes_raw()
st, s = post(
    "/v1/session",
    {"nonce": nonce, "client_pub": base64.b64encode(cpub).decode()},
)
sid = s.get("session_id", "")
shared = priv.exchange(X25519PublicKey.from_public_bytes(spub))
report_data = expected_report_data(nonce, q["binary_hash"])
transcript = f"{nonce}|{cpub.hex()}|{spub_b64}|{report_data}|{q['vendor']}"
ikm = shared + report_data.encode()
key = HKDF(
    algorithm=hashes.SHA256(),
    length=SESSION_KEY_BYTES,
    salt=transcript.encode(),
    info=INFO,
).derive(ikm)
if sid and hashlib.sha256(key).hexdigest() == sid:
    ok("session_id = sha256(maestra) — servidor y cliente coinciden")
    ch = Channel(key, role="client")  # cliente: sella c2s, abre s2c (B-01)
else:
    ko(f"session_id no cuadra: {s}")
    ch = None

print("== F5-G4 echo cifrado ida+vuelta ==")
if ch is not None:
    msg = ch.seal("hola hermetik F5")
    st, reply = post(
        "/v1/echo",
        {"session_id": sid, "seq": msg["seq"], "sealed": msg["sealed"]},
    )
    try:
        txt = ch.open(reply["seq"], reply["sealed"])
    except Exception as exc:  # noqa: BLE001
        txt = f"ERROR: {exc}"
    if txt == "echo: hola hermetik F5":
        ok("eco descifrado con la clave derivada")
    else:
        ko(f"eco no cuadra: {txt!r}")
else:
    ko("sin canal (G3 falló)")

print()
print("===================================")
print(f"  PASS: {PASS}   FAIL: {FAIL}")
print("===================================")
sys.exit(1 if FAIL else 0)
