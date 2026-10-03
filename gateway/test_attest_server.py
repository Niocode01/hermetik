"""Tests del servidor de atestación de transporte (F4).

La propiedad central NO es "el mock funciona": es que
  1. el modo real FALLA en vez de degradar a dev (regla dura ADR-01),
  2. el quote de desarrollo lleva el marcador obligatorio e inconfundible,
  3. el handshake falla cerrado ante nonce/client_pub malformados,
  4. el servidor deriva la MISMA clave que un cliente WebCrypto real (interop
     byte a byte contra `attest_interop.mjs`, espejo de session.ts).
"""

import base64
import hashlib
import json
import shutil
import subprocess

import pytest

from attest_server import (
    EPHEMERAL_MAX,
    EPHEMERAL_TTL_NS,
    AttestMode,
    AttestServer,
    AttestServerError,
    expected_report_data,
    from_env,
)

BIN = "ab" * 32  # sha256 hex de 64 chars de pega
NONCE = "0" * 64  # 64 chars hex, > 32

NODE = shutil.which("node")
INTEROP = __import__("os").path.join(
    __import__("os").path.dirname(__file__), "attest_interop.mjs"
)


def test_dev_quote_marked_and_shaped():
    s = AttestServer(AttestMode.DEV, BIN)
    q = s.attest(NONCE)
    assert q["attestation_state"] == "dev-unattested"
    assert q["quote"].startswith("dev-unattested:")
    assert q["vendor"] == "dev"
    assert q["binary_hash"] == BIN
    assert q["expires_at"] > 0
    # session_pub es base64 de 32 bytes → 44 chars con padding.
    assert len(base64.b64decode(q["session_pub"])) == 32


def test_dev_quote_report_data_matches_expected():
    s = AttestServer(AttestMode.DEV, BIN)
    q = s.attest(NONCE)
    rd = expected_report_data(NONCE, BIN)
    assert q["quote"] == f"dev-unattested:{rd}|dev-root,sig=dev"


def test_real_mode_fails_instead_of_degrading():
    s = AttestServer(AttestMode.SEV_SNP, BIN, vendor="amd-sev-snp")
    with pytest.raises(AttestServerError):
        s.attest(NONCE)


def test_unknown_mode_rejected():
    with pytest.raises(AttestServerError):
        AttestServer("bogus", BIN)  # type: ignore[arg-type]


def test_bad_binary_hash_rejected():
    with pytest.raises(AttestServerError):
        AttestServer(AttestMode.DEV, "not-hex")
    with pytest.raises(AttestServerError):
        AttestServer(AttestMode.DEV, "ab" * 31)  # 62 chars


def test_short_nonce_rejected():
    s = AttestServer(AttestMode.DEV, BIN)
    with pytest.raises(AttestServerError):
        s.attest("short")
    with pytest.raises(AttestServerError):
        s.session("short", base64.b64encode(b"\x00" * 32).decode())


def test_session_without_attest_rejected():
    s = AttestServer(AttestMode.DEV, BIN)
    with pytest.raises(AttestServerError):
        s.session(NONCE, base64.b64encode(b"\x11" * 32).decode())


def test_session_bad_client_pub_rejected():
    s = AttestServer(AttestMode.DEV, BIN)
    s.attest(NONCE)
    with pytest.raises(AttestServerError):
        s.session(NONCE, "not-base64!!!")
    with pytest.raises(AttestServerError):
        s.session(NONCE, base64.b64encode(b"\x11" * 31).decode())  # 31 B


def test_session_key_never_equals_session_id():
    s = AttestServer(AttestMode.DEV, BIN)
    s.attest(NONCE)
    client_pub = base64.b64encode(b"\x22" * 32).decode()
    est = s.session(NONCE, client_pub)
    assert len(est.session_key) == 32
    # El session_id es un hash de la clave, no la clave: no debe poder
    # invertirse trivialmente ni confundirse con ella.
    assert est.session_id == hashlib.sha256(est.session_key).hexdigest()
    assert est.session_id != est.session_key.hex()


def test_session_deterministic_for_same_inputs():
    # Mismo nonce + client_pub ⇒ misma clave (el keypair efímero queda fijado
    # por el nonce en `attest`). Dos nonces distintos con el MISMO client_pub
    # derivan claves distintas por el transcript. Nota: cada nonce es
    # single-use (run-5 B-02) — no se puede llamar dos veces con el mismo.
    s = AttestServer(AttestMode.DEV, BIN)
    client_pub = base64.b64encode(b"\x22" * 32).decode()
    s.attest(NONCE)
    a = s.session(NONCE, client_pub)
    nonce2 = "1" * 64
    s.attest(nonce2)
    b = s.session(nonce2, client_pub)
    assert a.session_key != b.session_key


def test_transcript_format_exact():
    s = AttestServer(AttestMode.DEV, BIN)
    q = s.attest(NONCE)
    client_raw = b"\x22" * 32
    est = s.session(NONCE, base64.b64encode(client_raw).decode())
    rd = expected_report_data(NONCE, BIN)
    expected = f"{NONCE}|{client_raw.hex()}|{q['session_pub']}|{rd}|dev"
    assert est.transcript == expected


@pytest.mark.skipif(NODE is None, reason="node no disponible")
def test_interop_with_node_client():
    """El servidor Python y un cliente WebCrypto derivan la MISMA clave.

    Este es el eslabón que no se puede probar con un solo lado: verifica que el
    orden del transcript, el IKM y los parámetros HKDF coinciden byte a byte
    con la implementación real del navegador (session.ts, vía WebCrypto).
    """
    s = AttestServer(AttestMode.DEV, BIN)
    q = s.attest(NONCE)

    payload = json.dumps(
        {
            "nonce": NONCE,
            "binaryHash": BIN,
            "sessionPubB64": q["session_pub"],
            "vendor": q["vendor"],
        }
    )
    out = subprocess.run(
        [NODE, INTEROP, payload],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    client = json.loads(out.stdout)

    est = s.session(NONCE, client["clientPubB64"])
    assert est.session_key.hex() == client["clientKeyHex"]


def test_from_env_dev_explicit(monkeypatch):
    monkeypatch.setenv("HERMETIK_BINARY_HASH", BIN)
    monkeypatch.setenv("DEV_ATTEST", "1")
    s = from_env()
    assert s.mode is AttestMode.DEV


def test_from_env_requires_binary_hash(monkeypatch):
    monkeypatch.delenv("HERMETIK_BINARY_HASH", raising=False)
    with pytest.raises(AttestServerError):
        from_env()


def test_from_env_real_without_dev_flag(monkeypatch):
    monkeypatch.setenv("HERMETIK_BINARY_HASH", BIN)
    monkeypatch.delenv("DEV_ATTEST", raising=False)
    s = from_env()
    assert s.mode in (AttestMode.SEV_SNP, AttestMode.TDX)
    # Y emitir un quote en modo real falla (no hay TEE).
    with pytest.raises(AttestServerError):
        s.attest(NONCE)


# ------------------------------------------------------------------ run-5 B-02


def _server_with_clock(start_ns: int = 1_000_000_000_000):
    now = [start_ns]
    s = AttestServer(AttestMode.DEV, BIN, now_ns=lambda: now[0])
    return s, now


def _nonce(i: int) -> str:
    return f"{i:064x}"  # 64 hex chars, >= 32


def test_nonce_single_use_second_session_rejected():
    s, _ = _server_with_clock()
    client_pub = base64.b64encode(b"\x22" * 32).decode()
    s.attest(NONCE)
    s.session(NONCE, client_pub)  # consume
    with pytest.raises(AttestServerError):
        s.session(NONCE, client_pub)  # replay del nonce → rechazado


def test_ephemeral_expires_after_ttl():
    s, now = _server_with_clock()
    s.attest(NONCE)
    now[0] += EPHEMERAL_TTL_NS + 1
    s.attest(_nonce(1))  # este attest purga el anterior por TTL
    assert NONCE not in s._ephemeral
    assert _nonce(1) in s._ephemeral


def test_ephemeral_cap_evicts_oldest():
    s, _ = _server_with_clock()
    for i in range(EPHEMERAL_MAX + 5):
        s.attest(_nonce(i))
    assert len(s._ephemeral) <= EPHEMERAL_MAX
    # Los más viejos salieron; los recientes quedan.
    assert _nonce(EPHEMERAL_MAX + 4) in s._ephemeral
    assert _nonce(0) not in s._ephemeral
