"""Tests del canal cifrado (F4 + run-5 B-01): AES-GCM con subclaves
direccionales + interop WebCrypto.

La propiedad central: el canal es exactamente el mismo en Python y en el
navegador. Un cifrado que solo funciona en un lado no sirve de nada — por eso
se prueba byte a byte contra WebCrypto (Node), además del anti-replay.

La propiedad de run-5 B-01: cada dirección cifra con su propia subclave
(c2s/s2c derivadas de la maestra), así el seq=1 del cliente y el seq=1 del
servidor NUNCA comparten (clave, nonce).
"""

import json
import os
import shutil
import subprocess

import pytest

from attest_server import INFO_C2S, INFO_S2C, derive_directional_keys
from channel import MAX_SEQ, Channel, open_message, seal_message

KEY = bytes(range(32))  # clave MAESTRA de 32 bytes determinista
NODE = shutil.which("node")
INTEROP = os.path.join(os.path.dirname(__file__), "channel_interop.mjs")


# ------------------------------------------------------------------ direccionales

def test_directional_keys_distinct_and_deterministic():
    c2s, s2c = derive_directional_keys(KEY)
    assert len(c2s) == 32 and len(s2c) == 32
    assert c2s != s2c  # sin esto, el fix B-01 no existiría
    assert derive_directional_keys(KEY) == (c2s, s2c)


def test_same_seq_both_directions_no_nonce_reuse():
    # El invariante de run-5 B-01: mismo seq en ambas direcciones → ct distintos
    # (claves distintas ⇒ nonces efectivos distintos).
    c2s, s2c = derive_directional_keys(KEY)
    a = seal_message(c2s, 1, "client-hello!")
    b = seal_message(s2c, 1, "server-reply!")
    assert a != b
    assert open_message(c2s, 1, a) == "client-hello!"
    assert open_message(s2c, 1, b) == "server-reply!"
    # Cruzado NO abre: la clave contraria no valida el tag.
    with pytest.raises(Exception):
        open_message(s2c, 1, a)
    with pytest.raises(Exception):
        open_message(c2s, 1, b)


def test_bad_role_rejected():
    with pytest.raises(ValueError):
        Channel(KEY, role="atacante")


# ------------------------------------------------------------------ primitivas

def test_seal_open_roundtrip():
    sealed = seal_message(KEY, 1, "hola enclave")
    assert "hola" not in sealed
    assert open_message(KEY, 1, sealed) == "hola enclave"


def test_seal_deterministic_given_same_key_seq_plaintext():
    # AES-GCM con IV determinista (seq fijo) → mismo ciphertext (y mismo tag).
    assert seal_message(KEY, 5, "x") == seal_message(KEY, 5, "x")


def test_different_seq_different_ciphertext():
    assert seal_message(KEY, 1, "x") != seal_message(KEY, 2, "x")


def test_open_rejects_wrong_seq():
    sealed = seal_message(KEY, 3, "mensaje")
    with pytest.raises(Exception):
        open_message(KEY, 4, sealed)  # IV distinto → tag no valida


def test_open_rejects_tampered():
    sealed = seal_message(KEY, 1, "mensaje")
    tampered = "A" + sealed[1:]
    with pytest.raises(Exception):
        open_message(KEY, 1, tampered)


def test_open_rejects_bad_base64():
    with pytest.raises(ValueError):
        open_message(KEY, 1, "not base64!!!")


def test_bad_key_length_rejected():
    with pytest.raises(ValueError):
        seal_message(b"corta", 1, "x")
    with pytest.raises(ValueError):
        Channel(b"corta")


def test_seq_out_of_range_rejected():
    with pytest.raises(ValueError):
        seal_message(KEY, 0, "x")
    with pytest.raises(ValueError):
        seal_message(KEY, MAX_SEQ + 1, "x")


# ------------------------------------------------------------------ Channel

def test_channel_monotonic_and_replay_protected():
    c = Channel(KEY, role="client")
    m1 = c.seal("primero")
    m2 = c.seal("segundo")
    assert m1["seq"] == 1 and m2["seq"] == 2
    # El MISMO extremo no puede abrir lo que selló (claves tx/rx distintas).
    with pytest.raises(Exception):
        c.open(1, m1["sealed"])
    # Su par servidor sí abre (rx=c2s coincide con tx del cliente).
    srv = Channel(KEY, role="server")
    assert srv.open(1, m1["sealed"]) == "primero"
    assert srv.open(2, m2["sealed"]) == "segundo"
    # Replay: mismo seq ya consumido → rechazado.
    with pytest.raises(ValueError):
        srv.open(1, m1["sealed"])
    # Contador no estrictamente creciente → rechazado.
    with pytest.raises(ValueError):
        srv.open(2, m2["sealed"])


def test_channel_directions_independent():
    cli = Channel(KEY, role="client")
    srv = Channel(KEY, role="server")
    m = cli.seal("a→b")
    assert srv.open(m["seq"], m["sealed"]) == "a→b"
    # El servidor responde con su propio contador (también empieza en 1) y su
    # propia subclave: sin colisión de (clave, nonce) aunque el seq coincida.
    r = srv.seal("b→a")
    assert r["seq"] == 1
    assert cli.open(r["seq"], r["sealed"]) == "b→a"
    assert m["sealed"] != r["sealed"]  # invariante B-01 a nivel Channel


# ------------------------------------------------------------------ interop

def _node(op: str, seq: int = 0, **extra) -> dict:
    payload = json.dumps({"op": op, "seq": seq, **extra})
    out = subprocess.run(
        [NODE, INTEROP, payload], capture_output=True, text=True, timeout=30, check=True
    )
    return json.loads(out.stdout)


def _node_expand(master_hex: str, info: str) -> str:
    return _node("expand", masterHex=master_hex, info=info)["keyHex"]


@pytest.mark.skipif(NODE is None, reason="node no disponible")
def test_interop_expand_matches_python():
    # WebCrypto HKDF (session.ts deriveDirectionalKey) == Python HKDF (B-01).
    c2s_py, s2c_py = derive_directional_keys(KEY)
    assert _node_expand(KEY.hex(), "hermetik/v1/c2s") == c2s_py.hex()
    assert _node_expand(KEY.hex(), "hermetik/v1/s2c") == s2c_py.hex()


@pytest.mark.skipif(NODE is None, reason="node no disponible")
def test_interop_python_seal_node_open():
    c2s, _ = derive_directional_keys(KEY)
    sealed = seal_message(c2s, 1, "hola desde python")
    opened = _node("open", 1, keyHex=c2s.hex(), sealed=sealed)
    assert opened["plaintext"] == "hola desde python"


@pytest.mark.skipif(NODE is None, reason="node no disponible")
def test_interop_node_seal_python_open():
    _, s2c = derive_directional_keys(KEY)
    sealed = _node("seal", 2, keyHex=s2c.hex(), plaintext="hola desde el navegador")
    assert open_message(s2c, 2, sealed["sealed"]) == "hola desde el navegador"


@pytest.mark.skipif(NODE is None, reason="node no disponible")
def test_interop_tamper_fails_both_directions():
    c2s, _ = derive_directional_keys(KEY)
    sealed = seal_message(c2s, 1, "integro")
    # Node debe rechazar el ciphertext manipulado (tag no valida).
    tampered = "A" + sealed[1:]
    with pytest.raises(subprocess.CalledProcessError):
        _node("open", 1, keyHex=c2s.hex(), sealed=tampered)
