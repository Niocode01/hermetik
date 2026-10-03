"""Tests de la verificación nb2 del gateway (F4).

Lo que se prueba NO es "el mock funciona": se prueba que la frontera de auth es
fail-closed y que el wire format (CBOR + candid + principal base32/CRC32) es
exacto byte a byte contra vectores conocidos. Un fallo aquí significa que el
gateway o bien no autentica (DoS) o bien autentica de más (fuga).
"""

import binascii

import pytest

from nb2 import (
    Nb2Gate,
    candid_decode_bool,
    candid_text_arg,
    nb2_call_verify_credential,
    nb2_query_envelope,
    parse_nb2_credential,
    principal_bytes,
    is_valid_user,
)


# ------------------------------------------------------------------ parseo

def test_parse_nb2_valid():
    p = parse_nb2_credential("nb2.2vxsx-fae.123.4.5." + "ab" * 32)
    assert p is not None
    assert p["who"] == "2vxsx-fae"
    assert p["expiry"] == 123
    assert p["epoch"] == 4
    assert p["nonce"] == 5
    assert p["tag"] == "ab" * 32


def test_parse_nb2_uppercase_tag_normalized():
    p = parse_nb2_credential("nb2.2vxsx-fae.1.2.3." + "AB" * 32)
    assert p is not None and p["tag"] == "ab" * 32


def test_parse_nb2_rejects_bad_shapes():
    assert parse_nb2_credential("") is None
    assert parse_nb2_credential("nope") is None
    assert parse_nb2_credential("nb2.2vxsx-fae.1.2.3.deadbeef") is None  # tag corta
    assert parse_nb2_credential("nb2..1.2.3." + "ab" * 32) is None  # who vacío
    assert parse_nb2_credential("nb2.2vxsx-fae.x.2.3." + "ab" * 32) is None  # expiry no num


def test_is_valid_user():
    assert is_valid_user("2vxsx-fae")
    assert is_valid_user("a.b-c_d.e")
    assert not is_valid_user("")
    assert not is_valid_user("con espacio")
    assert not is_valid_user("injection\r\nX: y")
    assert not is_valid_user("a" * 65)


# ------------------------------------------------------------------ principal

def test_principal_management_canister():
    assert principal_bytes("aaaaa-aa") == b""


def test_principal_known_real_id_crc_selfcheck():
    # ryjl3-tyaaa-aaaaa-aaaba-cai (ICP ledger mainnet): el CRC32 self-check
    # interno fallaría con probabilidad ~1/2^32 si el orden base32/CRC fuese
    # erróneo. Que no lance YA es una verificación fuerte.
    body = principal_bytes("ryjl3-tyaaa-aaaaa-aaaba-cai")
    assert len(body) > 0


def test_principal_roundtrip_synthetic():
    # Construimos un principal desde un cuerpo conocido y verificamos que el
    # decodificador lo recupera (CRC32 ISO HDLC incluido).
    body = b"hermetik-v3.1"
    crc = binascii.crc32(body) & 0xFFFFFFFF
    raw = crc.to_bytes(4, "big") + body
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    bits = "".join(f"{b:08b}" for b in raw)
    # relleno base32 a múltiplo de 5 bits
    pad = (5 - len(bits) % 5) % 5
    bits += "0" * pad
    text = "".join(alphabet[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))
    # guiones cada 5 chars
    text = "-".join(text[i:i + 5] for i in range(0, len(text), 5))
    assert principal_bytes(text) == body


def test_principal_rejects_bad():
    with pytest.raises(ValueError):
        principal_bytes("")
    with pytest.raises(ValueError):
        principal_bytes("1nv4l1d-ch4r$")


def test_principal_rejects_corrupt_crc():
    # Cogemos un principal válido y le cambiamos un carácter del cuerpo: el CRC
    # ya no cuadra y debe rechazar.
    bad = "ryjl3-tyaaa-aaaaa-aaaba-cax"
    with pytest.raises(ValueError):
        principal_bytes(bad)


# ------------------------------------------------------------------ candid

def test_candid_text_arg_exact_bytes():
    assert candid_text_arg("abc") == b"DIDL\x00\x01\x71\x03abc"


def test_candid_decode_bool_true_and_false():
    assert candid_decode_bool(b"DIDL\x00\x01\x7e\x01") is True
    assert candid_decode_bool(b"DIDL\x00\x01\x7e\x00") is False


def test_candid_decode_bool_rejects_malformed():
    with pytest.raises(ValueError):
        candid_decode_bool(b"XXXX")
    with pytest.raises(ValueError):
        candid_decode_bool(b"DIDL\x00\x02\x7e\x01")  # nargs != 1
    with pytest.raises(ValueError):
        candid_decode_bool(b"DIDL\x00\x01\x7e\x02")  # bool inválido


# ------------------------------------------------------------------ query

def test_query_envelope_roundtrips_through_cbor():
    from nb2 import _cbor_decode, _cbor_encode

    env = nb2_query_envelope("ryjl3-tyaaa-aaaaa-aaaba-cai", "verify_credential", b"arg")
    decoded, pos = _cbor_decode(env)
    assert pos == len(env)
    content = decoded["content"]
    assert content["request_type"] == "query"
    assert content["method_name"] == "verify_credential"
    assert content["arg"] == b"arg"
    assert isinstance(content["canister_id"], bytes) and len(content["canister_id"]) > 0


# ------------------------------------------------------------------ gate

def _reply_cbor(value: bool) -> bytes:
    from nb2 import _cbor_encode

    arg = b"DIDL\x00\x01\x7e" + (b"\x01" if value else b"\x00")
    return _cbor_encode({"reply": {"arg": arg}})


def test_gate_authenticates_and_caches():
    calls = []

    def fake(url, envelope):
        calls.append(url)
        return _reply_cbor(True)

    gate = Nb2Gate("ryjl3-tyaaa-aaaaa-aaaba-cai", transport=fake, now=lambda: 1000.0)
    cred = "nb2.2vxsx-fae.9999999999.1.2." + "ab" * 32
    assert gate.authenticate(cred, "2vxsx-fae") is True
    assert gate.authenticate(cred, "2vxsx-fae") is True  # caché, sin red
    assert len(calls) == 1


def test_gate_rejects_when_user_mismatch_no_network():
    calls = []

    def fake(url, envelope):
        calls.append(url)
        return _reply_cbor(True)

    gate = Nb2Gate("ryjl3-tyaaa-aaaaa-aaaba-cai", transport=fake)
    cred = "nb2.2vxsx-fae.9999999999.1.2." + "ab" * 32
    # Credencial de 2vxsx-fae presentada como otro usuario: rechazo SIN red.
    assert gate.authenticate(cred, "zzzzz-aa") is False
    assert calls == []


def test_gate_fail_closed_on_network_error():
    def fake(url, envelope):
        raise ConnectionError("réplica caída")

    gate = Nb2Gate("ryjl3-tyaaa-aaaaa-aaaba-cai", transport=fake)
    cred = "nb2.2vxsx-fae.9999999999.1.2." + "ab" * 32
    assert gate.authenticate(cred, "2vxsx-fae") is False


def test_gate_fail_closed_on_bad_cbor():
    gate = Nb2Gate("ryjl3-tyaaa-aaaaa-aaaba-cai", transport=lambda u, e: b"\xff\xff\xff")
    cred = "nb2.2vxsx-fae.9999999999.1.2." + "ab" * 32
    assert gate.authenticate(cred, "2vxsx-fae") is False


def test_gate_fail_closed_on_canister_false():
    gate = Nb2Gate(
        "ryjl3-tyaaa-aaaaa-aaaba-cai",
        transport=lambda u, e: _reply_cbor(False),
        now=lambda: 1000.0,
    )
    cred = "nb2.2vxsx-fae.9999999999.1.2." + "ab" * 32
    assert gate.authenticate(cred, "2vxsx-fae") is False


def test_gate_negative_cache_short():
    calls = []

    def fake(url, envelope):
        calls.append(url)
        return _reply_cbor(False)

    gate = Nb2Gate("ryjl3-tyaaa-aaaaa-aaaba-cai", transport=fake, now=lambda: 1000.0)
    cred = "nb2.2vxsx-fae.9999999999.1.2." + "ab" * 32
    assert gate.authenticate(cred, "2vxsx-fae") is False
    assert gate.authenticate(cred, "2vxsx-fae") is False  # neg-cache
    assert len(calls) == 1


def test_verify_credential_direct_call_ok():
    gate = Nb2Gate(
        "ryjl3-tyaaa-aaaaa-aaaba-cai",
        transport=lambda u, e: _reply_cbor(True),
    )
    assert nb2_call_verify_credential(
        "http://x", "ryjl3-tyaaa-aaaaa-aaaba-cai", "nb2.2vxsx-fae.1.2.3." + "ab" * 32,
        transport=lambda u, e: _reply_cbor(True),
    ) is True
