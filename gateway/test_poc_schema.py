"""Tests unitarios del esquema canónico PoC.

Los casos de conformidad contra la norma están en `test_poc_conformance.py`.
Aquí van las propiedades de la implementación, con el motivo del rechazo
comprobado (un negativo rechazado por el motivo equivocado no es un aprobado).
"""

import pytest

from poc_schema import (
    CanonicalizationError,
    EvidenceRecord,
    digest_claim,
    jcs,
    load_token,
    sha256_tagged,
    signing_input,
)

NONCE = "n-00000001"


def rec(**kw) -> EvidenceRecord:
    base = dict(
        iss="https://verifier.example/poc",
        iat=1754400000,
        nonce=NONCE,
        agent_id="did:web:example.org:agents:ref-1",
        initiating_user="user:alice",
        interception_point=4,
        step_index=0,
        verdict=1,
        action_id="act-test-1",
    )
    base.update(kw)
    return EvidenceRecord(**base)


# --- Determinismo: lo que hace la firma verificable -------------------------


def test_same_record_same_bytes():
    """Mismo registro ⇒ bytes idénticos."""
    a = signing_input(rec().token())
    b = signing_input(rec().token())
    assert a == b


def test_field_insertion_order_does_not_matter():
    """El orden de construcción no cambia los bytes: las claves se ordenan."""
    r1 = rec(agbom_digest=digest_claim(b"m"), target_resource="tool:web_search")
    r2 = rec(target_resource="tool:web_search", agbom_digest=digest_claim(b"m"))
    assert signing_input(r1.token()) == signing_input(r2.token())


def test_signature_field_excluded_from_signing_input():
    """`signature` no cubre a sí misma: se excluye del payload firmable."""
    t = rec().token()
    t["signature"] = "aa" * 64
    assert signing_input(t) == signing_input(rec().token())


def test_different_step_index_changes_bytes():
    a = signing_input(rec(step_index=0).token())
    b = signing_input(rec(step_index=1).token())
    assert a != b


# --- Ausente ≠ vacío --------------------------------------------------------


def test_absent_optional_omitted_not_null():
    """Un opcional que no aplica se OMITE; nunca null."""
    c = rec().claims()
    for k in ("agbom_digest", "chain_head", "target_resource", "reason"):
        assert k not in c


def test_null_and_absent_differ_in_bytes():
    """Por qué existe la regla: null y ausente dan bytes distintos."""
    assert jcs({"a": 1, "b": None}) != jcs({"a": 1})


# --- Floats ----------------------------------------------------------------


def test_float_iat_rejected():
    with pytest.raises(CanonicalizationError, match="int"):
        rec(iat=1754400000.5).claims()


def test_float_anywhere_rejected_in_jcs():
    with pytest.raises(CanonicalizationError, match="float"):
        jcs({"a": 1.5})


def test_nested_float_rejected():
    with pytest.raises(CanonicalizationError, match="float"):
        jcs({"k": [{"ttl": 1.5}]})


def test_int_not_treated_as_float():
    """Un int del rango de segundos pasa sin problema."""
    assert jcs({"iat": 1754400000}) == b'{"iat":1754400000}'


# --- Digests ---------------------------------------------------------------


def test_digest_claim_shape():
    d = digest_claim(b"x")
    assert isinstance(d, str) and d.startswith("sha-256:")
    assert len(d) == len("sha-256:") + 64 and d == d.lower()


def test_digest_alg_alternatives():
    assert len(digest_claim(b"x", "sha-384")) == len("sha-384:") + 96
    assert len(digest_claim(b"x", "sha-512")) == len("sha-512:") + 128
    assert len(digest_claim(b"x", "sha3-256")) == len("sha3-256:") + 64


def test_unknown_hash_alg_rejected():
    with pytest.raises(CanonicalizationError, match="no admitido"):
        digest_claim(b"x", "md5")


def test_uppercase_hex_rejected():
    with pytest.raises(CanonicalizationError, match="minúsculas"):
        rec(policy_bundle_hash="sha-256:" + "AA" * 32).claims()


def test_non_hex_rejected():
    with pytest.raises(CanonicalizationError, match="hex"):
        rec(policy_bundle_hash="sha-256:" + "zz" * 32).claims()


def test_array_digest_rejected():
    """El digest como array es el error que hay que no cometer en JSON."""
    with pytest.raises(CanonicalizationError, match="digest"):
        rec(policy_bundle_hash=["sha-256", "aa" * 32]).claims()  # type: ignore[arg-type]


def test_sha256_tagged_is_for_internal_use():
    d = sha256_tagged(b"x")
    assert d.startswith("sha-256:") and len(d) == 8 + 64


# --- Claves duplicadas ------------------------------------------------------


def test_duplicate_keys_rejected():
    with pytest.raises(CanonicalizationError, match="duplicada"):
        load_token('{"1":"a","1":"b"}')


def test_last_wins_would_be_the_bug():
    """Demuestra el peligro: json normal se queda con la última en silencio."""
    import json

    assert json.loads('{"1":"a","1":"b"}') == {"1": "b"}


def test_valid_json_loads():
    assert load_token('{"a":1,"b":2}') == {"a": 1, "b": 2}


# --- Enumerados -------------------------------------------------------------


def test_all_eight_hooks_accepted():
    for p in range(1, 9):
        assert rec(interception_point=p).claims()
    for bad in (0, 9, -1):
        with pytest.raises(CanonicalizationError, match="1..8"):
            rec(interception_point=bad).claims()


def test_all_four_verdicts_accepted():
    for v in (1, 2, 3, 4):
        assert rec(verdict=v).claims()
    with pytest.raises(CanonicalizationError, match="verdict"):
        rec(verdict=5).claims()


def test_verdict_rendered_as_name():
    """El veredicto se serializa con su nombre textual, como en los vectores."""
    assert rec(verdict=2).claims()["verdict"] == "DENY"


def test_hook_rendered_as_name():
    assert (
        rec(interception_point=4).claims()["interception_point"]
        == "PRE_CALL_TOOL_INVOCATION"
    )


def test_all_hooks_use_normative_names():
    """Los 8 hooks usan EXACTAMENTE los nombres del schema (run-2, H1)."""
    expected = {
        1: "TASK_INITIALIZATION",
        2: "CONTEXT_ASSEMBLY",
        3: "PLAN_GENERATION",
        4: "PRE_CALL_TOOL_INVOCATION",
        5: "POST_CALL_TOOL_RESULT",
        6: "MEMORY_WRITE",
        7: "SUBAGENT_DELEGATION",
        8: "TASK_COMPLETION",
    }
    for n, name in expected.items():
        assert rec(interception_point=n).claims()["interception_point"] == name, n


def test_all_alg_enum_values_accepted():
    """Los 5 valores normativos de alg pasan; cualquier otro se rechaza (H2)."""
    for alg in ("EdDSA", "ES256", "ML-DSA-44", "ML-DSA-65", "Ed25519+ML-DSA-44"):
        assert rec(alg=alg).claims()["alg"] == alg
    for bad in ("RSA-FAKE-9999", "hybrid-eddsa-mldsa44", "", "eddsa"):
        with pytest.raises(CanonicalizationError, match="alg"):
            rec(alg=bad).claims()


def test_action_id_required_and_signed():
    """action_id va firmado en cada claim; vacío ⇒ rechazo (run-2, H3)."""
    assert rec(action_id="act-1").claims()["action_id"] == "act-1"
    assert rec(action_id="act-1").claims()["action_id"] in signing_input(
        rec(action_id="act-1").token()
    ).decode()
    with pytest.raises(CanonicalizationError, match="action_id"):
        rec(action_id="").claims()


def test_negative_step_index_rejected():
    with pytest.raises(CanonicalizationError, match="step_index"):
        rec(step_index=-1).claims()


# --- UTF-8 y forma canónica ------------------------------------------------


def test_output_is_utf8_without_bom():
    b = jcs({"iss": "ñ"})
    assert not b.startswith(b"\xef\xbb\xbf")
    assert b.decode("utf-8")


def test_no_insignificant_whitespace():
    assert b" " not in jcs({"a": "b", "c": "d"})


def test_unicode_not_escaped():
    b = jcs({"a": "ñ"})
    assert "ñ".encode() in b
    assert b"\\u00f1" not in b


def test_control_chars_escaped():
    assert jcs({"a": "\n"}) == b'{"a":"\\n"}'


def test_token_round_trips():
    r = rec(chain_head=digest_claim(b"prev"), reason="within grant")
    t = r.token()
    assert jcs(t) == jcs(load_token(jcs(t)))


def test_attestation_omitted_when_absent():
    assert "submods" not in rec().token()
