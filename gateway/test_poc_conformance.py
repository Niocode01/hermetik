"""Conformidad contra los vectores PUBLICADOS de la norma.

Este es el único test que vale: no comprueba que mi código haga lo que yo digo,
comprueba que reproduce lo que dice la norma. Usa el validador normativo
(`/tmp/ov-poc/schema/validate.py`) como oráculo.

Si el clone de la norma no está disponible, los tests de conformidad se SALTAN de
forma explícita (skip con motivo), nunca pasan en falso.
"""

import importlib.util
import json
from pathlib import Path

import pytest

from poc_schema import (
    PROFILE_URI,
    CanonicalizationError,
    EvidenceRecord,
    digest_claim,
    jcs,
    load_token,
    signing_input,
    tier_of_platform,
)

STANDARD = Path("/tmp/ov-poc")
SCHEMA = STANDARD / "schema"
VECTORS = SCHEMA / "vectors"

pytestmark = pytest.mark.skipif(
    not (SCHEMA / "validate.py").exists(),
    reason=f"norma no clonada en {STANDARD} (conformidad no verificable)",
)


def _load_validator():
    spec = importlib.util.spec_from_file_location("poc_validate", SCHEMA / "validate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def validator():
    return _load_validator()


@pytest.fixture(scope="module")
def manifest():
    return json.loads((VECTORS / "manifest.json").read_text())


# --- El oráculo mismo debe pasar (si no, no hay contra qué comparar) ---------


def test_normative_validator_passes_all_vectors(validator):
    """El validador de la norma acepta sus propios vectores: 17/17."""
    import contextlib
    import io
    import sys

    buf = io.StringIO()
    old_argv = sys.argv
    sys.argv = ["validate.py", "--vectors"]
    try:
        with contextlib.redirect_stdout(buf):
            rc = validator.main()
    finally:
        sys.argv = old_argv
    assert rc == 0, buf.getvalue()


# --- Claves duplicadas: comparación directa con la norma --------------------


def test_duplicate_key_rejected_like_normative_validator(validator, manifest):
    """Mi parser rechaza duplicate-key igual que el de la norma."""
    raw = (VECTORS / "negative/duplicate-key.json").read_text()
    # La norma lo rechaza.
    with pytest.raises(validator.ValidationError):
        validator.load_token(raw)
    # Y yo también.
    with pytest.raises(CanonicalizationError, match="duplicada"):
        load_token(raw)


# --- Canonicalización: reproducir los bytes publicados ----------------------


def test_reproduce_published_canonical_digests(validator, manifest):
    """Reproduzco el digest canónico de cada vector canonical publicado.

    Si mi JCS difiere del normativo en un solo byte, el digest cambia y esto
    falla. Es la prueba dura de la canonicalización.
    """
    import hashlib

    for entry in manifest["canonical"]:
        path = VECTORS / entry["file"]
        obj = json.loads(path.read_text())
        mine = hashlib.sha256(jcs(obj)).hexdigest()
        assert mine == entry["canonical_sha256"], (
            f"{entry['file']}: mi JCS difiere del publicado"
        )


def test_jcs_order_is_utf16_code_unit_not_codepoint(validator):
    """El vector nonbmp distingue orden UTF-16 (norma) de code point (mi error previo)."""
    obj = json.loads((VECTORS / "canonical/nonbmp-key-ordering.json").read_text())
    norm = validator.jcs(obj)
    mine = jcs(obj)
    assert mine == norm
    # Y demuestra que ordenar por code point daría OTRO resultado.
    codepoint_order = json.dumps(
        dict(sorted(obj.items(), key=lambda kv: kv[0])),
        separators=(",", ":"), ensure_ascii=False,
    ).encode()
    assert codepoint_order != norm, "el vector debe distinguir ambos órdenes"


def test_jcs_matches_normative_on_tricky_strings(validator):
    """Escapes, Unicode y contenedores vacíos: byte a byte igual que la norma."""
    obj = json.loads((VECTORS / "canonical/tricky-strings.json").read_text())
    assert jcs(obj) == validator.jcs(obj)


# --- Firming input ----------------------------------------------------------


def test_signing_input_matches_normative(validator):
    """`signing_input` (token sin `signature`) coincide con el de la norma."""
    token = json.loads((VECTORS / "positive/allow-read.json").read_text())
    assert signing_input(token) == validator.signing_input(token)


# --- Digests del claim set: array [alg, hex], no string ---------------------


def test_digest_claim_is_tagged_string():
    """El digest JSON es string "alg:hex" (norma); el array es solo CBOR."""
    d = digest_claim(b"hello")
    assert isinstance(d, str) and d.startswith("sha-256:")
    assert len(d) == len("sha-256:") + 64 and d == d.lower()


def test_array_digest_rejected_in_claims():
    """Un digest como array en poc_claims JSON se RECHAZA (era el bug H4)."""
    r = EvidenceRecord(
        iss="https://verifier.example/poc",
        iat=1754400000,
        nonce="n-00000001",
        agent_id="did:web:example.org:agents:ref-1",
        initiating_user="user:alice",
        interception_point=4,
        step_index=0,
        verdict=1,
        action_id="act-test-1",
        policy_bundle_hash=["sha-256", "aa" * 32],  # type: ignore[arg-type] — array: incorrecto en JSON
    )
    with pytest.raises(CanonicalizationError, match="digest"):
        r.claims()


def test_untagged_string_digest_rejected_in_claims():
    """Un digest sin etiqueta 'sha-256:...' en poc_claims se RECHAZA."""
    r = EvidenceRecord(
        iss="https://verifier.example/poc",
        iat=1754400000,
        nonce="n-00000001",
        agent_id="did:web:example.org:agents:ref-1",
        initiating_user="user:alice",
        interception_point=4,
        step_index=0,
        verdict=1,
        action_id="act-test-1",
        policy_bundle_hash="aa" * 64,  # sin etiqueta: incorrecto
    )
    with pytest.raises(CanonicalizationError, match="digest"):
        r.claims()


def test_digest_width_mismatch_rejected():
    """sha-256 con 96 hex (=hash de 384) ⇒ rechazo: vector digest-alg-width-mismatch."""
    r = EvidenceRecord(
        iss="iss", iat=1754400000, nonce="n-1", agent_id="did:x:1",
        initiating_user="user:a", interception_point=4, step_index=0, verdict=1,
        action_id="act-test-1",
        policy_bundle_hash="sha-256:" + "aa" * 48,
    )
    with pytest.raises(CanonicalizationError, match="longitud"):
        r.claims()


# --- Perfil y enumerados ----------------------------------------------------


def test_unknown_profile_rejected():
    """Perfil desconocido ⇒ rechazo (vector wrong-profile)."""
    r = EvidenceRecord(
        iss="iss", iat=1754400000, nonce="n-1", agent_id="did:x:1",
        initiating_user="user:a", interception_point=4, step_index=0, verdict=1,
        action_id="act-test-1",
        eat_profile="https://example.org/other/v9",
    )
    with pytest.raises(CanonicalizationError, match="perfil"):
        r.claims()


def test_bad_interception_point_rejected():
    """Hook fuera de 1..8 ⇒ rechazo (vector bad-interception-point)."""
    r = EvidenceRecord(
        iss="iss", iat=1754400000, nonce="n-1", agent_id="did:x:1",
        initiating_user="user:a", interception_point=99, step_index=0, verdict=1,
        action_id="act-test-1",
    )
    with pytest.raises(CanonicalizationError, match="1..8"):
        r.claims()


def test_float_timestamp_rejected():
    """iat float ⇒ rechazo (vector float-timestamp)."""
    r = EvidenceRecord(
        iss="iss", iat=1754400000.5, nonce="n-1", agent_id="did:x:1",
        initiating_user="user:a", interception_point=4, step_index=0, verdict=1,
        action_id="act-test-1",
    )
    with pytest.raises(CanonicalizationError, match="int"):
        r.claims()


# --- Capa semántica: el techo Tier 2 sin TEE --------------------------------


def test_software_platform_caps_at_tier_2():
    """SOFTWARE ⇒ Tier 2. Es el techo real hoy, y la norma lo confirma."""
    tier, why = tier_of_platform("SOFTWARE")
    assert tier == 2
    assert "Tier 2" in why


def test_hardware_platforms_are_tier_capable():
    """TDX / SEV-SNP / CCA / Nitro pueden sostener Tier 3+."""
    for p in ("INTEL_TDX", "AMD_SEV_SNP", "ARM_CCA", "AWS_NITRO"):
        tier, _ = tier_of_platform(p)
        assert tier == 3, p


# --- Round-trip -------------------------------------------------------------


def test_record_is_canonicalization_stable():
    """El token generado es estable: jcs(token) == jcs(load(jcs(token)))."""
    r = EvidenceRecord(
        iss="https://verifier.example/poc", iat=1754400000, nonce="n-00000001",
        agent_id="did:web:example.org:agents:ref-1", initiating_user="user:alice",
        interception_point=4, step_index=0, verdict=1,
        action_id="act-test-1",
        policy_bundle_hash=digest_claim(b"policy"),
        agbom_digest=digest_claim(b"model"),
        attestation={"measurement": digest_claim(b"m"), "platform": "SOFTWARE"},
    )
    t = r.token()
    assert jcs(t) == jcs(load_token(jcs(t)))
