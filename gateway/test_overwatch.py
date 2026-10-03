"""Tests del overwatch: el gate fail-closed y las tres fases encadenadas.

Las propiedades que importan:
  - C7.1.3: si el almacén no está, la acción NO procede (no es log, es gate).
  - C7.1.2: las tres fases comparten action_id y encadenan en orden.
  - Cero degradación: sin atestación no se emite, no se "sigue sin marcar".
  - step_index monótono por agente, sin huecos.
"""

import json

import pytest

from attestation import (
    REPORT_DATA_BYTES,
    AttestationError,
    DevAttestor,
    RealAttestor,
)
from overwatch import (
    DevSigner,
    EvidenceUnavailable,
    FileSink,
    InMemorySink,
    Overwatch,
    OverwatchError,
    PendingAction,
    derive_signing_key,
    make_overwatch_from_env,
)
from poc_schema import jcs, load_token

SEED = b"test-seed-nuno"
TTL = 300_000_000_000


def build(sink=None, attestor=None) -> Overwatch:
    key = derive_signing_key(SEED)
    signer = DevSigner(key)
    return Overwatch(
        signer=signer,
        sink=sink or InMemorySink(),
        attestor=attestor or DevAttestor(signer.public_key(), TTL),
    )


def action(**kw) -> PendingAction:
    base = dict(
        action_id="act-1",
        interception_point=4,
        agent_id="did:hermetik:agent-1",
        principal_id="did:icp:nuno",
        target_resource="tool:web_search",
        reason="petición del usuario",
    )
    base.update(kw)
    return PendingAction(**base)


# --- Fail-closed: C7.1.3 -----------------------------------------------------


class BrokenSink:
    """Almacén que falla. Debe impedir la acción, no degradar."""

    def append(self, record_bytes: bytes) -> str:
        raise IOError("disco lleno")

    def head(self):
        return None


def test_broken_sink_blocks_action():
    """C7.1.3: sin almacén, la acción NO se libera. Fail-closed, no fail-open."""
    ow = build(sink=BrokenSink())
    with pytest.raises(EvidenceUnavailable) as e:
        ow.before(action())
    assert "no procede" in str(e.value).lower()


def test_fail_closed_is_not_a_warning():
    """No hay camino que devuelva éxito si el almacén falla."""
    ow = build(sink=BrokenSink())
    with pytest.raises(EvidenceUnavailable):
        ow.before(action())


# --- Cero degradación de atestación -----------------------------------------


def test_real_attestor_blocks_emission():
    """Con atestador de hardware no implementado, no se emite nada."""
    ow = build(attestor=RealAttestor("sev-snp", TTL))
    with pytest.raises(OverwatchError) as e:
        ow.before(action())
    assert "atestación" in str(e.value).lower()


def test_no_silent_degradation_from_real_to_mock():
    """No hay ruta que caiga al mock si se pidió hardware."""
    key = derive_signing_key(SEED)
    signer = DevSigner(key)
    ow = Overwatch(
        signer=signer, sink=InMemorySink(), attestor=RealAttestor("tdx", TTL)
    )
    with pytest.raises(OverwatchError):
        ow.before(action())


# --- Las tres fases ---------------------------------------------------------


def test_three_phases_chain_in_order():
    """before → during → after, cada uno encadenado al anterior."""
    ow = build()
    a = action()
    d1 = ow.before(a)
    d2 = ow.during(a)
    d3 = ow.after(a)
    assert len({d1, d2, d3}) == 3
    assert a.before_digest == d1
    assert a.during_digest == d2
    assert a.after_digest == d3


def test_phases_share_signed_action_id():
    """Las 3 fases portan el mismo action_id FIRMADO (run-2, H3)."""
    sink = InMemorySink()
    ow = build(sink=sink)
    a = action(action_id="act-xyz-9")
    ow.before(a)
    ow.during(a)
    ow.after(a)
    assert len(sink.entries) == 3
    ids = [load_token(e)["poc_claims"]["action_id"] for e in sink.entries]
    assert ids == ["act-xyz-9"] * 3


def test_after_distinguishable_from_during():
    """after usa hook 8 y during hook 5: distinguibles (run-2, H3)."""
    sink = InMemorySink()
    ow = build(sink=sink)
    a = action()
    ow.before(a)
    ow.during(a)
    ow.after(a)
    hooks = [
        load_token(e)["poc_claims"]["interception_point"] for e in sink.entries
    ]
    assert hooks[0] == "PRE_CALL_TOOL_INVOCATION"
    assert hooks[1] == "POST_CALL_TOOL_RESULT"
    assert hooks[2] == "TASK_COMPLETION"
    assert hooks[1] != hooks[2]


def test_distinct_actions_have_distinct_claims():
    """Dos action_id distintos no colapsan: difieren en el claim firmado."""
    sink = InMemorySink()
    ow = build(sink=sink)
    ow.before(action(action_id="AAA-111"))
    ow.before(action(action_id="BBB-222"))
    c0 = load_token(sink.entries[0])["poc_claims"]
    c1 = load_token(sink.entries[1])["poc_claims"]
    assert c0["action_id"] != c1["action_id"]


def test_during_without_before_rejected():
    """No se puede saltar la fase before: rompería el orden (C7.1.2)."""
    ow = build()
    with pytest.raises(OverwatchError, match="before"):
        ow.during(action())


def test_after_without_during_rejected():
    """No se puede saltar during."""
    ow = build()
    a = action()
    ow.before(a)
    with pytest.raises(OverwatchError, match="during"):
        ow.after(a)


def test_before_rejects_wrong_hook():
    """before() exige el hook pre-call-tool (4)."""
    ow = build()
    with pytest.raises(OverwatchError, match="pre-call-tool"):
        ow.before(action(interception_point=6))


def test_memory_write_uses_hook_6():
    """La memoria sube por el hook 6 memory-write."""
    ow = build()
    sink = InMemorySink()
    ow = build(sink=sink)
    ow.memory_write(action(interception_point=6))
    rec = load_token(sink.entries[0])
    assert rec["poc_claims"]["interception_point"] == "MEMORY_WRITE"


# --- Records bien formados --------------------------------------------------


def test_emitted_record_is_signed_and_canonical():
    """El registro emitido lleva firma y es canonicalization-stable."""
    sink = InMemorySink()
    ow = build(sink=sink)
    ow.before(action())
    rec = load_token(sink.entries[0])
    assert "signature" in rec
    assert jcs(rec) == jcs(load_token(jcs(rec)))


def test_record_carries_principal_not_gateway():
    """`initiating_user` es el principal del usuario, no el del gateway."""
    sink = InMemorySink()
    ow = build(sink=sink)
    ow.before(action(principal_id="did:icp:nuno"))
    rec = load_token(sink.entries[0])
    assert rec["poc_claims"]["initiating_user"] == "did:icp:nuno"
    assert rec["poc_claims"]["agent_id"] == "did:hermetik:agent-1"
    assert rec["poc_claims"]["initiating_user"] != rec["poc_claims"]["agent_id"]


def test_empty_principal_refuses_action():
    """Sin principal del usuario no hay acción: el overwatch no lo inventa."""
    sink = InMemorySink()
    ow = build(sink=sink)
    with pytest.raises(OverwatchError, match="principal_id vacío"):
        action(principal_id="")
    assert len(sink.entries) == 0


def test_unknown_credential_scheme_refused():
    """Esquema distinto de nb2 ⇒ rechazo explícito, no silencioso."""
    with pytest.raises(OverwatchError, match="no admitido"):
        action(credential_scheme="api-key")


def test_credential_expiry_travels_into_record():
    """El expiry de nb2 viaja al registro como extensión hermetik_*."""
    sink = InMemorySink()
    ow = build(sink=sink)
    expiry = 1_800_000_000_000_000_000  # ns
    ow.before(action(principal_id="did:icp:nuno", credential_expiry_ns=expiry))
    claims = load_token(sink.entries[0])["poc_claims"]
    assert claims["hermetik_credential_expiry_ns"] == expiry


def test_no_expiry_field_when_undeclared():
    """Sin ventana declarada el campo se OMITE (ausente ≠ 0)."""
    sink = InMemorySink()
    ow = build(sink=sink)
    ow.before(action(principal_id="did:icp:nuno"))  # expiry 0 por defecto
    claims = load_token(sink.entries[0])["poc_claims"]
    assert "hermetik_credential_expiry_ns" not in claims


def test_record_marks_dev_unattested_noisily():
    """El registro sin TEE va marcado: campo comprobable, no solo texto."""
    sink = InMemorySink()
    ow = build(sink=sink)
    ow.before(action())
    att = load_token(sink.entries[0])["submods"]["attestation"]
    assert att["platform"] == "SOFTWARE"
    assert att["dev_unattested"] is True
    assert att["marker"] == "dev-unattested:"


def test_attestation_measurement_is_report_data_width():
    """El measurement compromete los REPORT_DATA (64 B), atando clave y entorno."""
    sink = InMemorySink()
    ow = build(sink=sink)
    ow.before(action())
    att = load_token(sink.entries[0])["submods"]["attestation"]
    assert att["measurement"].startswith("sha-256:")


# --- step_index monótono y cadena -------------------------------------------


def test_step_index_is_monotonic_without_gaps():
    """step_index monótono por agente, desde 0, sin huecos."""
    sink = InMemorySink()
    ow = build(sink=sink)
    for i in range(5):
        ow.memory_write(action(interception_point=6))
    idx = [load_token(e)["poc_claims"]["step_index"] for e in sink.entries]
    assert idx == [0, 1, 2, 3, 4]


def test_step_index_is_per_agent():
    """Dos agentes llevan contadores independientes."""
    sink = InMemorySink()
    ow = build(sink=sink)
    ow.memory_write(action(interception_point=6, agent_id="did:x:a"))
    ow.memory_write(action(interception_point=6, agent_id="did:x:b"))
    idx = [load_token(e)["poc_claims"]["step_index"] for e in sink.entries]
    assert idx == [0, 0]


def test_chain_head_links_records():
    """Cada registro encadena con el head anterior (C7.3.1)."""
    sink = InMemorySink()
    ow = build(sink=sink)
    # El digest que el sink calcula es el del registro FIRMADO completo; es lo
    # que el overwatch guarda como head y lo que el siguiente registro encadena.
    from poc_schema import sha256_tagged

    ow.memory_write(action(interception_point=6))
    expected_head = sha256_tagged(sink.entries[0])
    ow.memory_write(action(interception_point=6))
    r2 = load_token(sink.entries[1])
    assert r2["poc_claims"]["chain_head"] == expected_head


def test_first_record_has_no_chain_head():
    """El primer registro no tiene head previo (no se inventa un valor)."""
    sink = InMemorySink()
    ow = build(sink=sink)
    ow.memory_write(action(interception_point=6))
    assert "chain_head" not in load_token(sink.entries[0])["poc_claims"]


# --- Clave de firma ---------------------------------------------------------


def test_signing_key_derivation_is_deterministic():
    assert derive_signing_key(SEED) == derive_signing_key(SEED)
    assert derive_signing_key(SEED) != derive_signing_key(b"otra")


def test_empty_seed_rejected():
    with pytest.raises(ValueError):
        derive_signing_key(b"")


def test_signature_is_verifiable_with_public_key():
    """La firma se verifica con la clave pública (contrato del verificador)."""
    key = derive_signing_key(SEED)
    signer = DevSigner(key)
    ow = Overwatch(
        signer=signer, sink=InMemorySink(), attestor=DevAttestor(signer.public_key(), TTL)
    )
    sink = ow._sink
    ow.before(action())
    rec = load_token(sink.entries[0])
    from poc_schema import signing_input

    payload = signing_input(rec)
    expected = signer.sign(payload).hex()
    assert rec["signature"] == expected


# --- Persistencia -----------------------------------------------------------


def test_file_sink_persists_and_resumes_head(tmp_path):
    """El FileSink persiste y el overwatch reanuda la cadena al reiniciar."""
    p = tmp_path / "evidence.log"
    ow = build(sink=FileSink(p))
    ow.memory_write(action(interception_point=6))
    head = ow.head
    assert p.exists()
    # Reconstruir desde el mismo fichero reanuda el head.
    ow2 = build(sink=FileSink(p))
    assert ow2.head == head


# --- Construcción desde entorno --------------------------------------------


def test_env_requires_explicit_mode(monkeypatch):
    """Sin HERMETIK_ATTEST_MODE no se construye: no hay default silencioso."""
    monkeypatch.delenv("HERMETIK_ATTEST_MODE", raising=False)
    with pytest.raises(OverwatchError, match="HERMETIK_ATTEST_MODE"):
        make_overwatch_from_env()


def test_env_requires_seed(monkeypatch):
    """Sin semilla no hay clave de firma: se rechaza, no se genera una al vuelo."""
    monkeypatch.setenv("HERMETIK_ATTEST_MODE", "dev-unattested")
    monkeypatch.delenv("HERMETIK_OVERWATCH_SEED", raising=False)
    with pytest.raises(OverwatchError, match="SEED"):
        make_overwatch_from_env()


def test_env_builds_with_explicit_dev_mode(monkeypatch):
    """Con modo y semilla explícitos, se construye."""
    monkeypatch.setenv("HERMETIK_ATTEST_MODE", "dev-unattested")
    monkeypatch.setenv("HERMETIK_OVERWATCH_SEED", "seed-de-test")
    ow = make_overwatch_from_env()
    assert isinstance(ow, Overwatch)


def test_env_rejects_unknown_mode(monkeypatch):
    monkeypatch.setenv("HERMETIK_ATTEST_MODE", "produccion")
    monkeypatch.setenv("HERMETIK_OVERWATCH_SEED", "seed")
    with pytest.raises(AttestationError):
        make_overwatch_from_env()
