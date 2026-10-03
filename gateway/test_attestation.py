"""Tests del atestador del overwatch.

Lo que se prueba aquí NO es "funciona el mock". Se prueba la propiedad que hace
que el diseño sea honesto: que el modo sin TEE NO PUEDE pasar por atestiguado, y
que el modo con TEE no degrada en silencio.
"""

import hashlib

import pytest

from attestation import (
    ALG_EDDSA,
    DEV_UNATTESTED_PREFIX,
    REPORT_DATA_BYTES,
    AttestationError,
    AttestationMode,
    DevAttestor,
    RealAttestor,
    build_report_data,
    digest_of_signing_key,
    make_attestor,
)

PUB = b"\x11" * 32  # clave pública Ed25519 de mentira
NONCE = b"0123456789abcdef"  # 16 B, dentro de 8..64
INTERVAL = 300_000_000_000  # 300 s en ns


# --- El marcador de desarrollo: la propiedad central -------------------------


def test_dev_report_is_marked_not_attested():
    """El reporte de desarrollo NO es atestiguado y trae el marcador."""
    r = DevAttestor(PUB, INTERVAL).attest(NONCE)
    assert r.mode is AttestationMode.DEV_UNATTESTED
    assert r.is_attested is False
    assert r.dev_marker_present is True
    assert r.quote.startswith(DEV_UNATTESTED_PREFIX.encode())


def test_dev_report_vendor_is_not_a_hardware_vendor():
    """El vendor nunca puede ser un fabricante real en modo desarrollo."""
    r = DevAttestor(PUB, INTERVAL).attest(NONCE)
    assert r.vendor == "none"
    assert r.measured_binary == "unmeasured"


# --- REPORT_DATA: el contrato con el verificador (C7.2.4) --------------------


def test_report_data_is_64_bytes():
    """REPORT_DATA mide 64 B (SEV-SNP y TDX). Este es el contrato de tamaño."""
    r = DevAttestor(PUB, INTERVAL).attest(NONCE)
    assert len(r.report_data) == REPORT_DATA_BYTES


def test_report_data_binds_signing_key_digest():
    """El digest de la clave de firma está DENTRO de REPORT_DATA (C7.2.4).

    El verificador recomputa esto desde la clave que ve firmar. Si no coincide,
    el handshake falla. Esta es la atadura clave↔entorno.
    """
    r = DevAttestor(PUB, INTERVAL).attest(NONCE)
    expected = build_report_data(r.signing_key_digest, NONCE)
    assert r.report_data == expected
    assert r.report_data[:32] == hashlib.sha256(r.signing_key_digest.encode()).digest()


def test_report_data_changes_with_nonce():
    """Nonce distinto ⇒ REPORT_DATA distinto (no se puede replayar un nonce)."""
    a = DevAttestor(PUB, INTERVAL).attest(b"nonce-aaaaaaaaaa")
    b = DevAttestor(PUB, INTERVAL).attest(b"nonce-bbbbbbbbbb")
    assert a.report_data != b.report_data


def test_report_data_changes_with_signing_key():
    """Clave distinta ⇒ REPORT_DATA distinto (no se puede suplantar la clave)."""
    other = b"\x22" * 32
    a = DevAttestor(PUB, INTERVAL).attest(NONCE)
    b = DevAttestor(other, INTERVAL).attest(NONCE)
    assert a.report_data != b.report_data
    assert a.signing_key_digest != b.signing_key_digest


def test_signing_key_digest_is_tagged():
    """Digest etiquetado: un digest sin etiqueta se rechaza (canonicalización)."""
    d = digest_of_signing_key(PUB)
    assert d.startswith("sha-256:")
    assert len(d) == len("sha-256:") + 64


# --- Sin fallback automático -------------------------------------------------


def test_real_attestor_refuses_instead_of_degrading():
    """El modo hardware FALLA si no hay TEE. No degrada a dev-unattested.

    Esta es la línea que impide vender Tier 3 sin TEE: no hay camino silencioso
    desde 'real' hasta 'mock'.
    """
    with pytest.raises(AttestationError) as e:
        RealAttestor("sev-snp", INTERVAL).attest(NONCE)
    msg = str(e.value).lower()
    assert "no implementado" in msg or "no hay tee" in msg
    assert "dev-unattested" in msg  # deja claro que NO se degrada ahí


def test_factory_requires_explicit_mode():
    """Modo desconocido o vacío ⇒ error. No hay modo por defecto permisivo."""
    with pytest.raises(AttestationError):
        make_attestor("", PUB, INTERVAL)
    with pytest.raises(AttestationError):
        make_attestor("production", PUB, INTERVAL)
    with pytest.raises(AttestationError):
        make_attestor("auto", PUB, INTERVAL)


def test_factory_dev_mode_is_explicit():
    """Solo pidiendo 'dev-unattested' por nombre se obtiene el mock."""
    a = make_attestor("dev-unattested", PUB, INTERVAL)
    assert isinstance(a, DevAttestor)
    assert a.attest(NONCE).is_attested is False


def test_factory_hardware_mode_returns_real_attestor():
    """Pedir hardware devuelve el real, que hoy falla. No cae al mock."""
    a = make_attestor("sev-snp", PUB, INTERVAL)
    assert isinstance(a, RealAttestor)
    with pytest.raises(AttestationError):
        a.attest(NONCE)


# --- Validación de entradas --------------------------------------------------


def test_empty_signing_key_rejected():
    """Clave pública vacía ⇒ rechazo (no se firma con clave vacía)."""
    with pytest.raises(AttestationError):
        DevAttestor(b"", INTERVAL)


def test_non_positive_interval_rejected():
    """Intervalo <= 0 ⇒ rechazo: C7.2.3 exige declarar intervalo."""
    with pytest.raises(AttestationError):
        DevAttestor(PUB, 0)
    with pytest.raises(AttestationError):
        DevAttestor(PUB, -1)


def test_nonce_length_enforced():
    """eat_nonce fuera de 8..64 B ⇒ rechazo (esquema PoC)."""
    a = DevAttestor(PUB, INTERVAL)
    with pytest.raises(AttestationError):
        a.attest(b"short")  # 5 B
    with pytest.raises(AttestationError):
        a.attest(b"x" * 65)  # 65 B
    # Los límites exactos sí pasan.
    assert a.attest(b"x" * 8).report_data
    assert a.attest(b"x" * 64).report_data


def test_interval_is_carried_into_report():
    """El intervalo declarado viaja en el reporte (C7.2.3: debe declararse)."""
    r = DevAttestor(PUB, INTERVAL).attest(NONCE)
    assert r.unwrap_interval_ns == INTERVAL
