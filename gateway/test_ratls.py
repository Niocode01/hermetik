"""Tests de la interfaz RA-TLS (F4, ADR-01 capa 1).

La propiedad central NO es "el mock emite un certificado": es que
  1. el modo real FALLA en vez de degradar a un certificado autofirmado sin
     marcar (regla dura),
  2. el certificado de desarrollo queda MARCADO de forma inconfundible y su
     vínculo con la atestación es re-verificable,
  3. el dominio de tenant se valida estricto (sin IP, sin wildcard, sin userinfo).
"""

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

import pytest

from ratls import (
    RATlsError,
    DevRATlsProvider,
    RealRATlsProvider,
    cert_digest,
    make_ratls_provider,
    validate_tenant_domain,
    verify_ratls_binding,
)

NOW = 1_700_000_000_000_000_000


def _parse_san(cert_pem: str) -> list[str]:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    return ext.value.get_values_for_type(x509.DNSName)


def test_dev_issues_cert_with_san_matching_domain():
    p = DevRATlsProvider()
    c = p.issue("abc123.hermetik.eu", now_ns=lambda: NOW)
    assert c.domain == "abc123.hermetik.eu"
    assert c.state == "dev-unattested"
    assert _parse_san(c.cert_pem) == ["abc123.hermetik.eu"]


def test_dev_cert_marked_and_bound():
    p = DevRATlsProvider()
    c = p.issue("abc123.hermetik.eu", now_ns=lambda: NOW)
    assert c.attestation_ref.startswith("dev-unattested:")
    assert c.attestation_ref == f"dev-unattested:{c.cert_der_sha256}"
    # El certificado se puede volver a parsear y su digest coincide.
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_pem_x509_certificate(c.cert_pem.encode())
    der = cert.public_bytes(serialization.Encoding.DER)
    assert c.cert_der_sha256 == cert_digest(der)


def test_verify_binding_ok_and_rejects_mismatch():
    p = DevRATlsProvider()
    c = p.issue("abc123.hermetik.eu", now_ns=lambda: NOW)
    assert verify_ratls_binding(c, "abc123.hermetik.eu") is True
    # Dominio esperado distinto → no liga.
    assert verify_ratls_binding(c, "otro.hermetik.eu") is False


def test_real_provider_fails_instead_of_degrading():
    p = RealRATlsProvider("amd-sev-snp")
    with pytest.raises(RATlsError):
        p.issue("abc123.hermetik.eu", now_ns=lambda: NOW)


def test_make_provider_explicit_and_rejects_unknown():
    assert isinstance(make_ratls_provider("dev"), DevRATlsProvider)
    assert isinstance(make_ratls_provider("sev-snp"), RealRATlsProvider)
    assert isinstance(make_ratls_provider("tdx"), RealRATlsProvider)
    with pytest.raises(RATlsError):
        make_ratls_provider("bogus")


def test_validate_tenant_domain_accepts_good():
    assert validate_tenant_domain("abc123.hermetik.eu") == "abc123.hermetik.eu"
    assert validate_tenant_domain("https://abc123.hermetik.eu") == "abc123.hermetik.eu"
    assert validate_tenant_domain("ABC123.HERMETIK.EU") == "abc123.hermetik.eu"
    # esquema con path/query se descarta
    assert validate_tenant_domain("https://abc.hermetik.eu/path?q=1#f") == "abc.hermetik.eu"


def test_validate_tenant_domain_rejects_bad():
    assert validate_tenant_domain("") is None
    assert validate_tenant_domain("hermetik.eu") is None  # el base en sí no es tenant
    assert validate_tenant_domain("http://abc.hermetik.eu") is None  # http no vale
    assert validate_tenant_domain("*.hermetik.eu") is None  # wildcard
    assert validate_tenant_domain("1.2.3.4") is None  # IP
    assert validate_tenant_domain("a.b.hermetik.eu") is None  # dos etiquetas
    assert validate_tenant_domain("user@hermetik.eu") is None  # userinfo
    assert validate_tenant_domain("abc.otro-dominio.com") is None  # base distinto
    assert validate_tenant_domain("abc.hermetik.eu:8443") is None  # puerto


def test_issue_rejects_invalid_domain():
    p = DevRATlsProvider()
    with pytest.raises(RATlsError):
        p.issue("*.hermetik.eu", now_ns=lambda: NOW)
    with pytest.raises(RATlsError):
        p.issue("hermetik.eu", now_ns=lambda: NOW)
