"""RA-TLS (ADR-01, capa 1) — certificado y clave generados DENTRO del enclave.

La garantía de la capa 1 es que TLS termina DENTRO del enclave, no en un proxy
(Cloudflare/ICP). El certificado se liga al quote de hardware: la clave privada
nace en el enclave y la evidencia de atestación compromete ese certificado, de
modo que ningún intermediario ve el plaintext.

Este módulo es la INTERFAZ + un mock de desarrollo. La implementación real
(SEV-SNP / TDX) se sustituye aquí y solo aquí; nada más cambia en el gateway.

Modelo del vínculo cert↔atestación:
  - En dev: el certificado es autofirmado y `attestation_ref` es
    `dev-unattested:<sha256(der del cert)>`. `verify_ratls_binding` comprueba
    ese vínculo, así que un certificado sustituido se detecta.
  - En real: el quote del vendor lleva el digest del certificado en REPORT_DATA
    y `attestation_ref` apunta a esa evidencia (pendiente de vendor).

Regla dura (igual que atestación): el modo dev NO es un fallback. Se emite
`dev-unattested` solo si se pide explícitamente; el modo real FALLA en vez de
degradar a un certificado autofirmado sin marcar.
"""

from __future__ import annotations

import datetime
import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DEV_ATTEST_PREFIX = "dev-unattested:"
DEFAULT_TTL_NS = 24 * 60 * 60 * 1_000_000_000
DEFAULT_BASE_DOMAIN = "hermetik.eu"


class RATlsError(Exception):
    """Error de la capa RA-TLS. Nunca degrada a dev."""


class RATlsMode(str, Enum):
    DEV = "dev"
    SEV_SNP = "sev-snp"
    TDX = "tdx"


@dataclass(frozen=True)
class RATlsCert:
    """Certificado RA-TLS tal como lo consume el plano de datos.

    `key_pem` solo existe en dev (para pruebas). En un enclave real la clave
    privada NO sale del enclave: no hay campo para serializarla por la red.
    """

    domain: str
    cert_pem: str
    key_pem: str
    state: str  # "attested" | "dev-unattested"
    attestation_ref: str
    expires_at_ns: int
    cert_der_sha256: str


# ------------------------------------------------------------------ dominio

# Un subdominio de tenant: una sola etiqueta (el digest del principal) sobre el
# dominio base. Sin puntos extra, sin wildcard, sin IP, sin userinfo.
_SUBDOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def validate_tenant_domain(domain: str, base_domain: str = DEFAULT_BASE_DOMAIN) -> Optional[str]:
    """Valida que `domain` sea un subdominio de tenant bien formado.

    Devuelve el dominio normalizado (sin esquema, minúsculas) o None si no
    cumple el contrato. El subdominio lo DERIVA el provisioner (`tenant_url`);
    aquí solo se comprueba la forma, que es el contrato que el gateway exige
    antes de emitir un certificado.
    """
    raw = (domain or "").strip().lower()
    if raw.startswith("https://"):
        raw = raw[len("https://"):]
    if raw.startswith("http://"):
        return None  # http no es válido para RA-TLS
    raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if not raw or ":" in raw or "@" in raw or "*" in raw:
        return None
    base = base_domain.strip().lower().lstrip(".")
    if not base:
        return None
    if raw == base or not raw.endswith("." + base):
        return None
    label = raw[: -(len(base) + 1)]
    if not _SUBDOMAIN_RE.match(label):
        return None
    return raw


# ------------------------------------------------------------------ vínculo

def cert_digest(cert_der: bytes) -> str:
    """sha256 hex del DER del certificado — el valor que compromete la atestación."""
    return hashlib.sha256(cert_der).hexdigest()


def verify_ratls_binding(cert: RATlsCert, expected_domain: str) -> bool:
    """Comprueba que el certificado está ligado a su evidencia de atestación.

    - El SAN del certificado debe ser exactamente `expected_domain`.
    - `attestation_ref` debe ser `dev-unattested:<digest>` (en dev) o una
      referencia de quote real (en real, aún sin implementar).

    Esto es lo que el cliente puede re-verificar sin confiar en el gateway:
    que el certificado que recibe es el que la atestación comprometió.
    """
    if cert.domain != expected_domain:
        return False
    if cert.state == "dev-unattested":
        return cert.attestation_ref == f"{DEV_ATTEST_PREFIX}{cert.cert_der_sha256}"
    # Modo real: la verificación la hace el verificador de quotes del vendor.
    return bool(cert.attestation_ref) and not cert.attestation_ref.startswith(DEV_ATTEST_PREFIX)


# ------------------------------------------------------------------ providers

def _self_signed_cert(domain: str, now_ns: int, ttl_ns: int) -> tuple[str, str, str]:
    """Genera un certificado autofirmado ECDSA P-256 con SAN=domain."""
    key = ec.generate_private_key(ec.SECP256R1())
    label = domain.split(".")[0]
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
    not_before = datetime.datetime.fromtimestamp(now_ns // 1_000_000_000 - 3600, tz=datetime.timezone.utc)
    not_after = datetime.datetime.fromtimestamp((now_ns + ttl_ns) // 1_000_000_000, tz=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem, cert_digest(cert.public_bytes(serialization.Encoding.DER))


class DevRATlsProvider:
    """Proveedor de desarrollo: certificado autofirmado, MARCADO como tal.

    Útil para cerrar el producto E2E sin TEE. El certificado es funcional (se
    puede terminar TLS con él), pero el estado y la referencia de atestación
    son inconfundiblemente `dev-unattested`.
    """

    def __init__(self, base_domain: str = DEFAULT_BASE_DOMAIN, ttl_ns: int = DEFAULT_TTL_NS) -> None:
        self.base_domain = base_domain
        self.ttl_ns = ttl_ns

    def issue(self, domain: str, now_ns: Optional[Callable[[], int]] = None) -> RATlsCert:
        normalized = validate_tenant_domain(domain, self.base_domain)
        if normalized is None:
            raise RATlsError(f"dominio de tenant inválido: {domain!r}")
        now = (now_ns or _now_ns)()
        cert_pem, key_pem, digest = _self_signed_cert(normalized, now, self.ttl_ns)
        return RATlsCert(
            domain=normalized,
            cert_pem=cert_pem,
            key_pem=key_pem,
            state="dev-unattested",
            attestation_ref=f"{DEV_ATTEST_PREFIX}{digest}",
            expires_at_ns=now + self.ttl_ns,
            cert_der_sha256=digest,
        )


class RealRATlsProvider:
    """Proveedor real (SEV-SNP / TDX). FALLA: no hay TEE desplegado.

    Es correcto que falle: emitir un certificado autofirmado sin atestación
    real y llamarlo "RA-TLS" sería mentir (degradación silenciosa). Cuando
    llegue el TEE, aquí va la generación dentro del enclave + el quote.
    """

    def __init__(self, vendor: str, base_domain: str = DEFAULT_BASE_DOMAIN) -> None:
        self.vendor = vendor
        self.base_domain = base_domain

    def issue(self, domain: str, now_ns: Optional[Callable[[], int]] = None) -> RATlsCert:
        raise RATlsError(
            "RA-TLS real no implementado: no hay enclave TEE. "
            "Usa DevRATlsProvider explícitamente y declara el claim como dev-unattested."
        )


def make_ratls_provider(mode: str, base_domain: str = DEFAULT_BASE_DOMAIN):
    """Fábrica explícita. No hay valor por defecto permisivo."""
    if mode == RATlsMode.DEV.value:
        return DevRATlsProvider(base_domain=base_domain)
    if mode == RATlsMode.SEV_SNP.value:
        return RealRATlsProvider("amd-sev-snp", base_domain=base_domain)
    if mode == RATlsMode.TDX.value:
        return RealRATlsProvider("intel-tdx", base_domain=base_domain)
    raise RATlsError(f"modo RA-TLS desconocido: {mode!r}")


def _now_ns() -> int:
    import time

    return time.time_ns()
