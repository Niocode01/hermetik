"""Atestación del emisor de evidencia — módulo intercambiable.

Diseño (ADR-02 §3b): la evidencia la firma el EMISOR (el overwatch), no el TEE.
El TEE no firma: atestigua QUÉ CÓDIGO CORRE Y EN QUÉ CLAVE. La pieza que el TEE
aporta es que la clave de firma nace dentro del enclave y que el quote compromete
esa clave (PoC C7.2.4: el digest de la clave va en REPORT_DATA).

Este módulo implementa SOLO la parte atestadora. El emisor le pregunta:
  - "¿cuál es el digest de la clave de firma que hay que poner en REPORT_DATA?"
  - "dame un reporte de atestación para este nonce"

Hoy devuelve un reporte MARCADO como no atestiguado (`dev-unattested:`). Nunca
hay fallback automático: si no hay TEE, el reporte sale marcado y ruidoso, con un
campo comprobable por el frontend. Un verificador honesto tiene que FALLAR al
recibirlo, y la UI lo pinta como "enclave no atestiguado — modo desarrollo".

Cuando llegue el TEE real, se sustituye la implementación de esta clase. Nada más
cambia: ni el formato del registro, ni la firma, ni la cadena.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from enum import Enum

# Prefijo obligatorio del modo de desarrollo. Un verificador que no lo compruebe
# aceptará evidencia no atestiguada como si lo estuviera: por eso es ruidoso y
# por eso va también en el campo estructurado `mode`, no solo en el texto.
DEV_UNATTESTED_PREFIX = "dev-unattested:"

# Tamaño de REPORT_DATA en SEV-SNP (64 B) y TDX (64 B). El digest de la clave de
# firma va aquí, no la clave. Esto es el contrato con el verificador.
REPORT_DATA_BYTES = 64

# Algoritmo por defecto hoy: Ed25519 puro (COSE alg_id -8).
# Con TEE + PQ pasará a híbrido Ed25519+ML-DSA-65 (alg_id -1000).
ALG_EDDSA = -8
ALG_ML_DSA_65 = -49
ALG_HYBRID_PQ = -1000


class AttestationMode(str, Enum):
    """Modo del atestador. Explícito, sin valores implícitos."""

    DEV_UNATTESTED = "dev-unattested"
    SEV_SNP = "sev-snp"
    TDX = "tdx"


class AttestationError(Exception):
    """Error de atestación. Nunca se degrada en silencio."""


@dataclass(frozen=True)
class AttestationReport:
    """Reporte de atestación tal y como lo consume el verificador.

    Con TEE real, `quote` es el quote crudo (SEV-SNP o TDX) y `vendor` lo
    identifica. Hoy, `quote` es una cadena `dev-unattested:` y `mode` lo marca.
    """

    mode: AttestationMode
    vendor: str
    quote: bytes
    report_data: bytes  # 64 B: digest de la clave de firma + nonce, según §3b
    signing_key_digest: str  # sha-256:<hex> del keypair de firma del emisor
    unwrap_interval_ns: int  # C7.2.3: intervalo máx. de refresco declarado
    measured_binary: str  # digest del binario medido (con TEE); "unmeasured" hoy

    @property
    def is_attested(self) -> bool:
        """True solo si hay atestación real de hardware.

        NO basta con que el campo exista: exige un modo de hardware.
        """
        return self.mode in (AttestationMode.SEV_SNP, AttestationMode.TDX)

    @property
    def dev_marker_present(self) -> bool:
        """Comprueba que el marcador de desarrollo está donde debe estar."""
        return self.quote.startswith(DEV_UNATTESTED_PREFIX.encode())


def digest_of_signing_key(public_key: bytes) -> str:
    """Digest etiquetado del keypair de firma (PoC: digests SIEMPRE etiquetados).

    Este valor es el que va dentro de REPORT_DATA con TEE real (C7.2.4): ata la
    clave de firma al entorno medido. Sin etiqueta el digest se RECHAZA.
    """
    return "sha-256:" + hashlib.sha256(public_key).hexdigest()


def build_report_data(signing_key_digest: str, eat_nonce: bytes) -> bytes:
    """Construye los 64 B de REPORT_DATA = digest(clave firma) || digest(nonce).

    El verificador recomputa esto desde la clave que ve firmar y el nonce que él
    mismo emitió: si no coincide, el handshake falla (no hay fallback).
    """
    m = hashlib.sha256(signing_key_digest.encode()).digest()
    n = hashlib.sha256(eat_nonce).digest()
    return (m + n)[:REPORT_DATA_BYTES]


class DevAttestor:
    """Atestador de desarrollo. Produce evidencia NO atestiguada, marcada.

    Es deliberadamente ruidoso y no debe usarse en producción. El modo real debe
    instanciarse explícitamente; no hay elección automática entre ambos.
    """

    def __init__(self, signing_public_key: bytes, unwrap_interval_ns: int) -> None:
        if not signing_public_key:
            raise AttestationError("signing_public_key vacía: rechazado")
        if unwrap_interval_ns <= 0:
            raise AttestationError(
                "unwrap_interval_ns debe ser > 0 (C7.2.3: hay que declarar intervalo)"
            )
        self._pub = signing_public_key
        self._interval = unwrap_interval_ns

    def attest(self, eat_nonce: bytes) -> AttestationReport:
        """Emite un reporte marcado como no atestiguado."""
        if not (8 <= len(eat_nonce) <= 64):
            raise AttestationError(
                f"eat_nonce debe medir 8..64 B (PoC), recibidos {len(eat_nonce)}"
            )
        key_digest = digest_of_signing_key(self._pub)
        report_data = build_report_data(key_digest, eat_nonce)
        # El quote de desarrollo lleva el prefijo obligatorio. No es un quote.
        quote = DEV_UNATTESTED_PREFIX.encode() + report_data.hex().encode()
        return AttestationReport(
            mode=AttestationMode.DEV_UNATTESTED,
            vendor="none",
            quote=quote,
            report_data=report_data,
            signing_key_digest=key_digest,
            unwrap_interval_ns=self._interval,
            measured_binary="unmeasured",
        )


class RealAttestor:
    """Atestador de hardware real (SEV-SNP / TDX).

    NO implementado todavía: no hay TEE desplegado. Existir y fallar es lo
    correcto — es el punto entero del diseño (ADR-02 §3b). Debe fallar en vez
    de degradar a dev-unattested.
    """

    def __init__(self, vendor: str, unwrap_interval_ns: int) -> None:
        self._vendor = vendor
        self._interval = unwrap_interval_ns

    def attest(self, eat_nonce: bytes) -> AttestationReport:
        raise AttestationError(
            "RealAttestor no implementado: no hay TEE disponible. "
            "No se degrada a dev-unattested automáticamente (eso sería mentir). "
            "Usa DevAttestor explícitamente y declara el claim como Tier 2."
        )


def make_attestor(mode: str, signing_public_key: bytes, unwrap_interval_ns: int):
    """Fábrica explícita. NO hay valor por defecto permisivo.

    Devuelve un atestador de desarrollo solo si se pide por nombre; un modo de
    hardware devuelve el atestador real (que hoy fallará, y debe fallar).
    """
    if mode == AttestationMode.DEV_UNATTESTED.value:
        return DevAttestor(signing_public_key, unwrap_interval_ns)
    if mode in (AttestationMode.SEV_SNP.value, AttestationMode.TDX.value):
        return RealAttestor(mode, unwrap_interval_ns)
    raise AttestationError(
        f"modo de atestación desconocido: {mode!r}. "
        f"Esperado: dev-unattested | sev-snp | tdx"
    )
