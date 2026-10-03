"""Atestación de transporte del gateway (F4) — `/v1/attest` + `/v1/session`.

Implementa el LADO SERVIDOR del handshake de ADR-01 (capa 2 + 3). El cliente
(`app/frontend/src/attest/session.ts`) y este módulo deben derivar la MISMA
clave de sesión; si no, el canal falla al primer mensaje cifrado. La clave
queda ligada a la evidencia del enclave: `report_data` entra en el material de
entrada del HKDF.

Contrato (espejo exacto de `session.ts`):

  GET /v1/attest?nonce=<32+B hex>
    → { quote, vendor, binary_hash, session_pub, attestation_state, expires_at }

  POST /v1/session { nonce, client_pub, kem_pub? }
    → el servidor deriva la misma clave (NO la devuelve; devuelve session_id)

  shared      = X25519(server_priv, client_pub)          (32 B)
  reportData  = sha256(nonce || binary_hash)             (hex, 64 chars)
  transcript  = nonce | clientPubHex | sessionPubB64 | reportData | vendor
  ikm         = shared || utf8(reportData)
  sessionKey  = HKDF-SHA256(ikm, salt=utf8(transcript), info="hermetik/v1", 32)

Regla dura (ADR-01): el modo dev NO es un fallback. Se emite `dev-unattested`
solo si `DEV_ATTEST=1` explícita; el modo real FALLA en vez de degradar.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from attestation import DEV_UNATTESTED_PREFIX

# TTL de la referencia de atestación. Debe coincidir con `ATTESTATION_TTL_NS`
# del canister `access` (24h): publicar evidencia más tiempo sería mentir sobre
# su frescura.
DEFAULT_TTL_NS = 24 * 60 * 60 * 1_000_000_000

# Estado efímero del handshake (run-5 HUNT-B-02): TTL + cap. Sin esto, un
# atacante pre-auth podía hinchar `_ephemeral` (un attest por nonce) sin
# límite. TTL 5 min >> RTT del handshake; cap 1024 con evicción del más viejo.
EPHEMERAL_TTL_NS = 5 * 60 * 1_000_000_000
EPHEMERAL_MAX = 1024

# Sesiones del plano de datos (run-5 HUNT-B-02): mismo tratamiento en app.py.
SESSIONS_MAX = 1024
SESSIONS_TTL_S = 30 * 60  # 30 min de inactividad

INFO = b"hermetik/v1"
INFO_C2S = b"hermetik/v1/c2s"
INFO_S2C = b"hermetik/v1/s2c"
SESSION_KEY_BYTES = 32


class AttestMode(str, Enum):
    DEV = "dev"
    SEV_SNP = "amd-sev-snp"
    TDX = "intel-tdx"


class AttestServerError(Exception):
    """Error del handshake de transporte. Nunca degrada a dev."""


@dataclass(frozen=True)
class SessionEstablished:
    """Resultado del `/v1/session`. `session_key` es la clave MAESTRA del canal
    (canónica: `session_id = sha256(maestra)`); NO se devuelve al cliente.
    `session_id` es lo que sí se devuelve (handle opaco). Las subclaves
    direccionales (`tx`/`rx` según el rol) se derivan con
    `derive_directional_keys` — cada dirección cifra con su propia clave, así
    los nonces AES-GCM nunca colisionan aunque el seq coincida (run-5 B-01)."""

    session_key: bytes
    session_id: str
    transcript: str


def expected_report_data(nonce: str, binary_hash: str) -> str:
    """`sha256(nonce || binary_hash)` en hex — espejo de `expectedReportData` en
    el verificador JS. Ata el quote al binario Y a esta sesión."""
    return hashlib.sha256((nonce + binary_hash).encode()).hexdigest()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


class AttestServer:
    """Servidor de atestación con dos modos. La selección es EXPLÍCITA."""

    def __init__(
        self,
        mode: AttestMode,
        binary_hash: str,
        ttl_ns: int = DEFAULT_TTL_NS,
        now_ns: Optional[Callable[[], int]] = None,
        vendor: str = "dev",
    ) -> None:
        if mode not in (AttestMode.DEV, AttestMode.SEV_SNP, AttestMode.TDX):
            raise AttestServerError(f"modo de atestación desconocido: {mode!r}")
        if not binary_hash or len(binary_hash) != 64 or any(
            c not in "0123456789abcdefABCDEF" for c in binary_hash
        ):
            raise AttestServerError("binary_hash debe ser sha256 hex de 64 chars")
        if ttl_ns <= 0:
            raise AttestServerError("ttl_ns debe ser > 0")
        self.mode = mode
        self.binary_hash = binary_hash.lower()
        self.ttl_ns = ttl_ns
        self.vendor = vendor
        self._now = now_ns or time.time_ns
        # nonce -> (keypair, emitido_ns). Con TTL+cap (run-5 B-02).
        self._ephemeral: Dict[str, Tuple[X25519PrivateKey, int]] = {}

    def _validate_nonce(self, nonce: str) -> None:
        # El verificador JS exige nonce.length >= 32 y el gateway lo usa como
        # clave del estado efímero: nonce corto ⇒ anti-replay débil.
        if not nonce or len(nonce) < 32:
            raise AttestServerError("nonce inválido o demasiado corto (mín 32)")

    def _purge_ephemeral(self) -> None:
        """Evicta entradas caducadas (TTL) y, si sigue por encima del cap,
        las más viejas primero. Sin esto el dict crecía sin límite (B-02)."""
        now = self._now()
        expired = [n for n, (_, ts) in self._ephemeral.items() if now - ts > EPHEMERAL_TTL_NS]
        for n in expired:
            self._ephemeral.pop(n, None)
        while len(self._ephemeral) > EPHEMERAL_MAX:
            oldest = min(self._ephemeral, key=lambda n: self._ephemeral[n][1])
            self._ephemeral.pop(oldest, None)

    def attest(self, nonce: str) -> dict:
        """Emite el quote del `/v1/attest` y guarda el keypair efímero del nonce."""
        self._validate_nonce(nonce)
        key = X25519PrivateKey.generate()
        session_pub = _b64(key.public_key().public_bytes_raw())
        report_data = expected_report_data(nonce, self.binary_hash)

        if self.mode is AttestMode.DEV:
            # Quote de desarrollo: marcado y ruidoso. Espejo de `buildDevQuote`.
            quote = f"{DEV_UNATTESTED_PREFIX}{report_data}|dev-root,sig=dev"
            state = "dev-unattested"
        else:
            # Modo real: necesita TEE. Falla, no degrada.
            raise AttestServerError(
                "modo real no implementado: no hay TEE desplegado. "
                "Usa AttestMode.DEV explícitamente o despliega la infra."
            )

        self._ephemeral[nonce] = (key, self._now())
        self._purge_ephemeral()
        return {
            "quote": quote,
            "vendor": self.vendor,
            "binary_hash": self.binary_hash,
            "session_pub": session_pub,
            "attestation_state": state,
            "expires_at": self._now() + self.ttl_ns,
        }

    def session(self, nonce: str, client_pub_b64: str) -> SessionEstablished:
        """Deriva la clave de sesión del `/v1/session`. La clave NO se devuelve."""
        self._validate_nonce(nonce)
        entry = self._ephemeral.pop(nonce, None)  # single-use: consumir aquí (B-02)
        if entry is None:
            raise AttestServerError("nonce desconocido o ya consumido (¿session sin attest previo?)")
        key = entry[0]
        try:
            client_pub_raw = base64.b64decode(client_pub_b64, validate=True)
        except Exception as exc:
            raise AttestServerError("client_pub no es base64 válido") from exc
        if len(client_pub_raw) != 32:
            raise AttestServerError("client_pub debe medir 32 bytes")

        peer = X25519PublicKey.from_public_bytes(client_pub_raw)
        shared = key.exchange(peer)  # 32 B
        session_pub_b64 = _b64(key.public_key().public_bytes_raw())
        report_data = expected_report_data(nonce, self.binary_hash)

        transcript = f"{nonce}|{client_pub_raw.hex()}|{session_pub_b64}|{report_data}|{self.vendor}"
        session_key = self._derive(shared, report_data, transcript)

        # session_id = handle opaco (sha256 de la clave), nunca la clave.
        session_id = hashlib.sha256(session_key).hexdigest()
        return SessionEstablished(
            session_key=session_key,
            session_id=session_id,
            transcript=transcript,
        )

    @staticmethod
    def _derive(shared: bytes, report_data: str, transcript: str) -> bytes:
        ikm = shared + report_data.encode()  # shared(32) || utf8(reportData)(64)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=SESSION_KEY_BYTES,
            salt=transcript.encode(),
            info=INFO,
        )
        return hkdf.derive(ikm)

    @staticmethod
    def _expand(master: bytes, info: bytes) -> bytes:
        """Subclave direccional: HKDF-SHA256(master, salt=b"", info)."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=SESSION_KEY_BYTES,
            salt=b"",
            info=info,
        )
        return hkdf.derive(master)


def derive_directional_keys(master: bytes) -> Tuple[bytes, bytes]:
    """(c2s, s2c) desde la clave maestra. El cliente cifra con c2s y abre con
    s2c; el servidor al revés. Mismo `session_id` (sha256 de la maestra)."""
    if len(master) != SESSION_KEY_BYTES:
        raise AttestServerError("la clave maestra debe medir 32 bytes")
    c2s = AttestServer._expand(master, INFO_C2S)
    s2c = AttestServer._expand(master, INFO_S2C)
    if c2s == s2c:
        raise AttestServerError("colisión de subclaves direccionales (imposible)")
    return c2s, s2c


def from_env() -> AttestServer:
    """Construye el servidor desde el entorno. Selección EXPLÍCITA.

    `DEV_ATTEST=1` → modo dev (emitirá `dev-unattested`). Ausente → modo real,
    que hoy FALLA al emitir (no hay TEE). No hay valor por defecto permisivo.
    """
    binary_hash = os.environ.get("HERMETIK_BINARY_HASH", "").strip()
    if not binary_hash:
        raise AttestServerError(
            "HERMETIK_BINARY_HASH no configurado (pinning del binario del gateway)"
        )
    if os.environ.get("DEV_ATTEST", "").strip() in ("1", "true", "yes"):
        return AttestServer(AttestMode.DEV, binary_hash)
    # Sin DEV_ATTEST: modo real. Emitir un quote fallará (correcto: no hay TEE).
    vendor = os.environ.get("HERMETIK_TEE_VENDOR", "amd-sev-snp").strip()
    mode = AttestMode.SEV_SNP if "snp" in vendor.lower() else AttestMode.TDX
    return AttestServer(mode, binary_hash, vendor=vendor)
