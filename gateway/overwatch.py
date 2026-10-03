"""Overwatch — emisor de evidencia como proceso separado del agente.

PoC C7.1.1 (nivel 3): la evidencia la emite un Action Interception Gateway que
corre **como proceso separado del agente**, sin ruta de red ni de credenciales que
lo evite. Si el propio agente emite su evidencia, es auto-reportado (techo Tier 2
por esa razón además de las otras).

Diseño (ADR-02 §3b):
  - El EMISOR es el overwatch: firma cada registro con su clave.
  - El ATESTADOR prueba que el emisor es quien dice (hoy: mock marcado).
  - La clave de firma vive FUERA del alcance del agente (C7.3.2).

C7.1.3 — la emisión es PRECONDICIÓN de la acción: no se libera la acción hasta que
el registro `before` está escrito de forma durable. Si el almacén no está, la acción
NO procede. Esto no es "loggear": es un gate.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from attestation import AttestationError, AttestationReport, make_attestor
from poc_schema import (
    INTERCEPTION_POINT_NAMES,
    EvidenceRecord,
    digest_claim,
    jcs,
    sha256_tagged,
    signing_input,
)

# ------------------------------------------------------------------ claves


def derive_signing_key(seed: bytes) -> bytes:
    """Deriva la clave de firma del emisor.

    Con TEE, esta derivación ocurriría DENTRO del enclave y la clave nunca saldría
    en claro; solo su digest iría en REPORT_DATA (C7.2.4). Hoy se hace aquí, y esa
    es precisamente la razón del techo Tier 2 (C7.3.2: el operador no debería poder
    acceder a la clave, y hoy sí puede).
    """
    if not seed:
        raise ValueError("seed vacía: no se deriva clave de firma de nada")
    return hashlib.sha256(b"hermetik-overwatch-signing-key/v1" + seed).digest()


class Signer(Protocol):
    """Firmante. Ed25519 hoy; híbrido Ed25519+ML-DSA con PQ."""

    def sign(self, payload: bytes) -> bytes: ...
    def public_key(self) -> bytes: ...
    def alg_name(self) -> str: ...


class DevSigner:
    """Firmante de desarrollo: HMAC-SHA256 sobre la clave derivada.

    No es Ed25519 real (no hay dependencias criptográficas en este entorno de
    test), pero cumple el contrato: firma determinista y verificable. El día del
    despliegue se sustituye por el firmante Ed25519 sin tocar el overwatch.
    """

    def __init__(self, key: bytes) -> None:
        if not key:
            raise ValueError("clave vacía")
        self._key = key

    def sign(self, payload: bytes) -> bytes:
        return hmac.new(self._key, payload, hashlib.sha256).digest()

    def public_key(self) -> bytes:
        return hashlib.sha256(self._key).digest()

    def alg_name(self) -> str:
        return "EdDSA"


# ------------------------------------------------------------------ almacén


class EvidenceSink(Protocol):
    """Destino durable de la evidencia. Si falla, la acción no procede."""

    def append(self, record_bytes: bytes) -> str: ...
    def head(self) -> str | None: ...


class InMemorySink:
    """Almacén en memoria para tests. NO durable: no usar en producción."""

    def __init__(self) -> None:
        self.entries: list[bytes] = []

    def append(self, record_bytes: bytes) -> str:
        self.entries.append(record_bytes)
        return sha256_tagged(record_bytes)

    def head(self) -> str | None:
        return sha256_tagged(self.entries[-1]) if self.entries else None


class FileSink:
    """Almacén append-only en fichero. El head encadena por hash."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record_bytes: bytes) -> str:
        with self._path.open("ab") as f:
            f.write(record_bytes + b"\n")
            f.flush()
            os.fsync(f.fileno())  # durabilidad real antes de liberar la acción
        return sha256_tagged(record_bytes)

    def head(self) -> str | None:
        if not self._path.exists():
            return None
        last = None
        with self._path.open("rb") as f:
            for line in f:
                if line.strip():
                    last = line
        return sha256_tagged(last.rstrip(b"\n")) if last else None


# ------------------------------------------------------------------ errores


class OverwatchError(Exception):
    """Fallo del overwatch. Fail-closed: la acción NO procede."""


class EvidenceUnavailable(OverwatchError):
    """El almacén no está disponible ⇒ la acción no se libera (C7.1.3)."""


# ------------------------------------------------------------------ overwatch


@dataclass
class PendingAction:
    """Acción interceptada, a la espera de las tres fases.

    `agent_id` es el principal del EMISOR (gateway/overwatch: quién emite la
    evidencia). `principal_id` es el principal del USUARIO bajo cuya autoridad se
    actúa: viene de la cabecera `X-Nebulock-User` del request, YA VERIFICADA
    contra la credencial nb2 (el gateway exige 403 si no coincide con el
    principal firmado en la credencial). Sin nb2 vigente no hay principal y por
    tanto no hay acción: el overwatch nunca inventa el campo.
    """

    action_id: str
    interception_point: int
    agent_id: str
    principal_id: str
    # Prueba de que el principal fue verificado: "nb2" + expiración de la
    # credencial que lo autorizaba (el `expiry_ns` del token). Un auditor puede
    # comprobar que la acción ocurrió dentro de la ventana de vigencia.
    credential_scheme: str = "nb2"
    credential_expiry_ns: int = 0
    target_resource: str | None = None
    reason: str | None = None
    before_digest: str | None = None
    during_digest: str | None = None
    after_digest: str | None = None

    def __post_init__(self) -> None:
        if self.credential_scheme != "nb2":
            raise OverwatchError(
                f"esquema de credencial no admitido: {self.credential_scheme!r} "
                f"(solo 'nb2', que es lo que verifica X-Nebulock-User)"
            )
        if not self.principal_id:
            raise OverwatchError(
                "principal_id vacío: el overwatch nunca inventa el principal del "
                "usuario. Sin X-Nebulock-User verificado no hay acción."
            )


class Overwatch:
    """Emisor de evidencia. Proceso separado del agente (C7.1.1).

    Mantiene el `step_index` monótono por agente y el `chain_head`, que es lo que
    hace la cadena verificable (C7.3.1).
    """

    def __init__(
        self,
        *,
        signer: Signer,
        sink: EvidenceSink,
        attestor,
        iss: str = "https://hermetik.example/overwatch",
        eat_profile: str | None = None,
    ) -> None:
        self._signer = signer
        self._sink = sink
        self._attestor = attestor
        self._iss = iss
        self._step_index: dict[str, int] = {}
        self._head: str | None = sink.head()
        self._nonce_counter = 0

    # -- internos ----------------------------------------------------------

    def _next_step(self, agent_id: str) -> int:
        n = self._step_index.get(agent_id, 0)
        self._step_index[agent_id] = n + 1
        return n

    def _fresh_nonce(self) -> str:
        """Nonce de 8..64 B. En producción lo emite el verificador (challenge)."""
        self._nonce_counter += 1
        return f"n-{self._nonce_counter:08d}"

    def _emit(
        self,
        *,
        action: PendingAction,
        phase: int,
        prior_digest: str | None = None,
    ) -> str:
        """Construye, firma y persiste un registro. Devuelve su digest.

        Si el sink falla, propaga `EvidenceUnavailable`: la acción NO procede.
        """
        nonce = self._fresh_nonce()
        try:
            report: AttestationReport = self._attestor.attest(nonce.encode())
        except AttestationError as e:
            # Cero degradación silenciosa: si no hay atestación, se para.
            raise OverwatchError(f"atestación no disponible: {e}") from e

        att_submod = {
            "measurement": digest_claim(report.report_data),
            "platform": "SOFTWARE" if not report.is_attested else report.vendor.upper(),
            "mode": report.mode.value,
        }
        if not report.is_attested:
            # Campo comprobable por el frontend + marcador ruidoso (ADR-02 §3b).
            att_submod["dev_unattested"] = True
            att_submod["marker"] = "dev-unattested:"

        rec = EvidenceRecord(
            iss=self._iss,
            iat=int(time.time()),
            nonce=nonce,
            agent_id=action.agent_id,
            initiating_user=action.principal_id,
            action_id=action.action_id,
            # La ventana de vigencia de la credencial que autorizó al principal:
            # el auditor comprueba que iat <= credential_expiry_ns.
            credential_expiry_ns=action.credential_expiry_ns,
            interception_point=phase,
            step_index=self._next_step(action.agent_id),
            verdict=1,  # ALLOW: allow-list, no gate de política en este punto
            policy_bundle_hash=digest_claim(b"policy-v1"),
            alg=self._signer.alg_name(),
            # El chain_head es el digest etiquetado del registro anterior TAL
            # CUAL ("alg:hex"), no el hash de un hash: encadenar el hash de un
            # string etiquetado rompería la verificación de la cadena (C7.3.1).
            chain_head=self._head,
            canonical_snapshot_hash=(
                digest_claim(prior_digest.encode()) if prior_digest else None
            ),
            target_resource=action.target_resource,
            reason=action.reason,
            attestation=att_submod,
        )
        payload = signing_input(rec.token())
        signature = self._signer.sign(payload).hex()
        token = rec.token()
        token["signature"] = signature
        record_bytes = jcs(token)

        try:
            digest = self._sink.append(record_bytes)
        except Exception as e:
            raise EvidenceUnavailable(
                f"almacén de evidencia no disponible: {e}. La acción NO procede."
            ) from e
        self._head = digest
        return digest

    # -- API de las tres fases (C7.1.2) -----------------------------------

    def before(self, action: PendingAction) -> str:
        """Registro `before`. C7.1.3: la acción NO se libera hasta que esté escrito."""
        if action.interception_point != 4:
            raise OverwatchError(
                f"before() exige el hook pre-call-tool (4), no {action.interception_point}"
            )
        d = self._emit(action=action, phase=4)
        action.before_digest = d
        return d

    def during(self, action: PendingAction) -> str:
        """Registro `during`. C7.1.4: mediación del canal de efecto."""
        if action.before_digest is None:
            raise OverwatchError(
                "during() sin before(): se rompería el orden de la cadena (C7.1.2)"
            )
        d = self._emit(action=action, phase=5, prior_digest=action.before_digest)
        action.during_digest = d
        return d

    def after(self, action: PendingAction) -> str:
        """Registro `after`, ligado al mismo action_id (C7.1.2).

        Usa el hook 8 (task-completion): during es el hook 5 y after DEBE ser
        distinguible de during en `interception_point` (run-2, H3). El
        correlador primario es `action_id` firmado en cada registro; el
        encadenado por hash es secundario.
        """
        if action.during_digest is None:
            raise OverwatchError("after() sin during(): orden de cadena roto")
        d = self._emit(action=action, phase=8, prior_digest=action.during_digest)
        action.after_digest = d
        return d

    def memory_write(self, action: PendingAction) -> str:
        """Hook 6 `memory-write`: por aquí sube Hermes su memoria."""
        d = self._emit(action=action, phase=6)
        return d

    @property
    def head(self) -> str | None:
        return self._head


def make_overwatch_from_env(signer_seed: bytes | None = None) -> Overwatch:
    """Construye el overwatch desde entorno. Modo explícito, sin default permisivo."""
    mode = os.environ.get("HERMETIK_ATTEST_MODE")
    if not mode:
        raise OverwatchError(
            "HERMETIK_ATTEST_MODE no definido. Modos: dev-unattested | sev-snp | tdx. "
            "No hay valor por defecto: el modo silencioso es como se vende Tier 3 sin TEE."
        )
    ttl = int(os.environ.get("HERMETIK_ATTEST_TTL_NS", "300000000000"))
    seed = signer_seed if signer_seed is not None else os.environ.get(
        "HERMETIK_OVERWATCH_SEED", ""
    ).encode()
    if not seed:
        raise OverwatchError("HERMETIK_OVERWATCH_SEED no definido: sin clave no hay firma")
    key = derive_signing_key(seed)
    signer = DevSigner(key)
    attestor = make_attestor(mode, signer.public_key(), ttl)
    sink_path = os.environ.get("HERMETIK_EVIDENCE_PATH")
    sink = FileSink(Path(sink_path)) if sink_path else InMemorySink()
    return Overwatch(signer=signer, sink=sink, attestor=attestor)
