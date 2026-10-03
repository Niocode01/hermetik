"""Esquema canónico PoC — renderizado JSON del token de evidencia.

CONFORMIDAD: este módulo se escribe contra el schema JSON normativo
(`poc-evidence.schema.json`) y sus vectores publicados. En el renderizado
JSON los digests son STRINGS etiquetados "alg:hex" (estilo OCI). El CDDL
define `digest = [ hash-alg, bstr ]` (ARRAY) solo para el renderizado
CBOR/CWT: son dos renderizados del mismo claim set, y el mapeo está
declarado en el `cbor_profile.py` normativo (string <-> [int-alg, bytes]).

Historial: la primera versión de este fichero emitía arrays en el JSON
(run-2, rejected de interop: fail-closed pero rechazado por un verificador
estricto). Desde el fix, el JSON usa strings en todas partes; el helper
`digest_claim_cbor` conserva la forma array solo para el futuro CBOR.

Reglas del perfil (canonicalization.md), todas aplicadas:
  - Sin floats NUNCA en el claim set.
  - Digests etiquetados "alg:hex" en minúsculas, con la longitud de su alg
    (vectores untagged-digest y digest-alg-width-mismatch).
  - Ausente ≠ vacío: el opcional que no aplica se OMITE.
  - Claves duplicadas ⇒ RECHAZO.
  - Firma sobre el token SIN el campo `signature`.

Los 8 hooks (C7.1), con los nombres EXACTOS del schema normativo
(`poc-evidence.schema.json`, enum de `interception_point`):
  1 task-initialization  2 context-assembly  3 plan-generation
  4 pre-call-tool-invocation  5 post-call-tool-result  6 memory-write
  7 subagent-delegation  8 task-completion
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

PROFILE_URI = "https://advancedaisociety.org/poc/v0.1"

# --- Enumerados del schema JSON ----------------------------------------------

INTERCEPTION_POINT_NAMES = {
    1: "TASK_INITIALIZATION",
    2: "CONTEXT_ASSEMBLY",
    3: "PLAN_GENERATION",
    4: "PRE_CALL_TOOL_INVOCATION",
    5: "POST_CALL_TOOL_RESULT",
    6: "MEMORY_WRITE",
    7: "SUBAGENT_DELEGATION",
    8: "TASK_COMPLETION",
}

VERDICT_NAMES = {1: "ALLOW", 2: "DENY", 3: "MODIFY", 4: "ESCALATE"}

# Valores normativos del claim `alg` (poc-evidence.schema.json, enum exacto).
# El 5o valor es "Ed25519+ML-DSA-44": el repo lo tuvo una temporada como
# "hybrid-eddsa-mldsa44" y ese nombre NO es normativo (run-2, H2).
ALG_ALLOWLIST = {"EdDSA", "ES256", "ML-DSA-44", "ML-DSA-65",
                 "Ed25519+ML-DSA-44"}

# Plataformas que pueden soportar Tier 3+ (validador normativo, capa semántica).
# SOFTWARE NO está aquí: es exactamente el motivo de que hoy el techo sea Tier 2.
TIER_CAPABLE_PLATFORMS = {"INTEL_TDX", "AMD_SEV_SNP", "ARM_CCA", "AWS_NITRO"}

HASH_ALGS = {"sha-256", "sha-384", "sha-512", "sha3-256"}


class CanonicalizationError(Exception):
    """El token no se puede canonicalizar sin ambigüedad. Nunca se degrada."""


# ---------------------------------------------------------------- RFC 8785 JCS

_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
            "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)  # non-ASCII se emite literal
    out.append('"')
    return "".join(out)


def _sort_key(k: str) -> bytes:
    """RFC 8785 ordena por code UNIT UTF-16, no por code point.

    Difieren para caracteres fuera del BMP; hay un vector publicado solo para
    esto (canonical/nonbmp-key-ordering.json, RFC 8785 §3.2.3).
    """
    return k.encode("utf-16-be")


def _jcs(obj: Any) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        return _jcs_string(obj)
    if isinstance(obj, bool):  # por si acaso, antes que int
        return "true" if obj else "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        # El claim set los prohíbe; aquí se rechaza en vez de serializar.
        raise CanonicalizationError(f"float prohibido en el claim set: {obj!r}")
    if isinstance(obj, list):
        return "[" + ",".join(_jcs(v) for v in obj) + "]"
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: _sort_key(kv[0]))
        return "{" + ",".join(f"{_jcs_string(k)}:{_jcs(v)}" for k, v in items) + "}"
    raise CanonicalizationError(f"tipo no serializable: {type(obj).__name__}")


def jcs(obj: Any) -> bytes:
    """Bytes canónicos RFC 8785. Es lo que cubre la firma."""
    return _jcs(obj).encode("utf-8")


def load_token(raw: str | bytes) -> dict:
    """Carga un token rechazando claves duplicadas.

    Sin esta guarda, un parser 'gana la última' hace que un mismo token signifique
    dos cosas distintas: hay vector negativo publicado (duplicate-key).
    """

    def hook(pairs):
        seen = set()
        for k, _ in pairs:
            if k in seen:
                raise CanonicalizationError(f"clave duplicada: {k!r}")
            seen.add(k)
        return dict(pairs)

    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    try:
        return json.loads(raw, object_pairs_hook=hook)
    except CanonicalizationError:
        raise
    except json.JSONDecodeError as e:
        raise CanonicalizationError(f"JSON ilegible: {e}") from e


def signing_input(token: dict) -> bytes:
    """Bytes que cubre la firma: el token con `signature` eliminado."""
    return jcs({k: v for k, v in token.items() if k != "signature"})


def sha256_tagged(data: bytes) -> str:
    """Digest etiquetado para uso interno (cadena, no claim set)."""
    return "sha-256:" + hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- digest helper


def digest_claim(data: bytes, alg: str = "sha-256") -> str:
    """Construye un digest del claim set JSON: STRING "alg:hex" (estilo OCI).

    Es lo que exige el schema JSON normativo. Para la forma array del
    renderizado CBOR, ver `digest_claim_cbor`.
    """
    if alg not in HASH_ALGS:
        raise CanonicalizationError(f"algoritmo de hash no admitido: {alg!r}")
    if alg == "sha-256":
        h = hashlib.sha256(data).hexdigest()
    elif alg == "sha-384":
        h = hashlib.sha384(data).hexdigest()
    elif alg == "sha-512":
        h = hashlib.sha512(data).hexdigest()
    else:  # sha3-256
        h = hashlib.sha3_256(data).hexdigest()
    return f"{alg}:{h}"


def digest_claim_cbor(data: bytes, alg: str = "sha-256") -> list:
    """Forma array [alg, hex] del digest, SOLO para el futuro renderizado CBOR.

    El CDDL define `digest = [ hash-alg, bstr ]`. No usar en el JSON: allí el
    digest es string (ver `digest_claim`). Se conserva para no perder el
    mapeo cuando se implemente el segundo renderizado.
    """
    if alg not in HASH_ALGS:
        raise CanonicalizationError(f"algoritmo de hash no admitido: {alg!r}")
    _, _, hexpart = digest_claim(data, alg).partition(":")
    return [alg, hexpart]


# ---------------------------------------------------------------- registro


@dataclass
class EvidenceRecord:
    """Registro de evidencia en el renderizado JSON del token PoC.

    `verdict` y `interception_point` se dan aquí como nombres de enum (1..4 y
    1..8) y se serializan con su nombre textual, como en los vectores.
    """

    iss: str
    iat: int
    nonce: str
    agent_id: str
    initiating_user: str
    interception_point: int
    step_index: int
    verdict: int
    action_id: str = ""
    policy_bundle_hash: str | None = None
    alg: str = "EdDSA"
    agbom_digest: str | None = None
    chain_head: str | None = None
    canonical_snapshot_hash: str | None = None
    path_summary_hash: str | None = None
    merkle_root: str | None = None
    tree_size: int | None = None
    target_resource: str | None = None
    reason: str | None = None
    # Ventana de vigencia de la credencial nb2 que autorizó al principal
    # (el `expiry_ns` del token). Campo de extensión propio (hermetik-*):
    # el CDDL permite `* tstr => any` como puntos de extensión que los
    # verificadores que no los entienden ignoran. El auditor comprueba
    # `iat <= credential_expiry_ns`: evidencia emitida con credencial caducada
    # no vale. 0 = sin ventana declarada (solo en tests sin nb2).
    credential_expiry_ns: int = 0
    attestation: dict | None = None
    eat_profile: str = PROFILE_URI

    def _check(self) -> None:
        if self.interception_point not in INTERCEPTION_POINT_NAMES:
            raise CanonicalizationError(
                f"interception_point fuera de 1..8: {self.interception_point}"
            )
        if self.verdict not in VERDICT_NAMES:
            raise CanonicalizationError(f"verdict fuera de 1..4: {self.verdict}")
        if self.alg not in ALG_ALLOWLIST:
            raise CanonicalizationError(
                f"alg fuera del enum normativo "
                f"(EdDSA, ES256, ML-DSA-44, ML-DSA-65, Ed25519+ML-DSA-44): "
                f"{self.alg!r}"
            )
        if not self.action_id:
            raise CanonicalizationError(
                "action_id vacío: el correlador de fases debe ir firmado "
                "en cada registro (run-2, H3)"
            )
        if not isinstance(self.iat, int) or isinstance(self.iat, bool):
            raise CanonicalizationError(f"iat debe ser int (segundos): {self.iat!r}")
        if self.step_index < 0:
            raise CanonicalizationError(f"step_index negativo: {self.step_index}")
        if self.eat_profile != PROFILE_URI:
            raise CanonicalizationError(
                f"eat_profile desconocido: {self.eat_profile!r} "
                f"(un claim no se interpreta bajo un perfil desconocido)"
            )
        if not isinstance(self.credential_expiry_ns, int) or isinstance(
            self.credential_expiry_ns, bool
        ):
            raise CanonicalizationError(
                f"credential_expiry_ns debe ser int (ns): {self.credential_expiry_ns!r}"
            )
        if self.credential_expiry_ns < 0:
            raise CanonicalizationError(
                f"credential_expiry_ns negativo: {self.credential_expiry_ns}"
            )
        for name in (
            "policy_bundle_hash", "agbom_digest", "chain_head",
            "canonical_snapshot_hash", "path_summary_hash", "merkle_root",
        ):
            v = getattr(self, name)
            if v is not None:
                _check_digest_claim(v, name)

    def claims(self) -> dict:
        """Mapa `poc_claims`, OMITIENDO los opcionales que no aplican."""
        self._check()
        c: dict = {
            "action_id": self.action_id,
            "agent_id": self.agent_id,
            "alg": self.alg,
            "initiating_user": self.initiating_user,
            "interception_point": INTERCEPTION_POINT_NAMES[self.interception_point],
            "step_index": self.step_index,
            "verdict": VERDICT_NAMES[self.verdict],
        }
        optional = {
            "policy_bundle_hash": self.policy_bundle_hash,
            "agbom_digest": self.agbom_digest,
            "chain_head": self.chain_head,
            "canonical_snapshot_hash": self.canonical_snapshot_hash,
            "path_summary_hash": self.path_summary_hash,
            "merkle_root": self.merkle_root,
            "tree_size": self.tree_size,
            "target_resource": self.target_resource,
            "reason": self.reason,
            # Extensión hermetik: solo se emite cuando hay ventana declarada
            # (ausente ≠ 0: 0 significa "sin declarar", nunca se serializa).
            "hermetik_credential_expiry_ns": (
                self.credential_expiry_ns if self.credential_expiry_ns > 0 else None
            ),
        }
        for k, v in optional.items():
            if v is not None:
                c[k] = v
        return c

    def token(self, *, with_attestation: bool = True) -> dict:
        t: dict = {
            "eat_profile": self.eat_profile,
            "iat": self.iat,
            "iss": self.iss,
            "nonce": self.nonce,
            "poc_claims": self.claims(),
        }
        if with_attestation and self.attestation is not None:
            t["submods"] = {"attestation": self.attestation}
        return t

    def signing_digest(self) -> str:
        """Digest del payload firmable. Va al hash-chain del vault."""
        return sha256_tagged(signing_input(self.token()))


def _check_digest_claim(v: Any, path: str) -> None:
    """Un digest del claim set JSON es "alg:hex-minúsculas" con longitud correcta.

    El string SIN etiqueta se rechaza (hay que no adivinar el algoritmo:
    vector untagged-digest) y la longitud debe corresponder al alg declarado
    (vector digest-alg-width-mismatch).
    """
    if not isinstance(v, str) or ":" not in v:
        raise CanonicalizationError(
            f"{path}: un digest es \"alg:hex\", recibido {v!r}. "
            f"El algoritmo nunca se adivina (vector untagged-digest)."
        )
    alg, _, hexpart = v.partition(":")
    if alg not in HASH_ALGS:
        raise CanonicalizationError(f"{path}: alg no admitido {alg!r}")
    expected = {"sha-256": 64, "sha-384": 96, "sha-512": 128, "sha3-256": 64}[alg]
    if len(hexpart) != expected:
        raise CanonicalizationError(
            f"{path}: longitud {len(hexpart)} "
            f"no corresponde a {alg} (esperado {expected}) "
            f"— vector digest-alg-width-mismatch"
        )
    if hexpart != hexpart.lower():
        raise CanonicalizationError(f"{path}: el hex debe ir en minúsculas")
    try:
        int(hexpart, 16)
    except ValueError:
        raise CanonicalizationError(f"{path}: hex no válido")


def tier_of_platform(platform: str) -> tuple[int, str]:
    """Techo de Tier que la evidencia puede soportar, dado el platform.

    Es la capa semántica del validador: una atestación SOFTWARE no sostiene un
    claim Tier 3, por buena que sea la firma.
    """
    if platform in TIER_CAPABLE_PLATFORMS:
        return 3, f"plataforma {platform} puede sostener Tier 3+"
    return 2, (
        f"platform SOFTWARE: la evidencia sostiene Tier 2 como máximo "
        f"(C8.1.7: atestación vendor-rooted necesita anclaje independiente)"
    )
