#!/usr/bin/env python3
"""F4 — Contrato de provisioning (mock).

Traduce la orden de `access` en un contenedor con URL atestiguable.

Modelo de confianza:
- El provisioner es la ÚNICA pieza autorizada a llamar `set_container` en `access`.
  El usuario nunca escribe su mapping (si pudiera, apuntaría su sesión a un
  contenedor ajeno).
- El provisioner NO ve contenido de usuario: solo metadatos de control
  (principal, tier, URL, referencia de atestación).
- La URL que se publica en el directorio certificado pasa por la MISMA
  normalización que aplica el canister (https, sin userinfo, sin query).

Modos:
- `Mock` (v3.1): levanta un contenedor de prueba local y produce una referencia
  de atestación FALSA pero marcada como tal. Sirve para cerrar el producto E2E.
- `Real` (F4-real, cuando exista la infra TEE-CC): habla con el orquestador.

Regla que gobierna los modos (ver ADR-01): el modo mock NO es un fallback. Se
selecciona por variable de entorno explícita y su referencia de atestación lleva
el prefijo `dev-unattested:` para que sea imposible confundirla con una real.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import urllib.parse
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Optional

# ------------------------------------------------------------------ constantes

#: Prefijo obligatorio de las referencias de atestación de desarrollo.
#: El frontend lo comprueba y la UI lo muestra. Sin él no hay forma de
#: distinguir una referencia real de una simulada.
DEV_ATTEST_PREFIX = "dev-unattested:"

#: TTL de la referencia de atestación. Debe coincidir con el del canister
#: (`ATTESTATION_TTL_NS` en access), porque el canister OMITE la referencia
#: pasados 24h y publicarla más tiempo sería mentir sobre su frescura.
ATTESTATION_TTL_NS = 24 * 60 * 60 * 1_000_000_000


class ProvisionerError(Exception):
    """Error del contrato de provisioning. El llamante ve el motivo, no un estado
    degradado."""


class Mode(str, Enum):
    MOCK = "mock"
    REAL = "real"


# --------------------------------------------------------------- normalización

def normalize_url(raw: str) -> Optional[str]:
    """Normaliza la URL publicable al directorio.

    Réplica EXACTA de `normalize_url` de `access_core.rs`: si las dos
    divergen, el provisioner publicaría una URL que el canister rechazaría
    (o peor, el canister aceptaría una que el provisioner creía rechazada).

    - exige esquema https (http rompe el E2E y la atestación);
    - descarta userinfo, query y fragmento (no filtramos secretos);
    - descarta el path (el subdominio ES el tenant);
    - valida charset de hostname, rechaza puntos al inicio/fin y `..`.
    """
    t = raw.strip()
    if not t.startswith("https://"):
        return None
    rest = t[len("https://"):]
    host_chars = []
    for c in rest:
        if c in "/?#":
            break
        host_chars.append(c)
    host = "".join(host_chars)
    if "@" in host:                      # descarta userinfo
        host = host.rsplit("@", 1)[1]
    if not host or "." not in host or len(host) > 253:
        return None
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
    if not all(c in allowed for c in host):
        return None
    if host.startswith(".") or host.endswith(".") or ".." in host:
        return None
    return f"https://{host}"


def tenant_url(principal: str, domain: str = "hermetik.eu") -> str:
    """Subdominio por inquilino: `https://<tenant>.hermetik.eu`.

    El identificador de inquilino deriva del principal de forma determinista y
    truncado, para que sea estable entre despliegues y no revele el principal
    completo en el nombre del host.
    """
    digest = hashlib.sha256(principal.encode()).hexdigest()[:16]
    url = f"https://{digest}.{domain}"
    normalized = normalize_url(url)
    if normalized is None:                      # no debería ocurrir nunca
        raise ProvisionerError(f"url de inquilino invalida: {url}")
    return normalized


# ------------------------------------------------------------------- contrato

@dataclass
class ProvisionOrder:
    """Orden de provisioning tal como la emite `access`."""
    principal: str
    tier: int
    requested_ns: int
    nonce: str = field(default_factory=lambda: secrets.token_hex(16))

    def validate(self) -> None:
        if not self.principal or not isinstance(self.principal, str):
            raise ProvisionerError("principal ausente")
        if self.tier <= 0:
            raise ProvisionerError("tier invalido: el tier 0 no se provisiona")
        if self.requested_ns <= 0:
            raise ProvisionerError("marca temporal ausente")


@dataclass
class ContainerResult:
    """Resultado que el provisioner entrega a `access` vía `set_container`."""
    principal: str
    url: str
    attestation_ref: str
    state: str                     # "attested" | "dev-unattested"
    expires_at_ns: int
    container_id: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


class Provisioner:
    """Provisioner con dos modos. La selección es EXPLÍCITA: no hay detección
    automática ni degradación."""

    def __init__(self, mode: Mode, domain: str = "hermetik.eu",
                 now_ns: Optional[int] = None) -> None:
        self.mode = mode
        self.domain = domain
        self._now_ns = now_ns
        self._containers: dict[str, str] = {}

    def _now(self) -> int:
        return self._now_ns if self._now_ns is not None else time.time_ns()

    # ---- ciclo de vida ----

    def provision(self, order: ProvisionOrder) -> ContainerResult:
        order.validate()
        url = tenant_url(order.principal, self.domain)
        now = self._now()
        if self.mode is Mode.MOCK:
            ref = self._mock_attestation_ref(order, url)
            state = "dev-unattested"
        else:
            ref = self._real_attestation_ref(order, url)
            state = "attested"
        container_id = hashlib.sha256(
            f"{order.principal}:{order.nonce}".encode()
        ).hexdigest()[:24]
        self._containers[order.principal] = container_id
        return ContainerResult(
            principal=order.principal,
            url=url,
            attestation_ref=ref,
            state=state,
            expires_at_ns=now + ATTESTATION_TTL_NS,
            container_id=container_id,
        )

    def teardown(self, principal: str) -> bool:
        """Apaga el contenedor. Devuelve si había algo que apagar.

        NO propaga errores hacia arriba como estado degradado: si no había
        contenedor, es un no-op explícito.
        """
        return self._containers.pop(principal, None) is not None

    def is_running(self, principal: str) -> bool:
        return principal in self._containers

    # ---- referencias de atestación ----

    def _mock_attestation_ref(self, order: ProvisionOrder, url: str) -> str:
        """Referencia FALSA, marcada como tal de forma inconfundible.

        El prefijo `dev-unattested:` es obligatorio: es lo que permite al
        frontend y a la UI distinguir este caso de uno real. Sin él, el mock
        sería una degradación silenciosa (patrón de los hallazgos H-01/H-02
        de `hermetik-run-1`).
        """
        digest = hashlib.sha256(
            f"{order.principal}{order.nonce}{url}".encode()
        ).hexdigest()
        return f"{DEV_ATTEST_PREFIX}{digest}"

    def _real_attestation_ref(self, order: ProvisionOrder, url: str) -> str:
        """Referencia real. Requiere el orquestador TEE-CC, que no existe.

        Falla EXPLÍCITAMENTE en vez de degradar a mock.
        """
        raise ProvisionerError(
            "modo real no disponible: no existe orquestador de contenedores "
            "TEE-CC. Usa Mode.MOCK explicitamente o despliega la infra."
        )


# ------------------------------------------------------------------ utilidades

def attestation_is_dev(ref: str) -> bool:
    """`True` si la referencia es de desarrollo. El frontend DEBE comprobarlo
    antes de aceptar el canal, y la UI DEBE mostrarlo."""
    return ref.startswith(DEV_ATTEST_PREFIX)


def from_env() -> Provisioner:
    """Construye el provisioner desde el entorno. Selección EXPLÍCITA.

    `HERMETIK_PROVISION_MODE=mock|real` y `HERMETIK_TENANT_DOMAIN`.
    Ausente => falla. No hay valor por defecto permisivo en una pieza que
    entrega contenedores con datos de usuario.
    """
    raw = os.environ.get("HERMETIK_PROVISION_MODE", "").strip().lower()
    if raw not in ("mock", "real"):
        raise ProvisionerError(
            "HERMETIK_PROVISION_MODE debe ser 'mock' o 'real' explicitamente"
        )
    domain = os.environ.get("HERMETIK_TENANT_DOMAIN", "hermetik.eu").strip() or "hermetik.eu"
    return Provisioner(Mode(raw), domain=domain)


if __name__ == "__main__":  # pragma: no cover - utilidad manual
    p = Provisioner(Mode.MOCK)
    res = p.provision(ProvisionOrder(principal="2vxsx-fae", tier=1,
                                     requested_ns=time.time_ns()))
    print(res.to_json())
    print("es_dev:", attestation_is_dev(res.attestation_ref))
