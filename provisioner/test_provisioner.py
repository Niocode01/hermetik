#!/usr/bin/env python3
"""Tests del contrato de provisioning (F4).

Cubren las propiedades que importan de verdad:
- la normalización de URL es la MISMA que la del canister (paridad);
- el modo mock está marcado de forma inconfundible;
- el modo real falla explícitamente en vez de degradar;
- no hay valor por defecto permisivo en la selección de modo.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from provisioner import (
    ATTESTATION_TTL_NS,
    DEV_ATTEST_PREFIX,
    Mode,
    ProvisionOrder,
    Provisioner,
    ProvisionerError,
    attestation_is_dev,
    from_env,
    normalize_url,
    tenant_url,
)

PASS = 0
FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print(f"  ok  {msg}")


def ko(msg):
    global FAIL
    FAIL += 1
    print(f"  FAIL {msg}")


def check(cond, msg):
    ok(msg) if cond else ko(msg)


def raises(fn, msg):
    try:
        fn()
    except Exception:
        ok(msg)
    else:
        ko(msg + " (no lanzo)")


print("== 1. paridad de normalize_url con el canister ==")
# Mismos casos que el test Rust `container_url_never_leaks_credentials`.
check(normalize_url("https://t1.hermetik.eu") == "https://t1.hermetik.eu",
      "https simple pasa")
check(normalize_url("https://user:pass@t1.hermetik.eu/path?token=abc") == "https://t1.hermetik.eu",
      "descarta userinfo, path y query")
check(normalize_url("http://inseguro.hermetik.eu") is None,
      "http en claro rechazado")
check(normalize_url("https://evil") is None, "host sin punto rechazado")
check(normalize_url("https://.hermetik.eu") is None, "host empezando por punto rechazado")
check(normalize_url("https://a..b.eu") is None, "doble punto rechazado")
check(normalize_url("https://evil\"x.hermetik.eu") is None, "comilla inyectada rechazada")
check(normalize_url("  https://t1.hermetik.eu/  ") == "https://t1.hermetik.eu", "trim aplicado")
check(normalize_url("") is None, "vacio rechazado")

print("== 2. url de inquilino ==")
u1 = tenant_url("2vxsx-fae")
u2 = tenant_url("2vxsx-fae")
u3 = tenant_url("otro-principal")
check(u1 == u2, "determinista por principal")
check(u1 != u3, "distinta por principal")
check(u1.startswith("https://") and u1.endswith(".hermetik.eu"), "formato de subdominio")
check("2vxsx-fae" not in u1, "el principal completo NO aparece en el host")
check(normalize_url(u1) == u1, "la url generada ya esta normalizada")

print("== 3. referencia de atestacion en modo mock ==")
p = Provisioner(Mode.MOCK)
r = p.provision(ProvisionOrder(principal="abc", tier=1, requested_ns=time.time_ns()))
check(attestation_is_dev(r.attestation_ref), "la referencia lleva el prefijo de desarrollo")
check(r.attestation_ref.startswith(DEV_ATTEST_PREFIX), "prefijo exacto")
check(r.state == "dev-unattested", "el estado declara que NO esta atestiguado")
check(r.url == tenant_url("abc"), "url publicada normalizada")

print("== 4. la referencia mock es inconfundible con una real ==")
check(not attestation_is_dev("snp:" + "a" * 128), "una referencia real no se confunde")
check(attestation_is_dev(DEV_ATTEST_PREFIX + "x"), "deteccion por prefijo")
check(not attestation_is_dev(""), "cadena vacia no es dev")

print("== 5. modo real FALLA, no degrada ==")
pr = Provisioner(Mode.REAL)
raises(lambda: pr.provision(ProvisionOrder(principal="abc", tier=1, requested_ns=1)),
       "modo real sin infra lanza error explicito (no cae a mock)")

print("== 6. validacion de la orden ==")
raises(lambda: Provisioner(Mode.MOCK).provision(
    ProvisionOrder(principal="", tier=1, requested_ns=1)), "principal vacio rechazado")
raises(lambda: Provisioner(Mode.MOCK).provision(
    ProvisionOrder(principal="a", tier=0, requested_ns=1)), "tier 0 rechazado")
raises(lambda: Provisioner(Mode.MOCK).provision(
    ProvisionOrder(principal="a", tier=1, requested_ns=0)), "marca temporal ausente rechazada")

print("== 7. TTL coincide con el del canister ==")
check(ATTESTATION_TTL_NS == 24 * 60 * 60 * 1_000_000_000, "TTL de 24h")
now = 1_000_000_000_000_000_000
p2 = Provisioner(Mode.MOCK, now_ns=now)
r2 = p2.provision(ProvisionOrder(principal="abc", tier=1, requested_ns=now))
check(r2.expires_at_ns == now + ATTESTATION_TTL_NS, "expira a 24h exactas")

print("== 8. ciclo de vida del contenedor ==")
p3 = Provisioner(Mode.MOCK)
check(not p3.is_running("abc"), "no hay contenedor antes de aprovisionar")
p3.provision(ProvisionOrder(principal="abc", tier=1, requested_ns=time.time_ns()))
check(p3.is_running("abc"), "contenedor vivo tras aprovisionar")
check(p3.teardown("abc") is True, "teardown devuelve que habia algo")
check(not p3.is_running("abc"), "ya no corre")
check(p3.teardown("abc") is False, "teardown de algo inexistente es no-op explicito")

print("== 9. seleccion de modo: sin valor por defecto permisivo ==")
saved = os.environ.pop("HERMETIK_PROVISION_MODE", None)
raises(from_env, "sin variable de entorno FALLA (no hay default)")
os.environ["HERMETIK_PROVISION_MODE"] = "banana"
raises(from_env, "modo desconocido FALLA")
os.environ["HERMETIK_PROVISION_MODE"] = "mock"
check(from_env().mode is Mode.MOCK, "modo mock explicito funciona")
os.environ["HERMETIK_PROVISION_MODE"] = "real"
check(from_env().mode is Mode.REAL, "modo real explicito funciona")
os.environ["HERMETIK_PROVISION_MODE"] = "MOCK "
check(from_env().mode is Mode.MOCK, "normaliza mayusculas y espacios")
if saved is not None:
    os.environ["HERMETIK_PROVISION_MODE"] = saved
else:
    os.environ.pop("HERMETIK_PROVISION_MODE", None)

print("== 10. dos inquilinos no comparten contenedor ==")
p4 = Provisioner(Mode.MOCK)
a = p4.provision(ProvisionOrder(principal="alice", tier=1, requested_ns=1))
b = p4.provision(ProvisionOrder(principal="bob", tier=2, requested_ns=1))
check(a.url != b.url, "urls distintas")
check(a.container_id != b.container_id, "contenedores distintos")
check(p4.is_running("alice") and p4.is_running("bob"), "ambos vivos e independientes")

print()
print("=" * 35)
print(f"  PASS: {PASS}   FAIL: {FAIL}")
print("=" * 35)
sys.exit(1 if FAIL else 0)
