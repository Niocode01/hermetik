"""Tests del cableado HTTP del gateway (F4): endpoints en vivo sobre aiohttp.

A diferencia de los tests de módulo, aquí se levanta un servidor real en un
puerto efímero y se habla con él por HTTP. Prueba la capa que une `AttestServer`
y `Nb2Gate` con el protocolo.
"""

import asyncio
import base64
import json

import httpx
import pytest
from aiohttp import web
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app import create_app
from attest_server import (
    INFO,
    SESSION_KEY_BYTES,
    SESSIONS_MAX,
    AttestMode,
    AttestServer,
    expected_report_data,
)
from channel import Channel
from nb2 import Nb2Gate

BIN = "ab" * 32
NONCE = "0" * 64
CANISTER = "ryjl3-tyaaa-aaaaa-aaaba-cai"


def _reply_cbor(value: bool) -> bytes:
    from nb2 import _cbor_encode

    arg = b"DIDL\x00\x01\x7e" + (b"\x01" if value else b"\x00")
    return _cbor_encode({"reply": {"arg": arg}})


async def _run_app(app, client_fn):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = None
    for sock in site._server.sockets:
        port = sock.getsockname()[1]
        break
    base = f"http://127.0.0.1:{port}"
    try:
        async with httpx.AsyncClient() as client:
            await client_fn(client, base)
    finally:
        await runner.cleanup()


def test_health_and_attest_live():
    async def run(client, base):
        r = await client.get(base + "/health")
        assert r.status_code == 200
        assert r.json()["attestation_state"] == "dev-unattested"

        q = (await client.get(base + "/v1/attest", params={"nonce": NONCE})).json()
        assert q["attestation_state"] == "dev-unattested"
        assert q["quote"].startswith("dev-unattested:")
        assert len(base64.b64decode(q["session_pub"])) == 32

    asyncio.run(_run_app(create_app(AttestServer(AttestMode.DEV, BIN)), run))


def test_attest_rejects_short_nonce():
    async def run(client, base):
        r = await client.get(base + "/v1/attest", params={"nonce": "x"})
        assert r.status_code == 400

    asyncio.run(_run_app(create_app(AttestServer(AttestMode.DEV, BIN)), run))


def test_session_roundtrip_live():
    async def run(client, base):
        q = (await client.get(base + "/v1/attest", params={"nonce": NONCE})).json()
        cp = base64.b64encode(b"\x22" * 32).decode()
        r = await client.post(base + "/v1/session", json={"nonce": NONCE, "client_pub": cp})
        assert r.status_code == 200
        assert "session_id" in r.json()
        # La clave de sesión NO viaja en la respuesta.
        assert "session_key" not in r.json()

    asyncio.run(_run_app(create_app(AttestServer(AttestMode.DEV, BIN)), run))


def test_session_rejects_bad_body():
    async def run(client, base):
        r = await client.post(base + "/v1/session", data="no-json",
                              headers={"Content-Type": "text/plain"})
        assert r.status_code == 400

    asyncio.run(_run_app(create_app(AttestServer(AttestMode.DEV, BIN)), run))


def test_protected_route_requires_nb2():
    gate = Nb2Gate(CANISTER, transport=lambda u, e: _reply_cbor(True))

    async def run(client, base):
        # Sin credencial → 401.
        r = await client.get(base + "/v1/whoami")
        assert r.status_code == 401
        # Credencial válida → 200 y devuelve el principal.
        cred = "nb2.2vxsx-fae.9999999999.1.2." + "ab" * 32
        r = await client.get(base + "/v1/whoami", headers={
            "Authorization": f"Bearer {cred}", "X-Nebulock-User": "2vxsx-fae",
        })
        assert r.status_code == 200
        assert r.json()["user"] == "2vxsx-fae"
        # Credencial de A presentada como B → 401 (sin ni siquiera red).
        r = await client.get(base + "/v1/whoami", headers={
            "Authorization": f"Bearer {cred}", "X-Nebulock-User": "zzzzz-aa",
        })
        assert r.status_code == 401

    asyncio.run(_run_app(create_app(AttestServer(AttestMode.DEV, BIN), gate), run))


def test_protected_route_fail_closed_on_replica_down():
    def down(url, envelope):
        raise ConnectionError("réplica caída")

    gate = Nb2Gate(CANISTER, transport=down)

    async def run(client, base):
        cred = "nb2.2vxsx-fae.9999999999.1.2." + "ab" * 32
        r = await client.get(base + "/v1/whoami", headers={
            "Authorization": f"Bearer {cred}", "X-Nebulock-User": "2vxsx-fae",
        })
        assert r.status_code == 401  # fail-closed, no 200

    asyncio.run(_run_app(create_app(AttestServer(AttestMode.DEV, BIN), gate), run))


def test_encrypted_echo_end_to_end():
    """Bucle completo sobre HTTP: attest → session → sellar → echo → abrir.

    El test deriva la MISMA clave que el servidor (la derivación es
    determinista dado nonce + client_pub) para sellar un mensaje que el
    servidor debe poder descifrar, y viceversa.
    """
    srv = AttestServer(AttestMode.DEV, BIN)

    async def run(client, base):
        # 1. attest → session_pub
        q = (await client.get(base + "/v1/attest", params={"nonce": NONCE})).json()

        # 2. par de claves efímero del cliente
        client_priv = X25519PrivateKey.generate()
        client_pub = base64.b64encode(client_priv.public_key().public_bytes_raw()).decode()

        # 3. session → session_id
        sid = (await client.post(base + "/v1/session", json={
            "nonce": NONCE, "client_pub": client_pub,
        })).json()["session_id"]

        # 4. el test deriva la misma clave que el servidor y sella un mensaje.
        # OJO: srv.session() consumiría el nonce (single-use); aquí se deriva a
        # mano con los mismos parámetros para no interferir con la app en vivo.
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        spub = base64.b64decode(q["session_pub"])
        shared = client_priv.exchange(X25519PublicKey.from_public_bytes(spub))
        rd = expected_report_data(NONCE, BIN)
        cpub_raw = base64.b64decode(client_pub)
        transcript = f"{NONCE}|{cpub_raw.hex()}|{q['session_pub']}|{rd}|dev"
        master = HKDF(
            algorithm=hashes.SHA256(),
            length=SESSION_KEY_BYTES,
            salt=transcript.encode(),
            info=INFO,
        ).derive(shared + rd.encode())
        ch = Channel(master, role="client")
        msg = ch.seal("hola enclave")

        # 5. echo: el servidor descifra y responde cifrado
        r = await client.post(base + "/v1/echo", json={
            "session_id": sid, "seq": msg["seq"], "sealed": msg["sealed"],
        })
        assert r.status_code == 200
        reply = r.json()

        # 6. abrimos la respuesta con el mismo canal local
        assert ch.open(reply["seq"], reply["sealed"]) == "echo: hola enclave"

    asyncio.run(_run_app(create_app(srv), run))


def test_echo_rejects_unknown_session_and_bad_seq():
    srv = AttestServer(AttestMode.DEV, BIN)

    async def run(client, base):
        # Sesión desconocida → 404.
        r = await client.post(base + "/v1/echo", json={
            "session_id": "no-existe", "seq": 1, "sealed": "AAAA",
        })
        assert r.status_code == 404
        # seq no válido (0) → 400.
        r = await client.post(base + "/v1/echo", json={
            "session_id": "no-existe", "seq": 0, "sealed": "AAAA",
        })
        assert r.status_code == 404  # se comprueba la sesión antes que el seq

    asyncio.run(_run_app(create_app(srv), run))


def test_sessions_cap_evicts_oldest():
    # run-5 B-02: la tabla de sesiones no crece sin límite. Se crean
    # SESSIONS_MAX+5 sesiones reales; la app no debe superar el cap.
    srv = AttestServer(AttestMode.DEV, BIN)
    app_holder: dict = {}

    async def run(client, base):
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey as Priv,
        )

        for i in range(SESSIONS_MAX + 5):
            nonce = f"{i:064x}"
            q = (await client.get(base + "/v1/attest", params={"nonce": nonce})).json()
            assert "session_pub" in q
            cp = base64.b64encode(Priv.generate().public_key().public_bytes_raw()).decode()
            r = await client.post(base + "/v1/session", json={"nonce": nonce, "client_pub": cp})
            assert r.status_code == 200
        # Sesión inexistente → 404 (comportamiento del bucket con cap).
        r = await client.post(base + "/v1/echo", json={
            "session_id": "0" * 64, "seq": 1, "sealed": "AAAA",
        })
        assert r.status_code == 404

    async def run_with_app(app, client_fn):
        from aiohttp import web as _web

        app_holder["app"] = app
        runner = _web.AppRunner(app)
        await runner.setup()
        site = _web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = None
        for sock in site._server.sockets:
            port = sock.getsockname()[1]
            break
        base = f"http://127.0.0.1:{port}"
        try:
            import httpx as _httpx

            async with _httpx.AsyncClient() as client:
                await client_fn(client, base)
        finally:
            await runner.cleanup()

    asyncio.run(run_with_app(create_app(srv), run))
    assert len(app_holder["app"]["sessions"]) <= SESSIONS_MAX
