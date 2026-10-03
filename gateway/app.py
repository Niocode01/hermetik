"""App HTTP del gateway (F4) — cableado de los endpoints de atestación + auth nb2.

Capa fina sobre `attest_server.AttestServer` y `nb2.Nb2Gate`. No es el gateway
Hermes completo (eso lo aporta el contenedor per-tenant); es el esqueleto del
plano de control de confianza que TODO gateway per-tenant debe exponer:

  GET  /health            → liveness + estado de atestación (nunca oculto)
  GET  /v1/attest?nonce=  → quote de atestación (SIN auth: es el primer contacto)
  POST /v1/session        → { nonce, client_pub } → { session_id } (clave NO se envía)
  POST /v1/echo           → { session_id, seq, sealed } → descifra y devuelve { seq, sealed }
  GET  /v1/whoami         → RUTA PROTEGIDA de ejemplo: exige Bearer nb2 válido

La auth nb2 es fail-closed: credencial malformada, principal que no coincide con
`X-Nebulock-User`, réplica caída o respuesta no-`(bool)` → 401, nunca se deja
pasar por defecto.
"""

from __future__ import annotations

from aiohttp import web

from attest_server import (
    AttestMode,
    AttestServer,
    AttestServerError,
    SESSIONS_MAX,
    SESSIONS_TTL_S,
)
from channel import Channel
import time


def _get_channel(app: web.Application, sid: str):
    """Canal con TTL de inactividad (run-5 B-02). Entradas: (Channel, last_ns)."""
    bucket = app["sessions"]
    entry = bucket.get(sid)
    if entry is None:
        return None
    ch, last = entry
    if time.monotonic() - last > SESSIONS_TTL_S:
        bucket.pop(sid, None)
        return None
    return ch


def _put_channel(app: web.Application, sid: str, ch: Channel) -> None:
    bucket = app["sessions"]
    bucket[sid] = (ch, time.monotonic())
    while len(bucket) > SESSIONS_MAX:
        oldest = min(bucket, key=lambda k: bucket[k][1])
        bucket.pop(oldest, None)


def _touch_channel(app: web.Application, sid: str) -> None:
    entry = app["sessions"].get(sid)
    if entry is not None:
        app["sessions"][sid] = (entry[0], time.monotonic())


def create_app(attest_server: AttestServer, nb2_gate=None) -> web.Application:
    app = web.Application(middlewares=[_nb2_auth_middleware])
    app["attest"] = attest_server
    app["nb2"] = nb2_gate
    # session_id -> (Channel rol servidor, último_uso_monotonic). TTL+cap (B-02).
    app["sessions"] = {}

    async def health(request: web.Request) -> web.Response:
        state = "dev-unattested" if attest_server.mode is AttestMode.DEV else attest_server.mode.value
        return web.json_response({"status": "ok", "attestation_state": state})

    async def attest(request: web.Request) -> web.Response:
        nonce = request.query.get("nonce", "")
        try:
            quote = attest_server.attest(nonce)
        except AttestServerError as exc:
            return web.json_response({"error": str(exc)}, status=400)
        return web.json_response(quote)

    async def session(request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "cuerpo no JSON"}, status=400)
        nonce = body.get("nonce", "") if isinstance(body, dict) else ""
        client_pub = body.get("client_pub", "") if isinstance(body, dict) else ""
        try:
            est = attest_server.session(nonce, client_pub)
        except AttestServerError as exc:
            return web.json_response({"error": str(exc)}, status=400)
        # Registra el canal SERVIDOR (tx=s2c, rx=c2s) con la clave derivada;
        # expone solo el handle opaco.
        _put_channel(app, est.session_id, Channel(est.session_key, role="server"))
        return web.json_response({"session_id": est.session_id})

    async def echo(request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "cuerpo no JSON"}, status=400)
        sid = body.get("session_id", "") if isinstance(body, dict) else ""
        seq = body.get("seq", 0) if isinstance(body, dict) else 0
        sealed = body.get("sealed", "") if isinstance(body, dict) else ""
        ch = _get_channel(app, sid)
        if ch is None:
            return web.json_response({"error": "sesión desconocida o caducada"}, status=404)
        try:
            plaintext = ch.open(seq, sealed)
        except Exception as exc:
            return web.json_response({"error": f"no se pudo descifrar: {exc}"}, status=400)
        reply = ch.seal(f"echo: {plaintext}")
        _touch_channel(app, sid)
        return web.json_response(reply)

    async def whoami(request: web.Request) -> web.Response:
        return web.json_response({"user": request["nb2_user"]})

    app.router.add_get("/health", health)
    app.router.add_get("/v1/attest", attest)
    app.router.add_post("/v1/session", session)
    app.router.add_post("/v1/echo", echo)
    app.router.add_get("/v1/whoami", whoami)
    return app


# Rutas protegidas por nb2. `/v1/attest` y `/v1/session` NO lo están (son el
# establecimiento de confianza previo a cualquier autenticación).
_PROTECTED = ("/v1/whoami",)


@web.middleware
async def _nb2_auth_middleware(request: web.Request, handler):
    if request.path.startswith(_PROTECTED):
        gate = request.app.get("nb2")
        if gate is None:
            return web.json_response({"error": "auth nb2 no configurada"}, status=503)
        auth = request.headers.get("Authorization", "")
        cred = auth[7:] if auth.startswith("Bearer ") else ""
        user = (request.headers.get("X-Nebulock-User", "") or "").strip()
        if not gate.authenticate(cred, user):
            return web.json_response({"error": "no autorizado"}, status=401)
        request["nb2_user"] = user
    return await handler(request)
