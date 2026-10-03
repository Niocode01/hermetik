"""Gateway F5-debug: igual que app.create_app pero con /debug/auth que dice
EN QUÉ RAMA cae el rechazo (parse / user / who / on-canister).
NO es código de prod: solo para cerrar el diagnóstico F5.2.
"""
import asyncio
import subprocess
import sys

from aiohttp import web

from app import create_app
from attest_server import AttestMode, AttestServer
from nb2 import (
    Nb2Gate,
    is_valid_user,
    nb2_call_verify_credential,
    parse_nb2_credential,
)

CANISTER = (
    subprocess.run(
        ["dfx", "canister", "id", "access", "--network", "local"],
        capture_output=True,
        text=True,
    )
    .stdout.strip()
    .split()[-1]
)
print(f"F5-DEBUG canister_id={CANISTER}", flush=True)


async def debug_auth(request: web.Request) -> web.Response:
    auth = request.headers.get("Authorization", "")
    cred = auth[7:] if auth.startswith("Bearer ") else ""
    user = (request.headers.get("X-Nebulock-User", "") or "").strip()
    parsed = parse_nb2_credential(cred)
    step_parse = parsed is not None
    step_user = is_valid_user(user)
    step_who = (parsed or {}).get("who") == user if parsed else False
    step_oncanister = None
    if step_parse and step_user and step_who:
        gate = request.app.get("nb2")
        step_oncanister = nb2_call_verify_credential(
            gate.replica, gate.canister_id, cred
        )
    return web.json_response(
        {
            "canister_id": CANISTER,
            "cred_prefix": cred[:12],
            "user_prefix": user[:12],
            "step_parse": step_parse,
            "step_user": step_user,
            "step_who": step_who,
            "step_oncanister": step_oncanister,
            "gate_canister": request.app.get("nb2").canister_id,
            "gate_replica": request.app.get("nb2").replica,
        }
    )


async def main() -> None:
    gate = Nb2Gate(canister_id=CANISTER)
    srv = AttestServer(AttestMode.DEV, "ab" * 32)
    app = create_app(srv, gate)
    app.router.add_get("/debug/auth", debug_auth)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 18791)
    await site.start()
    print("GW-UP", flush=True)
    await asyncio.sleep(600)


if __name__ == "__main__":
    asyncio.run(main())
