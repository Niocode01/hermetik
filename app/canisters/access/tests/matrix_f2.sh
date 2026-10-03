#!/usr/bin/env bash
# F2 access — matriz E2E: entitlements, anti-replay de pago, mapping y provisioning.
set -uo pipefail
export HOME=/opt/data/home
cd /opt/data/hermetik
C=access
dfx() { command dfx "$@" 2>&1 | grep -v "^WARNING: dfx is deprecated"; }
PASS=0; FAIL=0
ok(){ echo "  ✓ $1"; PASS=$((PASS+1)); }
ko(){ echo "  ✗ $1"; FAIL=$((FAIL+1)); }

echo "== -1. reinstalación limpia =="
dfx canister install $C --network local --mode reinstall --wasm target/wasm32-unknown-unknown/release/access.wasm --yes >/dev/null 2>&1 && echo "  ✓ reinstalado"

echo "== 0. bootstrap =="
ADMIN=$(dfx identity get-principal)
dfx canister call $C init "(principal \"$ADMIN\")" >/dev/null 2>&1
GOT=$(dfx canister call $C get_admin '()' | tr -d '()" ')
[[ "$GOT" == *"$ADMIN"* ]] && ok "admin fijado" || ko "admin: $GOT"

echo "== 0b. vía legada explícita (sunset default OFF) =="
# matrix_f2 ejercita register_payment legada: se activa a propósito y queda
# auditado en LEGACY_HISTORY. La vía verificada se prueba en matrix_f2_icrc3.sh.
R=$(dfx canister call $C set_legacy_enabled '(true)')
echo "$R" | grep -q 'true' && ok "legada activada explícitamente" || ko "no activó legada: $R"

echo "== 1. entitlement nace inactivo (fail-closed) =="
R=$(dfx canister call $C is_entitled_caller '()')
echo "$R" | grep -q 'false' && ok "sin pago -> no entitled" || ko "ENTITLED SIN PAGAR: $R"
R=$(dfx canister call $C get_my_entitlement '()')
echo "$R" | grep -q 'active = false' && ok "entitlement inactivo" || ko "entitlement activo sin pago: $R"

echo "== 2. request_provision sin suscripción -> rechazado =="
R=$(dfx canister call $C request_provision '(1 : nat8)')
echo "$R" | grep -qiE 'no active subscription|Error|reject' && ok "provisioning sin pagar -> rechazado" || ko "PROVISIONÓ SIN PAGAR (crítico): $R"

echo "== 3. info de pago (precio + subcuenta) =="
R=$(dfx canister call $C get_payment_info '(1 : nat8)')
echo "$R" | grep -q '500_000_000' && ok "precio tier1 = 5 ICP (500000000 e8s)" || ko "precio inesperado: $R"
echo "$R" | grep -qE 'blob "(\\[0-9A-F]{2})+' && ok "subcuenta derivada devuelta" || ko "sin subcuenta: $R"

echo "== 4. register_payment lo hace SOLO el admin =="
dfx identity new tester --storage-mode=plaintext >/dev/null 2>&1 || true
TESTER=$(dfx identity get-principal --identity tester)
ME=$(dfx identity get-principal)
dfx identity use tester >/dev/null 2>&1
R=$(dfx canister call $C register_payment "(principal \"$ME\", 1 : nat8, 500000000 : nat64, \"tx-hack\", 30 : nat32)")
echo "$R" | grep -qiE 'only admin|Error|reject' && ok "no-admin no puede acreditarse pago" || ko "USUARIO SE AUTOCREDITÓ (crítico)"
dfx identity use default >/dev/null 2>&1

echo "== 5. importe por debajo del precio -> rechazado =="
R=$(dfx canister call $C register_payment "(principal \"$TESTER\", 1 : nat8, 499999999 : nat64, \"tx-poco\", 30 : nat32)")
echo "$R" | grep -qiE 'below price|Error|reject' && ok "pago insuficiente rechazado" || ko "ACEPTÓ PAGO INSUFICIENTE"

echo "== 6. tier desconocido -> rechazado =="
R=$(dfx canister call $C register_payment "(principal \"$TESTER\", 9 : nat8, 999999999 : nat64, \"tx-tier9\", 30 : nat32)")
echo "$R" | grep -qiE 'below price|Error|reject' && ok "tier 9 rechazado" || ko "ACEPTÓ TIER INEXISTENTE"

echo "== 7. pago válido acredita =="
R=$(dfx canister call $C register_payment "(principal \"$TESTER\", 1 : nat8, 500000000 : nat64, \"tx-ok-1\", 30 : nat32)")
echo "$R" | grep -q 'active = true' && ok "entitlement activado" || ko "no activó: $R"
R=$(dfx canister call $C get_entitlement "(principal \"$TESTER\")")
echo "$R" | grep -q 'tier = 1' && ok "tier 1" || ko "tier mal: $R"

echo "== 8. ANTI-REPLAY: el mismo tx no se acredita dos veces =="
R=$(dfx canister call $C register_payment "(principal \"$TESTER\", 1 : nat8, 500000000 : nat64, \"tx-ok-1\", 30 : nat32)")
echo "$R" | grep -qiE 'already credited|Error|reject' && ok "tx reutilizado rechazado" || ko "REPLAY DE PAGO ACEPTADO (crítico)"
# get_paid_tx_count devuelve tupla (len,cap): parsear el PRIMER campo.
N=$(dfx canister call $C get_paid_tx_count '()' | grep -oE '[0-9_]+' | head -1 | tr -d '_')
[[ "$N" == "1" ]] && ok "1 tx acreditado en total" || ko "contador de tx esperado 1, hay $N"

echo "== 9. renovación suma al vencimiento, no reinicia =="
dfx canister call $C register_payment "(principal \"$TESTER\", 1 : nat8, 500000000 : nat64, \"tx-ok-2\", 30 : nat32)" >/dev/null 2>&1
EXP2=$(dfx canister call $C get_entitlement "(principal \"$TESTER\")" | grep -oE 'expires_ns = [0-9_]+([0-9]+)?' | head -1 | tr -dc '0-9')
dfx canister call $C register_payment "(principal \"$TESTER\", 1 : nat8, 500000000 : nat64, \"tx-ok-3\", 30 : nat32)" >/dev/null 2>&1
EXP3=$(dfx canister call $C get_entitlement "(principal \"$TESTER\")" | grep -oE 'expires_ns = [0-9_]+([0-9]+)?' | head -1 | tr -dc '0-9')
D=$((EXP3 - EXP2))
DAYS_NS=2592000000000000
[[ "$D" == "$DAYS_NS" ]] && ok "renovación suma exactamente 30 días" || ko "delta de renovación = $D (esperado $DAYS_NS)"

echo "== 10. mapping: el usuario NO puede escribir su propio contenedor =="
dfx identity use tester >/dev/null 2>&1
R=$(dfx canister call $C set_container "(principal \"$TESTER\", \"https://evil.example.com\", \"fake-att\")")
echo "$R" | grep -qiE 'only admin|Error|reject' && ok "no-admin no escribe mapping" || ko "USUARIO ESCRIBIÓ SU MAPPING (crítico)"
R=$(dfx canister call $C teardown_container "(principal \"$TESTER\")")
echo "$R" | grep -qiE 'only admin|Error|reject' && ok "no-admin no hace teardown" || ko "USUARIO HIZO TEARDOWN (crítico)"
dfx identity use default >/dev/null 2>&1

echo "== 11. el usuario SÍ puede pedir su provisioning (ya pagó) =="
dfx identity use tester >/dev/null 2>&1
R=$(dfx canister call $C request_provision '(1 : nat8)')
echo "$R" | grep -q 'Pending' && ok "request -> Pending" || ko "no pidió: $R"
R=$(dfx canister call $C get_container "(principal \"$TESTER\")")
echo "$R" | grep -qE 'status = variant \{ None \}' && ok "el directorio NO publica un contenedor Pending" || ko "PUBLICÓ UN PENDING (crítico): $R"
dfx identity use default >/dev/null 2>&1

echo "== 12. set_container: exige https =="
R=$(dfx canister call $C set_container "(principal \"$TESTER\", \"http://t1.hermetik.eu\", \"att-1\")")
echo "$R" | grep -q 'Pending' && ok "http:// rechazado (sigue Pending)" || ko "ACEPTÓ HTTP EN CLARO"
R=$(dfx canister call $C set_container "(principal \"$TESTER\", \"https://t1.hermetik.eu\", \"\")")
echo "$R" | grep -q 'Pending' && ok "sin atestación rechazado" || ko "ACEPTÓ SIN ATESTACIÓN"

echo "== 13. activación de contenedor =="
R=$(dfx canister call $C set_container "(principal \"$TESTER\", \"https://t1.hermetik.eu\", \"att-1\")")
echo "$R" | grep -q 'Active' && ok "contenedor Active" || ko "no activó: $R"
R=$(dfx canister call $C get_container "(principal \"$TESTER\")")
echo "$R" | grep -q 't1.hermetik.eu' && ok "el directorio publica la URL" || ko "sin URL en el directorio"

echo "== 14. la URL publicada NO filtra credenciales ni query =="
dfx canister call $C set_container "(principal \"$TESTER\", \"https://user:pass@t2.hermetik.eu/api?token=SECRETO\", \"att-2\")" >/dev/null 2>&1
R=$(dfx canister call $C get_container "(principal \"$TESTER\")")
echo "$R" | grep -q 'SECRETO' && ko "FUGA: query con secreto publicada" || ok "sin query en la URL"
echo "$R" | grep -q 'user:pass' && ko "FUGA: userinfo publicada" || ok "sin userinfo en la URL"

echo "== 15. re-request no degrada un contenedor activo =="
dfx identity use tester >/dev/null 2>&1
dfx canister call $C request_provision '(1 : nat8)' >/dev/null 2>&1
R=$(dfx canister call $C get_container "(principal \"$TESTER\")")
echo "$R" | grep -q 'Active' && ok "sigue Active tras re-request" || ko "DEGRADÓ EL ESTADO A PENDING"
dfx identity use default >/dev/null 2>&1

echo "== 16. get_container de un tercero sin contenedor devuelve None =="
OTHER=$(dfx canister call $C me '()' | grep -oE '[a-z0-9-]{5,}-[a-z0-9-]+' | head -1)
R=$(dfx canister call $C get_container "(principal \"$OTHER\")")
echo "$R" | grep -q 'status = variant { None }' && ok "None para quien no tiene" || ko "estado inesperado: $R"

echo "== 17. revoke_entitlement (solo admin) desactiva =="
dfx identity use tester >/dev/null 2>&1
R=$(dfx canister call $C revoke_entitlement "(principal \"$TESTER\")")
echo "$R" | grep -qiE 'only admin|Error|reject' && ok "no-admin no revoca" || ko "USUARIO SE REVOCÓ/REACTIVÓ (crítico)"
dfx identity use default >/dev/null 2>&1
dfx canister call $C revoke_entitlement "(principal \"$TESTER\")" >/dev/null 2>&1
R=$(dfx canister call $C get_entitlement "(principal \"$TESTER\")")
echo "$R" | grep -q 'active = false' && ok "admin revoca -> inactivo" || ko "no revocó: $R"
dfx canister call $C grant "(principal \"$TESTER\")" >/dev/null 2>&1
A1=$(dfx canister call $C is_allowed "(principal \"$TESTER\")" | grep -oE 'true|false' | head -1)
dfx canister call $C revoke_entitlement "(principal \"$TESTER\")" >/dev/null 2>&1
A2=$(dfx canister call $C is_allowed "(principal \"$TESTER\")" | grep -oE 'true|false' | head -1)
[[ "$A1" == "true" && "$A2" == "true" ]] && ok "revocar el entitlement NO toca la allowlist nb2" || ko "allowlist cambió con el revoke ($A1 -> $A2)"

echo
echo "==================================="
echo "  PASS: $PASS   FAIL: $FAIL"
echo "==================================="
exit $FAIL
