#!/usr/bin/env bash
# F5 access — matriz E2E del camino completo en réplica local.
# Cubre: pago verificado on-canister (mock ledger) -> grant -> issue_credential
# -> provisioning (request/set/get) -> directorio publicado. Y el canal
# gateway attest->session->echo se prueba en F5-gateway (gateway en :18791).
#
# Requiere: réplica local, wasm access + mock_ledger compilados en
# target/wasm32-unknown-unknown/release/. Reinstala ambos (estado limpio).
set -uo pipefail
export HOME=/opt/data/home
cd /opt/data/hermetik
C=access
dfx() { command dfx "$@" 2>&1 | grep -v "^WARNING: dfx is deprecated"; }
PASS=0; FAIL=0
ok(){ echo "  ✓ $1"; PASS=$((PASS+1)); }
ko(){ echo "  ✗ $1"; FAIL=$((FAIL+1)); }

echo "== F5.0 deploy limpio =="
dfx canister install $C --network local --mode reinstall --wasm target/wasm32-unknown-unknown/release/access.wasm --yes >/dev/null 2>&1 && echo "  ✓ access reinstalado"
dfx canister create mock_ledger --network local >/dev/null 2>&1 || true
dfx canister install mock_ledger --network local --mode reinstall --wasm target/wasm32-unknown-unknown/release/mock_ledger.wasm --yes >/dev/null 2>&1 && echo "  ✓ mock_ledger reinstalado"
ADMIN=$(dfx identity get-principal)
MOCK=$(dfx canister id mock_ledger --network local 2>/dev/null | tail -1)
ACC=$(dfx canister id $C --network local 2>/dev/null | tail -1)
dfx canister call $C init "(principal \"$ADMIN\")" --network local >/dev/null 2>&1
dfx canister call $C set_ledger_canister "(principal \"$MOCK\")" --network local >/dev/null 2>&1
GOT=$(dfx canister call $C get_ledger_canister '()' --network local 2>/dev/null | tr -d '()" ')
[[ "$GOT" == *"$MOCK"* || "$MOCK" == *"$GOT"* ]] && ok "ledger apuntado al mock" || ko "ledger no apunta al mock: $GOT vs $MOCK"

subhex_for_admin() {
  RAW=$(dfx canister call $C get_payment_info '(1 : nat8)' --network local 2>/dev/null)
  SUBBLOB=$(echo "$RAW" | grep -oE 'blob "[^"]*"' | head -1)
  printf '%s' "$SUBBLOB" | python3 -c "
import sys
s = sys.stdin.read().split('\"', 1)[1].rsplit('\"', 1)[0]
out = bytearray(); i = 0
while i < len(s):
    if s[i] == chr(92): out.append(int(s[i+1:i+3], 16)); i += 3
    else: out.append(ord(s[i])); i += 1
print(bytes(out).hex())"
}

echo "== F5.1 pago verificado on-canister acredita (vía feliz) =="
SUBHEX=$(subhex_for_admin)
dfx canister call mock_ledger mock_set_block "(100 : nat64, \"xfer\", \"$ACC\", \"$SUBHEX\", 700_000_000 : nat64)" --network local >/dev/null 2>&1
R=$(dfx canister call $C register_payment_verified "(principal \"$ADMIN\", 1 : nat8, 100 : nat64, 30 : nat32)" --network local 2>/dev/null)
echo "$R" | grep -q 'active = true' && ok "tx100 acredita -> active" || ko "no acreditó: $R"

echo "== F5.2 grant + issue_credential + verify on-canister =="
dfx canister call $C grant "(principal \"$ADMIN\")" --network local >/dev/null 2>&1
CRED=$(dfx canister call $C issue_credential '()' --network local 2>/dev/null | grep -oE 'nb2\.[^"]+' | head -1)
[[ -n "$CRED" ]] && ok "credencial nb2 emitida" || ko "no emitió credencial"
R=$(dfx canister call $C verify_credential "(\"$CRED\")" --network local 2>/dev/null)
echo "$R" | grep -q 'true' && ok "verify_credential(true) on-canister" || ko "verify falló: $R"

echo "== F5.3 provisioning: request -> set -> directorio =="
dfx identity new tester --storage-mode=plaintext >/dev/null 2>&1 || true
TESTER=$(dfx identity get-principal --identity tester)
dfx canister call $C set_legacy_enabled '(true)' --network local >/dev/null 2>&1
dfx canister call $C register_payment "(principal \"$TESTER\", 1 : nat8, 500000000 : nat64, \"tx-f5-e2e\", 30 : nat32)" --network local >/dev/null 2>&1
dfx identity use tester >/dev/null 2>&1
R=$(dfx canister call $C request_provision '(1 : nat8)' --network local 2>/dev/null)
echo "$R" | grep -q 'Pending' && ok "tester request -> Pending" || ko "no pidió: $R"
dfx identity use default >/dev/null 2>&1
R=$(dfx canister call $C set_container "(principal \"$TESTER\", \"https://t-f5.hermetik.eu\", \"att-f5\")" --network local 2>/dev/null)
echo "$R" | grep -q 'Active' && ok "set_container -> Active" || ko "no activó: $R"
R=$(dfx canister call $C get_container "(principal \"$TESTER\")" --network local 2>/dev/null)
echo "$R" | grep -q 't-f5.hermetik.eu' && ok "directorio publica URL" || ko "sin URL: $R"

echo
echo "==================================="
echo "  PASS: $PASS   FAIL: $FAIL"
echo "==================================="
exit $FAIL
