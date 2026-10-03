#!/usr/bin/env bash
# F2 ICRC-1 verificación on-canister — validación viva en réplica local.
# Fail-fast: cualquier fallo aborta con el comando y la salida visibles.
set -euo pipefail
export PATH="$HOME/.local/share/dfx/bin:$PATH"
export HOME=/opt/data/home
export CARGO_HOME=/opt/data/home/.cargo
cd /opt/data/hermetik

dfx() { command dfx "$@" 2>&1 | grep -v '^WARNING: dfx is deprecated' || true; }

ACCESS_WASM="target/wasm32-unknown-unknown/release/access.wasm"
MOCK_WASM="target/wasm32-unknown-unknown/release/mock_ledger.wasm"
[ -f "$ACCESS_WASM" ] || { echo "falta $ACCESS_WASM (cargo build primero)"; exit 1; }
[ -f "$MOCK_WASM" ] || { echo "falta $MOCK_WASM (cargo build primero)"; exit 1; }

echo '== deploy mock ledger =='
dfx canister create mock_ledger --network local >/dev/null || true
dfx canister install mock_ledger --network local --mode reinstall --wasm "$MOCK_WASM" --yes >/dev/null
MOCK_ID=$(dfx canister id mock_ledger --network local)
echo "mock_ledger=$MOCK_ID"

echo '== redeploy access (limpio) =='
dfx canister install access --network local --mode reinstall --wasm "$ACCESS_WASM" --yes >/dev/null
ACCESS_ID=$(dfx canister id access --network local)
echo "access=$ACCESS_ID"

ADMIN=$(dfx identity get-principal)
echo "admin=$ADMIN"

echo '== init + grant admin =='
dfx canister call access init "(principal \"$ADMIN\")" --network local >/dev/null

echo '== apuntar access al mock ledger =='
GOT=$(dfx canister call access set_ledger_canister "(principal \"$MOCK_ID\")" --network local | grep -oE '[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{3}' | head -1)
echo "ledger configurado: $GOT"

echo '== subcuenta del admin (mock_set_block la necesita en hex) =='
RAW=$(dfx canister call access get_payment_info '(1 : nat8)' --network local)
INFO=$(echo "$RAW" | grep -E 'nat64|blob|vec \{' || echo "$RAW")
AMOUNT=$(echo "$INFO" | grep -oE '[0-9_]+' | head -1 | tr -d '_')
[ -n "$AMOUNT" ] || { echo "FAIL: no se pudo leer el precio"; echo "$RAW"; exit 1; }
SUBBLOB=$(echo "$INFO" | grep -oE 'blob "[^"]*"' | head -1)
[ -n "$SUBBLOB" ] || { echo "FAIL: no se pudo leer la subcuenta (se esperaba blob)"; echo "$RAW"; exit 1; }
# blob "\18\99..." usa escapes hex \XX → convertir a hex de 32 bytes
SUBHEX=$(printf '%s' "$SUBBLOB" | python3 -c "
import sys
s = sys.stdin.read().split('\"', 1)[1].rsplit('\"', 1)[0]
out = bytearray()
i = 0
while i < len(s):
    if s[i] == chr(92):
        out.append(int(s[i+1:i+3], 16))
        i += 3
    else:
        out.append(ord(s[i])); i += 1
assert len(out) == 32, 'subcuenta len=%d' % len(out)
print(bytes(out).hex())
")
echo "subcuenta hex: $SUBHEX"

echo '== caso 1: pago válido 7 ICP, tx_id=42 =='
dfx canister call mock_ledger mock_set_block "(42 : nat64, \"xfer\", \"$ACCESS_ID\", \"$SUBHEX\", 700_000_000 : nat64)" --network local >/dev/null
ENT=$(dfx canister call access register_payment_verified "(principal \"$ADMIN\", 1 : nat8, 42 : nat64, 30 : nat32)" --network local)
echo "$ENT"
echo "$ENT" | grep -q 'active = true' || { echo 'FAIL: caso 1 debería activar'; exit 1; }

echo '== caso 1b: replay del mismo tx 42 → trap =='
if dfx canister call access register_payment_verified "(principal \"$ADMIN\", 1 : nat8, 42 : nat64, 30 : nat32)" --network local 2>&1 | grep -qi 'already credited\|reject\|trap\|error'; then
  echo 'replay rechazado OK'
else
  echo 'FAIL: replay 42 aceptado'; exit 1
fi

echo '== caso 2: importe insuficiente 1 ICP, tx_id=43 → trap =='
dfx canister call mock_ledger mock_set_block "(43 : nat64, \"xfer\", \"$ACCESS_ID\", \"$SUBHEX\", 100_000_000 : nat64)" --network local >/dev/null
if dfx canister call access register_payment_verified "(principal \"$ADMIN\", 1 : nat8, 43 : nat64, 30 : nat32)" --network local 2>&1 | grep -qi 'importe\|below\|reject\|trap\|error\|invalid'; then
  echo 'infrapago rechazado OK'
else
  echo 'FAIL: infrapago 43 aceptado'; exit 1
fi

echo '== caso 3: bloque ausente tx_id=999 → trap =='
if dfx canister call access register_payment_verified "(principal \"$ADMIN\", 1 : nat8, 999 : nat64, 30 : nat32)" --network local 2>&1 | grep -qi 'no devolvió\|bloque\|reject\|trap\|error\|invalid'; then
  echo 'bloque ausente rechazado OK'
else
  echo 'FAIL: bloque ausente 999 aceptado'; exit 1
fi

echo '== caso 4: destino equivocado (subcuenta ajena), tx_id=44 → trap =='
WRONG_HEX=$(python3 -c "print('ab'*32)")
dfx canister call mock_ledger mock_set_block "(44 : nat64, \"xfer\", \"$ACCESS_ID\", \"$WRONG_HEX\", 700_000_000 : nat64)" --network local >/dev/null
if dfx canister call access register_payment_verified "(principal \"$ADMIN\", 1 : nat8, 44 : nat64, 30 : nat32)" --network local 2>&1 | grep -qi 'subcuenta\|invalid\|reject\|trap\|error'; then
  echo 'destino equivocado rechazado OK'
else
  echo 'FAIL: destino equivocado 44 aceptado'; exit 1
fi

echo '== caso 5: op no-transfer (burn), tx_id=45 → trap =='
dfx canister call mock_ledger mock_set_block "(45 : nat64, \"burn\", \"$ACCESS_ID\", \"$SUBHEX\", 700_000_000 : nat64)" --network local >/dev/null
if dfx canister call access register_payment_verified "(principal \"$ADMIN\", 1 : nat8, 45 : nat64, 30 : nat32)" --network local 2>&1 | grep -qi 'bloque\|transfer\|reject\|trap\|error\|invalid'; then
  echo 'burn rechazado OK'
else
  echo 'FAIL: burn 45 aceptado'; exit 1
fi

echo '== OK: F2 on-canister verificado en réplica (5 casos) =='
