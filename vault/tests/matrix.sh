#!/usr/bin/env bash
# F1 vault — matriz de tests (auth + http_request + integridad de la cadena)
# Requiere: replica local corriendo, canister `vault` desplegado.
set -uo pipefail
export HOME=/opt/data/home
cd /opt/data/hermetik
C=vault
dfx() { command dfx "$@" 2>&1 | grep -v "^WARNING: dfx is deprecated"; }
PASS=0; FAIL=0
ok(){ echo "  ✓ $1"; PASS=$((PASS+1)); }
ko(){ echo "  ✗ $1"; FAIL=$((FAIL+1)); }

echo "== -1. reinstalación limpia (tests idempotentes) =="
dfx canister install $C --mode reinstall --yes >/dev/null 2>&1 && echo "  ✓ canister reinstalado" || echo "  ! reinstall falló (¿controladores?)"

echo "== 0. bootstrap =="
ADMIN=$(dfx identity get-principal)
dfx canister call $C admin_bootstrap '()' >/dev/null 2>&1
GOT=$(dfx canister call $C admin_get_admin '()' 2>&1 | tr -d '()"')
[[ "$GOT" == "$ADMIN" ]] && ok "admin = identidad desplegadora" || ko "admin incorrecto ($GOT)"

echo "== 1. el token de lectura nace vacío (fail-closed) =="
R=$(dfx canister call $C http_request '(record { method="GET"; url="/log/count"; headers=vec {}; body=blob ""; certificate_version=null })' 2>&1)
echo "$R" | grep -q '401' && ok "sin token -> 401" || ko "sin token NO da 401: $R"
R=$(dfx canister call $C http_request '(record { method="GET"; url="/log/count"; headers=vec { record { "authorization"; "Bearer inventado" } }; body=blob ""; certificate_version=null })' 2>&1)
echo "$R" | grep -q '401' && ok "token inventado -> 401" || ko "token inventado NO da 401"
R=$(dfx canister call $C http_request '(record { method="GET"; url="/health"; headers=vec {}; body=blob ""; certificate_version=null })' 2>&1)
echo "$R" | grep -q '401' && ok "/health también exige token (no filtra existencia)" || ko "/health sin token NO da 401"
R=$(dfx canister call $C http_request '(record { method="GET"; url="/log/count"; headers=vec { record { "authorization"; "" } }; body=blob ""; certificate_version=null })' 2>&1)
echo "$R" | grep -q '401' && ok "header vacío -> 401" || ko "header vacío NO da 401"

echo "== 2. token correcto (+ backup_token separado, run-2 H5) =="
TOKEN="tok-fix-h5"
BTOKEN="bak-fix-h5-diferente"
dfx canister call $C admin_set_read_token "(\"$TOKEN\")" >/dev/null 2>&1
dfx canister call $C admin_set_backup_token "(\"$BTOKEN\")" >/dev/null 2>&1
H="record { \"authorization\"; \"Bearer $TOKEN\" }"
HB="record { \"authorization\"; \"Bearer $BTOKEN\" }"
R=$(dfx canister call $C http_request "(record { method=\"GET\"; url=\"/log/count\"; headers=vec { $H }; body=blob \"\"; certificate_version=null })" 2>&1)
echo "$R" | grep -q '200' && ok "token correcto -> 200" || ko "token correcto falló: $R"

echo "== 3. prefijo del token NO sirve (comparación exacta) =="
R=$(dfx canister call $C http_request "(record { method=\"GET\"; url=\"/log/count\"; headers=vec { record { \"authorization\"; \"Bearer ${TOKEN:0:5}\" } }; body=blob \"\"; certificate_version=null })" 2>&1)
echo "$R" | grep -q '401' && ok "prefijo -> 401" || ko "PREFIJO ACEPTADO (crítico)"

echo "== 4. JSON válido + esquema (tokens separados, run-2 H5) =="
for PATH_ in /log/count /chain/verify /log/recent; do
  R=$(dfx canister call $C http_request "(record { method=\"GET\"; url=\"$PATH_\"; headers=vec { $H }; body=blob \"\"; certificate_version=null })" 2>&1)
  echo "$R" | grep -q '200' && ok "$PATH_ -> 200" || ko "$PATH_ falló"
done
for PATH_ in /backup/version /backup/meta; do
  R=$(dfx canister call $C http_request "(record { method=\"GET\"; url=\"$PATH_\"; headers=vec { $HB }; body=blob \"\"; certificate_version=null })" 2>&1)
  echo "$R" | grep -q '200' && ok "$PATH_ con backup_token -> 200" || ko "$PATH_ con backup_token falló"
done
R=$(dfx canister call $C http_request "(record { method=\"GET\"; url=\"/ruta/no/existe\"; headers=vec { $H }; body=blob \"\"; certificate_version=null })" 2>&1)
echo "$R" | grep -q '404' && ok "ruta desconocida -> 404" || ko "ruta desconocida no da 404"
echo "== 4b. frontera HTTP log vs backup NO colapsa (run-2 H5) =="
R=$(dfx canister call $C http_request "(record { method=\"GET\"; url=\"/backup/version\"; headers=vec { $H }; body=blob \"\"; certificate_version=null })" 2>&1)
echo "$R" | grep -q '401' && ok "read_token NO abre /backup/version" || ko "COLAPSO: read_token abrió backup"
R=$(dfx canister call $C http_request "(record { method=\"GET\"; url=\"/backup/meta\"; headers=vec { $H }; body=blob \"\"; certificate_version=null })" 2>&1)
echo "$R" | grep -q '401' && ok "read_token NO abre /backup/meta" || ko "COLAPSO: read_token abrió backup"
R=$(dfx canister call $C http_request "(record { method=\"GET\"; url=\"/log/count\"; headers=vec { $HB }; body=blob \"\"; certificate_version=null })" 2>&1)
echo "$R" | grep -q '401' && ok "backup_token NO abre /log/count" || ko "backup_token abrió el log"

echo "== 5. log + cadena =="
dfx canister call $C log_action '("agente-1", "test", "hash1", "meta1")' >/dev/null 2>&1
dfx canister call $C log_action '("agente-1", "test", "hash2", "meta2")' >/dev/null 2>&1
CNT=$(dfx canister call $C get_total_count '()' | tr -dc '0-9')
[[ "$CNT" == "2" ]] && ok "2 entradas registradas" || ko "conteo esperado 2, hay $CNT"
V=$(dfx canister call $C verify_chain_authorized '()' 2>&1)
echo "$V" | grep -q 'true' && ok "verify_chain_authorized dice true" || ko "verify_chain_authorized falló: $V"
echo "== 5b. verify_chain pública eliminada (run-2 H6) =="
V=$(dfx canister call $C verify_chain '()' 2>&1)
echo "$V" | grep -qiE 'eliminada|trap|Error|reject' && ok "verify_chain pública -> trap" || ko "verify_chain pública SIGUE ABIERTA: $V"
R=$(dfx canister call $C http_request "(record { method=\"GET\"; url=\"/chain/verify\"; headers=vec { $H }; body=blob \"\"; certificate_version=null })" 2>&1)
echo "$R" | grep -q 'true' && ok "http /chain/verify coincide" || ko "http /chain/verify discrepa"

echo "== 6. frontera de escritura (no-writer) =="
dfx identity new tester --storage-mode=plaintext >/dev/null 2>&1 || true
OLD=$(dfx identity get-principal)
dfx identity use tester >/dev/null 2>&1
R=$(dfx canister call $C log_action '("intruso", "x", "y", "z")' 2>&1)
echo "$R" | grep -qiE 'unauthorized|reject|Error' && ok "caller ajeno -> rechazado" || ko "INTRUSO PUDO ESCRIBIR (crítico)"
dfx identity use default >/dev/null 2>&1

echo "== 7. frontera admin (no-admin no puede tocar el token) =="
dfx identity use tester >/dev/null 2>&1
R=$(dfx canister call $C admin_set_read_token '("token-del-intruso")' 2>&1)
echo "$R" | grep -qiE 'unauthorized|reject|Error' && ok "no-admin no cambia el token" || ko "INTRUSO CAMBIÓ EL TOKEN (crítico)"
dfx identity use default >/dev/null 2>&1

echo "== 8. el token viejo sigue vivo tras el intento del intruso =="
R=$(dfx canister call $C http_request "(record { method=\"GET\"; url=\"/log/count\"; headers=vec { record { \"authorization\"; \"Bearer token-del-intruso\" } }; body=blob \"\"; certificate_version=null })" 2>&1)
echo "$R" | grep -q '401' && ok "token del intruso rechazado" || ko "TOKEN DEL INTRUSO ACEPTADO (crítico)"

echo "== 9. subida por chunks (protocolo de backup) =="
dfx canister call $C backup_begin '(2 : nat)' >/dev/null 2>&1
printf '(0 : nat, blob "\\DE\\AD\\BE\\EF")' > /tmp/c0.did
printf '(1 : nat, blob "\\01\\02\\03\\04")' > /tmp/c1.did
dfx canister call $C backup_put --argument-file /tmp/c0.did >/dev/null 2>&1
dfx canister call $C backup_put --argument-file /tmp/c1.did >/dev/null 2>&1
R=$(dfx canister call $C backup_commit '("sha-falso-del-cliente")' 2>&1)
echo "$R" | grep -qE '\(1 : nat\)|1' && ok "backup_commit -> version 1" || ko "commit falló: $R"
R=$(dfx canister call $C http_request "(record { method=\"GET\"; url=\"/backup/version\"; headers=vec { $HB }; body=blob \"\"; certificate_version=null })" 2>&1)
echo "$R" | grep -q '200' && ok "http /backup/version -> 200" || ko "http backup falló"
CNT=$(dfx canister call $C get_total_count '()' | tr -dc '0-9')
[[ "$CNT" == "3" ]] && ok "el commit auto-registra en el log (3 entradas)" || ko "esperado 3 entradas, hay $CNT"

echo "== 10. chunk fuera de orden / sin subida =="
dfx canister call $C backup_begin '(2 : nat)' >/dev/null 2>&1
R=$(dfx canister call $C backup_put --argument-file /tmp/c1.did 2>&1)
echo "$R" | grep -qiE 'out-of-order|Error|reject' && ok "chunk 1 primero -> rechazado" || ko "ACEPTÓ CHUNK FUERA DE ORDEN"
dfx canister call $C backup_abort '()' >/dev/null 2>&1
R=$(dfx canister call $C backup_put --argument-file /tmp/c0.did 2>&1)
echo "$R" | grep -qiE 'no upload|Error|reject' && ok "put sin begin -> rechazado" || ko "ACEPTÓ PUT SIN BEGIN"
R=$(dfx canister call $C backup_commit '("x")' 2>&1)
echo "$R" | grep -qiE 'no upload|Error|reject' && ok "commit sin begin -> rechazado" || ko "ACEPTÓ COMMIT SIN BEGIN"

echo "== 11. freeze =="
dfx canister call $C admin_freeze '()' >/dev/null 2>&1
R=$(dfx canister call $C log_action '("agente-1", "test", "h", "m")' 2>&1)
echo "$R" | grep -qiE 'frozen|Error|reject' && ok "frozen bloquea escrituras" || ko "FROZEN NO BLOQUEA (crítico)"

echo
echo "==================================="
echo "  PASS: $PASS   FAIL: $FAIL"
echo "==================================="
exit $FAIL
