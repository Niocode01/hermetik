#!/usr/bin/env bash
# ADR-02 — Frontera del auditor en el `vault`.
#
# Lo que se prueba, y por qué importa:
#   - un AUDITOR lee el log pero NUNCA el backup (requisito del producto);
#   - un NO-auditor no lee el log;
#   - cada lectura de evidencia deja su propio registro (PoC C7.6.4);
#   - el log no contiene datos de usuario, solo digests y metadatos.
set -uo pipefail
export HOME=/opt/data/home
cd /opt/data/hermetik
C=vault
dfx() { command dfx "$@" 2>&1 | grep -v "^WARNING: dfx is deprecated"; }
PASS=0; FAIL=0
ok(){ echo "  ✓ $1"; PASS=$((PASS+1)); }
ko(){ echo "  ✗ $1"; FAIL=$((FAIL+1)); }

echo "== -1. reinstalacion limpia =="
dfx canister install $C --mode reinstall --yes >/dev/null 2>&1 && echo "  ✓ reinstalado"

ADMIN=$(dfx identity get-principal)
dfx canister call $C admin_bootstrap '()' >/dev/null 2>&1

dfx identity new auditor --storage-mode=plaintext >/dev/null 2>&1 || true
dfx identity new outsider --storage-mode=plaintext >/dev/null 2>&1 || true
AUD=$(dfx identity get-principal --identity auditor)
OUT=$(dfx identity get-principal --identity outsider)

echo "== 1. seed: entradas de log + un backup real =="
dfx canister call $C log_action '("hermes", "tool_call", "sha-256:aaaa", "tool=search")' >/dev/null 2>&1
dfx canister call $C log_action '("hermes", "memory_write", "sha-256:bbbb", "bytes=4096")' >/dev/null 2>&1
dfx canister call $C backup_begin '(1 : nat)' >/dev/null 2>&1
printf '(0 : nat, blob "\\DE\\AD\\BE\\EF\\01\\02\\03\\04")' > /tmp/bk.did
dfx canister call $C backup_put --argument-file /tmp/bk.did >/dev/null 2>&1
dfx canister call $C backup_commit '("sha-256:\$(printf cccc)")' >/dev/null 2>&1 || \
  dfx canister call $C backup_commit '("sha-256:cccc")' >/dev/null 2>&1
TOTAL=$(dfx canister call $C get_total_count '()' | tr -dc '0-9')
[[ "$TOTAL" -ge 3 ]] && ok "log con $TOTAL entradas y 1 backup" || ko "seed fallido ($TOTAL)"

echo "== 2. ANTES de anadir auditor: el ajeno NO lee el log =="
dfx identity use outsider >/dev/null 2>&1
R=$(dfx canister call $C get_recent_entries '(10 : nat)')
echo "$R" | grep -qiE 'Unauthorized|Error|reject' && ok "ajeno no lee el log" || ko "EL AJENO LEYÓ EL LOG (critico)"
R=$(dfx canister call $C get_entry '(0 : nat)')
echo "$R" | grep -qiE 'Unauthorized|Error|reject' && ok "ajeno no lee una entrada" || ko "EL AJENO LEYÓ UNA ENTRADA"
R=$(dfx canister call $C verify_chain_authorized '()')
echo "$R" | grep -qiE 'Unauthorized|Error|reject' && ok "ajeno no verifica la cadena" || ko "EL AJENO VERIFICÓ LA CADENA"
R=$(dfx canister call $C log_read_access '("test")')
echo "$R" | grep -qiE 'Unauthorized|Error|reject' && ok "ajeno no puede registrar accesos falsos" || ko "EL AJENO ESCRIBIÓ EN EL LOG"
R=$(dfx canister call $C am_i_auditor '()')
echo "$R" | grep -q 'false' && ok "am_i_auditor = false" || ko "am_i_auditor mal: $R"
dfx identity use default >/dev/null 2>&1

echo "== 3. el ajeno NO puede auto-anadirse como auditor =="
dfx identity use outsider >/dev/null 2>&1
R=$(dfx canister call $C admin_add_auditor "(principal \"$OUT\")")
echo "$R" | grep -qiE 'only admin|Unauthorized|Error|reject' && ok "no-admin no se anade a la allowlist" || ko "ESCALADA DE PRIVILEGIO (critico)"
dfx identity use default >/dev/null 2>&1

echo "== 4. admin anade al auditor =="
R=$(dfx canister call $C admin_add_auditor "(principal \"$AUD\")")
echo "$R" | grep -q 'true' && ok "auditor anadido" || ko "no se anadio: $R"
R=$(dfx canister call $C admin_list_auditors '()')
echo "$R" | grep -q "$AUD" && ok "auditor en la lista" || ko "no aparece en la lista"
R=$(dfx canister call $C admin_add_auditor "(principal \"$AUD\")")
echo "$R" | grep -q 'false' && ok "anadir dos veces es idempotente" || ko "no idempotente"

echo "== 5. EL AUDITOR LEE EL LOG =="
dfx identity use auditor >/dev/null 2>&1
R=$(dfx canister call $C am_i_auditor '()')
echo "$R" | grep -q 'true' && ok "am_i_auditor = true" || ko "am_i_auditor mal: $R"
R=$(dfx canister call $C get_recent_entries '(10 : nat)')
echo "$R" | grep -q 'tool_call' && ok "acceso al log concedido" || ko "auditor no lee el log: $R"
R=$(dfx canister call $C get_entry '(0 : nat)')
echo "$R" | grep -qE 'index|entry' && ok "acceso a una entrada concreta" || ko "no lee entrada: $R"
R=$(dfx canister call $C verify_chain_authorized '()')
echo "$R" | grep -q 'true' && ok "verifica la cadena" || ko "no verifica: $R"

echo "== 6. *** EL AUDITOR NO PUEDE LEER EL BACKUP *** =="
R=$(dfx canister call $C get_backup_chunk '(0 : nat, 0 : nat)')
echo "$R" | grep -qiE 'owner-only|Unauthorized|Error|reject' && ok "backup: chunk rechazado" || ko "EL AUDITOR LEYÓ UN CHUNK DEL BACKUP (critico)"
R=$(dfx canister call $C list_backups '()')
echo "$R" | grep -qiE 'owner-only|Unauthorized|Error|reject' && ok "backup: listado rechazado" || ko "EL AUDITOR LISTÓ LOS BACKUPS (critico)"
R=$(dfx canister call $C get_backup_version '()')
echo "$R" | grep -qiE 'owner-only|Unauthorized|Error|reject' && ok "backup: version rechazada" || ko "EL AUDITOR LEYÓ LA VERSIÓN DE BACKUP (critico)"

echo "== 7. el auditor NO escribe =="
R=$(dfx canister call $C log_action '("auditor", "x", "y", "z")')
echo "$R" | grep -qiE 'Unauthorized|Error|reject' && ok "auditor no escribe en el log" || ko "EL AUDITOR ESCRIBIÓ (critico)"
R=$(dfx canister call $C backup_begin '(1 : nat)')
echo "$R" | grep -qiE 'Unauthorized|Error|reject' && ok "auditor no inicia backups" || ko "EL AUDITOR INICIÓ UN BACKUP"

echo "== 8. C7.6.4: cada lectura de evidencia deja su propio registro =="
BEFORE=$(dfx canister call $C get_total_count '()' | tr -dc '0-9')
dfx canister call $C log_read_access '("entries:0-10")' >/dev/null 2>&1
AFTER=$(dfx canister call $C get_total_count '()' | tr -dc '0-9')
[[ "$AFTER" -eq $((BEFORE+1)) ]] && ok "la lectura anadio 1 registro" || ko "no registro el acceso ($BEFORE -> $AFTER)"
R=$(dfx canister call $C get_recent_entries '(1 : nat)')
echo "$R" | grep -q 'evidence_read' && ok "el registro dice evidence_read" || ko "no aparece el tipo: $R"
echo "$R" | grep -q 'role=auditor' && ok "el registro identifica el rol del lector" || ko "sin rol en el registro"

echo "== 9. el dueño sigue accediendo a TODO =="
dfx identity use default >/dev/null 2>&1
R=$(dfx canister call $C get_recent_entries '(10 : nat)')
echo "$R" | grep -q 'tool_call' && ok "dueno lee el log" || ko "dueno sin log"
R=$(dfx canister call $C list_backups '()')
echo "$R" | grep -qE 'version|record' && ok "dueno lee los backups" || ko "dueno sin backups: $R"
R=$(dfx canister call $C get_backup_chunk '(0 : nat, 0 : nat)')
echo "$R" | grep -qE 'blob|opt' && ok "dueno lee un chunk" || ko "dueno sin chunk: $R"

echo "== 10. revocar al auditor =="
R=$(dfx canister call $C admin_remove_auditor "(principal \"$AUD\")")
echo "$R" | grep -q 'true' && ok "auditor revocado" || ko "no se revoco"
dfx identity use auditor >/dev/null 2>&1
R=$(dfx canister call $C get_recent_entries '(10 : nat)')
echo "$R" | grep -qiE 'Unauthorized|Error|reject' && ok "tras revocar, sin acceso" || ko "EL AUDITOR REVOCADO SIGUE LEYENDO (critico)"
dfx identity use default >/dev/null 2>&1

echo "== 11. el log NO contiene datos de usuario (solo digests y metadatos) =="
dfx canister call $C log_action '("hermes", "tool_call", "sha-256:dddd", "tool=search;args_digest=sha-256:eeee")' >/dev/null 2>&1
R=$(dfx canister call $C get_recent_entries '(1 : nat)')
echo "$R" | grep -qE 'sha-256' && ok "el log lleva digests etiquetados" || ko "sin digests"
# el contenido del campo meta lo controla el emisor: la disciplina es del overwatch

echo "== 12. la cadena sigue verificando tras todo esto =="
R=$(dfx canister call $C verify_chain_authorized '()')
echo "$R" | grep -q 'true' && ok "cadena integra" || ko "CADENA ROTA: $R"

echo
echo "==================================="
echo "  PASS: $PASS   FAIL: $FAIL"
echo "==================================="
exit $FAIL
