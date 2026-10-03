//! Nebulock v2 `access` canister: admin + allowlist + credencial nb2 (Tasks 3+4).
//!
//! Modelo de seguridad: el canister es plano de control. Sin secretos
//! configurables ni legibles: el secreto nb2 es efímero, aleatorio por
//! despliegue (vía `raw_rand` en `init`), vive solo en heap y nunca se expone.
//! `issue_credential` emite `nb2.<principal>.<expiry>.<epoch>.<nonce>.<tag>`
//! con `tag = HMAC-SHA256(secreto, mensaje)`; `verify_credential` la valida
//! on-canister (el gateway valida llamando aquí, sin secreto compartido).
//! En mainnet el destino es tECDSA — Task 15.

use candid::{Decode, Encode, Principal};
use hmac::{Hmac, Mac};
use ic_cdk::{init, post_upgrade, pre_upgrade, query, update};
use sha2::Sha256;
use std::cell::RefCell;
use std::collections::BTreeSet;

type HmacSha256 = Hmac<Sha256>;

/// Task 15: esqueleto tECDSA (diseño, no activo). El flujo HMAC sigue
/// siendo el camino por defecto; este módulo no se invoca desde aquí.
mod tecdsa;
pub mod access_core;

#[cfg(test)]
mod f2_tests;

/// TTL de la credencial nb2: 8h en nanosegundos.
const NB2_TTL_NS: u64 = 8 * 60 * 60 * 1_000_000_000;

thread_local! {
    static ADMIN: RefCell<Option<Principal>> = const { RefCell::new(None) };
    static ALLOWLIST: RefCell<BTreeSet<Principal>> = const { RefCell::new(BTreeSet::new()) };
    static EPOCH: RefCell<u64> = const { RefCell::new(0) };
    static NONCE: RefCell<u64> = const { RefCell::new(0) };
    /// Secreto efímero nb2: aleatorio por despliegue, solo en heap.
    /// Ningún método lo expone.
    static SECRET: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    /// Modo prueba abierta: cualquiera con II entra (auto-grant en
    /// `issue_credential`). Solo el admin lo activa/desactiva.
    /// Por defecto cerrado (fail-closed); al cerrar NO se expulsa a nadie
    /// (la allowlist conserva los auto-grants; usa `revoke` para limpiar).
    static OPEN_ACCESS: RefCell<bool> = const { RefCell::new(false) };
}

fn admin() -> Option<Principal> {
    ADMIN.with(|a| *a.borrow())
}

fn require_admin() {
    let caller = ic_cdk::api::msg_caller();
    assert_eq!(admin(), Some(caller), "only admin");
}

/// Fija el admin + allowlist y genera el secreto efímero nb2 (32 bytes de
/// `raw_rand`, sin semilla configurable ni método que lo lea).
///
/// Atómico: `raw_rand` se pide PRIMERO y el estado (ADMIN+ALLOWLIST+SECRET)
/// se escribe junto al final, sin `await` entre medias — nunca queda una
/// ventana con admin fijado y secreto vacío.
///
/// Solo se puede llamar una vez: si el hook instalador (`canister_init`) ya
/// fijó un admin, falla con "already initialized" salvo que se llame con el
/// mismo admin (idempotente para completar el secreto en mainnet).
#[update]
async fn init(admin: Principal) {
    if let Some(current) = ADMIN.with(|a| *a.borrow()) {
        assert_eq!(current, admin, "already initialized");
        if !SECRET.with(|s| s.borrow().is_empty()) {
            return; // init ya completo: idempotente.
        }
    }
    let rand = ic_cdk::management_canister::raw_rand()
        .await
        .expect("raw_rand failed");
    assert!(rand.len() >= 32, "raw_rand too short");
    let secret = rand[..32].to_vec();
    ADMIN.with(|a| {
        *a.borrow_mut() = Some(admin);
    });
    ALLOWLIST.with(|l| {
        l.borrow_mut().insert(admin);
    });
    SECRET.with(|s| {
        *s.borrow_mut() = secret;
    });
}

/// Hook instalador (corre solo en `install`, nunca en `upgrade`): fija el
/// admin = caller-instalador + allowlist con él, SIN secreto (el secreto nb2
/// queda pendiente hasta llamar a `init(admin)` explícito, que completa de
/// forma idempotente). Firma sin args para ser compatible con `dfx.json`,
/// que no declara `init_arg` para `access` (dfx pasa `()` por defecto).
/// En mainnet el deploy pasa el admin de control y luego se llama a
/// `init(admin)` para el secreto.
#[init]
fn canister_init() {
    let installer = ic_cdk::api::msg_caller();
    ADMIN.with(|a| {
        let mut a = a.borrow_mut();
        if a.is_none() {
            *a = Some(installer);
        }
    });
    ALLOWLIST.with(|l| {
        l.borrow_mut().insert(installer);
    });
}

/// Instantánea del estado para stable memory (tupla Candid).
/// Incluye el flag de prueba-abierta (6º campo; los snapshots viejos de
/// 5 campos se leen como cerrado = fail-closed).
type StateSnapshot = (Option<Principal>, Vec<Principal>, u64, u64, Vec<u8>, bool);
/// Snapshot v7: añade entitlements + containers + tx pagados. Se guarda como
/// un blob aparte para no tocar el formato v6 (append-only, pitfall §5).
/// v7b (run-3 fixes): + ledger configurado + flag vía legada +
/// historial de cambios de ledger (cap 32, append-only) + pin + cause
/// strings estructurados en PaymentLog. Los restores viejos (3 campos) se
/// rellenan con defaults: ledger=anonymous(=mainnet), legacy_enabled=FALSE
/// (sunset B4; los restores v7b guardan el valor real), historiales vacíos.
/// v7c (run-4 fixes): + historial de purgas + historial del flag legada.
type F2Snapshot = (
    Vec<(Principal, Entitlement)>,
    Vec<(Principal, ProvisionState)>,
    Vec<String>,
    Option<Principal>,
    Option<bool>,
    Option<Vec<(Principal, Principal, u64)>>,
    Option<bool>,
    Option<Vec<(Principal, String, u64)>>,
    Option<Vec<(Principal, bool, u64)>>,
);

/// Lee el estado vivo como instantánea pura (testeable sin réplica).
fn snapshot_state(
    admin: Option<Principal>,
    allowlist: Vec<Principal>,
    epoch: u64,
    nonce: u64,
    secret: Vec<u8>,
    open_access: bool,
) -> StateSnapshot {
    (admin, allowlist, epoch, nonce, secret, open_access)
}

/// Serializa la instantánea a bytes Candid (puro, testeable sin réplica).
fn encode_snapshot(snap: &StateSnapshot) -> Vec<u8> {
    Encode!(snap).expect("encode snapshot")
}

/// Deserializa la instantánea desde bytes Candid (puro, testeable sin réplica).
fn decode_snapshot(bytes: &[u8]) -> Result<StateSnapshot, String> {
    Decode!(bytes, StateSnapshot).map_err(|e| e.to_string())
}

/// Guarda (ADMIN, ALLOWLIST, EPOCH, NONCE, SECRET) en stable memory.
/// Si no hay estado, no escribe nada (el `post_upgrade` restaura vacío =
/// requiere `init`).
#[pre_upgrade]
fn save_state() {
    let snap: StateSnapshot = ADMIN.with(|a| {
        ALLOWLIST.with(|l| {
            EPOCH.with(|e| {
                NONCE.with(|n| {
                    SECRET.with(|s| {
                        OPEN_ACCESS.with(|o| {
                            snapshot_state(
                                *a.borrow(),
                                l.borrow().iter().cloned().collect(),
                                *e.borrow(),
                                *n.borrow(),
                                s.borrow().clone(),
                                *o.borrow(),
                            )
                        })
                    })
                })
            })
        })
    });
    if snap.0.is_none() && snap.1.is_empty() && snap.2 == 0 && snap.3 == 0 && snap.4.is_empty() {
        return;
    }
    let bytes = encode_snapshot(&snap);
    let f2: F2Snapshot = ENTITLEMENTS.with(|e| {
        CONTAINERS.with(|c| {
            PAID_TXS.with(|t| {
                LEDGER_CANISTER_ID.with(|l| {
                    LEGACY_ENABLED.with(|g| {
                        LEDGER_HISTORY.with(|h| {
                            LEDGER_PINNED.with(|p| {
                                PURGE_HISTORY.with(|u| {
                                    LEGACY_HISTORY.with(|g2| {
                                        (
                                            e.borrow().iter().map(|(k, v)| (*k, *v)).collect(),
                                            c.borrow().iter().map(|(k, v)| (*k, v.clone())).collect(),
                                            t.borrow().seen.iter().cloned().collect(),
                                            Some(*l.borrow()),
                                            Some(*g.borrow()),
                                            Some(h.borrow().clone()),
                                            Some(*p.borrow()),
                                            Some(u.borrow().clone()),
                                            Some(g2.borrow().clone()),
                                        )
                                    })
                                })
                            })
                        })
                    })
                })
            })
        })
    });
    let f2_bytes = Encode!(&f2).expect("encode f2 snapshot");
    ic_cdk::storage::stable_save((bytes, f2_bytes)).expect("stable_save failed");
}

/// Restaura el estado desde stable memory. Si no hay nada guardado, el
/// estado queda vacío (= requiere `init`). Acepta snapshots viejos de
/// 5 campos (sin flag open_access → cerrado = fail-closed).
#[post_upgrade]
fn restore_state() {
    // Compatibilidad: instalaciones viejas guardaron solo (bytes,); las
    // nuevas guardan (bytes, f2_bytes). Probamos la tupla de 2 y caemos a la
    // de 1 (F2 queda vacío = sin entitlements hasta que se acredite).
    let two: Result<(Vec<u8>, Vec<u8>), _> = ic_cdk::storage::stable_restore();
    if let Ok((bytes, f2_bytes)) = two {
        restore_v6(&bytes);
        restore_f2(&f2_bytes);
        return;
    }
    let stored: Result<(Vec<u8>,), _> = ic_cdk::storage::stable_restore();
    let Ok((bytes,)) = stored else {
        return;
    };
    restore_v6(&bytes);
}

fn restore_f2(f2_bytes: &[u8]) {
    // Formato v7c (9 campos).
    if let Ok((ents, conts, txs, ledger, legacy, hist, pinned, purges, leghist)) =
        Decode!(f2_bytes, F2Snapshot)
    {
        restore_f2_parts(ents, conts, txs);
        if let Some(l) = ledger {
            LEDGER_CANISTER_ID.with(|x| *x.borrow_mut() = l);
        }
        if let Some(b) = legacy {
            LEGACY_ENABLED.with(|x| *x.borrow_mut() = b);
        }
        if let Some(h) = hist {
            LEDGER_HISTORY.with(|x| *x.borrow_mut() = h.into_iter().take(32).collect());
        }
        if let Some(p) = pinned {
            LEDGER_PINNED.with(|x| *x.borrow_mut() = p);
        }
        if let Some(u) = purges {
            PURGE_HISTORY.with(|x| *x.borrow_mut() = u.into_iter().take(32).collect());
        }
        if let Some(g) = leghist {
            LEGACY_HISTORY.with(|x| *x.borrow_mut() = g.into_iter().take(32).collect());
        }
        return;
    }
    // Formato v7b (7 campos): migrar sin los historiales nuevos.
    type V7b = (
        Vec<(Principal, Entitlement)>,
        Vec<(Principal, ProvisionState)>,
        Vec<String>,
        Option<Principal>,
        Option<bool>,
        Option<Vec<(Principal, Principal, u64)>>,
        Option<bool>,
    );
    if let Ok((ents, conts, txs, ledger, legacy, hist, pinned)) =
        Decode!(f2_bytes, V7b)
    {
        restore_f2_parts(ents, conts, txs);
        if let Some(l) = ledger {
            LEDGER_CANISTER_ID.with(|x| *x.borrow_mut() = l);
        }
        if let Some(b) = legacy {
            LEGACY_ENABLED.with(|x| *x.borrow_mut() = b);
        }
        if let Some(h) = hist {
            LEDGER_HISTORY.with(|x| *x.borrow_mut() = h.into_iter().take(32).collect());
        }
        if let Some(p) = pinned {
            LEDGER_PINNED.with(|x| *x.borrow_mut() = p);
        }
        return;
    }
    // Formato v7 viejo (3 campos): defaults seguros = ledger mainnet
    // (anonymous), legada DESACTIVADA (sunset B4), historiales vacíos.
    type OldF2 = (
        Vec<(Principal, Entitlement)>,
        Vec<(Principal, ProvisionState)>,
        Vec<String>,
    );
    if let Ok((ents, conts, txs)) = Decode!(f2_bytes, OldF2) {
        restore_f2_parts(ents, conts, txs);
        LEGACY_ENABLED.with(|x| *x.borrow_mut() = false);
    }
}

fn restore_f2_parts(
    ents: Vec<(Principal, Entitlement)>,
    conts: Vec<(Principal, ProvisionState)>,
    txs: Vec<String>,
) {
    ENTITLEMENTS.with(|e| {
        let mut e = e.borrow_mut();
        for (k, v) in ents {
            e.insert(k, v);
        }
    });
    CONTAINERS.with(|c| {
        let mut c = c.borrow_mut();
        for (k, v) in conts {
            c.insert(k, v);
        }
    });
    PAID_TXS.with(|t| {
        let mut t = t.borrow_mut();
        for x in txs {
            t.seen.insert(x);
        }
    });
}

fn restore_v6(bytes: &[u8]) {
    // Formato actual (6 campos).
    if let Ok((admin, allowlist, epoch, nonce, secret, open_access)) =
        Decode!(&bytes, StateSnapshot)
    {
        ADMIN.with(|a| *a.borrow_mut() = admin);
        ALLOWLIST.with(|l| {
            *l.borrow_mut() = allowlist.into_iter().collect();
        });
        EPOCH.with(|e| *e.borrow_mut() = epoch);
        NONCE.with(|n| *n.borrow_mut() = nonce);
        SECRET.with(|s| *s.borrow_mut() = secret);
        OPEN_ACCESS.with(|o| *o.borrow_mut() = open_access);
        return;
    }
    // Snapshots viejos (5 campos): el flag queda en `false` (fail-closed).
    type OldSnapshot = (Option<Principal>, Vec<Principal>, u64, u64, Vec<u8>);
    let Ok((admin, allowlist, epoch, nonce, secret)) = Decode!(&bytes, OldSnapshot) else {
        return;
    };
    ADMIN.with(|a| *a.borrow_mut() = admin);
    ALLOWLIST.with(|l| {
        *l.borrow_mut() = allowlist.into_iter().collect();
    });
    EPOCH.with(|e| *e.borrow_mut() = epoch);
    NONCE.with(|n| *n.borrow_mut() = nonce);
    SECRET.with(|s| *s.borrow_mut() = secret);
}

/// Principal admin actual (`None` antes de `init`).
#[query]
fn get_admin() -> Option<Principal> {
    admin()
}

/// `true` si el llamante está en la allowlist.
#[query]
fn is_allowed_caller() -> bool {
    if OPEN_ACCESS.with(|o| *o.borrow()) {
        return true;
    }
    let caller = ic_cdk::api::msg_caller();
    ALLOWLIST.with(|l| l.borrow().contains(&caller))
}

/// `true` si `p` está en la allowlist (para que el gateway consulte por terceros).
#[query]
fn is_allowed(p: Principal) -> bool {
    if OPEN_ACCESS.with(|o| *o.borrow()) {
        return true;
    }
    ALLOWLIST.with(|l| l.borrow().contains(&p))
}

/// Añade `p` a la allowlist. Solo admin.
#[update]
fn grant(p: Principal) {
    require_admin();
    ALLOWLIST.with(|l| {
        l.borrow_mut().insert(p);
    });
}

/// Saca `p` de la allowlist. Solo admin. No permite revocar al propio admin.
#[update]
fn revoke(p: Principal) {
    require_admin();
    assert_ne!(admin(), Some(p), "cannot revoke admin");
    ALLOWLIST.with(|l| {
        l.borrow_mut().remove(&p);
    });
}

/// Época vigente (las credenciales nb2 emitidas con otra época se rechazan).
#[query]
fn get_epoch() -> u64 {
    EPOCH.with(|e| *e.borrow())
}

/// Incrementa la época de forma saturante. Solo admin. Invalida todas las
/// credenciales nb2 emitidas con la época anterior.
#[update]
fn bump_epoch() -> u64 {
    require_admin();
    EPOCH.with(|e| {
        let mut e = e.borrow_mut();
        *e = e.saturating_add(1);
        *e
    })
}

/// Incremento puro de época (testeable sin réplica): saturante.
#[cfg(test)]
fn bump_epoch_pure(epoch: u64) -> u64 {
    epoch.saturating_add(1)
}

/// Principal del llamante (útil para depurar login II en el frontend).
#[query]
fn me() -> Principal {
    ic_cdk::api::msg_caller()
}

/// Mensaje firmado: `nb2.<principal-text>.<expiry-ns>.<epoch>.<nonce>`.
/// `pub(crate)` para que el esqueleto tECDSA (Task 15) reutilice el formato.
pub(crate) fn nb2_message(principal_text: &str, expiry_ns: u64, epoch: u64, nonce: u64) -> String {
    format!("nb2.{principal_text}.{expiry_ns}.{epoch}.{nonce}")
}

/// Tag HMAC-SHA256 del mensaje, en hex minúsculas.
fn nb2_tag(secret: &[u8], message: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Emisión pura (testeable sin réplica): `nb2.<p>.<exp>.<epoch>.<nonce>.<tag>`.
fn nb2_issue(secret: &[u8], who: &Principal, now_ns: u64, epoch: u64, nonce: u64) -> String {
    let expiry = now_ns.saturating_add(NB2_TTL_NS);
    let msg = nb2_message(&who.to_text(), expiry, epoch, nonce);
    let tag = nb2_tag(secret, &msg);
    format!("{msg}.{tag}")
}

/// Verificación pura (testeable sin réplica): parsea, compara tag en tiempo
/// constante, exige `now < expiry`, época vigente y principal autorizado
/// (vía `allowed`, para no tocar estado global en tests).
///
/// OJO parseo: el texto del principal (`parts[1]`) contiene puntos
/// (`abcd-efg....`), así que NO se puede hacer split('.') esperando 6 partes.
/// Se trocea desde la derecha: tag, nonce, epoch, expiry; el resto
/// (prefijo `nb2.` + principal) se valida por separado.
fn nb2_verify_token(
    secret: &[u8],
    cred: &str,
    now_ns: u64,
    current_epoch: u64,
    allowed: bool,
) -> bool {
    let mut it = cred.rsplit('.');
    let (Some(tag_hex), Some(nonce_s), Some(epoch_s), Some(expiry_s)) =
        (it.next(), it.next(), it.next(), it.next())
    else {
        return false;
    };
    let head: String = it.rev().collect::<Vec<&str>>().join(".");
    let Some(who_text) = head.strip_prefix("nb2.") else {
        return false;
    };
    if who_text.is_empty() || Principal::from_text(who_text).is_err() {
        return false;
    }
    let (Ok(expiry), Ok(epoch), Ok(nonce)) = (
        expiry_s.parse::<u64>(),
        epoch_s.parse::<u64>(),
        nonce_s.parse::<u64>(),
    ) else {
        return false;
    };
    let Ok(tag_bytes) = hex::decode(tag_hex) else {
        return false;
    };
    if tag_bytes.len() != 32 {
        return false;
    }
    if now_ns >= expiry {
        return false;
    }
    if epoch != current_epoch {
        return false;
    }
    if !allowed {
        return false;
    }
    let msg = nb2_message(who_text, expiry, epoch, nonce);
    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(msg.as_bytes());
    use subtle::ConstantTimeEq;
    mac.finalize()
        .into_bytes()
        .as_slice()
        .ct_eq(tag_bytes.as_slice())
        .into()
}

/// Emite una credencial nb2 para el llamante. Solo si está en la allowlist
/// (o si el modo prueba-abierta está activo: auto-grant del llamante).
/// TTL 8h, época vigente, nonce monótono.
#[update]
fn issue_credential() -> String {
    let caller = ic_cdk::api::msg_caller();
    if OPEN_ACCESS.with(|o| *o.borrow()) {
        ALLOWLIST.with(|l| {
            l.borrow_mut().insert(caller);
        });
    } else {
        assert!(
            ALLOWLIST.with(|l| l.borrow().contains(&caller)),
            "not allowed"
        );
    }
    let now = ic_cdk::api::time();
    let epoch = EPOCH.with(|e| *e.borrow());
    let nonce = NONCE.with(|n| {
        let mut n = n.borrow_mut();
        *n = n.saturating_add(1);
        *n
    });
    SECRET.with(|s| nb2_issue(&s.borrow(), &caller, now, epoch, nonce))
}

/// Verifica una credencial nb2 on-canister. `true` solo si firma válida,
/// no expirada, época vigente y principal en allowlist
/// (o modo prueba-abierta activo: la allowlist se considera satisfecha).
///
/// El who se extrae desde la derecha (el texto del principal contiene puntos).
#[query]
fn verify_credential(cred: String) -> bool {
    let now = ic_cdk::api::time();
    let epoch = EPOCH.with(|e| *e.borrow());
    // who = todo entre "nb2." y los últimos 4 campos numéricos + tag.
    let mut it = cred.rsplit('.');
    let (Some(_tag), Some(_nonce), Some(_epoch), Some(_expiry)) =
        (it.next(), it.next(), it.next(), it.next())
    else {
        return false;
    };
    let head: String = it.rev().collect::<Vec<&str>>().join(".");
    let Some(who_text) = head.strip_prefix("nb2.") else {
        return false;
    };
    let Ok(who) = Principal::from_text(who_text) else {
        return false;
    };
    let allowed = OPEN_ACCESS.with(|o| *o.borrow())
        || ALLOWLIST.with(|l| l.borrow().contains(&who));
    SECRET.with(|s| nb2_verify_token(&s.borrow(), &cred, now, epoch, allowed))
}

/// Modo prueba-abierta: cualquiera con II entra (auto-grant en
/// `issue_credential`). Solo admin. Por defecto cerrado (fail-closed).
#[query]
fn get_open_access() -> bool {
    OPEN_ACCESS.with(|o| *o.borrow())
}

/// Activa/desactiva el modo prueba-abierta. Solo admin.
/// Al cerrar NO se expulsa a nadie: la allowlist conserva los auto-grants
/// (usa `revoke` para limpiar uno a uno).
#[update]
fn set_open_access(open: bool) -> bool {
    require_admin();
    OPEN_ACCESS.with(|o| *o.borrow_mut() = open);
    open
}


// ============================================================================
// F2 — entitlements, mapping II→contenedor y provisioning.
//
// Modelo de confianza (importante):
// - El mapping de contenedor lo escribe SOLO el admin (que actúa de
//   provisioner autorizado). El usuario solo puede LEERLO: si pudiera
//   escribirlo, apuntaría su propia sesión a un contenedor ajeno.
// - El pago se acredita por dos vías: admin (grant manual) o
//   `register_payment` (admin confirma que el ledger ICRC-1 tiene el tx).
//   No hay auto-acreditación desde el usuario.
// ============================================================================

use access_core::{
    activate as activate_ent, amount_ok, deactivate as deactivate_ent, decode_icrc3_payment_block,
    price_e8s, replay_key_for_block, subaccount_for, verify_icrc3_payment, ConsumeOutcome, Entitlement,
    PaymentLog, ProvisionState, ProvisionStatus,
};

/// Canister del ledger ICRC-1 de producción (ICP). Solo lectura: las
/// consultas `icrc3_get_blocks` se hacen a este principal salvo que el admin
/// fije otro para dev (`set_ledger_canister`).
const MAINNET_LEDGER_CANISTER_ID_TEXT: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";

thread_local! {
    /// Entitlement por principal.
    static ENTITLEMENTS: RefCell<std::collections::BTreeMap<Principal, Entitlement>> =
        const { RefCell::new(std::collections::BTreeMap::new()) };
    /// Mapping principal → estado de su contenedor.
    static CONTAINERS: RefCell<std::collections::BTreeMap<Principal, ProvisionState>> =
        const { RefCell::new(std::collections::BTreeMap::new()) };
    /// tx_ids del ledger ya acreditados (anti-replay).
    static PAID_TXS: RefCell<PaymentLog> = const { RefCell::new(PaymentLog::new_const(100_000)) };
    /// Ledger ICRC-1 contra el que se verifica on-canister. Por defecto el de
    /// mainnet; el admin puede fijar otro (réplica local con ledger de dev).
    static LEDGER_CANISTER_ID: RefCell<Principal> = const { RefCell::new(Principal::anonymous()) };
    /// Vía legada `register_payment` activada (default FALSE = sunset B4:
/// solo la vía verificada acredita; el admin puede reactivarla
/// temporalmente con `set_legacy_enabled(true)` y cada cambio queda en
/// LEGACY_HISTORY para auditoría).
    static LEGACY_ENABLED: RefCell<bool> = const { RefCell::new(false) };
    /// Historial de cambios de ledger (B1: evento auditable). Tuplas
    /// (quien, ledger_nuevo, cuando_ns). Cap 32, append-only.
    static LEDGER_HISTORY: RefCell<Vec<(Principal, Principal, u64)>> =
        const { RefCell::new(Vec::new()) };
    /// Historial de purgas del anti-replay (run-4 F3: auditabilidad).
    /// Tuplas (quien, clave_purgada, cuando_ns). Cap 32, append-only.
    static PURGE_HISTORY: RefCell<Vec<(Principal, String, u64)>> =
        const { RefCell::new(Vec::new()) };
    /// Historial del flag de vía legada (run-4 F5: sunset auditable).
    /// Tuplas (quien, nuevo_valor, cuando_ns). Cap 32, append-only.
    static LEGACY_HISTORY: RefCell<Vec<(Principal, bool, u64)>> =
        const { RefCell::new(Vec::new()) };
    /// Pin a mainnet (B1): una vez fijado el ledger oficial explícitamente,
    /// el canister queda clavado y rechaza cualquier otro. En dev (sin pin)
    /// el admin puede cambiar libremente.
    static LEDGER_PINNED: RefCell<bool> = const { RefCell::new(false) };
}

/// LEDGER_CANISTER_ID anonimo = mainnet (sentinela, nunca un ledger real).
/// (Se conserva para `ledger_canister_id`; el pin B1 vive en LEDGER_PINNED.)
#[allow(dead_code)]
fn is_mainnet_default() -> bool {
    LEDGER_CANISTER_ID.with(|l| *l.borrow() == Principal::anonymous())
}

/// Resuelve el ledger configurado; si el admin no fijó ninguno, el de mainnet.
fn ledger_canister_id() -> Principal {
    let configured = LEDGER_CANISTER_ID.with(|l| *l.borrow());
    if configured == Principal::anonymous() {
        Principal::from_text(MAINNET_LEDGER_CANISTER_ID_TEXT).expect("ledger mainnet")
    } else {
        configured
    }
}

/// Fija el ledger ICRC-1 contra el que se verifica. SOLO admin.
///
/// B1: pin + evento. Si el canister está clavado a mainnet
/// (`set_ledger_canister(mainnet)` una vez), cualquier otro principal
/// trapea. En dev (sin pin) el admin puede cambiar libremente.
/// Fijar explícitamente el ledger oficial ACTIVA el pin.
/// Cada cambio se registra en LEDGER_HISTORY (quien, nuevo, cuando; cap 32)
/// y el puntero persiste en stable (snapshot v7b).
#[update]
fn set_ledger_canister(id: Principal) -> Principal {
    require_admin();
    let mainnet = Principal::from_text(MAINNET_LEDGER_CANISTER_ID_TEXT).expect("ledger mainnet");
    if LEDGER_PINNED.with(|x| *x.borrow()) && id != mainnet {
        panic!("ledger clavado a mainnet: pin activo");
    }
    let who = ic_cdk::api::msg_caller();
    LEDGER_CANISTER_ID.with(|l| {
        *l.borrow_mut() = id;
    });
    if id == mainnet {
        LEDGER_PINNED.with(|x| *x.borrow_mut() = true);
    }
    LEDGER_HISTORY.with(|h| {
        let mut h = h.borrow_mut();
        h.push((who, id, now_ns()));
        while h.len() > 32 {
            h.remove(0);
        }
    });
    ledger_canister_id()
}

/// Ledger ICRC-1 en uso (configurado o mainnet por defecto).
#[query]
fn get_ledger_canister() -> Principal {
    ledger_canister_id()
}

/// Historial de cambios de ledger (B1: evento auditable). Solo admin.
/// Tuplas (quien, ledger_nuevo, cuando_ns). Cap 32, append-only.
#[query]
fn get_ledger_history() -> Vec<(Principal, Principal, u64)> {
    require_admin();
    LEDGER_HISTORY.with(|h| h.borrow().clone())
}

/// Vía legada activada. Solo admin (lectura del flag B4).
#[query]
fn get_legacy_enabled() -> bool {
    require_admin();
    LEGACY_ENABLED.with(|x| *x.borrow())
}

/// Activa/desactiva la vía legada `register_payment`. Solo admin (B4:
/// sunset con flag; default DESACTIVADA). Cada cambio queda registrado en
/// LEGACY_HISTORY (quien, nuevo_valor, cuando; cap 32).
#[update]
fn set_legacy_enabled(on: bool) -> bool {
    require_admin();
    let who = ic_cdk::api::msg_caller();
    LEGACY_ENABLED.with(|x| *x.borrow_mut() = on);
    LEGACY_HISTORY.with(|h| {
        let mut h = h.borrow_mut();
        h.push((who, on, now_ns()));
        while h.len() > 32 {
            h.remove(0);
        }
    });
    on
}

/// Historial del flag de vía legada (run-4 F5: sunset auditable).
/// Solo admin. Tuplas (quien, nuevo_valor, cuando_ns). Cap 32.
#[query]
fn get_legacy_history() -> Vec<(Principal, bool, u64)> {
    require_admin();
    LEGACY_HISTORY.with(|h| h.borrow().clone())
}

/// Nº de pagos acreditados (para que el admin audite el anti-replay).
/// Incluye capacidad del log para vigilar el cap (A3).
#[query]
fn get_paid_tx_count() -> (u64, u64) {
    require_admin();
    PAID_TXS.with(|l| (l.borrow().len() as u64, l.borrow().cap as u64))
}

/// Purga UNA clave del anti-replay (A3: recovery ante clave quemada por
/// fallo operativo, p.ej. days==0 o tx_id erróneo). Solo admin.
/// `true` = existía y se eliminó (reintentable); `false` = no estaba.
/// Run-4 F3: cada purga queda en PURGE_HISTORY (quien, clave, cuando).
#[update]
fn purge_paid_tx(tx_id: String) -> bool {
    require_admin();
    let who = ic_cdk::api::msg_caller();
    let removed = PAID_TXS.with(|l| l.borrow_mut().remove(&tx_id));
    if removed {
        PURGE_HISTORY.with(|h| {
            let mut h = h.borrow_mut();
            h.push((who, tx_id.trim().to_string(), now_ns()));
            while h.len() > 32 {
                h.remove(0);
            }
        });
    }
    removed
}

/// Historial de purgas del anti-replay (run-4 F3). Solo admin.
/// Tuplas (quien, clave_purgada, cuando_ns). Cap 32, append-only.
#[query]
fn get_purge_history() -> Vec<(Principal, String, u64)> {
    require_admin();
    PURGE_HISTORY.with(|h| h.borrow().clone())
}

/// TTL de la referencia de atestación publicada: 24h. Pasado ese plazo el
/// frontend debe pedir una nueva; no publicamos evidencia rancia para siempre.
const ATTESTATION_TTL_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

fn now_ns() -> u64 {
    ic_cdk::api::time()
}

/// Entitlement vigente del llamante.
#[query]
fn get_my_entitlement() -> Entitlement {
    let caller = ic_cdk::api::msg_caller();
    ENTITLEMENTS.with(|e| e.borrow().get(&caller).copied().unwrap_or_default())
}

/// `true` si el llamante tiene suscripción vigente.
#[query]
fn is_entitled_caller() -> bool {
    let caller = ic_cdk::api::msg_caller();
    is_entitled_at(&caller, now_ns())
}

/// Entitlement de un tercero (para que el provisioner decida sin suplantar).
#[query]
fn get_entitlement(p: Principal) -> Entitlement {
    ENTITLEMENTS.with(|e| e.borrow().get(&p).copied().unwrap_or_default())
}

fn is_entitled_at(p: &Principal, now: u64) -> bool {
    ENTITLEMENTS.with(|e| {
        e.borrow()
            .get(p)
            .map(|x| x.is_active_at(now))
            .unwrap_or(false)
    })
}

/// Precio (e8s) del tier y la subcuenta a la que debe llegar el pago.
/// El frontend usa esto para construir la transferencia ICRC-1.
#[query]
fn get_payment_info(tier: u8) -> (u64, [u8; 32]) {
    let caller = ic_cdk::api::msg_caller();
    (price_e8s(tier), subaccount_for(&caller))
}

/// Acredita una suscripción. SOLO admin (que verifica el ledger ICRC-1 fuera
/// del canister y confirma aquí). Anti-replay por `tx_id`.
/// `days` = duración del periodo contratado.
///
/// Vía legada (texto arbitrario como `tx_id`): el admin declara haber visto el
/// pago fuera del canister. SUNSET B4 (run-4 F5): desactivada por defecto;
/// solo `register_payment_verified` acredita salvo reactivación temporal
/// explícita del admin (auditada en LEGACY_HISTORY).
/// B4: desactivable con `set_legacy_enabled(false)` (sunset con flag).
#[update]
fn register_payment(who: Principal, tier: u8, amount_e8s: u64, tx_id: String, days: u32) -> Entitlement {
    require_admin();
    assert!(
        LEGACY_ENABLED.with(|x| *x.borrow()),
        "vía legada desactivada (sunset): use register_payment_verified"
    );
    assert!(days > 0, "days debe ser > 0");
    assert!(amount_ok(tier, amount_e8s), "amount below price for tier");
    match PAID_TXS.with(|l| l.borrow_mut().consume_result(&tx_id)) {
        ConsumeOutcome::Accepted => {}
        ConsumeOutcome::Empty => panic!("tx_id vacío"),
        ConsumeOutcome::Duplicate => panic!("tx already credited"),
        ConsumeOutcome::Full => panic!("anti-replay lleno (100000): purgue con purge_paid_tx"),
    }
    let now = now_ns();
    let e = ENTITLEMENTS.with(|m| {
        let mut m = m.borrow_mut();
        let cur = m.get(&who).copied().unwrap_or_default();
        let next = activate_ent(cur, tier, now, days);
        m.insert(who, next);
        next
    });
    e
}

/// Acredita una suscripción VERIFICANDO el pago on-canister.
///
/// Flujo (fail-closed en cada paso):
/// 1. solo admin (igual que `register_payment`).
/// 2. fast-path anti-replay: si `icrc3:<tx_id>` ya visto → trap sin tocar
///    el ledger (ahorra la llamada; la carrera la cierra el consume
///    post-verify).
/// 3. pide al ledger el bloque `tx_id` (`icrc3_get_blocks { start: tx_id,
///    length: 1 }`). Si `blocks` viene vacío pero hay `archived_blocks`,
///    sigue el callback del archive (1 nivel, A1); si tampoco hay bloque →
///    trap accionable ("bloque ausente o archivado no disponible").
/// 4. decodifica el bloque y exige `op = "xfer"` hacia
///    `(este canister, subaccount_for(who))` por importe >= precio.
/// 5. consume `icrc3:<tx_id>` TRAS verificar (A2: sin await entre verify y
///    consume+insert, el trap post-await ya no quema la clave). Carrera
///    concurrente: el segundo pierde el consume → trap, sin doble crédito.
/// 6. activa/renueva el entitlement como `register_payment`.
///
/// `days` = duración del periodo contratado. El importe LO DECIDE el bloque
/// del ledger, no un parámetro: ya no se puede acreditar declarando un
/// `amount_e8s` que nadie envió.
#[update]
async fn register_payment_verified(
    who: Principal,
    tier: u8,
    tx_id: u64,
    days: u32,
) -> Entitlement {
    require_admin();
    assert!(days > 0, "days debe ser > 0");
    // Fast-path: replay ya visto → trap antes del await (no consume).
    let key = replay_key_for_block(tx_id);
    assert!(
        !PAID_TXS.with(|l| l.borrow().contains(&key)),
        "tx already credited"
    );

    let ledger = ledger_canister_id();
    let me = ic_cdk::api::canister_self();
    let args = vec![icrc_ledger_types::icrc3::blocks::GetBlocksRequest {
        start: candid::Nat::from(tx_id),
        length: candid::Nat::from(1u64),
    }];
    let res: icrc_ledger_types::icrc3::blocks::GetBlocksResult =
        ic_cdk::call::Call::unbounded_wait(ledger, "icrc3_get_blocks")
            .with_arg(args)
            .await
            .map_err(|e| format!("ledger icrc3_get_blocks falló: {e:?}"))
            .expect("ledger icrc3_get_blocks falló")
            .candid()
            .map_err(|e| format!("ledger icrc3_get_blocks: respuesta no candid: {e:?}"))
            .expect("ledger icrc3_get_blocks: respuesta no candid");
    // A1: fallback a archive cuando blocks viene vacío.
    // El callback se pinea al ledger configurado: mismo canister, método
    // allowlist (icrc3_get_blocks), y args reconstruidos propios
    // {start:tx_id,length:1} (run-4 F2). Un ledger que devuelva callback a
    // un tercero o método raro trapea aquí, antes de gastar el 2º await.
    let b = match res.blocks.into_iter().next() {
        Some(b) => b,
        None => {
            let arch = res.archived_blocks.into_iter().next().expect(
                "bloque ausente o archivado no disponible: verifique el tx_id",
            );
            assert_eq!(
                arch.callback.canister_id, ledger,
                "callback de archive fuera del ledger configurado"
            );
            assert!(
                arch.callback.method == "icrc3_get_blocks"
                    || arch.callback.method == "get_blocks",
                "método de archive no permitido"
            );
            let arch_args = vec![icrc_ledger_types::icrc3::blocks::GetBlocksRequest {
                start: candid::Nat::from(tx_id),
                length: candid::Nat::from(1u64),
            }];
            let arch_res: icrc_ledger_types::icrc3::blocks::GetBlocksResult =
                ic_cdk::call::Call::unbounded_wait(arch.callback.canister_id, &arch.callback.method)
                    .with_arg(arch_args)
                    .await
                    .map_err(|e| format!("archive icrc3_get_blocks falló: {e:?}"))
                    .expect("archive icrc3_get_blocks falló")
                    .candid()
                    .map_err(|e| format!("archive: respuesta no candid: {e:?}"))
                    .expect("archive: respuesta no candid");
            arch_res.blocks.into_iter().next().expect(
                "bloque ausente o archivado no disponible: verifique el tx_id",
            )
        }
    };
    let ev = decode_icrc3_payment_block(&b.id, &b.block, &candid::Nat::from(tx_id))
        .expect("el bloque no es un pago acreditable");
    verify_icrc3_payment(&me, &who, tier, &ev).expect("pago inválido");

    // A2+A3: consume TRAS verificar, sin await hasta el insert.
    // Sin await entre medias = atómico ante trap: ningún fallo posterior
    // quema la clave. Concurrencia: el segundo en llegar pierde aquí.
    match PAID_TXS.with(|l| l.borrow_mut().consume_result(&key)) {
        ConsumeOutcome::Accepted => {}
        ConsumeOutcome::Empty => panic!("tx_id vacío"),
        ConsumeOutcome::Duplicate => panic!("tx already credited"),
        ConsumeOutcome::Full => panic!("anti-replay lleno (100000): purgue con purge_paid_tx"),
    }

    let now = now_ns();
    ENTITLEMENTS.with(|m| {
        let mut m = m.borrow_mut();
        let cur = m.get(&who).copied().unwrap_or_default();
        let next = activate_ent(cur, tier, now, days);
        m.insert(who, next);
        next
    })
}

/// Revoca la suscripción de alguien. Solo admin.
#[update]
fn revoke_entitlement(who: Principal) -> Entitlement {
    require_admin();
    ENTITLEMENTS.with(|m| {
        let mut m = m.borrow_mut();
        let cur = m.get(&who).copied().unwrap_or_default();
        let next = deactivate_ent(cur);
        m.insert(who, next);
        next
    })
}

// ------------------------------------------------------------- provisioning

/// El llamante pide su contenedor. Solo si tiene suscripción vigente.
/// Idempotente: repetir no degrada un contenedor ya activo.
#[update]
fn request_provision(tier: u8) -> ProvisionState {
    let caller = ic_cdk::api::msg_caller();
    assert!(is_entitled_at(&caller, now_ns()), "no active subscription");
    CONTAINERS.with(|m| {
        let mut m = m.borrow_mut();
        let cur = m.get(&caller).cloned().unwrap_or_default();
        let next = cur.request(tier);
        m.insert(caller, next.clone());
        next
    })
}

/// El provisioner confirma contenedor listo. SOLO admin.
/// `url` debe ser https; `attestation_ref` no puede ir vacía.
#[update]
fn set_container(who: Principal, url: String, attestation_ref: String) -> ProvisionState {
    require_admin();
    let now = now_ns();
    CONTAINERS.with(|m| {
        let mut m = m.borrow_mut();
        let cur = m.get(&who).cloned().unwrap_or_default();
        let mut next = cur.activate(&url, &attestation_ref);
        // El módulo puro deja los timestamps a 0 (no conoce el reloj);
        // el canister los sella aquí.
        if next.status == ProvisionStatus::Active {
            next.activated_ns = now;
        }
        m.insert(who, next.clone());
        next
    })
}

/// El admin apaga el contenedor (impago / baja / incidente).
#[update]
fn teardown_container(who: Principal) -> ProvisionState {
    require_admin();
    CONTAINERS.with(|m| {
        let mut m = m.borrow_mut();
        let cur = m.get(&who).cloned().unwrap_or_default();
        let next = cur.teardown();
        m.insert(who, next.clone());
        next
    })
}

/// **El directorio.** El frontend pregunta aquí dónde está su Hermes.
/// Devuelve solo estados `Active`; el resto se presenta como `None`.
/// La referencia de atestación se OMITE si tiene más de 24h (no publicamos
/// evidencia rancia como si fuera fresca).
#[query]
fn get_container(who: Principal) -> ProvisionState {
    let now = now_ns();
    CONTAINERS.with(|m| {
        let mut s = m.borrow().get(&who).cloned().unwrap_or_default();
        if s.status != ProvisionStatus::Active {
            return ProvisionState::default();
        }
        if now.saturating_sub(s.activated_ns) > ATTESTATION_TTL_NS {
            s.attestation_ref = None;
        }
        s
    })
}

/// Atajo para el llamante (el frontend no necesita pasar su principal).
#[query]
fn get_my_container() -> ProvisionState {
    get_container(ic_cdk::api::msg_caller())
}

#[query]
fn get_attestation_ttl_ns() -> u64 {
    ATTESTATION_TTL_NS
}

ic_cdk::export_candid!();

#[cfg(test)]
mod nb2_tests {
    //! Task 4 (TDD): emisión + verificación nb2 sobre funciones puras.
    use super::nb2_issue;
    use super::nb2_verify_token;
    use super::NB2_TTL_NS;
    use candid::Principal;

    fn test_secret() -> [u8; 32] {
        [0x42; 32]
    }

    fn tamper_field(cred: &str, idx: usize, new_val: &str) -> String {
        let mut parts: Vec<String> = cred.split('.').map(|s| s.to_string()).collect();
        parts[idx] = new_val.to_string();
        parts.join(".")
    }

    fn issue_at(now: u64, epoch: u64, nonce: u64) -> String {
        nb2_issue(&test_secret(), &Principal::anonymous(), now, epoch, nonce)
    }

    #[test]
    fn nb2_roundtrip() {
        let now = 1_700_000_000_000_000_000u64;
        let cred = issue_at(now, 0, 1);
        assert!(cred.starts_with("nb2."), "debe empezar por nb2.: {cred}");
        assert_eq!(cred.split('.').count(), 6, "formato nb2.<p>.<exp>.<epoch>.<nonce>.<tag>");
        assert!(nb2_verify_token(&test_secret(), &cred, now + 1_000, 0, true));
    }

    #[test]
    fn nb2_tampered_expiry_rejected() {
        let now = 1_700_000_000_000_000_000u64;
        let cred = issue_at(now, 0, 1);
        let parts: Vec<&str> = cred.split('.').collect();
        let bumped = parts[2].parse::<u64>().unwrap() + 1;
        let tampered = tamper_field(&cred, 2, &bumped.to_string());
        assert!(!nb2_verify_token(&test_secret(), &tampered, now + 1_000, 0, true));
    }

    #[test]
    fn nb2_expired_rejected() {
        let now = 1_700_000_000_000_000_000u64;
        let cred = issue_at(now, 0, 1);
        // `now >= expiry` rechaza (frontera exacta incluida).
        assert!(!nb2_verify_token(&test_secret(), &cred, now + NB2_TTL_NS, 0, true));
        assert!(!nb2_verify_token(
            &test_secret(),
            &cred,
            now + NB2_TTL_NS + 1,
            0,
            true
        ));
    }

    #[test]
    fn nb2_tampered_tag_rejected() {
        let now = 1_700_000_000_000_000_000u64;
        let cred = issue_at(now, 0, 1);
        let parts: Vec<&str> = cred.split('.').collect();
        let mut tag = parts[5].to_string();
        tag.replace_range(0..1, if &tag[0..1] == "a" { "b" } else { "a" });
        let tampered = tamper_field(&cred, 5, &tag);
        assert!(!nb2_verify_token(&test_secret(), &tampered, now + 1_000, 0, true));
    }

    #[test]
    fn nb2_wrong_epoch_rejected() {
        let now = 1_700_000_000_000_000_000u64;
        let cred = issue_at(now, 0, 1);
        assert!(!nb2_verify_token(&test_secret(), &cred, now + 1_000, 1, true));
    }

    #[test]
    fn nb2_not_allowed_rejected() {
        let now = 1_700_000_000_000_000_000u64;
        let cred = issue_at(now, 0, 1);
        assert!(!nb2_verify_token(&test_secret(), &cred, now + 1_000, 0, false));
    }

    #[test]
    fn nb2_wrong_secret_rejected() {
        let now = 1_700_000_000_000_000_000u64;
        let cred = issue_at(now, 0, 1);
        assert!(!nb2_verify_token(&[0x99; 32], &cred, now + 1_000, 0, true));
    }

    #[test]
    fn nb2_malformed_rejected() {
        let now = 1_700_000_000_000_000_000u64;
        for bad in [
            "",
            "nb2.",
            "nb1.2vxsx-fae.1.0.1.abcdef",
            "nb2.2vxsx-fae.notanumber.0.1.abcdef",
            "nb2.2vxsx-fae.1.0.1",
            "nb2.2vxsx-fae.1.0.1.zzzznotthex",
            "nb2.2vxsx-fae.1.0.1.aa",
        ] {
            assert!(
                !nb2_verify_token(&test_secret(), bad, now, 0, true),
                "debe rechazar: {bad:?}"
            );
        }
    }

    #[test]
    fn nb2_ttl_is_8h() {
        assert_eq!(NB2_TTL_NS, 8 * 60 * 60 * 1_000_000_000u64);
        let now = 1_700_000_000_000_000_000u64;
        let cred = issue_at(now, 3, 7);
        let parts: Vec<&str> = cred.split('.').collect();
        assert_eq!(parts[2].parse::<u64>().unwrap(), now + NB2_TTL_NS);
        assert_eq!(parts[4].parse::<u64>().unwrap(), 7);
    }

    #[test]
    fn nb2_known_vector() {
        // Vector reproducible: secreto [0x42;32], anónimo (2vxsx-fae),
        // now=1700000000000000000, epoch=0, nonce=1.
        let cred = issue_at(1_700_000_000_000_000_000, 0, 1);
        assert_eq!(
            cred,
            "nb2.2vxsx-fae.1700028800000000000.0.1.\
             95dfa4bbcd4eb5394409f1f1ee60144b731b40094c68bd293c774627cd9c8884"
        );
    }
}

#[cfg(test)]
mod mainnet_reserves_tests {
    //! Reservas mainnet: roundtrip de la instantánea stable + bump_epoch puro.
    use super::{bump_epoch_pure, decode_snapshot, encode_snapshot, snapshot_state};
    use candid::Principal;

    #[test]
    fn snapshot_roundtrip() {
        let admin = Principal::from_text("2vxsx-fae").unwrap();
        let snap = snapshot_state(
            Some(admin),
            vec![admin],
            3,
            41,
            vec![0x42; 32],
            true,
        );
        let bytes = encode_snapshot(&snap);
        let back = decode_snapshot(&bytes).expect("decode");
        assert_eq!(back, snap);
    }

    #[test]
    fn snapshot_empty_roundtrip() {
        let snap = snapshot_state(None, vec![], 0, 0, vec![], false);
        let back = decode_snapshot(&encode_snapshot(&snap)).expect("decode");
        assert_eq!(back, snap);
    }

    #[test]
    fn snapshot_old_5field_decodes_as_closed() {
        // Snapshot viejo (5 campos, sin flag): al decodificar con el tipo
        // actual falla → restore_state lo trata como cerrado (fail-closed).
        // Aquí se verifica que el formato viejo sigue siendo legible con
        // su propio tipo (compatibilidad de lectura explícita).
        use candid::{Decode, Encode};
        type Old = (Option<Principal>, Vec<Principal>, u64, u64, Vec<u8>);
        let old: Old = (None, vec![], 0, 0, vec![]);
        let bytes = Encode!(&old).expect("encode old");
        let back: Old = Decode!(&bytes, Old).expect("decode old");
        assert_eq!(back, old);
    }

    #[test]
    fn snapshot_corrupt_rejected() {
        assert!(decode_snapshot(b"no-es-candid").is_err());
    }

    #[test]
    fn bump_epoch_pure_increments_and_saturates() {
        assert_eq!(bump_epoch_pure(0), 1);
        assert_eq!(bump_epoch_pure(41), 42);
        assert_eq!(bump_epoch_pure(u64::MAX), u64::MAX);
    }
}

#[cfg(test)]
mod did_export {
    /// Regenera `access.did` junto al Cargo.toml para que `dfx.json`
    /// (campo `candid`) siempre apunte a una interfaz sincronizada.
    #[test]
    fn export_did_file() {
        let did = super::__export_service();
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        std::fs::write(format!("{dir}/access.did"), did).unwrap();
    }
}
