//! F2 — núcleo de entitlements, mapping de contenedor y provisioning.
//!
//! Todo lo de este módulo es **puro** (sin `ic_cdk`): recibe el estado, lo
//! transforma y lo devuelve. Así se testea sin réplica y `lib.rs` solo cablea
//! estado + llamadas.
//!
//! Invariantes de seguridad que se comprueban aquí:
//! 1. Un entitlement nace **inactivo** — nada se activa por defecto.
//! 2. La renovación **suma al vencimiento vigente**, no reinicia desde `now`
//!    (si no, renovar antes de caducar regalaría el tiempo restante).
//! 3. Un `tx_id` del ledger se consume **una vez** (anti-replay).
//! 4. La subcuenta ICRC-1 es determinista por principal — el usuario paga a
//!    SU cuenta, no a una genérica.
//! 5. El contenedor solo se activa con `https://` y con referencia de
//!    atestación; la URL publicada se **normaliza** (sin userinfo, sin query
//!    ni fragmento) para que el directorio certificado no filtre secretos.
//! 6. El estado de provisioning es **monótono**: un `Active` no vuelve a
//!    `Pending` porque el usuario repita la petición.

use candid::{CandidType, Deserialize, Nat, Principal};
use std::collections::BTreeSet;

pub const DAY_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

/// Precio del tier 1 en e8s (ICP tiene 8 decimales). Placeholder de v3.1:
/// se ajusta cuando se fije el precio comercial.
pub const PRICE_TIER1_E8S: u64 = 5 * 100_000_000; // 5 ICP

/// Convierte días a nanosegundos de forma saturante.
pub fn days_to_ns(days: u32) -> u64 {
    (days as u64).saturating_mul(DAY_NS)
}

// ----------------------------------------------------------------- entitlements

#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Entitlement {
    /// Tier contratado. 0 = ninguno.
    pub tier: u8,
    /// Cuándo se pagó por última vez (ns).
    pub paid_ns: u64,
    /// Cuándo caduca (ns). 0 = nunca activado.
    pub expires_ns: u64,
    /// Flag explícito; `false` = no hay suscripción.
    pub active: bool,
}

impl Entitlement {
    /// Suscripción vigente en `now` (activa y sin caducar).
    pub fn is_active_at(&self, now: u64) -> bool {
        self.active && self.tier > 0 && now < self.expires_ns
    }

    /// Alias explícito usado en los tests.
    pub fn is_valid_at(&self, now: u64) -> bool {
        self.is_active_at(now)
    }
}

/// Activa o renueva un entitlement. `days` = duración del periodo.
///
/// - tier 0 no activa nada (evita "activar sin plan").
/// - Si ya había una suscripción vigente, el nuevo periodo se **suma** al
///   vencimiento actual. Si estaba caducada (o nunca existió), arranca desde
///   `now`.
pub fn activate(mut e: Entitlement, tier: u8, now: u64, days: u32) -> Entitlement {
    if tier == 0 || days == 0 {
        return e;
    }
    let base = if e.is_active_at(now) { e.expires_ns } else { now };
    e.tier = tier;
    e.paid_ns = now;
    e.expires_ns = base.saturating_add(days_to_ns(days));
    e.active = true;
    e
}

/// Revoca la suscripción sin borrar el histórico de pago.
pub fn deactivate(mut e: Entitlement) -> Entitlement {
    e.active = false;
    e.tier = 0;
    e
}

// --------------------------------------------------------- pago ICRC-1 (anti-replay)

/// Registro de `tx_id` ya consumidos. Un mismo pago no puede acreditarse dos
/// veces (el usuario no puede reenviar el mismo comprobante).
#[derive(Default)]
pub struct PaymentLog {
    /// `pub(crate)` para que `lib.rs` pueda volcar/restaurar el snapshot.
    pub(crate) seen: BTreeSet<String>,
    /// Tope de entradas retenidas: el log no puede crecer sin límite
    /// (evita agotar ciclos con pagos basura).
    pub cap: usize,
}

impl PaymentLog {
    pub const fn new_const(cap: usize) -> Self {
        Self {
            seen: BTreeSet::new(),
            cap,
        }
    }

    pub fn new(cap: usize) -> Self {
        Self {
            seen: BTreeSet::new(),
            cap,
        }
    }

    /// Resultado estructurado del intento de consumo (A3: mensajes por
    /// causa en vez de un `bool` colapsado).
    pub fn consume_result(&mut self, tx_id: &str) -> ConsumeOutcome {
        let t = tx_id.trim();
        if t.is_empty() {
            return ConsumeOutcome::Empty;
        }
        if self.seen.contains(t) {
            return ConsumeOutcome::Duplicate;
        }
        let cap = if self.cap == 0 { 100_000 } else { self.cap };
        if self.seen.len() >= cap {
            return ConsumeOutcome::Full;
        }
        self.seen.insert(t.to_string());
        ConsumeOutcome::Accepted
    }

    /// Intenta consumir un `tx_id`. `true` = es la primera vez y se acepta.
    /// `false` = vacío/en blanco, ya usado, o el log está lleno.
    /// (Se conserva por compatibilidad con tests; el canister usa
    /// `consume_result` para mensajes por causa.)
    pub fn consume(&mut self, tx_id: &str) -> bool {
        matches!(self.consume_result(tx_id), ConsumeOutcome::Accepted)
    }

    /// ¿Ya visto (sin consumir)? Para el fast-path pre-await de la vía
    /// verificada: evita una llamada inter-canister inútil ante replay.
    /// No sustituye al `consume` post-verify (la carrera la cierra el
    /// `consume` atómico tras el último await).
    pub fn contains(&self, tx_id: &str) -> bool {
        self.seen.contains(tx_id.trim())
    }

    /// Purga admin (A3): elimina UNA clave concreta (p.ej. quemada por un
    /// fallo operativo). Solo admin vía `purge_paid_tx`. `true` = existía.
    pub fn remove(&mut self, tx_id: &str) -> bool {
        self.seen.remove(tx_id.trim())
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Causa del resultado de `consume_result` (A3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumeOutcome {
    Accepted,
    Empty,
    Duplicate,
    Full,
}

/// Subcuenta ICRC-1 derivada del principal del usuario.
///
/// Determinista: el usuario paga a SU subcuenta y `register_payment` puede
/// recomputarla y exigir que el pago llegó ahí. Sin esto, cualquiera podría
/// reclamar el pago de otro.
pub fn subaccount_for(p: &Principal) -> [u8; 32] {
    // sha256("hermetik-subaccount" || principal-bytes) truncado a 32.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"hermetik-subaccount");
    h.update(p.as_slice());
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d[..32]);
    out
}

/// Precio del tier (e8s). 0 = tier desconocido (no se puede acreditar).
pub fn price_e8s(tier: u8) -> u64 {
    match tier {
        1 => PRICE_TIER1_E8S,
        _ => 0,
    }
}

/// ¿El importe cubre el precio del tier?
pub fn amount_ok(tier: u8, amount_e8s: u64) -> bool {
    let p = price_e8s(tier);
    p > 0 && amount_e8s >= p
}

// ------------------------------------------------------------------- provisioning

#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ProvisionStatus {
    /// Nunca se pidió nada.
    #[default]
    None,
    /// Pedido aceptado, el provisioner aún no ha levantado el contenedor.
    Pending,
    /// Contenedor vivo con URL y atestación publicadas.
    Active,
}

#[derive(CandidType, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct ProvisionState {
    pub status: ProvisionStatus,
    pub tier: u8,
    pub url: Option<String>,
    /// Referencia opaca a la evidencia de atestación (no el quote entero).
    pub attestation_ref: Option<String>,
    /// ns en que se pidió / se activó.
    pub requested_ns: u64,
    pub activated_ns: u64,
}

impl ProvisionState {
    /// El usuario pide su contenedor. Idempotente sobre `Active`: repetir la
    /// petición NO degrada un contenedor ya vivo.
    pub fn request(mut self, tier: u8) -> Self {
        if self.status == ProvisionStatus::Active {
            return self;
        }
        self.status = ProvisionStatus::Pending;
        self.tier = tier;
        self.requested_ns = now_placeholder();
        self
    }

    /// El provisioner confirma el contenedor. Solo válido desde `Pending`,
    /// solo `https://`, y solo con referencia de atestación.
    pub fn activate(mut self, raw_url: &str, attestation_ref: &str) -> Self {
        if self.status != ProvisionStatus::Pending {
            return self;
        }
        if attestation_ref.trim().is_empty() {
            return self;
        }
        let Some(url) = normalize_url(raw_url) else {
            return self;
        };
        self.status = ProvisionStatus::Active;
        self.url = Some(url);
        self.attestation_ref = Some(attestation_ref.trim().to_string());
        self.activated_ns = now_placeholder();
        self
    }

    /// El admin apaga el contenedor (impago, baja voluntaria, incidente).
    pub fn teardown(mut self) -> Self {
        self.status = ProvisionStatus::None;
        self.url = None;
        self.attestation_ref = None;
        self.tier = 0;
        self
    }
}

/// `now` inyectable en tests; en el canister lo sobreescribe `lib.rs`.
/// Aquí se deja 0 para que el módulo siga siendo puro y testeable.
fn now_placeholder() -> u64 {
    0
}

/// Normaliza la URL publicable al directorio:
/// - exige esquema `https://` (http rompe el E2E y la atestación);
/// - descarta userinfo (`user:pass@`), query y fragmento (no filtramos secretos);
/// - descarta el path (el subdominio ES el tenant; un path añadiría confusión);
/// - devuelve `None` si no es utilizable.
pub fn normalize_url(raw: &str) -> Option<String> {
    let t = raw.trim();
    let rest = t.strip_prefix("https://")?;
    // Corta en el primer '/', '?' o '#' para quedarnos solo con el host.
    let host: String = rest
        .chars()
        .take_while(|c| *c != '/' && *c != '?' && *c != '#')
        .collect();
    // Descarta userinfo.
    let host = match host.rsplit_once('@') {
        Some((_, h)) => h.to_string(),
        None => host,
    };
    if host.is_empty() || !host.contains('.') || host.len() > 253 {
        return None;
    }
    // Solo caracteres válidos de hostname (evita inyección tipo `evil"`).
    let ok = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    if !ok || host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return None;
    }
    Some(format!("https://{host}"))
}

// ------------------------------------------- verificación on-canister ICRC-3
//
// El canister puede demostrar por sí mismo que un pago ICRC-1 llegó: pide al
// ledger el bloque `tx_id` (`icrc3_get_blocks`), decodifica el bloque ICRC-3
// y exige que describa una transferencia `op = "xfer"` hacia
// `(este canister, subaccount_for(who))` por importe >= precio del tier.
//
// El valor literal de `op` para transferencia en bloques ICRC-3 canónicos es
// `"xfer"` (no `"transfer"`; ese es el `kind` de la vista decodificada
// `icrc3_get_transactions`, hoy deprecada). Fuente: `icrc-ledger-types`
// `src/icrc3/schema.rs` (`item("op", Required, is(Value::text("xfer")))`) +
//
// Todo lo de esta sección es **puro** (sin `ic_cdk`): `lib.rs` solo hace la
// llamada al ledger y pasa el `ICRC3Value` aquí. Así se testea la decisión
// de crédito sin réplica.
//
// NOTA de honestidad: esto verifica el bloque que DEVUELVE el ledger vía
// query. No re-verifica certificados de la réplica ni la cadena de bloques;
// eso sería F5/F7. Lo que elimina es la confianza ciega en `amount_e8s`
// declarado por cualquiera que llame.

/// Extracto mínimo y suficiente de un bloque ICRC-3 para acreditar un pago.
///
/// `Nat` de `candid` se usa tal cual en la firma del lector del bloque para
/// no acoplar `access_core` (puro, sin ic_cdk) a la crate de tipos del ledger.
///
/// Campos:
/// - `tx_id`: índice del bloque (`icrc3_get_blocks { start, length: 1 }`).
/// - `kind_is_transfer`: `tx.op == "1xfer"`.
/// - `to_owner` / `to_subaccount`: el `tx.to` decodificado del bloque
///   (`owner` + subcuenta de 32 bytes).
/// - `amount_e8s`: `tx.amt` del bloque.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icrc3PaymentEvidence {
    pub tx_id: u64,
    pub kind_is_transfer: bool,
    pub to_owner: Principal,
    pub to_subaccount: Option<[u8; 32]>,
    pub amount_e8s: u64,
}

/// Lee un Nat ICRC-3 como e8s. Falla cerrado ante enteros negativos,
/// ausentes o que no quepan en `u64` (un importe que no cabe en u64 no puede
/// acreditar un precio fijado en u64; eso no es perder un pago válido porque
/// ningún pago real de ICP cabe fuera de u64, y si algún día cupiera se
/// amplía el tipo aquí, jamás se redondea en silencio).
fn icrc3_nat_e8s(v: &Nat) -> Option<u64> {
    use num_traits::cast::ToPrimitive;
    v.0.to_u64()
}

/// Extrae `(owner, subcuenta)` de un `tx.to`/`tx.from` ICRC-3.
///
/// Acepta las dos formas que circulan en el ecosistema:
/// - `Map { "owner": Blob(principal-bytes), "subaccount": Blob(32) }`
///   (la que devuelve el icrc1-ledger canónico vía `icrc3_get_blocks`).
/// - `Array [ Blob(principal-bytes), Blob(32)? ]`
///   (la forma compacta de otros ledgers ICRC-3).
///
/// Cualquier otra forma → `None` (el bloque no describe una cuenta
/// interpretable; la evidencia se rechaza).
fn icrc3_account(value: &icrc_ledger_types::icrc::generic_value::ICRC3Value) -> Option<(Principal, Option<[u8; 32]>)> {
    use icrc_ledger_types::icrc::generic_value::ICRC3Value as V;
    let to_icrc_account = |value: &V| -> Option<icrc_ledger_types::icrc1::account::Account> {
        match value {
            V::Map(m) => {
                let owner = match m.get("owner")? {
                    V::Blob(b) => Principal::try_from_slice(b.as_slice()).ok()?,
                    _ => return None,
                };
                let subaccount = match m.get("subaccount") {
                    None => None,
                    Some(V::Blob(b)) => {
                        let raw: &[u8] = b.as_ref();
                        if raw.len() != 32 {
                            return None;
                        }
                        let mut sub = [0u8; 32];
                        sub.copy_from_slice(raw);
                        Some(sub)
                    }
                    Some(_) => return None,
                };
                Some(icrc_ledger_types::icrc1::account::Account { owner, subaccount })
            }
            V::Array(items) => {
                let (owner_value, sub_value) = match items.as_slice() {
                    [owner, sub] => (owner, Some(sub)),
                    [owner] => (owner, None),
                    _ => return None,
                };
                let owner = match owner_value {
                    V::Blob(b) => Principal::try_from_slice(b.as_slice()).ok()?,
                    _ => return None,
                };
                let subaccount = match sub_value {
                    None => None,
                    Some(V::Blob(b)) => {
                        let raw: &[u8] = b.as_ref();
                        if raw.len() != 32 {
                            return None;
                        }
                        let mut sub = [0u8; 32];
                        sub.copy_from_slice(raw);
                        Some(sub)
                    }
                    Some(_) => return None,
                };
                Some(icrc_ledger_types::icrc1::account::Account { owner, subaccount })
            }
            _ => None,
        }
    };
    let account = to_icrc_account(value)?;
    let subaccount = account.subaccount;
    Some((account.owner, subaccount))
}

fn icrc3_get_text<'a>(
    map: &'a std::collections::BTreeMap<String, icrc_ledger_types::icrc::generic_value::ICRC3Value>,
    key: &str,
) -> Option<&'a str> {
    use icrc_ledger_types::icrc::generic_value::ICRC3Value as V;
    match map.get(key)? {
        V::Text(s) => Some(s.as_str()),
        _ => None,
    }
}

fn icrc3_get_u64(
    map: &std::collections::BTreeMap<String, icrc_ledger_types::icrc::generic_value::ICRC3Value>,
    key: &str,
) -> Option<u64> {
    use icrc_ledger_types::icrc::generic_value::ICRC3Value as V;
    match map.get(key)? {
        V::Nat(n) => icrc3_nat_e8s(n),
        _ => None,
    }
}

/// Decodifica UN bloque ICRC-3 (`BlockWithId`) en la evidencia mínima.
///
/// Estructura esperada del ledger canónico (bloques `Map`, claves de texto;
/// ver `icrc-ledger-types::icrc3::schema`):
/// `block["tx"] = Map { "op": "xfer", "to": <cuenta>, "amt": Nat, ... }`.
///
/// Devuelve `None` ante CUALQUIER desviación: no es transferencia, falta un
/// campo, el importe no cabe en u64, la cuenta es ilegible, o el `id` del
/// bloque no coincide con `start` esperado. `None` siempre significa
/// "no se puede acreditar con este bloque", jamás "inténtalo a ciegas".
pub fn decode_icrc3_payment_block(
    block_id: &Nat,
    block: &icrc_ledger_types::icrc::generic_value::ICRC3Value,
    start: &Nat,
) -> Option<Icrc3PaymentEvidence> {
    use icrc_ledger_types::icrc::generic_value::ICRC3Value as V;
    use num_traits::cast::ToPrimitive;

    let tx_id: u64 = block_id.0.to_u64()?;
    let start_u64: u64 = start.0.to_u64()?;
    if tx_id != start_u64 {
        return None;
    }
    let V::Map(top) = block else {
        return None;
    };
    let V::Map(tx) = top.get("tx")? else {
        return None;
    };
    let op = icrc3_get_text(tx, "op")?;
    if op != "xfer" {
        return None;
    }
    let (to_owner, to_subaccount) = icrc3_account(tx.get("to")?)?;
    let amount_e8s = icrc3_get_u64(tx, "amt")?;
    Some(Icrc3PaymentEvidence {
        tx_id,
        kind_is_transfer: true,
        to_owner,
        to_subaccount,
        amount_e8s,
    })
}

/// Decisión pura de crédito a partir de la evidencia decodificada.
///
/// Exige, en este orden (fail-closed, el primer fallo decide):
/// 1. que sea transferencia (`kind_is_transfer`);
/// 2. que el destino sea EXACTAMENTE `(access, subaccount_for(who))`;
/// 3. que el importe cubra el precio del tier (`amount_ok`).
///
/// Devuelve `Ok(())` acreditables o `Err(motivo)` para el trap del canister.
pub fn verify_icrc3_payment(
    access: &Principal,
    who: &Principal,
    tier: u8,
    ev: &Icrc3PaymentEvidence,
) -> Result<(), String> {
    if !ev.kind_is_transfer {
        return Err("el bloque no es una transferencia".to_string());
    }
    if &ev.to_owner != access {
        return Err("el pago no llegó a este canister".to_string());
    }
    match ev.to_subaccount {
        Some(got) if got == subaccount_for(who) => {}
        _ => return Err("el pago no llegó a la subcuenta del usuario".to_string()),
    }
    if !amount_ok(tier, ev.amount_e8s) {
        return Err("importe por debajo del precio del tier".to_string());
    }
    Ok(())
}

/// Clave anti-replay para un `tx_id`/`BlockIndex` ICRC-3: prefijo explícito
/// `icrc3:` + decimal canónico, para no colisionar con los `tx_id` texto
/// legados que ya pueda haber en `PAID_TXS`.
pub fn replay_key_for_block(tx_id: u64) -> String {
    format!("icrc3:{tx_id}")
}
