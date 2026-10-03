//! F2 (TDD): entitlements (suscripción ICRC-1), mapping II→contenedor y
//! ciclo de provisioning. Funciones puras, sin réplica.
//!
//! Modelo de confianza:
//! - El canister es plano de CONTROL: guarda metadatos, nunca contenido.
//! - El pago se acredita SOLO por dos vías: (a) el ledger ICRC-1 vía
//!   `register_payment` (tx_id consumido una vez, no reutilizable) o
//!   (b) el admin (grant manual / cortesía). No hay auto-acreditación.
//! - El mapping de contenedor lo escribe SOLO el admin/provisioner
//!   autorizado; el usuario solo puede LEERLO. Si el usuario pudiera
//!   escribirlo, podría apuntar su sesión a un contenedor ajeno.

use super::access_core::*;
use candid::Principal;

fn p(n: u8) -> Principal {
    Principal::from_slice(&[n; 29])
}

// ---------------------------------------------------------------- entitlements

#[test]
fn entitlement_starts_inactive() {
    let e = Entitlement::default();
    assert!(!e.active, "un entitlement recién creado debe estar inactivo");
    assert_eq!(e.tier, 0);
    assert_eq!(e.expires_ns, 0);
}

#[test]
fn entitlement_activate_sets_expiry_and_tier() {
    let now = 1_700_000_000_000_000_000u64;
    let e = activate(Entitlement::default(), 1, now, 30);
    assert!(e.active);
    assert_eq!(e.tier, 1);
    assert_eq!(e.paid_ns, now);
    assert!(e.expires_ns > now);
    assert!(e.is_valid_at(now));
}

#[test]
fn entitlement_expires() {
    let now = 1_700_000_000_000_000_000u64;
    let e = activate(Entitlement::default(), 1, now, 30);
    assert!(e.is_valid_at(e.expires_ns - 1), "válido un ns antes");
    assert!(!e.is_valid_at(e.expires_ns), "expirado en el instante exacto");
    assert!(!e.is_valid_at(e.expires_ns + 1), "expirado después");
}

#[test]
fn entitlement_renewal_extends_from_current_expiry_not_from_now() {
    // Renovar antes de caducar NO debe regalar el tiempo restante.
    let now = 1_000_000_000u64;
    let e = activate(Entitlement::default(), 1, now, 30);
    let later = now + 10 * DAY_NS;
    let e2 = activate(e, 1, later, 30);
    assert_eq!(
        e2.expires_ns,
        e.expires_ns + 30 * DAY_NS,
        "la renovación suma al vencimiento vigente, no reinicia desde now"
    );
}

#[test]
fn entitlement_is_expired_before_any_payment() {
    assert!(!Entitlement::default().is_valid_at(1));
    assert!(!Entitlement::default().is_active_at(1));
}

#[test]
fn tier_must_be_known() {
    let now = 1_000_000_000u64;
    let e = activate(Entitlement::default(), 1, now, 30);
    assert_eq!(e.tier, 1);
    // tier 0 = inválido para activar (sería "activar sin plan").
    let e0 = activate(Entitlement::default(), 0, now, 30);
    assert!(!e0.active, "no se puede activar el tier 0");
}

#[test]
fn days_convert_to_ns() {
    assert_eq!(days_to_ns(30), 30 * DAY_NS);
    assert_eq!(days_to_ns(0), 0);
}

// ------------------------------------------------------- ledger ICRC-1 / anti-replay

#[test]
fn payment_tx_cannot_be_replayed() {
    let mut seen = PaymentLog::default();
    assert!(seen.consume("tx-1"), "primer uso del tx debe aceptarse");
    assert!(
        !seen.consume("tx-1"),
        "el MISMO tx_id no puede acreditarse dos veces"
    );
    assert!(seen.consume("tx-2"), "otro tx_id sí");
}

#[test]
fn empty_and_blank_tx_rejected() {
    let mut seen = PaymentLog::default();
    assert!(!seen.consume(""));
    assert!(!seen.consume("   "));
}

#[test]
fn expected_subaccount_matches_principal_derivation() {
    // La subcuenta es determinista a partir del principal: si cambia,
    // el usuario pagaría a una cuenta que no es la suya.
    let a = subaccount_for(&p(1));
    let b = subaccount_for(&p(1));
    let c = subaccount_for(&p(2));
    assert_eq!(a, b, "determinista");
    assert_ne!(a, c, "distinta por principal");
    assert_eq!(a.len(), 32, "subcuenta ICRC-1 = 32 bytes");
}

#[test]
fn payment_amount_must_meet_price() {
    // Precio por tier (en e8s). No se acredita si el pago es insuficiente.
    assert!(amount_ok(1, PRICE_TIER1_E8S));
    assert!(amount_ok(1, PRICE_TIER1_E8S + 1), "pagar de más vale");
    assert!(!amount_ok(1, PRICE_TIER1_E8S - 1), "pagar de menos NO");
    assert!(!amount_ok(1, 0), "cero no acredita");
    assert!(!amount_ok(0, u64::MAX), "tier 0 no tiene precio");
}

// -------------------------------- verificación on-canister de bloques ICRC-3

use candid::Nat;
use icrc_ledger_types::icrc::generic_value::ICRC3Value as V;
use serde_bytes::ByteBuf;

fn access_principal() -> Principal {
    Principal::from_text("2vxsx-fae").expect("principal de tests")
}

fn user_principal() -> Principal {
    Principal::from_slice(&[9u8; 29])
}

fn tx_map(entries: Vec<(&str, V)>) -> V {
    V::Map(entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn blob(bytes: &[u8]) -> V {
    V::Blob(ByteBuf::from(bytes.to_vec()))
}

fn good_transfer_tx(to_owner: Principal, sub: [u8; 32], amount: u64) -> V {
    let owner_blob = blob(to_owner.as_slice());
    let sub_blob = blob(&sub);
    let to = tx_map(vec![("owner", owner_blob), ("subaccount", sub_blob)]);
    tx_map(vec![
        ("op", V::Text("xfer".to_string())),
        ("to", to),
        ("amt", V::Nat(Nat::from(amount))),
    ])
}

fn good_block(tx: V, id: u64) -> (Nat, V) {
    (
        Nat::from(id),
        tx_map(vec![("ts", V::Nat(Nat::from(1_700_000_000u64))), ("tx", tx)]),
    )
}

#[test]
fn icrc3_good_transfer_decodes() {
    let access = access_principal();
    let who = user_principal();
    let sub = subaccount_for(&who);
    let (id, block) = good_block(good_transfer_tx(access, sub, PRICE_TIER1_E8S), 42);
    let ev = decode_icrc3_payment_block(&id, &block, &Nat::from(42u64)).expect("bloque válido");
    assert_eq!(ev.tx_id, 42);
    assert!(ev.kind_is_transfer);
    assert_eq!(ev.to_owner, access);
    assert_eq!(ev.to_subaccount, Some(sub));
    assert_eq!(ev.amount_e8s, PRICE_TIER1_E8S);
    verify_icrc3_payment(&access, &who, 1, &ev).expect("pago válido");
    assert_eq!(replay_key_for_block(42), "icrc3:42");
}

#[test]
fn icrc3_wrong_subaccount_is_rejected() {
    let access = access_principal();
    let who = user_principal();
    let (id, block) = good_block(good_transfer_tx(access, [7u8; 32], PRICE_TIER1_E8S), 7);
    let ev = decode_icrc3_payment_block(&id, &block, &Nat::from(7u64)).expect("decodificable");
    assert!(verify_icrc3_payment(&access, &who, 1, &ev).is_err());
}

#[test]
fn icrc3_wrong_owner_is_rejected() {
    let access = access_principal();
    let who = user_principal();
    let sub = subaccount_for(&who);
    let other = Principal::from_slice(&[8u8; 29]);
    let (id, block) = good_block(good_transfer_tx(other, sub, PRICE_TIER1_E8S), 7);
    let ev = decode_icrc3_payment_block(&id, &block, &Nat::from(7u64)).expect("decodificable");
    assert!(verify_icrc3_payment(&access, &who, 1, &ev).is_err());
}

#[test]
fn icrc3_underpaid_is_rejected() {
    let access = access_principal();
    let who = user_principal();
    let sub = subaccount_for(&who);
    let (id, block) = good_block(good_transfer_tx(access, sub, PRICE_TIER1_E8S - 1), 7);
    let ev = decode_icrc3_payment_block(&id, &block, &Nat::from(7u64)).expect("decodificable");
    assert!(verify_icrc3_payment(&access, &who, 1, &ev).is_err());
    assert!(verify_icrc3_payment(&access, &who, 0, &ev).is_err());
}

#[test]
fn icrc3_non_transfer_op_is_rejected() {
    let access = access_principal();
    let who = user_principal();
    let sub = subaccount_for(&who);
    let owner_blob = blob(access.as_slice());
    let sub_blob = blob(&sub);
    let to = tx_map(vec![("owner", owner_blob), ("subaccount", sub_blob)]);
    let tx = tx_map(vec![
        ("op", V::Text("burn".to_string())),
        ("to", to),
        ("amt", V::Nat(Nat::from(PRICE_TIER1_E8S))),
    ]);
    let (id, block) = good_block(tx, 9);
    assert!(decode_icrc3_payment_block(&id, &block, &Nat::from(9u64)).is_none());
    let ev = Icrc3PaymentEvidence {
        tx_id: 9,
        kind_is_transfer: false,
        to_owner: access,
        to_subaccount: Some(sub),
        amount_e8s: PRICE_TIER1_E8S,
    };
    assert!(verify_icrc3_payment(&access, &who, 1, &ev).is_err());
}

#[test]
fn icrc3_block_id_must_match_start() {
    let access = access_principal();
    let who = user_principal();
    let sub = subaccount_for(&who);
    let (id, block) = good_block(good_transfer_tx(access, sub, PRICE_TIER1_E8S), 10);
    assert!(decode_icrc3_payment_block(&id, &block, &Nat::from(11u64)).is_none());
}

#[test]
fn icrc3_malformed_block_is_rejected() {
    use icrc_ledger_types::icrc::generic_value::ICRC3Value as V2;
    let bad: Vec<V2> = vec![
        tx_map(vec![]),
        tx_map(vec![("tx", V::Text("no-es-mapa".to_string()))]),
        tx_map(vec![(
            "tx",
            tx_map(vec![("op", V::Text("xfer".to_string()))]),
        )]),
        tx_map(vec![(
            "tx",
            tx_map(vec![
                ("op", V::Text("xfer".to_string())),
                ("to", V::Text("no-es-cuenta".to_string())),
                ("amt", V::Nat(Nat::from(PRICE_TIER1_E8S))),
            ]),
        )]),
        tx_map(vec![(
            "tx",
            tx_map(vec![
                ("op", V::Text("xfer".to_string())),
                (
                    "to",
                    tx_map(vec![
                        ("owner", blob(access_principal().as_slice())),
                        ("subaccount", blob(&[1u8; 4])),
                    ]),
                ),
                ("amt", V::Nat(Nat::from(PRICE_TIER1_E8S))),
            ]),
        )]),
        tx_map(vec![(
            "tx",
            tx_map(vec![
                ("op", V::Text("xfer".to_string())),
                (
                    "to",
                    tx_map(vec![
                        ("owner", blob(access_principal().as_slice())),
                        ("subaccount", blob(&subaccount_for(&user_principal()))),
                    ]),
                ),
            ]),
        )]),
    ];
    for (i, raw) in bad.into_iter().enumerate() {
        let (id, block) = good_block(raw, 100 + i as u64);
        assert!(
            decode_icrc3_payment_block(&id, &block, &(100 + i as u64).into()).is_none(),
            "bloque malformado #{i} debe rechazarse"
        );
    }
    assert!(decode_icrc3_payment_block(&Nat::from(1u64), &V::Text("x".into()), &Nat::from(1u64)).is_none());
}

// ------------------------------------------------------------ provisioning state

#[test]
fn provisioning_starts_pending_then_active() {
    let s = ProvisionState::default();
    assert_eq!(s.status, ProvisionStatus::None);
    let s1 = s.request(1);
    assert_eq!(s1.status, ProvisionStatus::Pending);
    assert_eq!(s1.tier, 1);
    let s2 = s1.activate("https://t1.hermetik.eu", "att-ref-abc");
    assert_eq!(s2.status, ProvisionStatus::Active);
    assert_eq!(s2.url.as_deref(), Some("https://t1.hermetik.eu"));
}

#[test]
fn provisioning_cannot_activate_without_request() {
    let s = ProvisionState::default();
    let out = s.activate("https://x", "att");
    assert_eq!(
        out.status,
        ProvisionStatus::None,
        "no se puede activar lo que nunca se pidió"
    );
    assert!(out.url.is_none());
}

#[test]
fn provisioning_requires_https() {
    let s = ProvisionState::default().request(1);
    let out = s.activate("http://inseguro.hermetik.eu", "att");
    assert_eq!(
        out.status,
        ProvisionStatus::Pending,
        "http:// en claro no se activa (rompería el E2E)"
    );
    assert!(out.url.is_none());
}

#[test]
fn provisioning_rejects_empty_attestation() {
    let s = ProvisionState::default().request(1);
    let out = s.activate("https://t1.hermetik.eu", "");
    assert_eq!(
        out.status,
        ProvisionStatus::Pending,
        "sin referencia de atestación no hay confianza"
    );
}

#[test]
fn provisioning_state_is_monotonic() {
    // Un estado Active no puede volver a Pending por re-request del usuario.
    let s = ProvisionState::default()
        .request(1)
        .activate("https://t1.hermetik.eu", "att");
    let s2 = s.clone().request(1);
    assert_eq!(
        s2.status,
        ProvisionStatus::Active,
        "re-request no degrada un contenedor ya activo"
    );
}

#[test]
fn provisioning_can_be_torn_down_by_admin() {
    let s = ProvisionState::default()
        .request(1)
        .activate("https://t1.hermetik.eu", "att");
    let s2 = s.teardown();
    assert_eq!(s2.status, ProvisionStatus::None);
    assert!(s2.url.is_none(), "teardown borra la URL");
}

#[test]
fn container_url_never_leaks_credentials() {
    // La URL que el canister publica NO debe llevar userinfo ni query.
    let s = ProvisionState::default()
        .request(1)
        .activate("https://user:pass@t1.hermetik.eu/path?token=abc", "att");
    let url = s.url.expect("url");
    assert!(!url.contains("user:pass"), "sin credenciales embebidas");
    assert!(!url.contains("token="), "sin query con secretos");
    assert_eq!(url, "https://t1.hermetik.eu");
}

// --------------------------------- run-3 fixes: PaymentLog causa + purga

#[test]
fn consume_result_distinguishes_cause() {
    let mut l = PaymentLog::new(10);
    assert_eq!(l.consume_result("a"), ConsumeOutcome::Accepted);
    assert_eq!(l.consume_result("a"), ConsumeOutcome::Duplicate);
    assert_eq!(l.consume_result("   "), ConsumeOutcome::Empty);
    assert!(l.contains("a"));
    assert!(!l.contains("b"));
}

#[test]
fn consume_result_full_and_purge_recovers() {
    let mut l = PaymentLog::new(2);
    assert_eq!(l.consume_result("a"), ConsumeOutcome::Accepted);
    assert_eq!(l.consume_result("b"), ConsumeOutcome::Accepted);
    assert_eq!(l.consume_result("c"), ConsumeOutcome::Full);
    assert!(l.remove("a"));
    assert_eq!(l.consume_result("c"), ConsumeOutcome::Accepted);
    assert!(!l.remove("zzz"));
}
