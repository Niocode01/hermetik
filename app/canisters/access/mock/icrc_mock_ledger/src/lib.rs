//! Mock mínimo del ledger ICRC-1/ICRC-3 SOLO para tests de `access`.
//!
//! NO es un ledger: solo sirve bloques ICRC-3 prefabricados por índice para
//! que `register_payment_verified` ejecute su llamada inter-canister real
//! (`icrc3_get_blocks`) en réplica local. Cada caso de test decide qué
//! bloque devuelve; el mock es tonto y honesto.
//!
//! B3 (gate anti-prod): este mock se niega a operar fuera de réplica local.
//! `mock_set_block`/`mock_clear`/`mock_archive_only` trapean si el caller NO
//! es controller del propio mock. En mainnet (donde el deployer no es
//! ninguno de esos) los writers quedan inertes.

use candid::Nat;
use ic_cdk::{query, update};
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use icrc_ledger_types::icrc3::blocks::{BlockWithId, GetBlocksRequest, GetBlocksResult};
use serde_bytes::ByteBuf;
use std::cell::RefCell;

thread_local! {
    static BLOCKS: RefCell<std::collections::BTreeMap<u64, ICRC3Value>> =
        const { RefCell::new(std::collections::BTreeMap::new()) };
    /// Bloques "archivados" (A1-test): se sirven SOLO vía callback de
    /// `archived_blocks`, nunca en `blocks`.
    static ARCHIVED: RefCell<std::collections::BTreeMap<u64, ICRC3Value>> =
        const { RefCell::new(std::collections::BTreeMap::new()) };
}

fn nat_u64(n: &Nat) -> Option<u64> {
    use num_traits::cast::ToPrimitive;
    n.0.to_u64()
}

/// B3: solo controllers del mock pueden escribir. En réplica local el
/// deployer (dfx identity) es controller y la matriz funciona. En mainnet,
/// si alguien despliega el mock por error, solo sus controllers (el
/// operador que lo desplegó) podrían fabricar bloques — un atacante externo
/// no puede. El gate principal sigue siendo no desplegar el mock en prod.
fn require_mock_writer() {
    let caller = ic_cdk::api::msg_caller();
    assert!(
        ic_cdk::api::is_controller(&caller),
        "mock solo réplica local: solo controllers escriben"
    );
}

#[update]
fn mock_set_block(id: u64, kind: String, to_owner_text: String, sub_hex: String, amount: u64) {
    require_mock_writer();
    let owner = candid::Principal::from_text(&to_owner_text).expect("principal");
    let sub: Vec<u8> = (0..sub_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&sub_hex[i..i + 2], 16).expect("hex"))
        .collect();
    assert_eq!(sub.len(), 32, "subcuenta mock");
    let block = ICRC3Value::Map(
        [
            (
                "tx".to_string(),
                ICRC3Value::Map(
                    [
                        ("op".to_string(), ICRC3Value::Text(kind)),
                        (
                            "to".to_string(),
                            ICRC3Value::Map(
                                [
                                    ("owner".to_string(), ICRC3Value::Blob(ByteBuf::from(owner.as_slice().to_vec()))),
                                    ("subaccount".to_string(), ICRC3Value::Blob(ByteBuf::from(sub))),
                                ]
                                .into_iter()
                                .collect(),
                            ),
                        ),
                        ("amt".to_string(), ICRC3Value::Nat(Nat::from(amount))),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
        ]
        .into_iter()
        .collect(),
    );
    BLOCKS.with(|b| {
        b.borrow_mut().insert(id, block);
    });
}

/// Mueve un bloque a ARCHIVED para el test vivo A1: `icrc3_get_blocks`
/// responde blocks=[] + callback al propio mock, y `access` debe seguirlo.
#[update]
fn mock_archive_only(id: u64) {
    require_mock_writer();
    let block = BLOCKS.with(|b| b.borrow_mut().remove(&id));
    if let Some(block) = block {
        ARCHIVED.with(|a| {
            a.borrow_mut().insert(id, block);
        });
    }
}

#[update]
fn mock_clear() {
    require_mock_writer();
    BLOCKS.with(|b| b.borrow_mut().clear());
    ARCHIVED.with(|a| a.borrow_mut().clear());
}

/// Sirve los bloques archivados (A1-test). `access` lo llama vía el
/// callback de `archived_blocks` cuando `blocks` viene vacío.
/// Alias canónico `get_blocks` para que el callback pase el pin de método
/// de `access` (run-4 F2): `mock_get_archived` queda como alias histórico.
#[query]
fn get_blocks(args: Vec<GetBlocksRequest>) -> GetBlocksResult {
    get_archived_impl(args)
}

/// Alias histórico del lector de archivados (run-3). Conservado para no
/// romper harnesses viejos; el callback A1 usa el canónico `get_blocks`.
#[query]
fn mock_get_archived(args: Vec<GetBlocksRequest>) -> GetBlocksResult {
    get_archived_impl(args)
}

fn get_archived_impl(args: Vec<GetBlocksRequest>) -> GetBlocksResult {
    let arg = args.into_iter().next().expect("GetBlocksRequest");
    let start = nat_u64(&arg.start).expect("start u64");
    let blocks: Vec<BlockWithId> = ARCHIVED.with(|a| {
        let a = a.borrow();
        if let Some(block) = a.get(&start) {
            vec![BlockWithId {
                id: Nat::from(start),
                block: block.clone(),
            }]
        } else {
            vec![]
        }
    });
    GetBlocksResult {
        log_length: Nat::from(BLOCKS.with(|b| b.borrow().len() as u64)),
        blocks,
        archived_blocks: vec![],
    }
}

#[query]
fn icrc3_get_blocks(args: Vec<GetBlocksRequest>) -> GetBlocksResult {
    let arg = args.into_iter().next().expect("GetBlocksRequest");
    let start = nat_u64(&arg.start).expect("start u64");
    let blocks: Vec<BlockWithId> = BLOCKS.with(|b| {
        let b = b.borrow();
        if let Some(block) = b.get(&start) {
            vec![BlockWithId {
                id: Nat::from(start),
                block: block.clone(),
            }]
        } else {
            vec![]
        }
    });
    if !blocks.is_empty() {
        return GetBlocksResult {
            log_length: Nat::from(BLOCKS.with(|b| b.borrow().len() as u64)),
            blocks,
            archived_blocks: vec![],
        };
    }
    // blocks vacío + índice archivado → callback al propio mock (A1).
    let has_archived = ARCHIVED.with(|a| a.borrow().contains_key(&start));
    if !has_archived {
        return GetBlocksResult {
            log_length: Nat::from(BLOCKS.with(|b| b.borrow().len() as u64)),
            blocks: vec![],
            archived_blocks: vec![],
        };
    }
    use icrc_ledger_types::icrc3::archive::QueryArchiveFn;
    GetBlocksResult {
        log_length: Nat::from(BLOCKS.with(|b| b.borrow().len() as u64)),
        blocks: vec![],
        archived_blocks: vec![
            icrc_ledger_types::icrc3::blocks::ArchivedBlocks {
                args: vec![GetBlocksRequest {
                    start: candid::Nat::from(start),
                    length: candid::Nat::from(1u64),
                }],
                callback: QueryArchiveFn::new(ic_cdk::api::canister_self(), "get_blocks"),
            },
        ],
    }
}

ic_cdk::export_candid!();

#[cfg(test)]
mod did_export {
    /// Regenera `mock_ledger.did` para que siempre incluya los métodos
    /// nuevos (mock_archive_only, mock_get_archived). Run-4 F3.
    #[test]
    fn export_did_file() {
        let did = super::__export_service();
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        std::fs::write(format!("{dir}/mock_ledger.did"), did).unwrap();
    }
}
