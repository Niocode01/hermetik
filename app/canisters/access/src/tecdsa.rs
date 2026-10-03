//! Ruta tECDSA (Task 15 — diseño, NO activa).
//!
//! El flujo activo sigue siendo HMAC-SHA256 con secreto efímero
//! (`nb2_issue` / `nb2_verify_token` en `lib.rs`). Este módulo deja
//! escrita y compilando la variante mainnet donde `issue_credential`
//! firma con tECDSA del subnet en vez de HMAC.
//!
//! Compilación:
//! - Sin flag: solo compilan los helpers puros (mensaje, hash, key-id,
//!   parseo). Testeables sin réplica.
//! - Con `--features tecdsa`: además compilan las llamadas reales al
//!   management canister (`sign_with_ecdsa`, `ecdsa_public_key` vía
//!   `ic_cdk::management_canister`, disponible en ic-cdk 0.18).
//!
//! Formato del token tECDSA (prefijo distinto para no colisionar con HMAC):
//! `nb2t.<principal-text>.<expiry-ns>.<epoch>.<nonce>.<sig-hex>`
//! donde `sig-hex` es la firma ECDSA (r||s, 64 bytes) sobre
//! `SHA256("nb2.<principal>.<expiry>.<epoch>.<nonce>")`.
//!
//! Verificación on-canister: ic-cdk 0.18 NO expone `ecdsa_verify` ni
//! recover on-canister; en mainnet la verificación sería recuperar la
//! clave con `ecdsa_public_key` + una crate secp256k1 (p. ej. `k256`,
//! pendiente de añadir) o exponer `verify_tecdsa` en candid. Ver
//! `docs/adr-02-tecdsa.md`.

#![allow(dead_code)]

use candid::Principal;
use sha2::{Digest, Sha256};

/// Prefijo del token tECDSA (distinto de `nb2.` para no colisionar).
pub(crate) const TECDSA_PREFIX: &str = "nb2t";

/// Clave de test que `dfx >= 0.14` expone en réplica local.
/// NO existe en mainnet; allí se usa una llave de producción
/// (ver [`production_key_name`]).
pub(crate) const TEST_KEY_NAME: &str = "test_key_1";

/// Nombre de llave documentado para mainnet (se crea al desplegar;
/// el canister debe ser controlador o estar autorizado).
/// Se deja como referencia de diseño; el valor final se fija al activar.
pub(crate) fn production_key_name() -> String {
    "key_1".to_string()
}

/// Derivation path por canister para la llave tECDSA.
/// Aisla la clave derivada de este canister de la de otros canisters
/// que compartan la misma llave maestra del subnet.
pub(crate) fn derivation_path() -> Vec<Vec<u8>> {
    vec![b"nebulock-nb2".to_vec()]
}

/// Mensaje a firmar: reutiliza el formato nb2 de `lib.rs`
/// (`nb2.<principal>.<expiry>.<epoch>.<nonce>`).
pub(crate) fn tecdsa_sign_message(
    principal_text: &str,
    expiry_ns: u64,
    epoch: u64,
    nonce: u64,
) -> String {
    crate::nb2_message(principal_text, expiry_ns, epoch, nonce)
}

/// Hash de 32 bytes que se pasa a `sign_with_ecdsa` (`message_hash`).
pub(crate) fn tecdsa_message_hash(message: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(message.as_bytes());
    h.finalize().into()
}

/// Campos parseados de un token `nb2t.*` (sin verificar firma).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TecdsaCredential {
    pub who_text: String,
    pub expiry_ns: u64,
    pub epoch: u64,
    pub nonce: u64,
    pub sig_hex: String,
}

/// Parseo puro del token tECDSA (troceo desde la derecha: el texto del
/// principal contiene puntos, igual que en `nb2_verify_token`).
/// Devuelve `None` si el formato es inválido.
pub(crate) fn tecdsa_parse_credential(cred: &str) -> Option<TecdsaCredential> {
    let mut it = cred.rsplit('.');
    let (Some(sig_hex), Some(nonce_s), Some(epoch_s), Some(expiry_s)) =
        (it.next(), it.next(), it.next(), it.next())
    else {
        return None;
    };
    let head: String = it.rev().collect::<Vec<&str>>().join(".");
    let who_text = head.strip_prefix("nb2t.")?;
    if who_text.is_empty() || Principal::from_text(who_text).is_err() {
        return None;
    }
    let (Ok(expiry_ns), Ok(epoch), Ok(nonce)) = (
        expiry_s.parse::<u64>(),
        epoch_s.parse::<u64>(),
        nonce_s.parse::<u64>(),
    ) else {
        return None;
    };
    if hex::decode(sig_hex).is_err() {
        return None;
    }
    Some(TecdsaCredential {
        who_text: who_text.to_string(),
        expiry_ns,
        epoch,
        nonce,
        sig_hex: sig_hex.to_string(),
    })
}

/// Construye el token `nb2t.*` a partir de sus campos y la firma (r||s).
pub(crate) fn tecdsa_format_credential(
    who_text: &str,
    expiry_ns: u64,
    epoch: u64,
    nonce: u64,
    sig_hex: &str,
) -> String {
    format!("{TECDSA_PREFIX}.{who_text}.{expiry_ns}.{epoch}.{nonce}.{sig_hex}")
}

// ---------------------------------------------------------------------------
// Llamadas al management canister: solo con `--features tecdsa`.
// En réplica local requieren la llave de test (`dfx >= 0.14` la soporta);
// en mainnet, la llave de producción + ciclos (ver ADR-02).
// ---------------------------------------------------------------------------
#[cfg(feature = "tecdsa")]
pub(crate) mod canister_calls {
    use super::{derivation_path, TEST_KEY_NAME};
    use ic_cdk::management_canister::{
        EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs, SignWithEcdsaArgs,
    };

    /// `EcdsaKeyId` para la llave de test local (secp256k1).
    pub fn test_key_id() -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: TEST_KEY_NAME.to_string(),
        }
    }

    /// Firma `message_hash` (32 bytes) con tECDSA. Devuelve la firma
    /// (r||s, 64 bytes). Llamada de espera ilimitada; cuesta ciclos.
    pub async fn tecdsa_sign(
        message_hash: [u8; 32],
        key_name: String,
    ) -> Result<Vec<u8>, String> {
        let arg = SignWithEcdsaArgs {
            message_hash: message_hash.to_vec(),
            derivation_path: derivation_path(),
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: key_name,
            },
        };
        let res = ic_cdk::management_canister::sign_with_ecdsa(&arg)
            .await
            .map_err(|e| format!("sign_with_ecdsa: {e:?}"))?;
        Ok(res.signature)
    }

    /// Clave pública SEC1 comprimida derivada para este canister.
    /// Sirve para verificar firmas fuera o dentro del canister
    /// (dentro: pendiente añadir crate secp256k1 — ver ADR-02).
    pub async fn tecdsa_public_key(key_name: String) -> Result<Vec<u8>, String> {
        let arg = EcdsaPublicKeyArgs {
            canister_id: None,
            derivation_path: derivation_path(),
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: key_name,
            },
        };
        let res = ic_cdk::management_canister::ecdsa_public_key(&arg)
            .await
            .map_err(|e| format!("ecdsa_public_key: {e:?}"))?;
        Ok(res.public_key)
    }
}

#[cfg(test)]
mod tecdsa_tests {
    //! Task 15: tests puros del esqueleto tECDSA (sin réplica).
    use super::{
        tecdsa_format_credential, tecdsa_message_hash, tecdsa_parse_credential,
        tecdsa_sign_message, derivation_path, production_key_name,
        TECDSA_PREFIX, TEST_KEY_NAME,
    };

    #[test]
    fn tecdsa_message_reuses_nb2_format() {
        // El mensaje a firmar es idéntico al formato nb2 HMAC:
        // la migración a tECDSA no cambia el contenido firmado.
        let msg = tecdsa_sign_message("2vxsx-fae", 1700028800000000000, 3, 7);
        assert_eq!(msg, "nb2.2vxsx-fae.1700028800000000000.3.7");
        assert_eq!(crate::nb2_message("2vxsx-fae", 1700028800000000000, 3, 7), msg);
    }

    #[test]
    fn tecdsa_hash_is_sha256_deterministic() {
        let h1 = tecdsa_message_hash("nb2.2vxsx-fae.1.0.1");
        let h2 = tecdsa_message_hash("nb2.2vxsx-fae.1.0.1");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
        let h3 = tecdsa_message_hash("nb2.2vxsx-fae.1.0.2");
        assert_ne!(h1, h3, "el nonce cambia el hash a firmar");
    }

    #[test]
    fn tecdsa_token_roundtrip_parse() {
        let sig_hex = "ab".repeat(64); // 64 bytes ficticios (r||s)
        let cred = tecdsa_format_credential("2vxsx-fae", 1700028800000000000, 3, 7, &sig_hex);
        assert!(cred.starts_with("nb2t."), "prefijo propio: {cred}");
        let p = tecdsa_parse_credential(&cred).expect("parsea");
        assert_eq!(p.who_text, "2vxsx-fae");
        assert_eq!(p.expiry_ns, 1700028800000000000);
        assert_eq!(p.epoch, 3);
        assert_eq!(p.nonce, 7);
        assert_eq!(p.sig_hex, sig_hex);
    }

    #[test]
    fn tecdsa_malformed_rejected() {
        for bad in [
            "",
            "nb2t.",
            // Prefijo HMAC no es token tECDSA.
            "nb2.2vxsx-fae.1.0.1.aa",
            "nb2t.2vxsx-fae.notanumber.0.1.aa",
            "nb2t.2vxsx-fae.1.0.1",
            "nb2t.2vxsx-fae.1.0.1.zzzznotthex",
            "nb2t.not-a-principal.1.0.1.aa",
        ] {
            assert!(
                tecdsa_parse_credential(bad).is_none(),
                "debe rechazar: {bad:?}"
            );
        }
    }

    #[test]
    fn tecdsa_key_and_path_constants() {
        assert_eq!(TECDSA_PREFIX, "nb2t");
        assert_eq!(TEST_KEY_NAME, "test_key_1");
        assert!(!production_key_name().is_empty());
        assert_ne!(production_key_name(), TEST_KEY_NAME);
        assert_eq!(derivation_path(), vec![b"nebulock-nb2".to_vec()]);
    }
}
