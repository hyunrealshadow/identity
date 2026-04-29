use crate::{
    application::data_protection::{DATA_PROTECTION_KEY_SIZE, DataProtectionCipher},
    domain::data_protection::DataProtectionError,
};

use super::xchacha20;

pub struct XChaCha20DataProtectionCipher;

impl DataProtectionCipher for XChaCha20DataProtectionCipher {
    fn encrypt(
        &self,
        key: &[u8; DATA_PROTECTION_KEY_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<([u8; 24], Vec<u8>), DataProtectionError> {
        xchacha20::encrypt(key, plaintext, aad).map_err(|_| DataProtectionError::EncryptionFailed)
    }

    fn decrypt(
        &self,
        key: &[u8; DATA_PROTECTION_KEY_SIZE],
        nonce: &[u8; 24],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, DataProtectionError> {
        xchacha20::decrypt(key, nonce, ciphertext, aad)
            .map_err(|_| DataProtectionError::InvalidProtectedPayload)
    }
}
