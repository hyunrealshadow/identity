use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, Payload},
};
use rand::rngs::OsRng;

pub const KEY_SIZE: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
}

pub fn encrypt(
    key: &[u8; KEY_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; 24], Vec<u8>), CryptoError> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes.copy_from_slice(&nonce);
    Ok((nonce_bytes, ciphertext))
}

pub fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; 24],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; KEY_SIZE];
        let plaintext = b"hello world";
        let aad = b"some aad";
        let (nonce, ciphertext) = encrypt(&key, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_fails_with_wrong_aad() {
        let key = [0x42u8; KEY_SIZE];
        let plaintext = b"hello world";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad!!";
        let (nonce, ciphertext) = encrypt(&key, plaintext, aad).unwrap();
        let result = decrypt(&key, &nonce, &ciphertext, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_fails_with_tampered_ciphertext() {
        let key = [0x42u8; KEY_SIZE];
        let plaintext = b"hello world";
        let aad = b"some aad";
        let (nonce, mut ciphertext) = encrypt(&key, plaintext, aad).unwrap();
        ciphertext[0] ^= 0xFF;
        let result = decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn different_nonces_produce_different_ciphertext() {
        let key = [0x42u8; KEY_SIZE];
        let plaintext = b"same plaintext";
        let aad = b"aad";
        let (_, ct1) = encrypt(&key, plaintext, aad).unwrap();
        let (_, ct2) = encrypt(&key, plaintext, aad).unwrap();
        assert_ne!(ct1, ct2);
    }
}
