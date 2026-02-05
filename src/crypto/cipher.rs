//! ChaCha20-Poly1305 AEAD Encryption
//!
//! Provides authenticated encryption with associated data (AEAD).

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;

use super::error::{CryptoError, CryptoResult};

/// Size of the encryption key in bytes
pub const KEY_SIZE: usize = 32;

/// Size of the nonce in bytes
pub const NONCE_SIZE: usize = 12;

/// Size of the authentication tag in bytes
pub const TAG_SIZE: usize = 16;

/// Symmetric cipher for encryption/decryption
pub struct Cipher;

impl Cipher {
    /// Encrypt data with authentication
    ///
    /// Returns: nonce || ciphertext || tag
    pub fn encrypt(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Vec<u8> {
        Self::encrypt_with_aad(key, plaintext, &[])
    }

    /// Encrypt data with associated data (AAD)
    ///
    /// AAD is authenticated but not encrypted (e.g., headers, metadata)
    /// Returns: nonce || ciphertext || tag
    pub fn encrypt_with_aad(key: &[u8; KEY_SIZE], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(key.into());

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create payload with AAD
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        // Encrypt (this cannot fail with valid inputs)
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .expect("encryption should never fail with valid inputs");

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        result
    }

    /// Decrypt data
    ///
    /// Input: nonce || ciphertext || tag
    pub fn decrypt(key: &[u8; KEY_SIZE], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        Self::decrypt_with_aad(key, ciphertext, &[])
    }

    /// Decrypt data with associated data (AAD)
    ///
    /// The AAD must match what was used during encryption
    pub fn decrypt_with_aad(
        key: &[u8; KEY_SIZE],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        // Minimum size: nonce + tag
        if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
            return Err(CryptoError::DecryptionFailed);
        }

        let cipher = ChaCha20Poly1305::new(key.into());

        // Extract nonce
        let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
        let encrypted = &ciphertext[NONCE_SIZE..];

        // Create payload with AAD
        let payload = Payload {
            msg: encrypted,
            aad,
        };

        // Decrypt and verify
        cipher
            .decrypt(nonce, payload)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    /// Encrypt with a specific nonce (for deterministic encryption)
    ///
    /// WARNING: Using the same nonce twice with the same key is catastrophic!
    /// Only use this if you have a unique nonce derivation scheme.
    pub fn encrypt_with_nonce(
        key: &[u8; KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce_obj = Nonce::from_slice(nonce);

        let ciphertext = cipher
            .encrypt(nonce_obj, plaintext)
            .expect("encryption should never fail");

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(nonce);
        result.extend_from_slice(&ciphertext);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [42u8; KEY_SIZE];
        let plaintext = b"Hello, Sovereign!";

        let ciphertext = Cipher::encrypt(&key, plaintext);
        let decrypted = Cipher::decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_ciphertext_different_each_time() {
        let key = [42u8; KEY_SIZE];
        let plaintext = b"Hello";

        let ct1 = Cipher::encrypt(&key, plaintext);
        let ct2 = Cipher::encrypt(&key, plaintext);

        // Different nonces mean different ciphertexts
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [1u8; KEY_SIZE];
        let key2 = [2u8; KEY_SIZE];
        let plaintext = b"Secret";

        let ciphertext = Cipher::encrypt(&key1, plaintext);
        assert!(Cipher::decrypt(&key2, &ciphertext).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [42u8; KEY_SIZE];
        let plaintext = b"Hello";

        let mut ciphertext = Cipher::encrypt(&key, plaintext);

        // Tamper with the ciphertext
        if let Some(byte) = ciphertext.get_mut(NONCE_SIZE + 1) {
            *byte ^= 0xFF;
        }

        assert!(Cipher::decrypt(&key, &ciphertext).is_err());
    }

    #[test]
    fn test_encrypt_with_aad() {
        let key = [42u8; KEY_SIZE];
        let plaintext = b"Secret data";
        let aad = b"public header";

        let ciphertext = Cipher::encrypt_with_aad(&key, plaintext, aad);

        // Correct AAD works
        let decrypted = Cipher::decrypt_with_aad(&key, &ciphertext, aad).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Wrong AAD fails
        assert!(Cipher::decrypt_with_aad(&key, &ciphertext, b"wrong").is_err());

        // Missing AAD fails
        assert!(Cipher::decrypt(&key, &ciphertext).is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [42u8; KEY_SIZE];
        let plaintext = b"";

        let ciphertext = Cipher::encrypt(&key, plaintext);
        let decrypted = Cipher::decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_large_plaintext() {
        let key = [42u8; KEY_SIZE];
        let plaintext = vec![0u8; 1_000_000]; // 1MB

        let ciphertext = Cipher::encrypt(&key, &plaintext);
        let decrypted = Cipher::decrypt(&key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_deterministic_encryption() {
        let key = [42u8; KEY_SIZE];
        let nonce = [1u8; NONCE_SIZE];
        let plaintext = b"Hello";

        let ct1 = Cipher::encrypt_with_nonce(&key, &nonce, plaintext);
        let ct2 = Cipher::encrypt_with_nonce(&key, &nonce, plaintext);

        // Same nonce = same ciphertext (deterministic)
        assert_eq!(ct1, ct2);
    }
}
