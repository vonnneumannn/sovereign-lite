//! Cryptographic primitives for Sovereign
//!
//! This module provides all the cryptographic building blocks:
//! - `identity`: Ed25519 signatures for identity and contract signing
//! - `exchange`: X25519 ECDH for key exchange
//! - `cipher`: ChaCha20-Poly1305 AEAD encryption
//! - `hash`: BLAKE3 hashing and key derivation

pub mod cipher;
pub mod error;
pub mod exchange;
pub mod hash;
pub mod identity;

// Re-export commonly used types
pub use cipher::Cipher;
pub use error::{CryptoError, CryptoResult};
pub use exchange::{EphemeralKeypair, ExchangePublicKey, KeyExchange, SharedSecret};
pub use hash::Hash;
pub use identity::{Identity, PublicKey, SignatureBytes};

/// Generate cryptographically secure random bytes
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut bytes = [0u8; N];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_full_encryption_flow() {
        // Two parties establish shared secret
        let alice = KeyExchange::generate_ephemeral();
        let bob = KeyExchange::generate_ephemeral();

        let alice_shared = KeyExchange::derive_shared(&alice, bob.public_key());
        let bob_shared = KeyExchange::derive_shared(&bob, alice.public_key());

        // Derive encryption keys
        let alice_key = alice_shared.derive_key(b"encryption");
        let bob_key = bob_shared.derive_key(b"encryption");

        assert_eq!(alice_key, bob_key);

        // Alice encrypts a message
        let message = b"Hello, Bob! This is a secret.";
        let ciphertext = Cipher::encrypt(&alice_key, message);

        // Bob decrypts
        let decrypted = Cipher::decrypt(&bob_key, &ciphertext).unwrap();
        assert_eq!(message, decrypted.as_slice());
    }

    #[test]
    fn test_identity_and_signature_flow() {
        // Alice creates an identity
        let alice = Identity::generate();

        // Alice creates and signs a document
        let document = b"I, Alice, agree to the terms.";
        let signature = alice.sign(document);

        // Anyone can verify with Alice's public key
        let public_key = *alice.public_key();
        assert!(public_key.verify(document, &signature).is_ok());

        // Signature is invalid for different document
        let tampered = b"I, Alice, agree to nothing.";
        assert!(public_key.verify(tampered, &signature).is_err());
    }

    #[test]
    fn test_x3dh_and_encryption() {
        // Alice's long-term identity
        let alice_identity = Identity::generate();
        let alice_ephemeral = KeyExchange::generate_ephemeral();
        let alice_id_exchange =
            KeyExchange::identity_to_exchange(alice_identity.secret_key_bytes());

        // Bob's long-term identity
        let bob_identity = Identity::generate();
        let bob_ephemeral = KeyExchange::generate_ephemeral();
        let bob_id_exchange = KeyExchange::identity_to_exchange(bob_identity.secret_key_bytes());

        // X3DH key agreement
        let alice_shared = KeyExchange::x3dh(
            alice_identity.secret_key_bytes(),
            &alice_ephemeral,
            &bob_id_exchange,
            bob_ephemeral.public_key(),
            true,
        );

        let bob_shared = KeyExchange::x3dh(
            bob_identity.secret_key_bytes(),
            &bob_ephemeral,
            &alice_id_exchange,
            alice_ephemeral.public_key(),
            false,
        );

        // Both derive same encryption key
        let alice_enc_key = alice_shared.derive_key(b"message-encryption");
        let bob_enc_key = bob_shared.derive_key(b"message-encryption");
        assert_eq!(alice_enc_key, bob_enc_key);

        // Alice sends encrypted message to Bob
        let message = b"Hello Bob, this is encrypted!";
        let ciphertext = Cipher::encrypt(&alice_enc_key, message);
        let decrypted = Cipher::decrypt(&bob_enc_key, &ciphertext).unwrap();
        assert_eq!(message, decrypted.as_slice());
    }
}
