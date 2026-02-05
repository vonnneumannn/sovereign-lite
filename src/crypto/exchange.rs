//! X25519 Key Exchange
//!
//! Provides Elliptic Curve Diffie-Hellman (ECDH) key exchange
//! for establishing shared secrets between parties.

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::ZeroizeOnDrop;

use super::error::{CryptoError, CryptoResult};
use super::hash::Hash;

/// Size of a shared secret in bytes
pub const SHARED_SECRET_SIZE: usize = 32;

/// A public key for key exchange (X25519)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExchangePublicKey(pub [u8; 32]);

impl ExchangePublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(ExchangePublicKey(arr))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Create from hex
    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(s).map_err(|_| CryptoError::InvalidPublicKey)?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for ExchangePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ExchangePublicKey({}...)", &self.to_hex()[..16])
    }
}

impl serde::Serialize for ExchangePublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for ExchangePublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Shared secret derived from key exchange
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret {
    secret: [u8; SHARED_SECRET_SIZE],
}

impl SharedSecret {
    /// Get the raw bytes (be careful with this!)
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_SIZE] {
        &self.secret
    }

    /// Derive a key from this shared secret for a specific purpose
    pub fn derive_key(&self, context: &[u8]) -> [u8; 32] {
        Hash::derive_key(&self.secret, context)
    }
}

/// An ephemeral keypair for key exchange
///
/// Used once and then discarded (forward secrecy)
#[derive(ZeroizeOnDrop)]
pub struct EphemeralKeypair {
    #[zeroize(skip)]
    public_key: ExchangePublicKey,
    secret_key: [u8; 32],
}

impl EphemeralKeypair {
    /// Generate a new ephemeral keypair
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519Public::from(&secret);

        EphemeralKeypair {
            public_key: ExchangePublicKey(public.to_bytes()),
            secret_key: secret.to_bytes(),
        }
    }

    /// Get the public key to share with the peer
    pub fn public_key(&self) -> &ExchangePublicKey {
        &self.public_key
    }

    /// Compute shared secret with a peer's public key
    pub fn diffie_hellman(&self, peer_public: &ExchangePublicKey) -> SharedSecret {
        let secret = StaticSecret::from(self.secret_key);
        let peer = X25519Public::from(peer_public.0);
        let shared = secret.diffie_hellman(&peer);

        SharedSecret {
            secret: shared.to_bytes(),
        }
    }
}

/// Key exchange operations
pub struct KeyExchange;

impl KeyExchange {
    /// Generate an ephemeral keypair for one-time use
    pub fn generate_ephemeral() -> EphemeralKeypair {
        EphemeralKeypair::generate()
    }

    /// Perform a complete key exchange between two parties
    ///
    /// This computes a shared secret using X25519 ECDH
    pub fn derive_shared(
        my_keypair: &EphemeralKeypair,
        their_public: &ExchangePublicKey,
    ) -> SharedSecret {
        my_keypair.diffie_hellman(their_public)
    }

    /// Derive exchange public key from Ed25519 identity secret
    ///
    /// This converts an Ed25519 signing key to an X25519 key exchange key.
    /// Used for X3DH-style protocols.
    pub fn identity_to_exchange(identity_secret: &[u8; 32]) -> ExchangePublicKey {
        let secret = StaticSecret::from(*identity_secret);
        let public = X25519Public::from(&secret);
        ExchangePublicKey(public.to_bytes())
    }

    /// Perform X3DH-style key agreement (used in session establishment)
    ///
    /// Combines multiple DH operations for stronger security:
    /// - DH(my_identity, their_ephemeral)
    /// - DH(my_ephemeral, their_identity)
    /// - DH(my_ephemeral, their_ephemeral)
    ///
    /// The `is_initiator` flag determines the role and affects key derivation
    /// to ensure both parties derive the same final secret.
    pub fn x3dh(
        my_identity_secret: &[u8; 32],
        my_ephemeral: &EphemeralKeypair,
        their_identity_public: &ExchangePublicKey,
        their_ephemeral: &ExchangePublicKey,
        is_initiator: bool,
    ) -> SharedSecret {
        // DH1: my_identity <-> their_ephemeral
        let my_id_secret = StaticSecret::from(*my_identity_secret);
        let their_eph = X25519Public::from(their_ephemeral.0);
        let dh1 = my_id_secret.diffie_hellman(&their_eph);

        // DH2: my_ephemeral <-> their_identity
        let my_eph_secret = StaticSecret::from(my_ephemeral.secret_key);
        let their_id = X25519Public::from(their_identity_public.0);
        let dh2 = my_eph_secret.diffie_hellman(&their_id);

        // DH3: my_ephemeral <-> their_ephemeral
        let dh3 = my_ephemeral.diffie_hellman(their_ephemeral);

        // Combine all DH outputs in consistent order
        // Initiator: DH1 || DH2 || DH3
        // Responder: DH2 || DH1 || DH3 (swapped first two to match initiator's view)
        let mut combined = Vec::with_capacity(96);
        if is_initiator {
            combined.extend_from_slice(dh1.as_bytes());
            combined.extend_from_slice(dh2.as_bytes());
        } else {
            combined.extend_from_slice(dh2.as_bytes());
            combined.extend_from_slice(dh1.as_bytes());
        }
        combined.extend_from_slice(dh3.as_bytes());

        // Derive final shared secret
        let final_secret = Hash::derive_key_from_slice(&combined, b"sovereign-x3dh-v1");

        SharedSecret {
            secret: final_secret,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_key_exchange() {
        let alice = KeyExchange::generate_ephemeral();
        let bob = KeyExchange::generate_ephemeral();

        let alice_shared = KeyExchange::derive_shared(&alice, bob.public_key());
        let bob_shared = KeyExchange::derive_shared(&bob, alice.public_key());

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_different_keys_different_secrets() {
        let alice = KeyExchange::generate_ephemeral();
        let bob = KeyExchange::generate_ephemeral();
        let carol = KeyExchange::generate_ephemeral();

        let alice_bob = KeyExchange::derive_shared(&alice, bob.public_key());
        let alice_carol = KeyExchange::derive_shared(&alice, carol.public_key());

        assert_ne!(alice_bob.as_bytes(), alice_carol.as_bytes());
    }

    #[test]
    fn test_key_derivation() {
        let alice = KeyExchange::generate_ephemeral();
        let bob = KeyExchange::generate_ephemeral();

        let shared = KeyExchange::derive_shared(&alice, bob.public_key());

        let key1 = shared.derive_key(b"encryption");
        let key2 = shared.derive_key(b"authentication");

        // Different contexts produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = KeyExchange::generate_ephemeral();
        let hex = keypair.public_key().to_hex();
        let restored = ExchangePublicKey::from_hex(&hex).unwrap();

        assert_eq!(keypair.public_key().0, restored.0);
    }

    #[test]
    fn test_x3dh_agreement() {
        // Alice's keys (initiator)
        let alice_identity = [1u8; 32];
        let alice_ephemeral = KeyExchange::generate_ephemeral();

        // Bob's keys (responder)
        let bob_identity = [2u8; 32];
        let bob_ephemeral = KeyExchange::generate_ephemeral();

        // Convert identity secrets to public keys for exchange
        let alice_id_public = KeyExchange::identity_to_exchange(&alice_identity);
        let bob_id_public = KeyExchange::identity_to_exchange(&bob_identity);

        // Alice computes shared secret (as initiator)
        let alice_shared = KeyExchange::x3dh(
            &alice_identity,
            &alice_ephemeral,
            &bob_id_public,
            bob_ephemeral.public_key(),
            true, // Alice is initiator
        );

        // Bob computes shared secret (as responder)
        let bob_shared = KeyExchange::x3dh(
            &bob_identity,
            &bob_ephemeral,
            &alice_id_public,
            alice_ephemeral.public_key(),
            false, // Bob is responder
        );

        // Both should derive the same secret
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_identity_to_exchange() {
        let identity_secret = [42u8; 32];

        let exchange_public = KeyExchange::identity_to_exchange(&identity_secret);

        // Should produce valid 32-byte public key
        assert_eq!(exchange_public.0.len(), 32);

        // Same secret should produce same public key
        let exchange_public_2 = KeyExchange::identity_to_exchange(&identity_secret);
        assert_eq!(exchange_public.0, exchange_public_2.0);
    }
}
