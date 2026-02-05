//! Ed25519 Identity management
//!
//! Provides cryptographic identity through Ed25519 key pairs.
//! Used for long-term identity verification and contract signing.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::error::{CryptoError, CryptoResult};

/// Size of a public key in bytes
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of a secret key in bytes
pub const SECRET_KEY_SIZE: usize = 32;

/// Size of a signature in bytes
pub const SIGNATURE_SIZE: usize = 64;

/// A public key for identity verification
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; PUBLIC_KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(PublicKey(arr))
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Convert to hex string for display
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Create from hex string
    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(s).map_err(|_| CryptoError::InvalidPublicKey)?;
        Self::from_bytes(&bytes)
    }

    /// Verify a signature against this public key
    pub fn verify(&self, message: &[u8], signature: &SignatureBytes) -> CryptoResult<()> {
        let verifying_key =
            VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::InvalidPublicKey)?;

        let sig = Signature::from_bytes(&signature.0);

        verifying_key
            .verify(message, &sig)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({}...)", &self.to_hex()[..16])
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A signature produced by an identity
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignatureBytes(pub [u8; SIGNATURE_SIZE]);

// Custom serde impl because arrays >32 don't auto-derive
impl serde::Serialize for SignatureBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for SignatureBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl SignatureBytes {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignatureLength {
                expected: SIGNATURE_SIZE,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; SIGNATURE_SIZE];
        arr.copy_from_slice(bytes);
        Ok(SignatureBytes(arr))
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Create from hex string
    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(s).map_err(|_| CryptoError::SignatureVerificationFailed)?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({}...)", &self.to_hex()[..16])
    }
}

/// A cryptographic identity consisting of a keypair
///
/// The secret key is automatically zeroized when dropped.
#[derive(ZeroizeOnDrop)]
pub struct Identity {
    #[zeroize(skip)]
    public_key: PublicKey,
    secret_key: [u8; SECRET_KEY_SIZE],
}

impl Identity {
    /// Generate a new random identity
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        Identity {
            public_key: PublicKey(verifying_key.to_bytes()),
            secret_key: signing_key.to_bytes(),
        }
    }

    /// Create from a seed (deterministic generation)
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();

        Identity {
            public_key: PublicKey(verifying_key.to_bytes()),
            secret_key: signing_key.to_bytes(),
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the secret key bytes (for key exchange operations)
    ///
    /// # Security Warning
    /// Handle with extreme care! The secret key should never be logged,
    /// stored unencrypted, or transmitted over a network.
    pub fn secret_key_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.secret_key
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> SignatureBytes {
        let signing_key = SigningKey::from_bytes(&self.secret_key);
        let signature = signing_key.sign(message);
        SignatureBytes(signature.to_bytes())
    }

    /// Verify a signature (convenience method)
    pub fn verify(&self, message: &[u8], signature: &SignatureBytes) -> CryptoResult<()> {
        self.public_key.verify(message, signature)
    }

    /// Export identity to bytes (for secure backup)
    ///
    /// WARNING: This exposes the secret key. Handle with extreme care.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE + PUBLIC_KEY_SIZE] {
        let mut bytes = [0u8; SECRET_KEY_SIZE + PUBLIC_KEY_SIZE];
        bytes[..SECRET_KEY_SIZE].copy_from_slice(&self.secret_key);
        bytes[SECRET_KEY_SIZE..].copy_from_slice(&self.public_key.0);
        bytes
    }

    /// Import identity from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != SECRET_KEY_SIZE + PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength {
                expected: SECRET_KEY_SIZE + PUBLIC_KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut secret_key = [0u8; SECRET_KEY_SIZE];
        secret_key.copy_from_slice(&bytes[..SECRET_KEY_SIZE]);

        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(&bytes[SECRET_KEY_SIZE..]);

        // Verify that the public key matches the secret key
        let signing_key = SigningKey::from_bytes(&secret_key);
        let derived_public = signing_key.verifying_key().to_bytes();

        if derived_public != public_key {
            // Zeroize the secret key before returning error
            let mut sk = secret_key;
            sk.zeroize();
            return Err(CryptoError::InvalidSecretKey);
        }

        Ok(Identity {
            public_key: PublicKey(public_key),
            secret_key,
        })
    }
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Identity {
            public_key: self.public_key,
            secret_key: self.secret_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();

        // Each identity should be unique
        assert_ne!(id1.public_key().0, id2.public_key().0);
    }

    #[test]
    fn test_deterministic_generation() {
        let seed = [42u8; 32];
        let id1 = Identity::from_seed(&seed);
        let id2 = Identity::from_seed(&seed);

        assert_eq!(id1.public_key().0, id2.public_key().0);
    }

    #[test]
    fn test_sign_verify() {
        let id = Identity::generate();
        let message = b"Hello, Sovereign!";

        let signature = id.sign(message);
        assert!(id.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_wrong_message_fails() {
        let id = Identity::generate();
        let message = b"Hello, Sovereign!";
        let wrong_message = b"Wrong message";

        let signature = id.sign(message);
        assert!(id.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let message = b"Hello, Sovereign!";

        let signature = id1.sign(message);
        assert!(id2.verify(message, &signature).is_err());
    }

    #[test]
    fn test_export_import() {
        let id = Identity::generate();
        let message = b"Test message";
        let signature = id.sign(message);

        let bytes = id.to_bytes();
        let restored = Identity::from_bytes(&bytes).unwrap();

        assert_eq!(id.public_key().0, restored.public_key().0);
        assert!(restored.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_public_key_hex() {
        let id = Identity::generate();
        let hex = id.public_key().to_hex();
        let restored = PublicKey::from_hex(&hex).unwrap();

        assert_eq!(id.public_key().0, restored.0);
    }

    #[test]
    fn test_third_party_verification() {
        let signer = Identity::generate();
        let message = b"I agree to these terms";

        let signature = signer.sign(message);

        // Anyone with the public key can verify
        let public_key = *signer.public_key();
        assert!(public_key.verify(message, &signature).is_ok());
    }
}
