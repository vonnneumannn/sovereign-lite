//! Cryptographic error types

use thiserror::Error;

/// Errors that can occur in cryptographic operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// The provided key has an invalid length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length in bytes
        expected: usize,
        /// Actual key length in bytes
        actual: usize,
    },

    /// The provided signature has an invalid length
    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength {
        /// Expected signature length in bytes
        expected: usize,
        /// Actual signature length in bytes
        actual: usize,
    },

    /// Signature verification failed - the signature is invalid
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Encryption operation failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed - authentication tag mismatch (possibly tampered data)
    #[error("Decryption failed: authentication tag mismatch")]
    DecryptionFailed,

    /// The public key format is invalid
    #[error("Invalid public key format")]
    InvalidPublicKey,

    /// The secret key format is invalid
    #[error("Invalid secret key format")]
    InvalidSecretKey,

    /// Random number generation failed
    #[error("Random number generation failed")]
    RngError,
}

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;
