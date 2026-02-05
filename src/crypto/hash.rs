//! BLAKE3 Hashing and Key Derivation
//!
//! Provides cryptographic hashing and key derivation functions.

/// Size of a hash output in bytes
pub const HASH_SIZE: usize = 32;

/// A hash output
pub type HashOutput = [u8; HASH_SIZE];

/// Hashing and key derivation operations
pub struct Hash;

impl Hash {
    /// Compute hash of data
    pub fn hash(data: &[u8]) -> HashOutput {
        blake3::hash(data).into()
    }

    /// Compute keyed MAC (message authentication code)
    pub fn mac(key: &[u8; 32], data: &[u8]) -> HashOutput {
        blake3::keyed_hash(key, data).into()
    }

    /// Derive a key from a master key and context string
    ///
    /// The context should be a unique string identifying the purpose
    /// of this derived key (e.g., "sovereign-encryption-key")
    pub fn derive_key(master: &[u8; 32], context: &[u8]) -> [u8; 32] {
        // BLAKE3's derive_key takes context as a string
        let context_str = String::from_utf8_lossy(context);
        blake3::derive_key(&context_str, master)
    }

    /// Derive a key from arbitrary-length input
    pub fn derive_key_from_slice(input: &[u8], context: &[u8]) -> [u8; 32] {
        // First hash the input to fixed size
        let hashed: [u8; 32] = blake3::hash(input).into();
        // Then derive
        Self::derive_key(&hashed, context)
    }

    /// Compute hash and return as hex string
    pub fn hash_hex(data: &[u8]) -> String {
        hex::encode(Self::hash(data))
    }

    /// Verify that data matches expected hash
    pub fn verify(data: &[u8], expected: &HashOutput) -> bool {
        let computed = Self::hash(data);
        constant_time_eq(&computed, expected)
    }
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let data = b"Hello, Sovereign!";
        let h1 = Hash::hash(data);
        let h2 = Hash::hash(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_different_inputs() {
        let h1 = Hash::hash(b"input1");
        let h2 = Hash::hash(b"input2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_mac_with_key() {
        let key = [42u8; 32];
        let data = b"Hello";

        let mac1 = Hash::mac(&key, data);
        let mac2 = Hash::mac(&key, data);
        assert_eq!(mac1, mac2);

        // Different key = different MAC
        let other_key = [43u8; 32];
        let mac3 = Hash::mac(&other_key, data);
        assert_ne!(mac1, mac3);
    }

    #[test]
    fn test_key_derivation() {
        let master = [0u8; 32];

        let key1 = Hash::derive_key(&master, b"purpose-1");
        let key2 = Hash::derive_key(&master, b"purpose-2");

        // Different contexts produce different keys
        assert_ne!(key1, key2);

        // Same context produces same key
        let key1_again = Hash::derive_key(&master, b"purpose-1");
        assert_eq!(key1, key1_again);
    }

    #[test]
    fn test_hash_verify() {
        let data = b"test data";
        let hash = Hash::hash(data);

        assert!(Hash::verify(data, &hash));
        assert!(!Hash::verify(b"wrong data", &hash));
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }
}
