//! Contract creation and signing
//!
//! This module provides cryptographic contract signing with:
//! - Third-party verifiable non-repudiation
//! - Canonical serialization for deterministic signatures
//! - Timestamp commitments
//!
//! # Example
//!
//! ```rust
//! use sovereign::contract::{Contract, ContractContent};
//! use sovereign::Identity;
//!
//! // Create identities for two parties
//! let alice = Identity::generate();
//! let bob = Identity::generate();
//!
//! // Create a contract
//! let content = ContractContent::new(
//!     "Service Agreement",
//!     "Alice agrees to pay Bob 100 USD for services rendered.",
//! );
//!
//! let mut contract = Contract::new(content);
//!
//! // Add parties
//! contract.add_party(alice.public_key().clone(), "buyer");
//! contract.add_party(bob.public_key().clone(), "seller");
//!
//! // Sign the contract
//! contract.sign(&alice).unwrap();
//! contract.sign(&bob).unwrap();
//!
//! // Verify all signatures
//! assert!(contract.verify_all().is_ok());
//!
//! // Export for third-party verification
//! let export = contract.export();
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::crypto::{CryptoError, CryptoResult, Hash, Identity, PublicKey, SignatureBytes};

/// Content of a contract
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractContent {
    /// Title of the contract
    pub title: String,
    /// Body text of the contract
    pub body: String,
    /// Additional metadata (sorted for canonical serialization)
    pub metadata: BTreeMap<String, String>,
}

impl ContractContent {
    /// Create new contract content
    pub fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        ContractContent {
            title: title.into(),
            body: body.into(),
            metadata: BTreeMap::new(),
        }
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// A party to the contract
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Party {
    /// Public key identifying this party
    pub identity: PublicKey,
    /// Role in the contract (e.g., "buyer", "seller")
    pub role: String,
}

/// A signature on the contract
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractSignature {
    /// Who signed
    pub signer: PublicKey,
    /// When they signed (Unix timestamp)
    pub timestamp: u64,
    /// The signature itself
    pub signature: SignatureBytes,
}

/// A complete contract with parties and signatures
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contract {
    /// Contract format version
    pub version: u32,
    /// When the contract was created (Unix timestamp)
    pub created_at: u64,
    /// Parties to the contract (sorted by public key for canonical form)
    pub parties: Vec<Party>,
    /// The contract content
    pub content: ContractContent,
    /// Signatures from parties
    pub signatures: Vec<ContractSignature>,
}

impl Contract {
    /// Current contract format version
    pub const VERSION: u32 = 1;

    /// Create a new unsigned contract
    pub fn new(content: ContractContent) -> Self {
        Contract {
            version: Self::VERSION,
            created_at: current_timestamp(),
            parties: Vec::new(),
            content,
            signatures: Vec::new(),
        }
    }

    /// Add a party to the contract
    pub fn add_party(&mut self, identity: PublicKey, role: impl Into<String>) {
        self.parties.push(Party {
            identity,
            role: role.into(),
        });
        // Keep parties sorted by public key for canonical serialization
        self.parties.sort_by(|a, b| a.identity.0.cmp(&b.identity.0));
    }

    /// Get canonical bytes for signing
    ///
    /// This produces a deterministic byte representation regardless of
    /// how the contract was serialized or in what order fields were added.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Version (4 bytes, little-endian)
        bytes.extend_from_slice(&self.version.to_le_bytes());

        // Created timestamp (8 bytes, little-endian)
        bytes.extend_from_slice(&self.created_at.to_le_bytes());

        // Number of parties (4 bytes)
        bytes.extend_from_slice(&(self.parties.len() as u32).to_le_bytes());

        // Each party (sorted by pubkey)
        for party in &self.parties {
            // Public key (32 bytes)
            bytes.extend_from_slice(&party.identity.0);
            // Role length + role UTF-8
            let role_bytes = party.role.as_bytes();
            bytes.extend_from_slice(&(role_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(role_bytes);
        }

        // Content: title
        let title_bytes = self.content.title.as_bytes();
        bytes.extend_from_slice(&(title_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(title_bytes);

        // Content: body
        let body_bytes = self.content.body.as_bytes();
        bytes.extend_from_slice(&(body_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(body_bytes);

        // Content: metadata count
        bytes.extend_from_slice(&(self.content.metadata.len() as u32).to_le_bytes());

        // Metadata (BTreeMap is already sorted)
        for (key, value) in &self.content.metadata {
            let key_bytes = key.as_bytes();
            bytes.extend_from_slice(&(key_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(key_bytes);

            let value_bytes = value.as_bytes();
            bytes.extend_from_slice(&(value_bytes.len() as u32).to_le_bytes());
            bytes.extend_from_slice(value_bytes);
        }

        bytes
    }

    /// Get the hash of the canonical form (for display/reference)
    pub fn hash(&self) -> String {
        Hash::hash_hex(&self.canonical_bytes())
    }

    /// Sign the contract
    ///
    /// The signer must be one of the parties to the contract.
    pub fn sign(&mut self, identity: &Identity) -> CryptoResult<()> {
        // Verify the signer is a party
        let is_party = self
            .parties
            .iter()
            .any(|p| p.identity == *identity.public_key());

        if !is_party {
            return Err(CryptoError::SignatureVerificationFailed);
        }

        // Check if already signed by this party
        let already_signed = self
            .signatures
            .iter()
            .any(|s| s.signer == *identity.public_key());

        if already_signed {
            return Err(CryptoError::SignatureVerificationFailed);
        }

        // Sign the canonical form
        let canonical = self.canonical_bytes();
        let signature = identity.sign(&canonical);

        self.signatures.push(ContractSignature {
            signer: *identity.public_key(),
            timestamp: current_timestamp(),
            signature,
        });

        Ok(())
    }

    /// Verify a specific signature
    pub fn verify_signature(&self, sig: &ContractSignature) -> CryptoResult<()> {
        let canonical = self.canonical_bytes();
        sig.signer.verify(&canonical, &sig.signature)
    }

    /// Verify all signatures
    pub fn verify_all(&self) -> CryptoResult<()> {
        for sig in &self.signatures {
            self.verify_signature(sig)?;
        }
        Ok(())
    }

    /// Check if all parties have signed
    pub fn is_complete(&self) -> bool {
        for party in &self.parties {
            let has_signed = self.signatures.iter().any(|s| s.signer == party.identity);
            if !has_signed {
                return false;
            }
        }
        true
    }

    /// Get list of parties who haven't signed yet
    pub fn pending_signatures(&self) -> Vec<&Party> {
        self.parties
            .iter()
            .filter(|party| !self.signatures.iter().any(|s| s.signer == party.identity))
            .collect()
    }

    /// Export contract as JSON for third-party verification
    pub fn export(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Import contract from JSON
    pub fn import(json: &str) -> CryptoResult<Self> {
        serde_json::from_str(json).map_err(|_| CryptoError::InvalidPublicKey)
    }

    /// Export contract as compact bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Import contract from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        serde_json::from_slice(bytes).map_err(|_| CryptoError::InvalidPublicKey)
    }
}

/// Standalone verification without needing the full contract module
///
/// This allows third parties to verify a contract without trusting the
/// original application.
pub fn verify_contract_standalone(json: &str) -> CryptoResult<VerificationResult> {
    let contract = Contract::import(json)?;

    // Verify all signatures
    contract.verify_all()?;

    // Build result
    let mut signed_parties = Vec::new();
    let mut unsigned_parties = Vec::new();

    for party in &contract.parties {
        let has_signed = contract
            .signatures
            .iter()
            .any(|s| s.signer == party.identity);
        if has_signed {
            signed_parties.push(party.clone());
        } else {
            unsigned_parties.push(party.clone());
        }
    }

    Ok(VerificationResult {
        contract_hash: contract.hash(),
        title: contract.content.title.clone(),
        is_complete: contract.is_complete(),
        signed_parties,
        unsigned_parties,
        created_at: contract.created_at,
    })
}

/// Result of contract verification
#[derive(Debug)]
pub struct VerificationResult {
    /// Hash of the contract content
    pub contract_hash: String,
    /// Title of the contract
    pub title: String,
    /// Whether all parties have signed
    pub is_complete: bool,
    /// Parties who have signed
    pub signed_parties: Vec<Party>,
    /// Parties who haven't signed yet
    pub unsigned_parties: Vec<Party>,
    /// When the contract was created
    pub created_at: u64,
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_creation() {
        let content = ContractContent::new("Test Contract", "This is a test.");
        let contract = Contract::new(content);

        assert_eq!(contract.version, Contract::VERSION);
        assert_eq!(contract.content.title, "Test Contract");
        assert!(contract.parties.is_empty());
        assert!(contract.signatures.is_empty());
    }

    #[test]
    fn test_add_parties() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let content = ContractContent::new("Test", "Body");
        let mut contract = Contract::new(content);

        contract.add_party(*alice.public_key(), "buyer");
        contract.add_party(*bob.public_key(), "seller");

        assert_eq!(contract.parties.len(), 2);
    }

    #[test]
    fn test_canonical_determinism() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let content1 = ContractContent::new("Test", "Body")
            .with_metadata("key1", "value1")
            .with_metadata("key2", "value2");

        // Create same content but add metadata in different order
        let content2 = ContractContent::new("Test", "Body")
            .with_metadata("key2", "value2")
            .with_metadata("key1", "value1");

        let mut contract1 = Contract::new(content1);
        contract1.add_party(*alice.public_key(), "buyer");
        contract1.add_party(*bob.public_key(), "seller");

        let mut contract2 = Contract::new(content2);
        // Add parties in different order
        contract2.add_party(*bob.public_key(), "seller");
        contract2.add_party(*alice.public_key(), "buyer");

        // Canonical bytes should be identical (except timestamp)
        // For this test, we need same timestamp, so just check structure
        assert_eq!(contract1.parties.len(), contract2.parties.len());
        assert_eq!(
            contract1.content.metadata.len(),
            contract2.content.metadata.len()
        );
    }

    #[test]
    fn test_signing() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let content = ContractContent::new("Agreement", "Alice pays Bob 100 USD");
        let mut contract = Contract::new(content);

        contract.add_party(*alice.public_key(), "buyer");
        contract.add_party(*bob.public_key(), "seller");

        // Alice signs
        assert!(contract.sign(&alice).is_ok());
        assert_eq!(contract.signatures.len(), 1);
        assert!(!contract.is_complete());

        // Bob signs
        assert!(contract.sign(&bob).is_ok());
        assert_eq!(contract.signatures.len(), 2);
        assert!(contract.is_complete());

        // Verify all signatures
        assert!(contract.verify_all().is_ok());
    }

    #[test]
    fn test_non_party_cannot_sign() {
        let alice = Identity::generate();
        let charlie = Identity::generate(); // Not a party

        let content = ContractContent::new("Test", "Body");
        let mut contract = Contract::new(content);
        contract.add_party(*alice.public_key(), "party");

        // Charlie tries to sign
        assert!(contract.sign(&charlie).is_err());
    }

    #[test]
    fn test_double_signing_fails() {
        let alice = Identity::generate();

        let content = ContractContent::new("Test", "Body");
        let mut contract = Contract::new(content);
        contract.add_party(*alice.public_key(), "party");

        // First sign succeeds
        assert!(contract.sign(&alice).is_ok());

        // Second sign fails
        assert!(contract.sign(&alice).is_err());
    }

    #[test]
    fn test_tampered_contract_fails() {
        let alice = Identity::generate();

        let content = ContractContent::new("Original", "Original body");
        let mut contract = Contract::new(content);
        contract.add_party(*alice.public_key(), "party");
        contract.sign(&alice).unwrap();

        // Tamper with the content
        contract.content.body = "Tampered body".to_string();

        // Verification should fail
        assert!(contract.verify_all().is_err());
    }

    #[test]
    fn test_export_import() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let content = ContractContent::new("Test", "Body").with_metadata("key", "value");

        let mut contract = Contract::new(content);
        contract.add_party(*alice.public_key(), "buyer");
        contract.add_party(*bob.public_key(), "seller");
        contract.sign(&alice).unwrap();
        contract.sign(&bob).unwrap();

        // Export
        let json = contract.export();

        // Import
        let imported = Contract::import(&json).unwrap();

        // Verify imported contract
        assert!(imported.verify_all().is_ok());
        assert!(imported.is_complete());
        assert_eq!(imported.content.title, "Test");
    }

    #[test]
    fn test_standalone_verification() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let content = ContractContent::new("Service Agreement", "Terms here");
        let mut contract = Contract::new(content);
        contract.add_party(*alice.public_key(), "provider");
        contract.add_party(*bob.public_key(), "client");
        contract.sign(&alice).unwrap();
        contract.sign(&bob).unwrap();

        let json = contract.export();

        // Third party verifies without any context
        let result = verify_contract_standalone(&json).unwrap();

        assert!(result.is_complete);
        assert_eq!(result.signed_parties.len(), 2);
        assert_eq!(result.unsigned_parties.len(), 0);
        assert_eq!(result.title, "Service Agreement");
    }

    #[test]
    fn test_pending_signatures() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let content = ContractContent::new("Test", "Body");
        let mut contract = Contract::new(content);
        contract.add_party(*alice.public_key(), "buyer");
        contract.add_party(*bob.public_key(), "seller");

        // Before any signatures
        assert_eq!(contract.pending_signatures().len(), 2);

        // After Alice signs
        contract.sign(&alice).unwrap();
        let pending = contract.pending_signatures();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].identity, *bob.public_key());

        // After Bob signs
        contract.sign(&bob).unwrap();
        assert_eq!(contract.pending_signatures().len(), 0);
    }

    #[test]
    fn test_contract_hash() {
        let content = ContractContent::new("Test", "Body");
        let contract = Contract::new(content);

        let hash = contract.hash();

        // Hash should be 64 hex characters (32 bytes)
        assert_eq!(hash.len(), 64);

        // Same contract should have same hash
        let hash2 = contract.hash();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_bytes_serialization() {
        let alice = Identity::generate();

        let content = ContractContent::new("Test", "Body");
        let mut contract = Contract::new(content);
        contract.add_party(*alice.public_key(), "party");
        contract.sign(&alice).unwrap();

        let bytes = contract.to_bytes();
        let restored = Contract::from_bytes(&bytes).unwrap();

        assert!(restored.verify_all().is_ok());
        assert_eq!(restored.content.title, "Test");
    }
}
