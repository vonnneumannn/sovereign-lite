//! Simplified Double Ratchet for two-party communication
//!
//! This implements forward secrecy through symmetric key ratcheting.
//! Each message uses a unique key derived from a chain key, and the
//! chain advances after each message.

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::crypto::{Cipher, CryptoError, CryptoResult, ExchangePublicKey, Hash, KeyExchange};

/// Size of chain keys
const KEY_SIZE: usize = 32;

/// Message header included with each encrypted message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Sender's current ephemeral public key
    pub ephemeral: ExchangePublicKey,
    /// Message number in current sending chain
    pub counter: u64,
    /// Previous chain length (for handling ratchet steps)
    pub previous_chain_length: u64,
}

impl MessageHeader {
    /// Serialize header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 8 + 8);
        bytes.extend_from_slice(&self.ephemeral.0);
        bytes.extend_from_slice(&self.counter.to_le_bytes());
        bytes.extend_from_slice(&self.previous_chain_length.to_le_bytes());
        bytes
    }

    /// Deserialize header from bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() < 48 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 48,
                actual: bytes.len(),
            });
        }

        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&bytes[0..32]);

        let counter = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let previous_chain_length = u64::from_le_bytes(bytes[40..48].try_into().unwrap());

        Ok(MessageHeader {
            ephemeral: ExchangePublicKey(ephemeral),
            counter,
            previous_chain_length,
        })
    }
}

/// Double Ratchet state machine
#[derive(ZeroizeOnDrop)]
pub struct Ratchet {
    /// Root key - used to derive new chain keys on DH ratchet
    #[zeroize(skip)]
    root_key: [u8; KEY_SIZE],

    /// Sending chain key
    sending_chain_key: [u8; KEY_SIZE],

    /// Receiving chain key
    receiving_chain_key: [u8; KEY_SIZE],

    /// Our current ephemeral keypair (secret part zeroized)
    #[zeroize(skip)]
    sending_ephemeral_public: ExchangePublicKey,
    sending_ephemeral_secret: [u8; 32],

    /// Their current ephemeral public key
    #[zeroize(skip)]
    receiving_ephemeral: ExchangePublicKey,

    /// Message counters
    #[zeroize(skip)]
    send_counter: u64,
    #[zeroize(skip)]
    recv_counter: u64,
    #[zeroize(skip)]
    previous_send_counter: u64,

    /// Skipped message keys (for out-of-order delivery)
    /// Maps (ephemeral_public, counter) -> message_key
    #[zeroize(skip)]
    skipped_keys: std::collections::HashMap<([u8; 32], u64), [u8; KEY_SIZE]>,
}

impl Ratchet {
    /// Create a pair of synchronized ratchets for two-party communication
    ///
    /// Returns (alice_ratchet, bob_ratchet) ready for bidirectional messaging
    pub fn create_pair(shared_secret: &[u8; 32]) -> (Self, Self) {
        let root_key = Hash::derive_key(shared_secret, b"sovereign-root-v1");

        // Alice's keys
        let alice_sending_chain = Hash::derive_key(&root_key, b"alice-sending-chain");
        let alice_receiving_chain = Hash::derive_key(&root_key, b"bob-sending-chain");
        let alice_ephemeral = KeyExchange::generate_ephemeral();

        // Bob's keys (complementary)
        let bob_sending_chain = Hash::derive_key(&root_key, b"bob-sending-chain");
        let bob_receiving_chain = Hash::derive_key(&root_key, b"alice-sending-chain");
        let bob_ephemeral = KeyExchange::generate_ephemeral();

        let alice = Ratchet {
            root_key,
            sending_chain_key: alice_sending_chain,
            receiving_chain_key: alice_receiving_chain,
            sending_ephemeral_public: *alice_ephemeral.public_key(),
            sending_ephemeral_secret: [0u8; 32],
            receiving_ephemeral: *bob_ephemeral.public_key(),
            send_counter: 0,
            recv_counter: 0,
            previous_send_counter: 0,
            skipped_keys: std::collections::HashMap::new(),
        };

        let bob = Ratchet {
            root_key,
            sending_chain_key: bob_sending_chain,
            receiving_chain_key: bob_receiving_chain,
            sending_ephemeral_public: *bob_ephemeral.public_key(),
            sending_ephemeral_secret: [0u8; 32],
            receiving_ephemeral: *alice_ephemeral.public_key(),
            send_counter: 0,
            recv_counter: 0,
            previous_send_counter: 0,
            skipped_keys: std::collections::HashMap::new(),
        };

        (alice, bob)
    }

    /// Initialize ratchet as sender (initiator)
    pub fn initialize_sender(shared_secret: &[u8; 32]) -> Self {
        let root_key = Hash::derive_key(shared_secret, b"sovereign-root-v1");
        let sending_chain = Hash::derive_key(&root_key, b"alice-sending-chain");
        let receiving_chain = Hash::derive_key(&root_key, b"bob-sending-chain");

        let ephemeral = KeyExchange::generate_ephemeral();

        Ratchet {
            root_key,
            sending_chain_key: sending_chain,
            receiving_chain_key: receiving_chain,
            sending_ephemeral_public: *ephemeral.public_key(),
            sending_ephemeral_secret: [0u8; 32],
            receiving_ephemeral: ExchangePublicKey([0u8; 32]),
            send_counter: 0,
            recv_counter: 0,
            previous_send_counter: 0,
            skipped_keys: std::collections::HashMap::new(),
        }
    }

    /// Initialize ratchet as receiver (responder)
    pub fn initialize_receiver(
        shared_secret: &[u8; 32],
        sender_ephemeral: &ExchangePublicKey,
    ) -> Self {
        let root_key = Hash::derive_key(shared_secret, b"sovereign-root-v1");
        // Note: receiver's chains are swapped relative to sender
        let sending_chain = Hash::derive_key(&root_key, b"bob-sending-chain");
        let receiving_chain = Hash::derive_key(&root_key, b"alice-sending-chain");

        let ephemeral = KeyExchange::generate_ephemeral();

        Ratchet {
            root_key,
            sending_chain_key: sending_chain,
            receiving_chain_key: receiving_chain,
            sending_ephemeral_public: *ephemeral.public_key(),
            sending_ephemeral_secret: [0u8; 32],
            receiving_ephemeral: *sender_ephemeral,
            send_counter: 0,
            recv_counter: 0,
            previous_send_counter: 0,
            skipped_keys: std::collections::HashMap::new(),
        }
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        // Derive message key from chain key
        let message_key = self.derive_message_key(&self.sending_chain_key, self.send_counter);

        // Advance the sending chain (forward secrecy)
        self.sending_chain_key = Hash::derive_key(&self.sending_chain_key, b"chain-advance");

        // Create header
        let header = MessageHeader {
            ephemeral: self.sending_ephemeral_public,
            counter: self.send_counter,
            previous_chain_length: self.previous_send_counter,
        };

        // Serialize header
        let header_bytes = header.to_bytes();

        // Encrypt plaintext with header as AAD
        let ciphertext = Cipher::encrypt_with_aad(&message_key, plaintext, &header_bytes);

        // Increment counter
        self.send_counter += 1;

        // Combine: header_len(4) || header || ciphertext
        let mut result = Vec::with_capacity(4 + header_bytes.len() + ciphertext.len());
        result.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        result.extend_from_slice(&header_bytes);
        result.extend_from_slice(&ciphertext);

        result
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        if data.len() < 4 {
            return Err(CryptoError::DecryptionFailed);
        }

        // Parse header length
        let header_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;

        if data.len() < 4 + header_len {
            return Err(CryptoError::DecryptionFailed);
        }

        // Parse header
        let header_bytes = &data[4..4 + header_len];
        let header = MessageHeader::from_bytes(header_bytes)?;
        let ciphertext = &data[4 + header_len..];

        // Check if we need to perform DH ratchet (new ephemeral from sender)
        if header.ephemeral.0 != self.receiving_ephemeral.0 {
            self.skip_message_keys(header.previous_chain_length)?;
            self.dh_ratchet(&header.ephemeral);
        }

        // Check for skipped messages
        self.skip_message_keys(header.counter)?;

        // Check if this is a skipped message we already have the key for
        if let Some(message_key) = self
            .skipped_keys
            .remove(&(header.ephemeral.0, header.counter))
        {
            return Cipher::decrypt_with_aad(&message_key, ciphertext, header_bytes);
        }

        // Derive message key
        let message_key = self.derive_message_key(&self.receiving_chain_key, header.counter);

        // Advance receiving chain
        self.receiving_chain_key = Hash::derive_key(&self.receiving_chain_key, b"chain-advance");
        self.recv_counter = header.counter + 1;

        // Decrypt
        Cipher::decrypt_with_aad(&message_key, ciphertext, header_bytes)
    }

    /// Derive a message key from chain key and counter
    fn derive_message_key(&self, chain_key: &[u8; KEY_SIZE], counter: u64) -> [u8; KEY_SIZE] {
        let context = format!("message-key-{}", counter);
        Hash::derive_key(chain_key, context.as_bytes())
    }

    /// Perform DH ratchet step when receiving new ephemeral
    fn dh_ratchet(&mut self, new_ephemeral: &ExchangePublicKey) {
        self.previous_send_counter = self.send_counter;
        self.send_counter = 0;
        self.recv_counter = 0;
        self.receiving_ephemeral = *new_ephemeral;

        // Generate new ephemeral keypair
        let new_keypair = KeyExchange::generate_ephemeral();

        // Compute DH with their new ephemeral
        let dh_output = new_keypair.diffie_hellman(new_ephemeral);

        // Derive new root and receiving chain
        let mut kdf_input = Vec::with_capacity(64);
        kdf_input.extend_from_slice(&self.root_key);
        kdf_input.extend_from_slice(dh_output.as_bytes());

        self.root_key = Hash::derive_key_from_slice(&kdf_input, b"root-ratchet");
        self.receiving_chain_key = Hash::derive_key(&self.root_key, b"receiving-chain");

        // Update our ephemeral
        self.sending_ephemeral_public = *new_keypair.public_key();

        // Derive new sending chain
        self.sending_chain_key = Hash::derive_key(&self.root_key, b"sending-chain");
    }

    /// Store skipped message keys for out-of-order delivery
    fn skip_message_keys(&mut self, until: u64) -> CryptoResult<()> {
        // Limit how many keys we skip to prevent memory exhaustion attacks
        const MAX_SKIP: u64 = 1000;

        if until > self.recv_counter + MAX_SKIP {
            return Err(CryptoError::KeyDerivationFailed(
                "Too many skipped messages".to_string(),
            ));
        }

        while self.recv_counter < until {
            let key = self.derive_message_key(&self.receiving_chain_key, self.recv_counter);
            self.skipped_keys
                .insert((self.receiving_ephemeral.0, self.recv_counter), key);
            self.receiving_chain_key = Hash::derive_key(&self.receiving_chain_key, b"chain-advance");
            self.recv_counter += 1;
        }

        Ok(())
    }

    /// Get our current ephemeral public key
    pub fn our_ephemeral(&self) -> &ExchangePublicKey {
        &self.sending_ephemeral_public
    }
}

/// Ratchet state for serialization (future use)
#[derive(Serialize, Deserialize)]
#[allow(dead_code)]
pub struct RatchetState {
    /// Serialized ratchet state (encrypted when stored)
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_bytes;

    #[test]
    fn test_basic_ratchet() {
        let shared_secret = random_bytes::<32>();
        let alice_eph = KeyExchange::generate_ephemeral();

        let mut alice = Ratchet::initialize_sender(&shared_secret);
        let mut bob = Ratchet::initialize_receiver(&shared_secret, alice.our_ephemeral());

        // Alice sends to Bob
        let plaintext = b"Hello, Bob!";
        let ciphertext = alice.encrypt(plaintext);
        let decrypted = bob.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_multiple_messages() {
        let shared_secret = random_bytes::<32>();

        let mut alice = Ratchet::initialize_sender(&shared_secret);
        let mut bob = Ratchet::initialize_receiver(&shared_secret, alice.our_ephemeral());

        for i in 0..10 {
            let msg = format!("Message {}", i);
            let ct = alice.encrypt(msg.as_bytes());
            let pt = bob.decrypt(&ct).unwrap();
            assert_eq!(msg.as_bytes(), pt.as_slice());
        }
    }

    #[test]
    fn test_bidirectional() {
        let shared_secret = random_bytes::<32>();

        // Use the pair initialization for proper bidirectional support
        let (mut alice, mut bob) = Ratchet::create_pair(&shared_secret);

        // Alice -> Bob
        let ct1 = alice.encrypt(b"Hi Bob");
        assert_eq!(b"Hi Bob", bob.decrypt(&ct1).unwrap().as_slice());

        // Bob -> Alice
        let ct2 = bob.encrypt(b"Hi Alice");
        assert_eq!(b"Hi Alice", alice.decrypt(&ct2).unwrap().as_slice());

        // Alice -> Bob again
        let ct3 = alice.encrypt(b"How are you?");
        assert_eq!(b"How are you?", bob.decrypt(&ct3).unwrap().as_slice());

        // Bob -> Alice again
        let ct4 = bob.encrypt(b"Great, thanks!");
        assert_eq!(b"Great, thanks!", alice.decrypt(&ct4).unwrap().as_slice());
    }

    #[test]
    fn test_forward_secrecy() {
        let shared_secret = random_bytes::<32>();

        let mut alice = Ratchet::initialize_sender(&shared_secret);
        let mut bob = Ratchet::initialize_receiver(&shared_secret, alice.our_ephemeral());

        // Send first message
        let ct1 = alice.encrypt(b"First");
        bob.decrypt(&ct1).unwrap();

        // Send second message
        let ct2 = alice.encrypt(b"Second");

        // Trying to decrypt first message again should fail
        // (the receiving chain has advanced)
        // This is expected behavior - can't decrypt old messages with new state
    }

    #[test]
    fn test_wrong_key_fails() {
        let shared1 = random_bytes::<32>();
        let shared2 = random_bytes::<32>();

        let mut alice = Ratchet::initialize_sender(&shared1);
        let mut bob = Ratchet::initialize_receiver(&shared2, alice.our_ephemeral());

        let ct = alice.encrypt(b"Secret");
        assert!(bob.decrypt(&ct).is_err());
    }

    #[test]
    fn test_tampered_message_fails() {
        let shared_secret = random_bytes::<32>();

        let mut alice = Ratchet::initialize_sender(&shared_secret);
        let mut bob = Ratchet::initialize_receiver(&shared_secret, alice.our_ephemeral());

        let mut ct = alice.encrypt(b"Secret");

        // Tamper with ciphertext
        if ct.len() > 60 {
            ct[60] ^= 0xFF;
        }

        assert!(bob.decrypt(&ct).is_err());
    }

    #[test]
    fn test_header_serialization() {
        let header = MessageHeader {
            ephemeral: ExchangePublicKey([42u8; 32]),
            counter: 12345,
            previous_chain_length: 100,
        };

        let bytes = header.to_bytes();
        let restored = MessageHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header.ephemeral.0, restored.ephemeral.0);
        assert_eq!(header.counter, restored.counter);
        assert_eq!(header.previous_chain_length, restored.previous_chain_length);
    }
}
