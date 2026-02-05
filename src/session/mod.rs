//! Session management with forward secrecy
//!
//! This module handles secure session establishment and message encryption
//! using a simplified Double Ratchet algorithm optimized for two-party communication.

mod ratchet;

pub use ratchet::{Ratchet, MessageHeader};

use crate::crypto::{
    CryptoResult, ExchangePublicKey, Identity, KeyExchange, PublicKey,
};

/// Session state between two parties
pub struct Session {
    /// Our identity
    pub local_identity: Identity,
    /// Peer's public key
    pub peer_identity: PublicKey,
    /// Peer's exchange public key
    pub peer_exchange: ExchangePublicKey,
    /// Message ratchet for encryption
    pub ratchet: Ratchet,
    /// Whether we initiated this session
    pub is_initiator: bool,
}

impl Session {
    /// Create a new session as initiator
    pub fn initiate(
        local_identity: Identity,
        peer_identity: PublicKey,
        peer_exchange: ExchangePublicKey,
    ) -> Self {
        let local_ephemeral = KeyExchange::generate_ephemeral();
        let _local_exchange = KeyExchange::identity_to_exchange(local_identity.secret_key_bytes());

        let shared_secret = KeyExchange::x3dh(
            local_identity.secret_key_bytes(),
            &local_ephemeral,
            &peer_exchange,
            &peer_exchange, // Using identity as ephemeral for simplification
            true,
        );

        let ratchet = Ratchet::initialize_sender(shared_secret.as_bytes());

        Session {
            local_identity,
            peer_identity,
            peer_exchange,
            ratchet,
            is_initiator: true,
        }
    }

    /// Accept an incoming session as responder
    pub fn accept(
        local_identity: Identity,
        peer_identity: PublicKey,
        peer_exchange: ExchangePublicKey,
        peer_ephemeral: &ExchangePublicKey,
    ) -> Self {
        let local_ephemeral = KeyExchange::generate_ephemeral();

        let shared_secret = KeyExchange::x3dh(
            local_identity.secret_key_bytes(),
            &local_ephemeral,
            &peer_exchange,
            peer_ephemeral,
            false,
        );

        let ratchet = Ratchet::initialize_receiver(shared_secret.as_bytes(), peer_ephemeral);

        Session {
            local_identity,
            peer_identity,
            peer_exchange,
            ratchet,
            is_initiator: false,
        }
    }

    /// Encrypt a message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.ratchet.encrypt(plaintext)
    }

    /// Decrypt a message
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        self.ratchet.decrypt(ciphertext)
    }
}
