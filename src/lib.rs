//! # Sovereign-Lite
//!
//! Two-party secure communication with contract signing.
//!
//! ## Features
//!
//! - **End-to-end encryption** with forward secrecy
//! - **Contract signing** with third-party verifiable non-repudiation
//! - **Pluggable transport** layer (WebSocket, TCP, manual exchange)
//! - **Out-of-band verification** model for initial trust
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use sovereign::{Identity, crypto::KeyExchange};
//!
//! // Generate identity
//! let alice = Identity::generate();
//! println!("My public key: {}", alice.public_key());
//!
//! // Sign a document
//! let document = b"I agree to these terms";
//! let signature = alice.sign(document);
//!
//! // Anyone can verify
//! assert!(alice.public_key().verify(document, &signature).is_ok());
//! ```
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │              APPLICATION LAYER              │
//! │         CLI  |  Web UI  |  Future apps      │
//! └─────────────────────┬───────────────────────┘
//!                       │
//! ┌─────────────────────▼───────────────────────┐
//! │              PROTOCOL LAYER                 │
//! │  Session (KEX) | Messaging | Contracts      │
//! └─────────────────────┬───────────────────────┘
//!                       │
//! ┌─────────────────────▼───────────────────────┐
//! │               CRYPTO LAYER                  │
//! │  Ed25519 | X25519 | ChaCha20-Poly1305 | BLAKE3
//! └─────────────────────┬───────────────────────┘
//!                       │
//! ┌─────────────────────▼───────────────────────┐
//! │             TRANSPORT LAYER                 │
//! │   WebSocket | TCP | Manual | QR | Future    │
//! └─────────────────────────────────────────────┘
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod crypto;
pub mod session;
pub mod contract;
pub mod transport;

// Re-export main types at crate root
pub use crypto::{Identity, PublicKey, SignatureBytes, CryptoError, CryptoResult, random_bytes};
