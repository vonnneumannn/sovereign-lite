//! Transport layer abstraction
//!
//! This module provides a pluggable transport layer supporting:
//! - In-memory channels (for testing)
//! - Manual copy-paste exchange (maximum security)
//! - WebSocket connections (for real-time communication via relay)
//!
//! # Design
//!
//! The transport layer is intentionally simple - it just moves bytes
//! between two endpoints. Encryption is handled by the session layer.

use async_trait::async_trait;
use thiserror::Error;

pub mod websocket;
pub use websocket::WebSocketTransport;

/// Transport errors
#[derive(Error, Debug)]
pub enum TransportError {
    /// Connection failed
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Connection closed
    #[error("Connection closed")]
    Disconnected,

    /// Send failed
    #[error("Failed to send: {0}")]
    SendFailed(String),

    /// Receive failed
    #[error("Failed to receive: {0}")]
    ReceiveFailed(String),

    /// Timeout
    #[error("Operation timed out")]
    Timeout,

    /// Invalid data
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

/// Result type for transport operations
pub type TransportResult<T> = Result<T, TransportError>;

/// Abstract transport trait
///
/// All transports must implement this trait. The transport is responsible
/// only for moving bytes - encryption is handled at a higher layer.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send data to the peer
    async fn send(&mut self, data: &[u8]) -> TransportResult<()>;

    /// Receive data from the peer
    ///
    /// Blocks until data is available or the connection is closed.
    async fn receive(&mut self) -> TransportResult<Vec<u8>>;

    /// Check if the transport is connected
    fn is_connected(&self) -> bool;

    /// Close the transport
    async fn close(&mut self) -> TransportResult<()>;
}

/// In-memory transport for testing
///
/// Uses channels to simulate a connection between two endpoints.
pub mod memory {
    use super::*;
    use tokio::sync::mpsc;

    /// Create a pair of connected in-memory transports
    pub fn create_pair() -> (MemoryTransport, MemoryTransport) {
        let (tx1, rx1) = mpsc::channel(100);
        let (tx2, rx2) = mpsc::channel(100);

        let transport1 = MemoryTransport {
            tx: tx1,
            rx: rx2,
            connected: true,
        };

        let transport2 = MemoryTransport {
            tx: tx2,
            rx: rx1,
            connected: true,
        };

        (transport1, transport2)
    }

    /// In-memory transport endpoint
    pub struct MemoryTransport {
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
        connected: bool,
    }

    #[async_trait]
    impl Transport for MemoryTransport {
        async fn send(&mut self, data: &[u8]) -> TransportResult<()> {
            if !self.connected {
                return Err(TransportError::Disconnected);
            }

            self.tx
                .send(data.to_vec())
                .await
                .map_err(|_| TransportError::SendFailed("Channel closed".to_string()))
        }

        async fn receive(&mut self) -> TransportResult<Vec<u8>> {
            if !self.connected {
                return Err(TransportError::Disconnected);
            }

            self.rx.recv().await.ok_or(TransportError::Disconnected)
        }

        fn is_connected(&self) -> bool {
            self.connected
        }

        async fn close(&mut self) -> TransportResult<()> {
            self.connected = false;
            Ok(())
        }
    }
}

/// Manual transport for copy-paste exchange
///
/// Messages are base64 encoded for easy copying. This is the most secure
/// transport as it doesn't require any network connection.
pub mod manual {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc;

    /// Manual transport that queues messages for retrieval
    pub struct ManualTransport {
        /// Outbound messages (base64 encoded)
        outbound: Arc<Mutex<Vec<String>>>,
        /// Inbound message receiver
        inbound_rx: mpsc::Receiver<Vec<u8>>,
        /// Inbound message sender (for feeding data)
        inbound_tx: mpsc::Sender<Vec<u8>>,
        connected: bool,
    }

    impl ManualTransport {
        /// Create a new manual transport
        pub fn new() -> Self {
            let (tx, rx) = mpsc::channel(100);
            ManualTransport {
                outbound: Arc::new(Mutex::new(Vec::new())),
                inbound_rx: rx,
                inbound_tx: tx,
                connected: true,
            }
        }

        /// Get the next outbound message (base64 encoded)
        ///
        /// Returns None if there are no pending messages.
        pub fn get_outbound(&self) -> Option<String> {
            let mut outbound = self.outbound.lock().unwrap();
            if outbound.is_empty() {
                None
            } else {
                Some(outbound.remove(0))
            }
        }

        /// Get all pending outbound messages
        pub fn get_all_outbound(&self) -> Vec<String> {
            let mut outbound = self.outbound.lock().unwrap();
            std::mem::take(&mut *outbound)
        }

        /// Feed an inbound message (base64 encoded)
        pub async fn feed_inbound(&self, base64_data: &str) -> TransportResult<()> {
            let data = BASE64
                .decode(base64_data.trim())
                .map_err(|e| TransportError::InvalidData(e.to_string()))?;

            self.inbound_tx
                .send(data)
                .await
                .map_err(|_| TransportError::SendFailed("Channel closed".to_string()))
        }

        /// Get a handle for feeding inbound data from another context
        pub fn inbound_handle(&self) -> mpsc::Sender<Vec<u8>> {
            self.inbound_tx.clone()
        }
    }

    impl Default for ManualTransport {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl Transport for ManualTransport {
        async fn send(&mut self, data: &[u8]) -> TransportResult<()> {
            if !self.connected {
                return Err(TransportError::Disconnected);
            }

            let encoded = BASE64.encode(data);
            self.outbound.lock().unwrap().push(encoded);
            Ok(())
        }

        async fn receive(&mut self) -> TransportResult<Vec<u8>> {
            if !self.connected {
                return Err(TransportError::Disconnected);
            }

            self.inbound_rx.recv().await.ok_or(TransportError::Disconnected)
        }

        fn is_connected(&self) -> bool {
            self.connected
        }

        async fn close(&mut self) -> TransportResult<()> {
            self.connected = false;
            Ok(())
        }
    }

    /// Encode bytes to base64 for display
    pub fn encode(data: &[u8]) -> String {
        BASE64.encode(data)
    }

    /// Decode base64 to bytes
    pub fn decode(encoded: &str) -> TransportResult<Vec<u8>> {
        BASE64
            .decode(encoded.trim())
            .map_err(|e| TransportError::InvalidData(e.to_string()))
    }
}

/// Protocol message types for transport
#[derive(Clone, Debug)]
pub enum ProtocolMessage {
    /// Handshake initiation
    HandshakeInit {
        /// Sender's identity public key
        identity: Vec<u8>,
        /// Sender's ephemeral public key
        ephemeral: Vec<u8>,
    },

    /// Handshake response
    HandshakeResponse {
        /// Responder's identity public key
        identity: Vec<u8>,
        /// Responder's ephemeral public key
        ephemeral: Vec<u8>,
    },

    /// Encrypted message
    EncryptedMessage {
        /// The encrypted payload
        ciphertext: Vec<u8>,
    },

    /// Contract proposal
    ContractProposal {
        /// Serialized contract
        contract: Vec<u8>,
    },

    /// Contract signature
    ContractSigned {
        /// Contract hash
        contract_hash: Vec<u8>,
        /// The signature
        signature: Vec<u8>,
    },

    /// Ping (keepalive)
    Ping,

    /// Pong (keepalive response)
    Pong,

    /// Close connection
    Close {
        /// Reason for closing
        reason: String,
    },
}

impl ProtocolMessage {
    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        match self {
            ProtocolMessage::HandshakeInit { identity, ephemeral } => {
                bytes.push(0x01); // Type tag
                bytes.extend_from_slice(&(identity.len() as u16).to_le_bytes());
                bytes.extend_from_slice(identity);
                bytes.extend_from_slice(&(ephemeral.len() as u16).to_le_bytes());
                bytes.extend_from_slice(ephemeral);
            }
            ProtocolMessage::HandshakeResponse { identity, ephemeral } => {
                bytes.push(0x02);
                bytes.extend_from_slice(&(identity.len() as u16).to_le_bytes());
                bytes.extend_from_slice(identity);
                bytes.extend_from_slice(&(ephemeral.len() as u16).to_le_bytes());
                bytes.extend_from_slice(ephemeral);
            }
            ProtocolMessage::EncryptedMessage { ciphertext } => {
                bytes.push(0x10);
                bytes.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
                bytes.extend_from_slice(ciphertext);
            }
            ProtocolMessage::ContractProposal { contract } => {
                bytes.push(0x20);
                bytes.extend_from_slice(&(contract.len() as u32).to_le_bytes());
                bytes.extend_from_slice(contract);
            }
            ProtocolMessage::ContractSigned {
                contract_hash,
                signature,
            } => {
                bytes.push(0x21);
                bytes.extend_from_slice(&(contract_hash.len() as u16).to_le_bytes());
                bytes.extend_from_slice(contract_hash);
                bytes.extend_from_slice(&(signature.len() as u16).to_le_bytes());
                bytes.extend_from_slice(signature);
            }
            ProtocolMessage::Ping => {
                bytes.push(0xF0);
            }
            ProtocolMessage::Pong => {
                bytes.push(0xF1);
            }
            ProtocolMessage::Close { reason } => {
                bytes.push(0xFF);
                let reason_bytes = reason.as_bytes();
                bytes.extend_from_slice(&(reason_bytes.len() as u16).to_le_bytes());
                bytes.extend_from_slice(reason_bytes);
            }
        }

        bytes
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> TransportResult<Self> {
        if bytes.is_empty() {
            return Err(TransportError::InvalidData("Empty message".to_string()));
        }

        let tag = bytes[0];
        let rest = &bytes[1..];

        match tag {
            0x01 => {
                // HandshakeInit
                let (identity, rest) = read_vec16(rest)?;
                let (ephemeral, _) = read_vec16(rest)?;
                Ok(ProtocolMessage::HandshakeInit { identity, ephemeral })
            }
            0x02 => {
                // HandshakeResponse
                let (identity, rest) = read_vec16(rest)?;
                let (ephemeral, _) = read_vec16(rest)?;
                Ok(ProtocolMessage::HandshakeResponse { identity, ephemeral })
            }
            0x10 => {
                // EncryptedMessage
                let (ciphertext, _) = read_vec32(rest)?;
                Ok(ProtocolMessage::EncryptedMessage { ciphertext })
            }
            0x20 => {
                // ContractProposal
                let (contract, _) = read_vec32(rest)?;
                Ok(ProtocolMessage::ContractProposal { contract })
            }
            0x21 => {
                // ContractSigned
                let (contract_hash, rest) = read_vec16(rest)?;
                let (signature, _) = read_vec16(rest)?;
                Ok(ProtocolMessage::ContractSigned {
                    contract_hash,
                    signature,
                })
            }
            0xF0 => Ok(ProtocolMessage::Ping),
            0xF1 => Ok(ProtocolMessage::Pong),
            0xFF => {
                // Close
                let (reason_bytes, _) = read_vec16(rest)?;
                let reason = String::from_utf8(reason_bytes)
                    .map_err(|e| TransportError::InvalidData(e.to_string()))?;
                Ok(ProtocolMessage::Close { reason })
            }
            _ => Err(TransportError::InvalidData(format!(
                "Unknown message type: {:#x}",
                tag
            ))),
        }
    }
}

/// Helper: read a length-prefixed vector (16-bit length)
fn read_vec16(bytes: &[u8]) -> TransportResult<(Vec<u8>, &[u8])> {
    if bytes.len() < 2 {
        return Err(TransportError::InvalidData("Not enough data".to_string()));
    }

    let len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    let rest = &bytes[2..];

    if rest.len() < len {
        return Err(TransportError::InvalidData("Not enough data".to_string()));
    }

    Ok((rest[..len].to_vec(), &rest[len..]))
}

/// Helper: read a length-prefixed vector (32-bit length)
fn read_vec32(bytes: &[u8]) -> TransportResult<(Vec<u8>, &[u8])> {
    if bytes.len() < 4 {
        return Err(TransportError::InvalidData("Not enough data".to_string()));
    }

    let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let rest = &bytes[4..];

    if rest.len() < len {
        return Err(TransportError::InvalidData("Not enough data".to_string()));
    }

    Ok((rest[..len].to_vec(), &rest[len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_transport() {
        let (mut alice, mut bob) = memory::create_pair();

        // Alice sends to Bob
        alice.send(b"Hello Bob").await.unwrap();
        let received = bob.receive().await.unwrap();
        assert_eq!(received, b"Hello Bob");

        // Bob sends to Alice
        bob.send(b"Hello Alice").await.unwrap();
        let received = alice.receive().await.unwrap();
        assert_eq!(received, b"Hello Alice");
    }

    #[tokio::test]
    async fn test_memory_transport_close() {
        let (mut alice, mut bob) = memory::create_pair();

        alice.close().await.unwrap();
        assert!(!alice.is_connected());

        // Should fail after close
        assert!(alice.send(b"test").await.is_err());
    }

    #[tokio::test]
    async fn test_manual_transport() {
        let mut transport = manual::ManualTransport::new();

        // Send creates outbound message
        transport.send(b"Hello").await.unwrap();

        let outbound = transport.get_outbound().unwrap();
        assert!(!outbound.is_empty());

        // Should be valid base64
        let decoded = manual::decode(&outbound).unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[tokio::test]
    async fn test_manual_transport_inbound() {
        let mut transport = manual::ManualTransport::new();

        // Encode some data
        let encoded = manual::encode(b"Incoming message");

        // Feed it to the transport
        transport.feed_inbound(&encoded).await.unwrap();

        // Should be able to receive it
        let received = transport.receive().await.unwrap();
        assert_eq!(received, b"Incoming message");
    }

    #[test]
    fn test_protocol_message_roundtrip() {
        let messages = vec![
            ProtocolMessage::HandshakeInit {
                identity: vec![1, 2, 3],
                ephemeral: vec![4, 5, 6],
            },
            ProtocolMessage::HandshakeResponse {
                identity: vec![7, 8, 9],
                ephemeral: vec![10, 11, 12],
            },
            ProtocolMessage::EncryptedMessage {
                ciphertext: vec![0; 100],
            },
            ProtocolMessage::ContractProposal {
                contract: b"contract data".to_vec(),
            },
            ProtocolMessage::ContractSigned {
                contract_hash: vec![1; 32],
                signature: vec![2; 64],
            },
            ProtocolMessage::Ping,
            ProtocolMessage::Pong,
            ProtocolMessage::Close {
                reason: "goodbye".to_string(),
            },
        ];

        for msg in messages {
            let bytes = msg.to_bytes();
            let restored = ProtocolMessage::from_bytes(&bytes).unwrap();

            // Verify roundtrip
            let bytes2 = restored.to_bytes();
            assert_eq!(bytes, bytes2);
        }
    }
}
