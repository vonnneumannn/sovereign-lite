//! WebSocket transport for real-time communication via relay server
//!
//! This transport connects to a Sovereign relay server and enables
//! real-time encrypted communication between two peers.

use super::{TransportError, TransportResult, Transport};
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream,
};

/// Messages exchanged with the relay server
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
#[allow(missing_docs)]
pub enum RelayMessage {
    /// Create a new room
    CreateRoom,
    /// Room created successfully
    RoomCreated { code: String },
    /// Join an existing room
    JoinRoom { code: String },
    /// Successfully joined room
    Joined { code: String, peer_count: usize },
    /// Peer joined your room
    PeerJoined,
    /// Peer left your room
    PeerLeft,
    /// Forward data to peer (opaque blob)
    Forward { data: String },
    /// Received data from peer
    Message { data: String },
    /// Error occurred
    Error { message: String },
    /// Ping
    Ping,
    /// Pong
    Pong,
}

/// WebSocket transport connected to a relay server
pub struct WebSocketTransport {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    room_code: Option<String>,
    connected: bool,
    peer_connected: bool,
}

impl WebSocketTransport {
    /// Connect to a relay server
    pub async fn connect(relay_url: &str) -> TransportResult<Self> {
        let (ws, _) = connect_async(relay_url)
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        Ok(WebSocketTransport {
            ws,
            room_code: None,
            connected: true,
            peer_connected: false,
        })
    }

    /// Create a new room on the relay
    pub async fn create_room(&mut self) -> TransportResult<String> {
        let msg = RelayMessage::CreateRoom;
        self.send_relay_message(&msg).await?;

        // Wait for room created response
        loop {
            match self.receive_relay_message().await? {
                RelayMessage::RoomCreated { code } => {
                    self.room_code = Some(code.clone());
                    return Ok(code);
                }
                RelayMessage::Error { message } => {
                    return Err(TransportError::ConnectionFailed(message));
                }
                _ => continue,
            }
        }
    }

    /// Join an existing room
    pub async fn join_room(&mut self, code: &str) -> TransportResult<usize> {
        let msg = RelayMessage::JoinRoom {
            code: code.to_string(),
        };
        self.send_relay_message(&msg).await?;

        // Wait for joined response
        loop {
            match self.receive_relay_message().await? {
                RelayMessage::Joined { code, peer_count } => {
                    self.room_code = Some(code);
                    if peer_count > 1 {
                        self.peer_connected = true;
                    }
                    return Ok(peer_count);
                }
                RelayMessage::Error { message } => {
                    return Err(TransportError::ConnectionFailed(message));
                }
                _ => continue,
            }
        }
    }

    /// Wait for peer to join the room
    pub async fn wait_for_peer(&mut self) -> TransportResult<()> {
        if self.peer_connected {
            return Ok(());
        }

        loop {
            match self.receive_relay_message().await? {
                RelayMessage::PeerJoined => {
                    self.peer_connected = true;
                    return Ok(());
                }
                RelayMessage::Error { message } => {
                    return Err(TransportError::ConnectionFailed(message));
                }
                _ => continue,
            }
        }
    }

    /// Check if peer is connected
    pub fn is_peer_connected(&self) -> bool {
        self.peer_connected
    }

    /// Get the room code
    pub fn room_code(&self) -> Option<&str> {
        self.room_code.as_deref()
    }

    /// Send a relay protocol message
    async fn send_relay_message(&mut self, msg: &RelayMessage) -> TransportResult<()> {
        let json = serde_json::to_string(msg)
            .map_err(|e| TransportError::SendFailed(e.to_string()))?;

        self.ws
            .send(Message::Text(json))
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))
    }

    /// Receive a relay protocol message
    async fn receive_relay_message(&mut self) -> TransportResult<RelayMessage> {
        loop {
            match self.ws.next().await {
                Some(Ok(Message::Text(text))) => {
                    return serde_json::from_str(&text)
                        .map_err(|e| TransportError::InvalidData(e.to_string()));
                }
                Some(Ok(Message::Close(_))) | None => {
                    self.connected = false;
                    return Err(TransportError::Disconnected);
                }
                Some(Ok(Message::Ping(data))) => {
                    let _ = self.ws.send(Message::Pong(data)).await;
                }
                Some(Err(e)) => {
                    return Err(TransportError::ReceiveFailed(e.to_string()));
                }
                _ => continue,
            }
        }
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    async fn send(&mut self, data: &[u8]) -> TransportResult<()> {
        if !self.connected {
            return Err(TransportError::Disconnected);
        }

        // Encode as base64 for JSON transport
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            data,
        );

        let msg = RelayMessage::Forward { data: encoded };
        self.send_relay_message(&msg).await
    }

    async fn receive(&mut self) -> TransportResult<Vec<u8>> {
        if !self.connected {
            return Err(TransportError::Disconnected);
        }

        loop {
            match self.receive_relay_message().await? {
                RelayMessage::Message { data } => {
                    // Decode from base64
                    return base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        &data,
                    )
                    .map_err(|e| TransportError::InvalidData(e.to_string()));
                }
                RelayMessage::PeerJoined => {
                    self.peer_connected = true;
                    continue;
                }
                RelayMessage::PeerLeft => {
                    self.peer_connected = false;
                    return Err(TransportError::Disconnected);
                }
                RelayMessage::Error { message } => {
                    return Err(TransportError::ReceiveFailed(message));
                }
                _ => continue,
            }
        }
    }

    fn is_connected(&self) -> bool {
        self.connected && self.peer_connected
    }

    async fn close(&mut self) -> TransportResult<()> {
        self.connected = false;
        self.ws
            .close(None)
            .await
            .map_err(|e| TransportError::SendFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration tests would require a running relay server
    // These are basic unit tests

    #[test]
    fn test_relay_message_serialization() {
        let msg = RelayMessage::Forward {
            data: "SGVsbG8gV29ybGQ=".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: RelayMessage = serde_json::from_str(&json).unwrap();

        match parsed {
            RelayMessage::Forward { data } => {
                assert_eq!(data, "SGVsbG8gV29ybGQ=");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_relay_message_types() {
        let messages = vec![
            RelayMessage::CreateRoom,
            RelayMessage::RoomCreated {
                code: "ABC123".to_string(),
            },
            RelayMessage::JoinRoom {
                code: "ABC123".to_string(),
            },
            RelayMessage::Joined {
                code: "ABC123".to_string(),
                peer_count: 2,
            },
            RelayMessage::PeerJoined,
            RelayMessage::PeerLeft,
            RelayMessage::Forward {
                data: "test".to_string(),
            },
            RelayMessage::Message {
                data: "test".to_string(),
            },
            RelayMessage::Error {
                message: "error".to_string(),
            },
            RelayMessage::Ping,
            RelayMessage::Pong,
        ];

        for msg in messages {
            let json = serde_json::to_string(&msg).unwrap();
            let _: RelayMessage = serde_json::from_str(&json).unwrap();
        }
    }
}
