//! Sovereign Relay Server
//!
//! A WebSocket relay server that facilitates communication between peers.
//! The server provides:
//! - Room-based message routing
//! - Zero-knowledge relay (never sees plaintext)
//! - Simple room codes for easy joining
//!
//! Usage:
//!   sovereign-relay [--port 8765] [--host 0.0.0.0]

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use tracing::{error, info, warn};

/// Sovereign Relay Server
#[derive(Parser)]
#[command(name = "sovereign-relay")]
#[command(about = "WebSocket relay server for Sovereign secure communication")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "8765")]
    port: u16,

    /// Host to bind to
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
}

/// Messages between client and relay
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
enum RelayMessage {
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

/// A room for two peers to communicate
struct Room {
    code: String,
    /// Broadcast channel for the room
    tx: broadcast::Sender<(usize, String)>,
    /// Number of connected peers
    peer_count: Arc<RwLock<usize>>,
}

impl Room {
    fn new(code: String) -> Self {
        let (tx, _) = broadcast::channel(100);
        Room {
            code,
            tx,
            peer_count: Arc::new(RwLock::new(0)),
        }
    }
}

/// Server state
struct RelayState {
    rooms: RwLock<HashMap<String, Arc<Room>>>,
}

impl RelayState {
    fn new() -> Self {
        RelayState {
            rooms: RwLock::new(HashMap::new()),
        }
    }

    /// Generate a unique 6-character room code
    async fn generate_room_code(&self) -> String {
        let rooms = self.rooms.read().await;
        loop {
            let code: String = (0..6)
                .map(|_| {
                    let idx = rand::random::<usize>() % 36;
                    if idx < 10 {
                        (b'0' + idx as u8) as char
                    } else {
                        (b'A' + (idx - 10) as u8) as char
                    }
                })
                .collect();

            if !rooms.contains_key(&code) {
                return code;
            }
        }
    }

    /// Create a new room
    async fn create_room(&self) -> String {
        let code = self.generate_room_code().await;
        let room = Arc::new(Room::new(code.clone()));

        let mut rooms = self.rooms.write().await;
        rooms.insert(code.clone(), room);

        info!("Room created: {}", code);
        code
    }

    /// Get a room by code
    async fn get_room(&self, code: &str) -> Option<Arc<Room>> {
        let rooms = self.rooms.read().await;
        rooms.get(code).cloned()
    }

    /// Remove a room if empty
    async fn cleanup_room(&self, code: &str) {
        let mut rooms = self.rooms.write().await;
        if let Some(room) = rooms.get(code) {
            let count = *room.peer_count.read().await;
            if count == 0 {
                rooms.remove(code);
                info!("Room removed: {}", code);
            }
        }
    }
}

/// Handle a single WebSocket connection
async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    state: Arc<RelayState>,
) {
    info!("New connection from: {}", addr);

    let ws_stream = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            error!("WebSocket handshake failed for {}: {}", addr, e);
            return;
        }
    };

    let (mut write, mut read) = ws_stream.split();

    // Client state
    let mut current_room: Option<Arc<Room>> = None;
    let mut room_rx: Option<broadcast::Receiver<(usize, String)>> = None;
    let client_id: usize = rand::random();

    loop {
        tokio::select! {
            // Handle incoming WebSocket messages
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<RelayMessage>(&text) {
                            Ok(relay_msg) => {
                                match relay_msg {
                                    RelayMessage::CreateRoom => {
                                        let code = state.create_room().await;
                                        if let Some(room) = state.get_room(&code).await {
                                            // Join the room we created
                                            *room.peer_count.write().await += 1;
                                            room_rx = Some(room.tx.subscribe());
                                            current_room = Some(room);

                                            let response = RelayMessage::RoomCreated { code };
                                            if let Ok(json) = serde_json::to_string(&response) {
                                                let _ = write.send(Message::Text(json)).await;
                                            }
                                        }
                                    }

                                    RelayMessage::JoinRoom { code } => {
                                        if let Some(room) = state.get_room(&code).await {
                                            let mut count = room.peer_count.write().await;
                                            if *count >= 2 {
                                                let response = RelayMessage::Error {
                                                    message: "Room is full".to_string(),
                                                };
                                                if let Ok(json) = serde_json::to_string(&response) {
                                                    let _ = write.send(Message::Text(json)).await;
                                                }
                                            } else {
                                                *count += 1;
                                                let peer_count = *count;
                                                drop(count);

                                                room_rx = Some(room.tx.subscribe());

                                                // Notify existing peer
                                                let _ = room.tx.send((client_id, String::new()));

                                                current_room = Some(room);

                                                let response = RelayMessage::Joined {
                                                    code,
                                                    peer_count,
                                                };
                                                if let Ok(json) = serde_json::to_string(&response) {
                                                    let _ = write.send(Message::Text(json)).await;
                                                }

                                                info!("Client {} joined room, {} peers", addr, peer_count);
                                            }
                                        } else {
                                            let response = RelayMessage::Error {
                                                message: "Room not found".to_string(),
                                            };
                                            if let Ok(json) = serde_json::to_string(&response) {
                                                let _ = write.send(Message::Text(json)).await;
                                            }
                                        }
                                    }

                                    RelayMessage::Forward { data } => {
                                        if let Some(room) = &current_room {
                                            // Broadcast to other peer(s) in the room
                                            let _ = room.tx.send((client_id, data));
                                        } else {
                                            let response = RelayMessage::Error {
                                                message: "Not in a room".to_string(),
                                            };
                                            if let Ok(json) = serde_json::to_string(&response) {
                                                let _ = write.send(Message::Text(json)).await;
                                            }
                                        }
                                    }

                                    RelayMessage::Ping => {
                                        let response = RelayMessage::Pong;
                                        if let Ok(json) = serde_json::to_string(&response) {
                                            let _ = write.send(Message::Text(json)).await;
                                        }
                                    }

                                    _ => {}
                                }
                            }
                            Err(e) => {
                                warn!("Invalid message from {}: {}", addr, e);
                            }
                        }
                    }

                    Some(Ok(Message::Close(_))) | None => {
                        info!("Client {} disconnected", addr);
                        break;
                    }

                    Some(Ok(Message::Ping(data))) => {
                        let _ = write.send(Message::Pong(data)).await;
                    }

                    Some(Err(e)) => {
                        error!("WebSocket error from {}: {}", addr, e);
                        break;
                    }

                    _ => {}
                }
            }

            // Handle messages from the room
            room_msg = async {
                if let Some(rx) = &mut room_rx {
                    rx.recv().await.ok()
                } else {
                    // Sleep forever if no room
                    std::future::pending::<Option<(usize, String)>>().await
                }
            } => {
                if let Some((sender_id, data)) = room_msg {
                    if sender_id != client_id {
                        if data.is_empty() {
                            // Peer joined notification
                            let response = RelayMessage::PeerJoined;
                            if let Ok(json) = serde_json::to_string(&response) {
                                let _ = write.send(Message::Text(json)).await;
                            }
                        } else {
                            // Forward message from peer
                            let response = RelayMessage::Message { data };
                            if let Ok(json) = serde_json::to_string(&response) {
                                let _ = write.send(Message::Text(json)).await;
                            }
                        }
                    }
                }
            }
        }
    }

    // Cleanup on disconnect
    if let Some(room) = current_room {
        let code = room.code.clone();
        let mut count = room.peer_count.write().await;
        *count = count.saturating_sub(1);
        let remaining = *count;
        drop(count);

        // Notify remaining peer
        if remaining > 0 {
            let _ = room.tx.send((client_id, String::new())); // Empty = peer left
        }

        // Cleanup empty room
        drop(room);
        state.cleanup_room(&code).await;
    }
}

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sovereign_relay=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();
    let addr = format!("{}:{}", args.host, args.port);

    let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
    info!("Sovereign Relay Server listening on ws://{}", addr);
    info!("Rooms are limited to 2 peers each (two-party communication)");

    let state = Arc::new(RelayState::new());

    while let Ok((stream, addr)) = listener.accept().await {
        let state = state.clone();
        tokio::spawn(handle_connection(stream, addr, state));
    }
}
