# Sovereign

**Zero-trust, end-to-end encrypted communication for sovereign individuals.**

Sovereign is a cryptographic communication library and application that provides:

- **Ed25519** digital signatures for identity
- **X25519** ECDH for key exchange
- **ChaCha20-Poly1305** AEAD encryption
- **BLAKE3** hashing and key derivation
- **Double Ratchet** algorithm for forward secrecy
- **Contract signing** with cryptographic non-repudiation

## Quick Start

### Option 1: Web UI (No Installation)

Visit: **[https://YOUR_USERNAME.github.io/sovereign-lite/](https://YOUR_USERNAME.github.io/sovereign-lite/)**

1. Both users open the web UI
2. User 1 clicks "Create Room" → gets a 6-character code
3. User 1 shares the code with User 2 (via text, call, etc.)
4. User 2 enters the code → clicks "Join"
5. Chat with end-to-end encryption!

### Option 2: Run Locally

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/sovereign-lite.git
cd sovereign-lite

# Start the relay server
cargo run --bin sovereign-relay

# Open the web UI
open docs/index.html
```

### Option 3: CLI

```bash
# Terminal 1 - Create a room
cargo run --bin sovereign-cli -- session create

# Terminal 2 - Join with code
cargo run --bin sovereign-cli -- session join ABC123
```

## Architecture

```
┌─────────────┐                    ┌─────────────┐
│   Alice     │                    │    Bob      │
│  (Browser)  │                    │  (Browser)  │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │  Encrypted Messages              │
       │  ◄──────────────────────────────►│
       │                                  │
       └──────────────┬───────────────────┘
                      │
                      ▼
              ┌───────────────┐
              │ Relay Server  │
              │ (Zero-Knowledge)│
              └───────────────┘

The relay server ONLY sees encrypted blobs.
It cannot read your messages.
```

## Security Model

1. **Identity**: Each user generates an Ed25519 keypair. The public key IS your identity.

2. **Key Exchange**: When connecting, users perform X25519 ECDH to establish a shared secret.

3. **Double Ratchet**: Each message uses a new encryption key, providing forward secrecy.

4. **Zero-Knowledge Relay**: The server only routes encrypted blobs between peers.

## Relay Server

The relay server is needed to route messages between peers (NAT traversal).

### Public Relay

A public relay is available at: `wss://sovereign-relay.fly.dev`

### Self-Host

```bash
# Build
cargo build --release --bin sovereign-relay

# Run (default port 8765)
./target/release/sovereign-relay

# Custom port
./target/release/sovereign-relay --port 9000
```

### Deploy to Fly.io (Free Tier)

```bash
cd sovereign-lite
fly launch --name sovereign-relay
fly deploy
```

## Library Usage

```rust
use sovereign_lite::{Identity, Session, Ratchet};

// Create identity
let alice = Identity::generate();

// Create session
let mut session = Session::new(alice);

// ... perform key exchange ...

// Encrypt message
let ciphertext = session.encrypt(b"Hello, Bob!")?;

// Decrypt message
let plaintext = session.decrypt(&ciphertext)?;
```

## Contract Signing

Sovereign includes cryptographic contract signing with non-repudiation:

```rust
use sovereign_lite::{Identity, Contract};

let alice = Identity::generate();
let bob = Identity::generate();

// Create contract
let mut contract = Contract::new(
    "Service Agreement",
    "Alice agrees to pay Bob 100 tokens for services.",
    vec![alice.public_key(), bob.public_key()],
)?;

// Sign
contract.sign(&alice)?;
contract.sign(&bob)?;

// Verify all signatures
assert!(contract.is_fully_signed());
assert!(contract.verify_all());
```

## Testing

```bash
cargo test
```

## License

MIT
