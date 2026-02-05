//! Sovereign CLI tool
//!
//! A command-line interface for secure two-party communication
//! with contract signing capabilities.

use clap::{Parser, Subcommand};
use sovereign::{
    contract::{Contract, ContractContent},
    crypto::{Identity, KeyExchange, PublicKey},
    session::Ratchet,
    transport::manual,
};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

/// Sovereign: Secure two-party communication with contract signing
#[derive(Parser)]
#[command(name = "sovereign")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to identity file (default: ~/.sovereign/identity.key)
    #[arg(short, long)]
    identity: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new identity keypair
    Init {
        /// Force overwrite existing identity
        #[arg(short, long)]
        force: bool,
    },

    /// Display your public key
    Identity,

    /// Start an interactive session with a peer
    Connect {
        /// Peer's public key (hex encoded)
        peer_pubkey: String,
    },

    /// Encrypt a message for a peer (manual transport mode)
    Message {
        /// Message to encrypt
        message: String,

        /// Shared secret (hex encoded, from prior key exchange)
        #[arg(short, long)]
        secret: String,
    },

    /// Decrypt a message from a peer (manual transport mode)
    Decrypt {
        /// Base64 encoded ciphertext
        ciphertext: String,

        /// Shared secret (hex encoded)
        #[arg(short, long)]
        secret: String,
    },

    /// Create a new contract
    ContractNew {
        /// Contract title
        #[arg(short, long)]
        title: String,

        /// Contract body text
        #[arg(short, long)]
        body: String,

        /// Your role in the contract (e.g., "party_a", "seller")
        #[arg(short, long)]
        role: String,

        /// Peer's public key (hex)
        #[arg(short, long)]
        peer: String,

        /// Peer's role
        #[arg(long)]
        peer_role: String,
    },

    /// Sign a contract
    ContractSign {
        /// Path to contract JSON file
        contract_file: PathBuf,
    },

    /// Verify a contract's signatures
    ContractVerify {
        /// Path to contract JSON file
        contract_file: PathBuf,
    },

    /// Export a contract for third-party verification
    ContractExport {
        /// Path to contract JSON file
        contract_file: PathBuf,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Run interactive demo showing all features
    Demo,
}

fn main() {
    let cli = Cli::parse();

    let identity_path = cli.identity.unwrap_or_else(default_identity_path);

    match cli.command {
        Commands::Init { force } => cmd_init(&identity_path, force),
        Commands::Identity => cmd_identity(&identity_path),
        Commands::Connect { peer_pubkey } => cmd_connect(&identity_path, &peer_pubkey),
        Commands::Message { message, secret } => cmd_message(&message, &secret),
        Commands::Decrypt { ciphertext, secret } => cmd_decrypt(&ciphertext, &secret),
        Commands::ContractNew {
            title,
            body,
            role,
            peer,
            peer_role,
        } => cmd_contract_new(&identity_path, &title, &body, &role, &peer, &peer_role),
        Commands::ContractSign { contract_file } => cmd_contract_sign(&identity_path, &contract_file),
        Commands::ContractVerify { contract_file } => cmd_contract_verify(&contract_file),
        Commands::ContractExport { contract_file, output } => {
            cmd_contract_export(&contract_file, output.as_deref())
        }
        Commands::Demo => cmd_demo(),
    }
}

fn default_identity_path() -> PathBuf {
    dirs::home_dir()
        .expect("Could not find home directory")
        .join(".sovereign")
        .join("identity.key")
}

fn load_identity(path: &PathBuf) -> Identity {
    let bytes = fs::read(path).unwrap_or_else(|_| {
        eprintln!("Error: No identity found at {:?}", path);
        eprintln!("Run 'sovereign init' to create one.");
        std::process::exit(1);
    });

    Identity::from_bytes(&bytes).unwrap_or_else(|e| {
        eprintln!("Error: Invalid identity file: {}", e);
        std::process::exit(1);
    })
}

fn save_identity(identity: &Identity, path: &PathBuf) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("Error creating directory: {}", e);
            std::process::exit(1);
        });
    }

    let bytes = identity.to_bytes();
    fs::write(path, bytes).unwrap_or_else(|e| {
        eprintln!("Error saving identity: {}", e);
        std::process::exit(1);
    });
}

fn cmd_init(path: &PathBuf, force: bool) {
    if path.exists() && !force {
        eprintln!("Identity already exists at {:?}", path);
        eprintln!("Use --force to overwrite.");
        std::process::exit(1);
    }

    let identity = Identity::generate();
    save_identity(&identity, path);

    println!("Identity created successfully!");
    println!();
    println!("Your public key (share this with peers):");
    println!("{}", identity.public_key().to_hex());
    println!();
    println!("Identity saved to: {:?}", path);
    println!();
    println!("IMPORTANT: Back up your identity file securely!");
}

fn cmd_identity(path: &PathBuf) {
    let identity = load_identity(path);

    println!("Your public key:");
    println!("{}", identity.public_key().to_hex());
}

fn cmd_connect(identity_path: &PathBuf, peer_pubkey_hex: &str) {
    let identity = load_identity(identity_path);

    let peer_pubkey = PublicKey::from_hex(peer_pubkey_hex).unwrap_or_else(|e| {
        eprintln!("Invalid peer public key: {}", e);
        std::process::exit(1);
    });

    println!("=== Sovereign Interactive Session ===");
    println!();
    println!("Your public key: {}", identity.public_key().to_hex());
    println!("Peer public key: {}", peer_pubkey.to_hex());
    println!();
    println!("This is a manual transport session. Messages are base64 encoded.");
    println!("Copy/paste messages between terminals to communicate.");
    println!();
    println!("Commands:");
    println!("  /send <message>     - Encrypt and send a message");
    println!("  /recv <base64>      - Decrypt a received message");
    println!("  /contract           - Start contract creation wizard");
    println!("  /quit               - Exit session");
    println!();

    // Generate ephemeral keypair for this session
    let ephemeral = KeyExchange::generate_ephemeral();

    println!("--- HANDSHAKE ---");
    println!("Send this to your peer:");
    let handshake_data = format!(
        "SOVEREIGN:HANDSHAKE:{}:{}",
        identity.public_key().to_hex(),
        hex::encode(ephemeral.public_key().0)
    );
    println!("{}", handshake_data);
    println!();

    print!("Enter peer's handshake message: ");
    io::stdout().flush().unwrap();

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let peer_handshake = lines.next().unwrap().unwrap();
    let parts: Vec<&str> = peer_handshake.split(':').collect();

    if parts.len() != 4 || parts[0] != "SOVEREIGN" || parts[1] != "HANDSHAKE" {
        eprintln!("Invalid handshake format");
        std::process::exit(1);
    }

    let peer_eph_bytes = hex::decode(parts[3]).unwrap_or_else(|_| {
        eprintln!("Invalid peer ephemeral key");
        std::process::exit(1);
    });

    let mut peer_eph_arr = [0u8; 32];
    peer_eph_arr.copy_from_slice(&peer_eph_bytes);
    let peer_ephemeral = sovereign::crypto::ExchangePublicKey(peer_eph_arr);

    // Derive shared secret using X3DH-like protocol
    let shared_secret = KeyExchange::x3dh(
        identity.secret_key_bytes(),
        &ephemeral,
        &peer_ephemeral,
        &peer_ephemeral,
        true, // we initiated
    );

    // Initialize ratchet
    let (mut our_ratchet, _) = Ratchet::create_pair(shared_secret.as_bytes());

    println!();
    println!("Session established! You can now exchange encrypted messages.");
    println!();

    // Interactive loop
    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let line = match lines.next() {
            Some(Ok(l)) => l,
            _ => break,
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with("/send ") {
            let msg = &line[6..];
            let encrypted = our_ratchet.encrypt(msg.as_bytes());
            let encoded = manual::encode(&encrypted);
            println!("Encrypted message (send this):");
            println!("{}", encoded);
        } else if line.starts_with("/recv ") {
            let encoded = &line[6..];
            match manual::decode(encoded) {
                Ok(ciphertext) => match our_ratchet.decrypt(&ciphertext) {
                    Ok(plaintext) => {
                        println!(
                            "Decrypted: {}",
                            String::from_utf8_lossy(&plaintext)
                        );
                    }
                    Err(e) => println!("Decryption failed: {}", e),
                },
                Err(e) => println!("Invalid base64: {}", e),
            }
        } else if line == "/contract" {
            println!("Contract creation wizard - coming soon!");
        } else if line == "/quit" {
            println!("Goodbye!");
            break;
        } else {
            println!("Unknown command. Use /send, /recv, /contract, or /quit");
        }
    }
}

fn cmd_message(message: &str, secret_hex: &str) {
    let secret_bytes = hex::decode(secret_hex).unwrap_or_else(|_| {
        eprintln!("Invalid secret hex");
        std::process::exit(1);
    });

    if secret_bytes.len() != 32 {
        eprintln!("Secret must be 32 bytes (64 hex chars)");
        std::process::exit(1);
    }

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);

    let (mut ratchet, _) = Ratchet::create_pair(&secret);
    let encrypted = ratchet.encrypt(message.as_bytes());
    let encoded = manual::encode(&encrypted);

    println!("{}", encoded);
}

fn cmd_decrypt(ciphertext_b64: &str, secret_hex: &str) {
    let secret_bytes = hex::decode(secret_hex).unwrap_or_else(|_| {
        eprintln!("Invalid secret hex");
        std::process::exit(1);
    });

    if secret_bytes.len() != 32 {
        eprintln!("Secret must be 32 bytes (64 hex chars)");
        std::process::exit(1);
    }

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&secret_bytes);

    let ciphertext = manual::decode(ciphertext_b64).unwrap_or_else(|e| {
        eprintln!("Invalid base64: {}", e);
        std::process::exit(1);
    });

    // Note: For proper decryption, the receiver needs their own ratchet state
    // This is a simplified single-message mode
    let (_, mut ratchet) = Ratchet::create_pair(&secret);
    match ratchet.decrypt(&ciphertext) {
        Ok(plaintext) => {
            println!("{}", String::from_utf8_lossy(&plaintext));
        }
        Err(e) => {
            eprintln!("Decryption failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_contract_new(
    identity_path: &PathBuf,
    title: &str,
    body: &str,
    our_role: &str,
    peer_hex: &str,
    peer_role: &str,
) {
    let identity = load_identity(identity_path);

    let peer_pubkey = PublicKey::from_hex(peer_hex).unwrap_or_else(|e| {
        eprintln!("Invalid peer public key: {}", e);
        std::process::exit(1);
    });

    let content = ContractContent::new(title.to_string(), body.to_string());

    let mut contract = Contract::new(content);
    contract.add_party(*identity.public_key(), our_role.to_string());
    contract.add_party(peer_pubkey, peer_role.to_string());

    let contract_hash = contract.hash();
    let json = serde_json::to_string_pretty(&contract).unwrap();
    let filename = format!("contract_{}.json", &contract_hash[..8]);

    fs::write(&filename, &json).unwrap_or_else(|e| {
        eprintln!("Error saving contract: {}", e);
        std::process::exit(1);
    });

    println!("Contract created: {}", filename);
    println!();
    println!("Contract Hash: {}", contract_hash);
    println!("Status: {} of {} signatures", contract.signatures.len(), contract.parties.len());
    println!();
    println!("Next step: Sign the contract with 'sovereign contract-sign {}'", filename);
}

fn cmd_contract_sign(identity_path: &PathBuf, contract_path: &PathBuf) {
    let identity = load_identity(identity_path);

    let json = fs::read_to_string(contract_path).unwrap_or_else(|e| {
        eprintln!("Error reading contract: {}", e);
        std::process::exit(1);
    });

    let mut contract: Contract = serde_json::from_str(&json).unwrap_or_else(|e| {
        eprintln!("Invalid contract format: {}", e);
        std::process::exit(1);
    });

    // Check if we're a party to this contract
    let our_pubkey = identity.public_key();
    if !contract.parties.iter().any(|p| &p.identity == our_pubkey) {
        eprintln!("Error: You are not a party to this contract.");
        eprintln!("Your public key: {}", our_pubkey.to_hex());
        std::process::exit(1);
    }

    // Check if already signed by us
    if contract.signatures.iter().any(|s| &s.signer == our_pubkey) {
        eprintln!("Error: You have already signed this contract.");
        std::process::exit(1);
    }

    // Sign the contract
    contract.sign(&identity).unwrap_or_else(|e| {
        eprintln!("Error signing contract: {}", e);
        std::process::exit(1);
    });

    // Save updated contract
    let json = serde_json::to_string_pretty(&contract).unwrap();
    fs::write(contract_path, &json).unwrap_or_else(|e| {
        eprintln!("Error saving contract: {}", e);
        std::process::exit(1);
    });

    println!("Contract signed successfully!");
    println!();
    println!("Contract Hash: {}", contract.hash());
    println!(
        "Signatures: {}/{}",
        contract.signatures.len(),
        contract.parties.len()
    );

    if contract.is_complete() {
        println!();
        println!("CONTRACT IS NOW FULLY SIGNED!");
        println!("All parties have agreed. This contract is legally binding.");
    } else {
        println!();
        println!("Waiting for other party to sign.");
        println!("Share the contract file with them.");
    }
}

fn cmd_contract_verify(contract_path: &PathBuf) {
    let json = fs::read_to_string(contract_path).unwrap_or_else(|e| {
        eprintln!("Error reading contract: {}", e);
        std::process::exit(1);
    });

    let contract: Contract = serde_json::from_str(&json).unwrap_or_else(|e| {
        eprintln!("Invalid contract format: {}", e);
        std::process::exit(1);
    });

    println!("=== Contract Verification Report ===");
    println!();
    println!("Contract Hash: {}", contract.hash());
    println!("Created: {}", format_timestamp(contract.created_at));
    println!("Signatures: {}/{}", contract.signatures.len(), contract.parties.len());
    println!();
    println!("--- Content ---");
    println!("Title: {}", contract.content.title);
    println!("Body: {}", contract.content.body);
    println!();
    println!("--- Parties ---");
    for party in &contract.parties {
        let signed = contract.signatures.iter().any(|s| s.signer == party.identity);
        let status = if signed { "[SIGNED]" } else { "[PENDING]" };
        println!("  {} ({}...): {}", party.role, &party.identity.to_hex()[..16], status);
    }
    println!();
    println!("--- Signature Verification ---");

    let mut all_valid = true;
    for sig in &contract.signatures {
        let signer_hex = &sig.signer.to_hex()[..16];
        match contract.verify_signature(sig) {
            Ok(()) => {
                println!("  [VALID] Signature by {}...", signer_hex);
            }
            Err(e) => {
                println!("  [INVALID] Signature by {}...: {}", signer_hex, e);
                all_valid = false;
            }
        }
    }

    println!();
    if contract.is_complete() && all_valid {
        println!("VERIFICATION RESULT: CONTRACT IS VALID AND FULLY SIGNED");
    } else if all_valid {
        println!("VERIFICATION RESULT: All signatures valid, but contract not fully signed");
    } else {
        println!("VERIFICATION RESULT: INVALID - Some signatures failed verification!");
    }
}

fn cmd_contract_export(contract_path: &PathBuf, output: Option<&std::path::Path>) {
    let json = fs::read_to_string(contract_path).unwrap_or_else(|e| {
        eprintln!("Error reading contract: {}", e);
        std::process::exit(1);
    });

    let contract: Contract = serde_json::from_str(&json).unwrap_or_else(|e| {
        eprintln!("Invalid contract format: {}", e);
        std::process::exit(1);
    });

    // Create a verification bundle
    let bundle = serde_json::json!({
        "type": "sovereign_contract_verification_bundle",
        "version": 1,
        "contract": contract,
        "canonical_hash": contract.hash(),
        "verification_instructions": {
            "1": "Deserialize the contract object",
            "2": "Compute canonical bytes (see protocol spec)",
            "3": "Hash canonical bytes with BLAKE3 to verify contract hash",
            "4": "For each signature, verify Ed25519 signature over canonical bytes",
            "5": "Confirm all parties have signed",
        }
    });

    let output_json = serde_json::to_string_pretty(&bundle).unwrap();

    match output {
        Some(path) => {
            fs::write(path, &output_json).unwrap_or_else(|e| {
                eprintln!("Error writing output: {}", e);
                std::process::exit(1);
            });
            println!("Verification bundle exported to: {:?}", path);
        }
        None => {
            println!("{}", output_json);
        }
    }
}

fn cmd_demo() {
    println!("=== Sovereign-Lite Demo ===");
    println!();
    println!("This demo shows the complete flow of:");
    println!("1. Identity generation");
    println!("2. Session establishment");
    println!("3. Encrypted messaging");
    println!("4. Contract signing");
    println!("5. Third-party verification");
    println!();

    // Step 1: Generate identities
    println!("--- Step 1: Identity Generation ---");
    let alice = Identity::generate();
    let bob = Identity::generate();
    println!("Alice's public key: {}...", &alice.public_key().to_hex()[..32]);
    println!("Bob's public key: {}...", &bob.public_key().to_hex()[..32]);
    println!();

    // Step 2: Establish session
    println!("--- Step 2: Session Establishment ---");
    let shared_secret = sovereign::random_bytes::<32>();
    let (mut alice_ratchet, mut bob_ratchet) = Ratchet::create_pair(&shared_secret);
    println!("Session established with shared secret (in real use, derived via X3DH)");
    println!();

    // Step 3: Exchange messages
    println!("--- Step 3: Encrypted Messaging ---");

    let msg1 = b"Hello Bob! Ready to sign our agreement?";
    let ct1 = alice_ratchet.encrypt(msg1);
    println!("Alice encrypts: \"{}\"", String::from_utf8_lossy(msg1));
    println!("Ciphertext (base64): {}...", &manual::encode(&ct1)[..40]);

    let pt1 = bob_ratchet.decrypt(&ct1).unwrap();
    println!("Bob decrypts: \"{}\"", String::from_utf8_lossy(&pt1));
    println!();

    let msg2 = b"Yes, let's do it!";
    let ct2 = bob_ratchet.encrypt(msg2);
    println!("Bob encrypts: \"{}\"", String::from_utf8_lossy(msg2));

    let pt2 = alice_ratchet.decrypt(&ct2).unwrap();
    println!("Alice decrypts: \"{}\"", String::from_utf8_lossy(&pt2));
    println!();

    // Step 4: Create and sign contract
    println!("--- Step 4: Contract Signing ---");

    let content = ContractContent::new(
        "Service Agreement".to_string(),
        "Alice agrees to provide consulting services to Bob for the amount of $1000 USD.".to_string(),
    );

    let mut contract = Contract::new(content);
    contract.add_party(*alice.public_key(), "service_provider".to_string());
    contract.add_party(*bob.public_key(), "client".to_string());

    println!("Contract created:");
    println!("  Hash: {}", contract.hash());
    println!("  Title: {}", contract.content.title);
    println!("  Signatures: {}/{}", contract.signatures.len(), contract.parties.len());
    println!();

    // Alice signs
    contract.sign(&alice).unwrap();
    println!("Alice signed the contract");
    println!("  Signatures: {}/{}", contract.signatures.len(), contract.parties.len());

    // Bob signs
    contract.sign(&bob).unwrap();
    println!("Bob signed the contract");
    println!("  Signatures: {}/{}", contract.signatures.len(), contract.parties.len());
    println!();

    // Step 5: Third-party verification
    println!("--- Step 5: Third-Party Verification ---");
    println!("A third party (Charlie) can verify without any session:");
    println!();

    // Verify all signatures
    let mut all_valid = true;
    for sig in &contract.signatures {
        match contract.verify_signature(sig) {
            Ok(()) => {
                let role = contract
                    .parties
                    .iter()
                    .find(|p| p.identity == sig.signer)
                    .map(|p| p.role.as_str())
                    .unwrap_or("unknown");
                println!(
                    "  [VALID] Signature from {} ({}...)",
                    role,
                    &sig.signer.to_hex()[..16]
                );
            }
            Err(e) => {
                println!("  [INVALID] Signature: {}", e);
                all_valid = false;
            }
        }
    }

    println!();
    if all_valid && contract.is_complete() {
        println!("CONTRACT VERIFIED: All parties have signed, all signatures valid!");
    }

    println!();
    println!("=== Demo Complete ===");
    println!();
    println!("This demonstrates the core Sovereign-Lite capabilities:");
    println!("- End-to-end encryption with forward secrecy");
    println!("- Contract signing by multiple parties");
    println!("- Third-party verifiable non-repudiation");
}

fn format_timestamp(ts: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let contract_time = UNIX_EPOCH + Duration::from_secs(ts);
    let now = SystemTime::now();

    match now.duration_since(contract_time) {
        Ok(diff) => {
            let secs = diff.as_secs();
            let days = secs / 86400;
            let hours = (secs % 86400) / 3600;
            let mins = (secs % 3600) / 60;

            if days > 0 {
                format!("{} days, {} hours ago", days, hours)
            } else if hours > 0 {
                format!("{} hours, {} mins ago", hours, mins)
            } else if mins > 0 {
                format!("{} mins ago", mins)
            } else {
                "just now".to_string()
            }
        }
        Err(_) => "in the future".to_string(),
    }
}
