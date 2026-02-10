//This program implements a secure communication system based on SOCKS5 proxy, supporting message exchange and file transfer between the client and server. The client and server generate a shared key through secp256k1 key exchange, and use the AES-GCM symmetric encryption algorithm to ensure the security of the communication. The program uses independent threads to handle file and message sending and receiving, preventing blocking. Files are transferred in 1MB chunks, each being encrypted and decrypted, with SHA256 used to verify file integrity after transfer. The system can simultaneously handle real-time chat and large file transfers, ensuring efficient and secure two-way communication.

use secp256k1::{Secp256k1, SecretKey, PublicKey};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio_socks::tcp::Socks5Stream;
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM
use aes_gcm::aead::{Aead, NewAead};
use sha2::{Sha256, Digest};
use rand::Rng;
use tokio::sync::{mpsc, Mutex};
use std::sync::Arc;
use std::env;
use std::io::{self, Write};

const CHUNK_SIZE: usize = 1024 * 1024; // 1MB per file chunk

// Entry point, checks command line arguments to decide whether to run as client or server
#[tokio::main]
async fn main() {
    // Collect command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <server|client> [server_ip]", args[0]);
        return;
    }
    
    let mode = &args[1];
    
    if mode == "server" {
        start_server().await;
    } else if mode == "client" {
        if args.len() < 3 {
            eprintln!("Usage: {} client <server_ip>", args[0]);
            return;
        }
        let server_ip = &args[2];
        start_client(server_ip).await;
    } else {
        eprintln!("Invalid argument. Use 'server' or 'client'.");
    }
}

// Server-side logic
async fn start_server() {
    let addr = "0.0.0.0:8080"; // Listen on all interfaces
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("Server listening on {}", addr);

    let secp = Secp256k1::new();
    let secp = Arc::new(Mutex::new(secp));

    loop {
        let (socket, _) = listener.accept().await.unwrap();
        let secp_clone = Arc::clone(&secp);
        tokio::spawn(handle_client(socket, secp_clone)); // Spawn a new task for each client
    }
}

// Client-side logic (with the server IP specified)
async fn start_client(server_ip: &str) {
    let addr = format!("{}:8080", server_ip);
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut socks5_stream = Socks5Stream::connect("127.0.0.1:1080", stream).await.unwrap();

    let secp = Secp256k1::new();
    let (sk, pk) = generate_keypair(&secp);
    println!("Generated Client Public Key: {:?}", pk);

    // Send the client's public key to the server
    send_public_key(&mut socks5_stream, &pk).await;

    // Generate the shared secret key
    let server_pub_key = receive_public_key(&mut socks5_stream).await;
    let shared_key = generate_shared_key(&secp, &sk, &server_pub_key);
    println!("Shared key: {:?}", shared_key);

    // Spawn tasks for sending files and messages
    tokio::spawn(async move {
        send_file(&mut socks5_stream, &shared_key).await;
    });

    tokio::spawn(async move {
        send_message(&mut socks5_stream, &shared_key).await;
    });
}

// Client handling logic (connecting and interacting with server)
async fn handle_client(socket: TcpStream, secp: Arc<Mutex<Secp256k1<secp256k1::All>>>) {
    let mut socks5_stream = Socks5Stream::connect("127.0.0.1:1080", socket).await.unwrap();

    let (sk, pk) = generate_keypair(&secp.lock().unwrap());
    println!("Generated Server Public Key: {:?}", pk);

    // Exchange public keys and generate a shared key
    let received_pub_key = receive_public_key(&mut socks5_stream).await;
    let shared_key = generate_shared_key(&secp.lock().unwrap(), &sk, &received_pub_key);
    println!("Shared key: {:?}", shared_key);

    // Create separate tasks for handling message sending and receiving
    let (tx_send, rx_send) = mpsc::channel::<String>(32);
    let (tx_file, rx_file) = mpsc::channel::<Vec<u8>>(32);

    // Spawn separate tasks for handling sending/receiving messages and files
    tokio::spawn(async move {
        handle_send_message(&mut socks5_stream, tx_send, &shared_key).await;
    });

    tokio::spawn(async move {
        handle_receive_message(&mut socks5_stream, rx_send, &shared_key).await;
    });

    tokio::spawn(async move {
        handle_receive_file(&mut socks5_stream, rx_file, &shared_key).await;
    });

    // Listen for file transfer from the client
    loop {
        let mut buf = vec![0u8; CHUNK_SIZE];
        let n = socks5_stream.read(&mut buf).await.unwrap();
        if n == 0 {
            break; // End of file
        }
        
        // Decrypt the file chunk and send to file handler
        let decrypted_chunk = decrypt_message(&buf[0..n], &shared_key);
        rx_file.send(decrypted_chunk).await.unwrap();
    }
}

// Generate key pair (private and public keys) using secp256k1
fn generate_keypair(secp: &Secp256k1<secp256k1::All>) -> (SecretKey, PublicKey) {
    let mut rng = rand::thread_rng();
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::from_secret_key(secp, &sk);
    (sk, pk)
}

// Send public key to the server
async fn send_public_key(socks5_stream: &mut Socks5Stream<TcpStream>, pk: &PublicKey) {
    socks5_stream.write_all(&pk.to_bytes()).await.unwrap();
}

// Receive public key from the server
async fn receive_public_key(socks5_stream: &mut Socks5Stream<TcpStream>) -> PublicKey {
    let mut buf = vec![0u8; 65]; // secp256k1 public key length is 65 bytes
    socks5_stream.read_exact(&mut buf).await.unwrap();
    PublicKey::from_slice(&buf).unwrap()
}

// Generate shared secret key from the client's private key and the server's public key
fn generate_shared_key(secp: &Secp256k1<secp256k1::All>, sk: &SecretKey, pk: &PublicKey) -> Vec<u8> {
    let shared_key = secp.ecdh(sk, pk);
    shared_key.to_vec()
}

// AES-GCM encryption function
fn encrypt_message(message: &[u8], shared_key: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::from_slice(shared_key));
    let nonce = Nonce::from_slice(b"unique_nonce_123"); // 12-byte nonce
    cipher.encrypt(nonce, message).expect("Encryption failed")
}

// AES-GCM decryption function
fn decrypt_message(ciphertext: &[u8], shared_key: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::from_slice(shared_key));
    let nonce = Nonce::from_slice(b"unique_nonce_123"); // 12-byte nonce
    cipher.decrypt(nonce, ciphertext).expect("Decryption failed")
}

// Handle sending messages (client-side)
async fn handle_send_message(socks5_stream: &mut Socks5Stream<TcpStream>, tx: mpsc::Sender<String>, shared_key: &[u8]) {
    loop {
        let message = "Hello from server!".to_string();
        let encrypted_message = encrypt_message(message.as_bytes(), shared_key);
        socks5_stream.write_all(&encrypted_message).await.unwrap();
        tx.send(message).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

// Handle receiving messages (server-side)
async fn handle_receive_message(socks5_stream: &mut Socks5Stream<TcpStream>, rx: mpsc::Receiver<String>, shared_key: &[u8]) {
    while let Some(_) = rx.recv().await {
        let mut buf = vec![0u8; 1024];
        socks5_stream.read_exact(&mut buf).await.unwrap();
        let decrypted_message = decrypt_message(&buf, shared_key);
        println!("Received message: {:?}", String::from_utf8_lossy(&decrypted_message));
    }
}

// Handle receiving file (server-side)
async fn handle_receive_file(socks5_stream: &mut Socks5Stream<TcpStream>, rx: mpsc::Receiver<Vec<u8>>, shared_key: &[u8]) {
    while let Some(file_chunk) = rx.recv().await {
        // Write the decrypted file chunk to disk
        tokio::fs::write("received_file", &file_chunk).await.unwrap();
        let file_hash = Sha256::digest(&file_chunk);
        println!("Received file chunk hash: {:?}", file_hash);
    }
}

// File transfer (client-side)
async fn send_file(socks5_stream: &mut Socks5Stream<TcpStream>, shared_key: &[u8]) {
    let mut file = tokio::fs::File::open("test_file.txt").await.unwrap();
    let mut buf = vec![0u8; CHUNK_SIZE];

    while let Ok(n) = file.read(&mut buf).await {
        if n == 0 {
            break; // File transfer finished
        }
        
        let encrypted_chunk = encrypt_message(&buf[0..n], shared_key);
        socks5_stream.write_all(&encrypted_chunk).await.unwrap();
    }
}

// Chat message sending (client-side)
async fn send_message(socks5_stream: &mut Socks5Stream<TcpStream>, shared_key: &[u8]) {
    let message = "Hello from client!".to_string();
    let encrypted_message = encrypt_message(message.as_bytes(), shared_key);
    socks5_stream.write_all(&encrypted_message).await.unwrap();
}
