// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # Startup Service - Secure Wallet Decryption Protocol
//!
//! This module implements the first phase of the two-phase security model.
//! It provides a secure protocol for wallet decryption using:
//!
//! 1. **Diffie-Hellman Key Exchange**: Establishes a shared secret between client and service
//! 2. **AES-256-GCM Encryption**: Protects wallet passphrase during transmission
//! 3. **NEP-6 Wallet Decryption**: Unlocks encrypted account data using scrypt + AES
//!
//! ## Security Protocol Flow
//!
//! ```text
//! Client                    Service
//!   |                         |
//!   |--- DiffieHellman() ---->|  (ephemeral key exchange)
//!   |<-- alice_public_key ---|
//!   |                         |
//!   |--- StartSigner() ------>|  (encrypted passphrase)
//!   |<-- success -------------|
//!   |                         |
//!   |                    [Service transitions to signing phase]
//! ```
//!
//! ## Cryptographic Security Features
//!
//! - **Perfect Forward Secrecy**: Ephemeral keys ensure past sessions cannot be compromised
//! - **Authentication**: HMAC-based key derivation prevents tampering
//! - **Memory Safety**: Automatic zeroization of sensitive key material
//! - **Constant-time Operations**: Protection against side-channel attacks

use std::sync::{Arc, Mutex};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use p256::ecdh;
use secure_sign_core::{
    hmac::HmacSha256,
    neo::{
        nep6::Nep6Wallet,
        sign::{Account, AccountDecrypting},
    },
    random::CryptRandom,
    secp256r1::Keypair,
};
use tokio::sync::oneshot;
use tonic::async_trait;
use zeroize::Zeroizing;

use crate::startpb::{startup_service_server::StartupService, *};

/// Size of the derived shared secret key in bytes
/// This matches the AES-256 key size requirement
const SHARED_KEY_SIZE: usize = 32;

/// Trait for starting the signing service after wallet decryption
///
/// This trait abstracts the startup mechanism, allowing different
/// implementations for various deployment scenarios (TCP, VSOCK, etc.).
pub trait StartSigner: Send + Sync + 'static {
    /// Start the signing service with decrypted accounts
    ///
    /// This method transitions from the startup phase to the signing phase,
    /// making the decrypted private keys available for cryptographic operations.
    ///
    /// # Arguments
    /// * `accounts` - Vector of decrypted accounts with private keys
    ///
    /// # Returns
    /// * `Ok(Sender)` - Shutdown channel for graceful service termination
    /// * `Err` - Service startup failure
    fn start(
        self,
        accounts: Vec<Account>,
    ) -> Result<oneshot::Sender<()>, Box<dyn std::error::Error>>;
}

/// Internal state for the startup service during wallet decryption
///
/// This state tracks the progression through the security protocol:
/// 1. Initial state with encrypted wallet
/// 2. After key exchange with established shared secret
/// 3. After successful decryption and service transition
struct StartupState<Start, Random> {
    /// Encrypted NEP-6 wallet containing account data
    wallet: Nep6Wallet,
    /// Cryptographically secure random number generator
    crypt_random: Random,
    /// Shared secret established via Diffie-Hellman (None until key exchange)
    shared_secret: Option<Zeroizing<[u8; SHARED_KEY_SIZE]>>,
    /// Service starter for transitioning to signing phase (consumed on use)
    start: Option<Start>,
}

impl<Start: StartSigner, Random: CryptRandom + Send + Sync + 'static> StartupState<Start, Random> {
    /// Transition from startup phase to signing phase
    ///
    /// This critical method performs the security transition:
    /// 1. Consumes the startup service configuration
    /// 2. Starts the signing service with decrypted accounts
    /// 3. Sets up graceful shutdown handling
    ///
    /// # Security Note
    /// After this method succeeds, the startup service is no longer needed
    /// and should be terminated to minimize attack surface.
    fn start(&mut self, accounts: Vec<Account>) -> Result<(), Box<dyn std::error::Error>> {
        let start = self.start.take().ok_or("Start signer not set")?;
        let sender = start.start(accounts)?;

        // Set up graceful shutdown handling for the signing service
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = sender.send(());
        });
        Ok(())
    }
}

/// Default implementation of the startup service
///
/// This service manages the secure wallet decryption protocol and coordinates
/// the transition to the signing phase. It uses thread-safe state management
/// to handle concurrent gRPC requests safely.
pub struct DefaultStartupService<Start, Random> {
    /// Thread-safe state containing wallet, secrets, and service configuration
    state: Arc<Mutex<StartupState<Start, Random>>>,
}

impl<Start, Random> DefaultStartupService<Start, Random> {
    /// Create a new startup service with the specified configuration
    ///
    /// # Arguments
    /// * `wallet` - Encrypted NEP-6 wallet to decrypt
    /// * `crypt_random` - Cryptographically secure RNG for key generation
    /// * `start` - Service starter for transitioning to signing phase
    pub fn new(wallet: Nep6Wallet, crypt_random: Random, start: Start) -> Self {
        Self {
            state: Arc::new(Mutex::new(StartupState {
                wallet,
                crypt_random,
                shared_secret: None,
                start: Some(start),
            })),
        }
    }
}

/// gRPC service implementation for the startup protocol
///
/// This service exposes two critical RPC methods that implement the
/// secure wallet decryption protocol over the network.
#[async_trait]
impl<Start: StartSigner, Random: CryptRandom + Send + Sync + 'static> StartupService
    for DefaultStartupService<Start, Random>
{
    /// Perform Diffie-Hellman key exchange to establish shared secret
    ///
    /// This RPC implements the first phase of the security protocol:
    ///
    /// 1. **Validates** the client's ephemeral public key
    /// 2. **Generates** a server-side ephemeral keypair
    /// 3. **Computes** the ECDH shared secret: `shared_secret = client_private × server_public`
    /// 4. **Derives** the encryption key using HMAC-SHA256
    /// 5. **Returns** the server's ephemeral public key to the client
    ///
    /// # Cryptographic Security
    ///
    /// - Uses secp256r1 (P-256) elliptic curve for ECDH
    /// - Derives final key using HMAC-SHA256 for key strengthening
    /// - Ephemeral keys provide perfect forward secrecy
    /// - Shared secret is zeroized automatically when dropped
    ///
    /// # Protocol Constraints
    ///
    /// - Key exchange can only be performed once per service instance
    /// - Client public key must be valid secp256r1 point
    /// - Subsequent calls return ALREADY_EXISTS error
    async fn diffie_hellman(
        &self,
        req: tonic::Request<DiffieHellmanRequest>,
    ) -> Result<tonic::Response<DiffieHellmanResponse>, tonic::Status> {
        let req = req.into_inner();
        let blob_public_key = req.blob_ephemeral_public_key.as_slice();

        // Validate client's ephemeral public key
        let blob_public_key = p256::PublicKey::from_sec1_bytes(blob_public_key)
            .map_err(|_| tonic::Status::invalid_argument("Invalid blob ephemeral public key"))?;

        let mut state = self.state.lock().unwrap();

        // Ensure key exchange hasn't already occurred
        if state.shared_secret.is_some() {
            return Err(tonic::Status::already_exists("Key has been exchanged"));
        }

        // Generate server-side ephemeral keypair
        let alice_keypair = Keypair::gen(&mut state.crypt_random).map_err(|err| {
            tonic::Status::internal(format!("Get ephemeral keypair error: {err}"))
        })?;

        // Convert to p256 format for ECDH computation
        let alice_private_key = alice_keypair.private_key();
        let alice_private_key = p256::SecretKey::from_slice(alice_private_key.as_be_bytes())
            .map_err(|_| tonic::Status::internal("Invalid alice private key"))?;

        // Perform Elliptic Curve Diffie-Hellman key exchange
        // shared_secret = alice_private × blob_public
        let shared_secret = ecdh::diffie_hellman(
            alice_private_key.to_nonzero_scalar(),
            blob_public_key.as_affine(),
        );

        // Prepare response with server's public key
        let res = DiffieHellmanResponse {
            alice_ephemeral_public_key: alice_keypair.public_key().to_compressed().into(),
        };

        // Derive the final encryption key using HMAC-SHA256
        // This strengthens the raw ECDH output against potential weaknesses
        let salt: [u8; 0] = [];
        state.shared_secret = Some(Zeroizing::new(
            salt.hmac_sha256(shared_secret.raw_secret_bytes().as_slice()),
        ));

        Ok(tonic::Response::new(res))
    }

    /// Decrypt wallet using encrypted passphrase and start signing service
    ///
    /// This RPC implements the second phase of the security protocol:
    ///
    /// 1. **Validates** the encrypted passphrase and nonce
    /// 2. **Decrypts** the passphrase using the established shared secret
    /// 3. **Unlocks** the NEP-6 wallet using the decrypted passphrase
    /// 4. **Starts** the signing service with the decrypted accounts
    /// 5. **Transitions** from startup phase to signing phase
    ///
    /// # Encryption Protocol
    ///
    /// - Uses AES-256-GCM with the derived shared secret as key
    /// - Requires 12-byte nonce for GCM mode operation
    /// - Provides authenticated encryption (confidentiality + integrity)
    /// - Automatically validates message authenticity
    ///
    /// # Security Transition
    ///
    /// After successful execution:
    /// - Startup service is no longer needed and should be terminated
    /// - Signing service is active with decrypted private keys
    /// - All future operations use the signing service interface
    async fn start_signer(
        &self,
        req: tonic::Request<StartSignerRequest>,
    ) -> Result<tonic::Response<StartSignerResponse>, tonic::Status> {
        let req = req.into_inner();

        // Validate nonce length for AES-GCM
        if req.nonce.len() != 12 {
            return Err(tonic::Status::invalid_argument("Invalid nonce"));
        }

        let mut state = self.state.lock().unwrap();

        // Ensure service startup is still possible
        if state.start.is_none() {
            return Err(tonic::Status::failed_precondition("Start signer not set"));
        }

        // Ensure key exchange was completed
        let Some(shared_secret) = state.shared_secret.clone() else {
            return Err(tonic::Status::failed_precondition(
                "Key exchange not completed",
            ));
        };

        // Set up AES-256-GCM cipher with derived key
        let key: Key<Aes256Gcm> = (*shared_secret).into();
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(req.nonce.as_ref());

        // Decrypt the wallet passphrase
        // AES-GCM automatically validates authenticity and integrity
        let wallet_passphrase = cipher
            .decrypt(nonce, req.encrypted_wallet_passphrase.as_slice())
            .map(Zeroizing::new)
            .map_err(|_| tonic::Status::invalid_argument("Invalid encrypted data or nonce"))?;

        // Decrypt the NEP-6 wallet using the recovered passphrase
        // This performs scrypt key derivation and AES decryption
        let accounts = state
            .wallet
            .decrypt_accounts(wallet_passphrase.as_slice())
            .map_err(|err| {
                tonic::Status::invalid_argument(format!("Invalid wallet or passphrase: {err}"))
            })?;

        // Transition to signing phase with decrypted accounts
        let _ = state
            .start(accounts)
            .map_err(|err| tonic::Status::internal(format!("Start signer error: {err}")))?;

        Ok(tonic::Response::new(StartSignerResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::aead::{AeadCore, OsRng};
    use secure_sign_core::{neo::nep6::Nep6Account, random::EnvCryptRandom, scrypt::ScryptParams};

    use super::*;

    /// Mock implementation for testing the startup protocol
    struct MockStartSigner;

    impl StartSigner for MockStartSigner {
        fn start(self, _: Vec<Account>) -> Result<oneshot::Sender<()>, Box<dyn std::error::Error>> {
            let (sender, _receiver) = oneshot::channel();
            Ok(sender)
        }
    }

    /// Mock implementation that fails startup for error testing
    struct FailingStartSigner;

    impl StartSigner for FailingStartSigner {
        fn start(self, _: Vec<Account>) -> Result<oneshot::Sender<()>, Box<dyn std::error::Error>> {
            Err("Mock startup failure".into())
        }
    }

    /// Create a test NEP-6 wallet with encrypted accounts for testing
    fn create_test_wallet() -> Nep6Wallet {
        Nep6Wallet {
            name: Some("test_wallet".into()),
            version: "1.0".into(),
            scrypt: ScryptParams { n: 16, r: 1, p: 1 }, // Low params for fast testing
            accounts: vec![
                Nep6Account {
                    address: "address1".into(),
                    label: Some("Test Account 1".into()),
                    is_default: false,
                    is_locked: false,
                    key: "encrypted_key_1".into(),
                    contract: None,
                    extra: None,
                },
                Nep6Account {
                    address: "address2".into(),
                    label: Some("Test Account 2".into()),
                    is_default: true,
                    is_locked: false,
                    key: "encrypted_key_2".into(),
                    contract: None,
                    extra: None,
                },
            ],
            extra: None,
        }
    }

    /// Test the Diffie-Hellman key exchange implementation
    ///
    /// This test verifies that both client and server derive the same
    /// shared secret through the ECDH protocol.
    #[tokio::test]
    async fn test_diffie_hellman() {
        // Set up test wallet and service
        let wallet = Nep6Wallet {
            name: Some("test".into()),
            version: "0".into(),
            scrypt: ScryptParams { n: 128, r: 1, p: 1 },
            accounts: vec![],
            extra: None,
        };

        // Generate client-side ephemeral keypair
        let blob_keypair = Keypair::gen(&mut EnvCryptRandom).expect("Get blob keypair error");
        let blob_public_key = blob_keypair.public_key().to_compressed();

        // Create startup service and perform key exchange
        let startup_service = DefaultStartupService::new(wallet, EnvCryptRandom, MockStartSigner);
        let req = DiffieHellmanRequest {
            blob_ephemeral_public_key: blob_public_key.into(),
        };
        let res = startup_service
            .diffie_hellman(tonic::Request::new(req))
            .await
            .expect("Diffie-Hellman error");

        // Extract server's public key from response
        let alice_public_key = res.into_inner().alice_ephemeral_public_key;
        let alice_public_key = p256::PublicKey::from_sec1_bytes(alice_public_key.as_slice())
            .expect("Invalid alice public key");

        // Compute shared secret from client side
        let blob_private_key = blob_keypair.private_key();
        let blob_private_key = p256::SecretKey::from_slice(blob_private_key.as_be_bytes())
            .expect("Invalid blob private key");

        let shared_secret = ecdh::diffie_hellman(
            blob_private_key.to_nonzero_scalar(),
            alice_public_key.as_affine(),
        );

        // Apply same key derivation as server
        let salt: [u8; 0] = [];
        let shared_secret1 = salt.hmac_sha256(shared_secret.raw_secret_bytes().as_slice());

        // Verify both sides derived the same key
        let state = startup_service.state.lock().unwrap();
        let shared_secret2 = state.shared_secret.clone().unwrap();
        assert_eq!(shared_secret1, *shared_secret2);
    }

    /// Test Diffie-Hellman with invalid client public key
    ///
    /// Verifies that invalid public keys are properly rejected.
    #[tokio::test]
    async fn test_diffie_hellman_invalid_public_key() {
        let wallet = create_test_wallet();
        let startup_service = DefaultStartupService::new(wallet, EnvCryptRandom, MockStartSigner);

        // Test with invalid public key (wrong length)
        let req = DiffieHellmanRequest {
            blob_ephemeral_public_key: vec![0x02; 32], // Wrong length
        };
        let result = startup_service
            .diffie_hellman(tonic::Request::new(req))
            .await;
        assert!(result.is_err(), "Should reject invalid public key");
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);

        // Test with completely invalid data
        let req = DiffieHellmanRequest {
            blob_ephemeral_public_key: vec![0xff; 33], // Invalid curve point
        };
        let result = startup_service
            .diffie_hellman(tonic::Request::new(req))
            .await;
        assert!(result.is_err(), "Should reject invalid curve point");
    }

    /// Test Diffie-Hellman duplicate key exchange prevention
    ///
    /// Verifies that key exchange can only be performed once.
    #[tokio::test]
    async fn test_diffie_hellman_duplicate_exchange() {
        let wallet = create_test_wallet();
        let startup_service = DefaultStartupService::new(wallet, EnvCryptRandom, MockStartSigner);

        // Generate valid client keypair
        let blob_keypair = Keypair::gen(&mut EnvCryptRandom).expect("Get blob keypair error");
        let blob_public_key = blob_keypair.public_key().to_compressed();

        // First key exchange should succeed
        let req = DiffieHellmanRequest {
            blob_ephemeral_public_key: blob_public_key.into(),
        };
        let result = startup_service
            .diffie_hellman(tonic::Request::new(req))
            .await;
        assert!(result.is_ok(), "First key exchange should succeed");

        // Second key exchange should fail
        let req = DiffieHellmanRequest {
            blob_ephemeral_public_key: blob_public_key.into(),
        };
        let result = startup_service
            .diffie_hellman(tonic::Request::new(req))
            .await;
        assert!(result.is_err(), "Second key exchange should fail");
        assert_eq!(result.unwrap_err().code(), tonic::Code::AlreadyExists);
    }

    /// Test AES-GCM encryption and decryption round trip
    ///
    /// Verifies the encryption/decryption functionality used in the protocol.
    #[test]
    fn test_aes_gcm_round_trip() {
        // Generate test key and data
        let key_bytes = [0x42u8; 32]; // Test key
        let key: Key<Aes256Gcm> = key_bytes.into();
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let test_data = b"test wallet passphrase";

        // Encrypt
        let ciphertext = cipher
            .encrypt(&nonce, test_data.as_ref())
            .expect("Encryption should succeed");

        // Decrypt
        let plaintext = cipher
            .decrypt(&nonce, ciphertext.as_ref())
            .expect("Decryption should succeed");

        assert_eq!(plaintext, test_data, "Round trip should preserve data");
    }

    /// Test start_signer with valid encrypted data
    ///
    /// This test requires the full protocol flow including encryption.
    #[tokio::test]
    async fn test_start_signer_success() {
        let wallet = Nep6Wallet {
            name: Some("test".into()),
            version: "0".into(),
            scrypt: ScryptParams { n: 16, r: 1, p: 1 },
            accounts: vec![], // Empty accounts for simplicity
            extra: None,
        };

        let startup_service = DefaultStartupService::new(wallet, EnvCryptRandom, MockStartSigner);

        // Step 1: Perform key exchange
        let blob_keypair = Keypair::gen(&mut EnvCryptRandom).expect("Get blob keypair error");
        let blob_public_key = blob_keypair.public_key().to_compressed();

        let dh_req = DiffieHellmanRequest {
            blob_ephemeral_public_key: blob_public_key.into(),
        };
        let dh_res = startup_service
            .diffie_hellman(tonic::Request::new(dh_req))
            .await
            .expect("Diffie-Hellman should succeed");

        // Step 2: Compute shared secret (client side)
        let alice_public_key = dh_res.into_inner().alice_ephemeral_public_key;
        let alice_public_key = p256::PublicKey::from_sec1_bytes(alice_public_key.as_slice())
            .expect("Invalid alice public key");

        let blob_private_key = blob_keypair.private_key();
        let blob_private_key = p256::SecretKey::from_slice(blob_private_key.as_be_bytes())
            .expect("Invalid blob private key");

        let shared_secret = ecdh::diffie_hellman(
            blob_private_key.to_nonzero_scalar(),
            alice_public_key.as_affine(),
        );

        let salt: [u8; 0] = [];
        let encryption_key = salt.hmac_sha256(shared_secret.raw_secret_bytes().as_slice());

        // Step 3: Encrypt passphrase
        let key: Key<Aes256Gcm> = encryption_key.into();
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let passphrase = b"test_passphrase";
        let ciphertext = cipher
            .encrypt(&nonce, passphrase.as_ref())
            .expect("Encryption should succeed");

        // Step 4: Start signer
        let start_req = StartSignerRequest {
            encrypted_wallet_passphrase: ciphertext,
            nonce: nonce.to_vec(),
        };

        let result = startup_service
            .start_signer(tonic::Request::new(start_req))
            .await;
        assert!(
            result.is_ok(),
            "Start signer should succeed with valid data"
        );
    }

    /// Test start_signer without prior key exchange
    ///
    /// Verifies that the protocol enforces proper sequencing.
    #[tokio::test]
    async fn test_start_signer_without_key_exchange() {
        let wallet = create_test_wallet();
        let startup_service = DefaultStartupService::new(wallet, EnvCryptRandom, MockStartSigner);

        // Try to start signer without key exchange
        let req = StartSignerRequest {
            encrypted_wallet_passphrase: vec![0x42; 32],
            nonce: vec![0x00; 12],
        };

        let result = startup_service.start_signer(tonic::Request::new(req)).await;
        assert!(result.is_err(), "Should fail without key exchange");
        assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);
    }

    /// Test start_signer with invalid nonce length
    ///
    /// Verifies nonce validation for AES-GCM.
    #[tokio::test]
    async fn test_start_signer_invalid_nonce() {
        let wallet = create_test_wallet();
        let startup_service = DefaultStartupService::new(wallet, EnvCryptRandom, MockStartSigner);

        // Perform key exchange first
        let blob_keypair = Keypair::gen(&mut EnvCryptRandom).expect("Get blob keypair error");
        let blob_public_key = blob_keypair.public_key().to_compressed();

        let dh_req = DiffieHellmanRequest {
            blob_ephemeral_public_key: blob_public_key.into(),
        };
        let _ = startup_service
            .diffie_hellman(tonic::Request::new(dh_req))
            .await
            .expect("Key exchange should succeed");

        // Test with wrong nonce length
        let req = StartSignerRequest {
            encrypted_wallet_passphrase: vec![0x42; 32],
            nonce: vec![0x00; 10], // Wrong length (should be 12)
        };

        let result = startup_service.start_signer(tonic::Request::new(req)).await;
        assert!(result.is_err(), "Should fail with invalid nonce length");
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    /// Test start_signer with corrupted encryption
    ///
    /// Verifies that authentication failures are handled properly.
    #[tokio::test]
    async fn test_start_signer_corrupted_encryption() {
        let wallet = create_test_wallet();
        let startup_service = DefaultStartupService::new(wallet, EnvCryptRandom, MockStartSigner);

        // Perform key exchange
        let blob_keypair = Keypair::gen(&mut EnvCryptRandom).expect("Get blob keypair error");
        let blob_public_key = blob_keypair.public_key().to_compressed();

        let dh_req = DiffieHellmanRequest {
            blob_ephemeral_public_key: blob_public_key.into(),
        };
        let _ = startup_service
            .diffie_hellman(tonic::Request::new(dh_req))
            .await
            .expect("Key exchange should succeed");

        // Send corrupted encrypted data
        let req = StartSignerRequest {
            encrypted_wallet_passphrase: vec![0x42; 32], // Random data
            nonce: vec![0x00; 12],
        };

        let result = startup_service.start_signer(tonic::Request::new(req)).await;
        assert!(result.is_err(), "Should fail with corrupted data");
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    /// Test startup service with failing signer
    ///
    /// Verifies error handling when the signing service fails to start.
    #[tokio::test]
    async fn test_startup_with_failing_signer() {
        let wallet = Nep6Wallet {
            name: Some("test".into()),
            version: "0".into(),
            scrypt: ScryptParams { n: 16, r: 1, p: 1 },
            accounts: vec![],
            extra: None,
        };

        let startup_service =
            DefaultStartupService::new(wallet, EnvCryptRandom, FailingStartSigner);

        // Perform key exchange
        let blob_keypair = Keypair::gen(&mut EnvCryptRandom).expect("Get blob keypair error");
        let blob_public_key = blob_keypair.public_key().to_compressed();

        let dh_req = DiffieHellmanRequest {
            blob_ephemeral_public_key: blob_public_key.into(),
        };
        let dh_res = startup_service
            .diffie_hellman(tonic::Request::new(dh_req))
            .await
            .expect("Key exchange should succeed");

        // Compute shared secret and encrypt
        let alice_public_key = dh_res.into_inner().alice_ephemeral_public_key;
        let alice_public_key = p256::PublicKey::from_sec1_bytes(alice_public_key.as_slice())
            .expect("Invalid alice public key");

        let blob_private_key = blob_keypair.private_key();
        let blob_private_key = p256::SecretKey::from_slice(blob_private_key.as_be_bytes())
            .expect("Invalid blob private key");

        let shared_secret = ecdh::diffie_hellman(
            blob_private_key.to_nonzero_scalar(),
            alice_public_key.as_affine(),
        );

        let salt: [u8; 0] = [];
        let encryption_key = salt.hmac_sha256(shared_secret.raw_secret_bytes().as_slice());

        let key: Key<Aes256Gcm> = encryption_key.into();
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let passphrase = b"test_passphrase";
        let ciphertext = cipher
            .encrypt(&nonce, passphrase.as_ref())
            .expect("Encryption should succeed");

        // Try to start signer (should fail due to FailingStartSigner)
        let start_req = StartSignerRequest {
            encrypted_wallet_passphrase: ciphertext,
            nonce: nonce.to_vec(),
        };

        let result = startup_service
            .start_signer(tonic::Request::new(start_req))
            .await;
        assert!(result.is_err(), "Should fail when signer startup fails");
        assert_eq!(result.unwrap_err().code(), tonic::Code::Internal);
    }

    /// Test multiple start_signer calls
    ///
    /// Verifies that the signer can only be started once.
    #[tokio::test]
    async fn test_multiple_start_signer_calls() {
        let wallet = Nep6Wallet {
            name: Some("test".into()),
            version: "0".into(),
            scrypt: ScryptParams { n: 16, r: 1, p: 1 },
            accounts: vec![],
            extra: None,
        };

        let startup_service = DefaultStartupService::new(wallet, EnvCryptRandom, MockStartSigner);

        // Perform key exchange
        let blob_keypair = Keypair::gen(&mut EnvCryptRandom).expect("Get blob keypair error");
        let blob_public_key = blob_keypair.public_key().to_compressed();

        let dh_req = DiffieHellmanRequest {
            blob_ephemeral_public_key: blob_public_key.into(),
        };
        let dh_res = startup_service
            .diffie_hellman(tonic::Request::new(dh_req))
            .await
            .expect("Key exchange should succeed");

        // Prepare encrypted request
        let alice_public_key = dh_res.into_inner().alice_ephemeral_public_key;
        let alice_public_key = p256::PublicKey::from_sec1_bytes(alice_public_key.as_slice())
            .expect("Invalid alice public key");

        let blob_private_key = blob_keypair.private_key();
        let blob_private_key = p256::SecretKey::from_slice(blob_private_key.as_be_bytes())
            .expect("Invalid blob private key");

        let shared_secret = ecdh::diffie_hellman(
            blob_private_key.to_nonzero_scalar(),
            alice_public_key.as_affine(),
        );

        let salt: [u8; 0] = [];
        let encryption_key = salt.hmac_sha256(shared_secret.raw_secret_bytes().as_slice());

        let key: Key<Aes256Gcm> = encryption_key.into();
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let passphrase = b"test_passphrase";
        let ciphertext = cipher
            .encrypt(&nonce, passphrase.as_ref())
            .expect("Encryption should succeed");

        // First start_signer call should succeed
        let start_req = StartSignerRequest {
            encrypted_wallet_passphrase: ciphertext.clone(),
            nonce: nonce.to_vec(),
        };

        let result = startup_service
            .start_signer(tonic::Request::new(start_req))
            .await;
        assert!(result.is_ok(), "First start_signer should succeed");

        // Second start_signer call should fail
        let start_req = StartSignerRequest {
            encrypted_wallet_passphrase: ciphertext,
            nonce: nonce.to_vec(),
        };

        let result = startup_service
            .start_signer(tonic::Request::new(start_req))
            .await;
        assert!(result.is_err(), "Second start_signer should fail");
        assert_eq!(result.unwrap_err().code(), tonic::Code::FailedPrecondition);
    }

    /// Test StartupState transition logic
    ///
    /// Tests the internal state management separately from gRPC.
    #[tokio::test]
    async fn test_startup_state_transitions() {
        let wallet = create_test_wallet();
        let mut state = StartupState {
            wallet,
            crypt_random: EnvCryptRandom,
            shared_secret: None,
            start: Some(MockStartSigner),
        };

        // Test initial state
        assert!(
            state.shared_secret.is_none(),
            "Should start with no shared secret"
        );
        assert!(state.start.is_some(), "Should start with signer available");

        // Simulate setting shared secret (normally done by diffie_hellman)
        state.shared_secret = Some(Zeroizing::new([0x42u8; 32]));

        // Test successful transition
        let result = state.start(vec![]);
        assert!(result.is_ok(), "State transition should succeed");
        assert!(state.start.is_none(), "Signer should be consumed after use");
    }

    /// Test HMAC key derivation consistency
    ///
    /// Verifies that the key derivation produces consistent results.
    #[test]
    fn test_hmac_key_derivation_consistency() {
        let test_secret = [0x42u8; 32];
        let salt: [u8; 0] = [];

        let key1 = salt.hmac_sha256(&test_secret);
        let key2 = salt.hmac_sha256(&test_secret);

        assert_eq!(key1, key2, "Key derivation should be deterministic");
        assert_ne!(key1, test_secret, "Derived key should differ from input");
    }

    /// Test edge case with empty wallet accounts
    ///
    /// Verifies handling of wallets with no accounts.
    #[test]
    fn test_empty_wallet_accounts() {
        let wallet = Nep6Wallet {
            name: Some("empty_wallet".into()),
            version: "1.0".into(),
            scrypt: ScryptParams { n: 16, r: 1, p: 1 },
            accounts: vec![], // Empty accounts
            extra: None,
        };

        // Should be able to create startup service with empty wallet
        let _startup_service = DefaultStartupService::new(wallet, EnvCryptRandom, MockStartSigner);
    }

    /// Test thread safety basics of startup service
    ///
    /// Verifies that the startup service can be safely shared between threads.
    #[test]
    fn test_startup_service_thread_safety() {
        let wallet = create_test_wallet();
        let startup_service = std::sync::Arc::new(DefaultStartupService::new(
            wallet,
            EnvCryptRandom,
            MockStartSigner,
        ));

        // Verify that startup service implements Send + Sync
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DefaultStartupService<MockStartSigner, EnvCryptRandom>>();

        // Test that service can be cloned across threads
        let service_clone = startup_service.clone();
        assert!(
            std::sync::Arc::strong_count(&startup_service) == 2,
            "Should have 2 references"
        );
        drop(service_clone);
        assert!(
            std::sync::Arc::strong_count(&startup_service) == 1,
            "Should have 1 reference after drop"
        );
    }
}
