// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # SGX Enclave Startup Implementation
//!
//! This module implements the secure startup protocol within an Intel SGX enclave.
//! The enclave provides hardware-enforced security guarantees:
//!
//! - **Memory Protection**: Enclave memory is encrypted and inaccessible to the host OS
//! - **Attestation**: Remote parties can verify the enclave's identity and integrity
//! - **Sealed Storage**: Data can be encrypted to specific enclave measurements
//! - **Side-Channel Protection**: Hardware mitigations against various attacks
//!
//! ## SGX Security Model
//!
//! The enclave implements the same two-phase protocol as the standard service:
//! 1. **Wallet Loading**: NEP-6 wallet data loaded securely into enclave memory
//! 2. **Key Exchange**: Diffie-Hellman protocol with the external client
//! 3. **Wallet Decryption**: AES-GCM decryption of the wallet passphrase
//! 4. **Signing Ready**: Private keys accessible only within the enclave
//!
//! ## State Management
//!
//! The enclave maintains global state that progresses through security phases:
//! - Initial: No wallet loaded
//! - Wallet Loaded: Encrypted wallet in enclave memory
//! - Key Exchanged: Shared secret established with client
//! - Signer Ready: Private keys decrypted and available for signing

use secure_sign_core::hmac::HmacSha256;
use secure_sign_core::neo::nep6::Nep6Wallet;
use secure_sign_core::neo::sign::{AccountDecrypting, Signer};
use secure_sign_core::random::EnvCryptRandom;
use secure_sign_core::secp256r1::{Keypair, KEY_SIZE};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use zeroize::Zeroizing;

use crate::{ErrCode, STATE};

/// Size of the Diffie-Hellman shared secret in bytes
/// Must match AES-256 key size for symmetric encryption
pub(crate) const SHARED_KEY_SIZE: usize = 32;

// SGX Enclave State Progression (for reference)
// const STATE_NOT_STARTED: u32 = 0;      // Initial state, no wallet loaded
// const STATE_STARTED: u32 = 1;          // Wallet loaded into enclave
// const STATE_KEY_EXCHANGED: u32 = 2;    // Shared secret established
// const STATE_SIGNER_STARTED: u32 = 3;   // Private keys decrypted and ready

/// Initialize the SGX enclave with an encrypted NEP-6 wallet
///
/// This function performs the first phase of the SGX security protocol:
/// 1. Validates that the enclave is in a clean initial state
/// 2. Parses the provided NEP-6 wallet data to ensure validity
/// 3. Stores the encrypted wallet in protected enclave memory
///
/// # Security Guarantees
///
/// - **Hardware Protection**: Wallet data is stored in SGX enclave memory
/// - **Host Isolation**: Host OS cannot access the wallet data
/// - **Attestation Ready**: Remote clients can verify enclave integrity
/// - **Memory Encryption**: Intel MEE encrypts all enclave memory
///
/// # Arguments
/// * `nep6_wallet_data` - Serialized NEP-6 wallet in JSON format
///
/// # Returns
/// * `Ok(())` - Wallet successfully loaded into enclave
/// * `Err(ErrCode)` - Invalid state or malformed wallet data
///
/// # State Transition
/// Initial State → Wallet Loaded
pub(crate) fn secure_sign_sgx_startup(nep6_wallet_data: &[u8]) -> Result<(), ErrCode> {
    // Ensure enclave is in clean initial state
    // Multiple startup calls are not allowed for security
    if unsafe { STATE.wallet.is_some() } {
        return Err(ErrCode::InvalidStartupState);
    }
    
    // Parse and validate the NEP-6 wallet structure
    // This ensures the wallet is well-formed before storing in enclave
    let wallet = serde_json::from_slice::<Nep6Wallet>(nep6_wallet_data)
        .map_err(|_| ErrCode::InvalidNep6Wallet)?;

    // Store encrypted wallet in protected enclave memory
    // The wallet remains encrypted until passphrase decryption
    unsafe { STATE.wallet = Some(wallet) };
    Ok(())
}

/// Perform Diffie-Hellman key exchange within the SGX enclave
///
/// This function implements the secure key exchange protocol:
/// 1. Validates the client's ephemeral public key
/// 2. Generates an enclave-side ephemeral keypair using hardware RNG
/// 3. Computes the ECDH shared secret within the enclave
/// 4. Derives the final encryption key using HMAC-SHA256
/// 5. Returns the enclave's public key to establish shared secret
///
/// # SGX Security Features
///
/// - **Hardware RNG**: Uses Intel RDRAND/RDSEED instructions via SGX SDK
/// - **Protected Computation**: All operations occur within enclave boundaries
/// - **Memory Encryption**: Shared secret stored in encrypted enclave memory
/// - **Side-Channel Protection**: Hardware mitigations against timing attacks
///
/// # Arguments
/// * `blob_ephemeral_public_key` - Client's ephemeral public key (SEC1 format)
///
/// # Returns
/// * `Ok([u8; 33])` - Enclave's compressed ephemeral public key
/// * `Err(ErrCode)` - Invalid key, wrong state, or crypto failure
///
/// # State Transition
/// Wallet Loaded → Key Exchanged
pub(crate) fn secure_sign_sgx_diffie_hellman(
    blob_ephemeral_public_key: &[u8],
) -> Result<[u8; KEY_SIZE + 1], ErrCode> {
    // Validate client's ephemeral public key format
    let blob_public_key = p256::PublicKey::from_sec1_bytes(blob_ephemeral_public_key)
        .map_err(|_| ErrCode::InvalidEphemeralPublicKey)?;

    // Ensure wallet has been loaded into enclave
    if unsafe { STATE.wallet.is_none() } {
        return Err(ErrCode::InvalidStartupState);
    }

    // Prevent multiple key exchanges for security
    if unsafe { STATE.shared_secret.is_some() } {
        return Err(ErrCode::AlreadyExchanged);
    }

    // Generate enclave-side ephemeral keypair using hardware RNG
    // SGX provides access to Intel's hardware random number generator
    let alice_keypair = Keypair::gen(&mut EnvCryptRandom).map_err(|_| ErrCode::GenKeypairError)?;

    // Convert to p256 format for ECDH computation
    let alice_private_key = alice_keypair.private_key();
    let alice_private_key = p256::SecretKey::from_slice(alice_private_key.as_be_bytes())
        .map_err(|_| ErrCode::GenKeypairError)?;

    // Perform ECDH within the secure enclave
    // Computation: shared_secret = alice_private × blob_public
    let shared_secret = p256::ecdh::diffie_hellman(
        alice_private_key.to_nonzero_scalar(),
        blob_public_key.as_affine(),
    );

    // Derive the final AES-256 key using HMAC-SHA256
    // This strengthens the raw ECDH output against potential weaknesses
    let salt: [u8; 0] = [];
    unsafe {
        STATE.shared_secret = Some(Zeroizing::new(
            salt.hmac_sha256(shared_secret.raw_secret_bytes().as_slice()),
        ));
    }

    // Return enclave's public key in compressed format
    // Client will use this to compute the same shared secret
    Ok(alice_keypair.public_key().to_compressed())
}

/// Decrypt wallet passphrase and initialize the signing service within SGX
///
/// This function completes the secure startup protocol:
/// 1. Validates the encrypted passphrase and AES-GCM nonce
/// 2. Decrypts the passphrase using the established shared secret
/// 3. Uses the passphrase to decrypt the NEP-6 wallet accounts
/// 4. Initializes the signing service with decrypted private keys
/// 5. Makes private keys available for signing operations within the enclave
///
/// # Security Transition
///
/// After successful execution:
/// - Private keys exist only in encrypted enclave memory
/// - Host OS cannot access private key material
/// - Remote attestation can verify enclave integrity
/// - All signing operations are hardware-protected
///
/// # Arguments
/// * `encrypted_wallet_passphrase` - AES-GCM encrypted passphrase
/// * `nonce` - 12-byte AES-GCM nonce for decryption
///
/// # Returns
/// * `Ok(())` - Wallet successfully decrypted, signing service ready
/// * `Err(ErrCode)` - Decryption failure or invalid state
///
/// # State Transition
/// Key Exchanged → Signer Ready
pub(crate) fn secure_sign_sgx_start_signer(
    encrypted_wallet_passphrase: &[u8],
    nonce: &[u8],
) -> Result<(), ErrCode> {
    // Retrieve the shared secret established during key exchange
    let shared_secret = unsafe { STATE.shared_secret.clone() };
    let Some(shared_secret) = shared_secret else {
        return Err(ErrCode::InvalidStartupState);
    };

    // Set up AES-256-GCM cipher with the derived shared secret
    let key: Key<Aes256Gcm> = (*shared_secret).into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce);

    // Decrypt the wallet passphrase within the secure enclave
    // AES-GCM provides both confidentiality and authenticity
    let wallet_passphrase = cipher
        .decrypt(&nonce, encrypted_wallet_passphrase)
        .map(|x| Zeroizing::new(x))
        .map_err(|_| ErrCode::DecryptPassphraseError)?;

    // Retrieve the encrypted wallet from enclave state
    let wallet = unsafe { STATE.wallet.as_ref() };
    let Some(wallet) = wallet else {
        return Err(ErrCode::InvalidStartupState);
    };

    // Decrypt the NEP-6 wallet accounts using the recovered passphrase
    // This performs scrypt key derivation and AES decryption within the enclave
    let accounts = wallet
        .decrypt_accounts(wallet_passphrase.as_slice())
        .map_err(|_| ErrCode::DecryptWalletError)?;

    // Ensure signing service hasn't already been initialized
    if unsafe { STATE.signer.is_some() } {
        return Err(ErrCode::InvalidStartupState);
    }

    // Initialize the signing service with decrypted accounts
    // Private keys are now accessible within the secure enclave
    unsafe { STATE.signer = Some(Signer::new(accounts)) };
    Ok(())
}
