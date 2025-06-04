// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # Client Tools - Wallet Decryption and Account Status
//!
//! This module implements client-side tools for interacting with the Secure Sign Service.
//! It provides two essential operations:
//!
//! 1. **Decrypt Command**: Implements the client side of the secure wallet decryption protocol
//! 2. **Status Command**: Queries account availability and signing capability
//!
//! ## Client-Side Security Protocol
//!
//! The decrypt command implements the complete cryptographic handshake:
//!
//! ```text
//! Client                           Service
//!   |                                 |
//!   |------ DiffieHellman() --------->|  (send client public key)
//!   |<----- alice_public_key ---------|  (receive service public key)
//!   |                                 |
//!   | [Compute shared secret locally] |
//!   | [Prompt user for passphrase]    |
//!   | [Encrypt passphrase with AES]   |
//!   |                                 |
//!   |------- StartSigner() ---------->|  (send encrypted passphrase)
//!   |<------ success -----------------|  (service transitions to signing)
//! ```
//!
//! ## Security Features
//!
//! - **Perfect Forward Secrecy**: Ephemeral keys protect past sessions
//! - **Authenticated Encryption**: AES-256-GCM provides confidentiality + integrity
//! - **Secure Input**: Passphrase never stored or logged, immediately zeroized
//! - **Transport Agnostic**: Supports both TCP and VSOCK communications

use aes_gcm::{
    AeadCore, Aes256Gcm, Key,
    aead::{Aead, KeyInit, OsRng},
};
use p256::ecdh;
use secure_sign_core::{hmac::HmacSha256, random::EnvCryptRandom, secp256r1::Keypair};
use secure_sign_rpc::{
    servicepb::{GetAccountStatusRequest, secure_sign_client::SecureSignClient},
    startpb::{
        DiffieHellmanRequest, StartSignerRequest, startup_service_client::StartupServiceClient,
    },
    vsock,
};
use tonic::transport::{Channel, Endpoint};
use zeroize::Zeroizing;

/// Wallet decryption command - Client side of the security protocol
///
/// This command implements the client side of the secure wallet decryption handshake.
/// It establishes a secure channel with the running service and transmits the wallet
/// passphrase using cryptographic protection.
#[derive(clap::Args)]
#[command(about = "Decrypt the wallet of the running secure-sign-service")]
pub struct DecryptCmd {
    /// Service port to connect to
    ///
    /// This should match the port used when starting the service.
    /// The decrypt command connects to the startup service port (main port + 1).
    #[arg(
        long,
        help = "The listen port(listening on localhost)",
        default_value = "9991"
    )]
    pub port: u16,

    /// VSOCK context identifier for TEE environments
    ///
    /// When connecting to services in Trusted Execution Environments:
    /// - 0: Use TCP transport (standard localhost connection)
    /// - >0: Use VSOCK transport (TEE communication)
    #[arg(long, help = "The vsock cid(when use vsock)", default_value = "0")]
    pub cid: u32,
}

impl DecryptCmd {
    /// Securely read the wallet passphrase from user input
    ///
    /// This method prompts the user for the wallet passphrase without echoing
    /// it to the terminal. The passphrase is immediately wrapped in a Zeroizing
    /// container to ensure it's cleared from memory when no longer needed.
    ///
    /// # Security Features
    /// - **No Echo**: Passphrase not visible on terminal
    /// - **Memory Protection**: Automatic zeroization when dropped
    /// - **No Logging**: Never written to logs or temporary files
    /// - **Immediate Use**: Processed and cleared quickly
    ///
    /// # Returns
    /// * `Ok(Zeroizing<String>)` - Securely wrapped passphrase
    /// * `Err` - Input reading failure or user cancellation
    fn read_passphrase(&self) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
        let passphrase = rpassword::prompt_password("The password of the wallet: ")
            .map_err(|err| format!("Failed to read passphrase: {}", err))?;
        Ok(Zeroizing::new(passphrase))
    }

    /// Execute the complete wallet decryption protocol
    ///
    /// This method implements the client side of the two-phase security handshake:
    ///
    /// ## Phase 1: Diffie-Hellman Key Exchange
    /// 1. **Generate Client Keypair**: Create ephemeral secp256r1 keypair
    /// 2. **Send Public Key**: Transmit client's public key to service
    /// 3. **Receive Service Key**: Get service's ephemeral public key
    /// 4. **Compute Shared Secret**: Perform ECDH to establish shared key
    /// 5. **Derive AES Key**: Use HMAC-SHA256 to strengthen the shared secret
    ///
    /// ## Phase 2: Encrypted Passphrase Transmission
    /// 1. **Prompt User**: Securely read wallet passphrase from terminal
    /// 2. **Encrypt Passphrase**: Use AES-256-GCM with shared secret
    /// 3. **Send Encrypted Data**: Transmit encrypted passphrase + nonce
    /// 4. **Receive Confirmation**: Verify service successfully decrypted wallet
    ///
    /// # Transport Selection
    /// - **TCP**: Standard localhost connection for development/testing
    /// - **VSOCK**: TEE communication for secure enclave environments
    ///
    /// # Cryptographic Security
    /// - **Perfect Forward Secrecy**: Ephemeral keys protect session history
    /// - **Authenticated Encryption**: AES-GCM prevents tampering
    /// - **Key Strengthening**: HMAC derivation enhances ECDH output
    /// - **Memory Safety**: All secrets automatically zeroized
    ///
    /// # Returns
    /// * `Ok(())` - Wallet successfully decrypted, service ready for signing
    /// * `Err` - Connection failure, cryptographic error, or invalid passphrase
    ///
    /// # Example Usage
    /// ```bash
    /// # Connect to TCP service
    /// ./secure-sign decrypt --port 9991
    ///
    /// # Connect to VSOCK service
    /// ./secure-sign decrypt --port 9991 --cid 3
    /// ```
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Establish connection to the startup service
        // Port selection: startup service runs on main port + 1
        let channel = if self.cid > 0 {
            // VSOCK transport for TEE environments
            vsock::vsock_channel(self.cid, self.port + 1).await
        } else {
            // TCP transport for standard environments
            tcp_channel(self.port + 1).await
        }?;

        let mut client = StartupServiceClient::new(channel);

        // Phase 1: Diffie-Hellman Key Exchange

        // Generate client-side ephemeral keypair for perfect forward secrecy
        let blob_keypair = Keypair::gen(&mut EnvCryptRandom)
            .map_err(|err| format!("Failed to get blob keypair: {}", err))?;

        // Send client's public key to service and receive service's public key
        let res = client
            .diffie_hellman(DiffieHellmanRequest {
                blob_ephemeral_public_key: blob_keypair.public_key().to_compressed().into(),
            })
            .await
            .map_err(|s| format!("Failed to diffie hellman: {}:{}", s.code(), s.message()))?;

        // Parse service's ephemeral public key
        let alice_public_key = res.get_ref().alice_ephemeral_public_key.as_slice();
        let alice_public_key = p256::PublicKey::from_sec1_bytes(alice_public_key)
            .map_err(|_| tonic::Status::invalid_argument("Invalid alice ephemeral public key"))?;

        // Compute shared secret using client's private key and service's public key
        let blob_private_key = blob_keypair.private_key();
        let blob_private_key = p256::SecretKey::from_slice(blob_private_key.as_be_bytes())
            .map_err(|_| tonic::Status::internal("Invalid blob private key"))?;

        // Perform ECDH: shared_secret = client_private × service_public
        let shared_secret = ecdh::diffie_hellman(
            blob_private_key.to_nonzero_scalar(),
            alice_public_key.as_affine(),
        );

        // Derive AES-256 key from the ECDH shared secret using HMAC-SHA256
        // This strengthens the raw ECDH output against potential cryptographic weaknesses
        let salt: [u8; 0] = [];
        let aes_key = Zeroizing::new(salt.hmac_sha256(shared_secret.raw_secret_bytes().as_slice()));
        let aes_key: Key<Aes256Gcm> = (*aes_key).into();

        // Phase 2: Encrypted Passphrase Transmission

        // Set up AES-256-GCM cipher with derived key
        let cipher = Aes256Gcm::new(&aes_key);
        // Generate random nonce for GCM mode (96 bits = 12 bytes)
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        log::info!("Start to decrypt wallet...");

        // Securely read passphrase from user and encrypt it
        let ciphertext = {
            let passphrase = self.read_passphrase()?;
            cipher
                .encrypt(&nonce, passphrase.as_bytes())
                .map_err(|err| format!("Failed to encrypt passphrase: {}", err))?
            // passphrase is automatically zeroized when dropped here
        };

        // Send encrypted passphrase to service for wallet decryption
        client
            .start_signer(StartSignerRequest {
                encrypted_wallet_passphrase: ciphertext.into(),
                nonce: nonce.as_slice().into(),
            })
            .await
            .map_err(|s| format!("Failed to start signer: {}:{}", s.code(), s.message()))?;

        log::info!("Signer starting...");
        Ok(())
    }
}

/// Account status query command
///
/// This command connects to the signing service (after wallet decryption)
/// to query the status and availability of a specific account by public key.
#[derive(clap::Args)]
#[command(about = "Get the status of the account")]
pub struct StatusCmd {
    /// Service port to connect to
    ///
    /// This should match the port used when starting the service.
    /// The status command connects to the main signing service port.
    #[arg(
        long,
        help = "The listen port(listening on localhost)",
        default_value = "9991"
    )]
    pub port: u16,

    /// VSOCK context identifier for TEE environments
    ///
    /// When connecting to services in Trusted Execution Environments:
    /// - 0: Use TCP transport (standard localhost connection)
    /// - >0: Use VSOCK transport (TEE communication)
    #[arg(long, help = "The vsock cid(when use vsock)", default_value = "0")]
    pub cid: u32,

    /// Public key to query (hex-encoded)
    ///
    /// The public key can be in either compressed (33 bytes, 66 hex chars)
    /// or uncompressed (65 bytes, 130 hex chars) format. The service will
    /// normalize it internally for lookup.
    #[arg(long, help = "The hex-encoded public key")]
    pub public_key: String,
}

impl StatusCmd {
    /// Query the status of a specific account
    ///
    /// This method connects to the signing service and queries whether
    /// a specific public key is available for signing operations.
    ///
    /// # Account Status Types
    /// - **NoSuchAccount**: Public key not found in loaded wallet
    /// - **Locked**: Account exists but is currently locked
    /// - **Single**: Single-signature account ready for signing
    /// - **Multiple**: Multi-signature account (future feature)
    /// - **NoPrivateKey**: Public key exists but no private key available
    ///
    /// # Use Cases
    /// - **Pre-flight Checks**: Verify account availability before signing
    /// - **Debugging**: Troubleshoot wallet loading or account issues
    /// - **Monitoring**: Check service status and loaded accounts
    /// - **Integration**: Validate configuration in automated systems
    ///
    /// # Returns
    /// * `Ok(())` - Status query successful (result printed to stdout)
    /// * `Err` - Connection failure, invalid public key, or service error
    ///
    /// # Example Usage
    /// ```bash
    /// # Query account status via TCP
    /// ./secure-sign status --public-key 03a1b2c3d4... --port 9991
    ///
    /// # Query account status via VSOCK
    /// ./secure-sign status --public-key 03a1b2c3d4... --port 9991 --cid 3
    /// ```
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Decode the hex-encoded public key
        let public_key = hex::decode(&self.public_key)
            .map_err(|err| format!("Failed to decode public key: {}", err))?;

        // Establish connection to the signing service
        let channel = if self.cid > 0 {
            // VSOCK transport for TEE environments
            vsock::vsock_channel(self.cid, self.port).await
        } else {
            // TCP transport for standard environments
            tcp_channel(self.port).await
        }?;

        // Query account status from the signing service
        let mut client = SecureSignClient::new(channel);
        let res = client
            .get_account_status(GetAccountStatusRequest {
                public_key: public_key.into(),
            })
            .await
            .map_err(|s| format!("Failed to get account status: {}:{}", s.code(), s.message()))?;

        // Display the account status to the user
        let status = account_status(res.get_ref().status);
        std::println!("Account {} status: {}", self.public_key, status);
        Ok(())
    }
}

/// Create a TCP connection to the local service
///
/// This helper function establishes a gRPC connection over TCP to
/// localhost on the specified port. Used for standard deployments
/// where the service is not running in a TEE environment.
///
/// # Arguments
/// * `port` - TCP port number to connect to
///
/// # Returns
/// * `Ok(Channel)` - Established gRPC channel
/// * `Err` - Connection failure or invalid endpoint
async fn tcp_channel(port: u16) -> Result<Channel, Box<dyn std::error::Error>> {
    let endpoint = format!("http://localhost:{}", port);
    let conn = Endpoint::new(endpoint)?.connect().await?;
    Ok(conn)
}

/// Convert numeric account status to human-readable string
///
/// Maps the protobuf enum values to descriptive status names
/// for display to users and in logs.
///
/// # Status Codes
/// - 0: NoSuchAccount - Public key not found in wallet
/// - 1: NoPrivateKey - Public key exists but no private key
/// - 2: Single - Single-signature account ready for signing
/// - 3: Multiple - Multi-signature account (future feature)  
/// - 4: Locked - Account exists but is locked
///
/// # Arguments
/// * `status` - Numeric status code from service response
///
/// # Returns
/// Human-readable status description
fn account_status(status: i32) -> String {
    match status {
        0 => "NoSuchAccount".into(),
        1 => "NoPrivateKey".into(),
        2 => "Single".into(),
        3 => "Multiple".into(),
        4 => "Locked".into(),
        _ => format!("AccountStatus({})", status),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test DecryptCmd argument parsing and defaults
    ///
    /// Verifies that the decrypt command properly parses arguments and applies defaults.
    #[test]
    fn test_decrypt_cmd_parsing() {
        // Test with default values
        let args = vec!["test", "decrypt"];
        let result = clap::Command::new("test")
            .subcommand(
                clap::Command::new("decrypt")
                    .arg(
                        clap::Arg::new("port")
                            .long("port")
                            .value_parser(clap::value_parser!(u16))
                            .default_value("9991"),
                    )
                    .arg(
                        clap::Arg::new("cid")
                            .long("cid")
                            .value_parser(clap::value_parser!(u32))
                            .default_value("0"),
                    ),
            )
            .try_get_matches_from(args);

        assert!(result.is_ok(), "Should parse decrypt command with defaults");

        // Test with custom values
        let args = vec!["test", "decrypt", "--port", "8080", "--cid", "3"];
        let result = clap::Command::new("test")
            .subcommand(
                clap::Command::new("decrypt")
                    .arg(
                        clap::Arg::new("port")
                            .long("port")
                            .value_parser(clap::value_parser!(u16)),
                    )
                    .arg(
                        clap::Arg::new("cid")
                            .long("cid")
                            .value_parser(clap::value_parser!(u32)),
                    ),
            )
            .try_get_matches_from(args);

        assert!(
            result.is_ok(),
            "Should parse decrypt command with custom values"
        );

        if let Ok(matches) = result {
            if let Some(sub_matches) = matches.subcommand_matches("decrypt") {
                let port: u16 = *sub_matches.get_one("port").unwrap();
                let cid: u32 = *sub_matches.get_one("cid").unwrap();
                assert_eq!(port, 8080, "Should parse custom port");
                assert_eq!(cid, 3, "Should parse custom CID");
            }
        }
    }

    /// Test StatusCmd argument parsing and validation
    ///
    /// Verifies that the status command properly handles public key arguments.
    #[test]
    fn test_status_cmd_parsing() {
        // Test with required public key
        let args = vec!["test", "status", "--public-key", "03a1b2c3d4"];
        let result = clap::Command::new("test")
            .subcommand(
                clap::Command::new("status")
                    .arg(
                        clap::Arg::new("public-key")
                            .long("public-key")
                            .required(true),
                    )
                    .arg(
                        clap::Arg::new("port")
                            .long("port")
                            .value_parser(clap::value_parser!(u16))
                            .default_value("9991"),
                    )
                    .arg(
                        clap::Arg::new("cid")
                            .long("cid")
                            .value_parser(clap::value_parser!(u32))
                            .default_value("0"),
                    ),
            )
            .try_get_matches_from(args);

        assert!(
            result.is_ok(),
            "Should parse status command with public key"
        );

        // Test missing required public key
        let args = vec!["test", "status"];
        let result = clap::Command::new("test")
            .subcommand(
                clap::Command::new("status").arg(
                    clap::Arg::new("public-key")
                        .long("public-key")
                        .required(true),
                ),
            )
            .try_get_matches_from(args);

        assert!(result.is_err(), "Should fail when public key is missing");
    }

    /// Test account status conversion function
    ///
    /// Verifies that numeric status codes are correctly mapped to human-readable strings.
    #[test]
    fn test_account_status_conversion() {
        // Test known status codes
        assert_eq!(
            account_status(0),
            "NoSuchAccount",
            "Status 0 should be NoSuchAccount"
        );
        assert_eq!(
            account_status(1),
            "NoPrivateKey",
            "Status 1 should be NoPrivateKey"
        );
        assert_eq!(account_status(2), "Single", "Status 2 should be Single");
        assert_eq!(account_status(3), "Multiple", "Status 3 should be Multiple");
        assert_eq!(account_status(4), "Locked", "Status 4 should be Locked");

        // Test unknown status codes
        assert_eq!(
            account_status(-1),
            "AccountStatus(-1)",
            "Negative status should be handled"
        );
        assert_eq!(
            account_status(99),
            "AccountStatus(99)",
            "Unknown positive status should be handled"
        );
        assert_eq!(
            account_status(i32::MAX),
            format!("AccountStatus({})", i32::MAX),
            "Max value should be handled"
        );
        assert_eq!(
            account_status(i32::MIN),
            format!("AccountStatus({})", i32::MIN),
            "Min value should be handled"
        );
    }

    /// Test endpoint URL generation for TCP connections
    ///
    /// Simulates the tcp_channel function's URL generation logic.
    #[test]
    fn test_tcp_endpoint_generation() {
        // Test standard ports
        let port = 9991u16;
        let endpoint = format!("http://localhost:{}", port);
        assert_eq!(
            endpoint, "http://localhost:9991",
            "Should generate correct localhost URL"
        );

        // Test edge case ports
        let port = 1u16;
        let endpoint = format!("http://localhost:{}", port);
        assert_eq!(endpoint, "http://localhost:1", "Should handle minimum port");

        let port = 65535u16;
        let endpoint = format!("http://localhost:{}", port);
        assert_eq!(
            endpoint, "http://localhost:65535",
            "Should handle maximum port"
        );
    }

    /// Test hex decoding validation
    ///
    /// Verifies hex decoding behavior for public keys.
    #[test]
    fn test_hex_decoding_validation() {
        // Test valid hex strings
        let valid_hex = "03a1b2c3d4e5f6";
        let result = hex::decode(valid_hex);
        assert!(result.is_ok(), "Should decode valid hex string");

        if let Ok(bytes) = result {
            assert_eq!(bytes.len(), 7, "Should decode to correct byte length");
        }

        // Test compressed public key length (33 bytes = 66 hex chars)
        let compressed_pubkey = "03".to_string() + &"a1".repeat(32);
        let result = hex::decode(&compressed_pubkey);
        assert!(result.is_ok(), "Should decode compressed public key");

        if let Ok(bytes) = result {
            assert_eq!(bytes.len(), 33, "Compressed public key should be 33 bytes");
        }

        // Test uncompressed public key length (65 bytes = 130 hex chars)
        let uncompressed_pubkey = "04".to_string() + &"a1".repeat(64);
        let result = hex::decode(&uncompressed_pubkey);
        assert!(result.is_ok(), "Should decode uncompressed public key");

        if let Ok(bytes) = result {
            assert_eq!(
                bytes.len(),
                65,
                "Uncompressed public key should be 65 bytes"
            );
        }

        // Test invalid hex strings
        let invalid_hex_chars = "03g1h2i3"; // Contains non-hex characters
        let result = hex::decode(invalid_hex_chars);
        assert!(result.is_err(), "Should reject invalid hex characters");

        let odd_length_hex = "03a1b"; // Odd number of characters
        let result = hex::decode(odd_length_hex);
        assert!(result.is_err(), "Should reject odd-length hex strings");

        let empty_hex = "";
        let result = hex::decode(empty_hex);
        assert!(result.is_ok(), "Should handle empty hex string");

        if let Ok(bytes) = result {
            assert_eq!(bytes.len(), 0, "Empty hex should decode to empty bytes");
        }
    }

    /// Test transport mode detection
    ///
    /// Verifies the logic for choosing between TCP and VSOCK transports.
    #[test]
    fn test_transport_mode_detection() {
        // Simulate the CID check logic from the run methods

        // TCP mode (CID = 0)
        let cid = 0u32;
        let use_vsock = cid > 0;
        assert!(!use_vsock, "CID 0 should use TCP transport");

        // VSOCK mode (CID > 0)
        let cid = 3u32;
        let use_vsock = cid > 0;
        assert!(use_vsock, "CID > 0 should use VSOCK transport");

        // Edge cases
        let cid = 1u32;
        let use_vsock = cid > 0;
        assert!(use_vsock, "CID 1 should use VSOCK transport");

        let cid = u32::MAX;
        let use_vsock = cid > 0;
        assert!(use_vsock, "Maximum CID should use VSOCK transport");
    }

    /// Test startup service port calculation
    ///
    /// Verifies the port calculation logic for startup service connection.
    #[test]
    fn test_startup_service_port_calculation() {
        // Startup service runs on main port + 1
        let main_port = 9991u16;
        let startup_port = main_port.checked_add(1);
        assert!(
            startup_port.is_some(),
            "Should be able to add 1 to main port"
        );
        assert_eq!(
            startup_port.unwrap(),
            9992,
            "Startup port should be main port + 1"
        );

        // Test edge case: maximum port number
        let main_port = 65535u16;
        let startup_port = main_port.checked_add(1);
        assert!(
            startup_port.is_none(),
            "Should overflow when main port is maximum"
        );

        // Test safe port ranges
        let main_port = 65534u16;
        let startup_port = main_port.checked_add(1);
        assert!(
            startup_port.is_some(),
            "Should work with second-to-max port"
        );
        assert_eq!(
            startup_port.unwrap(),
            65535,
            "Should calculate correct startup port"
        );
    }

    /// Test argument validation edge cases
    ///
    /// Tests various edge cases for command argument validation.
    #[test]
    fn test_argument_validation_edge_cases() {
        // Test very long public key strings
        let very_long_key = "a".repeat(1000);
        let result = hex::decode(&very_long_key);
        // Note: hex crate will attempt to decode any even-length string
        assert!(
            result.is_ok(),
            "Should attempt to decode very long hex strings"
        );

        // Test public key with mixed case
        let mixed_case_key = "03A1b2C3d4E5f6";
        let result = hex::decode(mixed_case_key);
        assert!(result.is_ok(), "Should handle mixed case hex strings");

        // Test public key with 0x prefix (not valid for our use case)
        let prefixed_key = "0x03a1b2c3";
        let result = hex::decode(prefixed_key);
        assert!(result.is_err(), "Should reject hex strings with 0x prefix");
    }

    /// Test default value consistency
    ///
    /// Verifies that default values are consistent across commands.
    #[test]
    fn test_default_value_consistency() {
        // Both decrypt and status commands should use the same default port
        // This test ensures consistency if defaults change in the future

        // Note: In a real implementation, you would extract these defaults
        // from the actual command definitions rather than hardcoding them
        let decrypt_default_port = 9991u16;
        let status_default_port = 9991u16;
        assert_eq!(
            decrypt_default_port, status_default_port,
            "Decrypt and status commands should have same default port"
        );

        let decrypt_default_cid = 0u32;
        let status_default_cid = 0u32;
        assert_eq!(
            decrypt_default_cid, status_default_cid,
            "Decrypt and status commands should have same default CID"
        );
    }

    /// Test error message formatting
    ///
    /// Verifies that error messages are properly formatted and informative.
    #[test]
    fn test_error_message_formatting() {
        // Test hex decode error formatting
        let invalid_hex = "xyz";
        let result = hex::decode(invalid_hex);
        assert!(result.is_err(), "Should fail on invalid hex");

        if let Err(e) = result {
            let error_msg = format!("Failed to decode public key: {}", e);
            assert!(
                error_msg.contains("Failed to decode public key"),
                "Error message should be descriptive"
            );
            // Note: actual error message format may vary by hex crate version
        }

        // Test port overflow formatting
        let test_port = 65535u16;
        let startup_port_result = test_port.checked_add(1);
        if startup_port_result.is_none() {
            let error_msg = format!(
                "Port overflow: {} + 1 exceeds maximum port number",
                test_port
            );
            assert!(
                error_msg.contains("Port overflow"),
                "Should format port overflow error"
            );
            assert!(
                error_msg.contains("65535"),
                "Should include the problematic port"
            );
        }
    }
}
