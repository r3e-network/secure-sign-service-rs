// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # Mock Command - Development and Testing Mode
//!
//! This module implements a simplified development version of the Secure Sign Service
//! that bypasses the full two-phase security protocol. Instead of the secure
//! Diffie-Hellman + AES-GCM wallet decryption process, it accepts the passphrase
//! directly as a command-line argument.
//!
//! ## 🚨 SECURITY WARNING 🚨
//!
//! **This mode is intended ONLY for development and testing purposes.**
//! It has significant security limitations:
//!
//! - Passphrase exposed in command line (visible in process lists)
//! - No perfect forward secrecy (no ephemeral keys)
//! - No authenticated encryption of passphrase transmission
//! - Single-phase operation (no secure wallet decryption protocol)
//!
//! ## When to Use Mock Mode
//!
//! - **Development**: Rapid iteration without complex client setup
//! - **Testing**: Automated testing scenarios with known passphrases
//! - **Debugging**: Simplified setup for troubleshooting functionality
//! - **CI/CD**: Continuous integration with controlled environments
//!
//! ## Production Deployment
//!
//! For production environments, always use the `run` command which implements
//! the full security protocol with separate wallet decryption step.

use secure_sign_core::neo::{nep6::Nep6Wallet, sign::AccountDecrypting};
#[allow(unused_imports)]
use secure_sign_rpc::startup::StartSigner;
use tokio::sync::oneshot;

#[allow(unused_imports)]
use crate::startup::DefaultStartSigner;

/// Mock command configuration for development and testing
///
/// This command provides a simplified interface that combines wallet loading
/// and passphrase provision in a single step, bypassing the secure two-phase
/// protocol used in production.
#[derive(clap::Args)]
#[command(about = "Run the mock secure-sign-service")]
pub(crate) struct MockCmd {
    /// Path to the encrypted NEP-6 wallet file
    ///
    /// The wallet file must be in standard NEP-6 format. Unlike the production
    /// `run` command, the mock command will immediately decrypt this wallet
    /// using the provided passphrase.
    #[arg(long, help = "The wallet file path")]
    pub wallet: String,

    /// Network port for service binding
    ///
    /// The mock service binds to localhost (127.0.0.1) on this port.
    /// Unlike production mode, only the signing service runs (no startup service).
    #[arg(
        long,
        help = "The listen port(listening on localhost)",
        default_value = "9991"
    )]
    pub port: u16,

    /// VSOCK context identifier for TEE environments
    ///
    /// When VSOCK feature is enabled, this determines the communication method:
    /// - VSOCK transport for TEE environments
    /// - Same behavior as production mode for transport selection
    #[cfg(feature = "vsock")]
    #[arg(long, help = "The vsock context identifier", default_value = "0")]
    pub cid: u32,

    /// Wallet decryption passphrase (DEVELOPMENT ONLY)
    ///
    /// ⚠️  **SECURITY RISK**: This passphrase will be visible in:
    /// - Command line history
    /// - Process lists (ps, htop, etc.)
    /// - Shell completion
    /// - System logs
    ///
    /// **Never use this mode in production environments.**
    #[arg(long, help = "The passphrase of the wallet")]
    pub passphrase: String,
}

impl MockCmd {
    /// Start the mock signing service with direct passphrase decryption
    ///
    /// This method implements a simplified workflow that bypasses the secure
    /// startup protocol:
    ///
    /// 1. **Load Wallet**: Read and parse the encrypted NEP-6 wallet file
    /// 2. **Direct Decryption**: Decrypt accounts using the provided passphrase
    /// 3. **Start Service**: Launch the signing service directly with decrypted keys
    ///
    /// ## Differences from Production Mode
    ///
    /// - **No Startup Service**: No separate wallet decryption protocol
    /// - **No Key Exchange**: No Diffie-Hellman ephemeral key generation
    /// - **No Encrypted Transport**: Passphrase provided in plaintext
    /// - **Single Phase**: Direct transition to signing service
    ///
    /// ## Development Benefits
    ///
    /// - **Faster Setup**: No separate client needed for wallet decryption
    /// - **Simpler Testing**: Direct service startup for automated tests
    /// - **Easier Debugging**: Immediate service availability
    /// - **Known State**: Predictable initialization for development
    ///
    /// # Returns
    /// * `Ok(Sender)` - Shutdown channel for graceful service termination
    /// * `Err` - Wallet loading, decryption, or service startup failure
    ///
    /// # Example Usage
    /// ```bash
    /// # Development with TCP transport
    /// ./secure-sign mock --wallet config/test_wallet.json --passphrase "dev123" --port 9991
    ///
    /// # Development with VSOCK transport
    /// ./secure-sign mock --wallet config/test_wallet.json --passphrase "dev123" --cid 3 --port 9991
    /// ```
    ///
    /// # Security Notes
    /// - The passphrase argument will be visible in shell history
    /// - Process lists will show the passphrase in command arguments
    /// - No protection against memory dumps or system monitoring
    /// - Should never be used with production wallets or real keys
    pub fn run(&self) -> Result<oneshot::Sender<()>, Box<dyn std::error::Error>> {
        // Load and immediately decrypt the wallet using the provided passphrase
        // This bypasses the secure Diffie-Hellman + AES-GCM protocol
        #[allow(unused)]
        let accounts = {
            // Read the NEP-6 wallet file from disk
            let content = std::fs::read_to_string(&self.wallet)?;
            let wallet: Nep6Wallet = serde_json::from_str(&content)?;

            // Directly decrypt accounts using the plaintext passphrase
            // This performs scrypt key derivation and AES decryption
            wallet.decrypt_accounts(self.passphrase.as_bytes())?
        };

        // Start the appropriate signing service based on transport configuration
        // Unlike production mode, there's no startup service - we go directly to signing

        #[cfg(feature = "vsock")]
        return DefaultStartSigner::with_vsock(self.cid, self.port).start(accounts);

        #[cfg(not(feature = "vsock"))]
        return DefaultStartSigner::with_tcp(self.port).start(accounts);
    }
}
