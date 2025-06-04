// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # Production Service Command (`run`)
//!
//! This module implements the production deployment command for the Secure Sign Service.
//! Unlike the mock command, the `run` command implements the full two-phase security model:
//!
//! ## Phase 1: Startup Service (Wallet Decryption)
//! - Loads encrypted NEP-6 wallet from file
//! - Starts startup service on port+1 (default: 9992)
//! - Accepts secure wallet decryption requests
//! - Implements Diffie-Hellman + AES-GCM protocol
//!
//! ## Phase 2: Signing Service (Cryptographic Operations)
//! - Automatically started after successful wallet decryption
//! - Runs on main port (default: 9991)
//! - Provides signing operations with decrypted keys
//! - Startup service terminates after transition
//!
//! ## Security Features
//! - Never exposes private keys in plaintext
//! - Requires separate client for wallet decryption
//! - Automatic key zeroization on service shutdown
//! - Transport-agnostic (TCP/VSOCK) based on feature flags

#[allow(unused_imports)]
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use secure_sign_core::{neo::nep6::Nep6Wallet, random::EnvCryptRandom};
use secure_sign_rpc::{
    startpb::startup_service_server::StartupServiceServer, startup::DefaultStartupService,
};
use tokio::sync::oneshot;
use tonic::transport::Server;

use crate::startup::DefaultStartSigner;

// Compile-time safety: ensure mutually exclusive transport features
#[cfg(all(feature = "vsock", feature = "tcp"))]
compile_error!("vsock and tcp cannot be both enabled");

/// Production service command configuration
///
/// This command starts the secure signing service in production mode,
/// requiring a separate client interaction for wallet decryption.
#[derive(clap::Args)]
#[command(about = "Run the secure-sign-service")]
pub(crate) struct RunCmd {
    /// Path to the encrypted NEP-6 wallet file
    ///
    /// The wallet file must be in standard NEP-6 format with:
    /// - Encrypted account data using scrypt key derivation
    /// - AES-256 encryption for private key protection
    /// - Valid JSON structure with required fields
    #[arg(long, help = "The wallet file path")]
    pub wallet: String,

    /// Network port for service binding
    ///
    /// **Port Usage:**
    /// - Main port: Signing service (after wallet decryption)
    /// - Main port + 1: Startup service (for wallet decryption)
    ///
    /// **Security Note:** Both services bind to localhost (127.0.0.1) only
    #[arg(
        long,
        help = "The listen port(listening on localhost)",
        default_value = "9991"
    )]
    pub port: u16,

    /// VSOCK context identifier for TEE environments
    ///
    /// When VSOCK feature is enabled:
    /// - CID 0: Use TCP transport (fallback)
    /// - CID > 0: Use VSOCK transport for TEE communication
    ///
    /// VSOCK is used in Trusted Execution Environments like
    /// AWS Nitro Enclaves and Intel SGX environments.
    #[cfg(feature = "vsock")]
    #[arg(long, help = "The vsock context identifier", default_value = "0")]
    pub cid: u32,
}

impl RunCmd {
    /// Start the production secure signing service
    ///
    /// This method implements the production workflow:
    ///
    /// 1. **Load Wallet**: Read and parse the encrypted NEP-6 wallet file
    /// 2. **Configure Transport**: Select TCP or VSOCK based on feature flags
    /// 3. **Start Startup Service**: Begin wallet decryption phase on port+1
    /// 4. **Return Control**: Allow external client to trigger wallet decryption
    ///
    /// ## Port Management
    ///
    /// The service uses a two-port strategy:
    /// - **Startup Port** (port+1): Handles wallet decryption protocol
    /// - **Signing Port** (port): Handles signing operations (started automatically)
    ///
    /// ## Security Considerations
    ///
    /// - Wallet file is loaded but remains encrypted until client interaction
    /// - No private keys are accessible until successful decryption
    /// - Services bind to localhost only for security
    /// - Automatic cleanup on shutdown or failure
    ///
    /// # Returns
    /// * `Ok(Sender)` - Shutdown channel for graceful service termination
    /// * `Err` - Wallet loading, parsing, or service startup failure
    ///
    /// # Example Usage
    /// ```bash
    /// # Start the service
    /// ./secure-sign run --wallet config/wallet.json --port 9991
    ///
    /// # In another terminal, decrypt the wallet
    /// ./secure-sign decrypt --port 9991
    /// ```
    pub fn run(&self) -> Result<oneshot::Sender<()>, Box<dyn std::error::Error>> {
        // Load and parse the encrypted NEP-6 wallet file
        // This validates the wallet structure but keeps it encrypted
        let wallet: Nep6Wallet = {
            let content = std::fs::read_to_string(&self.wallet)?;
            serde_json::from_str(&content)?
        };

        // Configure transport based on compile-time feature flags
        // This ensures the service uses the appropriate communication method
        #[cfg(feature = "vsock")]
        let startup = DefaultStartSigner::with_vsock(self.cid, self.port);

        #[cfg(not(feature = "vsock"))]
        let startup = DefaultStartSigner::with_tcp(self.port);

        // Create the startup service with encrypted wallet and transport config
        // The service will handle the secure wallet decryption protocol
        let service = DefaultStartupService::new(wallet, EnvCryptRandom, startup);
        let (tx, rx) = oneshot::channel::<()>();

        // Calculate startup service port (main port + 1)
        // This separation allows both services to coexist during transition
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port + 1);
        log::info!("Starting startup server on {}", addr);

        // Start the startup service in the background
        // This service handles the wallet decryption protocol and then
        // automatically transitions to the signing service
        tokio::spawn(async move {
            let r = Server::builder()
                .add_service(StartupServiceServer::new(service))
                .serve_with_shutdown(addr, async { rx.await.unwrap_or(()) })
                .await;
            if let Err(err) = r {
                log::error!("startup server error: {}", err);
            }
        });

        // Return shutdown channel for graceful termination
        // The caller can use this to stop the service cleanly
        Ok(tx)
    }
}
