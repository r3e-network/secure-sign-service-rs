// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # Startup Phase Implementation
//!
//! This module implements the second phase of the two-phase security model.
//! After the wallet has been securely decrypted (Phase 1), this module:
//!
//! 1. Creates the signing service with decrypted accounts
//! 2. Starts the gRPC server for signing operations
//! 3. Selects appropriate transport (TCP or VSOCK)
//!
//! ## Security Transition
//!
//! At this point, the startup service (wallet decryption) is replaced by
//! the signing service (cryptographic operations). Private keys are now
//! accessible only within the signing service memory space.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use secure_sign_core::neo::sign::{Account, Signer};
use secure_sign_rpc::{
    DefaultSignService, servicepb::secure_sign_server::SecureSignServer, startup::StartSigner,
};
use tokio::sync::oneshot;
use tonic::transport::Server;

/// Default implementation of the signing service startup
///
/// This service handles the transition from wallet decryption to
/// active signing operations. It supports both TCP and VSOCK transports
/// based on the configured context ID (CID).
pub struct DefaultStartSigner {
    /// VSOCK context ID (0 indicates TCP mode)
    cid: u32,
    /// Network port for binding the service
    port: u16,
}

impl DefaultStartSigner {
    /// Create a VSOCK-based starter for TEE environments
    ///
    /// VSOCK transport is used in Trusted Execution Environments (TEEs)
    /// such as AWS Nitro Enclaves or Intel SGX environments where
    /// traditional TCP networking may not be available or desired.
    ///
    /// # Arguments
    /// * `cid` - VSOCK context identifier (must be > 0)
    /// * `port` - VSOCK port number
    #[allow(unused)]
    pub fn with_vsock(cid: u32, port: u16) -> Self {
        Self { cid, port }
    }

    /// Create a TCP-based starter for standard environments
    ///
    /// TCP transport binds to localhost (127.0.0.1) for security.
    /// This prevents external network access while allowing local
    /// client connections.
    ///
    /// # Arguments
    /// * `port` - TCP port to bind to (typically 9991)
    #[allow(dead_code)]
    pub fn with_tcp(port: u16) -> Self {
        Self { cid: 0, port }
    }
}

impl StartSigner for DefaultStartSigner {
    /// Start the signing service with decrypted accounts
    ///
    /// This method performs the critical security transition:
    /// 1. Creates the signing service with decrypted private keys
    /// 2. Starts the appropriate transport (TCP or VSOCK)
    /// 3. Returns a shutdown channel for graceful termination
    ///
    /// # Security Notes
    /// - Private keys are now accessible within the signing service
    /// - The startup service is no longer needed and can be terminated
    /// - All subsequent operations use the signing service interface
    ///
    /// # Arguments
    /// * `accounts` - Vector of decrypted accounts with private keys
    ///
    /// # Returns
    /// * `Ok(Sender)` - Shutdown channel for service termination
    /// * `Err` - Network binding or service startup failure
    fn start(
        self,
        accounts: Vec<Account>,
    ) -> Result<oneshot::Sender<()>, Box<dyn std::error::Error>> {
        // Create the signing service with decrypted accounts
        // This is where private keys become accessible for signing operations
        let sign_service = DefaultSignService::new(Signer::new(accounts));
        let router = Server::builder().add_service(SecureSignServer::new(sign_service));

        // Create shutdown channel for graceful termination
        let (tx, rx) = oneshot::channel::<()>();

        // Select transport based on context ID
        if self.cid > 0 {
            // VSOCK transport for TEE environments
            let incoming = secure_sign_rpc::vsock::vsock_incoming(self.cid, self.port)?;
            log::info!("Starting vsock server on {}:{}", self.cid, self.port);

            // Spawn VSOCK server task
            tokio::spawn(async move {
                let r = router
                    .serve_with_incoming_shutdown(incoming, async { rx.await.unwrap_or(()) })
                    .await;
                if let Err(err) = r {
                    log::error!("vsock server error: {}", err);
                }
            });
        } else {
            // TCP transport for standard environments
            // Bind to localhost only for security
            let ip_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port);
            log::info!("Starting tcp server on {}", ip_addr);

            // Spawn TCP server task
            tokio::spawn(async move {
                let r = router
                    .serve_with_shutdown(ip_addr, async { rx.await.unwrap_or(()) })
                    .await;
                if let Err(err) = r {
                    log::error!("tcp server error: {}", err);
                }
            });
        }

        // Return shutdown sender to allow graceful termination
        Ok(tx)
    }
}
