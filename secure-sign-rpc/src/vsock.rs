// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # VSOCK Transport for Trusted Execution Environments
//!
//! This module implements VSOCK (Virtual Socket) transport for communication
//! between trusted execution environments (TEEs) and their host systems.
//! VSOCK provides a secure, efficient communication channel specifically
//! designed for virtualized and enclave environments.
//!
//! ## VSOCK Overview
//!
//! VSOCK is a socket family designed for communication between virtual machines
//! and their hypervisors, or between enclaves and host applications:
//!
//! - **Isolation**: Communication bypasses the network stack entirely
//! - **Performance**: High-throughput, low-latency communication channel
//! - **Security**: Controlled by hypervisor/enclave security policies
//! - **Addressing**: Uses Context ID (CID) and port numbers for addressing
//!
//! ## Use Cases in Secure Sign Service
//!
//! ### AWS Nitro Enclaves
//! - **Enclave-to-Host**: Secure communication between Nitro enclave and EC2 instance
//! - **Isolation**: Network isolation while maintaining controlled communication
//! - **Performance**: High-speed data transfer for signing operations
//!
//! ### Intel SGX (Future)
//! - **SGX-to-Host**: Communication between SGX enclave and host application
//! - **Remote Attestation**: Secure channel for attestation data exchange
//! - **Sealed Storage**: Efficient transfer of sealed data blobs
//!
//! ## Addressing Model
//!
//! VSOCK uses a two-part addressing scheme:
//! - **Context ID (CID)**: Identifies the communication endpoint
//!   - 0: Hypervisor/Host
//!   - 1: Local loopback
//!   - 2: Host (from guest perspective)
//!   - 3+: Guest VMs/Enclaves
//! - **Port**: Service endpoint within the context
//!
//! ## Security Properties
//!
//! - **Host Controlled**: Host can restrict which enclaves can communicate
//! - **No Network Exposure**: Traffic never leaves the physical machine
//! - **Enclave Verification**: Combined with attestation for secure channels
//! - **Efficient**: Optimized for secure high-frequency operations

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use hyper_util::rt::tokio::TokioIo;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};
use tonic::transport::{Channel, Endpoint, Uri};

/// Type alias for incoming VSOCK connections
///
/// This represents a stream of incoming VSOCK connections, similar to
/// how TCP listeners work but for the VSOCK address family.
pub type VsockIncoming = tokio_vsock::Incoming;

/// Create a VSOCK listener for incoming connections
///
/// This function sets up a VSOCK listener that can accept incoming connections
/// from clients using the VSOCK transport. Typically used by server-side
/// applications running in TEE host environments.
///
/// # Arguments
/// * `cid` - Context ID for the listener (usually 0 for host-side services)
/// * `port` - Port number for the service
///
/// # Returns
/// * `Ok(VsockIncoming)` - Stream of incoming VSOCK connections
/// * `Err(std::io::Error)` - Failed to bind to the VSOCK address
///
/// # Example Usage
/// ```rust,no_run
/// use secure_sign_rpc::vsock::vsock_incoming;
///
/// // Listen for connections from Nitro enclave (CID 3) on port 9991
/// let incoming = vsock_incoming(0, 9991).expect("Should create VSOCK listener");
/// // Accept connections and handle them...
/// ```
///
/// # TEE Integration
/// - **AWS Nitro**: Host listens on CID 0, enclave connects from CID 3+
/// - **Intel SGX**: Host application listens for SGX enclave connections
/// - **Development**: Can use loopback (CID 1) for testing
#[inline]
pub fn vsock_incoming(cid: u32, port: u16) -> Result<VsockIncoming, std::io::Error> {
    let addr = VsockAddr::new(cid, port as u32);
    VsockListener::bind(addr).map(|listener| listener.incoming())
}

/// VSOCK connector for outbound connections
///
/// This structure implements the Tower service trait to provide VSOCK
/// connectivity for gRPC clients. It enables gRPC to work over VSOCK
/// transport instead of traditional TCP/IP networking.
pub struct VsockConnector {
    /// Context ID of the target endpoint
    ///
    /// Identifies which TEE or host context to connect to:
    /// - 0: Hypervisor/Host system
    /// - 2: Host (from guest/enclave perspective)  
    /// - 3+: Specific guest VM or enclave instance
    cid: u32,

    /// Port number on the target context
    ///
    /// Service port within the target context, similar to TCP ports
    /// but scoped to the specific VSOCK context.
    port: u16,
}

impl VsockConnector {
    /// Create a new VSOCK connector for the specified endpoint
    ///
    /// # Arguments
    /// * `cid` - Context ID of the target (0=host, 2=host-from-guest, 3+=specific-guest)
    /// * `port` - Port number of the target service
    ///
    /// # Returns
    /// New VsockConnector instance configured for the specified endpoint
    ///
    /// # Usage Examples
    /// ```rust
    /// use secure_sign_rpc::vsock::VsockConnector;
    ///
    /// // Connect from enclave to host service
    /// let _connector = VsockConnector::new(2, 9991);
    ///
    /// // Connect from host to specific enclave
    /// let _connector = VsockConnector::new(3, 9991);
    /// ```
    pub fn new(cid: u32, port: u16) -> Self {
        Self { cid, port }
    }
}

impl tower::Service<Uri> for VsockConnector {
    type Response = VsockStream;
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    /// Check if the service is ready to handle requests
    ///
    /// VSOCK connections are typically always ready to attempt connection,
    /// so this returns `Ready(Ok(()))` immediately.
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    /// Establish a VSOCK connection to the configured endpoint
    ///
    /// This method creates an actual VSOCK connection to the target context
    /// and port. The URI parameter is ignored since VSOCK addressing is
    /// configured at connector creation time.
    ///
    /// # Arguments
    /// * `_uri` - Ignored for VSOCK (addressing is CID-based)
    ///
    /// # Returns
    /// Future that resolves to a VSOCK stream connection
    ///
    /// # Connection Process
    /// 1. Create VSOCK address from configured CID and port
    /// 2. Attempt connection to target endpoint
    /// 3. Return established stream for gRPC communication
    ///
    /// # Error Conditions
    /// - Target context/enclave not running
    /// - Port not listening on target
    /// - VSOCK driver not available
    /// - Permission restrictions
    fn call(&mut self, _uri: Uri) -> Self::Future {
        let addr = VsockAddr::new(self.cid, self.port as u32);
        Box::pin(async move { VsockStream::connect(addr).await })
    }
}

/// Create a gRPC channel using VSOCK transport
///
/// This function creates a gRPC channel that communicates over VSOCK instead
/// of traditional TCP. This enables secure, high-performance communication
/// between TEEs and their host systems.
///
/// # Implementation Details
///
/// The function works around gRPC/Tonic's TCP-centric design by:
/// 1. Creating a placeholder HTTP endpoint (not actually used)
/// 2. Providing a custom connector that establishes VSOCK connections
/// 3. Wrapping VSOCK streams in TokioIo for compatibility
///
/// # Arguments
/// * `cid` - Context ID of the target endpoint
/// * `port` - Port number of the target service
///
/// # Returns
/// * `Ok(Channel)` - gRPC channel using VSOCK transport
/// * `Err(Box<dyn std::error::Error>)` - Failed to create channel
///
/// # Usage Examples
/// ```rust,no_run
/// use secure_sign_rpc::vsock::vsock_channel;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Client connecting from enclave to host service
/// let channel = vsock_channel(2, 9991).await?;
/// // Channel can be used with gRPC clients...
///
/// // Host connecting to enclave service  
/// let channel = vsock_channel(3, 9991).await?;
/// // Channel can be used with gRPC clients...
/// # Ok(())
/// # }
/// ```
///
/// # Security Notes
/// - VSOCK connections bypass network security policies
/// - Ensure proper authentication at the application layer
/// - Consider combining with remote attestation for enclave verification
/// - Monitor VSOCK connections for unauthorized access attempts
pub async fn vsock_channel(cid: u32, port: u16) -> Result<Channel, Box<dyn std::error::Error>> {
    // Create a placeholder URI (not actually used for VSOCK addressing)
    // The format includes port and CID for debugging purposes only
    let endpoint = Endpoint::try_from(format!("http://127.0.0.1:{}/{}", port, cid))?; // Just a placeholder

    // Create the gRPC channel with custom VSOCK connector
    let channel = endpoint
        .connect_with_connector(tower::service_fn(move |_uri: Uri| {
            let addr = VsockAddr::new(cid, port as u32);
            async move {
                // Establish VSOCK connection and wrap for Tonic compatibility
                let stream = VsockStream::connect(addr).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await?;

    Ok(channel)
}
