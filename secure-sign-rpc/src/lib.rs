// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # gRPC Service Implementation for Secure Sign Service
//!
//! This module provides the gRPC interface layer that exposes the NEO signing
//! functionality over the network. It includes:
//!
//! - **Protocol Buffer Definitions**: Auto-generated service interfaces
//! - **Service Implementation**: Business logic integration with signing engine
//! - **Error Mapping**: Conversion from internal errors to gRPC status codes
//! - **Transport Support**: TCP and VSOCK transport implementations
//!
//! ## Service Architecture
//!
//! The gRPC layer acts as a bridge between network clients and the core
//! signing engine, providing type-safe serialization and robust error handling.

/// Generated protocol buffer definitions for the signing service
pub mod servicepb;
/// Generated protocol buffer definitions for the startup service
pub mod startpb;
/// Startup service trait definitions
pub mod startup;

/// VSOCK transport implementation for TEE environments
// #[cfg(feature = "vsock")]
pub mod vsock;

use secure_sign_core::{
    bytes::ToArray,
    h160::{H160, H160_SIZE},
    neo::sign::{SignError, Signer},
};
use servicepb::{secure_sign_server::SecureSign, *};
use tonic::async_trait;

/// Trait for converting internal errors to gRPC status codes
///
/// This provides a standardized way to map internal error types
/// to appropriate gRPC status codes with meaningful error messages.
pub trait IntoRpcStatus {
    /// Convert an internal error to a gRPC status
    ///
    /// # Returns
    /// A `tonic::Status` with appropriate error code and message
    fn into_rpc_status(self) -> tonic::Status;
}

/// Error mapping for signing operations
///
/// Maps internal signing errors to appropriate gRPC status codes:
/// - InvalidPublicKey/InvalidBlock/InvalidExtensiblePayload → INVALID_ARGUMENT
/// - NoSuchAccount → NOT_FOUND  
/// - AccountLocked → FAILED_PRECONDITION
/// - EcdsaSignError → INTERNAL
impl IntoRpcStatus for SignError {
    fn into_rpc_status(self) -> tonic::Status {
        match self {
            // Client-side errors (invalid input)
            SignError::InvalidPublicKey(s) => tonic::Status::invalid_argument(s),
            SignError::InvalidBlock(s) => tonic::Status::invalid_argument(s),
            SignError::InvalidExtensiblePayload(s) => tonic::Status::invalid_argument(s),

            // Resource not found
            SignError::NoSuchAccount => tonic::Status::not_found("no such account"),

            // Precondition failures (account state)
            SignError::AccountLocked => tonic::Status::failed_precondition("account locked"),

            // Internal cryptographic errors
            SignError::EcdsaSignError(s) => tonic::Status::internal(s),
        }
    }
}

/// Convert a vector of byte vectors to H160 script hashes
///
/// This utility function validates that each byte vector is exactly 20 bytes
/// (the required length for NEO script hashes) and converts them to the
/// internal H160 representation with little-endian byte ordering.
///
/// # Arguments
/// * `source` - Vector of byte vectors representing script hashes
///
/// # Returns
/// * `Ok(Vec<H160>)` - Successfully converted script hashes
/// * `Err(tonic::Status)` - Invalid script hash length
///
/// # Validation
/// Each script hash must be exactly 20 bytes. Invalid lengths result
/// in an INVALID_ARGUMENT gRPC status.
pub fn to_h160_vec(source: Vec<Vec<u8>>) -> Result<Vec<H160>, tonic::Status> {
    let mut h160s = Vec::with_capacity(source.len());
    for hash in source {
        if hash.len() != H160_SIZE {
            return Err(tonic::Status::invalid_argument(
                "ScriptHash must be 20 bytes",
            ));
        }
        h160s.push(H160::from_le_bytes(hash.as_slice().to_array()));
    }
    Ok(h160s)
}

/// Default implementation of the SecureSign gRPC service
///
/// This service wraps the core signing engine and exposes its functionality
/// via gRPC. It handles:
/// - Request validation and parameter extraction
/// - Data type conversions between protobuf and internal types
/// - Error mapping to appropriate gRPC status codes
/// - Response construction and serialization
pub struct DefaultSignService {
    /// The core signing engine that performs cryptographic operations
    signer: Signer,
}

impl DefaultSignService {
    /// Create a new gRPC service wrapper around a signing engine
    ///
    /// # Arguments
    /// * `signer` - The core signing engine with loaded accounts
    pub fn new(signer: Signer) -> Self {
        Self { signer }
    }
}

/// gRPC service implementation for cryptographic signing operations
///
/// This implementation provides the network interface for the three main
/// operations: extensible payload signing, block signing, and account status queries.
#[async_trait]
impl SecureSign for DefaultSignService {
    /// Sign a NEO extensible payload with multiple script hashes
    ///
    /// This RPC handles transaction signing and other extensible payload operations.
    /// It validates input parameters, converts data types, and returns signing
    /// results for each provided script hash.
    ///
    /// # Request Validation
    /// - `payload` field must be present
    /// - All script hashes must be exactly 20 bytes
    /// - Network ID must be valid
    ///
    /// # Response
    /// Returns `MultiAccountSigns` containing results for each script hash,
    /// including signatures for available accounts and status for unavailable ones.
    async fn sign_extensible_payload(
        &self,
        req: tonic::Request<SignExtensiblePayloadRequest>,
    ) -> Result<tonic::Response<SignExtensiblePayloadResponse>, tonic::Status> {
        let req = req.into_inner();

        // Validate and convert script hashes from bytes to H160
        let script_hashes = to_h160_vec(req.script_hashes)?;

        // Validate payload presence
        let Some(payload) = req.payload.as_ref() else {
            return Err(tonic::Status::invalid_argument("payload is required"));
        };

        // Perform signing operation and convert result
        self.signer
            .sign_extensible_payload(payload, script_hashes, req.network)
            .map(|signs| SignExtensiblePayloadResponse { signs: signs.signs })
            .map_err(|err| err.into_rpc_status())
            .map(tonic::Response::new)
    }

    /// Sign a NEO block header for consensus participation
    ///
    /// This RPC handles block signing for consensus nodes. It validates
    /// the block structure, verifies the merkle root, and generates
    /// an ECDSA signature for the specified public key.
    ///
    /// # Request Validation
    /// - `block` field must be present
    /// - `public_key` must be valid (33 or 65 bytes)
    /// - Block structure must be valid (merkle root, timestamps, etc.)
    ///
    /// # Response
    /// Returns a 64-byte ECDSA signature or an error status.
    async fn sign_block(
        &self,
        req: tonic::Request<SignBlockRequest>,
    ) -> Result<tonic::Response<SignBlockResponse>, tonic::Status> {
        let req = req.into_inner();

        // Validate block presence
        let Some(block) = req.block.as_ref() else {
            return Err(tonic::Status::invalid_argument("block is required"));
        };

        // Perform block signing operation
        self.signer
            .sign_block(&req.public_key, block, req.network)
            .map(|sign| SignBlockResponse { signature: sign })
            .map_err(|err| err.into_rpc_status())
            .map(tonic::Response::new)
    }

    /// Query the status of an account by public key
    ///
    /// This RPC allows clients to check if an account is available for signing
    /// and determine its type (single-sig, multi-sig, locked, etc.).
    ///
    /// # Request Validation
    /// - `public_key` must be valid (33 or 65 bytes)
    ///
    /// # Response
    /// Returns `AccountStatus` indicating the account's signing capability:
    /// - NoSuchAccount: Account not found
    /// - Locked: Account exists but is locked
    /// - Single: Single-signature account ready for signing
    /// - Multiple: Multi-signature account (future feature)
    async fn get_account_status(
        &self,
        req: tonic::Request<GetAccountStatusRequest>,
    ) -> Result<tonic::Response<GetAccountStatusResponse>, tonic::Status> {
        let req = req.into_inner();

        // Query account status and convert to gRPC response
        self.signer
            .get_account_status(&req.public_key)
            .map(|x| GetAccountStatusResponse { status: x as i32 })
            .map_err(|err| tonic::Status::invalid_argument(err.to_string()))
            .map(tonic::Response::new)
    }
}
