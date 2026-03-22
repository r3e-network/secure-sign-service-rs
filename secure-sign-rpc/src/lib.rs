// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

pub mod servicepb;
pub mod startpb;
pub mod startup;

// #[cfg(feature = "vsock")]
pub mod vsock;

use secure_sign_core::bytes::ToArray;
use secure_sign_core::h160::{H160, H160_SIZE};
use secure_sign_core::neo::sign::{SignError, Signer};
use servicepb::{secure_sign_server::SecureSign, *};
use tonic::async_trait;

pub trait IntoRpcStatus {
    fn into_rpc_status(self) -> tonic::Status;
}

impl IntoRpcStatus for SignError {
    fn into_rpc_status(self) -> tonic::Status {
        match self {
            SignError::InvalidPublicKey(s) => tonic::Status::invalid_argument(s),
            SignError::NoSuchAccount => tonic::Status::not_found("no such account"),
            SignError::AccountLocked => tonic::Status::failed_precondition("account locked"),
            SignError::EcdsaSignError(s) => tonic::Status::internal(s),
            SignError::InvalidBlock(s) => tonic::Status::invalid_argument(s),
            SignError::InvalidExtensiblePayload(s) => tonic::Status::invalid_argument(s),
        }
    }
}

#[allow(clippy::result_large_err)]
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

pub struct DefaultSignService {
    signer: Signer,
}

impl DefaultSignService {
    pub fn new(signer: Signer) -> Self {
        Self { signer }
    }
}

#[async_trait]
impl SecureSign for DefaultSignService {
    async fn sign_extensible_payload(
        &self,
        req: tonic::Request<SignExtensiblePayloadRequest>,
    ) -> Result<tonic::Response<SignExtensiblePayloadResponse>, tonic::Status> {
        let req = req.into_inner();
        let script_hashes = to_h160_vec(req.script_hashes)?;
        let Some(payload) = req.payload.as_ref() else {
            return Err(tonic::Status::invalid_argument("payload is required"));
        };

        self.signer
            .sign_extensible_payload(payload, script_hashes, req.network)
            .map(|signs| SignExtensiblePayloadResponse { signs: signs.signs })
            .map_err(|err| err.into_rpc_status())
            .map(tonic::Response::new)
    }

    async fn sign_block(
        &self,
        req: tonic::Request<SignBlockRequest>,
    ) -> Result<tonic::Response<SignBlockResponse>, tonic::Status> {
        let req = req.into_inner();
        let Some(block) = req.block.as_ref() else {
            return Err(tonic::Status::invalid_argument("block is required"));
        };

        self.signer
            .sign_block(&req.public_key, block, req.network)
            .map(|sign| SignBlockResponse { signature: sign })
            .map_err(|err| err.into_rpc_status())
            .map(tonic::Response::new)
    }

    async fn get_account_status(
        &self,
        req: tonic::Request<GetAccountStatusRequest>,
    ) -> Result<tonic::Response<GetAccountStatusResponse>, tonic::Status> {
        let req = req.into_inner();
        self.signer
            .get_account_status(&req.public_key)
            .map(|x| GetAccountStatusResponse { status: x as i32 })
            .map_err(|err| tonic::Status::invalid_argument(err.to_string()))
            .map(tonic::Response::new)
    }
}
