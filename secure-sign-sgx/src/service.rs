// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use crate::enclave::SgxEnclave;
use crate::sign::SgxSigner;
use crate::startup::SgxStartup;

use secure_sign_rpc::servicepb::secure_sign_server::*;
use secure_sign_rpc::servicepb::*;
use secure_sign_rpc::startpb::startup_service_server::*;
use secure_sign_rpc::startpb::*;
use secure_sign_rpc::{to_h160_vec, IntoRpcStatus};
use tonic::async_trait;

pub struct SgxSignService {
    _enclave: SgxEnclave,
    signer: SgxSigner,
    startup: SgxStartup,
}

impl SgxSignService {
    pub fn new(enclave: SgxEnclave) -> Self {
        let eid = enclave.eid;
        Self {
            _enclave: enclave,
            signer: SgxSigner::new(eid),
            startup: SgxStartup::new(eid),
        }
    }
}

#[async_trait]
impl SecureSign for SgxSignService {
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
            .sign_extensible_payload(payload, &script_hashes, req.network)
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
            .map(|signature| SignBlockResponse { signature })
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
            .map_err(|err| err.into_rpc_status())
            .map(tonic::Response::new)
    }
}

#[async_trait]
impl StartupService for SgxSignService {
    async fn diffie_hellman(
        &self,
        req: tonic::Request<DiffieHellmanRequest>,
    ) -> Result<tonic::Response<DiffieHellmanResponse>, tonic::Status> {
        let req = req.into_inner();
        self.startup
            .diffie_hellman(&req.blob_ephemeral_public_key)
            .map(|alice_ephemeral_public_key| DiffieHellmanResponse {
                alice_ephemeral_public_key,
            })
            .map_err(|err| err.into_rpc_status())
            .map(tonic::Response::new)
    }

    async fn start_signer(
        &self,
        req: tonic::Request<StartSignerRequest>,
    ) -> Result<tonic::Response<StartSignerResponse>, tonic::Status> {
        let req = req.into_inner();
        self.startup
            .start_signer(&req.encrypted_wallet_passphrase, &req.nonce)
            .map(|_| StartSignerResponse {})
            .map_err(|err| err.into_rpc_status())
            .map(tonic::Response::new)
    }
}
