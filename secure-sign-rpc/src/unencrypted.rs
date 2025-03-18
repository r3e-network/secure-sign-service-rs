// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use crate::servicepb::*;
use crate::{SignService, ToRpcStatus};

use secure_sign_core::bytes::ToArray;
use secure_sign_core::h160;
use secure_sign_core::neo::sign::Signer;

/// Unencrypted sign service
/// NOTE: This service hasn't any encryption mechanism for critical data.
pub struct UnencryptedSignService {
    signer: Signer,
}

impl UnencryptedSignService {
    pub fn new(signer: Signer) -> Self {
        Self { signer }
    }
}

impl SignService for UnencryptedSignService {
    fn sign_with_script_hashes(
        &self,
        req: SignWithScriptHashesRequest,
    ) -> Result<SignWithScriptHashesResponse, tonic::Status> {
        let mut script_hashes = Vec::with_capacity(req.script_hashes.len());
        for hash in req.script_hashes {
            if hash.len() != h160::H160_SIZE {
                return Err(tonic::Status::invalid_argument(
                    "script_hashes must be 20 bytes",
                ));
            }
            script_hashes.push(h160::H160::from_le_bytes(hash.as_slice().to_array()));
        }

        self.signer
            .sign_with_script_hashes(script_hashes, &req.sign_data)
            .map(|signs| SignWithScriptHashesResponse { signs: signs })
            .map_err(|err| err.to_rpc_status())
    }

    fn sign_with_public_key(
        &self,
        req: SignWithPublicKeyRequest,
    ) -> Result<SignWithPublicKeyResponse, tonic::Status> {
        self.signer
            .sign_with_public_key(&req.public_key, &req.sign_data)
            .map(|sign| SignWithPublicKeyResponse { signature: sign })
            .map_err(|err| err.to_rpc_status())
    }

    fn get_account_status(
        &self,
        req: GetAccountStatusRequest,
    ) -> Result<GetAccountStatusResponse, tonic::Status> {
        self.signer
            .get_account_status(&req.public_key)
            .map(|status| GetAccountStatusResponse {
                status: status as i32,
            })
            .map_err(|err| tonic::Status::invalid_argument(err.to_string()))
    }
}
