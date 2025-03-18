// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

pub mod servicepb;
pub mod unencrypted;

use secure_sign_core::neo::sign::SignError;
use servicepb::*;

use tonic::async_trait;

// It may should be an async trait
pub trait SignService {
    fn sign_with_script_hashes(
        &self,
        req: SignWithScriptHashesRequest,
    ) -> Result<SignWithScriptHashesResponse, tonic::Status>;

    fn sign_with_public_key(
        &self,
        req: SignWithPublicKeyRequest,
    ) -> Result<SignWithPublicKeyResponse, tonic::Status>;

    fn get_account_status(
        &self,
        req: GetAccountStatusRequest,
    ) -> Result<GetAccountStatusResponse, tonic::Status>;
}

pub trait ToRpcStatus {
    fn to_rpc_status(&self) -> tonic::Status;
}

impl ToRpcStatus for SignError {
    fn to_rpc_status(&self) -> tonic::Status {
        match self {
            SignError::InvalidPublicKey(_) => tonic::Status::invalid_argument("invalid public key"),
            SignError::NoSuchAccount => tonic::Status::not_found("no such account"),
            SignError::AccountLocked => tonic::Status::permission_denied("account locked"),
            SignError::EcdsaSignError(_) => tonic::Status::internal("ecdsa sign error"),
        }
    }
}

pub struct SignServiceFacade<T> {
    sign_service: T,
}

impl<T> SignServiceFacade<T> {
    pub fn new(sign_service: T) -> Self {
        Self { sign_service }
    }
}

#[async_trait]
impl<T: SignService + Send + Sync + 'static> secure_sign_server::SecureSign
    for SignServiceFacade<T>
{
    async fn sign_with_script_hashes(
        &self,
        req: tonic::Request<SignWithScriptHashesRequest>,
    ) -> Result<tonic::Response<SignWithScriptHashesResponse>, tonic::Status> {
        let req = req.into_inner();
        self.sign_service
            .sign_with_script_hashes(req)
            .map(tonic::Response::new)
    }

    async fn sign_with_public_key(
        &self,
        req: tonic::Request<SignWithPublicKeyRequest>,
    ) -> Result<tonic::Response<SignWithPublicKeyResponse>, tonic::Status> {
        let req = req.into_inner();
        self.sign_service
            .sign_with_public_key(req)
            .map(tonic::Response::new)
    }

    async fn get_account_status(
        &self,
        req: tonic::Request<GetAccountStatusRequest>,
    ) -> Result<tonic::Response<GetAccountStatusResponse>, tonic::Status> {
        let req = req.into_inner();
        self.sign_service
            .get_account_status(req)
            .map(tonic::Response::new)
    }
}
