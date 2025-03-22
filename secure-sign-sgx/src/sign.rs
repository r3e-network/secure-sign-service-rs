// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use crate::ffi::*;

use secure_sign_core::h160::{H160, H160_SIZE};
use secure_sign_core::neo::signpb::*;
use secure_sign_rpc::IntoRpcStatus;

use prost::Message;
use sgx_types::*;

#[derive(Debug, Clone, thiserror::Error)]
pub enum GetAccountStatusError {
    #[error("get-account-status: sgx ecall error: {0}")]
    EcallError(sgx_status_t),

    #[error("get-account-status: status error: {0}")]
    StatusError(i32),
}

impl IntoRpcStatus for GetAccountStatusError {
    fn into_rpc_status(self) -> tonic::Status {
        match self {
            GetAccountStatusError::EcallError(_) => tonic::Status::internal(self.to_string()),
            GetAccountStatusError::StatusError(_) => {
                tonic::Status::invalid_argument(self.to_string())
            }
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum SignError {
    #[error("sign: sgx ecall error: {0}")]
    EcallError(sgx_status_t),

    #[error("sign: invalid argument: {0}")]
    InvalidArgument(i32),

    #[error("sign: invalid output: {0}")]
    InvalidOutput(String),

    #[error("sign: internal error: {0}")]
    InternalError(i32),

    #[error("sign: no such account")]
    NoSuchAccount,

    #[error("sign: account is locked")]
    AccountLocked,
}

impl IntoRpcStatus for SignError {
    fn into_rpc_status(self) -> tonic::Status {
        match self {
            SignError::EcallError(_) => tonic::Status::internal(self.to_string()),
            SignError::InvalidArgument(_) => tonic::Status::invalid_argument(self.to_string()),
            SignError::InvalidOutput(_) => tonic::Status::internal(self.to_string()),
            SignError::InternalError(_) => tonic::Status::internal(self.to_string()),
            SignError::NoSuchAccount => tonic::Status::not_found("no such account"),
            SignError::AccountLocked => tonic::Status::failed_precondition("account locked"),
        }
    }
}

impl From<i32> for SignError {
    fn from(retval: i32) -> Self {
        const NO_SUCH_ACCOUNT: i32 = -12;
        const ACCOUNT_LOCKED: i32 = -13;
        const ECDSA_SIGN_ERROR: i32 = -14;
        match retval {
            NO_SUCH_ACCOUNT => Self::NoSuchAccount,
            ACCOUNT_LOCKED => Self::AccountLocked,
            ECDSA_SIGN_ERROR => Self::InternalError(retval),
            _ => Self::InvalidArgument(retval),
        }
    }
}

pub struct SgxSigner {
    eid: sgx_enclave_id_t,
}

impl SgxSigner {
    pub fn new(eid: sgx_enclave_id_t) -> Self {
        Self { eid }
    }

    pub fn get_account_status(
        &self,
        public_key: &[u8],
    ) -> Result<AccountStatus, GetAccountStatusError> {
        let mut retval: i32 = 0;
        let status = unsafe {
            secure_sign_sgx_account_status(
                self.eid,
                &mut retval,
                public_key.as_ptr(),
                public_key.len(),
            )
        };
        if status != sgx_status_t::SGX_SUCCESS {
            return Err(GetAccountStatusError::EcallError(status));
        }

        if retval < 0 {
            return Err(GetAccountStatusError::StatusError(retval));
        }
        AccountStatus::try_from(retval).map_err(|_err| GetAccountStatusError::StatusError(retval))
    }

    pub fn sign_block(
        &self,
        public_key: &[u8],
        block: &TrimmedBlock,
        network: u32,
    ) -> Result<Vec<u8>, SignError> {
        let mut retval: i32 = 0;
        let mut sign = vec![0u8; 64];
        let trimmed_block = block.encode_to_vec();
        let status = unsafe {
            secure_sign_sgx_sign_block(
                self.eid,
                &mut retval,
                public_key.as_ptr(),
                public_key.len(),
                trimmed_block.as_ptr(),
                trimmed_block.len(),
                network,
                sign.as_mut_ptr(),
                sign.len(),
            )
        };
        if status != sgx_status_t::SGX_SUCCESS {
            return Err(SignError::EcallError(status));
        }

        if retval < 0 {
            return Err(retval.into());
        }
        Ok(sign)
    }

    pub fn sign_extensible_payload(
        &self,
        payload: &ExtensiblePayload,
        script_hashes: &[H160],
        network: u32,
    ) -> Result<MultiAccountSigns, SignError> {
        let mut retval: i32 = 0;
        let mut signs = vec![0u8; 4096];
        let extensible_payload = payload.encode_to_vec();

        let mut hashes = Vec::with_capacity(script_hashes.len() * H160_SIZE);
        for hash in script_hashes {
            hashes.extend_from_slice(hash.as_ref());
        }

        let status = unsafe {
            secure_sign_sgx_sign_extensible_payload(
                self.eid,
                &mut retval,
                extensible_payload.as_ptr(),
                extensible_payload.len(),
                hashes.as_ptr(),
                hashes.len(),
                network,
                signs.as_mut_ptr(),
                signs.len(),
            )
        };
        if status != sgx_status_t::SGX_SUCCESS {
            return Err(SignError::EcallError(status));
        }

        if retval < 0 {
            return Err(retval.into());
        }

        MultiAccountSigns::decode(&signs[..retval as usize])
            .map_err(|err| SignError::InvalidOutput(err.to_string()))
    }
}
