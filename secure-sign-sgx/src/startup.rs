// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use crate::ffi::*;
use secure_sign_rpc::IntoRpcStatus;

use sgx_types::*;

#[derive(Debug, Clone, thiserror::Error)]
pub enum StartupError {
    #[error("startup: sgx ecall error: {0}")]
    EcallError(sgx_status_t),

    #[error("startup: status error: {0}")]
    StatusError(i32),
}

impl IntoRpcStatus for StartupError {
    fn into_rpc_status(self) -> tonic::Status {
        match self {
            StartupError::EcallError(_) => tonic::Status::internal(self.to_string()),
            StartupError::StatusError(_) => tonic::Status::invalid_argument(self.to_string()),
        }
    }
}

pub struct SgxStartup {
    eid: sgx_enclave_id_t,
}

impl SgxStartup {
    pub fn new(eid: sgx_enclave_id_t) -> Self {
        Self { eid }
    }

    pub fn diffie_hellman(
        &self,
        blob_ephemeral_public_key: &[u8],
    ) -> Result<Vec<u8>, StartupError> {
        let mut retval = 0;
        let status = unsafe { secure_sign_sgx_startup(self.eid, &mut retval) };
        if status != sgx_status_t::SGX_SUCCESS {
            return Err(StartupError::EcallError(status));
        }

        if retval < 0 {
            return Err(StartupError::StatusError(retval));
        }

        let mut alice_ephemeral_public_key = vec![0u8; 33];
        let status = unsafe {
            secure_sign_sgx_diffie_hellman(
                self.eid,
                &mut retval,
                blob_ephemeral_public_key.as_ptr(),
                blob_ephemeral_public_key.len(),
                alice_ephemeral_public_key.as_mut_ptr(),
            )
        };
        if status != sgx_status_t::SGX_SUCCESS {
            return Err(StartupError::EcallError(status));
        }

        if retval < 0 {
            return Err(StartupError::StatusError(retval));
        }
        Ok(alice_ephemeral_public_key)
    }

    pub fn start_signer(
        &self,
        encrypted_wallet_passphrase: &[u8],
        nonce: &[u8],
    ) -> Result<(), StartupError> {
        let mut retval = 0;
        let status = unsafe {
            secure_sign_sgx_start_signer(
                self.eid,
                &mut retval,
                encrypted_wallet_passphrase.as_ptr(),
                encrypted_wallet_passphrase.len(),
                nonce.as_ptr(),
                nonce.len(),
            )
        };
        if status != sgx_status_t::SGX_SUCCESS {
            return Err(StartupError::EcallError(status));
        }

        if retval < 0 {
            return Err(StartupError::StatusError(retval));
        }
        Ok(())
    }
}
