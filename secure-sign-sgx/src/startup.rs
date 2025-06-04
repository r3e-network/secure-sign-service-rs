// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::fs;

use crate::ffi::*;
use secure_sign_rpc::startpb::*;
use sgx_types::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StartupError {
    #[error("startup: sgx ecall error: {0}")]
    EcallError(sgx_status_t),
    
    #[error("startup: enclave returned error: {0}")]
    EnclaveError(i32),
    
    #[error("startup: failed to read wallet file: {0}")]
    WalletReadError(std::io::Error),
}

impl From<StartupError> for tonic::Status {
    fn from(err: StartupError) -> Self {
        tonic::Status::internal(err.to_string())
    }
}

pub struct SgxStartup {
    eid: sgx_enclave_id_t,
    wallet_path: String,
}

impl SgxStartup {
    pub fn new(eid: sgx_enclave_id_t, wallet_path: String) -> Self {
        Self { eid, wallet_path }
    }

    pub fn startup(&self) -> Result<(), StartupError> {
        // Read the wallet file
        let wallet_data = fs::read(&self.wallet_path)
            .map_err(StartupError::WalletReadError)?;

        let mut retval = 0i32;
        let status = unsafe { 
            secure_sign_sgx_startup(
                self.eid, 
                &mut retval,
                wallet_data.as_ptr(),
                wallet_data.len(),
            ) 
        };
        
        if status != sgx_status_t::SGX_SUCCESS {
            return Err(StartupError::EcallError(status));
        }
        
        if retval != 0 {
            return Err(StartupError::EnclaveError(retval));
        }

        Ok(())
    }

    pub fn diffie_hellman(
        &self,
        blob_ephemeral_public_key: &[u8],
    ) -> Result<Vec<u8>, StartupError> {
        let mut alice_ephemeral_public_key = [0u8; 33];
        let mut retval = 0i32;

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
        
        if retval != 0 {
            return Err(StartupError::EnclaveError(retval));
        }

        Ok(alice_ephemeral_public_key.to_vec())
    }

    pub fn start_signer(
        &self,
        encrypted_wallet_passphrase: &[u8],
        nonce: &[u8],
    ) -> Result<(), StartupError> {
        let mut retval = 0i32;

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
        
        if retval != 0 {
            return Err(StartupError::EnclaveError(retval));
        }

        Ok(())
    }
}
