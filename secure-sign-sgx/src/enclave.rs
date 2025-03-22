// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use sgx_types::*;
use std::ffi::CString;

pub struct SgxEnclave {
    pub eid: sgx_enclave_id_t,
    pub launch_token: sgx_launch_token_t,
    pub launch_token_updated: bool,
    pub misc_attr: sgx_misc_attribute_t,
}

impl SgxEnclave {
    pub fn new(
        enclave_file: String,
        launch_token: Option<sgx_launch_token_t>,
        debug: bool,
    ) -> Result<SgxEnclave, sgx_status_t> {
        let mut token = if let Some(token) = launch_token {
            token
        } else {
            [0; 1024]
        };

        let mut token_updated = 0;
        let mut eid = 0 as sgx_enclave_id_t;
        let mut misc_attr = sgx_misc_attribute_t {
            secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
            misc_select: 0,
        };
        let file =
            CString::new(enclave_file).map_err(|_err| sgx_status_t::SGX_ERROR_INVALID_ENCLAVE)?;

        let status = unsafe {
            sgx_create_enclave(
                file.as_ptr(),
                if debug { 1 } else { 0 },
                &mut token,
                &mut token_updated,
                &mut eid,
                &mut misc_attr,
            )
        };
        if status != sgx_status_t::SGX_SUCCESS {
            return Err(status);
        }

        Ok(SgxEnclave {
            eid,
            launch_token: token,
            launch_token_updated: token_updated != 0,
            misc_attr,
        })
    }
}

impl Drop for SgxEnclave {
    fn drop(&mut self) {
        let _status = unsafe { sgx_destroy_enclave(self.eid) };
    }
}
