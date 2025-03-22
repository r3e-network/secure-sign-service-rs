// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use secure_sign_core::random::CryptRandom;

use aws_nitro_enclaves_nsm_api::{api, driver};
use zeroize::Zeroizing;

pub struct Nsm {
    fd: i32,
}

#[derive(Debug, thiserror::Error)]
pub enum NsmError {
    #[error("nitro: initialize nsm error: {0}")]
    InitError(i32),

    #[error("nitro: request error: {0:?}")]
    RequestError(api::ErrorCode),

    #[error("nitro: unexpected error")]
    Unexpected,
}

impl Nsm {
    pub fn new() -> Result<Self, NsmError> {
        let fd = driver::nsm_init();
        if fd < 0 {
            return Err(NsmError::InitError(fd).into());
        }

        Ok(Self { fd })
    }

    pub fn get_random(&self) -> Result<Zeroizing<Vec<u8>>, NsmError> {
        let req: api::Request = api::Request::GetRandom;
        let bytes = match driver::nsm_process_request(self.fd, req) {
            api::Response::GetRandom { random } => random,
            api::Response::Error(code) => return Err(NsmError::RequestError(code)),
            _ => return Err(NsmError::Unexpected),
        };

        Ok(Zeroizing::new(bytes))
    }
}

impl CryptRandom for Nsm {
    type Error = NsmError;

    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), NsmError> {
        let mut n = 0;
        while n < buf.len() {
            let bytes = self.get_random()?; // TODO: clear the `buf` if error
            let once = core::cmp::min(bytes.len(), buf.len() - n);
            buf[n..n + once].copy_from_slice(&bytes[..once]);
            n += once;
        }
        Ok(())
    }
}
