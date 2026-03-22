// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use secure_sign_core::random::CryptRandom;

use aws_nitro_enclaves_nsm_api::{api, driver};
use rand_core::{CryptoRng, RngCore};
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
            return Err(NsmError::InitError(fd));
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

    pub fn get_attestation_with_public_key(
        &self,
        public_key_der: &[u8],
    ) -> Result<Vec<u8>, NsmError> {
        let req: api::Request = api::Request::Attestation {
            user_data: None,
            nonce: None,
            public_key: Some(public_key_der.to_vec().into()),
        };

        match driver::nsm_process_request(self.fd, req) {
            api::Response::Attestation { document } => Ok(document),
            api::Response::Error(code) => Err(NsmError::RequestError(code)),
            _ => Err(NsmError::Unexpected),
        }
    }
}

impl Drop for Nsm {
    fn drop(&mut self) {
        driver::nsm_exit(self.fd);
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

impl RngCore for Nsm {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        CryptRandom::try_fill_bytes(self, dest)
            .expect("Nsm random generation failed");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        CryptRandom::try_fill_bytes(self, dest)
            .map_err(|err| rand_core::Error::new(std::io::Error::other(err.to_string())))
    }
}

impl CryptoRng for Nsm {}
