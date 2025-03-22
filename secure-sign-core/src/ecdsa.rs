// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use alloc::string::{String, ToString};

use crate::bytes::ToArray;
use crate::secp256r1;

use p256::ecdsa::signature::{Signer, Verifier as P256Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

pub const ECC256_SIGN_SIZE: usize = 32 * 2;

pub trait Sign {
    type Sign;
    type Error;

    fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<Self::Sign, Self::Error>;
}

pub trait Verify {
    type Sign;
    type Error;

    fn verify<T: AsRef<[u8]>>(&self, message: T, sign: &Self::Sign) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum SignError {
    #[error("ecdsa: invalid private key")]
    InvalidPrivateKey,

    #[error("ecdsa: sign error: {0}")]
    SignError(String),
}

impl Sign for secp256r1::PrivateKey {
    type Sign = [u8; ECC256_SIGN_SIZE];
    type Error = SignError;

    fn sign<T: AsRef<[u8]>>(&self, message: T) -> Result<Self::Sign, Self::Error> {
        let sk: SigningKey = p256::SecretKey::from_slice(self.as_be_bytes())
            .map(|key| key.into())
            .map_err(|_err| SignError::InvalidPrivateKey)?;

        // let mut rnd = rand_core::OsRng;
        let signature: Signature = sk
            .try_sign(message.as_ref())
            .map_err(|err| SignError::SignError(err.to_string()))?;

        let buf = signature.to_bytes(); // big endian
        Ok(buf.as_slice().to_array())
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum VerifyError {
    #[error("ecdsa: invalid public key")]
    InvalidPublicKey,

    #[error("ecdsa: invalid sign")]
    InvalidSign,
}

impl Verify for secp256r1::PublicKey {
    type Sign = [u8; ECC256_SIGN_SIZE];
    type Error = VerifyError;

    #[inline]
    fn verify<T: AsRef<[u8]>>(&self, message: T, sign: &Self::Sign) -> Result<(), Self::Error> {
        let sign = Signature::try_from(sign.as_ref()).map_err(|_err| VerifyError::InvalidSign)?;
        VerifyingKey::from_sec1_bytes(&self.to_uncompressed())
            .map_err(|_err| VerifyError::InvalidPublicKey)?
            .verify(message.as_ref(), &sign)
            .map_err(|_err| VerifyError::InvalidSign)
    }
}
