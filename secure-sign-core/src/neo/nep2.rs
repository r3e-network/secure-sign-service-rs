// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use alloc::vec::Vec;
use zeroize::Zeroizing;

use crate::aes::Aes256EcbCipher;
use crate::base58::FromBase58Check;
use crate::bytes::ToArray;
use crate::hash::Sha256;
use crate::neo::ToNeo3Address;
use crate::scrypt::{DeriveScryptKey, ScryptParams};
use crate::secp256r1::{Keypair, PrivateKey};

use subtle::ConstantTimeEq;

const KEY_SIZE: usize = 32;
const NEP2_KEY_SIZE: usize = 39;
const DERIVED_KEY_SIZE: usize = KEY_SIZE * 2;

#[derive(Debug, Clone, thiserror::Error)]
pub enum Nep2DecryptError {
    #[error("nep2-key: invalid base58check")]
    InvalidBase58Check,

    #[error("nep2-key: the key length(base58-decoded) must be 39")]
    InvalidKeyLength,

    #[error("nep2-key: invalid key hash")]
    InvalidHash,

    #[error("nep2-key: invalid nep2 key")]
    InvalidKey,
}

pub const fn scrypt_params() -> ScryptParams {
    ScryptParams {
        n: 16384,
        p: 8,
        r: 8,
        len: 64,
    }
}

pub trait Nep2KeyDecrypt {
    fn decrypt_nep2_key(&self, nep2_key: &str) -> Result<Keypair, Nep2DecryptError>;
}

impl<T: AsRef<[u8]>> Nep2KeyDecrypt for T {
    /// self is the password
    fn decrypt_nep2_key(&self, nep2_key: &str) -> Result<Keypair, Nep2DecryptError> {
        let raw = Vec::from_base58_check(nep2_key)
            .map_err(|_err| Nep2DecryptError::InvalidBase58Check)?;

        if raw.len() != NEP2_KEY_SIZE {
            return Err(Nep2DecryptError::InvalidKeyLength);
        }

        let derived = self
            .derive_scrypt_key::<DERIVED_KEY_SIZE>(&raw[3..7], scrypt_params())
            .expect("default nep2-key params should be ok");

        let mut encrypted: [u8; KEY_SIZE] = raw[7..].to_array();
        let _ = derived[KEY_SIZE..]
            .aes256_ecb_decrypt_aligned(encrypted.as_mut_slice())
            .expect("`aes256_ecb_decrypt_aligned` should be ok");

        let private_key = xor_array::<KEY_SIZE>(&encrypted, &derived[..KEY_SIZE]);
        let private_key = PrivateKey::from_be_bytes(private_key.as_slice())
            .map_err(|_err| Nep2DecryptError::InvalidKey)?;

        let keypair = Keypair::new(private_key).map_err(|_err| Nep2DecryptError::InvalidKey)?;

        let addr = keypair.public_key().to_neo3_address();
        let hash = addr.as_str().sha256().sha256();
        if hash[..4].ct_eq(&raw[3..7]).into() {
            Ok(keypair)
        } else {
            Err(Nep2DecryptError::InvalidHash)
        }
    }
}

fn xor_array<const N: usize>(left: &[u8], right: &[u8]) -> Zeroizing<[u8; N]> {
    let mut dest = Zeroizing::new([0u8; N]);
    if left.len() != right.len() {
        core::panic!("left length {} != right length {}", left.len(), right.len());
    }

    if left.len() != dest.len() {
        core::panic!("source length {} != dest length {}", left.len(), N);
    }

    left.into_iter()
        .enumerate()
        .for_each(|(idx, v)| dest[idx] = v ^ right[idx]);
    dest
}
