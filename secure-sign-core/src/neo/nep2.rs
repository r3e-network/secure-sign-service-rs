// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use alloc::string::String;
use alloc::vec::Vec;

use crate::aes::Aes256EcbCipher;
use crate::base58::{FromBase58Check, ToBase58Check};
use crate::bytes::ToArray;
use crate::hash::Sha256;
use crate::neo::ToNeo3Address;
use crate::scrypt::{DeriveScryptKey, ScryptParams};
use crate::secp256r1::{Keypair, PrivateKey};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const KEY_SIZE: usize = 32;
const NEP2_KEY_SIZE: usize = 39;
const DERIVED_KEY_SIZE: usize = KEY_SIZE * 2;

pub const fn scrypt_params() -> ScryptParams {
    ScryptParams {
        n: 16384,
        p: 8,
        r: 8,
    }
}

pub trait TryToNep2Key {
    type Error;

    fn try_to_nep2_key(
        &self,
        scrypt_params: ScryptParams,
        passphrase: &[u8],
    ) -> Result<String, Self::Error>;
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ToNep2KeyError {
    #[error("nep2-key: invalid scrypt params")]
    InvalidScryptParams,

    #[error("nep2-key: invalid passphrase")]
    InvalidPassphrase,
}

impl TryToNep2Key for Keypair {
    type Error = ToNep2KeyError;

    /// NOTE: there is no normalization for password
    fn try_to_nep2_key(
        &self,
        scrypt: ScryptParams,
        passphrase: &[u8],
    ) -> Result<String, Self::Error> {
        if passphrase.is_empty() {
            return Err(ToNep2KeyError::InvalidPassphrase);
        }

        let address = self.public_key().to_neo3_address();
        let hash = address.as_str().sha256().sha256();
        let derived = passphrase
            .derive_scrypt_key::<DERIVED_KEY_SIZE>(&hash[..4], scrypt)
            .map_err(|_err| ToNep2KeyError::InvalidScryptParams)?;

        let sk = self.private_key().as_be_bytes();
        let mut key = xor_array::<KEY_SIZE>(sk, &derived[..KEY_SIZE]);
        let _ = derived[KEY_SIZE..]
            .aes256_ecb_encrypt_aligned(key.as_mut_slice())
            .expect("`aes256_ecb_encrypt_aligned` should be ok");

        let mut buf = Vec::<u8>::with_capacity(3 + 4 + key.len());
        buf.push(0x01);
        buf.push(0x42);
        buf.push(0xe0);
        buf.extend_from_slice(&hash[..4]);
        buf.extend_from_slice(key.as_slice());

        Ok(buf.to_base58_check())
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum FromNep2KeyError {
    #[error("nep2-key: invalid base58check")]
    InvalidBase58Check,

    #[error("nep2-key: the key length(base58-decoded) must be 39")]
    InvalidKeyLength,

    #[error("nep2-key: invalid scrypt params")]
    InvalidScryptParams,

    #[error("nep2-key: invalid key hash(maybe wrong passphrase)")]
    InvalidHash,

    #[error("nep2-key: invalid nep2 key")]
    InvalidKey,
}

pub trait TryFromNep2Key {
    fn try_from_nep2_key(
        nep2_key: &str,
        scrypt: ScryptParams,
        passphrase: &[u8],
    ) -> Result<Keypair, FromNep2KeyError>;
}

impl TryFromNep2Key for Keypair {
    /// self is the password
    fn try_from_nep2_key(
        nep2_key: &str,
        scrypt: ScryptParams,
        passphrase: &[u8],
    ) -> Result<Keypair, FromNep2KeyError> {
        let raw = Vec::from_base58_check(nep2_key)
            .map_err(|_err| FromNep2KeyError::InvalidBase58Check)?;
        if raw.len() != NEP2_KEY_SIZE {
            return Err(FromNep2KeyError::InvalidKeyLength);
        }

        let derived = passphrase
            .derive_scrypt_key::<DERIVED_KEY_SIZE>(&raw[3..7], scrypt)
            .expect("default nep2-key params should be ok");

        let mut encrypted: [u8; KEY_SIZE] = raw[7..].to_array();
        let _ = derived[KEY_SIZE..]
            .aes256_ecb_decrypt_aligned(encrypted.as_mut_slice())
            .expect("`aes256_ecb_decrypt_aligned` should be ok");

        let private_key = xor_array::<KEY_SIZE>(&encrypted, &derived[..KEY_SIZE]);
        let keypair = Keypair::new(PrivateKey::new(private_key))
            .map_err(|_err| FromNep2KeyError::InvalidKey)?;

        let addr = keypair.public_key().to_neo3_address();
        let hash = addr.as_str().sha256().sha256();
        if hash[..4].ct_eq(&raw[3..7]).into() {
            Ok(keypair)
        } else {
            Err(FromNep2KeyError::InvalidHash)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256r1::{Keypair, PublicKey};

    #[test]
    fn test_nep2_key_simplified() {
        let key = "6PYWucwbu5pQV9j1wq9kyb571qxUhqDK6vcTsGQtoJXuErzhfptc72RdGF";
        let passphrase = b"xyz";
        let scrypt = ScryptParams { n: 64, p: 2, r: 2 };
        let keypair = Keypair::try_from_nep2_key(key, scrypt, passphrase)
            .expect("try from nep2 key should be ok");

        assert_eq!(
            hex::encode(keypair.private_key().as_be_bytes()),
            "0101010101010101010101010101010101010101010101010101010101010101"
        );

        let addr = keypair.public_key().to_neo3_address();
        assert_eq!(addr.as_str(), "NUz6PKTAM7NbPJzkKJFNay3VckQtcDkgWo");

        assert_eq!(
            hex::encode(keypair.public_key().to_compressed()),
            "026ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca16"
        );
    }

    #[test]
    #[ignore = "skip slow test"]
    fn test_nep2_key_default_params() {
        let sk = hex::decode("7d128a6d096f0c14c3a25a2b0c41cf79661bfcb4a8cc95aaaea28bde4d732344")
            .expect("hex decode should be ok");

        let sk = PrivateKey::from_be_bytes(sk.as_slice()).expect("from be-bytes should be ok");
        let pk = PublicKey::try_from(&sk).expect("from private key should be ok");
        assert_eq!(
            "02028a99826edc0c97d18e22b6932373d908d323aa7f92656a77ec26e8861699ef",
            hex::encode(pk.to_compressed()),
        );
        assert_eq!(
            pk.to_neo3_address().as_str(),
            "NPTmAHDxo6Pkyic8Nvu3kwyXoYJCvcCB6i"
        );

        let passphrase = b"city of zion";
        let key = Keypair::new(sk)
            .expect("private key should be ok")
            .try_to_nep2_key(scrypt_params(), passphrase)
            .expect("try to nep2 key should be ok");
        assert_eq!(
            key.as_str(),
            "6PYUUUFei9PBBfVkSn8q7hFCnewWFRBKPxcn6Kz6Bmk3FqWyLyuTQE2XFH"
        );

        let got = Keypair::try_from_nep2_key(key.as_str(), scrypt_params(), passphrase)
            .expect("try from nep2 key should be ok");
        assert_eq!(
            hex::encode(got.private_key().as_be_bytes()),
            "7d128a6d096f0c14c3a25a2b0c41cf79661bfcb4a8cc95aaaea28bde4d732344",
        );
    }
}
