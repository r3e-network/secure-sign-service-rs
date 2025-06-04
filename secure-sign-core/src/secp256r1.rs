// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use alloc::string::{String, ToString};

use p256::elliptic_curve::sec1::ToEncodedPoint;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{bytes::ToArray, random::CryptRandom};

pub const KEY_SIZE: usize = 32;

#[derive(Debug, Clone)]
pub struct PrivateKey {
    // key is in big endian
    key: Zeroizing<[u8; KEY_SIZE]>,
}

#[derive(Debug, Copy, Clone, thiserror::Error)]
pub enum DecodePrivateKeyError {
    #[error("secp256r1: invalid key length")]
    InvalidKeyLength,
}

impl PrivateKey {
    #[inline]
    pub fn new(big_endian_key: Zeroizing<[u8; KEY_SIZE]>) -> Self {
        Self {
            key: big_endian_key,
        }
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Result<Self, DecodePrivateKeyError> {
        if bytes.len() != KEY_SIZE {
            return Err(DecodePrivateKeyError::InvalidKeyLength);
        }
        Ok(Self::new(Zeroizing::new(bytes.to_array())))
    }

    #[inline]
    pub fn as_be_bytes(&self) -> &[u8] {
        self.key.as_slice()
    }
}

impl Eq for PrivateKey {}

impl PartialEq for PrivateKey {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.key.as_slice().ct_eq(other.key.as_slice()).into()
    }
}

impl PartialEq<[u8]> for PrivateKey {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.key.as_slice().ct_eq(other).into()
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PublicKey {
    // gx, gy are in big endian
    gx: [u8; KEY_SIZE],
    gy: [u8; KEY_SIZE],
}

impl PublicKey {
    pub fn to_uncompressed(&self) -> [u8; 2 * KEY_SIZE + 1] {
        let mut buf = [0u8; 2 * KEY_SIZE + 1];
        buf[0] = 0x04;
        buf[1..1 + KEY_SIZE].copy_from_slice(self.gx.as_slice());
        buf[1 + KEY_SIZE..].copy_from_slice(self.gy.as_slice());

        // buf[1..1 + KEY_SIZE].reverse();
        // buf[1 + KEY_SIZE..].reverse();
        buf
    }

    pub fn to_compressed(&self) -> [u8; KEY_SIZE + 1] {
        let mut buf = [0u8; KEY_SIZE + 1];
        buf[0] = 0x02 + (self.gy[KEY_SIZE - 1] & 0x01); // 0x02 when y is even, 0x03 when y is odd
        buf[1..].copy_from_slice(self.gx.as_slice());

        // buf[1..].reverse();
        buf
    }

    pub fn try_to_compressed(key: &[u8]) -> Result<[u8; KEY_SIZE + 1], DecodePublicKeyError> {
        match key.len() {
            33 => {
                if key[0] != 0x02 && key[0] != 0x03 {
                    return Err(DecodePublicKeyError::InvalidPrefix(key[0], 33));
                }
                Ok(key.to_array())
            }
            65 => {
                if key[0] != 0x04 {
                    return Err(DecodePublicKeyError::InvalidPrefix(key[0], 65));
                }

                let mut buf = [0u8; KEY_SIZE + 1];
                buf[0] = 0x02 + (key[2 * KEY_SIZE] & 0x01); // 0x02 when y is even, 0x03 when y is odd
                buf[1..].copy_from_slice(&key[1..1 + KEY_SIZE]); // copy x
                Ok(buf)
            }
            _ => Err(DecodePublicKeyError::InvalidKeyLength(key.len())),
        }
    }
}

#[derive(Debug, Copy, Clone, thiserror::Error)]
pub enum DecodePublicKeyError {
    #[error("secp256r1: invalid key length({0}, not 33 or 65)")]
    InvalidKeyLength(usize),

    #[error("secp256r1: invalid prefix byte({0}) when length is {1}")]
    InvalidPrefix(u8, usize),
}

#[derive(Debug, Copy, Clone, thiserror::Error)]
pub enum FromPrivateKeyError {
    #[error("secp256r1: invalid private key")]
    InvalidPrivateKey,
}

impl TryFrom<&PrivateKey> for PublicKey {
    type Error = FromPrivateKeyError;

    fn try_from(private_key: &PrivateKey) -> Result<Self, Self::Error> {
        use FromPrivateKeyError as Error;

        // let private_key = Zeroizing::new(private_key.key.to_rev_array());
        let pk = p256::SecretKey::from_slice(private_key.as_be_bytes())
            .map_err(|_| Error::InvalidPrivateKey)?
            .public_key()
            .to_encoded_point(false);

        let gx = pk.x().ok_or(Error::InvalidPrivateKey)?;
        let gy = pk.y().ok_or(Error::InvalidPrivateKey)?;
        Ok(PublicKey {
            gx: gx.as_slice().to_array(),
            gy: gy.as_slice().to_array(),
        })
    }
}

#[derive(Clone)]
pub struct Keypair {
    private_key: PrivateKey,
    public_key: PublicKey,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum GenKeypairError {
    #[error("secp256r1: generate random bytes")]
    GenRandomError(String),

    #[error("secp256r1: invalid random bytes")]
    InvalidRandom,
}

impl Keypair {
    #[inline]
    pub fn new(private_key: PrivateKey) -> Result<Self, FromPrivateKeyError> {
        let public_key = PublicKey::try_from(&private_key)?;
        Ok(Self {
            private_key,
            public_key,
        })
    }

    #[inline]
    pub const fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    #[inline]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn gen(crypt_rand: &mut impl CryptRandom) -> Result<Self, GenKeypairError> {
        let mut buf = p256::FieldBytes::default();
        crypt_rand
            .try_fill_bytes(&mut buf)
            .map_err(|err| GenKeypairError::GenRandomError(err.to_string()))?;

        let sk = p256::SecretKey::from_slice(&buf).map_err(|_| GenKeypairError::InvalidRandom)?;
        let pk = sk.public_key().to_encoded_point(false);
        let gx = pk.x().ok_or(GenKeypairError::InvalidRandom)?;
        let gy = pk.y().ok_or(GenKeypairError::InvalidRandom)?;

        buf.zeroize();
        Ok(Self {
            private_key: PrivateKey::new(Zeroizing::new(sk.to_bytes().as_slice().to_array())),
            public_key: PublicKey {
                gx: gx.as_slice().to_array(),
                gy: gy.as_slice().to_array(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ecdsa::{Sign, Verify},
        random::EnvCryptRandom,
    };

    #[test]
    fn test_keypair_gen() {
        let mut rng = EnvCryptRandom;
        let keypair = Keypair::gen(&mut rng).expect("gen keypair");

        let message = b"hello, world";
        let sign = keypair.private_key().sign(message).expect("sign message");

        keypair
            .public_key()
            .verify(message, &sign)
            .expect("verify message");
    }
}
