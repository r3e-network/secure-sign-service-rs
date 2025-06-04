// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use alloc::{string::String, vec::Vec};

use ::base58::{FromBase58, FromBase58Error, ToBase58};

use crate::hash::Sha256;

pub trait ToBase58Check {
    fn to_base58_check(&self) -> String;
}

impl<T: AsRef<[u8]>> ToBase58Check for T {
    fn to_base58_check(&self) -> String {
        let mut buf = Vec::with_capacity(1 + self.as_ref().len() + 1 + 4);
        buf.extend(self.as_ref());

        let check = buf.sha256().sha256();
        buf.extend(&check[..4]);
        buf.to_base58()
    }
}

pub trait FromBase58Check: Sized {
    type Error;

    fn from_base58_check<T: AsRef<str>>(src: T) -> Result<Self, Self::Error>;
}

#[derive(Debug, Copy, Clone, thiserror::Error)]
pub enum FromBase58CheckError {
    #[error("base58check: invalid character '{0}'")]
    InvalidChar(char),

    #[error("base58check: invalid length")]
    InvalidLength,

    #[error("base58check: invalid checksum")]
    InvalidChecksum,
}

impl FromBase58Check for Vec<u8> {
    type Error = FromBase58CheckError;

    fn from_base58_check<T: AsRef<str>>(src: T) -> Result<Vec<u8>, Self::Error> {
        const MIN_SIZE: usize = 5;
        const START_AT: usize = 0;

        let decoded = src.as_ref().from_base58().map_err(|err| match err {
            FromBase58Error::InvalidBase58Character(ch, _) => Self::Error::InvalidChar(ch),
            FromBase58Error::InvalidBase58Length => Self::Error::InvalidLength,
        })?;

        let s = decoded.as_slice();
        if s.len() < MIN_SIZE {
            return Err(Self::Error::InvalidLength);
        }

        let sha = (&s[..s.len() - 4]).sha256().sha256();
        if sha[..4] != s[s.len() - 4..] {
            return Err(Self::Error::InvalidChecksum);
        }

        Ok(s[START_AT..s.len() - 4].into())
    }
}
