// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use alloc::string::{String, ToString};
use core::fmt::{Display, Formatter};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

use crate::bin::{BinEncoder, BinWriter};

pub const H160_SIZE: usize = 20;

/// little endian
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
#[repr(align(8))]
pub struct H160([u8; H160_SIZE]);

impl H160 {
    #[inline]
    pub fn from_le_bytes(src: [u8; H160_SIZE]) -> Self {
        H160(src)
    }

    #[inline]
    pub fn as_le_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; H160_SIZE]> for H160 {
    #[inline]
    fn as_ref(&self) -> &[u8; H160_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for H160 {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for H160 {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        const TABLE: &[u8] = b"0123456789abcdef";
        let mut h = String::with_capacity(H160_SIZE * 2);
        self.0.iter().rev().for_each(|b| {
            h.push(TABLE[(b >> 4) as usize] as char);
            h.push(TABLE[(b & 0x0F) as usize] as char);
        });

        f.write_str("0x")?;
        f.write_str(&h)
    }
}

impl Default for H160 {
    #[inline]
    fn default() -> Self {
        Self([0u8; H160_SIZE])
    }
}

impl BinEncoder for H160 {
    #[inline]
    fn encode_bin(&self, w: &mut impl BinWriter) {
        w.write(self.0);
    }
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum ToH160Error {
    #[error("to-h160: hex-encode H160's length must be 40(without '0x')")]
    InvalidLength,

    #[error("to-h160: invalid character '{0}'")]
    InvalidChar(char),
}

impl TryFrom<&str> for H160 {
    type Error = ToH160Error;

    /// value must be big-endian
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        use hex::FromHexError as HexError;

        let value = value.trim_matches('"');
        let value = if value.starts_with("0x") || value.starts_with("0X") {
            &value[2..]
        } else {
            value
        };

        let mut buf = [0u8; H160_SIZE];
        hex::decode_to_slice(value, &mut buf).map_err(|err| match err {
            HexError::OddLength | HexError::InvalidStringLength => Self::Error::InvalidLength,
            HexError::InvalidHexCharacter { c, index: _ } => Self::Error::InvalidChar(c),
        })?;

        buf.reverse();
        Ok(Self(buf))
    }
}

impl Serialize for H160 {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for H160 {
    #[inline]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        H160::try_from(value.as_str()).map_err(D::Error::custom)
    }
}
