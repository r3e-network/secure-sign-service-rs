// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use alloc::string::String;
use core::fmt::{Display, Formatter};

use crate::bin::{BinEncoder, BinWriter};

pub const H256_SIZE: usize = 32;

/// little endian
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub struct H256([u8; H256_SIZE]);

impl H256 {
    pub fn from_le_bytes(src: [u8; H256_SIZE]) -> Self {
        H256(src)
    }

    pub fn as_le_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; H256_SIZE]> for H256 {
    #[inline]
    fn as_ref(&self) -> &[u8; H256_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for H256 {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for H256 {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        const TABLE: &[u8] = b"0123456789abcdef";
        let mut h = String::with_capacity(H256_SIZE * 2);
        self.0.iter().rev().for_each(|b| {
            h.push(TABLE[(b >> 4) as usize] as char);
            h.push(TABLE[(b & 0x0F) as usize] as char);
        });

        f.write_str("0x")?;
        f.write_str(&h)
    }
}

impl Default for H256 {
    #[inline]
    fn default() -> Self {
        Self([0u8; H256_SIZE])
    }
}

impl BinEncoder for H256 {
    #[inline]
    fn encode_bin(&self, w: &mut impl BinWriter) {
        w.write(self.0);
    }
}
