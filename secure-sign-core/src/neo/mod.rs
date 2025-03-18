// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

pub mod check_sign;
pub mod nep2;
pub mod nep6;
pub mod sign;
pub mod signpb;

use alloc::vec::Vec;
use alloc::string::String;
use serde::{Deserialize, Serialize};

use crate::base58::ToBase58Check;
use crate::h160::{H160, H160_SIZE};
use crate::hash::{Ripemd160, Sha256};
use crate::neo::check_sign::{CheckSign, ToCheckSign};
use crate::secp256r1::PublicKey;

pub const SCRIPT_HASH_SIZE: usize = H160_SIZE;
pub const ADDRESS_NEO3: u8 = 0x35;

pub trait ToScriptHash {
    fn to_script_hash(&self) -> H160;
}

impl<T: AsRef<[u8]>> ToScriptHash for T {
    #[inline]
    fn to_script_hash(&self) -> H160 {
        H160::from_le_bytes(self.as_ref().sha256().ripemd160())
    }
}

impl ToScriptHash for CheckSign {
    #[inline]
    fn to_script_hash(&self) -> H160 {
        H160::from_le_bytes(self.as_bytes().sha256().ripemd160())
    }
}

pub struct Address {
    version: u8,
    base58check: String,
}

impl Address {
    #[inline]
    pub fn version(&self) -> u8 {
        self.version
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        self.base58check.as_str()
    }
}

pub trait ToNeo3Address {
    fn to_neo3_address(&self) -> Address;
}

impl ToNeo3Address for H160 {
    #[inline]
    fn to_neo3_address(&self) -> Address {
        let mut addr = [0u8; 1 + SCRIPT_HASH_SIZE];
        addr[0] = ADDRESS_NEO3;
        addr[1..].copy_from_slice(self.as_le_bytes());

        Address {
            version: ADDRESS_NEO3,
            base58check: addr.to_base58_check(),
        }
    }
}

impl ToNeo3Address for PublicKey {
    #[inline]
    fn to_neo3_address(&self) -> Address {
        self.to_check_sign().to_script_hash().to_neo3_address()
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum ParamType {
    Any = 0x00,
    Boolean = 0x10,
    Integer = 0x11,
    ByteArray = 0x12,
    String = 0x13,
    H160 = 0x14,
    H256 = 0x15,
    PublicKey = 0x16,
    Signature = 0x17,
    Array = 0x20,
    Map = 0x22,
    InteropInterface = 0x30,
    Void = 0xff,
}

#[derive(Debug, Clone)]
pub struct Contract {
    pub script: Vec<u8>,
    pub deployed: bool,
    pub parameters: Vec<ParamType>,
}
