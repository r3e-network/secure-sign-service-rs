// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::neo::ParamType;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Scrypt {
    pub n: u64,
    pub r: u64,
    pub p: u64,
}

pub type Extra = Option<serde_json::Map<String, serde_json::Value>>;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Nep6Contract {
    pub script: String, // base64 encoded
    pub deployed: bool,
    pub parameters: Vec<ParamType>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Nep6Account {
    // uint160, 0x...
    pub address: String,

    pub label: Option<String>,

    #[serde(rename = "isDefault")]
    pub is_default: bool,

    #[serde(rename = "lock")]
    pub is_locked: bool,

    // i.e. EncryptedWIF
    pub key: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<Nep6Contract>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Extra,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Nep6Wallet {
    pub name: Option<String>,
    pub version: String,
    pub scrypt: Scrypt,
    pub accounts: Vec<Nep6Account>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Extra,
}

impl Nep6Wallet {
    pub fn default_account(&self) -> Option<&Nep6Account> {
        self.accounts.iter().find(|item| item.is_default)
    }
}
