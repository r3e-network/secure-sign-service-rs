// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use alloc::string::{String, ToString};
use alloc::{vec, vec::Vec};
use hashbrown::HashMap;

use crate::ecdsa::Sign;
use crate::h160::H160;
use crate::neo::check_sign::ToCheckSign;
use crate::neo::signpb::*;
use crate::neo::{Contract, ToScriptHash};
use crate::secp256r1::{Keypair, PublicKey, KEY_SIZE};

#[derive(Clone)]
pub struct Account {
    pub keypair: Keypair,
    pub contract: Option<Contract>,
    pub is_locked: bool,
    // pub is_default: bool,
    // pub address: String,
    // pub label: Option<String>,
    // pub extra: Option<serde_json::Map<String, serde_json::Value>>,
}

pub struct Signer {
    // script hash -> account
    script_hashes: HashMap<H160, Account>,

    // compressed public key -> account
    public_keys: HashMap<[u8; KEY_SIZE + 1], Account>,
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum SignError {
    #[error("sign: invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("sign: no such account")]
    NoSuchAccount,

    #[error("sign: account is locked")]
    AccountLocked,

    #[error("sign: ecdsa sign error: {0}")]
    EcdsaSignError(String),
}

#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum GetAccountStatusError {
    #[error("get-account-status: invalid public key: {0}")]
    InvalidPublicKey(String),
}

impl Signer {
    pub fn new(accounts: Vec<Account>) -> Self {
        let mut script_hashes = HashMap::with_capacity(accounts.len());
        let mut public_keys = HashMap::with_capacity(accounts.len());
        for account in accounts {
            let public_key = account.keypair.public_key();
            let script_hash = public_key.to_check_sign().to_script_hash();
            script_hashes.insert(script_hash, account.clone());
            public_keys.insert(public_key.to_compressed(), account);
        }

        Self {
            script_hashes,
            public_keys,
        }
    }

    pub fn get_account_status(
        &self,
        public_key: &[u8],
    ) -> Result<AccountStatus, GetAccountStatusError> {
        let compressed_public_key = PublicKey::try_to_compressed(public_key)
            .map_err(|err| GetAccountStatusError::InvalidPublicKey(err.to_string()))?;

        let Some(account) = self.public_keys.get(&compressed_public_key) else {
            return Ok(AccountStatus::NoSuchAccount);
        };

        if account.is_locked {
            Ok(AccountStatus::Locked)
        } else {
            // TODO: multisig support
            Ok(AccountStatus::Single)
        }
    }

    pub fn sign_with_public_key(
        &self,
        public_key: &[u8],
        sign_data: &[u8],
    ) -> Result<Vec<u8>, SignError> {
        let compressed_public_key = PublicKey::try_to_compressed(public_key)
            .map_err(|err| SignError::InvalidPublicKey(err.to_string()))?;

        let account = self
            .public_keys
            .get(&compressed_public_key)
            .ok_or(SignError::NoSuchAccount)?;

        if account.is_locked {
            return Err(SignError::AccountLocked);
        }

        account
            .keypair
            .private_key()
            .sign(sign_data)
            .map(|ref sign| sign.to_vec())
            .map_err(|err| SignError::EcdsaSignError(err.to_string()))
    }

    pub fn sign_with_script_hashes(
        &self,
        script_hashes: Vec<H160>,
        sign_data: &[u8],
    ) -> Result<Vec<ScriptHashSigns>, SignError> {
        let mut signs = Vec::<ScriptHashSigns>::with_capacity(script_hashes.len());
        for script_hash in script_hashes {
            let Some(account) = self.script_hashes.get(&script_hash) else {
                signs.push(ScriptHashSigns {
                    signs: Default::default(),
                    status: AccountStatus::NoSuchAccount as i32,
                });
                continue;
            };

            if account.is_locked {
                signs.push(ScriptHashSigns {
                    signs: Default::default(),
                    status: AccountStatus::Locked as i32,
                });
                continue;
            }

            // TODO: multisig support
            let contract = account
                .contract
                .as_ref()
                .map(|c| c.script.clone())
                .unwrap_or_default();

            let signature = account
                .keypair
                .private_key()
                .sign(sign_data)
                .map_err(|err| SignError::EcdsaSignError(err.to_string()))?;

            signs.push(ScriptHashSigns {
                signs: vec![ScriptHashSign {
                    public_key: account.keypair.public_key().to_compressed().to_vec(),
                    signature: signature.to_vec(),
                    contract,
                }],
                status: AccountStatus::Single as i32,
            });
        }
        Ok(signs)
    }
}
