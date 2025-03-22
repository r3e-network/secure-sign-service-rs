// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use alloc::string::{String, ToString};
use alloc::{vec, vec::Vec};

use crate::bin::BinEncoder;
use crate::bytes::ToArray;
use crate::ecdsa::Sign;
use crate::h160::{H160, H160_SIZE};
use crate::h256::{H256, H256_SIZE};
use crate::merkle::MerkleSha256;
use crate::neo::check_sign::ToCheckSign;
use crate::neo::signpb::*;
use crate::neo::{Contract, ToScriptHash, ToSignData, SIGN_DATA_SIZE};
use crate::secp256r1::{Keypair, PublicKey, KEY_SIZE};

use bytes::BytesMut;
use hashbrown::HashMap;

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

pub trait AccountDecrypting {
    type Error;

    fn decrypt_accounts(&self, passphrase: &[u8]) -> Result<Vec<Account>, Self::Error>;
}

pub struct Signer {
    // script hash -> account
    script_hashes: HashMap<H160, Account>,

    // compressed public key -> account
    public_keys: HashMap<[u8; KEY_SIZE + 1], Account>,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum SignError {
    #[error("sign: invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("sign: invalid block: {0}")]
    InvalidBlock(String),

    #[error("sign: invalid extensible payload: {0}")]
    InvalidExtensiblePayload(String),

    #[error("sign: no such account")]
    NoSuchAccount,

    #[error("sign: account is locked")]
    AccountLocked,

    #[error("sign: ecdsa sign error: {0}")]
    EcdsaSignError(String),
}

#[derive(Debug, Clone, thiserror::Error)]
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

    pub fn sign_block(
        &self,
        public_key: &[u8],
        block: &TrimmedBlock,
        network: u32,
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

        let sign_data = Self::trimmed_block_sign_data(block, network)?;
        account
            .keypair
            .private_key()
            .sign(&sign_data)
            .map(|ref sign| sign.into())
            .map_err(|err| SignError::EcdsaSignError(err.to_string()))
    }

    fn trimmed_block_sign_data(
        block: &TrimmedBlock,
        network: u32,
    ) -> Result<[u8; SIGN_DATA_SIZE], SignError> {
        let Some(header) = block.header.as_ref() else {
            return Err(SignError::InvalidBlock("no header".into()));
        };

        let mut buf = BytesMut::with_capacity(512);
        header.version.encode_bin(&mut buf);
        if header.prev_hash.len() != H256_SIZE {
            return Err(SignError::InvalidBlock("invalid prev hash".into()));
        }
        H256::from_le_bytes(header.prev_hash.as_slice().to_array()).encode_bin(&mut buf);

        if header.merkle_root.len() != H256_SIZE {
            return Err(SignError::InvalidBlock("invalid merkle root".into()));
        }
        let merkle_root = H256::from_le_bytes(header.merkle_root.as_slice().to_array());

        let mut tx_hashes = Vec::with_capacity(block.tx_hashes.len());
        for tx_hash in block.tx_hashes.iter() {
            if tx_hash.len() != H256_SIZE {
                return Err(SignError::InvalidBlock("invalid tx hash".into()));
            }
            tx_hashes.push(H256::from_le_bytes(tx_hash.as_slice().to_array()));
        }

        if tx_hashes.merkle_sha256() != merkle_root {
            return Err(SignError::InvalidBlock("merkle root mismatch".into()));
        }

        merkle_root.encode_bin(&mut buf);
        header.timestamp.encode_bin(&mut buf);
        header.nonce.encode_bin(&mut buf);
        header.index.encode_bin(&mut buf);
        if header.primary_index > u8::MAX as u32 {
            return Err(SignError::InvalidBlock("primary index is too large".into()));
        }
        (header.primary_index as u8).encode_bin(&mut buf);

        if header.next_consensus.len() != H160_SIZE {
            return Err(SignError::InvalidBlock("invalid next consensus".into()));
        }
        H160::from_le_bytes(header.next_consensus.as_slice().to_array()).encode_bin(&mut buf);

        Ok(buf.to_sign_data(network))
    }

    pub fn sign_extensible_payload(
        &self,
        payload: &ExtensiblePayload,
        script_hashes: Vec<H160>,
        network: u32,
    ) -> Result<MultiAccountSigns, SignError> {
        let mut signs = Vec::<AccountSigns>::with_capacity(script_hashes.len());
        for script_hash in script_hashes {
            let Some(account) = self.script_hashes.get(&script_hash) else {
                signs.push(AccountSigns {
                    signs: Default::default(),
                    contract: None,
                    status: AccountStatus::NoSuchAccount as i32,
                });
                continue;
            };

            if account.is_locked {
                signs.push(AccountSigns {
                    signs: Default::default(),
                    contract: None,
                    status: AccountStatus::Locked as i32,
                });
                continue;
            }

            // TODO: multisig support
            let contract = account.contract.as_ref().map(|contract| AccountContract {
                script: contract.script.clone(),
                parameters: contract.parameters.iter().map(|p| p.typ as u32).collect(),
                deployed: contract.deployed,
            });

            let sign_data = Self::extensible_sign_data(payload, network)?;
            let signature = account
                .keypair
                .private_key()
                .sign(&sign_data)
                .map_err(|err| SignError::EcdsaSignError(err.to_string()))?;

            signs.push(AccountSigns {
                signs: vec![AccountSign {
                    public_key: account.keypair.public_key().to_compressed().into(),
                    signature: signature.into(),
                }],
                contract,
                status: AccountStatus::Single as i32,
            });
        }

        Ok(MultiAccountSigns { signs })
    }

    fn extensible_sign_data(
        payload: &ExtensiblePayload,
        network: u32,
    ) -> Result<[u8; SIGN_DATA_SIZE], SignError> {
        let mut buf = BytesMut::with_capacity(512);
        payload.category.as_bytes().encode_bin(&mut buf);
        payload.valid_block_start.encode_bin(&mut buf);
        payload.valid_block_end.encode_bin(&mut buf);

        if payload.sender.len() != H160_SIZE {
            return Err(SignError::InvalidExtensiblePayload("invalid sender".into()));
        }
        H160::from_le_bytes(payload.sender.as_slice().to_array()).encode_bin(&mut buf);
        payload.data.as_slice().encode_bin(&mut buf);

        Ok(buf.to_sign_data(network))
    }
}
