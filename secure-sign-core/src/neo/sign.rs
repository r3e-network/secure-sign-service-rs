// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # NEO Blockchain Signing Implementation
//!
//! This module provides cryptographic signing services specifically designed for the NEO N3 blockchain.
//! It handles two primary operations:
//!
//! 1. **Block Signing**: For consensus node participation in block creation
//! 2. **Extensible Payload Signing**: For transactions and other blockchain operations
//!
//! ## Security Features
//!
//! - Account-based signing with locked/unlocked state management
//! - Script hash and public key indexing for fast lookups
//! - Comprehensive input validation for all NEO data structures
//! - Memory-safe operations with automatic cleanup

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

use bytes::BytesMut;
use hashbrown::HashMap;

use crate::{
    bin::BinEncoder,
    bytes::ToArray,
    ecdsa::Sign,
    h160::{H160, H160_SIZE},
    h256::{H256, H256_SIZE},
    merkle::MerkleSha256,
    neo::{check_sign::ToCheckSign, signpb::*, Contract, ToScriptHash, ToSignData, SIGN_DATA_SIZE},
    secp256r1::{Keypair, PublicKey, KEY_SIZE},
};

/// Represents a NEO account with cryptographic credentials and metadata
///
/// Each account contains:
/// - A secp256r1 keypair for signing operations
/// - Optional smart contract information for multi-signature accounts
/// - Lock status to prevent unauthorized signing
#[derive(Clone)]
pub struct Account {
    /// The cryptographic keypair for this account
    pub keypair: Keypair,
    /// Smart contract details for multi-signature accounts (optional)
    pub contract: Option<Contract>,
    /// Whether this account is locked and cannot perform signing operations
    pub is_locked: bool,
}

/// Trait for decrypting NEP-6 encrypted account data
///
/// Implementations should handle the scrypt key derivation and AES decryption
/// required to unlock NEP-6 wallet files with the provided passphrase.
pub trait AccountDecrypting {
    type Error;

    /// Decrypt all accounts in a wallet using the provided passphrase
    ///
    /// # Arguments
    /// * `passphrase` - The wallet decryption passphrase
    ///
    /// # Returns
    /// Vector of decrypted accounts or an error if decryption fails
    fn decrypt_accounts(&self, passphrase: &[u8]) -> Result<Vec<Account>, Self::Error>;
}

/// Core signing service for NEO blockchain operations
///
/// The Signer maintains two lookup tables for efficient account access:
/// 1. Script hash -> Account (for extensible payload signing)
/// 2. Compressed public key -> Account (for block signing and status queries)
///
/// This dual indexing allows O(1) lookups for both signing scenarios.
pub struct Signer {
    /// Maps script hash to account (used for extensible payload signing)
    script_hashes: HashMap<H160, Account>,
    /// Maps compressed public key to account (used for block signing)
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
    /// Create a new signer from a collection of decrypted accounts
    ///
    /// This constructor builds the internal lookup tables for efficient
    /// account resolution during signing operations.
    ///
    /// # Arguments
    /// * `accounts` - Vector of decrypted accounts to manage
    ///
    /// # Performance Note
    /// This method has O(n) complexity where n is the number of accounts.
    /// The resulting lookup operations are O(1).
    pub fn new(accounts: Vec<Account>) -> Self {
        let mut script_hashes = HashMap::with_capacity(accounts.len());
        let mut public_keys = HashMap::with_capacity(accounts.len());

        for account in accounts {
            let public_key = account.keypair.public_key();

            // Generate script hash for this account's verification script
            // This is used for extensible payload signing
            let script_hash = public_key.to_check_sign().to_script_hash();
            script_hashes.insert(script_hash, account.clone());

            // Index by compressed public key for block signing
            public_keys.insert(public_key.to_compressed(), account);
        }

        Self {
            script_hashes,
            public_keys,
        }
    }

    /// Query the status of an account by public key
    ///
    /// Returns the signing capability of the account:
    /// - NoSuchAccount: Account not found in this signer
    /// - Locked: Account exists but is locked
    /// - Single: Single-signature account ready for signing
    /// - Multiple: Multi-signature account (future implementation)
    ///
    /// # Arguments
    /// * `public_key` - Public key in compressed or uncompressed format
    pub fn get_account_status(
        &self,
        public_key: &[u8],
    ) -> Result<AccountStatus, GetAccountStatusError> {
        // Normalize to compressed format for lookup
        let compressed_public_key = PublicKey::try_to_compressed(public_key)
            .map_err(|err| GetAccountStatusError::InvalidPublicKey(err.to_string()))?;

        let Some(account) = self.public_keys.get(&compressed_public_key) else {
            return Ok(AccountStatus::NoSuchAccount);
        };

        if account.is_locked {
            Ok(AccountStatus::Locked)
        } else {
            // TODO: Add support for multi-signature accounts
            Ok(AccountStatus::Single)
        }
    }

    /// Sign a NEO block header for consensus participation
    ///
    /// This method performs the complete block signing workflow:
    /// 1. Validates the public key and finds the corresponding account
    /// 2. Checks account lock status
    /// 3. Validates the block structure and merkle root
    /// 4. Constructs the signing data according to NEO protocol
    /// 5. Generates the ECDSA signature
    ///
    /// # Arguments
    /// * `public_key` - Public key of the signing account
    /// * `block` - Block header to sign
    /// * `network` - NEO network identifier (mainnet/testnet)
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - 64-byte ECDSA signature
    /// * `Err(SignError)` - Validation or signing failure
    ///
    /// # NEO Protocol Notes
    /// The signing data includes:
    /// - Block header fields (version, prev_hash, merkle_root, etc.)
    /// - Network-specific magic number
    /// - SHA256 hash for final signature input
    pub fn sign_block(
        &self,
        public_key: &[u8],
        block: &TrimmedBlock,
        network: u32,
    ) -> Result<Vec<u8>, SignError> {
        // Normalize public key format for account lookup
        let compressed_public_key = PublicKey::try_to_compressed(public_key)
            .map_err(|err| SignError::InvalidPublicKey(err.to_string()))?;

        // Find the account for this public key
        let account = self
            .public_keys
            .get(&compressed_public_key)
            .ok_or(SignError::NoSuchAccount)?;

        // Check if account is available for signing
        if account.is_locked {
            return Err(SignError::AccountLocked);
        }

        // Construct NEO block signing data
        let sign_data = Self::trimmed_block_sign_data(block, network)?;

        // Generate ECDSA signature
        account
            .keypair
            .private_key()
            .sign(sign_data)
            .map(|ref sign| sign.into())
            .map_err(|err| SignError::EcdsaSignError(err.to_string()))
    }

    /// Construct signing data for a NEO block according to protocol specification
    ///
    /// The NEO block signing data format is:
    /// ```text
    /// version (4 bytes) || prev_hash (32 bytes) || merkle_root (32 bytes) ||
    /// timestamp (8 bytes) || nonce (8 bytes) || index (4 bytes) ||
    /// primary_index (1 byte) || next_consensus (20 bytes) || network (4 bytes)
    /// ```
    ///
    /// This data is then hashed with SHA256 to produce the final signing input.
    ///
    /// # Security Notes
    /// - Validates merkle root against transaction hashes
    /// - Ensures all hash fields are exactly the required length
    /// - Validates primary index fits in a single byte
    fn trimmed_block_sign_data(
        block: &TrimmedBlock,
        network: u32,
    ) -> Result<[u8; SIGN_DATA_SIZE], SignError> {
        let Some(header) = block.header.as_ref() else {
            return Err(SignError::InvalidBlock("no header".into()));
        };

        let mut buf = BytesMut::with_capacity(512);

        // Encode block header fields in NEO binary format
        header.version.encode_bin(&mut buf);

        // Validate and encode previous block hash
        if header.prev_hash.len() != H256_SIZE {
            return Err(SignError::InvalidBlock("invalid prev hash".into()));
        }
        H256::from_le_bytes(header.prev_hash.as_slice().to_array()).encode_bin(&mut buf);

        // Validate merkle root length
        if header.merkle_root.len() != H256_SIZE {
            return Err(SignError::InvalidBlock("invalid merkle root".into()));
        }
        let merkle_root = H256::from_le_bytes(header.merkle_root.as_slice().to_array());

        // Verify merkle root matches transaction hashes
        let mut tx_hashes = Vec::with_capacity(block.tx_hashes.len());
        for tx_hash in block.tx_hashes.iter() {
            if tx_hash.len() != H256_SIZE {
                return Err(SignError::InvalidBlock("invalid tx hash".into()));
            }
            tx_hashes.push(H256::from_le_bytes(tx_hash.as_slice().to_array()));
        }

        // Critical security check: ensure merkle root integrity
        if tx_hashes.merkle_sha256() != merkle_root {
            return Err(SignError::InvalidBlock("merkle root mismatch".into()));
        }

        // Continue encoding header fields
        merkle_root.encode_bin(&mut buf);
        header.timestamp.encode_bin(&mut buf);
        header.nonce.encode_bin(&mut buf);
        header.index.encode_bin(&mut buf);

        // Validate primary index fits in one byte
        if header.primary_index > u8::MAX as u32 {
            return Err(SignError::InvalidBlock("primary index is too large".into()));
        }
        (header.primary_index as u8).encode_bin(&mut buf);

        // Validate and encode next consensus script hash
        if header.next_consensus.len() != H160_SIZE {
            return Err(SignError::InvalidBlock("invalid next consensus".into()));
        }
        H160::from_le_bytes(header.next_consensus.as_slice().to_array()).encode_bin(&mut buf);

        // Finalize with network magic and SHA256 hash
        Ok(buf.to_sign_data(network))
    }

    /// Sign a NEO extensible payload (transactions, oracle responses, etc.)
    ///
    /// Extensible payloads are signed by their associated script hashes rather than
    /// specific public keys. This method:
    /// 1. Attempts to sign with each provided script hash
    /// 2. Returns appropriate status for each (signed, not found, locked)
    /// 3. Includes contract information for multi-signature accounts
    ///
    /// # Arguments
    /// * `payload` - The extensible payload to sign
    /// * `script_hashes` - Vector of script hashes to attempt signing with
    /// * `network` - NEO network identifier
    ///
    /// # Returns
    /// `MultiAccountSigns` containing results for each script hash
    pub fn sign_extensible_payload(
        &self,
        payload: &ExtensiblePayload,
        script_hashes: Vec<H160>,
        network: u32,
    ) -> Result<MultiAccountSigns, SignError> {
        let mut signs = Vec::<AccountSigns>::with_capacity(script_hashes.len());

        for script_hash in script_hashes {
            // Try to find account for this script hash
            let Some(account) = self.script_hashes.get(&script_hash) else {
                signs.push(AccountSigns {
                    signs: Default::default(),
                    contract: None,
                    status: AccountStatus::NoSuchAccount as i32,
                });
                continue;
            };

            // Check if account is locked
            if account.is_locked {
                signs.push(AccountSigns {
                    signs: Default::default(),
                    contract: None,
                    status: AccountStatus::Locked as i32,
                });
                continue;
            }

            // Include contract information for multi-signature accounts
            let contract = account.contract.as_ref().map(|contract| AccountContract {
                script: contract.script.clone(),
                parameters: contract.parameters.iter().map(|p| p.typ as u32).collect(),
                deployed: contract.deployed,
            });

            // Construct signing data and generate signature
            let sign_data = Self::extensible_sign_data(payload, network)?;
            let signature = account
                .keypair
                .private_key()
                .sign(sign_data)
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

    /// Construct signing data for NEO extensible payloads
    ///
    /// The extensible payload signing data format is:
    /// ```text
    /// category (variable) || valid_block_start (4 bytes) || valid_block_end (4 bytes) ||
    /// sender (20 bytes) || data (variable) || network (4 bytes)
    /// ```
    ///
    /// This data is then hashed with SHA256 to produce the final signing input.
    fn extensible_sign_data(
        payload: &ExtensiblePayload,
        network: u32,
    ) -> Result<[u8; SIGN_DATA_SIZE], SignError> {
        let mut buf = BytesMut::with_capacity(512);

        // Encode payload fields in NEO binary format
        payload.category.as_bytes().encode_bin(&mut buf);
        payload.valid_block_start.encode_bin(&mut buf);
        payload.valid_block_end.encode_bin(&mut buf);

        // Validate and encode sender script hash
        if payload.sender.len() != H160_SIZE {
            return Err(SignError::InvalidExtensiblePayload("invalid sender".into()));
        }
        H160::from_le_bytes(payload.sender.as_slice().to_array()).encode_bin(&mut buf);
        payload.data.as_slice().encode_bin(&mut buf);

        // Finalize with network magic and SHA256 hash
        Ok(buf.to_sign_data(network))
    }
}
