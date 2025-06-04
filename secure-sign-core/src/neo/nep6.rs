// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! # NEP-6 Wallet Implementation
//!
//! This module implements the NEP-6 wallet standard for the NEO blockchain.
//! NEP-6 defines the JSON wallet format that securely stores encrypted private keys
//! and associated account metadata.
//!
//! ## NEP-6 Standard Overview
//!
//! NEP-6 wallets use a multi-layer encryption scheme:
//!
//! 1. **Key Derivation**: Scrypt algorithm stretches the user passphrase
//! 2. **Private Key Encryption**: AES-256-CBC encrypts each private key individually  
//! 3. **Base58Check Encoding**: NEP-2 format for the encrypted key string
//! 4. **JSON Serialization**: Human-readable wallet file format
//!
//! ## Security Features
//!
//! - **Scrypt Key Derivation**: Configurable N, r, p parameters for computational cost
//! - **Per-Key Encryption**: Each private key encrypted separately with derived key
//! - **Checksum Validation**: NEP-2 format includes integrity checking
//! - **Memory Safety**: Automatic zeroization of decrypted keys when dropped
//!
//! ## Wallet Structure
//!
//! ```json
//! {
//!   "name": "MyWallet",
//!   "version": "3.0",
//!   "scrypt": { "n": 16384, "r": 8, "p": 8 },
//!   "accounts": [
//!     {
//!       "address": "NcpFNZqS5YLVWtZKJ5yYKfzXUcDsGx2Fhw",
//!       "label": "Main Account",
//!       "isdefault": true,
//!       "lock": false,
//!       "key": "6PYWVp3xfgvnuNKP7ZMTgXxWBCPNKGShkhyzUWvqWjPJECRKOkLAd4",
//!       "contract": {
//!         "script": "DCECb8A7lJJBzh2t1...",
//!         "deployed": false,
//!         "parameters": [{"name": "signature", "type": "Signature"}]
//!       }
//!     }
//!   ]
//! }
//! ```

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use serde::{Deserialize, Serialize};

use crate::{
    base64::FromBase64,
    neo::{
        nep2::TryFromNep2Key,
        sign::{Account, AccountDecrypting},
        Contract, NamedParamType,
    },
    scrypt::ScryptParams,
    secp256r1::Keypair,
};

/// Extended JSON data for additional wallet metadata
/// Allows wallets to store custom application-specific data
pub type Extra = Option<serde_json::Map<String, serde_json::Value>>;

/// NEP-6 smart contract information
///
/// Contains the verification script and metadata for accounts that use
/// smart contracts (such as multi-signature accounts) instead of simple
/// single-signature verification.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Nep6Contract {
    /// Base64-encoded verification script bytecode
    ///
    /// This script defines the conditions under which transactions
    /// from this account are considered valid. For single-signature accounts,
    /// this is typically a simple signature verification script.
    pub script: String,

    /// Whether the contract has been deployed to the blockchain
    ///
    /// - `true`: Contract is deployed and can be invoked
    /// - `false`: Contract exists only in the wallet (typical for verification scripts)
    pub deployed: bool,

    /// Parameter definitions for the contract
    ///
    /// Describes the expected input parameters for the contract's main method,
    /// typically used for signature verification.
    pub parameters: Vec<NamedParamType>,
}

/// NEP-6 account entry within a wallet
///
/// Represents a single blockchain account with its encrypted private key
/// and associated metadata. Each account corresponds to one NEO address.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Nep6Account {
    /// NEO address in Base58Check format (e.g., "NcpFNZqS5YLVWtZKJ5yYKfzXUcDsGx2Fhw")
    ///
    /// This is the public identifier for the account, derived from the
    /// account's verification script hash.
    pub address: String,

    /// Optional human-readable label for the account
    ///
    /// Used in wallet UIs to help users identify accounts.
    /// Common examples: "Main Account", "Savings", "Trading"
    #[serde(default)]
    pub label: Option<String>,

    /// Whether this account is the default for the wallet
    ///
    /// Wallets typically designate one account as the default for
    /// operations when no specific account is specified.
    #[serde(default, rename = "isdefault")]
    pub is_default: bool,

    /// Whether this account is locked and cannot perform operations
    ///
    /// Locked accounts require additional authorization before use.
    /// This provides an extra security layer for important accounts.
    #[serde(default, rename = "lock")]
    pub is_locked: bool,

    /// NEP-2 encrypted private key string
    ///
    /// The private key encrypted using the wallet's passphrase and scrypt parameters.
    /// Format: Base58Check-encoded encrypted key with NEP-2 prefix.
    /// Example: "6PYWVp3xfgvnuNKP7ZMTgXxWBCPNKGShkhyzUWvqWjPJECRKOkLAd4"
    pub key: String,

    /// Smart contract information (optional)
    ///
    /// Present for accounts that use custom verification scripts,
    /// such as multi-signature accounts or contract-based accounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<Nep6Contract>,

    /// Additional application-specific metadata (optional)
    ///
    /// Allows wallet applications to store custom data associated
    /// with this account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Extra,
}

/// NEP-6 wallet file structure
///
/// The top-level container for a NEO wallet, containing multiple accounts
/// and the shared encryption parameters used to protect all private keys.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Nep6Wallet {
    /// Human-readable wallet name (optional)
    ///
    /// Used in wallet UIs to help users identify different wallets.
    /// Example: "Personal Wallet", "Business Account"
    pub name: Option<String>,

    /// NEP-6 specification version
    ///
    /// Indicates the version of the NEP-6 standard used.
    /// Current standard version is "3.0".
    pub version: String,

    /// Scrypt key derivation parameters
    ///
    /// These parameters control the computational cost of deriving
    /// encryption keys from the user's passphrase. Higher values
    /// provide better security but require more computation time.
    pub scrypt: ScryptParams,

    /// Array of accounts in this wallet
    ///
    /// Each account represents one NEO address with its encrypted
    /// private key and associated metadata.
    pub accounts: Vec<Nep6Account>,

    /// Additional wallet-level metadata (optional)
    ///
    /// Allows wallet applications to store custom data at the
    /// wallet level rather than per-account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Extra,
}

/// Errors that can occur during NEP-6 account processing
#[derive(Debug, Clone, thiserror::Error)]
pub enum Nep6AccountError {
    #[error("nep6-account: invalid encrypted key: {0}")]
    InvalidEncryptedKey(String),

    #[error("nep6-account: invalid contract: {0}")]
    InvalidContract(String),
}

/// Implementation of wallet decryption for NEP-6 format
///
/// This trait implementation handles the complete decryption process:
/// 1. Derives the encryption key from passphrase using scrypt
/// 2. Decrypts each account's private key using NEP-2 format
/// 3. Reconstructs keypairs and contract information
/// 4. Returns ready-to-use Account objects for signing operations
impl AccountDecrypting for Nep6Wallet {
    type Error = Nep6AccountError;

    /// Decrypt all accounts in the wallet using the provided passphrase
    ///
    /// This method performs the complete NEP-6 wallet decryption process:
    ///
    /// ## Decryption Process
    ///
    /// For each account in the wallet:
    /// 1. **NEP-2 Decryption**: Decrypt the private key using scrypt + AES
    /// 2. **Keypair Reconstruction**: Create secp256r1 keypair from private key
    /// 3. **Contract Processing**: Decode contract scripts from Base64
    /// 4. **Account Assembly**: Create Account object with all metadata
    ///
    /// ## Cryptographic Operations
    ///
    /// - **Scrypt Key Derivation**: Uses wallet's N, r, p parameters
    /// - **AES-256-CBC Decryption**: Decrypts private key with derived key
    /// - **Checksum Validation**: Verifies NEP-2 format integrity
    /// - **Public Key Derivation**: Generates public key from private key
    ///
    /// # Arguments
    /// * `passphrase` - Wallet decryption passphrase as UTF-8 bytes
    ///
    /// # Returns
    /// * `Ok(Vec<Account>)` - Successfully decrypted accounts ready for signing
    /// * `Err(Nep6AccountError)` - Decryption failure or malformed data
    ///
    /// # Security Notes
    /// - Passphrase is used directly without additional processing
    /// - Private keys are automatically zeroized when Account is dropped
    /// - Invalid passphrases result in decryption errors
    /// - Each account is processed independently (partial success possible)
    ///
    /// # Performance Considerations
    /// - Scrypt key derivation is computationally expensive
    /// - Time required scales with scrypt parameters (N, r, p)
    /// - Each account requires separate decryption operation
    /// - Consider caching for frequently accessed wallets
    fn decrypt_accounts(&self, passphrase: &[u8]) -> Result<Vec<Account>, Self::Error> {
        let mut accounts = Vec::with_capacity(self.accounts.len());

        // Process each account in the wallet
        for item in self.accounts.iter() {
            // Decrypt the private key using NEP-2 format
            // This performs: passphrase → scrypt → AES decryption → private key
            let keypair = Keypair::try_from_nep2_key(&item.key, self.scrypt, passphrase)
                .map_err(|err| Self::Error::InvalidEncryptedKey(err.to_string()))?;

            // Process contract information if present
            let contract = if let Some(nep6_contract) = &item.contract {
                // Decode the Base64-encoded verification script
                let script = Vec::<u8>::from_base64_std(&nep6_contract.script)
                    .map_err(|err| Self::Error::InvalidContract(err.to_string()))?;

                // Create internal Contract representation
                Some(Contract {
                    script,
                    deployed: nep6_contract.deployed,
                    parameters: nep6_contract.parameters.clone(),
                })
            } else {
                None
            };

            // Assemble the complete account with decrypted keys and metadata
            accounts.push(Account {
                keypair,
                contract,
                is_locked: item.is_locked,
            });
        }

        Ok(accounts)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use zeroize::Zeroizing;

    use super::*;
    use crate::{
        base64::ToBase64,
        neo::{nep2::TryToNep2Key, ToNeo3Address},
        secp256r1::{Keypair, PrivateKey},
    };

    /// Test comprehensive NEP-6 wallet creation, serialization, and decryption
    ///
    /// This test validates the complete NEP-6 workflow:
    /// 1. Create keypairs with known private keys
    /// 2. Encrypt private keys using NEP-2 format
    /// 3. Construct NEP-6 wallet structure with contracts
    /// 4. Decrypt wallet and verify all data matches
    #[test]
    fn test_nep6_wallet() {
        let passphrase = "xyz";
        let scrypt = ScryptParams { n: 64, r: 2, p: 2 };

        // Create test keypairs with deterministic private keys
        let sk1 = PrivateKey::new(Zeroizing::new([1u8; 32]));
        let sk2 = PrivateKey::new(Zeroizing::new([2u8; 32]));
        let keypair1 = Keypair::new(sk1).expect("keypair1 should be ok");
        let keypair2 = Keypair::new(sk2).expect("keypair2 should be ok");

        // Create sample contract for testing
        let contract = Nep6Contract {
            script: "test-script".to_base64_std(),
            deployed: false,
            parameters: vec![],
        };

        // Construct complete NEP-6 wallet with two accounts
        let wallet = Nep6Wallet {
            name: Some("test-wallet".into()),
            version: "3.0".to_string(),
            scrypt,
            accounts: vec![
                // Account 1: With contract, default account
                Nep6Account {
                    address: keypair1.public_key().to_neo3_address().into(),
                    label: None,
                    is_default: true,
                    is_locked: false,
                    key: keypair1
                        .try_to_nep2_key(scrypt, passphrase.as_bytes())
                        .expect("nep2-key should be ok"),
                    contract: Some(contract),
                    extra: None,
                },
                // Account 2: Simple account without contract
                Nep6Account {
                    address: keypair2.public_key().to_neo3_address().into(),
                    label: None,
                    is_default: false,
                    is_locked: false,
                    key: keypair2
                        .try_to_nep2_key(scrypt, passphrase.as_bytes())
                        .expect("nep2-key should be ok"),
                    contract: None,
                    extra: None,
                },
            ],
            extra: None,
        };

        // Uncomment to see the JSON structure:
        // let json = serde_json::to_string(&wallet).expect("wallet to_string should be ok");
        // std::println!("{}", json);

        // Test wallet decryption
        let accounts = wallet
            .decrypt_accounts(passphrase.as_bytes())
            .expect("decrypt_accounts should be ok");
        assert_eq!(accounts.len(), 2);

        // Verify private keys were correctly decrypted
        assert_eq!(accounts[0].keypair.private_key(), keypair1.private_key());
        assert_eq!(accounts[1].keypair.private_key(), keypair2.private_key());

        // Verify public keys match
        assert_eq!(accounts[0].keypair.public_key(), keypair1.public_key());
        assert_eq!(accounts[1].keypair.public_key(), keypair2.public_key());

        // Verify contract information
        assert!(accounts[0].contract.is_some());
        if let Some(contract) = accounts[0].contract.as_ref() {
            assert_eq!(contract.script.as_slice(), "test-script".as_bytes());
            assert!(!contract.deployed);
            assert!(contract.parameters.is_empty());
        }
        assert!(accounts[1].contract.is_none());

        // Verify account metadata
        assert!(!accounts[0].is_locked);
        assert!(!accounts[1].is_locked);
    }
}
