// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::base64::FromBase64;
use crate::neo::nep2::TryFromNep2Key;
use crate::neo::sign::{Account, AccountDecrypting};
use crate::neo::{Contract, NamedParamType};
use crate::scrypt::ScryptParams;
use crate::secp256r1::Keypair;

use serde::{Deserialize, Serialize};

pub type Extra = Option<serde_json::Map<String, serde_json::Value>>;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Nep6Contract {
    /// base64 encoded script
    pub script: String,
    pub deployed: bool,
    pub parameters: Vec<NamedParamType>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Nep6Account {
    // uint160, 0x...
    pub address: String,

    #[serde(default)]
    pub label: Option<String>,

    #[serde(default, rename = "isdefault")]
    pub is_default: bool,

    #[serde(default, rename = "lock")]
    pub is_locked: bool,

    // i.e. EncryptedWIF
    pub key: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<Nep6Contract>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Extra,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Nep6Wallet {
    pub name: Option<String>,
    pub version: String,
    pub scrypt: ScryptParams,
    pub accounts: Vec<Nep6Account>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Extra,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Nep6AccountError {
    #[error("nep6-account: invalid encrypted key: {0}")]
    InvalidEncryptedKey(String),

    #[error("nep6-account: invalid contract: {0}")]
    InvalidContract(String),
}

impl AccountDecrypting for Nep6Wallet {
    type Error = Nep6AccountError;

    fn decrypt_accounts(&self, passphrase: &[u8]) -> Result<Vec<Account>, Self::Error> {
        let mut accounts = Vec::with_capacity(self.accounts.len());
        for item in self.accounts.iter() {
            let keypair = Keypair::try_from_nep2_key(&item.key, self.scrypt, passphrase)
                .map_err(|err| Self::Error::InvalidEncryptedKey(err.to_string()))?;

            let contract = if let Some(nep6_contract) = &item.contract {
                let script = Vec::<u8>::from_base64_std(&nep6_contract.script)
                    .map_err(|err| Self::Error::InvalidContract(err.to_string()))?;
                Some(Contract {
                    script,
                    deployed: nep6_contract.deployed,
                    parameters: nep6_contract.parameters.clone(),
                })
            } else {
                None
            };
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

    use super::*;
    use crate::base64::ToBase64;
    use crate::neo::nep2::TryToNep2Key;
    use crate::neo::ToNeo3Address;
    use crate::secp256r1::{Keypair, PrivateKey};

    use zeroize::Zeroizing;

    #[test]
    fn test_nep6_wallet() {
        let passphrase = "xyz";
        let scrypt = ScryptParams { n: 64, r: 2, p: 2 };

        let sk1 = PrivateKey::new(Zeroizing::new([1u8; 32]));
        let sk2 = PrivateKey::new(Zeroizing::new([2u8; 32]));
        let keypair1 = Keypair::new(sk1).expect("keypair1 should be ok");
        let keypair2 = Keypair::new(sk2).expect("keypair2 should be ok");

        let contract = Nep6Contract {
            script: "test-script".to_base64_std(),
            deployed: false,
            parameters: vec![],
        };

        let wallet = Nep6Wallet {
            name: Some("test-wallet".into()),
            version: "3.0".to_string(),
            scrypt,
            accounts: vec![
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

        // let json = serde_json::to_string(&wallet).expect("wallet to_string should be ok");
        // std::println!("{}", json);

        let accounts = wallet
            .decrypt_accounts(passphrase.as_bytes())
            .expect("decrypt_accounts should be ok");
        assert_eq!(accounts.len(), 2);

        // assert private key
        assert_eq!(accounts[0].keypair.private_key(), keypair1.private_key());
        assert_eq!(accounts[1].keypair.private_key(), keypair2.private_key());

        // assert public key
        assert_eq!(accounts[0].keypair.public_key(), keypair1.public_key());
        assert_eq!(accounts[1].keypair.public_key(), keypair2.public_key());

        // assert contract
        assert!(accounts[0].contract.is_some());
        if let Some(contract) = accounts[0].contract.as_ref() {
            assert_eq!(contract.script.as_slice(), "test-script".as_bytes());
            assert_eq!(contract.deployed, false);
            assert!(contract.parameters.is_empty());
        }
        assert!(accounts[1].contract.is_none());

        // assert is_locked
        assert_eq!(accounts[0].is_locked, false);
        assert_eq!(accounts[1].is_locked, false);
    }
}
