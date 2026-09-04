// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! Fail-closed policy for allowlisted MainNet GAS sweep SignTransaction (Option B).
//!
//! Destination allowlist and source pin come from deploy/runtime config only.
//! Unset destination or source → SignTransaction refuses everything.

use crate::base58::FromBase58Check;
use crate::h160::{H160, H160_SIZE};
use crate::neo::check_sign::CheckSign;
use crate::neo::gas_sweep_constants::{
    FEE_CAP_FRACTIONS, GAS_SWEEP_NETWORK_MAGIC, ONE_GAS_FRACTIONS, WITNESS_SCOPE_CALLED_BY_ENTRY,
};
use crate::neo::gas_transfer_script::{
    parse_allowlisted_gas_transfer_amount, validate_gas_transfer_script, ScriptPolicyError,
};
use crate::neo::tx::{decode_unsigned_transaction, TxDecodeError, UnsignedTransaction};
use crate::neo::{ToScriptHash, ADDRESS_NEO3};
use crate::secp256r1::PublicKey;
use alloc::string::String;
use alloc::vec::Vec;
use hex;

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum GasSweepPolicyError {
    #[error("gas sweep policy: SignTransaction is disabled")]
    Disabled,

    #[error("gas sweep policy: destination allowlist is not configured")]
    AllowlistNotConfigured,

    #[error("gas sweep policy: source pin is not configured")]
    SourceNotConfigured,

    #[error("gas sweep policy: network {actual} is not allowed (expected {expected})")]
    NetworkNotAllowed { actual: u32, expected: u32 },

    #[error("gas sweep policy: public key is not the pinned source account")]
    PublicKeyNotAllowed,

    #[error("gas sweep policy: invalid public key encoding")]
    InvalidPublicKey,

    #[error("gas sweep policy: transaction decode failed: {0}")]
    Tx(#[from] TxDecodeError),

    #[error("gas sweep policy: script policy failed: {0}")]
    Script(#[from] ScriptPolicyError),

    #[error("gas sweep policy: signer account is not the source account")]
    SignerAccountMismatch,

    #[error("gas sweep policy: fee total {actual} exceeds cap {cap}")]
    FeeCapExceeded { actual: u64, cap: u64 },

    #[error("gas sweep policy: expected fee total mismatch")]
    ExpectedFeeMismatch,

    #[error("gas sweep policy: expected amount mismatch")]
    ExpectedAmountMismatch,

    #[error("gas sweep policy: amount does not leave >= 1 GAS reserve given asserted balance")]
    ReserveViolation,

    #[error("gas sweep policy: destination allowlist violated")]
    DestinationNotAllowlisted,

    #[error("gas sweep policy: idempotency key required")]
    MissingIdempotencyKey,
}

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum GasSweepConfigError {
    #[error("gas sweep config: invalid destination script hash hex: {0}")]
    InvalidScriptHashHex(String),

    #[error("gas sweep config: invalid destination Neo N3 address: {0}")]
    InvalidAddress(String),

    #[error("gas sweep config: invalid source public key: {0}")]
    InvalidPublicKey(String),

    #[error("gas sweep config: destination allowlist required when SignTransaction is enabled")]
    DestinationRequiredWhenEnabled,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GasSweepSigningPolicy {
    network: u32,
    enabled: bool,
    /// Single allowlisted destination script hash (LE). None → fail-closed.
    allowlisted_destination: Option<H160>,
    /// Pinned source account public key (SEC1 compressed or uncompressed).
    source_public_key: Option<Vec<u8>>,
    /// Script hash derived from `source_public_key` (or set explicitly for tests).
    source_script_hash: Option<H160>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ValidatedGasSweep {
    pub tx: UnsignedTransaction,
    pub amount: u64,
    pub fee_total: u64,
}

impl GasSweepSigningPolicy {
    /// Construct a fail-closed policy (no destination/source pin until configured).
    pub const fn new(network: u32, enabled: bool) -> Self {
        Self {
            network,
            enabled,
            allowlisted_destination: None,
            source_public_key: None,
            source_script_hash: None,
        }
    }

    /// Production MainNet policy with feature flag default OFF and no deploy pins.
    pub const fn mainnet_default_off() -> Self {
        Self::new(GAS_SWEEP_NETWORK_MAGIC, false)
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub const fn network(&self) -> u32 {
        self.network
    }

    pub fn allowlisted_destination(&self) -> Option<H160> {
        self.allowlisted_destination
    }

    pub fn source_script_hash(&self) -> Option<H160> {
        self.source_script_hash
    }

    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn with_allowlisted_destination(mut self, destination: H160) -> Self {
        self.allowlisted_destination = Some(destination);
        self
    }

    /// Pin source account from SEC1 public key bytes; derives Neo script hash.
    pub fn with_source_public_key(
        mut self,
        public_key: Vec<u8>,
    ) -> Result<Self, GasSweepConfigError> {
        let script_hash = script_hash_from_public_key(&public_key)
            .map_err(GasSweepConfigError::InvalidPublicKey)?;
        self.source_public_key = Some(public_key);
        self.source_script_hash = Some(script_hash);
        Ok(self)
    }

    /// Test helper: set source pin without requiring a cryptographically valid curve point.
    pub fn with_source_pin_for_tests(mut self, public_key: Vec<u8>, script_hash: H160) -> Self {
        self.source_public_key = Some(public_key);
        self.source_script_hash = Some(script_hash);
        self
    }

    pub fn validate_network(&self, network: u32) -> Result<(), GasSweepPolicyError> {
        if network == self.network {
            Ok(())
        } else {
            Err(GasSweepPolicyError::NetworkNotAllowed {
                actual: network,
                expected: self.network,
            })
        }
    }

    pub fn validate_public_key(&self, public_key: &[u8]) -> Result<(), GasSweepPolicyError> {
        let Some(expected) = self.source_public_key.as_ref() else {
            return Err(GasSweepPolicyError::SourceNotConfigured);
        };
        if public_key == expected.as_slice() {
            Ok(())
        } else {
            Err(GasSweepPolicyError::PublicKeyNotAllowed)
        }
    }

    /// Fail-closed validation of an unsigned tx (hash-data, no witnesses).
    pub fn validate_sign_transaction(
        &self,
        raw_tx: &[u8],
        public_key: &[u8],
        network: u32,
        idempotency_key: &str,
        expected_amount: u64,
        expected_fee_total: u64,
        asserted_balance: Option<u64>,
    ) -> Result<ValidatedGasSweep, GasSweepPolicyError> {
        if !self.enabled {
            return Err(GasSweepPolicyError::Disabled);
        }
        let Some(destination) = self.allowlisted_destination else {
            return Err(GasSweepPolicyError::AllowlistNotConfigured);
        };
        let Some(source_hash) = self.source_script_hash else {
            return Err(GasSweepPolicyError::SourceNotConfigured);
        };
        if idempotency_key.is_empty() {
            return Err(GasSweepPolicyError::MissingIdempotencyKey);
        }
        self.validate_network(network)?;
        self.validate_public_key(public_key)?;

        let tx = decode_unsigned_transaction(raw_tx)?;
        if tx.signers.len() != 1
            || tx.signers[0].account != source_hash
            || tx.signers[0].scopes != WITNESS_SCOPE_CALLED_BY_ENTRY
        {
            return Err(GasSweepPolicyError::SignerAccountMismatch);
        }

        let fee_total = tx
            .fee_total()
            .ok_or(GasSweepPolicyError::FeeCapExceeded {
                actual: u64::MAX,
                cap: FEE_CAP_FRACTIONS,
            })?;
        if fee_total > FEE_CAP_FRACTIONS {
            return Err(GasSweepPolicyError::FeeCapExceeded {
                actual: fee_total,
                cap: FEE_CAP_FRACTIONS,
            });
        }
        if fee_total != expected_fee_total {
            return Err(GasSweepPolicyError::ExpectedFeeMismatch);
        }

        validate_gas_transfer_script(&tx.script, &source_hash, &destination, expected_amount)
            .map_err(|err| match err {
                ScriptPolicyError::DestinationNotAllowlisted => {
                    GasSweepPolicyError::DestinationNotAllowlisted
                }
                other => GasSweepPolicyError::Script(other),
            })?;
        let amount =
            parse_allowlisted_gas_transfer_amount(&tx.script, &source_hash, &destination)?;
        if amount != expected_amount {
            return Err(GasSweepPolicyError::ExpectedAmountMismatch);
        }

        if !tx
            .script
            .windows(20)
            .any(|w| w == destination.as_le_bytes())
        {
            return Err(GasSweepPolicyError::DestinationNotAllowlisted);
        }

        if let Some(balance) = asserted_balance {
            let need = ONE_GAS_FRACTIONS
                .checked_add(fee_total)
                .and_then(|v| v.checked_add(amount));
            if need != Some(balance) {
                return Err(GasSweepPolicyError::ReserveViolation);
            }
        }

        Ok(ValidatedGasSweep {
            tx,
            amount,
            fee_total,
        })
    }
}

/// Derive Neo N3 script hash from SEC1 public key bytes.
pub fn script_hash_from_public_key(public_key: &[u8]) -> Result<H160, String> {
    let compressed =
        PublicKey::try_to_compressed(public_key).map_err(|err| alloc::format!("{err}"))?;
    Ok(CheckSign::from_compressed_public_key(&compressed).to_script_hash())
}

/// Parse LE script-hash hex (40 hex chars / 20 bytes).
pub fn parse_destination_script_hash_hex(value: &str) -> Result<H160, GasSweepConfigError> {
    let trimmed = value.trim();
    let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(hex_str)
        .map_err(|err| GasSweepConfigError::InvalidScriptHashHex(alloc::format!("{err}")))?;
    if bytes.len() != H160_SIZE {
        return Err(GasSweepConfigError::InvalidScriptHashHex(alloc::format!(
            "expected {H160_SIZE} bytes, got {}",
            bytes.len()
        )));
    }
    let mut buf = [0u8; H160_SIZE];
    buf.copy_from_slice(&bytes);
    Ok(H160::from_le_bytes(buf))
}

/// Parse a Neo N3 base58check address into its script hash (LE).
pub fn parse_neo3_address_to_script_hash(address: &str) -> Result<H160, GasSweepConfigError> {
    let raw = Vec::from_base58_check(address.trim())
        .map_err(|err| GasSweepConfigError::InvalidAddress(alloc::format!("{err}")))?;
    if raw.len() != 1 + H160_SIZE || raw[0] != ADDRESS_NEO3 {
        return Err(GasSweepConfigError::InvalidAddress(
            "expected Neo N3 address (version 0x35 + 20-byte script hash)".into(),
        ));
    }
    let mut buf = [0u8; H160_SIZE];
    buf.copy_from_slice(&raw[1..]);
    Ok(H160::from_le_bytes(buf))
}

/// Resolve destination from optional address and/or LE script-hash hex.
pub fn resolve_allowlisted_destination(
    address: Option<&str>,
    script_hash_hex: Option<&str>,
) -> Result<Option<H160>, GasSweepConfigError> {
    let from_addr = match address.map(str::trim).filter(|s| !s.is_empty()) {
        Some(a) => Some(parse_neo3_address_to_script_hash(a)?),
        None => None,
    };
    let from_hex = match script_hash_hex.map(str::trim).filter(|s| !s.is_empty()) {
        Some(h) => Some(parse_destination_script_hash_hex(h)?),
        None => None,
    };
    match (from_addr, from_hex) {
        (None, None) => Ok(None),
        (Some(a), None) => Ok(Some(a)),
        (None, Some(h)) => Ok(Some(h)),
        (Some(a), Some(h)) if a == h => Ok(Some(a)),
        (Some(_), Some(_)) => Err(GasSweepConfigError::InvalidAddress(
            "GAS_SWEEP_DESTINATION_ADDRESS and GAS_SWEEP_DESTINATION_SCRIPT_HASH disagree".into(),
        )),
    }
}

/// Build deploy-time policy. When `enabled`, destination must be configured.
pub fn build_deploy_policy(
    network: u32,
    enabled: bool,
    source_public_key: Vec<u8>,
    destination_address: Option<&str>,
    destination_script_hash_hex: Option<&str>,
) -> Result<GasSweepSigningPolicy, GasSweepConfigError> {
    let destination =
        resolve_allowlisted_destination(destination_address, destination_script_hash_hex)?;
    if enabled && destination.is_none() {
        return Err(GasSweepConfigError::DestinationRequiredWhenEnabled);
    }
    let mut policy =
        GasSweepSigningPolicy::new(network, enabled).with_source_public_key(source_public_key)?;
    if let Some(dest) = destination {
        policy = policy.with_allowlisted_destination(dest);
    }
    Ok(policy)
}

pub fn is_allowlisted_destination(policy: &GasSweepSigningPolicy, account: &H160) -> bool {
    policy
        .allowlisted_destination
        .map(|d| d == *account)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neo::gas_transfer_script::build_gas_transfer_script;
    use crate::neo::tx::encode_unsigned_transaction;

    /// TEST-ONLY pins — deliberately NOT MainNet operational addresses.
    fn test_source_pk() -> Vec<u8> {
        let mut pk = alloc::vec![0xAAu8; 33];
        pk[0] = 0x02;
        pk
    }

    fn test_source_hash() -> H160 {
        H160::from_le_bytes([0x11; 20])
    }

    fn test_dest_a() -> H160 {
        H160::from_le_bytes([0x22; 20])
    }

    fn test_dest_b() -> H160 {
        H160::from_le_bytes([0x33; 20])
    }

    fn test_policy(enabled: bool) -> GasSweepSigningPolicy {
        GasSweepSigningPolicy::new(GAS_SWEEP_NETWORK_MAGIC, enabled)
            .with_allowlisted_destination(test_dest_a())
            .with_source_pin_for_tests(test_source_pk(), test_source_hash())
    }

    fn good_tx(amount: u64, system_fee: u64, network_fee: u64) -> Vec<u8> {
        let script = build_gas_transfer_script(&test_source_hash(), &test_dest_a(), amount);
        encode_unsigned_transaction(
            42,
            system_fee,
            network_fee,
            1000,
            &test_source_hash(),
            &script,
        )
    }

    #[test]
    fn flag_off_rejects() {
        let policy = test_policy(false);
        let tx = good_tx(1, 1000, 1000);
        assert_eq!(
            policy
                .validate_sign_transaction(
                    &tx,
                    &test_source_pk(),
                    GAS_SWEEP_NETWORK_MAGIC,
                    "k",
                    1,
                    2000,
                    None
                )
                .unwrap_err(),
            GasSweepPolicyError::Disabled
        );
    }

    #[test]
    fn unset_destination_refuses_everything() {
        let policy = GasSweepSigningPolicy::new(GAS_SWEEP_NETWORK_MAGIC, true)
            .with_source_pin_for_tests(test_source_pk(), test_source_hash());
        let tx = good_tx(1, 1000, 1000);
        assert_eq!(
            policy
                .validate_sign_transaction(
                    &tx,
                    &test_source_pk(),
                    GAS_SWEEP_NETWORK_MAGIC,
                    "k",
                    1,
                    2000,
                    None
                )
                .unwrap_err(),
            GasSweepPolicyError::AllowlistNotConfigured
        );
    }

    #[test]
    fn accepts_allowlisted_destination_only() {
        let policy = test_policy(true);
        let amount = 100_000_000u64;
        let fees = 2_000u64;
        let tx = good_tx(amount, 1000, 1000);
        let validated = policy
            .validate_sign_transaction(
                &tx,
                &test_source_pk(),
                GAS_SWEEP_NETWORK_MAGIC,
                "idem-1",
                amount,
                fees,
                Some(ONE_GAS_FRACTIONS + fees + amount),
            )
            .unwrap();
        assert_eq!(validated.amount, amount);
        assert!(is_allowlisted_destination(&policy, &test_dest_a()));
    }

    #[test]
    fn rejects_wrong_destination_critically() {
        // Critical: allowlist set to test dest A; tx goes to test dest B → rejected.
        let policy = test_policy(true);
        let amount = 100_000_000u64;
        let fees = 2_000u64;
        let bad_script = build_gas_transfer_script(&test_source_hash(), &test_dest_b(), amount);
        let tx = encode_unsigned_transaction(
            42,
            1000,
            1000,
            1000,
            &test_source_hash(),
            &bad_script,
        );
        let err = policy
            .validate_sign_transaction(
                &tx,
                &test_source_pk(),
                GAS_SWEEP_NETWORK_MAGIC,
                "idem-bad-dest",
                amount,
                fees,
                None,
            )
            .unwrap_err();
        assert_eq!(err, GasSweepPolicyError::DestinationNotAllowlisted);
    }

    #[test]
    fn rejects_wrong_asset_and_bad_scope() {
        let policy = test_policy(true);
        let amount = 1u64;
        let from = test_source_hash();
        let to = test_dest_a();
        let neo = H160::from_le_bytes([
            0xc3, 0xc2, 0xa9, 0xe1, 0xd0, 0x8e, 0x3a, 0x4d, 0x0e, 0x05, 0xc4, 0x8e, 0xa3, 0x05, 0xb3,
            0xf2, 0xa0, 0x73, 0x40, 0xef,
        ]);
        let mut script = alloc::vec![0x0b];
        script.extend_from_slice(&crate::neo::gas_transfer_script::emit_push_integer(amount));
        script.push(0x0c);
        script.push(0x14);
        script.extend_from_slice(to.as_le_bytes());
        script.push(0x0c);
        script.push(0x14);
        script.extend_from_slice(from.as_le_bytes());
        script.push(0x14);
        script.push(0xc0);
        script.push(0x1f);
        script.push(0x0c);
        script.push(0x08);
        script.extend_from_slice(b"transfer");
        script.push(0x0c);
        script.push(0x14);
        script.extend_from_slice(neo.as_le_bytes());
        script.push(0x41);
        script.extend_from_slice(&crate::neo::gas_sweep_constants::SYSTEM_CONTRACT_CALL_ID);
        let tx = encode_unsigned_transaction(1, 1000, 1000, 10, &from, &script);
        assert!(matches!(
            policy.validate_sign_transaction(
                &tx,
                &test_source_pk(),
                GAS_SWEEP_NETWORK_MAGIC,
                "k",
                amount,
                2000,
                None
            ),
            Err(GasSweepPolicyError::Script(ScriptPolicyError::AssetNotGas))
                | Err(GasSweepPolicyError::Script(ScriptPolicyError::RebuildMismatch))
        ));

        let good_script = build_gas_transfer_script(&from, &to, amount);
        let mut raw = encode_unsigned_transaction(1, 1000, 1000, 10, &from, &good_script);
        let scope_idx = 1 + 4 + 8 + 8 + 4 + 1 + 20;
        raw[scope_idx] = 0x80; // Global
        assert!(matches!(
            policy.validate_sign_transaction(
                &raw,
                &test_source_pk(),
                GAS_SWEEP_NETWORK_MAGIC,
                "k",
                amount,
                2000,
                None
            ),
            Err(GasSweepPolicyError::Tx(TxDecodeError::InvalidWitnessScope(0x80)))
        ));
    }

    #[test]
    fn build_deploy_policy_requires_destination_when_enabled() {
        let pk = test_source_pk();
        let err = build_deploy_policy(GAS_SWEEP_NETWORK_MAGIC, true, pk.clone(), None, None)
            .unwrap_err();
        assert_eq!(err, GasSweepConfigError::DestinationRequiredWhenEnabled);

        let dest_hex = hex::encode(test_dest_a().as_le_bytes());
        let policy = build_deploy_policy(
            GAS_SWEEP_NETWORK_MAGIC,
            true,
            pk,
            None,
            Some(dest_hex.as_str()),
        )
        .unwrap();
        assert!(policy.enabled());
        assert_eq!(policy.allowlisted_destination(), Some(test_dest_a()));
    }
}
