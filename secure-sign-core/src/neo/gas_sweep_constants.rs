// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! Network / asset constants for Option B allowlisted SignTransaction.
//!
//! Personal/operational Neo addresses and script hashes are **never** hardcoded
//! here. Destination allowlist and source pin are supplied only at deploy/runtime
//! via gateway CLI / env (see `GasSweepSigningPolicy` and gateway flags).

use crate::h160::{H160, H160_SIZE};
use crate::neo::consensus::NEO_N3_MAINNET_MAGIC;

/// GAS native contract hash LE (UInt160 bytes for `0xd2a4cff31913016155e38e474a2c06d08be276cf`).
pub const GAS_SCRIPT_HASH_LE: [u8; H160_SIZE] = [
    0xcf, 0x76, 0xe2, 0x8b, 0xd0, 0x06, 0x2c, 0x4a, 0x47, 0x8e, 0xe3, 0x55, 0x61, 0x01, 0x13, 0x19,
    0xf3, 0xcf, 0xa4, 0xd2,
];

/// 1 GAS in fractions (8 decimals).
pub const ONE_GAS_FRACTIONS: u64 = 100_000_000;

/// Maximum system_fee + network_fee (0.1 GAS).
pub const FEE_CAP_FRACTIONS: u64 = 10_000_000;

/// WitnessScope::CalledByEntry
pub const WITNESS_SCOPE_CALLED_BY_ENTRY: u8 = 0x01;

/// Network magic required for production sweeps.
pub const GAS_SWEEP_NETWORK_MAGIC: u32 = NEO_N3_MAINNET_MAGIC;

/// System.Contract.Call interop id (LE bytes).
pub const SYSTEM_CONTRACT_CALL_ID: [u8; 4] = [0x62, 0x7d, 0x5b, 0x52];

/// CallFlags::All
pub const CALL_FLAGS_ALL: u8 = 0x0f;

#[inline]
pub fn gas_script_hash() -> H160 {
    H160::from_le_bytes(GAS_SCRIPT_HASH_LE)
}

/// Compute transferable amount: balance - 1_GAS - fees. Returns None if not positive.
#[inline]
pub fn transferable_amount(balance: u64, fee_total: u64) -> Option<u64> {
    let reserve = ONE_GAS_FRACTIONS.checked_add(fee_total)?;
    balance.checked_sub(reserve).filter(|amount| *amount > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transferable_amount_formula() {
        assert_eq!(transferable_amount(ONE_GAS_FRACTIONS, 0), None);
        assert_eq!(
            transferable_amount(ONE_GAS_FRACTIONS + FEE_CAP_FRACTIONS + 1, FEE_CAP_FRACTIONS),
            Some(1)
        );
        assert_eq!(transferable_amount(ONE_GAS_FRACTIONS + 5, 10), None);
    }
}
