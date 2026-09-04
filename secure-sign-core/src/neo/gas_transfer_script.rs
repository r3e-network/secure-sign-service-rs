// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! Exact NEP-17 `GAS.transfer(from, to, amount, null)` script emitter + validator.
//! Preferred check: rebuild-and-compare against pinned Neo ScriptBuilder rules.
//!
//! `from` / `to` script hashes are supplied by the caller (deploy-time policy pins),
//! never from hardcoded operational addresses.

use alloc::vec::Vec;

use crate::h160::H160;
use crate::neo::gas_sweep_constants::{gas_script_hash, CALL_FLAGS_ALL, SYSTEM_CONTRACT_CALL_ID};

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum ScriptPolicyError {
    #[error("gas transfer script: empty script")]
    Empty,

    #[error("gas transfer script: rebuild mismatch (not exact GAS.transfer template)")]
    RebuildMismatch,

    #[error("gas transfer script: amount must be > 0")]
    NonPositiveAmount,

    #[error("gas transfer script: destination is not allowlisted")]
    DestinationNotAllowlisted,

    #[error("gas transfer script: source mismatch")]
    SourceMismatch,

    #[error("gas transfer script: asset is not GAS")]
    AssetNotGas,

    #[error("gas transfer script: amount does not match expected")]
    AmountMismatch,
}

/// Emit Neo integer push opcodes (ScriptBuilder.EmitPush for non-negative integers).
pub fn emit_push_integer(amount: u64) -> Vec<u8> {
    if amount <= 16 {
        // PUSH0..=PUSH16
        return alloc::vec![0x10 + amount as u8];
    }

    let mut bytes = Vec::new();
    let mut v = amount;
    while v > 0 {
        bytes.push((v & 0xff) as u8);
        v >>= 8;
    }
    if bytes.last().copied().unwrap_or(0) & 0x80 != 0 {
        bytes.push(0x00);
    }

    let (op, size) = match bytes.len() {
        1 => (0x00u8, 1usize), // PUSHINT8
        2 => (0x01, 2),        // PUSHINT16
        n if n <= 4 => (0x02, 4), // PUSHINT32
        n if n <= 8 => (0x03, 8), // PUSHINT64
        n if n <= 16 => (0x04, 16), // PUSHINT128
        _ => (0x05, 32),       // PUSHINT256
    };
    let mut out = Vec::with_capacity(1 + size);
    out.push(op);
    out.extend_from_slice(&bytes);
    while out.len() < 1 + size {
        out.push(0x00);
    }
    out
}

fn emit_push_hash160(hash: &H160) -> Vec<u8> {
    let mut out = alloc::vec![0x0c, 0x14]; // PUSHDATA1, 20
    out.extend_from_slice(hash.as_le_bytes());
    out
}

/// Build exact `GAS.transfer(from, to, amount, null)` AppCall script.
pub fn build_gas_transfer_script(from: &H160, to: &H160, amount: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.push(0x0b); // PUSHNULL (data)
    out.extend_from_slice(&emit_push_integer(amount));
    out.extend_from_slice(&emit_push_hash160(to));
    out.extend_from_slice(&emit_push_hash160(from));
    out.push(0x14); // PUSH4 (argc)
    out.push(0xc0); // PACK
    out.push(0x10 + CALL_FLAGS_ALL); // PUSH15 CallFlags.All
    out.push(0x0c); // PUSHDATA1
    out.push(0x08);
    out.extend_from_slice(b"transfer");
    out.extend_from_slice(&emit_push_hash160(&gas_script_hash()));
    out.push(0x41); // SYSCALL
    out.extend_from_slice(&SYSTEM_CONTRACT_CALL_ID);
    out
}

/// Rebuild-and-compare validation for the allowlisted sweep script.
pub fn validate_gas_transfer_script(
    script: &[u8],
    from: &H160,
    to: &H160,
    expected_amount: u64,
) -> Result<(), ScriptPolicyError> {
    if script.is_empty() {
        return Err(ScriptPolicyError::Empty);
    }
    if expected_amount == 0 {
        return Err(ScriptPolicyError::NonPositiveAmount);
    }

    let expected = build_gas_transfer_script(from, to, expected_amount);
    if script == expected.as_slice() {
        return Ok(());
    }

    // Diagnose: same shape with a different `to` hash → hard allowlist violation.
    if let Some(actual_to) = extract_transfer_to_hash(script) {
        if actual_to != *to {
            return Err(ScriptPolicyError::DestinationNotAllowlisted);
        }
    }
    if let Some(actual_asset) = extract_transfer_asset_hash(script) {
        if actual_asset != gas_script_hash() {
            return Err(ScriptPolicyError::AssetNotGas);
        }
    }
    if let Some(actual_from) = extract_transfer_from_hash(script) {
        if actual_from != *from {
            return Err(ScriptPolicyError::SourceMismatch);
        }
    }
    let alt = build_gas_transfer_script(from, to, expected_amount.saturating_add(1));
    if script == alt.as_slice() {
        return Err(ScriptPolicyError::AmountMismatch);
    }
    Err(ScriptPolicyError::RebuildMismatch)
}

fn extract_hash160_pushes(script: &[u8]) -> Vec<H160> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 22 <= script.len() {
        if script[i] == 0x0c && script[i + 1] == 0x14 {
            let mut buf = [0u8; 20];
            buf.copy_from_slice(&script[i + 2..i + 22]);
            out.push(H160::from_le_bytes(buf));
            i += 22;
            continue;
        }
        i += 1;
    }
    out
}

/// Script push order: data(null), amount, **to**, **from**, then later **GAS**.
fn extract_transfer_to_hash(script: &[u8]) -> Option<H160> {
    let pushes = extract_hash160_pushes(script);
    pushes.first().copied()
}

fn extract_transfer_from_hash(script: &[u8]) -> Option<H160> {
    let pushes = extract_hash160_pushes(script);
    pushes.get(1).copied()
}

fn extract_transfer_asset_hash(script: &[u8]) -> Option<H160> {
    let pushes = extract_hash160_pushes(script);
    pushes.get(2).copied()
}

/// Validate script is exactly allowlisted GAS.transfer for some amount; return that amount.
pub fn parse_allowlisted_gas_transfer_amount(
    script: &[u8],
    from: &H160,
    to: &H160,
) -> Result<u64, ScriptPolicyError> {
    if script.is_empty() {
        return Err(ScriptPolicyError::Empty);
    }
    if script.first() != Some(&0x0b) {
        return Err(ScriptPolicyError::RebuildMismatch);
    }
    let suffix_tail = {
        let mut tail = Vec::new();
        tail.extend_from_slice(&emit_push_hash160(to));
        tail.extend_from_slice(&emit_push_hash160(from));
        tail.push(0x14);
        tail.push(0xc0);
        tail.push(0x10 + CALL_FLAGS_ALL);
        tail.push(0x0c);
        tail.push(0x08);
        tail.extend_from_slice(b"transfer");
        tail.extend_from_slice(&emit_push_hash160(&gas_script_hash()));
        tail.push(0x41);
        tail.extend_from_slice(&SYSTEM_CONTRACT_CALL_ID);
        tail
    };
    if script.len() <= 1 + suffix_tail.len() {
        return Err(ScriptPolicyError::RebuildMismatch);
    }
    let int_region = &script[1..script.len() - suffix_tail.len()];
    if &script[script.len() - suffix_tail.len()..] != suffix_tail.as_slice() {
        let to_push = emit_push_hash160(to);
        if !script.windows(to_push.len()).any(|w| w == to_push.as_slice()) {
            return Err(ScriptPolicyError::DestinationNotAllowlisted);
        }
        let gas_push = emit_push_hash160(&gas_script_hash());
        if !script.windows(gas_push.len()).any(|w| w == gas_push.as_slice()) {
            return Err(ScriptPolicyError::AssetNotGas);
        }
        return Err(ScriptPolicyError::RebuildMismatch);
    }

    let _ = int_region;
    let amount = decode_push_integer(&script[1..script.len() - suffix_tail.len()])?;
    if amount == 0 {
        return Err(ScriptPolicyError::NonPositiveAmount);
    }
    validate_gas_transfer_script(script, from, to, amount)?;
    Ok(amount)
}

fn decode_push_integer(bytes: &[u8]) -> Result<u64, ScriptPolicyError> {
    if bytes.is_empty() {
        return Err(ScriptPolicyError::RebuildMismatch);
    }
    let op = bytes[0];
    if (0x10..=0x20).contains(&op) {
        if bytes.len() != 1 {
            return Err(ScriptPolicyError::RebuildMismatch);
        }
        return Ok((op - 0x10) as u64);
    }
    let size = match op {
        0x00 => 1usize,
        0x01 => 2,
        0x02 => 4,
        0x03 => 8,
        0x04 => 16,
        0x05 => 32,
        _ => return Err(ScriptPolicyError::RebuildMismatch),
    };
    if bytes.len() != 1 + size {
        return Err(ScriptPolicyError::RebuildMismatch);
    }
    let data = &bytes[1..];
    // Reject negative (high bit of last byte) and values that don't fit u64.
    if size > 8 {
        if data[8..].iter().any(|b| *b != 0) || data[7] & 0x80 != 0 {
            return Err(ScriptPolicyError::RebuildMismatch);
        }
    } else if data[size - 1] & 0x80 != 0 {
        return Err(ScriptPolicyError::RebuildMismatch);
    }
    let mut buf = [0u8; 8];
    let take = core::cmp::min(8, size);
    buf[..take].copy_from_slice(&data[..take]);
    Ok(u64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TEST-ONLY hashes — not MainNet operational addresses.
    fn test_from() -> H160 {
        H160::from_le_bytes([0x11; 20])
    }
    fn test_to() -> H160 {
        H160::from_le_bytes([0x22; 20])
    }

    #[test]
    fn rebuild_roundtrip_matches_emitter() {
        let amount = 10_000_000_000u64;
        let script = build_gas_transfer_script(&test_from(), &test_to(), amount);
        validate_gas_transfer_script(&script, &test_from(), &test_to(), amount).unwrap();
        assert_eq!(
            parse_allowlisted_gas_transfer_amount(&script, &test_from(), &test_to()).unwrap(),
            amount
        );
    }

    #[test]
    fn rejects_wrong_destination() {
        let amount = 100_000_000u64;
        let bad = build_gas_transfer_script(
            &test_from(),
            &H160::from_le_bytes([0xde; 20]),
            amount,
        );
        assert_eq!(
            validate_gas_transfer_script(&bad, &test_from(), &test_to(), amount),
            Err(ScriptPolicyError::DestinationNotAllowlisted)
        );
        assert_eq!(
            parse_allowlisted_gas_transfer_amount(&bad, &test_from(), &test_to()),
            Err(ScriptPolicyError::DestinationNotAllowlisted)
        );
        let good = build_gas_transfer_script(&test_from(), &test_to(), amount);
        validate_gas_transfer_script(&good, &test_from(), &test_to(), amount).unwrap();
    }

    #[test]
    fn rejects_wrong_asset_neo() {
        let amount = 1u64;
        let from = test_from();
        let to = test_to();
        let neo = H160::from_le_bytes([
            0xc3, 0xc2, 0xa9, 0xe1, 0xd0, 0x8e, 0x3a, 0x4d, 0x0e, 0x05, 0xc4, 0x8e, 0xa3, 0x05, 0xb3,
            0xf2, 0xa0, 0x73, 0x40, 0xef,
        ]);
        let mut bad = Vec::new();
        bad.push(0x0b);
        bad.extend_from_slice(&emit_push_integer(amount));
        bad.extend_from_slice(&emit_push_hash160(&to));
        bad.extend_from_slice(&emit_push_hash160(&from));
        bad.push(0x14);
        bad.push(0xc0);
        bad.push(0x10 + CALL_FLAGS_ALL);
        bad.push(0x0c);
        bad.push(0x08);
        bad.extend_from_slice(b"transfer");
        bad.extend_from_slice(&emit_push_hash160(&neo));
        bad.push(0x41);
        bad.extend_from_slice(&SYSTEM_CONTRACT_CALL_ID);
        assert_eq!(
            validate_gas_transfer_script(&bad, &from, &to, amount),
            Err(ScriptPolicyError::AssetNotGas)
        );
    }

    #[test]
    fn rejects_trailing_junk_and_zero_amount() {
        let amount = 1u64;
        let mut script = build_gas_transfer_script(&test_from(), &test_to(), amount);
        script.push(0x21);
        assert!(validate_gas_transfer_script(&script, &test_from(), &test_to(), amount).is_err());
        assert_eq!(
            validate_gas_transfer_script(
                &build_gas_transfer_script(&test_from(), &test_to(), 0),
                &test_from(),
                &test_to(),
                0
            ),
            Err(ScriptPolicyError::NonPositiveAmount)
        );
    }
}
