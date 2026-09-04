// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! Minimal Neo N3 transaction decode for unsigned (witness-free) hash data.

use alloc::vec::Vec;

use crate::bin::to_varint_le;
use crate::bytes::ToArray;
use crate::h160::{H160, H160_SIZE};
use crate::hash::Sha256;
use crate::neo::gas_sweep_constants::WITNESS_SCOPE_CALLED_BY_ENTRY;

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum TxDecodeError {
    #[error("tx: truncated")]
    Truncated,

    #[error("tx: unsupported version {0}")]
    UnsupportedVersion(u8),

    #[error("tx: invalid signer count")]
    InvalidSignerCount,

    #[error("tx: invalid witness scope 0x{0:02x}")]
    InvalidWitnessScope(u8),

    #[error("tx: attributes are not allowed")]
    AttributesNotAllowed,

    #[error("tx: trailing bytes after unsigned hash data")]
    TrailingBytes,

    #[error("tx: negative fee")]
    NegativeFee,

    #[error("tx: varint too large")]
    VarIntTooLarge,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DecodedSigner {
    pub account: H160,
    pub scopes: u8,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnsignedTransaction {
    pub version: u8,
    pub nonce: u32,
    pub system_fee: u64,
    pub network_fee: u64,
    pub valid_until_block: u32,
    pub signers: Vec<DecodedSigner>,
    pub script: Vec<u8>,
    /// Canonical unsigned serialization (no witnesses) used for Neo hash / sign-data.
    pub hash_data: Vec<u8>,
}

fn read_exact<'a>(data: &'a [u8], idx: &mut usize, n: usize) -> Result<&'a [u8], TxDecodeError> {
    if *idx + n > data.len() {
        return Err(TxDecodeError::Truncated);
    }
    let slice = &data[*idx..*idx + n];
    *idx += n;
    Ok(slice)
}

fn read_u8(data: &[u8], idx: &mut usize) -> Result<u8, TxDecodeError> {
    Ok(read_exact(data, idx, 1)?[0])
}

fn read_u32(data: &[u8], idx: &mut usize) -> Result<u32, TxDecodeError> {
    Ok(u32::from_le_bytes(read_exact(data, idx, 4)?.to_array()))
}

fn read_i64(data: &[u8], idx: &mut usize) -> Result<i64, TxDecodeError> {
    Ok(i64::from_le_bytes(read_exact(data, idx, 8)?.to_array()))
}

fn read_varint(data: &[u8], idx: &mut usize) -> Result<u64, TxDecodeError> {
    let first = read_u8(data, idx)?;
    match first {
        v if v < 0xfd => Ok(v as u64),
        0xfd => {
            let v = u16::from_le_bytes(read_exact(data, idx, 2)?.to_array());
            Ok(v as u64)
        }
        0xfe => {
            let v = u32::from_le_bytes(read_exact(data, idx, 4)?.to_array());
            Ok(v as u64)
        }
        0xff => {
            let v = u64::from_le_bytes(read_exact(data, idx, 8)?.to_array());
            Ok(v)
        }
        _ => unreachable!(),
    }
}

fn read_varbytes<'a>(data: &'a [u8], idx: &mut usize) -> Result<&'a [u8], TxDecodeError> {
    let len = read_varint(data, idx)?;
    if len > data.len() as u64 {
        return Err(TxDecodeError::VarIntTooLarge);
    }
    read_exact(data, idx, len as usize)
}

/// Decode unsigned Neo N3 transaction hash-data (must not include witnesses).
pub fn decode_unsigned_transaction(raw: &[u8]) -> Result<UnsignedTransaction, TxDecodeError> {
    let mut idx = 0usize;
    let version = read_u8(raw, &mut idx)?;
    if version != 0 {
        return Err(TxDecodeError::UnsupportedVersion(version));
    }
    let nonce = read_u32(raw, &mut idx)?;
    let system_fee_i = read_i64(raw, &mut idx)?;
    let network_fee_i = read_i64(raw, &mut idx)?;
    if system_fee_i < 0 || network_fee_i < 0 {
        return Err(TxDecodeError::NegativeFee);
    }
    let system_fee = system_fee_i as u64;
    let network_fee = network_fee_i as u64;
    let valid_until_block = read_u32(raw, &mut idx)?;

    let signer_count = read_varint(raw, &mut idx)?;
    if signer_count != 1 {
        return Err(TxDecodeError::InvalidSignerCount);
    }
    let account_bytes = read_exact(raw, &mut idx, H160_SIZE)?;
    let account = H160::from_le_bytes(account_bytes.to_array());
    let scopes = read_u8(raw, &mut idx)?;
    if scopes != WITNESS_SCOPE_CALLED_BY_ENTRY {
        return Err(TxDecodeError::InvalidWitnessScope(scopes));
    }
    // CalledByEntry has no allowed_contracts / groups / rules payloads.

    let attr_count = read_varint(raw, &mut idx)?;
    if attr_count != 0 {
        return Err(TxDecodeError::AttributesNotAllowed);
    }

    let script = read_varbytes(raw, &mut idx)?.to_vec();
    if idx != raw.len() {
        return Err(TxDecodeError::TrailingBytes);
    }

    Ok(UnsignedTransaction {
        version,
        nonce,
        system_fee,
        network_fee,
        valid_until_block,
        signers: alloc::vec![DecodedSigner { account, scopes }],
        script,
        hash_data: raw.to_vec(),
    })
}

impl UnsignedTransaction {
    pub fn fee_total(&self) -> Option<u64> {
        self.system_fee.checked_add(self.network_fee)
    }

    /// Neo N3 transaction hash (single SHA256 of unsigned hash data), LE bytes.
    pub fn tx_hash_le(&self) -> [u8; 32] {
        self.hash_data.sha256()
    }
}

/// Encode unsigned tx (version0, one CalledByEntry signer, no attributes).
pub fn encode_unsigned_transaction(
    nonce: u32,
    system_fee: u64,
    network_fee: u64,
    valid_until_block: u32,
    signer_account: &H160,
    script: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    out.push(0u8);
    out.extend_from_slice(&nonce.to_le_bytes());
    out.extend_from_slice(&(system_fee as i64).to_le_bytes());
    out.extend_from_slice(&(network_fee as i64).to_le_bytes());
    out.extend_from_slice(&valid_until_block.to_le_bytes());
    out.push(0x01); // one signer
    out.extend_from_slice(signer_account.as_le_bytes());
    out.push(WITNESS_SCOPE_CALLED_BY_ENTRY);
    out.push(0x00); // no attributes
    let (n, buf) = to_varint_le(script.len() as u64);
    out.extend_from_slice(&buf[..n as usize]);
    out.extend_from_slice(script);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h160::H160;
    use crate::neo::gas_transfer_script::build_gas_transfer_script;

    /// TEST-ONLY hashes — not MainNet operational addresses.
    fn test_from() -> H160 {
        H160::from_le_bytes([0x11; 20])
    }
    fn test_to() -> H160 {
        H160::from_le_bytes([0x22; 20])
    }

    #[test]
    fn decodes_encoded_roundtrip() {
        let script = build_gas_transfer_script(&test_from(), &test_to(), 10_000_000_000);
        let raw =
            encode_unsigned_transaction(3909438403, 215925, 37824, 12935784, &test_from(), &script);
        let tx = decode_unsigned_transaction(&raw).unwrap();
        assert_eq!(tx.version, 0);
        assert_eq!(tx.nonce, 3909438403);
        assert_eq!(tx.system_fee, 215925);
        assert_eq!(tx.network_fee, 37824);
        assert_eq!(tx.valid_until_block, 12935784);
        assert_eq!(tx.signers.len(), 1);
        assert_eq!(tx.signers[0].account, test_from());
        assert_eq!(tx.signers[0].scopes, WITNESS_SCOPE_CALLED_BY_ENTRY);
        assert!(tx.script.windows(20).any(|w| w == test_to().as_le_bytes()));
    }

    #[test]
    fn transaction_hash_matches_neo_single_sha256() {
        // Canonical unsigned transaction fixture. Neo's Uint256 display order
        // is reversed elsewhere; this method intentionally returns digest bytes.
        let raw = hex::decode(
            "0001000000010000000000000001000000000000006400000001\
             000000000000000000000000000000000000000001000140",
        )
        .unwrap();
        let tx = decode_unsigned_transaction(&raw).unwrap();
        assert_eq!(
            hex::encode(tx.tx_hash_le()),
            "166fac15c98704128d58f9a46d1946647970b997478494d7e4bf3070d28da195"
        );
    }

    #[test]
    fn rejects_global_scope_and_trailing_witness_bytes() {
        let script = build_gas_transfer_script(&test_from(), &test_to(), 1);
        let mut raw = encode_unsigned_transaction(1, 1000, 1000, 100, &test_from(), &script);
        // Flip scope to Global (0x80)
        let scope_idx = 1 + 4 + 8 + 8 + 4 + 1 + 20;
        raw[scope_idx] = 0x80;
        assert!(matches!(
            decode_unsigned_transaction(&raw),
            Err(TxDecodeError::InvalidWitnessScope(0x80))
        ));

        let mut with_trail = encode_unsigned_transaction(1, 1000, 1000, 100, &test_from(), &script);
        with_trail.push(0x01);
        assert_eq!(
            decode_unsigned_transaction(&with_trail),
            Err(TxDecodeError::TrailingBytes)
        );
    }
}
