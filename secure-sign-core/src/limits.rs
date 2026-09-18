// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! Post-decode size limits for SecureSign RPCs.
//!
//! Tonic's default 4 MiB window is far larger than a dBFT payload. These
//! defaults cover normal consensus (including Recovery) while failing closed
//! on memory-exhaustion requests.

use crate::h160::H160_SIZE;
use crate::h256::H256_SIZE;
use crate::neo::signpb::{ExtensiblePayload, TrimmedBlock};
use crate::neo::SIGN_DATA_SIZE;
use crate::secp256r1::KEY_SIZE;
use alloc::string::{String, ToString};

/// gRPC decode/encode ceiling applied to every `SecureSignServer`.
pub const MAX_RPC_MESSAGE_BYTES: usize = 256 * 1024;

pub const MAX_CATEGORY_BYTES: usize = 32;
pub const MAX_EXTENSIBLE_DATA_BYTES: usize = 128 * 1024;
pub const MAX_SCRIPT_HASHES: usize = 8;
pub const MAX_BLOCK_TX_HASHES: usize = 4096;
pub const MAX_RAW_TX_BYTES: usize = 128 * 1024;
pub const MAX_PUBLIC_KEY_BYTES: usize = KEY_SIZE + 1; // compressed SEC1
pub const MAX_UNCOMPRESSED_PUBLIC_KEY_BYTES: usize = 65;
pub const SIGN_DATA_BYTES: usize = SIGN_DATA_SIZE;

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum RequestSizeError {
    #[error("request exceeds the {MAX_RPC_MESSAGE_BYTES} byte message limit")]
    MessageTooLarge,

    #[error("extensible payload is required")]
    MissingPayload,

    #[error("extensible payload category exceeds {MAX_CATEGORY_BYTES} bytes")]
    CategoryTooLarge,

    #[error("extensible payload data exceeds {MAX_EXTENSIBLE_DATA_BYTES} bytes")]
    PayloadDataTooLarge,

    #[error("too many script hashes (max {MAX_SCRIPT_HASHES})")]
    TooManyScriptHashes,

    #[error("script hash must be {H160_SIZE} bytes")]
    InvalidScriptHash,

    #[error("block is required")]
    MissingBlock,

    #[error("too many block transaction hashes (max {MAX_BLOCK_TX_HASHES})")]
    TooManyTxHashes,

    #[error("transaction hash must be {H256_SIZE} bytes")]
    InvalidTxHash,

    #[error("raw transaction exceeds {MAX_RAW_TX_BYTES} bytes")]
    RawTxTooLarge,

    #[error(
        "public key must be {MAX_PUBLIC_KEY_BYTES} or {MAX_UNCOMPRESSED_PUBLIC_KEY_BYTES} bytes"
    )]
    InvalidPublicKey,

    #[error("block header field is oversized")]
    BlockHeaderTooLarge,
}

impl RequestSizeError {
    pub fn as_message(&self) -> String {
        self.to_string()
    }
}

pub fn validate_script_hashes(script_hashes: &[impl AsRef<[u8]>]) -> Result<(), RequestSizeError> {
    if script_hashes.len() > MAX_SCRIPT_HASHES {
        return Err(RequestSizeError::TooManyScriptHashes);
    }
    for hash in script_hashes {
        if hash.as_ref().len() != H160_SIZE {
            return Err(RequestSizeError::InvalidScriptHash);
        }
    }
    Ok(())
}

pub fn validate_extensible_payload(payload: &ExtensiblePayload) -> Result<(), RequestSizeError> {
    if payload.category.len() > MAX_CATEGORY_BYTES {
        return Err(RequestSizeError::CategoryTooLarge);
    }
    if payload.data.len() > MAX_EXTENSIBLE_DATA_BYTES {
        return Err(RequestSizeError::PayloadDataTooLarge);
    }
    if payload.sender.len() != H160_SIZE {
        return Err(RequestSizeError::InvalidScriptHash);
    }
    Ok(())
}

pub fn validate_extensible_request(
    payload: Option<&ExtensiblePayload>,
    script_hashes: &[impl AsRef<[u8]>],
) -> Result<(), RequestSizeError> {
    let payload = payload.ok_or(RequestSizeError::MissingPayload)?;
    validate_extensible_payload(payload)?;
    validate_script_hashes(script_hashes)
}

pub fn validate_public_key(public_key: &[u8]) -> Result<(), RequestSizeError> {
    if public_key.len() != MAX_PUBLIC_KEY_BYTES
        && public_key.len() != MAX_UNCOMPRESSED_PUBLIC_KEY_BYTES
    {
        return Err(RequestSizeError::InvalidPublicKey);
    }
    Ok(())
}

pub fn validate_trimmed_block(block: Option<&TrimmedBlock>) -> Result<(), RequestSizeError> {
    let block = block.ok_or(RequestSizeError::MissingBlock)?;
    if block.tx_hashes.len() > MAX_BLOCK_TX_HASHES {
        return Err(RequestSizeError::TooManyTxHashes);
    }
    for hash in &block.tx_hashes {
        if hash.len() != H256_SIZE {
            return Err(RequestSizeError::InvalidTxHash);
        }
    }
    if let Some(header) = block.header.as_ref() {
        if header.prev_hash.len() != H256_SIZE
            || header.merkle_root.len() != H256_SIZE
            || header.next_consensus.len() != H160_SIZE
            || (!header.prev_state_root.is_empty() && header.prev_state_root.len() != H256_SIZE)
        {
            return Err(RequestSizeError::BlockHeaderTooLarge);
        }
    }
    Ok(())
}

pub fn validate_raw_tx(raw_tx: &[u8]) -> Result<(), RequestSizeError> {
    if raw_tx.len() > MAX_RAW_TX_BYTES {
        return Err(RequestSizeError::RawTxTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neo::signpb::{ExtensiblePayload, Header, TrimmedBlock};
    use alloc::vec;
    use alloc::vec::Vec;

    fn payload(data_len: usize) -> ExtensiblePayload {
        ExtensiblePayload {
            category: "dBFT".into(),
            valid_block_start: 0,
            valid_block_end: 1,
            sender: vec![0x11; H160_SIZE],
            data: vec![0u8; data_len],
        }
    }

    #[test]
    fn extensible_limits_accept_normal_consensus_and_reject_oversize() {
        let hashes: Vec<Vec<u8>> = vec![vec![0x11; H160_SIZE]];
        validate_extensible_request(Some(&payload(32)), &hashes).unwrap();
        validate_extensible_request(Some(&payload(MAX_EXTENSIBLE_DATA_BYTES)), &hashes).unwrap();
        assert_eq!(
            validate_extensible_request(Some(&payload(MAX_EXTENSIBLE_DATA_BYTES + 1)), &hashes),
            Err(RequestSizeError::PayloadDataTooLarge)
        );

        let mut long_category = payload(1);
        long_category.category = "x".repeat(MAX_CATEGORY_BYTES + 1);
        assert_eq!(
            validate_extensible_request(Some(&long_category), &hashes),
            Err(RequestSizeError::CategoryTooLarge)
        );

        let too_many: Vec<Vec<u8>> = (0..=MAX_SCRIPT_HASHES)
            .map(|_| vec![0x11; H160_SIZE])
            .collect();
        assert_eq!(
            validate_extensible_request(Some(&payload(1)), &too_many),
            Err(RequestSizeError::TooManyScriptHashes)
        );

        let bad_hash: Vec<Vec<u8>> = vec![vec![0x11; 19]];
        assert_eq!(
            validate_extensible_request(Some(&payload(1)), &bad_hash),
            Err(RequestSizeError::InvalidScriptHash)
        );
        assert_eq!(
            validate_extensible_request(None, &hashes),
            Err(RequestSizeError::MissingPayload)
        );
    }

    #[test]
    fn block_and_transaction_limits_reject_oversize_repeated_fields() {
        let ok = TrimmedBlock {
            header: Some(Header {
                version: 0,
                prev_hash: vec![0; H256_SIZE],
                merkle_root: vec![0; H256_SIZE],
                timestamp: 0,
                nonce: 0,
                index: 0,
                primary_index: 0,
                next_consensus: vec![0; H160_SIZE],
                prev_state_root: vec![],
                state_root_enabled: false,
            }),
            tx_hashes: vec![vec![0x22; H256_SIZE]; MAX_BLOCK_TX_HASHES],
        };
        validate_trimmed_block(Some(&ok)).unwrap();

        let mut over = ok.clone();
        over.tx_hashes.push(vec![0x22; H256_SIZE]);
        assert_eq!(
            validate_trimmed_block(Some(&over)),
            Err(RequestSizeError::TooManyTxHashes)
        );

        validate_raw_tx(&[0u8; MAX_RAW_TX_BYTES]).unwrap();
        assert_eq!(
            validate_raw_tx(&vec![0u8; MAX_RAW_TX_BYTES + 1]),
            Err(RequestSizeError::RawTxTooLarge)
        );
        validate_public_key(&[0u8; 33]).unwrap();
        assert_eq!(
            validate_public_key(&[0u8; 32]),
            Err(RequestSizeError::InvalidPublicKey)
        );
        assert_eq!(
            validate_trimmed_block(None),
            Err(RequestSizeError::MissingBlock)
        );
    }

    #[test]
    fn rpc_message_limit_is_below_tonic_default() {
        assert_eq!(MAX_RPC_MESSAGE_BYTES, 256 * 1024);
        const _: () = assert!(MAX_RPC_MESSAGE_BYTES < 4 * 1024 * 1024);
        const _: () = assert!(MAX_RPC_MESSAGE_BYTES >= 64 * 1024);
    }
}
