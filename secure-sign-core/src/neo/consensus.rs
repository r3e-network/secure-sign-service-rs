// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use crate::bytes::ToArray;
use crate::h160::{H160, H160_SIZE};
use crate::h256::H256_SIZE;
use crate::neo::signpb::ExtensiblePayload;
use alloc::string::{String, ToString};

pub const DBFT_CATEGORY: &str = "dBFT";
pub const NEO_N3_MAINNET_MAGIC: u32 = 860_833_102;

const CONSENSUS_HEADER_SIZE: usize = 7;
const CHANGE_VIEW_MIN_BODY: usize = 9;
const PREPARE_RESPONSE_BODY: usize = H256_SIZE;
const COMMIT_BODY: usize = 64;
const RECOVERY_REQUEST_BODY: usize = 8;
const PREPARE_REQUEST_FIXED: usize = 4 + H256_SIZE + 8 + 8;
const MAX_CONSENSUS_TX_HASHES: u64 = 512;
const MAX_RECOVERY_COMPACTS: u64 = 32;
const MAX_INVOCATION_SCRIPT: u64 = 1_024;
const CV_TX_REJECTED_BY_POLICY: u8 = 0x03;
const CV_TX_INVALID: u8 = 0x04;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum ConsensusMessageType {
    ChangeView = 0x00,
    PrepareRequest = 0x20,
    PrepareResponse = 0x21,
    Commit = 0x30,
    RecoveryRequest = 0x40,
    RecoveryMessage = 0x41,
}

impl TryFrom<u8> for ConsensusMessageType {
    type Error = ConsensusPolicyError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::ChangeView),
            0x20 => Ok(Self::PrepareRequest),
            0x21 => Ok(Self::PrepareResponse),
            0x30 => Ok(Self::Commit),
            0x40 => Ok(Self::RecoveryRequest),
            0x41 => Ok(Self::RecoveryMessage),
            _ => Err(ConsensusPolicyError::UnsupportedMessageType(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ConsensusMessageMetadata {
    pub message_type: ConsensusMessageType,
    pub block_index: u32,
    pub validator_index: u8,
    pub view_number: u8,
}

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum ConsensusPolicyError {
    #[error("consensus policy: network {actual} is not allowed (expected {expected})")]
    NetworkNotAllowed { actual: u32, expected: u32 },

    #[error("consensus policy: category {0:?} is not allowed")]
    CategoryNotAllowed(String),

    #[error("consensus policy: payload data is shorter than the consensus header")]
    TruncatedMessage,

    #[error("consensus policy: consensus message body is malformed")]
    MalformedMessage,

    #[error("consensus policy: consensus message body exceeds the type limit")]
    MessageBodyTooLarge,

    #[error("consensus policy: unsupported message type 0x{0:02x}")]
    UnsupportedMessageType(u8),

    #[error("consensus policy: valid block start must be zero")]
    InvalidValidBlockStart,

    #[error("consensus policy: valid block end {actual} does not match message height {expected}")]
    InvalidValidBlockEnd { actual: u32, expected: u32 },

    #[error("consensus policy: sender must be a 20-byte script hash")]
    InvalidSender,

    #[error("consensus policy: exactly one signer script hash is required")]
    InvalidSignerCount,

    #[error("consensus policy: payload sender does not match the requested signer")]
    SenderMismatch,

    #[error("consensus policy: signer script hashes must be exactly the pinned consensus account")]
    SignerNotPinned,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ConsensusSigningPolicy {
    network: u32,
    pinned_script_hash: Option<H160>,
}

impl ConsensusSigningPolicy {
    pub const fn new(network: u32) -> Self {
        Self {
            network,
            pinned_script_hash: None,
        }
    }

    pub const fn with_pinned_script_hash(self, pinned_script_hash: H160) -> Self {
        Self {
            pinned_script_hash: Some(pinned_script_hash),
            ..self
        }
    }

    pub const fn network(&self) -> u32 {
        self.network
    }

    pub const fn pinned_script_hash(&self) -> Option<H160> {
        self.pinned_script_hash
    }

    pub fn validate_network(&self, network: u32) -> Result<(), ConsensusPolicyError> {
        if network == self.network {
            Ok(())
        } else {
            Err(ConsensusPolicyError::NetworkNotAllowed {
                actual: network,
                expected: self.network,
            })
        }
    }

    pub fn validate_extensible_payload(
        &self,
        payload: &ExtensiblePayload,
        signer_script_hashes: &[H160],
        network: u32,
    ) -> Result<ConsensusMessageMetadata, ConsensusPolicyError> {
        self.validate_network(network)?;

        if payload.category != DBFT_CATEGORY {
            return Err(ConsensusPolicyError::CategoryNotAllowed(
                payload.category.to_string(),
            ));
        }
        if payload.valid_block_start != 0 {
            return Err(ConsensusPolicyError::InvalidValidBlockStart);
        }
        if payload.data.len() < CONSENSUS_HEADER_SIZE {
            return Err(ConsensusPolicyError::TruncatedMessage);
        }

        let metadata = ConsensusMessageMetadata {
            message_type: ConsensusMessageType::try_from(payload.data[0])?,
            block_index: u32::from_le_bytes(payload.data[1..5].to_array()),
            validator_index: payload.data[5],
            view_number: payload.data[6],
        };
        if payload.valid_block_end != metadata.block_index {
            return Err(ConsensusPolicyError::InvalidValidBlockEnd {
                actual: payload.valid_block_end,
                expected: metadata.block_index,
            });
        }
        if payload.valid_block_end < payload.valid_block_start {
            return Err(ConsensusPolicyError::InvalidValidBlockEnd {
                actual: payload.valid_block_end,
                expected: metadata.block_index,
            });
        }
        validate_consensus_body(
            metadata.message_type,
            &payload.data[CONSENSUS_HEADER_SIZE..],
        )?;
        if payload.sender.len() != H160_SIZE {
            return Err(ConsensusPolicyError::InvalidSender);
        }
        if signer_script_hashes.len() != 1 {
            return Err(ConsensusPolicyError::InvalidSignerCount);
        }

        let sender = H160::from_le_bytes(payload.sender.as_slice().to_array());
        if signer_script_hashes[0] != sender {
            return Err(ConsensusPolicyError::SenderMismatch);
        }
        if let Some(pinned) = self.pinned_script_hash {
            if signer_script_hashes[0] != pinned || sender != pinned {
                return Err(ConsensusPolicyError::SignerNotPinned);
            }
        }

        Ok(metadata)
    }
}

fn validate_consensus_body(
    message_type: ConsensusMessageType,
    body: &[u8],
) -> Result<(), ConsensusPolicyError> {
    match message_type {
        ConsensusMessageType::ChangeView => validate_change_view_body(body),
        ConsensusMessageType::PrepareRequest => {
            let mut idx = 0;
            validate_prepare_request_body(body, &mut idx)?;
            if idx != body.len() {
                return Err(ConsensusPolicyError::MalformedMessage);
            }
            Ok(())
        }
        ConsensusMessageType::PrepareResponse => exact_body(body, PREPARE_RESPONSE_BODY),
        ConsensusMessageType::Commit => exact_body(body, COMMIT_BODY),
        ConsensusMessageType::RecoveryRequest => exact_body(body, RECOVERY_REQUEST_BODY),
        ConsensusMessageType::RecoveryMessage => validate_recovery_message_body(body),
    }
}

fn exact_body(body: &[u8], expected: usize) -> Result<(), ConsensusPolicyError> {
    if body.len() < expected {
        Err(ConsensusPolicyError::TruncatedMessage)
    } else if body.len() > expected {
        Err(ConsensusPolicyError::MalformedMessage)
    } else {
        Ok(())
    }
}

fn validate_change_view_body(body: &[u8]) -> Result<(), ConsensusPolicyError> {
    if body.len() < CHANGE_VIEW_MIN_BODY {
        return Err(ConsensusPolicyError::TruncatedMessage);
    }
    if body.len() == CHANGE_VIEW_MIN_BODY || body.len() == CHANGE_VIEW_MIN_BODY + 1 {
        return Ok(());
    }
    let reason = body[8];
    if reason != CV_TX_REJECTED_BY_POLICY && reason != CV_TX_INVALID {
        return Err(ConsensusPolicyError::MalformedMessage);
    }
    let mut idx = CHANGE_VIEW_MIN_BODY;
    let count = read_varint(body, &mut idx)?;
    if count > MAX_CONSENSUS_TX_HASHES {
        return Err(ConsensusPolicyError::MessageBodyTooLarge);
    }
    for _ in 0..count {
        read_exact(body, &mut idx, H256_SIZE)?;
    }
    if idx != body.len() {
        return Err(ConsensusPolicyError::MalformedMessage);
    }
    Ok(())
}

fn validate_prepare_request_body(data: &[u8], idx: &mut usize) -> Result<(), ConsensusPolicyError> {
    if data.len().saturating_sub(*idx) < PREPARE_REQUEST_FIXED {
        return Err(ConsensusPolicyError::TruncatedMessage);
    }
    let version = u32::from_le_bytes(read_exact(data, idx, 4)?.to_array());
    if version != 0 {
        return Err(ConsensusPolicyError::MalformedMessage);
    }
    read_exact(data, idx, H256_SIZE)?;
    read_exact(data, idx, 8)?;
    read_exact(data, idx, 8)?;
    let count = read_varint(data, idx)?;
    if count > MAX_CONSENSUS_TX_HASHES {
        return Err(ConsensusPolicyError::MessageBodyTooLarge);
    }
    for _ in 0..count {
        read_exact(data, idx, H256_SIZE)?;
    }
    let remaining = data.len().saturating_sub(*idx);
    if remaining == H256_SIZE {
        *idx += H256_SIZE;
    } else if remaining != 0 {
        return Err(ConsensusPolicyError::MalformedMessage);
    }
    Ok(())
}

fn validate_recovery_message_body(body: &[u8]) -> Result<(), ConsensusPolicyError> {
    let mut idx = 0;
    read_compact_array(body, &mut idx, 10, |data, idx| {
        read_exact(data, idx, 1)?;
        read_exact(data, idx, 1)?;
        read_exact(data, idx, 8)?;
        read_varbytes(data, idx, MAX_INVOCATION_SCRIPT)?;
        Ok(())
    })?;
    let has_request = read_exact(body, &mut idx, 1)?[0];
    match has_request {
        0 => {
            let hash_len = read_varint(body, &mut idx)?;
            if hash_len == 0 {
            } else if hash_len == H256_SIZE as u64 {
                read_exact(body, &mut idx, H256_SIZE)?;
            } else {
                return Err(ConsensusPolicyError::MalformedMessage);
            }
        }
        1 => {
            let header = read_exact(body, &mut idx, CONSENSUS_HEADER_SIZE)?;
            let nested = ConsensusMessageType::try_from(header[0])?;
            if nested != ConsensusMessageType::PrepareRequest {
                return Err(ConsensusPolicyError::MalformedMessage);
            }
            validate_prepare_request_body(body, &mut idx)?;
        }
        _ => return Err(ConsensusPolicyError::MalformedMessage),
    }
    read_compact_array(body, &mut idx, 1, |data, idx| {
        read_exact(data, idx, 1)?;
        read_varbytes(data, idx, MAX_INVOCATION_SCRIPT)?;
        Ok(())
    })?;
    read_compact_array(body, &mut idx, 66, |data, idx| {
        read_exact(data, idx, 1)?;
        read_exact(data, idx, 1)?;
        read_exact(data, idx, COMMIT_BODY)?;
        read_varbytes(data, idx, MAX_INVOCATION_SCRIPT)?;
        Ok(())
    })?;
    if idx != body.len() {
        return Err(ConsensusPolicyError::MalformedMessage);
    }
    Ok(())
}

fn read_compact_array(
    data: &[u8],
    idx: &mut usize,
    min_item: usize,
    mut read_item: impl FnMut(&[u8], &mut usize) -> Result<(), ConsensusPolicyError>,
) -> Result<(), ConsensusPolicyError> {
    let count = read_varint(data, idx)?;
    if count > MAX_RECOVERY_COMPACTS {
        return Err(ConsensusPolicyError::MessageBodyTooLarge);
    }
    let remaining = data.len().saturating_sub(*idx) as u64;
    if count.saturating_mul(min_item as u64) > remaining {
        return Err(ConsensusPolicyError::TruncatedMessage);
    }
    for _ in 0..count {
        read_item(data, idx)?;
    }
    Ok(())
}

fn read_exact<'a>(
    data: &'a [u8],
    idx: &mut usize,
    n: usize,
) -> Result<&'a [u8], ConsensusPolicyError> {
    let end = idx
        .checked_add(n)
        .ok_or(ConsensusPolicyError::TruncatedMessage)?;
    if end > data.len() {
        return Err(ConsensusPolicyError::TruncatedMessage);
    }
    let slice = &data[*idx..end];
    *idx = end;
    Ok(slice)
}

fn read_varint(data: &[u8], idx: &mut usize) -> Result<u64, ConsensusPolicyError> {
    let first = read_exact(data, idx, 1)?[0];
    match first {
        0xfd => Ok(u16::from_le_bytes(read_exact(data, idx, 2)?.to_array()) as u64),
        0xfe => Ok(u32::from_le_bytes(read_exact(data, idx, 4)?.to_array()) as u64),
        0xff => Ok(u64::from_le_bytes(read_exact(data, idx, 8)?.to_array())),
        v => Ok(v as u64),
    }
}

fn read_varbytes<'a>(
    data: &'a [u8],
    idx: &mut usize,
    max_len: u64,
) -> Result<&'a [u8], ConsensusPolicyError> {
    let len = read_varint(data, idx)?;
    if len > max_len {
        return Err(ConsensusPolicyError::MessageBodyTooLarge);
    }
    read_exact(data, idx, len as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn typed_body(message_type: u8) -> Vec<u8> {
        match message_type {
            0x00 => vec![0u8; CHANGE_VIEW_MIN_BODY],
            0x20 => {
                let mut body = vec![0u8; PREPARE_REQUEST_FIXED];
                body.push(0);
                body
            }
            0x21 => vec![0u8; PREPARE_RESPONSE_BODY],
            0x30 => vec![0u8; COMMIT_BODY],
            0x40 => vec![0u8; RECOVERY_REQUEST_BODY],
            0x41 => vec![0, 0, 0, 0, 0],
            _ => vec![0xaa, 0xbb],
        }
    }

    fn payload(message_type: u8, height: u32, sender: H160) -> ExtensiblePayload {
        let mut data = Vec::from([message_type]);
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&[1, 2]);
        data.extend_from_slice(&typed_body(message_type));

        ExtensiblePayload {
            category: DBFT_CATEGORY.into(),
            valid_block_start: 0,
            valid_block_end: height,
            sender: sender.as_le_bytes().to_vec(),
            data,
        }
    }

    #[test]
    fn accepts_mainnet_dbft_payload() {
        let policy = ConsensusSigningPolicy::new(NEO_N3_MAINNET_MAGIC);
        let sender = H160::from_le_bytes([7; H160_SIZE]);
        let metadata = policy
            .validate_extensible_payload(
                &payload(ConsensusMessageType::Commit as u8, 42, sender),
                &[sender],
                NEO_N3_MAINNET_MAGIC,
            )
            .unwrap();

        assert_eq!(metadata.message_type, ConsensusMessageType::Commit);
        assert_eq!(metadata.block_index, 42);
        assert_eq!(metadata.validator_index, 1);
        assert_eq!(metadata.view_number, 2);
    }

    #[test]
    fn rejects_other_network_and_category() {
        let policy = ConsensusSigningPolicy::new(NEO_N3_MAINNET_MAGIC);
        let sender = H160::from_le_bytes([7; H160_SIZE]);
        let valid = payload(ConsensusMessageType::PrepareResponse as u8, 42, sender);

        assert!(matches!(
            policy.validate_extensible_payload(&valid, &[sender], 123),
            Err(ConsensusPolicyError::NetworkNotAllowed { .. })
        ));

        let mut wrong_category = valid;
        wrong_category.category = "oracle".into();
        assert!(matches!(
            policy.validate_extensible_payload(&wrong_category, &[sender], NEO_N3_MAINNET_MAGIC),
            Err(ConsensusPolicyError::CategoryNotAllowed(_))
        ));
    }

    #[test]
    fn rejects_inconsistent_height_sender_and_message_type() {
        let policy = ConsensusSigningPolicy::new(NEO_N3_MAINNET_MAGIC);
        let sender = H160::from_le_bytes([7; H160_SIZE]);

        let mut wrong_height = payload(ConsensusMessageType::Commit as u8, 42, sender);
        wrong_height.valid_block_end = 43;
        assert!(matches!(
            policy.validate_extensible_payload(&wrong_height, &[sender], NEO_N3_MAINNET_MAGIC),
            Err(ConsensusPolicyError::InvalidValidBlockEnd { .. })
        ));

        let other = H160::from_le_bytes([8; H160_SIZE]);
        assert_eq!(
            policy.validate_extensible_payload(
                &payload(ConsensusMessageType::Commit as u8, 42, sender),
                &[other],
                NEO_N3_MAINNET_MAGIC,
            ),
            Err(ConsensusPolicyError::SenderMismatch)
        );

        assert_eq!(
            policy.validate_extensible_payload(
                &payload(0xff, 42, sender),
                &[sender],
                NEO_N3_MAINNET_MAGIC,
            ),
            Err(ConsensusPolicyError::UnsupportedMessageType(0xff))
        );
    }

    #[test]
    fn pinned_key_rejects_wrong_signer_and_multi_account_sets() {
        let pinned = H160::from_le_bytes([7; H160_SIZE]);
        let other = H160::from_le_bytes([8; H160_SIZE]);
        let policy =
            ConsensusSigningPolicy::new(NEO_N3_MAINNET_MAGIC).with_pinned_script_hash(pinned);

        let ok = payload(ConsensusMessageType::ChangeView as u8, 9, pinned);
        assert!(policy
            .validate_extensible_payload(&ok, &[pinned], NEO_N3_MAINNET_MAGIC)
            .is_ok());

        assert_eq!(
            policy.validate_extensible_payload(
                &payload(ConsensusMessageType::RecoveryRequest as u8, 9, other),
                &[other],
                NEO_N3_MAINNET_MAGIC,
            ),
            Err(ConsensusPolicyError::SignerNotPinned)
        );
        assert_eq!(
            policy.validate_extensible_payload(
                &payload(ConsensusMessageType::RecoveryMessage as u8, 9, pinned),
                &[pinned, other],
                NEO_N3_MAINNET_MAGIC,
            ),
            Err(ConsensusPolicyError::InvalidSignerCount)
        );
        assert_eq!(
            policy.validate_extensible_payload(&ok, &[other], NEO_N3_MAINNET_MAGIC),
            Err(ConsensusPolicyError::SenderMismatch)
        );
    }

    #[test]
    fn rejects_malformed_category_range_and_bodies() {
        let policy = ConsensusSigningPolicy::new(NEO_N3_MAINNET_MAGIC);
        let sender = H160::from_le_bytes([7; H160_SIZE]);

        let mut header_only = payload(ConsensusMessageType::ChangeView as u8, 9, sender);
        header_only.data.truncate(CONSENSUS_HEADER_SIZE);
        assert_eq!(
            policy.validate_extensible_payload(&header_only, &[sender], NEO_N3_MAINNET_MAGIC),
            Err(ConsensusPolicyError::TruncatedMessage)
        );

        let mut start = payload(ConsensusMessageType::Commit as u8, 9, sender);
        start.valid_block_start = 1;
        assert_eq!(
            policy.validate_extensible_payload(&start, &[sender], NEO_N3_MAINNET_MAGIC),
            Err(ConsensusPolicyError::InvalidValidBlockStart)
        );

        let mut commit_garbage = payload(ConsensusMessageType::Commit as u8, 9, sender);
        commit_garbage.data.push(0xff);
        assert_eq!(
            policy.validate_extensible_payload(&commit_garbage, &[sender], NEO_N3_MAINNET_MAGIC),
            Err(ConsensusPolicyError::MalformedMessage)
        );

        let mut prepare = payload(ConsensusMessageType::PrepareRequest as u8, 9, sender);
        prepare.data[CONSENSUS_HEADER_SIZE] = 1;
        assert_eq!(
            policy.validate_extensible_payload(&prepare, &[sender], NEO_N3_MAINNET_MAGIC),
            Err(ConsensusPolicyError::MalformedMessage)
        );

        let mut huge = payload(ConsensusMessageType::PrepareRequest as u8, 9, sender);
        huge.data
            .truncate(CONSENSUS_HEADER_SIZE + PREPARE_REQUEST_FIXED);
        huge.data.push(0xff);
        huge.data.extend_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            policy.validate_extensible_payload(&huge, &[sender], NEO_N3_MAINNET_MAGIC),
            Err(ConsensusPolicyError::MessageBodyTooLarge)
        );

        let mut recovery = payload(ConsensusMessageType::RecoveryMessage as u8, 9, sender);
        recovery.data.push(0xaa);
        assert_eq!(
            policy.validate_extensible_payload(&recovery, &[sender], NEO_N3_MAINNET_MAGIC),
            Err(ConsensusPolicyError::MalformedMessage)
        );
    }
}
