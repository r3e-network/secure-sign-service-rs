// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use crate::bytes::ToArray;
use crate::h160::{H160, H160_SIZE};
use crate::neo::signpb::ExtensiblePayload;
use alloc::string::{String, ToString};

pub const DBFT_CATEGORY: &str = "dBFT";
pub const NEO_N3_MAINNET_MAGIC: u32 = 860_833_102;

const CONSENSUS_HEADER_SIZE: usize = 7;

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
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ConsensusSigningPolicy {
    network: u32,
}

impl ConsensusSigningPolicy {
    pub const fn new(network: u32) -> Self {
        Self { network }
    }

    pub const fn network(&self) -> u32 {
        self.network
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

        Ok(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn payload(message_type: u8, height: u32, sender: H160) -> ExtensiblePayload {
        let mut data = Vec::from([message_type]);
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&[1, 2]);
        data.extend_from_slice(&[0xaa, 0xbb]);

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
}
