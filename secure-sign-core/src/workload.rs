// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! Application-layer workload identity for the parent gateway.
//!
//! This is a deploy-time shared-secret token policy. It is not mTLS and it is
//! not hardware attestation.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{Debug, Formatter};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ct::constant_time_eq;
use crate::hash::Sha256;
use crate::hmac::HmacSha256;

pub const WORKLOAD_ID_HEADER: &str = "x-workload-id";
pub const WORKLOAD_ROLE_HEADER: &str = "x-workload-role";
pub const WORKLOAD_TOKEN_HEADER: &str = "x-workload-token";
pub const REQUEST_NONCE_HEADER: &str = "x-request-nonce";
pub const REQUEST_NOT_AFTER_HEADER: &str = "x-request-not-after";
pub const REQUEST_MAC_HEADER: &str = "x-request-mac";
pub const SIGN_CONTRACT_VERSION_HEADER: &str = "x-sign-contract-version";

pub const REQUEST_MAC_VERSION: &str = "v1";
pub const SIGN_CONTRACT_VERSION: &str = "1";
pub const REQUEST_MAC_METHOD_RAW_PAYLOAD: &str = "/servicepb.SecureSign/SignExtensiblePayload";
pub const REQUEST_MAC_HEX_CHARS: usize = 64;
pub const REQUEST_DIGEST_HEX_CHARS: usize = 64;

pub const MIN_TOKEN_BYTES: usize = 32;
pub const MIN_NONCE_HEX_CHARS: usize = 32;
pub const MAX_NONCE_HEX_CHARS: usize = 128;
pub const MAX_RAW_PAYLOAD_TTL_SECS: i64 = 60;
pub const MAX_REPLAY_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Zeroize)]
pub enum WorkloadRole {
    Consensus,
    Economic,
}

impl WorkloadRole {
    pub fn parse(value: &str) -> Result<Self, WorkloadIdentityError> {
        match value {
            "consensus" => Ok(Self::Consensus),
            "economic" => Ok(Self::Economic),
            _ => Err(WorkloadIdentityError::UnknownRole),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Consensus => "consensus",
            Self::Economic => "economic",
        }
    }
}

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct WorkloadIdentity {
    pub id: String,
    pub role: WorkloadRole,
    pub token: Vec<u8>,
}

impl Debug for WorkloadIdentity {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WorkloadIdentity")
            .field("id", &self.id)
            .field("role", &self.role)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WorkloadIdentityPolicy {
    identities: Vec<WorkloadIdentity>,
}

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum WorkloadIdentityError {
    #[error("workload identity table is required")]
    MissingTable,

    #[error("workload identity entry must be id:role:hex-token")]
    InvalidEntry,

    #[error("workload identity id is invalid")]
    InvalidId,

    #[error("workload identity role is unknown")]
    UnknownRole,

    #[error("workload identity token must be at least {MIN_TOKEN_BYTES} random bytes")]
    TokenTooShort,

    #[error("workload identity token is not hex")]
    TokenNotHex,

    #[error("duplicate workload identity token for id")]
    DuplicateId,

    #[error("workload identity id has conflicting roles")]
    ConflictingRole,

    #[error("caller identity is missing")]
    Unauthenticated,

    #[error("caller identity is not recognized")]
    UnknownIdentity,

    #[error("caller role is not allowed")]
    RoleNotAllowed,

    #[error("raw payload signing is disabled")]
    RawPayloadDisabled,

    #[error("request nonce is invalid")]
    InvalidNonce,

    #[error("request freshness window is invalid")]
    InvalidNotAfter,

    #[error("request freshness window has expired")]
    Expired,

    #[error("request TTL exceeds the maximum of {MAX_RAW_PAYLOAD_TTL_SECS} seconds")]
    TtlTooLong,

    #[error("request MAC is invalid")]
    InvalidMac,

    #[error("sign contract version is required")]
    MissingContractVersion,

    #[error("sign contract version is unknown")]
    UnknownContractVersion,

    #[error("identical request already consumed")]
    IdempotentConsumed,

    #[error("request nonce or payload digest has already been used")]
    Replay,

    #[error("request replay journal is at capacity")]
    ReplayJournalFull,
}

impl WorkloadIdentityPolicy {
    pub fn parse_table(raw: &str) -> Result<Self, WorkloadIdentityError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(WorkloadIdentityError::MissingTable);
        }

        let mut identities: Vec<WorkloadIdentity> = Vec::new();
        for entry in trimmed.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                return Err(WorkloadIdentityError::InvalidEntry);
            }
            let mut parts = entry.splitn(3, ':');
            let id = parts.next().ok_or(WorkloadIdentityError::InvalidEntry)?;
            let role = parts.next().ok_or(WorkloadIdentityError::InvalidEntry)?;
            let token = parts.next().ok_or(WorkloadIdentityError::InvalidEntry)?;
            if !is_identity_id(id) {
                return Err(WorkloadIdentityError::InvalidId);
            }
            let role = WorkloadRole::parse(role)?;
            let token = decode_token(token)?;
            if identities
                .iter()
                .any(|existing| existing.id == id && existing.role != role)
            {
                return Err(WorkloadIdentityError::ConflictingRole);
            }
            if identities
                .iter()
                .any(|existing| existing.id == id && existing.token == token)
            {
                return Err(WorkloadIdentityError::DuplicateId);
            }
            identities.push(WorkloadIdentity {
                id: id.into(),
                role,
                token,
            });
        }
        Ok(Self { identities })
    }

    pub fn authenticate(
        &self,
        id: &str,
        role: WorkloadRole,
        token: &[u8],
    ) -> Result<&WorkloadIdentity, WorkloadIdentityError> {
        const DUMMY: [u8; MIN_TOKEN_BYTES] = [0u8; MIN_TOKEN_BYTES];
        let mut matched = None;
        let mut compared = false;
        for identity in &self.identities {
            if identity.id != id {
                continue;
            }
            compared = true;
            let token_ok = constant_time_eq(&identity.token, token);
            let role_ok = identity.role == role;
            if token_ok && role_ok {
                matched = Some(identity);
            }
        }
        if !compared {
            let _ = constant_time_eq(&DUMMY, token);
        }
        matched.ok_or(WorkloadIdentityError::Unauthenticated)
    }

    pub fn identities(&self) -> &[WorkloadIdentity] {
        &self.identities
    }
}

pub fn validate_request_freshness(
    nonce: &str,
    not_after: i64,
    now: i64,
    max_ttl_secs: i64,
) -> Result<(), WorkloadIdentityError> {
    if !is_lowercase_hex(nonce)
        || nonce.len() < MIN_NONCE_HEX_CHARS
        || nonce.len() > MAX_NONCE_HEX_CHARS
        || !nonce.len().is_multiple_of(2)
    {
        return Err(WorkloadIdentityError::InvalidNonce);
    }
    if not_after <= 0 {
        return Err(WorkloadIdentityError::InvalidNotAfter);
    }
    if not_after <= now {
        return Err(WorkloadIdentityError::Expired);
    }
    if not_after.saturating_sub(now) > max_ttl_secs {
        return Err(WorkloadIdentityError::TtlTooLong);
    }
    Ok(())
}

pub fn decode_request_mac(value: &str) -> Result<Vec<u8>, WorkloadIdentityError> {
    if value.len() != REQUEST_MAC_HEX_CHARS || !is_lowercase_hex(value) {
        return Err(WorkloadIdentityError::InvalidMac);
    }
    hex::decode(value).map_err(|_| WorkloadIdentityError::InvalidMac)
}

pub fn validate_contract_version(value: Option<&str>) -> Result<(), WorkloadIdentityError> {
    match value {
        None => Err(WorkloadIdentityError::MissingContractVersion),
        Some(SIGN_CONTRACT_VERSION) => Ok(()),
        Some(_) => Err(WorkloadIdentityError::UnknownContractVersion),
    }
}

/// SHA-256 of Neo N3 exact signed bytes (36-byte `network_le || SHA-256(unsigned)`).
/// This is the 32-byte MAC digest, not a hex encoding of the 36-byte sign-data.
pub fn request_digest(sign_data: &[u8]) -> Result<[u8; 32], WorkloadIdentityError> {
    if sign_data.len() != crate::neo::SIGN_DATA_SIZE {
        return Err(WorkloadIdentityError::InvalidMac);
    }
    Ok(sign_data.sha256())
}

pub fn request_digest_hex(sign_data: &[u8]) -> Result<String, WorkloadIdentityError> {
    Ok(encode_lowercase_hex(&request_digest(sign_data)?))
}

pub fn payload_digest_hex(sign_data: &[u8]) -> String {
    request_digest_hex(sign_data).expect("sign_data must be Neo N3 36-byte exact signed bytes")
}

#[derive(Debug, Clone, Copy)]
pub struct RequestMacV1<'a> {
    pub identity_id: &'a str,
    pub role: WorkloadRole,
    pub method: &'a str,
    pub network: u32,
    pub payload_digest_hex: &'a str,
    pub nonce: &'a str,
    pub not_after: i64,
}

impl RequestMacV1<'_> {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Labeled v1 transcript. No trailing newline. Signer is protocol authority.
        format!(
            "{REQUEST_MAC_VERSION}\nmethod={}\nnetwork={}\nnonce={}\nnot_after={}\ndigest={}\nworkload_id={}\nworkload_role={}",
            self.method,
            self.network,
            self.nonce,
            self.not_after,
            self.payload_digest_hex,
            self.identity_id,
            self.role.as_str()
        )
        .into_bytes()
    }

    pub fn compute(&self, token: &[u8]) -> [u8; 32] {
        token.hmac_sha256(&self.canonical_bytes())
    }

    pub fn verify(&self, token: &[u8], provided_mac: &[u8]) -> Result<(), WorkloadIdentityError> {
        if self.payload_digest_hex.len() != REQUEST_DIGEST_HEX_CHARS
            || !is_lowercase_hex(self.payload_digest_hex)
        {
            return Err(WorkloadIdentityError::InvalidMac);
        }
        if constant_time_eq(&self.compute(token), provided_mac) {
            Ok(())
        } else {
            Err(WorkloadIdentityError::Unauthenticated)
        }
    }
}

fn is_identity_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_' || byte == b'-'
        })
}

fn decode_token(value: &str) -> Result<Vec<u8>, WorkloadIdentityError> {
    let token = hex::decode(value).map_err(|_| WorkloadIdentityError::TokenNotHex)?;
    if token.len() < MIN_TOKEN_BYTES {
        return Err(WorkloadIdentityError::TokenTooShort);
    }
    Ok(token)
}

pub fn is_lowercase_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn encode_lowercase_hex(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    fn policy() -> WorkloadIdentityPolicy {
        WorkloadIdentityPolicy::parse_table(&format!(
            "dBFT-node:consensus:{},gas-sweeper:economic:{}",
            "aa".repeat(32),
            "bb".repeat(32)
        ))
        .unwrap()
    }

    #[test]
    fn table_requires_distinct_id_role_and_long_hex_token() {
        assert!(matches!(
            WorkloadIdentityPolicy::parse_table(""),
            Err(WorkloadIdentityError::MissingTable)
        ));
        assert!(matches!(
            WorkloadIdentityPolicy::parse_table("node:consensus:aa"),
            Err(WorkloadIdentityError::TokenTooShort)
        ));
        assert!(matches!(
            WorkloadIdentityPolicy::parse_table(
                "node:observer:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            Err(WorkloadIdentityError::UnknownRole)
        ));
        assert!(matches!(
            WorkloadIdentityPolicy::parse_table(&format!(
                "dBFT-node:consensus:{},dBFT-node:economic:{}",
                "aa".repeat(32),
                "bb".repeat(32)
            )),
            Err(WorkloadIdentityError::ConflictingRole)
        ));
        assert!(policy().identities().len() == 2);
    }

    #[test]
    fn authentication_is_fail_closed_for_unknown_wrong_role_and_wrong_token() {
        let policy = policy();
        let token = vec![0xaa; 32];
        assert!(policy
            .authenticate("dBFT-node", WorkloadRole::Consensus, &token)
            .is_ok());
        assert!(matches!(
            policy.authenticate("missing", WorkloadRole::Consensus, &token),
            Err(WorkloadIdentityError::Unauthenticated)
        ));
        assert!(matches!(
            policy.authenticate("dBFT-node", WorkloadRole::Economic, &token),
            Err(WorkloadIdentityError::Unauthenticated)
        ));
        assert!(matches!(
            policy.authenticate("dBFT-node", WorkloadRole::Consensus, &[0xbb; 32]),
            Err(WorkloadIdentityError::Unauthenticated)
        ));
        assert!(matches!(
            policy.authenticate("dBFT-node", WorkloadRole::Consensus, &[0xaa; 16]),
            Err(WorkloadIdentityError::Unauthenticated)
        ));
    }

    #[test]
    fn overlapping_tokens_rotate_and_old_tokens_can_be_revoked() {
        let old = "aa".repeat(32);
        let new = "cc".repeat(32);
        let overlapping = WorkloadIdentityPolicy::parse_table(&format!(
            "dBFT-node:consensus:{old},dBFT-node:consensus:{new}"
        ))
        .unwrap();
        assert!(overlapping
            .authenticate("dBFT-node", WorkloadRole::Consensus, &[0xaa; 32])
            .is_ok());
        assert!(overlapping
            .authenticate("dBFT-node", WorkloadRole::Consensus, &[0xcc; 32])
            .is_ok());

        let revoked =
            WorkloadIdentityPolicy::parse_table(&format!("dBFT-node:consensus:{new}")).unwrap();
        assert!(matches!(
            revoked.authenticate("dBFT-node", WorkloadRole::Consensus, &[0xaa; 32]),
            Err(WorkloadIdentityError::Unauthenticated)
        ));
        assert!(revoked
            .authenticate("dBFT-node", WorkloadRole::Consensus, &[0xcc; 32])
            .is_ok());
    }

    #[test]
    fn debug_output_redacts_token_bytes() {
        let policy = policy();
        let rendered = format!("{:?}", policy.identities()[0]);
        assert!(rendered.contains("dBFT-node"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("170"));
        assert!(!rendered.contains("0xaa"));
    }

    #[test]
    fn freshness_window_rejects_short_expired_and_overlong_nonces() {
        let nonce = "ab".repeat(16);
        assert!(validate_request_freshness(&nonce, 940, 900, 60).is_ok());
        assert!(matches!(
            validate_request_freshness("short", 940, 900, 60),
            Err(WorkloadIdentityError::InvalidNonce)
        ));
        assert!(matches!(
            validate_request_freshness(&nonce, 800, 900, 60),
            Err(WorkloadIdentityError::Expired)
        ));
        assert!(matches!(
            validate_request_freshness(&nonce, 1_000, 900, 60),
            Err(WorkloadIdentityError::TtlTooLong)
        ));
        assert!(matches!(
            validate_request_freshness(&"AB".repeat(16), 940, 900, 60),
            Err(WorkloadIdentityError::InvalidNonce)
        ));
        assert!(matches!(
            validate_request_freshness(&format!("0x{nonce}"), 940, 900, 60),
            Err(WorkloadIdentityError::InvalidNonce)
        ));
    }

    #[test]
    fn request_mac_binds_identity_method_network_digest_nonce_and_expiry() {
        let token = [0xaa_u8; 32];
        let digest = encode_lowercase_hex(&[0x11; 32]);
        let nonce = "ab".repeat(16);
        let fields = RequestMacV1 {
            identity_id: "dBFT-node",
            role: WorkloadRole::Consensus,
            method: REQUEST_MAC_METHOD_RAW_PAYLOAD,
            network: 860_833_102,
            payload_digest_hex: &digest,
            nonce: &nonce,
            not_after: 940,
        };
        let mac = fields.compute(&token);
        assert!(fields.verify(&token, &mac).is_ok());
        let mut wrong_method = fields;
        wrong_method.method = "SignBlock";
        assert!(matches!(
            wrong_method.verify(&token, &mac),
            Err(WorkloadIdentityError::Unauthenticated)
        ));
        let mut wrong_network = fields;
        wrong_network.network = 1;
        assert!(matches!(
            wrong_network.verify(&token, &mac),
            Err(WorkloadIdentityError::Unauthenticated)
        ));
        assert!(matches!(
            decode_request_mac(&encode_lowercase_hex(&mac).to_ascii_uppercase()),
            Err(WorkloadIdentityError::InvalidMac)
        ));
        assert!(!core::str::from_utf8(&fields.canonical_bytes())
            .unwrap()
            .ends_with('\n'));
        assert!(core::str::from_utf8(&fields.canonical_bytes())
            .unwrap()
            .starts_with("v1\nmethod=/servicepb.SecureSign/SignExtensiblePayload\n"));
    }

    #[test]
    fn contract_version_is_fail_closed() {
        assert!(validate_contract_version(Some(SIGN_CONTRACT_VERSION)).is_ok());
        assert!(matches!(
            validate_contract_version(None),
            Err(WorkloadIdentityError::MissingContractVersion)
        ));
        assert!(matches!(
            validate_contract_version(Some("2")),
            Err(WorkloadIdentityError::UnknownContractVersion)
        ));
        assert!(matches!(
            validate_contract_version(Some("")),
            Err(WorkloadIdentityError::UnknownContractVersion)
        ));
    }

    #[test]
    fn request_digest_is_sha256_of_36_byte_sign_data_not_the_sign_data() {
        let sign_data = [0x11_u8; crate::neo::SIGN_DATA_SIZE];
        let digest = request_digest(&sign_data).unwrap();
        assert_eq!(digest.len(), 32);
        assert_ne!(&digest[..], &sign_data[..32]);
        assert!(request_digest(&[0x11; 32]).is_err());
    }

    #[derive(serde::Deserialize)]
    struct GoldenPayload {
        category: String,
        valid_block_start: u32,
        valid_block_end: u32,
        sender_hex: String,
        data_hex: String,
    }

    #[derive(serde::Deserialize)]
    struct GoldenVector {
        token_hex: String,
        workload_id: String,
        workload_role: String,
        method: String,
        network: u32,
        payload: GoldenPayload,
        nonce_hex: String,
        not_after: i64,
        unsigned_bytes_hex: String,
        sign_data_hex: String,
        digest_hex: String,
        canonical_transcript: String,
        mac_hex: String,
        incompatible_fura_length_prefix_digest_hex: String,
    }

    fn load_golden() -> GoldenVector {
        const FIXTURE: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/workload-request-auth-v1.json"
        ));
        #[cfg(feature = "std")]
        {
            let path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/testdata/workload-request-auth-v1.json"
            );
            let from_disk = std::fs::read_to_string(path).expect("load golden fixture");
            assert_eq!(from_disk, FIXTURE, "included fixture drifted from disk");
        }
        serde_json::from_str(FIXTURE).expect("golden fixture JSON")
    }

    #[test]
    fn golden_vector_verifies_each_signer_step() {
        use crate::neo::sign::Signer;
        use crate::neo::signpb::ExtensiblePayload;

        let golden = load_golden();
        assert_eq!(golden.method, REQUEST_MAC_METHOD_RAW_PAYLOAD);
        assert_eq!(golden.workload_role, "consensus");
        assert_eq!(golden.sign_data_hex.len(), crate::neo::SIGN_DATA_SIZE * 2);
        assert_eq!(golden.digest_hex.len(), REQUEST_DIGEST_HEX_CHARS);

        let payload = ExtensiblePayload {
            category: golden.payload.category.clone(),
            valid_block_start: golden.payload.valid_block_start,
            valid_block_end: golden.payload.valid_block_end,
            sender: hex::decode(&golden.payload.sender_hex).unwrap(),
            data: hex::decode(&golden.payload.data_hex).unwrap(),
        };
        let unsigned = Signer::extensible_unsigned_bytes(&payload).unwrap();
        assert_eq!(encode_lowercase_hex(&unsigned), golden.unsigned_bytes_hex);

        let sign_data = Signer::extensible_sign_data(&payload, golden.network).unwrap();
        assert_eq!(encode_lowercase_hex(&sign_data), golden.sign_data_hex);
        assert_eq!(sign_data.len(), crate::neo::SIGN_DATA_SIZE);

        let digest = request_digest(&sign_data).unwrap();
        assert_eq!(encode_lowercase_hex(&digest), golden.digest_hex);
        assert_eq!(
            encode_lowercase_hex(
                &Signer::extensible_request_digest(&payload, golden.network).unwrap()
            ),
            golden.digest_hex
        );

        let mut range_changed = payload.clone();
        range_changed.valid_block_end = payload.valid_block_end + 1;
        assert_ne!(
            Signer::extensible_request_digest(&range_changed, golden.network).unwrap(),
            digest
        );

        let fields = RequestMacV1 {
            identity_id: &golden.workload_id,
            role: WorkloadRole::Consensus,
            method: REQUEST_MAC_METHOD_RAW_PAYLOAD,
            network: golden.network,
            payload_digest_hex: &golden.digest_hex,
            nonce: &golden.nonce_hex,
            not_after: golden.not_after,
        };
        let canonical = fields.canonical_bytes();
        let transcript = core::str::from_utf8(&canonical).unwrap();
        assert_eq!(transcript, golden.canonical_transcript);
        assert!(!transcript.ends_with('\n'));

        let token = hex::decode(&golden.token_hex).unwrap();
        let mac = fields.compute(&token);
        assert_eq!(encode_lowercase_hex(&mac), golden.mac_hex);
        assert!(fields.verify(&token, &mac).is_ok());

        assert_ne!(
            golden.digest_hex, golden.incompatible_fura_length_prefix_digest_hex,
            "Fura length-prefix digest must not match Signer digest"
        );
        let mut fura = fields;
        fura.payload_digest_hex = &golden.incompatible_fura_length_prefix_digest_hex;
        assert!(matches!(
            fura.verify(&token, &mac),
            Err(WorkloadIdentityError::Unauthenticated)
        ));
    }
}
