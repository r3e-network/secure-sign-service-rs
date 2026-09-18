// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

#![allow(clippy::result_large_err)]

use secure_sign_core::workload::{
    decode_request_mac, request_digest_hex, validate_contract_version, validate_request_freshness,
    RequestMacV1, WorkloadIdentityError, WorkloadIdentityPolicy, WorkloadRole,
    MAX_RAW_PAYLOAD_TTL_SECS, REQUEST_MAC_HEADER, REQUEST_MAC_METHOD_RAW_PAYLOAD,
    REQUEST_NONCE_HEADER, REQUEST_NOT_AFTER_HEADER, SIGN_CONTRACT_VERSION_HEADER,
    WORKLOAD_ID_HEADER, WORKLOAD_ROLE_HEADER, WORKLOAD_TOKEN_HEADER,
};
use tonic::{Request, Status};

#[derive(Debug, Clone)]
pub struct RawPayloadRequest {
    pub identity_id: String,
    pub token: Vec<u8>,
    pub nonce: String,
    pub not_after: i64,
    pub mac: Vec<u8>,
}

impl RawPayloadRequest {
    pub fn verify_mac(&self, network: u32, sign_data: &[u8]) -> Result<(), Status> {
        let digest = request_digest_hex(sign_data).map_err(identity_status)?;
        RequestMacV1 {
            identity_id: &self.identity_id,
            role: WorkloadRole::Consensus,
            method: REQUEST_MAC_METHOD_RAW_PAYLOAD,
            network,
            payload_digest_hex: &digest,
            nonce: &self.nonce,
            not_after: self.not_after,
        }
        .verify(&self.token, &self.mac)
        .map_err(identity_status)
    }
}

pub fn authenticate<T>(
    request: &Request<T>,
    policy: &WorkloadIdentityPolicy,
    required_role: WorkloadRole,
) -> Result<(), Status> {
    let role = authenticate_any(request, policy)?;
    if role != required_role {
        return Err(identity_status(WorkloadIdentityError::RoleNotAllowed));
    }
    Ok(())
}

pub fn authenticate_any<T>(
    request: &Request<T>,
    policy: &WorkloadIdentityPolicy,
) -> Result<WorkloadRole, Status> {
    inspect_identity(request, policy).map(|(_, role, _)| role)
}

fn inspect_identity<T>(
    request: &Request<T>,
    policy: &WorkloadIdentityPolicy,
) -> Result<(String, WorkloadRole, Vec<u8>), Status> {
    let id = metadata_str(request, WORKLOAD_ID_HEADER)?;
    let role = WorkloadRole::parse(&metadata_str(request, WORKLOAD_ROLE_HEADER)?)
        .map_err(identity_status)?;
    let token = hex::decode(metadata_str(request, WORKLOAD_TOKEN_HEADER)?)
        .map_err(|_| Status::unauthenticated("workload token is not hex"))?;
    policy
        .authenticate(&id, role, &token)
        .map(|identity| (identity.id.clone(), identity.role, token))
        .map_err(identity_status)
}

pub fn inspect_raw_payload<T>(
    request: &Request<T>,
    policy: &WorkloadIdentityPolicy,
    enabled: bool,
    now: i64,
) -> Result<RawPayloadRequest, Status> {
    if !enabled {
        return Err(identity_status(WorkloadIdentityError::RawPayloadDisabled));
    }
    let (identity_id, role, token) = inspect_identity(request, policy)?;
    if role != WorkloadRole::Consensus {
        return Err(identity_status(WorkloadIdentityError::RoleNotAllowed));
    }
    let version = request
        .metadata()
        .get(SIGN_CONTRACT_VERSION_HEADER)
        .and_then(|value| value.to_str().ok());
    validate_contract_version(version).map_err(identity_status)?;
    let nonce = metadata_str(request, REQUEST_NONCE_HEADER)?;
    let not_after = metadata_str(request, REQUEST_NOT_AFTER_HEADER)?
        .parse::<i64>()
        .map_err(|_| identity_status(WorkloadIdentityError::InvalidNotAfter))?;
    validate_request_freshness(&nonce, not_after, now, MAX_RAW_PAYLOAD_TTL_SECS)
        .map_err(identity_status)?;
    let mac =
        decode_request_mac(&metadata_str(request, REQUEST_MAC_HEADER)?).map_err(identity_status)?;
    Ok(RawPayloadRequest {
        identity_id,
        token,
        nonce,
        not_after,
        mac,
    })
}

pub fn identity_status(err: WorkloadIdentityError) -> Status {
    match err {
        WorkloadIdentityError::Unauthenticated
        | WorkloadIdentityError::UnknownIdentity
        | WorkloadIdentityError::MissingTable => Status::unauthenticated(err.to_string()),
        WorkloadIdentityError::RawPayloadDisabled => Status::failed_precondition(err.to_string()),
        WorkloadIdentityError::IdempotentConsumed => Status::already_exists(err.to_string()),
        WorkloadIdentityError::Replay
        | WorkloadIdentityError::Expired
        | WorkloadIdentityError::ReplayJournalFull
        | WorkloadIdentityError::MissingContractVersion
        | WorkloadIdentityError::UnknownContractVersion => {
            Status::failed_precondition(err.to_string())
        }
        _ => Status::permission_denied(err.to_string()),
    }
}

fn metadata_str<T>(request: &Request<T>, key: &'static str) -> Result<String, Status> {
    request
        .metadata()
        .get(key)
        .ok_or_else(|| Status::unauthenticated(format!("{key} is required")))?
        .to_str()
        .map(|value| value.to_owned())
        .map_err(|_| Status::unauthenticated(format!("{key} is not ASCII")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure_sign_core::neo::SIGN_DATA_SIZE;
    use secure_sign_core::workload::{
        encode_lowercase_hex, request_digest_hex, RequestMacV1, REQUEST_MAC_METHOD_RAW_PAYLOAD,
        SIGN_CONTRACT_VERSION, SIGN_CONTRACT_VERSION_HEADER,
    };
    use secure_sign_rpc::servicepb::SignExtensiblePayloadRequest;

    fn policy() -> WorkloadIdentityPolicy {
        WorkloadIdentityPolicy::parse_table(&format!(
            "dBFT-node:consensus:{},gas-sweeper:economic:{}",
            "aa".repeat(32),
            "bb".repeat(32)
        ))
        .unwrap()
    }

    fn request(
        id: &str,
        role: &str,
        token: &str,
        nonce: Option<&str>,
        not_after: Option<&str>,
        mac: Option<&str>,
    ) -> Request<SignExtensiblePayloadRequest> {
        let mut request = Request::new(SignExtensiblePayloadRequest::default());
        let metadata = request.metadata_mut();
        metadata.insert(WORKLOAD_ID_HEADER, id.parse().unwrap());
        metadata.insert(WORKLOAD_ROLE_HEADER, role.parse().unwrap());
        metadata.insert(WORKLOAD_TOKEN_HEADER, token.parse().unwrap());
        if let Some(nonce) = nonce {
            metadata.insert(REQUEST_NONCE_HEADER, nonce.parse().unwrap());
        }
        if let Some(not_after) = not_after {
            metadata.insert(REQUEST_NOT_AFTER_HEADER, not_after.parse().unwrap());
        }
        if let Some(mac) = mac {
            metadata.insert(REQUEST_MAC_HEADER, mac.parse().unwrap());
        }
        metadata.insert(
            SIGN_CONTRACT_VERSION_HEADER,
            SIGN_CONTRACT_VERSION.parse().unwrap(),
        );
        request
    }

    fn signed_raw(
        nonce: &str,
        not_after: i64,
        sign_data: &[u8; SIGN_DATA_SIZE],
    ) -> Request<SignExtensiblePayloadRequest> {
        let digest = request_digest_hex(sign_data).unwrap();
        let mac = RequestMacV1 {
            identity_id: "dBFT-node",
            role: WorkloadRole::Consensus,
            method: REQUEST_MAC_METHOD_RAW_PAYLOAD,
            network: 860_833_102,
            payload_digest_hex: &digest,
            nonce,
            not_after,
        }
        .compute(&[0xaa; 32]);
        request(
            "dBFT-node",
            "consensus",
            &"aa".repeat(32),
            Some(nonce),
            Some(&not_after.to_string()),
            Some(&encode_lowercase_hex(&mac)),
        )
    }

    #[test]
    fn unauthenticated_and_wrong_role_calls_are_denied() {
        let policy = policy();
        let missing = Request::new(SignExtensiblePayloadRequest::default());
        assert_eq!(
            authenticate(&missing, &policy, WorkloadRole::Consensus)
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );

        let wrong_role = request(
            "gas-sweeper",
            "economic",
            &"bb".repeat(32),
            None,
            None,
            None,
        );
        assert_eq!(
            authenticate(&wrong_role, &policy, WorkloadRole::Consensus)
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );

        let ok = request("dBFT-node", "consensus", &"aa".repeat(32), None, None, None);
        assert!(authenticate(&ok, &policy, WorkloadRole::Consensus).is_ok());
    }

    #[test]
    fn raw_payload_defaults_off_and_requires_lowercase_mac() {
        let policy = policy();
        let nonce = "ab".repeat(16);
        let sign_data = [0x11; SIGN_DATA_SIZE];
        let req = signed_raw(&nonce, 940, &sign_data);
        assert!(inspect_raw_payload(&req, &policy, false, 900)
            .unwrap_err()
            .message()
            .contains("disabled"));
        let inspected = inspect_raw_payload(&req, &policy, true, 900).unwrap();
        assert!(inspected.verify_mac(860_833_102, &sign_data).is_ok());
        assert_eq!(
            inspected
                .verify_mac(860_833_102, &[0x22; SIGN_DATA_SIZE])
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );

        let mut missing_version = signed_raw(&nonce, 940, &sign_data);
        missing_version
            .metadata_mut()
            .remove(SIGN_CONTRACT_VERSION_HEADER);
        assert!(inspect_raw_payload(&missing_version, &policy, true, 900)
            .unwrap_err()
            .message()
            .contains("version"));
        let mut unknown_version = signed_raw(&nonce, 940, &sign_data);
        unknown_version
            .metadata_mut()
            .insert(SIGN_CONTRACT_VERSION_HEADER, "2".parse().unwrap());
        assert!(inspect_raw_payload(&unknown_version, &policy, true, 900)
            .unwrap_err()
            .message()
            .contains("unknown"));

        let mixed = request(
            "dBFT-node",
            "consensus",
            &"aa".repeat(32),
            Some(&"AB".repeat(16)),
            Some("940"),
            Some(&"aa".repeat(32)),
        );
        assert!(inspect_raw_payload(&mixed, &policy, true, 900)
            .unwrap_err()
            .message()
            .contains("nonce"));
    }
}
