// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

pub mod servicepb;
pub mod startpb;
pub mod startup;

// #[cfg(feature = "vsock")]
pub mod vsock;

use secure_sign_core::bytes::ToArray;
use secure_sign_core::h160::{H160, H160_SIZE};
use secure_sign_core::limits::{
    validate_extensible_request, validate_public_key, validate_raw_tx, validate_trimmed_block,
    MAX_RPC_MESSAGE_BYTES,
};
use secure_sign_core::neo::consensus::{ConsensusPolicyError, ConsensusSigningPolicy};
use secure_sign_core::neo::gas_sweep_policy::{
    GasSweepPolicyError, GasSweepSigningPolicy, GasSweepValidationRequest,
};
use secure_sign_core::neo::sign::{SignError, Signer};
use servicepb::{
    secure_sign_server::{SecureSign, SecureSignServer},
    *,
};
use tonic::async_trait;

pub fn bounded_secure_sign_server<T: SecureSign>(service: T) -> SecureSignServer<T> {
    SecureSignServer::new(service)
        .max_decoding_message_size(MAX_RPC_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_RPC_MESSAGE_BYTES)
}

pub fn bounded_secure_sign_server_from_arc<T: SecureSign>(
    service: std::sync::Arc<T>,
) -> SecureSignServer<T> {
    SecureSignServer::from_arc(service)
        .max_decoding_message_size(MAX_RPC_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_RPC_MESSAGE_BYTES)
}

pub trait IntoRpcStatus {
    fn into_rpc_status(self) -> tonic::Status;
}

impl IntoRpcStatus for SignError {
    fn into_rpc_status(self) -> tonic::Status {
        match self {
            SignError::InvalidPublicKey(s) => tonic::Status::invalid_argument(s),
            SignError::NoSuchAccount => tonic::Status::not_found("no such account"),
            SignError::AccountLocked => tonic::Status::failed_precondition("account locked"),
            SignError::EcdsaSignError(s) => tonic::Status::internal(s),
            SignError::InvalidBlock(s) => tonic::Status::invalid_argument(s),
            SignError::InvalidExtensiblePayload(s) => tonic::Status::invalid_argument(s),
        }
    }
}

impl IntoRpcStatus for GasSweepPolicyError {
    fn into_rpc_status(self) -> tonic::Status {
        match self {
            GasSweepPolicyError::Disabled => {
                tonic::Status::unimplemented("SignTransaction is disabled")
            }
            GasSweepPolicyError::AllowlistNotConfigured
            | GasSweepPolicyError::SourceNotConfigured
            | GasSweepPolicyError::NetworkNotAllowed { .. }
            | GasSweepPolicyError::PublicKeyNotAllowed
            | GasSweepPolicyError::SignerAccountMismatch
            | GasSweepPolicyError::DestinationNotAllowlisted
            | GasSweepPolicyError::FeeCapExceeded { .. }
            | GasSweepPolicyError::ReserveViolation => {
                tonic::Status::permission_denied(self.to_string())
            }
            GasSweepPolicyError::MissingIdempotencyKey
            | GasSweepPolicyError::InvalidIdempotencyKey
            | GasSweepPolicyError::InvalidPublicKey
            | GasSweepPolicyError::ExpectedFeeMismatch
            | GasSweepPolicyError::ExpectedAmountMismatch
            | GasSweepPolicyError::Tx(_)
            | GasSweepPolicyError::Script(_) => tonic::Status::invalid_argument(self.to_string()),
        }
    }
}

#[allow(clippy::result_large_err)]
pub fn to_h160_vec(source: Vec<Vec<u8>>) -> Result<Vec<H160>, tonic::Status> {
    let mut h160s = Vec::with_capacity(source.len());
    for hash in source {
        if hash.len() != H160_SIZE {
            return Err(tonic::Status::invalid_argument(
                "ScriptHash must be 20 bytes",
            ));
        }
        h160s.push(H160::from_le_bytes(hash.as_slice().to_array()));
    }
    Ok(h160s)
}

/// Signing service that is always gated by a [`ConsensusSigningPolicy`].
///
/// Every constructor installs a consensus policy and every consensus-bearing RPC
/// is validated against it before any key is used: the network magic must match,
/// extensible payloads must be dBFT with the sender pinned to the requested
/// signer. There is no constructor that can build a policy-less service.
pub struct DefaultSignService {
    signer: Signer,
    consensus_policy: ConsensusSigningPolicy,
    gas_sweep_policy: GasSweepSigningPolicy,
}

impl DefaultSignService {
    /// Builds a service that refuses every request the consensus policy rejects.
    ///
    /// `network` is the only Neo network magic this signer may sign for. Gas
    /// sweep (economic) signing stays disabled until explicitly configured via
    /// [`Self::with_gas_sweep_enabled`] or [`Self::with_gas_sweep_policy`].
    pub fn new(signer: Signer, network: u32) -> Self {
        Self {
            signer,
            consensus_policy: ConsensusSigningPolicy::new(network),
            // Feature flag default OFF — economic signing refused until explicitly enabled.
            gas_sweep_policy: GasSweepSigningPolicy::new(network, false),
        }
    }

    pub fn with_gas_sweep_enabled(mut self, enabled: bool) -> Self {
        self.gas_sweep_policy = self.gas_sweep_policy.with_enabled(enabled);
        self
    }

    pub fn with_gas_sweep_policy(mut self, policy: GasSweepSigningPolicy) -> Self {
        self.gas_sweep_policy = policy;
        self
    }

    fn policy_status(err: ConsensusPolicyError) -> tonic::Status {
        tonic::Status::permission_denied(err.to_string())
    }
}

#[async_trait]
impl SecureSign for DefaultSignService {
    async fn sign_extensible_payload(
        &self,
        req: tonic::Request<SignExtensiblePayloadRequest>,
    ) -> Result<tonic::Response<SignExtensiblePayloadResponse>, tonic::Status> {
        let req = req.into_inner();
        validate_extensible_request(req.payload.as_ref(), &req.script_hashes)
            .map_err(|err| tonic::Status::invalid_argument(err.to_string()))?;
        let script_hashes = to_h160_vec(req.script_hashes)?;
        let Some(payload) = req.payload.as_ref() else {
            return Err(tonic::Status::invalid_argument("payload is required"));
        };
        self.consensus_policy
            .validate_extensible_payload(payload, &script_hashes, req.network)
            .map_err(Self::policy_status)?;

        self.signer
            .sign_extensible_payload(payload, script_hashes, req.network)
            .map(|signs| SignExtensiblePayloadResponse { signs: signs.signs })
            .map_err(|err| err.into_rpc_status())
            .map(tonic::Response::new)
    }

    async fn sign_block(
        &self,
        req: tonic::Request<SignBlockRequest>,
    ) -> Result<tonic::Response<SignBlockResponse>, tonic::Status> {
        let req = req.into_inner();
        validate_public_key(&req.public_key)
            .map_err(|err| tonic::Status::invalid_argument(err.to_string()))?;
        validate_trimmed_block(req.block.as_ref())
            .map_err(|err| tonic::Status::invalid_argument(err.to_string()))?;
        let Some(block) = req.block.as_ref() else {
            return Err(tonic::Status::invalid_argument("block is required"));
        };
        self.consensus_policy
            .validate_network(req.network)
            .map_err(Self::policy_status)?;

        self.signer
            .sign_block(&req.public_key, block, req.network)
            .map(|sign| SignBlockResponse { signature: sign })
            .map_err(|err| err.into_rpc_status())
            .map(tonic::Response::new)
    }

    async fn get_account_status(
        &self,
        req: tonic::Request<GetAccountStatusRequest>,
    ) -> Result<tonic::Response<GetAccountStatusResponse>, tonic::Status> {
        let req = req.into_inner();
        validate_public_key(&req.public_key)
            .map_err(|err| tonic::Status::invalid_argument(err.to_string()))?;
        self.signer
            .get_account_status(&req.public_key)
            .map(|x| GetAccountStatusResponse { status: x as i32 })
            .map_err(|err| tonic::Status::invalid_argument(err.to_string()))
            .map(tonic::Response::new)
    }

    async fn sign_transaction(
        &self,
        req: tonic::Request<SignTransactionRequest>,
    ) -> Result<tonic::Response<SignTransactionResponse>, tonic::Status> {
        let req = req.into_inner();
        validate_public_key(&req.public_key)
            .map_err(|err| tonic::Status::invalid_argument(err.to_string()))?;
        validate_raw_tx(&req.raw_tx)
            .map_err(|err| tonic::Status::invalid_argument(err.to_string()))?;
        // Enclave re-validates pure byte/policy invariants (incl. deploy-time destination allowlist).
        // Chain-state dual-RPC binding is enforced on the gateway when enabled.
        let validated = self
            .gas_sweep_policy
            .validate_sign_transaction(GasSweepValidationRequest {
                raw_tx: &req.raw_tx,
                public_key: &req.public_key,
                network: req.network,
                idempotency_key: &req.idempotency_key,
                expected_amount: req.expected_amount,
                expected_fee_total: req.expected_fee_total,
                asserted_safe_balance: None,
            })
            .map_err(|err| err.into_rpc_status())?;

        let (signature, tx_hash) = self
            .signer
            .sign_transaction(&req.public_key, &validated.tx.hash_data, req.network)
            .map_err(|err| err.into_rpc_status())?;

        Ok(tonic::Response::new(SignTransactionResponse {
            signature,
            tx_hash: tx_hash.to_vec(),
            idempotency_key: req.idempotency_key,
            cache_hit: false,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure_sign_core::h256::H256;
    use secure_sign_core::merkle::MerkleSha256;
    use secure_sign_core::neo::consensus::{ConsensusMessageType, DBFT_CATEGORY, NEO_N3_MAINNET_MAGIC};
    use secure_sign_core::neo::gas_sweep_policy::script_hash_from_public_key;
    use secure_sign_core::neo::sign::{Account, Signer};
    use secure_sign_core::neo::signpb::{ExtensiblePayload, Header, TrimmedBlock};
    use secure_sign_core::random::EnvCryptRandom;
    use secure_sign_core::secp256r1::Keypair;

    struct TestSigner {
        signer: Signer,
        public_key: Vec<u8>,
        script_hash: H160,
    }

    fn test_signer() -> TestSigner {
        let keypair = Keypair::gen_random(&mut EnvCryptRandom).expect("keypair generation");
        let public_key = keypair.public_key().to_compressed().to_vec();
        let script_hash = script_hash_from_public_key(&public_key).expect("script hash");
        let account = Account {
            keypair,
            contract: None,
            is_locked: false,
        };
        TestSigner {
            signer: Signer::new(vec![account]),
            public_key,
            script_hash,
        }
    }

    /// Well-formed dBFT Commit payload for the given sender (header + 64-byte body).
    fn commit_payload(sender: H160) -> ExtensiblePayload {
        let mut data = vec![ConsensusMessageType::Commit as u8];
        data.extend_from_slice(&42u32.to_le_bytes()); // block index
        data.push(1); // validator index
        data.push(0); // view number
        data.extend_from_slice(&[0u8; 64]); // commit body
        ExtensiblePayload {
            category: DBFT_CATEGORY.to_string(),
            valid_block_start: 0,
            valid_block_end: 42,
            sender: sender.as_le_bytes().to_vec(),
            data,
        }
    }

    /// Well-formed empty trimmed block whose merkle root matches its (empty) tx set.
    fn empty_block() -> TrimmedBlock {
        TrimmedBlock {
            header: Some(Header {
                version: 0,
                prev_hash: vec![0u8; 32],
                merkle_root: Vec::<H256>::new().merkle_sha256().as_le_bytes().to_vec(),
                timestamp: 1,
                nonce: 2,
                index: 42,
                primary_index: 0,
                next_consensus: vec![0u8; 20],
                prev_state_root: vec![],
                state_root_enabled: false,
            }),
            tx_hashes: vec![],
        }
    }

    /// Regression (SSS-1): an attacker-chosen non-dBFT payload must never be signed.
    /// Without the mandatory consensus policy this request produced one signature
    /// over category="ATTACKER"; the policy must refuse it before any key is used.
    #[tokio::test]
    async fn sign_extensible_payload_refuses_attacker_category() {
        let t = test_signer();
        let service = DefaultSignService::new(t.signer, NEO_N3_MAINNET_MAGIC);

        let mut attacker = commit_payload(t.script_hash);
        attacker.category = "ATTACKER".to_string();

        let req = SignExtensiblePayloadRequest {
            payload: Some(attacker),
            script_hashes: vec![t.script_hash.as_le_bytes().to_vec()],
            network: NEO_N3_MAINNET_MAGIC,
        };
        let err = service
            .sign_extensible_payload(tonic::Request::new(req))
            .await
            .expect_err("non-dBFT payload must be refused");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    /// Regression (SSS-1): a block request on an attacker-chosen network must not
    /// produce a block signature.
    #[tokio::test]
    async fn sign_block_refuses_attacker_network() {
        let t = test_signer();
        let service = DefaultSignService::new(t.signer, NEO_N3_MAINNET_MAGIC);

        let req = SignBlockRequest {
            block: Some(empty_block()),
            public_key: t.public_key.clone(),
            network: u32::from_be_bytes(*b"ATTC"), // attacker-chosen, not the pinned network
        };
        let err = service
            .sign_block(tonic::Request::new(req))
            .await
            .expect_err("foreign network must be refused");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    /// Positive control: a well-formed dBFT Commit is still signed on the pinned network.
    #[tokio::test]
    async fn sign_extensible_payload_signs_valid_dbft_commit() {
        let t = test_signer();
        let service = DefaultSignService::new(t.signer, NEO_N3_MAINNET_MAGIC);

        let req = SignExtensiblePayloadRequest {
            payload: Some(commit_payload(t.script_hash)),
            script_hashes: vec![t.script_hash.as_le_bytes().to_vec()],
            network: NEO_N3_MAINNET_MAGIC,
        };
        let res = service
            .sign_extensible_payload(tonic::Request::new(req))
            .await
            .expect("valid dBFT commit must be signed")
            .into_inner();
        assert_eq!(res.signs.len(), 1);
        assert_eq!(res.signs[0].signs.len(), 1);
        assert_eq!(res.signs[0].signs[0].signature.len(), 64);
    }

    /// Positive control: a well-formed block is still signed on the pinned network.
    #[tokio::test]
    async fn sign_block_signs_on_pinned_network() {
        let t = test_signer();
        let service = DefaultSignService::new(t.signer, NEO_N3_MAINNET_MAGIC);

        let req = SignBlockRequest {
            block: Some(empty_block()),
            public_key: t.public_key.clone(),
            network: NEO_N3_MAINNET_MAGIC,
        };
        let res = service
            .sign_block(tonic::Request::new(req))
            .await
            .expect("block on the pinned network must be signed")
            .into_inner();
        assert_eq!(res.signature.len(), 64);
    }

    /// Economic signing must stay off until explicitly enabled.
    #[tokio::test]
    async fn sign_transaction_refused_while_gas_sweep_disabled() {
        let t = test_signer();
        let service = DefaultSignService::new(t.signer, NEO_N3_MAINNET_MAGIC);

        let req = SignTransactionRequest {
            raw_tx: vec![0u8; 32],
            public_key: t.public_key,
            network: NEO_N3_MAINNET_MAGIC,
            idempotency_key: "test-key".to_string(),
            client_dry_run_id: String::new(),
            expected_amount: 0,
            expected_fee_total: 0,
        };
        let err = service
            .sign_transaction(tonic::Request::new(req))
            .await
            .expect_err("economic signing must stay off by default");
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }
}
