// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use crate::enclave::SgxEnclave;
use crate::sign::SgxSigner;
use crate::startup::SgxStartup;

use secure_sign_core::limits::{
    validate_extensible_request, validate_public_key, validate_trimmed_block,
};
use secure_sign_core::neo::consensus::{ConsensusPolicyError, ConsensusSigningPolicy};
use secure_sign_rpc::servicepb::secure_sign_server::*;
use secure_sign_rpc::servicepb::*;
use secure_sign_rpc::startpb::startup_service_server::*;
use secure_sign_rpc::startpb::*;
use secure_sign_rpc::{to_h160_vec, IntoRpcStatus};
use tonic::async_trait;

/// SGX-backed signing service.
///
/// Host-side request gating mirrors [`secure_sign_rpc::DefaultSignService`]:
/// a non-optional [`ConsensusSigningPolicy`] validates network + dBFT category +
/// pinned sender on every consensus-bearing request before any enclave ecall.
pub struct SgxSignService {
    /// Keeps the enclave loaded for the service lifetime. `None` only in
    /// host-side gate tests, which must reject every request before an ecall.
    _enclave: Option<SgxEnclave>,
    signer: SgxSigner,
    startup: SgxStartup,
    consensus_policy: ConsensusSigningPolicy,
}

impl SgxSignService {
    /// `network` is the only Neo network magic this consensus signer may sign.
    pub fn new(enclave: SgxEnclave, network: u32) -> Self {
        let eid = enclave.eid;
        Self {
            _enclave: Some(enclave),
            signer: SgxSigner::new(eid),
            startup: SgxStartup::new(eid),
            consensus_policy: ConsensusSigningPolicy::new(network),
        }
    }

    #[cfg(test)]
    fn new_for_host_gate_tests(network: u32) -> Self {
        Self {
            _enclave: None,
            signer: SgxSigner::new(0),
            startup: SgxStartup::new(0),
            consensus_policy: ConsensusSigningPolicy::new(network),
        }
    }

    fn policy_status(err: ConsensusPolicyError) -> tonic::Status {
        tonic::Status::permission_denied(err.to_string())
    }
}

#[async_trait]
impl SecureSign for SgxSignService {
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
            .sign_extensible_payload(payload, &script_hashes, req.network)
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
            .map(|signature| SignBlockResponse { signature })
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
            .map_err(|err| err.into_rpc_status())
            .map(tonic::Response::new)
    }

    /// Deliberately unimplemented on the SGX service.
    ///
    /// The enclave exposes no transaction-signing ecall (only block and
    /// extensible-payload signing), so `GasSweepSigningPolicy` cannot be
    /// re-validated and enforced end-to-end here. Rather than half-validate and
    /// sign host-side, or silently pass the request through, the entire RPC is
    /// refused. Economic (GAS sweep) signing must go through
    /// `DefaultSignService`, which re-runs `GasSweepSigningPolicy` before any
    /// key use.
    async fn sign_transaction(
        &self,
        _req: tonic::Request<SignTransactionRequest>,
    ) -> Result<tonic::Response<SignTransactionResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "SignTransaction is deliberately unimplemented in secure-sign-sgx: \
             the enclave has no transaction-signing ecall, so GasSweepSigningPolicy \
             cannot be enforced here",
        ))
    }
}

#[async_trait]
impl StartupService for SgxSignService {
    async fn diffie_hellman(
        &self,
        req: tonic::Request<DiffieHellmanRequest>,
    ) -> Result<tonic::Response<DiffieHellmanResponse>, tonic::Status> {
        let req = req.into_inner();
        self.startup
            .diffie_hellman(&req.blob_ephemeral_public_key)
            .map(|alice_ephemeral_public_key| DiffieHellmanResponse {
                alice_ephemeral_public_key,
            })
            .map_err(|err| err.into_rpc_status())
            .map(tonic::Response::new)
    }

    async fn start_signer(
        &self,
        req: tonic::Request<StartSignerRequest>,
    ) -> Result<tonic::Response<StartSignerResponse>, tonic::Status> {
        let req = req.into_inner();
        self.startup
            .start_signer(&req.encrypted_wallet_passphrase, &req.nonce)
            .map(|_| StartSignerResponse {})
            .map_err(|err| err.into_rpc_status())
            .map(tonic::Response::new)
    }

    /// Deliberately unimplemented on the SGX service.
    ///
    /// The SGX startup flow is enclave-side Diffie-Hellman (`diffie_hellman`) +
    /// `start_signer`; there is no KMS recipient-attestation enclave path. The
    /// request is refused explicitly instead of being ignored or half-handled.
    async fn get_kms_recipient_attestation(
        &self,
        _req: tonic::Request<GetKmsRecipientAttestationRequest>,
    ) -> Result<tonic::Response<GetKmsRecipientAttestationResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "get_kms_recipient_attestation is deliberately unimplemented in secure-sign-sgx: \
             use DiffieHellman + StartSigner, the SGX startup flow",
        ))
    }

    /// Deliberately unimplemented on the SGX service (see
    /// [`Self::get_kms_recipient_attestation`]).
    async fn start_signer_with_recipient_ciphertext(
        &self,
        _req: tonic::Request<StartSignerWithRecipientCiphertextRequest>,
    ) -> Result<tonic::Response<StartSignerWithRecipientCiphertextResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "start_signer_with_recipient_ciphertext is deliberately unimplemented in \
             secure-sign-sgx: use DiffieHellman + StartSigner, the SGX startup flow",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure_sign_core::h160::H160;
    use secure_sign_core::neo::consensus::{DBFT_CATEGORY, NEO_N3_MAINNET_MAGIC};
    use secure_sign_core::neo::gas_sweep_policy::script_hash_from_public_key;
    use secure_sign_core::neo::signpb::{ExtensiblePayload, Header, TrimmedBlock};
    use secure_sign_core::random::EnvCryptRandom;
    use secure_sign_core::secp256r1::Keypair;

    fn commit_payload(sender: H160) -> ExtensiblePayload {
        let mut data = vec![0x30u8]; // dBFT Commit
        data.extend_from_slice(&42u32.to_le_bytes());
        data.push(1);
        data.push(0);
        data.extend_from_slice(&[0u8; 64]);
        ExtensiblePayload {
            category: DBFT_CATEGORY.to_string(),
            valid_block_start: 0,
            valid_block_end: 42,
            sender: sender.as_le_bytes().to_vec(),
            data,
        }
    }

    fn empty_block() -> TrimmedBlock {
        use secure_sign_core::h256::H256;
        use secure_sign_core::merkle::MerkleSha256;
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

    fn test_identity() -> (Vec<u8>, H160) {
        let keypair = Keypair::gen_random(&mut EnvCryptRandom).expect("keypair generation");
        let public_key = keypair.public_key().to_compressed().to_vec();
        let script_hash = script_hash_from_public_key(&public_key).expect("script hash");
        (public_key, script_hash)
    }

    /// Regression (SSS-2): SgxSignService must apply the same consensus policy as
    /// `DefaultSignService::new_consensus` — an attacker-chosen non-dBFT payload
    /// is refused before any enclave ecall.
    #[tokio::test]
    async fn sign_extensible_payload_refuses_attacker_category() {
        let service = SgxSignService::new_for_host_gate_tests(NEO_N3_MAINNET_MAGIC);
        let (_public_key, script_hash) = test_identity();

        let mut attacker = commit_payload(script_hash);
        attacker.category = "ATTACKER".to_string();

        let req = SignExtensiblePayloadRequest {
            payload: Some(attacker),
            script_hashes: vec![script_hash.as_le_bytes().to_vec()],
            network: NEO_N3_MAINNET_MAGIC,
        };
        let err = service
            .sign_extensible_payload(tonic::Request::new(req))
            .await
            .expect_err("non-dBFT payload must be refused");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    /// Regression (SSS-2): a block on an attacker-chosen network must be refused
    /// before any enclave ecall.
    #[tokio::test]
    async fn sign_block_refuses_attacker_network() {
        let service = SgxSignService::new_for_host_gate_tests(NEO_N3_MAINNET_MAGIC);
        let (public_key, _script_hash) = test_identity();

        let req = SignBlockRequest {
            block: Some(empty_block()),
            public_key,
            network: u32::from_be_bytes(*b"ATTC"),
        };
        let err = service
            .sign_block(tonic::Request::new(req))
            .await
            .expect_err("foreign network must be refused");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    /// SignTransaction must never silently pass on the SGX service.
    #[tokio::test]
    async fn sign_transaction_is_deliberately_unimplemented() {
        let service = SgxSignService::new_for_host_gate_tests(NEO_N3_MAINNET_MAGIC);
        let (public_key, _script_hash) = test_identity();

        let req = SignTransactionRequest {
            raw_tx: vec![0u8; 32],
            public_key,
            network: NEO_N3_MAINNET_MAGIC,
            idempotency_key: "test-key".to_string(),
            client_dry_run_id: String::new(),
            expected_amount: 0,
            expected_fee_total: 0,
        };
        let err = service
            .sign_transaction(tonic::Request::new(req))
            .await
            .expect_err("SignTransaction must be refused on the SGX service");
        assert_eq!(err.code(), tonic::Code::Unimplemented);
        assert!(err.message().contains("GasSweepSigningPolicy"));
    }

    /// The KMS recipient-attestation startup flow is refused explicitly on SGX.
    #[tokio::test]
    async fn kms_recipient_startup_is_deliberately_unimplemented() {
        let service = SgxSignService::new_for_host_gate_tests(NEO_N3_MAINNET_MAGIC);

        let err = service
            .get_kms_recipient_attestation(tonic::Request::new(
                GetKmsRecipientAttestationRequest {},
            ))
            .await
            .expect_err("KMS recipient attestation must be refused on the SGX service");
        assert_eq!(err.code(), tonic::Code::Unimplemented);

        let err = service
            .start_signer_with_recipient_ciphertext(tonic::Request::new(
                StartSignerWithRecipientCiphertextRequest {
                    ciphertext_for_recipient: vec![0x01],
                },
            ))
            .await
            .expect_err("recipient-ciphertext start must be refused on the SGX service");
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }
}
