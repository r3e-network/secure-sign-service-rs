use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use secure_sign_core::h160::{H160, H160_SIZE};
use secure_sign_core::neo::consensus::{
    ConsensusMessageMetadata, ConsensusMessageType, ConsensusSigningPolicy,
};
use secure_sign_core::neo::sign::Signer;
use secure_sign_rpc::servicepb::secure_sign_client::SecureSignClient;
use secure_sign_rpc::servicepb::secure_sign_server::{SecureSign, SecureSignServer};
use secure_sign_core::neo::gas_sweep_policy::{build_deploy_policy, GasSweepSigningPolicy};
use secure_sign_rpc::servicepb::{
    GetAccountStatusRequest, GetAccountStatusResponse, SignBlockRequest, SignBlockResponse,
    SignExtensiblePayloadRequest, SignExtensiblePayloadResponse, SignTransactionRequest,
    SignTransactionResponse,
};
use secure_sign_rpc::vsock::vsock_channel;
use tokio::sync::{Mutex, Semaphore};
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};

const JOURNAL_VERSION: &str = "v1";

#[derive(Debug, Parser)]
#[command(about = "Consensus-only TCP gateway for a Nitro Enclave signer")]
struct Args {
    #[arg(long, default_value = "10.78.0.1:9991")]
    listen: SocketAddr,

    #[arg(long, default_value_t = 2345)]
    enclave_cid: u32,

    #[arg(long, default_value_t = 9991)]
    enclave_port: u16,

    #[arg(long, default_value_t = 860_833_102)]
    network: u32,

    #[arg(long)]
    public_key: String,

    #[arg(long, default_value = "/var/lib/neo-signer/anti-equivocation.log")]
    journal: PathBuf,

    #[arg(long, default_value_t = 900)]
    timeout_ms: u64,

    /// Master switch for allowlisted SignTransaction (default OFF).
    #[arg(long, default_value_t = false, env = "ENABLE_SIGN_TRANSACTION")]
    enable_sign_transaction: bool,

    /// Allowlisted GAS sweep destination Neo N3 address (deploy-time only).
    /// Required when `--enable-sign-transaction` is on (or set via env).
    #[arg(long, env = "GAS_SWEEP_DESTINATION_ADDRESS")]
    gas_sweep_destination: Option<String>,

    /// Allowlisted destination script hash LE hex (alternative to address).
    #[arg(long, env = "GAS_SWEEP_DESTINATION_SCRIPT_HASH")]
    gas_sweep_destination_script_hash: Option<String>,

    /// Separate timeout for economic SignTransaction path (ms).
    #[arg(long, default_value_t = 10_000)]
    economic_timeout_ms: u64,
}

struct AntiEquivocationJournal {
    entries: HashMap<String, String>,
    file: File,
}

impl AntiEquivocationJournal {
    fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("create journal directory: {err}"))?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|err| format!("set journal directory permissions: {err}"))?;
        }

        let mut entries = HashMap::new();
        if path.exists() {
            let input = File::open(path).map_err(|err| format!("open journal: {err}"))?;
            for (line_number, line) in BufReader::new(input).lines().enumerate() {
                let line = line.map_err(|err| format!("read journal: {err}"))?;
                let fields: Vec<_> = line.split('\t').collect();
                if fields.len() != 3 || fields[0] != JOURNAL_VERSION {
                    return Err(format!(
                        "invalid journal record at line {}",
                        line_number + 1
                    ));
                }
                match entries.insert(fields[1].to_owned(), fields[2].to_owned()) {
                    Some(previous) if previous != fields[2] => {
                        return Err(format!(
                            "conflicting journal records for slot {}",
                            fields[1]
                        ));
                    }
                    _ => {}
                }
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|err| format!("open journal for append: {err}"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("set journal permissions: {err}"))?;

        Ok(Self { entries, file })
    }

    fn reserve(&mut self, slot: &str, digest: &str) -> Result<(), String> {
        if let Some(previous) = self.entries.get(slot) {
            return if previous == digest {
                Ok(())
            } else {
                Err(format!("conflicting signing request for slot {slot}"))
            };
        }

        writeln!(self.file, "{JOURNAL_VERSION}\t{slot}\t{digest}")
            .map_err(|err| format!("append journal: {err}"))?;
        self.file
            .sync_data()
            .map_err(|err| format!("sync journal: {err}"))?;
        self.entries.insert(slot.to_owned(), digest.to_owned());
        Ok(())
    }
}

#[derive(Clone)]
struct Gateway {
    client: SecureSignClient<Channel>,
    policy: ConsensusSigningPolicy,
    gas_sweep_policy: GasSweepSigningPolicy,
    public_key: Arc<Vec<u8>>,
    journal: Arc<Mutex<AntiEquivocationJournal>>,
    single_flight: Arc<Semaphore>,
    /// Low-priority economic path; never shares consensus single_flight.
    economic_flight: Arc<Semaphore>,
    timeout: Duration,
    economic_timeout: Duration,
}

impl Gateway {
    fn signer_hashes(raw: &[Vec<u8>]) -> Result<Vec<H160>, &'static str> {
        raw.iter()
            .map(|value| {
                let bytes: [u8; H160_SIZE] = value
                    .as_slice()
                    .try_into()
                    .map_err(|_| "invalid signer script hash")?;
                Ok(H160::from_le_bytes(bytes))
            })
            .collect()
    }

    fn payload_slot(metadata: ConsensusMessageMetadata) -> Option<String> {
        match metadata.message_type {
            ConsensusMessageType::PrepareRequest
            | ConsensusMessageType::PrepareResponse
            | ConsensusMessageType::Commit => Some(format!(
                "payload/{}/{:02x}/{}/{}/{}",
                metadata.block_index,
                metadata.message_type as u8,
                metadata.validator_index,
                metadata.view_number,
                JOURNAL_VERSION
            )),
            ConsensusMessageType::ChangeView
            | ConsensusMessageType::RecoveryRequest
            | ConsensusMessageType::RecoveryMessage => None,
        }
    }

    async fn reserve(&self, slot: Option<String>, digest: &[u8]) -> Result<(), Status> {
        let Some(slot) = slot else {
            return Ok(());
        };
        self.journal
            .lock()
            .await
            .reserve(&slot, &hex::encode(digest))
            .map_err(Status::failed_precondition)
    }

    async fn permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, Status> {
        self.single_flight
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Status::unavailable("signing gateway is shutting down"))
    }

    async fn economic_permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, Status> {
        // Do not starve dBFT: refuse economic signing if consensus permit is held.
        if self.single_flight.available_permits() == 0 {
            return Err(Status::resource_exhausted(
                "consensus signing in flight; economic sign refused",
            ));
        }
        self.economic_flight
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("economic signing already in flight"))
    }
}

#[tonic::async_trait]
impl SecureSign for Gateway {
    async fn sign_extensible_payload(
        &self,
        request: Request<SignExtensiblePayloadRequest>,
    ) -> Result<Response<SignExtensiblePayloadResponse>, Status> {
        let _permit = self.permit().await?;
        let request = request.into_inner();
        let payload = request
            .payload
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing extensible payload"))?;
        let script_hashes =
            Self::signer_hashes(&request.script_hashes).map_err(Status::invalid_argument)?;
        let metadata = self
            .policy
            .validate_extensible_payload(payload, &script_hashes, request.network)
            .map_err(|err| Status::permission_denied(err.to_string()))?;
        let sign_data = Signer::extensible_sign_data(payload, request.network)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        self.reserve(Self::payload_slot(metadata), &sign_data)
            .await?;

        let mut client = self.client.clone();
        tokio::time::timeout(self.timeout, client.sign_extensible_payload(request))
            .await
            .map_err(|_| Status::deadline_exceeded("enclave signing deadline exceeded"))?
    }

    async fn sign_block(
        &self,
        request: Request<SignBlockRequest>,
    ) -> Result<Response<SignBlockResponse>, Status> {
        let _permit = self.permit().await?;
        let request = request.into_inner();
        self.policy
            .validate_network(request.network)
            .map_err(|err| Status::permission_denied(err.to_string()))?;
        if request.public_key != *self.public_key {
            return Err(Status::permission_denied("public key is not allowed"));
        }
        let block = request
            .block
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing block"))?;
        let height = block
            .header
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing block header"))?
            .index;
        let sign_data = Signer::trimmed_block_sign_data(block, request.network)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        self.reserve(
            Some(format!("block/{height}/{JOURNAL_VERSION}")),
            &sign_data,
        )
        .await?;

        let mut client = self.client.clone();
        tokio::time::timeout(self.timeout, client.sign_block(request))
            .await
            .map_err(|_| Status::deadline_exceeded("enclave signing deadline exceeded"))?
    }

    async fn sign_transaction(
        &self,
        request: Request<SignTransactionRequest>,
    ) -> Result<Response<SignTransactionResponse>, Status> {
        let _permit = self.economic_permit().await?;
        let request = request.into_inner();
        if request.public_key != *self.public_key {
            return Err(Status::permission_denied("public key is not allowed"));
        }
        // Fail-closed policy including deploy-time destination allowlist.
        self.gas_sweep_policy
            .validate_sign_transaction(
                &request.raw_tx,
                &request.public_key,
                request.network,
                &request.idempotency_key,
                request.expected_amount,
                request.expected_fee_total,
                None,
            )
            .map_err(|err| match err {
                secure_sign_core::neo::gas_sweep_policy::GasSweepPolicyError::Disabled => {
                    Status::unimplemented("SignTransaction is disabled")
                }
                other => Status::permission_denied(other.to_string()),
            })?;

        let mut client = self.client.clone();
        tokio::time::timeout(
            self.economic_timeout,
            client.sign_transaction(request),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("enclave economic signing deadline exceeded"))?
    }

    async fn get_account_status(
        &self,
        request: Request<GetAccountStatusRequest>,
    ) -> Result<Response<GetAccountStatusResponse>, Status> {
        let request = request.into_inner();
        if request.public_key != *self.public_key {
            return Err(Status::permission_denied("public key is not allowed"));
        }
        let mut client = self.client.clone();
        tokio::time::timeout(self.timeout, client.get_account_status(request))
            .await
            .map_err(|_| Status::deadline_exceeded("enclave status deadline exceeded"))?
    }
}

fn decode_public_key(value: &str) -> Result<Vec<u8>, String> {
    let public_key = hex::decode(value).map_err(|err| format!("invalid public key hex: {err}"))?;
    if !matches!(public_key.len(), 33 | 65) {
        return Err("public key must be compressed or uncompressed P-256 SEC1 data".to_owned());
    }
    Ok(public_key)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let public_key = decode_public_key(&args.public_key)?;
    let gas_sweep_policy = build_deploy_policy(
        args.network,
        args.enable_sign_transaction,
        public_key.clone(),
        args.gas_sweep_destination.as_deref(),
        args.gas_sweep_destination_script_hash.as_deref(),
    )
    .map_err(|err| format!("gas sweep deploy config: {err}"))?;
    let journal = AntiEquivocationJournal::open(&args.journal)?;
    let channel = vsock_channel(args.enclave_cid, args.enclave_port).await?;

    let gateway = Gateway {
        client: SecureSignClient::new(channel),
        policy: ConsensusSigningPolicy::new(args.network),
        gas_sweep_policy,
        public_key: Arc::new(public_key),
        journal: Arc::new(Mutex::new(journal)),
        single_flight: Arc::new(Semaphore::new(1)),
        economic_flight: Arc::new(Semaphore::new(1)),
        timeout: Duration::from_millis(args.timeout_ms),
        economic_timeout: Duration::from_millis(args.economic_timeout_ms),
    };

    Server::builder()
        .add_service(SecureSignServer::new(gateway))
        .serve(args.listen)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn journal_rejects_conflicts_and_survives_restart() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.log");
        let mut journal = AntiEquivocationJournal::open(&path).unwrap();

        journal.reserve("payload/1/20/0/0/v1", "aaaa").unwrap();
        journal.reserve("payload/1/20/0/0/v1", "aaaa").unwrap();
        assert!(journal
            .reserve("payload/1/20/0/0/v1", "bbbb")
            .unwrap_err()
            .contains("conflicting signing request"));
        drop(journal);

        let mut reloaded = AntiEquivocationJournal::open(&path).unwrap();
        assert!(reloaded.reserve("payload/1/20/0/0/v1", "bbbb").is_err());
        reloaded.reserve("payload/2/20/0/0/v1", "bbbb").unwrap();
    }

    #[test]
    fn only_safety_critical_payloads_receive_slots() {
        let metadata = |message_type| ConsensusMessageMetadata {
            message_type,
            block_index: 42,
            validator_index: 3,
            view_number: 2,
        };

        assert!(Gateway::payload_slot(metadata(ConsensusMessageType::PrepareRequest)).is_some());
        assert!(Gateway::payload_slot(metadata(ConsensusMessageType::PrepareResponse)).is_some());
        assert!(Gateway::payload_slot(metadata(ConsensusMessageType::Commit)).is_some());
        assert!(Gateway::payload_slot(metadata(ConsensusMessageType::ChangeView)).is_none());
        assert!(Gateway::payload_slot(metadata(ConsensusMessageType::RecoveryRequest)).is_none());
        assert!(Gateway::payload_slot(metadata(ConsensusMessageType::RecoveryMessage)).is_none());
    }

    #[test]
    fn public_key_must_be_sec1_encoded() {
        assert!(decode_public_key(&"02".repeat(33)).is_ok());
        assert!(decode_public_key(&"04".repeat(65)).is_ok());
        assert!(decode_public_key("abcd").is_err());
        assert!(decode_public_key("not-hex").is_err());
    }

    #[test]
    fn sign_transaction_flag_defaults_off() {
        let policy = GasSweepSigningPolicy::mainnet_default_off();
        assert!(!policy.enabled());
        assert!(policy.allowlisted_destination().is_none());
    }

    #[test]
    fn enable_requires_destination_allowlist() {
        let pk = decode_public_key(&"02".repeat(33)).unwrap();
        let err = build_deploy_policy(860_833_102, true, pk, None, None).unwrap_err();
        assert!(err.to_string().contains("destination allowlist required"));
    }
}
