#![allow(clippy::result_large_err)]

mod bind;
mod budget;
mod identity;
mod journal_worker;
#[cfg(test)]
mod remediation_tests;
mod secret;

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use budget::Budget;
use chrono::{DateTime, FixedOffset, Utc};
use clap::Parser;
use journal_worker::JournalWorker;
use prost::Message;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use secure_sign_core::ct::constant_time_eq;
use secure_sign_core::h160::{H160, H160_SIZE};
use secure_sign_core::limits::{
    validate_extensible_request, validate_public_key, validate_raw_tx, validate_trimmed_block,
    MAX_RPC_MESSAGE_BYTES,
};
#[cfg(test)]
use secure_sign_core::neo::consensus::ConsensusMessageType;
use secure_sign_core::neo::consensus::{ConsensusMessageMetadata, ConsensusSigningPolicy};
use secure_sign_core::neo::gas_sweep_policy::{
    build_deploy_policy, script_hash_from_public_key, GasSweepSigningPolicy,
    GasSweepValidationRequest,
};
use secure_sign_core::neo::sign::Signer;
use secure_sign_core::neo::signpb::{AccountSign, AccountSigns, AccountStatus};
use secure_sign_core::neo::SIGN_DATA_SIZE;
use secure_sign_core::workload::{
    request_digest_hex, WorkloadIdentityError, WorkloadIdentityPolicy, WorkloadRole,
    MAX_REPLAY_ENTRIES, REQUEST_MAC_METHOD_RAW_PAYLOAD,
};
use secure_sign_neo_rpc::DualRpcVerifier;
use secure_sign_rpc::servicepb::secure_sign_client::SecureSignClient;
use secure_sign_rpc::servicepb::secure_sign_server::{SecureSign, SecureSignServer};
use secure_sign_rpc::servicepb::{
    GetAccountStatusRequest, GetAccountStatusResponse, SignBlockRequest, SignBlockResponse,
    SignExtensiblePayloadRequest, SignExtensiblePayloadResponse, SignTransactionRequest,
    SignTransactionResponse,
};
use secure_sign_rpc::vsock::vsock_channel;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};

const JOURNAL_VERSION: &str = "v1";
const JOURNAL_CACHE_BYTES: usize = 16 * 1024 * 1024;
const LEGACY_IMPORT_BATCH_SIZE: usize = 4_096;
const JOURNAL_ENTRIES: TableDefinition<&str, &str> =
    TableDefinition::new("anti_equivocation_entries_v1");
const JOURNAL_META: TableDefinition<&str, &str> = TableDefinition::new("anti_equivocation_meta_v1");
const REPLAY_NONCES: TableDefinition<&str, &str> = TableDefinition::new("replay_nonces_v1");
const REPLAY_DIGESTS: TableDefinition<&str, &str> = TableDefinition::new("replay_digests_v1");
const REPLAY_EXPIRY: TableDefinition<&str, &str> = TableDefinition::new("replay_expiry_v1");
const REPLAY_CLEANUP_BATCH: usize = 128;
const MAX_SIGNING_ADMISSION: usize = 32;
const REPLAY_RESULT_PREFIX: &str = "response-v1:";
const MAX_RECOVERY_BYTES: usize = 4 * 1024 * 1024;
const MAX_REPLAY_RESULT_BYTES: usize = 2 * MAX_RPC_MESSAGE_BYTES + REPLAY_RESULT_PREFIX.len();
const LEGACY_OFFSET_KEY: &str = "legacy_imported_bytes";
const LEGACY_HASH_KEY: &str = "legacy_prefix_sha256";
const MAX_ACCOUNT_STATUS_INFLIGHT: usize = 4;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Consensus-only TCP gateway for a Nitro Enclave signer"
)]
struct Args {
    #[arg(long, default_value = bind::DEFAULT_WIREGUARD_LISTEN)]
    listen: SocketAddr,

    /// Extra CIDRs that may be bound in addition to the WireGuard parent range.
    /// Public, global, or wide CIDRs also require `--allow-wildcard-bind`.
    #[arg(long, env = "GATEWAY_ALLOW_BIND_CIDR", value_delimiter = ',')]
    allow_bind_cidr: Vec<String>,

    /// Permit wildcard, public, or wide binds. Default off; requires an external firewall.
    #[arg(long, default_value_t = false, env = "GATEWAY_ALLOW_WILDCARD_BIND")]
    allow_wildcard_bind: bool,

    /// Secret file or mount with `id:role:hex-token` entries. Never pass tokens on argv.
    #[arg(long, env = "GATEWAY_WORKLOAD_IDENTITIES_FILE")]
    workload_identities_file: Option<PathBuf>,

    /// File descriptor with the identity table (for example a systemd credential).
    #[arg(long, env = "GATEWAY_WORKLOAD_IDENTITIES_FD")]
    workload_identities_fd: Option<i32>,

    /// Legacy raw `SignExtensiblePayload` path. Default OFF; `SignBlock` remains.
    #[arg(long, default_value_t = false, env = "ENABLE_RAW_PAYLOAD_SIGNING")]
    enable_raw_payload_signing: bool,

    #[arg(long, default_value_t = 2345)]
    enclave_cid: u32,

    #[arg(long, default_value_t = 9991)]
    enclave_port: u16,

    #[arg(long, default_value_t = 860_833_102)]
    network: u32,

    #[arg(long)]
    public_key: String,

    #[arg(long, default_value = "/var/lib/neo-signer/anti-equivocation.redb")]
    journal_db: PathBuf,

    /// Append-only v1 journal imported into the disk-backed database.
    #[arg(long, default_value = "/var/lib/neo-signer/anti-equivocation.log")]
    legacy_journal: PathBuf,

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
    #[arg(long, default_value_t = 900, env = "SIGNER_ECONOMIC_TIMEOUT_MS")]
    economic_timeout_ms: u64,

    /// Exactly two independent HTTPS Neo N3 RPC endpoints, comma-separated.
    #[arg(long, env = "GAS_SWEEP_RPC_URLS")]
    gas_sweep_rpc_urls: Option<String>,

    /// Per-request timeout for chain-state verification.
    #[arg(long, default_value_t = 4_000, env = "GAS_SWEEP_RPC_TIMEOUT_MS")]
    gas_sweep_rpc_timeout_ms: u64,

    /// Maximum accepted height difference between the two RPC nodes.
    #[arg(long, default_value_t = 10, env = "GAS_SWEEP_MAX_HEIGHT_SKEW")]
    gas_sweep_max_height_skew: u32,

    /// Maximum valid-until distance from the lower of the two RPC tips.
    #[arg(long, default_value_t = 120, env = "GAS_SWEEP_MAX_VALID_UNTIL_DELTA")]
    gas_sweep_max_valid_until_delta: u32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum JournalMatch {
    Vacant,
    Matching,
    Conflicting,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ReplayReserve {
    Fresh,
    RetryPending,
    Committed(String),
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ReplayRecord {
    Pending {
        expiry: i64,
        peer: String,
    },
    Committed {
        expiry: i64,
        peer: String,
        result: String,
    },
}

impl ReplayRecord {
    fn expiry(&self) -> i64 {
        match self {
            Self::Pending { expiry, .. } | Self::Committed { expiry, .. } => *expiry,
        }
    }

    fn peer(&self) -> &str {
        match self {
            Self::Pending { peer, .. } | Self::Committed { peer, .. } => peer,
        }
    }

    fn encode(&self) -> String {
        match self {
            Self::Pending { expiry, peer } => format!("pending\t{expiry}\t{peer}"),
            Self::Committed {
                expiry,
                peer,
                result,
            } => format!("committed\t{expiry}\t{result}\t{peer}"),
        }
    }
}

#[derive(Clone, Copy)]
struct ReplayClaim<'a> {
    identity: &'a str,
    method: &'a str,
    network: u32,
    nonce: &'a str,
    digest: &'a str,
    not_after: i64,
}

#[derive(Clone)]
struct OwnedReplayClaim {
    identity: String,
    method: &'static str,
    network: u32,
    nonce: String,
    digest: String,
    not_after: i64,
}

impl OwnedReplayClaim {
    fn borrowed(&self) -> ReplayClaim<'_> {
        ReplayClaim {
            identity: &self.identity,
            method: self.method,
            network: self.network,
            nonce: &self.nonce,
            digest: &self.digest,
            not_after: self.not_after,
        }
    }
    fn digest_key(&self) -> String {
        replay_digest_key(&self.identity, self.method, self.network, &self.digest)
    }
}

fn transport_signing_status(error: Status, digest: &str) -> Status {
    if matches!(
        error.code(),
        tonic::Code::DeadlineExceeded | tonic::Code::Unavailable | tonic::Code::Cancelled
    ) {
        recovery_status("signing-outcome-unknown", digest)
    } else {
        error
    }
}

fn recovery_status(outcome: &'static str, digest: &str) -> Status {
    let mut status = Status::unavailable(
        "signing outcome requires recovery; retry the identical request digest",
    );
    status.metadata_mut().insert(
        "x-signing-outcome",
        outcome.parse().expect("static outcome"),
    );
    if let Ok(value) = digest.parse() {
        status.metadata_mut().insert("x-signing-digest", value);
    }
    status
}

fn replay_nonce_key(identity: &str, nonce: &str) -> String {
    format!("{identity}\t{nonce}")
}

fn replay_digest_key(identity: &str, method: &str, network: u32, digest: &str) -> String {
    format!("{identity}\t{method}\t{network}\t{digest}")
}

struct AntiEquivocationJournal {
    database: Database,
    replay_entries: AtomicU64,
    cleanup_rows: AtomicU64,
    #[cfg(test)]
    fail_result_commits: std::sync::atomic::AtomicBool,
}

impl AntiEquivocationJournal {
    fn open(database_path: &Path, legacy_path: &Path) -> Result<Self, String> {
        if database_path == legacy_path {
            return Err("journal database and legacy journal must use different paths".to_owned());
        }
        if let Some(parent) = database_path.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("create journal directory: {err}"))?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|err| format!("set journal directory permissions: {err}"))?;
        }

        let mut builder = Database::builder();
        builder.set_cache_size(JOURNAL_CACHE_BYTES);
        let database = builder
            .create(database_path)
            .map_err(|err| format!("open journal database: {err}"))?;
        fs::set_permissions(database_path, fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("set journal database permissions: {err}"))?;

        let write = database
            .begin_write()
            .map_err(|err| format!("initialize journal database: {err}"))?;
        {
            write
                .open_table(JOURNAL_ENTRIES)
                .map_err(|err| format!("initialize journal entries: {err}"))?;
            write
                .open_table(JOURNAL_META)
                .map_err(|err| format!("initialize journal metadata: {err}"))?;
            write
                .open_table(REPLAY_NONCES)
                .map_err(|err| format!("initialize replay nonces: {err}"))?;
            write
                .open_table(REPLAY_DIGESTS)
                .map_err(|err| format!("initialize replay digests: {err}"))?;
        }
        write
            .commit()
            .map_err(|err| format!("commit journal initialization: {err}"))?;

        let journal = Self {
            database,
            replay_entries: AtomicU64::new(0),
            cleanup_rows: AtomicU64::new(0),
            #[cfg(test)]
            fail_result_commits: std::sync::atomic::AtomicBool::new(false),
        };
        journal.import_legacy(legacy_path)?;
        journal
            .rebuild_expiry_index()
            .map_err(|err| err.to_string())?;
        Ok(journal)
    }

    // Rebuild derived state on startup, before serving requests. The durable
    // nonce/digest rows and anti-equivocation slots remain authoritative.
    fn rebuild_expiry_index(&self) -> Result<(), Status> {
        let write = self
            .database
            .begin_write()
            .map_err(|e| journal_status(e.to_string()))?;
        write
            .delete_table(REPLAY_EXPIRY)
            .map_err(|e| journal_status(e.to_string()))?;
        {
            let nonces = write
                .open_table(REPLAY_NONCES)
                .map_err(|e| journal_status(e.to_string()))?;
            let digests = write
                .open_table(REPLAY_DIGESTS)
                .map_err(|e| journal_status(e.to_string()))?;
            let mut expiry = write
                .open_table(REPLAY_EXPIRY)
                .map_err(|e| journal_status(e.to_string()))?;
            let count = nonces.len().map_err(|e| journal_status(e.to_string()))?;
            if count > MAX_REPLAY_ENTRIES as u64
                || count != digests.len().map_err(|e| journal_status(e.to_string()))?
            {
                return Err(journal_status(
                    "replay journal size or pair count invalid".into(),
                ));
            }
            for row in nonces.iter().map_err(|e| journal_status(e.to_string()))? {
                let (key, value) = row.map_err(|e| journal_status(e.to_string()))?;
                let record = parse_replay_record(value.value())?;
                let peer = digests
                    .get(record.peer())
                    .map_err(|e| journal_status(e.to_string()))?
                    .ok_or_else(|| {
                        journal_status("replay digest missing during index rebuild".into())
                    })?;
                let peer_record = parse_replay_record(peer.value())?;
                if peer_record.peer() != key.value()
                    || peer_record.expiry() != record.expiry()
                    || replay_state_from_record(&peer_record) != replay_state_from_record(&record)
                {
                    return Err(journal_status(
                        "replay pair mismatch during index rebuild".into(),
                    ));
                }
                expiry
                    .insert(
                        replay_expiry_key(record.expiry(), key.value()).as_str(),
                        key.value(),
                    )
                    .map_err(|e| journal_status(e.to_string()))?;
            }
            self.replay_entries.store(count, Ordering::Relaxed);
        }
        write.commit().map_err(|e| journal_status(e.to_string()))?;
        Ok(())
    }

    fn import_legacy(&self, legacy_path: &Path) -> Result<(), String> {
        if !legacy_path.exists() {
            return Ok(());
        }

        let (imported_offset, expected_hash) = self.legacy_checkpoint()?;
        let mut input = File::open(legacy_path)
            .map_err(|err| format!("open legacy journal for migration: {err}"))?;
        let file_len = input
            .metadata()
            .map_err(|err| format!("stat legacy journal: {err}"))?
            .len();
        if file_len < imported_offset {
            return Err(format!(
                "legacy journal shrank below imported offset {imported_offset}"
            ));
        }

        let mut hasher = Sha256::new();
        let mut remaining = imported_offset;
        let mut buffer = [0_u8; 64 * 1024];
        while remaining > 0 {
            let read_len = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| "legacy journal offset exceeds platform limits")?;
            input
                .read_exact(&mut buffer[..read_len])
                .map_err(|err| format!("read imported legacy journal prefix: {err}"))?;
            hasher.update(&buffer[..read_len]);
            remaining -= read_len as u64;
        }

        let actual_hash = hex::encode(hasher.clone().finalize());
        match (imported_offset, expected_hash.as_deref()) {
            (0, None) => {}
            (_, Some(expected)) if expected == actual_hash => {}
            (0, Some(_)) => {
                return Err("legacy journal checkpoint has a hash without an offset".to_owned())
            }
            (_, None) => return Err("legacy journal checkpoint is missing its hash".to_owned()),
            _ => return Err("legacy journal prefix changed after migration".to_owned()),
        }

        input
            .seek(std::io::SeekFrom::Start(imported_offset))
            .map_err(|err| format!("seek legacy journal: {err}"))?;
        let mut reader = BufReader::new(input);
        let mut offset = imported_offset;
        let mut line_number = 0_u64;
        let mut batch = Vec::with_capacity(LEGACY_IMPORT_BATCH_SIZE);

        loop {
            let mut raw = Vec::new();
            let bytes = reader
                .read_until(b'\n', &mut raw)
                .map_err(|err| format!("read legacy journal: {err}"))?;
            if bytes == 0 {
                break;
            }
            line_number += 1;
            if raw.last() != Some(&b'\n') {
                return Err("legacy journal ends with a partial record".to_owned());
            }
            hasher.update(&raw);
            offset = offset
                .checked_add(bytes as u64)
                .ok_or_else(|| "legacy journal offset overflow".to_owned())?;
            raw.pop();
            if raw.last() == Some(&b'\r') {
                raw.pop();
            }
            let line = std::str::from_utf8(&raw)
                .map_err(|err| format!("legacy journal record is not UTF-8: {err}"))?;
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 3 || fields[0] != JOURNAL_VERSION {
                return Err(format!(
                    "invalid legacy journal record after imported offset at line {line_number}"
                ));
            }
            batch.push((fields[1].to_owned(), fields[2].to_owned()));

            if batch.len() == LEGACY_IMPORT_BATCH_SIZE {
                self.commit_legacy_batch(&batch, offset, &hex::encode(hasher.clone().finalize()))?;
                batch.clear();
            }
        }

        if !batch.is_empty() {
            self.commit_legacy_batch(&batch, offset, &hex::encode(hasher.finalize()))?;
        }
        Ok(())
    }

    fn legacy_checkpoint(&self) -> Result<(u64, Option<String>), String> {
        let read = self
            .database
            .begin_read()
            .map_err(|err| format!("read journal checkpoint: {err}"))?;
        let table = read
            .open_table(JOURNAL_META)
            .map_err(|err| format!("open journal metadata: {err}"))?;
        let offset = table
            .get(LEGACY_OFFSET_KEY)
            .map_err(|err| format!("read legacy journal offset: {err}"))?
            .map(|value| value.value().parse::<u64>())
            .transpose()
            .map_err(|err| format!("parse legacy journal offset: {err}"))?
            .unwrap_or(0);
        let hash = table
            .get(LEGACY_HASH_KEY)
            .map_err(|err| format!("read legacy journal hash: {err}"))?
            .map(|value| value.value().to_owned());
        Ok((offset, hash))
    }

    fn commit_legacy_batch(
        &self,
        batch: &[(String, String)],
        offset: u64,
        prefix_hash: &str,
    ) -> Result<(), String> {
        let write = self
            .database
            .begin_write()
            .map_err(|err| format!("begin legacy journal migration: {err}"))?;
        {
            let mut entries = write
                .open_table(JOURNAL_ENTRIES)
                .map_err(|err| format!("open journal entries: {err}"))?;
            for (slot, digest) in batch {
                let previous = entries
                    .get(slot.as_str())
                    .map_err(|err| format!("read migrated journal entry: {err}"))?
                    .map(|value| value.value().to_owned());
                match previous.as_deref() {
                    Some(previous) if previous != digest => {
                        return Err(format!(
                            "conflicting legacy journal records for slot {slot}"
                        ));
                    }
                    Some(_) => {}
                    None => {
                        entries
                            .insert(slot.as_str(), digest.as_str())
                            .map_err(|err| format!("migrate journal entry: {err}"))?;
                    }
                }
            }
        }
        {
            let mut meta = write
                .open_table(JOURNAL_META)
                .map_err(|err| format!("open journal metadata: {err}"))?;
            let offset = offset.to_string();
            meta.insert(LEGACY_OFFSET_KEY, offset.as_str())
                .map_err(|err| format!("store legacy journal offset: {err}"))?;
            meta.insert(LEGACY_HASH_KEY, prefix_hash)
                .map_err(|err| format!("store legacy journal hash: {err}"))?;
        }
        write
            .commit()
            .map_err(|err| format!("commit legacy journal migration: {err}"))
    }

    fn reserve(&self, slot: &str, digest: &str) -> Result<(), String> {
        let write = self
            .database
            .begin_write()
            .map_err(|err| format!("begin journal reservation: {err}"))?;
        {
            let mut entries = write
                .open_table(JOURNAL_ENTRIES)
                .map_err(|err| format!("open journal entries: {err}"))?;
            let previous = entries
                .get(slot)
                .map_err(|err| format!("read journal entry: {err}"))?
                .map(|value| value.value().to_owned());
            match previous.as_deref() {
                Some(previous) if previous == digest => return Ok(()),
                Some(_) => return Err(format!("conflicting signing request for slot {slot}")),
                None => {
                    entries
                        .insert(slot, digest)
                        .map_err(|err| format!("reserve journal entry: {err}"))?;
                }
            }
        }
        write
            .commit()
            .map_err(|err| format!("commit journal reservation: {err}"))
    }

    fn matches(&self, slot: &str, digest: &str) -> Result<JournalMatch, String> {
        let read = self
            .database
            .begin_read()
            .map_err(|err| format!("begin journal read: {err}"))?;
        let entries = read
            .open_table(JOURNAL_ENTRIES)
            .map_err(|err| format!("open journal entries: {err}"))?;
        Ok(
            match entries
                .get(slot)
                .map_err(|err| format!("read journal entry: {err}"))?
            {
                None => JournalMatch::Vacant,
                Some(previous) if previous.value() == digest => JournalMatch::Matching,
                Some(_) => JournalMatch::Conflicting,
            },
        )
    }

    fn reserve_replay(&self, claim: ReplayClaim<'_>, now: i64) -> Result<ReplayReserve, Status> {
        self.reserve_replay_limited(claim, now, MAX_REPLAY_ENTRIES)
    }

    fn reserve_replay_limited(
        &self,
        claim: ReplayClaim<'_>,
        now: i64,
        max_entries: usize,
    ) -> Result<ReplayReserve, Status> {
        if claim.not_after <= now {
            return Err(Status::deadline_exceeded(
                "request expired before replay reservation",
            ));
        }
        let nonce_key = replay_nonce_key(claim.identity, claim.nonce);
        let digest_key =
            replay_digest_key(claim.identity, claim.method, claim.network, claim.digest);
        let write = self
            .database
            .begin_write()
            .map_err(|err| journal_status(format!("begin replay reserve: {err}")))?;
        let outcome = {
            let mut nonces = write
                .open_table(REPLAY_NONCES)
                .map_err(|err| journal_status(format!("open replay nonces: {err}")))?;
            let mut digests = write
                .open_table(REPLAY_DIGESTS)
                .map_err(|err| journal_status(format!("open replay digests: {err}")))?;
            let mut expiry = write
                .open_table(REPLAY_EXPIRY)
                .map_err(|err| journal_status(format!("open replay expiry: {err}")))?;
            let cleaned = expire_replay(&mut nonces, &mut digests, &mut expiry, now)?;
            self.cleanup_rows.store(cleaned as u64, Ordering::Relaxed);
            self.replay_entries.store(
                nonces
                    .len()
                    .map_err(|err| journal_status(err.to_string()))?,
                Ordering::Relaxed,
            );

            let existing_nonce = match nonces
                .get(nonce_key.as_str())
                .map_err(|err| journal_status(format!("read replay nonce: {err}")))?
            {
                Some(previous) => Some(parse_replay_record(previous.value())?),
                None => None,
            };
            if let Some(record) = existing_nonce {
                if record.peer() == digest_key {
                    Ok(replay_state_from_record(&record))
                } else {
                    Err(identity::identity_status(WorkloadIdentityError::Replay))
                }
            } else {
                let existing_digest = match digests
                    .get(digest_key.as_str())
                    .map_err(|err| journal_status(format!("read replay digest: {err}")))?
                {
                    Some(previous) => Some(parse_replay_record(previous.value())?),
                    None => None,
                };
                if let Some(record) = existing_digest {
                    if record.peer() == nonce_key {
                        Ok(replay_state_from_record(&record))
                    } else {
                        Err(identity::identity_status(WorkloadIdentityError::Replay))
                    }
                } else {
                    let count = nonces
                        .len()
                        .map_err(|err| journal_status(format!("count replay nonces: {err}")))?;
                    if count >= max_entries as u64 {
                        Err(identity::identity_status(
                            WorkloadIdentityError::ReplayJournalFull,
                        ))
                    } else {
                        let pending = ReplayRecord::Pending {
                            expiry: claim.not_after,
                            peer: digest_key.clone(),
                        }
                        .encode();
                        let digest_pending = ReplayRecord::Pending {
                            expiry: claim.not_after,
                            peer: nonce_key.clone(),
                        }
                        .encode();
                        nonces
                            .insert(nonce_key.as_str(), pending.as_str())
                            .map_err(|err| journal_status(format!("store replay nonce: {err}")))?;
                        digests
                            .insert(digest_key.as_str(), digest_pending.as_str())
                            .map_err(|err| journal_status(format!("store replay digest: {err}")))?;
                        expiry
                            .insert(
                                replay_expiry_key(claim.not_after, &nonce_key).as_str(),
                                nonce_key.as_str(),
                            )
                            .map_err(|err| journal_status(format!("store replay expiry: {err}")))?;
                        self.replay_entries.store(count + 1, Ordering::Relaxed);
                        Ok(ReplayReserve::Fresh)
                    }
                }
            }
        };
        write
            .commit()
            .map_err(|err| journal_status(format!("commit replay reserve: {err}")))?;
        outcome
    }

    fn commit_replay(
        &self,
        claim: ReplayClaim<'_>,
        _now: i64,
        signature_hex: &str,
    ) -> Result<(), Status> {
        #[cfg(test)]
        if self.fail_result_commits.load(Ordering::Relaxed) {
            return Err(journal_status("injected result commit failure".into()));
        }
        let nonce_key = replay_nonce_key(claim.identity, claim.nonce);
        let digest_key =
            replay_digest_key(claim.identity, claim.method, claim.network, claim.digest);
        let write = self
            .database
            .begin_write()
            .map_err(|err| journal_status(format!("begin replay commit: {err}")))?;
        {
            let mut nonces = write
                .open_table(REPLAY_NONCES)
                .map_err(|err| journal_status(format!("open replay nonces: {err}")))?;
            let mut digests = write
                .open_table(REPLAY_DIGESTS)
                .map_err(|err| journal_status(format!("open replay digests: {err}")))?;
            let mut expiry = write
                .open_table(REPLAY_EXPIRY)
                .map_err(|err| journal_status(format!("open replay expiry: {err}")))?;
            let previous_expiry = match nonces
                .get(nonce_key.as_str())
                .map_err(|err| journal_status(format!("read replay nonce: {err}")))?
            {
                Some(previous) => {
                    let record = parse_replay_record(previous.value())?;
                    if record.peer() != digest_key {
                        return Err(identity::identity_status(WorkloadIdentityError::Replay));
                    }
                    if let ReplayRecord::Committed { result, .. } = &record {
                        if result != signature_hex {
                            return Err(journal_status(
                                "committed replay signature does not match".to_owned(),
                            ));
                        }
                    }
                    record.expiry()
                }
                None => {
                    return Err(journal_status(
                        "replay commit has no pending reservation".to_owned(),
                    ));
                }
            };
            expiry
                .remove(replay_expiry_key(previous_expiry, &nonce_key).as_str())
                .map_err(|err| journal_status(format!("remove old replay expiry: {err}")))?;
            expiry
                .insert(
                    replay_expiry_key(claim.not_after, &nonce_key).as_str(),
                    nonce_key.as_str(),
                )
                .map_err(|err| journal_status(format!("store committed replay expiry: {err}")))?;
            let committed_nonce = ReplayRecord::Committed {
                expiry: claim.not_after,
                peer: digest_key.clone(),
                result: signature_hex.to_owned(),
            }
            .encode();
            let committed_digest = ReplayRecord::Committed {
                expiry: claim.not_after,
                peer: nonce_key.clone(),
                result: signature_hex.to_owned(),
            }
            .encode();
            nonces
                .insert(nonce_key.as_str(), committed_nonce.as_str())
                .map_err(|err| journal_status(format!("commit replay nonce: {err}")))?;
            digests
                .insert(digest_key.as_str(), committed_digest.as_str())
                .map_err(|err| journal_status(format!("commit replay digest: {err}")))?;
        }
        write
            .commit()
            .map_err(|err| journal_status(format!("commit replay result: {err}")))?;
        Ok(())
    }
}

fn replay_state_from_record(record: &ReplayRecord) -> ReplayReserve {
    match record {
        ReplayRecord::Committed { result, .. } if !result.is_empty() => {
            ReplayReserve::Committed(result.clone())
        }
        _ => ReplayReserve::RetryPending,
    }
}

fn parse_replay_record(value: &str) -> Result<ReplayRecord, Status> {
    if let Some(rest) = value.strip_prefix("pending\t") {
        let (expiry, peer) = split_replay_expiry_peer(rest)?;
        return Ok(ReplayRecord::Pending { expiry, peer });
    }
    if let Some(rest) = value.strip_prefix("committed\t") {
        let (expiry, rest) = rest.split_once('\t').ok_or_else(|| {
            journal_status("committed replay journal value is missing a field separator".to_owned())
        })?;
        let expiry = expiry
            .parse::<i64>()
            .map_err(|err| journal_status(format!("replay journal expiry is invalid: {err}")))?;
        let (result, peer) = rest.split_once('\t').ok_or_else(|| {
            journal_status("committed replay journal value is missing a signature".to_owned())
        })?;
        if result.is_empty() || peer.is_empty() {
            return Err(journal_status(
                "committed replay journal value is missing a field".to_owned(),
            ));
        }
        return Ok(ReplayRecord::Committed {
            expiry,
            peer: peer.to_owned(),
            result: result.to_owned(),
        });
    }
    let (expiry, peer) = split_replay_expiry_peer(value)?;
    Ok(ReplayRecord::Pending { expiry, peer })
}

fn split_replay_expiry_peer(value: &str) -> Result<(i64, String), Status> {
    let (expiry, peer) = value.split_once('\t').ok_or_else(|| {
        journal_status("replay journal value is missing a field separator".to_owned())
    })?;
    let expiry = expiry
        .parse::<i64>()
        .map_err(|err| journal_status(format!("replay journal expiry is invalid: {err}")))?;
    if peer.is_empty() {
        return Err(journal_status(
            "replay journal value is missing its bound field".to_owned(),
        ));
    }
    Ok((expiry, peer.to_owned()))
}

fn replay_expiry_key(expiry: i64, nonce: &str) -> String {
    // Bias the signed timestamp so lexicographic order also handles legacy
    // negative values. The fixed-width hexadecimal prefix orders by expiry.
    format!("{:016x}\t{nonce}", (expiry as u64) ^ (1u64 << 63))
}

fn expire_replay(
    nonces: &mut redb::Table<'_, &str, &str>,
    digests: &mut redb::Table<'_, &str, &str>,
    expiry: &mut redb::Table<'_, &str, &str>,
    now: i64,
) -> Result<usize, Status> {
    let end = replay_expiry_key(now, "\u{10ffff}");
    let mut stale = Vec::new();
    for row in expiry
        .range(..=end.as_str())
        .map_err(|err| journal_status(err.to_string()))?
        .take(REPLAY_CLEANUP_BATCH)
    {
        let (key, nonce) = row.map_err(|err| journal_status(err.to_string()))?;
        stale.push((key.value().to_owned(), nonce.value().to_owned()));
    }
    for (index_key, nonce_key) in &stale {
        let record = nonces
            .get(nonce_key.as_str())
            .map_err(|err| journal_status(err.to_string()))?
            .map(|value| parse_replay_record(value.value()))
            .transpose()?;
        if let Some(record) = record {
            if record.expiry() <= now {
                nonces
                    .remove(nonce_key.as_str())
                    .map_err(|err| journal_status(err.to_string()))?;
                digests
                    .remove(record.peer())
                    .map_err(|err| journal_status(err.to_string()))?;
            }
        }
        expiry
            .remove(index_key.as_str())
            .map_err(|err| journal_status(err.to_string()))?;
    }
    Ok(stale.len())
}

#[derive(Default)]
struct RecoveryCache {
    records: std::collections::HashMap<String, String>,
    bytes: usize,
}

#[cfg(test)]
impl RecoveryCache {
    fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[derive(Clone)]
struct Gateway {
    client: SecureSignClient<Channel>,
    policy: ConsensusSigningPolicy,
    gas_sweep_policy: GasSweepSigningPolicy,
    gas_sweep_rpc: Option<Arc<DualRpcVerifier>>,
    public_key: Arc<Vec<u8>>,
    identity: Arc<WorkloadIdentityPolicy>,
    raw_payload_enabled: bool,
    journal: JournalWorker,
    signing_admission: Arc<Semaphore>,
    // RAM-only result recovery is bounded and never replaces durable slot reservation.
    recovery: Arc<std::sync::Mutex<RecoveryCache>>,
    single_flight: Arc<Semaphore>,
    /// Serializes economic requests while RPC verification runs.
    economic_flight: Arc<Semaphore>,
    status_flight: Arc<Semaphore>,
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

    fn payload_slot(metadata: ConsensusMessageMetadata) -> String {
        format!(
            "payload/{}/{:02x}/{}/{}/{}",
            metadata.block_index,
            metadata.message_type as u8,
            metadata.validator_index,
            metadata.view_number,
            JOURNAL_VERSION
        )
    }

    async fn reserve(&self, slot: String, digest: &[u8], budget: Budget) -> Result<(), Status> {
        let digest = hex::encode(digest);
        self.journal
            .run("reserve-slot", budget.deadline, move |journal| {
                journal.reserve(&slot, &digest).map_err(journal_status)
            })
            .await
    }

    fn admit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, Status> {
        self.signing_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("signing admission queue full"))
    }

    async fn permit(&self, budget: Budget) -> Result<tokio::sync::OwnedSemaphorePermit, Status> {
        tokio::time::timeout_at(
            budget.deadline.into(),
            self.single_flight.clone().acquire_owned(),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("signing queue deadline exceeded"))?
        .map_err(|_| Status::unavailable("signing gateway is shutting down"))
    }

    async fn replay_reserve(
        &self,
        claim: OwnedReplayClaim,
        budget: Budget,
    ) -> Result<ReplayReserve, Status> {
        self.journal
            .run("reserve-replay", budget.deadline, move |journal| {
                journal.reserve_replay(claim.borrowed(), Utc::now().timestamp())
            })
            .await
    }

    fn recovery_result(&self, key: &str) -> Result<Option<String>, Status> {
        let pending = self
            .recovery
            .lock()
            .map_err(|_| Status::unavailable("result recovery unavailable"))?;
        if let Some(signature) = pending.records.get(key) {
            return Ok(Some(signature.clone()));
        }
        if pending.records.len() >= MAX_REPLAY_ENTRIES
            || pending
                .bytes
                .saturating_add(MAX_REPLAY_RESULT_BYTES + key.len())
                > MAX_RECOVERY_BYTES
        {
            return Err(Status::resource_exhausted(
                "recover pending signing results before new signing",
            ));
        }
        Ok(None)
    }

    fn clear_recovery(&self, key: &str) -> Result<(), Status> {
        let mut pending = self
            .recovery
            .lock()
            .map_err(|_| Status::unavailable("result recovery unavailable"))?;
        if let Some((key, value)) = pending.records.remove_entry(key) {
            pending.bytes -= key.len() + value.len();
        }
        Ok(())
    }

    async fn commit_signed_result(
        &self,
        claim: OwnedReplayClaim,
        signature: String,
        budget: Budget,
    ) -> Result<(), Status> {
        let key = claim.digest_key();
        {
            let mut pending = self
                .recovery
                .lock()
                .map_err(|_| recovery_status("result-commit-pending", &claim.digest))?;
            if !pending.records.contains_key(&key)
                && (pending.records.len() >= MAX_REPLAY_ENTRIES
                    || pending.bytes.saturating_add(key.len() + signature.len())
                        > MAX_RECOVERY_BYTES)
            {
                return Err(recovery_status("result-commit-pending", &claim.digest));
            }
            if pending
                .records
                .get(&key)
                .is_some_and(|previous| previous != &signature)
            {
                return Err(recovery_status("result-conflict", &claim.digest));
            }
            if !pending.records.contains_key(&key) {
                pending.bytes += key.len() + signature.len();
                pending.records.insert(key.clone(), signature.clone());
            }
        }
        // A bounded retry of persistence, never a new enclave signing request.
        for attempt in 1..=2 {
            let owned = claim.clone();
            let result = signature.clone();
            match self
                .journal
                .run("commit-result", budget.deadline, move |journal| {
                    journal.commit_replay(owned.borrowed(), Utc::now().timestamp(), &result)
                })
                .await
            {
                Ok(()) => {
                    self.clear_recovery(&key)?;
                    return Ok(());
                }
                Err(error) => {
                    self.journal
                        .metrics
                        .commit_failures
                        .fetch_add(1, Ordering::Relaxed);
                    eprintln!("signing_result_commit_failed request_digest={} attempt={attempt} code={:?}", claim.digest, error.code());
                    if budget.remaining().is_err() {
                        break;
                    }
                }
            }
        }
        Err(recovery_status("result-commit-pending", &claim.digest))
    }

    fn status_permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, Status> {
        self.status_flight
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("GetAccountStatus concurrency limit reached"))
    }

    fn economic_gate(&self) -> Result<tokio::sync::OwnedSemaphorePermit, &'static str> {
        self.economic_flight
            .clone()
            .try_acquire_owned()
            .map_err(|_| "economic signing already in flight")
    }

    fn economic_signing_permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, &'static str> {
        // The consensus semaphore is held only for the enclave signing call. RPC
        // checks run before this point and therefore cannot delay dBFT traffic.
        self.single_flight
            .clone()
            .try_acquire_owned()
            .map_err(|_| "consensus signing in flight; economic sign refused")
    }

    async fn economic_journal_match(
        &self,
        slot: &str,
        digest: &str,
        budget: Budget,
    ) -> Result<JournalMatch, Status> {
        let slot = slot.to_owned();
        let digest = digest.to_owned();
        self.journal
            .run("match-economic", budget.deadline, move |journal| {
                journal.matches(&slot, &digest).map_err(journal_status)
            })
            .await
    }
}

#[derive(Debug)]
struct PreparedRawPayload {
    identity_id: String,
    nonce: String,
    not_after: i64,
    inner: SignExtensiblePayloadRequest,
    metadata: ConsensusMessageMetadata,
    sign_data: [u8; SIGN_DATA_SIZE],
    digest: String,
}

fn prepare_raw_payload(
    request: Request<SignExtensiblePayloadRequest>,
    identity: &WorkloadIdentityPolicy,
    policy: &ConsensusSigningPolicy,
    enabled: bool,
    now: i64,
) -> Result<PreparedRawPayload, Status> {
    let auth = identity::inspect_raw_payload(&request, identity, enabled, now)?;
    let inner = request.into_inner();
    validate_extensible_request(inner.payload.as_ref(), &inner.script_hashes)
        .map_err(|err| Status::invalid_argument(err.to_string()))?;
    let payload = inner
        .payload
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("missing extensible payload"))?;
    let script_hashes =
        Gateway::signer_hashes(&inner.script_hashes).map_err(Status::invalid_argument)?;
    let metadata = policy
        .validate_extensible_payload(payload, &script_hashes, inner.network)
        .map_err(|err| Status::permission_denied(err.to_string()))?;
    let sign_data = Signer::extensible_sign_data(payload, inner.network)
        .map_err(|err| Status::invalid_argument(err.to_string()))?;
    auth.verify_mac(inner.network, &sign_data)?;
    let digest =
        request_digest_hex(&sign_data).map_err(|err| Status::invalid_argument(err.to_string()))?;
    Ok(PreparedRawPayload {
        identity_id: auth.identity_id,
        nonce: auth.nonce,
        not_after: auth.not_after,
        inner,
        metadata,
        sign_data,
        digest,
    })
}

fn cached_extensible_response(
    signature_hex: &str,
    public_key: &[u8],
) -> Result<SignExtensiblePayloadResponse, Status> {
    if let Some(encoded) = signature_hex.strip_prefix(REPLAY_RESULT_PREFIX) {
        if signature_hex.len() > MAX_REPLAY_RESULT_BYTES {
            return Err(Status::internal("cached replay response too large"));
        }
        let bytes = hex::decode(encoded)
            .map_err(|_| Status::internal("cached replay response encoding invalid"))?;
        let response = SignExtensiblePayloadResponse::decode(bytes.as_slice())
            .map_err(|_| Status::internal("cached replay response protobuf invalid"))?;
        if first_signature_hex(&response).is_none() {
            return Err(Status::internal(
                "cached replay response has no valid single signature",
            ));
        }
        return Ok(response);
    }
    let signature = hex::decode(signature_hex)
        .map_err(|_| Status::internal("cached replay signature is not hex"))?;
    if signature.len() != 64 {
        return Err(Status::internal("cached replay signature length invalid"));
    }
    Ok(SignExtensiblePayloadResponse {
        signs: vec![AccountSigns {
            signs: vec![AccountSign {
                signature,
                public_key: public_key.to_vec(),
            }],
            contract: None,
            status: AccountStatus::Single as i32,
        }],
    })
}

fn encode_replay_result(response: &SignExtensiblePayloadResponse) -> Option<String> {
    if response.encoded_len() > MAX_RPC_MESSAGE_BYTES || first_signature_hex(response).is_none() {
        return None;
    }
    Some(format!(
        "{REPLAY_RESULT_PREFIX}{}",
        hex::encode(response.encode_to_vec())
    ))
}

fn first_signature_hex(response: &SignExtensiblePayloadResponse) -> Option<String> {
    let [account] = response.signs.as_slice() else {
        return None;
    };
    if account.status != AccountStatus::Single as i32 {
        return None;
    }
    let [sign] = account.signs.as_slice() else {
        return None;
    };
    (sign.signature.len() == 64).then(|| hex::encode(&sign.signature))
}

#[tonic::async_trait]
impl SecureSign for Gateway {
    async fn sign_extensible_payload(
        &self,
        request: Request<SignExtensiblePayloadRequest>,
    ) -> Result<Response<SignExtensiblePayloadResponse>, Status> {
        let budget = Budget::new(self.timeout, request.metadata())?;
        let prepared = prepare_raw_payload(
            request,
            &self.identity,
            &self.policy,
            self.raw_payload_enabled,
            Utc::now().timestamp(),
        )?;
        let budget = budget.with_expiry(prepared.not_after)?;
        let _admission = self.admit()?;
        let claim = OwnedReplayClaim {
            identity: prepared.identity_id,
            method: REQUEST_MAC_METHOD_RAW_PAYLOAD,
            network: prepared.inner.network,
            nonce: prepared.nonce,
            digest: prepared.digest,
            not_after: prepared.not_after,
        };
        let key = claim.digest_key();
        if let ReplayReserve::Committed(signature) =
            self.replay_reserve(claim.clone(), budget).await?
        {
            self.clear_recovery(&key)?;
            return Ok(Response::new(cached_extensible_response(
                &signature,
                &self.public_key,
            )?));
        }
        let _permit = self.permit(budget).await?;
        Budget::check_expiry(claim.not_after)?;
        if let ReplayReserve::Committed(signature) =
            self.replay_reserve(claim.clone(), budget).await?
        {
            self.clear_recovery(&key)?;
            return Ok(Response::new(cached_extensible_response(
                &signature,
                &self.public_key,
            )?));
        }
        if let Some(signature) = self.recovery_result(&key)? {
            self.commit_signed_result(claim, signature.clone(), budget)
                .await?;
            return Ok(Response::new(cached_extensible_response(
                &signature,
                &self.public_key,
            )?));
        }
        self.reserve(
            Self::payload_slot(prepared.metadata),
            &prepared.sign_data,
            budget,
        )
        .await?;
        Budget::check_expiry(claim.not_after)?;
        budget.remaining()?;
        let mut client = self.client.clone();
        let mut enclave_request = Request::new(prepared.inner);
        enclave_request.set_timeout(budget.remaining()?);
        let response = tokio::time::timeout_at(
            budget.deadline.into(),
            client.sign_extensible_payload(enclave_request),
        )
        .await
        .map_err(|_| recovery_status("signing-outcome-unknown", &claim.digest))?
        .map_err(|error| {
            if matches!(
                error.code(),
                tonic::Code::DeadlineExceeded | tonic::Code::Unavailable | tonic::Code::Cancelled
            ) {
                recovery_status("signing-outcome-unknown", &claim.digest)
            } else {
                error
            }
        })?;
        let signature = encode_replay_result(response.get_ref())
            .ok_or_else(|| recovery_status("invalid-enclave-result", &claim.digest))?;
        self.commit_signed_result(claim, signature, budget).await?;
        Ok(response)
    }

    async fn sign_block(
        &self,
        request: Request<SignBlockRequest>,
    ) -> Result<Response<SignBlockResponse>, Status> {
        let budget = Budget::new(self.timeout, request.metadata())?;
        identity::authenticate(&request, &self.identity, WorkloadRole::Consensus)?;
        let request = request.into_inner();
        validate_public_key(&request.public_key)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        validate_trimmed_block(request.block.as_ref())
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        self.policy
            .validate_network(request.network)
            .map_err(|err| Status::permission_denied(err.to_string()))?;
        if !constant_time_eq(&request.public_key, &self.public_key) {
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
        let _admission = self.admit()?;
        let _permit = self.permit(budget).await?;
        self.reserve(
            format!("block/{height}/{JOURNAL_VERSION}"),
            &sign_data,
            budget,
        )
        .await?;
        let mut client = self.client.clone();
        let mut enclave_request = Request::new(request);
        enclave_request.set_timeout(budget.remaining()?);
        tokio::time::timeout_at(budget.deadline.into(), client.sign_block(enclave_request))
            .await
            .map_err(|_| {
                recovery_status(
                    "signing-outcome-unknown",
                    &hex::encode(Sha256::digest(sign_data)),
                )
            })?
            .map_err(|error| {
                transport_signing_status(error, &hex::encode(Sha256::digest(sign_data)))
            })
    }

    async fn sign_transaction(
        &self,
        request: Request<SignTransactionRequest>,
    ) -> Result<Response<SignTransactionResponse>, Status> {
        let budget = Budget::new(self.economic_timeout, request.metadata())?;
        identity::authenticate(&request, &self.identity, WorkloadRole::Economic)?;
        let _economic_gate = self.economic_gate().map_err(Status::resource_exhausted)?;
        let request = request.into_inner();
        validate_public_key(&request.public_key)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        validate_raw_tx(&request.raw_tx)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        if !constant_time_eq(&request.public_key, &self.public_key) {
            return Err(Status::permission_denied("public key is not allowed"));
        }

        // Reject malformed or non-allowlisted transactions before making any
        // network request. Balance binding is repeated below after dual-RPC proof.
        let preliminary = self
            .gas_sweep_policy
            .validate_sign_transaction(GasSweepValidationRequest {
                raw_tx: &request.raw_tx,
                public_key: &request.public_key,
                network: request.network,
                idempotency_key: &request.idempotency_key,
                expected_amount: request.expected_amount,
                expected_fee_total: request.expected_fee_total,
                asserted_safe_balance: None,
            })
            .map_err(gas_sweep_status)?;

        let slot = format!("economic/{}/{JOURNAL_VERSION}", request.idempotency_key);
        let digest = hex::encode(preliminary.tx.tx_hash_le());
        match self.economic_journal_match(&slot, &digest, budget).await? {
            JournalMatch::Matching => {
                // A retry of bytes that already passed the live policy is safe.
            }
            JournalMatch::Conflicting => {
                return Err(Status::failed_precondition(
                    "a different transaction is already reserved for this daily sweep",
                ));
            }
            JournalMatch::Vacant => {
                let expected_key = daily_sweep_key_at(Utc::now());
                if request.idempotency_key != expected_key {
                    return Err(Status::invalid_argument(
                        "idempotency key must identify today's Asia/Shanghai sweep",
                    ));
                }
                let verifier = self.gas_sweep_rpc.as_ref().ok_or_else(|| {
                    Status::failed_precondition("dual-RPC verification is not configured")
                })?;
                let verified = tokio::time::timeout_at(
                    budget.deadline.into(),
                    verifier.verify_transaction(&preliminary.tx, &request.public_key),
                )
                .await
                .map_err(|_| {
                    Status::deadline_exceeded(
                        "economic verification deadline exceeded before signing",
                    )
                })?
                .map_err(|err| {
                    Status::failed_precondition(format!("dual-RPC verification failed: {err}"))
                })?;
                self.gas_sweep_policy
                    .validate_sign_transaction(GasSweepValidationRequest {
                        raw_tx: &request.raw_tx,
                        public_key: &request.public_key,
                        network: request.network,
                        idempotency_key: &request.idempotency_key,
                        expected_amount: request.expected_amount,
                        expected_fee_total: request.expected_fee_total,
                        asserted_safe_balance: Some(verified.safe_balance),
                    })
                    .map_err(gas_sweep_status)?;
                self.reserve(slot, &preliminary.tx.tx_hash_le(), budget)
                    .await?;
            }
        }

        let _signing_permit = self
            .economic_signing_permit()
            .map_err(Status::resource_exhausted)?;
        let mut client = self.client.clone();
        let mut enclave_request = Request::new(request);
        enclave_request.set_timeout(budget.remaining()?);
        tokio::time::timeout_at(
            budget.deadline.into(),
            client.sign_transaction(enclave_request),
        )
        .await
        .map_err(|_| recovery_status("signing-outcome-unknown", &digest))?
        .map_err(|error| transport_signing_status(error, &digest))
    }

    async fn get_account_status(
        &self,
        request: Request<GetAccountStatusRequest>,
    ) -> Result<Response<GetAccountStatusResponse>, Status> {
        let budget = Budget::new(self.timeout, request.metadata())?;
        identity::authenticate_any(&request, &self.identity)?;
        let request = request.into_inner();
        validate_public_key(&request.public_key)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        if !constant_time_eq(&request.public_key, &self.public_key) {
            return Err(Status::permission_denied("public key is not allowed"));
        }
        let _permit = self.status_permit()?;
        let mut client = self.client.clone();
        let mut enclave_request = Request::new(request);
        enclave_request.set_timeout(budget.remaining()?);
        let mut response = tokio::time::timeout_at(
            budget.deadline.into(),
            client.get_account_status(enclave_request),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("enclave status deadline exceeded"))??;
        let metrics = &self.journal.metrics;
        for (key, value) in [
            (
                "x-journal-completed",
                metrics.completed.load(Ordering::Relaxed),
            ),
            (
                "x-journal-rejected",
                metrics.rejected.load(Ordering::Relaxed),
            ),
            (
                "x-journal-queue-wait-us",
                metrics.queue_wait_us.load(Ordering::Relaxed),
            ),
            (
                "x-journal-operation-us",
                metrics.operation_us.load(Ordering::Relaxed),
            ),
            (
                "x-journal-commit-failures",
                metrics.commit_failures.load(Ordering::Relaxed),
            ),
            ("x-journal-stopped", u64::from(self.journal.is_stopped())),
        ] {
            response
                .metadata_mut()
                .insert(key, value.to_string().parse().expect("integer metric"));
        }
        Ok(response)
    }
}

fn gas_sweep_status(err: secure_sign_core::neo::gas_sweep_policy::GasSweepPolicyError) -> Status {
    use secure_sign_core::neo::gas_sweep_policy::GasSweepPolicyError;
    match err {
        GasSweepPolicyError::Disabled => Status::unimplemented("SignTransaction is disabled"),
        GasSweepPolicyError::MissingIdempotencyKey
        | GasSweepPolicyError::InvalidIdempotencyKey
        | GasSweepPolicyError::ExpectedAmountMismatch
        | GasSweepPolicyError::ExpectedFeeMismatch
        | GasSweepPolicyError::InvalidPublicKey
        | GasSweepPolicyError::Tx(_)
        | GasSweepPolicyError::Script(_) => Status::invalid_argument(err.to_string()),
        _ => Status::permission_denied(err.to_string()),
    }
}

fn journal_status(err: String) -> Status {
    if err.starts_with("conflicting signing request") {
        Status::failed_precondition(err)
    } else {
        Status::unavailable(format!("anti-equivocation journal unavailable: {err}"))
    }
}

fn daily_sweep_key_at(now: DateTime<Utc>) -> String {
    let shanghai = FixedOffset::east_opt(8 * 60 * 60).expect("valid fixed UTC offset");
    format!(
        "gas-sweep/{}",
        now.with_timezone(&shanghai).format("%Y-%m-%d")
    )
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
    let extra_cidrs = bind::parse_bind_cidrs(&args.allow_bind_cidr)?;
    if bind::validate_listen_address(args.listen, &extra_cidrs, args.allow_wildcard_bind)? {
        eprintln!("{}", bind::WILDCARD_BIND_WARNING);
    }
    let identity = WorkloadIdentityPolicy::parse_table(&secret::load_secret(
        args.workload_identities_fd,
        args.workload_identities_file.as_deref(),
        std::env::var("GATEWAY_WORKLOAD_IDENTITIES").ok(),
        "GATEWAY_WORKLOAD_IDENTITIES",
    )?)?;
    if args.economic_timeout_ms == 0 || args.economic_timeout_ms > args.timeout_ms {
        return Err(
            "economic timeout must be non-zero and no greater than consensus timeout".into(),
        );
    }
    if args.gas_sweep_rpc_timeout_ms == 0 || args.gas_sweep_rpc_timeout_ms > 10_000 {
        return Err("GAS sweep RPC timeout must be between 1 and 10000 ms".into());
    }
    if args.gas_sweep_max_valid_until_delta <= args.gas_sweep_max_height_skew {
        return Err("GAS sweep valid-until delta must exceed maximum RPC height skew".into());
    }
    let public_key = decode_public_key(&args.public_key)?;
    let pinned_script_hash = script_hash_from_public_key(&public_key)
        .map_err(|err| format!("public key is not a valid consensus pin: {err}"))?;
    let gas_sweep_policy = build_deploy_policy(
        args.network,
        args.enable_sign_transaction,
        public_key.clone(),
        args.gas_sweep_destination.as_deref(),
        args.gas_sweep_destination_script_hash.as_deref(),
    )
    .map_err(|err| format!("gas sweep deploy config: {err}"))?;
    let gas_sweep_rpc = match (
        args.enable_sign_transaction,
        args.gas_sweep_rpc_urls.as_deref(),
    ) {
        (false, _) => None,
        (true, Some(urls)) => Some(Arc::new(DualRpcVerifier::from_csv(
            urls,
            Duration::from_millis(args.gas_sweep_rpc_timeout_ms),
            args.gas_sweep_max_height_skew,
            args.gas_sweep_max_valid_until_delta,
        )?)),
        (true, None) => {
            return Err("GAS_SWEEP_RPC_URLS is required when SignTransaction is enabled".into())
        }
    };
    let journal = AntiEquivocationJournal::open(&args.journal_db, &args.legacy_journal)?;
    let channel = vsock_channel(args.enclave_cid, args.enclave_port).await?;

    let gateway = Gateway {
        client: SecureSignClient::new(channel),
        policy: ConsensusSigningPolicy::new(args.network)
            .with_pinned_script_hash(pinned_script_hash),
        gas_sweep_policy,
        gas_sweep_rpc,
        public_key: Arc::new(public_key),
        identity: Arc::new(identity),
        raw_payload_enabled: args.enable_raw_payload_signing,
        journal: JournalWorker::start(journal)?,
        signing_admission: Arc::new(Semaphore::new(MAX_SIGNING_ADMISSION)),
        recovery: Arc::new(std::sync::Mutex::new(RecoveryCache::default())),
        single_flight: Arc::new(Semaphore::new(1)),
        economic_flight: Arc::new(Semaphore::new(1)),
        status_flight: Arc::new(Semaphore::new(MAX_ACCOUNT_STATUS_INFLIGHT)),
        timeout: Duration::from_millis(args.timeout_ms),
        economic_timeout: Duration::from_millis(args.economic_timeout_ms),
    };

    Server::builder()
        .add_service(
            SecureSignServer::new(gateway)
                .max_decoding_message_size(MAX_RPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_RPC_MESSAGE_BYTES),
        )
        .serve(args.listen)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn replay_claim<'a>(
        identity: &'a str,
        network: u32,
        nonce: &'a str,
        digest: &'a str,
        not_after: i64,
    ) -> ReplayClaim<'a> {
        ReplayClaim {
            identity,
            method: REQUEST_MAC_METHOD_RAW_PAYLOAD,
            network,
            nonce,
            digest,
            not_after,
        }
    }

    #[test]
    fn journal_rejects_conflicts_and_survives_restart() {
        let dir = tempdir().unwrap();
        let database_path = dir.path().join("journal.redb");
        let legacy_path = dir.path().join("journal.log");
        let journal = AntiEquivocationJournal::open(&database_path, &legacy_path).unwrap();

        assert_eq!(
            journal.matches("payload/1/20/0/0/v1", "aaaa").unwrap(),
            JournalMatch::Vacant
        );

        journal.reserve("payload/1/20/0/0/v1", "aaaa").unwrap();
        assert_eq!(
            journal.matches("payload/1/20/0/0/v1", "aaaa").unwrap(),
            JournalMatch::Matching
        );
        assert_eq!(
            journal.matches("payload/1/20/0/0/v1", "bbbb").unwrap(),
            JournalMatch::Conflicting
        );
        journal.reserve("payload/1/20/0/0/v1", "aaaa").unwrap();
        assert!(journal
            .reserve("payload/1/20/0/0/v1", "bbbb")
            .unwrap_err()
            .contains("conflicting signing request"));
        drop(journal);

        let reloaded = AntiEquivocationJournal::open(&database_path, &legacy_path).unwrap();
        assert!(reloaded.reserve("payload/1/20/0/0/v1", "bbbb").is_err());
        reloaded.reserve("payload/2/20/0/0/v1", "bbbb").unwrap();
    }

    #[test]
    fn journal_imports_legacy_records_incrementally() {
        let dir = tempdir().unwrap();
        let database_path = dir.path().join("journal.redb");
        let legacy_path = dir.path().join("journal.log");
        fs::write(
            &legacy_path,
            "v1\tpayload/1/20/0/0/v1\taaaa\nv1\tpayload/2/20/0/0/v1\tbbbb\n",
        )
        .unwrap();
        let journal = AntiEquivocationJournal::open(&database_path, &legacy_path).unwrap();
        assert_eq!(
            journal.matches("payload/1/20/0/0/v1", "aaaa").unwrap(),
            JournalMatch::Matching
        );
        drop(journal);

        use std::io::Write;
        let mut legacy = fs::OpenOptions::new()
            .append(true)
            .open(&legacy_path)
            .unwrap();
        writeln!(legacy, "v1\tpayload/3/20/0/0/v1\tcccc").unwrap();
        legacy.sync_data().unwrap();

        let reloaded = AntiEquivocationJournal::open(&database_path, &legacy_path).unwrap();
        assert_eq!(
            reloaded.matches("payload/3/20/0/0/v1", "cccc").unwrap(),
            JournalMatch::Matching
        );
    }

    #[test]
    fn journal_rejects_changed_or_partial_legacy_history() {
        let dir = tempdir().unwrap();
        let database_path = dir.path().join("journal.redb");
        let legacy_path = dir.path().join("journal.log");
        fs::write(&legacy_path, "v1\tpayload/1/20/0/0/v1\taaaa\n").unwrap();
        drop(AntiEquivocationJournal::open(&database_path, &legacy_path).unwrap());

        fs::write(&legacy_path, "v1\tpayload/1/20/0/0/v1\tbbbb\n").unwrap();
        let changed = AntiEquivocationJournal::open(&database_path, &legacy_path);
        assert!(matches!(changed, Err(ref err) if err.contains("prefix changed")));

        let second_database = dir.path().join("partial.redb");
        fs::write(&legacy_path, "v1\tpayload/2/20/0/0/v1\tcccc").unwrap();
        let partial = AntiEquivocationJournal::open(&second_database, &legacy_path);
        assert!(matches!(partial, Err(ref err) if err.contains("partial record")));
    }

    #[test]
    fn all_consensus_message_types_receive_journal_slots() {
        let metadata = |message_type| ConsensusMessageMetadata {
            message_type,
            block_index: 42,
            validator_index: 3,
            view_number: 2,
        };

        for message_type in [
            ConsensusMessageType::PrepareRequest,
            ConsensusMessageType::PrepareResponse,
            ConsensusMessageType::Commit,
            ConsensusMessageType::ChangeView,
            ConsensusMessageType::RecoveryRequest,
            ConsensusMessageType::RecoveryMessage,
        ] {
            let slot = Gateway::payload_slot(metadata(message_type));
            assert!(slot.starts_with("payload/42/"));
            assert!(slot.ends_with("/3/2/v1"));
        }
        assert_ne!(
            Gateway::payload_slot(metadata(ConsensusMessageType::ChangeView)),
            Gateway::payload_slot(metadata(ConsensusMessageType::RecoveryMessage))
        );
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
    fn listen_address_defaults_to_wireguard_and_rejects_wrong_binds() {
        assert!(bind::validate_listen_address(
            bind::DEFAULT_WIREGUARD_LISTEN.parse().unwrap(),
            &[],
            false
        )
        .is_ok());
        assert!(
            bind::validate_listen_address("0.0.0.0:9991".parse().unwrap(), &[], false).is_err()
        );
        let extra = bind::parse_bind_cidrs(&["10.0.0.0/16".to_owned()]).unwrap();
        assert!(
            bind::validate_listen_address("10.0.2.3:9991".parse().unwrap(), &extra, false).is_ok()
        );
        let wide = bind::parse_bind_cidrs(&["10.0.0.0/8".to_owned()]).unwrap();
        assert!(
            bind::validate_listen_address("10.1.2.3:9991".parse().unwrap(), &wide, false).is_err()
        );
    }

    #[test]
    fn enable_requires_destination_allowlist() {
        let pk = decode_public_key(&"02".repeat(33)).unwrap();
        let err = build_deploy_policy(860_833_102, true, pk, None, None).unwrap_err();
        assert!(err.to_string().contains("destination allowlist required"));
    }

    #[test]
    fn raw_payload_integration_pins_signer_and_journals_change_view() {
        use secure_sign_core::h160::{H160, H160_SIZE};
        use secure_sign_core::neo::consensus::NEO_N3_MAINNET_MAGIC;
        use secure_sign_core::neo::signpb::ExtensiblePayload;

        let pinned = H160::from_le_bytes([0x11; H160_SIZE]);
        let other = H160::from_le_bytes([0x22; H160_SIZE]);
        let policy =
            ConsensusSigningPolicy::new(NEO_N3_MAINNET_MAGIC).with_pinned_script_hash(pinned);

        let mut data = vec![ConsensusMessageType::ChangeView as u8];
        data.extend_from_slice(&9u32.to_le_bytes());
        data.extend_from_slice(&[1, 2]);
        data.extend_from_slice(&[0u8; 9]);
        let payload = ExtensiblePayload {
            category: "dBFT".into(),
            valid_block_start: 0,
            valid_block_end: 9,
            sender: pinned.as_le_bytes().to_vec(),
            data,
        };
        let metadata = policy
            .validate_extensible_payload(&payload, &[pinned], NEO_N3_MAINNET_MAGIC)
            .unwrap();
        assert_eq!(metadata.message_type, ConsensusMessageType::ChangeView);
        assert!(policy
            .validate_extensible_payload(&payload, &[other], NEO_N3_MAINNET_MAGIC)
            .is_err());
        assert!(policy
            .validate_extensible_payload(&payload, &[pinned, other], NEO_N3_MAINNET_MAGIC)
            .is_err());

        let dir = tempdir().unwrap();
        let database_path = dir.path().join("journal.redb");
        let legacy_path = dir.path().join("journal.log");
        let journal = AntiEquivocationJournal::open(&database_path, &legacy_path).unwrap();
        let slot = Gateway::payload_slot(metadata);
        assert!(slot.contains("/00/"));
        journal.reserve(&slot, "aaaa").unwrap();
        assert!(journal
            .reserve(&slot, "bbbb")
            .unwrap_err()
            .contains("conflicting"));
        let nonce_ab = "ab".repeat(16);
        let nonce_cd = "cd".repeat(16);
        let nonce_ef = "ef".repeat(16);
        assert_eq!(
            journal
                .reserve_replay(
                    replay_claim("dBFT-node", NEO_N3_MAINNET_MAGIC, &nonce_ab, "aaaa", 940),
                    900,
                )
                .unwrap(),
            ReplayReserve::Fresh
        );
        assert_eq!(
            journal
                .reserve_replay(
                    replay_claim("dBFT-node", NEO_N3_MAINNET_MAGIC, &nonce_ab, "aaaa", 940),
                    900,
                )
                .unwrap(),
            ReplayReserve::RetryPending
        );
        assert!(journal
            .reserve_replay(
                replay_claim("dBFT-node", NEO_N3_MAINNET_MAGIC, &nonce_cd, "aaaa", 940),
                900,
            )
            .is_err());
        drop(journal);

        let reloaded = AntiEquivocationJournal::open(&database_path, &legacy_path).unwrap();
        assert_eq!(
            reloaded
                .reserve_replay(
                    replay_claim("dBFT-node", NEO_N3_MAINNET_MAGIC, &nonce_ab, "aaaa", 940),
                    900,
                )
                .unwrap(),
            ReplayReserve::RetryPending
        );
        assert!(reloaded
            .reserve_replay(
                replay_claim("dBFT-node", NEO_N3_MAINNET_MAGIC, &nonce_ef, "aaaa", 940),
                900,
            )
            .is_err());
        reloaded
            .reserve(
                &Gateway::payload_slot(ConsensusMessageMetadata {
                    message_type: ConsensusMessageType::RecoveryMessage,
                    block_index: 9,
                    validator_index: 1,
                    view_number: 2,
                }),
                "cccc",
            )
            .unwrap();
    }

    #[test]
    fn replay_journal_rejects_expired_claim_before_reservation() {
        let dir = tempdir().unwrap();
        let journal = AntiEquivocationJournal::open(
            &dir.path().join("journal.redb"),
            &dir.path().join("journal.log"),
        )
        .unwrap();
        let err = journal
            .reserve_replay(replay_claim("node", 1, "nonce", "digest", 900), 900)
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::DeadlineExceeded);
        assert_eq!(
            journal
                .reserve_replay(replay_claim("node", 1, "nonce", "other", 950), 900)
                .unwrap(),
            ReplayReserve::Fresh
        );
    }

    #[tokio::test]
    async fn permit_wait_is_part_of_the_signing_budget() {
        let dir = tempdir().unwrap();
        let journal = AntiEquivocationJournal::open(
            &dir.path().join("journal.redb"),
            &dir.path().join("journal.log"),
        )
        .unwrap();
        let public_key = vec![2; 33];
        let gateway = Gateway {
            client: SecureSignClient::new(
                Channel::from_static("http://127.0.0.1:1").connect_lazy(),
            ),
            policy: ConsensusSigningPolicy::new(860_833_102),
            gas_sweep_policy: build_deploy_policy(
                860_833_102,
                false,
                public_key.clone(),
                None,
                None,
            )
            .unwrap(),
            gas_sweep_rpc: None,
            public_key: Arc::new(public_key),
            identity: Arc::new(identity_policy()),
            raw_payload_enabled: false,
            journal: JournalWorker::start(journal).unwrap(),
            signing_admission: Arc::new(Semaphore::new(MAX_SIGNING_ADMISSION)),
            recovery: Arc::new(std::sync::Mutex::new(RecoveryCache::default())),
            single_flight: Arc::new(Semaphore::new(1)),
            economic_flight: Arc::new(Semaphore::new(1)),
            status_flight: Arc::new(Semaphore::new(4)),
            timeout: Duration::from_millis(20),
            economic_timeout: Duration::from_millis(20),
        };
        let _held = gateway.single_flight.clone().acquire_owned().await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            gateway.permit(Budget::new(gateway.timeout, &Default::default()).unwrap()),
        )
        .await;
        assert_eq!(
            result
                .expect("permit must not wait beyond signing budget")
                .unwrap_err()
                .code(),
            tonic::Code::DeadlineExceeded
        );
    }

    #[test]
    fn replay_journal_expires_and_enforces_capacity() {
        let dir = tempdir().unwrap();
        let journal = AntiEquivocationJournal::open(
            &dir.path().join("journal.redb"),
            &dir.path().join("journal.log"),
        )
        .unwrap();
        let nonce_aa = "aa".repeat(16);
        let nonce_bb = "bb".repeat(16);
        let nonce_cc = "cc".repeat(16);
        assert_eq!(
            journal
                .reserve_replay_limited(replay_claim("dBFT-node", 1, &nonce_aa, "d1", 910), 900, 1,)
                .unwrap(),
            ReplayReserve::Fresh
        );
        assert!(journal
            .reserve_replay_limited(replay_claim("dBFT-node", 1, &nonce_bb, "d2", 910), 900, 1)
            .is_err());
        journal
            .reserve_replay_limited(replay_claim("dBFT-node", 1, &nonce_cc, "d3", 940), 920, 1)
            .unwrap();
    }

    #[test]
    fn replay_keys_bind_identity_and_same_pair_is_idempotent_not_resign() {
        let dir = tempdir().unwrap();
        let journal = AntiEquivocationJournal::open(
            &dir.path().join("journal.redb"),
            &dir.path().join("journal.log"),
        )
        .unwrap();
        let nonce = "ab".repeat(16);
        assert_eq!(
            journal
                .reserve_replay(replay_claim("node-a", 1, &nonce, "d1", 940), 900)
                .unwrap(),
            ReplayReserve::Fresh
        );
        assert_eq!(
            journal
                .reserve_replay(replay_claim("node-b", 1, &nonce, "d1", 940), 900)
                .unwrap(),
            ReplayReserve::Fresh
        );
        assert!(journal
            .reserve_replay(replay_claim("node-a", 2, &nonce, "d1", 940), 900)
            .is_err());
        assert_eq!(
            journal
                .reserve_replay(replay_claim("node-a", 1, &nonce, "d1", 940), 900)
                .unwrap(),
            ReplayReserve::RetryPending
        );
    }

    #[test]
    fn concurrent_consume_allows_one_fresh_and_rest_idempotent() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempdir().unwrap();
        let journal = Arc::new(
            AntiEquivocationJournal::open(
                &dir.path().join("journal.redb"),
                &dir.path().join("journal.log"),
            )
            .unwrap(),
        );
        let nonce = "ab".repeat(16);
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let journal = Arc::clone(&journal);
                let nonce = nonce.clone();
                thread::spawn(move || {
                    journal.reserve_replay(
                        replay_claim("dBFT-node", 860_833_102, &nonce, "deadbeef", 940),
                        900,
                    )
                })
            })
            .collect();
        let mut fresh = 0;
        let mut pending = 0;
        for worker in workers {
            match worker.join().unwrap().unwrap() {
                ReplayReserve::Fresh => fresh += 1,
                ReplayReserve::RetryPending => pending += 1,
                ReplayReserve::Committed(_) => panic!("no commit in this test"),
            }
        }
        assert_eq!(fresh, 1);
        assert_eq!(pending, 7);
    }

    #[test]
    fn daily_key_uses_asia_shanghai_calendar_day() {
        let before_midnight = DateTime::parse_from_rfc3339("2026-09-03T15:59:59Z")
            .unwrap()
            .with_timezone(&Utc);
        let after_midnight = DateTime::parse_from_rfc3339("2026-09-03T16:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(daily_sweep_key_at(before_midnight), "gas-sweep/2026-09-03");
        assert_eq!(daily_sweep_key_at(after_midnight), "gas-sweep/2026-09-04");
    }

    #[test]
    fn replay_pending_commit_survives_restart_and_rejects_other_digest() {
        let dir = tempdir().unwrap();
        let database_path = dir.path().join("journal.redb");
        let legacy_path = dir.path().join("journal.log");
        let journal = AntiEquivocationJournal::open(&database_path, &legacy_path).unwrap();
        let nonce = "ab".repeat(16);
        let claim = replay_claim("dBFT-node", 1, &nonce, "deadbeef", 940);
        assert_eq!(
            journal.reserve_replay(claim, 900).unwrap(),
            ReplayReserve::Fresh
        );
        assert_eq!(
            journal.reserve_replay(claim, 900).unwrap(),
            ReplayReserve::RetryPending
        );
        journal.commit_replay(claim, 900, "cafebabe").unwrap();
        assert_eq!(
            journal.reserve_replay(claim, 900).unwrap(),
            ReplayReserve::Committed("cafebabe".to_owned())
        );
        assert!(journal
            .reserve_replay(replay_claim("dBFT-node", 1, &nonce, "feedface", 940), 900)
            .is_err());
        drop(journal);

        let reloaded = AntiEquivocationJournal::open(&database_path, &legacy_path).unwrap();
        assert_eq!(
            reloaded.reserve_replay(claim, 900).unwrap(),
            ReplayReserve::Committed("cafebabe".to_owned())
        );
        let other_nonce = "cd".repeat(16);
        assert!(reloaded
            .reserve_replay(
                replay_claim("dBFT-node", 1, &other_nonce, "deadbeef", 940),
                900
            )
            .is_err());
    }

    #[test]
    fn pending_timeout_recovers_with_new_nonce_and_does_not_double_sign_live() {
        let dir = tempdir().unwrap();
        let journal = AntiEquivocationJournal::open(
            &dir.path().join("journal.redb"),
            &dir.path().join("journal.log"),
        )
        .unwrap();
        let nonce = "ab".repeat(16);
        assert_eq!(
            journal
                .reserve_replay(replay_claim("dBFT-node", 1, &nonce, "d1", 910), 900)
                .unwrap(),
            ReplayReserve::Fresh
        );
        assert!(journal
            .reserve_replay(replay_claim("dBFT-node", 1, &nonce, "d2", 910), 900)
            .is_err());
        let new_nonce = "cd".repeat(16);
        assert_eq!(
            journal
                .reserve_replay(replay_claim("dBFT-node", 1, &new_nonce, "d2", 940), 920)
                .unwrap(),
            ReplayReserve::Fresh
        );
    }

    #[test]
    fn legacy_numeric_replay_rows_are_pending_not_committed() {
        let dir = tempdir().unwrap();
        let journal = AntiEquivocationJournal::open(
            &dir.path().join("journal.redb"),
            &dir.path().join("journal.log"),
        )
        .unwrap();
        let record = parse_replay_record("940\tid\tmethod\t1\tdigest").unwrap();
        assert!(matches!(record, ReplayRecord::Pending { expiry: 940, .. }));
        journal
            .reserve_replay(
                replay_claim("dBFT-node", 1, &"ab".repeat(16), "d1", 940),
                900,
            )
            .unwrap();
        drop(journal);
        let _ = dir;
    }

    pub(super) fn identity_policy() -> WorkloadIdentityPolicy {
        WorkloadIdentityPolicy::parse_table(&format!("dBFT-node:consensus:{}", "aa".repeat(32)))
            .unwrap()
    }

    pub(super) fn signed_raw_request(
        payload: secure_sign_core::neo::signpb::ExtensiblePayload,
        script_hash: Vec<u8>,
        nonce: &str,
        not_after: i64,
        mac_override: Option<String>,
    ) -> Request<SignExtensiblePayloadRequest> {
        use secure_sign_core::workload::{
            RequestMacV1, REQUEST_MAC_HEADER, REQUEST_NONCE_HEADER, REQUEST_NOT_AFTER_HEADER,
            SIGN_CONTRACT_VERSION, SIGN_CONTRACT_VERSION_HEADER, WORKLOAD_ID_HEADER,
            WORKLOAD_ROLE_HEADER, WORKLOAD_TOKEN_HEADER,
        };

        let inner = SignExtensiblePayloadRequest {
            payload: Some(payload.clone()),
            script_hashes: vec![script_hash],
            network: 860_833_102,
        };
        let sign_data = Signer::extensible_sign_data(&payload, 860_833_102).unwrap();
        let digest = request_digest_hex(&sign_data).unwrap();
        let mac = mac_override.unwrap_or_else(|| {
            hex::encode(
                RequestMacV1 {
                    identity_id: "dBFT-node",
                    role: WorkloadRole::Consensus,
                    method: REQUEST_MAC_METHOD_RAW_PAYLOAD,
                    network: 860_833_102,
                    payload_digest_hex: &digest,
                    nonce,
                    not_after,
                }
                .compute(&[0xaa; 32]),
            )
        });
        let mut request = Request::new(inner);
        let metadata = request.metadata_mut();
        metadata.insert(WORKLOAD_ID_HEADER, "dBFT-node".parse().unwrap());
        metadata.insert(WORKLOAD_ROLE_HEADER, "consensus".parse().unwrap());
        metadata.insert(WORKLOAD_TOKEN_HEADER, "aa".repeat(32).parse().unwrap());
        metadata.insert(REQUEST_NONCE_HEADER, nonce.parse().unwrap());
        metadata.insert(
            REQUEST_NOT_AFTER_HEADER,
            not_after.to_string().parse().unwrap(),
        );
        metadata.insert(REQUEST_MAC_HEADER, mac.parse().unwrap());
        metadata.insert(
            SIGN_CONTRACT_VERSION_HEADER,
            SIGN_CONTRACT_VERSION.parse().unwrap(),
        );
        request
    }

    pub(super) fn valid_change_view_payload(
        sender: secure_sign_core::h160::H160,
    ) -> secure_sign_core::neo::signpb::ExtensiblePayload {
        let mut data = vec![ConsensusMessageType::ChangeView as u8];
        data.extend_from_slice(&9u32.to_le_bytes());
        data.extend_from_slice(&[1, 2]);
        data.extend_from_slice(&[0u8; 9]);
        secure_sign_core::neo::signpb::ExtensiblePayload {
            category: "dBFT".into(),
            valid_block_start: 0,
            valid_block_end: 9,
            sender: sender.as_le_bytes().to_vec(),
            data,
        }
    }

    #[test]
    fn raw_validation_rejects_bad_mac_and_malformed_body_before_permit() {
        use secure_sign_core::h160::{H160, H160_SIZE};
        use secure_sign_core::neo::consensus::NEO_N3_MAINNET_MAGIC;
        use std::time::Instant;
        use tokio::sync::Semaphore;

        let sender = H160::from_le_bytes([0x11; H160_SIZE]);
        let policy =
            ConsensusSigningPolicy::new(NEO_N3_MAINNET_MAGIC).with_pinned_script_hash(sender);
        let identity = identity_policy();
        let payload = valid_change_view_payload(sender);
        let nonce = "ab".repeat(16);

        let bad_mac = signed_raw_request(
            payload.clone(),
            sender.as_le_bytes().to_vec(),
            &nonce,
            940,
            Some("00".repeat(32)),
        );
        let held = Semaphore::new(1);
        let permit = held.try_acquire().unwrap();
        let start = Instant::now();
        assert_eq!(
            prepare_raw_payload(bad_mac, &identity, &policy, true, 900)
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        assert!(start.elapsed().as_millis() < 200);
        assert_eq!(held.available_permits(), 0);
        drop(permit);

        let mut malformed = payload.clone();
        malformed.data.truncate(7);
        let truncated =
            signed_raw_request(malformed, sender.as_le_bytes().to_vec(), &nonce, 940, None);
        assert_eq!(
            prepare_raw_payload(truncated, &identity, &policy, true, 900)
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );

        let ok = signed_raw_request(payload, sender.as_le_bytes().to_vec(), &nonce, 940, None);
        assert!(prepare_raw_payload(ok, &identity, &policy, true, 900).is_ok());
    }

    #[test]
    fn account_status_has_independent_bounded_concurrency() {
        let consensus = Semaphore::new(1);
        let status = Semaphore::new(MAX_ACCOUNT_STATUS_INFLIGHT);
        let _held = consensus.try_acquire().unwrap();
        let mut held_status = Vec::new();
        for _ in 0..MAX_ACCOUNT_STATUS_INFLIGHT {
            held_status.push(status.try_acquire().unwrap());
        }
        assert!(status.try_acquire().is_err());
        assert_eq!(consensus.available_permits(), 0);
        drop(held_status);
        assert!(status.try_acquire().is_ok());
    }
}
