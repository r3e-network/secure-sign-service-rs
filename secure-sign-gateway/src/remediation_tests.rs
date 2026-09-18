//! Local transport/fault tests. The enclave stub returns fixed test bytes; no
//! production key, enclave image or public chain is involved.
use super::*;
use std::time::Instant;
use tempfile::tempdir;
use tests::{identity_policy, signed_raw_request, valid_change_view_payload};

#[derive(Clone)]
struct EnclaveStub {
    calls: Arc<AtomicU64>,
    delay: Duration,
}

#[tonic::async_trait]
impl SecureSign for EnclaveStub {
    async fn sign_extensible_payload(
        &self,
        _: Request<SignExtensiblePayloadRequest>,
    ) -> Result<Response<SignExtensiblePayloadResponse>, Status> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut signed = cached_extensible_response(&"41".repeat(64), &[2; 33])?;
        signed.signs[0].contract = Some(secure_sign_core::neo::signpb::AccountContract {
            script: vec![0x40, 0x10],
            parameters: vec![0],
            deployed: false,
        });
        tokio::time::sleep(self.delay).await;
        Ok(Response::new(signed))
    }
    async fn sign_block(
        &self,
        _: Request<SignBlockRequest>,
    ) -> Result<Response<SignBlockResponse>, Status> {
        Err(Status::unimplemented("test stub"))
    }
    async fn sign_transaction(
        &self,
        _: Request<SignTransactionRequest>,
    ) -> Result<Response<SignTransactionResponse>, Status> {
        Err(Status::unimplemented("test stub"))
    }
    async fn get_account_status(
        &self,
        _: Request<GetAccountStatusRequest>,
    ) -> Result<Response<GetAccountStatusResponse>, Status> {
        Ok(Response::new(GetAccountStatusResponse {
            status: AccountStatus::Single as i32,
        }))
    }
}

async fn backend(
    delay: Duration,
) -> (
    SecureSignClient<Channel>,
    Arc<AtomicU64>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicU64::new(0));
    let stub = EnclaveStub {
        calls: Arc::clone(&calls),
        delay,
    };
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(SecureSignServer::new(stub))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let client = SecureSignClient::connect(format!("http://{addr}"))
        .await
        .unwrap();
    (client, calls, server)
}

fn gateway(journal: AntiEquivocationJournal, client: SecureSignClient<Channel>) -> Gateway {
    let public_key = vec![2; 33];
    Gateway {
        client,
        policy: ConsensusSigningPolicy::new(860_833_102)
            .with_pinned_script_hash(H160::from_le_bytes([0x11; H160_SIZE])),
        gas_sweep_policy: build_deploy_policy(860_833_102, false, public_key.clone(), None, None)
            .unwrap(),
        gas_sweep_rpc: None,
        public_key: Arc::new(public_key),
        identity: Arc::new(identity_policy()),
        raw_payload_enabled: true,
        journal: JournalWorker::start(journal).unwrap(),
        signing_admission: Arc::new(Semaphore::new(MAX_SIGNING_ADMISSION)),
        recovery: Arc::new(std::sync::Mutex::new(RecoveryCache::default())),
        single_flight: Arc::new(Semaphore::new(1)),
        economic_flight: Arc::new(Semaphore::new(1)),
        status_flight: Arc::new(Semaphore::new(4)),
        timeout: Duration::from_secs(2),
        economic_timeout: Duration::from_secs(1),
    }
}

fn raw(nonce_byte: &str, not_after: i64, changed: bool) -> Request<SignExtensiblePayloadRequest> {
    let sender = H160::from_le_bytes([0x11; H160_SIZE]);
    let mut payload = valid_change_view_payload(sender);
    if changed {
        payload.data[7] = 1;
    }
    signed_raw_request(
        payload,
        sender.as_le_bytes().to_vec(),
        &nonce_byte.repeat(16),
        not_after,
        None,
    )
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}

#[tokio::test]
async fn admission_and_recovery_byte_limits_refuse_before_enclave_dispatch() {
    let dir = tempdir().unwrap();
    let (client, calls, server) = backend(Duration::ZERO).await;
    let gateway = gateway(
        AntiEquivocationJournal::open(&dir.path().join("j.redb"), &dir.path().join("j.log"))
            .unwrap(),
        client,
    );
    let held = gateway
        .signing_admission
        .clone()
        .acquire_many_owned(MAX_SIGNING_ADMISSION as u32)
        .await
        .unwrap();
    let expiry = Utc::now().timestamp() + 60;
    assert_eq!(
        gateway
            .sign_extensible_payload(raw("ab", expiry, false))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::ResourceExhausted
    );
    drop(held);
    let mut large = cached_extensible_response(&"41".repeat(64), &[2; 33]).unwrap();
    large.signs[0].contract = Some(secure_sign_core::neo::signpb::AccountContract {
        script: vec![0; MAX_RPC_MESSAGE_BYTES - 512],
        parameters: vec![],
        deployed: false,
    });
    let encoded = encode_replay_result(&large).unwrap();
    {
        let mut cache = gateway.recovery.lock().unwrap();
        for i in 0..8 {
            let key = format!("pending-{i}");
            cache.bytes += key.len() + encoded.len();
            cache.records.insert(key, encoded.clone());
        }
        assert!(cache.bytes <= MAX_RECOVERY_BYTES);
        assert!(cache.records.len() < MAX_REPLAY_ENTRIES);
    }
    assert_eq!(
        gateway
            .sign_extensible_payload(raw("ab", expiry, false))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::ResourceExhausted
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn queued_request_expires_without_calling_the_enclave() {
    let dir = tempdir().unwrap();
    let journal =
        AntiEquivocationJournal::open(&dir.path().join("j.redb"), &dir.path().join("j.log"))
            .unwrap();
    let (client, calls, server) = backend(Duration::ZERO).await;
    let gateway = gateway(journal, client);
    let _held = gateway.single_flight.clone().acquire_owned().await.unwrap();
    let error = tokio::time::timeout(
        Duration::from_secs(2),
        gateway.sign_extensible_payload(raw("ab", Utc::now().timestamp() + 1, false)),
    )
    .await
    .expect("queue must obey TTL")
    .unwrap_err();
    assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn committed_recovery_preserves_the_complete_enclave_response() {
    let dir = tempdir().unwrap();
    let (client, calls, server) = backend(Duration::ZERO).await;
    let gateway = gateway(
        AntiEquivocationJournal::open(&dir.path().join("j.redb"), &dir.path().join("j.log"))
            .unwrap(),
        client,
    );
    let expiry = Utc::now().timestamp() + 60;
    let first = gateway
        .sign_extensible_payload(raw("ab", expiry, false))
        .await
        .unwrap();
    let second = gateway
        .sign_extensible_payload(raw("ab", expiry, false))
        .await
        .unwrap();
    assert_eq!(first.get_ref(), second.get_ref());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn commit_failure_is_explicit_and_recovery_never_resigns_in_process() {
    let dir = tempdir().unwrap();
    let journal =
        AntiEquivocationJournal::open(&dir.path().join("j.redb"), &dir.path().join("j.log"))
            .unwrap();
    let (client, calls, server) = backend(Duration::ZERO).await;
    let gateway = gateway(journal, client);
    gateway
        .journal
        .run("inject-commit-failure", deadline(), |j| {
            j.fail_result_commits.store(true, Ordering::Relaxed);
            Ok(())
        })
        .await
        .unwrap();
    let expiry = Utc::now().timestamp() + 60;
    for _ in 0..2 {
        let error = gateway
            .sign_extensible_payload(raw("ab", expiry, false))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert_eq!(
            error.metadata().get("x-signing-outcome").unwrap(),
            "result-commit-pending"
        );
        assert_eq!(
            error
                .metadata()
                .get("x-signing-digest")
                .unwrap()
                .as_bytes()
                .len(),
            64
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    assert!(
        gateway
            .journal
            .metrics
            .commit_failures
            .load(Ordering::Relaxed)
            >= 2
    );
    assert_eq!(
        gateway
            .sign_extensible_payload(raw("cd", expiry, true))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    gateway
        .journal
        .run("restore-storage", deadline(), |j| {
            j.fail_result_commits.store(false, Ordering::Relaxed);
            Ok(())
        })
        .await
        .unwrap();
    let result = gateway
        .sign_extensible_payload(raw("ab", expiry, false))
        .await
        .unwrap();
    assert_eq!(
        first_signature_hex(result.get_ref()).unwrap(),
        "41".repeat(64)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(gateway.recovery.lock().unwrap().is_empty());
    let cached = gateway
        .sign_extensible_payload(raw("ab", expiry, false))
        .await
        .unwrap();
    assert_eq!(
        first_signature_hex(cached.get_ref()).unwrap(),
        "41".repeat(64)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn pending_result_recovers_identical_digest_after_restart_and_keeps_slot_fence() {
    let dir = tempdir().unwrap();
    let database = dir.path().join("j.redb");
    let legacy = dir.path().join("j.log");
    let (client, calls, server) = backend(Duration::ZERO).await;
    let first = gateway(
        AntiEquivocationJournal::open(&database, &legacy).unwrap(),
        client.clone(),
    );
    first
        .journal
        .run("inject-commit-failure", deadline(), |j| {
            j.fail_result_commits.store(true, Ordering::Relaxed);
            Ok(())
        })
        .await
        .unwrap();
    let expiry = Utc::now().timestamp() + 60;
    assert!(first
        .sign_extensible_payload(raw("ab", expiry, false))
        .await
        .is_err());
    let mut stopped = first.journal.stopped_signal();
    drop(first);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !*stopped.borrow_and_update() {
            stopped.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    let recovered = gateway(
        AntiEquivocationJournal::open(&database, &legacy).unwrap(),
        client,
    );
    assert_eq!(
        recovered
            .sign_extensible_payload(raw("cd", expiry, true))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let signed = recovered
        .sign_extensible_payload(raw("ab", expiry, false))
        .await
        .unwrap();
    assert_eq!(
        first_signature_hex(signed.get_ref()).unwrap(),
        "41".repeat(64)
    );
    // Uncommitted bytes cannot survive power loss; only the identical durable
    // intent may be signed again. No previous attempt returned success.
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    recovered
        .sign_extensible_payload(raw("ab", expiry, false))
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    server.abort();
}

#[tokio::test]
async fn timeout_after_enclave_dispatch_reports_unknown_digest() {
    let dir = tempdir().unwrap();
    let (client, calls, server) = backend(Duration::from_millis(300)).await;
    let mut gateway = gateway(
        AntiEquivocationJournal::open(&dir.path().join("j.redb"), &dir.path().join("j.log"))
            .unwrap(),
        client,
    );
    gateway.timeout = Duration::from_millis(100);
    let error = gateway
        .sign_extensible_payload(raw("ab", Utc::now().timestamp() + 60, false))
        .await
        .unwrap_err();
    assert_eq!(
        error.metadata().get("x-signing-outcome").unwrap(),
        "signing-outcome-unknown"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_storage_does_not_block_account_status() {
    let dir = tempdir().unwrap();
    let (client, _, server) = backend(Duration::ZERO).await;
    let gateway = gateway(
        AntiEquivocationJournal::open(&dir.path().join("j.redb"), &dir.path().join("j.log"))
            .unwrap(),
        client,
    );
    let worker = gateway.journal.clone();
    let runtime_thread = std::thread::current().id();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let slow = tokio::spawn(async move {
        worker
            .run("slow-storage", deadline(), move |_| {
                assert_ne!(runtime_thread, std::thread::current().id());
                let _ = started_tx.send(());
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                Ok(())
            })
            .await
    });
    started_rx.await.unwrap();
    let mut request = Request::new(GetAccountStatusRequest {
        public_key: vec![2; 33],
    });
    request
        .metadata_mut()
        .insert("x-workload-id", "dBFT-node".parse().unwrap());
    request
        .metadata_mut()
        .insert("x-workload-role", "consensus".parse().unwrap());
    request
        .metadata_mut()
        .insert("x-workload-token", "aa".repeat(32).parse().unwrap());
    let status = tokio::time::timeout(
        Duration::from_millis(500),
        gateway.get_account_status(request),
    )
    .await
    .expect("storage must not block status")
    .unwrap();
    assert!(status.metadata().get("x-journal-completed").is_some());
    release_tx.send(()).unwrap();
    slow.await.unwrap().unwrap();
    server.abort();
}

fn seed_replay(journal: &AntiEquivocationJournal, count: usize, expiry: i64) {
    let write = journal.database.begin_write().unwrap();
    {
        let mut nonces = write.open_table(REPLAY_NONCES).unwrap();
        let mut digests = write.open_table(REPLAY_DIGESTS).unwrap();
        let mut index = write.open_table(REPLAY_EXPIRY).unwrap();
        for i in 0..count {
            let nonce = replay_nonce_key("node", &format!("n{i}"));
            let digest =
                replay_digest_key("node", REQUEST_MAC_METHOD_RAW_PAYLOAD, 1, &format!("d{i}"));
            nonces
                .insert(
                    nonce.as_str(),
                    ReplayRecord::Pending {
                        expiry,
                        peer: digest.clone(),
                    }
                    .encode()
                    .as_str(),
                )
                .unwrap();
            digests
                .insert(
                    digest.as_str(),
                    ReplayRecord::Pending {
                        expiry,
                        peer: nonce.clone(),
                    }
                    .encode()
                    .as_str(),
                )
                .unwrap();
            index
                .insert(replay_expiry_key(expiry, &nonce).as_str(), nonce.as_str())
                .unwrap();
        }
    }
    write.commit().unwrap();
}

#[test]
fn indexed_expiry_cleanup_has_a_fixed_batch_and_never_removes_signing_slots() {
    let dir = tempdir().unwrap();
    let journal =
        AntiEquivocationJournal::open(&dir.path().join("j.redb"), &dir.path().join("j.log"))
            .unwrap();
    seed_replay(&journal, 300, 910);
    journal.reserve("block/9/v1", "signed-digest").unwrap();
    let fresh = ReplayClaim {
        identity: "node",
        method: REQUEST_MAC_METHOD_RAW_PAYLOAD,
        network: 1,
        nonce: "fresh",
        digest: "fresh",
        not_after: 950,
    };
    journal.reserve_replay(fresh, 920).unwrap();
    assert_eq!(
        journal.cleanup_rows.load(Ordering::Relaxed),
        REPLAY_CLEANUP_BATCH as u64
    );
    let read = journal.database.begin_read().unwrap();
    assert_eq!(
        read.open_table(REPLAY_NONCES).unwrap().len().unwrap(),
        300 - REPLAY_CLEANUP_BATCH as u64 + 1
    );
    assert_eq!(
        read.open_table(REPLAY_EXPIRY).unwrap().len().unwrap(),
        300 - REPLAY_CLEANUP_BATCH as u64 + 1
    );
    assert!(journal.reserve("block/9/v1", "conflicting-digest").is_err());
}

#[test]
fn expiry_index_is_rebuilt_on_startup_and_pair_corruption_fails_closed() {
    let dir = tempdir().unwrap();
    let database = dir.path().join("j.redb");
    let legacy = dir.path().join("j.log");
    let journal = AntiEquivocationJournal::open(&database, &legacy).unwrap();
    seed_replay(&journal, 10, 950);
    let write = journal.database.begin_write().unwrap();
    write.delete_table(REPLAY_EXPIRY).unwrap();
    write.commit().unwrap();
    drop(journal);
    let reopened = AntiEquivocationJournal::open(&database, &legacy).unwrap();
    {
        let read = reopened.database.begin_read().unwrap();
        assert_eq!(read.open_table(REPLAY_EXPIRY).unwrap().len().unwrap(), 10);
    }
    let write = reopened.database.begin_write().unwrap();
    {
        let mut digests = write.open_table(REPLAY_DIGESTS).unwrap();
        digests
            .remove(replay_digest_key("node", REQUEST_MAC_METHOD_RAW_PAYLOAD, 1, "d0").as_str())
            .unwrap();
    }
    write.commit().unwrap();
    drop(reopened);
    assert!(AntiEquivocationJournal::open(&database, &legacy).is_err());
}

#[test]
fn journal_size_latency_samples() {
    // Local post-change baseline, not a Nitro throughput benchmark. Seed in one
    // transaction so setup cost is excluded. No environment-specific SLO asserts.
    for size in [0, 2048, 4096] {
        let dir = tempdir().unwrap();
        let journal =
            AntiEquivocationJournal::open(&dir.path().join("j.redb"), &dir.path().join("j.log"))
                .unwrap();
        seed_replay(&journal, size, 950);
        let mut reserve_us = Vec::new();
        let mut commit_us = Vec::new();
        let claim = ReplayClaim {
            identity: "node",
            method: REQUEST_MAC_METHOD_RAW_PAYLOAD,
            network: 1,
            nonce: "n0",
            digest: "d0",
            not_after: 950,
        };
        for _ in 0..32 {
            let start = Instant::now();
            journal.reserve_replay(claim, 900).unwrap();
            reserve_us.push(start.elapsed().as_micros());
            let start = Instant::now();
            journal.commit_replay(claim, 900, &"41".repeat(64)).unwrap();
            commit_us.push(start.elapsed().as_micros());
        }
        reserve_us.sort_unstable();
        commit_us.sort_unstable();
        eprintln!("journal_baseline rows={size} samples=32 reserve_us_p50={} p95={} p99={} commit_us_p50={} p95={} p99={}", reserve_us[15], reserve_us[30], reserve_us[31], commit_us[15], commit_us[30], commit_us[31]);
    }
}
