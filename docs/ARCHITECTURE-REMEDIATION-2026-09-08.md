# Signing gateway architecture remediation — 2026-09-08

This change addresses L-06, L-07 and L-08 in the local gateway. It does not
deploy a gateway, build a production enclave, change an enclave measurement,
enable raw/economic signing, or modify private-key operations.

## Deadlines and admission (L-06)

`budget::Budget` captures one monotonic deadline at handler entry. The effective
budget is the shorter of the configured timeout and a valid inbound
`grpc-timeout`. Raw signing additionally caps it by the authenticated
`not_after`. The same deadline covers admission, the consensus permit,
journal requests, enclave RPC and result persistence; no stage receives a
fresh 900 ms window. The remaining budget is also sent to the enclave as its
gRPC timeout.

Raw requests are rechecked against wall-clock expiry after obtaining the
permit and immediately before enclave dispatch. The storage layer separately
rejects `not_after <= now` before opening a write transaction. Expired or
cancelled jobs waiting in the storage queue do not execute their operation.

Consensus admission is a try-acquire limit of 32 requests including the active
request. Storage has a bounded 64-job queue. Full queues return
`resource_exhausted`; permit waits return `deadline_exceeded`. Account status
keeps its independent four-request gate. Economic signing keeps its separate
single-flight gate and never holds the consensus permit during dual-RPC
verification.

`SIGNER_ECONOMIC_TIMEOUT_MS` now bounds the **entire** economic handler,
including dual-RPC verification and journal access, not just enclave RPC.
The RPC provider timeout is subordinate to this overall budget. Existing
900 ms defaults and default-off feature gates are unchanged. Before explicitly
enabling this path, operators must test their providers against that budget or
set suitable economic/consensus timeouts while retaining the existing rule
that economic timeout cannot exceed consensus timeout.

An expiry/queue error before dispatch means this attempt did not call the
enclave; it does not erase a durable reservation from an earlier attempt.
After dispatch, timeout/transport cancellation may have produced a signature,
so the gateway reports an unknown outcome bound to the request digest. A
client disconnect cannot revoke a signature already requested.

## Storage execution and cleanup (L-07)

All request-path redb reads and writes run on one named OS thread through
`journal_worker::JournalWorker`. No request-path disk transaction executes on
a Tokio worker. The actor acknowledges reservation only after redb commit;
moving I/O off the async runtime does not introduce memory-only authorization.

An in-progress disk commit cannot safely be cancelled. If its caller times
out, the commit can finish and the reply can be dropped; the durable record
remains available to an identical retry. Queue cancellation only skips jobs
that have not started. Shutdown closes the actor channel and lets owned
operations finish; abrupt process loss still relies on redb transactions and
the pre-signing slot reservation.

The new `replay_expiry_v1` table is a derived ordered index:

```text
key   = fixed-width hex((expiry as u64) XOR 2^63) + "\t" + nonce_key
value = nonce_key
```

At startup, before serving, it is rebuilt from the authoritative nonce/digest
pairs. Pair counts, reciprocal keys, expiry and pending/committed state are
checked; inconsistent data refuses startup. Existing numeric/pending/committed
records remain readable. Rebuilding the derived index never changes the
anti-equivocation slots.

Each reserve visits at most 128 expired index rows, not all 4096 nonce rows.
Commit no longer performs cleanup. Cleanup is transactional and affects only
expired replay-cache pairs, never the permanent height/type/view signing
fence. A large expired backlog is drained over bounded batches; admission may
be conservative while that work completes.

Structured `signing_journal` events contain operation, queue wait, operation
duration, replay entry count, cleanup count and success. Authenticated
`GetAccountStatus` replies also include cumulative `x-journal-*` headers for
completed/rejected operations, queue wait, operation time, commit failures and
worker-stopped state. These are counters, not precomputed latency percentiles.
They contain no workload token, wallet password, private key or result bytes.

## Result acknowledgment and recovery (L-08)

The state progression is represented by existing durable tables plus the
bounded result cache:

| Phase | Evidence | May return a successful signature response? |
|---|---|---|
| Reserved | Durable nonce/digest `pending` pair | No |
| Signing | Durable anti-equivocation slot fixed to the exact signed bytes before dispatch | No |
| Signed | Complete validated enclave response retained in the bounded RAM recovery cache | No |
| ResultCommitted | Complete result committed in both replay rows | Yes |

Commit failures are no longer ignored. The gateway retries persistence at most
twice within the same remaining budget, emits `signing_result_commit_failed`,
increments a counter, and returns `unavailable` if the result is still not
confirmed durable. Error metadata provides:

- `x-signing-outcome=result-commit-pending` for unconfirmed result persistence;
- `x-signing-outcome=signing-outcome-unknown` for timeout/transport ambiguity
  after enclave dispatch;
- `x-signing-digest=<stable request digest>` for the original intent.

A retry in the same process reuses retained result bytes and only retries
the commit; it does not call the enclave again. The RAM cache has both a 4096
entry cap and a 4 MiB byte cap, reserving room for a maximum-size result before
new enclave dispatch. A full recovery cache refuses new signing and requires
recovery of existing results. It is not used as a substitute for a durable
anti-equivocation reservation.

Committed records now preserve the **whole** protobuf response, including
public key and optional account-contract metadata:

```text
result_record = "response-v1:" + hex(SignExtensiblePayloadResponse protobuf)
nonce value   = "committed\t" + expiry + "\t" + result_record + "\t" + digest_key
digest value  = "committed\t" + expiry + "\t" + result_record + "\t" + nonce_key
```

The original signature-only hex format remains readable. New readers validate
the response size and single 64-byte signature shape before returning cached
data. No protobuf request or response schema changed. This also fixes loss of
account-contract metadata on a cached retry.

If a process loses power before result commit, RAM bytes cannot be recovered.
The durable pending pair and signing slot still constrain recovery to the same
digest; the enclave may be called again for that identical intent. No prior
attempt was acknowledged successful. A different digest for the same slot is
still rejected after restart. This is not exactly-once cryptographic execution
or a claim of atomicity between an enclave and an external disk.

Clients must retain the original payload/transaction bytes. Inside the live
request window, retry the same nonce+digest with valid auth; after expiry,
renew authorization with a fresh nonce while preserving the intent/digest.
Do not create a different signing intent in response to an unknown outcome.

## Local validation and measured baseline

Local tonic servers return fixed test signatures; they do not use production
keys or emulate hardware attestation. Tests cover expired direct reservation,
queue expiry without enclave calls, bounded storage backlog, expired queued
jobs with zero side effects, blocked storage with responsive account status,
commit failure and in-process retry without signing again, restart recovery,
permanent conflicting-slot rejection, complete cached response equality,
recovery-cache byte/admission caps, bounded expiry cleanup and cold index
rebuild/corruption refusal.

The post-change redb sample below was measured locally with 32 reserve/commit
samples per size. Setup was excluded. Units are milliseconds; this is neither
a production SLO nor a before/after speedup claim, and it excludes enclave,
network and actor queue wait.

| Replay rows | Reserve p50/p95/p99 | Commit p50/p95/p99 |
|---|---|---|
| 0 | 5.280 / 7.139 / 10.071 | 5.836 / 8.313 / 11.139 |
| 2048 | 4.883 / 7.996 / 8.028 | 6.824 / 10.643 / 11.729 |
| 4096 | 5.206 / 9.582 / 11.579 | 7.104 / 10.756 / 13.580 |

Run:

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p secure-sign-gateway journal_size_latency_samples -- --nocapture
bash scripts/check-format.sh
```

The default workspace suite includes a pre-existing ignored slow NEP-2 test;
run it separately with `cargo test -p secure-sign-core
neo::nep2::tests::test_nep2_key_default_params -- --ignored` when recording a
complete validation result. SGX is outside the workspace and real Nitro/SGX
attestation or production-vsock latency is not established by these tests.

## Release and rollback

Keep raw/economic gates off during migration. Stop/drain the gateway, retain
the current authoritative database and legacy import checkpoint, then restart
with the new reader. Startup rebuilds the derived expiry index. Never restore
an older signing-history backup as current state, delete uncertain pending
rows, or clear the permanent signing table to make a request pass.

Before re-enabling an optional path, verify exact binary/config provenance,
current database continuity, caller handling of recovery metadata, queue/disk
timings and provider deadlines in the actual deployment. This task performed
none of those production actions.

Old binaries do not understand `response-v1:` cached results. Rollback therefore
means disable raw/economic ingress and preserve the database; use a compatible
reader to recover pending/committed work. Do not downgrade by deleting new
records. Keep existing public-key pinning, role/MAC checks, source/destination
allowlists, fee caps and default-off switches unchanged.
