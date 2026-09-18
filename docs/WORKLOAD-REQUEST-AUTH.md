# Workload request authentication (v1)

**Status:** required for raw `SignExtensiblePayload`  
**Audience:** `secure-sign-gateway` operators and `neo-os-fura` consensus callers  
**Protocol authority:** this Signer repository. Callers must match these bytes.

## Overview

The parent gateway is a fail-closed policy proxy, not an enclave. A shared
workload token proves which deploy-time identity is calling, but it is **not**
mTLS and **not** hardware attestation. WireGuard membership is also not
authentication.

Raw `SignExtensiblePayload` is a compatibility path. When
`ENABLE_RAW_PAYLOAD_SIGNING` is on, every request must:

1. Present `x-sign-contract-version=1` (unknown or missing versions fail closed).
2. Present a `consensus` identity.
3. Bind the request with HMAC-SHA256 over the labeled v1 transcript below.
4. Use `digest = SHA-256(Neo N3 exact signed bytes)`, not the 36-byte
   sign-data itself and not a length-prefixed field hash.
5. Pass semantic dBFT checks, including a **pinned signer** invariant,
   `category=dBFT`, the `valid_block_start` / `valid_block_end` range, and
   a per-type body schema (length and layout). Header-only or trailing
   garbage is rejected before any journal write or enclave call.
6. Atomically **reserve** `identity+nonce` and
   `identity+method+network+digest` as `pending` in the durable replay
   journal. A later successful enclave call **commits** the pair and
   caches the signature bytes.
7. Acquire the consensus single-flight permit only after those cheap
   checks. Bad MAC, oversized, or malformed bodies never occupy the
   permit.
8. Reserve the anti-equivocation slot, including ChangeView and Recovery.

A captured request cannot be replayed after restart. Changing only the nonce
cannot re-authenticate the same payload. Tokens must never appear on a
process command line or in logs.

The portable golden vector is
[`secure-sign-core/testdata/workload-request-auth-v1.json`](../secure-sign-core/testdata/workload-request-auth-v1.json).
Go callers must reproduce every hex field byte-for-byte. Isolated
`cargo test --manifest-path secure-sign-core/Cargo.toml --locked` loads that
file through `CARGO_MANIFEST_DIR`.

## Design

### Why a request MAC

The previous gate compared a bearer token and stored the plaintext nonce in
an in-process `HashMap`. That failed closed only for the lifetime of one
process:

- nonce was outside any MAC/signature domain
- the same payload could be resent with a fresh nonce
- restart cleared the set
- the map had no capacity bound

v1 keeps the existing protobuf messages and adds **versioned gRPC metadata**.
Callers that cannot send `x-request-mac` must use `SignBlock` instead.

### Pinned signer

`--public-key` is the only account the gateway will sign for. The requested
`script_hashes` set must be exactly `{script_hash(pinned_key)}`. The payload
`sender` must match that hash. Multi-account wallets cannot be used to sign
an arbitrary script hash with a consensus token.

### Journal slots

Every recognized consensus message type, including ChangeView,
RecoveryRequest, and RecoveryMessage, occupies

`payload/{height}/{type:02x}/{validator}/{view}/v1`

A retry of the identical digest is accepted by the anti-equivocation slot.
A different digest for the same slot is refused.

### Replay journal (pending / committed)

The `redb` database keeps authoritative nonce/digest pairs and a derived expiry
index. Tagged values allow recovery without releasing the signing-slot fence:

| Table | Key | Value |
|---|---|---|
| `replay_nonces_v1` | `{identity_id}\t{nonce}` | `pending\t{not_after}\t{digest_key}` or `committed\t{not_after}\t{result_record}\t{digest_key}` |
| `replay_digests_v1` | `{identity_id}\t{method}\t{network}\t{digest}` | `pending\t{not_after}\t{nonce_key}` or `committed\t{not_after}\t{result_record}\t{nonce_key}` |

`method` is the full gRPC method
`/servicepb.SecureSign/SignExtensiblePayload`. `network` is the unsigned
decimal magic. Each reservation/recheck is an atomic write transaction; the
result commit after enclave success must finish before success is returned.
`result_record` is `response-v1:` plus the complete protobuf response as hex;
legacy signature-only hex remains readable. The derived `replay_expiry_v1`
index limits each cleanup to at most 128 due rows and is rebuilt/checked at
startup. Result commit does not run expiry cleanup:

- first seen `(identity, nonce, digest)` is reserved `pending` and may
  call the enclave
- identical nonce+digest while still `pending` is a safe retry of the
  **same** payload (no new digest, so not equivocation)
- identical nonce+digest after `committed` returns the cached signature
  and does **not** call the enclave again
- reused nonce with a different digest is replay
- same digest with a different nonce is replay while the original entry
  is live
- a different identity may reuse the same nonce bytes
- `pending` and `committed` entries expire when `not_after <= now`. After
  expiry the caller must use a **new** nonce. The anti-equivocation slot
  still refuses a different digest for the same height/type/view
- capacity is 4096 nonce entries; a full journal fails closed
- a signed but uncommitted response is retained in a bounded 4 MiB/4096-entry
  RAM recovery cache; identical retries only retry persistence in-process
- commit failure never returns success: inspect `x-signing-outcome` and
  `x-signing-digest`, then recover the identical intent
- the store is durable across restart: `pending` can resume, `committed`
  returns the same cached signature

This is **at-most-once for distinct payloads** and **idempotent retry for
the same nonce+digest**. It is not exactly-once RPC. If a `pending` entry
expires before commit, use a new nonce; do not expect the old nonce to
revive. Caching the signature is the liveness path after a dropped
response. The gateway does not claim exactly-once delivery.

Legacy `{not_after}\t{peer}` rows (no `pending`/`committed` prefix) are
treated as `pending` without a cached result so a restart mid-upgrade can
still finish the same nonce+digest.

### Request pipeline and GetAccountStatus

Cheap metadata, contract version, identity, size, MAC, and dBFT schema
checks run **before** bounded signing admission and the consensus single-flight
permit. Queue/storage/enclave/commit waits share one absolute deadline, capped
by the caller's gRPC timeout and the raw request expiry; expiry is checked again
after queueing and before enclave dispatch. A flood of
authorized-but-bad-MAC raw requests cannot stall `SignBlock`.

`GetAccountStatus` has its own try-acquire limit (`4` in-flight). Excess
calls fail with `resource_exhausted` and never share the consensus
permit or wait unbounded on vsock. Synchronous redb work runs on a dedicated
64-job storage lane, not Tokio workers. See
[the remediation runbook](ARCHITECTURE-REMEDIATION-2026-09-08.md) for error
metadata, complete result recovery, byte limits, metrics and rollback.

## API Reference

### gRPC metadata (no protobuf change)

| Header | Required on | Format |
|---|---|---|
| `x-sign-contract-version` | raw payload only | exactly `1` |
| `x-workload-id` | every gateway RPC | `[A-Za-z0-9._-]{1,64}` |
| `x-workload-role` | every gateway RPC | `consensus` or `economic` |
| `x-workload-token` | every gateway RPC | hex of ≥32 random bytes |
| `x-request-nonce` | raw payload only | **lowercase** `[0-9a-f]{32,128}` |
| `x-request-not-after` | raw payload only | Unix seconds, TTL ≤ 60 |
| `x-request-mac` | raw payload only | lowercase hex HMAC-SHA256 (64 chars) |

Uppercase hex, mixed case, `0x` prefixes, and whitespace are rejected for
nonce and MAC. Token hex may be mixed case because it is compared as bytes.
Missing or unknown `x-sign-contract-version` on the raw path fails closed.

### Exact signed bytes and digest

Signer is the protocol authority. Neo N3 exact signed bytes are **36 bytes**:

```
unsigned = Neo N3 extensible serialization:
           VarInt(len(category)) || category
           || u32le(valid_block_start)
           || u32le(valid_block_end)
           || sender   # 20-byte little-endian H160, no length prefix
           || VarInt(len(data)) || data

unsigned_hash = SHA-256(unsigned)                 # 32 bytes
sign_data     = u32le(network) || unsigned_hash   # 36 bytes
digest        = SHA-256(sign_data)                # 32 bytes
```

`sign_data` is what ECDSA signs. `digest` is **not** `sign_data`. Do not
hex-encode the 36-byte sign-data and call that a 32-byte digest. The MAC
`digest=` field is `lowercase_hex(digest)` (64 hex chars).

The serialization binds `category`, `valid_block_start`, `valid_block_end`,
`sender`, and `data`. Omitting the block validity range changes both
`sign_data` and `digest`.

VarInt is Bitcoin/Neo compact size: one byte when `len < 0xfd`.

### MAC transcript (`v1`)

UTF-8, LF (`0x0a`) separators, **no trailing newline**:

```
v1
method=/servicepb.SecureSign/SignExtensiblePayload
network=<u32 decimal>
nonce=<lowercase hex>
not_after=<unix decimal>
digest=<lowercase hex SHA-256>
workload_id=<id>
workload_role=consensus
```

```
mac = HMAC-SHA256(token_bytes, transcript_utf8)
x-request-mac = lowercase_hex(mac)
```

`network` is decimal with no leading zeros (`860833102`, not `0x334f454e`).
A future `v2` would change the first line. Unknown versions are rejected.

### Gateway configuration (secrets)

| Source | Variable / flag | Allowed |
|---|---|---|
| Environment | `GATEWAY_WORKLOAD_IDENTITIES` | yes |
| Secret file / mount | `GATEWAY_WORKLOAD_IDENTITIES_FILE` / `--workload-identities-file` | yes; mode `0600` or stricter |
| File descriptor | `GATEWAY_WORKLOAD_IDENTITIES_FD` / `--workload-identities-fd` | yes |
| CLI argv string | `--workload-identities <table>` | **rejected** |

Exactly one identities source must be set. File mode must be `0600` or
stricter (no group/world bits). Production systemd must set
`GATEWAY_WORKLOAD_IDENTITIES_FILE` or `_FD` through `EnvironmentFile` /
`LoadCredential`, never ExecStart argv. `deploy/run-gateway.sh` refuses to
start when the source is missing. Tokens are never printed.

Wildcard listen (`0.0.0.0`, `::`, `0.0.0.0/0`, `::/0`) is refused unless
`GATEWAY_ALLOW_WILDCARD_BIND=true` / `--allow-wildcard-bind` is set. The
same switch is required for every **public, global, or wide** extra CIDR
(IPv4 prefix `< /16`, IPv6 prefix `< /64`, `/1`, `/8`, IPv6 `2000::/3`,
and any non-private network). Private `/24` and `/32` binds, including
the WireGuard parent `10.78.0.0/24`, stay allowed without it. The process
then prints a firewall warning and still requires an external
control-plane firewall.

### Sweeper token

`GATEWAY_WORKLOAD_TOKEN` (env), `GATEWAY_WORKLOAD_TOKEN_FILE`, or
`GATEWAY_WORKLOAD_TOKEN_FD`. The `--workload-token` argv flag is removed.

### Message size

`SecureSignServer` sets `max_decoding_message_size` and
`max_encoding_message_size` to 256 KiB. After protobuf decode, the business
layer also rejects oversized `category`, payload `data`, `script_hashes`,
block `tx_hashes`, and raw transaction bytes. Limits live in
`secure-sign-core/src/limits.rs`.

## Usage examples

Compute a v1 MAC (caller-side). Prefer loading
`secure-sign-core/testdata/workload-request-auth-v1.json` and asserting
equality rather than inventing a second encoder.

```rust
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

fn request_mac_v1(
    token: &[u8],
    id: &str,
    network: u32,
    digest32: &[u8; 32],
    nonce_hex: &str,
    not_after: i64,
) -> [u8; 32] {
    let canonical = format!(
        "v1\nmethod=/servicepb.SecureSign/SignExtensiblePayload\nnetwork={network}\nnonce={nonce_hex}\nnot_after={not_after}\ndigest={}\nworkload_id={id}\nworkload_role=consensus",
        hex::encode(digest32)
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(token).expect("HMAC key");
    mac.update(canonical.as_bytes());
    mac.finalize().into_bytes().into()
}
```

Metadata on a `SignExtensiblePayload` call:

```
x-sign-contract-version: 1
x-workload-id: dBFT-node
x-workload-role: consensus
x-workload-token: <64+ lowercase or mixed hex>
x-request-nonce: <32..128 lowercase hex>
x-request-not-after: 1770000000
x-request-mac: <64 lowercase hex>
```

`script_hashes` must be the single little-endian script hash of the gateway
`--public-key`. A second hash, a different hash, or a sender that does not
match the pin is permission-denied.

## Cross-repo migration for neo-os-fura

**Do not treat the current Fura caller as compatible.** The checked-in
`neo-os-fura` implementation
(`neo3fura_neogo_patch/securesign/contract.go`) **will be rejected** by this
gateway. This repository is not changing Fura; Fura must later align to the
golden fixture.

### Why the current Fura build fails closed

| Step | This Signer (authoritative) | Current Fura (`PayloadDigest` / `bindingTranscript`) |
|---|---|---|
| Transcript | labeled `key=value` lines, full method, no trailing newline | labeled `key=value` lines, full method, no trailing newline |
| `digest` | `SHA-256(u32le(network) \|\| SHA-256(Neo unsigned extensible bytes))` | `SHA-256(u64be(len)\|\|category \|\| u64be(len)\|\|sender \|\| u64be(len)\|\|data)` |
| Block range | `valid_block_start` and `valid_block_end` are inside unsigned bytes | **omitted** |
| `category` / `data` length | Neo VarInt (1 byte when `< 0xfd`) | 8-byte big-endian length |
| `sender` | raw 20-byte H160, no length prefix | length-prefixed |
| Network | inside `sign_data` **and** the `network=` transcript line | transcript only |
| Fixture | `secure-sign-core/testdata/workload-request-auth-v1.json` | none; must not invent a second vector |

The transcript *shape* looks similar. The digest bytes do not match. HMAC
verification is constant-time and fail-closed, so a Fura MAC computed over
the length-prefix digest is `Unauthenticated`.

On the golden payload, Fura's length-prefix digest is
`c3b67ad52d2a5cfbdf040b5f7818e1ad6c936cbe63c449fcbd2e2089e26b9206`.
The Signer digest is
`fd201da95db93157197ac47659d272cce51953be15237f612d1a3d714f34e05b`.
Those values are recorded in the fixture as `digest_hex` versus
`incompatible_fura_length_prefix_digest_hex`.

Reproduce the Signer digest in Go:

```go
// unsigned: VarInt(category) || category || u32le(start) || u32le(end)
//           || sender20 || VarInt(data) || data
// signData: binary.LittleEndian.AppendUint32(nil, network) || sha256(unsigned)
// digest:   sha256(signData)   // 32 bytes, never the 36-byte signData
```

Then build the transcript exactly as `canonical_transcript` in the fixture
and `HMAC-SHA256(token, transcript)`. Compare with `mac_hex`.

### Compatibility table

| Item | Before | After |
|---|---|---|
| Protobuf `SignExtensiblePayloadRequest` | unchanged | unchanged |
| Bearer token headers | required | required |
| `x-sign-contract-version` | sent by Fura, ignored here | **required `1` on raw path** |
| Nonce / not-after | required when raw path on | required; **lowercase only** |
| `x-request-mac` | required by Fura; previously a different digest | **required**; Signer digest |
| `script_hashes` | any wallet account | must equal pinned consensus key |
| ChangeView / Recovery journal | no slot | durable slot, same schema as prepare/commit |
| Replay store | process memory | `redb` identity-bound `replay_*_v1` |
| `--workload-identities` argv | accepted | rejected; use env/file/fd |

Semantic `SignBlock` / `SignTransaction` keep bearer identity headers and do
not require a request MAC in v1.

### Rollout

1. Keep `ENABLE_RAW_PAYLOAD_SIGNING` unset. Consensus stays on `SignBlock`.
2. Deploy this gateway. Raw calls that still use Fura's length-prefix digest
   fail closed (`Unauthenticated`).
3. Align Fura to
   `secure-sign-core/testdata/workload-request-auth-v1.json` (do not invent
   another transcript).
4. Enable the raw path only after Fura produces the fixture MAC and pinned
   `script_hashes`.
5. Confirm ChangeView/Recovery conflicts are journaled and that a captured
   request fails after gateway restart.

### Rotation

Token rotation is unchanged: add `id:consensus:<new-hex>` beside the old
entry, restart the gateway, switch fura, remove the old token, restart
again. Overlapping tokens are each valid MAC keys. A request MAC must be
computed with the same token bytes sent in `x-workload-token`.

### Rollback

1. Set `ENABLE_RAW_PAYLOAD_SIGNING=false` and restart the gateway. Consensus
   continues on `SignBlock`.
2. Do not roll back the gateway binary while fura still sends only the old
   nonce headers if the new binary is already required for other P0 fixes.
   Prefer leaving the new gateway in place and disabling the raw path.
3. Replay / anti-equivocation tables are additive (`*_v1`). A rollback to a
   binary that does not open `replay_*_v1` leaves those tables unused; do
   not delete the database.

### Caller checklist

- [ ] Load `secure-sign-core/testdata/workload-request-auth-v1.json` and
      match `unsigned_bytes_hex`, `sign_data_hex`, `digest_hex`,
      `canonical_transcript`, and `mac_hex`.
- [ ] Do not hash `category`/`sender`/`data` with `uint64` big-endian
      length prefixes.
- [ ] Include `valid_block_start` and `valid_block_end` in unsigned bytes.
- [ ] Send `x-sign-contract-version: 1`.
- [ ] Send lowercase nonce and MAC only.
- [ ] Set `script_hashes = [script_hash(pinned_council_key)]`.
- [ ] Retry an identical nonce+digest inside the TTL to recover a lost
      response; the gateway returns the cached signature after commit.
- [ ] After `pending` expiry or `Expired`, use a **new** nonce. Do not
      treat this protocol as exactly-once.
- [ ] Treat `failed_precondition` on a different digest/nonce pair as
      replay: non-retryable.
- [ ] Never log `x-workload-token` or `x-request-mac`.
- [ ] Never pass the token table or sweeper token on argv.

## Test coverage

| Case | Expected |
|---|---|
| Golden fixture each step | unsigned, sign-data, digest, transcript, MAC match JSON |
| Fura length-prefix digest | not equal to Signer digest; MAC verify fails |
| Missing/unknown contract version on raw path | fail closed |
| Missing/wrong token or role | unauthenticated / permission denied |
| Raw path default off | failed precondition |
| Uppercase or mixed-case nonce/MAC | invalid nonce / unauthenticated |
| MAC over wrong method, network, or digest | unauthenticated |
| Semantic / MAC / schema failure before reserve | journal unchanged; consensus permit not taken |
| Same identity+nonce+digest while pending | retry same payload; may call enclave again |
| Same identity+nonce+digest after commit | cached signature; enclave not invoked |
| Pending survives process restart | retry still pending, not burned |
| Committed survives process restart | same cached signature |
| Pending TTL expiry | old nonce dead; caller uses a new nonce |
| Same nonce, different digest | replay |
| Same digest, new nonce while live | replay |
| Same nonce, different identity | allowed (keys include identity) |
| Restart, captured different digest | replay |
| Journal at capacity | fail closed |
| Concurrent reserve of one nonce | exactly one Fresh; others pending or cached |
| Flood of bad-MAC raw requests | SignBlock permit stays free |
| GetAccountStatus over the in-flight cap | resource_exhausted; independent of SignBlock |
| Wrong script hash / two hashes | permission denied |
| ChangeView and Recovery slots | reserved; conflict on different digest |
| Header-only / extra-garbage / unknown type | permission denied; not signed |
| Oversized category / data / hashes / tx | invalid argument |
| RPC URL with query, userinfo, or fragment | rejected; error text redacted |
| `0.0.0.0/0`, `/1`, `/8`, IPv6 global without danger switch | bind refused |
| Isolated `cargo test --manifest-path secure-sign-core/Cargo.toml --locked` | green; no workspace feature unification |
| Isolated `--no-default-features` and `--features std` | green |

## Residual risk

Shared tokens are still bearer secrets. A compromised consensus token can
sign any well-formed dBFT payload for the **pinned** account until the token
is revoked. There is no per-request mTLS, no RPC certificate pin, and no
enclave attestation of the caller. The raw path should stay off once fura
has moved to `SignBlock`.
