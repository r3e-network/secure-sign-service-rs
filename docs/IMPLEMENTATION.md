# Neo Signer RS v0.2.0 implementation

**Release:** `v0.2.0`
**Date:** 2026-09-04

## What landed

Fail-closed `SecureSign.SignTransaction` for a **single** MainNet GAS sweep destination
supplied only at **deploy/runtime** (never hardcoded in the public repo):

- Destination allowlist: deploy config / env (address **or** LE script-hash hex)
- Source pin: gateway `--public-key` / `SIGNER`-style public key (script hash derived)
- Asset: GAS only; scope: CalledByEntry; fee cap: 0.1 GAS; feature flag **default OFF**
- Misconfiguring the destination as the signer source account is rejected at startup
- The enclave signer **never** broadcasts; a separate deterministic client does
- If destination (or source pin) is unset/empty while signing is attempted → refuse everything

## Deploy-time env / CLI (gateway)

| Purpose | CLI | Env |
|---|---|---|
| Master switch (default OFF) | `--enable-sign-transaction` | `ENABLE_SIGN_TRANSACTION` |
| Allowlisted destination address | `--gas-sweep-destination` | `GAS_SWEEP_DESTINATION_ADDRESS` |
| Allowlisted destination script hash (LE hex) | `--gas-sweep-destination-script-hash` | `GAS_SWEEP_DESTINATION_SCRIPT_HASH` |
| Source account public key (SEC1 hex) | `--public-key` | (existing gateway flag) |
| Two independent Neo HTTPS RPCs | `--gas-sweep-rpc-urls` | `GAS_SWEEP_RPC_URLS` |
| RPC timeout | `--gas-sweep-rpc-timeout-ms` | `GAS_SWEEP_RPC_TIMEOUT_MS` |
| Maximum RPC height skew | `--gas-sweep-max-height-skew` | `GAS_SWEEP_MAX_HEIGHT_SKEW` |
| Maximum transaction validity window | `--gas-sweep-max-valid-until-delta` | `GAS_SWEEP_MAX_VALID_UNTIL_DELTA` |
| Workload identity table (required) | `--workload-identities-file` / `_FD` | `GATEWAY_WORKLOAD_IDENTITIES` / `_FILE` / `_FD` |
| Extra listen CIDRs | `--allow-bind-cidr` | `GATEWAY_ALLOW_BIND_CIDR` |
| Wildcard / public / wide listen (default OFF) | `--allow-wildcard-bind` | `GATEWAY_ALLOW_WILDCARD_BIND` |
| Raw `SignExtensiblePayload` (default OFF) | `--enable-raw-payload-signing` | `ENABLE_RAW_PAYLOAD_SIGNING` |

When `ENABLE_SIGN_TRANSACTION` / `--enable-sign-transaction` is on, a destination
(`GAS_SWEEP_DESTINATION_ADDRESS` or `GAS_SWEEP_DESTINATION_SCRIPT_HASH`) is **required**.
Do not commit real operational addresses into source, tests, or docs.

`GAS_SWEEP_RPC_URLS` must contain exactly two HTTPS URLs with no userinfo,
query, or fragment. After URL checks, both
hosts are resolved through a pinned `HostResolver`. Construction fails if either
resolution set contains a loopback, private, link-local, unique-local,
multicast, reserved, or unspecified address, if the hostnames match, or if the
resolved address sets intersect. The HTTP client disables redirects, ignores
proxies, and reuses the same resolver so a later private or changed answer is
treated as DNS rebinding and refused. Hostname-only inequality is not enough.

The gateway listen address defaults to the WireGuard parent `10.78.0.1`. Any
other bind requires an explicit `--allow-bind-cidr` / `GATEWAY_ALLOW_BIND_CIDR`
entry that covers it. Unspecified binds (`0.0.0.0`, `::`), wildcard CIDRs
(`0.0.0.0/0`, `::/0`), public/global networks, and wide prefixes (IPv4
`< /16`, IPv6 `< /64`, including `/1` and `/8`) stay rejected unless
`--allow-wildcard-bind` / `GATEWAY_ALLOW_WILDCARD_BIND` is also set. That
switch is the explicit danger override. It prints a startup warning and
still requires an external firewall. Private `/24` (including WireGuard)
does not need the switch.

Network location is not authentication. Every RPC requires an application-layer
workload identity from `GATEWAY_WORKLOAD_IDENTITIES`,
`GATEWAY_WORKLOAD_IDENTITIES_FILE`, or `GATEWAY_WORKLOAD_IDENTITIES_FD`
(`id:role:hex-token`, comma-separated). There is no default table, no implicit
identity, and no argv string for the table: passing tokens on the command line
is rejected. An empty or missing value refuses startup. Tokens are compared in
constant time after hex decode. Unknown ids, wrong tokens, and a claimed role
that does not match the table all fail as unauthenticated so a caller cannot
enumerate ids or roles without a valid token. Roles are `consensus` and
`economic`. This is a deploy-time shared-secret token policy, not mTLS and not
hardware attestation.

Rotate a token by adding a second `id:role:new-hex-token` for the same id and
role, restarting `neo-nitro-gateway.service`, switching clients, then removing
the old token and restarting again. Revoke by deleting the entry and
restarting. There is no live in-process reload; `systemctl daemon-reload`
does not refresh an already-running gateway. Do not keep unused tokens in the
table after clients have moved.

`SignBlock` and `SignTransaction` are the semantic signing endpoints.
`SignExtensiblePayload` is the legacy raw-payload compatibility path and is
**disabled by default**. Enabling it requires `ENABLE_RAW_PAYLOAD_SIGNING=true`,
a `consensus` identity, the dBFT network/category/sender/body-schema policy,
the pinned `--public-key` script-hash set, `x-sign-contract-version=1`, a v1
labeled request MAC, and a lowercase `x-request-nonce` plus
`x-request-not-after` header (maximum 60 seconds). The MAC digest is
`SHA-256` of the 36-byte Neo N3 exact signed bytes (network magic LE plus
`SHA-256` of unsigned extensible serialization), not a hex encoding of those
36 bytes. Identity, size, MAC, and dBFT schema checks run **before** the
consensus single-flight permit. The durable replay journal then reserves
`identity+nonce` / `identity+method+network+digest` as `pending` and
commits the complete response after the enclave succeeds before returning
success. All waits share the handler deadline; disk operations use a bounded
storage worker. Signed-but-uncommitted results return explicit recovery
metadata and are retried without new enclave calls while retained in RAM. The same nonce+digest
retries the pending work or returns the cached result. A different
digest/nonce is replay. Pending expiry requires a new nonce; this is
one digest per durable signing slot, not exactly-once RPC. Replay and the
cached result survive process restart. `GetAccountStatus` has a separate
in-flight cap of 4. Caller migration is in
[WORKLOAD-REQUEST-AUTH.md](WORKLOAD-REQUEST-AUTH.md).
The golden vector is
`secure-sign-core/testdata/workload-request-auth-v1.json`. The current
neo-os-fura length-prefix digest is incompatible and will be rejected.

## Enforcement paths / symbols

| Layer | Path | Symbol |
|---|---|---|
| Asset/fee constants | `secure-sign-core/src/neo/gas_sweep_constants.rs` | `GAS_SCRIPT_HASH_LE`, fee caps (no personal addresses) |
| Script rebuild | `secure-sign-core/src/neo/gas_transfer_script.rs` | `validate_gas_transfer_script(from, to, …)` |
| Tx decode | `secure-sign-core/src/neo/tx.rs` | `decode_unsigned_transaction` (rejects non-CalledByEntry) |
| Policy | `secure-sign-core/src/neo/gas_sweep_policy.rs` | `GasSweepSigningPolicy`, `build_deploy_policy` |
| Enclave RPC | `secure-sign-rpc/src/lib.rs` | `DefaultSignService::sign_transaction` |
| RPC agreement | `secure-sign-neo-rpc/src/lib.rs` | dual-provider balance, simulation, fee, height, and expiry proof |
| RPC trust boundary | `secure-sign-neo-rpc/src/endpoint.rs` | `HostResolver`, public-address pin, disjoint resolution sets, no redirects |
| Workload identity | `secure-sign-core/src/workload.rs` | shared-secret table, overlapping rotation, constant-time token, v1 request MAC, lowercase nonce |
| Gateway bind | `secure-sign-gateway/src/bind.rs` | WireGuard default, explicit CIDR allowlist, independent wildcard switch |
| Request auth | `docs/WORKLOAD-REQUEST-AUTH.md` | fura metadata, MAC domain, rotation, rollback |
| Gateway | `secure-sign-gateway/src/main.rs` | identity gate, raw-payload switch, daily journal, live balance binding |
| Sweep client | `secure-sign-sweeper/src/main.rs` | deterministic plan, workload token, local signature verification |

Wrong `to` address → `GasSweepPolicyError::DestinationNotAllowlisted` (permission denied).  
Unset allowlist while enabled → `AllowlistNotConfigured` / startup config error.

## Daily execution contract

1. Read the source balance and chain height from two independent RPC providers.
2. Construct only `GAS.transfer(pinned source, allowlisted destination, amount, null)`.
3. Iterate system and network fee estimation until the transaction is stable.
4. Require both providers to report enough balance, agree on VM `HALT + true`
   and fees, and stay within a bounded height skew before the gateway will sign.
5. Build from the lower independently observed balance and leave at least 1 GAS
   after fees. Rewards that accrue during verification remain for the next run.
6. Reserve `gas-sweep/YYYY-MM-DD` in the immediate-durability, disk-backed
   gateway journal. The gateway imports the legacy append-only journal in
   bounded batches, verifies its checkpointed prefix on every restart, and
   keeps its page cache at 16 MiB. A
   conflicting transaction for the same Asia/Shanghai day is refused.
7. Hold the consensus signing semaphore only during the sub-second enclave
   signature call. All external RPC work happens before it, so economic work
   cannot delay normal dBFT signing.
8. Verify the returned P-256 signature locally and accept Neo N3's standard
   `sendrawtransaction` result object (`{"hash":"0x..."}`). A broadcast
   acknowledgement is not confirmation: require an application log matching
   the locally calculated single-SHA256 transaction ID, VM `HALT`, and the
   successful boolean transfer result before marking the plan confirmed.

The sweep client is dry-run by default. Production execution requires the
explicit `--broadcast` argument used by `neo-gas-sweep.service`. The state file
is mode 0600 and supports retrying the exact signed transaction after a process
or network interruption. Before retrying an unresolved saved transaction,
reconcile its application log. If already successful, record both confirmation
and its broadcast hash without signing or broadcasting again. Never replace a
pending same-day plan simply because its broadcast acknowledgement was lost.
If an unsigned, unbroadcast same-day plan expires before signing, the client
reconciles both RPC application logs and the independently observed chain tip,
marks that plan expired, and creates a fresh plan. Signed or broadcast plans are
never replaced automatically. Any change to `GAS_SWEEP_RPC_URLS` or related
signer environment must restart both `neo-nitro-gateway.service` and the sweep
unit; `systemctl daemon-reload` alone does not refresh an already-running
gateway process.

The official RustCrypto `rsa` crate is used only for in-enclave generation and
PKCS#8 export of an ephemeral KMS recipient key. The Rust RSA decrypt/sign
padding paths covered by RUSTSEC-2023-0071 are not called; CMS decryption is
delegated to the packaged OpenSSL binary. Recipient key, ciphertext, and
plaintext temporary files are atomically created as mode 0600 inside the
enclave and removed on every exit path.

## Operations

Run a no-signature/no-broadcast preflight:

```bash
sudo -u neo-signer /opt/neo-signer/bin/secure-sign-sweeper \
  --state-path /var/lib/neo-signer/gas-sweep-preflight.json
```

Run the production unit and inspect its result:

```bash
sudo systemctl start neo-gas-sweep.service
sudo systemctl show neo-gas-sweep.service -p Result -p ExecMainStatus
sudo journalctl -u neo-gas-sweep.service -n 30 --no-pager
```

GrokBot must only start this audited unit through SSM `AWS-RunShellScript` and
report the fresh command ID, terminal SSM status, response code, service start
time, unit result, and plan status. Historical chat output or a persisted
confirmed plan is not evidence that the current automation invocation ran. It
must never generate raw transactions, choose a destination, or call the signer
RPC directly.

The unit uses `Restart=on-failure`, a 20-second restart delay, and a bounded
start limit. A failed first attempt is not a terminal daily sweep failure.
GrokBot must follow the unit through automatic retries for a bounded observation
window (up to ten minutes), recording `ActiveState`, `SubState`, `NRestarts`,
`Result`, `ExecMainStatus`, and fresh journal output. Report `recovering` while
the unit is restarting; report recovery only after the fresh run exits zero and
the current-day plan is `confirmed` or `no_op`. Verify confirmed transactions
against their matching on-chain application logs. If the window expires or the
start limit is reached, report the actual terminal state and retain the plan.
Do not manually trigger another transaction. The SSM shell's final exit status
must reflect acceptance checks, not the success of a trailing status-print or
JSON command. SSM `Success` alone does not establish sweep success.

The external routine runs daily at 09:00 Asia/Shanghai. The host-local
`neo-gas-sweep.timer` is a fallback at 09:05 with up to five minutes of
randomized delay. The durable plan and gateway journal make overlapping or
repeated triggers safe.

## Measured EIF rollout

AWS KMS `kms:RecipientAttestation:ImageSha384` corresponds to the EIF PCR0.
Every rebuilt EIF therefore requires an attestation-policy rollout:

1. Add the candidate PCR0 alongside the running PCR0 temporarily.
2. Install the candidate and perform a controlled signer cold start.
3. Require a fresh recipient-attestation decrypt, `Single` signer status,
   active services, live consensus journal writes, and advancing chain height.
4. Remove the previous PCR0 and read the final single-value policy back.

Do not infer KMS readiness from an enclave that was unlocked before the policy
change. A cold start is the acceptance test for restart survivability.

Emergency stop:

```bash
sudo systemctl disable --now neo-gas-sweep.timer
sudo systemctl mask neo-gas-sweep.service
```

Then set `ENABLE_SIGN_TRANSACTION=false` in the protected signer environment
and restart only the gateway. Consensus block and payload signing remain
available while economic signing is disabled.

## RSA dependency scope

The official RustCrypto `rsa` crate is used only inside the enclave to generate
an ephemeral KMS recipient key and encode it as PKCS#8. The application does not
use that crate for network-observable RSA decryption or signing; KMS recipient
ciphertext is decrypted by the local OpenSSL CMS process. Therefore the Marvin
padding-oracle advisory (`RUSTSEC-2023-0071`) does not apply to the exercised
Rust code path. Do not replace this mature dependency with an unaudited fork
merely to suppress the scanner finding.

## Test focus

```bash
cargo test --manifest-path secure-sign-core/Cargo.toml --locked
cargo test --manifest-path secure-sign-core/Cargo.toml --locked --no-default-features
cargo test --manifest-path secure-sign-core/Cargo.toml --locked --features std
./scripts/check-gateway-identities.sh
cargo test -p secure-sign-core gas_sweep
cargo test -p secure-sign-core gas_transfer
cargo test -p secure-sign-core consensus
cargo test -p secure-sign-core workload
cargo test -p secure-sign-neo-rpc
cargo test -p secure-sign-gateway
cargo test -p secure-sign-sweeper
```

## Production trust boundary

Fail closed. Missing identities, a non-allowlisted listen address, a private
DNS answer, overlapping RPC resolutions, or a disabled raw-payload path refuse
the request or refuse to start. Do not treat WireGuard membership as the only
control.

The daily sweep client must send `x-workload-id`, `x-workload-role=economic`,
and `x-workload-token` when it calls `SignTransaction`. Load that token from
env, a `0600` file, or a file descriptor — never argv. Consensus callers that
still need `SignExtensiblePayload` must set the migration switch and send a
`consensus` identity, pinned `script_hashes`, lowercase nonce/TTL headers, and
`x-request-mac`. `SignBlock` remains the semantic block path and still
requires a `consensus` identity.

What this does **not** implement: gateway mTLS, RPC certificate pinning, or
hardware-backed workload attestation. Residual risk is documented in the
release procedure.

The complete source, artifact, deployment, KMS, automation, and rollback gates
are documented in [RELEASE.md](RELEASE.md).

Tests use clearly fake/TEST-ONLY script hashes generated in-test (e.g. `[0x11;20]` / `[0x22;20]`),
never real MainNet operational addresses.


## 2026-09-08 gateway architecture update

See [ARCHITECTURE-REMEDIATION-2026-09-08.md](ARCHITECTURE-REMEDIATION-2026-09-08.md)
for shared request deadlines, bounded storage/admission, expiry indexing and
explicit signed-result recovery. The economic timeout includes RPC verification;
default switches remain off. No production enclave deployment is implied.
