# Allowlisted daily council GAS sweep

**Branch:** `feat/enclave-gas-sweep-enable`
**Date:** 2026-09-04 (Asia/Shanghai)

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

When `ENABLE_SIGN_TRANSACTION` / `--enable-sign-transaction` is on, a destination
(`GAS_SWEEP_DESTINATION_ADDRESS` or `GAS_SWEEP_DESTINATION_SCRIPT_HASH`) is **required**.
Do not commit real operational addresses into source, tests, or docs.

`GAS_SWEEP_RPC_URLS` must contain exactly two HTTPS URLs on different public
hosts. Redirects, embedded credentials, loopback/private IP literals, and a
single shared host are rejected at gateway startup.

## Enforcement paths / symbols

| Layer | Path | Symbol |
|---|---|---|
| Asset/fee constants | `secure-sign-core/src/neo/gas_sweep_constants.rs` | `GAS_SCRIPT_HASH_LE`, fee caps (no personal addresses) |
| Script rebuild | `secure-sign-core/src/neo/gas_transfer_script.rs` | `validate_gas_transfer_script(from, to, …)` |
| Tx decode | `secure-sign-core/src/neo/tx.rs` | `decode_unsigned_transaction` (rejects non-CalledByEntry) |
| Policy | `secure-sign-core/src/neo/gas_sweep_policy.rs` | `GasSweepSigningPolicy`, `build_deploy_policy` |
| Enclave RPC | `secure-sign-rpc/src/lib.rs` | `DefaultSignService::sign_transaction` |
| RPC agreement | `secure-sign-neo-rpc/src/lib.rs` | dual-provider balance, simulation, fee, height, and expiry proof |
| Gateway | `secure-sign-gateway/src/main.rs` | deploy flag, daily journal, live balance binding, consensus-priority lock |
| Sweep client | `secure-sign-sweeper/src/main.rs` | deterministic plan, local signature verification, broadcast, confirmation |

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
8. Verify the returned P-256 signature locally, broadcast, and wait for a HALT
   application log before marking the local plan confirmed.

The sweep client is dry-run by default. Production execution requires the
explicit `--broadcast` argument used by `neo-gas-sweep.service`. The state file
is mode 0600 and supports retrying the exact signed transaction after a process
or network interruption.

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

GrokBot must only start this audited unit through SSM and report the unit result
plus the transaction hash. It must never generate raw transactions, choose a
destination, or call the signer RPC directly. `neo-gas-sweep.timer` is a
host-local daily fallback at 09:05 Asia/Shanghai; the durable plan and gateway
journal make duplicate triggers safe.

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
cargo test -p secure-sign-core gas_sweep
cargo test -p secure-sign-core gas_transfer
cargo test -p secure-sign-core consensus
cargo test -p secure-sign-neo-rpc
cargo test -p secure-sign-gateway
cargo test -p secure-sign-sweeper
```

Tests use clearly fake/TEST-ONLY script hashes generated in-test (e.g. `[0x11;20]` / `[0x22;20]`),
never real MainNet operational addresses.
