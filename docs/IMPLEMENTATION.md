# Option B: Allowlisted SignTransaction (local implementation notes)

**Branch:** `feat/allowlisted-sign-transaction`  
**Date:** 2026-09-04 (Asia/Shanghai)

## What landed

Fail-closed `SecureSign.SignTransaction` for a **single** MainNet GAS sweep destination
supplied only at **deploy/runtime** (never hardcoded in the public repo):

- Destination allowlist: deploy config / env (address **or** LE script-hash hex)
- Source pin: gateway `--public-key` / `SIGNER`-style public key (script hash derived)
- Asset: GAS only; scope: CalledByEntry; fee cap: 0.1 GAS; feature flag **default OFF**
- Signer **never** broadcasts
- If destination (or source pin) is unset/empty while signing is attempted → refuse everything

## Deploy-time env / CLI (gateway)

| Purpose | CLI | Env |
|---|---|---|
| Master switch (default OFF) | `--enable-sign-transaction` | `ENABLE_SIGN_TRANSACTION` |
| Allowlisted destination address | `--gas-sweep-destination` | `GAS_SWEEP_DESTINATION_ADDRESS` |
| Allowlisted destination script hash (LE hex) | `--gas-sweep-destination-script-hash` | `GAS_SWEEP_DESTINATION_SCRIPT_HASH` |
| Source account public key (SEC1 hex) | `--public-key` | (existing gateway flag) |

When `ENABLE_SIGN_TRANSACTION` / `--enable-sign-transaction` is on, a destination
(`GAS_SWEEP_DESTINATION_ADDRESS` or `GAS_SWEEP_DESTINATION_SCRIPT_HASH`) is **required**.
Do not commit real operational addresses into source, tests, or docs.

## Enforcement paths / symbols

| Layer | Path | Symbol |
|---|---|---|
| Asset/fee constants | `secure-sign-core/src/neo/gas_sweep_constants.rs` | `GAS_SCRIPT_HASH_LE`, fee caps (no personal addresses) |
| Script rebuild | `secure-sign-core/src/neo/gas_transfer_script.rs` | `validate_gas_transfer_script(from, to, …)` |
| Tx decode | `secure-sign-core/src/neo/tx.rs` | `decode_unsigned_transaction` (rejects non-CalledByEntry) |
| Policy | `secure-sign-core/src/neo/gas_sweep_policy.rs` | `GasSweepSigningPolicy`, `build_deploy_policy` |
| Enclave RPC | `secure-sign-rpc/src/lib.rs` | `DefaultSignService::sign_transaction` |
| Gateway | `secure-sign-gateway/src/main.rs` | `--enable-sign-transaction`, `--gas-sweep-destination`, separate `economic_flight` |

Wrong `to` address → `GasSweepPolicyError::DestinationNotAllowlisted` (permission denied).  
Unset allowlist while enabled → `AllowlistNotConfigured` / startup config error.

## Not in this PR (follow-ups)

- Live dual-RPC balance/fee binding on gateway (policy accepts optional `asserted_balance`; gateway currently passes `None`)
- Durable economic idempotency DB / audit journal
- Nitro EIF rebuild / deploy / flag enable on live RemoteSigner
- History scrub of prior commits that still contain old operational addresses (additive fix only on this branch)

## Test focus

```bash
cargo test -p secure-sign-core gas_sweep
cargo test -p secure-sign-core gas_transfer
cargo test -p secure-sign-core consensus
cargo test -p secure-sign-gateway
```

Tests use clearly fake/TEST-ONLY script hashes generated in-test (e.g. `[0x11;20]` / `[0x22;20]`),
never real MainNet operational addresses.
