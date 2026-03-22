# KMS Attested Auto-Unlock Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable automatic startup where wallet passphrase is never stored plaintext on host and signer is unlocked via Nitro attestation + KMS recipient ciphertext.

**Architecture:** Add startup RPC methods to (1) mint an enclave attestation document with ephemeral RSA recipient key and (2) accept KMS `CiphertextForRecipient` bytes for in-enclave decryption and signer start. Keep existing manual decrypt flow for fallback. Add host boot script that calls new RPC + AWS KMS decrypt recipient mode and never holds plaintext passphrase.

**Tech Stack:** Rust (`tonic`, `prost`, `rsa`, `sha2`, `pkcs8`), AWS CLI KMS recipient mode, systemd.

### Task 1: Startup RPC contract
**Files:**
- Modify: `secure-sign-rpc/proto/startpb.proto`
- Generated: `secure-sign-rpc/src/startpb.rs`

Steps:
1. Add `GetKmsRecipientAttestation` RPC and request/response messages.
2. Add `StartSignerWithRecipientCiphertext` RPC and request/response messages.
3. Regenerate protobuf bindings by building workspace.

### Task 2: Failing tests for attested path
**Files:**
- Modify: `secure-sign-rpc/src/startup.rs` tests

Steps:
1. Add failing test for `start_signer_with_recipient_ciphertext` without prior attestation.
2. Add failing test for successful path using test recipient implementation.
3. Run targeted tests and confirm RED.

### Task 3: Implement startup state and crypto path
**Files:**
- Modify: `secure-sign-rpc/src/startup.rs`
- Modify: `secure-sign-nitro/src/lib.rs`
- Modify: `secure-sign-rpc/Cargo.toml`

Steps:
1. Introduce recipient provider trait to decouple Nitro/test implementations.
2. Add state for recipient private key and attestation doc.
3. Implement RSA OAEP decrypt of `CiphertextForRecipient` inside enclave path.
4. Wire service methods and preserve existing decrypt flow.

### Task 4: Host helper + service automation
**Files:**
- Create: `scripts/auto-unlock-kms-recipient.sh`
- Modify: `/etc/systemd/system/neo-signer-decrypt.service`
- Verify: `/etc/systemd/system/neo-mainnet.service`

Steps:
1. Script gets attestation doc via tool command.
2. Script calls `aws kms decrypt --recipient ...` and captures `CiphertextForRecipient`.
3. Script submits ciphertext to signer startup RPC.
4. Re-enable signer service using this script (no plaintext file).

### Task 5: Verification
**Files:**
- Verify runtime via systemd/journal/RPC

Steps:
1. Rebuild `secure-sign-vsock` + `secure-sign-tools`, rebuild EIF.
2. Restart enclave + signer unlock + neo-mainnet services.
3. Verify signer status is `Single`, periodic consensus command active, plugins loaded, sync progressing.
4. Document residual requirement: KMS key policy must enforce recipient attestation constraints.
