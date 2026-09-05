# Release Procedure

This procedure releases Neo Signer RS without publishing signer secrets or
coupling a source release to an unverified production cutover.

## 1. Prepare

1. Start from an up-to-date default branch and a clean tracked worktree.
2. Update every crate version and `CHANGELOG.md` in the same commit.
3. Confirm examples contain placeholders only. Never stage wallets, WIFs,
   passwords, KMS ciphertext, EIF files, production addresses, instance IDs,
   PCR values, WireGuard material, or deployment environment files.
4. Review the full staged diff and run a secret scanner against staged bytes.

## 2. Validate Source

```bash
./scripts/check-format.sh
cargo test --workspace
cargo clippy --workspace --all-targets --no-deps -- -D warnings
cargo audit --ignore RUSTSEC-2023-0071
cargo audit --file secure-sign-sgx/Cargo.lock --ignore RUSTSEC-2023-0071
cargo audit --file secure-sign-sgx-enclave/Cargo.lock --ignore RUSTSEC-2023-0071
```

The format check excludes `servicepb.rs` and `startpb.rs` because `build.rs`
regenerates those files through `tonic-build`. All hand-written Rust source is
checked.

`RUSTSEC-2023-0071` currently has no patched RustCrypto `rsa` release. This
repository uses the crate only to generate and encode a one-time ephemeral KMS
recipient key. OpenSSL CMS performs recipient decryption, so the vulnerable
Rust RSA padding path is not exercised. Re-evaluate this exception on every
release.

The audit also reports `serde_cbor` as unmaintained through AWS's
`aws-nitro-enclaves-nsm-api`. The current upstream release still uses that
dependency, so replacing it locally would fork the attestation protocol
implementation. Treat this as an upstream maintenance warning and re-evaluate
it on every release. All dependencies with available security fixes are pinned
to patched releases in the root and independent SGX lock files.

## 3. Build Release Artifacts

Build reproducible Linux ARM64 parent and enclave binaries:

```bash
make linux-arm64
install -d -m 0755 dist/v0.2.0
install -m 0755 target/secure-sign-vsock dist/v0.2.0/
install -m 0755 target/secure-sign-gateway dist/v0.2.0/
install -m 0755 target/secure-sign-sweeper dist/v0.2.0/
tar -C dist/v0.2.0 -czf dist/neo-signer-rs-v0.2.0-linux-arm64.tar.gz \
  secure-sign-vsock secure-sign-gateway secure-sign-sweeper
shasum -a 256 dist/neo-signer-rs-v0.2.0-linux-arm64.tar.gz \
  > dist/neo-signer-rs-v0.2.0-linux-arm64.tar.gz.sha256
```

Do not attach an EIF to a GitHub release. A production EIF contains an encrypted
wallet and is sensitive infrastructure material.

## 4. Tag and Publish

The tag must point to the reviewed and tested default-branch commit:

```bash
git tag -s v0.2.0 -m "Neo Signer RS v0.2.0"
git push origin v0.2.0
gh release create v0.2.0 \
  dist/neo-signer-rs-v0.2.0-linux-arm64.tar.gz \
  dist/neo-signer-rs-v0.2.0-linux-arm64.tar.gz.sha256 \
  --title "Neo Signer RS v0.2.0" \
  --notes-file docs/releases/v0.2.0.md
```

If signed Git tags are unavailable in the release environment, use an annotated
tag and record that limitation in the release notes. Never substitute an
untested commit.

## 5. Deploy a New EIF

1. Build the EIF only on the controlled deployment host.
2. Record its PCR0 without committing it.
3. Back up the current KMS key policy with mode `0600`.
4. Temporarily allow both the running and candidate image digests.
5. Install the new EIF and binaries, then cold-start the signer target.
6. Require all of the following before tightening policy:
   - KMS recipient-attestation unlock completed in this invocation.
   - Enclave status is `Single` for the configured public key.
   - Enclave, unlock, gateway, target, and health timer are active.
   - Gateway restart count and memory remain within expected bounds.
   - The anti-equivocation journal advances from live consensus traffic.
   - Chain height advances through independent RPC providers.
7. Replace the transition policy with the candidate digest only and read it
   back. Remove all local policy copies and one-time access material.

## 6. Validate Daily GAS Sweep

The automation runner may only start `neo-gas-sweep.service` through AWS SSM
`AWS-RunShellScript`. For every manual or scheduled validation, retain fresh:

- SSM command ID and terminal `Success` status;
- response code `0`;
- service start time later than the automation trigger;
- systemd `Result=success` and `ExecMainStatus=0`;
- plan status `confirmed` or `no_op`;
- matching transaction and broadcast hashes for a confirmed plan;
- a matching on-chain application log with `HALT` and boolean transfer success.

Follow the unit's automatic restarts rather than treating its first nonzero
exit as the terminal result. Record `NRestarts` and observe for a bounded window
as described in [Operations](IMPLEMENTATION.md#operations). The SSM wrapper
must exit nonzero when acceptance fails even if its diagnostic commands succeed.

Run the automation twice during acceptance. The second invocation must reuse
the confirmed transaction bytes and must not broadcast a second transaction.
Keep the host fallback timer enabled after the external routine is proven.

## 7. Roll Back

If the candidate cannot unlock, restore the backed-up KMS policy and previous
EIF before restarting the signer target. If economic signing fails, disable and
mask the GAS sweep timer/service and set `ENABLE_SIGN_TRANSACTION=false`;
consensus signing must remain available. Do not delete the previous artifact or
policy backup until the cold-start and live-consensus gates have passed.
