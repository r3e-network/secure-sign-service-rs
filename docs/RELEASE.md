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
./scripts/check-gateway-identities.sh
cargo test --workspace --locked
cargo test --manifest-path secure-sign-core/Cargo.toml --locked
cargo test --manifest-path secure-sign-core/Cargo.toml --locked --no-default-features
cargo clippy --workspace --all-targets -- -D warnings
cargo audit --ignore RUSTSEC-2023-0071
cargo audit --file secure-sign-sgx/Cargo.lock --ignore RUSTSEC-2023-0071
cargo audit --file secure-sign-sgx-enclave/Cargo.lock --ignore RUSTSEC-2023-0071
```

Do not use `cargo fmt --check` as the format gate. `secure-sign-rpc/src/servicepb.rs`
and `startpb.rs` are committed `tonic-build` / `prost-build` output. The locked
generators format with `prettyplease`, which does not match `rustfmt`. That
mismatch is present on HEAD and is not a hand-written style regression. Do not
mass-edit those files to satisfy rustfmt.

`./scripts/check-format.sh` is the reproducible check:

1. rustfmt-check every tracked hand-written `*.rs` file;
2. exclude the two tonic-generated RPC sources;
3. re-run `secure-sign-rpc/build.rs` and `secure-sign-core/build.rs` with the
   locked `tonic-build` 0.12.3 / `prost-build` 0.13.5 and fail if committed
   output drifted.

`rustfmt.toml` ignores the same generated RPC files so an accidental
`cargo fmt` does not rewrite them. `secure-sign-core/src/neo/signpb.rs` is also
generated and is included in the generation-consistency check.

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

An unsigned, unbroadcast same-day plan may be replaced only after both RPC
application-log checks find no successful transaction and the independently
observed chain tip is past its validity window. Signed or broadcast plans must
remain unchanged for manual reconciliation. Whenever `GAS_SWEEP_RPC_URLS`,
`GATEWAY_WORKLOAD_IDENTITIES`, `GATEWAY_ALLOW_BIND_CIDR`,
`ENABLE_RAW_PAYLOAD_SIGNING`, or another signer environment value changes,
restart both `neo-nitro-gateway.service` and the sweep unit; `systemctl
daemon-reload` does not refresh an already-running gateway process.

Before accepting a build that includes the tightened trust boundary:

1. Confirm both RPC hostnames resolve to disjoint public address sets. A
   private, loopback, link-local, unique-local, multicast, reserved, or
   unspecified answer must prevent gateway and sweeper startup.
2. Confirm the gateway listen address is `10.78.0.1` or covered by an explicit
   **private, non-wide** bind CIDR. `0.0.0.0` / `0.0.0.0/0`, `/1`, `/8`,
   IPv6 global, and any public listen without `--allow-wildcard-bind` must
   fail closed.
3. Confirm the identity table comes from env, a `0600` file, or a credential
   fd — never argv — and that the sweeper sends the economic token the same
   way. `deploy/run-gateway.sh` and `neo-nitro-gateway.service` must load
   `GATEWAY_WORKLOAD_IDENTITIES*` from `EnvironmentFile` / `LoadCredential`.
   `./scripts/check-gateway-identities.sh` must pass. Unauthenticated or
   wrong-role calls must be denied.
4. Treat `SignExtensiblePayload` as off unless `ENABLE_RAW_PAYLOAD_SIGNING` is
   set for a controlled dBFT migration. Enabled raw calls must present
   `x-sign-contract-version=1`, the Signer digest from
   `secure-sign-core/testdata/workload-request-auth-v1.json`, and the pinned
   consensus `script_hashes`. The current Fura length-prefix digest is
   rejected. Semantic `SignBlock` / `SignTransaction` remain the default paths.

This release adds application-layer bearer tokens and a request MAC, not mTLS.
Token material is deploy-time secret; never stage it in Git or on argv. Caller
rollout for `neo-os-fura` is in [WORKLOAD-REQUEST-AUTH.md](WORKLOAD-REQUEST-AUTH.md).

Run the automation twice during acceptance. The second invocation must reuse
the confirmed transaction bytes and must not broadcast a second transaction.
Keep the host fallback timer enabled after the external routine is proven.

## 7. Roll Back

If the candidate cannot unlock, restore the backed-up KMS policy and previous
EIF before restarting the signer target. If economic signing fails, disable and
mask the GAS sweep timer/service and set `ENABLE_SIGN_TRANSACTION=false`;
consensus signing must remain available. Do not delete the previous artifact or
policy backup until the cold-start and live-consensus gates have passed.
