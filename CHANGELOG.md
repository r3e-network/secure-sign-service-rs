# Changelog

All notable changes to Neo Signer RS are documented in this file.

The project follows [Semantic Versioning](https://semver.org/), with the usual
pre-1.0 rule that minor releases may introduce operationally significant
changes.

## [Unreleased]

### Security

- Run raw-path identity, size, MAC, and dBFT schema checks before the
  consensus single-flight permit so a flood of bad-MAC requests cannot
  stall `SignBlock`. Cap `GetAccountStatus` at 4 in-flight vsock calls.
- Split the durable replay journal into `pending` reserve and
  `committed` signature cache. The same nonce+digest can retry after a
  lost response; a different digest/nonce is still replay. Pending TTL
  expiry requires a new nonce. This is at-most-once for distinct
  payloads, not exactly-once RPC.
- Reject public, IPv6-global, and wide listen CIDRs (`/1`, `/8`, IPv4
  `< /16`, IPv6 `< /64`) unless `--allow-wildcard-bind` is set. Literal
  `0.0.0.0/0` is no longer the only blocked wide pattern.
- Reject raw consensus payloads that are not `category=dBFT` with a
  valid range and a per-type body (ChangeView, Prepare*, Commit,
  Recovery*). Header-only and trailing-garbage bodies fail closed.
- Bind raw `SignExtensiblePayload` to the configured pinned consensus public
  key. The requested `script_hashes` set must be exactly that account. ChangeView
  and Recovery now occupy durable anti-equivocation slots.
- Replace the in-process nonce `HashMap` with a labeled v1 request MAC and a
  durable identity-bound replay journal. The transcript is
  `method=` / `network=` / `nonce=` / `not_after=` / `digest=` /
  `workload_id=` / `workload_role=` with no trailing newline. `digest` is
  SHA-256 of the 36-byte Neo N3 exact signed bytes, not a hex encoding of
  those 36 bytes. Raw path requires `x-sign-contract-version=1`. Semantic
  checks run before pending reserve. Identical identity+nonce+digest is
  reserved pending, then committed with a cached signature. Mixed-case or
  `0x`-prefixed nonces are rejected.
  Protobuf is unchanged. Golden vector:
  `secure-sign-core/testdata/workload-request-auth-v1.json`. Current
  neo-os-fura length-prefix digests are rejected. See
  [docs/WORKLOAD-REQUEST-AUTH.md](docs/WORKLOAD-REQUEST-AUTH.md).
- Cap `SecureSignServer` decode/encode size at 256 KiB and reject oversized
  category, payload data, script hashes, block `tx_hashes`, and raw
  transactions after protobuf decode.
- Require production gateway identities through
  `deploy/run-gateway.sh`, `signer.env`, and systemd `LoadCredential`. Tokens
  never appear on argv. `./scripts/check-gateway-identities.sh` proves the
  entry loads a source and fails closed when it is missing.
- Reject RPC URLs that contain userinfo, query, or fragment, and redact those
  fields from error text so API keys cannot appear in logs.
- Stop accepting workload identity tables and sweeper tokens on argv. Use env,
  a `0600` secret file, or a file descriptor. Shared tokens remain bearer
  secrets, not mTLS or attestation.
- Refuse `0.0.0.0` / `::` / `0.0.0.0/0` and other public or wide CIDRs
  unless an explicit danger switch is set; the process then prints a
  firewall warning.
- Resolve dual-RPC hosts after URL validation and refuse any loopback, private,
  link-local, unique-local, multicast, reserved, or unspecified address, plus
  overlapping resolution sets. The RPC client disables redirects and pins DNS
  through a testable resolver so rebinding or a changed answer fails closed.
- Restrict the gateway listen address to the WireGuard parent unless an
  explicit bind CIDR is configured.
- Require application-layer workload identity and role on gateway RPCs. Tokens
  are compared in constant time. Network location alone is not accepted.
  Authentication failures do not distinguish unknown ids, wrong roles, or
  wrong tokens. The same id may carry overlapping tokens so rotation can add
  a new secret before the old one is revoked. Debug output redacts token
  bytes. This remains a shared-secret policy, not mTLS.
- Disable the raw `SignExtensiblePayload` compatibility path by default. When
  the migration switch is on, require a consensus identity, the pinned
  signer, network/policy checks, a v1 request MAC, and a durable nonce/digest
  replay window.

### Fixed

- Recognize Neo N3's standard object-shaped broadcast acknowledgement and
  compact `AlreadyExists` errors instead of reporting a false broadcast failure.
- Reconcile unresolved saved sweeps before signing or rebroadcasting, requiring
  a matching transaction ID, VM `HALT`, and a successful transfer return value.
- Document bounded observation of systemd automatic recovery and end-to-end
  acceptance checks for GrokBot's daily GAS sweep routine.

## [0.2.0] - 2026-09-04

### Added

- Fail-closed Neo N3 `SignTransaction` support for one deploy-time allowlisted
  GAS destination. Economic signing remains disabled by default.
- Deterministic daily GAS sweep planning with independent HTTPS RPC agreement,
  VM simulation, fee validation, source-balance binding, local signature
  verification, confirmation, and resumable state.
- Asia/Shanghai daily idempotency and a host-local systemd fallback timer.
- KMS recipient-attestation auto-unlock for AWS Nitro Enclaves.
- WireGuard-bound parent gateway health supervision and recovery units.

### Changed

- Replaced the unbounded in-memory anti-equivocation journal with a durable
  `redb` store and bounded 16 MiB page cache.
- Added verified migration from the legacy append-only journal, including
  checkpoint protection against truncation or historical mutation.
- Kept external RPC work outside the consensus signing semaphore so slow
  providers cannot block dBFT signing.
- Updated transitive `anyhow`, `bytes`, `h2`, `rand`, and `rpassword`
  dependencies to patched releases across the root and independent SGX
  workspaces.
- Documented a measured-EIF/KMS rotation procedure with a temporary transition
  allowlist, controlled cold start, and mandatory single-measurement cleanup.

### Fixed

- Corrected Neo N3 transaction ID derivation to use one SHA-256 over unsigned
  transaction data, matching node confirmation semantics.
- Made a confirmed sweep retry byte-identical and prevented duplicate daily
  broadcasts after process, network, or automation retries.
- Hardened enclave temporary recipient files with exclusive creation, mode
  `0600`, synchronized writes, and cleanup on every exit path.

### Security

- Consensus signing validates network magic, payload category, sender,
  recognized message type, and anti-equivocation slot before enclave access.
- Economic signing validates the pinned source, GAS asset, exact destination,
  `CalledByEntry` scope, fee ceiling, balance reserve, validity window, and two
  independent chain views.
- No wallet password, WIF, production destination, KMS ciphertext, instance
  identifier, or enclave measurement is included in this release.

[0.2.0]: https://github.com/r3e-network/secure-sign-service-rs/releases/tag/v0.2.0
