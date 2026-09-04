# Changelog

All notable changes to Neo Signer RS are documented in this file.

The project follows [Semantic Versioning](https://semver.org/), with the usual
pre-1.0 rule that minor releases may introduce operationally significant
changes.

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
