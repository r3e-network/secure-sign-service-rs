# Neo Signer RS

## Overview
Neo Signer RS is a fail-closed signing service for
[Neo](https://github.com/neo-project). It keeps private-key operations inside a
hardware-isolated execution environment and exposes narrowly scoped signing
policies to trusted clients.

Current release: **v0.2.0**. See [CHANGELOG.md](CHANGELOG.md) for release notes
and [docs/RELEASE.md](docs/RELEASE.md) for the reproducible release procedure.

### Deployment Modes
- **Mock Mode**: For development and testing purposes
- **SGX Mode**: For Intel SGX enclave deployment with hardware security
- **AWS Nitro Enclave Mode**: For AWS Nitro Enclave deployment with isolated execution

### Key Features
- Hardware-based security through SGX and Nitro Enclaves
- Secure key storage and management
- Encrypted wallet support (NEP-6 format)
- Isolated execution environments
- Neo N3 consensus-only validation at the parent gateway and inside the enclave
- A WireGuard-bound gateway with durable, bounded anti-equivocation storage
- KMS recipient-attestation unlock bound to the deployed EIF measurement
- An optional allowlisted daily council GAS sweep with dual-RPC verification
- systemd supervision, health recovery, and an idempotent local fallback timer

## Prerequisites

Build and attest production artifacts in a controlled environment. Never place
wallet passwords, WIFs, production destinations, KMS ciphertext, signing
certificates, or enclave measurements in Git.

### For Mock Mode
- Rust toolchain (latest stable version)

### For SGX Mode
- SGX-enabled hardware (Intel processors with SGX support)
- Intel SGX SDK and PSW (Platform Software)
- SGX driver installed
- Rust toolchain
- OpenSSL development libraries

### For AWS Nitro Enclave Mode
- AWS EC2 instance with Nitro Enclave support
- Docker
- AWS Nitro CLI (`nitro-cli`)
- Rust toolchain
- For Vsock support: `rustup target add x86_64-unknown-linux-musl` (x86_64) or `rustup target add aarch64-unknown-linux-musl` (ARM64)

For a dedicated Neo consensus signer, the production minimum is a
`c6g.large` parent (2 vCPU, 4 GiB) with 1 vCPU and 1 GiB reserved for the
enclave. The parent should run only SSM, WireGuard, the TCP-to-vsock gateway,
and signer supervision; chain storage, RPC, indexing, and build tooling belong
on separate hosts. Smaller burstable or single-vCPU shapes cannot provide the
required enclave resources. Recheck regional EC2 pricing before provisioning,
but do not trade signer availability for Spot interruption risk.

## Installation & Compilation

### Quick Start
```bash
# Clone the repository
git clone https://github.com/r3e-network/secure-sign-service-rs.git neo-signer-rs
cd neo-signer-rs

# Build for development (TCP mode)
make tcp
```

### Compilation Commands

#### Mock Mode
```bash
# TCP mode (for testing and development)
make tcp

# Vsock mode (for AWS Nitro Enclave)
make vsock

# Tools (wallet decryption and status checking)
make tools

# Clean build artifacts
make clean
```

#### SGX Mode
```bash
# Build SGX enclave and application
make sgx WALLET_PATH=path/to/your/wallet.json SIGN_KEY=path/to/sgx_sign_private_key.pem
```

#### AWS Nitro Enclave Mode
```bash
# First build the Vsock binary
make vsock

# Linux reports ARM64 as aarch64; make vsock selects the matching MUSL target.
# On a 2-vCPU Graviton parent, run.sh defaults to one enclave vCPU.

# Then build the enclave image
./scripts/nitro/build.sh \
    --wallet path/to/your/wallet.json \
    --bin ../../target/secure-sign-vsock \
    --image secure-sign-nitro

# Sign the enclave with private key and certificate
./scripts/nitro/build.sh \
    --wallet path/to/your/wallet.json \
    --bin ../../target/secure-sign-vsock \
    --key path/to/private-key.pem \
    --cert path/to/certificate.pem
```

The build script uses an ephemeral Docker context and a `scratch` runtime image,
then removes the context on exit. The NEP-6 wallet is never copied into the
source tree. Only the signer and the OpenSSL CMS runtime required to unwrap the
AWS KMS `RecipientInfo` response are present; there is no shell, package
manager, CA bundle, or general-purpose Linux userland. The resulting EIF still
contains the encrypted wallet and must be handled as sensitive infrastructure
material.

The Nitro command is consensus-only by default. It accepts only Neo N3 mainnet
magic `860833102`, `dBFT` extensible payloads, recognized N3 consensus message
types, and a single signer matching the payload sender. Use `--network` when
building a deliberately separate signer for another Neo network.

## Usage

### Mock Mode (Development/Testing)
```bash
# Run with TCP server on localhost
./target/secure-sign-tcp mock \
    --wallet config/nep6_wallet.json \
    --port 9991 \
    --passphrase "your-wallet-passphrase"

# Run with custom port
./target/secure-sign-tcp mock \
    --wallet config/nep6_wallet.json \
    --port 8080 \
    --passphrase "your-wallet-passphrase"
```

### SGX Mode
NOTE: Must run `secure-sign-tools` to decrypt wallet after start up
```bash
# Run SGX application
./scripts/sgx/run.sh \
    --sgx-bin ./secure-sign-sgx/target/secure-sign-sgx \
    --enclave-bin ./secure-sign-sgx-enclave/secure_sign_sgx_enclave.signed.so

# Run as daemon (background process)
./scripts/sgx/run.sh --daemon

# Check SGX application status
ps aux | grep secure-sign-sgx
```

### Vsock Mode (AWS Nitro Enclave)
NOTE: Must run `secure-sign-tools` to decrypt wallet after start up
```bash
# Run the enclave with default settings
./scripts/nitro/run.sh \
    --cpu-count 1 \
    --memory 1024 \
    --cid 2345 \
    --eif-path secure-sign-nitro.eif

# Run in debug mode for development
./scripts/nitro/run.sh \
    --debug \
    --cpu-count 1 \
    --memory 1024 \
    --cid 2345 \
    --eif-path secure-sign-nitro.eif

# Check enclave status
nitro-cli describe-enclaves

# Stop enclave
nitro-cli terminate-enclave --enclave-id <enclave-id>

# Console access (debug mode only)
nitro-cli console --enclave-id <enclave-id>
```

### Remote Consensus Gateway

Keep the enclave startup service private to the parent instance. Expose only
the `SecureSign` service through the gateway on a dedicated WireGuard address:

```bash
make gateway
./target/secure-sign-gateway \
    --listen 10.78.0.1:9991 \
    --enclave-cid 2345 \
    --enclave-port 9991 \
    --network 860833102 \
    --public-key <compressed-council-public-key> \
    --journal-db /var/lib/neo-signer/anti-equivocation.redb \
    --legacy-journal /var/lib/neo-signer/anti-equivocation.log
```

The gateway accepts one request at a time, enforces the configured network and
public key, and durably rejects conflicting prepare/commit or block signatures
for the same consensus slot. Change-view and recovery messages remain retryable
because their payloads can legitimately evolve within a view.

The disk-backed journal uses a 16 MiB page cache, so historical growth does not
increase gateway RSS. On first start it migrates the legacy text journal in
durable bounded batches; later starts verify the imported prefix and process
only newly appended records. Keep the legacy file until the new gateway has
completed migration and a production soak.

The optional daily GAS sweep is a separate, fail-closed economic path. It uses
two independent HTTPS Neo RPC providers, an exact destination allowlist, live
fee/simulation agreement, a minimum 1 GAS reserve, an Asia/Shanghai daily
idempotency journal, and local signature verification before broadcast. The
economic path takes the shared signing permit only for the enclave call, so RPC
latency cannot delay consensus. See [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)
for deployment, scheduling, rollback, and GrokBot-trigger rules.

### Production Service Topology

The supported Nitro deployment installs these units:

| Unit | Responsibility |
|---|---|
| `neo-nitro-enclave.service` | Runs the measured EIF |
| `neo-nitro-unlock.service` | Performs KMS recipient-attestation unlock |
| `neo-nitro-gateway.service` | Exposes the policy gateway on WireGuard only |
| `neo-nitro-health.timer` | Detects failures and restarts the signer target |
| `neo-gas-sweep.service` | Runs one explicit, allowlisted economic sweep |
| `neo-gas-sweep.timer` | Host-local daily fallback with randomized delay |

Install and enable the signer with `sudo ./deploy/install.sh`. The external
automation trigger may start only `neo-gas-sweep.service` through an auditable
remote-execution channel. It must not construct transactions, select a
destination, or call the enclave directly.

The production automation schedule is 09:00 Asia/Shanghai. The host timer runs
at 09:05 Asia/Shanghai with up to five minutes of randomized delay. Both paths
are intentionally safe to overlap: the daily plan and gateway journal ensure
that retries reuse the same bytes and cannot create a second transaction for
the same day.

### EIF and KMS Policy Rotation

Every EIF rebuild changes PCR0. Treat a KMS policy update and an EIF deployment
as one release operation:

1. Record the currently allowed image digest and the candidate EIF PCR0.
2. Temporarily allow both values in the attestation condition.
3. Deploy the candidate EIF and perform a controlled cold start.
4. Require a fresh KMS recipient unlock, signer `Single` status, active gateway,
   advancing consensus journal, and advancing chain height.
5. Replace the transition condition with the candidate digest only and read the
   policy back before declaring the release complete.

Never remove the running measurement before the candidate has completed an
attested cold start. Never leave the previous measurement enabled after the
validation window.

For a production installation, set `SIGNER_BASE`, `SIGNER_TOOL`,
`KMS_CIPHERTEXT_BLOB_PATH`, and `SIGNER_PUBLIC_KEY` in the KMS unlock service.
When `SIGNER_PUBLIC_KEY` is configured, the parent instance does not need a
copy of the encrypted wallet after the EIF has been built.

### Wallet Management Tools
Decrypt wallet and check account status after server is started (for SGX or AWS Nitro modes):
```bash
# Decrypt wallet
./target/secure-sign-tools decrypt --wallet config/nep6_wallet.json

# Check account status
./target/secure-sign-tools status --wallet config/nep6_wallet.json

# Decrypt with passphrase (for mock mode)
./target/secure-sign-tools decrypt \
    --wallet config/nep6_wallet.json \
    --passphrase "your-passphrase"
```

## Configuration

### Wallet Format
The service uses NEP-6 wallet format. Example wallet structure:
```json
{
    "name": "wallet-name",
    "version": "3.0",
    "scrypt": {
        "n": 64,
        "r": 2,
        "p": 2
    },
    "accounts": [
        {
            "address": "<neo-address>",
            "label": null,
            "isdefault": true,
            "lock": false,
            "key": "<encrypted-nep2-key>",
            "contract": {
                "script": "<base64-verification-script>",
                "deployed": false,
                "parameters": [{"name": "signature", "type": "Signature"}]
            }
        }
    ]
}
```

### Environment Variables
- `WALLET_PATH`: Path to the NEP-6 wallet file (for SGX builds)
- `SIGN_KEY`: Path to SGX signing private key (for SGX builds)
- `RUST_LOG`: Log level (e.g., `info`, `debug`, `warn`), Only for mock mode

### Network Configuration
- **TCP Mode**: Listens on localhost with configurable port
- **Vsock Mode**: Uses Vsock protocol with configurable CID and port
- **Default Port**: 9991
- **Default CID**: 2345 (for Vsock mode)

## API Reference
### Protocol Buffers
Service definitions are located in:
- `secure-sign-rpc/proto/servicepb.proto`
- `secure-sign-rpc/proto/startpb.proto`

## Project Structure
```
neo-signer-rs/
├── secure-sign/              # Signer, startup service, and operator tools
├── secure-sign-core/         # Neo validation and cryptographic primitives
├── secure-sign-rpc/          # gRPC and vsock service definitions
├── secure-sign-nitro/        # Nitro Secure Module integration
├── secure-sign-gateway/      # WireGuard-bound parent policy gateway
├── secure-sign-neo-rpc/      # Independent Neo RPC verification
├── secure-sign-sweeper/      # Deterministic daily GAS sweep client
├── secure-sign-sgx/          # SGX host application
├── secure-sign-sgx-enclave/  # SGX enclave implementation
├── deploy/                   # Hardened systemd units and installer
└── scripts/                  # Build, attestation, and unlock helpers
```

## Security Considerations

### Hardware Security
- **SGX Mode**: Leverages Intel SGX for hardware-based memory encryption and isolation
- **Nitro Enclave Mode**: Uses AWS Nitro Enclaves for isolated execution environment
- **Mock Mode**: For development only - not suitable for production

### Key Management
- Private keys are encrypted using NEP-6 standard
- Keys are decrypted only within secure enclaves
- No persistent storage of decrypted keys
- Parent hosts receive only KMS ciphertext for the one-time recipient flow
- Production EIFs and KMS ciphertext are sensitive deployment artifacts even
  though they do not contain plaintext keys
- Startup and signing endpoints must remain private; expose only the
  WireGuard-bound policy gateway
- Rotate KMS attestation policy values with the measured-EIF procedure above

## Release Verification

A release is complete only after all of these gates pass:

```bash
./scripts/check-format.sh
cargo test --workspace
cargo clippy --workspace --all-targets --no-deps -- -D warnings
cargo audit --ignore RUSTSEC-2023-0071
cargo audit --file secure-sign-sgx/Cargo.lock --ignore RUSTSEC-2023-0071
cargo audit --file secure-sign-sgx-enclave/Cargo.lock --ignore RUSTSEC-2023-0071
make linux-arm64
```

The RSA advisory exception is limited to the documented ephemeral key-generation
path; Rust `rsa` decrypt/sign padding APIs are not used. Release artifacts must
be checksummed, the tag must point at the tested commit, and production status
must be read back independently after deployment. See
[docs/RELEASE.md](docs/RELEASE.md) for the complete checklist.
