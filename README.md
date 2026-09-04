# Secure Sign Service

## Overview
This is a secure sign service for NEO (https://github.com/neo-project).
It provides secure signing capabilities through multiple deployment modes with hardware-based security features.

### Deployment Modes
- **Mock Mode**: For development and testing purposes
- **SGX Mode**: For Intel SGX enclave deployment with hardware security
- **AWS Nitro Enclave Mode**: For AWS Nitro Enclave deployment with isolated execution

### Key Features
- Hardware-based security through SGX and Nitro Enclaves
- Secure key storage and management
- Encrypted wallet support (NEP-6 format)
- Isolated execution environments
- A WireGuard-bound consensus gateway with persistent anti-equivocation checks

## Prerequisites
NOTE: This is service for manageing private keys in scure.
So it needs to be compiled manually. And the compiled product may needs to be signed(See how to sign SGX binary and AWS Nitrol Enclave image).

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
git clone <repository-url>
cd secure-sign-service-rs

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
    --cpu-count 2 \
    --memory 512 \
    --cid 2345 \
    --eif-path secure-sign-nitro.eif

# Run in debug mode for development
./scripts/nitro/run.sh \
    --debug \
    --cpu-count 2 \
    --memory 512 \
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
    --journal /var/lib/neo-signer/anti-equivocation.log
```

The gateway accepts one request at a time, enforces the configured network and
public key, and durably rejects conflicting prepare/commit or block signatures
for the same consensus slot. Change-view and recovery messages remain retryable
because their payloads can legitimately evolve within a view.

The optional daily GAS sweep is a separate, fail-closed economic path. It uses
two independent HTTPS Neo RPC providers, an exact destination allowlist, live
fee/simulation agreement, a minimum 1 GAS reserve, an Asia/Shanghai daily
idempotency journal, and local signature verification before broadcast. The
economic path takes the shared signing permit only for the enclave call, so RPC
latency cannot delay consensus. See [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)
for deployment, scheduling, rollback, and GrokBot-trigger rules.

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
            "address": "NUz6PKTAM7NbPJzkKJFNay3VckQtcDkgWo",
            "label": null,
            "isdefault": true,
            "lock": false,
            "key": "6PYWucwbu5pQV9j1wq9kyb571qxUhqDK6vcTsGQtoJXuErzhfptc72RdGF",
            "contract": {
                "script": "DCECb/A7lJJBzh2t1DUZ5pYOCoW0GmmgXDKBA6orzhWUyhZBVuezJw==",
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
secure-sign-service-rs/
├── secure-sign/              # Main application with mock mode
├── secure-sign-core/         # Core cryptographic and NEO functionality
├── secure-sign-sgx/          # SGX enclave application
├── secure-sign-sgx-enclave/  # SGX enclave implementation
├── secure-sign-nitro/        # AWS Nitro Enclave specific code
├── secure-sign-rpc/          # RPC service definitions
│   ├── nitro/               # AWS Nitro Enclave scripts
│   └── sgx/                 # SGX scripts
└── config/                  # Configuration files
    └── nep6_wallet.json     # Example wallet
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
