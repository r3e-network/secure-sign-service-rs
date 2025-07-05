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
