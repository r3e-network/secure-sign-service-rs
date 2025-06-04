# Configuration Guide

## Overview

The Secure Sign Service uses a simple command-line interface for configuration. There is no complex configuration file system - all settings are provided via command-line arguments.

## Command Structure

The service operates through subcommands with their respective options:

```bash
secure-sign <COMMAND> [OPTIONS]
```

## Available Commands

### `run` - Production Service

Starts the service with an encrypted NEP-6 wallet file.

```bash
secure-sign run --wallet <WALLET_FILE> [--port <PORT>] [--cid <CID>]
```

**Options:**
- `--wallet <WALLET_FILE>`: Path to the NEP-6 wallet file (required)
- `--port <PORT>`: Listen port (default: 9991)
- `--cid <CID>`: VSOCK context identifier (default: 0, use 0 for TCP)

**Example:**
```bash
# TCP mode (standard)
./target/secure-sign-tcp run --wallet config/wallet.json --port 9991

# VSOCK mode (for TEE environments)
./target/secure-sign-vsock run --wallet config/wallet.json --port 9991 --cid 3
```

### `mock` - Development Service

Starts the service with a pre-decrypted wallet (development/testing only).

```bash
secure-sign mock --wallet <WALLET_FILE> --passphrase <PASSPHRASE> [--port <PORT>] [--cid <CID>]
```

**Options:**
- `--wallet <WALLET_FILE>`: Path to the NEP-6 wallet file (required)
- `--passphrase <PASSPHRASE>`: Wallet decryption passphrase (required)
- `--port <PORT>`: Listen port (default: 9991)
- `--cid <CID>`: VSOCK context identifier (default: 0 for TCP)

**Example:**
```bash
./target/secure-sign-tcp mock --wallet config/wallet.json --passphrase "my-secret-password" --port 9991
```

### `decrypt` - Wallet Decryption Tool

Connects to a running service to provide the wallet passphrase securely.

```bash
secure-sign decrypt [--port <PORT>] [--cid <CID>]
```

**Options:**
- `--port <PORT>`: Service port (default: 9991)
- `--cid <CID>`: VSOCK context identifier (default: 0 for TCP)

**Example:**
```bash
# Connect to TCP service
./target/secure-sign-tcp decrypt --port 9991

# Connect to VSOCK service
./target/secure-sign-vsock decrypt --port 9991 --cid 3
```

### `status` - Account Status Query

Queries the status of a specific account by public key.

```bash
secure-sign status --public-key <PUBLIC_KEY> [--port <PORT>] [--cid <CID>]
```

**Options:**
- `--public-key <PUBLIC_KEY>`: Hex-encoded public key (required)
- `--port <PORT>`: Service port (default: 9991)
- `--cid <CID>`: VSOCK context identifier (default: 0 for TCP)

**Example:**
```bash
./target/secure-sign-tcp status --public-key 03b4af8d061b6b320cce6c63bc4ec7894dce107bfc5f5ef5c68a93b4ad1e136816 --port 9991
```

## NEP-6 Wallet Configuration

The service uses standard NEP-6 wallet files. Here's the structure:

```json
{
  "name": "MyWallet",
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

### Scrypt Parameters

The `scrypt` section configures key derivation:
- `n`: CPU/memory cost parameter (power of 2)
- `r`: Block size parameter
- `p`: Parallelization parameter

Higher values increase security but require more resources for decryption.

## Environment Variables

Logging can be controlled via environment variables:

```bash
# Enable debug logging
export RUST_LOG=debug

# Enable specific module logging
export RUST_LOG=secure_sign=debug

# Enable all logging
export RUST_LOG=trace
```

## Transport Configuration

### TCP Mode (Default)

TCP mode binds to localhost for security:
- Default binding: `127.0.0.1:<port>`
- Uses standard TCP sockets
- Suitable for standard environments

### VSOCK Mode

VSOCK mode is designed for TEE environments:
- Requires `--cid` parameter > 0
- Uses AF_VSOCK sockets
- Suitable for SGX enclaves, Nitro enclaves, etc.

### Intel SGX Mode

For Intel SGX enclave deployments:

#### Prerequisites
```bash
# Install Intel SGX SDK
# Download from: https://software.intel.com/content/www/us/en/develop/topics/software-guard-extensions/sdk.html

# Install Rust SGX target
rustup target add x86_64-fortanix-unknown-sgx

# Generate SGX signing key (first time only)
openssl genrsa -out sgx_sign_private_key.pem -3 3072
```

#### Building SGX Version
```bash
# Build for hardware SGX
make sgx

# Build for software simulation
SGX_MODE=SW make sgx

# Build for Alibaba Cloud
cd secure-sign-sgx-enclave && ./build.sh --aliyun
```

#### Running SGX Service
```bash
# Start SGX service
./target/secure-sign-sgx run --wallet config/wallet.json --enclave secure_sign_sgx_enclave.signed.so

# Decrypt wallet (in another terminal)
secure-sign decrypt --port 9991
```

#### SGX Configuration Options
- `--enclave`: Path to signed SGX enclave (.so file)
- `--wallet`: Path to NEP-6 wallet file (loaded into enclave at runtime)
- `--debug`: Enable debug mode for development
- `--port`: Service port (default: 9991)

## Build-time Configuration

Feature flags control transport capabilities:

```bash
# Build with TCP support (default)
cargo build --release

# Build with VSOCK support
cargo build --release --features vsock

# Build with TCP support explicitly
cargo build --release --features tcp
```

**Note:** TCP and VSOCK features are mutually exclusive.

## Security Considerations

### File Permissions

Ensure wallet files have restricted permissions:

```bash
chmod 600 config/nep6_wallet.json
```

### Network Security

- Service binds to localhost by default (127.0.0.1)
- Use firewall rules to restrict access
- Consider using a reverse proxy for TLS termination

### Passphrase Security

- Use strong, unique passphrases
- Never pass passphrases via command line in production
- Use the `decrypt` command for secure passphrase input

## Common Usage Patterns

### Development Workflow

```bash
# 1. Start mock service for testing
./target/secure-sign-tcp mock --wallet config/test_wallet.json --passphrase "test123"

# 2. Test account status
./target/secure-sign-tcp status --public-key 03b4af8d... --port 9991
```

### Production Workflow

```bash
# 1. Start production service
./target/secure-sign-tcp run --wallet config/wallet.json --port 9991

# 2. In another terminal, decrypt wallet
./target/secure-sign-tcp decrypt --port 9991
# (Enter passphrase when prompted)

# 3. Service is now ready for signing operations
```

### VSOCK/TEE Workflow

```bash
# 1. Start service in VSOCK mode
./target/secure-sign-vsock run --wallet config/wallet.json --port 9991 --cid 3

# 2. Decrypt from host system
./target/secure-sign-vsock decrypt --port 9991 --cid 3
```

## Troubleshooting

### Common Issues

1. **Port already in use**
   ```bash
   netstat -tulpn | grep :9991
   ```

2. **Wallet file not found**
   ```bash
   ls -la config/nep6_wallet.json
   ```

3. **Permission denied**
   ```bash
   chmod 600 config/nep6_wallet.json
   ```

4. **VSOCK not available**
   ```bash
   ls -la /dev/vsock
   modprobe vsock
   ```

### Debug Information

Enable verbose logging for troubleshooting:

```bash
RUST_LOG=debug ./target/secure-sign-tcp run --wallet config/wallet.json
```

This will provide detailed information about:
- Service startup
- Wallet loading
- Network binding
- Request processing
- Error conditions 