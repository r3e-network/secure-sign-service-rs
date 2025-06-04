# Secure Sign Service

A high-performance, security-first NEO blockchain signing service designed for **Trusted Execution Environments (TEE)**. Supports **Intel SGX**, **AWS Nitro**, and standard deployments with hardware-enforced security guarantees.

## 🔥 Key Features

- **Multi-TEE Support**: Intel SGX, AWS Nitro Enclaves, standard deployment
- **Two-Phase Security**: Separate wallet decryption and signing phases
- **NEO N3 Ready**: Full NEP-6 wallet support with extensible payload signing
- **Memory Safe**: Rust implementation with automatic key zeroization
- **Production Ready**: Comprehensive monitoring, logging, and deployment guides

## 🚀 Quick Start

### Environment Setup
```bash
# Set up development environment (one-time setup)
./scripts/setup-environment.sh

# Verify everything is working
make check
```

### Standard Deployment
```bash
# Build and run TCP version
make tcp
./target/secure-sign-tcp run --wallet secure-sign/config/nep6_wallet.json

# Decrypt wallet (separate terminal)
./target/secure-sign-tcp decrypt
```

### AWS Nitro Deployment  
```bash
# Build VSOCK version
make vsock
./target/secure-sign-vsock run --wallet secure-sign/config/nep6_wallet.json --cid 3
```

### Intel SGX Deployment
```bash
# Build SGX version (requires Intel SGX SDK)
make sgx
./target/secure-sign-sgx run --wallet secure-sign/config/nep6_wallet.json --enclave enclave.signed.so
```

## 📦 Project Structure

```
secure-sign-service-rs/
├── secure-sign/          # Main CLI application
├── secure-sign-core/     # Cryptographic engine (NEO N3, secp256r1)
├── secure-sign-rpc/      # gRPC API layer
├── secure-sign-nitro/    # AWS Nitro Enclaves support
├── secure-sign-sgx/      # Intel SGX host application
├── secure-sign-sgx-enclave/  # Intel SGX enclave implementation
└── docs/                 # Comprehensive documentation
```

## 🔧 Build Requirements

**All Deployments:**
- Rust 1.70+
- Protocol Buffers compiler (`protoc`)

**VSOCK/Nitro:**
- Target: `rustup target add x86_64-unknown-linux-musl`

**Intel SGX:**
- Intel SGX SDK
- Target: `rustup target add x86_64-fortanix-unknown-sgx`

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design and security model |
| [Configuration](docs/configuration.md) | Setup and configuration guide |
| [API Reference](docs/api.md) | gRPC API documentation |
| [API Examples](docs/examples.md) | Client code examples in multiple languages |
| [Deployment](docs/deployment.md) | Production deployment strategies |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and solutions |
| [Security Policy](SECURITY.md) | Security practices and vulnerability reporting |

## 🔒 Security Model

### Two-Phase Operation
1. **Startup Phase**: Secure wallet decryption via ECDH + AES-GCM
2. **Signing Phase**: Cryptographic operations with protected keys

### Trust Boundaries
- **Standard**: Process isolation + memory safety
- **VSOCK/Nitro**: Hardware-enforced enclave isolation  
- **SGX**: CPU-level attestation + sealed storage

## 🛠️ Development

```bash
# Run all checks
make check

# Run tests
make test

# Build all targets
make all-targets

# Development server
make dev-tcp

# Security & Quality
make security          # Comprehensive security audit
make audit            # Dependency security check
make sbom             # Generate Software Bill of Materials
make pre-commit       # Pre-commit quality checks
```

## 🔍 Monitoring

```bash
# Health check
./scripts/health-check.sh -v

# Service status
systemctl status secure-sign

# Security audit
./scripts/security-audit.sh

# Continuous monitoring
watch -n 30 ./scripts/health-check.sh
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright © 2025 R3E Network

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:

- **Security-first development** practices
- **Code standards** and review process  
- **Testing requirements** and guidelines
- **Documentation** standards

For security vulnerabilities, please see our [Security Policy](SECURITY.md).

---

**Production Ready** • **TEE Optimized** • **NEO N3 Native**
