# Architecture Guide

## Overview

The Secure Sign Service is designed as a modular, security-first cryptographic signing service that can operate in various trusted execution environments (TEEs). The architecture prioritizes security, performance, and maintainability.

## System Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Applications                       │
│                   (decrypt, status)                         │
└─────────────────────┬───────────────────────────────────────┘
                      │ gRPC over TCP/VSOCK
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              Two-Phase Service Architecture                 │
├─────────────────────────────────────────────────────────────┤
│  Phase 1: StartupService    │  Phase 2: SecureSign          │
│  ┌─────────────────────────┐│ ┌─────────────────────────────┐│
│  │     DiffieHellman      ││ │   SignExtensiblePayload    ││
│  │     StartSigner        ││ │   SignBlock               ││
│  │                        ││ │   GetAccountStatus        ││
│  └─────────────────────────┘│ └─────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                 secure-sign-rpc (gRPC Layer)               │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │  Protocol   │ │   Service   │ │  Transport  │            │
│  │   Buffers   │ │    Impl     │ │ (TCP/VSOCK) │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              secure-sign-core (Crypto Engine)               │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │   NEO N3    │ │ Cryptographic│ │    NEP-6    │            │
│  │ Blockchain  │ │  Primitives  │ │   Wallets   │            │
│  │  Support    │ │ (P-256, AES) │ │             │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
└─────────────────────────────────────────────────────────────┘
```

## Component Details

### Core Modules

#### secure-sign (Main Application)
- **Purpose**: Application entry point and orchestration
- **Responsibilities**:
  - Command-line interface handling
  - Configuration management
  - Service lifecycle management
  - Signal handling and graceful shutdown
- **Key Files**:
  - `main.rs`: Entry point and CLI parsing
  - `run.rs`: Production service runner
  - `mock.rs`: Development/testing service
  - `tools.rs`: Utility commands (decrypt, status)

#### secure-sign-core (Cryptographic Engine)
- **Purpose**: Core cryptographic operations and NEO blockchain support
- **Responsibilities**:
  - Elliptic curve cryptography (secp256r1)
  - Key derivation and management
  - NEO-specific signing operations
  - Secure memory management
- **Key Components**:
  - **Cryptographic Primitives**: ECDSA, AES, HMAC, Hash functions
  - **NEO Support**: NEP-2/NEP-6 wallet formats, transaction signing
  - **Data Types**: H160, H256 hash types, secure binary handling
  - **Memory Safety**: Automatic zeroization of sensitive data

#### secure-sign-rpc (gRPC Interface)
- **Purpose**: Network communication layer
- **Responsibilities**:
  - gRPC service implementation
  - Protocol buffer serialization
  - Transport layer abstraction (TCP/VSOCK)
  - Client session management
- **Features**:
  - Extensible payload signing
  - Block header signing
  - Account status queries
  - Multi-signature support

#### secure-sign-nitro (AWS Nitro Enclaves)
- **Purpose**: AWS Nitro Enclave-specific functionality
- **Responsibilities**:
  - Nitro-specific attestation
  - VSOCK communication
  - Enclave lifecycle management

#### secure-sign-sgx (Intel SGX)
- **Purpose**: Intel SGX enclave support for trusted execution
- **Responsibilities**:
  - SGX enclave lifecycle management
  - Hardware-based key attestation
  - Memory-safe enclave operations
  - VSOCK communication within enclaves
- **Status**: Fully implemented and functional

## Security Architecture

### Threat Model

#### Assets to Protect
1. **Private Keys**: Cryptographic signing keys
2. **Wallet Data**: Encrypted wallet files and metadata
3. **Signed Transactions**: Integrity of signing operations
4. **Service Availability**: Protection against DoS attacks

#### Trust Boundaries
1. **TEE Boundary**: Code and data within the trusted execution environment
2. **Network Boundary**: gRPC communication layer
3. **Storage Boundary**: Persistent key storage mechanisms
4. **Process Boundary**: Application isolation from other processes

#### Security Controls

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Layers                          │
├─────────────────────────────────────────────────────────────┤
│  Application Security                                       │
│  ├─ Input Validation                                        │
│  ├─ Memory Safety (Rust + zeroize)                         │
│  └─ Secure Error Handling                                  │
├─────────────────────────────────────────────────────────────┤
│  Cryptographic Security                                     │
│  ├─ Constant-time Operations                               │
│  ├─ Secure Random Number Generation                        │
│  └─ Key Derivation (scrypt)                               │
├─────────────────────────────────────────────────────────────┤
│  Network Security                                           │
│  ├─ gRPC Transport Security                                │
│  ├─ Input Sanitization                                     │
│  └─ Rate Limiting                                          │
├─────────────────────────────────────────────────────────────┤
│  Platform Security                                          │
│  ├─ TEE Isolation (SGX/Nitro)                             │
│  ├─ Remote Attestation                                     │
│  └─ Sealed Storage                                         │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

### Signing Request Flow

```
Client Request
      │
      ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   gRPC      │───▶│  Request    │───▶│ Validation  │
│  Transport  │    │ Parsing     │    │  & Auth     │
└─────────────┘    └─────────────┘    └─────────────┘
                                               │
                                               ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  Response   │◀───│  Signature  │◀───│    Key      │
│  Encoding   │    │ Generation  │    │  Retrieval  │
└─────────────┘    └─────────────┘    └─────────────┘
      │
      ▼
Client Response
```

### Key Management Flow

```
Encrypted Wallet
      │
      ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Wallet    │───▶│ Decryption  │───▶│    Key      │
│   Loading   │    │  (scrypt +  │    │ Extraction  │
│             │    │   AES-GCM)  │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
                                               │
                                               ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Secure    │◀───│   Memory    │◀───│   Private   │
│   Storage   │    │  Protection │    │    Key      │
│   (TEE)     │    │ (zeroize)   │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
```

## Performance Considerations

### Optimization Strategies

1. **Memory Management**
   - Zero-copy operations where possible
   - Efficient buffer reuse
   - Automatic cleanup of sensitive data

2. **Cryptographic Performance**
   - Hardware acceleration where available
   - Optimized elliptic curve implementations
   - Batch processing for multiple signatures

3. **Network Efficiency**
   - Protocol buffer binary encoding
   - Connection pooling
   - VSOCK for TEE environments

### Scalability Design

- **Stateless Service**: No persistent state between requests
- **Concurrent Processing**: Tokio async runtime
- **Resource Limits**: Configurable memory and CPU limits
- **Load Balancing**: Multiple instance support

## Configuration Architecture

The service uses a simple command-line interface without complex configuration files:

### Configuration Sources

```
┌─────────────────────────────────────┐
│        Environment Variables        │  (RUST_LOG=debug)
├─────────────────────────────────────┤
│         Command Line Args           │  (--wallet, --port, --cid)
├─────────────────────────────────────┤
│            NEP-6 Wallet             │  (Encrypted wallet file)
├─────────────────────────────────────┤
│           Default Values            │  (Built-in defaults)
└─────────────────────────────────────┘
```

### Configuration Options

- **Transport**: TCP (default) or VSOCK (--cid > 0)
- **Port**: Service binding port (default: 9991)
- **Wallet**: NEP-6 wallet file path (required)
- **Logging**: Controlled via RUST_LOG environment variable

## Deployment Patterns

### Standard Deployment
- Direct binary execution
- Docker containers
- Systemd service

### TEE-Ready Features
- VSOCK transport support
- Memory-safe implementation
- Feature flag compilation

### Development Patterns
- Mock service for testing (with plain-text passphrase)
- Local development environments
- Simple build system with make targets

## Extension Points

### Adding New TEE Platforms
1. Create new crate (e.g., `secure-sign-trustzone`)
2. Implement platform-specific attestation
3. Add transport layer support
4. Update build system

### Adding New Blockchain Support
1. Extend `secure-sign-core` with new crypto primitives
2. Add protocol buffer definitions
3. Implement signing algorithms
4. Add configuration support

### Custom Authentication
1. Implement authentication middleware
2. Add to gRPC service layer
3. Configure via configuration files
4. Integrate with existing session management

## Observability

### Logging
- Standard Rust logging via `log` crate
- Configurable via `RUST_LOG` environment variable
- Supports levels: trace, debug, info, warn, error

### Process Monitoring
- Standard process monitoring via systemd
- Resource usage via system tools (ps, top, etc.)
- Log file monitoring and rotation

### Service Health
- Process-based health checking
- Port availability monitoring
- Basic status command for account queries 