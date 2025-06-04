# Security Guide

## Overview

The Secure Sign Service implements defense-in-depth security for NEO blockchain signing operations with support for Trusted Execution Environments (TEE).

## Core Security Features

### Cryptographic Foundation
- **P-256 (secp256r1)**: NIST-approved elliptic curve cryptography
- **AES-256-GCM**: Authenticated encryption for wallet storage and communication
- **Scrypt Key Derivation**: Configurable parameters for key stretching
- **Memory Zeroization**: Automatic clearing of sensitive data using Rust `zeroize` crate
- **Constant-time Operations**: Side-channel attack resistance

### Two-Phase Security Protocol

#### Phase 1: Secure Wallet Decryption
1. **ECDH Key Exchange**: Client and service establish shared secret with ephemeral keys
2. **Encrypted Transmission**: Wallet passphrase encrypted with AES-256-GCM
3. **Perfect Forward Secrecy**: Session keys destroyed after use

#### Phase 2: Protected Signing Operations
1. **In-Memory Keys**: Private keys exist only in protected memory
2. **Input Validation**: All requests validated before processing
3. **Automatic Cleanup**: Keys zeroized on service shutdown

## Security Architecture

### Trust Boundaries

| Deployment | Memory Protection | Key Storage | Attestation |
|------------|------------------|-------------|-------------|
| TCP | Process isolation | System memory | None |
| VSOCK/Nitro | Hardware enclave | Enclave memory | AWS attestation |
| SGX | CPU-level isolation | Sealed storage | Intel attestation |

### Threat Model

**Protected Assets:**
- Private signing keys
- Wallet passphrases
- Signature operations
- Service availability

**Attack Mitigations:**
- **Memory attacks**: Rust memory safety + automatic zeroization
- **Network attacks**: ECDH key exchange + AES encryption
- **Side-channel attacks**: Constant-time cryptographic operations
- **Physical access**: Encrypted storage + TEE isolation

## Implementation Security

### Memory Safety
```rust
// Automatic cleanup of sensitive data
use zeroize::Zeroizing;

let sensitive_data = Zeroizing::new(wallet_passphrase);
// Automatically zeroed when dropped
```

### Error Handling
- **No information leakage**: Generic error messages for external clients
- **Fail-safe defaults**: Secure configuration when errors occur
- **Proper propagation**: Errors handled at appropriate security boundaries

### Input Validation
- Public key format verification (33/65 bytes)
- Network ID validation (mainnet/testnet)
- Payload structure validation
- Parameter bounds checking

## Deployment Security

### Service Configuration
```bash
# Secure file permissions
chmod 600 config/wallet.json
chmod 755 /usr/local/bin/secure-sign

# Network binding (localhost only by default)
--port 9991  # Binds to 127.0.0.1:9991

# VSOCK for TEE environments
--cid 3      # Uses AF_VSOCK instead of TCP
```

### Process Security
- **Minimal privileges**: Non-root execution
- **Resource limits**: Memory and CPU constraints
- **File access**: Read-only wallet files, write-only logs
- **Network access**: Specific ports only

### TEE-Specific Security

#### Intel SGX
- **Hardware attestation**: CPU-level trust verification
- **Sealed storage**: Keys protected by hardware
- **Enclave isolation**: Code and data protection
- **Remote verification**: Intel Attestation Service integration

#### AWS Nitro
- **Enclave isolation**: Hardware-enforced boundaries
- **VSOCK communication**: Secure host-enclave channel
- **Attestation documents**: Cryptographic proof of execution
- **No persistent storage**: Stateless operation

## Operational Security

### Key Management Best Practices
```bash
# Wallet file security
sudo chown secure-sign:secure-sign /opt/secure-sign/config/wallet.json
sudo chmod 600 /opt/secure-sign/config/wallet.json

# Service user isolation
sudo useradd -r -s /bin/false secure-sign
```

### Network Security
```bash
# Firewall configuration (localhost only)
sudo ufw allow from 127.0.0.1 to any port 9991
sudo ufw deny 9991

# Or with iptables
sudo iptables -A INPUT -i lo -p tcp --dport 9991 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9991 -j DROP
```

### Monitoring & Incident Response
```bash
# Security event monitoring
journalctl -u secure-sign -f | grep -i "error\|fail\|invalid"

# Process monitoring
ps aux | grep secure-sign
netstat -tuln | grep :9991

# Resource monitoring
systemctl status secure-sign
```

## Security Testing

### Recommended Validation
1. **Cryptographic correctness**: Verify signature outputs
2. **Memory safety**: Test for leaks and proper cleanup
3. **Input fuzzing**: Malformed request handling
4. **Side-channel resistance**: Timing analysis
5. **TEE attestation**: Remote verification testing

### Security Tools
```bash
# Static analysis
cargo clippy --all-targets
cargo audit

# Memory testing
valgrind --tool=memcheck ./target/release/secure-sign

# Fuzzing (example)
cargo fuzz run fuzz_signing_requests
```

## Security Limitations & Mitigations

### Current Limitations
1. **No built-in authentication**: Service trusts all localhost connections
2. **Single-user operation**: Designed for single tenant use
3. **No persistent audit log**: Logs may be rotated/lost
4. **Limited rate limiting**: No built-in DoS protection

### Recommended Mitigations
1. **Network authentication**: Use reverse proxy with mTLS
2. **Access control**: Deploy in isolated environment
3. **Audit logging**: External log aggregation
4. **Rate limiting**: Proxy-level or firewall rate limits

### Production Deployment Security
```bash
# Example systemd security settings
[Service]
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/secure-sign/logs
DevicePolicy=closed
MemoryDenyWriteExecute=true
```

## Compliance Considerations

### Standards Compliance
- **FIPS 140-2**: P-256 curve approved for government use
- **Common Criteria**: Memory-safe implementation
- **SOC 2**: Operational security controls
- **ISO 27001**: Information security management

### Audit Requirements
1. **Code audit**: Third-party security code review
2. **Cryptographic audit**: Verification of crypto implementations
3. **Operational audit**: Deployment and configuration review
4. **Penetration testing**: External security assessment

## Emergency Procedures

### Security Incident Response
1. **Immediate**: Stop service if breach suspected
2. **Isolate**: Disconnect from network if necessary
3. **Preserve**: Capture memory dumps and logs
4. **Investigate**: Analyze for indicators of compromise
5. **Recover**: Restore from known-good state
6. **Prevent**: Update security measures

### Key Compromise Response
1. **Revoke**: Invalidate compromised keys immediately
2. **Rotate**: Generate new wallet and keys
3. **Audit**: Review all recent signing operations
4. **Notify**: Inform stakeholders of potential impact

---

**Security is a shared responsibility.** This document provides technical controls; operational security depends on proper deployment, monitoring, and incident response procedures. 