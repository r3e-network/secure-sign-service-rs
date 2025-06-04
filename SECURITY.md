# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

The security of the Secure Sign Service is our top priority. We appreciate your efforts to responsibly disclose security vulnerabilities.

### Reporting Process

**Do NOT** report security vulnerabilities through public GitHub issues, discussions, or pull requests.

Instead, please report security vulnerabilities by emailing: **security@r3e.network**

### What to Include

Please include as much of the following information as possible:

- **Type of issue** (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
- **Full paths** of source file(s) related to the manifestation of the issue
- **Location** of the affected source code (tag/branch/commit or direct URL)
- **Special configuration** required to reproduce the issue
- **Step-by-step instructions** to reproduce the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact** of the issue, including how an attacker might exploit it

### Response Timeline

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours
- **Initial Assessment**: We will provide an initial assessment within 5 business days
- **Status Updates**: We will keep you informed of our progress every 10 business days
- **Resolution**: We aim to resolve critical vulnerabilities within 30 days

### Safe Harbor

We support safe harbor for security researchers who:

- Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our services
- Only interact with accounts you own or with explicit permission of the account holder
- Do not access a system beyond what is necessary to demonstrate a vulnerability
- Report vulnerabilities as soon as possible after discovery
- Do not download or modify user data; instead use only "touch" files or non-sensitive test data

## Security Features

### Cryptographic Security
- **secp256r1** elliptic curve cryptography
- **AES-256-GCM** symmetric encryption
- **scrypt** key derivation function
- **HMAC-SHA256** message authentication
- **Secure random number generation**

### Memory Safety
- **Rust memory safety** guarantees
- **Automatic zeroization** of sensitive data
- **Constant-time operations** where applicable
- **No unsafe code** in cryptographic paths

### Platform Security
- **Trusted Execution Environment** support (Intel SGX, AWS Nitro)
- **Hardware-based attestation**
- **Secure communication** channels (VSOCK)
- **Process isolation**

### Network Security
- **gRPC transport security**
- **Input validation** and sanitization
- **Rate limiting** considerations
- **Localhost binding** by default

## Security Considerations

### Threat Model
Our threat model assumes:
- **Network adversaries** can monitor and modify network traffic
- **Host compromise** is possible outside the TEE
- **Side-channel attacks** may be attempted
- **Supply chain attacks** are a concern

### Out of Scope
The following are explicitly out of scope:
- Physical attacks on hardware
- Social engineering attacks
- Attacks requiring physical access to the server
- Vulnerabilities in third-party dependencies (report to maintainers)

## Security Best Practices

### For Developers
- Review all cryptographic code carefully
- Use `cargo clippy` and `cargo audit` regularly
- Follow secure coding practices
- Test in isolation environments

### For Operators
- Keep systems updated
- Use strong wallet passphrases
- Secure file permissions (600 for wallets)
- Monitor for suspicious activity
- Use network firewalls
- Deploy in TEE environments when possible

### For Users
- Verify binary signatures when available
- Use secure communication channels
- Keep wallet files encrypted and backed up
- Use strong, unique passphrases
- Monitor account activity

## Vulnerability Disclosure Timeline

1. **Day 0**: Vulnerability reported
2. **Day 1-2**: Acknowledgment sent
3. **Day 3-7**: Initial assessment and triage
4. **Day 8-30**: Investigation and fix development
5. **Day 31**: Public disclosure coordination
6. **Day 32+**: Fix deployment and public disclosure

## Security Contacts

- **Primary**: security@r3e.network
- **GPG Key**: [Request via email]
- **Emergency**: Use Signal for time-sensitive issues (contact via email for phone number)

## Recognition

We maintain a hall of fame for security researchers who help improve our security:

- *Your name could be here!*

## Legal

This policy is designed to be compatible with common vulnerability disclosure good practices. It does not give you permission to access our systems in ways that are otherwise prohibited by law or our terms of service.

---

**Last Updated**: January 2025 