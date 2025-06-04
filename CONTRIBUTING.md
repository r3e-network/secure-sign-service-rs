# Contributing to Secure Sign Service

Thank you for your interest in contributing to the Secure Sign Service! This document provides guidelines for contributing to this security-critical blockchain infrastructure project.

## 🔒 Security First

This is a **security-critical** project handling private keys and cryptographic operations. All contributions must meet the highest security standards.

### Security Review Process
- All code changes undergo mandatory security review
- Cryptographic changes require specialized review
- Dependencies are strictly controlled and audited
- No exceptions for security requirements

## 🚀 Getting Started

### Prerequisites
```bash
# Set up your development environment
./scripts/setup-environment.sh

# Verify everything works
make check
```

### Development Workflow
```bash
# 1. Format code
make format

# 2. Run linting
make lint

# 3. Run tests
make test

# 4. Security audit
make security

# 5. Pre-commit checks
make pre-commit
```

## 📋 Contribution Guidelines

### Code Standards
- **Rust Edition**: 2021
- **MSRV**: 1.70.0
- **Formatting**: Use `cargo fmt` with project `rustfmt.toml`
- **Linting**: All `clippy` warnings must be addressed
- **Documentation**: All public APIs must be documented

### Security Requirements
- **No unsafe code** in core cryptographic modules
- **Memory safety**: Use `zeroize` for sensitive data
- **Constant-time operations** where applicable
- **Input validation** on all external inputs
- **Error handling**: No panics in production code paths

### Testing Requirements
- **Unit tests** for all new functionality
- **Integration tests** for API endpoints
- **Security tests** for cryptographic operations
- **Test coverage** must not decrease

### Documentation Requirements
- **Update README.md** if adding new features
- **API documentation** for all public interfaces
- **Inline comments** for complex algorithms
- **Architecture docs** for significant changes

## 🔄 Pull Request Process

### Before Submitting
1. **Fork the repository** and create a feature branch
2. **Run full test suite**: `make production-ready`
3. **Update documentation** as needed
4. **Write descriptive commit messages**

### PR Requirements
- **Clear description** of changes and motivation
- **Security impact assessment** for all changes
- **Breaking change** documentation if applicable
- **Test coverage** for new functionality

### Review Process
1. **Automated checks** must pass (CI/CD pipeline)
2. **Security review** by maintainers
3. **Code review** by at least one maintainer
4. **Final approval** by project leads

## 🛠️ Development Guidelines

### Branching Strategy
- **main**: Production-ready code
- **develop**: Integration branch
- **feature/**: New features
- **security/**: Security fixes
- **hotfix/**: Critical production fixes

### Commit Message Format
```
type(scope): brief description

Detailed explanation of the change, including:
- What was changed and why
- Security implications if any
- Breaking changes if any

Closes #issue-number
```

Types: `feat`, `fix`, `security`, `docs`, `style`, `refactor`, `test`, `chore`

### Code Organization
```
secure-sign-service-rs/
├── secure-sign/          # Main CLI application
├── secure-sign-core/     # Cryptographic primitives
├── secure-sign-rpc/      # gRPC API layer
├── secure-sign-nitro/    # AWS Nitro support
├── docs/                 # Documentation
├── scripts/              # Operational scripts
├── monitoring/           # Monitoring configs
└── config/               # Configuration templates
```

## 🚨 Security Vulnerabilities

**DO NOT** report security vulnerabilities through public issues!

### Reporting Process
1. **Email**: security@r3e.network
2. **Include**: Detailed description, reproduction steps, impact assessment
3. **Response**: We will acknowledge within 48 hours
4. **Disclosure**: Coordinated disclosure after fix is ready

### Safe Harbor
We support responsible security research under safe harbor guidelines outlined in [SECURITY.md](SECURITY.md).

## 🧪 Testing

### Running Tests
```bash
# All tests
make test

# Specific test types
cargo test --lib                    # Unit tests
cargo test --test integration_tests # Integration tests
cargo test --doc                    # Documentation tests
```

### Test Categories
- **Unit Tests**: Fast, isolated functionality tests
- **Integration Tests**: End-to-end API testing
- **Security Tests**: Cryptographic correctness
- **Performance Tests**: Benchmark critical paths

### Test Requirements
- **Fast execution**: Unit tests should run quickly
- **Deterministic**: No flaky tests allowed
- **Isolated**: No external dependencies
- **Comprehensive**: Cover edge cases and error conditions

## 📚 Documentation

### Types of Documentation
- **API Documentation**: Generated from code comments
- **User Guides**: How to use the service
- **Developer Guides**: How to contribute
- **Security Documentation**: Threat model and controls
- **Deployment Guides**: Production deployment

### Documentation Standards
- **Clear and concise** writing
- **Code examples** for all APIs
- **Security considerations** for all operations
- **Up-to-date** with current implementation

## 🔍 Code Review Checklist

### Security Review
- [ ] No hardcoded secrets or keys
- [ ] Proper input validation
- [ ] Secure error handling
- [ ] Memory safety considerations
- [ ] Cryptographic correctness

### Code Quality Review
- [ ] Follows Rust idioms
- [ ] Proper error handling
- [ ] Comprehensive tests
- [ ] Documentation updates
- [ ] Performance considerations

### Functional Review
- [ ] Meets requirements
- [ ] Backward compatibility
- [ ] Integration testing
- [ ] User experience
- [ ] Edge case handling

## 📞 Getting Help

### Communication Channels
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Security Issues**: security@r3e.network
- **Documentation**: Check [docs/](docs/) directory

### Project Structure Help
- **Architecture**: See [docs/architecture.md](docs/architecture.md)
- **API Reference**: See [docs/api.md](docs/api.md)
- **Troubleshooting**: See [docs/troubleshooting.md](docs/troubleshooting.md)

## 📝 License

By contributing to this project, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

Contributors will be recognized in:
- Project README.md
- Release notes for significant contributions
- Annual contributor recognition

---

**Thank you for helping make blockchain infrastructure more secure!** 