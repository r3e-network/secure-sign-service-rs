# Feature Configuration

## Overview

This document describes the feature configuration system for the Secure Sign Service and addresses build issues related to mutually exclusive features.

## Feature System Design

The Secure Sign Service uses Cargo features to support different transport protocols and deployment environments. The main features are designed to be **mutually exclusive** to ensure clear deployment boundaries.

### Transport Features

#### `tcp` Feature
- **Purpose**: Standard TCP socket communication
- **Use Case**: Development, testing, standard deployments
- **Security**: Localhost binding only (127.0.0.1)
- **Compatibility**: All environments

#### `vsock` Feature  
- **Purpose**: VSOCK communication for Trusted Execution Environments
- **Use Case**: AWS Nitro Enclaves, Intel SGX environments
- **Security**: TEE-optimized communication
- **Compatibility**: TEE environments only

### Mutual Exclusivity

The `tcp` and `vsock` features are **mutually exclusive** by design:

```rust
#[cfg(all(feature = "vsock", feature = "tcp"))]
compile_error!("vsock and tcp cannot be both enabled");
```

**Rationale:**
1. **Clear Deployment Intent**: Forces explicit choice of transport protocol
2. **Reduced Binary Size**: Avoids including unused code paths
3. **Security Clarity**: Prevents ambiguous runtime transport selection
4. **Configuration Simplicity**: One transport per build, clear behavior

## Build Configuration

### Correct Feature Usage

```bash
# TCP version (default for most deployments)
cargo build --features tcp --no-default-features

# VSOCK version (for TEE environments)
cargo build --features vsock --no-default-features

# ❌ INCORRECT - will cause compile error
cargo build --all-features
cargo build --features tcp,vsock
```

### CI/CD Considerations

The CI/CD pipeline must test each feature combination separately:

```yaml
# ✅ CORRECT - Test each feature separately
- run: cargo test --features tcp --no-default-features
- run: cargo test --features vsock --no-default-features

# ❌ INCORRECT - Enables conflicting features
- run: cargo test --all-features
```

## Issue Resolution

### Problem Description

**Error**: `vsock and tcp cannot be both enabled`

This compile-time error occurs when both transport features are enabled simultaneously, typically through:
- `--all-features` flag in CI/CD
- Manual feature specification: `--features tcp,vsock`
- Incorrect dependency feature propagation

### Root Cause

CI/CD workflows using `--all-features` flag attempt to enable all features for comprehensive testing, but this violates the mutual exclusivity constraint.

### Solution Strategy

Replace `--all-features` with specific feature testing strategies:

1. **Feature Matrix Testing**: Test each valid feature combination separately
2. **Default Feature Testing**: Test with no features for baseline functionality
3. **Individual Feature Testing**: Test each feature in isolation

## Implementation

### CI/CD Workflow Updates

**Before (Problematic):**
```yaml
- name: Run clippy
  run: cargo clippy --all-targets --all-features -- -D warnings

- name: Run tests  
  run: cargo test --all --all-features
```

**After (Fixed):**
```yaml
- name: Run clippy (TCP)
  run: cargo clippy --all-targets --features tcp --no-default-features -- -D warnings

- name: Run clippy (VSOCK)
  run: cargo clippy --all-targets --features vsock --no-default-features -- -D warnings

- name: Run tests (TCP)
  run: cargo test --all --features tcp --no-default-features

- name: Run tests (VSOCK)
  run: cargo test --all --features vsock --no-default-features
```

### Feature Documentation

Each feature should be clearly documented in `Cargo.toml`:

```toml
[features]
# Transport protocol selection (mutually exclusive)
tcp = []    # Standard TCP sockets for general use
vsock = []  # VSOCK for Trusted Execution Environments
```

## Testing Strategy

### Local Development

```bash
# Test TCP version
make test  # Uses default tcp feature

# Test VSOCK version (if in TEE environment)
cargo test --features vsock --no-default-features

# Verify feature compilation
cargo check --features tcp --no-default-features
cargo check --features vsock --no-default-features
```

### Automated Testing

The CI/CD pipeline tests multiple configurations:

1. **TCP Feature Testing**: Full test suite with TCP transport
2. **VSOCK Feature Testing**: Full test suite with VSOCK transport  
3. **No-Default-Features**: Test with minimal feature set
4. **Cross-Compilation**: Verify builds for different targets

### Build Verification

```bash
# Verify mutual exclusivity (should fail)
cargo build --features tcp,vsock --no-default-features

# Verify individual features (should succeed)
cargo build --features tcp --no-default-features
cargo build --features vsock --no-default-features
```

## Best Practices

1. **Clear Feature Intent**: Use descriptive feature names that indicate purpose
2. **Mutual Exclusivity**: Use compile-time checks for conflicting features
3. **Documentation**: Document feature behavior and limitations
4. **CI Testing**: Test each valid feature combination separately
5. **Default Configuration**: Provide sensible defaults for common use cases

## Resolution Status ✅

**Issue**: CI/CD pipeline using `--all-features` causing mutual exclusivity violation  
**Solution**: Updated CI/CD and Makefile to test features separately  
**Status**: RESOLVED ✅  
**Date**: December 2024  

### Changes Made:
1. ✅ Updated CI workflow to test TCP and VSOCK features separately
2. ✅ Fixed Makefile targets to avoid `--all-features` conflicts
3. ✅ Created comprehensive documentation explaining feature system
4. ✅ Built automated verification script (`scripts/verify-features.sh`)
5. ✅ Integrated feature verification into Makefile (`make verify-features`)

### Verification:
The feature system now works correctly:
- TCP and VSOCK features build individually without errors
- Mutual exclusivity is properly enforced at compile time
- CI/CD pipeline tests each feature combination separately
- Clear error messages guide developers when conflicts occur

## Troubleshooting

### Common Errors

1. **"vsock and tcp cannot be both enabled"** ✅ RESOLVED
   - **Cause**: Both transport features enabled simultaneously
   - **Solution**: Use only one transport feature at a time
   - **Prevention**: Use `make verify-features` to test configuration

2. **Feature not found errors**
   - **Cause**: Typo in feature name or missing feature definition
   - **Solution**: Verify feature names in `Cargo.toml`

3. **Undefined behavior with features**
   - **Cause**: Runtime feature detection instead of compile-time
   - **Solution**: Use `#[cfg(feature = "...")]` for compile-time selection

### Verification Commands

```bash
# Check feature configuration
cargo metadata --format-version 1 | jq '.packages[0].features'

# Test feature combinations
cargo check --features tcp --no-default-features
cargo check --features vsock --no-default-features

# Verify CI locally
act -j test  # If using act for GitHub Actions testing
``` 