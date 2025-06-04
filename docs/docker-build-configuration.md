# Docker Build Configuration

## Overview

This document describes the Docker build configuration for the Secure Sign Service and addresses common build issues, particularly Cargo version compatibility problems.

## Issue: Cargo Lock File Version Compatibility

### Problem Description

**Error**: `lock file version 4 was found, but this version of Cargo does not understand this lock file`

This error occurs when there's a mismatch between:
- The Cargo version used to generate `Cargo.lock` (locally or in CI)
- The Cargo version available in the Docker build environment

### Root Cause

- **Lock file version 4**: Introduced in Rust/Cargo 1.77
- **Docker image `rust:1.75-alpine`**: Contains Cargo 1.75 (doesn't support v4 lock files)
- **Local development**: Using newer Cargo version (1.77+)

### Solution Strategy

#### Option 1: Update Docker Rust Version (Recommended)
Update the Dockerfile to use a newer Rust version that supports lock file version 4.

#### Option 2: Downgrade Lock File Version
Regenerate the lock file with an older Cargo version (not recommended for production).

## Docker Configuration

### Multi-Stage Build Design

The Dockerfile uses a multi-stage build approach:

1. **Builder Stage**: Compiles the Rust application with all dependencies
2. **Runtime Stage**: Minimal Alpine image with only the compiled binary

### Build Optimization

- **Dependency Caching**: Copies `Cargo.toml` files first to cache dependency builds
- **Target-Specific Builds**: Uses `x86_64-unknown-linux-musl` for portable Linux binaries
- **Feature Selection**: Builds with specific features (`--features tcp`)

### Security Considerations

- **Non-root User**: Creates and uses a dedicated `secure-sign` user
- **Minimal Base Image**: Uses Alpine Linux for reduced attack surface
- **Health Checks**: Includes application health monitoring

## Implementation

### Required Changes ✅ COMPLETED

1. ✅ **Update Rust Version**: Changed from `rust:1.75-alpine` to `rust:1.81-alpine`
2. ✅ **Verify Compatibility**: All dependencies work with the new Rust version
3. ✅ **Test Build Process**: Created automated test script for Docker build pipeline

### Rust Version Selection

- **Minimum Required**: Rust 1.77+ (for Cargo lock file version 4 support)
- **Recommended**: Rust 1.81+ (latest stable with performance improvements)
- **Project Requirement**: Rust 1.70+ (as specified in `Cargo.toml`)

## Environment Dependencies

### Alpine Packages Required

- `musl-dev`: For static linking with musl libc
- `protobuf-dev`: Protocol Buffers development files
- `protobuf`: Protocol Buffers runtime
- `openssl-dev`: OpenSSL development libraries
- `pkgconfig`: Package configuration tool
- `make`: Build automation tool

### Build Process

1. **Dependency Resolution**: Cargo resolves and downloads dependencies
2. **Proto Compilation**: Protocol Buffer files are compiled
3. **Application Build**: Rust source code compilation
4. **Binary Optimization**: Release mode with LTO and optimizations

## Troubleshooting

### Common Build Issues

1. **Lock File Version Mismatch**
   - **Symptom**: "lock file version X was found, but this version of Cargo does not understand"
   - **Solution**: Update Docker Rust version or regenerate lock file

2. **Missing System Dependencies**
   - **Symptom**: Linker errors or missing library errors
   - **Solution**: Ensure all required Alpine packages are installed

3. **Target Architecture Issues**
   - **Symptom**: Binary won't run in container
   - **Solution**: Verify `x86_64-unknown-linux-musl` target is properly configured

4. **Build Cache Problems**
   - **Symptom**: Slow builds or dependency resolution issues
   - **Solution**: Clear Docker build cache and rebuild

### Verification Commands

```bash
# Check Rust version in Docker image
docker run --rm rust:1.81-alpine rustc --version

# Check Cargo version
docker run --rm rust:1.81-alpine cargo --version

# Test local lock file compatibility
cargo check --locked

# Verify Docker build (manual)
docker build -t secure-sign-test .

# Automated Docker build test (recommended)
make test-docker
```

## CI/CD Integration

### Build Pipeline Considerations

- **Consistent Environments**: Ensure CI uses same Rust version as Docker
- **Dependency Caching**: Leverage Docker layer caching for faster builds
- **Security Scanning**: Include container security scanning in pipeline
- **Multi-Architecture**: Consider building for different architectures if needed

### Environment Variables

- `RUST_LOG`: Logging level configuration
- `CARGO_NET_GIT_FETCH_WITH_CLI`: Git dependency handling
- `CARGO_REGISTRIES_CRATES_IO_PROTOCOL`: Registry protocol configuration

## Resolution Status ✅

**Issue**: Cargo lock file version 4 compatibility with Docker build environment  
**Solution**: Updated Dockerfile from `rust:1.75-alpine` to `rust:1.81-alpine`  
**Status**: RESOLVED ✅  
**Date**: December 2024  

### Changes Made:
1. ✅ Updated Dockerfile to use `rust:1.81-alpine` (supports Cargo lock file version 4)
2. ✅ Created comprehensive documentation explaining the issue and solution
3. ✅ Built automated test script (`scripts/test-docker-build.sh`) for verification
4. ✅ Integrated Docker build testing into Makefile (`make test-docker`)
5. ✅ Verified CI/CD compatibility with GitHub Actions workflow

### Verification:
The Docker build now works correctly with Cargo lock file version 4:
- No more "lock file version 4 was found, but this version of Cargo does not understand" errors
- Build process completes successfully
- Container runs properly with security configurations intact

## Best Practices

1. **Version Pinning**: Pin Rust version to ensure reproducible builds
2. **Dependency Management**: Keep dependencies up to date
3. **Security Updates**: Regularly update base images
4. **Build Testing**: Test Docker builds in CI/CD pipeline
5. **Documentation**: Keep build configuration documented and updated 