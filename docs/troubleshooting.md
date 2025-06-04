# Troubleshooting Guide

This guide covers common issues and their solutions when deploying and operating the Secure Sign Service.

## 🔍 Quick Diagnostics

### Health Check
```bash
# Run comprehensive health check
./scripts/health-check.sh -v

# Check specific port/transport
./scripts/health-check.sh -p 9991 -c 0  # TCP mode
./scripts/health-check.sh -p 9991 -c 3  # VSOCK mode
```

### Security Audit
```bash
# Run security audit
./scripts/security-audit.sh

# Quick dependency check
make audit
```

## 🚨 Common Issues

### 1. Service Won't Start

#### Symptoms
- Process exits immediately
- "Address already in use" error
- Permission denied errors

#### Diagnosis
```bash
# Check if process is already running
pgrep -f "secure-sign.*run"

# Check if port is in use
netstat -tuln | grep :9991

# Check file permissions
ls -la secure-sign/config/nep6_wallet.json

# Check logs
RUST_LOG=debug ./target/secure-sign-tcp run --wallet config/wallet.json
```

#### Solutions

**Port already in use:**
```bash
# Find process using the port
lsof -i :9991

# Kill existing process
pkill -f "secure-sign.*run"

# Use different port
./target/secure-sign-tcp run --wallet config/wallet.json --port 9992
```

**Permission denied:**
```bash
# Fix wallet permissions
chmod 600 secure-sign/config/nep6_wallet.json

# Fix binary permissions
chmod +x ./target/secure-sign-tcp

# Check directory permissions
ls -la /opt/secure-sign/
```

**Missing dependencies:**
```bash
# Install protobuf compiler
sudo apt-get install protobuf-compiler  # Ubuntu/Debian
brew install protobuf                   # macOS

# Install Rust targets
rustup target add x86_64-unknown-linux-musl
```

### 2. Wallet Decryption Fails

#### Symptoms
- "Failed to decrypt wallet" error
- Connection refused when running decrypt command
- Invalid passphrase error

#### Diagnosis
```bash
# Check if service is running
./scripts/health-check.sh

# Verify wallet format
jq . secure-sign/config/nep6_wallet.json

# Test connectivity
./target/secure-sign-tcp status --public-key test --port 9991
```

#### Solutions

**Service not running:**
```bash
# Start service first
./target/secure-sign-tcp run --wallet secure-sign/config/nep6_wallet.json &

# Then decrypt
./target/secure-sign-tcp decrypt --port 9991
```

**Invalid wallet format:**
```bash
# Validate JSON structure
jq . secure-sign/config/nep6_wallet.json

# Check required fields
jq '.accounts[0] | keys' secure-sign/config/nep6_wallet.json
```

**Wrong passphrase:**
```bash
# Use mock mode for testing
./target/secure-sign-tcp mock --wallet secure-sign/config/nep6_wallet.json --passphrase "your-password"
```

### 3. Build Failures

#### Symptoms
- Compilation errors
- Missing protoc error
- Target not found error

#### Diagnosis
```bash
# Check Rust installation
rustc --version
cargo --version

# Check required tools
protoc --version

# Check available targets
rustup target list --installed
```

#### Solutions

**Missing protoc:**
```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install protobuf-compiler

# CentOS/RHEL
sudo yum install protobuf-compiler

# macOS
brew install protobuf

# Alpine
apk add protobuf-dev protobuf
```

**Missing Rust targets:**
```bash
# Add required targets
rustup target add x86_64-unknown-linux-musl
rustup target add x86_64-fortanix-unknown-sgx  # For SGX

# Install musl tools (Linux)
sudo apt-get install musl-tools
```

**Compilation errors:**
```bash
# Clean and rebuild
cargo clean
cargo build --release

# Check for dependency conflicts
cargo tree --duplicates

# Update dependencies
cargo update
```

### 4. SGX Build Issues

#### Symptoms
- SGX SDK not found
- Enclave build failures
- Target not supported

#### Diagnosis
```bash
# Check SGX SDK installation
ls -la /opt/intel/sgxsdk/

# Check SGX targets
rustup target list | grep sgx

# Check make variables
make info
```

#### Solutions

**SGX SDK not found:**
```bash
# Install Intel SGX SDK
# Download from: https://software.intel.com/sgx

# Set correct path
export SGX_SDK_PATH=/opt/intel/sgxsdk
make sgx

# Or specify path
SGX_SDK_PATH=/custom/path make sgx
```

**Target not installed:**
```bash
# Install SGX target
rustup target add x86_64-fortanix-unknown-sgx

# Verify installation
rustup target list --installed | grep sgx
```

**Enclave build failures:**
```bash
# Check SGX mode
SGX_MODE=SW make sgx  # Software mode for testing
SGX_MODE=HW make sgx  # Hardware mode for production

# Clean SGX builds
cd secure-sign-sgx-enclave && make clean
cd ../secure-sign-sgx && cargo clean
```

### 5. Docker Build Issues

#### Symptoms
- Docker build failures
- Image too large
- Container won't start

#### Diagnosis
```bash
# Check Docker version
docker --version

# Check available space
df -h

# Check build context
du -sh .
```

#### Solutions

**Build failures:**
```bash
# Build with verbose output
docker build --progress=plain .

# Check for .dockerignore
cat .dockerignore

# Clean Docker cache
docker system prune -a
```

**Large image size:**
```bash
# Check image layers
docker history secure-sign:latest

# Use multi-stage build (already implemented)
# Remove unnecessary files in .dockerignore
```

**Container won't start:**
```bash
# Check container logs
docker logs secure-sign-service

# Run interactively
docker run -it --entrypoint /bin/sh secure-sign:latest

# Check volume mounts
docker inspect secure-sign-service
```

### 6. Performance Issues

#### Symptoms
- High memory usage
- Slow signing operations
- High CPU usage

#### Diagnosis
```bash
# Check resource usage
./scripts/health-check.sh -v

# Monitor with top
top -p $(pgrep -f "secure-sign.*run")

# Profile memory
valgrind --tool=massif ./target/secure-sign-tcp --help
```

#### Solutions

**High memory usage:**
```bash
# Check for memory leaks
RUST_LOG=debug ./target/secure-sign-tcp run --wallet config/wallet.json

# Monitor with htop
htop -p $(pgrep -f "secure-sign.*run")

# Set memory limits (systemd)
MemoryMax=512M
```

**Slow operations:**
```bash
# Enable performance optimizations
export RUSTFLAGS="-C target-cpu=native"
cargo build --release

# Use release builds
make tcp  # Instead of cargo build
```

## 🔧 Advanced Troubleshooting

### Debug Mode
```bash
# Enable debug logging
export RUST_LOG=debug
./target/secure-sign-tcp run --wallet config/wallet.json

# Trace level (very verbose)
export RUST_LOG=trace
./target/secure-sign-tcp run --wallet config/wallet.json

# Module-specific logging
export RUST_LOG="secure_sign_core=debug,secure_sign_rpc=info"
```

### Network Diagnostics
```bash
# Test gRPC connectivity
grpcurl -plaintext localhost:9991 list

# Monitor network traffic
sudo tcpdump -i lo port 9991

# Check firewall rules
sudo ufw status  # Ubuntu
sudo firewall-cmd --list-all  # CentOS/RHEL
```

### Systemd Service Debugging
```bash
# Check service status
systemctl status secure-sign

# View detailed logs
journalctl -u secure-sign -f

# Check service configuration
systemctl cat secure-sign

# Reload configuration
sudo systemctl daemon-reload
sudo systemctl restart secure-sign
```

### File System Issues
```bash
# Check disk space
df -h

# Check inodes
df -i

# Check file permissions recursively
find /opt/secure-sign -type f -ls

# Check SELinux context (if applicable)
ls -Z /opt/secure-sign/config/wallet.json
```

## 📊 Monitoring and Metrics

### Health Monitoring
```bash
# Continuous health monitoring
watch -n 30 ./scripts/health-check.sh

# Service status with systemd
systemctl is-active secure-sign

# Memory monitoring
watch -n 5 'ps aux | grep secure-sign'
```

### Log Analysis
```bash
# Search for errors
grep -i error /var/log/secure-sign.log

# Count operations
grep "signing" /var/log/secure-sign.log | wc -l

# Monitor in real-time
tail -f /var/log/secure-sign.log | grep -E "(ERROR|WARN)"
```

## 🚨 Emergency Procedures

### Service Recovery
```bash
# Stop service gracefully
pkill -TERM -f "secure-sign.*run"

# Force kill if needed
pkill -KILL -f "secure-sign.*run"

# Restart with systemd
sudo systemctl restart secure-sign

# Check service health
./scripts/health-check.sh
```

### Backup and Restore
```bash
# Emergency backup
cp /opt/secure-sign/config/wallet.json /backup/wallet-$(date +%Y%m%d-%H%M%S).json

# Restore from backup
cp /backup/wallet-20250115-120000.json /opt/secure-sign/config/wallet.json
chmod 600 /opt/secure-sign/config/wallet.json
```

### Security Incident Response
```bash
# Stop service immediately
sudo systemctl stop secure-sign

# Audit recent activity
journalctl -u secure-sign --since "1 hour ago"

# Check for unauthorized access
last | grep secure-sign

# Run security audit
./scripts/security-audit.sh
```

## 📞 Getting Help

### Information to Collect
```bash
# System information
./scripts/health-check.sh -v > health-report.txt

# Build information
make info > build-info.txt

# Service logs
journalctl -u secure-sign --since "1 hour ago" > service-logs.txt

# System logs
dmesg | tail -50 > system-logs.txt
```

### Support Checklist
- [ ] Health check output
- [ ] Build information
- [ ] Service logs (with sensitive data removed)
- [ ] Steps to reproduce the issue
- [ ] Expected vs actual behavior
- [ ] Environment details (OS, Docker version, etc.)

### Community Resources
- **Documentation**: [docs/](.)
- **Security Policy**: [SECURITY.md](../SECURITY.md)
- **Issues**: GitHub Issues (if available)
- **Security Contact**: security@r3e.network

---

**Remember**: Never share wallet files, private keys, or passphrases in support requests! 