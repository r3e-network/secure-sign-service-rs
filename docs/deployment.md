# Deployment Guide

## Overview

This guide covers deployment strategies for the Secure Sign Service. The service is designed as a simple command-line application that can be deployed in various environments while maintaining security.

## Basic Deployment

### Direct Binary Deployment

The simplest deployment method using the compiled binary directly.

#### Prerequisites

- Rust 1.70+ (for building from source)
- Protocol Buffers compiler (protoc)
- NEP-6 wallet file

#### Building from Source

```bash
# Clone repository
git clone <repository-url>
cd secure-sign-service-rs

# Build standard version
cargo build --release

# Build TCP-specific version
make tcp

# Build VSOCK-specific version  
make vsock
```

#### Running the Service

```bash
# Production mode (requires separate decryption step)
./target/secure-sign-tcp run --wallet config/wallet.json --port 9991

# Development mode (passphrase provided directly)
./target/secure-sign-tcp mock --wallet config/wallet.json --passphrase "your-password" --port 9991
```

### File Structure

Recommended directory structure for deployment:

```
/opt/secure-sign/
├── bin/
│   └── secure-sign              # Binary
├── config/
│   └── wallet.json              # NEP-6 wallet file
├── logs/
│   └── secure-sign.log          # Log files
└── scripts/
    ├── start.sh                 # Start script
    └── stop.sh                  # Stop script
```

## Docker Deployment

### Basic Docker Setup

#### Dockerfile

```dockerfile
FROM rust:1.75-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    protobuf-dev \
    protobuf \
    openssl-dev \
    pkgconfig

WORKDIR /app
COPY . .

# Build the application
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime image
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Create user
RUN adduser -D -s /bin/sh secure-sign

# Copy binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/secure-sign /usr/local/bin/

# Create directories
RUN mkdir -p /app/config /app/logs \
    && chown -R secure-sign:secure-sign /app

USER secure-sign
WORKDIR /app

EXPOSE 9991

ENTRYPOINT ["/usr/local/bin/secure-sign"]
CMD ["run", "--wallet", "/app/config/wallet.json", "--port", "9991"]
```

#### Docker Compose

```yaml
version: '3.8'

services:
  secure-sign:
    build: .
    ports:
      - "9991:9991"
    volumes:
      - ./config/wallet.json:/app/config/wallet.json:ro
      - secure-sign-logs:/app/logs
    environment:
      - RUST_LOG=info
    restart: unless-stopped

volumes:
  secure-sign-logs:
```

#### Running with Docker

```bash
# Build image
docker build -t secure-sign .

# Run container
docker run -d \
  --name secure-sign \
  -p 9991:9991 \
  -v $(pwd)/config/wallet.json:/app/config/wallet.json:ro \
  secure-sign

# Decrypt wallet (in another terminal)
docker exec -it secure-sign secure-sign-tcp decrypt --port 9991
```

## Systemd Service

For production Linux deployments, use systemd for service management.

### Service File

Create `/etc/systemd/system/secure-sign.service`:

```ini
[Unit]
Description=Secure Sign Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=secure-sign
Group=secure-sign
WorkingDirectory=/opt/secure-sign
ExecStart=/usr/local/bin/secure-sign-tcp run --wallet /opt/secure-sign/config/wallet.json --port 9991
ExecStop=/bin/kill -TERM $MAINPID
Restart=always
RestartSec=5

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/secure-sign/logs
PrivateTmp=true

# Resource limits
LimitNOFILE=1024
MemoryMax=512M

[Install]
WantedBy=multi-user.target
```

### Service Management

```bash
# Create user
sudo useradd -r -s /bin/false secure-sign

# Install service
sudo systemctl daemon-reload
sudo systemctl enable secure-sign

# Start service
sudo systemctl start secure-sign

# Check status
sudo systemctl status secure-sign

# View logs
sudo journalctl -u secure-sign -f
```

## Security Hardening

### File Permissions

```bash
# Secure wallet file
chmod 600 /opt/secure-sign/config/wallet.json
chown secure-sign:secure-sign /opt/secure-sign/config/wallet.json

# Secure binary
chmod 755 /opt/secure-sign/bin/secure-sign
chown root:root /opt/secure-sign/bin/secure-sign

# Secure logs directory
chmod 750 /opt/secure-sign/logs
chown secure-sign:secure-sign /opt/secure-sign/logs
```

### Network Security

```bash
# Firewall rules (example with ufw)
sudo ufw allow from 127.0.0.1 to any port 9991
sudo ufw deny 9991

# Or with iptables
sudo iptables -A INPUT -i lo -p tcp --dport 9991 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9991 -j DROP
```

### Process Security

```bash
# Set process limits
echo "secure-sign soft nofile 1024" >> /etc/security/limits.conf
echo "secure-sign hard nofile 2048" >> /etc/security/limits.conf

# System hardening
echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.conf
echo "kernel.kptr_restrict = 2" >> /etc/sysctl.conf
sysctl -p
```

## VSOCK Deployment (TEE Environments)

For deployment in Trusted Execution Environments that support VSOCK.

### Prerequisites

```bash
# Ensure VSOCK kernel module is loaded
modprobe vsock

# Verify VSOCK device exists
ls -la /dev/vsock
```

### VSOCK Configuration

```bash
# Build VSOCK version
make vsock

# Run with VSOCK transport
./target/secure-sign-vsock run --wallet config/wallet.json --port 9991 --cid 3

# Connect from host
./target/secure-sign-vsock decrypt --port 9991 --cid 3
```

### Container with VSOCK

```dockerfile
# Special VSOCK-enabled container
FROM alpine:3.19

# Copy VSOCK binary
COPY target/secure-sign-vsock /usr/local/bin/secure-sign-vsock

# VSOCK device access
VOLUME ["/dev/vsock"]

CMD ["/usr/local/bin/secure-sign-vsock", "run", "--wallet", "/config/wallet.json", "--port", "9991", "--cid", "3"]
```

## Monitoring and Logging

### Log Management

```bash
# Configure log rotation
cat > /etc/logrotate.d/secure-sign << EOF
/opt/secure-sign/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 secure-sign secure-sign
    postrotate
        systemctl reload secure-sign
    endscript
}
EOF
```

### Basic Monitoring Script

```bash
#!/bin/bash
# /opt/secure-sign/scripts/healthcheck.sh

# Check if service is running
if ! pgrep -f "secure-sign run" > /dev/null; then
    echo "ERROR: Secure sign service is not running"
    exit 1
fi

# Check if port is listening
if ! netstat -tuln | grep ":9991" > /dev/null; then
    echo "ERROR: Service not listening on port 9991"
    exit 1
fi

echo "OK: Service is healthy"
exit 0
```

### Service Status Script

```bash
#!/bin/bash
# /opt/secure-sign/scripts/status.sh

echo "=== Secure Sign Service Status ==="
echo "Service Status: $(systemctl is-active secure-sign)"
echo "Process: $(pgrep -f 'secure-sign run' | wc -l) running"
echo "Port 9991: $(netstat -tuln | grep ':9991' | wc -l) listening"
echo "Memory Usage: $(ps -o pid,ppid,cmd,%mem,%cpu --sort=-%mem -C secure-sign)"
echo "Log tail:"
tail -5 /opt/secure-sign/logs/secure-sign.log
```

## Backup and Recovery

### Backup Strategy

```bash
#!/bin/bash
# /opt/secure-sign/scripts/backup.sh

BACKUP_DIR="/backup/secure-sign/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup wallet file
cp /opt/secure-sign/config/wallet.json "$BACKUP_DIR/"

# Backup configuration
cp -r /opt/secure-sign/config "$BACKUP_DIR/"

# Backup logs (optional)
tar -czf "$BACKUP_DIR/logs.tar.gz" /opt/secure-sign/logs/

echo "Backup completed: $BACKUP_DIR"
```

### Recovery Procedure

```bash
#!/bin/bash
# /opt/secure-sign/scripts/restore.sh

BACKUP_DATE=${1:-$(date +%Y%m%d)}
BACKUP_DIR="/backup/secure-sign/$BACKUP_DATE"

if [ ! -d "$BACKUP_DIR" ]; then
    echo "Error: Backup directory not found: $BACKUP_DIR"
    exit 1
fi

# Stop service
systemctl stop secure-sign

# Restore wallet
cp "$BACKUP_DIR/wallet.json" /opt/secure-sign/config/

# Set permissions
chown secure-sign:secure-sign /opt/secure-sign/config/wallet.json
chmod 600 /opt/secure-sign/config/wallet.json

# Start service
systemctl start secure-sign

echo "Recovery completed from: $BACKUP_DIR"
```

## Troubleshooting

### Common Issues

1. **Service won't start**
   ```bash
   # Check logs
   journalctl -u secure-sign -n 50
   
   # Check file permissions
   ls -la /opt/secure-sign/config/wallet.json
   
   # Check if port is available
   netstat -tuln | grep :9991
   ```

2. **Wallet decryption fails**
   ```bash
   # Verify wallet format
   jq . /opt/secure-sign/config/wallet.json
   
   # Check service is running
   systemctl status secure-sign
   ```

3. **Permission denied errors**
   ```bash
   # Fix permissions
   chown -R secure-sign:secure-sign /opt/secure-sign
   chmod 600 /opt/secure-sign/config/wallet.json
   chmod 755 /opt/secure-sign/bin/secure-sign
   ```

4. **Memory issues**
   ```bash
   # Check memory usage
   ps aux | grep secure-sign
   
   # Check system resources
   free -h
   df -h
   ```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Set environment variable
export RUST_LOG=debug

# Or modify systemd service
sudo systemctl edit secure-sign

# Add:
[Service]
Environment=RUST_LOG=debug
```

### Performance Tuning

For high-load environments:

```bash
# Increase file descriptor limits
echo "secure-sign soft nofile 4096" >> /etc/security/limits.conf
echo "secure-sign hard nofile 8192" >> /etc/security/limits.conf

# Tune network settings
echo "net.core.somaxconn = 1024" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 1024" >> /etc/sysctl.conf
sysctl -p
```

## Best Practices

### Security
- Always run as non-root user
- Use strict file permissions (600 for wallet, 750 for directories)
- Bind to localhost only unless external access is required
- Use firewall rules to restrict access
- Regularly update dependencies

### Operations
- Implement log rotation
- Monitor service health
- Backup wallet files regularly
- Use systemd for service management
- Set resource limits

### Development
- Use mock mode for testing
- Never commit wallet files with real keys
- Use environment-specific configurations
- Test deployment procedures regularly 

## Intel SGX Deployment

### Prerequisites

#### SGX Hardware Requirements
- Intel CPU with SGX support (check with `cpuid | grep SGX`)
- SGX enabled in BIOS
- SGX Platform Software (PSW) installed
- SGX SDK installed

#### Software Installation
```bash
# Install Intel SGX SDK
wget https://download.01.org/intel-sgx/sgx-linux/2.17/distro/ubuntu20.04-server/sgx_linux_x64_sdk_2.17.100.3.bin
chmod +x sgx_linux_x64_sdk_2.17.100.3.bin
echo 'yes' | ./sgx_linux_x64_sdk_2.17.100.3.bin

# Install SGX PSW (Platform Software)
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install libsgx-enclave-common libsgx-dcap-ql

# Install Rust SGX target
rustup target add x86_64-fortanix-unknown-sgx
```

### Building SGX Service

#### Generate Signing Key
```bash
# Generate SGX enclave signing key (only needed once)
cd secure-sign-sgx-enclave
openssl genrsa -out sgx_sign_private_key.pem -3 3072
```

#### Build Enclave and Service
```bash
# Build for hardware SGX
make sgx

# Or build for simulation mode (development)
SGX_MODE=SW make sgx

# Verify build artifacts
ls -la target/secure-sign-sgx secure-sign-sgx-enclave/*.signed.so
```

### SGX Deployment Example

#### Directory Structure
```
/opt/secure-sign-sgx/
├── bin/
│   ├── secure-sign-sgx                    # SGX service binary
│   └── secure_sign_sgx_enclave.signed.so  # Signed enclave
├── config/
│   ├── wallet.json                        # NEP-6 wallet
│   └── sgx_sign_private_key.pem          # SGX signing key
├── logs/
│   └── sgx-service.log
└── scripts/
    ├── start-sgx.sh
    └── stop-sgx.sh
```

#### Start Script
```bash
#!/bin/bash
# /opt/secure-sign-sgx/scripts/start-sgx.sh

set -e

SGX_SERVICE="/opt/secure-sign-sgx/bin/secure-sign-sgx"
ENCLAVE="/opt/secure-sign-sgx/bin/secure_sign_sgx_enclave.signed.so"
WALLET="/opt/secure-sign-sgx/config/wallet.json"
LOG_FILE="/opt/secure-sign-sgx/logs/sgx-service.log"

# Check if SGX is available
if [ ! -c /dev/sgx_enclave ]; then
    echo "Error: SGX device not found. Is SGX enabled and PSW installed?"
    exit 1
fi

# Check files exist
for file in "$SGX_SERVICE" "$ENCLAVE" "$WALLET"; do
    if [ ! -f "$file" ]; then
        echo "Error: Required file not found: $file"
        exit 1
    fi
done

echo "Starting SGX Secure Sign Service..."
echo "  Service: $SGX_SERVICE"
echo "  Enclave: $ENCLAVE"
echo "  Wallet: $WALLET"
echo "  Logs: $LOG_FILE"

# Source SGX SDK environment
source /opt/intel/sgxsdk/environment

# Start service
nohup "$SGX_SERVICE" run \
    --wallet "$WALLET" \
    --enclave "$ENCLAVE" \
    --port 9991 \
    > "$LOG_FILE" 2>&1 &

PID=$!
echo "SGX service started with PID: $PID"
echo "To decrypt wallet, run: ./target/secure-sign-sgx decrypt --port 9991"
```

#### Systemd Service for SGX
```ini
# /etc/systemd/system/secure-sign-sgx.service
[Unit]
Description=Secure Sign SGX Service
After=network.target
Requires=aesmd.service
After=aesmd.service

[Service]
Type=simple
User=secure-sign
Group=secure-sign
WorkingDirectory=/opt/secure-sign-sgx
Environment=SGX_SDK=/opt/intel/sgxsdk
ExecStartPre=/bin/bash -c 'source /opt/intel/sgxsdk/environment'
ExecStart=/opt/secure-sign-sgx/bin/secure-sign-sgx run --wallet /opt/secure-sign-sgx/config/wallet.json --enclave /opt/secure-sign-sgx/bin/secure_sign_sgx_enclave.signed.so --port 9991
ExecStop=/bin/kill -TERM $MAINPID
Restart=always
RestartSec=10

# Security settings for SGX
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/secure-sign-sgx/logs
DeviceAllow=/dev/sgx_enclave rw
DeviceAllow=/dev/sgx_provision rw

[Install]
WantedBy=multi-user.target
```

### SGX-Specific Security

#### Remote Attestation
```bash
# Get SGX platform info
sgx_cap_verifier

# Generate attestation report (in production)
# This requires integration with Intel Attestation Service (IAS)
# or Intel Data Center Attestation Primitives (DCAP)
```

#### Enclave Verification
```bash
# Verify enclave signature
sgx_sign dump -enclave secure_sign_sgx_enclave.signed.so -dumpfile enclave.metadata
cat enclave.metadata | grep -A 10 "signature"
```

### Monitoring SGX Service

#### SGX-specific Health Checks
```bash
#!/bin/bash
# /opt/secure-sign-sgx/scripts/sgx-healthcheck.sh

# Check SGX device availability
if [ ! -c /dev/sgx_enclave ]; then
    echo "ERROR: SGX device not available"
    exit 1
fi

# Check if AESM service is running
if ! systemctl is-active --quiet aesmd; then
    echo "ERROR: AESM service not running"
    exit 1
fi

# Check service process
if ! pgrep -f "secure-sign-sgx" > /dev/null; then
    echo "ERROR: SGX service not running"
    exit 1
fi

# Check port availability
if ! netstat -tuln | grep ":9991" > /dev/null; then
    echo "ERROR: SGX service not listening on port 9991"
    exit 1
fi

echo "OK: SGX service is healthy"
exit 0
```

### Troubleshooting SGX

#### Common Issues

1. **SGX Device Not Found**
   ```bash
   # Check SGX support
   cpuid | grep SGX
   
   # Check SGX kernel modules
   lsmod | grep intel_sgx
   
   # Install SGX driver if needed
   sudo apt-get install sgx-aesm-service
   ```

2. **Enclave Launch Failed**
   ```bash
   # Check SGX PSW service
   sudo systemctl status aesmd
   
   # Check SGX configuration
   cat /sys/module/intel_sgx/parameters/sgx_enforce_kss
   ```

3. **Attestation Failures**
   ```bash
   # Check network connectivity to Intel services
   ping api.trustedservices.intel.com
   
   # Verify PCCS configuration (for DCAP)
   curl -k https://localhost:8081/sgx/certification/v3/pckcrl
   ```

### SGX vs Standard Deployment

| Feature | Standard | SGX |
|---------|----------|-----|
| Memory Protection | OS-level | Hardware-enforced |
| Key Storage | Process memory | Enclave memory |
| Attestation | None | Hardware-based |
| Performance | Faster | Slight overhead |
| Setup Complexity | Simple | Complex |
| Hardware Requirements | Any x86_64 | SGX-capable Intel CPU | 