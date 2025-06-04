# Multi-stage Docker build for Secure Sign Service
# Stage 1: Build environment
# Updated to rust:1.81-alpine to support Cargo lock file version 4
FROM rust:1.81-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    protobuf-dev \
    protobuf \
    protobuf-c-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    make \
    git

# Set protobuf environment variables
ENV PROTOC=/usr/bin/protoc
ENV PROTOC_INCLUDE=/usr/include

# Create app directory
WORKDIR /app

# Copy dependency files first for better caching
COPY Cargo.toml Cargo.lock ./
COPY secure-sign/Cargo.toml ./secure-sign/
COPY secure-sign-core/Cargo.toml ./secure-sign-core/
COPY secure-sign-rpc/Cargo.toml ./secure-sign-rpc/
COPY secure-sign-nitro/Cargo.toml ./secure-sign-nitro/

# Copy protobuf files needed for build scripts
COPY secure-sign-core/proto/ ./secure-sign-core/proto/
COPY secure-sign-rpc/proto/ ./secure-sign-rpc/proto/

# Copy build scripts
COPY secure-sign/build.rs ./secure-sign/
COPY secure-sign-core/build.rs ./secure-sign-core/
COPY secure-sign-rpc/build.rs ./secure-sign-rpc/

# Create minimal source files for dependency build
RUN mkdir -p secure-sign/src secure-sign-core/src/neo secure-sign-rpc/src secure-sign-nitro/src && \
    echo "fn main() {}" > secure-sign/src/main.rs && \
    echo "// dummy lib" > secure-sign-core/src/lib.rs && \
    echo "// dummy lib" > secure-sign-rpc/src/lib.rs && \
    echo "// dummy lib" > secure-sign-nitro/src/lib.rs

# Build dependencies
RUN cargo build --release --features tcp --no-default-features

# Copy actual source code
COPY secure-sign/src/ ./secure-sign/src/
COPY secure-sign-core/src/ ./secure-sign-core/src/
COPY secure-sign-rpc/src/ ./secure-sign-rpc/src/
COPY secure-sign-nitro/src/ ./secure-sign-nitro/src/

# Build the application with real source
RUN cargo build --release --features tcp --no-default-features

# Stage 2: Runtime environment
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata && \
    rm -rf /var/cache/apk/*

# Create non-root user
RUN adduser -D -s /bin/sh -u 1000 secure-sign

# Create application directories
RUN mkdir -p /app/config /app/logs /app/bin && \
    chown -R secure-sign:secure-sign /app

# Copy binary from builder stage
COPY --from=builder /app/target/release/secure-sign /app/bin/secure-sign

# Set proper permissions
RUN chmod +x /app/bin/secure-sign

# Switch to non-root user
USER secure-sign
WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -f "secure-sign run" > /dev/null || exit 1

# Expose gRPC port
EXPOSE 9991

# Set environment variables
ENV RUST_LOG=info
ENV PATH="/app/bin:$PATH"

# Default command
ENTRYPOINT ["/app/bin/secure-sign"]
CMD ["run", "--wallet", "/app/config/wallet.json", "--port", "9991"]

# Labels for metadata
LABEL maintainer="R3E Network Team"
LABEL version="0.1.0"
LABEL description="Secure Sign Service for NEO blockchain with TEE support" 