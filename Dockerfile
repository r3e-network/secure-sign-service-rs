# Multi-stage Docker build for Secure Sign Service
# Stage 1: Build environment
# Updated to rust:1.81-alpine to support Cargo lock file version 4
FROM rust:1.81-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    protobuf-dev \
    protobuf \
    openssl-dev \
    pkgconfig \
    make

# Set protobuf environment variables
ENV PROTOC=/usr/bin/protoc
ENV PROTOC_INCLUDE=/usr/include

# Create app directory
WORKDIR /app

# Copy all source files and build configuration
COPY . .

# Build the application
RUN cargo build --release --target x86_64-unknown-linux-musl --features tcp --no-default-features

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
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/secure-sign /app/bin/secure-sign

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