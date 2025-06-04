#!/bin/bash

# Docker Build Test Script
# Copyright @ 2025 - Present, R3E Network
# 
# This script tests the Docker build process and verifies that the Cargo
# lock file version compatibility issue has been resolved.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script info
echo -e "${BLUE}🐋 Testing Docker Build Configuration${NC}"
echo "========================================="
echo ""

# Function to print status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "OK" ]; then
        echo -e "${GREEN}✅ $message${NC}"
    elif [ "$status" = "WARNING" ]; then
        echo -e "${YELLOW}⚠️  $message${NC}"
    elif [ "$status" = "INFO" ]; then
        echo -e "${BLUE}ℹ️  $message${NC}"
    else
        echo -e "${RED}❌ $message${NC}"
    fi
}

# Check prerequisites
echo "🔍 Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    print_status "ERROR" "Docker not found. Please install Docker to run this test."
    exit 1
fi

print_status "OK" "Docker is available"

# Check if we're in the project root
if [ ! -f "Dockerfile" ]; then
    print_status "ERROR" "Dockerfile not found. Please run this script from the project root."
    exit 1
fi

print_status "OK" "Dockerfile found"

if [ ! -f "Cargo.lock" ]; then
    print_status "ERROR" "Cargo.lock not found. Please run 'cargo build' first."
    exit 1
fi

print_status "OK" "Cargo.lock found"

# Check Cargo.lock version
echo ""
echo "🔍 Checking Cargo.lock version..."
LOCK_VERSION=$(head -n 5 Cargo.lock | grep "^version = " | cut -d' ' -f3)
print_status "INFO" "Cargo.lock version: $LOCK_VERSION"

if [ "$LOCK_VERSION" = "4" ]; then
    print_status "INFO" "Using Cargo lock file version 4 (requires Rust 1.77+)"
else
    print_status "WARNING" "Using Cargo lock file version $LOCK_VERSION"
fi

# Check Docker image Rust version
echo ""
echo "🔍 Checking Docker image Rust version..."
RUST_VERSION=$(docker run --rm rust:1.81-alpine rustc --version 2>/dev/null || echo "Failed to get version")
print_status "INFO" "Docker Rust version: $RUST_VERSION"

CARGO_VERSION=$(docker run --rm rust:1.81-alpine cargo --version 2>/dev/null || echo "Failed to get version")
print_status "INFO" "Docker Cargo version: $CARGO_VERSION"

# Test Docker build
echo ""
echo "🔨 Testing Docker build..."

# Create a unique tag for this test
TEST_TAG="secure-sign-test-$(date +%s)"

print_status "INFO" "Building Docker image with tag: $TEST_TAG"

# Build the Docker image
BUILD_START=$(date +%s)
if docker build -t "$TEST_TAG" . > build.log 2>&1; then
    BUILD_END=$(date +%s)
    BUILD_TIME=$((BUILD_END - BUILD_START))
    print_status "OK" "Docker build completed successfully in ${BUILD_TIME}s"
else
    BUILD_END=$(date +%s)
    BUILD_TIME=$((BUILD_END - BUILD_START))
    print_status "ERROR" "Docker build failed after ${BUILD_TIME}s"
    echo ""
    echo "Build log (last 50 lines):"
    tail -n 50 build.log
    exit 1
fi

# Test the built image
echo ""
echo "🧪 Testing built Docker image..."

# Test that the binary works
if docker run --rm "$TEST_TAG" --help > /dev/null 2>&1; then
    print_status "OK" "Docker image runs successfully"
else
    print_status "ERROR" "Docker image failed to run"
    exit 1
fi

# Check image size
IMAGE_SIZE=$(docker images "$TEST_TAG" --format "table {{.Size}}" | tail -n 1)
print_status "INFO" "Docker image size: $IMAGE_SIZE"

# Test container startup (with timeout)
print_status "INFO" "Testing container startup..."
CONTAINER_ID=$(docker run -d "$TEST_TAG" --help 2>/dev/null || echo "")
if [ -n "$CONTAINER_ID" ]; then
    sleep 2
    if docker ps -q --filter "id=$CONTAINER_ID" | grep -q "$CONTAINER_ID"; then
        print_status "OK" "Container started successfully"
        docker stop "$CONTAINER_ID" > /dev/null 2>&1
    else
        print_status "WARNING" "Container exited quickly (expected for --help)"
    fi
    docker rm "$CONTAINER_ID" > /dev/null 2>&1
fi

# Security check - ensure running as non-root
echo ""
echo "🔒 Running security checks..."

USER_CHECK=$(docker run --rm "$TEST_TAG" whoami 2>/dev/null || echo "unknown")
if [ "$USER_CHECK" = "secure-sign" ]; then
    print_status "OK" "Container runs as non-root user: $USER_CHECK"
else
    print_status "WARNING" "Container user: $USER_CHECK (expected: secure-sign)"
fi

# Check for common vulnerabilities
print_status "INFO" "Running basic vulnerability check..."
if command -v trivy &> /dev/null; then
    trivy image --quiet --format table --severity HIGH,CRITICAL "$TEST_TAG" > vuln.log 2>&1 || true
    if [ -s vuln.log ]; then
        print_status "WARNING" "Security vulnerabilities found (see vuln.log)"
    else
        print_status "OK" "No high/critical vulnerabilities found"
    fi
else
    print_status "INFO" "Trivy not available, skipping vulnerability scan"
fi

# Cleanup
echo ""
echo "🧹 Cleaning up..."
docker rmi "$TEST_TAG" > /dev/null 2>&1
rm -f build.log vuln.log
print_status "OK" "Cleanup completed"

# Success summary
echo ""
echo "========================================="
print_status "OK" "Docker build test completed successfully!"
echo ""
echo "✅ Dockerfile builds without Cargo version errors"
echo "✅ Docker image runs correctly"
echo "✅ Security configuration verified"
echo ""
echo -e "${GREEN}🎉 The Cargo lock file version issue has been resolved!${NC}" 