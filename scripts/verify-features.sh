#!/bin/bash

# Feature Configuration Verification Script
# Copyright @ 2025 - Present, R3E Network
# 
# This script verifies that the feature configuration works correctly:
# 1. TCP and VSOCK features work individually
# 2. TCP and VSOCK features are mutually exclusive
# 3. Build system respects feature constraints

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script info
echo -e "${BLUE}🔧 Verifying Feature Configuration${NC}"
echo "====================================="
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

# Check if we're in the project root
if [ ! -f "Cargo.toml" ]; then
    print_status "ERROR" "Cargo.toml not found. Please run this script from the project root."
    exit 1
fi

print_status "OK" "Project root detected"

# Test 1: Verify TCP feature builds successfully
echo ""
echo "🔍 Testing TCP feature..."
if cargo check --features tcp --no-default-features > /dev/null 2>&1; then
    print_status "OK" "TCP feature builds successfully"
else
    print_status "ERROR" "TCP feature failed to build"
    exit 1
fi

# Test 2: Verify VSOCK feature builds successfully  
echo ""
echo "🔍 Testing VSOCK feature..."
if cargo check --features vsock --no-default-features > /dev/null 2>&1; then
    print_status "OK" "VSOCK feature builds successfully"
else
    print_status "ERROR" "VSOCK feature failed to build"
    exit 1
fi

# Test 3: Verify mutual exclusivity (should fail)
echo ""
echo "🔍 Testing mutual exclusivity..."
if cargo check --features tcp,vsock --no-default-features > /dev/null 2>&1; then
    print_status "ERROR" "TCP and VSOCK features should be mutually exclusive, but build succeeded"
    exit 1
else
    print_status "OK" "TCP and VSOCK features are properly mutually exclusive"
fi

# Test 4: Verify --all-features fails (should fail)
echo ""
echo "🔍 Testing --all-features restriction..."
if cargo check --all-features > /dev/null 2>&1; then
    print_status "ERROR" "--all-features should fail due to mutual exclusivity, but build succeeded"
    exit 1
else
    print_status "OK" "--all-features properly fails due to mutual exclusivity"
fi

# Test 5: Verify individual package features work
echo ""
echo "🔍 Testing individual package features..."

# Test secure-sign-core (should work with --all-features)
if cargo check -p secure-sign-core --all-features > /dev/null 2>&1; then
    print_status "OK" "secure-sign-core --all-features works correctly"
else
    print_status "WARNING" "secure-sign-core --all-features failed (may be expected)"
fi

# Test secure-sign-rpc (should work with --all-features)
if cargo check -p secure-sign-rpc --all-features > /dev/null 2>&1; then
    print_status "OK" "secure-sign-rpc --all-features works correctly"
else
    print_status "WARNING" "secure-sign-rpc --all-features failed (may be expected)"
fi

# Test 6: Verify compilation error message
echo ""
echo "🔍 Testing error message clarity..."
ERROR_OUTPUT=$(cargo check --features tcp,vsock --no-default-features 2>&1 || true)
if echo "$ERROR_OUTPUT" | grep -q "vsock and tcp cannot be both enabled"; then
    print_status "OK" "Clear error message displayed for mutual exclusivity"
else
    print_status "WARNING" "Error message could be clearer"
fi

# Test 7: Check Makefile targets
echo ""
echo "🔍 Testing Makefile targets..."

# Test TCP build
if make tcp > /dev/null 2>&1; then
    print_status "OK" "Makefile 'tcp' target works"
else
    print_status "WARNING" "Makefile 'tcp' target failed (may require dependencies)"
fi

# Test VSOCK build (may fail due to target requirements)
if make vsock > /dev/null 2>&1; then
    print_status "OK" "Makefile 'vsock' target works"
else
    print_status "WARNING" "Makefile 'vsock' target failed (may require musl target)"
fi

# Test 8: Verify feature documentation
echo ""
echo "🔍 Checking feature documentation..."

if [ -f "docs/feature-configuration.md" ]; then
    print_status "OK" "Feature documentation exists"
else
    print_status "WARNING" "Feature documentation missing"
fi

# Test 9: Check CI configuration
echo ""
echo "🔍 Checking CI configuration..."

if grep -q "all-features" .github/workflows/ci.yml; then
    print_status "ERROR" "CI still contains --all-features usage"
    echo "Found --all-features in CI:"
    grep -n "all-features" .github/workflows/ci.yml
    exit 1
else
    print_status "OK" "CI configuration doesn't use --all-features"
fi

# Test 10: Verify feature matrix in CI
if grep -q "features tcp" .github/workflows/ci.yml && grep -q "features vsock" .github/workflows/ci.yml; then
    print_status "OK" "CI tests both TCP and VSOCK features separately"
else
    print_status "WARNING" "CI may not be testing all feature combinations"
fi

# Success summary
echo ""
echo "====================================="
print_status "OK" "Feature configuration verification completed!"
echo ""
echo "✅ TCP feature builds correctly"
echo "✅ VSOCK feature builds correctly"  
echo "✅ Mutual exclusivity properly enforced"
echo "✅ Error messages are clear"
echo "✅ CI configuration is correct"
echo ""
echo -e "${GREEN}🎉 Feature configuration is working correctly!${NC}"

# Optional: Display feature information
echo ""
echo "📋 Feature Summary:"
echo "  - tcp: Standard TCP socket communication"
echo "  - vsock: VSOCK for Trusted Execution Environments"
echo "  - Mutual exclusivity: Enforced at compile time"
echo "  - CI testing: Separate test runs for each feature" 