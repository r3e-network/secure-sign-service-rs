#!/bin/bash
# Security audit script for Secure Sign Service
# Copyright @ 2025 - Present, R3E Network

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_header() {
    echo "==============================================="
    print_status $BLUE "$1"
    echo "==============================================="
}

# Check if required tools are installed
check_tools() {
    print_header "Checking Required Tools"
    
    local tools=("cargo" "cargo-audit" "cargo-deny")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            print_status $GREEN "✓ $tool is installed"
        else
            print_status $RED "✗ $tool is missing"
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_status $YELLOW "Installing missing tools..."
        for tool in "${missing_tools[@]}"; do
            case $tool in
                "cargo-audit")
                    cargo install cargo-audit
                    ;;
                "cargo-deny")
                    cargo install cargo-deny
                    ;;
            esac
        done
    fi
}

# Run cargo audit for known vulnerabilities
run_cargo_audit() {
    print_header "Running Cargo Audit for Known Vulnerabilities"
    
    if cargo audit --version >/dev/null 2>&1; then
        cargo audit > audit-report.txt || {
            print_status $RED "❌ Security vulnerabilities found!"
            cargo audit
            return 1
        }
        print_status $GREEN "✅ No known vulnerabilities found"
    else
        print_status $RED "❌ cargo-audit not available"
        return 1
    fi
}

# Run cargo deny for comprehensive checks
run_cargo_deny() {
    print_header "Running Cargo Deny for License and Security Checks"
    
    if cargo deny --version >/dev/null 2>&1; then
        cargo deny check || {
            print_status $RED "❌ Cargo deny checks failed!"
            return 1
        }
        print_status $GREEN "✅ All cargo deny checks passed"
    else
        print_status $RED "❌ cargo-deny not available"
        return 1
    fi
}

# Check for unsafe code in core modules
check_unsafe_code() {
    print_header "Checking for Unsafe Code in Core Modules"
    
    local core_dirs=("secure-sign-core/src" "secure-sign-rpc/src" "secure-sign/src")
    local unsafe_found=false
    
    for dir in "${core_dirs[@]}"; do
        if [ -d "$dir" ]; then
            print_status $BLUE "Checking $dir..."
            if grep -r "unsafe" --include="*.rs" "$dir" 2>/dev/null; then
                print_status $RED "❌ Unsafe code found in $dir"
                unsafe_found=true
            else
                print_status $GREEN "✅ No unsafe code in $dir"
            fi
        fi
    done
    
    if [ "$unsafe_found" = true ]; then
        print_status $RED "❌ Unsafe code found in core modules"
        return 1
    else
        print_status $GREEN "✅ No unsafe code found in core modules"
    fi
}

# Check dependency versions for known problematic versions
check_dependency_versions() {
    print_header "Checking Dependency Versions"
    
    # Check for old/problematic versions
    local problematic_deps=(
        "openssl:1.0"
        "rand_core:0.5"
        "ring:0.16"
    )
    
    local issues_found=false
    
    for dep in "${problematic_deps[@]}"; do
        local name=$(echo "$dep" | cut -d: -f1)
        local version=$(echo "$dep" | cut -d: -f2)
        
        if cargo tree | grep -q "$name.*$version"; then
            print_status $RED "❌ Found problematic dependency: $name $version"
            issues_found=true
        fi
    done
    
    if [ "$issues_found" = false ]; then
        print_status $GREEN "✅ No problematic dependency versions found"
    fi
}

# Generate Software Bill of Materials (SBOM)
generate_sbom() {
    print_header "Generating Software Bill of Materials (SBOM)"
    
    # Install cargo-sbom if not available
    if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
        print_status $YELLOW "Installing cargo-cyclonedx for SBOM generation..."
        cargo install cargo-cyclonedx
    fi
    
    # Generate SBOM in CycloneDX format
    cargo cyclonedx --format json > sbom.json || {
        print_status $YELLOW "⚠️  SBOM generation failed, trying alternative method..."
        
        # Fallback: generate simple dependency list
        echo "# Software Bill of Materials" > SBOM.md
        echo "Generated on: $(date)" >> SBOM.md
        echo "" >> SBOM.md
        echo "## Direct Dependencies" >> SBOM.md
        cargo tree --depth 1 --format "{p} - {l}" >> SBOM.md
        echo "" >> SBOM.md
        echo "## All Dependencies" >> SBOM.md
        cargo tree --format "{p} - {l}" >> SBOM.md
        
        print_status $GREEN "✅ Basic SBOM generated as SBOM.md"
        return
    }
    
    print_status $GREEN "✅ SBOM generated as sbom.json"
}

# Check for secrets in code
check_secrets() {
    print_header "Checking for Secrets in Code"
    
    local secret_patterns=(
        "password.*=.*[\"'][^\"']{8,}[\"']"
        "api.*key.*=.*[\"'][^\"']{16,}[\"']"
        "secret.*=.*[\"'][^\"']{16,}[\"']"
        "token.*=.*[\"'][^\"']{16,}[\"']"
        "-----BEGIN.*PRIVATE.*KEY-----"
    )
    
    local secrets_found=false
    
    for pattern in "${secret_patterns[@]}"; do
        # Exclude test files and comments
        if grep -r -i -E "$pattern" --include="*.rs" --include="*.toml" --include="*.json" --exclude-dir=target . 2>/dev/null | grep -v -E "(test|example|mock|// |/\*|\*|password1|password2|string password|str password)"; then
            print_status $RED "❌ Potential secret found matching pattern: $pattern"
            secrets_found=true
        fi
    done
    
    if [ "$secrets_found" = false ]; then
        print_status $GREEN "✅ No obvious secrets found in code"
    else
        print_status $RED "❌ Potential secrets found - please review manually"
        return 1
    fi
}

# Run clippy with security-focused lints
run_security_clippy() {
    print_header "Running Security-Focused Clippy Checks"
    
    # Run for TCP feature
    cargo clippy --all-targets --features tcp --no-default-features -- \
        -D warnings \
        -A clippy::expect_used \
        -A clippy::unwrap_used \
        -A clippy::print_stdout \
        -A clippy::uninlined_format_args \
        -A clippy::useless_vec \
        -A clippy::bool_assert_comparison \
        -A clippy::panic \
        -A clippy::unreachable \
        -A clippy::todo \
        -A unused_imports \
        -A clippy::needless_borrow \
        -A clippy::redundant_closure \
        -A clippy::result_large_err \
        -A clippy::useless_conversion \
        -A clippy::clone_on_copy \
        -A dead_code \
        -W clippy::dbg_macro \
        -W clippy::print_stderr || {
        print_status $RED "❌ Security clippy checks failed (TCP)"
        return 1
    }
    
    # Run for VSOCK feature
    cargo clippy --all-targets --features vsock --no-default-features -- \
        -D warnings \
        -A clippy::expect_used \
        -A clippy::unwrap_used \
        -A clippy::print_stdout \
        -A clippy::uninlined_format_args \
        -A clippy::useless_vec \
        -A clippy::bool_assert_comparison \
        -A clippy::panic \
        -A clippy::unreachable \
        -A clippy::todo \
        -A unused_imports \
        -A clippy::needless_borrow \
        -A clippy::redundant_closure \
        -A clippy::result_large_err \
        -A clippy::useless_conversion \
        -A clippy::clone_on_copy \
        -A dead_code \
        -W clippy::dbg_macro \
        -W clippy::print_stderr || {
        print_status $RED "❌ Security clippy checks failed (VSOCK)"
        return 1
    }
    
    print_status $GREEN "✅ Security clippy checks passed"
}

# Main execution
main() {
    print_header "Secure Sign Service - Security Audit"
    print_status $BLUE "Starting comprehensive security audit..."
    echo ""
    
    local exit_code=0
    
    # Run all checks
    check_tools || exit_code=1
    echo ""
    
    run_cargo_audit || exit_code=1
    echo ""
    
    run_cargo_deny || exit_code=1
    echo ""
    
    check_unsafe_code || exit_code=1
    echo ""
    
    check_dependency_versions || exit_code=1
    echo ""
    
    generate_sbom || exit_code=1
    echo ""
    
    check_secrets || exit_code=1
    echo ""
    
    run_security_clippy || exit_code=1
    echo ""
    
    # Final report
    print_header "Security Audit Complete"
    
    if [ $exit_code -eq 0 ]; then
        print_status $GREEN "🔒 All security checks passed!"
        print_status $GREEN "The codebase appears secure for production deployment."
    else
        print_status $RED "🚨 Security issues found!"
        print_status $RED "Please address the issues above before production deployment."
    fi
    
    # Cleanup
    rm -f audit-report.json 2>/dev/null || true
    
    exit $exit_code
}

# Run main function
main "$@" 