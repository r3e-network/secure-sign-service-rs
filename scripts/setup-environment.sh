#!/bin/bash
# Environment setup script for Secure Sign Service
# Copyright @ 2025 - Present, R3E Network

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
RUST_MIN_VERSION="1.70.0"
REQUIRED_TOOLS=("git" "curl" "protoc")
RUST_TARGETS=("x86_64-unknown-linux-musl")

print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_header() {
    echo "=================================================="
    print_status $BLUE "$1"
    echo "=================================================="
}

# Check if running as root
check_not_root() {
    if [[ $EUID -eq 0 ]]; then
        print_status $RED "❌ This script should not be run as root for security reasons."
        exit 1
    fi
}

# Detect operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            echo "ubuntu"
        elif command -v yum >/dev/null 2>&1; then
            echo "centos"
        elif command -v apk >/dev/null 2>&1; then
            echo "alpine"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

# Install system dependencies
install_system_deps() {
    local os=$(detect_os)
    print_header "Installing System Dependencies"
    
    case $os in
        "ubuntu")
            print_status $BLUE "Updating package lists..."
            sudo apt-get update
            print_status $BLUE "Installing required packages..."
            sudo apt-get install -y curl git build-essential protobuf-compiler musl-tools
            ;;
        "centos")
            print_status $BLUE "Installing required packages..."
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y curl git protobuf-compiler
            ;;
        "alpine")
            print_status $BLUE "Installing required packages..."
            sudo apk add --no-cache curl git build-base protobuf-dev protobuf musl-dev
            ;;
        "macos")
            if command -v brew >/dev/null 2>&1; then
                print_status $BLUE "Installing required packages via Homebrew..."
                brew install protobuf
            else
                print_status $YELLOW "⚠️  Homebrew not found. Please install: brew install protobuf"
            fi
            ;;
        *)
            print_status $YELLOW "⚠️  Unknown OS. Please manually install: git, curl, protobuf-compiler"
            ;;
    esac
    
    print_status $GREEN "✅ System dependencies installed"
}

# Check if tool exists
check_tool() {
    if command -v "$1" >/dev/null 2>&1; then
        print_status $GREEN "✅ $1 is available"
        return 0
    else
        print_status $RED "❌ $1 is not available"
        return 1
    fi
}

# Install Rust
install_rust() {
    print_header "Setting Up Rust Environment"
    
    if command -v rustc >/dev/null 2>&1; then
        local current_version=$(rustc --version | cut -d' ' -f2)
        print_status $GREEN "✅ Rust is already installed: $current_version"
        
        # Check if version is sufficient
        if [ "$(printf '%s\n' "$RUST_MIN_VERSION" "$current_version" | sort -V | head -n1)" = "$RUST_MIN_VERSION" ]; then
            print_status $GREEN "✅ Rust version is sufficient"
        else
            print_status $YELLOW "⚠️  Rust version $current_version is below minimum $RUST_MIN_VERSION"
            print_status $BLUE "Updating Rust..."
            rustup update
        fi
    else
        print_status $BLUE "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
        source "$HOME/.cargo/env"
        print_status $GREEN "✅ Rust installed successfully"
    fi
    
    # Install required targets
    print_status $BLUE "Installing Rust targets..."
    for target in "${RUST_TARGETS[@]}"; do
        rustup target add "$target"
        print_status $GREEN "✅ Added target: $target"
    done
    
    # Install useful tools
    print_status $BLUE "Installing additional Rust tools..."
    cargo install cargo-audit cargo-deny cargo-cyclonedx --force
    print_status $GREEN "✅ Rust tools installed"
}

# Setup project environment
setup_project() {
    print_header "Setting Up Project Environment"
    
    # Create directories
    print_status $BLUE "Creating project directories..."
    mkdir -p {logs,backup,monitoring,scripts}
    
    # Set up git hooks (if in git repo)
    if [ -d ".git" ]; then
        print_status $BLUE "Setting up git hooks..."
        cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Pre-commit hook for Secure Sign Service

echo "Running pre-commit checks..."

# Run security and quality checks
if command -v make >/dev/null 2>&1; then
    make pre-commit
else
    echo "Warning: make not available, skipping checks"
fi
EOF
        chmod +x .git/hooks/pre-commit
        print_status $GREEN "✅ Git hooks configured"
    fi
    
    # Create environment file template
    if [ ! -f ".env.example" ]; then
        cat > .env.example << 'EOF'
# Secure Sign Service Environment Variables
# Copy this file to .env and customize for your environment

# Logging
RUST_LOG=info

# Service Configuration
SECURE_SIGN_PORT=9991
SECURE_SIGN_WALLET_PATH=secure-sign/config/nep6_wallet.json

# Development
RUST_BACKTRACE=1

# Production (uncomment and configure)
# SECURE_SIGN_BIND_ADDRESS=127.0.0.1
# SECURE_SIGN_MAX_REQUESTS=1000
# SECURE_SIGN_TLS_CERT_PATH=/path/to/cert.pem
# SECURE_SIGN_TLS_KEY_PATH=/path/to/key.pem
EOF
        print_status $GREEN "✅ Environment template created (.env.example)"
    fi
    
    print_status $GREEN "✅ Project environment setup complete"
}

# Verify installation
verify_installation() {
    print_header "Verifying Installation"
    
    local all_good=true
    
    # Check required tools
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! check_tool "$tool"; then
            all_good=false
        fi
    done
    
    # Check Rust
    if check_tool "rustc" && check_tool "cargo"; then
        local rust_version=$(rustc --version)
        print_status $GREEN "✅ Rust: $rust_version"
    else
        print_status $RED "❌ Rust installation failed"
        all_good=false
    fi
    
    # Check targets
    print_status $BLUE "Checking Rust targets..."
    for target in "${RUST_TARGETS[@]}"; do
        if rustup target list --installed | grep -q "$target"; then
            print_status $GREEN "✅ Target installed: $target"
        else
            print_status $RED "❌ Target missing: $target"
            all_good=false
        fi
    done
    
    # Try to build the project
    if [ -f "Cargo.toml" ]; then
        print_status $BLUE "Testing build..."
        if cargo check --all-targets >/dev/null 2>&1; then
            print_status $GREEN "✅ Project builds successfully"
        else
            print_status $YELLOW "⚠️  Project build check failed (may need dependencies)"
        fi
    fi
    
    if [ "$all_good" = true ]; then
        print_status $GREEN "🎉 Environment setup completed successfully!"
        print_status $BLUE "Next steps:"
        echo "  1. Review .env.example and create .env if needed"
        echo "  2. Run 'make check' to verify everything works"
        echo "  3. Run 'make tcp' to build the TCP version"
        echo "  4. Check docs/ for deployment guides"
    else
        print_status $RED "❌ Some issues were found. Please resolve them before proceeding."
        exit 1
    fi
}

# Usage information
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --no-rust      Skip Rust installation"
    echo "  --no-deps      Skip system dependencies"
    echo "  --help         Show this help"
    echo ""
    echo "This script sets up the development environment for Secure Sign Service."
}

# Main execution
main() {
    local skip_rust=false
    local skip_deps=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-rust)
                skip_rust=true
                shift
                ;;
            --no-deps)
                skip_deps=true
                shift
                ;;
            --help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    print_header "Secure Sign Service - Environment Setup"
    print_status $BLUE "Setting up development environment..."
    echo ""
    
    check_not_root
    
    if [ "$skip_deps" = false ]; then
        install_system_deps
        echo ""
    fi
    
    if [ "$skip_rust" = false ]; then
        install_rust
        echo ""
    fi
    
    setup_project
    echo ""
    
    verify_installation
}

# Run main function with all arguments
main "$@" 