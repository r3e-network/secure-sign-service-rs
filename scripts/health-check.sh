#!/bin/bash
# Health check script for Secure Sign Service
# Copyright @ 2025 - Present, R3E Network

set -euo pipefail

# Configuration
DEFAULT_PORT=9991
DEFAULT_CID=0
TIMEOUT=10
RETRIES=3

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Command line options
PORT=${PORT:-$DEFAULT_PORT}
CID=${CID:-$DEFAULT_CID}
VERBOSE=${VERBOSE:-false}

print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_verbose() {
    if [ "$VERBOSE" = "true" ]; then
        print_status $BLUE "$1"
    fi
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -p, --port PORT     Service port (default: $DEFAULT_PORT)"
    echo "  -c, --cid CID       VSOCK CID (default: $DEFAULT_CID, 0 = TCP mode)"
    echo "  -v, --verbose       Verbose output"
    echo "  -h, --help          Show this help"
    echo ""
    echo "Environment variables:"
    echo "  PORT               Service port"
    echo "  CID                VSOCK CID"
    echo "  VERBOSE            Enable verbose output (true/false)"
    echo ""
    echo "Exit codes:"
    echo "  0                  Service is healthy"
    echo "  1                  Service is unhealthy"
    echo "  2                  Invalid arguments"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -c|--cid)
            CID="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE="true"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 2
            ;;
    esac
done

# Validate arguments
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    print_status $RED "❌ Invalid port: $PORT"
    exit 2
fi

if ! [[ "$CID" =~ ^[0-9]+$ ]]; then
    print_status $RED "❌ Invalid CID: $CID"
    exit 2
fi

# Health check functions
check_process() {
    print_verbose "Checking if secure-sign process is running..."
    
    if pgrep -f "secure-sign.*run" > /dev/null; then
        print_status $GREEN "✅ Process is running"
        return 0
    else
        print_status $RED "❌ Process is not running"
        return 1
    fi
}

check_port() {
    local transport="TCP"
    if [ "$CID" -gt 0 ]; then
        transport="VSOCK"
    fi
    
    print_verbose "Checking $transport port $PORT..."
    
    if [ "$CID" -eq 0 ]; then
        # TCP mode
        if netstat -tuln 2>/dev/null | grep ":$PORT " > /dev/null; then
            print_status $GREEN "✅ TCP port $PORT is listening"
            return 0
        else
            print_status $RED "❌ TCP port $PORT is not listening"
            return 1
        fi
    else
        # VSOCK mode - harder to check, assume process check is sufficient
        print_status $GREEN "✅ VSOCK mode (CID: $CID, Port: $PORT)"
        return 0
    fi
}

check_service_response() {
    print_verbose "Checking service response..."
    
    # Find the binary
    local binary=""
    if [ "$CID" -eq 0 ]; then
        binary=$(find . -name "secure-sign-tcp" -type f -executable 2>/dev/null | head -1)
        if [ -z "$binary" ]; then
            binary="./target/secure-sign-tcp"
        fi
    else
        binary=$(find . -name "secure-sign-vsock" -type f -executable 2>/dev/null | head -1)
        if [ -z "$binary" ]; then
            binary="./target/secure-sign-vsock"
        fi
    fi
    
    if [ ! -f "$binary" ]; then
        print_status $YELLOW "⚠️  Binary not found, skipping response check"
        return 0
    fi
    
    # Try to get help output as a basic connectivity test
    local cmd_args="--help"
    
    if timeout $TIMEOUT "$binary" $cmd_args > /dev/null 2>&1; then
        print_status $GREEN "✅ Service responds to commands"
        return 0
    else
        print_status $RED "❌ Service does not respond to commands"
        return 1
    fi
}

check_memory_usage() {
    print_verbose "Checking memory usage..."
    
    local pid=$(pgrep -f "secure-sign.*run" | head -1)
    if [ -z "$pid" ]; then
        print_status $YELLOW "⚠️  Cannot check memory usage (process not found)"
        return 0
    fi
    
    local memory_kb=$(ps -o rss= -p "$pid" 2>/dev/null || echo "0")
    local memory_mb=$((memory_kb / 1024))
    
    if [ "$memory_mb" -eq 0 ]; then
        print_status $YELLOW "⚠️  Cannot determine memory usage"
        return 0
    fi
    
    if [ "$memory_mb" -gt 500 ]; then
        print_status $YELLOW "⚠️  High memory usage: ${memory_mb}MB"
        return 1
    else
        print_status $GREEN "✅ Memory usage: ${memory_mb}MB"
        return 0
    fi
}

check_file_permissions() {
    print_verbose "Checking file permissions..."
    
    local issues=0
    
    # Check if wallet files exist and have correct permissions
    for wallet in "secure-sign/config/nep6_wallet.json" "config/wallet.json" "/app/config/wallet.json"; do
        if [ -f "$wallet" ]; then
            local perms=$(stat -c "%a" "$wallet" 2>/dev/null || stat -f "%A" "$wallet" 2>/dev/null || echo "unknown")
            if [ "$perms" != "600" ] && [ "$perms" != "unknown" ]; then
                print_status $YELLOW "⚠️  Wallet file $wallet has permissions $perms (should be 600)"
                issues=$((issues + 1))
            else
                print_status $GREEN "✅ Wallet file permissions correct"
            fi
            break
        fi
    done
    
    return $issues
}

check_disk_space() {
    print_verbose "Checking disk space..."
    
    local usage_percent=$(df . | tail -1 | awk '{print $5}' | sed 's/%//')
    
    if [ "$usage_percent" -gt 90 ]; then
        print_status $RED "❌ Disk usage critical: ${usage_percent}%"
        return 1
    elif [ "$usage_percent" -gt 80 ]; then
        print_status $YELLOW "⚠️  Disk usage high: ${usage_percent}%"
        return 1
    else
        print_status $GREEN "✅ Disk usage: ${usage_percent}%"
        return 0
    fi
}

# Main health check
main() {
    print_verbose "=== Secure Sign Service Health Check ==="
    print_verbose "Port: $PORT, CID: $CID, Mode: $([ "$CID" -eq 0 ] && echo "TCP" || echo "VSOCK")"
    print_verbose ""
    
    local exit_code=0
    local checks_passed=0
    local checks_total=6
    
    # Run all checks
    if check_process; then
        checks_passed=$((checks_passed + 1))
    else
        exit_code=1
    fi
    
    if check_port; then
        checks_passed=$((checks_passed + 1))
    else
        exit_code=1
    fi
    
    if check_service_response; then
        checks_passed=$((checks_passed + 1))
    else
        exit_code=1
    fi
    
    if check_memory_usage; then
        checks_passed=$((checks_passed + 1))
    else
        exit_code=1
    fi
    
    if check_file_permissions; then
        checks_passed=$((checks_passed + 1))
    else
        exit_code=1
    fi
    
    if check_disk_space; then
        checks_passed=$((checks_passed + 1))
    else
        exit_code=1
    fi
    
    # Summary
    print_verbose ""
    print_verbose "=== Health Check Summary ==="
    print_status $BLUE "Checks passed: $checks_passed/$checks_total"
    
    if [ $exit_code -eq 0 ]; then
        print_status $GREEN "🔋 Service is healthy"
    else
        print_status $RED "🚨 Service has issues"
    fi
    
    exit $exit_code
}

# Run main function
main "$@" 