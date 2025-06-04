#!/bin/bash

# Rustfmt Configuration and Formatting Verification Script
# Copyright @ 2025 - Present, R3E Network
# 
# This script verifies that:
# 1. rustfmt.toml uses only stable features (no nightly warnings)
# 2. All code is properly formatted according to the configuration
# 3. The project maintains formatting compliance

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script info
echo -e "${GREEN}🔍 Verifying Rustfmt Configuration and Formatting${NC}"
echo "=================================================="

# Function to print status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "OK" ]; then
        echo -e "${GREEN}✅ $message${NC}"
    elif [ "$status" = "WARNING" ]; then
        echo -e "${YELLOW}⚠️  $message${NC}"
    else
        echo -e "${RED}❌ $message${NC}"
    fi
}

# Check if rustfmt.toml exists
if [ ! -f "rustfmt.toml" ]; then
    print_status "ERROR" "rustfmt.toml not found in project root"
    exit 1
fi

print_status "OK" "rustfmt.toml found"

# Check for nightly-only features in rustfmt.toml
echo ""
echo "🔍 Checking for nightly-only features..."

NIGHTLY_FEATURES=(
    "doc_comment_code_block_width"
    "comment_width"
    "normalize_comments"
    "normalize_doc_attributes"
    "format_strings"
    "format_macro_matchers"
    "empty_item_single_line"
    "struct_lit_single_line"
    "fn_single_line"
    "where_single_line"
    "imports_layout"
    "imports_granularity"
    "group_imports"
    "reorder_impl_items"
    "type_punctuation_density"
    "space_before_colon"
    "space_after_colon"
    "spaces_around_ranges"
    "overflow_delimited_expr"
    "struct_field_align_threshold"
    "match_arm_blocks"
    "brace_style"
    "control_brace_style"
    "trailing_semicolon"
    "trailing_comma"
    "inline_attribute_width"
    "format_generated_files"
    "skip_children"
)

FOUND_NIGHTLY=false
for feature in "${NIGHTLY_FEATURES[@]}"; do
    if grep -q "^${feature}\s*=" rustfmt.toml; then
        print_status "ERROR" "Found nightly-only feature: $feature"
        FOUND_NIGHTLY=true
    fi
done

if [ "$FOUND_NIGHTLY" = false ]; then
    print_status "OK" "No nightly-only features found in rustfmt.toml"
else
    echo ""
    echo -e "${RED}❌ FAIL: Nightly-only features detected in rustfmt.toml${NC}"
    echo "Please remove the nightly-only features listed above."
    echo "See docs/rustfmt-configuration.md for guidance."
    exit 1
fi

# Test rustfmt for warnings
echo ""
echo "🔍 Checking for rustfmt warnings..."

RUSTFMT_OUTPUT=$(cargo fmt --all --verbose 2>&1 || true)
if echo "$RUSTFMT_OUTPUT" | grep -q "Warning:"; then
    print_status "ERROR" "rustfmt warnings detected"
    echo "$RUSTFMT_OUTPUT"
    echo ""
    echo -e "${RED}❌ FAIL: rustfmt configuration contains unstable features${NC}"
    echo "Please update rustfmt.toml to use only stable features."
    exit 1
else
    print_status "OK" "No rustfmt warnings detected"
fi

# Check formatting compliance
echo ""
echo "🔍 Checking formatting compliance..."

if cargo fmt --all -- --check > /dev/null 2>&1; then
    print_status "OK" "All code is properly formatted"
else
    print_status "ERROR" "Code formatting issues detected"
    echo ""
    echo "The following files need formatting:"
    cargo fmt --all -- --check 2>&1 || true
    echo ""
    echo -e "${RED}❌ FAIL: Code is not properly formatted${NC}"
    echo "Run 'cargo fmt --all' to fix formatting issues."
    exit 1
fi

# Success message
echo ""
echo "=================================================="
print_status "OK" "All rustfmt checks passed successfully!"
echo ""
echo "✅ rustfmt.toml uses only stable features"
echo "✅ No rustfmt warnings detected"
echo "✅ All code is properly formatted"
echo ""
echo -e "${GREEN}🎉 Rustfmt verification completed successfully!${NC}" 