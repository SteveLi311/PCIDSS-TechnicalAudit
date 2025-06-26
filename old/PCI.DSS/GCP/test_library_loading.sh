#\!/usr/bin/env bash

# Test loading all 4 framework libraries
LIB_DIR="./lib"

echo "Testing 4-library framework loading..."

# Load libraries in order
echo "Loading gcp_common.sh..."
source "$LIB_DIR/gcp_common.sh" || { echo "Failed to load gcp_common.sh"; exit 1; }

echo "Loading gcp_permissions.sh..."
source "$LIB_DIR/gcp_permissions.sh" || { echo "Failed to load gcp_permissions.sh"; exit 1; }

echo "Loading gcp_html_report.sh..."
source "$LIB_DIR/gcp_html_report.sh" || { echo "Failed to load gcp_html_report.sh"; exit 1; }

echo "Loading gcp_scope_mgmt.sh..."
source "$LIB_DIR/gcp_scope_mgmt.sh" || { echo "Failed to load gcp_scope_mgmt.sh"; exit 1; }

echo "✅ All 4 libraries loaded successfully\!"

# Test a few core functions exist
echo "Testing core function availability..."
type debug_log >/dev/null 2>&1 && echo "✅ gcp_common functions available"
type check_all_permissions >/dev/null 2>&1 && echo "✅ gcp_permissions functions available"  
type generate_final_report >/dev/null 2>&1 && echo "✅ gcp_html_report functions available"
type setup_assessment_scope >/dev/null 2>&1 && echo "✅ gcp_scope_mgmt functions available"

echo "Framework integration test complete\!"
EOF < /dev/null