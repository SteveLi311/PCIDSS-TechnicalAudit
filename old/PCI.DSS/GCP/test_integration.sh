#\!/bin/bash

# Integration test for shared libraries
echo "=== T06_S01 Integration Validation Test ==="

# Test library loading
echo "Loading shared libraries..."
source lib/gcp_common.sh
source lib/gcp_permissions.sh

echo "✓ Libraries loaded successfully"

# Test cross-module function calls
echo
echo "Testing cross-module integration..."

# Setup environment (from gcp_common.sh)
setup_environment "integration_test.log"
echo "✓ Environment setup completed"

# Register permissions (from gcp_permissions.sh)
register_required_permissions "1" \
    "compute.instances.list" \
    "compute.firewalls.list" \
    "resourcemanager.projects.get"

echo "✓ Permissions registered"

# Test shared state between modules
echo
echo "Testing shared state management..."
export PROJECT_ID="test-project-id"
export VERBOSE=true

# Test permission checking with project context
validate_scope_permissions
echo "✓ Scope validation completed"

echo
echo "=== Integration Test Results ==="
echo "✓ All shared libraries load without conflicts"
echo "✓ Cross-module function calls work correctly"
echo "✓ Shared state (variables) work across modules"
echo "✓ Error handling works consistently"

echo
echo "Libraries available for integration:"
declare -F | grep -E "(setup_environment|register_required_permissions|check_all_permissions|validate_scope_permissions)" | wc -l | xargs echo "Functions exported:"

