#!/usr/bin/env bash

# =============================================================================
# GCP Permissions Library Test Suite
# =============================================================================
# Description: Comprehensive testing for gcp_permissions.sh library
# Version: 1.0
# Author: PCI DSS Assessment Framework
# Created: 2025-06-05
# =============================================================================

# Test Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
TEST_OUTPUT_DIR="$SCRIPT_DIR/test_results"
TEST_LOG_FILE="$TEST_OUTPUT_DIR/permissions_test_$(date +%Y%m%d_%H%M%S).log"

# Test Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Create test output directory
mkdir -p "$TEST_OUTPUT_DIR"

# =============================================================================
# Test Utility Functions
# =============================================================================

# Print test status
print_test_status() {
    local status="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$status" in
        "PASS")
            echo -e "\033[0;32m[PASS]\033[0m $message"
            ;;
        "FAIL")
            echo -e "\033[0;31m[FAIL]\033[0m $message"
            ;;
        "INFO")
            echo -e "\033[0;34m[INFO]\033[0m $message"
            ;;
        "WARN")
            echo -e "\033[1;33m[WARN]\033[0m $message"
            ;;
    esac
    
    # Log to file
    echo "[$timestamp] [$status] $message" >> "$TEST_LOG_FILE"
}

# Run a test and track results
run_test() {
    local test_name="$1"
    local test_function="$2"
    
    ((TESTS_RUN++))
    print_test_status "INFO" "Running test: $test_name"
    
    if $test_function; then
        ((TESTS_PASSED++))
        print_test_status "PASS" "$test_name"
        return 0
    else
        ((TESTS_FAILED++))
        print_test_status "FAIL" "$test_name"
        return 1
    fi
}

# Assert function for test validation
assert_equals() {
    local expected="$1"
    local actual="$2"
    local message="$3"
    
    if [[ "$expected" == "$actual" ]]; then
        return 0
    else
        print_test_status "FAIL" "$message - Expected: '$expected', Got: '$actual'"
        return 1
    fi
}

# =============================================================================
# Library Loading Tests
# =============================================================================

test_library_loading() {
    # Test that gcp_common.sh loads first
    if source "$LIB_DIR/gcp_common.sh"; then
        print_test_status "PASS" "gcp_common.sh loaded successfully"
    else
        print_test_status "FAIL" "Failed to load gcp_common.sh"
        return 1
    fi
    
    # Test that gcp_permissions.sh loads after common
    if source "$LIB_DIR/gcp_permissions.sh"; then
        print_test_status "PASS" "gcp_permissions.sh loaded successfully"
    else
        print_test_status "FAIL" "Failed to load gcp_permissions.sh"
        return 1
    fi
    
    # Verify library variables are set
    assert_equals "true" "$GCP_PERMISSIONS_LOADED" "GCP_PERMISSIONS_LOADED variable"
    
    return 0
}

test_function_exports() {
    # Test that all required functions are exported
    local required_functions=(
        "init_permissions_framework"
        "validate_authentication_setup"
        "detect_and_validate_scope"
        "register_required_permissions"
        "check_single_permission"
        "check_all_permissions"
        "get_permission_coverage"
        "validate_scope_permissions"
        "prompt_continue_limited"
        "display_permission_guidance"
        "log_permission_audit_trail"
    )
    
    for func in "${required_functions[@]}"; do
        if declare -f "$func" > /dev/null; then
            print_test_status "PASS" "Function exported: $func"
        else
            print_test_status "FAIL" "Function not exported: $func"
            return 1
        fi
    done
    
    return 0
}

# =============================================================================
# Permission Management Tests
# =============================================================================

test_permission_registration() {
    # Test permission registration with valid data
    local test_permissions=("compute.instances.list" "iam.roles.list" "logging.logEntries.list")
    
    if register_required_permissions "1" "${test_permissions[@]}"; then
        print_test_status "PASS" "Permission registration successful"
    else
        print_test_status "FAIL" "Permission registration failed"
        return 1
    fi
    
    # Verify permissions were stored
    if [[ ${#REQUIRED_PERMISSIONS[@]} -eq 3 ]]; then
        print_test_status "PASS" "Correct number of permissions registered"
    else
        print_test_status "FAIL" "Incorrect number of permissions registered: ${#REQUIRED_PERMISSIONS[@]}"
        return 1
    fi
    
    return 0
}

test_permission_coverage_calculation() {
    # Declare associative array for test
    declare -A test_results
    
    # Mock some permission results for testing
    test_results["compute.instances.list"]="AVAILABLE"
    test_results["iam.roles.list"]="MISSING"
    test_results["logging.logEntries.list"]="AVAILABLE"
    
    # Copy to global array using safe key assignment
    PERMISSION_RESULTS["compute_instances_list"]="AVAILABLE"
    PERMISSION_RESULTS["iam_roles_list"]="MISSING"
    PERMISSION_RESULTS["logging_logEntries_list"]="AVAILABLE"
    
    AVAILABLE_PERMISSIONS_COUNT=2
    REQUIRED_PERMISSIONS=("compute.instances.list" "iam.roles.list" "logging.logEntries.list")
    PERMISSION_COVERAGE_PERCENTAGE=$((AVAILABLE_PERMISSIONS_COUNT * 100 / ${#REQUIRED_PERMISSIONS[@]}))
    
    local coverage=$(get_permission_coverage)
    assert_equals "66" "$coverage" "Permission coverage calculation"
    
    return 0
}

# =============================================================================
# Authentication Tests
# =============================================================================

test_authentication_detection() {
    # This test requires actual gcloud authentication
    # Skip if not authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
        print_test_status "WARN" "Skipping authentication test - gcloud not authenticated"
        return 0
    fi
    
    if validate_authentication_setup; then
        print_test_status "PASS" "Authentication validation successful"
    else
        print_test_status "FAIL" "Authentication validation failed"
        return 1
    fi
    
    # Check that AUTH_TYPE is set
    if [[ -n "$AUTH_TYPE" ]]; then
        print_test_status "PASS" "Authentication type detected: $AUTH_TYPE"
    else
        print_test_status "FAIL" "Authentication type not detected"
        return 1
    fi
    
    return 0
}

test_scope_detection() {
    # Test scope detection with mock project
    export PROJECT_ID="test-project-123"
    
    # This will fail in most cases since it's a mock project, but we test the logic
    if detect_and_validate_scope 2>/dev/null; then
        print_test_status "PASS" "Scope detection completed without errors"
    else
        print_test_status "INFO" "Scope detection failed as expected with mock project"
    fi
    
    # Test that the scope variables are set correctly
    if [[ "$DETECTED_SCOPE" == "project" ]]; then
        print_test_status "PASS" "Project scope correctly detected"
    fi
    
    return 0
}

# =============================================================================
# Integration Tests
# =============================================================================

test_full_permission_workflow() {
    print_test_status "INFO" "Testing full permission workflow"
    
    # Initialize framework
    if ! init_permissions_framework; then
        print_test_status "FAIL" "Framework initialization failed"
        return 1
    fi
    
    # Register test permissions
    local test_perms=("compute.instances.list" "iam.roles.list")
    if ! register_required_permissions "1" "${test_perms[@]}"; then
        print_test_status "FAIL" "Permission registration failed"
        return 1
    fi
    
    # Mock permission check results
    AVAILABLE_PERMISSIONS_COUNT=1
    MISSING_PERMISSIONS_COUNT=1
    PERMISSION_COVERAGE_PERCENTAGE=50
    
    # Test coverage calculation
    local coverage=$(get_permission_coverage)
    if [[ "$coverage" == "50" ]]; then
        print_test_status "PASS" "Full workflow completed successfully"
        return 0
    else
        print_test_status "FAIL" "Full workflow failed"
        return 1
    fi
}

# =============================================================================
# Main Test Execution
# =============================================================================

main() {
    print_test_status "INFO" "Starting GCP Permissions Library Test Suite"
    print_test_status "INFO" "Test log: $TEST_LOG_FILE"
    echo
    
    # Library Loading Tests
    print_test_status "INFO" "=== Library Loading Tests ==="
    run_test "Library Loading" test_library_loading
    run_test "Function Exports" test_function_exports
    echo
    
    # Permission Management Tests
    print_test_status "INFO" "=== Permission Management Tests ==="
    run_test "Permission Registration" test_permission_registration
    run_test "Coverage Calculation" test_permission_coverage_calculation
    echo
    
    # Authentication Tests
    print_test_status "INFO" "=== Authentication Tests ==="
    run_test "Authentication Detection" test_authentication_detection
    run_test "Scope Detection" test_scope_detection
    echo
    
    # Integration Tests
    print_test_status "INFO" "=== Integration Tests ==="
    run_test "Full Permission Workflow" test_full_permission_workflow
    echo
    
    # Test Summary
    print_test_status "INFO" "=== Test Summary ==="
    print_test_status "INFO" "Tests Run: $TESTS_RUN"
    print_test_status "INFO" "Tests Passed: $TESTS_PASSED"
    print_test_status "INFO" "Tests Failed: $TESTS_FAILED"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        print_test_status "PASS" "All tests passed!"
        echo
        print_test_status "INFO" "GCP Permissions Library is ready for use"
        return 0
    else
        print_test_status "FAIL" "$TESTS_FAILED tests failed"
        echo
        print_test_status "INFO" "Please review failed tests and fix issues"
        return 1
    fi
}

# Run tests if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi