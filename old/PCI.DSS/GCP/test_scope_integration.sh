#!/usr/bin/env bash

# =============================================================================
# Scope Management Library Integration Test
# =============================================================================
# Tests integration of gcp_scope_mgmt.sh with existing requirement script patterns
# This validates that the scope management library works with current CLI patterns

set -euo pipefail

# Load required libraries
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh"
source "$LIB_DIR/gcp_scope_mgmt.sh"

# Test configuration
TEST_PASSED=0
TEST_FAILED=0

# =============================================================================
# Test Helper Functions
# =============================================================================

run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo "Running test: $test_name"
    
    if eval "$test_command"; then
        echo "✅ PASS: $test_name"
        ((TEST_PASSED++))
    else
        echo "❌ FAIL: $test_name"
        ((TEST_FAILED++))
    fi
    echo ""
}

# =============================================================================
# Integration Tests
# =============================================================================

test_cli_integration() {
    echo "=== Testing CLI Integration ==="
    
    # Mock gcloud for CLI integration tests
    gcloud() {
        case "$*" in
            "projects describe test-project-123")
                echo "name: projects/test-project-123"
                return 0
                ;;
            "config get-value project")
                echo "test-project-123"
                return 0
                ;;
            *)
                echo "Mock gcloud: $*" >&2
                return 0
                ;;
        esac
    }
    export -f gcloud
    
    # Test 1: Parse arguments and setup project scope
    run_test "Project scope setup" '
        SCOPE_TYPE="project"
        PROJECT_ID="test-project-123"
        setup_assessment_scope >/dev/null 2>&1
    '
    
    # Test 2: Validate scope state after setup
    run_test "Scope state validation" '
        [[ "$ASSESSMENT_SCOPE" == "project" ]] && [[ "$SCOPE_VALIDATION_DONE" == "true" ]]
    '
    
    # Test 3: Get projects in scope
    run_test "Get projects in scope" '
        projects=$(get_projects_in_scope 2>/dev/null) && [[ "$projects" == "test-project-123" ]]
    '
    
    # Test 4: Build gcloud command
    run_test "Build gcloud command" '
        cmd=$(build_gcloud_command "gcloud compute instances list" 2>/dev/null)
        [[ "$cmd" == *"--project=\"test-project-123\""* ]]
    '
    
    # Clean up mock
    unset -f gcloud
}

test_function_interfaces() {
    echo "=== Testing Function Interfaces ==="
    
    # Test 5: Function availability
    run_test "All functions exported" '
        declare -F setup_assessment_scope >/dev/null &&
        declare -F get_projects_in_scope >/dev/null &&
        declare -F build_gcloud_command >/dev/null &&
        declare -F run_across_projects >/dev/null &&
        declare -F aggregate_cross_project_data >/dev/null
    '
    
    # Test 6: Error handling
    run_test "Error handling for empty command" '
        ! build_gcloud_command "" 2>/dev/null
    '
    
    # Test 7: Data aggregation
    run_test "Data aggregation functionality" '
        ASSESSMENT_SCOPE="project"
        PROJECT_ID="test-project"
        result=$(aggregate_cross_project_data "instance-1
instance-2" 2>/dev/null)
        [[ "$result" == *"Resource: instance-1"* ]] && [[ "$result" == *"Resource: instance-2"* ]]
    '
}

test_existing_script_patterns() {
    echo "=== Testing Compatibility with Existing Patterns ==="
    
    # Test 8: Backward compatibility variables
    run_test "Global variable compatibility" '
        [[ -n "$ASSESSMENT_SCOPE" ]] && [[ -n "$PROJECT_ID" ]]
    '
    
    # Test 9: Integration with gcp_common.sh patterns
    run_test "print_status function integration" '
        print_status "INFO" "Test message" >/dev/null 2>&1
    '
    
    # Test 10: Library loading
    run_test "Library loading validation" '
        [[ "$GCP_SCOPE_LOADED" == "true" ]] && [[ "$GCP_COMMON_LOADED" == "true" ]]
    '
}

# =============================================================================
# Mock Tests (Basic Functionality)
# =============================================================================

test_mock_execution() {
    echo "=== Testing Mock Execution Patterns ==="
    
    # Mock gcloud command for testing
    gcloud() {
        case "$*" in
            "projects describe test-project-123")
                echo "name: projects/test-project-123"
                return 0
                ;;
            "compute --project=\"test-project-123\" instances list --format=value(name)")
                echo "instance-1"
                echo "instance-2"
                return 0
                ;;
            *)
                echo "Mock gcloud: $*" >&2
                return 0
                ;;
        esac
    }
    export -f gcloud
    
    # Test 11: Mock command execution
    run_test "Mock command execution" '
        result=$(run_across_projects "gcloud compute instances list --format=value(name)" 2>/dev/null)
        [[ "$result" == *"instance-1"* ]] && [[ "$result" == *"instance-2"* ]]
    '
    
    # Clean up mock
    unset -f gcloud
}

# =============================================================================
# Main Test Execution
# =============================================================================

main() {
    echo "GCP Scope Management Library Integration Test"
    echo "============================================="
    echo ""
    
    # Initialize test environment
    VERBOSE=false  # Reduce output during testing
    
    # Run test suites
    test_cli_integration
    test_function_interfaces  
    test_existing_script_patterns
    test_mock_execution
    
    # Print test summary
    echo "=== Test Summary ==="
    echo "Tests Passed: $TEST_PASSED"
    echo "Tests Failed: $TEST_FAILED"
    echo "Total Tests: $((TEST_PASSED + TEST_FAILED))"
    echo ""
    
    if [[ $TEST_FAILED -eq 0 ]]; then
        echo "🎉 All integration tests passed!"
        echo "✅ Scope management library is compatible with existing patterns"
        return 0
    else
        echo "⚠️  Some integration tests failed"
        echo "❌ Review failed tests before proceeding"
        return 1
    fi
}

# Run tests if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi