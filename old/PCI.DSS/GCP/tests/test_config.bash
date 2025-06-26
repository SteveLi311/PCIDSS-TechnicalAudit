#!/bin/bash

# =============================================================================
# Test Configuration for GCP Shared Library Testing Framework
# =============================================================================

# Framework Information
export TEST_FRAMEWORK_VERSION="1.0.0"
export TEST_FRAMEWORK_NAME="GCP PCI DSS Shared Library Testing Framework"

# =============================================================================
# Coverage Configuration
# =============================================================================

# Coverage Targets (percentages)
export UNIT_TEST_FUNCTION_COVERAGE_TARGET=95
export UNIT_TEST_LINE_COVERAGE_TARGET=90
export INTEGRATION_TEST_COVERAGE_TARGET=85
export OVERALL_COVERAGE_TARGET=90

# Coverage Reporting
export COVERAGE_TOOL="kcov"
export COVERAGE_OUTPUT_DIR="coverage"
export COVERAGE_HTML_REPORT="true"
export COVERAGE_XML_REPORT="true"

# =============================================================================
# Test Execution Configuration
# =============================================================================

# Test Execution Settings
export REQUIRED_TEST_PASS_RATE=100
export MAX_TEST_EXECUTION_TIME=300  # 5 minutes
export INDIVIDUAL_TEST_TIMEOUT=30   # 30 seconds per test
export PARALLEL_TEST_EXECUTION="false"  # Set to "true" to enable parallel execution
export TEST_RETRY_COUNT=0          # Number of retries for failed tests

# Test Output Configuration
export TEST_OUTPUT_FORMAT="tap"    # tap, junit, or pretty
export TEST_VERBOSE_OUTPUT="false"
export TEST_SHOW_FAILURES_ONLY="false"
export TEST_COLORIZED_OUTPUT="true"

# =============================================================================
# Quality Gates Configuration
# =============================================================================

# Test Quality Requirements
export MIN_TESTS_PER_FUNCTION=2
export MIN_ASSERTION_PER_TEST=1
export REQUIRE_SETUP_TEARDOWN="true"
export REQUIRE_TEST_DOCUMENTATION="false"

# Code Quality Gates
export ENFORCE_FUNCTION_COVERAGE="true"
export ENFORCE_LINE_COVERAGE="true"
export ENFORCE_INTEGRATION_COVERAGE="true"
export FAIL_ON_COVERAGE_BELOW_TARGET="true"

# =============================================================================
# Test Environment Configuration
# =============================================================================

# Directory Structure
export TEST_ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TEST_UNIT_DIR="$TEST_ROOT_DIR/unit"
export TEST_INTEGRATION_DIR="$TEST_ROOT_DIR/integration"
export TEST_HELPERS_DIR="$TEST_ROOT_DIR/helpers"
export TEST_MOCKS_DIR="$TEST_ROOT_DIR/mocks"
export TEST_RESULTS_DIR="$TEST_ROOT_DIR/results"
export TEST_TEMP_DIR="/tmp/gcp_tests"

# Library Paths
export LIB_ROOT_DIR="$(dirname "$TEST_ROOT_DIR")/lib"
export GCP_COMMON_LIB="$LIB_ROOT_DIR/gcp_common.sh"
export GCP_PERMISSIONS_LIB="$LIB_ROOT_DIR/gcp_permissions.sh"
export GCP_HTML_REPORT_LIB="$LIB_ROOT_DIR/gcp_html_report.sh"
export GCP_SCOPE_MGMT_LIB="$LIB_ROOT_DIR/gcp_scope_mgmt.sh"

# =============================================================================
# Mock Configuration
# =============================================================================

# Mock Settings
export ENABLE_GCLOUD_MOCKING="true"
export ENABLE_USER_INPUT_MOCKING="true"
export ENABLE_FILE_SYSTEM_MOCKING="false"
export MOCK_GCP_RESPONSES="true"

# Mock Data Configuration
export MOCK_PROJECT_ID="test-project-123"
export MOCK_ORG_ID="123456789"
export MOCK_USER_EMAIL="test-user@example.com"
export MOCK_SERVICE_ACCOUNT="test-sa@test-project-123.iam.gserviceaccount.com"

# =============================================================================
# Library Specific Configuration
# =============================================================================

# GCP Common Library Test Configuration
export GCP_COMMON_TEST_FUNCTIONS=(
    "source_gcp_libraries"
    "setup_environment"
    "parse_common_arguments"
    "show_help"
    "validate_prerequisites"
    "print_status"
    "log_debug"
    "load_requirement_config"
    "check_script_permissions"
    "cleanup_temp_files"
    "get_script_name"
)

# GCP Permissions Library Test Configuration
export GCP_PERMISSIONS_TEST_FUNCTIONS=(
    "register_required_permissions"
    "check_all_permissions"
    "get_permission_coverage"
    "validate_scope_permissions"
    "prompt_continue_limited"
)

# GCP HTML Report Library Test Configuration
export GCP_HTML_REPORT_TEST_FUNCTIONS=(
    "generate_html_report"
    "create_assessment_summary"
    "format_permission_results"
    "add_visual_indicators"
)

# GCP Scope Management Library Test Configuration
export GCP_SCOPE_MGMT_TEST_FUNCTIONS=(
    "setup_scope_management"
    "validate_organization_scope"
    "aggregate_project_results"
    "manage_assessment_scope"
)

# Expected Function Counts for Validation
export EXPECTED_GCP_COMMON_FUNCTION_COUNT=11
export EXPECTED_GCP_PERMISSIONS_FUNCTION_COUNT=5
export EXPECTED_GCP_HTML_REPORT_FUNCTION_COUNT=4
export EXPECTED_GCP_SCOPE_MGMT_FUNCTION_COUNT=4

# =============================================================================
# Test Data Configuration
# =============================================================================

# Sample Test Permissions
export SAMPLE_COMPUTE_PERMISSIONS=(
    "compute.instances.list"
    "compute.instances.get"
    "compute.zones.list"
    "compute.machineTypes.list"
)

export SAMPLE_IAM_PERMISSIONS=(
    "iam.roles.list"
    "iam.roles.get"
    "iam.serviceAccounts.list"
    "iam.serviceAccounts.get"
)

export SAMPLE_STORAGE_PERMISSIONS=(
    "storage.buckets.list"
    "storage.buckets.get"
    "storage.objects.list"
    "storage.objects.get"
)

# =============================================================================
# Test Validation Configuration
# =============================================================================

# Validation Rules
export VALIDATE_FUNCTION_EXPORTS="true"
export VALIDATE_LIBRARY_LOADING="true"
export VALIDATE_ERROR_HANDLING="true"
export VALIDATE_INPUT_SANITIZATION="true"
export VALIDATE_OUTPUT_FORMAT="true"

# Test Requirements Validation
export REQUIRE_UNIT_TESTS="true"
export REQUIRE_INTEGRATION_TESTS="true"
export REQUIRE_MOCK_TESTS="true"
export REQUIRE_ERROR_TESTS="true"
export REQUIRE_EDGE_CASE_TESTS="true"

# =============================================================================
# Performance Configuration
# =============================================================================

# Performance Benchmarks
export BENCHMARK_FUNCTION_EXECUTION="true"
export MAX_FUNCTION_EXECUTION_TIME_MS=1000
export MAX_LIBRARY_LOAD_TIME_MS=50  # 0.050s for 4-library loading
export MEMORY_USAGE_TRACKING="true"

# Sprint S01 Performance Baseline
export BASELINE_LIBRARY_LOAD_TIME=0.012  # Sprint S01 baseline: 0.012s
export PERFORMANCE_THRESHOLD_PERCENTAGE=5  # <5% overhead requirement
export BASELINE_MEMORY_USAGE=1024  # KB baseline memory usage

# Performance Thresholds  
export PERFORMANCE_REGRESSION_THRESHOLD=5  # 5% performance degradation threshold
export MEMORY_LEAK_DETECTION="true"
export CONCURRENT_USAGE_TEST_COUNT=3  # Number of parallel executions for concurrent testing

# =============================================================================
# Reporting Configuration
# =============================================================================

# Report Generation
export GENERATE_HTML_REPORT="true"
export GENERATE_XML_REPORT="true"
export GENERATE_JSON_REPORT="false"
export GENERATE_JUNIT_REPORT="true"

# Report Details
export INCLUDE_COVERAGE_IN_REPORT="true"
export INCLUDE_PERFORMANCE_METRICS="false"
export INCLUDE_DETAILED_FAILURES="true"
export INCLUDE_TEST_EXECUTION_TIMES="true"

# Report Output
export REPORT_OUTPUT_DIR="$TEST_RESULTS_DIR"
export REPORT_FILENAME_PREFIX="gcp_shared_lib_test"
export REPORT_TIMESTAMP_FORMAT="%Y%m%d_%H%M%S"

# =============================================================================
# CI/CD Integration Configuration
# =============================================================================

# CI/CD Settings
export CI_INTEGRATION_ENABLED="true"
export CI_FAIL_ON_TEST_FAILURE="true"
export CI_FAIL_ON_COVERAGE_BELOW_TARGET="true"
export CI_GENERATE_ARTIFACTS="true"

# Artifact Configuration
export CI_ARTIFACT_RETENTION_DAYS=30
export CI_COVERAGE_BADGE_GENERATION="false"
export CI_NOTIFICATION_ON_FAILURE="false"

# =============================================================================
# Debug and Logging Configuration
# =============================================================================

# Debug Settings
export DEBUG_TEST_EXECUTION="false"
export DEBUG_MOCK_INTERACTIONS="false"
export DEBUG_LIBRARY_LOADING="false"
export DEBUG_COVERAGE_COLLECTION="false"

# Logging Configuration
export TEST_LOG_LEVEL="INFO"  # DEBUG, INFO, WARN, ERROR
export TEST_LOG_FILE="$TEST_RESULTS_DIR/test_execution.log"
export TEST_LOG_ROTATION="true"
export TEST_LOG_MAX_SIZE="10M"

# =============================================================================
# Security and Isolation Configuration
# =============================================================================

# Security Settings
export ISOLATE_TEST_ENVIRONMENT="true"
export CLEANUP_TEMP_FILES="true"
export PREVENT_SYSTEM_MODIFICATION="true"
export SANDBOX_TEST_EXECUTION="false"

# Isolation Configuration
export USE_TEMPORARY_DIRECTORIES="true"
export RESET_ENVIRONMENT_VARIABLES="true"
export MOCK_EXTERNAL_DEPENDENCIES="true"

# =============================================================================
# Validation Functions
# =============================================================================

# Validate test configuration
validate_test_config() {
    local errors=0
    
    # Check required directories
    for dir in "$TEST_UNIT_DIR" "$TEST_INTEGRATION_DIR" "$TEST_HELPERS_DIR"; do
        if [[ ! -d "$dir" ]]; then
            echo "ERROR: Required test directory not found: $dir" >&2
            ((errors++))
        fi
    done
    
    # Check library files
    for lib in "$GCP_COMMON_LIB" "$GCP_PERMISSIONS_LIB" "$GCP_HTML_REPORT_LIB" "$GCP_SCOPE_MGMT_LIB"; do
        if [[ ! -f "$lib" ]]; then
            echo "ERROR: Required library file not found: $lib" >&2
            ((errors++))
        fi
    done
    
    # Validate coverage targets
    if [[ $OVERALL_COVERAGE_TARGET -lt 0 || $OVERALL_COVERAGE_TARGET -gt 100 ]]; then
        echo "ERROR: Invalid coverage target: $OVERALL_COVERAGE_TARGET" >&2
        ((errors++))
    fi
    
    # Check for required tools
    if [[ "$COVERAGE_TOOL" == "kcov" ]] && ! command -v kcov &> /dev/null; then
        echo "WARNING: Coverage tool 'kcov' not found - coverage reporting disabled" >&2
    fi
    
    if ! command -v bats &> /dev/null; then
        echo "ERROR: bats testing framework not found" >&2
        ((errors++))
    fi
    
    return $errors
}

# Display test configuration summary
show_test_config_summary() {
    echo "=== GCP Shared Library Test Configuration Summary ==="
    echo "Framework: $TEST_FRAMEWORK_NAME v$TEST_FRAMEWORK_VERSION"
    echo "Coverage Target: $OVERALL_COVERAGE_TARGET%"
    echo "Test Pass Rate Requirement: $REQUIRED_TEST_PASS_RATE%"
    echo "Max Execution Time: $MAX_TEST_EXECUTION_TIME seconds"
    echo "Coverage Tool: $COVERAGE_TOOL"
    echo "Test Root: $TEST_ROOT_DIR"
    echo "Library Root: $LIB_ROOT_DIR"
    echo "Results Directory: $TEST_RESULTS_DIR"
    echo "=================================================="
}

# Initialize test environment
initialize_test_environment() {
    # Create required directories
    mkdir -p "$TEST_RESULTS_DIR" "$TEST_TEMP_DIR"
    
    # Set up logging
    if [[ -n "$TEST_LOG_FILE" ]]; then
        mkdir -p "$(dirname "$TEST_LOG_FILE")"
        touch "$TEST_LOG_FILE"
    fi
    
    # Validate configuration
    if ! validate_test_config; then
        echo "Test configuration validation failed" >&2
        return 1
    fi
    
    return 0
}

# Export configuration validation functions
export -f validate_test_config show_test_config_summary initialize_test_environment

# Auto-initialize when sourced (but not when executed directly)
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    initialize_test_environment
fi