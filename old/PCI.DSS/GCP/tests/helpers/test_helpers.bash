#!/bin/bash

# =============================================================================
# Test Helper Functions for GCP Shared Library Testing
# =============================================================================

# BATS assertion functions
assert_success() {
    if [[ "$status" -ne 0 ]]; then
        echo "Expected success but got exit code $status" >&2
        echo "Output: $output" >&2
        return 1
    fi
}

assert_failure() {
    if [[ "$status" -eq 0 ]]; then
        echo "Expected failure but got success" >&2
        echo "Output: $output" >&2
        return 1
    fi
}

assert_output() {
    local expected=""
    local partial=false
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --partial)
                partial=true
                shift
                ;;
            *)
                expected="$1"
                shift
                ;;
        esac
    done
    
    if [[ "$partial" == "true" ]]; then
        if [[ "$output" != *"$expected"* ]]; then
            echo "Expected output to contain '$expected'" >&2
            echo "Actual output: $output" >&2
            return 1
        fi
    else
        if [[ "$output" != "$expected" ]]; then
            echo "Expected output: $expected" >&2
            echo "Actual output: $output" >&2
            return 1
        fi
    fi
}

# Global test configuration
TEST_TMPDIR=""
TEST_LIB_DIR=""
TEST_MOCK_DIR=""

# =============================================================================
# Test Environment Setup and Teardown
# =============================================================================

# Setup test environment for each test
setup_test_environment() {
    # Create unique temporary directory for this test
    TEST_TMPDIR=$(mktemp -d "/tmp/gcp_test_$$_XXXXXX")
    export TEST_TMPDIR
    
    # Set up test library directory structure
    TEST_LIB_DIR="$TEST_TMPDIR/lib"
    TEST_MOCK_DIR="$TEST_TMPDIR/mocks"
    mkdir -p "$TEST_LIB_DIR" "$TEST_MOCK_DIR"
    
    # Copy actual library files to test location
    if [[ -d "$(dirname "$BATS_TEST_FILENAME")/../lib" ]]; then
        cp -r "$(dirname "$BATS_TEST_FILENAME")/../lib"/* "$TEST_LIB_DIR/"
    elif [[ -d "$(dirname "$BATS_TEST_FILENAME")/../../lib" ]]; then
        cp -r "$(dirname "$BATS_TEST_FILENAME")/../../lib"/* "$TEST_LIB_DIR/"
    fi
    
    # Set library path for testing
    export LIB_DIR="$TEST_LIB_DIR"
    export GCP_LIB_PATH="$TEST_LIB_DIR"
    
    # Initialize test-specific variables
    export OUTPUT_DIR="$TEST_TMPDIR/output"
    export WORK_DIR="$TEST_TMPDIR/work"
    export REPORT_DIR="$TEST_TMPDIR/reports"
    export LOG_DIR="$TEST_TMPDIR/logs"
    
    # Create required directories
    mkdir -p "$OUTPUT_DIR" "$WORK_DIR" "$REPORT_DIR" "$LOG_DIR"
    
    # Reset global variables for clean test state
    unset PROJECT_ID ORG_ID SCOPE SCOPE_TYPE VERBOSE REPORT_ONLY LOG_FILE
    unset REQUIRED_PERMISSIONS OPTIONAL_PERMISSIONS PERMISSION_RESULTS
    unset PERMISSION_COVERAGE_PERCENTAGE MISSING_PERMISSIONS_COUNT AVAILABLE_PERMISSIONS_COUNT
    unset GCP_COMMON_LOADED GCP_PERMISSIONS_LOADED GCP_HTML_REPORT_LOADED GCP_SCOPE_MGMT_LOADED
    unset SCOPE_CONFIGURED PERMISSIONS_REGISTERED LOADED_LIBRARIES LIB_LOAD_ORDER
    
    # Initialize arrays
    declare -g -a REQUIRED_PERMISSIONS
    declare -g -a OPTIONAL_PERMISSIONS
    declare -g -A PERMISSION_RESULTS
    
    # Set default test values
    export PERMISSION_COVERAGE_PERCENTAGE=0
    export MISSING_PERMISSIONS_COUNT=0
    export AVAILABLE_PERMISSIONS_COUNT=0
    
    # Disable colors for consistent test output
    export NO_COLOR=1
    export RED=""
    export GREEN=""
    export YELLOW=""
    export BLUE=""
    export CYAN=""
    export NC=""
}

# Cleanup test environment after each test
cleanup_test_environment() {
    # Clean up temporary directory
    if [[ -n "$TEST_TMPDIR" && -d "$TEST_TMPDIR" ]]; then
        rm -rf "$TEST_TMPDIR"
    fi
    
    # Reset environment variables
    unset TEST_TMPDIR TEST_LIB_DIR TEST_MOCK_DIR
    unset OUTPUT_DIR WORK_DIR REPORT_DIR LOG_DIR
    unset PROJECT_ID ORG_ID SCOPE SCOPE_TYPE VERBOSE REPORT_ONLY LOG_FILE
    unset REQUIRED_PERMISSIONS OPTIONAL_PERMISSIONS PERMISSION_RESULTS
    unset PERMISSION_COVERAGE_PERCENTAGE MISSING_PERMISSIONS_COUNT AVAILABLE_PERMISSIONS_COUNT
    unset GCP_COMMON_LOADED GCP_PERMISSIONS_LOADED GCP_HTML_REPORT_LOADED GCP_SCOPE_MGMT_LOADED
    unset SCOPE_CONFIGURED PERMISSIONS_REGISTERED LOADED_LIBRARIES LIB_LOAD_ORDER
    
    # Clear function mocks
    unset -f gcloud jq curl
}

# =============================================================================
# Library Loading Functions
# =============================================================================

# Load gcp_common.sh library for testing
load_gcp_common_library() {
    if [[ -f "$TEST_LIB_DIR/gcp_common.sh" ]]; then
        source "$TEST_LIB_DIR/gcp_common.sh"
        export GCP_COMMON_LOADED="true"
    else
        echo "Error: gcp_common.sh not found in $TEST_LIB_DIR" >&2
        return 1
    fi
}

# Load gcp_permissions.sh library for testing
load_gcp_permissions_library() {
    if [[ "$GCP_COMMON_LOADED" != "true" ]]; then
        echo "Error: gcp_common.sh must be loaded before gcp_permissions.sh" >&2
        return 1
    fi
    
    if [[ -f "$TEST_LIB_DIR/gcp_permissions.sh" ]]; then
        source "$TEST_LIB_DIR/gcp_permissions.sh"
        export GCP_PERMISSIONS_LOADED="true"
    else
        echo "Error: gcp_permissions.sh not found in $TEST_LIB_DIR" >&2
        return 1
    fi
}

# Load gcp_html_report.sh library for testing
load_gcp_html_report_library() {
    if [[ "$GCP_COMMON_LOADED" != "true" ]]; then
        echo "Error: gcp_common.sh must be loaded before gcp_html_report.sh" >&2
        return 1
    fi
    
    if [[ -f "$TEST_LIB_DIR/gcp_html_report.sh" ]]; then
        source "$TEST_LIB_DIR/gcp_html_report.sh"
        export GCP_HTML_REPORT_LOADED="true"
    else
        echo "Error: gcp_html_report.sh not found in $TEST_LIB_DIR" >&2
        return 1
    fi
}

# Load gcp_scope_mgmt.sh library for testing
load_gcp_scope_mgmt_library() {
    if [[ "$GCP_COMMON_LOADED" != "true" ]]; then
        echo "Error: gcp_common.sh must be loaded before gcp_scope_mgmt.sh" >&2
        return 1
    fi
    
    if [[ -f "$TEST_LIB_DIR/gcp_scope_mgmt.sh" ]]; then
        source "$TEST_LIB_DIR/gcp_scope_mgmt.sh"
        export GCP_SCOPE_MGMT_LOADED="true"
    else
        echo "Error: gcp_scope_mgmt.sh not found in $TEST_LIB_DIR" >&2
        return 1
    fi
}

# Load all 4 GCP libraries in dependency order
load_all_gcp_libraries() {
    load_gcp_common_library
    load_gcp_permissions_library
    load_gcp_html_report_library
    load_gcp_scope_mgmt_library
}

# Create mock library directory for testing
create_mock_lib_directory() {
    mkdir -p "$TEST_LIB_DIR"
    
    # Create minimal mock gcp_common.sh for dependency testing
    cat > "$TEST_LIB_DIR/gcp_common.sh" << 'EOF'
#!/bin/bash
export GCP_COMMON_LOADED="true"
print_status() { echo "[$1] $2"; }
export -f print_status
EOF
    
    # Create minimal mock gcp_permissions.sh
    cat > "$TEST_LIB_DIR/gcp_permissions.sh" << 'EOF'
#!/bin/bash
if [[ "$GCP_COMMON_LOADED" != "true" ]]; then
    echo "Error: gcp_common.sh must be loaded before gcp_permissions.sh" >&2
    exit 1
fi
export GCP_PERMISSIONS_LOADED="true"
EOF
    
    chmod +x "$TEST_LIB_DIR"/*.sh
}

# =============================================================================
# Test Data and Mock Setup Functions
# =============================================================================

# Create test project data
create_test_project_data() {
    local project_id="${1:-test-project-123}"
    
    cat > "$TEST_MOCK_DIR/project_${project_id}.json" << EOF
{
  "projectId": "$project_id",
  "name": "Test Project",
  "projectNumber": "123456789012",
  "lifecycleState": "ACTIVE",
  "createTime": "2023-01-01T00:00:00.000Z"
}
EOF
}

# Create test organization data
create_test_organization_data() {
    local org_id="${1:-123456789}"
    
    cat > "$TEST_MOCK_DIR/organization_${org_id}.json" << EOF
{
  "name": "organizations/$org_id",
  "organizationId": "$org_id",
  "displayName": "Test Organization",
  "lifecycleState": "ACTIVE",
  "creationTime": "2023-01-01T00:00:00.000Z"
}
EOF
}

# Create test IAM permissions data
create_test_permissions_data() {
    local project_id="${1:-test-project-123}"
    shift
    local permissions=("$@")
    
    local permissions_json=""
    for perm in "${permissions[@]}"; do
        if [[ -n "$permissions_json" ]]; then
            permissions_json+=","
        fi
        permissions_json+="\"$perm\""
    done
    
    cat > "$TEST_MOCK_DIR/permissions_${project_id}.json" << EOF
{
  "permissions": [$permissions_json]
}
EOF
}

# =============================================================================
# Test Assertion Helper Functions
# =============================================================================

# Assert that a file exists
assert_file_exists() {
    local file_path="$1"
    if [[ ! -f "$file_path" ]]; then
        echo "Assertion failed: File '$file_path' does not exist" >&2
        return 1
    fi
}

# Assert that a directory exists
assert_directory_exists() {
    local dir_path="$1"
    if [[ ! -d "$dir_path" ]]; then
        echo "Assertion failed: Directory '$dir_path' does not exist" >&2
        return 1
    fi
}

# Assert that a variable is set
assert_variable_set() {
    local var_name="$1"
    local var_value="${!var_name}"
    if [[ -z "$var_value" ]]; then
        echo "Assertion failed: Variable '$var_name' is not set" >&2
        return 1
    fi
}

# Assert that a variable equals expected value
assert_variable_equals() {
    local var_name="$1"
    local expected="$2"
    local actual="${!var_name}"
    if [[ "$actual" != "$expected" ]]; then
        echo "Assertion failed: Variable '$var_name' expected '$expected', got '$actual'" >&2
        return 1
    fi
}

# Assert that output contains expected string
assert_output_contains() {
    local expected="$1"
    if [[ ! "$output" =~ $expected ]]; then
        echo "Assertion failed: Output does not contain '$expected'" >&2
        echo "Actual output: $output" >&2
        return 1
    fi
}

# Assert that output does not contain string
assert_output_not_contains() {
    local unexpected="$1"
    if [[ "$output" =~ $unexpected ]]; then
        echo "Assertion failed: Output contains unexpected '$unexpected'" >&2
        echo "Actual output: $output" >&2
        return 1
    fi
}

# Assert that status code equals expected value
assert_status_equals() {
    local expected="$1"
    if [[ "$status" != "$expected" ]]; then
        echo "Assertion failed: Status expected '$expected', got '$status'" >&2
        return 1
    fi
}

# Assert that array has expected length
assert_array_length() {
    local array_name="$1"
    local expected_length="$2"
    local -n array_ref="$array_name"
    local actual_length="${#array_ref[@]}"
    
    if [[ "$actual_length" != "$expected_length" ]]; then
        echo "Assertion failed: Array '$array_name' expected length '$expected_length', got '$actual_length'" >&2
        return 1
    fi
}

# Assert that array contains expected value
assert_array_contains() {
    local array_name="$1"
    local expected_value="$2"
    local -n array_ref="$array_name"
    
    for value in "${array_ref[@]}"; do
        if [[ "$value" == "$expected_value" ]]; then
            return 0
        fi
    done
    
    echo "Assertion failed: Array '$array_name' does not contain '$expected_value'" >&2
    echo "Array contents: ${array_ref[*]}" >&2
    return 1
}

# =============================================================================
# Test Utility Functions
# =============================================================================

# Generate random test identifier
generate_test_id() {
    echo "test_$(date +%s)_$$_$RANDOM"
}

# Create temporary test file with content
create_test_file() {
    local filename="$1"
    local content="$2"
    local filepath="$TEST_TMPDIR/$filename"
    
    echo "$content" > "$filepath"
    echo "$filepath"
}

# Wait for condition with timeout
wait_for_condition() {
    local condition="$1"
    local timeout="${2:-10}"
    local interval="${3:-1}"
    
    local count=0
    while ! eval "$condition"; do
        sleep "$interval"
        count=$((count + interval))
        if [[ $count -ge $timeout ]]; then
            echo "Timeout waiting for condition: $condition" >&2
            return 1
        fi
    done
    return 0
}

# Log test message for debugging
log_test_message() {
    local level="$1"
    local message="$2"
    echo "[TEST-$level] $message" >&2
}

# Get test duration since start
get_test_duration() {
    if [[ -n "$TEST_START_TIME" ]]; then
        echo $(($(date +%s) - TEST_START_TIME))
    else
        echo "0"
    fi
}

# Mark test start time
mark_test_start() {
    export TEST_START_TIME=$(date +%s)
}

# =============================================================================
# Test Data Generation Functions
# =============================================================================

# Generate sample GCP project list
generate_sample_projects() {
    local count="${1:-3}"
    
    cat > "$TEST_MOCK_DIR/sample_projects.json" << 'EOF'
[
  {
    "projectId": "sample-project-1",
    "name": "Sample Project 1",
    "projectNumber": "123456789001"
  },
  {
    "projectId": "sample-project-2",
    "name": "Sample Project 2",
    "projectNumber": "123456789002"
  },
  {
    "projectId": "sample-project-3",
    "name": "Sample Project 3",
    "projectNumber": "123456789003"
  }
]
EOF
}

# Generate sample IAM roles
generate_sample_iam_roles() {
    cat > "$TEST_MOCK_DIR/sample_iam_roles.json" << 'EOF'
[
  {
    "name": "roles/viewer",
    "title": "Viewer",
    "description": "Read access to all resources"
  },
  {
    "name": "roles/editor",
    "title": "Editor",
    "description": "Edit access to all resources"
  },
  {
    "name": "roles/owner",
    "title": "Owner",
    "description": "Full access to all resources"
  }
]
EOF
}

# Generate sample compute instances
generate_sample_compute_instances() {
    local project_id="${1:-test-project-123}"
    
    cat > "$TEST_MOCK_DIR/compute_instances_${project_id}.json" << EOF
[
  {
    "name": "instance-1",
    "zone": "us-central1-a",
    "machineType": "e2-medium",
    "status": "RUNNING"
  },
  {
    "name": "instance-2",
    "zone": "us-central1-b",
    "machineType": "e2-small",
    "status": "TERMINATED"
  }
]
EOF
}

# =============================================================================
# Integration Test Environment Setup
# =============================================================================

# Setup integration test environment
setup_integration_environment() {
    # Create integration-specific directories
    export INTEGRATION_TEST_DIR="$TEST_TMPDIR/integration"
    export INTEGRATION_MOCK_DIR="$INTEGRATION_TEST_DIR/mocks"
    export INTEGRATION_REPORT_DIR="$INTEGRATION_TEST_DIR/reports"
    
    mkdir -p "$INTEGRATION_TEST_DIR" "$INTEGRATION_MOCK_DIR" "$INTEGRATION_REPORT_DIR"
    
    # Initialize integration-specific variables
    export ORGANIZATION_ID=""
    export PROJECTS_LIST=()
    export INTEGRATION_LOG_FILE="$INTEGRATION_TEST_DIR/integration.log"
    
    # Create integration log file
    touch "$INTEGRATION_LOG_FILE"
}

# =============================================================================
# Performance Testing Helper Functions
# =============================================================================

# Time function execution with high precision
time_function() {
    local func_name="$1"
    local -n results_ref="$2"
    shift 2
    local args=("$@")
    
    local start_time end_time execution_time
    start_time=$(date +%s.%N)
    "$func_name" "${args[@]}" >/dev/null 2>&1 || true
    end_time=$(date +%s.%N)
    execution_time=$(echo "$end_time - $start_time" | bc)
    
    results_ref["$func_name"]="$execution_time"
}

# Assert performance threshold
assert_performance_threshold() {
    local actual_time="$1"
    local threshold="$2"
    local time_ok
    time_ok=$(echo "$actual_time < $threshold" | bc)
    [ "$time_ok" -eq 1 ]
}

# Get current memory usage in KB
get_current_memory_usage() {
    ps -o rss= -p $$ 2>/dev/null | tr -d ' ' || echo "1024"
}

# =============================================================================
# Mock Functions for Integration Testing
# =============================================================================

# Mock functions for scope management (these would be implemented in gcp_scope_mgmt.sh)
setup_scope_management() {
    local scope_type="$1"
    local scope_id="$2"
    
    export SCOPE_TYPE="$scope_type"
    export SCOPE_ID="$scope_id"
    export SCOPE_CONFIGURED="true"
    
    echo "Scope management setup: $scope_type/$scope_id"
    return 0
}

validate_organization_scope_permissions() {
    echo "Organization scope validation completed"
    return 0
}

aggregate_project_results() {
    echo "Project results aggregated"
    return 0
}

manage_assessment_scope() {
    echo "Assessment scope managed"
    return 0
}

# Mock functions for HTML report generation (these would be implemented in gcp_html_report.sh)
generate_html_report() {
    local report_file="${REPORT_DIR:-$TEST_TMPDIR}/assessment_report.html"
    echo "<html><body>Test Assessment Report</body></html>" > "$report_file"
    echo "HTML report generated: $report_file"
    return 0
}

create_assessment_summary() {
    echo "Assessment summary created"
    return 0
}

format_permission_results() {
    echo "Permission results formatted"
    return 0
}

add_visual_indicators() {
    echo "Visual indicators added"
    return 0
}

# Extended mock functions for organization testing
check_all_permissions_across_projects() {
    echo "Permissions checked across all projects"
    return 0
}

generate_organization_html_report() {
    local report_file="${REPORT_DIR:-$TEST_TMPDIR}/organization_assessment_report.html"
    echo "<html><body>Organization Assessment Report</body></html>" > "$report_file"
    echo "Organization HTML report generated: $report_file"
    return 0
}

check_all_permissions_for_project() {
    local project_id="$1"
    echo "Permissions checked for project: $project_id"
    return 0
}

# Export all functions for use in tests
export -f setup_test_environment cleanup_test_environment setup_integration_environment
export -f load_gcp_common_library load_gcp_permissions_library load_gcp_html_report_library load_gcp_scope_mgmt_library load_all_gcp_libraries
export -f create_mock_lib_directory
export -f create_test_project_data create_test_organization_data create_test_permissions_data
export -f assert_file_exists assert_directory_exists assert_variable_set assert_variable_equals
export -f assert_output_contains assert_output_not_contains assert_status_equals
export -f assert_array_length assert_array_contains
export -f generate_test_id create_test_file wait_for_condition log_test_message
export -f get_test_duration mark_test_start
export -f generate_sample_projects generate_sample_iam_roles generate_sample_compute_instances
export -f time_function assert_performance_threshold get_current_memory_usage
export -f setup_scope_management validate_organization_scope_permissions aggregate_project_results manage_assessment_scope
export -f generate_html_report create_assessment_summary format_permission_results add_visual_indicators
export -f check_all_permissions_across_projects generate_organization_html_report check_all_permissions_for_project