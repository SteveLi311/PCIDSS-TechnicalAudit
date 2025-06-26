#!/usr/bin/env bats

# Integration tests for GCP shared library interactions

load ../helpers/test_helpers
load ../helpers/mock_helpers

setup() {
    setup_test_environment
    load_gcp_common_library
    load_gcp_permissions_library
}

teardown() {
    cleanup_test_environment
}

# =============================================================================
# Library Loading and Initialization Integration Tests
# =============================================================================

@test "integration: gcp_common loads before gcp_permissions successfully" {
    # Setup - Verify loading order is correct
    [ "$GCP_COMMON_LOADED" = "true" ]
    [ "$GCP_PERMISSIONS_LOADED" = "true" ]
    
    # Execute - Test that permissions library recognizes common library
    run register_required_permissions 1 "test.permission"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Registered 1 permissions for Requirement 1" ]]
}

@test "integration: gcp_permissions fails without gcp_common loaded" {
    # Setup - Simulate missing gcp_common
    unset GCP_COMMON_LOADED
    
    # Execute - Try to use permissions library
    run bash -c "source '../lib/gcp_permissions.sh'"
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Error: gcp_common.sh must be loaded before gcp_permissions.sh" ]]
}

@test "integration: both libraries export functions correctly" {
    # Execute - Check function availability from both libraries
    
    # Common library functions
    declare -F source_gcp_libraries >/dev/null || fail "source_gcp_libraries not exported"
    declare -F setup_environment >/dev/null || fail "setup_environment not exported"
    declare -F parse_common_arguments >/dev/null || fail "parse_common_arguments not exported"
    declare -F print_status >/dev/null || fail "print_status not exported"
    
    # Permissions library functions
    declare -F register_required_permissions >/dev/null || fail "register_required_permissions not exported"
    declare -F check_all_permissions >/dev/null || fail "check_all_permissions not exported"
    declare -F get_permission_coverage >/dev/null || fail "get_permission_coverage not exported"
    declare -F validate_scope_permissions >/dev/null || fail "validate_scope_permissions not exported"
    declare -F prompt_continue_limited >/dev/null || fail "prompt_continue_limited not exported"
}

# =============================================================================
# Cross-Library Configuration and State Integration Tests
# =============================================================================

@test "integration: shared state management between libraries" {
    # Setup - Use common library to set environment
    setup_environment "integration_test.log"
    parse_common_arguments -s project -p test-project-123 -v
    
    # Execute - Use permissions library with shared state
    register_required_permissions 1 "compute.instances.list"
    
    # Assert - Both libraries should access shared variables
    [ "$PROJECT_ID" = "test-project-123" ]
    [ "$VERBOSE" = "true" ]
    [ "$SCOPE" = "project" ]
    [ -n "$LOG_FILE" ]
    [ ${#REQUIRED_PERMISSIONS[@]} -eq 1 ]
}

@test "integration: logging works across both libraries" {
    # Setup
    setup_environment "cross_library_test.log"
    
    # Execute - Generate logs from both libraries
    print_status "INFO" "Common library test message"
    register_required_permissions 1 "test.permission"
    
    # Assert - Log file should contain entries from both libraries
    [ -f "$LOG_FILE" ]
    grep -q "Common library test message" "$LOG_FILE"
    grep -q "Registered 1 permissions" "$LOG_FILE"
}

@test "integration: color output consistency across libraries" {
    # Execute - Test color variables are shared
    run print_status "PASS" "Test message from common"
    common_output="$output"
    
    # Setup permissions library test
    export PROJECT_ID="test-project"
    register_required_permissions 1 "available.permission"
    mock_gcloud_test_iam_permissions_success "$PROJECT_ID" "available.permission"
    
    run check_all_permissions
    permissions_output="$output"
    
    # Assert - Both should use color formatting
    [[ "$common_output" =~ $'\033' ]]  # Contains ANSI color codes
    [[ "$permissions_output" =~ $'\033' ]]  # Contains ANSI color codes
}

# =============================================================================
# End-to-End Workflow Integration Tests
# =============================================================================

@test "integration: complete assessment workflow with project scope" {
    # Setup - Mock successful GCP environment
    export PROJECT_ID="test-project-123"
    mock_all_prerequisites_success
    mock_gcloud_project_describe_success "$PROJECT_ID"
    mock_gcloud_test_iam_permissions_success "$PROJECT_ID" "compute.instances.list" "iam.roles.list"
    
    # Execute - Complete workflow simulation
    run setup_environment "workflow_test.log"
    [ "$status" -eq 0 ]
    
    run parse_common_arguments -s project -p "$PROJECT_ID" -v
    [ "$status" -eq 0 ]
    
    run validate_prerequisites
    [ "$status" -eq 0 ]
    
    run register_required_permissions 1 "compute.instances.list" "iam.roles.list"
    [ "$status" -eq 0 ]
    
    run validate_scope_permissions
    [ "$status" -eq 0 ]
    
    run check_all_permissions
    [ "$status" -eq 0 ]
    
    # Assert - Workflow completed successfully
    coverage=$(get_permission_coverage)
    [ "$coverage" = "100" ]
}

@test "integration: complete assessment workflow with organization scope" {
    # Setup - Mock successful GCP environment for organization
    export ORG_ID="123456789"
    mock_all_prerequisites_success
    mock_gcloud_organization_describe_success "$ORG_ID"
    
    # Execute - Organization workflow simulation
    run setup_environment
    [ "$status" -eq 0 ]
    
    run parse_common_arguments -s organization -p "$ORG_ID"
    [ "$status" -eq 0 ]
    
    run validate_prerequisites
    [ "$status" -eq 0 ]
    
    run register_required_permissions 2 "orgpolicy.policies.list"
    [ "$status" -eq 0 ]
    
    run validate_scope_permissions
    [ "$status" -eq 0 ]
    
    # Assert - Organization scope properly handled
    [ "$SCOPE" = "organization" ]
    [ "$ORG_ID" = "123456789" ]
    [ ${#REQUIRED_PERMISSIONS[@]} -eq 1 ]
}

@test "integration: error handling propagation across libraries" {
    # Setup - Create error conditions
    export PROJECT_ID="nonexistent-project"
    mock_all_prerequisites_success
    mock_gcloud_project_describe_failure "$PROJECT_ID"
    
    # Execute - Test error propagation
    setup_environment
    parse_common_arguments -s project -p "$PROJECT_ID"
    register_required_permissions 1 "test.permission"
    
    run validate_scope_permissions
    
    # Assert - Error should propagate correctly
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Cannot access project: nonexistent-project" ]]
}

@test "integration: limited permissions workflow with user interaction" {
    # Setup - Mixed permission scenario
    export PROJECT_ID="test-project"
    register_required_permissions 1 "available.permission" "missing.permission"
    mock_gcloud_test_iam_permissions_mixed "$PROJECT_ID" "available.permission"
    mock_user_input "y"
    
    # Execute - Limited permissions workflow
    run check_all_permissions
    [ "$status" -eq 1 ]  # Returns 1 because some permissions missing
    
    run prompt_continue_limited
    
    # Assert - User interaction handled correctly
    [ "$status" -eq 0 ]  # User chose to continue
    [[ "$output" =~ "Continuing with limited permissions" ]]
    
    coverage=$(get_permission_coverage)
    [ "$coverage" = "50" ]
}

# =============================================================================
# Performance and Resource Management Integration Tests
# =============================================================================

@test "integration: cleanup functions work across libraries" {
    # Setup - Create temporary resources
    setup_environment "cleanup_test.log"
    mkdir -p "$WORK_DIR/test_subdir"
    echo "test content" > "$WORK_DIR/test_file.txt"
    
    # Execute - Test cleanup
    run cleanup_temp_files
    
    # Assert - Resources cleaned up
    [ "$status" -eq 0 ]
    [ ! -f "$WORK_DIR/test_file.txt" ]
}

@test "integration: concurrent library usage simulation" {
    # Setup - Simulate multiple requirement checks
    setup_environment
    export PROJECT_ID="test-project"
    mock_gcloud_test_iam_permissions_success "$PROJECT_ID" "perm1" "perm2" "perm3" "perm4"
    
    # Execute - Multiple permission registrations
    register_required_permissions 1 "perm1" "perm2"
    first_check=$(check_all_permissions && get_permission_coverage)
    
    register_required_permissions 2 "perm3" "perm4"
    second_check=$(check_all_permissions && get_permission_coverage)
    
    # Assert - Each check independent but using shared infrastructure
    [ "$first_check" = "100" ]
    [ "$second_check" = "100" ]
}

@test "integration: verbose mode consistency across libraries" {
    # Setup
    export VERBOSE=true
    setup_environment
    export PROJECT_ID="test-project"
    mock_gcloud_test_iam_permissions_success "$PROJECT_ID" "test.permission"
    
    # Execute - Test verbose output from both libraries
    run print_status "INFO" "Common library verbose test"
    common_verbose="$output"
    
    run register_required_permissions 1 "test.permission"
    permissions_verbose="$output"
    
    # Assert - Both libraries respect verbose setting
    [[ "$common_verbose" =~ "Debug:" ]]
    [[ "$permissions_verbose" =~ "test.permission" ]]
}

# =============================================================================
# Configuration and Argument Processing Integration Tests
# =============================================================================

@test "integration: argument parsing affects permissions behavior" {
    # Execute - Test different argument combinations
    
    # Test 1: Project scope
    parse_common_arguments -s project -p "proj-123"
    register_required_permissions 1 "project.permission"
    run validate_scope_permissions
    project_result="$status"
    
    # Test 2: Organization scope
    parse_common_arguments -s organization -p "org-456"
    mock_gcloud_organization_describe_success "org-456"
    run validate_scope_permissions
    org_result="$status"
    
    # Assert - Scope handling consistent between libraries
    [ "$project_result" -eq 1 ]  # Will fail without proper mocks
    [ "$org_result" -eq 0 ]      # Will succeed with mocks
}

@test "integration: help system works across libraries" {
    # Execute - Test help display
    run show_help
    
    # Assert - Help includes information relevant to both libraries
    [ "$status" -eq 0 ]
    [[ "$output" =~ "GCP PCI DSS Assessment Script" ]]
    [[ "$output" =~ "-s, --scope" ]]
    [[ "$output" =~ "-p, --project" ]]
    [[ "$output" =~ "Appropriate GCP permissions" ]]
}

@test "integration: configuration loading affects both libraries" {
    # Setup - Create test configuration
    local config_dir="$(dirname "$LIB_DIR")/config"
    mkdir -p "$config_dir"
    cat > "$config_dir/requirement_1.conf" << 'EOF'
export TEST_CONFIG_LOADED="true"
export PROJECT_ID="config-project-123"
EOF
    
    # Execute - Load configuration and test effects
    run load_requirement_config 1
    [ "$status" -eq 0 ]
    
    # Test that permissions library uses loaded configuration
    register_required_permissions 1 "test.permission"
    
    # Assert - Configuration affects both libraries
    [ "$TEST_CONFIG_LOADED" = "true" ]
    [ "$PROJECT_ID" = "config-project-123" ]
    [ ${#REQUIRED_PERMISSIONS[@]} -eq 1 ]
}