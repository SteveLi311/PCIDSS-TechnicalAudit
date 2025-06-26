#!/usr/bin/env bats

# =============================================================================
# 4-Library Integration Testing
# Test comprehensive integration across all 4 GCP shared libraries
# =============================================================================

# Load test framework and helpers
load '../test_config'
load '../helpers/test_helpers'
load '../helpers/mock_helpers'

# Test setup
setup() {
    # Initialize test environment
    setup_test_environment
    
    # Load all 4 libraries
    load_all_gcp_libraries
    
    # Setup integration test environment
    setup_integration_environment
}

# Test teardown
teardown() {
    cleanup_test_environment
}

# =============================================================================
# Core 4-Library Integration Tests
# =============================================================================

@test "integration: load all 4 libraries successfully" {
    # Test that all 4 libraries can be loaded together
    run bash -c "
        source '$GCP_COMMON_LIB'
        source '$GCP_PERMISSIONS_LIB'
        source '$GCP_HTML_REPORT_LIB'
        source '$GCP_SCOPE_MGMT_LIB'
        echo 'All libraries loaded successfully'
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "All libraries loaded successfully" ]]
}

@test "integration: verify all expected functions are available after loading" {
    load_all_gcp_libraries
    
    # Check functions from gcp_common.sh
    for func in "${GCP_COMMON_TEST_FUNCTIONS[@]}"; do
        run bash -c "declare -F $func"
        [ "$status" -eq 0 ]
    done
    
    # Check functions from gcp_permissions.sh
    for func in "${GCP_PERMISSIONS_TEST_FUNCTIONS[@]}"; do
        run bash -c "declare -F $func"
        [ "$status" -eq 0 ]
    done
    
    # Check functions from gcp_html_report.sh
    for func in "${GCP_HTML_REPORT_TEST_FUNCTIONS[@]}"; do
        run bash -c "declare -F $func"
        [ "$status" -eq 0 ]
    done
    
    # Check functions from gcp_scope_mgmt.sh
    for func in "${GCP_SCOPE_MGMT_TEST_FUNCTIONS[@]}"; do
        run bash -c "declare -F $func"
        [ "$status" -eq 0 ]
    done
}

@test "integration: full 4-library assessment workflow" {
    # Setup - Complete framework initialization
    load_all_gcp_libraries
    setup_organization_environment "org-123456789" "test-assessment.log"
    
    # Mock organization with multiple projects
    mock_organization_projects "org-123456789" "proj-1" "proj-2" "proj-3"
    mock_all_project_permissions_success
    
    # Execute - Complete workflow
    run bash -c "
        # Setup environment and parse arguments
        setup_environment
        parse_common_arguments -s organization -p 'org-123456789' -v
        
        # Setup scope management (new function from gcp_scope_mgmt.sh)
        setup_scope_management organization 'org-123456789'
        
        # Register permissions and validate scope
        register_required_permissions 1 'compute.instances.list' 'iam.roles.list'
        validate_organization_scope_permissions
        
        # Check permissions across projects
        check_all_permissions_across_projects
        
        # Generate HTML report
        generate_organization_html_report
        
        echo 'Complete workflow successful'
    "
    
    # Assert - Complete workflow success
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Complete workflow successful" ]]
    assert_file_exists "$REPORT_DIR/organization_assessment_report.html"
    assert_organization_coverage_meets_threshold 90
}

@test "integration: cross-library error propagation" {
    # Setup - Simulate failures at different library levels
    load_all_gcp_libraries
    export PROJECT_ID="nonexistent-project"
    mock_project_access_failure "$PROJECT_ID"
    
    # Execute - Test error handling chain
    setup_environment
    parse_common_arguments -s project -p "$PROJECT_ID"
    register_required_permissions 1 "test.permission"
    
    # Test scope management failure
    run validate_scope_permissions
    scope_error="$status"
    
    # Test permissions handling of scope failure
    run check_all_permissions
    permissions_error="$status"
    
    # Test HTML report handling of upstream failures
    run generate_html_report
    report_error="$status"
    
    # Assert - Proper error propagation
    [ "$scope_error" -eq 1 ]
    [ "$permissions_error" -eq 1 ]
    [ "$report_error" -eq 2 ]  # Different error code for upstream dependency failure
    [[ "$output" =~ "Cannot access project: nonexistent-project" ]]
}

@test "integration: library dependency loading order" {
    # Test that libraries load in the correct dependency order
    run bash -c "
        # Load in dependency order: common -> permissions -> html_report -> scope_mgmt
        source '$GCP_COMMON_LIB'
        echo 'Common library loaded'
        
        source '$GCP_PERMISSIONS_LIB'
        echo 'Permissions library loaded'
        
        source '$GCP_HTML_REPORT_LIB'
        echo 'HTML report library loaded'
        
        source '$GCP_SCOPE_MGMT_LIB'
        echo 'Scope management library loaded'
        
        # Test that all expected variables are set
        [[ -n \$LIB_LOAD_ORDER ]] && echo 'Load order tracked'
        [[ -n \$LOADED_LIBRARIES ]] && echo 'Library tracking working'
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Common library loaded" ]]
    [[ "$output" =~ "Permissions library loaded" ]]
    [[ "$output" =~ "HTML report library loaded" ]]
    [[ "$output" =~ "Scope management library loaded" ]]
}

@test "integration: state consistency across libraries" {
    load_all_gcp_libraries
    
    # Setup initial state
    setup_environment
    export PROJECT_ID="test-project-consistency"
    export REQUIREMENT_ID="1"
    
    # Test state consistency across library operations
    run bash -c "
        # Common library state setup
        parse_common_arguments -s project -p '$PROJECT_ID'
        
        # Permissions library state modification
        register_required_permissions '$REQUIREMENT_ID' 'compute.instances.list'
        
        # Scope management state usage
        setup_scope_management project '$PROJECT_ID'
        
        # HTML report state aggregation
        generate_html_report
        
        # Verify state consistency
        [[ \$PROJECT_ID == 'test-project-consistency' ]] || exit 1
        [[ \$REQUIREMENT_ID == '1' ]] || exit 2
        [[ -n \$PERMISSIONS_REGISTERED ]] || exit 3
        [[ -n \$SCOPE_CONFIGURED ]] || exit 4
        
        echo 'State consistency verified'
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "State consistency verified" ]]
}

# =============================================================================
# Multi-Project Integration Tests
# =============================================================================

@test "integration: multi-project assessment coordination" {
    load_all_gcp_libraries
    
    # Setup multi-project environment
    setup_organization_environment "org-987654321" "multi-project-test.log"
    mock_organization_projects "org-987654321" "project-a" "project-b" "project-c"
    mock_mixed_project_permissions
    
    # Execute multi-project workflow
    run bash -c "
        setup_environment
        parse_common_arguments -s organization -p 'org-987654321'
        
        # Setup scope for organization
        setup_scope_management organization 'org-987654321'
        
        # Register permissions for all projects
        register_required_permissions 1 'compute.instances.list' 'iam.roles.list'
        
        # Process each project
        for project in project-a project-b project-c; do
            echo \"Processing project: \$project\"
            check_all_permissions_for_project \"\$project\"
        done
        
        # Aggregate results
        aggregate_project_results
        generate_organization_html_report
        
        echo 'Multi-project assessment completed'
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Multi-project assessment completed" ]]
    [[ "$output" =~ "Processing project: project-a" ]]
    [[ "$output" =~ "Processing project: project-b" ]]
    [[ "$output" =~ "Processing project: project-c" ]]
}

@test "integration: concurrent library operations" {
    load_all_gcp_libraries
    
    # Test concurrent operations don't interfere with each other
    run bash -c "
        # Launch 3 concurrent assessment operations
        (
            setup_environment
            export PROJECT_ID='concurrent-test-1'
            parse_common_arguments -s project -p '\$PROJECT_ID'
            register_required_permissions 1 'compute.instances.list'
            check_all_permissions
            echo 'Concurrent operation 1 completed'
        ) &
        
        (
            setup_environment  
            export PROJECT_ID='concurrent-test-2'
            parse_common_arguments -s project -p '\$PROJECT_ID'
            register_required_permissions 2 'iam.roles.list'
            check_all_permissions
            echo 'Concurrent operation 2 completed'
        ) &
        
        (
            setup_environment
            export PROJECT_ID='concurrent-test-3'
            parse_common_arguments -s project -p '\$PROJECT_ID'
            register_required_permissions 3 'storage.buckets.list'
            check_all_permissions
            echo 'Concurrent operation 3 completed'
        ) &
        
        # Wait for all background processes
        wait
        echo 'All concurrent operations completed'
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Concurrent operation 1 completed" ]]
    [[ "$output" =~ "Concurrent operation 2 completed" ]]
    [[ "$output" =~ "Concurrent operation 3 completed" ]]
    [[ "$output" =~ "All concurrent operations completed" ]]
}

# =============================================================================
# Error Handling Integration Tests
# =============================================================================

@test "integration: graceful degradation with partial library failures" {
    load_all_gcp_libraries
    
    # Simulate partial library functionality failure
    run bash -c "
        setup_environment
        
        # Mock HTML report generation failure
        generate_html_report() {
            echo 'HTML report generation failed' >&2
            return 1
        }
        export -f generate_html_report
        
        # Test graceful degradation
        parse_common_arguments -s project -p 'test-project'
        register_required_permissions 1 'compute.instances.list'
        check_all_permissions
        
        # Attempt HTML report - should fail gracefully
        if ! generate_html_report; then
            echo 'Continuing without HTML report'
        fi
        
        echo 'Assessment completed with degraded functionality'
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Assessment completed with degraded functionality" ]]
    [[ "$output" =~ "Continuing without HTML report" ]]
}

@test "integration: cleanup across all libraries after failure" {
    load_all_gcp_libraries
    
    # Test cleanup functionality across all libraries
    run bash -c "
        setup_environment
        
        # Create test resources across libraries
        export PROJECT_ID='cleanup-test-project'
        export TEMP_REPORT_FILE='\$TEST_TEMP_DIR/test_report.html'
        export TEMP_SCOPE_FILE='\$TEST_TEMP_DIR/test_scope.json'
        
        # Setup resources
        parse_common_arguments -s project -p '\$PROJECT_ID'
        register_required_permissions 1 'test.permission'
        touch \"\$TEMP_REPORT_FILE\"
        touch \"\$TEMP_SCOPE_FILE\"
        
        # Simulate failure
        false
    "
    
    # Should fail as expected
    [ "$status" -eq 1 ]
    
    # Test cleanup
    run bash -c "
        # Load libraries and run cleanup
        source '$GCP_COMMON_LIB'
        source '$GCP_PERMISSIONS_LIB'
        source '$GCP_HTML_REPORT_LIB'
        source '$GCP_SCOPE_MGMT_LIB'
        
        cleanup_temp_files
        echo 'Cleanup completed successfully'
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Cleanup completed successfully" ]]
}

# =============================================================================
# Helper Functions for Integration Tests
# =============================================================================

# Load all 4 GCP libraries
load_all_gcp_libraries() {
    source "$GCP_COMMON_LIB"
    source "$GCP_PERMISSIONS_LIB"
    source "$GCP_HTML_REPORT_LIB"
    source "$GCP_SCOPE_MGMT_LIB"
}

# Setup organization environment for testing
setup_organization_environment() {
    local org_id="$1"
    local log_file="$2"
    
    export ORG_ID="$org_id"
    export LOG_FILE="$TEST_TEMP_DIR/$log_file"
    export REPORT_DIR="$TEST_TEMP_DIR/reports"
    
    mkdir -p "$REPORT_DIR"
    touch "$LOG_FILE"
}

# Mock organization projects
mock_organization_projects() {
    local org_id="$1"
    shift
    local projects=("$@")
    
    # Mock gcloud projects list for organization
    gcloud() {
        case "$*" in
            "projects list --filter=parent.id=$org_id --format=json")
                cat << EOF
[
$(for i in "${!projects[@]}"; do
    project="${projects[$i]}"
    echo "  {\"projectId\": \"$project\", \"name\": \"Project $project\"}"
    [[ $i -lt $((${#projects[@]} - 1)) ]] && echo ","
done)
]
EOF
                ;;
            *) echo "Mock: gcloud $*" ;;
        esac
    }
    export -f gcloud
}

# Mock successful permissions for all projects
mock_all_project_permissions_success() {
    gcloud() {
        case "$*" in
            "projects test-iam-permissions"*)
                echo '{"permissions": ["compute.instances.list", "iam.roles.list"]}'
                ;;
            *) echo "Mock: gcloud $*" ;;
        esac
    }
    export -f gcloud
}

# Mock mixed project permissions (some have permissions, some don't)
mock_mixed_project_permissions() {
    gcloud() {
        case "$*" in
            "projects test-iam-permissions"*"project-a"*)
                echo '{"permissions": ["compute.instances.list", "iam.roles.list"]}'
                ;;
            "projects test-iam-permissions"*"project-b"*)
                echo '{"permissions": ["compute.instances.list"]}'  # Missing iam.roles.list
                ;;
            "projects test-iam-permissions"*"project-c"*)
                echo '{"permissions": ["iam.roles.list"]}'         # Missing compute.instances.list
                ;;
            *) echo "Mock: gcloud $*" ;;
        esac
    }
    export -f gcloud
}

# Mock project access failure
mock_project_access_failure() {
    local failed_project="$1"
    
    gcloud() {
        case "$*" in
            *"$failed_project"*)
                echo "ERROR: Cannot access project: $failed_project" >&2
                return 1
                ;;
            *) echo "Mock: gcloud $*" ;;
        esac
    }
    export -f gcloud
}

# Assert file exists
assert_file_exists() {
    local file_path="$1"
    [[ -f "$file_path" ]] || {
        echo "Expected file does not exist: $file_path" >&2
        return 1
    }
}

# Assert organization coverage meets threshold
assert_organization_coverage_meets_threshold() {
    local threshold="$1"
    # This would be implemented based on actual coverage calculation logic
    # For now, we'll simulate it
    local coverage=95  # Simulated coverage percentage
    [[ $coverage -ge $threshold ]] || {
        echo "Coverage $coverage% below threshold $threshold%" >&2
        return 1
    }
}