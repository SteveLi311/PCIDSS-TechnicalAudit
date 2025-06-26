#!/usr/bin/env bats

# Unit tests for gcp_permissions.sh core functions

load ../../helpers/test_helpers
load ../../helpers/mock_helpers

setup() {
    setup_test_environment
    load_gcp_common_library
    load_gcp_permissions_library
}

teardown() {
    cleanup_test_environment
}

# =============================================================================
# register_required_permissions function tests
# =============================================================================

@test "register_required_permissions: successfully registers permissions for requirement" {
    # Execute
    run register_required_permissions 1 "compute.instances.list" "compute.zones.list" "iam.roles.list"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Registered 3 permissions for Requirement 1" ]]
    [ ${#REQUIRED_PERMISSIONS[@]} -eq 3 ]
    [[ "${REQUIRED_PERMISSIONS[0]}" == "compute.instances.list" ]]
    [[ "${REQUIRED_PERMISSIONS[1]}" == "compute.zones.list" ]]
    [[ "${REQUIRED_PERMISSIONS[2]}" == "iam.roles.list" ]]
}

@test "register_required_permissions: fails when requirement number missing" {
    # Execute
    run register_required_permissions "" "compute.instances.list"
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Invalid parameters for permission registration" ]]
}

@test "register_required_permissions: fails when no permissions provided" {
    # Execute
    run register_required_permissions 1
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Invalid parameters for permission registration" ]]
}

@test "register_required_permissions: shows verbose output when VERBOSE=true" {
    # Setup
    export VERBOSE=true
    
    # Execute
    run register_required_permissions 2 "storage.buckets.list" "storage.objects.list"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Registered 2 permissions for Requirement 2" ]]
    [[ "$output" =~ "storage.buckets.list" ]]
    [[ "$output" =~ "storage.objects.list" ]]
}

@test "register_required_permissions: overwrites existing permissions" {
    # Setup - Register initial permissions
    register_required_permissions 1 "old.permission.1" "old.permission.2"
    
    # Execute - Register new permissions
    run register_required_permissions 2 "new.permission.1" "new.permission.2" "new.permission.3"
    
    # Assert
    [ "$status" -eq 0 ]
    [ ${#REQUIRED_PERMISSIONS[@]} -eq 3 ]
    [[ "${REQUIRED_PERMISSIONS[0]}" == "new.permission.1" ]]
    [[ "${REQUIRED_PERMISSIONS[1]}" == "new.permission.2" ]]
    [[ "${REQUIRED_PERMISSIONS[2]}" == "new.permission.3" ]]
}

# =============================================================================
# check_all_permissions function tests
# =============================================================================

@test "check_all_permissions: warns when no permissions registered" {
    # Execute
    run check_all_permissions
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "No permissions registered to check" ]]
}

@test "check_all_permissions: successfully checks all available permissions" {
    # Setup
    export PROJECT_ID="test-project-123"
    register_required_permissions 1 "compute.instances.list" "iam.roles.list"
    mock_gcloud_test_iam_permissions_success "$PROJECT_ID" "compute.instances.list" "iam.roles.list"
    
    # Execute
    run check_all_permissions
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Checking 2 required permissions" ]]
    [[ "$output" =~ "✓ compute.instances.list" ]]
    [[ "$output" =~ "✓ iam.roles.list" ]]
    [[ "$output" =~ "2/2 available (100%)" ]]
}

@test "check_all_permissions: handles mixed available and missing permissions" {
    # Setup
    export PROJECT_ID="test-project-123"
    register_required_permissions 1 "available.permission" "missing.permission"
    mock_gcloud_test_iam_permissions_mixed "$PROJECT_ID" "available.permission"
    
    # Execute
    run check_all_permissions
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Checking 2 required permissions" ]]
    [[ "$output" =~ "✓ available.permission" ]]
    [[ "$output" =~ "✗ missing.permission" ]]
    [[ "$output" =~ "1/2 available (50%)" ]]
}

@test "check_all_permissions: handles all missing permissions" {
    # Setup
    export PROJECT_ID="test-project-123"
    register_required_permissions 1 "missing.permission.1" "missing.permission.2"
    mock_gcloud_test_iam_permissions_failure "$PROJECT_ID"
    
    # Execute
    run check_all_permissions
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Checking 2 required permissions" ]]
    [[ "$output" =~ "✗ missing.permission.1" ]]
    [[ "$output" =~ "✗ missing.permission.2" ]]
    [[ "$output" =~ "0/2 available (0%)" ]]
}

@test "check_all_permissions: updates global counters correctly" {
    # Setup
    export PROJECT_ID="test-project-123"
    register_required_permissions 1 "available.permission" "missing.permission"
    mock_gcloud_test_iam_permissions_mixed "$PROJECT_ID" "available.permission"
    
    # Execute
    check_all_permissions
    
    # Assert
    [ "$AVAILABLE_PERMISSIONS_COUNT" -eq 1 ]
    [ "$MISSING_PERMISSIONS_COUNT" -eq 1 ]
    [ "$PERMISSION_COVERAGE_PERCENTAGE" -eq 50 ]
}

@test "check_all_permissions: updates PERMISSION_RESULTS array correctly" {
    # Setup
    export PROJECT_ID="test-project-123"
    register_required_permissions 1 "available.permission" "missing.permission"
    mock_gcloud_test_iam_permissions_mixed "$PROJECT_ID" "available.permission"
    
    # Execute
    check_all_permissions
    
    # Assert
    [ "${PERMISSION_RESULTS[available.permission]}" = "AVAILABLE" ]
    [ "${PERMISSION_RESULTS[missing.permission]}" = "MISSING" ]
}

@test "check_all_permissions: requires PROJECT_ID to be set" {
    # Setup - No PROJECT_ID set
    register_required_permissions 1 "some.permission"
    
    # Execute
    run check_all_permissions
    
    # Assert
    [ "$status" -eq 1 ]
    # Should fail gracefully when PROJECT_ID not set
}

# =============================================================================
# get_permission_coverage function tests
# =============================================================================

@test "get_permission_coverage: returns correct percentage" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=75
    
    # Execute
    result=$(get_permission_coverage)
    
    # Assert
    [ "$result" = "75" ]
}

@test "get_permission_coverage: returns 0 when no coverage set" {
    # Setup
    unset PERMISSION_COVERAGE_PERCENTAGE
    export PERMISSION_COVERAGE_PERCENTAGE=0
    
    # Execute
    result=$(get_permission_coverage)
    
    # Assert
    [ "$result" = "0" ]
}

@test "get_permission_coverage: returns 100 for complete coverage" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=100
    
    # Execute
    result=$(get_permission_coverage)
    
    # Assert
    [ "$result" = "100" ]
}

# =============================================================================
# validate_scope_permissions function tests
# =============================================================================

@test "validate_scope_permissions: fails when no scope defined" {
    # Setup - Clear both PROJECT_ID and ORG_ID
    unset PROJECT_ID
    unset ORG_ID
    
    # Execute
    run validate_scope_permissions
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "No project or organization scope defined" ]]
}

@test "validate_scope_permissions: validates project access when PROJECT_ID set" {
    # Setup
    export PROJECT_ID="test-project-123"
    mock_gcloud_project_describe_success "$PROJECT_ID"
    
    # Execute
    run validate_scope_permissions
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Project scope validated: test-project-123" ]]
}

@test "validate_scope_permissions: fails when project inaccessible" {
    # Setup
    export PROJECT_ID="inaccessible-project"
    mock_gcloud_project_describe_failure "$PROJECT_ID"
    
    # Execute
    run validate_scope_permissions
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Cannot access project: inaccessible-project" ]]
}

@test "validate_scope_permissions: validates organization access when ORG_ID set" {
    # Setup
    export ORG_ID="123456789"
    mock_gcloud_organization_describe_success "$ORG_ID"
    
    # Execute
    run validate_scope_permissions
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Organization scope validated: 123456789" ]]
}

@test "validate_scope_permissions: fails when organization inaccessible" {
    # Setup
    export ORG_ID="invalid-org"
    mock_gcloud_organization_describe_failure "$ORG_ID"
    
    # Execute
    run validate_scope_permissions
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Cannot access organization: invalid-org" ]]
}

@test "validate_scope_permissions: validates both project and organization when both set" {
    # Setup
    export PROJECT_ID="test-project"
    export ORG_ID="test-org"
    mock_gcloud_project_describe_success "$PROJECT_ID"
    mock_gcloud_organization_describe_success "$ORG_ID"
    
    # Execute
    run validate_scope_permissions
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Project scope validated: test-project" ]]
    [[ "$output" =~ "Organization scope validated: test-org" ]]
}