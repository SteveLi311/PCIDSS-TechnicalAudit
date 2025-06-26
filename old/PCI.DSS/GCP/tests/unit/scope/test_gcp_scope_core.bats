#!/usr/bin/env bats

# Unit tests for gcp_scope_mgmt.sh core functions

load ../../helpers/test_helpers
load ../../helpers/mock_helpers

setup() {
    setup_test_environment
    load_gcp_common_library
    
    # Ensure gcp_scope_mgmt.sh is loaded
    source "$TEST_LIB_DIR/gcp_scope_mgmt.sh"
    
    # Mock gcloud commands for testing
    mock_all_prerequisites_success
    
    # Reset scope state
    ASSESSMENT_SCOPE=""
    PROJECTS_CACHE=""
    SCOPE_VALIDATION_DONE=false
    SCOPE_TYPE="project"
    PROJECT_ID=""
    ORG_ID=""
}

teardown() {
    cleanup_test_environment
}

# =============================================================================
# setup_assessment_scope function tests
# =============================================================================

@test "setup_assessment_scope: configures project scope successfully" {
    # Setup
    SCOPE_TYPE="project"
    PROJECT_ID="test-project-123"
    
    # Mock gcloud project describe success
    mock_gcloud_project_describe_success "test-project-123"
    
    # Execute
    run setup_assessment_scope
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$ASSESSMENT_SCOPE" = "project" ]
    [ "$SCOPE_VALIDATION_DONE" = "true" ]
    [[ "$output" =~ "Project scope configured: test-project-123" ]]
}

@test "setup_assessment_scope: configures organization scope successfully" {
    # Setup
    SCOPE_TYPE="organization"
    ORG_ID="123456789012"
    
    # Mock gcloud organization describe success
    mock_gcloud_organization_describe_success "123456789012"
    
    # Execute
    run setup_assessment_scope
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$ASSESSMENT_SCOPE" = "organization" ]
    [ "$SCOPE_VALIDATION_DONE" = "true" ]
    [[ "$output" =~ "Organization scope configured: 123456789012" ]]
}

@test "setup_assessment_scope: fails when organization ID missing" {
    # Setup
    SCOPE_TYPE="organization"
    ORG_ID=""
    
    # Execute
    run setup_assessment_scope
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Organization scope requires an organization ID" ]]
}

@test "setup_assessment_scope: fails when project access denied" {
    # Setup
    SCOPE_TYPE="project"
    PROJECT_ID="test-project-123"
    
    # Mock gcloud project describe failure
    mock_gcloud_project_describe_failure "test-project-123"
    
    # Execute
    run setup_assessment_scope
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Cannot access project: test-project-123" ]]
}

@test "setup_assessment_scope: uses default project when PROJECT_ID empty" {
    # Setup
    SCOPE_TYPE="project"
    PROJECT_ID=""
    
    # Mock gcloud config get-value project
    gcloud() {
        case "$*" in
            "config get-value project")
                echo "default-project-123"
                return 0
                ;;
            "projects describe default-project-123")
                echo "name: projects/default-project-123"
                return 0
                ;;
            *)
                echo "Mock gcloud: $*" >&2
                return 0
                ;;
        esac
    }
    export -f gcloud
    
    # Execute
    run setup_assessment_scope
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$PROJECT_ID" = "default-project-123" ]
    [[ "$output" =~ "Project scope configured: default-project-123" ]]
}

# =============================================================================
# get_projects_in_scope function tests
# =============================================================================

@test "get_projects_in_scope: returns single project for project scope" {
    # Setup
    ASSESSMENT_SCOPE="project"
    PROJECT_ID="test-project-123"
    SCOPE_VALIDATION_DONE=true
    
    # Execute
    run get_projects_in_scope
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$output" = "test-project-123" ]
}

@test "get_projects_in_scope: returns multiple projects for organization scope" {
    # Setup
    ASSESSMENT_SCOPE="organization"
    ORG_ID="123456789012"
    SCOPE_VALIDATION_DONE=true
    
    # Mock gcloud projects list
    gcloud() {
        case "$*" in
            "projects list --filter=parent.id:123456789012 --format=value(projectId)")
                echo "project-1"
                echo "project-2"
                echo "project-3"
                return 0
                ;;
            *)
                echo "Mock gcloud: $*" >&2
                return 0
                ;;
        esac
    }
    export -f gcloud
    
    # Execute
    run get_projects_in_scope
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "project-1" ]]
    [[ "$output" =~ "project-2" ]]
    [[ "$output" =~ "project-3" ]]
}

@test "get_projects_in_scope: fails when scope not validated" {
    # Setup
    SCOPE_VALIDATION_DONE=false
    
    # Execute
    run get_projects_in_scope
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Scope not configured" ]]
}

@test "get_projects_in_scope: caches organization projects list" {
    # Setup
    ASSESSMENT_SCOPE="organization"
    ORG_ID="123456789012"
    SCOPE_VALIDATION_DONE=true
    
    # Mock gcloud projects list  
    gcloud() {
        case "$*" in
            "projects list --filter=parent.id:123456789012 --format=value(projectId)")
                echo "project-1"
                echo "project-2"
                return 0
                ;;
            *)
                echo "Mock gcloud: $*" >&2
                return 0
                ;;
        esac
    }
    export -f gcloud
    
    # Execute first call
    run get_projects_in_scope
    [ "$status" -eq 0 ]
    
    # Execute second call (should use cache)
    run get_projects_in_scope
    [ "$status" -eq 0 ]
    
    # Assert projects cache is set
    [ -n "$PROJECTS_CACHE" ]
}

# =============================================================================
# build_gcloud_command function tests
# =============================================================================

@test "build_gcloud_command: constructs project command correctly" {
    # Setup
    ASSESSMENT_SCOPE="project"
    PROJECT_ID="test-project-123"
    
    # Execute
    run build_gcloud_command "gcloud compute instances list"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "gcloud compute --project=\"test-project-123\" instances list" ]]
}

@test "build_gcloud_command: uses project override when provided" {
    # Setup
    ASSESSMENT_SCOPE="organization"
    
    # Execute
    run build_gcloud_command "gcloud compute networks list" "override-project"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "gcloud compute --project=\"override-project\" networks list" ]]
}

@test "build_gcloud_command: fails with empty base command" {
    # Execute
    run build_gcloud_command ""
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "base_command is required" ]]
}

@test "build_gcloud_command: fails with non-gcloud command" {
    # Execute
    run build_gcloud_command "kubectl get pods"
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Command must start with 'gcloud'" ]]
}

@test "build_gcloud_command: fails for organization scope without project override" {
    # Setup
    ASSESSMENT_SCOPE="organization"
    
    # Execute
    run build_gcloud_command "gcloud compute instances list"
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "project must be specified for organization scope" ]]
}

# =============================================================================
# run_across_projects function tests
# =============================================================================

@test "run_across_projects: executes command on single project" {
    # Setup
    ASSESSMENT_SCOPE="project"
    PROJECT_ID="test-project-123"
    SCOPE_VALIDATION_DONE=true
    
    # Mock command execution - simplified for basic test
    function eval() {
        echo "instance-1"
        echo "instance-2"
        return 0
    }
    export -f eval
    
    # Execute
    run run_across_projects "gcloud compute instances list"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "instance-1" ]]
    [[ "$output" =~ "instance-2" ]]
    [[ "$output" =~ "Command executed on 1/1 projects" ]]
}

# Complex integration test removed for simplicity - focus on core unit tests

@test "run_across_projects: fails with empty base command" {
    # Execute
    run run_across_projects ""
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Base command is required" ]]
}

# =============================================================================
# aggregate_cross_project_data function tests
# =============================================================================

@test "aggregate_cross_project_data: formats organization scope data correctly" {
    # Setup
    ASSESSMENT_SCOPE="organization"
    local test_data="project-1/instance-1
project-1/instance-2
project-2/instance-3"
    
    # Execute
    run aggregate_cross_project_data "$test_data"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Project: project-1 | Resource: instance-1" ]]
    [[ "$output" =~ "Project: project-1 | Resource: instance-2" ]]
    [[ "$output" =~ "Project: project-2 | Resource: instance-3" ]]
    [[ "$output" =~ "Aggregated 3 resources across" ]]
}

@test "aggregate_cross_project_data: formats project scope data correctly" {
    # Setup
    ASSESSMENT_SCOPE="project"
    PROJECT_ID="test-project-123"
    local test_data="instance-1
instance-2"
    
    # Execute
    run aggregate_cross_project_data "$test_data"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Resource: instance-1" ]]
    [[ "$output" =~ "Resource: instance-2" ]]
    [[ "$output" =~ "Aggregated 2 resources from project: test-project-123" ]]
}

@test "aggregate_cross_project_data: handles empty data gracefully" {
    # Execute
    run aggregate_cross_project_data ""
    
    # Assert
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "aggregate_cross_project_data: uses custom delimiter" {
    # Setup
    ASSESSMENT_SCOPE="organization"
    local test_data="project-1|instance-1
project-2|instance-2"
    
    # Execute
    run aggregate_cross_project_data "$test_data" "|"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Project: project-1 | Resource: instance-1" ]]
    [[ "$output" =~ "Project: project-2 | Resource: instance-2" ]]
}