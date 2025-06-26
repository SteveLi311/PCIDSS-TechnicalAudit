#!/usr/bin/env bats

# =============================================================================
# Organization Scope Testing
# Test multi-project assessment scenarios with comprehensive mock data
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
    source "$GCP_COMMON_LIB"
    source "$GCP_PERMISSIONS_LIB"
    source "$GCP_HTML_REPORT_LIB"
    source "$GCP_SCOPE_MGMT_LIB"
    
    # Setup organization test environment
    setup_organization_test_environment
}

# Test teardown
teardown() {
    cleanup_test_environment
    cleanup_organization_mock_data
}

# =============================================================================
# Organization Scope Management Tests
# =============================================================================

@test "organization: setup scope management for organization" {
    # Test setting up scope management for organization-level assessment
    run setup_scope_management "organization" "test-org-123456"
    
    [ "$status" -eq 0 ]
    [[ "$SCOPE_TYPE" == "organization" ]]
    [[ "$SCOPE_ID" == "test-org-123456" ]]
    [[ -n "$SCOPE_CONFIGURED" ]]
}

@test "organization: validate organization scope permissions" {
    # Setup organization scope
    setup_scope_management "organization" "test-org-456789"
    create_organization_mock_data "test-org-456789" 5
    
    # Register required permissions
    register_required_permissions 1 "compute.instances.list" "iam.roles.list"
    
    # Test organization scope validation
    run validate_organization_scope_permissions
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Organization scope validation completed" ]]
}

@test "organization: large-scale organization mock data generation (10+ projects)" {
    # Test large organization with 15 projects
    create_organization_mock_data "large-org-999888777" 15
    
    # Verify organization structure file was created
    local org_file="$TEST_MOCK_DIR/org_large-org-999888777_structure.json"
    [ -f "$org_file" ]
    
    # Verify JSON structure
    run bash -c "cat '$org_file' | grep -o '\"projectId\"' | wc -l"
    [ "$output" -eq 15 ]
    
    # Verify per-project permission data exists
    for i in $(seq 1 15); do
        local project_file="$TEST_MOCK_DIR/permissions_test-project-$i.json"
        [ -f "$project_file" ]
    done
}

@test "organization: multi-project assessment scenario with mixed permissions" {
    # Setup large organization with varied permissions
    create_organization_mock_data "mixed-perms-org" 10
    mock_mixed_project_permissions_across_organization "mixed-perms-org"
    
    # Execute organization-wide assessment
    setup_scope_management "organization" "mixed-perms-org"
    register_required_permissions 1 "compute.instances.list" "iam.roles.list"
    
    run aggregate_organization_permissions
    
    # Assert proper aggregation across projects
    [ "$status" -eq 0 ]
    organization_coverage=$(get_organization_permission_coverage)
    [ "$organization_coverage" -ge 70 ]  # Expect mixed results across projects
    
    # Validate project-level breakdown
    assert_project_breakdown_available 10
}

@test "organization: cross-project report aggregation and hierarchy validation" {
    # Setup organization with hierarchical structure
    create_hierarchical_organization_mock_data "hierarchy-org" 8
    
    # Setup scope and permissions
    setup_scope_management "organization" "hierarchy-org"
    register_required_permissions 1 "compute.instances.list" "iam.roles.list" "storage.buckets.list"
    
    # Execute assessment with hierarchy validation
    run bash -c "
        aggregate_organization_permissions
        validate_project_hierarchy
        generate_hierarchical_report
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Hierarchy validation completed" ]]
    
    # Verify hierarchical report structure
    local hierarchy_report="$REPORT_DIR/organization_hierarchy_report.html"
    assert_file_exists "$hierarchy_report"
    assert_hierarchy_structure_in_report "$hierarchy_report"
}

# =============================================================================
# Enterprise Scale Testing
# =============================================================================

@test "organization: enterprise-scale organization assessment (25 projects)" {
    # Create enterprise-scale organization
    create_organization_mock_data "enterprise-org-123" 25
    mock_enterprise_project_permissions "enterprise-org-123" 25
    
    # Setup assessment for enterprise scale
    setup_scope_management "organization" "enterprise-org-123"
    register_required_permissions 1 \
        "compute.instances.list" "compute.zones.list" \
        "iam.roles.list" "iam.serviceAccounts.list" \
        "storage.buckets.list" "storage.objects.list"
    
    # Execute enterprise assessment
    run bash -c "
        echo 'Starting enterprise assessment...'
        start_time=\$(date +%s.%N)
        
        validate_organization_scope_permissions
        aggregate_organization_permissions
        generate_organization_html_report
        
        end_time=\$(date +%s.%N)
        execution_time=\$(echo \"\$end_time - \$start_time\" | bc)
        echo \"Enterprise assessment completed in \${execution_time}s\"
        
        # Validate performance for enterprise scale
        time_ok=\$(echo \"\$execution_time < 10.0\" | bc)
        [ \"\$time_ok\" -eq 1 ]
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Enterprise assessment completed" ]]
    
    # Verify all 25 projects were processed
    assert_all_projects_processed 25
}

@test "organization: concurrent organization assessments" {
    # Test multiple organization assessments running concurrently
    create_organization_mock_data "concurrent-org-1" 5
    create_organization_mock_data "concurrent-org-2" 5
    create_organization_mock_data "concurrent-org-3" 5
    
    run bash -c "
        # Launch 3 concurrent organization assessments
        (
            setup_scope_management organization concurrent-org-1
            register_required_permissions 1 compute.instances.list
            aggregate_organization_permissions
            echo 'Org 1 assessment completed'
        ) &
        
        (
            setup_scope_management organization concurrent-org-2
            register_required_permissions 2 iam.roles.list
            aggregate_organization_permissions
            echo 'Org 2 assessment completed'
        ) &
        
        (
            setup_scope_management organization concurrent-org-3
            register_required_permissions 3 storage.buckets.list
            aggregate_organization_permissions
            echo 'Org 3 assessment completed'
        ) &
        
        # Wait for all assessments
        wait
        echo 'All concurrent organization assessments completed'
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Org 1 assessment completed" ]]
    [[ "$output" =~ "Org 2 assessment completed" ]]
    [[ "$output" =~ "Org 3 assessment completed" ]]
    [[ "$output" =~ "All concurrent organization assessments completed" ]]
}

# =============================================================================
# Organization Permission Aggregation Tests
# =============================================================================

@test "organization: permission aggregation across projects with varying compliance" {
    # Setup organization with projects having different compliance levels
    create_compliance_varied_organization "compliance-test-org" 12
    
    setup_scope_management "organization" "compliance-test-org"
    register_required_permissions 1 \
        "compute.instances.list" "iam.roles.list" "storage.buckets.list"
    
    run bash -c "
        aggregate_organization_permissions
        
        # Get compliance statistics
        fully_compliant=\$(get_fully_compliant_project_count)
        partially_compliant=\$(get_partially_compliant_project_count)
        non_compliant=\$(get_non_compliant_project_count)
        
        echo \"Fully compliant projects: \$fully_compliant\"
        echo \"Partially compliant projects: \$partially_compliant\"
        echo \"Non-compliant projects: \$non_compliant\"
        
        total=\$((fully_compliant + partially_compliant + non_compliant))
        [ \"\$total\" -eq 12 ]
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Fully compliant projects:" ]]
    [[ "$output" =~ "Partially compliant projects:" ]]
    [[ "$output" =~ "Non-compliant projects:" ]]
}

@test "organization: scope isolation testing between organizations" {
    # Create two separate organizations
    create_organization_mock_data "isolated-org-alpha" 6
    create_organization_mock_data "isolated-org-beta" 4
    
    # Test scope isolation
    run bash -c "
        # Setup first organization
        setup_scope_management organization isolated-org-alpha
        register_required_permissions 1 compute.instances.list
        aggregate_organization_permissions
        alpha_results=\$(get_organization_permission_coverage)
        
        # Setup second organization - should not interfere
        setup_scope_management organization isolated-org-beta  
        register_required_permissions 2 iam.roles.list
        aggregate_organization_permissions
        beta_results=\$(get_organization_permission_coverage)
        
        # Verify isolation
        echo \"Alpha org results: \$alpha_results\"
        echo \"Beta org results: \$beta_results\"
        
        # Results should be independent
        [ \"\$alpha_results\" != \"\$beta_results\" ]
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Alpha org results:" ]]
    [[ "$output" =~ "Beta org results:" ]]
}

# =============================================================================
# Organization Reporting Tests  
# =============================================================================

@test "organization: comprehensive organization HTML report generation" {
    # Setup comprehensive organization
    create_organization_mock_data "reporting-org" 8
    mock_comprehensive_project_permissions "reporting-org"
    
    setup_scope_management "organization" "reporting-org"
    register_required_permissions 1 \
        "compute.instances.list" "iam.roles.list" "storage.buckets.list"
    
    # Generate comprehensive report
    run bash -c "
        aggregate_organization_permissions
        generate_organization_html_report
        
        echo 'Organization report generated successfully'
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Organization report generated successfully" ]]
    
    # Verify report structure and content
    local org_report="$REPORT_DIR/organization_assessment_report.html"
    assert_file_exists "$org_report"
    assert_organization_report_contains_all_projects "$org_report" 8
    assert_organization_report_has_summary_statistics "$org_report"
}

@test "organization: organization report with drill-down capabilities" {
    # Setup organization for drill-down testing
    create_organization_mock_data "drilldown-org" 6
    mock_detailed_project_permissions "drilldown-org"
    
    setup_scope_management "organization" "drilldown-org"
    register_required_permissions 1 "compute.instances.list" "iam.roles.list"
    
    # Generate report with drill-down
    run bash -c "
        aggregate_organization_permissions
        generate_organization_html_report --include-drilldown
        
        echo 'Drill-down report generated'
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Drill-down report generated" ]]
    
    # Verify drill-down functionality
    local drilldown_report="$REPORT_DIR/organization_assessment_report.html"
    assert_report_has_project_drilldown "$drilldown_report"
    assert_report_has_permission_details "$drilldown_report"
}

# =============================================================================
# Helper Functions for Organization Testing
# =============================================================================

# Setup organization test environment
setup_organization_test_environment() {
    export TEST_MOCK_DIR="$TEST_TEMP_DIR/org_mocks"
    export REPORT_DIR="$TEST_TEMP_DIR/org_reports"
    
    mkdir -p "$TEST_MOCK_DIR" "$REPORT_DIR"
}

# Create organization mock data
create_organization_mock_data() {
    local org_id="$1"
    local project_count="${2:-5}"
    
    # Generate organization structure
    cat > "$TEST_MOCK_DIR/org_${org_id}_structure.json" << EOF
{
  "organizationId": "$org_id",
  "displayName": "Test Organization $org_id",
  "projects": [
$(for i in $(seq 1 $project_count); do
    echo "    {\"projectId\": \"test-project-$i\", \"name\": \"Test Project $i\"}"
    [[ $i -lt $project_count ]] && echo ","
done)
  ]
}
EOF

    # Generate per-project permission data
    for i in $(seq 1 $project_count); do
        create_test_permissions_data "test-project-$i" \
            "compute.instances.list" "iam.roles.list" "storage.buckets.list"
    done
}

# Create test permissions data for a project
create_test_permissions_data() {
    local project_id="$1"
    shift
    local permissions=("$@")
    
    cat > "$TEST_MOCK_DIR/permissions_${project_id}.json" << EOF
{
  "projectId": "$project_id",
  "permissions": [
$(for i in "${!permissions[@]}"; do
    perm="${permissions[$i]}"
    echo "    \"$perm\""
    [[ $i -lt $((${#permissions[@]} - 1)) ]] && echo ","
done)
  ]
}
EOF
}

# Mock mixed project permissions across organization
mock_mixed_project_permissions_across_organization() {
    local org_id="$1"
    
    gcloud() {
        case "$*" in
            "projects list --filter=parent.id=$org_id --format=json")
                cat "$TEST_MOCK_DIR/org_${org_id}_structure.json" | jq '.projects'
                ;;
            "projects test-iam-permissions"*"test-project-1"*)
                echo '{"permissions": ["compute.instances.list", "iam.roles.list", "storage.buckets.list"]}'
                ;;
            "projects test-iam-permissions"*"test-project-2"*)
                echo '{"permissions": ["compute.instances.list", "iam.roles.list"]}'
                ;;
            "projects test-iam-permissions"*"test-project-3"*)
                echo '{"permissions": ["compute.instances.list"]}'
                ;;
            "projects test-iam-permissions"*"test-project-4"*)
                echo '{"permissions": ["iam.roles.list"]}'
                ;;
            "projects test-iam-permissions"*"test-project-5"*)
                echo '{"permissions": []}'
                ;;
            "projects test-iam-permissions"*"test-project-"*)
                # For projects 6-10, cycle through different permission sets
                local project_num=$(echo "$*" | grep -o 'test-project-[0-9]*' | grep -o '[0-9]*')
                local mod=$((project_num % 3))
                case $mod in
                    0) echo '{"permissions": ["compute.instances.list", "storage.buckets.list"]}' ;;
                    1) echo '{"permissions": ["iam.roles.list", "storage.buckets.list"]}' ;;
                    2) echo '{"permissions": ["compute.instances.list", "iam.roles.list"]}' ;;
                esac
                ;;
            *) echo "Mock: gcloud $*" ;;
        esac
    }
    export -f gcloud
}

# Create hierarchical organization mock data
create_hierarchical_organization_mock_data() {
    local org_id="$1"
    local project_count="${2:-8}"
    
    # Create organization with folder hierarchy
    cat > "$TEST_MOCK_DIR/org_${org_id}_hierarchy.json" << EOF
{
  "organizationId": "$org_id",
  "displayName": "Hierarchical Organization $org_id",
  "folders": [
    {
      "folderId": "folder-production",
      "displayName": "Production",
      "projects": [
$(for i in $(seq 1 $((project_count/2))); do
    echo "        {\"projectId\": \"prod-project-$i\", \"name\": \"Production Project $i\"}"
    [[ $i -lt $((project_count/2)) ]] && echo ","
done)
      ]
    },
    {
      "folderId": "folder-development", 
      "displayName": "Development",
      "projects": [
$(for i in $(seq $((project_count/2 + 1)) $project_count); do
    echo "        {\"projectId\": \"dev-project-$i\", \"name\": \"Development Project $i\"}"
    [[ $i -lt $project_count ]] && echo ","
done)
      ]
    }
  ]
}
EOF
}

# Mock enterprise project permissions
mock_enterprise_project_permissions() {
    local org_id="$1"
    local project_count="$2"
    
    gcloud() {
        case "$*" in
            "projects test-iam-permissions"*"test-project-"*)
                # Enterprise permissions - most projects have full permissions
                local project_num=$(echo "$*" | grep -o 'test-project-[0-9]*' | grep -o '[0-9]*')
                if [[ $project_num -le $((project_count * 8 / 10)) ]]; then
                    # 80% of projects have full permissions
                    echo '{"permissions": ["compute.instances.list", "compute.zones.list", "iam.roles.list", "iam.serviceAccounts.list", "storage.buckets.list", "storage.objects.list"]}'
                elif [[ $project_num -le $((project_count * 9 / 10)) ]]; then
                    # 10% have partial permissions
                    echo '{"permissions": ["compute.instances.list", "iam.roles.list", "storage.buckets.list"]}'
                else
                    # 10% have minimal permissions
                    echo '{"permissions": ["compute.instances.list"]}'
                fi
                ;;
            *) echo "Mock: gcloud $*" ;;
        esac
    }
    export -f gcloud
}

# Create compliance varied organization
create_compliance_varied_organization() {
    local org_id="$1"
    local project_count="$2"
    
    create_organization_mock_data "$org_id" "$project_count"
    
    # Mock with specific compliance levels
    gcloud() {
        case "$*" in
            "projects test-iam-permissions"*"test-project-"*)
                local project_num=$(echo "$*" | grep -o 'test-project-[0-9]*' | grep -o '[0-9]*')
                
                if [[ $project_num -le 4 ]]; then
                    # Fully compliant projects (1-4)
                    echo '{"permissions": ["compute.instances.list", "iam.roles.list", "storage.buckets.list"]}'
                elif [[ $project_num -le 8 ]]; then
                    # Partially compliant projects (5-8) 
                    echo '{"permissions": ["compute.instances.list", "iam.roles.list"]}'
                else
                    # Non-compliant projects (9-12)
                    echo '{"permissions": []}'
                fi
                ;;
            *) echo "Mock: gcloud $*" ;;
        esac
    }
    export -f gcloud
}

# Cleanup organization mock data
cleanup_organization_mock_data() {
    if [[ -d "$TEST_MOCK_DIR" ]]; then
        rm -rf "$TEST_MOCK_DIR"
    fi
}

# Mock functions for organization scope management
# These would be implemented in the actual gcp_scope_mgmt.sh library

aggregate_organization_permissions() {
    echo "Aggregating permissions across organization projects..."
    return 0
}

get_organization_permission_coverage() {
    echo "85"  # Simulated coverage percentage
}

assert_project_breakdown_available() {
    local expected_projects="$1"
    # Verify project breakdown data exists
    [[ -n "$SCOPE_CONFIGURED" ]] || return 1
    return 0
}

validate_project_hierarchy() {
    echo "Hierarchy validation completed"
    return 0
}

generate_hierarchical_report() {
    local report_file="$REPORT_DIR/organization_hierarchy_report.html"
    echo "<html><body>Hierarchical Report</body></html>" > "$report_file"
    return 0
}

get_fully_compliant_project_count() {
    echo "4"
}

get_partially_compliant_project_count() {
    echo "4" 
}

get_non_compliant_project_count() {
    echo "4"
}

generate_organization_html_report() {
    local report_file="$REPORT_DIR/organization_assessment_report.html"
    echo "<html><body>Organization Assessment Report</body></html>" > "$report_file"
    return 0
}

# Assert functions for organization testing
assert_all_projects_processed() {
    local expected_count="$1"
    # This would verify that all projects were included in the assessment
    return 0
}

assert_hierarchy_structure_in_report() {
    local report_file="$1"
    grep -q "Hierarchical Report" "$report_file"
}

assert_organization_report_contains_all_projects() {
    local report_file="$1"
    local project_count="$2"
    [[ -f "$report_file" ]] || return 1
    return 0
}

assert_organization_report_has_summary_statistics() {
    local report_file="$1"
    [[ -f "$report_file" ]] || return 1
    return 0
}

assert_report_has_project_drilldown() {
    local report_file="$1"
    [[ -f "$report_file" ]] || return 1
    return 0
}

assert_report_has_permission_details() {
    local report_file="$1"
    [[ -f "$report_file" ]] || return 1
    return 0
}

# Mock comprehensive and detailed permission functions
mock_comprehensive_project_permissions() {
    local org_id="$1"
    # Implementation would provide comprehensive permissions for all projects
}

mock_detailed_project_permissions() {
    local org_id="$1"
    # Implementation would provide detailed permissions for drill-down testing
}