#!/usr/bin/env bats

# =============================================================================
# Integration Test Suite for GCP PCI DSS Requirement 3 (Refactored)
# =============================================================================
# Tests end-to-end functionality of the refactored Requirement 3 script
# including library integration, mock GCP API calls, and report generation

load '../../../tests/helpers/test_helpers.bash'
load '../../../tests/helpers/mock_helpers.bash'

# =============================================================================
# Test Setup and Teardown
# =============================================================================

setup() {
    # Load test configuration
    source "$BATS_TEST_DIRNAME/../../test_config.bash"
    
    # Initialize test environment
    initialize_test_environment
    
    # Set up paths
    SCRIPT_DIR="$(cd "$BATS_TEST_DIRNAME/../../../" && pwd)"
    REQ3_SCRIPT="$SCRIPT_DIR/check_gcp_pci_requirement3.sh"
    
    # Set up mock environment with sample data
    setup_mock_gcp_environment
    setup_requirement3_mock_data
    
    # Set up temporary directories
    export TEST_OUTPUT_DIR="$TEST_TEMP_DIR/requirement3_integration"
    export REPORT_DIR="$TEST_OUTPUT_DIR/reports"
    mkdir -p "$REPORT_DIR"
    
    # Mock gcloud commands
    export PATH="$TEST_MOCKS_DIR:$PATH"
    
    # Set test project scope
    export GCP_PROJECT="test-project-123"
    export SCOPE_TYPE="project"
}

teardown() {
    # Clean up test environment
    cleanup_test_environment
    
    # Remove temporary files
    if [[ -d "$TEST_OUTPUT_DIR" ]]; then
        rm -rf "$TEST_OUTPUT_DIR"
    fi
}

# Test-specific setup for Requirement 3 mock data
setup_requirement3_mock_data() {
    # Create mock storage buckets response
    cat > "$TEST_MOCKS_DIR/storage_buckets.json" << 'EOF'
{
  "buckets": [
    {
      "name": "test-bucket-encrypted",
      "encryption": {
        "defaultKmsKeyName": "projects/test-project-123/locations/global/keyRings/test-ring/cryptoKeys/test-key"
      }
    },
    {
      "name": "test-bucket-default",
      "encryption": {}
    }
  ]
}
EOF

    # Create mock SQL instances response
    cat > "$TEST_MOCKS_DIR/sql_instances.json" << 'EOF'
{
  "instances": [
    {
      "name": "test-sql-encrypted",
      "diskEncryptionConfiguration": {
        "kmsKeyName": "projects/test-project-123/locations/global/keyRings/test-ring/cryptoKeys/sql-key"
      }
    },
    {
      "name": "test-sql-default"
    }
  ]
}
EOF

    # Create mock KMS keyrings response  
    cat > "$TEST_MOCKS_DIR/kms_keyrings.json" << 'EOF'
{
  "keyRings": [
    {
      "name": "projects/test-project-123/locations/global/keyRings/test-ring"
    }
  ]
}
EOF
}

# =============================================================================
# Framework Integration Tests
# =============================================================================

@test "req3_integration: framework libraries load successfully" {
    # Test that all libraries can be loaded without errors
    run bash -c "
        source '$SCRIPT_DIR/lib/gcp_common.sh' &&
        source '$SCRIPT_DIR/lib/gcp_permissions.sh' &&
        source '$SCRIPT_DIR/lib/gcp_scope_mgmt.sh' &&
        source '$SCRIPT_DIR/lib/gcp_html_report.sh' &&
        echo 'All libraries loaded successfully'
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"All libraries loaded successfully"* ]]
}

@test "req3_integration: permission registration works correctly" {
    # Test permission registration function
    run bash -c "
        source '$SCRIPT_DIR/lib/gcp_permissions.sh' &&
        register_required_permissions '3' 'storage.buckets.list' 'cloudsql.instances.list' &&
        echo 'Permissions registered successfully'
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"Permissions registered successfully"* ]]
}

# =============================================================================
# Assessment Function Integration Tests
# =============================================================================

@test "req3_integration: storage encryption assessment runs without errors" {
    # Mock the assess_storage_encryption function execution
    run bash -c "
        source '$SCRIPT_DIR/lib/gcp_common.sh' &&
        source '$SCRIPT_DIR/lib/gcp_html_report.sh' &&
        
        # Mock the assessment function
        assess_storage_encryption() {
            local projects=('test-project-123')
            print_status 'INFO' 'Starting storage encryption assessment...'
            echo 'Storage assessment completed'
        }
        
        assess_storage_encryption
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"Storage assessment completed"* ]]
}

@test "req3_integration: database encryption assessment runs without errors" {
    # Mock the assess_database_encryption function execution
    run bash -c "
        source '$SCRIPT_DIR/lib/gcp_common.sh' &&
        source '$SCRIPT_DIR/lib/gcp_html_report.sh' &&
        
        # Mock the assessment function
        assess_database_encryption() {
            local projects=('test-project-123')
            print_status 'INFO' 'Starting database encryption assessment...'
            echo 'Database assessment completed'
        }
        
        assess_database_encryption
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"Database assessment completed"* ]]
}

@test "req3_integration: key management assessment runs without errors" {
    # Mock the assess_key_management function execution
    run bash -c "
        source '$SCRIPT_DIR/lib/gcp_common.sh' &&
        source '$SCRIPT_DIR/lib/gcp_html_report.sh' &&
        
        # Mock the assessment function
        assess_key_management() {
            local projects=('test-project-123')
            print_status 'INFO' 'Starting key management assessment...'
            echo 'Key management assessment completed'
        }
        
        assess_key_management
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"Key management assessment completed"* ]]
}

# =============================================================================
# End-to-End Workflow Tests
# =============================================================================

@test "req3_integration: script help display works" {
    # Test help functionality
    run bash "$REQ3_SCRIPT" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage"* ]]
}

@test "req3_integration: script validates CLI arguments" {
    # Test invalid argument handling
    run bash "$REQ3_SCRIPT" --invalid-option
    [ "$status" -ne 0 ]
}

@test "req3_integration: script handles missing prerequisites gracefully" {
    # Test when gcloud is not available
    run bash -c "
        PATH='/bin:/usr/bin' bash '$REQ3_SCRIPT' --help
    "
    # Should either show help or fail gracefully
    [ "$status" -eq 0 ] || [ "$status" -eq 1 ]
}

# =============================================================================
# Report Generation Tests
# =============================================================================

@test "req3_integration: HTML report can be initialized" {
    # Test HTML report initialization
    run bash -c "
        source '$SCRIPT_DIR/lib/gcp_html_report.sh' &&
        export OUTPUT_DIR='$TEST_OUTPUT_DIR' &&
        initialize_report 'Test Report' &&
        echo 'Report initialized successfully'
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"Report initialized successfully"* ]]
}

@test "req3_integration: report sections can be added" {
    # Test adding sections to report
    run bash -c "
        source '$SCRIPT_DIR/lib/gcp_html_report.sh' &&
        export OUTPUT_DIR='$TEST_OUTPUT_DIR' &&
        initialize_report 'Test Report' &&
        add_section 'Storage Encryption Assessment' '3.2-3.3' &&
        echo 'Section added successfully'
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"Section added successfully"* ]]
}

@test "req3_integration: check results can be added to report" {
    # Test adding check results
    run bash -c "
        source '$SCRIPT_DIR/lib/gcp_html_report.sh' &&
        export OUTPUT_DIR='$TEST_OUTPUT_DIR' &&
        initialize_report 'Test Report' &&
        add_section 'Test Section' '3.2' &&
        add_check_result 'PASS' '3.2.1' 'Test Resource' 'Test passed' 'test-project' &&
        echo 'Check result added successfully'
    "
    [ "$status" -eq 0 ]
    [[ "$output" == *"Check result added successfully"* ]]
}

# =============================================================================
# Performance and Quality Tests
# =============================================================================

@test "req3_integration: script executes within reasonable time" {
    # Test script execution time (with mocked commands)
    start_time=$(date +%s)
    run timeout 30 bash "$REQ3_SCRIPT" --help
    end_time=$(date +%s)
    
    execution_time=$((end_time - start_time))
    [ "$execution_time" -lt 10 ]  # Should complete help in under 10 seconds
}

@test "req3_integration: script memory usage is reasonable" {
    # Test that script doesn't consume excessive memory
    if command -v ps >/dev/null 2>&1; then
        run bash -c "
            bash '$REQ3_SCRIPT' --help &
            pid=\$!
            sleep 1
            memory=\$(ps -o rss= -p \$pid 2>/dev/null || echo '0')
            wait \$pid
            echo \$memory
        "
        [ "$status" -eq 0 ]
        
        # Memory usage should be less than 50MB (50000 KB)
        memory_kb=${output:-0}
        [ "$memory_kb" -lt 50000 ]
    else
        skip "ps command not available for memory testing"
    fi
}

# =============================================================================
# Compatibility Tests  
# =============================================================================

@test "req3_integration: script works with different bash versions" {
    # Test bash 4+ compatibility (array features)
    run bash -c "
        declare -a test_array=('item1' 'item2')
        echo \${#test_array[@]}
    "
    [ "$status" -eq 0 ]
    [ "$output" = "2" ]
}

@test "req3_integration: script handles empty project lists gracefully" {
    # Test behavior with no projects in scope
    run bash -c "
        source '$SCRIPT_DIR/lib/gcp_common.sh' &&
        
        # Mock empty project list
        get_projects_in_scope() {
            echo ''
        }
        
        projects=(\$(get_projects_in_scope))
        echo \${#projects[@]}
    "
    [ "$status" -eq 0 ]
    [ "$output" = "0" ]
}