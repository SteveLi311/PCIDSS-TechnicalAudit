#!/usr/bin/env bats

# =============================================================================
# Test Suite for GCP PCI DSS Requirement 3 Scripts (Refactored)
# =============================================================================
# Tests the functionality of the refactored Requirement 3 script:
# - Framework compliance and API integration
# - Assessment function modularity
# - Error handling and logging
# - PCI DSS 3.2-3.7 coverage validation

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
    
    # Set up paths to the requirement script
    SCRIPT_DIR="$(cd "$BATS_TEST_DIRNAME/../../../" && pwd)"
    REQ3_SCRIPT="$SCRIPT_DIR/check_gcp_pci_requirement3.sh"
    REQ3_BACKUP="$SCRIPT_DIR/check_gcp_pci_requirement3_original_backup.sh"
    
    # Set up mock environment
    setup_mock_gcp_environment
    
    # Set up temporary directories
    export TEST_OUTPUT_DIR="$TEST_TEMP_DIR/requirement3_output"
    mkdir -p "$TEST_OUTPUT_DIR"
    
    # Mock gcloud commands for testing
    export PATH="$TEST_MOCKS_DIR:$PATH"
    
    # Source the shared libraries for testing
    LIB_DIR="$SCRIPT_DIR/lib"
    source "$LIB_DIR/gcp_common.sh" 2>/dev/null || true
}

teardown() {
    # Clean up test environment
    cleanup_test_environment
    
    # Remove temporary files
    if [[ -d "$TEST_OUTPUT_DIR" ]]; then
        rm -rf "$TEST_OUTPUT_DIR"
    fi
}

# =============================================================================
# Framework Integration Tests
# =============================================================================

@test "requirement3: script follows framework initialization pattern" {
    # Test that script uses proper framework functions
    run grep -E "setup_environment|parse_common_arguments|validate_prerequisites" "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
    
    # Verify all three functions are present
    [[ "$output" == *"setup_environment"* ]]
    [[ "$output" == *"parse_common_arguments"* ]]
    [[ "$output" == *"validate_prerequisites"* ]]
}

@test "requirement3: script loads all 4 shared libraries" {
    # Test that all required libraries are loaded
    run grep -E "source.*gcp_common\.sh|source.*gcp_permissions\.sh|source.*gcp_scope_mgmt\.sh|source.*gcp_html_report\.sh" "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
    
    # Count library loads (should be 4)
    library_count=$(echo "$output" | wc -l)
    [ "$library_count" -eq 4 ]
}

@test "requirement3: script uses proper permission registration" {
    # Test that register_required_permissions is called
    run grep "register_required_permissions" "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
    
    # Verify required permissions are registered
    [[ "$output" == *"storage.buckets.list"* ]]
    [[ "$output" == *"cloudsql.instances.list"* ]]
    [[ "$output" == *"cloudkms.cryptoKeys.list"* ]]
}

@test "requirement3: script uses HTML report framework API" {
    # Test that proper HTML report functions are used
    run grep -E "initialize_report|add_section|add_check_result|finalize_report" "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
    
    # Verify all report functions are present
    [[ "$output" == *"initialize_report"* ]]
    [[ "$output" == *"add_section"* ]]
    [[ "$output" == *"add_check_result"* ]]
    [[ "$output" == *"finalize_report"* ]]
}

@test "requirement3: script uses scope management functions" {
    # Test that scope management API is used
    run grep -E "setup_assessment_scope|get_projects_in_scope" "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
    
    [[ "$output" == *"setup_assessment_scope"* ]]
    [[ "$output" == *"get_projects_in_scope"* ]]
}

# =============================================================================
# Modular Function Tests
# =============================================================================

@test "requirement3: modular assessment functions exist" {
    # Test that assessment functions are defined
    run grep -E "^assess_storage_encryption\(\)|^assess_database_encryption\(\)|^assess_key_management\(\)" "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
    
    # Verify all three functions are present
    function_count=$(echo "$output" | wc -l)
    [ "$function_count" -eq 3 ]
}

@test "requirement3: assessment functions use proper error handling" {
    # Test that functions use print_status for logging
    run grep -A 20 "assess_storage_encryption()" "$REQ3_SCRIPT" | grep "print_status"
    [ "$status" -eq 0 ]
    
    # Test error handling patterns
    run grep -A 20 "assess_storage_encryption()" "$REQ3_SCRIPT" | grep "if !"
    [ "$status" -eq 0 ]
}

@test "requirement3: script has proper shebang" {
    # Test shebang follows project standards
    run head -1 "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
    [ "$output" = "#!/usr/bin/env bash" ]
}

# =============================================================================
# PCI DSS Coverage Tests
# =============================================================================

@test "requirement3: covers PCI DSS 3.2 storage encryption" {
    # Test that 3.2 requirements are covered
    run grep -i "3\.2" "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
    
    # Verify storage encryption assessment
    run grep -i "storage.*encryption" "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
}

@test "requirement3: covers PCI DSS 3.4 database encryption" {
    # Test that 3.4 requirements are covered
    run grep -i "3\.4" "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
    
    # Verify database encryption assessment
    run grep -i "database.*encryption" "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
}

@test "requirement3: covers PCI DSS 3.6 key management" {
    # Test that 3.6 requirements are covered
    run grep -i "3\.6" "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
    
    # Verify key management assessment
    run grep -i "key.*management" "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
}

# =============================================================================
# Error Handling Tests
# =============================================================================

@test "requirement3: main function has comprehensive error handling" {
    # Test that main function checks return codes
    run grep -A 50 "main()" "$REQ3_SCRIPT" | grep -c "if !"
    [ "$status" -eq 0 ]
    
    # Should have multiple error checks
    error_checks=$(echo "$output")
    [ "$error_checks" -gt 5 ]
}

@test "requirement3: uses framework logging patterns" {
    # Test that print_status is used throughout
    run grep -c "print_status" "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
    
    # Should have multiple logging statements
    log_count=$(echo "$output")
    [ "$log_count" -gt 10 ]
}

# =============================================================================
# Code Quality Tests
# =============================================================================

@test "requirement3: script is significantly reduced from original" {
    # Test that refactored script is much smaller than original
    if [[ -f "$REQ3_BACKUP" ]]; then
        original_lines=$(wc -l < "$REQ3_BACKUP")
        refactored_lines=$(wc -l < "$REQ3_SCRIPT")
        
        # Should be less than 50% of original size
        max_allowed=$((original_lines / 2))
        [ "$refactored_lines" -lt "$max_allowed" ]
    else
        skip "Original backup not available for comparison"
    fi
}

@test "requirement3: script syntax is valid" {
    # Test bash syntax validation
    run bash -n "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
}

@test "requirement3: script has no shellcheck violations" {
    # Test with shellcheck if available
    if command -v shellcheck >/dev/null 2>&1; then
        run shellcheck -S error "$REQ3_SCRIPT"
        [ "$status" -eq 0 ]
    else
        skip "shellcheck not available"
    fi
}

# =============================================================================
# Integration Readiness Tests
# =============================================================================

@test "requirement3: script accepts standard CLI arguments" {
    # Test help functionality
    run bash "$REQ3_SCRIPT" --help
    [ "$status" -eq 0 ]
}

@test "requirement3: script exports main function" {
    # Test that main function is properly defined and called
    run grep "main.*\".*@.*\"" "$REQ3_SCRIPT"
    [ "$status" -eq 0 ]
}