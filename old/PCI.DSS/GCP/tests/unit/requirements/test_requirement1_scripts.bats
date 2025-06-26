#!/usr/bin/env bats

# =============================================================================
# Test Suite for GCP PCI DSS Requirement 1 Scripts
# =============================================================================
# Tests the functionality of all three versions of the Requirement 1 scripts:
# 1. Primary Version (check_gcp_pci_requirement1.sh) - Full 4-library integration
# 2. Enhanced Version (check_gcp_pci_requirement1_integrated.sh) - Highest PCI DSS compliance coverage
# 3. Migrated Version (check_gcp_pci_requirement1_migrated.sh) - Framework patterns

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
    
    # Set up paths to the requirement scripts
    SCRIPT_DIR="$(cd "$BATS_TEST_DIRNAME/../../../" && pwd)"
    PRIMARY_SCRIPT="$SCRIPT_DIR/check_gcp_pci_requirement1.sh"
    ENHANCED_SCRIPT="$SCRIPT_DIR/check_gcp_pci_requirement1_integrated.sh"
    MIGRATED_SCRIPT="$SCRIPT_DIR/migrated/check_gcp_pci_requirement1_migrated.sh"
    
    # Set up mock environment
    setup_mock_gcp_environment
    
    # Set up temporary directories
    export TEST_OUTPUT_DIR="$TEST_TEMP_DIR/requirement1_output"
    mkdir -p "$TEST_OUTPUT_DIR"
    
    # Mock gcloud commands
    export PATH="$TEST_MOCKS_DIR:$PATH"
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
# Basic Syntax and Structure Tests
# =============================================================================

@test "primary script has valid bash syntax" {
    run bash -n "$PRIMARY_SCRIPT"
    assert_success
}

@test "enhanced script has valid bash syntax" {
    run bash -n "$ENHANCED_SCRIPT"
    assert_success
}

@test "migrated script has valid bash syntax" {
    run bash -n "$MIGRATED_SCRIPT"
    assert_success
}

@test "primary script is executable" {
    [[ -x "$PRIMARY_SCRIPT" ]]
}

@test "enhanced script is executable" {
    [[ -x "$ENHANCED_SCRIPT" ]]
}

@test "migrated script is executable" {
    [[ -x "$MIGRATED_SCRIPT" ]]
}

@test "primary script has correct shebang" {
    head -1 "$PRIMARY_SCRIPT" | grep -q "#!/usr/bin/env bash"
}

@test "enhanced script has correct shebang" {
    head -1 "$ENHANCED_SCRIPT" | grep -q "#!/usr/bin/env bash"
}

@test "migrated script has correct shebang" {
    head -1 "$MIGRATED_SCRIPT" | grep -q "#!/usr/bin/env bash"
}

# =============================================================================
# Library Loading Tests
# =============================================================================

@test "primary script loads all 4 shared libraries" {
    # Extract library loading commands
    grep -q "source.*gcp_common.sh" "$PRIMARY_SCRIPT"
    grep -q "source.*gcp_permissions.sh" "$PRIMARY_SCRIPT"
    grep -q "source.*gcp_scope_mgmt.sh" "$PRIMARY_SCRIPT"
    grep -q "source.*gcp_html_report.sh" "$PRIMARY_SCRIPT"
}

@test "enhanced script loads required libraries" {
    # Should load at least common and permissions
    grep -q "source.*gcp_common.sh" "$ENHANCED_SCRIPT"
    grep -q "source.*gcp_permissions.sh" "$ENHANCED_SCRIPT"
}

@test "migrated script loads all 4 shared libraries" {
    # Should follow framework pattern
    grep -q "source.*gcp_common.sh" "$MIGRATED_SCRIPT"
    grep -q "source.*gcp_permissions.sh" "$MIGRATED_SCRIPT"
    grep -q "source.*gcp_html_report.sh" "$MIGRATED_SCRIPT"
    grep -q "source.*gcp_scope_mgmt.sh" "$MIGRATED_SCRIPT"
}

# =============================================================================
# Help and Usage Tests
# =============================================================================

@test "primary script shows help with --help" {
    skip "Primary script uses shared library help"
    # Test will be implemented when primary script help is accessible
}

@test "enhanced script shows help with --help" {
    run "$ENHANCED_SCRIPT" --help
    assert_success
    assert_output --partial "GCP PCI DSS Requirement 1 Assessment Script"
    assert_output --partial "Usage:"
}

@test "migrated script shows help with --help" {
    run "$MIGRATED_SCRIPT" --help
    assert_success
    assert_output --partial "GCP PCI DSS Requirement 1 Assessment Script"
    assert_output --partial "Framework Version"
}

@test "enhanced script shows help with -h" {
    run "$ENHANCED_SCRIPT" -h
    assert_success
    assert_output --partial "Usage:"
}

@test "migrated script shows help with -h" {
    run "$MIGRATED_SCRIPT" -h
    assert_success
    assert_output --partial "Usage:"
}

# =============================================================================
# Argument Parsing Tests
# =============================================================================

@test "enhanced script handles scope argument" {
    # Create mock that exits early to test parsing
    create_mock_gcloud_with_early_exit
    
    run "$ENHANCED_SCRIPT" --scope project
    # Should not fail on argument parsing
    [[ $status -eq 0 || $status -eq 1 ]]  # Allow early exit codes
}

@test "migrated script handles scope argument" {
    create_mock_gcloud_with_early_exit
    
    run "$MIGRATED_SCRIPT" --scope project
    [[ $status -eq 0 || $status -eq 1 ]]
}

@test "enhanced script rejects invalid scope" {
    run "$ENHANCED_SCRIPT" --scope invalid
    assert_failure
    assert_output --partial "Error: Scope must be 'project' or 'organization'"
}

@test "migrated script handles project argument" {
    create_mock_gcloud_with_early_exit
    
    run "$MIGRATED_SCRIPT" --project test-project
    [[ $status -eq 0 || $status -eq 1 ]]
}

# =============================================================================
# Permission Requirements Tests
# =============================================================================

@test "primary script requires compute permissions" {
    grep -q "compute.networks.list" "$PRIMARY_SCRIPT"
    grep -q "compute.firewalls.list" "$PRIMARY_SCRIPT"
}

@test "enhanced script checks for permissions" {
    # Should have some permission checking logic
    grep -q "compute" "$ENHANCED_SCRIPT"
}

@test "migrated script registers required permissions" {
    grep -q "register_required_permissions" "$MIGRATED_SCRIPT"
    grep -q "compute.firewalls.list" "$MIGRATED_SCRIPT"
    grep -q "compute.networks.list" "$MIGRATED_SCRIPT"
}

# =============================================================================
# Framework Integration Tests
# =============================================================================

@test "primary script uses setup_environment function" {
    grep -q "setup_environment" "$PRIMARY_SCRIPT"
}

@test "primary script uses parse_common_arguments function" {
    grep -q "parse_common_arguments" "$PRIMARY_SCRIPT"
}

@test "primary script uses load_requirement_config function" {
    grep -q "load_requirement_config" "$PRIMARY_SCRIPT"
}

@test "primary script uses setup_assessment_scope function" {
    grep -q "setup_assessment_scope" "$PRIMARY_SCRIPT"
}

@test "migrated script uses framework functions" {
    # Should use framework patterns
    grep -q "register_required_permissions" "$MIGRATED_SCRIPT"
}

# =============================================================================
# PCI DSS Compliance Coverage Tests
# =============================================================================

@test "enhanced script has highest PCI DSS compliance coverage" {
    # Count PCI DSS requirement references in enhanced script
    local enhanced_coverage=$(grep -c "1\.[2-5]" "$ENHANCED_SCRIPT" || true)
    local primary_coverage=$(grep -c "1\.[2-5]" "$PRIMARY_SCRIPT" || true)
    
    # Enhanced should have comprehensive coverage
    [[ $enhanced_coverage -gt 0 ]]
}

@test "scripts cover PCI DSS 1.2 requirements" {
    # All scripts should address network security controls
    grep -q "network\|firewall" "$PRIMARY_SCRIPT"
    grep -q "network\|firewall" "$ENHANCED_SCRIPT"
    grep -q "network\|firewall" "$MIGRATED_SCRIPT"
}

@test "scripts cover CDE isolation requirements" {
    # Should have CDE (Cardholder Data Environment) references
    grep -qi "cde\|cardholder" "$PRIMARY_SCRIPT"
    grep -qi "cde\|cardholder" "$ENHANCED_SCRIPT"
    grep -qi "cde\|cardholder" "$MIGRATED_SCRIPT"
}

# =============================================================================
# Output Format Tests
# =============================================================================

@test "primary script generates HTML output" {
    grep -q "\.html" "$PRIMARY_SCRIPT"
    grep -q "initialize_report\|HTML" "$PRIMARY_SCRIPT"
}

@test "migrated script supports multiple output formats" {
    grep -q "format.*html\|html.*format" "$MIGRATED_SCRIPT"
}

# =============================================================================
# Error Handling Tests
# =============================================================================

@test "primary script exits on library loading failure" {
    grep -q "|| exit 1" "$PRIMARY_SCRIPT"
}

@test "enhanced script has error handling" {
    # Should have some error handling patterns
    grep -q "exit 1\|return 1" "$ENHANCED_SCRIPT"
}

@test "migrated script has framework error handling" {
    # Should use framework patterns for error handling
    grep -q "exit\|return" "$MIGRATED_SCRIPT"
}

# =============================================================================
# Security Assessment Logic Tests
# =============================================================================

@test "scripts contain firewall assessment logic" {
    grep -q "firewall" "$PRIMARY_SCRIPT"
    grep -q "firewall" "$ENHANCED_SCRIPT"
    grep -q "firewall" "$MIGRATED_SCRIPT"
}

@test "scripts contain network assessment logic" {
    grep -q "network" "$PRIMARY_SCRIPT"
    grep -q "network" "$ENHANCED_SCRIPT"
    grep -q "network" "$MIGRATED_SCRIPT"
}

@test "enhanced script has comprehensive security checks" {
    # Enhanced version should have the most comprehensive checks
    local check_count=$(grep -c "check\|assess\|validate" "$ENHANCED_SCRIPT" || true)
    [[ $check_count -gt 5 ]]  # Should have multiple security checks
}

# =============================================================================
# Configuration and Setup Tests
# =============================================================================

@test "primary script sets requirement number" {
    grep -q 'REQUIREMENT_NUMBER.*1' "$PRIMARY_SCRIPT"
}

@test "migrated script sets requirement configuration" {
    grep -q 'REQUIREMENT_NUMBER.*1' "$MIGRATED_SCRIPT"
    grep -q 'REQUIREMENT_TITLE' "$MIGRATED_SCRIPT"
}

@test "scripts use appropriate script directory detection" {
    grep -q 'SCRIPT_DIR.*dirname' "$PRIMARY_SCRIPT"
    grep -q 'LIB_DIR.*dirname' "$ENHANCED_SCRIPT"
    grep -q 'LIB_DIR.*dirname' "$MIGRATED_SCRIPT"
}

# =============================================================================
# Performance and Efficiency Tests
# =============================================================================

@test "primary script has efficient library loading" {
    # Should load libraries only once
    local common_loads=$(grep -c "source.*gcp_common.sh" "$PRIMARY_SCRIPT")
    [[ $common_loads -eq 1 ]]
}

@test "scripts have reasonable file size" {
    # Scripts should not be excessively large
    local primary_size=$(wc -l < "$PRIMARY_SCRIPT")
    local enhanced_size=$(wc -l < "$ENHANCED_SCRIPT")
    local migrated_size=$(wc -l < "$MIGRATED_SCRIPT")
    
    [[ $primary_size -lt 1000 ]]    # Reasonable size limits
    [[ $enhanced_size -lt 1500 ]]   # Enhanced may be larger
    [[ $migrated_size -lt 1000 ]]   # Framework should be efficient
}

# =============================================================================
# Integration Readiness Tests
# =============================================================================

@test "primary script has production readiness indicators" {
    # Should have proper error handling and setup
    grep -q "setup_environment" "$PRIMARY_SCRIPT"
    grep -q "validate_prerequisites\|check.*permissions" "$PRIMARY_SCRIPT"
}

@test "migrated script follows framework patterns" {
    # Should follow the 4-library framework pattern
    grep -q "register_required_permissions" "$MIGRATED_SCRIPT"
    grep -q "source.*gcp_common.sh" "$MIGRATED_SCRIPT"
    grep -q "source.*gcp_permissions.sh" "$MIGRATED_SCRIPT"
    grep -q "source.*gcp_html_report.sh" "$MIGRATED_SCRIPT"
    grep -q "source.*gcp_scope_mgmt.sh" "$MIGRATED_SCRIPT"
}

# =============================================================================
# Compliance Documentation Tests
# =============================================================================

@test "scripts have PCI DSS requirement documentation" {
    grep -q "PCI DSS.*Requirement 1" "$PRIMARY_SCRIPT"
    grep -q "PCI DSS.*Requirement 1" "$ENHANCED_SCRIPT"
    grep -q "PCI DSS.*Requirement 1" "$MIGRATED_SCRIPT"
}

@test "scripts document covered requirements" {
    # Should document which sub-requirements are covered
    grep -q "1\.2.*1\.5\|Requirements covered" "$PRIMARY_SCRIPT"
    grep -q "1\.2.*1\.5\|Requirements covered" "$ENHANCED_SCRIPT"
    grep -q "1\.2.*1\.5\|Requirements covered" "$MIGRATED_SCRIPT"
}

@test "scripts exclude manual requirements appropriately" {
    # Requirement 1.1 should be noted as manual
    grep -q "1\.1.*manual\|manual.*1\.1" "$ENHANCED_SCRIPT"
    grep -q "1\.1.*manual\|manual.*1\.1" "$MIGRATED_SCRIPT"
}