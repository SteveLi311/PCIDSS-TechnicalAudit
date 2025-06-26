#!/usr/bin/env bats

# =============================================================================
# Test Suite for GCP PCI DSS Requirement 2 Scripts
# =============================================================================
# Tests the functionality of all four versions of the Requirement 2 scripts:
# 1. Primary Version (check_gcp_pci_requirement2.sh) - Full 4-library integration
# 2. Enhanced Version (check_gcp_pci_requirement2_integrated.sh) - Comprehensive checks
# 3. Migrated Version (check_gcp_pci_requirement2_migrated.sh) - Modern framework patterns
# 4. Backup Version (backup/check_gcp_pci_requirement2.sh) - Legacy standalone

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
    PRIMARY_SCRIPT="$SCRIPT_DIR/check_gcp_pci_requirement2.sh"
    ENHANCED_SCRIPT="$SCRIPT_DIR/check_gcp_pci_requirement2_integrated.sh"
    MIGRATED_SCRIPT="$SCRIPT_DIR/migrated/check_gcp_pci_requirement2_migrated.sh"
    BACKUP_SCRIPT="$SCRIPT_DIR/backup/check_gcp_pci_requirement2.sh"
    
    # Set up mock environment
    setup_mock_gcp_environment
    
    # Set up temporary directories
    export TEST_OUTPUT_DIR="$TEST_TEMP_DIR/requirement2_output"
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
# Syntax and Structure Tests
# =============================================================================

@test "PRIMARY: Script syntax is valid" {
    run bash -n "$PRIMARY_SCRIPT"
    assert_success
}

@test "ENHANCED: Script syntax is valid" {
    run bash -n "$ENHANCED_SCRIPT"
    assert_success
}

@test "MIGRATED: Script syntax is valid" {
    run bash -n "$MIGRATED_SCRIPT"
    assert_success
}

@test "BACKUP: Script syntax is valid" {
    run bash -n "$BACKUP_SCRIPT"
    assert_success
}

@test "PRIMARY: Script uses correct shebang" {
    run head -1 "$PRIMARY_SCRIPT"
    assert_output "#!/usr/bin/env bash"
}

@test "ENHANCED: Script uses correct shebang" {
    run head -1 "$ENHANCED_SCRIPT"
    assert_output "#!/usr/bin/env bash"
}

@test "MIGRATED: Script uses correct shebang" {
    run head -1 "$MIGRATED_SCRIPT"
    assert_output "#!/usr/bin/env bash"
}

# =============================================================================
# Library Loading Tests
# =============================================================================

@test "PRIMARY: Script loads all required shared libraries" {
    run grep -c "source.*lib.*sh" "$PRIMARY_SCRIPT"
    assert_output "4"
}

@test "PRIMARY: Script loads gcp_common.sh" {
    run grep "source.*gcp_common.sh" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script loads gcp_permissions.sh" {
    run grep "source.*gcp_permissions.sh" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script loads gcp_scope_mgmt.sh" {
    run grep "source.*gcp_scope_mgmt.sh" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script loads gcp_html_report.sh" {
    run grep "source.*gcp_html_report.sh" "$PRIMARY_SCRIPT"
    assert_success
}

# =============================================================================
# Help and Usage Tests
# =============================================================================

@test "PRIMARY: Script displays help when -h flag is used" {
    export REPORT_DIR="$TEST_OUTPUT_DIR"
    run "$PRIMARY_SCRIPT" -h
    assert_success
    assert_output --partial "Usage:"
}

@test "PRIMARY: Script displays help when --help flag is used" {
    export REPORT_DIR="$TEST_OUTPUT_DIR"
    run "$PRIMARY_SCRIPT" --help
    assert_success
    assert_output --partial "Usage:"
}

@test "ENHANCED: Script displays help when -h flag is used" {
    export REPORT_DIR="$TEST_OUTPUT_DIR"
    run "$ENHANCED_SCRIPT" -h
    assert_success
    assert_output --partial "Usage:"
}

# =============================================================================
# Framework Integration Tests
# =============================================================================

@test "PRIMARY: Script uses framework functions - run_across_projects" {
    run grep "run_across_projects" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script uses framework functions - add_section" {
    run grep "add_section" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script uses framework functions - add_check_result" {
    run grep "add_check_result" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script does not use deprecated functions" {
    run grep "run_gcp_command_across_projects\|add_html_section" "$PRIMARY_SCRIPT"
    assert_failure
}

@test "PRIMARY: Script uses shared library variables - ORG_ID" {
    run grep "ORG_ID" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script uses shared library variables - PROJECT_ID" {
    run grep "PROJECT_ID" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script does not use deprecated variables" {
    run grep "DEFAULT_ORG\|DEFAULT_PROJECT" "$PRIMARY_SCRIPT"
    assert_failure
}

# =============================================================================
# PCI DSS Compliance Coverage Tests
# =============================================================================

@test "PRIMARY: Script covers requirement 2.2.1 - Configuration standards" {
    run grep -i "2.2.1.*configuration.*standards" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script covers requirement 2.2.2 - Vendor default accounts" {
    run grep -i "2.2.2.*vendor.*default" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script covers requirement 2.2.3 - Primary functions security isolation" {
    run grep -i "2.2.3.*primary.*functions" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script covers requirement 2.2.4 - Unnecessary services disabled" {
    run grep -i "2.2.4.*unnecessary.*services" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script covers requirement 2.2.5 - Insecure services mitigation" {
    run grep -i "2.2.5.*insecure.*services" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script covers requirement 2.2.6 - System security parameters" {
    run grep -i "2.2.6.*system.*security" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script covers requirement 2.2.7 - Administrative access encryption" {
    run grep -i "2.2.7.*administrative.*access" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script covers requirement 2.3.1 & 2.3.2 - Wireless environment security" {
    run grep -i "2.3.*wireless" "$PRIMARY_SCRIPT"
    assert_success
}

# =============================================================================
# Security Assessment Logic Tests
# =============================================================================

@test "PRIMARY: Script checks organization policies when in organization scope" {
    run grep "org-policies list" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script checks default service accounts" {
    run grep "compute@developer\|appspot" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script checks firewall rules for security issues" {
    run grep "firewall-rules list" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script checks Cloud SQL SSL requirements" {
    run grep "sql instances" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script checks cloud storage security" {
    run grep "gsutil ls\|storage buckets" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script checks load balancer TLS configuration" {
    run grep "forwarding-rules.*https\|ssl" "$PRIMARY_SCRIPT"
    assert_success
}

# =============================================================================
# Output Format Tests
# =============================================================================

@test "PRIMARY: Script generates HTML output file" {
    run grep "OUTPUT_FILE.*html" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script initializes HTML report using shared library" {
    run grep "initialize_report" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script finalizes HTML report using shared library" {
    run grep "finalize_report" "$PRIMARY_SCRIPT"
    assert_success
}

# =============================================================================
# Error Handling Tests
# =============================================================================

@test "PRIMARY: Script validates required permissions" {
    run grep "check_required_permissions" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script sets up assessment scope" {
    run grep "setup_assessment_scope" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script uses proper error handling with exit codes" {
    run grep "exit 1" "$PRIMARY_SCRIPT"
    assert_success
}

# =============================================================================
# Enhanced Version Specific Tests
# =============================================================================

@test "ENHANCED: Script contains custom HTML generation functions" {
    run grep "add_html_section" "$ENHANCED_SCRIPT"
    assert_success
}

@test "ENHANCED: Script uses DEFAULT_ORG/DEFAULT_PROJECT variables" {
    run grep "DEFAULT_ORG\|DEFAULT_PROJECT" "$ENHANCED_SCRIPT"
    assert_success
}

# =============================================================================
# Performance and Efficiency Tests
# =============================================================================

@test "PRIMARY: Script uses efficient gcloud commands with proper formatting" {
    run grep "\-\-format=value" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script avoids inefficient operations in loops" {
    run grep -A5 -B5 "for.*in.*\$(.*gcloud" "$PRIMARY_SCRIPT"
    # Should not find many instances of gcloud commands inside for loops
    [[ $(echo "$output" | wc -l) -lt 10 ]]
}

# =============================================================================
# Configuration and Compliance Tests
# =============================================================================

@test "PRIMARY: Script checks OS Login policies" {
    run grep "requireOsLogin\|enable-oslogin" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script checks serial port access policies" {
    run grep "disableSerialPortAccess\|serial" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script examines audit logging configuration" {
    run grep "logging sinks" "$PRIMARY_SCRIPT"
    assert_success
}

@test "PRIMARY: Script identifies unused resources for cleanup" {
    run grep "unused\|cleanup" "$PRIMARY_SCRIPT"
    assert_success
}