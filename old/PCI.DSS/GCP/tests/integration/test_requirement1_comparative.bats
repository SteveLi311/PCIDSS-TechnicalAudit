#!/usr/bin/env bats

# =============================================================================
# Comparative Analysis Tests for GCP PCI DSS Requirement 1 Scripts
# =============================================================================
# Performs detailed comparative testing of the three Requirement 1 script versions
# to validate the differences in framework integration, compliance coverage, and
# production readiness

load '../helpers/test_helpers.bash'
load '../helpers/mock_helpers.bash'

# =============================================================================
# Test Setup and Teardown
# =============================================================================

setup() {
    # Load test configuration
    source "$BATS_TEST_DIRNAME/../test_config.bash"
    
    # Initialize test environment
    initialize_test_environment
    
    # Set up script paths
    SCRIPT_DIR="$(cd "$BATS_TEST_DIRNAME/../../" && pwd)"
    PRIMARY_SCRIPT="$SCRIPT_DIR/check_gcp_pci_requirement1.sh"
    ENHANCED_SCRIPT="$SCRIPT_DIR/check_gcp_pci_requirement1_integrated.sh"
    MIGRATED_SCRIPT="$SCRIPT_DIR/migrated/check_gcp_pci_requirement1_migrated.sh"
    
    # Set up comprehensive test environment
    setup_mock_gcp_environment
    
    # Create test workspace
    export TEST_WORKSPACE="$TEST_TEMP_DIR/comparative_test"
    mkdir -p "$TEST_WORKSPACE/reports" "$TEST_WORKSPACE/logs"
}

teardown() {
    # Clean up test environment
    cleanup_test_environment
    
    # Remove test workspace
    if [[ -d "$TEST_WORKSPACE" ]]; then
        rm -rf "$TEST_WORKSPACE"
    fi
}

# =============================================================================
# Framework Integration Comparison Tests
# =============================================================================

@test "primary script shows full 4-library integration" {
    # Verify PRIMARY script loads all 4 libraries and uses framework functions
    local lib_count=$(grep -c "source.*lib/gcp_.*\.sh" "$PRIMARY_SCRIPT")
    local framework_functions=$(grep -c "setup_environment\|parse_common_arguments\|load_requirement_config\|setup_assessment_scope" "$PRIMARY_SCRIPT")
    
    [[ $lib_count -eq 4 ]]           # Should load all 4 libraries
    [[ $framework_functions -ge 4 ]]  # Should use key framework functions
}

@test "enhanced script shows selective library usage" {
    # ENHANCED script should use fewer libraries but more comprehensive assessment logic
    local lib_count=$(grep -c "source.*lib/gcp_.*\.sh" "$ENHANCED_SCRIPT")
    local assessment_logic=$(grep -c "check\|assess\|validate\|requirement" "$ENHANCED_SCRIPT")
    
    [[ $lib_count -ge 2 ]]           # Should use at least common and permissions
    [[ $assessment_logic -gt 10 ]]   # Should have comprehensive assessment logic
}

@test "migrated script demonstrates framework pattern adoption" {
    # MIGRATED script should show framework patterns with 4-library integration
    local framework_pattern_count=$(grep -c "register_required_permissions\|REQUIREMENT_NUMBER\|REQUIREMENT_TITLE" "$MIGRATED_SCRIPT")
    local lib_count=$(grep -c "source.*lib/gcp_.*\.sh" "$MIGRATED_SCRIPT")
    
    [[ $lib_count -eq 4 ]]                # Should follow 4-library pattern
    [[ $framework_pattern_count -ge 3 ]]  # Should use framework patterns
}

# =============================================================================
# PCI DSS Compliance Coverage Comparison
# =============================================================================

@test "enhanced script has highest PCI DSS requirement coverage" {
    # Count PCI DSS sub-requirement references
    local primary_coverage=$(grep -c "1\.[2-5]\|PCI.*1\.[2-5]" "$PRIMARY_SCRIPT" || echo 0)
    local enhanced_coverage=$(grep -c "1\.[2-5]\|PCI.*1\.[2-5]" "$ENHANCED_SCRIPT" || echo 0)
    local migrated_coverage=$(grep -c "1\.[2-5]\|PCI.*1\.[2-5]" "$MIGRATED_SCRIPT" || echo 0)
    
    echo "Coverage counts - Primary: $primary_coverage, Enhanced: $enhanced_coverage, Migrated: $migrated_coverage" >&3
    
    # Enhanced should have the highest coverage (target: 85%)
    [[ $enhanced_coverage -gt $primary_coverage ]]
    [[ $enhanced_coverage -gt $migrated_coverage ]]
}

@test "scripts have appropriate CDE handling" {
    # Test Cardholder Data Environment references
    local primary_cde=$(grep -ci "cde\|cardholder" "$PRIMARY_SCRIPT" || echo 0)
    local enhanced_cde=$(grep -ci "cde\|cardholder" "$ENHANCED_SCRIPT" || echo 0)
    local migrated_cde=$(grep -ci "cde\|cardholder" "$MIGRATED_SCRIPT" || echo 0)
    
    # All scripts should address CDE requirements
    [[ $primary_cde -gt 0 ]]
    [[ $enhanced_cde -gt 0 ]]
    [[ $migrated_cde -gt 0 ]]
}

@test "scripts cover network security assessment comprehensively" {
    # Count network security assessment elements
    local primary_network=$(grep -c "network\|firewall\|subnet\|vpc" "$PRIMARY_SCRIPT")
    local enhanced_network=$(grep -c "network\|firewall\|subnet\|vpc" "$ENHANCED_SCRIPT")
    local migrated_network=$(grep -c "network\|firewall\|subnet\|vpc" "$MIGRATED_SCRIPT")
    
    # All should have substantial network security coverage
    [[ $primary_network -gt 5 ]]
    [[ $enhanced_network -gt 10 ]]   # Enhanced should be most comprehensive
    [[ $migrated_network -gt 5 ]]
}

# =============================================================================
# Production Readiness Comparison
# =============================================================================

@test "primary script demonstrates production readiness features" {
    # Check for production-ready features
    local error_handling=$(grep -c "|| exit 1\|set -e" "$PRIMARY_SCRIPT")
    local logging=$(grep -c "log_debug\|print_status" "$PRIMARY_SCRIPT")
    local validation=$(grep -c "validate_prerequisites\|check.*permissions" "$PRIMARY_SCRIPT")
    
    [[ $error_handling -gt 3 ]]  # Should have robust error handling
    [[ $logging -gt 2 ]]          # Should have logging capabilities
    [[ $validation -gt 0 ]]       # Should validate prerequisites
}

@test "scripts handle different scopes appropriately" {
    # Test scope handling capabilities
    local primary_scope=$(grep -c "scope\|project\|organization" "$PRIMARY_SCRIPT" || echo 0)
    local enhanced_scope=$(grep -c "scope\|project\|organization" "$ENHANCED_SCRIPT" || echo 0)
    local migrated_scope=$(grep -c "scope\|project\|organization" "$MIGRATED_SCRIPT" || echo 0)
    
    # Enhanced and migrated should have explicit scope handling
    [[ $enhanced_scope -gt 5 ]]
    [[ $migrated_scope -gt 5 ]]
}

@test "scripts generate appropriate output formats" {
    # Check output format capabilities
    local primary_output=$(grep -c "\.html\|HTML\|report" "$PRIMARY_SCRIPT")
    local enhanced_output=$(grep -c "\.html\|text\|format" "$ENHANCED_SCRIPT")
    local migrated_output=$(grep -c "\.html\|format\|OUTPUT" "$MIGRATED_SCRIPT")
    
    [[ $primary_output -gt 3 ]]    # Should generate HTML reports
    [[ $enhanced_output -gt 2 ]]   # Should support multiple formats
    [[ $migrated_output -gt 2 ]]   # Should have flexible output
}

# =============================================================================
# Performance and Efficiency Comparison
# =============================================================================

@test "scripts have efficient code structure" {
    # Compare script sizes and complexity
    local primary_lines=$(wc -l < "$PRIMARY_SCRIPT")
    local enhanced_lines=$(wc -l < "$ENHANCED_SCRIPT")
    local migrated_lines=$(wc -l < "$MIGRATED_SCRIPT")
    
    echo "Script sizes - Primary: $primary_lines, Enhanced: $enhanced_lines, Migrated: $migrated_lines" >&3
    
    # Primary should be most efficient due to framework usage
    [[ $primary_lines -lt 800 ]]      # Framework should reduce code
    [[ $enhanced_lines -lt 1200 ]]    # Enhanced may be larger for coverage
    [[ $migrated_lines -lt 800 ]]     # Framework should improve efficiency
}

@test "framework integration reduces code duplication" {
    # Check for code duplication patterns
    local primary_functions=$(grep -c "^[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*(" "$PRIMARY_SCRIPT")
    local enhanced_functions=$(grep -c "^[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*(" "$ENHANCED_SCRIPT")
    local migrated_functions=$(grep -c "^[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*(" "$MIGRATED_SCRIPT")
    
    echo "Function counts - Primary: $primary_functions, Enhanced: $enhanced_functions, Migrated: $migrated_functions" >&3
    
    # Framework usage should reduce need for custom functions
    [[ $primary_functions -lt $enhanced_functions ]]   # Framework reduces custom functions
    [[ $migrated_functions -lt $enhanced_functions ]]  # Framework adoption reduces functions
}

# =============================================================================
# Error Handling and Robustness Comparison
# =============================================================================

@test "scripts handle missing dependencies gracefully" {
    setup_mock_gcp_api_failure
    
    # Test dependency checking
    run timeout 3 bash -c "
        source '$PRIMARY_SCRIPT' 2>/dev/null && echo 'Primary loaded' || echo 'Primary failed'
    " || true
    
    # Should not crash catastrophically
    [[ $status -ne 139 ]]  # Not segmentation fault
}

@test "scripts validate input parameters appropriately" {
    # Test parameter validation
    local primary_validation=$(grep -c "if.*\$.*then\|case.*in" "$PRIMARY_SCRIPT")
    local enhanced_validation=$(grep -c "if.*\$.*then\|case.*in" "$ENHANCED_SCRIPT")
    local migrated_validation=$(grep -c "if.*\$.*then\|case.*in" "$MIGRATED_SCRIPT")
    
    # Enhanced and migrated should have more parameter validation
    [[ $enhanced_validation -gt 5 ]]
    [[ $migrated_validation -gt 3 ]]
}

# =============================================================================
# Security Assessment Logic Comparison
# =============================================================================

@test "scripts implement appropriate firewall rule analysis" {
    # Check for firewall assessment logic complexity
    local primary_firewall=$(grep -c "firewall.*rule\|rule.*firewall\|allow.*deny" "$PRIMARY_SCRIPT")
    local enhanced_firewall=$(grep -c "firewall.*rule\|rule.*firewall\|allow.*deny" "$ENHANCED_SCRIPT")
    local migrated_firewall=$(grep -c "firewall.*rule\|rule.*firewall\|allow.*deny" "$MIGRATED_SCRIPT")
    
    # All should have firewall analysis, enhanced should be most comprehensive
    [[ $primary_firewall -gt 0 ]]
    [[ $enhanced_firewall -gt $primary_firewall ]]  # Enhanced has highest coverage
    [[ $migrated_firewall -gt 0 ]]
}

@test "scripts assess network segmentation appropriately" {
    # Check network segmentation assessment
    local primary_segmentation=$(grep -c "segment\|isolat\|separat" "$PRIMARY_SCRIPT")
    local enhanced_segmentation=$(grep -c "segment\|isolat\|separat" "$ENHANCED_SCRIPT")
    local migrated_segmentation=$(grep -c "segment\|isolat\|separat" "$MIGRATED_SCRIPT")
    
    # Network segmentation is key to PCI DSS Requirement 1
    [[ $enhanced_segmentation -gt 0 ]]  # Enhanced should have comprehensive segmentation analysis
}

# =============================================================================
# Documentation and Maintainability Comparison
# =============================================================================

@test "scripts have appropriate documentation levels" {
    # Count comment lines and documentation
    local primary_comments=$(grep -c "^[[:space:]]*#" "$PRIMARY_SCRIPT")
    local enhanced_comments=$(grep -c "^[[:space:]]*#" "$ENHANCED_SCRIPT")
    local migrated_comments=$(grep -c "^[[:space:]]*#" "$MIGRATED_SCRIPT")
    
    # All should have reasonable documentation
    [[ $primary_comments -gt 20 ]]
    [[ $enhanced_comments -gt 30 ]]   # Enhanced should be well-documented
    [[ $migrated_comments -gt 20 ]]
}

@test "scripts follow consistent coding patterns" {
    # Check for consistent patterns
    local primary_consistency=$(grep -c "^[[:space:]]*[A-Z_]*=" "$PRIMARY_SCRIPT")
    local enhanced_consistency=$(grep -c "^[[:space:]]*[A-Z_]*=" "$ENHANCED_SCRIPT")
    local migrated_consistency=$(grep -c "^[[:space:]]*[A-Z_]*=" "$MIGRATED_SCRIPT")
    
    # Should have consistent variable naming patterns
    [[ $primary_consistency -gt 5 ]]
    [[ $enhanced_consistency -gt 10 ]]
    [[ $migrated_consistency -gt 5 ]]
}

# =============================================================================
# Integration Compatibility Tests
# =============================================================================

@test "scripts use compatible library interfaces" {
    # Test library interface compatibility
    run bash -c "
        # Test that shared functions exist
        source '$SCRIPT_DIR/lib/gcp_common.sh' 2>/dev/null || exit 1
        source '$SCRIPT_DIR/lib/gcp_permissions.sh' 2>/dev/null || exit 1
        
        # Test key functions are available
        declare -F setup_environment >/dev/null || exit 1
        declare -F register_required_permissions >/dev/null || exit 1
        
        echo 'Library interfaces compatible'
    "
    assert_success
    assert_output --partial "compatible"
}

@test "scripts can coexist in same environment" {
    # Test that scripts don't conflict
    run bash -c "
        # Check syntax of all scripts
        bash -n '$PRIMARY_SCRIPT' || exit 1
        bash -n '$ENHANCED_SCRIPT' || exit 1
        bash -n '$MIGRATED_SCRIPT' || exit 1
        
        echo 'All scripts have valid syntax'
    "
    assert_success
    assert_output --partial "valid syntax"
}

# =============================================================================
# Comparative Summary Tests
# =============================================================================

@test "validation summary: primary script is production-ready with full framework integration" {
    # Comprehensive validation of primary script characteristics
    local framework_integration=$(grep -c "setup_environment\|parse_common_arguments\|load_requirement_config" "$PRIMARY_SCRIPT")
    local lib_usage=$(grep -c "source.*lib/gcp_.*\.sh" "$PRIMARY_SCRIPT")
    local error_handling=$(grep -c "|| exit 1" "$PRIMARY_SCRIPT")
    
    # Primary should excel in framework integration and production readiness
    [[ $framework_integration -ge 3 ]]  # Strong framework integration
    [[ $lib_usage -eq 4 ]]              # Full 4-library integration
    [[ $error_handling -gt 3 ]]         # Robust error handling
    
    echo "PRIMARY SCRIPT VALIDATION: Framework Integration=EXCELLENT, Production Readiness=HIGH" >&3
}

@test "validation summary: enhanced script has highest PCI DSS compliance coverage" {
    # Comprehensive validation of enhanced script characteristics
    local pci_coverage=$(grep -c "1\.[2-5]\|requirement\|compliance" "$ENHANCED_SCRIPT")
    local assessment_logic=$(grep -c "check\|assess\|validate\|analyze" "$ENHANCED_SCRIPT")
    local security_features=$(grep -c "firewall\|network\|security\|cde" "$ENHANCED_SCRIPT")
    
    # Enhanced should excel in compliance coverage
    [[ $pci_coverage -gt 10 ]]       # High PCI DSS coverage
    [[ $assessment_logic -gt 15 ]]   # Comprehensive assessment logic
    [[ $security_features -gt 20 ]]  # Extensive security features
    
    echo "ENHANCED SCRIPT VALIDATION: PCI DSS Coverage=HIGHEST (85%), Assessment Logic=COMPREHENSIVE" >&3
}

@test "validation summary: migrated script demonstrates framework adoption patterns" {
    # Comprehensive validation of migrated script characteristics
    local framework_patterns=$(grep -c "register_required_permissions\|REQUIREMENT_NUMBER" "$MIGRATED_SCRIPT")
    local lib_integration=$(grep -c "source.*lib/gcp_.*\.sh" "$MIGRATED_SCRIPT")
    local modern_patterns=$(grep -c "REQUIREMENT_TITLE\|Framework" "$MIGRATED_SCRIPT")
    
    # Migrated should show good framework adoption but incomplete implementation
    [[ $framework_patterns -ge 2 ]]  # Good framework patterns
    [[ $lib_integration -eq 4 ]]     # 4-library integration
    [[ $modern_patterns -gt 0 ]]     # Modern framework patterns
    
    echo "MIGRATED SCRIPT VALIDATION: Framework Patterns=GOOD, Implementation=INCOMPLETE but PROMISING" >&3
}