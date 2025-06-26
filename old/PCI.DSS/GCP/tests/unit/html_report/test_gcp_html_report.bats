#!/usr/bin/env bats
# =============================================================================
# Unit Tests for GCP HTML Report Library
# =============================================================================
# Test Coverage: All 9 functions (5 core + 4 helpers)
# Target: 90%+ code coverage with positive and negative test cases
# Framework: BATS (Bash Automated Testing System)
# =============================================================================

# Load test helpers
load '../../helpers/test_helpers'

# Global test variables
export TEST_OUTPUT_DIR="/tmp/gcp_html_report_tests"
export TEST_HTML_FILE="$TEST_OUTPUT_DIR/test_report.html"
export TEST_PROJECT_ID="test-project-12345"

# Setup function - runs before each test
setup() {
    # Create test directory
    mkdir -p "$TEST_OUTPUT_DIR"
    
    # Mock global variables expected by the library
    export PROJECT_ID="$TEST_PROJECT_ID"
    export ORG_ID=""
    export SCOPE_TYPE="project"
    export VERBOSE="false"
    export OUTPUT_DIR="$TEST_OUTPUT_DIR"
    export PERMISSION_COVERAGE_PERCENTAGE="0"
    
    # Change to lib directory for proper loading
    cd "$BATS_TEST_DIRNAME/../../../lib"
    
    # Load the HTML report library
    source gcp_html_report.sh
}

# Teardown function - runs after each test
teardown() {
    # Clean up test files
    rm -rf "$TEST_OUTPUT_DIR"
}

# =============================================================================
# Core Function Tests
# =============================================================================

@test "initialize_report creates valid HTML5 document structure" {
    run initialize_report "$TEST_HTML_FILE" "Test PCI DSS Report" "1" "$TEST_PROJECT_ID"
    
    [ "$status" -eq 0 ]
    [ -f "$TEST_HTML_FILE" ]
    
    # Validate HTML5 structure
    grep -q "<!DOCTYPE html>" "$TEST_HTML_FILE"
    grep -q "<html lang=\"en\">" "$TEST_HTML_FILE"
    grep -q "<meta charset=\"UTF-8\">" "$TEST_HTML_FILE"
    grep -q "Test PCI DSS Report" "$TEST_HTML_FILE"
    # Check that project ID appears in the HTML content
    grep -q "$TEST_PROJECT_ID" "$TEST_HTML_FILE" || {
        echo "Project ID not found in HTML. Content:"
        cat "$TEST_HTML_FILE"
        return 1
    }
}

@test "initialize_report handles missing required parameters" {
    # Test missing output file
    run initialize_report "" "Test Report" "1" "$TEST_PROJECT_ID"
    [ "$status" -eq 1 ]
    
    # Test missing report title
    run initialize_report "$TEST_HTML_FILE" "" "1" "$TEST_PROJECT_ID"
    [ "$status" -eq 1 ]
    
    # Test missing requirement number
    run initialize_report "$TEST_HTML_FILE" "Test Report" "" "$TEST_PROJECT_ID"
    [ "$status" -eq 1 ]
}

@test "initialize_report creates output directory if missing" {
    local nested_file="$TEST_OUTPUT_DIR/nested/deep/test.html"
    
    run initialize_report "$nested_file" "Test Report" "1" "$TEST_PROJECT_ID"
    
    [ "$status" -eq 0 ]
    [ -f "$nested_file" ]
}

@test "add_section creates collapsible section with proper structure" {
    # Initialize report first
    initialize_report "$TEST_HTML_FILE" "Test Report" "1" "$TEST_PROJECT_ID"
    
    run add_section "$TEST_HTML_FILE" "section1" "Test Section Title" "active"
    
    [ "$status" -eq 0 ]
    grep -q "id=\"section-section1\"" "$TEST_HTML_FILE"
    grep -q "Test Section Title" "$TEST_HTML_FILE"
    grep -q "section-header active" "$TEST_HTML_FILE"
    grep -q "aria-expanded=\"true\"" "$TEST_HTML_FILE"
}

@test "add_section handles inactive sections" {
    initialize_report "$TEST_HTML_FILE" "Test Report" "1" "$TEST_PROJECT_ID"
    
    run add_section "$TEST_HTML_FILE" "section2" "Inactive Section" ""
    
    [ "$status" -eq 0 ]
    grep -q "section-header" "$TEST_HTML_FILE"
    grep -q "aria-expanded=\"false\"" "$TEST_HTML_FILE"
}

@test "add_section validates required parameters" {
    initialize_report "$TEST_HTML_FILE" "Test Report" "1" "$TEST_PROJECT_ID"
    
    # Test missing section ID
    run add_section "$TEST_HTML_FILE" "" "Title"
    [ "$status" -eq 1 ]
    
    # Test missing section title
    run add_section "$TEST_HTML_FILE" "section1" ""
    [ "$status" -eq 1 ]
}

@test "add_check_result handles all status types correctly" {
    initialize_report "$TEST_HTML_FILE" "Test Report" "1" "$TEST_PROJECT_ID"
    add_section "$TEST_HTML_FILE" "section1" "Test Section" "active"
    
    # Test all valid status types
    for status in pass fail warning info; do
        run add_check_result "$TEST_HTML_FILE" "$status" "Test Check $status" "Details for $status"
        [ "$status" -eq 0 ]
        grep -q "Test Check $status" "$TEST_HTML_FILE"
    done
}

@test "add_check_result validates status parameter" {
    initialize_report "$TEST_HTML_FILE" "Test Report" "1" "$TEST_PROJECT_ID"
    
    # Test invalid status
    run add_check_result "$TEST_HTML_FILE" "invalid" "Test Check" "Details"
    [ "$status" -eq 1 ]
}

@test "add_check_result includes optional recommendation" {
    initialize_report "$TEST_HTML_FILE" "Test Report" "1" "$TEST_PROJECT_ID"
    add_section "$TEST_HTML_FILE" "section1" "Test Section" "active"
    
    run add_check_result "$TEST_HTML_FILE" "fail" "Failed Check" "Error details" "Fix this issue"
    
    [ "$status" -eq 0 ]
    grep -q "Recommendation:" "$TEST_HTML_FILE"
    grep -q "Fix this issue" "$TEST_HTML_FILE"
}

@test "add_summary_metrics calculates compliance percentage correctly" {
    initialize_report "$TEST_HTML_FILE" "Test Report" "1" "$TEST_PROJECT_ID"
    
    # Test 80% compliance (8 passed, 2 failed, 1 warning)
    run add_summary_metrics "$TEST_HTML_FILE" "11" "8" "2" "1"
    
    [ "$status" -eq 0 ]
    grep -q "80% Compliant" "$TEST_HTML_FILE"
    grep -q "PARTIALLY COMPLIANT" "$TEST_HTML_FILE"
}

@test "add_summary_metrics handles edge cases" {
    initialize_report "$TEST_HTML_FILE" "Test Report" "1" "$TEST_PROJECT_ID"
    
    # Test 100% compliance
    run add_summary_metrics "$TEST_HTML_FILE" "5" "5" "0" "0"
    [ "$status" -eq 0 ]
    grep -q "100% Compliant" "$TEST_HTML_FILE"
    
    # Test 0% compliance
    run add_summary_metrics "$TEST_HTML_FILE" "5" "0" "5" "0"
    [ "$status" -eq 0 ]
    grep -q "0% Compliant" "$TEST_HTML_FILE"
    
    # Test no assessable checks
    run add_summary_metrics "$TEST_HTML_FILE" "3" "0" "0" "3"
    [ "$status" -eq 0 ]
    grep -q "NO ASSESSABLE CHECKS" "$TEST_HTML_FILE"
}

@test "add_summary_metrics validates numeric parameters" {
    initialize_report "$TEST_HTML_FILE" "Test Report" "1" "$TEST_PROJECT_ID"
    
    # Test non-numeric parameters
    run add_summary_metrics "$TEST_HTML_FILE" "abc" "5" "2" "1"
    [ "$status" -eq 1 ]
    
    run add_summary_metrics "$TEST_HTML_FILE" "10" "xyz" "2" "1"
    [ "$status" -eq 1 ]
}

@test "finalize_report completes HTML structure with JavaScript" {
    initialize_report "$TEST_HTML_FILE" "Test Report" "1" "$TEST_PROJECT_ID"
    add_section "$TEST_HTML_FILE" "section1" "Test Section" "active"
    
    run finalize_report "$TEST_HTML_FILE" "1"
    
    [ "$status" -eq 0 ]
    grep -q "</html>" "$TEST_HTML_FILE"
    grep -q "function toggleSection" "$TEST_HTML_FILE"
    grep -q "DOMContentLoaded" "$TEST_HTML_FILE"
    grep -q "Report Generated:" "$TEST_HTML_FILE"
}

# =============================================================================
# Helper Function Tests
# =============================================================================

@test "html_append safely appends content to file" {
    echo "<html>" > "$TEST_HTML_FILE"
    
    run html_append "$TEST_HTML_FILE" "<body>Test Content</body>"
    
    [ "$status" -eq 0 ]
    grep -q "Test Content" "$TEST_HTML_FILE"
}

@test "html_append handles missing file parameter" {
    run html_append "" "content"
    [ "$status" -eq 1 ]
}

@test "html_append handles file write errors" {
    # Create read-only directory to simulate write failure
    local readonly_dir="/tmp/readonly_test"
    mkdir -p "$readonly_dir"
    chmod 555 "$readonly_dir"
    
    run html_append "$readonly_dir/test.html" "content"
    [ "$status" -eq 1 ]
    
    # Clean up
    chmod 755 "$readonly_dir"
    rmdir "$readonly_dir"
}

@test "close_section adds proper closing tags" {
    echo "<div>" > "$TEST_HTML_FILE"
    
    run close_section "$TEST_HTML_FILE"
    
    [ "$status" -eq 0 ]
    grep -q "Close section content" "$TEST_HTML_FILE"
    grep -q "Close section" "$TEST_HTML_FILE"
}

@test "check_gcp_api_access validates parameters" {
    initialize_report "$TEST_HTML_FILE" "Test Report" "1" "$TEST_PROJECT_ID"
    
    # Test missing service parameter
    run check_gcp_api_access "$TEST_HTML_FILE" "" "list"
    [ "$status" -eq 1 ]
    
    # Test missing operation parameter  
    run check_gcp_api_access "$TEST_HTML_FILE" "compute" ""
    [ "$status" -eq 1 ]
}

@test "add_manual_check creates warning status check with guidance" {
    initialize_report "$TEST_HTML_FILE" "Test Report" "1" "$TEST_PROJECT_ID"
    add_section "$TEST_HTML_FILE" "section1" "Test Section" "active"
    
    run add_manual_check "$TEST_HTML_FILE" "Manual Verification Required" "Check this manually" "Custom guidance"
    
    [ "$status" -eq 0 ]
    grep -q "Manual Verification Required" "$TEST_HTML_FILE"
    grep -q "Custom guidance" "$TEST_HTML_FILE"
    grep -q "WARNING" "$TEST_HTML_FILE"
}

@test "add_manual_check uses default guidance when not provided" {
    initialize_report "$TEST_HTML_FILE" "Test Report" "1" "$TEST_PROJECT_ID"
    add_section "$TEST_HTML_FILE" "section1" "Test Section" "active"
    
    run add_manual_check "$TEST_HTML_FILE" "Manual Check" "Description only"
    
    [ "$status" -eq 0 ]
    grep -q "requires manual verification" "$TEST_HTML_FILE"
}

# =============================================================================
# Integration and Edge Case Tests
# =============================================================================

@test "complete report generation workflow" {
    # Test full workflow from start to finish
    run initialize_report "$TEST_HTML_FILE" "Complete Test Report" "1" "$TEST_PROJECT_ID"
    [ "$status" -eq 0 ]
    
    run add_section "$TEST_HTML_FILE" "checks" "Security Checks" "active"
    [ "$status" -eq 0 ]
    
    run add_check_result "$TEST_HTML_FILE" "pass" "Firewall Check" "All rules validated" "None needed"
    [ "$status" -eq 0 ]
    
    run add_check_result "$TEST_HTML_FILE" "fail" "Password Policy" "Weak settings found" "Strengthen policies"
    [ "$status" -eq 0 ]
    
    run add_manual_check "$TEST_HTML_FILE" "Physical Security" "Review datacenter access"
    [ "$status" -eq 0 ]
    
    run add_summary_metrics "$TEST_HTML_FILE" "3" "1" "1" "1"
    [ "$status" -eq 0 ]
    
    run finalize_report "$TEST_HTML_FILE" "1"
    [ "$status" -eq 0 ]
    
    # Validate complete HTML structure
    grep -q "<!DOCTYPE html>" "$TEST_HTML_FILE"
    grep -q "</html>" "$TEST_HTML_FILE"
    grep -q "Complete Test Report" "$TEST_HTML_FILE"
    grep -q "Firewall Check" "$TEST_HTML_FILE"
    grep -q "Password Policy" "$TEST_HTML_FILE"
    grep -q "Physical Security" "$TEST_HTML_FILE"
    # Compliance = 1 pass / (1 pass + 1 fail) = 50%
    grep -q "50% Compliant" "$TEST_HTML_FILE"
}

@test "library loading and initialization" {
    # Test that library sets proper flags
    [ "$GCP_HTML_REPORT_LOADED" = "true" ]
    
    # Test that required functions are available
    type initialize_report > /dev/null
    type add_section > /dev/null
    type add_check_result > /dev/null
    type add_summary_metrics > /dev/null
    type finalize_report > /dev/null
    type html_append > /dev/null
    type close_section > /dev/null
    type check_gcp_api_access > /dev/null
    type add_manual_check > /dev/null
}

@test "validate_html_params helper function" {
    # Test successful validation
    run validate_html_params "$TEST_HTML_FILE" "param" "test_function"
    [ "$status" -eq 0 ]
    
    # Test missing output file
    run validate_html_params "" "param" "test_function"
    [ "$status" -eq 1 ]
    
    # Test missing required parameter
    run validate_html_params "$TEST_HTML_FILE" "" "test_function"
    [ "$status" -eq 1 ]
}