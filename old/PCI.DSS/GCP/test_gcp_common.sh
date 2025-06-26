#!/bin/bash

# =============================================================================
# GCP Common Library Integration Test Script
# =============================================================================
# Description: Test script to validate gcp_common.sh library functions
# Version: 1.0
# Created: 2025-06-05
# =============================================================================

# Set up test environment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

# Colors for test output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Test helper functions
test_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

test_case() {
    local test_name="$1"
    local expected_result="$2"
    ((TEST_COUNT++))
    echo -e "\n${CYAN}Test $TEST_COUNT: $test_name${NC}"
}

test_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASS_COUNT++))
}

test_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((FAIL_COUNT++))
}

# Test results summary
test_summary() {
    echo -e "\n${BLUE}=== TEST SUMMARY ===${NC}"
    echo -e "Total Tests: $TEST_COUNT"
    echo -e "${GREEN}Passed: $PASS_COUNT${NC}"
    echo -e "${RED}Failed: $FAIL_COUNT${NC}"
    
    if [[ $FAIL_COUNT -eq 0 ]]; then
        echo -e "\n${GREEN}ALL TESTS PASSED!${NC}"
        return 0
    else
        echo -e "\n${RED}SOME TESTS FAILED!${NC}"
        return 1
    fi
}

# =============================================================================
# Test Library Loading
# =============================================================================

test_header "Library Loading Tests"

test_case "Load gcp_common.sh library" "success"
if source "$LIB_DIR/gcp_common.sh" 2>/dev/null; then
    test_pass "Library loaded successfully"
else
    test_fail "Failed to load library"
    exit 1
fi

test_case "Check library loaded variable" "GCP_COMMON_LOADED=true"
if [[ "$GCP_COMMON_LOADED" == "true" ]]; then
    test_pass "Library loaded variable set correctly"
else
    test_fail "Library loaded variable not set"
fi

# =============================================================================
# Test Function Availability
# =============================================================================

test_header "Function Availability Tests"

functions_to_test=(
    "source_gcp_libraries"
    "setup_environment" 
    "parse_common_arguments"
    "validate_prerequisites"
    "print_status"
    "load_requirement_config"
    "show_help"
    "log_debug"
    "cleanup_temp_files"
    "get_script_name"
    "check_script_permissions"
)

for func in "${functions_to_test[@]}"; do
    test_case "Function $func availability" "function exists"
    if declare -f "$func" > /dev/null; then
        test_pass "Function $func is available"
    else
        test_fail "Function $func is not available"
    fi
done

# =============================================================================
# Test Environment Setup
# =============================================================================

test_header "Environment Setup Tests"

test_case "Setup environment without log file" "success"
if setup_environment 2>/dev/null; then
    test_pass "Environment setup completed successfully"
else
    test_fail "Environment setup failed"
fi

test_case "Check color variables are set" "variables exist"
if [[ -n "$RED" && -n "$GREEN" && -n "$YELLOW" && -n "$BLUE" && -n "$CYAN" && -n "$NC" ]]; then
    test_pass "Color variables are properly set"
else
    test_fail "Color variables are not set"
fi

test_case "Check directory variables are set" "directories exist"
if [[ -n "$REPORT_DIR" && -n "$LOG_DIR" && -n "$WORK_DIR" ]]; then
    test_pass "Directory variables are properly set"
else
    test_fail "Directory variables are not set"
fi

# =============================================================================
# Test CLI Argument Parsing
# =============================================================================

test_header "CLI Argument Parsing Tests"

# Test with valid arguments
test_case "Parse valid arguments" "success"
if parse_common_arguments -s project -p test-project -o /tmp/test 2>/dev/null; then
    test_pass "Valid arguments parsed successfully"
    
    # Check if variables were set correctly
    if [[ "$SCOPE" == "project" && "$PROJECT_ID" == "test-project" && "$OUTPUT_DIR" == "/tmp/test" ]]; then
        test_pass "Arguments set correct variables"
    else
        test_fail "Arguments did not set variables correctly"
    fi
else
    test_fail "Failed to parse valid arguments"
fi

# Test with invalid scope
test_case "Parse invalid scope argument" "error"
if ! parse_common_arguments -s invalid 2>/dev/null; then
    test_pass "Invalid scope correctly rejected"
else
    test_fail "Invalid scope was accepted"
fi

# Test help display
test_case "Display help information" "help displayed"
parse_common_arguments -h >/dev/null 2>&1
help_exit_code=$?
if [[ $help_exit_code -eq 2 ]]; then
    test_pass "Help displayed with correct exit code"
else
    test_fail "Help displayed but wrong exit code: $help_exit_code"
fi

# =============================================================================
# Test Print Status Function
# =============================================================================

test_header "Print Status Function Tests"

test_case "Print info message" "success"
output=$(print_status "INFO" "Test info message" 2>/dev/null)
if [[ $? -eq 0 && "$output" =~ "Test info message" ]]; then
    test_pass "Info message printed successfully"
else
    test_fail "Info message printing failed"
fi

test_case "Print success message" "success"
output=$(print_status "PASS" "Test success message" 2>/dev/null)
if [[ $? -eq 0 && "$output" =~ "Test success message" ]]; then
    test_pass "Success message printed successfully"
else
    test_fail "Success message printing failed"
fi

test_case "Print warning message" "success" 
output=$(print_status "WARN" "Test warning message" 2>/dev/null)
if [[ $? -eq 0 && "$output" =~ "Test warning message" ]]; then
    test_pass "Warning message printed successfully"
else
    test_fail "Warning message printing failed"
fi

test_case "Print error message" "success"
output=$(print_status "FAIL" "Test error message" 2>/dev/null)
if [[ $? -eq 0 && "$output" =~ "Test error message" ]]; then
    test_pass "Error message printed successfully"
else
    test_fail "Error message printing failed"
fi

# =============================================================================
# Test Configuration Loading
# =============================================================================

test_header "Configuration Loading Tests"

test_case "Load non-existent configuration" "warning"
if ! load_requirement_config "nonexistent" 2>/dev/null; then
    test_pass "Non-existent configuration correctly handled"
else
    test_fail "Non-existent configuration should have failed"
fi

# =============================================================================
# Test Utility Functions
# =============================================================================

test_header "Utility Function Tests"

test_case "Get script name" "success"
script_name=$(get_script_name)
if [[ -n "$script_name" ]]; then
    test_pass "Script name retrieved: $script_name"
else
    test_fail "Script name not retrieved"
fi

test_case "Check script permissions" "success"
if check_script_permissions 2>/dev/null; then
    test_pass "Script permissions check completed"
else
    test_fail "Script permissions check failed"
fi

test_case "Cleanup temp files" "success"
if cleanup_temp_files 2>/dev/null; then
    test_pass "Temp files cleanup completed"
else
    test_fail "Temp files cleanup failed"
fi

# =============================================================================
# Test Source Libraries Function
# =============================================================================

test_header "Source Libraries Function Tests"

test_case "Source GCP libraries" "success"
if source_gcp_libraries 2>/dev/null; then
    test_pass "GCP libraries sourced successfully"
else
    test_fail "Failed to source GCP libraries"
fi

test_case "Check library path variable" "variable set"
if [[ -n "$GCP_LIB_PATH" ]]; then
    test_pass "Library path variable set: $GCP_LIB_PATH"
else
    test_fail "Library path variable not set"
fi

# =============================================================================
# Integration Test Results
# =============================================================================

echo -e "\n${BLUE}=== INTEGRATION TEST COMPLETE ===${NC}"
test_summary

# Clean up test variables
unset TEST_COUNT PASS_COUNT FAIL_COUNT

exit $?