#!/bin/bash

# =============================================================================
# GCP Shared Library Test Runner
# =============================================================================
# Comprehensive test execution and reporting for GCP shared libraries
# Supports unit tests, integration tests, coverage reporting, and quality gates

set -euo pipefail

# =============================================================================
# Script Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
START_TIME=$(date +%s)

# Load test configuration
if [[ -f "$SCRIPT_DIR/test_config.bash" ]]; then
    source "$SCRIPT_DIR/test_config.bash"
else
    echo "ERROR: Test configuration not found at $SCRIPT_DIR/test_config.bash" >&2
    exit 1
fi

# =============================================================================
# Global Variables
# =============================================================================

# Test Results
UNIT_TESTS_PASSED=0
UNIT_TESTS_FAILED=0
INTEGRATION_TESTS_PASSED=0
INTEGRATION_TESTS_FAILED=0
TOTAL_TESTS_PASSED=0
TOTAL_TESTS_FAILED=0

# Coverage Results
ACHIEVED_FUNCTION_COVERAGE=0
ACHIEVED_LINE_COVERAGE=0
ACHIEVED_INTEGRATION_COVERAGE=0

# Execution Flags
RUN_UNIT_TESTS=true
RUN_INTEGRATION_TESTS=true
RUN_COVERAGE_ANALYSIS=true
GENERATE_REPORTS=true
ENFORCE_QUALITY_GATES=true
VERBOSE_MODE=false
DRY_RUN=false

# Output Files
TEST_REPORT_FILE=""
COVERAGE_REPORT_FILE=""
JUNIT_REPORT_FILE=""
TEST_LOG_FILE=""

# =============================================================================
# Utility Functions
# =============================================================================

# Print colored output
print_colored() {
    local color="$1"
    local message="$2"
    
    if [[ "$TEST_COLORIZED_OUTPUT" == "true" ]]; then
        case "$color" in
            red)     echo -e "\033[0;31m$message\033[0m" ;;
            green)   echo -e "\033[0;32m$message\033[0m" ;;
            yellow)  echo -e "\033[1;33m$message\033[0m" ;;
            blue)    echo -e "\033[0;34m$message\033[0m" ;;
            cyan)    echo -e "\033[0;36m$message\033[0m" ;;
            *)       echo "$message" ;;
        esac
    else
        echo "$message"
    fi
}

# Log with timestamp
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" | tee -a "$TEST_LOG_FILE"
}

# Print status with formatting
print_status() {
    local status="$1"
    local message="$2"
    
    case "$status" in
        PASS)   print_colored green "✓ $message" ;;
        FAIL)   print_colored red "✗ $message" ;;
        WARN)   print_colored yellow "⚠ $message" ;;
        INFO)   print_colored blue "ℹ $message" ;;
        *)      echo "$message" ;;
    esac
}

# Show usage information
show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

GCP Shared Library Test Runner

OPTIONS:
    -u, --unit-only           Run only unit tests
    -i, --integration-only    Run only integration tests
    -c, --coverage-only       Run only coverage analysis
    -n, --no-coverage         Skip coverage analysis
    -r, --no-reports          Skip report generation
    -q, --no-quality-gates    Skip quality gate enforcement
    -v, --verbose             Enable verbose output
    -d, --dry-run            Show what would be executed without running
    -h, --help               Show this help message

EXAMPLES:
    $SCRIPT_NAME                    # Run all tests with coverage
    $SCRIPT_NAME --unit-only        # Run only unit tests
    $SCRIPT_NAME --verbose          # Run all tests with verbose output
    $SCRIPT_NAME --dry-run          # Preview test execution plan

CONFIGURATION:
    Test configuration is loaded from test_config.bash
    Coverage target: $OVERALL_COVERAGE_TARGET%
    Required pass rate: $REQUIRED_TEST_PASS_RATE%

EOF
}

# =============================================================================
# Test Discovery Functions
# =============================================================================

# Discover unit test files
discover_unit_tests() {
    local test_files=()
    
    if [[ -d "$TEST_UNIT_DIR" ]]; then
        while IFS= read -r -d '' file; do
            test_files+=("$file")
        done < <(find "$TEST_UNIT_DIR" -name "*.bats" -print0 | sort -z)
    fi
    
    printf '%s\n' "${test_files[@]}"
}

# Discover integration test files
discover_integration_tests() {
    local test_files=()
    
    if [[ -d "$TEST_INTEGRATION_DIR" ]]; then
        while IFS= read -r -d '' file; do
            test_files+=("$file")
        done < <(find "$TEST_INTEGRATION_DIR" -name "*.bats" -print0 | sort -z)
    fi
    
    printf '%s\n' "${test_files[@]}"
}

# Count total tests in files
count_tests_in_files() {
    local files=("$@")
    local total=0
    
    for file in "${files[@]}"; do
        local count=$(grep -c "^@test" "$file" 2>/dev/null || echo 0)
        total=$((total + count))
    done
    
    echo "$total"
}

# =============================================================================
# Test Execution Functions
# =============================================================================

# Run unit tests
run_unit_tests() {
    print_status INFO "Starting unit test execution..."
    
    local unit_test_files
    mapfile -t unit_test_files < <(discover_unit_tests)
    
    if [[ ${#unit_test_files[@]} -eq 0 ]]; then
        print_status WARN "No unit test files found in $TEST_UNIT_DIR"
        return 0
    fi
    
    local total_unit_tests
    total_unit_tests=$(count_tests_in_files "${unit_test_files[@]}")
    print_status INFO "Found $total_unit_tests unit tests in ${#unit_test_files[@]} files"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        for file in "${unit_test_files[@]}"; do
            echo "Would run: bats $file"
        done
        return 0
    fi
    
    local failed_files=()
    local passed_files=()
    
    for file in "${unit_test_files[@]}"; do
        local filename=$(basename "$file")
        print_status INFO "Running unit tests: $filename"
        
        local output_file="$TEST_RESULTS_DIR/unit_${filename%.bats}_$(date +%Y%m%d_%H%M%S).tap"
        
        if timeout "$INDIVIDUAL_TEST_TIMEOUT" bats "$file" > "$output_file" 2>&1; then
            local passed=$(grep -c "^ok " "$output_file" 2>/dev/null || echo 0)
            UNIT_TESTS_PASSED=$((UNIT_TESTS_PASSED + passed))
            passed_files+=("$file")
            print_status PASS "Unit tests passed: $filename ($passed tests)"
        else
            local failed=$(grep -c "^not ok " "$output_file" 2>/dev/null || echo 0)
            UNIT_TESTS_FAILED=$((UNIT_TESTS_FAILED + failed))
            failed_files+=("$file")
            print_status FAIL "Unit tests failed: $filename ($failed tests)"
            
            if [[ "$VERBOSE_MODE" == "true" ]]; then
                echo "--- Failure details for $filename ---"
                cat "$output_file"
                echo "--- End failure details ---"
            fi
        fi
    done
    
    # Summary
    local total_unit_files=${#unit_test_files[@]}
    local passed_unit_files=${#passed_files[@]}
    local failed_unit_files=${#failed_files[@]}
    
    print_status INFO "Unit test summary: $passed_unit_files/$total_unit_files files passed, $UNIT_TESTS_PASSED tests passed, $UNIT_TESTS_FAILED tests failed"
    
    if [[ $failed_unit_files -gt 0 ]]; then
        log_message "ERROR" "Unit tests failed in files: ${failed_files[*]}"
        return 1
    fi
    
    return 0
}

# Run integration tests
run_integration_tests() {
    print_status INFO "Starting integration test execution..."
    
    local integration_test_files
    mapfile -t integration_test_files < <(discover_integration_tests)
    
    if [[ ${#integration_test_files[@]} -eq 0 ]]; then
        print_status WARN "No integration test files found in $TEST_INTEGRATION_DIR"
        return 0
    fi
    
    local total_integration_tests
    total_integration_tests=$(count_tests_in_files "${integration_test_files[@]}")
    print_status INFO "Found $total_integration_tests integration tests in ${#integration_test_files[@]} files"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        for file in "${integration_test_files[@]}"; do
            echo "Would run: bats $file"
        done
        return 0
    fi
    
    local failed_files=()
    local passed_files=()
    
    for file in "${integration_test_files[@]}"; do
        local filename=$(basename "$file")
        print_status INFO "Running integration tests: $filename"
        
        local output_file="$TEST_RESULTS_DIR/integration_${filename%.bats}_$(date +%Y%m%d_%H%M%S).tap"
        
        if timeout "$INDIVIDUAL_TEST_TIMEOUT" bats "$file" > "$output_file" 2>&1; then
            local passed=$(grep -c "^ok " "$output_file" 2>/dev/null || echo 0)
            INTEGRATION_TESTS_PASSED=$((INTEGRATION_TESTS_PASSED + passed))
            passed_files+=("$file")
            print_status PASS "Integration tests passed: $filename ($passed tests)"
        else
            local failed=$(grep -c "^not ok " "$output_file" 2>/dev/null || echo 0)
            INTEGRATION_TESTS_FAILED=$((INTEGRATION_TESTS_FAILED + failed))
            failed_files+=("$file")
            print_status FAIL "Integration tests failed: $filename ($failed tests)"
            
            if [[ "$VERBOSE_MODE" == "true" ]]; then
                echo "--- Failure details for $filename ---"
                cat "$output_file"
                echo "--- End failure details ---"
            fi
        fi
    done
    
    # Summary
    local total_integration_files=${#integration_test_files[@]}
    local passed_integration_files=${#passed_files[@]}
    local failed_integration_files=${#failed_files[@]}
    
    print_status INFO "Integration test summary: $passed_integration_files/$total_integration_files files passed, $INTEGRATION_TESTS_PASSED tests passed, $INTEGRATION_TESTS_FAILED tests failed"
    
    if [[ $failed_integration_files -gt 0 ]]; then
        log_message "ERROR" "Integration tests failed in files: ${failed_files[*]}"
        return 1
    fi
    
    return 0
}

# =============================================================================
# Coverage Analysis Functions
# =============================================================================

# Run coverage analysis
run_coverage_analysis() {
    if [[ "$COVERAGE_TOOL" != "kcov" ]]; then
        print_status WARN "Coverage analysis skipped - kcov not configured"
        return 0
    fi
    
    if ! command -v kcov &> /dev/null; then
        print_status WARN "Coverage analysis skipped - kcov not found"
        return 0
    fi
    
    print_status INFO "Starting coverage analysis with kcov..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "Would run: kcov coverage analysis on shared libraries"
        return 0
    fi
    
    local coverage_dir="$TEST_RESULTS_DIR/$COVERAGE_OUTPUT_DIR"
    mkdir -p "$coverage_dir"
    
    # Run coverage on unit tests
    local unit_test_files
    mapfile -t unit_test_files < <(discover_unit_tests)
    
    for file in "${unit_test_files[@]}"; do
        local filename=$(basename "$file" .bats)
        local file_coverage_dir="$coverage_dir/unit_$filename"
        
        print_status INFO "Collecting coverage for: $filename"
        
        if ! kcov --include-path="$LIB_ROOT_DIR" "$file_coverage_dir" bats "$file" &>/dev/null; then
            print_status WARN "Coverage collection failed for: $filename"
        fi
    done
    
    # Run coverage on integration tests
    local integration_test_files
    mapfile -t integration_test_files < <(discover_integration_tests)
    
    for file in "${integration_test_files[@]}"; do
        local filename=$(basename "$file" .bats)
        local file_coverage_dir="$coverage_dir/integration_$filename"
        
        print_status INFO "Collecting coverage for: $filename"
        
        if ! kcov --include-path="$LIB_ROOT_DIR" "$file_coverage_dir" bats "$file" &>/dev/null; then
            print_status WARN "Coverage collection failed for: $filename"
        fi
    done
    
    # Merge coverage results
    local merged_coverage_dir="$coverage_dir/merged"
    print_status INFO "Merging coverage results..."
    
    if kcov --merge "$merged_coverage_dir" "$coverage_dir"/unit_* "$coverage_dir"/integration_* &>/dev/null; then
        print_status PASS "Coverage analysis completed"
        COVERAGE_REPORT_FILE="$merged_coverage_dir/index.html"
        
        # Extract coverage percentages (simplified)
        if [[ -f "$merged_coverage_dir/kcov-merged/index.json" ]]; then
            # Parse coverage from kcov JSON output (simplified approach)
            ACHIEVED_LINE_COVERAGE=$(grep -o '"covered_lines":[0-9]*' "$merged_coverage_dir/kcov-merged/index.json" | cut -d: -f2 || echo 0)
            local total_lines=$(grep -o '"total_lines":[0-9]*' "$merged_coverage_dir/kcov-merged/index.json" | cut -d: -f2 || echo 1)
            if [[ $total_lines -gt 0 ]]; then
                ACHIEVED_LINE_COVERAGE=$((ACHIEVED_LINE_COVERAGE * 100 / total_lines))
            fi
        fi
        
        print_status INFO "Achieved line coverage: $ACHIEVED_LINE_COVERAGE%"
    else
        print_status FAIL "Coverage analysis failed"
        return 1
    fi
    
    return 0
}

# =============================================================================
# Quality Gate Functions
# =============================================================================

# Enforce quality gates
enforce_quality_gates() {
    print_status INFO "Enforcing quality gates..."
    
    local quality_gate_failures=0
    
    # Test pass rate gate
    TOTAL_TESTS_PASSED=$((UNIT_TESTS_PASSED + INTEGRATION_TESTS_PASSED))
    TOTAL_TESTS_FAILED=$((UNIT_TESTS_FAILED + INTEGRATION_TESTS_FAILED))
    local total_tests=$((TOTAL_TESTS_PASSED + TOTAL_TESTS_FAILED))
    
    if [[ $total_tests -gt 0 ]]; then
        local pass_rate=$((TOTAL_TESTS_PASSED * 100 / total_tests))
        if [[ $pass_rate -lt $REQUIRED_TEST_PASS_RATE ]]; then
            print_status FAIL "Quality gate failed: Test pass rate $pass_rate% < $REQUIRED_TEST_PASS_RATE%"
            ((quality_gate_failures++))
        else
            print_status PASS "Quality gate passed: Test pass rate $pass_rate%"
        fi
    fi
    
    # Coverage gates
    if [[ "$ENFORCE_LINE_COVERAGE" == "true" && $ACHIEVED_LINE_COVERAGE -lt $OVERALL_COVERAGE_TARGET ]]; then
        print_status FAIL "Quality gate failed: Line coverage $ACHIEVED_LINE_COVERAGE% < $OVERALL_COVERAGE_TARGET%"
        ((quality_gate_failures++))
    else
        print_status PASS "Quality gate passed: Line coverage $ACHIEVED_LINE_COVERAGE%"
    fi
    
    # Function export validation
    if [[ "$VALIDATE_FUNCTION_EXPORTS" == "true" ]]; then
        if ! validate_function_exports; then
            print_status FAIL "Quality gate failed: Function export validation"
            ((quality_gate_failures++))
        else
            print_status PASS "Quality gate passed: Function export validation"
        fi
    fi
    
    if [[ $quality_gate_failures -gt 0 ]]; then
        print_status FAIL "Quality gates failed: $quality_gate_failures failures"
        return 1
    else
        print_status PASS "All quality gates passed"
        return 0
    fi
}

# Validate function exports
validate_function_exports() {
    print_status INFO "Validating function exports..."
    
    # Source libraries and check exports
    if ! source "$GCP_COMMON_LIB" &>/dev/null; then
        print_status FAIL "Failed to source gcp_common.sh"
        return 1
    fi
    
    if ! source "$GCP_PERMISSIONS_LIB" &>/dev/null; then
        print_status FAIL "Failed to source gcp_permissions.sh"
        return 1
    fi
    
    # Check expected functions are exported
    local missing_functions=()
    
    for func in "${GCP_COMMON_TEST_FUNCTIONS[@]}"; do
        if ! declare -F "$func" &>/dev/null; then
            missing_functions+=("gcp_common.sh:$func")
        fi
    done
    
    for func in "${GCP_PERMISSIONS_TEST_FUNCTIONS[@]}"; do
        if ! declare -F "$func" &>/dev/null; then
            missing_functions+=("gcp_permissions.sh:$func")
        fi
    done
    
    if [[ ${#missing_functions[@]} -gt 0 ]]; then
        print_status FAIL "Missing function exports: ${missing_functions[*]}"
        return 1
    fi
    
    return 0
}

# =============================================================================
# Report Generation Functions
# =============================================================================

# Generate HTML test report
generate_html_report() {
    print_status INFO "Generating HTML test report..."
    
    local report_file="$TEST_RESULTS_DIR/${REPORT_FILENAME_PREFIX}_$(date +$REPORT_TIMESTAMP_FORMAT).html"
    TEST_REPORT_FILE="$report_file"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>GCP Shared Library Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .pass { color: #28a745; }
        .fail { color: #dc3545; }
        .warn { color: #ffc107; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .metric-card { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .metric-value { font-size: 2em; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
        th { background-color: #f8f9fa; }
    </style>
</head>
<body>
    <div class="header">
        <h1>GCP Shared Library Test Report</h1>
        <p>Generated: $(date)</p>
        <p>Framework: $TEST_FRAMEWORK_NAME v$TEST_FRAMEWORK_VERSION</p>
    </div>

    <div class="section">
        <h2>Test Execution Summary</h2>
        <div class="metrics">
            <div class="metric-card">
                <div class="metric-value pass">$TOTAL_TESTS_PASSED</div>
                <div>Tests Passed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value fail">$TOTAL_TESTS_FAILED</div>
                <div>Tests Failed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$ACHIEVED_LINE_COVERAGE%</div>
                <div>Line Coverage</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$(date -d @$(($(date +%s) - START_TIME)) -u +%H:%M:%S)</div>
                <div>Execution Time</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Test Results</h2>
        <table>
            <tr>
                <th>Test Type</th>
                <th>Passed</th>
                <th>Failed</th>
                <th>Total</th>
                <th>Pass Rate</th>
            </tr>
            <tr>
                <td>Unit Tests</td>
                <td class="pass">$UNIT_TESTS_PASSED</td>
                <td class="fail">$UNIT_TESTS_FAILED</td>
                <td>$((UNIT_TESTS_PASSED + UNIT_TESTS_FAILED))</td>
                <td>$(if [[ $((UNIT_TESTS_PASSED + UNIT_TESTS_FAILED)) -gt 0 ]]; then echo $((UNIT_TESTS_PASSED * 100 / (UNIT_TESTS_PASSED + UNIT_TESTS_FAILED)))%; else echo "N/A"; fi)</td>
            </tr>
            <tr>
                <td>Integration Tests</td>
                <td class="pass">$INTEGRATION_TESTS_PASSED</td>
                <td class="fail">$INTEGRATION_TESTS_FAILED</td>
                <td>$((INTEGRATION_TESTS_PASSED + INTEGRATION_TESTS_FAILED))</td>
                <td>$(if [[ $((INTEGRATION_TESTS_PASSED + INTEGRATION_TESTS_FAILED)) -gt 0 ]]; then echo $((INTEGRATION_TESTS_PASSED * 100 / (INTEGRATION_TESTS_PASSED + INTEGRATION_TESTS_FAILED)))%; else echo "N/A"; fi)</td>
            </tr>
        </table>
    </div>

    <div class="section">
        <h2>Coverage Analysis</h2>
        <p>Target Coverage: $OVERALL_COVERAGE_TARGET%</p>
        <p>Achieved Coverage: $ACHIEVED_LINE_COVERAGE%</p>
        $(if [[ -n "$COVERAGE_REPORT_FILE" ]]; then echo "<p><a href=\"$COVERAGE_REPORT_FILE\">Detailed Coverage Report</a></p>"; fi)
    </div>

    <div class="section">
        <h2>Quality Gates</h2>
        <p>All quality gates status will be displayed here based on execution results.</p>
    </div>
</body>
</html>
EOF

    print_status PASS "HTML report generated: $report_file"
}

# Generate JUnit XML report
generate_junit_report() {
    if [[ "$GENERATE_JUNIT_REPORT" != "true" ]]; then
        return 0
    fi
    
    print_status INFO "Generating JUnit XML report..."
    
    local junit_file="$TEST_RESULTS_DIR/${REPORT_FILENAME_PREFIX}_junit_$(date +$REPORT_TIMESTAMP_FORMAT).xml"
    JUNIT_REPORT_FILE="$junit_file"
    
    local total_tests=$((TOTAL_TESTS_PASSED + TOTAL_TESTS_FAILED))
    local execution_time=$(($(date +%s) - START_TIME))
    
    cat > "$junit_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="GCP Shared Library Tests" tests="$total_tests" failures="$TOTAL_TESTS_FAILED" time="$execution_time">
    <testsuite name="Unit Tests" tests="$((UNIT_TESTS_PASSED + UNIT_TESTS_FAILED))" failures="$UNIT_TESTS_FAILED" time="0">
        <!-- Unit test results would be detailed here -->
    </testsuite>
    <testsuite name="Integration Tests" tests="$((INTEGRATION_TESTS_PASSED + INTEGRATION_TESTS_FAILED))" failures="$INTEGRATION_TESTS_FAILED" time="0">
        <!-- Integration test results would be detailed here -->
    </testsuite>
</testsuites>
EOF

    print_status PASS "JUnit report generated: $junit_file"
}

# =============================================================================
# Main Execution Functions
# =============================================================================

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--unit-only)
                RUN_INTEGRATION_TESTS=false
                shift
                ;;
            -i|--integration-only)
                RUN_UNIT_TESTS=false
                shift
                ;;
            -c|--coverage-only)
                RUN_UNIT_TESTS=false
                RUN_INTEGRATION_TESTS=false
                shift
                ;;
            -n|--no-coverage)
                RUN_COVERAGE_ANALYSIS=false
                shift
                ;;
            -r|--no-reports)
                GENERATE_REPORTS=false
                shift
                ;;
            -q|--no-quality-gates)
                ENFORCE_QUALITY_GATES=false
                shift
                ;;
            -v|--verbose)
                VERBOSE_MODE=true
                TEST_VERBOSE_OUTPUT="true"
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1" >&2
                show_usage
                exit 1
                ;;
        esac
    done
}

# Main execution function
main() {
    # Initialize
    mkdir -p "$TEST_RESULTS_DIR"
    TEST_LOG_FILE="$TEST_RESULTS_DIR/test_execution_$(date +%Y%m%d_%H%M%S).log"
    
    print_colored cyan "=== GCP Shared Library Test Runner ==="
    print_status INFO "Starting test execution at $(date)"
    
    if [[ "$VERBOSE_MODE" == "true" ]]; then
        show_test_config_summary
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_status INFO "DRY RUN MODE - No tests will be executed"
    fi
    
    local exit_code=0
    
    # Run unit tests
    if [[ "$RUN_UNIT_TESTS" == "true" ]]; then
        if ! run_unit_tests; then
            exit_code=1
        fi
    fi
    
    # Run integration tests
    if [[ "$RUN_INTEGRATION_TESTS" == "true" ]]; then
        if ! run_integration_tests; then
            exit_code=1
        fi
    fi
    
    # Run coverage analysis
    if [[ "$RUN_COVERAGE_ANALYSIS" == "true" ]]; then
        if ! run_coverage_analysis; then
            exit_code=1
        fi
    fi
    
    # Enforce quality gates
    if [[ "$ENFORCE_QUALITY_GATES" == "true" && "$DRY_RUN" == "false" ]]; then
        if ! enforce_quality_gates; then
            exit_code=1
        fi
    fi
    
    # Generate reports
    if [[ "$GENERATE_REPORTS" == "true" && "$DRY_RUN" == "false" ]]; then
        generate_html_report
        generate_junit_report
    fi
    
    # Final summary
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    
    print_colored cyan "=== Test Execution Complete ==="
    print_status INFO "Total execution time: ${duration} seconds"
    print_status INFO "Total tests passed: $TOTAL_TESTS_PASSED"
    print_status INFO "Total tests failed: $TOTAL_TESTS_FAILED"
    
    if [[ -n "$TEST_REPORT_FILE" ]]; then
        print_status INFO "HTML report: $TEST_REPORT_FILE"
    fi
    
    if [[ -n "$COVERAGE_REPORT_FILE" ]]; then
        print_status INFO "Coverage report: $COVERAGE_REPORT_FILE"
    fi
    
    if [[ $exit_code -eq 0 ]]; then
        print_status PASS "All tests completed successfully"
    else
        print_status FAIL "Test execution completed with failures"
    fi
    
    exit $exit_code
}

# =============================================================================
# Script Entry Point
# =============================================================================

# Check for required tools
if ! command -v bats &> /dev/null; then
    print_status FAIL "bats testing framework not found. Please install bats-core."
    exit 1
fi

# Parse arguments and run main function
parse_arguments "$@"
main