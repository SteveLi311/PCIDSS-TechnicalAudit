#!/bin/bash

# =============================================================================
# Coverage Helper Functions for GCP Shared Library Testing
# =============================================================================

# Global coverage state
COVERAGE_RESULTS_DIR=""
COVERAGE_SUMMARY_FILE=""
COVERAGE_THRESHOLD_FAILURES=()

# =============================================================================
# Coverage Environment Setup
# =============================================================================

# Initialize coverage environment
initialize_coverage_environment() {
    local base_dir="${1:-$TEST_RESULTS_DIR}"
    
    COVERAGE_RESULTS_DIR="$base_dir/coverage"
    COVERAGE_SUMMARY_FILE="$COVERAGE_RESULTS_DIR/coverage_summary.json"
    
    # Create coverage directories
    mkdir -p "$COVERAGE_RESULTS_DIR"/{individual,merged,reports}
    
    # Check for kcov availability
    if ! command -v kcov &> /dev/null; then
        echo "WARNING: kcov not found - coverage analysis will be skipped" >&2
        return 1
    fi
    
    return 0
}

# Clean up coverage environment
cleanup_coverage_environment() {
    if [[ -n "$COVERAGE_RESULTS_DIR" && -d "$COVERAGE_RESULTS_DIR" ]]; then
        # Keep results but clean temporary files
        find "$COVERAGE_RESULTS_DIR" -name "*.tmp" -delete 2>/dev/null || true
    fi
}

# =============================================================================
# Coverage Data Collection
# =============================================================================

# Collect coverage for a single test file
collect_file_coverage() {
    local test_file="$1"
    local test_type="${2:-unit}"  # unit or integration
    local output_name="${3:-$(basename "$test_file" .bats)}"
    
    if [[ ! -f "$test_file" ]]; then
        echo "ERROR: Test file not found: $test_file" >&2
        return 1
    fi
    
    local coverage_output_dir="$COVERAGE_RESULTS_DIR/individual/${test_type}_${output_name}"
    
    echo "Collecting coverage for: $output_name ($test_type)"
    
    # Run kcov with appropriate options
    if kcov \
        --include-path="$LIB_ROOT_DIR" \
        --exclude-pattern="/usr/,/opt/,/tmp/" \
        --collect-only \
        "$coverage_output_dir" \
        bats "$test_file" &>/dev/null; then
        
        echo "Coverage collected successfully for: $output_name"
        return 0
    else
        echo "WARNING: Coverage collection failed for: $output_name" >&2
        return 1
    fi
}

# Collect coverage for all unit tests
collect_unit_test_coverage() {
    local unit_test_files
    mapfile -t unit_test_files < <(discover_unit_tests)
    
    if [[ ${#unit_test_files[@]} -eq 0 ]]; then
        echo "No unit test files found for coverage collection"
        return 0
    fi
    
    echo "Collecting coverage for ${#unit_test_files[@]} unit test files..."
    
    local failed_collections=0
    for test_file in "${unit_test_files[@]}"; do
        local filename=$(basename "$test_file" .bats)
        if ! collect_file_coverage "$test_file" "unit" "$filename"; then
            ((failed_collections++))
        fi
    done
    
    if [[ $failed_collections -gt 0 ]]; then
        echo "WARNING: $failed_collections unit test coverage collections failed"
    fi
    
    return 0
}

# Collect coverage for all integration tests
collect_integration_test_coverage() {
    local integration_test_files
    mapfile -t integration_test_files < <(discover_integration_tests)
    
    if [[ ${#integration_test_files[@]} -eq 0 ]]; then
        echo "No integration test files found for coverage collection"
        return 0
    fi
    
    echo "Collecting coverage for ${#integration_test_files[@]} integration test files..."
    
    local failed_collections=0
    for test_file in "${integration_test_files[@]}"; do
        local filename=$(basename "$test_file" .bats)
        if ! collect_file_coverage "$test_file" "integration" "$filename"; then
            ((failed_collections++))
        fi
    done
    
    if [[ $failed_collections -gt 0 ]]; then
        echo "WARNING: $failed_collections integration test coverage collections failed"
    fi
    
    return 0
}

# Collect all coverage data
collect_all_coverage() {
    echo "Starting comprehensive coverage collection..."
    
    if ! initialize_coverage_environment; then
        echo "Coverage collection skipped - kcov not available"
        return 1
    fi
    
    # Collect unit test coverage
    collect_unit_test_coverage
    
    # Collect integration test coverage
    collect_integration_test_coverage
    
    echo "Coverage collection completed"
    return 0
}

# =============================================================================
# Coverage Analysis and Merging
# =============================================================================

# Merge coverage results from multiple test runs
merge_coverage_results() {
    local merged_output_dir="$COVERAGE_RESULTS_DIR/merged"
    
    # Find all individual coverage directories
    local coverage_dirs=()
    if [[ -d "$COVERAGE_RESULTS_DIR/individual" ]]; then
        while IFS= read -r -d '' dir; do
            coverage_dirs+=("$dir")
        done < <(find "$COVERAGE_RESULTS_DIR/individual" -mindepth 1 -maxdepth 1 -type d -print0)
    fi
    
    if [[ ${#coverage_dirs[@]} -eq 0 ]]; then
        echo "No coverage data found to merge"
        return 1
    fi
    
    echo "Merging coverage from ${#coverage_dirs[@]} test runs..."
    
    # Run kcov merge
    if kcov --merge "$merged_output_dir" "${coverage_dirs[@]}" &>/dev/null; then
        echo "Coverage merge completed successfully"
        return 0
    else
        echo "ERROR: Coverage merge failed" >&2
        return 1
    fi
}

# Extract coverage metrics from kcov output
extract_coverage_metrics() {
    local coverage_dir="$1"
    local output_file="${2:-$COVERAGE_SUMMARY_FILE}"
    
    if [[ ! -d "$coverage_dir" ]]; then
        echo "ERROR: Coverage directory not found: $coverage_dir" >&2
        return 1
    fi
    
    # Look for kcov index files
    local index_json="$coverage_dir/index.json"
    local index_html="$coverage_dir/index.html"
    
    # Initialize metrics
    local total_lines=0
    local covered_lines=0
    local total_functions=0
    local covered_functions=0
    local coverage_percentage=0
    local function_coverage_percentage=0
    
    # Extract metrics from JSON if available
    if [[ -f "$index_json" ]]; then
        total_lines=$(jq -r '.total_lines // 0' "$index_json" 2>/dev/null || echo 0)
        covered_lines=$(jq -r '.covered_lines // 0' "$index_json" 2>/dev/null || echo 0)
        total_functions=$(jq -r '.total_functions // 0' "$index_json" 2>/dev/null || echo 0)
        covered_functions=$(jq -r '.covered_functions // 0' "$index_json" 2>/dev/null || echo 0)
        
        # Calculate percentages
        if [[ $total_lines -gt 0 ]]; then
            coverage_percentage=$(( covered_lines * 100 / total_lines ))
        fi
        
        if [[ $total_functions -gt 0 ]]; then
            function_coverage_percentage=$(( covered_functions * 100 / total_functions ))
        fi
    elif [[ -f "$index_html" ]]; then
        # Extract from HTML as fallback
        coverage_percentage=$(grep -o '[0-9]\+\.[0-9]\+%' "$index_html" | head -1 | sed 's/%//' || echo 0)
        coverage_percentage=${coverage_percentage%.*}  # Remove decimal part
    fi
    
    # Create summary JSON
    cat > "$output_file" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "coverage_tool": "kcov",
  "line_coverage": {
    "total_lines": $total_lines,
    "covered_lines": $covered_lines,
    "percentage": $coverage_percentage
  },
  "function_coverage": {
    "total_functions": $total_functions,
    "covered_functions": $covered_functions,
    "percentage": $function_coverage_percentage
  },
  "targets": {
    "line_coverage_target": $UNIT_TEST_LINE_COVERAGE_TARGET,
    "function_coverage_target": $UNIT_TEST_FUNCTION_COVERAGE_TARGET,
    "overall_target": $OVERALL_COVERAGE_TARGET
  },
  "status": {
    "line_coverage_met": $(if [[ $coverage_percentage -ge $UNIT_TEST_LINE_COVERAGE_TARGET ]]; then echo true; else echo false; fi),
    "function_coverage_met": $(if [[ $function_coverage_percentage -ge $UNIT_TEST_FUNCTION_COVERAGE_TARGET ]]; then echo true; else echo false; fi),
    "overall_target_met": $(if [[ $coverage_percentage -ge $OVERALL_COVERAGE_TARGET ]]; then echo true; else echo false; fi)
  }
}
EOF
    
    echo "Coverage metrics extracted to: $output_file"
    echo "Line coverage: $coverage_percentage% ($covered_lines/$total_lines)"
    echo "Function coverage: $function_coverage_percentage% ($covered_functions/$total_functions)"
    
    return 0
}

# =============================================================================
# Coverage Reporting
# =============================================================================

# Generate HTML coverage report
generate_coverage_html_report() {
    local merged_coverage_dir="$COVERAGE_RESULTS_DIR/merged"
    local html_report_dir="$COVERAGE_RESULTS_DIR/reports"
    
    if [[ ! -d "$merged_coverage_dir" ]]; then
        echo "No merged coverage data found for HTML report generation"
        return 1
    fi
    
    # Copy kcov HTML output to reports directory
    if [[ -f "$merged_coverage_dir/index.html" ]]; then
        cp -r "$merged_coverage_dir"/* "$html_report_dir/"
        echo "HTML coverage report available at: $html_report_dir/index.html"
        return 0
    else
        echo "ERROR: kcov HTML output not found" >&2
        return 1
    fi
}

# Generate coverage XML report (Cobertura format)
generate_coverage_xml_report() {
    local merged_coverage_dir="$COVERAGE_RESULTS_DIR/merged"
    local xml_report_file="$COVERAGE_RESULTS_DIR/reports/coverage.xml"
    
    if [[ ! -d "$merged_coverage_dir" ]]; then
        echo "No merged coverage data found for XML report generation"
        return 1
    fi
    
    # Look for kcov XML output
    if [[ -f "$merged_coverage_dir/cobertura.xml" ]]; then
        cp "$merged_coverage_dir/cobertura.xml" "$xml_report_file"
        echo "XML coverage report available at: $xml_report_file"
        return 0
    else
        echo "WARNING: kcov XML output not found - generating basic XML report" >&2
        
        # Generate basic XML report from summary data
        if [[ -f "$COVERAGE_SUMMARY_FILE" ]]; then
            generate_basic_xml_report "$xml_report_file"
            return 0
        else
            echo "ERROR: No coverage data available for XML report" >&2
            return 1
        fi
    fi
}

# Generate basic XML report from summary data
generate_basic_xml_report() {
    local output_file="$1"
    
    if [[ ! -f "$COVERAGE_SUMMARY_FILE" ]]; then
        echo "ERROR: Coverage summary file not found" >&2
        return 1
    fi
    
    local line_coverage=$(jq -r '.line_coverage.percentage' "$COVERAGE_SUMMARY_FILE")
    local covered_lines=$(jq -r '.line_coverage.covered_lines' "$COVERAGE_SUMMARY_FILE")
    local total_lines=$(jq -r '.line_coverage.total_lines' "$COVERAGE_SUMMARY_FILE")
    local timestamp=$(jq -r '.timestamp' "$COVERAGE_SUMMARY_FILE")
    
    cat > "$output_file" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<coverage version="1.0" timestamp="$timestamp" lines-valid="$total_lines" lines-covered="$covered_lines" line-rate="$(echo "scale=4; $line_coverage / 100" | bc)">
  <sources>
    <source>$LIB_ROOT_DIR</source>
  </sources>
  <packages>
    <package name="gcp_shared_libraries" line-rate="$(echo "scale=4; $line_coverage / 100" | bc)" complexity="0">
      <classes>
        <class name="gcp_common" filename="$LIB_ROOT_DIR/gcp_common.sh" line-rate="$(echo "scale=4; $line_coverage / 100" | bc)" complexity="0">
          <methods/>
          <lines/>
        </class>
        <class name="gcp_permissions" filename="$LIB_ROOT_DIR/gcp_permissions.sh" line-rate="$(echo "scale=4; $line_coverage / 100" | bc)" complexity="0">
          <methods/>
          <lines/>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
EOF
    
    echo "Basic XML coverage report generated at: $output_file"
    return 0
}

# Generate coverage badge (SVG)
generate_coverage_badge() {
    local badge_file="$COVERAGE_RESULTS_DIR/reports/coverage_badge.svg"
    
    if [[ ! -f "$COVERAGE_SUMMARY_FILE" ]]; then
        echo "No coverage summary available for badge generation"
        return 1
    fi
    
    local coverage_percentage=$(jq -r '.line_coverage.percentage' "$COVERAGE_SUMMARY_FILE")
    local badge_color="red"
    
    # Determine badge color based on coverage
    if [[ $coverage_percentage -ge 90 ]]; then
        badge_color="brightgreen"
    elif [[ $coverage_percentage -ge 80 ]]; then
        badge_color="green"
    elif [[ $coverage_percentage -ge 70 ]]; then
        badge_color="yellow"
    elif [[ $coverage_percentage -ge 60 ]]; then
        badge_color="orange"
    fi
    
    # Generate SVG badge
    cat > "$badge_file" << EOF
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="104" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a">
    <rect width="104" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#a)">
    <path fill="#555" d="M0 0h63v20H0z"/>
    <path fill="$badge_color" d="M63 0h41v20H63z"/>
    <path fill="url(#b)" d="M0 0h104v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110">
    <text x="325" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="530">coverage</text>
    <text x="325" y="140" transform="scale(.1)" textLength="530">coverage</text>
    <text x="825" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="310">${coverage_percentage}%</text>
    <text x="825" y="140" transform="scale(.1)" textLength="310">${coverage_percentage}%</text>
  </g>
</svg>
EOF
    
    echo "Coverage badge generated at: $badge_file"
    return 0
}

# =============================================================================
# Coverage Validation and Quality Gates
# =============================================================================

# Validate coverage against targets
validate_coverage_targets() {
    if [[ ! -f "$COVERAGE_SUMMARY_FILE" ]]; then
        echo "ERROR: Coverage summary not available for validation" >&2
        return 1
    fi
    
    local line_coverage=$(jq -r '.line_coverage.percentage' "$COVERAGE_SUMMARY_FILE")
    local function_coverage=$(jq -r '.function_coverage.percentage' "$COVERAGE_SUMMARY_FILE")
    
    echo "Validating coverage targets..."
    echo "Line coverage: $line_coverage% (target: $UNIT_TEST_LINE_COVERAGE_TARGET%)"
    echo "Function coverage: $function_coverage% (target: $UNIT_TEST_FUNCTION_COVERAGE_TARGET%)"
    
    local validation_failures=0
    COVERAGE_THRESHOLD_FAILURES=()
    
    # Check line coverage
    if [[ $line_coverage -lt $UNIT_TEST_LINE_COVERAGE_TARGET ]]; then
        COVERAGE_THRESHOLD_FAILURES+=("Line coverage $line_coverage% below target $UNIT_TEST_LINE_COVERAGE_TARGET%")
        ((validation_failures++))
    fi
    
    # Check function coverage
    if [[ $function_coverage -lt $UNIT_TEST_FUNCTION_COVERAGE_TARGET ]]; then
        COVERAGE_THRESHOLD_FAILURES+=("Function coverage $function_coverage% below target $UNIT_TEST_FUNCTION_COVERAGE_TARGET%")
        ((validation_failures++))
    fi
    
    # Check overall target
    if [[ $line_coverage -lt $OVERALL_COVERAGE_TARGET ]]; then
        COVERAGE_THRESHOLD_FAILURES+=("Overall coverage $line_coverage% below target $OVERALL_COVERAGE_TARGET%")
        ((validation_failures++))
    fi
    
    if [[ $validation_failures -gt 0 ]]; then
        echo "Coverage validation FAILED with $validation_failures issues:"
        for failure in "${COVERAGE_THRESHOLD_FAILURES[@]}"; do
            echo "  - $failure"
        done
        return 1
    else
        echo "Coverage validation PASSED - all targets met"
        return 0
    fi
}

# Get coverage summary for external use
get_coverage_summary() {
    if [[ -f "$COVERAGE_SUMMARY_FILE" ]]; then
        cat "$COVERAGE_SUMMARY_FILE"
    else
        echo '{"error": "Coverage summary not available"}'
    fi
}

# Get line coverage percentage
get_line_coverage_percentage() {
    if [[ -f "$COVERAGE_SUMMARY_FILE" ]]; then
        jq -r '.line_coverage.percentage' "$COVERAGE_SUMMARY_FILE" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# Get function coverage percentage
get_function_coverage_percentage() {
    if [[ -f "$COVERAGE_SUMMARY_FILE" ]]; then
        jq -r '.function_coverage.percentage' "$COVERAGE_SUMMARY_FILE" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# =============================================================================
# Complete Coverage Workflow
# =============================================================================

# Execute complete coverage analysis workflow
execute_coverage_workflow() {
    echo "Starting complete coverage analysis workflow..."
    
    # Step 1: Initialize coverage environment
    if ! initialize_coverage_environment; then
        echo "Coverage workflow aborted - environment initialization failed"
        return 1
    fi
    
    # Step 2: Collect all coverage data
    if ! collect_all_coverage; then
        echo "Coverage workflow completed with collection errors"
    fi
    
    # Step 3: Merge coverage results
    if ! merge_coverage_results; then
        echo "Coverage workflow failed - merge step failed"
        return 1
    fi
    
    # Step 4: Extract metrics
    if ! extract_coverage_metrics "$COVERAGE_RESULTS_DIR/merged"; then
        echo "Coverage workflow failed - metrics extraction failed"
        return 1
    fi
    
    # Step 5: Generate reports
    generate_coverage_html_report
    generate_coverage_xml_report
    generate_coverage_badge
    
    # Step 6: Validate against targets
    if ! validate_coverage_targets; then
        echo "Coverage workflow completed with validation failures"
        return 1
    fi
    
    echo "Coverage analysis workflow completed successfully"
    return 0
}

# Export all coverage functions
export -f initialize_coverage_environment cleanup_coverage_environment
export -f collect_file_coverage collect_unit_test_coverage collect_integration_test_coverage collect_all_coverage
export -f merge_coverage_results extract_coverage_metrics
export -f generate_coverage_html_report generate_coverage_xml_report generate_basic_xml_report generate_coverage_badge
export -f validate_coverage_targets get_coverage_summary get_line_coverage_percentage get_function_coverage_percentage
export -f execute_coverage_workflow