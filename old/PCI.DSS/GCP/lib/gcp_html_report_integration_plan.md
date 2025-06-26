# GCP HTML Report Library Integration Plan

## Integration with gcp_common.sh

### Core Functions to Use

```bash
# 1. Logging and Status Output
print_status(level, message)
# Levels: "INFO", "PASS", "WARN", "FAIL"
# Usage in HTML library:
print_status "INFO" "Generating HTML report for Requirement $requirement_number"
print_status "PASS" "Report generated successfully: $output_file"

# 2. Debug Logging  
log_debug(message)
# Usage for verbose output when VERBOSE=true

# 3. Error Handling
validate_file_permissions(file_path)
# Usage before writing HTML files
```

### Global Variables to Utilize

```bash
# Scope and Project Information
$PROJECT_ID      # Current GCP project ID
$ORG_ID          # Organization ID (if applicable)
$SCOPE_TYPE      # "project" or "organization"
$OUTPUT_DIR      # Base output directory for reports

# Configuration Flags
$VERBOSE         # Enable detailed debug output
$REPORT_ONLY     # Skip interactive prompts

# Color Variables for Terminal Output
$RED, $GREEN, $YELLOW, $BLUE, $CYAN, $NC

# Assessment Tracking
$passed_checks   # Global passed check counter
$failed_checks   # Global failed check counter
```

### Integration Patterns

```bash
# 1. Library Loading Check
if [[ "$GCP_COMMON_LOADED" != "true" ]]; then
    source "$(dirname "${BASH_SOURCE[0]}")/gcp_common.sh" || {
        echo "Error: Failed to load gcp_common.sh" >&2
        exit 1
    }
fi

# 2. Verbose Output Pattern
if [[ "$VERBOSE" == "true" ]]; then
    print_status "INFO" "Including detailed failure information in report"
    log_debug "Writing HTML content to: $output_file"
fi

# 3. File Operations Pattern
validate_file_permissions "$output_file" || {
    print_status "FAIL" "Cannot write to output file: $output_file"
    return 1
}

# 4. Error Handling Pattern
if ! html_append "$output_file" "$content"; then
    print_status "FAIL" "Failed to write report content"
    return 1
fi
```

## Integration with gcp_permissions.sh

### Permission Coverage Integration

```bash
# 1. Check if permissions library is loaded
if [[ "$GCP_PERMISSIONS_LOADED" == "true" ]]; then
    # Include permission metrics in report
    local perm_coverage=$(get_permission_coverage)
    local missing_count="$MISSING_PERMISSIONS_COUNT"
    local available_count="$AVAILABLE_PERMISSIONS_COUNT"
    
    # Add permission coverage section to report
    add_check_result "$output_file" "info" "Permission Coverage" \
        "Assessment ran with ${perm_coverage}% permission coverage (${available_count}/${#REQUIRED_PERMISSIONS[@]} permissions available)" \
        "Ensure all required permissions are available for complete assessment"
fi
```

### Permission Variables to Include

```bash
$PERMISSION_COVERAGE_PERCENTAGE  # Overall permission coverage
$MISSING_PERMISSIONS_COUNT       # Count of missing permissions
$AVAILABLE_PERMISSIONS_COUNT     # Count of available permissions
$REQUIRED_PERMISSIONS[@]         # Array of required permissions
$PERMISSION_RESULTS              # Associative array of permission status
```

### Permission Status Reporting

```bash
# 1. Summary Metrics Enhancement
add_summary_metrics() {
    # ... standard metrics ...
    
    # Add permission coverage if available
    if [[ "$GCP_PERMISSIONS_LOADED" == "true" ]]; then
        local perm_coverage=$(get_permission_coverage)
        local perm_status="info"
        
        if [[ $perm_coverage -lt 70 ]]; then
            perm_status="warning"
        elif [[ $perm_coverage -eq 100 ]]; then
            perm_status="pass"
        fi
        
        add_check_result "$output_file" "$perm_status" "Permission Coverage" \
            "Assessment completed with ${perm_coverage}% permission coverage" \
            "Missing permissions may result in incomplete assessment"
    fi
}

# 2. Detailed Permission Section
add_permission_details() {
    local output_file="$1"
    
    if [[ "$GCP_PERMISSIONS_LOADED" == "true" && "$VERBOSE" == "true" ]]; then
        add_section "$output_file" "permission-details" "Permission Details" ""
        
        for permission in "${REQUIRED_PERMISSIONS[@]}"; do
            local status="${PERMISSION_RESULTS[$permission]:-MISSING}"
            local check_status="fail"
            [[ "$status" == "AVAILABLE" ]] && check_status="pass"
            
            add_check_result "$output_file" "$check_status" "Permission: $permission" \
                "Status: $status" ""
        done
        
        close_section "$output_file"
    fi
}
```

## HTML Report Library Structure

### Library Header Integration

```bash
#!/usr/bin/env bash
# GCP HTML Report Library v1.0
# Description: Modular HTML report generation for GCP PCI DSS assessments
# Integration: Designed for seamless use with gcp_common.sh and gcp_permissions.sh

# =============================================================================
# Library Dependencies and Initialization
# =============================================================================

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly" >&2
    exit 1
fi

# Load required shared libraries
if [[ "$GCP_COMMON_LOADED" != "true" ]]; then
    local common_lib="$(dirname "${BASH_SOURCE[0]}")/gcp_common.sh"
    if [[ -f "$common_lib" ]]; then
        source "$common_lib" || {
            echo "Error: Failed to load gcp_common.sh" >&2
            return 1
        }
    else
        echo "Error: gcp_common.sh not found at: $common_lib" >&2
        return 1
    fi
fi

# Load permissions library (optional)
if [[ "$GCP_PERMISSIONS_LOADED" != "true" ]]; then
    local permissions_lib="$(dirname "${BASH_SOURCE[0]}")/gcp_permissions.sh"
    if [[ -f "$permissions_lib" ]]; then
        source "$permissions_lib" || {
            print_status "WARN" "gcp_permissions.sh could not be loaded"
        }
    fi
fi

# Set library loaded flag
export GCP_HTML_REPORT_LOADED="true"
```

### Error Handling Integration

```bash
# Consistent error handling using gcp_common.sh patterns
validate_html_params() {
    local output_file="$1"
    local required_param="$2"
    local function_name="${3:-unknown_function}"
    
    if [[ -z "$output_file" ]]; then
        print_status "FAIL" "$function_name: Output file parameter is required"
        return 1
    fi
    
    if [[ -z "$required_param" ]]; then
        print_status "FAIL" "$function_name: Required parameter missing"
        return 1
    fi
    
    # Use gcp_common.sh file validation
    local output_dir=$(dirname "$output_file")
    if [[ ! -d "$output_dir" ]]; then
        print_status "INFO" "$function_name: Creating output directory: $output_dir"
        mkdir -p "$output_dir" || {
            print_status "FAIL" "$function_name: Cannot create output directory"
            return 1
        }
    fi
    
    return 0
}

# Safe HTML content appending with gcp_common.sh integration
html_append() {
    local output_file="$1"
    local content="$2"
    
    validate_html_params "$output_file" "$content" "html_append" || return 1
    
    if ! echo "$content" >> "$output_file" 2>/dev/null; then
        print_status "FAIL" "html_append: Failed to write to report file: $output_file"
        return 1
    fi
    
    log_debug "html_append: Successfully wrote content to $output_file"
    return 0
}
```

### Metadata Integration

```bash
# GCP metadata gathering using shared library variables
gather_gcp_metadata() {
    local assessment_date=$(date)
    local gcp_account=$(gcloud config get-value account 2>/dev/null || echo "Unknown")
    local scope_info="$PROJECT_ID"
    local scope_type_display="Project"
    
    # Use shared library scope detection
    if [[ "$SCOPE_TYPE" == "organization" && -n "$ORG_ID" ]]; then
        scope_info="$ORG_ID"
        scope_type_display="Organization"
    fi
    
    # Permission coverage information
    local perm_info=""
    if [[ "$GCP_PERMISSIONS_LOADED" == "true" ]]; then
        local coverage=$(get_permission_coverage)
        perm_info="Permission Coverage: ${coverage}%"
    fi
    
    # Return metadata as JSON-like structure for easy parsing
    cat << EOF
{
    "assessment_date": "$assessment_date",
    "gcp_account": "$gcp_account", 
    "scope": "$scope_info",
    "scope_type": "$scope_type_display",
    "permission_coverage": "$perm_info"
}
EOF
}
```

## Testing Integration Strategy

### Unit Test Integration with Shared Libraries

```bash
# Test setup with library loading
setup() {
    # Load required libraries in test environment
    source "$(dirname "$BATS_TEST_DIRNAME")/lib/gcp_common.sh"
    source "$(dirname "$BATS_TEST_DIRNAME")/lib/gcp_permissions.sh"
    source "$(dirname "$BATS_TEST_DIRNAME")/lib/gcp_html_report.sh"
    
    # Set test environment variables
    export PROJECT_ID="test-project-123"
    export VERBOSE="true"
    export OUTPUT_DIR="/tmp/test_reports"
    
    # Create test output directory
    mkdir -p "$OUTPUT_DIR"
}

# Test teardown
teardown() {
    rm -rf "$OUTPUT_DIR"
}

@test "html_report integrates with gcp_common.sh logging" {
    run initialize_report "$OUTPUT_DIR/test.html" "Test Report" "1" "$PROJECT_ID"
    [ "$status" -eq 0 ]
    
    # Verify gcp_common.sh print_status was used
    [[ "$output" == *"[INFO]"* ]]
}
```

## Performance and Memory Considerations

### Efficient Integration Patterns

```bash
# 1. Lazy loading of permission data
get_permission_info() {
    if [[ "$GCP_PERMISSIONS_LOADED" == "true" && -z "$_CACHED_PERMISSION_INFO" ]]; then
        _CACHED_PERMISSION_INFO=$(get_permission_coverage)
    fi
    echo "${_CACHED_PERMISSION_INFO:-0}"
}

# 2. Conditional verbose output
debug_html_append() {
    local output_file="$1"
    local content="$2"
    
    [[ "$VERBOSE" == "true" ]] && log_debug "Adding HTML content (${#content} chars)"
    html_append "$output_file" "$content"
}

# 3. Bulk operations for efficiency
add_multiple_check_results() {
    local output_file="$1"
    shift
    local check_results=("$@")
    
    print_status "INFO" "Adding ${#check_results[@]} check results to report"
    
    for result in "${check_results[@]}"; do
        # Parse result and add to report
        # Implementation would handle bulk HTML generation
    done
}
```