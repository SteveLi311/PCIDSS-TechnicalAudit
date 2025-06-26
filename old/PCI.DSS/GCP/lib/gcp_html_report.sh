#!/usr/bin/env bash
# =============================================================================
# GCP HTML Report Library v1.0
# =============================================================================
# Description: Modular HTML report generation for GCP PCI DSS assessments
# Integration: Designed for seamless use with gcp_common.sh and gcp_permissions.sh
# Author: PCI DSS Assessment Framework
# Created: 2025-06-06
# Target: ~300 lines, focused and efficient implementation
# =============================================================================

# =============================================================================
# Library Dependencies and Initialization
# =============================================================================

# Global variable to track temp files for cleanup
declare -a HTML_TEMP_FILES

# Cleanup function for temporary files
cleanup_html_temp_files() {
    local temp_file
    for temp_file in "${HTML_TEMP_FILES[@]}"; do
        if [[ -f "$temp_file" ]]; then
            rm -f "$temp_file" 2>/dev/null || true
            log_debug "Cleaned up temporary file: $temp_file"
        fi
    done
    HTML_TEMP_FILES=()
}

# Set up cleanup trap
trap cleanup_html_temp_files EXIT

# Ensure this script is sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Error: This script should be sourced, not executed directly" >&2
    exit 1
fi

# Load required shared libraries
if [[ "$GCP_COMMON_LOADED" != "true" ]]; then
    common_lib="$(dirname "${BASH_SOURCE[0]}")/gcp_common.sh"
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
    permissions_lib="$(dirname "${BASH_SOURCE[0]}")/gcp_permissions.sh"
    if [[ -f "$permissions_lib" ]]; then
        source "$permissions_lib" || {
            print_status "WARN" "gcp_permissions.sh could not be loaded"
        }
    fi
fi

# Set library loaded flag
export GCP_HTML_REPORT_LOADED="true"

# =============================================================================
# HTML Constants and Configuration
# =============================================================================

# HTML color constants (AWS-compatible)
if [[ -z "$HTML_PASS_COLOR" ]]; then
    readonly HTML_PASS_COLOR="#4CAF50"     # Green
    readonly HTML_FAIL_COLOR="#f44336"     # Red  
    readonly HTML_WARN_COLOR="#ff9800"     # Orange
    readonly HTML_INFO_COLOR="#2196F3"     # Blue
    readonly HTML_NEUTRAL_COLOR="#757575"  # Gray
fi

# GCP Brand colors for accents
if [[ -z "$GCP_BLUE" ]]; then
    readonly GCP_BLUE="#4285f4"
    readonly GCP_GREEN="#34a853"
    readonly GCP_YELLOW="#fbbc04"
    readonly GCP_RED="#ea4335"
fi

# =============================================================================
# Helper Functions
# =============================================================================

# Validate HTML function parameters
# Usage: validate_html_params OUTPUT_FILE REQUIRED_PARAM FUNCTION_NAME
# Returns: 0 on success, 1 on error
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
    
    # Validate output directory exists
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

# Safe HTML content appending with error handling
# Usage: html_append OUTPUT_FILE CONTENT
# Returns: 0 on success, 1 on error
html_append() {
    local output_file="$1"
    local content="$2"
    
    if [[ -z "$output_file" ]]; then
        print_status "FAIL" "html_append: Empty output file parameter"
        return 1
    fi
    
    if ! echo "$content" >> "$output_file" 2>/dev/null; then
        print_status "FAIL" "html_append: Failed to write to report file: $output_file"
        return 1
    fi
    
    log_debug "html_append: Successfully wrote content to $output_file"
    return 0
}

# Gather GCP metadata for report header
# Usage: gather_gcp_metadata
# Returns: JSON-like metadata string
gather_gcp_metadata() {
    local assessment_date=$(date)
    local gcp_account=$(gcloud config get-value account 2>/dev/null || echo "Unknown")
    local scope_info="${PROJECT_ID:-Unknown}"
    local scope_type_display="Project"
    
    # Use shared library scope detection
    if [[ "$SCOPE_TYPE" == "organization" && -n "$ORG_ID" ]]; then
        scope_info="$ORG_ID"
        scope_type_display="Organization"
    fi
    
    # Permission coverage information
    local perm_info="Not Available"
    if [[ "$GCP_PERMISSIONS_LOADED" == "true" ]]; then
        local coverage=$(get_permission_coverage 2>/dev/null || echo "0")
        perm_info="${coverage}%"
    fi
    
    echo "$assessment_date|$gcp_account|$scope_info|$scope_type_display|$perm_info"
}

# =============================================================================
# Core Report Functions
# =============================================================================

# Initialize HTML document structure with GCP metadata
# Usage: initialize_report OUTPUT_FILE REPORT_TITLE REQUIREMENT_NUMBER [PROJECT_OR_ORG]
# Returns: 0 on success, 1 on error
initialize_report() {
    local output_file="$1"
    local report_title="$2"
    local requirement_number="$3"
    local project_or_org="${4:-$PROJECT_ID}"
    
    # Parameter validation
    validate_html_params "$output_file" "$report_title" "initialize_report" || return 1
    
    if [[ -z "$requirement_number" ]]; then
        print_status "FAIL" "initialize_report: Requirement number is required"
        return 1
    fi
    
    print_status "INFO" "Initializing HTML report for Requirement $requirement_number"
    
    # Gather GCP-specific metadata
    local metadata=$(gather_gcp_metadata)
    IFS='|' read -r assessment_date gcp_account scope_info scope_type_display perm_coverage <<< "$metadata"
    
    # Generate HTML document with embedded CSS and GCP branding
    local html_content="<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>PCI DSS 4.0 - Requirement $requirement_number Assessment Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 30px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            border-radius: 5px;
        }
        h1 {
            color: #333;
            border-bottom: 2px solid #4285f4;
            padding-bottom: 10px;
            margin-top: 0;
        }
        h2 {
            color: #4285f4;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
            margin-top: 30px;
        }
        h3 {
            color: #555;
            margin-top: 20px;
        }
        .section {
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
        }
        .section-header {
            background-color: #f8f9fa;
            padding: 15px 20px;
            cursor: pointer;
            position: relative;
            border-bottom: 1px solid #dee2e6;
            transition: background-color 0.2s;
        }
        .section-header:hover {
            background-color: #e9ecef;
        }
        .section-header::after {
            content: \"+\";
            position: absolute;
            right: 15px;
            top: 10px;
            font-weight: bold;
        }
        .section-header.active::after {
            content: \"-\";
        }
        .section-content {
            padding: 20px;
            display: none;
            background-color: #ffffff;
        }
        .section-header.active + .section-content {
            display: block !important;
        }
        .check-item {
            border-left: 4px solid #ddd;
            padding: 10px;
            margin-bottom: 10px;
            background-color: #f9f9f9;
        }
        .pass {
            border-left-color: #4CAF50;
        }
        .fail {
            border-left-color: #f44336;
        }
        .warning {
            border-left-color: #ff9800;
        }
        .info {
            border-left-color: #2196F3;
        }
        .green { color: #4CAF50; font-weight: bold; }
        .red { color: #f44336; font-weight: bold; }
        .yellow { color: #ff9800; font-weight: bold; }
        .blue { color: #2196F3; font-weight: bold; }
        .info-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        .info-table th, .info-table td {
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }
        .info-table th {
            background-color: #f0f0f0;
        }
        .summary-box {
            margin-top: 20px;
            padding: 15px;
            background-color: #f0f0f0;
            border-radius: 5px;
        }
        .summary-table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        .summary-table th, .summary-table td {
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }
        .summary-table th {
            background-color: #e0e0e0;
        }
        .progress-container {
            width: 100%;
            background-color: #ddd;
            border-radius: 5px;
            margin-top: 10px;
        }
        .progress-bar {
            height: 25px;
            border-radius: 5px;
            background-color: #4CAF50;
            text-align: center;
            line-height: 25px;
            color: white;
            font-weight: bold;
        }
        .recommendation {
            margin-top: 10px;
            padding: 10px;
            background-color: #f0f8ff;
            border-left: 3px solid #2196F3;
        }
        .timestamp {
            margin-top: 30px;
            font-size: 0.9em;
            color: #666;
            text-align: center;
        }
        details {
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 0.5em 0.5em 0;
            margin-bottom: 15px;
        }
        summary {
            font-weight: bold;
            margin: -0.5em -0.5em 0;
            padding: 0.5em;
            cursor: pointer;
            background-color: #f0f0f0;
        }
        details[open] {
            padding: 0.5em;
        }
        details[open] summary {
            border-bottom: 1px solid #ddd;
            margin-bottom: 0.5em;
        }
        /* Print-friendly styles */
        @media print {
            body { background-color: white; }
            .container { box-shadow: none; padding: 0; }
            .section-content { display: block; }
            .section-header::after { display: none; }
        }
    </style>
</head>
<body>
    <div class=\"container\">
        <h1>$report_title</h1>
        
        <div class=\"info-table-container\">
            <table class=\"info-table\">
                <tr>
                    <th>Assessment Date</th>
                    <td>$assessment_date</td>
                </tr>
                <tr>
                    <th>GCP Account</th>
                    <td>$gcp_account</td>
                </tr>
                <tr>
                    <th>$scope_type_display</th>
                    <td>$scope_info</td>
                </tr>
                <tr>
                    <th>Permission Coverage</th>
                    <td>$perm_coverage</td>
                </tr>
            </table>
        </div>
        
        <!-- Summary will be added after assessment completion -->
        
        <!-- Report content will be added here -->
        <div id=\"report-content\">
"

    # Write initial HTML structure
    if html_append "$output_file" "$html_content"; then
        print_status "PASS" "HTML report initialized: $output_file"
        log_debug "Report title: $report_title"
        log_debug "GCP scope: $scope_type_display ($scope_info)"
        return 0
    else
        return 1
    fi
}

# Create collapsible report sections with navigation
# Usage: add_section OUTPUT_FILE SECTION_ID SECTION_TITLE [IS_ACTIVE]
# Returns: 0 on success, 1 on error
add_section() {
    local output_file="$1"
    local section_id="$2"
    local section_title="$3"
    local is_active="${4:-}"
    
    # Parameter validation
    validate_html_params "$output_file" "$section_id" "add_section" || return 1
    
    if [[ -z "$section_title" ]]; then
        print_status "FAIL" "add_section: Section title is required"
        return 1
    fi
    
    print_status "INFO" "Adding section: $section_title"
    
    # Determine active state for collapsible section
    local active_class=""
    local expanded="false"
    if [[ "$is_active" == "active" ]]; then
        active_class=" active"
        expanded="true"
    fi
    
    # Generate collapsible section HTML - only close previous section if not the first one
    local section_html=""
    
    # Add section closing tag for previous section (except for the very first section)
    if [[ -f "${output_file}.section_count" ]]; then
        section_html+="            </div> <!-- Close previous section content -->
        </div> <!-- Close previous section -->
        
"
    else
        # Create marker file for first section
        echo "1" > "${output_file}.section_count"
        # Register for cleanup
        HTML_TEMP_FILES+=("${output_file}.section_count")
    fi
    
    section_html+="        <div class=\"section\" id=\"section-$section_id\">
            <div class=\"section-header$active_class\" onclick=\"toggleSection('$section_id')\" aria-expanded=\"$expanded\">
                <h3 style=\"margin: 0;\">$section_title</h3>
            </div>
            <div class=\"section-content\" id=\"content-$section_id\">
"
    
    if html_append "$output_file" "$section_html"; then
        print_status "PASS" "Section added: $section_title"
        log_debug "Section ID: $section_id, Active: $is_active"
        return 0
    else
        return 1
    fi
}
# Add individual assessment results with rich formatting
# Usage: add_check_result OUTPUT_FILE STATUS TITLE DETAILS [RECOMMENDATION]
# Returns: 0 on success, 1 on error
add_check_result() {
    local output_file="$1"
    local check_status="$2"
    local title="$3"
    local details="$4"
    local recommendation="${5:-}"
    
    # Parameter validation
    validate_html_params "$output_file" "$check_status" "add_check_result" || return 1
    
    if [[ -z "$title" ]]; then
        print_status "FAIL" "add_check_result: Check title is required"
        return 1
    fi
    
    # Convert status to lowercase and handle common variations
    check_status="${check_status,,}"  # Convert to lowercase
    case "$check_status" in
        "warn")
            check_status="warning"
            ;;
        "manual")
            check_status="warning"
            ;;
    esac
    
    # Status validation
    case "$check_status" in
        "pass"|"fail"|"warning"|"info")
            ;;
        *)
            print_status "FAIL" "add_check_result: Invalid status '$check_status' (must be pass, fail, warning, or info)"
            return 1
            ;;
    esac
    
    print_status "INFO" "Adding check result: $title ($check_status)"
    
    # Status-specific styling and icons
    local status_class="$check_status"
    local status_icon=""
    local status_text=""
    
    case "$check_status" in
        "pass")
            status_icon="✓"
            status_text="PASS"
            ;;
        "fail")
            status_icon="✗"
            status_text="FAIL"
            ;;
        "warning")
            status_icon="⚠"
            status_text="WARNING"
            ;;
        "info")
            status_icon="ℹ"
            status_text="INFO"
            ;;
    esac
    
    # Generate unique ID for collapsible details
    local check_id="check_$(date +%s)_$(( RANDOM % 1000 ))"
    
    # Build check result HTML
    local check_html="                <div class=\"check-item $status_class\">
                    <div style=\"display: flex; justify-content: space-between; align-items: center;\">
                        <strong>$status_icon $title</strong>
                        <span class=\"${status_class:0:1}${status_class:1}\">$status_text</span>
                    </div>
"
    
    # Add details section if provided
    if [[ -n "$details" ]]; then
        check_html="$check_html                    <details style=\"margin-top: 10px;\">
                        <summary>Show Details</summary>
                        <div style=\"margin-top: 10px; padding: 10px; background-color: #f9f9f9; border-radius: 3px;\">
                            <pre style=\"white-space: pre-wrap; margin: 0;\">$details</pre>
                        </div>
                    </details>
"
    fi
    
    # Add recommendation section if provided
    if [[ -n "$recommendation" ]]; then
        check_html="$check_html                    <div class=\"recommendation\">
                        <strong>Recommendation:</strong><br>
                        $recommendation
                    </div>
"
    fi
    
    check_html="$check_html                </div>
"
    
    if html_append "$output_file" "$check_html"; then
        print_status "PASS" "Check result added: $title"
        log_debug "Status: $status, Details: $(echo "$details" | wc -c) chars"
        return 0
    else
        return 1
    fi
}
# Generate visual assessment statistics
# Usage: add_summary_metrics OUTPUT_FILE TOTAL_CHECKS PASSED_CHECKS FAILED_CHECKS WARNING_CHECKS
# Returns: 0 on success, 1 on error
add_summary_metrics() {
    local output_file="$1"
    local total_checks="$2"
    local passed_checks="$3"
    local failed_checks="$4"
    local warning_checks="$5"
    
    # Parameter validation
    validate_html_params "$output_file" "$total_checks" "add_summary_metrics" || return 1
    
    # Numeric validation
    if ! [[ "$total_checks" =~ ^[0-9]+$ ]] || ! [[ "$passed_checks" =~ ^[0-9]+$ ]] || 
       ! [[ "$failed_checks" =~ ^[0-9]+$ ]] || ! [[ "$warning_checks" =~ ^[0-9]+$ ]]; then
        print_status "FAIL" "add_summary_metrics: All check counts must be numeric"
        return 1
    fi
    
    print_status "INFO" "Generating summary metrics: $total_checks total, $passed_checks passed, $failed_checks failed, $warning_checks warnings"
    
    # Calculate compliance percentage (excluding warnings from calculation)
    local assessable_checks=$((passed_checks + failed_checks))
    local compliance_percentage=0
    
    if [[ $assessable_checks -gt 0 ]]; then
        compliance_percentage=$(( (passed_checks * 100) / assessable_checks ))
    fi
    
    # Determine compliance status and color
    local compliance_status="UNKNOWN"
    local compliance_color="#757575"
    
    if [[ $assessable_checks -eq 0 ]]; then
        compliance_status="NO ASSESSABLE CHECKS"
        compliance_color="#757575"
    elif [[ $compliance_percentage -ge 90 ]]; then
        compliance_status="COMPLIANT"
        compliance_color="#4CAF50"
    elif [[ $compliance_percentage -ge 70 ]]; then
        compliance_status="PARTIALLY COMPLIANT"
        compliance_color="#ff9800"
    else
        compliance_status="NON-COMPLIANT"
        compliance_color="#f44336"
    fi
    
    # Permission coverage information
    local perm_info=""
    if [[ "$GCP_PERMISSIONS_LOADED" == "true" ]]; then
        local coverage=$(get_permission_coverage 2>/dev/null || echo "0")
        perm_info="<tr>
                        <td><strong>Permission Coverage</strong></td>
                        <td>${coverage}%</td>
                    </tr>"
    fi
    
    # Generate summary metrics HTML as a standalone section (not collapsible)
    local summary_html="
        
        <div class=\"summary-section\" style=\"margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid $compliance_color;\">
            <h2 style=\"margin-top: 0; color: #333;\">📊 Assessment Summary</h2>
            
            <table class=\"summary-table\">
                <tr>
                    <td><strong>Total Checks</strong></td>
                    <td>$total_checks</td>
                </tr>
                <tr>
                    <td><strong>Passed</strong></td>
                    <td class=\"green\">$passed_checks</td>
                </tr>
                <tr>
                    <td><strong>Failed</strong></td>
                    <td class=\"red\">$failed_checks</td>
                </tr>
                <tr>
                    <td><strong>Warnings/Manual</strong></td>
                    <td class=\"yellow\">$warning_checks</td>
                </tr>
                <tr>
                    <td><strong>Compliance Status</strong></td>
                    <td style=\"color: $compliance_color; font-weight: bold;\">$compliance_status</td>
                </tr>
                $perm_info
            </table>
            
            <div class=\"progress-container\">
                <div class=\"progress-bar\" style=\"width: ${compliance_percentage}%; background-color: $compliance_color;\">
                    ${compliance_percentage}% Compliant
                </div>
            </div>
            
            <p style=\"margin-top: 15px; font-size: 0.9em; color: #666;\">
                <strong>Note:</strong> Compliance percentage calculated based on passed/failed checks only. 
                Warnings require manual verification and are excluded from compliance calculation.
            </p>
        </div>
"
    
    if html_append "$output_file" "$summary_html"; then
        print_status "PASS" "Summary metrics added: $compliance_percentage% compliance"
        log_debug "Assessable checks: $assessable_checks, Compliance: $compliance_status"
        return 0
    else
        return 1
    fi
}
# Complete HTML document with interactive features
# Usage: finalize_report OUTPUT_FILE REQUIREMENT_NUMBER
# Returns: 0 on success, 1 on error
finalize_report() {
    local output_file="$1"
    local requirement_number="$2"
    
    # Parameter validation
    validate_html_params "$output_file" "$requirement_number" "finalize_report" || return 1
    
    print_status "INFO" "Finalizing HTML report for Requirement $requirement_number"
    
    # Get current timestamp
    local finalization_time=$(date)
    
    # Close report content (sections already closed by summary)
    local finalization_html="        </div> <!-- Close report-content -->
        
        <div class=\"timestamp\">
            <p><strong>Report Generated:</strong> $finalization_time</p>
            <p><strong>PCI DSS Version:</strong> 4.0.1</p>
            <p><strong>Requirement:</strong> $requirement_number</p>
        </div>
    </div> <!-- Close container -->
    
    <script>
        // JavaScript for interactive features
        function toggleSection(sectionId) {
            const header = document.querySelector('#section-' + sectionId + ' .section-header');
            const content = document.querySelector('#content-' + sectionId);
            
            if (header && content) {
                const isActive = header.classList.contains('active');
                
                if (isActive) {
                    header.classList.remove('active');
                    content.style.removeProperty('display');
                    header.setAttribute('aria-expanded', 'false');
                } else {
                    header.classList.add('active');
                    content.style.removeProperty('display');
                    header.setAttribute('aria-expanded', 'true');
                }
            }
        }
        
        // Auto-expand sections with failed checks
        document.addEventListener('DOMContentLoaded', function() {
            const failedSections = document.querySelectorAll('.section .fail');
            failedSections.forEach(function(failedCheck) {
                const section = failedCheck.closest('.section');
                if (section) {
                    const header = section.querySelector('.section-header');
                    const content = section.querySelector('.section-content');
                    if (header && content && !header.classList.contains('active')) {
                        header.classList.add('active');
                        content.style.removeProperty('display');
                        header.setAttribute('aria-expanded', 'true');
                    }
                }
            });
            
            // Show print-friendly message
            const style = document.createElement('style');
            style.textContent = '@media print { .no-print { display: none !important; } }';
            document.head.appendChild(style);
        });
        
        // Keyboard navigation support
        document.addEventListener('keydown', function(event) {
            if (event.target.classList.contains('section-header') && (event.key === 'Enter' || event.key === ' ')) {
                event.preventDefault();
                event.target.click();
            }
        });
        
        // Summary metrics are added during report generation
    </script>
</body>
</html>"
    
    if html_append "$output_file" "$finalization_html"; then
        print_status "PASS" "HTML report finalized: $output_file"
        log_debug "Report closed with interactive JavaScript"
        
        # Clean up temporary marker file
        if [[ -f "${output_file}.section_count" ]]; then
            rm -f "${output_file}.section_count"
            # Remove from tracking array
            local temp_file="${output_file}.section_count"
            local new_array=()
            for file in "${HTML_TEMP_FILES[@]}"; do
                [[ "$file" != "$temp_file" ]] && new_array+=("$file")
            done
            HTML_TEMP_FILES=("${new_array[@]}")
        fi
        
        return 0
    else
        return 1
    fi
}
# Close collapsible section
# Usage: close_section OUTPUT_FILE
# Returns: 0 on success, 1 on error
close_section() {
    local output_file="$1"
    
    if [[ -z "$output_file" ]]; then
        print_status "FAIL" "close_section: Output file parameter is required"
        return 1
    fi
    
    print_status "INFO" "Closing current section"
    
    local close_html="            </div> <!-- Close section content -->
        </div> <!-- Close section -->
"
    
    if html_append "$output_file" "$close_html"; then
        print_status "PASS" "Section closed"
        return 0
    else
        return 1
    fi
}

# GCP API access validation (equivalent to AWS check_command_access)
# Usage: check_gcp_api_access OUTPUT_FILE SERVICE OPERATION [SCOPE]
# Returns: 0 on success, 1 on error
check_gcp_api_access() {
    local output_file="$1"
    local service="$2"
    local operation="$3"
    local scope="${4:-$PROJECT_ID}"
    
    # Parameter validation
    validate_html_params "$output_file" "$service" "check_gcp_api_access" || return 1
    
    if [[ -z "$operation" ]]; then
        print_status "FAIL" "check_gcp_api_access: Operation parameter is required"
        return 1
    fi
    
    print_status "INFO" "Checking access to GCP $service $operation..."
    
    # Test basic GCP API connectivity first
    if ! gcloud projects list --limit=1 &>/dev/null; then
        print_status "FAIL" "GCP API connectivity failed"
        add_check_result "$output_file" "fail" "GCP API Access: $service $operation" \
            "Cannot connect to GCP APIs. Check authentication and network connectivity." \
            "Run 'gcloud auth login' and verify network connectivity"
        export GCP_ACCESS_DENIED=1
        return 1
    fi
    
    # Service-specific access testing
    case "$service" in
        "compute")
            if ! gcloud compute zones list --limit=1 &>/dev/null; then
                print_status "FAIL" "GCP Compute Engine API access failed"
                add_check_result "$output_file" "fail" "GCP API Access: $service $operation" \
                    "Cannot access GCP Compute Engine APIs. Check permissions." \
                    "Ensure the assessment account has 'compute.zones.list' permission"
                export GCP_ACCESS_DENIED=1
                return 1
            fi
            ;;
        "iam")
            if ! gcloud iam roles list --limit=1 &>/dev/null; then
                print_status "FAIL" "GCP IAM API access failed"
                add_check_result "$output_file" "fail" "GCP API Access: $service $operation" \
                    "Cannot access GCP IAM APIs. Check permissions." \
                    "Ensure the assessment account has 'iam.roles.list' permission"
                export GCP_ACCESS_DENIED=1
                return 1
            fi
            ;;
        "storage")
            if ! gcloud storage buckets list --limit=1 &>/dev/null; then
                print_status "FAIL" "GCP Cloud Storage API access failed"
                add_check_result "$output_file" "fail" "GCP API Access: $service $operation" \
                    "Cannot access GCP Cloud Storage APIs. Check permissions." \
                    "Ensure the assessment account has 'storage.buckets.list' permission"
                export GCP_ACCESS_DENIED=1
                return 1
            fi
            ;;
    esac
    
    # If we get here, access test passed
    print_status "PASS" "GCP API access verified for $service"
    add_check_result "$output_file" "pass" "GCP API Access: $service $operation" \
        "Successfully verified access to GCP $service APIs." ""
    export GCP_ACCESS_DENIED=0
    return 0
}

# Add manual verification check warnings
# Usage: add_manual_check OUTPUT_FILE TITLE DESCRIPTION [GUIDANCE]
# Returns: 0 on success, 1 on error
add_manual_check() {
    local output_file="$1"
    local title="$2"
    local description="$3"
    local guidance="${4:-This check requires manual verification and cannot be automated. Please review the findings and validate compliance manually.}"
    
    # Parameter validation
    validate_html_params "$output_file" "$title" "add_manual_check" || return 1
    
    if [[ -z "$description" ]]; then
        print_status "FAIL" "add_manual_check: Description parameter is required"
        return 1
    fi
    
    print_status "INFO" "Adding manual check: $title"
    
    # Use add_check_result with warning status for manual checks
    add_check_result "$output_file" "warning" "$title" "$description" "$guidance"
    
    print_status "PASS" "Manual check added: $title"
    return 0
}

# Export all functions for use by scripts
export -f initialize_report add_section add_check_result finalize_report close_section add_manual_check html_append validate_html_params gather_gcp_metadata cleanup_html_temp_files

# Set library loaded flag
export GCP_HTML_REPORT_LOADED="true"
print_status "PASS" "GCP HTML Report Library v1.0 loaded successfully"