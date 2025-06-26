# GCP HTML Report Library Documentation

## Overview

The `gcp_html_report.sh` library provides comprehensive HTML report generation capabilities for GCP PCI DSS assessments. It creates interactive, professional-grade HTML reports with collapsible sections, assessment metrics, and responsive design optimized for compliance documentation and audit trails.

## Core Functions

### Report Initialization and Setup

#### `validate_html_params()`
Validates HTML report parameters and environment setup before report generation.
- **Returns:** 0 on success, 1 on validation failure
- **Side Effects:** Sets validation flags for report generation
- **Dependencies:** Requires `gcp_common.sh` for environment validation
- **Example:**
```bash
#!/usr/bin/env bash
source "$(dirname "$0")/lib/gcp_common.sh"
source "$(dirname "$0")/lib/gcp_html_report.sh"

# Validate environment before starting report
if ! validate_html_params; then
    print_status "FAIL" "HTML report parameters validation failed"
    exit 1
fi
```

#### `gather_gcp_metadata()`
Collects GCP environment metadata for report headers and context.
- **Returns:** 0 on success, 1 on metadata collection failure
- **Side Effects:** Populates global metadata variables for report context
- **Dependencies:** Requires active GCP authentication and `gcloud` CLI
- **Example:**
```bash
# Gather GCP metadata before report initialization
if ! gather_gcp_metadata; then
    print_status "WARN" "Could not gather GCP metadata, using defaults"
fi
```

#### `initialize_report(title, assessment_type)`
Initializes HTML report with header, CSS, and basic structure.
- **Parameters:**
  - `title`: Report title string
  - `assessment_type`: Assessment type (project, organization, or custom)
- **Returns:** 0 on success, 1 on initialization failure
- **Side Effects:** Creates HTML file with header, metadata, and navigation structure
- **Dependencies:** Requires `OUTPUT_FILE` environment variable to be set
- **Example:**
```bash
# Initialize a project-scope PCI DSS assessment report
OUTPUT_FILE="pci_requirement1_report.html"
initialize_report "PCI DSS Requirement 1 Assessment" "project"
```

### Content Management

#### `html_append(content)`
Safely appends HTML content to the report file with proper escaping.
- **Parameters:**
  - `content`: HTML content string to append
- **Returns:** 0 on success, 1 on write failure
- **Side Effects:** Appends content to `OUTPUT_FILE`
- **Dependencies:** Requires initialized report file
- **Example:**
```bash
# Add custom HTML content to report
html_append "<p>Custom assessment note: Environment validated successfully.</p>"
```

#### `add_section(section_id, section_title, description)`
Creates a new collapsible section in the HTML report.
- **Parameters:**
  - `section_id`: Unique identifier for the section
  - `section_title`: Display title for the section
  - `description`: Optional description or summary
- **Returns:** 0 on success, 1 on section creation failure
- **Side Effects:** Adds collapsible section with navigation entry
- **Dependencies:** Requires initialized report
- **Example:**
```bash
# Create section for firewall rules assessment
add_section "firewall_rules" "Firewall Rules Analysis" "Assessment of GCP firewall rule configurations"
```

#### `close_section()`
Closes the currently open section in the HTML report.
- **Returns:** 0 on success, 1 on section close failure
- **Side Effects:** Closes current section HTML structure
- **Dependencies:** Requires open section to close
- **Example:**
```bash
# Close the current section after adding all check results
close_section
```

### Assessment Results

#### `add_check_result(check_name, status, details, recommendation)`
Adds an individual assessment check result to the current section.
- **Parameters:**
  - `check_name`: Name of the assessment check
  - `status`: Check status (PASS, FAIL, WARN, INFO, MANUAL)
  - `details`: Detailed check results or findings
  - `recommendation`: Optional remediation recommendation
- **Returns:** 0 on success, 1 on result addition failure
- **Side Effects:** Adds formatted check result with status styling
- **Dependencies:** Requires open section in report
- **Example:**
```bash
# Add a passing firewall check result
add_check_result \
    "Default Network Firewall" \
    "PASS" \
    "Default network has appropriate firewall rules configured" \
    "No action required"

# Add a failing check with recommendation
add_check_result \
    "Insecure SSH Access" \
    "FAIL" \
    "Found firewall rule allowing SSH from 0.0.0.0/0" \
    "Restrict SSH access to specific IP ranges"
```

#### `add_manual_check(check_name, requirement, guidance)`
Adds a manual verification requirement to the current section.
- **Parameters:**
  - `check_name`: Name of the manual check
  - `requirement`: PCI DSS requirement reference
  - `guidance`: Manual verification guidance
- **Returns:** 0 on success, 1 on manual check addition failure
- **Side Effects:** Adds manual check with distinctive styling and guidance
- **Dependencies:** Requires open section in report
- **Example:**
```bash
# Add manual verification requirement
add_manual_check \
    "Network Segmentation Verification" \
    "PCI DSS 1.2.1" \
    "Manually verify that network segmentation isolates cardholder data environment"
```

### Report Metrics and Finalization

#### `add_summary_metrics(total_checks, passed, failed, warnings, manual)`
Adds assessment summary metrics with visual indicators.
- **Parameters:**
  - `total_checks`: Total number of checks performed
  - `passed`: Number of passed checks
  - `failed`: Number of failed checks  
  - `warnings`: Number of warning checks
  - `manual`: Number of manual verification checks
- **Returns:** 0 on success, 1 on metrics addition failure
- **Side Effects:** Adds metrics summary with progress bars and percentages
- **Dependencies:** Requires initialized report
- **Example:**
```bash
# Add summary metrics for the assessment
add_summary_metrics 25 18 3 2 2
```

#### `finalize_report()`
Finalizes HTML report with footer, timestamp, and closes document structure.
- **Returns:** 0 on success, 1 on finalization failure
- **Side Effects:** Closes HTML document, adds footer and navigation functionality
- **Dependencies:** Requires initialized report
- **Example:**
```bash
# Finalize the report after adding all content
if ! finalize_report; then
    print_status "FAIL" "Failed to finalize HTML report"
    exit 1
fi

print_status "PASS" "HTML report generated: $OUTPUT_FILE"
```

### Utility Functions

#### `check_gcp_api_access()`
Validates GCP API access for report metadata collection.
- **Returns:** 0 if API access available, 1 if limited or unavailable
- **Side Effects:** May set API access flags for conditional functionality
- **Dependencies:** Requires GCP authentication setup
- **Example:**
```bash
# Check API access before gathering extensive metadata
if check_gcp_api_access; then
    print_status "INFO" "Full GCP API access available"
else
    print_status "WARN" "Limited API access - some metadata may be unavailable"
fi
```

## Usage Examples

### Complete Report Generation Workflow

```bash
#!/usr/bin/env bash

# Load required libraries
source "$(dirname "$0")/lib/gcp_common.sh"
source "$(dirname "$0")/lib/gcp_html_report.sh"

# Setup environment
setup_environment
parse_common_arguments "$@"

# Set output file
OUTPUT_FILE="pci_requirement1_assessment_$(date +%Y%m%d_%H%M%S).html"

# Validate and initialize
if ! validate_html_params; then
    print_status "FAIL" "HTML report validation failed"
    exit 1
fi

gather_gcp_metadata
initialize_report "PCI DSS Requirement 1 Assessment" "project"

# Create assessment section
add_section "firewall_assessment" "Firewall Configuration Assessment" "Analysis of GCP firewall rules and network security"

# Add check results
add_check_result "Default Network Check" "PASS" "Default network configuration verified" ""
add_check_result "Open Ports Check" "FAIL" "Found ports 22,80,443 open to 0.0.0.0/0" "Restrict source IP ranges"
add_manual_check "Network Segmentation" "PCI DSS 1.2.1" "Verify network segmentation implementation"

# Close section and add metrics
close_section
add_summary_metrics 10 7 2 1 1

# Finalize report
finalize_report
print_status "PASS" "Assessment report generated: $OUTPUT_FILE"
```

### Integration with Scope Management

```bash
#!/usr/bin/env bash

# Load all required libraries
source "$(dirname "$0")/lib/gcp_common.sh"
source "$(dirname "$0")/lib/gcp_scope_mgmt.sh"
source "$(dirname "$0")/lib/gcp_html_report.sh"

# Setup scope and reporting
setup_assessment_scope
OUTPUT_FILE="organization_assessment_$(date +%Y%m%d_%H%M%S).html"

# Initialize report for organization scope
initialize_report "Organization-Wide PCI DSS Assessment" "organization"

# Process each project in scope
projects=$(get_projects_in_scope)
for project in $projects; do
    add_section "project_${project}" "Project: ${project}" "Assessment results for project ${project}"
    
    # Run project-specific checks and add results
    # ... assessment logic ...
    
    close_section
done

# Finalize organization report
finalize_report
```

## CSS Styling and Customization

The HTML report includes embedded CSS for:

- **Responsive Design**: Optimized for desktop and mobile viewing
- **Status Indicators**: Color-coded status badges (PASS=green, FAIL=red, WARN=yellow, etc.)
- **Collapsible Sections**: Interactive section navigation with expand/collapse
- **Progress Bars**: Visual metrics representation with percentage indicators
- **Print Optimization**: Clean printing layout with appropriate page breaks

## Performance Considerations

- **Large Reports**: For organization-scope assessments, consider section chunking for reports >1000 checks
- **Memory Usage**: Each report typically uses 2-5MB memory during generation
- **File Size**: Generated HTML reports typically range 100KB-2MB depending on content
- **Browser Compatibility**: Optimized for modern browsers (Chrome, Firefox, Safari, Edge)

## Error Handling

All functions return standardized exit codes:
- **0**: Success
- **1**: Function-specific error (validation, file I/O, etc.)

Error conditions are logged using the `print_status` function from `gcp_common.sh` for consistent error handling across the framework.

## Cross-Library Integration

### Related Functions Across Libraries

#### Scope-Aware Reporting
- **`initialize_report()`** integrates with **`setup_assessment_scope()`** (gcp_scope_mgmt.sh) for scope-aware report headers
- **`gather_gcp_metadata()`** uses **`get_projects_in_scope()`** (gcp_scope_mgmt.sh) for multi-project metadata collection
- **`add_section()`** works with **`run_across_projects()`** (gcp_scope_mgmt.sh) for project-based report sections

#### Permission-Enhanced Reporting
- **`check_gcp_api_access()`** complements **`check_all_permissions()`** (gcp_permissions.sh) for API availability validation
- **`add_check_result()`** integrates with **`get_permission_coverage()`** (gcp_permissions.sh) for permission-aware status reporting
- **`add_manual_check()`** works with **`prompt_continue_limited()`** (gcp_permissions.sh) for interactive verification flows

#### Framework Integration Points
- **All HTML functions** use **`print_status()`** (gcp_common.sh) for consistent logging and status output
- **Report generation** leverages **`cleanup_temp_files()`** (gcp_common.sh) for resource management
- **Error handling** integrates with **`log_debug()`** (gcp_common.sh) for comprehensive troubleshooting

### Recommended Function Combinations

```bash
# Complete assessment workflow with cross-library integration
source_gcp_libraries                    # gcp_common.sh
setup_environment                       # gcp_common.sh  
parse_common_arguments "$@"             # gcp_common.sh
init_permissions_framework              # gcp_permissions.sh
setup_assessment_scope                  # gcp_scope_mgmt.sh
initialize_report "Assessment" "$SCOPE" # gcp_html_report.sh (this library)
```

## Dependencies

- **gcp_common.sh**: Required for environment setup, logging, and error handling
- **gcp_permissions.sh**: Optional, enhances metadata collection if available
- **gcp_scope_mgmt.sh**: Optional, enables scope-aware reporting and multi-project assessments
- **gcloud CLI**: Required for GCP metadata collection
- **HTML5 Browser**: Required for viewing generated reports

## Security Considerations

- **Output Sanitization**: All dynamic content is properly escaped to prevent HTML injection
- **File Permissions**: Generated HTML files use restrictive permissions (644)
- **Sensitive Data**: No GCP credentials or sensitive configuration data included in reports
- **Audit Trail**: Report generation activities logged through `gcp_common.sh` framework