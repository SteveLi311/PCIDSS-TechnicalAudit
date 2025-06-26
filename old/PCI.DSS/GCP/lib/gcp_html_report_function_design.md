# GCP HTML Report Library Function Design

## Function Signatures (AWS-Compatible)

### Core Report Functions

```bash
# 1. Initialize HTML document structure with GCP metadata
initialize_report() {
    local output_file="$1"        # Report file path
    local report_title="$2"       # "PCI DSS Requirement X Assessment"
    local requirement_number="$3" # "1", "2", etc.
    local project_or_org="$4"     # GCP project ID or org ID (default: $PROJECT_ID)
}

# 2. Add collapsible report sections
add_section() {
    local output_file="$1"        # Report file path
    local section_id="$2"         # Unique section identifier
    local section_title="$3"      # Display title
    local is_active="$4"          # "active" for expanded, empty for collapsed
}

# 3. Add individual assessment results (renamed from add_check_item)
add_check_result() {
    local output_file="$1"        # Report file path
    local status="$2"             # "pass", "fail", "warning", "info"
    local title="$3"              # Check title/description
    local details="$4"            # Detailed results/findings
    local recommendation="$5"     # Optional remediation guidance
}

# 4. Generate summary statistics with progress visualization
add_summary_metrics() {
    local output_file="$1"        # Report file path
    local total_checks="$2"       # Total check count
    local passed_checks="$3"      # Passed check count
    local failed_checks="$4"      # Failed check count
    local warning_checks="$5"     # Warning/manual check count
}

# 5. Complete HTML document with interactive features
finalize_report() {
    local output_file="$1"        # Report file path
    local requirement_number="$2" # PCI DSS requirement number
}
```

### Helper Functions (AWS Compatibility)

```bash
# Safe HTML content appending with error handling
html_append() {
    local output_file="$1"        # Report file path
    local content="$2"            # HTML content to append
}

# Close collapsible section
close_section() {
    local output_file="$1"        # Report file path
}

# GCP API access validation (equivalent to check_command_access)
check_gcp_api_access() {
    local output_file="$1"        # Report file path
    local service="$2"            # GCP service (compute, storage, etc.)
    local operation="$3"          # API operation
    local scope="$4"              # Project or org scope (default: $PROJECT_ID)
}

# Manual verification check warnings
add_manual_check() {
    local output_file="$1"        # Report file path
    local title="$2"              # Check title
    local description="$3"        # Manual check description
    local guidance="$4"           # Guidance for manual verification
}
```

## Key Design Decisions

### 1. AWS Compatibility Maintained
- Function signatures match AWS patterns for easy migration
- Parameter order and naming conventions preserved
- Return codes and error handling patterns consistent

### 2. GCP-Specific Adaptations
- `initialize_report()` instead of `initialize_html_report()` (cleaner naming)
- `add_check_result()` instead of `add_check_item()` (more descriptive)
- `project_or_org` parameter replaces AWS `region` parameter
- `check_gcp_api_access()` replaces `check_command_access()`

### 3. Integration Points
- All functions will use `print_status()` from `gcp_common.sh`
- Respect `$VERBOSE` flag for debug output
- Utilize global variables: `$PROJECT_ID`, `$ORG_ID`, `$OUTPUT_DIR`
- Include permission coverage from `gcp_permissions.sh` when available

### 4. Error Handling Strategy
- Parameter validation for all functions
- Graceful degradation for invalid inputs
- Consistent error message formatting using `print_status()`
- Safe file operations with permission checks

## HTML Structure Design

### Document Structure
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <!-- Responsive meta tags -->
    <!-- GCP-themed title -->
    <!-- Embedded CSS (AWS-compatible with GCP branding) -->
</head>
<body>
    <div class="container">
        <!-- Header with GCP metadata -->
        <!-- Assessment information table -->
        <!-- Summary metrics box -->
        <!-- Collapsible sections for check results -->
        <!-- Footer with timestamp -->
    </div>
    <!-- Interactive JavaScript -->
</body>
</html>
```

### CSS Color Scheme
```css
/* Status Colors (AWS-compatible) */
--pass-color: #4CAF50;    /* Green */
--fail-color: #f44336;    /* Red */
--warning-color: #ff9800; /* Orange */
--info-color: #2196F3;    /* Blue */
--neutral-color: #757575; /* Gray */

/* GCP Brand Colors for accents */
--gcp-blue: #4285f4;      /* Primary */
--gcp-green: #34a853;     /* Success */
--gcp-yellow: #fbbc04;    /* Warning */
--gcp-red: #ea4335;       /* Error */
```

### Interactive Features
- Collapsible sections with expand/collapse indicators
- Click-to-expand detailed failure information
- Progress bars with color-coded compliance percentages
- Responsive design for mobile and print
- Keyboard navigation support

## Integration Requirements

### With gcp_common.sh
- Use `print_status()` for all logging (INFO, PASS, WARN, FAIL)
- Respect `$VERBOSE` flag for detailed output
- Follow established error handling patterns
- Use color variables for terminal output

### With gcp_permissions.sh
- Include permission coverage metrics in summary
- Display permission availability information
- Handle access-denied scenarios gracefully
- Show detailed permission info in verbose mode

## Performance Considerations
- Efficient HTML generation for large reports (100+ checks)
- Minimize DOM manipulation in JavaScript
- Lazy-load detailed failure information
- Optimize CSS for fast rendering