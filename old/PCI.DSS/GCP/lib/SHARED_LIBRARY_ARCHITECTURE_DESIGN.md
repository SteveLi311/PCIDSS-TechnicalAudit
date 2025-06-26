# GCP PCI DSS Shared Library Architecture Design

**Document Version:** 1.0  
**Created:** 2025-06-05  
**Task:** T02_S01_DESIGN_SHARED_LIBRARY_ARCHITECTURE  
**Status:** In Development

## Table of Contents

1. [System Architecture Overview](#1-system-architecture-overview)
2. [Module Specifications](#2-module-specifications)
3. [API Reference](#3-api-reference)
4. [Configuration Guide](#4-configuration-guide)
5. [Integration Patterns](#5-integration-patterns)
6. [Migration Guide](#6-migration-guide)
7. [Testing Strategy](#7-testing-strategy)
8. [Error Handling](#8-error-handling)

## 1. System Architecture Overview

### 1.1 Architecture Vision

The GCP PCI DSS Shared Library Architecture transforms the current monolithic script approach into a modular, maintainable, and scalable framework. This architecture achieves:

- **71.6% code reduction** (7,740 → 2,200 lines)
- **83.3% shared code duplication elimination** 
- **60% reduction in maintenance points**
- **Consistent user experience** across all PCI requirements

### 1.2 High-Level Architecture

```
GCP PCI DSS Framework Architecture
├── Shared Libraries (800 lines)
│   ├── lib/gcp_common.sh (200 lines)          # Core utilities & environment
│   ├── lib/gcp_html_report.sh (300 lines)     # HTML report generation
│   ├── lib/gcp_permissions.sh (150 lines)     # Permission management
│   └── lib/gcp_scope_mgmt.sh (150 lines)      # Scope & project handling
├── Configuration Framework (180 lines)
│   └── config/requirement_N.conf (20 lines × 9) # Declarative requirements
├── Assessment Modules (2,700 lines)
│   └── assessments/requirement_N_checks.sh (300 lines × 9) # Extracted logic
└── Simplified Scripts (450 lines)
    └── check_gcp_pci_requirement_N.sh (50 lines × 9) # Orchestration layer
```

### 1.3 Component Relationships

```mermaid
graph TD
    A[check_gcp_pci_requirement_N.sh] --> B[gcp_common.sh]
    A --> C[gcp_permissions.sh]
    A --> D[gcp_scope_mgmt.sh]
    A --> E[gcp_html_report.sh]
    A --> F[requirement_N.conf]
    A --> G[requirement_N_checks.sh]
    
    B --> H[Environment Setup]
    B --> I[CLI Parsing]
    B --> J[Validation]
    
    C --> K[Permission Checking]
    C --> L[Coverage Reporting]
    
    D --> M[Project Enumeration]
    D --> N[Scope Management]
    
    E --> O[Report Generation]
    E --> P[HTML Templates]
    
    F --> Q[Declarative Config]
    G --> R[Assessment Logic]
```

### 1.4 Design Principles

1. **Single Responsibility:** Each module has one clear purpose
2. **Loose Coupling:** Modules interact through well-defined APIs
3. **High Cohesion:** Related functionality grouped together
4. **Configuration-Driven:** Behavior configurable without code changes
5. **Backward Compatibility:** Existing CLI interfaces preserved
6. **Zero Logic Changes:** Assessment logic remains untouched

## 2. Module Specifications

### 2.1 gcp_common.sh - Core Utilities Module

**Purpose:** Provides foundational utilities for environment setup, CLI parsing, and common operations.

**Responsibilities:**
- Environment initialization and color definitions
- Common CLI argument parsing (-s, -p, -o, -h, etc.)
- Prerequisite validation (gcloud, permissions, connectivity)
- Status printing and logging utilities
- Configuration loading framework

**Dependencies:** None (base module)

**Size:** ~200 lines

### 2.2 gcp_html_report.sh - Report Generation Module

**Purpose:** Provides template-based HTML report generation with consistent styling and structure.

**Responsibilities:**
- HTML report initialization and template management
- Dynamic section and content generation
- Standardized check result formatting
- Summary metrics calculation and display
- Report finalization and browser launching

**Dependencies:** gcp_common.sh

**Size:** ~300 lines

### 2.3 gcp_permissions.sh - Permission Management Module

**Purpose:** Manages GCP IAM permission validation and coverage reporting.

**Responsibilities:**
- Declarative permission requirement registration
- Batch permission verification
- Permission coverage calculation and reporting
- User interaction for limited permissions
- Scope-specific permission validation

**Dependencies:** gcp_common.sh

**Size:** ~150 lines

### 2.4 gcp_scope_mgmt.sh - Scope Management Module

**Purpose:** Handles project and organization scope enumeration and command execution.

**Responsibilities:**
- Assessment scope configuration (project vs organization)
- Project enumeration and filtering
- gcloud command construction with proper scoping
- Cross-project command execution and aggregation
- Scope-aware error handling

**Dependencies:** gcp_common.sh, gcp_permissions.sh

**Size:** ~150 lines

## 3. API Reference

### 3.1 gcp_common.sh API

#### 3.1.1 source_gcp_libraries()
**Purpose:** Load all required shared libraries with dependency resolution  
**Signature:** `source_gcp_libraries()`  
**Parameters:** None  
**Returns:** 0 on success, 1 on failure  
**Dependencies:** None

```bash
source_gcp_libraries() {
    # Load libraries in dependency order
    local lib_dir="$(dirname "${BASH_SOURCE[0]}")"
    source "${lib_dir}/gcp_common.sh" || return 1
    source "${lib_dir}/gcp_permissions.sh" || return 1
    source "${lib_dir}/gcp_scope_mgmt.sh" || return 1
    source "${lib_dir}/gcp_html_report.sh" || return 1
    return 0
}
```

#### 3.1.2 setup_environment()
**Purpose:** Initialize colors, variables, and working directories  
**Signature:** `setup_environment()`  
**Parameters:** None  
**Returns:** 0 on success, 1 on failure  
**Side Effects:** Sets global variables for colors, paths, and counters

```bash
setup_environment() {
    # Color definitions for consistent output
    export RED='\033[0;31m'
    export GREEN='\033[0;32m'
    export YELLOW='\033[1;33m'
    export BLUE='\033[0;34m'
    export NC='\033[0m' # No Color
    
    # Initialize counters
    export passed_checks=0
    export failed_checks=0
    export total_projects=0
    
    # Working directories
    export WORK_DIR="/tmp/gcp_pci_assessment_$$"
    mkdir -p "${WORK_DIR}" || return 1
    
    return 0
}
```

#### 3.1.3 parse_common_arguments()
**Purpose:** Parse standard CLI arguments across all requirement scripts  
**Signature:** `parse_common_arguments "$@"`  
**Parameters:** All command line arguments  
**Returns:** 0 on success, 1 on invalid arguments  
**Side Effects:** Sets global variables for scope, output options, and help

```bash
parse_common_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--single-project)
                SCOPE_TYPE="project"
                shift
                ;;
            -p|--project)
                PROJECT_ID="$2"
                SCOPE_TYPE="project"
                shift 2
                ;;
            -o|--organization)
                ORG_ID="$2"
                SCOPE_TYPE="organization"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -r|--report-only)
                REPORT_ONLY="true"
                shift
                ;;
            *)
                echo "Unknown parameter: $1"
                return 1
                ;;
        esac
    done
    return 0
}
```

#### 3.1.4 validate_prerequisites()
**Purpose:** Check gcloud installation, authentication, and basic connectivity  
**Signature:** `validate_prerequisites()`  
**Parameters:** None  
**Returns:** 0 if all prerequisites met, 1 if validation fails

```bash
validate_prerequisites() {
    # Check gcloud installation
    if ! command -v gcloud &> /dev/null; then
        print_status "FAIL" "gcloud CLI not found. Please install Google Cloud SDK."
        return 1
    fi
    
    # Check authentication
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -n1 &> /dev/null; then
        print_status "FAIL" "No active gcloud authentication. Run 'gcloud auth login'."
        return 1
    fi
    
    # Check API connectivity
    if ! gcloud projects list --limit=1 &> /dev/null; then
        print_status "FAIL" "Cannot connect to GCP APIs. Check internet connectivity and permissions."
        return 1
    fi
    
    print_status "PASS" "Prerequisites validation successful"
    return 0
}
```

#### 3.1.5 print_status()
**Purpose:** Print colored status messages with consistent formatting  
**Signature:** `print_status STATUS MESSAGE`  
**Parameters:** 
- STATUS: "PASS", "FAIL", "WARN", "INFO"
- MESSAGE: Text to display  
**Returns:** Always 0

```bash
print_status() {
    local status="$1"
    local message="$2"
    
    case "$status" in
        "PASS")
            echo -e "[${GREEN}✓${NC}] $message"
            ;;
        "FAIL")
            echo -e "[${RED}✗${NC}] $message"
            ;;
        "WARN")
            echo -e "[${YELLOW}!${NC}] $message"
            ;;
        "INFO")
            echo -e "[${BLUE}i${NC}] $message"
            ;;
        *)
            echo -e "[?] $message"
            ;;
    esac
}
```

#### 3.1.6 load_requirement_config()
**Purpose:** Load requirement-specific configuration from config files  
**Signature:** `load_requirement_config REQUIREMENT_NUMBER`  
**Parameters:** REQUIREMENT_NUMBER (1-8)  
**Returns:** 0 on success, 1 if config file not found  
**Side Effects:** Sets requirement-specific global variables

```bash
load_requirement_config() {
    local req_num="$1"
    local config_file="$(dirname "${BASH_SOURCE[0]}")/../config/requirement_${req_num}.conf"
    
    if [[ ! -f "$config_file" ]]; then
        print_status "FAIL" "Configuration file not found: $config_file"
        return 1
    fi
    
    # Source the configuration file
    source "$config_file" || return 1
    
    print_status "INFO" "Loaded configuration for PCI DSS Requirement ${req_num}"
    return 0
}
```

### 3.2 gcp_scope_mgmt.sh API

#### 3.2.1 setup_assessment_scope()
**Purpose:** Configure project or organization scope based on CLI arguments  
**Signature:** `setup_assessment_scope`  
**Parameters:** None (uses global variables set by parse_common_arguments)  
**Returns:** 0 on success, 1 on invalid scope configuration  
**Side Effects:** Sets ASSESSMENT_SCOPE array with project IDs

```bash
setup_assessment_scope() {
    case "$SCOPE_TYPE" in
        "project")
            if [[ -n "$PROJECT_ID" ]]; then
                ASSESSMENT_SCOPE=("$PROJECT_ID")
            else
                # Get current project
                local current_project=$(gcloud config get-value project 2>/dev/null)
                if [[ -z "$current_project" ]]; then
                    print_status "FAIL" "No project specified and no default project set"
                    return 1
                fi
                ASSESSMENT_SCOPE=("$current_project")
            fi
            ;;
        "organization")
            if [[ -z "$ORG_ID" ]]; then
                print_status "FAIL" "Organization ID required for organization scope"
                return 1
            fi
            ASSESSMENT_SCOPE=($(get_projects_in_org "$ORG_ID"))
            ;;
        *)
            print_status "FAIL" "Invalid scope type: $SCOPE_TYPE"
            return 1
            ;;
    esac
    
    print_status "INFO" "Assessment scope: ${#ASSESSMENT_SCOPE[@]} project(s)"
    return 0
}
```

#### 3.2.2 get_projects_in_scope()
**Purpose:** Return array of project IDs within the current assessment scope  
**Signature:** `get_projects_in_scope`  
**Parameters:** None  
**Returns:** 0 on success  
**Output:** Space-separated list of project IDs to stdout

```bash
get_projects_in_scope() {
    printf '%s\n' "${ASSESSMENT_SCOPE[@]}"
}
```

#### 3.2.3 build_gcloud_command()
**Purpose:** Construct gcloud commands with proper project scoping  
**Signature:** `build_gcloud_command PROJECT_ID "BASE_COMMAND"`  
**Parameters:**
- PROJECT_ID: Target project for the command
- BASE_COMMAND: gcloud command without project specification  
**Returns:** 0 on success  
**Output:** Complete gcloud command to stdout

```bash
build_gcloud_command() {
    local project_id="$1"
    local base_command="$2"
    
    echo "gcloud --project=\"$project_id\" $base_command"
}
```

#### 3.2.4 run_across_projects()
**Purpose:** Execute a command across all projects in assessment scope  
**Signature:** `run_across_projects "COMMAND_TEMPLATE"`  
**Parameters:** COMMAND_TEMPLATE with {{PROJECT_ID}} placeholder  
**Returns:** 0 if all commands succeed, 1 if any fail  
**Side Effects:** Executes commands and collects results

```bash
run_across_projects() {
    local command_template="$1"
    local results=()
    local exit_code=0
    
    for project_id in "${ASSESSMENT_SCOPE[@]}"; do
        local command="${command_template//\{\{PROJECT_ID\}\}/$project_id}"
        print_status "INFO" "Executing for project: $project_id"
        
        if eval "$command"; then
            results+=("$project_id:SUCCESS")
        else
            results+=("$project_id:FAILURE")
            exit_code=1
        fi
    done
    
    # Store results for aggregation
    EXECUTION_RESULTS=("${results[@]}")
    return $exit_code
}
```

#### 3.2.5 aggregate_cross_project_data()
**Purpose:** Combine and summarize results from multiple projects  
**Signature:** `aggregate_cross_project_data DATA_FILES_PATTERN`  
**Parameters:** Pattern for data files to aggregate (e.g., "/tmp/*.json")  
**Returns:** 0 on success  
**Output:** Aggregated data to stdout

```bash
aggregate_cross_project_data() {
    local data_pattern="$1"
    local total_resources=0
    local compliant_resources=0
    
    for data_file in $data_pattern; do
        if [[ -f "$data_file" ]]; then
            # Parse and aggregate data (implementation depends on data format)
            local file_total=$(jq '.total_resources // 0' "$data_file" 2>/dev/null || echo 0)
            local file_compliant=$(jq '.compliant_resources // 0' "$data_file" 2>/dev/null || echo 0)
            
            total_resources=$((total_resources + file_total))
            compliant_resources=$((compliant_resources + file_compliant))
        fi
    done
    
    # Output aggregated results
    cat << EOF
{
    "total_projects": ${#ASSESSMENT_SCOPE[@]},
    "total_resources": $total_resources,
    "compliant_resources": $compliant_resources,
    "compliance_percentage": $(( total_resources > 0 ? (compliant_resources * 100) / total_resources : 100 ))
}
EOF
    
    return 0
}
```

### 3.3 gcp_html_report.sh API

#### 3.3.1 initialize_report()
**Purpose:** Set up HTML report structure with template and styling  
**Signature:** `initialize_report REQUIREMENT_NUMBER TITLE`  
**Parameters:**
- REQUIREMENT_NUMBER: PCI DSS requirement number (1-8)
- TITLE: Report title for header  
**Returns:** 0 on success, 1 on failure  
**Side Effects:** Creates HTML file and sets REPORT_FILE global variable

```bash
initialize_report() {
    local req_num="$1"
    local title="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    REPORT_FILE="${WORK_DIR}/pci_req${req_num}_report_$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>$title</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #007cba; }
        .pass { color: #28a745; } .fail { color: #dc3545; } .warn { color: #ffc107; }
        .summary { background: #e9ecef; padding: 15px; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>$title</h1>
        <p><strong>Generated:</strong> $timestamp</p>
        <p><strong>Assessment Scope:</strong> <span id="scope-info">Loading...</span></p>
    </div>
EOF
    
    print_status "INFO" "HTML report initialized: $REPORT_FILE"
    return 0
}
```

#### 3.3.2 add_section()
**Purpose:** Add a new section to the HTML report  
**Signature:** `add_section SECTION_TITLE`  
**Parameters:** SECTION_TITLE: Title for the section  
**Returns:** 0 on success  
**Side Effects:** Appends section HTML to report file

```bash
add_section() {
    local section_title="$1"
    
    cat >> "$REPORT_FILE" << EOF
    <div class="section">
        <h2>$section_title</h2>
        <div class="section-content">
EOF
    
    return 0
}
```

#### 3.3.3 add_check_result()
**Purpose:** Add a standardized check result to the current section  
**Signature:** `add_check_result STATUS CHECK_NAME DESCRIPTION [DETAILS]`  
**Parameters:**
- STATUS: "PASS", "FAIL", "WARN"
- CHECK_NAME: Name of the check
- DESCRIPTION: Brief description of what was checked
- DETAILS: Optional additional details  
**Returns:** 0 on success

```bash
add_check_result() {
    local status="$1"
    local check_name="$2"
    local description="$3"
    local details="${4:-}"
    
    local status_class="${status,,}"  # Convert to lowercase
    local status_icon=""
    
    case "$status" in
        "PASS") status_icon="✓" ;;
        "FAIL") status_icon="✗" ;;
        "WARN") status_icon="!" ;;
    esac
    
    cat >> "$REPORT_FILE" << EOF
        <div class="check-result">
            <h4><span class="$status_class">[$status_icon] $check_name</span></h4>
            <p>$description</p>
EOF
    
    if [[ -n "$details" ]]; then
        cat >> "$REPORT_FILE" << EOF
            <div class="details">
                <pre>$details</pre>
            </div>
EOF
    fi
    
    cat >> "$REPORT_FILE" << EOF
        </div>
EOF
    
    # Update counters
    case "$status" in
        "PASS") ((passed_checks++)) ;;
        "FAIL") ((failed_checks++)) ;;
    esac
    
    return 0
}
```

#### 3.3.4 add_summary_metrics()
**Purpose:** Add summary metrics table to the report  
**Signature:** `add_summary_metrics`  
**Parameters:** None (uses global counters)  
**Returns:** 0 on success

```bash
add_summary_metrics() {
    local total_checks=$((passed_checks + failed_checks))
    local pass_percentage=0
    
    if [[ $total_checks -gt 0 ]]; then
        pass_percentage=$(( (passed_checks * 100) / total_checks ))
    fi
    
    cat >> "$REPORT_FILE" << EOF
        </div>
    </div>
    <div class="summary">
        <h2>Assessment Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Projects Assessed</td><td>${#ASSESSMENT_SCOPE[@]}</td></tr>
            <tr><td>Total Checks Performed</td><td>$total_checks</td></tr>
            <tr><td class="pass">Passed Checks</td><td>$passed_checks</td></tr>
            <tr><td class="fail">Failed Checks</td><td>$failed_checks</td></tr>
            <tr><td>Compliance Percentage</td><td>$pass_percentage%</td></tr>
        </table>
    </div>
EOF
    
    return 0
}
```

#### 3.3.5 finalize_report()
**Purpose:** Complete the HTML report and optionally open in browser  
**Signature:** `finalize_report [OPEN_BROWSER]`  
**Parameters:** OPEN_BROWSER: "true" to open in browser (optional)  
**Returns:** 0 on success

```bash
finalize_report() {
    local open_browser="${1:-false}"
    
    cat >> "$REPORT_FILE" << EOF
</body>
</html>
EOF
    
    # Update scope information
    local scope_info="$SCOPE_TYPE"
    if [[ "$SCOPE_TYPE" == "project" ]]; then
        scope_info="Single Project: ${ASSESSMENT_SCOPE[0]}"
    else
        scope_info="Organization: $ORG_ID (${#ASSESSMENT_SCOPE[@]} projects)"
    fi
    
    # Update the scope info in the HTML
    sed -i.bak "s/<span id=\"scope-info\">Loading...<\/span>/<span id=\"scope-info\">$scope_info<\/span>/" "$REPORT_FILE"
    rm -f "${REPORT_FILE}.bak"
    
    print_status "PASS" "HTML report generated: $REPORT_FILE"
    
    if [[ "$open_browser" == "true" ]] && command -v open &> /dev/null; then
        open "$REPORT_FILE"
        print_status "INFO" "Report opened in browser"
    fi
    
    return 0
}
```

### 3.4 gcp_permissions.sh API

#### 3.4.1 register_required_permissions()
**Purpose:** Register API permissions required for a specific requirement  
**Signature:** `register_required_permissions REQUIREMENT_NUMBER PERMISSIONS_ARRAY`  
**Parameters:**
- REQUIREMENT_NUMBER: PCI DSS requirement number (1-8)
- PERMISSIONS_ARRAY: Array of required GCP IAM permissions  
**Returns:** 0 on success  
**Side Effects:** Populates REQUIRED_PERMISSIONS global array

```bash
register_required_permissions() {
    local req_num="$1"
    shift
    local permissions=("$@")
    
    REQUIRED_PERMISSIONS=("${permissions[@]}")
    
    print_status "INFO" "Registered ${#REQUIRED_PERMISSIONS[@]} required permissions for Requirement $req_num"
    return 0
}
```

#### 3.4.2 check_all_permissions()
**Purpose:** Check all registered permissions against current user/service account  
**Signature:** `check_all_permissions`  
**Parameters:** None (uses REQUIRED_PERMISSIONS array)  
**Returns:** 0 if all permissions available, 1 if any missing  
**Side Effects:** Populates PERMISSION_RESULTS associative array

```bash
check_all_permissions() {
    declare -gA PERMISSION_RESULTS
    local missing_count=0
    
    print_status "INFO" "Checking ${#REQUIRED_PERMISSIONS[@]} required permissions..."
    
    for permission in "${REQUIRED_PERMISSIONS[@]}"; do
        if check_single_permission "$permission"; then
            PERMISSION_RESULTS["$permission"]="AVAILABLE"
        else
            PERMISSION_RESULTS["$permission"]="MISSING"
            ((missing_count++))
        fi
    done
    
    if [[ $missing_count -eq 0 ]]; then
        print_status "PASS" "All required permissions are available"
        return 0
    else
        print_status "WARN" "$missing_count permissions are missing"
        return 1
    fi
}
```

#### 3.4.3 get_permission_coverage()
**Purpose:** Calculate percentage of available permissions  
**Signature:** `get_permission_coverage`  
**Parameters:** None  
**Returns:** 0 on success  
**Output:** Coverage percentage to stdout

```bash
get_permission_coverage() {
    local total_permissions=${#REQUIRED_PERMISSIONS[@]}
    local available_count=0
    
    for permission in "${REQUIRED_PERMISSIONS[@]}"; do
        if [[ "${PERMISSION_RESULTS[$permission]}" == "AVAILABLE" ]]; then
            ((available_count++))
        fi
    done
    
    local coverage_percentage=0
    if [[ $total_permissions -gt 0 ]]; then
        coverage_percentage=$(( (available_count * 100) / total_permissions ))
    fi
    
    echo $coverage_percentage
    return 0
}
```

#### 3.4.4 prompt_continue_limited()
**Purpose:** Prompt user to continue with limited permissions  
**Signature:** `prompt_continue_limited`  
**Parameters:** None  
**Returns:** 0 if user chooses to continue, 1 if user chooses to abort

```bash
prompt_continue_limited() {
    local coverage=$(get_permission_coverage)
    
    echo
    print_status "WARN" "Limited permissions detected ($coverage% coverage)"
    echo "Some checks may be skipped or incomplete."
    echo
    read -p "Continue with limited permissions? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "INFO" "Continuing with limited permissions"
        return 0
    else
        print_status "INFO" "Assessment aborted by user"
        return 1
    fi
}
```

#### 3.4.5 validate_scope_permissions()
**Purpose:** Validate permissions for current assessment scope  
**Signature:** `validate_scope_permissions`  
**Parameters:** None (uses ASSESSMENT_SCOPE array)  
**Returns:** 0 if scope permissions valid, 1 if invalid

```bash
validate_scope_permissions() {
    print_status "INFO" "Validating scope permissions for ${#ASSESSMENT_SCOPE[@]} project(s)"
    
    for project_id in "${ASSESSMENT_SCOPE[@]}"; do
        # Check basic project access
        if ! gcloud projects describe "$project_id" &> /dev/null; then
            print_status "FAIL" "Cannot access project: $project_id"
            return 1
        fi
        
        # Check if we can list resources in the project
        if ! gcloud compute instances list --project="$project_id" --limit=1 &> /dev/null; then
            print_status "WARN" "Limited access to project: $project_id"
        fi
    done
    
    print_status "PASS" "Scope permission validation completed"
    return 0
}
```

## 4. Configuration Guide

*[This section will be populated when we design the configuration framework]*

## 5. Integration Patterns

*[This section will be populated when we design integration approaches]*

## 6. Migration Guide

*[This section will be populated when we plan the migration strategy]*

## 7. Testing Strategy

*[This section will be populated when we design testing approaches]*

## 4. Configuration Guide

### 4.1 Configuration File Structure

The configuration framework provides declarative, customizable assessment behavior through standardized configuration files. Each PCI DSS requirement has a dedicated configuration file that controls assessment behavior, validation thresholds, and reporting options.

#### 4.1.1 Configuration File Format Specification

**File Naming Convention:** `config/requirement_N.conf` where N is the requirement number (1-8)

**File Structure Standard:**
```bash
#!/bin/bash
# Configuration file for PCI DSS Requirement N
# Auto-generated from template on: YYYY-MM-DD

#===============================================================================
# SECTION 1: REQUIREMENT METADATA
#===============================================================================
REQUIREMENT_NUMBER="N"
REQUIREMENT_TITLE="[Title from PCI DSS v4.0.1]"
REQUIREMENT_DESCRIPTION="[Description from PCI DSS v4.0.1]"
VERSION="1.0"
LAST_UPDATED="YYYY-MM-DD"

#===============================================================================
# SECTION 2: GCP API REQUIREMENTS
#===============================================================================
REQUIRED_PERMISSIONS=(
    # List of GCP IAM permissions required for this requirement
    # Format: "service.resource.action"
)

OPTIONAL_PERMISSIONS=(
    # Permissions that enhance assessment but are not required
)

#===============================================================================
# SECTION 3: ASSESSMENT BEHAVIOR CONFIGURATION
#===============================================================================
# Check enablement flags
CHECK_[SPECIFIC_FEATURE]="true|false"

# Compliance thresholds (0-100)
MIN_COMPLIANCE_PERCENTAGE=80
CRITICAL_FINDING_THRESHOLD=1

# Timeout configurations (seconds)
API_TIMEOUT=300
ASSESSMENT_TIMEOUT=1800

#===============================================================================
# SECTION 4: ORGANIZATION-SPECIFIC CUSTOMIZATIONS
#===============================================================================
# Denied/Allowed lists customizable per organization
DENIED_PROTOCOLS=()
DENIED_PORTS=()
ALLOWED_EXCEPTIONS=()

# Organization policies
REQUIRE_[SPECIFIC_POLICY]="true|false"

#===============================================================================
# SECTION 5: REPORT CONFIGURATION
#===============================================================================
INCLUDE_TECHNICAL_DETAILS="true"
INCLUDE_REMEDIATION_GUIDANCE="true"
REPORT_SECTIONS=("section1" "section2" "...")
OUTPUT_FORMAT="html"  # html, json, csv
REPORT_LEVEL="detailed"  # summary, detailed, technical
```

#### 4.1.2 Complete Configuration Examples

**requirement_1.conf - Network Security Controls:**
```bash
#!/bin/bash
# PCI DSS Requirement 1: Install and maintain network security controls

#===============================================================================
# SECTION 1: REQUIREMENT METADATA
#===============================================================================
REQUIREMENT_NUMBER="1"
REQUIREMENT_TITLE="Install and maintain network security controls"
REQUIREMENT_DESCRIPTION="Firewalls and routers are key components of the architecture that controls entry to and exit from the network"
VERSION="1.0"
LAST_UPDATED="2025-06-05"

#===============================================================================
# SECTION 2: GCP API REQUIREMENTS
#===============================================================================
REQUIRED_PERMISSIONS=(
    "compute.instances.list"
    "compute.firewalls.list"
    "compute.networks.list"
    "compute.subnetworks.list"
    "compute.routers.list"
    "compute.vpnTunnels.list"
    "compute.interconnects.list"
    "compute.securityPolicies.list"
    "servicenetworking.services.list"
)

OPTIONAL_PERMISSIONS=(
    "compute.urlMaps.list"
    "compute.backendServices.list"
    "dns.policies.list"
)

#===============================================================================
# SECTION 3: ASSESSMENT BEHAVIOR CONFIGURATION
#===============================================================================
CHECK_FIREWALL_RULES="true"
CHECK_VPC_FLOW_LOGS="true"
CHECK_NETWORK_SEGMENTATION="true"
CHECK_DENIED_PROTOCOLS="true"
CHECK_DEFAULT_FIREWALL_RULES="true"
CHECK_EGRESS_FILTERING="true"

MIN_COMPLIANCE_PERCENTAGE=85
CRITICAL_FINDING_THRESHOLD=0
API_TIMEOUT=300
ASSESSMENT_TIMEOUT=1800

#===============================================================================
# SECTION 4: ORGANIZATION-SPECIFIC CUSTOMIZATIONS
#===============================================================================
DENIED_PROTOCOLS=("telnet" "ftp" "rsh" "rlogin" "tftp")
DENIED_PORTS=("23" "21" "514" "513" "69")
ALLOWED_ADMIN_PROTOCOLS=("ssh" "https")
ALLOWED_ADMIN_PORTS=("22" "443")

REQUIRE_FULL_FIREWALL_COVERAGE="true"
REQUIRE_EGRESS_FILTERING="true"
ALLOW_INTERNAL_EXCEPTIONS="false"

#===============================================================================
# SECTION 5: REPORT CONFIGURATION
#===============================================================================
INCLUDE_TECHNICAL_DETAILS="true"
INCLUDE_REMEDIATION_GUIDANCE="true"
REPORT_SECTIONS=("firewall_analysis" "network_topology" "flow_logs" "recommendations" "policy_review")
OUTPUT_FORMAT="html"
REPORT_LEVEL="detailed"
```

**requirement_2.conf - Secure System Configurations:**
```bash
#!/bin/bash
# PCI DSS Requirement 2: Apply secure configurations to all system components

#===============================================================================
# SECTION 1: REQUIREMENT METADATA
#===============================================================================
REQUIREMENT_NUMBER="2"
REQUIREMENT_TITLE="Apply secure configurations to all system components"
REQUIREMENT_DESCRIPTION="Malicious individuals, both external and internal to a company, often use vendor default passwords and other vendor default settings to compromise systems"
VERSION="1.0"
LAST_UPDATED="2025-06-05"

#===============================================================================
# SECTION 2: GCP API REQUIREMENTS
#===============================================================================
REQUIRED_PERMISSIONS=(
    "compute.instances.list"
    "compute.images.list"
    "compute.instanceTemplates.list"
    "compute.machineTypes.list"
    "iam.serviceAccounts.list"
    "cloudsql.instances.list"
    "container.clusters.list"
    "appengine.applications.get"
)

OPTIONAL_PERMISSIONS=(
    "compute.instanceGroups.list"
    "run.services.list"
    "functions.functions.list"
)

#===============================================================================
# SECTION 3: ASSESSMENT BEHAVIOR CONFIGURATION
#===============================================================================
CHECK_DEFAULT_CREDENTIALS="true"
CHECK_UNNECESSARY_SERVICES="true"
CHECK_SECURITY_PARAMETERS="true"
CHECK_ENCRYPTION_CONFIGURATION="true"
CHECK_PATCH_LEVELS="true"

MIN_COMPLIANCE_PERCENTAGE=90
CRITICAL_FINDING_THRESHOLD=0
API_TIMEOUT=300
ASSESSMENT_TIMEOUT=2400

#===============================================================================
# SECTION 4: ORGANIZATION-SPECIFIC CUSTOMIZATIONS
#===============================================================================
ALLOWED_SYSTEM_ACCOUNTS=("gce-service-account@.*\.gserviceaccount\.com")
REQUIRED_ENCRYPTION_ALGORITHMS=("AES-256" "RSA-2048")
DENIED_ENCRYPTION_ALGORITHMS=("DES" "MD5" "SHA1")

REQUIRE_HARDENED_IMAGES="true"
REQUIRE_SERVICE_ACCOUNT_KEYS_ROTATION="true"
MAX_KEY_AGE_DAYS=90

#===============================================================================
# SECTION 5: REPORT CONFIGURATION
#===============================================================================
INCLUDE_TECHNICAL_DETAILS="true"
INCLUDE_REMEDIATION_GUIDANCE="true"
REPORT_SECTIONS=("system_inventory" "configuration_analysis" "credential_review" "encryption_status" "recommendations")
OUTPUT_FORMAT="html"
REPORT_LEVEL="detailed"
```

### 4.2 Configuration Template System

#### 4.2.1 Template-Based Generation Framework

The template system enables automated generation of requirement-specific configurations:

**Template Structure:** `config/templates/requirement_template.conf`
```bash
#!/bin/bash
# Template for PCI DSS Requirement Configuration Files
# Variables in {{VARIABLE}} format are replaced during generation

#===============================================================================
# SECTION 1: REQUIREMENT METADATA
#===============================================================================
REQUIREMENT_NUMBER="{{REQUIREMENT_NUMBER}}"
REQUIREMENT_TITLE="{{REQUIREMENT_TITLE}}"
REQUIREMENT_DESCRIPTION="{{REQUIREMENT_DESCRIPTION}}"
VERSION="{{VERSION}}"
LAST_UPDATED="{{GENERATION_DATE}}"

#===============================================================================
# SECTION 2: GCP API REQUIREMENTS
#===============================================================================
REQUIRED_PERMISSIONS=(
{{#REQUIRED_PERMISSIONS}}
    "{{.}}"
{{/REQUIRED_PERMISSIONS}}
)

{{#HAS_OPTIONAL_PERMISSIONS}}
OPTIONAL_PERMISSIONS=(
{{#OPTIONAL_PERMISSIONS}}
    "{{.}}"
{{/OPTIONAL_PERMISSIONS}}
)
{{/HAS_OPTIONAL_PERMISSIONS}}

#===============================================================================
# SECTION 3: ASSESSMENT BEHAVIOR CONFIGURATION
#===============================================================================
{{#CHECK_FLAGS}}
{{NAME}}="{{DEFAULT_VALUE}}"
{{/CHECK_FLAGS}}

MIN_COMPLIANCE_PERCENTAGE={{MIN_COMPLIANCE_PERCENTAGE}}
CRITICAL_FINDING_THRESHOLD={{CRITICAL_FINDING_THRESHOLD}}
API_TIMEOUT={{API_TIMEOUT}}
ASSESSMENT_TIMEOUT={{ASSESSMENT_TIMEOUT}}

#===============================================================================
# SECTION 4: ORGANIZATION-SPECIFIC CUSTOMIZATIONS
#===============================================================================
{{#CUSTOMIZATION_ARRAYS}}
{{NAME}}=({{#VALUES}}"{{.}}"{{^LAST}} {{/LAST}}{{/VALUES}})
{{/CUSTOMIZATION_ARRAYS}}

{{#POLICY_FLAGS}}
{{NAME}}="{{DEFAULT_VALUE}}"
{{/POLICY_FLAGS}}

#===============================================================================
# SECTION 5: REPORT CONFIGURATION
#===============================================================================
INCLUDE_TECHNICAL_DETAILS="{{INCLUDE_TECHNICAL_DETAILS}}"
INCLUDE_REMEDIATION_GUIDANCE="{{INCLUDE_REMEDIATION_GUIDANCE}}"
REPORT_SECTIONS=({{#REPORT_SECTIONS}}"{{.}}"{{^LAST}} {{/LAST}}{{/REPORT_SECTIONS}})
OUTPUT_FORMAT="{{OUTPUT_FORMAT}}"
REPORT_LEVEL="{{REPORT_LEVEL}}"
```

#### 4.2.2 Template Generation Specification

**Generation Data Format:** `config/generation_data/requirement_N.json`
```json
{
  "requirement_number": "1",
  "requirement_title": "Install and maintain network security controls",
  "requirement_description": "Firewalls and routers are key components...",
  "version": "1.0",
  "required_permissions": [
    "compute.instances.list",
    "compute.firewalls.list"
  ],
  "optional_permissions": [
    "compute.urlMaps.list"
  ],
  "check_flags": [
    {"name": "CHECK_FIREWALL_RULES", "default_value": "true"},
    {"name": "CHECK_VPC_FLOW_LOGS", "default_value": "true"}
  ],
  "min_compliance_percentage": 85,
  "critical_finding_threshold": 0,
  "api_timeout": 300,
  "assessment_timeout": 1800,
  "customization_arrays": [
    {"name": "DENIED_PROTOCOLS", "values": ["telnet", "ftp", "rsh"]},
    {"name": "DENIED_PORTS", "values": ["23", "21", "514"]}
  ],
  "policy_flags": [
    {"name": "REQUIRE_FULL_FIREWALL_COVERAGE", "default_value": "true"}
  ],
  "include_technical_details": "true",
  "include_remediation_guidance": "true",
  "report_sections": ["firewall_analysis", "network_topology", "flow_logs"],
  "output_format": "html",
  "report_level": "detailed"
}
```

### 4.3 Configuration Loading and Validation

#### 4.3.1 Configuration Loading Process

```bash
load_requirement_config() {
    local req_num="$1"
    local config_file="$(dirname "${BASH_SOURCE[0]}")/../config/requirement_${req_num}.conf"
    
    # Validate configuration file exists
    if [[ ! -f "$config_file" ]]; then
        handle_error 5 "Configuration file not found: $config_file" \
                     "Run: generate_config.sh $req_num"
        return 1
    fi
    
    # Validate configuration file format
    if ! validate_config_format "$config_file"; then
        handle_error 5 "Invalid configuration file format: $config_file" \
                     "Regenerate configuration file or fix formatting errors"
        return 1
    fi
    
    # Source the configuration file
    source "$config_file" || {
        handle_error 5 "Failed to load configuration: $config_file" \
                     "Check configuration file for syntax errors"
        return 1
    }
    
    # Validate required variables are set
    if ! validate_required_config_vars "$req_num"; then
        handle_error 5 "Missing required configuration variables" \
                     "Check configuration file completeness"
        return 1
    fi
    
    # Apply environment variable overrides
    apply_config_overrides "$req_num"
    
    # Set default values for optional variables
    set_config_defaults "$req_num"
    
    log_info "Loaded configuration for PCI DSS Requirement ${req_num}"
    return 0
}
```

#### 4.3.2 Configuration Validation Framework

```bash
validate_config_format() {
    local config_file="$1"
    
    # Check required sections exist
    local required_sections=(
        "SECTION 1: REQUIREMENT METADATA"
        "SECTION 2: GCP API REQUIREMENTS" 
        "SECTION 3: ASSESSMENT BEHAVIOR CONFIGURATION"
        "SECTION 4: ORGANIZATION-SPECIFIC CUSTOMIZATIONS"
        "SECTION 5: REPORT CONFIGURATION"
    )
    
    for section in "${required_sections[@]}"; do
        if ! grep -q "$section" "$config_file"; then
            log_error "Missing required section: $section"
            return 1
        fi
    done
    
    # Validate bash syntax
    if ! bash -n "$config_file"; then
        log_error "Configuration file has syntax errors"
        return 1
    fi
    
    return 0
}

validate_required_config_vars() {
    local req_num="$1"
    local required_vars=(
        "REQUIREMENT_NUMBER"
        "REQUIREMENT_TITLE"
        "REQUIRED_PERMISSIONS"
        "MIN_COMPLIANCE_PERCENTAGE"
        "OUTPUT_FORMAT"
    )
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            log_error "Required configuration variable not set: $var"
            return 1
        fi
    done
    
    # Validate requirement number matches
    if [[ "$REQUIREMENT_NUMBER" != "$req_num" ]]; then
        log_error "Configuration requirement number mismatch: expected $req_num, got $REQUIREMENT_NUMBER"
        return 1
    fi
    
    return 0
}
```

### 4.4 Environment Variable Overrides

Organizations can override configuration values using environment variables:

```bash
# Override format: GCP_PCI_REQ[N]_[VARIABLE_NAME]
export GCP_PCI_REQ1_MIN_COMPLIANCE_PERCENTAGE=95
export GCP_PCI_REQ1_INCLUDE_TECHNICAL_DETAILS=false
export GCP_PCI_REQ2_API_TIMEOUT=600

apply_config_overrides() {
    local req_num="$1"
    local override_prefix="GCP_PCI_REQ${req_num}_"
    
    # Get all environment variables with the override prefix
    while IFS='=' read -r name value; do
        if [[ "$name" =~ ^${override_prefix}(.+)$ ]]; then
            local var_name="${BASH_REMATCH[1]}"
            log_info "Applying configuration override: $var_name=$value"
            declare -g "$var_name"="$value"
        fi
    done < <(env | grep "^${override_prefix}")
}
```

### 4.5 Configuration Management Tools

#### 4.5.1 Configuration Generation Tool

```bash
#!/bin/bash
# tools/generate_config.sh - Generate configuration files from templates

generate_config() {
    local req_num="$1"
    local template_file="config/templates/requirement_template.conf"
    local data_file="config/generation_data/requirement_${req_num}.json"
    local output_file="config/requirement_${req_num}.conf"
    
    if [[ ! -f "$data_file" ]]; then
        log_error "Generation data file not found: $data_file"
        return 1
    fi
    
    # Use mustache templating to generate configuration
    mustache "$data_file" "$template_file" > "$output_file"
    
    # Validate generated configuration
    if validate_config_format "$output_file"; then
        log_info "Generated configuration file: $output_file"
        return 0
    else
        log_error "Generated configuration failed validation"
        return 1
    fi
}
```

#### 4.5.2 Configuration Validation Tool

```bash
#!/bin/bash
# tools/validate_config.sh - Validate configuration files

validate_all_configs() {
    local error_count=0
    
    for req_num in {1..8}; do
        local config_file="config/requirement_${req_num}.conf"
        
        if [[ -f "$config_file" ]]; then
            print_status "INFO" "Validating $config_file"
            
            if validate_config_format "$config_file" && \
               source "$config_file" && \
               validate_required_config_vars "$req_num"; then
                print_status "PASS" "Configuration valid: requirement_${req_num}.conf"
            else
                print_status "FAIL" "Configuration invalid: requirement_${req_num}.conf"
                ((error_count++))
            fi
        else
            print_status "WARN" "Configuration file missing: requirement_${req_num}.conf"
            ((error_count++))
        fi
    done
    
    if [[ $error_count -eq 0 ]]; then
        print_status "PASS" "All configuration files are valid"
        return 0
    else
        print_status "FAIL" "$error_count configuration issues found"
        return 1
    fi
}
```

### 4.6 Configuration Customization Guide

Organizations can customize assessments through configuration modifications:

#### 4.6.1 Compliance Threshold Customization
```bash
# Adjust compliance requirements per organizational risk tolerance
MIN_COMPLIANCE_PERCENTAGE=95  # Stricter than default 80%
CRITICAL_FINDING_THRESHOLD=0  # Zero tolerance for critical findings
```

#### 4.6.2 Protocol and Port Customization
```bash
# Add organization-specific denied protocols
DENIED_PROTOCOLS+=("rdp" "vnc" "x11")
DENIED_PORTS+=("3389" "5900" "6000-6063")

# Define organization-specific exceptions
ALLOWED_ADMIN_PROTOCOLS=("ssh" "https" "wireguard")
INTERNAL_MANAGEMENT_NETWORKS=("10.0.0.0/8" "172.16.0.0/12")
```

#### 4.6.3 Report Customization
```bash
# Customize report output for different audiences
REPORT_LEVEL="executive"     # executive, summary, detailed, technical
OUTPUT_FORMAT="json"         # html, json, csv, pdf
INCLUDE_CHARTS="true"        # Include visual compliance charts
INCLUDE_TRENDS="true"        # Include historical trend analysis
```

This comprehensive configuration framework provides the foundation for customizable, maintainable PCI DSS assessments while ensuring consistency and compliance across all requirement evaluations.

## 5. Integration Patterns

### 5.1 Standard Integration Pattern

All requirement scripts follow this standardized integration pattern with consistent structure and behavior:

#### 5.1.1 Main Script Structure

**Template:** `check_gcp_pci_requirement_N.sh`
```bash
#!/bin/bash
# GCP PCI DSS Requirement N Assessment Script
# Generated from shared library framework
# Maintains backward compatibility with original CLI interface

set -euo pipefail

#===============================================================================
# SCRIPT METADATA
#===============================================================================
readonly SCRIPT_VERSION="2.0.0"
readonly REQUIREMENT_NUMBER="N"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#===============================================================================
# SHARED LIBRARY LOADING
#===============================================================================
# Load shared libraries in dependency order
source "${SCRIPT_DIR}/lib/gcp_common.sh" || {
    echo "FATAL: Cannot load gcp_common.sh" >&2
    exit 1
}

# All other libraries are loaded via source_gcp_libraries()
source_gcp_libraries || {
    print_status "FAIL" "Failed to load shared libraries"
    exit 1
}

#===============================================================================
# REQUIREMENT-SPECIFIC CONFIGURATION
#===============================================================================
# Load requirement-specific configuration and assessment module
load_requirement_config "$REQUIREMENT_NUMBER" || {
    print_status "FAIL" "Failed to load requirement configuration"
    exit 1
}

# Source assessment module
readonly ASSESSMENT_MODULE="${SCRIPT_DIR}/assessments/requirement_${REQUIREMENT_NUMBER}_checks.sh"
if [[ -f "$ASSESSMENT_MODULE" ]]; then
    source "$ASSESSMENT_MODULE" || {
        print_status "FAIL" "Failed to load assessment module: $ASSESSMENT_MODULE"
        exit 1
    }
else
    print_status "FAIL" "Assessment module not found: $ASSESSMENT_MODULE"
    exit 1
fi

#===============================================================================
# HELP FUNCTION
#===============================================================================
show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

GCP PCI DSS Requirement ${REQUIREMENT_NUMBER} Assessment Script

DESCRIPTION:
    ${REQUIREMENT_DESCRIPTION}

OPTIONS:
    -s, --single-project        Assess current project only
    -p, --project PROJECT_ID    Assess specific project
    -o, --organization ORG_ID   Assess all projects in organization
    -r, --report-only           Generate report without opening browser
    -v, --verbose               Enable verbose output
    -d, --debug                 Enable debug output
    -h, --help                  Show this help message

EXAMPLES:
    $(basename "$0") -s                          # Assess current project
    $(basename "$0") -p my-project-123           # Assess specific project
    $(basename "$0") -o 123456789012             # Assess organization
    $(basename "$0") -p my-project -r            # Generate report only

CONFIGURATION:
    Configuration file: config/requirement_${REQUIREMENT_NUMBER}.conf
    Override with: GCP_PCI_REQ${REQUIREMENT_NUMBER}_[VARIABLE_NAME]

REQUIREMENTS:
    - gcloud CLI installed and authenticated
    - Required GCP IAM permissions (see documentation)
    - Internet connectivity for API access

For more information, visit: https://docs.example.com/gcp-pci-dss
EOF
}

#===============================================================================
# MAIN EXECUTION FLOW
#===============================================================================
main() {
    local start_time=$(date +%s)
    
    print_status "INFO" "Starting PCI DSS Requirement ${REQUIREMENT_NUMBER} Assessment"
    print_status "INFO" "Script version: $SCRIPT_VERSION"
    
    # 1. Environment and argument setup
    setup_environment || {
        handle_error 11 "Environment setup failed" "Check system requirements"
        return 1
    }
    
    parse_common_arguments "$@" || {
        handle_error 10 "Invalid command line arguments" "Use --help for usage information"
        return 1
    }
    
    # 2. Prerequisites validation
    validate_prerequisites || {
        handle_error 11 "Prerequisites validation failed" "Install required tools and authenticate"
        return 1
    }
    
    # 3. Permission validation
    register_required_permissions "$REQUIREMENT_NUMBER" "${REQUIRED_PERMISSIONS[@]}"
    
    if ! check_all_permissions; then
        local coverage=$(get_permission_coverage)
        if [[ $coverage -lt 50 ]]; then
            handle_error 3 "Insufficient permissions (${coverage}% coverage)" \
                         "Grant required IAM permissions or use service account"
            return 1
        else
            if ! prompt_continue_limited; then
                print_status "INFO" "Assessment cancelled by user"
                return 0
            fi
        fi
    fi
    
    # 4. Scope configuration
    setup_assessment_scope || {
        handle_error 20 "Scope configuration failed" "Verify project/organization access"
        return 1
    }
    
    validate_scope_permissions || {
        handle_error 20 "Scope permission validation failed" "Check project access rights"
        return 1
    }
    
    print_status "INFO" "Assessment scope: ${#ASSESSMENT_SCOPE[@]} project(s)"
    
    # 5. Report initialization
    initialize_report "$REQUIREMENT_NUMBER" "$REQUIREMENT_TITLE" || {
        handle_error 30 "Report initialization failed" "Check write permissions for output directory"
        return 1
    }
    
    # 6. Execute requirement-specific assessments
    print_status "INFO" "Executing requirement-specific assessments"
    
    if run_requirement_assessments; then
        print_status "PASS" "Assessment completed successfully"
    else
        print_status "WARN" "Assessment completed with issues"
    fi
    
    # 7. Generate summary and finalize report
    add_summary_metrics || {
        print_status "WARN" "Summary generation failed"
    }
    
    finalize_report "${OPEN_BROWSER:-false}" || {
        print_status "WARN" "Report finalization failed"
    }
    
    # 8. Cleanup and summary
    cleanup_environment
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    print_status "INFO" "Assessment completed in ${duration} seconds"
    print_status "INFO" "Report available at: $REPORT_FILE"
    
    return 0
}

#===============================================================================
# ERROR HANDLING AND CLEANUP
#===============================================================================
# Trap signals for graceful cleanup
trap 'cleanup_environment; exit 130' INT
trap 'cleanup_environment; exit 143' TERM

cleanup_environment() {
    if [[ -n "${WORK_DIR:-}" && -d "$WORK_DIR" ]]; then
        rm -rf "$WORK_DIR" 2>/dev/null || true
    fi
}

#===============================================================================
# SCRIPT EXECUTION
#===============================================================================
# Execute main function with all arguments
# Exit with appropriate code
if main "$@"; then
    exit 0
else
    exit 1
fi
```

#### 5.1.2 Assessment Module Structure

**Template:** `assessments/requirement_N_checks.sh`
```bash
#!/bin/bash
# Assessment module for PCI DSS Requirement N
# Contains requirement-specific assessment logic

#===============================================================================
# ASSESSMENT MODULE METADATA
#===============================================================================
readonly MODULE_VERSION="1.0.0"
readonly MODULE_NAME="requirement_${REQUIREMENT_NUMBER}_checks"

#===============================================================================
# MAIN ASSESSMENT ENTRY POINT
#===============================================================================
run_requirement_assessments() {
    print_status "INFO" "Starting ${MODULE_NAME} (version ${MODULE_VERSION})"
    
    add_section "PCI DSS Requirement ${REQUIREMENT_NUMBER} Assessment"
    add_section "Assessment Overview"
    
    # Add assessment metadata to report
    add_check_result "INFO" "Assessment Configuration" \
                    "Requirement: ${REQUIREMENT_NUMBER}" \
                    "Title: ${REQUIREMENT_TITLE}
Configuration: requirement_${REQUIREMENT_NUMBER}.conf
Assessment Module: ${MODULE_NAME} v${MODULE_VERSION}
Scope: ${#ASSESSMENT_SCOPE[@]} project(s)
Compliance Threshold: ${MIN_COMPLIANCE_PERCENTAGE}%"
    
    # Execute requirement-specific checks based on configuration
    local check_count=0
    local failed_checks=0
    
    # Dynamic check execution based on configuration flags
    for check_function in $(get_enabled_checks); do
        print_status "INFO" "Executing check: $check_function"
        ((check_count++))
        
        if ! "$check_function"; then
            ((failed_checks++))
            print_status "WARN" "Check failed: $check_function"
        fi
    done
    
    # Assessment summary
    local success_rate=$(( (check_count - failed_checks) * 100 / check_count ))
    
    add_section "Assessment Summary"
    add_check_result "INFO" "Assessment Statistics" \
                    "Total checks executed: $check_count" \
                    "Failed checks: $failed_checks
Success rate: ${success_rate}%
Compliance threshold: ${MIN_COMPLIANCE_PERCENTAGE}%"
    
    if [[ $success_rate -ge $MIN_COMPLIANCE_PERCENTAGE ]]; then
        add_check_result "PASS" "Overall Compliance" \
                        "Requirement ${REQUIREMENT_NUMBER} compliance achieved (${success_rate}%)"
        print_status "PASS" "Requirement ${REQUIREMENT_NUMBER} assessment: COMPLIANT"
        return 0
    else
        add_check_result "FAIL" "Overall Compliance" \
                        "Requirement ${REQUIREMENT_NUMBER} compliance not met (${success_rate}% < ${MIN_COMPLIANCE_PERCENTAGE}%)"
        print_status "FAIL" "Requirement ${REQUIREMENT_NUMBER} assessment: NON-COMPLIANT"
        return 1
    fi
}

#===============================================================================
# DYNAMIC CHECK DISCOVERY
#===============================================================================
get_enabled_checks() {
    # Discover and return enabled check functions based on configuration
    local enabled_checks=()
    
    # Parse configuration for CHECK_* variables set to "true"
    while IFS='=' read -r var_name var_value; do
        if [[ "$var_name" =~ ^CHECK_(.+)$ ]] && [[ "$var_value" == "true" ]]; then
            local check_name="${BASH_REMATCH[1],,}"  # Convert to lowercase
            local function_name="check_${check_name}"
            
            # Verify function exists
            if declare -f "$function_name" >/dev/null; then
                enabled_checks+=("$function_name")
            else
                print_status "WARN" "Check function not found: $function_name"
            fi
        fi
    done < <(set | grep "^CHECK_")
    
    printf '%s\n' "${enabled_checks[@]}"
}

#===============================================================================
# EXAMPLE CHECK IMPLEMENTATIONS
#===============================================================================
# These functions should be implemented per requirement

check_example_feature() {
    add_section "Example Feature Analysis"
    
    local compliant_resources=0
    local total_resources=0
    
    # Execute assessment across all projects in scope
    for project_id in "${ASSESSMENT_SCOPE[@]}"; do
        print_status "INFO" "Checking example feature in project: $project_id"
        
        # Use shared library functions for consistent behavior
        local project_data=$(run_gcloud_command "$project_id" "compute instances list --format=json")
        
        # Process results and update counters
        local project_total=$(echo "$project_data" | jq '. | length')
        local project_compliant=$(echo "$project_data" | jq '[.[] | select(.metadata.compliance == "true")] | length')
        
        total_resources=$((total_resources + project_total))
        compliant_resources=$((compliant_resources + project_compliant))
        
        # Add project-specific results to report
        add_check_result "INFO" "Project Analysis: $project_id" \
                        "Resources found: $project_total, Compliant: $project_compliant"
    done
    
    # Calculate overall compliance
    local compliance_rate=0
    if [[ $total_resources -gt 0 ]]; then
        compliance_rate=$(( compliant_resources * 100 / total_resources ))
    fi
    
    # Report results
    if [[ $compliance_rate -ge $MIN_COMPLIANCE_PERCENTAGE ]]; then
        add_check_result "PASS" "Example Feature Compliance" \
                        "Compliance rate: ${compliance_rate}% (${compliant_resources}/${total_resources})"
        return 0
    else
        add_check_result "FAIL" "Example Feature Compliance" \
                        "Compliance rate below threshold: ${compliance_rate}% (${compliant_resources}/${total_resources})" \
                        "Remediation: Update non-compliant resources to meet security requirements"
        return 1
    fi
}

# Additional check functions would be implemented here...
```

### 5.2 Cross-Project Integration Pattern

#### 5.2.1 Project Enumeration and Scope Management

```bash
# Enhanced project enumeration with filtering and validation
enumerate_assessment_projects() {
    local scope_type="$1"
    local scope_value="$2"
    local projects=()
    
    case "$scope_type" in
        "project")
            # Single project scope
            if validate_project_access "$scope_value"; then
                projects=("$scope_value")
            else
                handle_error 20 "Cannot access project: $scope_value"
                return 1
            fi
            ;;
            
        "organization")
            # Organization scope - enumerate all accessible projects
            print_status "INFO" "Enumerating projects in organization: $scope_value"
            
            local all_projects
            all_projects=$(gcloud projects list \
                --filter="parent.id:$scope_value AND lifecycleState:ACTIVE" \
                --format="value(projectId)" 2>/dev/null) || {
                handle_error 20 "Cannot list projects in organization: $scope_value"
                return 1
            }
            
            # Filter projects based on access and configuration
            while IFS= read -r project_id; do
                if validate_project_access "$project_id"; then
                    projects+=("$project_id")
                else
                    print_status "WARN" "Skipping inaccessible project: $project_id"
                fi
            done <<< "$all_projects"
            
            if [[ ${#projects[@]} -eq 0 ]]; then
                handle_error 20 "No accessible projects found in organization: $scope_value"
                return 1
            fi
            ;;
            
        *)
            handle_error 10 "Invalid scope type: $scope_type"
            return 1
            ;;
    esac
    
    # Apply project filtering if configured
    if [[ -n "${PROJECT_INCLUDE_FILTER:-}" ]]; then
        projects=($(filter_projects "include" "$PROJECT_INCLUDE_FILTER" "${projects[@]}"))
    fi
    
    if [[ -n "${PROJECT_EXCLUDE_FILTER:-}" ]]; then
        projects=($(filter_projects "exclude" "$PROJECT_EXCLUDE_FILTER" "${projects[@]}"))
    fi
    
    ASSESSMENT_SCOPE=("${projects[@]}")
    print_status "INFO" "Assessment scope configured: ${#ASSESSMENT_SCOPE[@]} project(s)"
    
    return 0
}

filter_projects() {
    local filter_type="$1"
    local filter_pattern="$2"
    shift 2
    local input_projects=("$@")
    local filtered_projects=()
    
    for project_id in "${input_projects[@]}"; do
        if [[ "$filter_type" == "include" ]]; then
            if [[ "$project_id" =~ $filter_pattern ]]; then
                filtered_projects+=("$project_id")
            fi
        elif [[ "$filter_type" == "exclude" ]]; then
            if [[ ! "$project_id" =~ $filter_pattern ]]; then
                filtered_projects+=("$project_id")
            fi
        fi
    done
    
    printf '%s\n' "${filtered_projects[@]}"
}
```

#### 5.2.2 Parallel Assessment Execution

```bash
# Execute assessments across multiple projects in parallel
run_parallel_assessments() {
    local assessment_function="$1"
    local max_parallel="${2:-5}"  # Default to 5 parallel executions
    local project_count=${#ASSESSMENT_SCOPE[@]}
    
    print_status "INFO" "Executing $assessment_function across $project_count projects (max parallel: $max_parallel)"
    
    # Create temporary directory for parallel execution results
    local parallel_work_dir="${WORK_DIR}/parallel_$$"
    mkdir -p "$parallel_work_dir"
    
    local project_index=0
    local running_jobs=0
    local completed_jobs=0
    local failed_jobs=0
    
    # Process projects in batches
    while [[ $project_index -lt $project_count ]]; do
        # Start new jobs up to max_parallel limit
        while [[ $running_jobs -lt $max_parallel && $project_index -lt $project_count ]]; do
            local project_id="${ASSESSMENT_SCOPE[$project_index]}"
            local job_file="${parallel_work_dir}/job_${project_index}"
            
            # Start background job
            (
                export PROJECT_CONTEXT="$project_id"
                export JOB_INDEX="$project_index"
                export JOB_OUTPUT="$job_file"
                
                if "$assessment_function" "$project_id" > "${job_file}.out" 2> "${job_file}.err"; then
                    echo "SUCCESS" > "${job_file}.status"
                else
                    echo "FAILED" > "${job_file}.status"
                fi
            ) &
            
            echo $! > "${job_file}.pid"
            ((project_index++))
            ((running_jobs++))
        done
        
        # Wait for at least one job to complete
        local completed_this_cycle=0
        for job_file in "${parallel_work_dir}"/job_*.pid; do
            [[ -f "$job_file" ]] || continue
            
            local pid=$(cat "$job_file")
            local job_status_file="${job_file%.*}.status"
            
            if [[ -f "$job_status_file" ]]; then
                # Job completed
                local status=$(cat "$job_status_file")
                if [[ "$status" == "SUCCESS" ]]; then
                    ((completed_jobs++))
                else
                    ((failed_jobs++))
                fi
                
                rm -f "$job_file" "${job_file%.*}".{out,err,status}
                ((running_jobs--))
                ((completed_this_cycle++))
            fi
        done
        
        # If no jobs completed this cycle, wait briefly
        if [[ $completed_this_cycle -eq 0 ]]; then
            sleep 1
        fi
        
        # Progress reporting
        local total_processed=$((completed_jobs + failed_jobs))
        if [[ $((total_processed % 10)) -eq 0 && $total_processed -gt 0 ]]; then
            print_status "INFO" "Progress: $total_processed/$project_count projects processed"
        fi
    done
    
    # Wait for remaining jobs to complete
    while [[ $running_jobs -gt 0 ]]; do
        for job_file in "${parallel_work_dir}"/job_*.pid; do
            [[ -f "$job_file" ]] || continue
            
            local pid=$(cat "$job_file")
            local job_status_file="${job_file%.*}.status"
            
            if [[ -f "$job_status_file" ]]; then
                local status=$(cat "$job_status_file")
                if [[ "$status" == "SUCCESS" ]]; then
                    ((completed_jobs++))
                else
                    ((failed_jobs++))
                fi
                
                rm -f "$job_file" "${job_file%.*}".{out,err,status}
                ((running_jobs--))
            fi
        done
        
        [[ $running_jobs -gt 0 ]] && sleep 1
    done
    
    # Cleanup
    rmdir "$parallel_work_dir" 2>/dev/null || true
    
    print_status "INFO" "Parallel assessment completed: $completed_jobs successful, $failed_jobs failed"
    
    if [[ $failed_jobs -gt 0 ]]; then
        return 1
    else
        return 0
    fi
}
```

### 5.3 Migration Compatibility Framework

#### 5.3.1 Legacy Function Mapping

```bash
# compatibility/legacy_support.sh
# Provides backward compatibility for existing scripts during migration

#===============================================================================
# LEGACY FUNCTION REDIRECTIONS
#===============================================================================
# Map legacy function calls to new shared library functions

# Output and formatting functions
print_colored_output() { print_status "$@"; }
colored_echo() { print_status "$@"; }
echo_with_color() { print_status "$@"; }

# Permission checking functions  
check_gcp_permission() { check_single_permission "$@"; }
verify_gcp_permissions() { check_all_permissions "$@"; }
validate_gcp_access() { validate_scope_permissions "$@"; }

# Report generation functions
generate_html_report() { finalize_report "$@"; }
create_assessment_report() { finalize_report "$@"; }
output_html_file() { finalize_report "$@"; }

# Project and scope functions
get_current_project() { echo "${ASSESSMENT_SCOPE[0]:-}"; }
enumerate_projects() { get_projects_in_scope "$@"; }
setup_project_context() { setup_assessment_scope "$@"; }

# Configuration functions
load_config_file() { load_requirement_config "$@"; }
read_configuration() { load_requirement_config "$@"; }
parse_config_options() { load_requirement_config "$@"; }

#===============================================================================
# LEGACY VARIABLE MAPPING
#===============================================================================
# Maintain compatibility with legacy variable names

# Color definitions (maintain exact legacy names)
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export PURPLE='\033[0;35m'
export CYAN='\033[0;36m'
export WHITE='\033[1;37m'
export NC='\033[0m'

# Legacy counter variables
alias passed_count='passed_checks'
alias failed_count='failed_checks'
alias total_count='total_checks'

# Legacy path variables
export SCRIPT_PATH="$SCRIPT_DIR"
export BASE_DIR="$SCRIPT_DIR"
export LIB_DIR="${SCRIPT_DIR}/lib"

#===============================================================================
# LEGACY ARGUMENT PARSING COMPATIBILITY
#===============================================================================
# Support legacy argument parsing patterns

parse_legacy_arguments() {
    # Convert legacy argument patterns to new format
    local legacy_args=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --single)
                legacy_args+=("-s")
                shift
                ;;
            --project-id)
                legacy_args+=("-p" "$2")
                shift 2
                ;;
            --organization-id)
                legacy_args+=("-o" "$2")
                shift 2
                ;;
            --no-browser)
                legacy_args+=("-r")
                shift
                ;;
            *)
                legacy_args+=("$1")
                shift
                ;;
        esac
    done
    
    # Pass converted arguments to new parser
    parse_common_arguments "${legacy_args[@]}"
}

#===============================================================================
# LEGACY CONFIGURATION COMPATIBILITY
#===============================================================================
# Support legacy configuration variable names

map_legacy_config_vars() {
    # Map legacy configuration variables to new names
    [[ -n "${COMPLIANCE_THRESHOLD:-}" ]] && MIN_COMPLIANCE_PERCENTAGE="$COMPLIANCE_THRESHOLD"
    [[ -n "${REPORT_FORMAT:-}" ]] && OUTPUT_FORMAT="$REPORT_FORMAT"
    [[ -n "${DETAIL_LEVEL:-}" ]] && REPORT_LEVEL="$DETAIL_LEVEL"
    [[ -n "${BROWSER_OPEN:-}" ]] && OPEN_BROWSER="$BROWSER_OPEN"
    
    # Map legacy permission arrays
    [[ -n "${REQUIRED_APIS:-}" ]] && REQUIRED_PERMISSIONS=("${REQUIRED_APIS[@]}")
    [[ -n "${OPTIONAL_APIS:-}" ]] && OPTIONAL_PERMISSIONS=("${OPTIONAL_APIS[@]}")
    
    # Map legacy check flags
    [[ -n "${ENABLE_FIREWALL_CHECK:-}" ]] && CHECK_FIREWALL_RULES="$ENABLE_FIREWALL_CHECK"
    [[ -n "${ENABLE_NETWORK_CHECK:-}" ]] && CHECK_NETWORK_SEGMENTATION="$ENABLE_NETWORK_CHECK"
}

#===============================================================================
# LEGACY COMPATIBILITY INITIALIZATION
#===============================================================================
# Initialize legacy compatibility when this file is sourced

init_legacy_compatibility() {
    print_status "INFO" "Legacy compatibility layer activated"
    
    # Apply legacy configuration mapping
    map_legacy_config_vars
    
    # Set legacy compatibility flag
    export LEGACY_COMPATIBILITY_MODE="true"
    
    # Override argument parsing if legacy patterns detected
    if [[ "${*}" =~ --single|--project-id|--organization-id|--no-browser ]]; then
        print_status "WARN" "Legacy argument format detected - using compatibility parser"
        parse_legacy_arguments "$@"
        return $?
    fi
    
    return 0
}

# Auto-initialize if legacy patterns are detected in script arguments
if [[ "${BASH_SOURCE[0]}" != "${0}" ]] && [[ "$*" =~ --single|--project-id|--organization-id|--no-browser ]]; then
    init_legacy_compatibility "$@"
fi
```

#### 5.3.2 Migration Validation Framework

```bash
# tools/migration_validator.sh
# Validates that migrated scripts produce identical output to legacy versions

validate_migration() {
    local requirement_number="$1"
    local test_project="${2:-}"
    local legacy_script="legacy/check_gcp_pci_requirement${requirement_number}.sh"
    local new_script="check_gcp_pci_requirement${requirement_number}.sh"
    
    print_status "INFO" "Validating migration for requirement $requirement_number"
    
    # Verify both scripts exist
    if [[ ! -f "$legacy_script" ]]; then
        print_status "FAIL" "Legacy script not found: $legacy_script"
        return 1
    fi
    
    if [[ ! -f "$new_script" ]]; then
        print_status "FAIL" "New script not found: $new_script"
        return 1
    fi
    
    # Test with different argument patterns
    local test_args=(
        "-s"
        "-p $test_project"
        "-r"
        "-s -r"
    )
    
    local validation_errors=0
    
    for args in "${test_args[@]}"; do
        print_status "INFO" "Testing with arguments: $args"
        
        # Run legacy script
        local legacy_output=$(timeout 300 bash "$legacy_script" $args 2>&1 || echo "SCRIPT_FAILED")
        local legacy_exit_code=$?
        
        # Run new script
        local new_output=$(timeout 300 bash "$new_script" $args 2>&1 || echo "SCRIPT_FAILED")
        local new_exit_code=$?
        
        # Compare exit codes
        if [[ $legacy_exit_code -ne $new_exit_code ]]; then
            print_status "FAIL" "Exit code mismatch: legacy=$legacy_exit_code, new=$new_exit_code"
            ((validation_errors++))
        fi
        
        # Compare key output elements (ignoring timestamps and PIDs)
        local legacy_normalized=$(normalize_output "$legacy_output")
        local new_normalized=$(normalize_output "$new_output")
        
        if ! compare_normalized_output "$legacy_normalized" "$new_normalized"; then
            print_status "FAIL" "Output differences detected"
            ((validation_errors++))
        else
            print_status "PASS" "Output validation successful"
        fi
    done
    
    if [[ $validation_errors -eq 0 ]]; then
        print_status "PASS" "Migration validation successful for requirement $requirement_number"
        return 0
    else
        print_status "FAIL" "Migration validation failed: $validation_errors errors"
        return 1
    fi
}

normalize_output() {
    local output="$1"
    
    # Remove timestamps, PIDs, and other variable elements
    echo "$output" | \
        sed 's/[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}/TIMESTAMP/g' | \
        sed 's/process [0-9]\+/process PID/g' | \
        sed 's/tmp\/[^[:space:]]*/tmp\/TMPDIR/g' | \
        sed 's/report_[0-9]\+\.html/report_TIMESTAMP.html/g' | \
        sort
}

compare_normalized_output() {
    local legacy_output="$1"
    local new_output="$2"
    
    # Focus on key compliance results and ignore formatting differences
    local legacy_results=$(echo "$legacy_output" | grep -E "PASS|FAIL|WARN" | sort)
    local new_results=$(echo "$new_output" | grep -E "PASS|FAIL|WARN" | sort)
    
    if [[ "$legacy_results" == "$new_results" ]]; then
        return 0
    else
        echo "Legacy results:"
        echo "$legacy_results"
        echo "New results:"
        echo "$new_results"
        return 1
    fi
}
```

This comprehensive integration pattern framework provides the foundation for consistent, maintainable script integration while ensuring backward compatibility during the migration process.

## 6. Migration Guide

### 6.1 Migration Strategy Overview

The migration from monolithic scripts to the shared library architecture follows a carefully planned 4-phase approach designed to minimize risk and ensure continuity of compliance assessments.

#### 6.1.1 Migration Phases

**Phase 1: Foundation Implementation** (Sprint S01 - 2 weeks)
- **Objective:** Implement and validate all 4 shared libraries
- **Deliverables:**
  - Complete implementation of `gcp_common.sh`, `gcp_html_report.sh`, `gcp_permissions.sh`, `gcp_scope_mgmt.sh`
  - Comprehensive unit test suite (90% coverage)
  - Integration test framework
  - Configuration management system
  - Migration validation tools
- **Success Criteria:**
  - All 26 API functions implemented and tested
  - Shared libraries pass independent validation tests
  - Configuration framework operational
  - Migration tools ready for use

**Phase 2: Pilot Migration** (Sprint S02 - 2 weeks)
- **Objective:** Migrate representative requirement scripts to validate approach
- **Target Scripts:**
  - Requirement 1 (simple): Network security controls
  - Requirement 3 (complex): Data protection with multiple sub-requirements
- **Deliverables:**
  - 2 fully migrated requirement scripts
  - Assessment modules for requirements 1 and 3
  - Migration validation reports
  - Performance benchmarking results
  - Refined migration procedures
- **Success Criteria:**
  - Identical assessment output compared to legacy scripts
  - Performance within 10% of original execution time
  - All CLI arguments and edge cases handled correctly
  - User acceptance testing passed

**Phase 3: Bulk Migration** (Sprints S03-S04 - 4 weeks)
- **Objective:** Migrate remaining 6 requirement scripts
- **Target Scripts:** Requirements 2, 4, 5, 6, 7, 8
- **Deliverables:**
  - 6 additional migrated requirement scripts
  - Complete assessment module library
  - Comprehensive integration testing
  - Updated documentation and user guides
  - Training materials for operations teams
- **Success Criteria:**
  - All 8 requirement scripts successfully migrated
  - Full regression testing passed
  - Documentation complete and validated
  - Operations team trained and signed off

**Phase 4: Optimization and Cleanup** (Sprint S05 - 2 weeks)
- **Objective:** Optimize performance and remove legacy code
- **Deliverables:**
  - Performance optimization implementation
  - Legacy code removal
  - Final validation and acceptance testing
  - Production deployment procedures
  - Post-migration monitoring setup
- **Success Criteria:**
  - 71.6% code reduction target achieved
  - Performance optimized (target: 5% improvement over baseline)
  - Legacy code completely removed
  - Production deployment successful
  - Monitoring and alerting operational

### 6.2 Detailed Migration Procedures

#### 6.2.1 Pre-Migration Preparation

**Step 1: Environment Setup**
```bash
# Create migration workspace
mkdir -p migration_workspace/{legacy_backup,new_scripts,validation_results}

# Backup existing scripts
cp check_gcp_pci_requirement*.sh migration_workspace/legacy_backup/

# Verify shared libraries are deployed
source lib/gcp_common.sh && echo "Libraries OK" || echo "Libraries FAILED"
```

**Step 2: Migration Readiness Assessment**
```bash
# Run pre-migration validation
tools/pre_migration_check.sh

# Validate configuration framework
tools/validate_config.sh

# Check test environment access
tools/test_environment_check.sh
```

#### 6.2.2 Per-Script Migration Process

**Step 1: Script Analysis and Planning**
```bash
# Analyze current script structure
tools/analyze_script.sh requirement_N > analysis_req_N.txt

# Identify unique vs common code
tools/code_classifier.sh check_gcp_pci_requirement_N.sh
```

**Script Analysis Output Example:**
```
================================================================================
SCRIPT ANALYSIS: check_gcp_pci_requirement1.sh
================================================================================
Total Lines: 932
Common Code Lines: 712 (76.4%)
Unique Code Lines: 220 (23.6%)

COMMON CODE SECTIONS:
- Lines 1-6: Header comments (COMMON)
- Lines 7-12: Color definitions (100% DUPLICATE - extract to gcp_common.sh)
- Lines 13-16: Scope variables (100% DUPLICATE - extract to gcp_common.sh)
- Lines 17-34: show_help() function (95% DUPLICATE - parameterize)
- Lines 35-64: CLI argument parsing (100% DUPLICATE - extract to gcp_common.sh)
- Lines 65-84: Variable setup (95% DUPLICATE - extract to gcp_common.sh)
- Lines 85-131: HTML report functions (100% DUPLICATE - extract to gcp_html_report.sh)
- Lines 132-156: GCP permission checking (100% DUPLICATE - extract to gcp_permissions.sh)
- Lines 157-176: Project/org logic (95% DUPLICATE - extract to gcp_scope_mgmt.sh)

UNIQUE CODE SECTIONS:
- Lines 177-897: Requirement 1 specific assessment logic (UNIQUE)
- Lines 898-917: Report finalization (95% DUPLICATE - extract to gcp_html_report.sh)

MIGRATION RECOMMENDATIONS:
1. Extract lines 177-897 to assessments/requirement_1_checks.sh
2. Replace common code with shared library calls
3. Estimated final script size: 45-50 lines (94.7% reduction)
```

**Step 2: Assessment Module Extraction**
```bash
# Extract unique assessment logic
tools/extract_assessment_module.sh requirement_N

# This creates: assessments/requirement_N_checks.sh
```

**Assessment Module Template Creation:**
```bash
#!/bin/bash
# Auto-generated assessment module for Requirement N
# Extracted from: check_gcp_pci_requirement_N.sh
# Extraction date: YYYY-MM-DD

# [EXTRACTED UNIQUE FUNCTIONS INSERTED HERE]

# Standard assessment entry point (auto-generated)
run_requirement_assessments() {
    add_section "PCI DSS Requirement N Assessment"
    
    # Call extracted assessment functions
    check_specific_requirement_N_feature_1
    check_specific_requirement_N_feature_2
    # ... additional checks
    
    return 0
}
```

**Step 3: Main Script Generation**
```bash
# Generate new main script using template
tools/generate_main_script.sh requirement_N

# This creates: check_gcp_pci_requirement_N.sh (new version)
```

**Step 4: Configuration File Creation**
```bash
# Generate requirement-specific configuration
tools/generate_config.sh requirement_N

# This creates: config/requirement_N.conf
```

**Step 5: Migration Validation**
```bash
# Run comprehensive validation
tools/migration_validator.sh requirement_N test_project_id

# Expected output:
# [✓] Script structure validation passed
# [✓] Output comparison: 100% match
# [✓] Performance test: 3% improvement
# [✓] CLI argument compatibility: passed
# [✓] Error handling validation: passed
# [i] Migration successful for requirement N
```

#### 6.2.3 Validation and Testing Framework

**Automated Validation Pipeline:**
```bash
#!/bin/bash
# migration_pipeline.sh - Complete migration validation pipeline

validate_migration_pipeline() {
    local requirement_num="$1"
    local test_project="$2"
    
    echo "Starting migration validation pipeline for requirement $requirement_num"
    
    # 1. Structure validation
    if ! validate_script_structure "$requirement_num"; then
        echo "FAIL: Script structure validation failed"
        return 1
    fi
    
    # 2. Functional validation
    if ! validate_functional_equivalence "$requirement_num" "$test_project"; then
        echo "FAIL: Functional validation failed"
        return 1
    fi
    
    # 3. Performance validation
    if ! validate_performance_regression "$requirement_num" "$test_project"; then
        echo "FAIL: Performance validation failed"
        return 1
    fi
    
    # 4. Integration validation
    if ! validate_integration_compatibility "$requirement_num"; then
        echo "FAIL: Integration validation failed"
        return 1
    fi
    
    # 5. Security validation
    if ! validate_security_compliance "$requirement_num"; then
        echo "FAIL: Security validation failed"
        return 1
    fi
    
    echo "SUCCESS: All validation tests passed for requirement $requirement_num"
    return 0
}

validate_functional_equivalence() {
    local requirement_num="$1"
    local test_project="$2"
    
    local legacy_script="migration_workspace/legacy_backup/check_gcp_pci_requirement${requirement_num}.sh"
    local new_script="check_gcp_pci_requirement${requirement_num}.sh"
    
    # Test scenarios
    local test_scenarios=(
        "-s"                                    # Single project (current)
        "-p $test_project"                      # Specific project
        "-s -r"                                 # Single project, report only
        "-p $test_project -r"                   # Specific project, report only
        "-p $test_project -v"                   # Verbose mode
        "-h"                                    # Help output
    )
    
    local failed_scenarios=0
    
    for scenario in "${test_scenarios[@]}"; do
        echo "Testing scenario: $scenario"
        
        # Run legacy script
        local legacy_output=$(timeout 600 bash "$legacy_script" $scenario 2>&1)
        local legacy_exit_code=$?
        
        # Run new script
        local new_output=$(timeout 600 bash "$new_script" $scenario 2>&1)
        local new_exit_code=$?
        
        # Compare results
        if ! compare_assessment_results "$legacy_output" "$new_output" "$legacy_exit_code" "$new_exit_code"; then
            echo "FAIL: Scenario '$scenario' produced different results"
            ((failed_scenarios++))
            
            # Save detailed comparison for analysis
            echo "=== LEGACY OUTPUT ===" > "validation_results/scenario_${requirement_num}_${scenario// /_}.diff"
            echo "$legacy_output" >> "validation_results/scenario_${requirement_num}_${scenario// /_}.diff"
            echo "=== NEW OUTPUT ===" >> "validation_results/scenario_${requirement_num}_${scenario// /_}.diff"
            echo "$new_output" >> "validation_results/scenario_${requirement_num}_${scenario// /_}.diff"
        else
            echo "PASS: Scenario '$scenario' validation successful"
        fi
    done
    
    if [[ $failed_scenarios -eq 0 ]]; then
        echo "Functional equivalence validation: PASSED"
        return 0
    else
        echo "Functional equivalence validation: FAILED ($failed_scenarios scenarios failed)"
        return 1
    fi
}

compare_assessment_results() {
    local legacy_output="$1"
    local new_output="$2"
    local legacy_exit_code="$3"
    local new_exit_code="$4"
    
    # Compare exit codes
    if [[ $legacy_exit_code -ne $new_exit_code ]]; then
        echo "Exit code mismatch: legacy=$legacy_exit_code, new=$new_exit_code"
        return 1
    fi
    
    # Extract and compare key assessment results
    local legacy_results=$(echo "$legacy_output" | extract_assessment_results)
    local new_results=$(echo "$new_output" | extract_assessment_results)
    
    # Normalize results (remove timestamps, file paths, etc.)
    local legacy_normalized=$(echo "$legacy_results" | normalize_assessment_output)
    local new_normalized=$(echo "$new_results" | normalize_assessment_output)
    
    # Compare normalized results
    if [[ "$legacy_normalized" == "$new_normalized" ]]; then
        return 0
    else
        echo "Assessment results differ:"
        echo "Legacy: $legacy_normalized"
        echo "New: $new_normalized"
        return 1
    fi
}

extract_assessment_results() {
    # Extract key compliance indicators from output
    grep -E "(PASS|FAIL|WARN).*:" | \
    grep -v "Prerequisites\|Permission\|Report" | \
    sort
}

normalize_assessment_output() {
    # Remove variable elements like timestamps, file paths, PIDs
    sed 's/[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}/TIMESTAMP/g' | \
    sed 's/\/tmp\/[^[:space:]]*/\/tmp\/WORKDIR/g' | \
    sed 's/report_[0-9]\+\.html/report_TIMESTAMP.html/g' | \
    sed 's/Assessment completed in [0-9]\+ seconds/Assessment completed in N seconds/g'
}
```

### 6.3 Risk Management and Rollback Procedures

#### 6.3.1 Risk Mitigation Strategies

**Low-Risk Migration Approach:**
- **Parallel Operation:** Run both legacy and new scripts simultaneously during transition
- **Gradual Rollout:** Migrate one requirement at a time with validation gates
- **Automated Testing:** Comprehensive test suite validates every change
- **Configuration Control:** All behavior changes managed through configuration

**Risk Monitoring:**
- **Performance Monitoring:** Continuous monitoring of execution times
- **Output Validation:** Automated comparison of assessment results
- **Error Rate Monitoring:** Track and alert on increased error rates
- **User Feedback:** Collect and respond to user-reported issues

#### 6.3.2 Rollback Procedures

**Immediate Rollback (Emergency):**
```bash
#!/bin/bash
# emergency_rollback.sh - Immediate rollback to legacy scripts

emergency_rollback() {
    local requirement_num="${1:-all}"
    
    echo "EMERGENCY: Initiating rollback for requirement $requirement_num"
    
    if [[ "$requirement_num" == "all" ]]; then
        # Rollback all requirements
        for req in {1..8}; do
            rollback_single_requirement "$req"
        done
    else
        rollback_single_requirement "$requirement_num"
    fi
    
    echo "Emergency rollback completed"
}

rollback_single_requirement() {
    local req="$1"
    local script_name="check_gcp_pci_requirement${req}.sh"
    local backup_script="migration_workspace/legacy_backup/$script_name"
    
    if [[ -f "$backup_script" ]]; then
        echo "Rolling back requirement $req"
        cp "$backup_script" "$script_name"
        chmod +x "$script_name"
        echo "Rollback completed for requirement $req"
    else
        echo "ERROR: Backup not found for requirement $req"
        return 1
    fi
}
```

**Planned Rollback (Validation Failure):**
```bash
#!/bin/bash
# planned_rollback.sh - Systematic rollback with validation

planned_rollback() {
    local requirement_num="$1"
    local reason="$2"
    
    echo "Initiating planned rollback for requirement $requirement_num"
    echo "Reason: $reason"
    
    # 1. Stop any running assessments
    stop_running_assessments "$requirement_num"
    
    # 2. Restore legacy script
    restore_legacy_script "$requirement_num"
    
    # 3. Validate rollback
    validate_rollback "$requirement_num"
    
    # 4. Update monitoring
    update_rollback_monitoring "$requirement_num"
    
    # 5. Notify stakeholders
    notify_rollback_completion "$requirement_num" "$reason"
}
```

### 6.4 Migration Success Metrics

#### 6.4.1 Technical Metrics

**Code Reduction Targets:**
- **Overall Reduction:** 71.6% (7,740 → 2,200 lines)
- **Duplication Elimination:** 83.3% (4,800 → 800 duplicated lines)
- **Per-Script Reduction:** 94%+ (900+ lines → 50 lines per script)
- **Maintenance Points:** 60% reduction (8 scripts → 4 libraries + 8 simplified)

**Performance Targets:**
- **Execution Time:** <10% increase (target: 5% improvement)
- **Memory Usage:** <100MB per script (unchanged)
- **Startup Time:** <5 seconds (target: 3 seconds)
- **API Call Efficiency:** 15% reduction in redundant calls

**Quality Targets:**
- **Test Coverage:** 90% for shared libraries
- **Bug Rate:** <2% of legacy bug rate
- **User-Reported Issues:** <5% increase during transition
- **Compatibility:** 100% CLI argument compatibility

#### 6.4.2 Operational Metrics

**Migration Timeline:**
- **Phase 1 Completion:** On schedule (2 weeks)
- **Phase 2 Pilot Success:** 100% validation pass rate
- **Phase 3 Bulk Migration:** On schedule (4 weeks)
- **Phase 4 Optimization:** On schedule (2 weeks)

**User Adoption:**
- **Training Completion:** 100% operations team
- **User Acceptance:** >95% satisfaction
- **Support Ticket Reduction:** 30% reduction post-migration
- **Documentation Quality:** >90% user approval

### 6.5 Post-Migration Optimization

#### 6.5.1 Performance Optimization

**Identified Optimization Opportunities:**
- **API Call Batching:** Combine multiple single API calls into batch operations
- **Caching:** Implement intelligent caching for repeated queries
- **Parallel Processing:** Leverage parallel execution for multi-project assessments
- **Resource Pooling:** Reuse connections and reduce initialization overhead

**Optimization Implementation:**
```bash
# Example: API call batching optimization
optimize_api_calls() {
    local project_ids=("$@")
    
    # Instead of individual calls:
    # for project in "${project_ids[@]}"; do
    #     gcloud compute instances list --project="$project"
    # done
    
    # Use batched approach:
    local batch_filter=""
    for project in "${project_ids[@]}"; do
        batch_filter="$batch_filter OR project:$project"
    done
    
    gcloud compute instances list --filter="$batch_filter" --format="json"
}
```

#### 6.5.2 Continuous Improvement Framework

**Monitoring and Feedback:**
- **Performance Monitoring:** Continuous tracking of execution metrics
- **User Feedback Collection:** Regular surveys and feedback sessions
- **Error Analysis:** Automated analysis of error patterns and trends
- **Improvement Suggestions:** User-driven feature requests and optimizations

**Iterative Enhancement:**
- **Monthly Reviews:** Regular assessment of migration success metrics
- **Quarterly Optimization:** Planned optimization cycles
- **Annual Architecture Review:** Comprehensive architecture assessment
- **Continuous Documentation:** Keep documentation current with changes

This comprehensive migration guide provides the roadmap for successfully transitioning from monolithic scripts to the shared library architecture while maintaining operational continuity and maximizing the benefits of the new design.

## 7. Testing Strategy

### 7.1 Testing Framework Overview

The shared library architecture requires comprehensive testing at multiple levels to ensure reliability, performance, and compatibility. The testing strategy encompasses unit tests, integration tests, performance benchmarks, and validation suites.

#### 7.1.1 Testing Infrastructure

**Testing Technology Stack:**
- **Unit Testing:** BATS (Bash Automated Testing System) for shell script testing
- **Integration Testing:** Custom test harnesses with real GCP API interactions
- **Performance Testing:** Automated benchmarking with statistical analysis
- **Validation Testing:** Output comparison and compatibility verification
- **Mock Services:** Simulated GCP API responses for consistent testing

**Test Environment Requirements:**
- **Isolated GCP Projects:** Dedicated test projects for safe assessment execution
- **Service Account:** Test service account with limited, well-defined permissions
- **Test Data:** Standardized test resources across all GCP services
- **CI/CD Integration:** Automated test execution on code changes

### 7.2 Unit Testing Framework

#### 7.2.1 Shared Library Unit Tests

**Test Structure:**
```
tests/
├── unit/
│   ├── test_gcp_common.sh           # Core functionality tests
│   ├── test_gcp_html_report.sh      # Report generation tests
│   ├── test_gcp_permissions.sh      # Permission management tests
│   ├── test_gcp_scope_mgmt.sh       # Scope management tests
│   └── helpers/
│       ├── test_helpers.sh          # Common test utilities
│       └── mock_gcloud.sh           # GCP API mocking
├── integration/
│   ├── test_end_to_end.sh           # Full workflow tests
│   ├── test_requirement_scripts.sh  # Individual script tests
│   └── test_migration_compatibility.sh # Legacy compatibility tests
├── performance/
│   ├── benchmark_suite.sh           # Performance benchmarking
│   ├── memory_profiling.sh          # Memory usage analysis
│   └── scalability_tests.sh         # Multi-project performance
└── validation/
    ├── output_validation.sh         # Output comparison tests
    ├── cli_compatibility.sh         # CLI argument testing
    └── error_handling.sh            # Error scenario testing
```

**Complete Unit Test Examples:**

**tests/unit/test_gcp_common.sh:**
```bash
#!/usr/bin/env bats

# Load test helpers and mocks
load helpers/test_helpers
load helpers/mock_gcloud

setup() {
    # Setup test environment
    source_test_libraries
    export WORK_DIR="/tmp/test_gcp_common_$$"
    export TEST_PROJECT="test-project-123"
    
    # Initialize mocks
    setup_gcloud_mocks
}

teardown() {
    # Cleanup test environment
    cleanup_test_environment
    cleanup_gcloud_mocks
}

@test "source_gcp_libraries loads all required libraries" {
    run source_gcp_libraries
    [ "$status" -eq 0 ]
    
    # Verify all libraries are loaded
    declare -f setup_environment > /dev/null
    declare -f print_status > /dev/null
    declare -f initialize_report > /dev/null
    declare -f check_all_permissions > /dev/null
}

@test "setup_environment creates working directory with correct permissions" {
    run setup_environment
    [ "$status" -eq 0 ]
    [ -d "$WORK_DIR" ]
    
    # Verify directory permissions
    local perms=$(stat -c "%a" "$WORK_DIR")
    [ "$perms" = "755" ]
    
    # Verify environment variables are set
    [ -n "$RED" ]
    [ -n "$GREEN" ]
    [ -n "$NC" ]
    [ "$passed_checks" -eq 0 ]
    [ "$failed_checks" -eq 0 ]
}

@test "parse_common_arguments handles single project scope" {
    run parse_common_arguments -s
    [ "$status" -eq 0 ]
    [ "$SCOPE_TYPE" = "project" ]
    [ -z "$PROJECT_ID" ]  # Should use current project
}

@test "parse_common_arguments handles specific project scope" {
    run parse_common_arguments -p "$TEST_PROJECT"
    [ "$status" -eq 0 ]
    [ "$SCOPE_TYPE" = "project" ]
    [ "$PROJECT_ID" = "$TEST_PROJECT" ]
}

@test "parse_common_arguments handles organization scope" {
    run parse_common_arguments -o "123456789012"
    [ "$status" -eq 0 ]
    [ "$SCOPE_TYPE" = "organization" ]
    [ "$ORG_ID" = "123456789012" ]
}

@test "parse_common_arguments rejects invalid arguments" {
    run parse_common_arguments --invalid-option
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Unknown parameter" ]]
}

@test "validate_prerequisites succeeds with proper setup" {
    # Mock successful gcloud commands
    mock_gcloud_success
    
    run validate_prerequisites
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Prerequisites validation successful" ]]
}

@test "validate_prerequisites fails without gcloud" {
    # Mock missing gcloud
    mock_gcloud_missing
    
    run validate_prerequisites
    [ "$status" -eq 1 ]
    [[ "$output" =~ "gcloud CLI not found" ]]
}

@test "print_status formats output correctly" {
    run print_status "PASS" "Test message"
    [ "$status" -eq 0 ]
    [[ "$output" =~ \[.*✓.*\].*Test\ message ]]
    
    run print_status "FAIL" "Error message"
    [ "$status" -eq 0 ]
    [[ "$output" =~ \[.*✗.*\].*Error\ message ]]
}

@test "load_requirement_config loads valid configuration" {
    # Create test configuration
    create_test_config "1" "test_requirement_1.conf"
    
    run load_requirement_config "1"
    [ "$status" -eq 0 ]
    [ "$REQUIREMENT_NUMBER" = "1" ]
    [ -n "$REQUIREMENT_TITLE" ]
    [ ${#REQUIRED_PERMISSIONS[@]} -gt 0 ]
}

@test "load_requirement_config fails with missing configuration" {
    run load_requirement_config "99"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Configuration file not found" ]]
}
```

**tests/unit/test_gcp_html_report.sh:**
```bash
#!/usr/bin/env bats

load helpers/test_helpers

setup() {
    source_test_libraries
    setup_environment
    export TEST_REPORT_FILE="/tmp/test_report_$$.html"
}

teardown() {
    cleanup_test_environment
    rm -f "$TEST_REPORT_FILE"
}

@test "initialize_report creates valid HTML structure" {
    run initialize_report "1" "Test Report Title"
    [ "$status" -eq 0 ]
    [ -f "$REPORT_FILE" ]
    
    # Verify HTML structure
    grep -q "<!DOCTYPE html>" "$REPORT_FILE"
    grep -q "<title>Test Report Title</title>" "$REPORT_FILE"
    grep -q "class=\"header\"" "$REPORT_FILE"
}

@test "add_section creates proper section structure" {
    initialize_report "1" "Test Report"
    
    run add_section "Test Section"
    [ "$status" -eq 0 ]
    
    # Verify section was added
    grep -q "<h2>Test Section</h2>" "$REPORT_FILE"
    grep -q "class=\"section\"" "$REPORT_FILE"
}

@test "add_check_result formats different status types correctly" {
    initialize_report "1" "Test Report"
    add_section "Test Section"
    
    # Test PASS result
    run add_check_result "PASS" "Test Check" "Check description" "Details"
    [ "$status" -eq 0 ]
    grep -q "class=\"pass\"" "$REPORT_FILE"
    grep -q "\\[✓\\] Test Check" "$REPORT_FILE"
    
    # Test FAIL result
    run add_check_result "FAIL" "Failed Check" "Failure description"
    [ "$status" -eq 0 ]
    grep -q "class=\"fail\"" "$REPORT_FILE"
    grep -q "\\[✗\\] Failed Check" "$REPORT_FILE"
    
    # Verify counters updated
    [ "$passed_checks" -eq 1 ]
    [ "$failed_checks" -eq 1 ]
}

@test "add_summary_metrics calculates percentages correctly" {
    initialize_report "1" "Test Report"
    passed_checks=8
    failed_checks=2
    
    run add_summary_metrics
    [ "$status" -eq 0 ]
    
    # Verify summary contains correct calculations
    grep -q "Total Checks Performed.*10" "$REPORT_FILE"
    grep -q "Passed Checks.*8" "$REPORT_FILE"
    grep -q "Failed Checks.*2" "$REPORT_FILE"
    grep -q "Compliance Percentage.*80%" "$REPORT_FILE"
}

@test "finalize_report completes HTML structure" {
    initialize_report "1" "Test Report"
    
    run finalize_report "false"
    [ "$status" -eq 0 ]
    
    # Verify HTML is properly closed
    grep -q "</html>" "$REPORT_FILE"
    
    # Verify scope information was updated
    grep -q "scope-info" "$REPORT_FILE"
}
```

#### 7.2.2 Configuration Testing

**tests/unit/test_configuration.sh:**
```bash
#!/usr/bin/env bats

load helpers/test_helpers

@test "configuration template system generates valid configs" {
    local test_data_file="test_generation_data.json"
    create_test_generation_data "$test_data_file"
    
    run generate_config_from_template "$test_data_file"
    [ "$status" -eq 0 ]
    
    # Verify generated configuration is valid
    source "config/requirement_test.conf"
    [ "$REQUIREMENT_NUMBER" = "test" ]
    [ ${#REQUIRED_PERMISSIONS[@]} -gt 0 ]
}

@test "configuration validation catches syntax errors" {
    create_invalid_config "config/invalid_test.conf"
    
    run validate_config_format "config/invalid_test.conf"
    [ "$status" -eq 1 ]
    [[ "$output" =~ "syntax errors" ]]
}

@test "environment variable overrides work correctly" {
    export GCP_PCI_REQ1_MIN_COMPLIANCE_PERCENTAGE=95
    export GCP_PCI_REQ1_API_TIMEOUT=600
    
    load_requirement_config "1"
    apply_config_overrides "1"
    
    [ "$MIN_COMPLIANCE_PERCENTAGE" = "95" ]
    [ "$API_TIMEOUT" = "600" ]
}
```

### 7.3 Integration Testing Framework

#### 7.3.1 End-to-End Testing

**tests/integration/test_end_to_end.sh:**
```bash
#!/usr/bin/env bats

load helpers/test_helpers

setup() {
    setup_integration_environment
    export TEST_PROJECT="gcp-pci-test-project"
    export TEST_ORG="123456789012"
}

@test "complete assessment workflow for single project" {
    # Run full assessment
    run ./check_gcp_pci_requirement1.sh -p "$TEST_PROJECT" -r
    [ "$status" -eq 0 ]
    
    # Verify report was generated
    local report_file=$(find /tmp -name "pci_req1_report_*.html" -type f | head -n1)
    [ -f "$report_file" ]
    
    # Verify report contains expected content
    grep -q "PCI DSS Requirement 1" "$report_file"
    grep -q "Assessment Summary" "$report_file"
    
    # Verify compliance results are present
    grep -E "(PASS|FAIL|WARN)" "$report_file" | wc -l | [ $(cat) -gt 0 ]
}

@test "organization scope assessment processes multiple projects" {
    # Mock organization with multiple projects
    mock_organization_projects "$TEST_ORG" "project-1 project-2 project-3"
    
    run ./check_gcp_pci_requirement2.sh -o "$TEST_ORG" -r
    [ "$status" -eq 0 ]
    
    # Verify multi-project processing
    [[ "$output" =~ "Assessment scope: 3 project" ]]
    [[ "$output" =~ "project-1" ]]
    [[ "$output" =~ "project-2" ]]
    [[ "$output" =~ "project-3" ]]
}

@test "error handling works correctly with invalid permissions" {
    # Mock permission failures
    mock_gcloud_permission_errors
    
    run ./check_gcp_pci_requirement3.sh -p "$TEST_PROJECT"
    
    # Should prompt for limited permissions or fail gracefully
    [[ "$output" =~ "Limited permissions detected" ]] || [ "$status" -eq 1 ]
    [[ "$output" =~ "permission" ]]
}

@test "CLI argument compatibility maintained" {
    local test_args=(
        "-s"
        "-p $TEST_PROJECT"
        "-o $TEST_ORG"
        "-s -r"
        "-h"
        "--help"
    )
    
    for args in "${test_args[@]}"; do
        run ./check_gcp_pci_requirement1.sh $args
        # Should not fail with argument parsing errors
        [[ ! "$output" =~ "Unknown parameter" ]]
    done
}
```

#### 7.3.2 Migration Compatibility Testing

**tests/integration/test_migration_compatibility.sh:**
```bash
#!/usr/bin/env bats

load helpers/test_helpers

@test "new scripts produce identical results to legacy scripts" {
    local requirements=(1 2 3 4 5 6 7 8)
    
    for req in "${requirements[@]}"; do
        if [[ -f "legacy/check_gcp_pci_requirement${req}.sh" ]] && \
           [[ -f "check_gcp_pci_requirement${req}.sh" ]]; then
            
            # Run legacy script
            local legacy_output=$(timeout 300 bash "legacy/check_gcp_pci_requirement${req}.sh" -p "$TEST_PROJECT" -r 2>&1)
            local legacy_exit=$?
            
            # Run new script
            local new_output=$(timeout 300 bash "check_gcp_pci_requirement${req}.sh" -p "$TEST_PROJECT" -r 2>&1)
            local new_exit=$?
            
            # Compare results
            compare_assessment_outputs "$legacy_output" "$new_output" "$legacy_exit" "$new_exit"
        fi
    done
}

@test "legacy argument formats still work" {
    # Test legacy argument patterns that should be automatically converted
    run ./check_gcp_pci_requirement1.sh --single --no-browser
    [ "$status" -eq 0 ]
    
    run ./check_gcp_pci_requirement1.sh --project-id "$TEST_PROJECT" --no-browser
    [ "$status" -eq 0 ]
}
```

### 7.4 Performance Testing Framework

#### 7.4.1 Benchmark Suite

**tests/performance/benchmark_suite.sh:**
```bash
#!/bin/bash
# Comprehensive performance benchmarking suite

run_performance_benchmark() {
    local requirement_num="$1"
    local test_project="$2"
    local iterations="${3:-5}"
    
    echo "Running performance benchmark for requirement $requirement_num"
    
    local script_path="check_gcp_pci_requirement${requirement_num}.sh"
    local legacy_path="legacy/check_gcp_pci_requirement${requirement_num}.sh"
    
    # Benchmark new script
    local new_times=()
    for i in $(seq 1 $iterations); do
        local start_time=$(date +%s.%N)
        bash "$script_path" -p "$test_project" -r > /dev/null 2>&1
        local end_time=$(date +%s.%N)
        local duration=$(echo "$end_time - $start_time" | bc -l)
        new_times+=("$duration")
    done
    
    # Benchmark legacy script (if available)
    local legacy_times=()
    if [[ -f "$legacy_path" ]]; then
        for i in $(seq 1 $iterations); do
            local start_time=$(date +%s.%N)
            bash "$legacy_path" -p "$test_project" -r > /dev/null 2>&1
            local end_time=$(date +%s.%N)
            local duration=$(echo "$end_time - $start_time" | bc -l)
            legacy_times+=("$duration")
        done
    fi
    
    # Calculate statistics
    local new_avg=$(calculate_average "${new_times[@]}")
    local new_stddev=$(calculate_stddev "${new_times[@]}")
    
    echo "New Script Performance:"
    echo "  Average: ${new_avg}s"
    echo "  Std Dev: ${new_stddev}s"
    echo "  Times: ${new_times[*]}"
    
    if [[ ${#legacy_times[@]} -gt 0 ]]; then
        local legacy_avg=$(calculate_average "${legacy_times[@]}")
        local legacy_stddev=$(calculate_stddev "${legacy_times[@]}")
        local improvement=$(echo "scale=2; (($legacy_avg - $new_avg) / $legacy_avg) * 100" | bc -l)
        
        echo "Legacy Script Performance:"
        echo "  Average: ${legacy_avg}s"
        echo "  Std Dev: ${legacy_stddev}s"
        echo "  Performance Change: ${improvement}%"
        
        # Validate performance target (<10% degradation)
        if (( $(echo "$improvement >= -10" | bc -l) )); then
            echo "PASS: Performance target met"
            return 0
        else
            echo "FAIL: Performance degradation exceeds 10%"
            return 1
        fi
    fi
    
    return 0
}

calculate_average() {
    local sum=0
    local count=$#
    for value in "$@"; do
        sum=$(echo "$sum + $value" | bc -l)
    done
    echo "scale=3; $sum / $count" | bc -l
}

calculate_stddev() {
    local values=("$@")
    local mean=$(calculate_average "${values[@]}")
    local sum_sq_diff=0
    
    for value in "${values[@]}"; do
        local diff=$(echo "$value - $mean" | bc -l)
        local sq_diff=$(echo "$diff * $diff" | bc -l)
        sum_sq_diff=$(echo "$sum_sq_diff + $sq_diff" | bc -l)
    done
    
    local variance=$(echo "scale=6; $sum_sq_diff / ${#values[@]}" | bc -l)
    echo "scale=3; sqrt($variance)" | bc -l
}
```

#### 7.4.2 Scalability Testing

**tests/performance/scalability_tests.sh:**
```bash
#!/bin/bash
# Test performance scaling with multiple projects

test_project_scalability() {
    local max_projects=100
    local project_increments=(1 5 10 25 50 100)
    
    echo "Testing scalability across multiple projects"
    
    for project_count in "${project_increments[@]}"; do
        if [[ $project_count -gt $max_projects ]]; then
            continue
        fi
        
        echo "Testing with $project_count projects"
        
        # Create mock organization with specified number of projects
        local test_org="test-org-$$"
        local test_projects=()
        for i in $(seq 1 $project_count); do
            test_projects+=("test-project-$i")
        done
        
        mock_organization_projects "$test_org" "${test_projects[*]}"
        
        # Measure execution time
        local start_time=$(date +%s.%N)
        ./check_gcp_pci_requirement1.sh -o "$test_org" -r > /dev/null 2>&1
        local end_time=$(date +%s.%N)
        local duration=$(echo "$end_time - $start_time" | bc -l)
        
        echo "  Projects: $project_count, Time: ${duration}s"
        
        # Calculate projects per second
        local projects_per_second=$(echo "scale=2; $project_count / $duration" | bc -l)
        echo "  Throughput: ${projects_per_second} projects/second"
        
        cleanup_mock_organization "$test_org"
    done
}

test_memory_usage() {
    local test_project="test-memory-project"
    local script="check_gcp_pci_requirement1.sh"
    
    echo "Testing memory usage patterns"
    
    # Run script with memory monitoring
    local pid
    bash "$script" -p "$test_project" -r &
    pid=$!
    
    # Monitor memory usage
    local max_memory=0
    while kill -0 $pid 2>/dev/null; do
        local current_memory=$(ps -o rss= -p $pid | tr -d ' ')
        if [[ -n "$current_memory" ]] && [[ $current_memory -gt $max_memory ]]; then
            max_memory=$current_memory
        fi
        sleep 0.5
    done
    
    wait $pid
    local exit_code=$?
    
    # Convert KB to MB
    local max_memory_mb=$(echo "scale=2; $max_memory / 1024" | bc -l)
    
    echo "Maximum memory usage: ${max_memory_mb} MB"
    
    # Validate memory target (<100MB)
    if (( $(echo "$max_memory_mb <= 100" | bc -l) )); then
        echo "PASS: Memory usage within target"
        return 0
    else
        echo "FAIL: Memory usage exceeds 100MB target"
        return 1
    fi
}
```

### 7.5 Continuous Integration and Quality Gates

#### 7.5.1 Automated Test Pipeline

**scripts/run_test_suite.sh:**
```bash
#!/bin/bash
# Complete automated test pipeline for CI/CD

run_complete_test_suite() {
    local test_project="${1:-gcp-pci-test-project}"
    local exit_code=0
    
    echo "Starting complete test suite execution"
    echo "Test project: $test_project"
    echo "Timestamp: $(date)"
    
    # 1. Unit Tests
    echo "=== Running Unit Tests ==="
    if ! run_unit_tests; then
        echo "FAIL: Unit tests failed"
        exit_code=1
    else
        echo "PASS: Unit tests completed"
    fi
    
    # 2. Integration Tests
    echo "=== Running Integration Tests ==="
    if ! run_integration_tests "$test_project"; then
        echo "FAIL: Integration tests failed"
        exit_code=1
    else
        echo "PASS: Integration tests completed"
    fi
    
    # 3. Performance Tests
    echo "=== Running Performance Tests ==="
    if ! run_performance_tests "$test_project"; then
        echo "FAIL: Performance tests failed"
        exit_code=1
    else
        echo "PASS: Performance tests completed"
    fi
    
    # 4. Compatibility Tests
    echo "=== Running Compatibility Tests ==="
    if ! run_compatibility_tests "$test_project"; then
        echo "FAIL: Compatibility tests failed"
        exit_code=1
    else
        echo "PASS: Compatibility tests completed"
    fi
    
    # 5. Generate Test Report
    generate_test_report
    
    echo "Test suite execution completed"
    return $exit_code
}

run_unit_tests() {
    local test_files=(
        "tests/unit/test_gcp_common.sh"
        "tests/unit/test_gcp_html_report.sh"
        "tests/unit/test_gcp_permissions.sh"
        "tests/unit/test_gcp_scope_mgmt.sh"
        "tests/unit/test_configuration.sh"
    )
    
    local failed_tests=0
    for test_file in "${test_files[@]}"; do
        echo "Running $test_file"
        if ! bats "$test_file"; then
            ((failed_tests++))
        fi
    done
    
    if [[ $failed_tests -eq 0 ]]; then
        echo "All unit tests passed"
        return 0
    else
        echo "$failed_tests unit test files failed"
        return 1
    fi
}

generate_test_report() {
    local report_file="test_report_$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>GCP PCI DSS Shared Library Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .pass { color: #28a745; }
        .fail { color: #dc3545; }
        .summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>Test Execution Report</h1>
    <div class="summary">
        <h2>Test Summary</h2>
        <p><strong>Execution Date:</strong> $(date)</p>
        <p><strong>Test Environment:</strong> $TEST_PROJECT</p>
        <p><strong>Total Test Suites:</strong> 4</p>
        <p><strong>Overall Status:</strong> $([ $exit_code -eq 0 ] && echo "PASS" || echo "FAIL")</p>
    </div>
    <!-- Additional test details would be populated here -->
</body>
</html>
EOF
    
    echo "Test report generated: $report_file"
}
```

#### 7.5.2 Quality Gates and Acceptance Criteria

**Quality Gate Requirements:**
- **Unit Test Coverage:** ≥90% for all shared libraries
- **Integration Test Success:** 100% pass rate for core workflows
- **Performance Benchmarks:** <10% degradation from baseline
- **Memory Usage:** <100MB peak memory per script
- **Compatibility Tests:** 100% pass rate for CLI arguments and output format
- **Security Scans:** No high or critical vulnerabilities
- **Documentation Coverage:** 100% API function documentation

**Acceptance Criteria Validation:**
```bash
#!/bin/bash
# validate_quality_gates.sh

validate_quality_gates() {
    local overall_status=0
    
    # Check unit test coverage
    local coverage=$(calculate_test_coverage)
    if (( $(echo "$coverage >= 90" | bc -l) )); then
        echo "PASS: Unit test coverage: ${coverage}%"
    else
        echo "FAIL: Unit test coverage below 90%: ${coverage}%"
        overall_status=1
    fi
    
    # Check performance benchmarks
    if validate_performance_benchmarks; then
        echo "PASS: Performance benchmarks within acceptable range"
    else
        echo "FAIL: Performance benchmarks failed"
        overall_status=1
    fi
    
    # Check documentation coverage
    if validate_documentation_coverage; then
        echo "PASS: Documentation coverage complete"
    else
        echo "FAIL: Documentation coverage incomplete"
        overall_status=1
    fi
    
    return $overall_status
}
```

This comprehensive testing strategy ensures the shared library architecture maintains high quality, performance, and compatibility standards throughout development and deployment.

## 8. Error Handling

### 8.1 Error Handling Principles

**Centralized Error Management:**
- All errors flow through standardized error handling functions
- Consistent error codes and messages across all modules
- Graceful degradation for non-critical failures

**User-Friendly Error Messages:**
- Clear, actionable error descriptions
- Suggested remediation steps
- Context-aware error reporting

### 8.2 Error Categories and Codes

```bash
# Error code definitions
readonly ERROR_CODES=(
    [1]="GENERAL_ERROR"
    [2]="AUTHENTICATION_ERROR" 
    [3]="PERMISSION_ERROR"
    [4]="NETWORK_ERROR"
    [5]="CONFIGURATION_ERROR"
    [10]="INVALID_ARGUMENTS"
    [11]="MISSING_PREREQUISITES"
    [20]="PROJECT_ACCESS_ERROR"
    [21]="API_QUOTA_ERROR"
    [30]="REPORT_GENERATION_ERROR"
)
```

### 8.3 Error Handling Functions

```bash
# Enhanced error handling with logging and recovery
handle_error() {
    local error_code="$1"
    local error_message="$2"
    local recovery_suggestion="${3:-}"
    
    # Log error details
    log_error "$error_code" "$error_message"
    
    # Print user-friendly error
    print_status "FAIL" "Error ${error_code}: $error_message"
    
    if [[ -n "$recovery_suggestion" ]]; then
        print_status "INFO" "Suggestion: $recovery_suggestion"
    fi
    
    # Add error to report if report is initialized
    if [[ -n "$REPORT_FILE" && -f "$REPORT_FILE" ]]; then
        add_check_result "FAIL" "System Error" "$error_message" "$recovery_suggestion"
    fi
    
    return "$error_code"
}

# Graceful error recovery with partial results
attempt_with_fallback() {
    local primary_command="$1"
    local fallback_command="$2"
    local error_message="$3"
    
    if eval "$primary_command"; then
        return 0
    else
        print_status "WARN" "$error_message - attempting fallback"
        eval "$fallback_command"
    fi
}
```

### 8.4 Logging Framework

```bash
# Multi-level logging with file and console output
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_file="${WORK_DIR}/assessment.log"
    
    # Write to log file
    echo "[$timestamp] [$level] $message" >> "$log_file"
    
    # Conditional console output based on verbosity
    case "$level" in
        "ERROR"|"WARN")
            echo "[$level] $message" >&2
            ;;
        "INFO")
            [[ "$VERBOSE" == "true" ]] && echo "[$level] $message"
            ;;
        "DEBUG")
            [[ "$DEBUG" == "true" ]] && echo "[$level] $message"
            ;;
    esac
}

# Convenience logging functions
log_error() { log_message "ERROR" "$*"; }
log_warn() { log_message "WARN" "$*"; }
log_info() { log_message "INFO" "$*"; }
log_debug() { log_message "DEBUG" "$*"; }
```

---

**Document Status:** Complete Architecture Design  
**Total APIs Designed:** 26 functions across 4 modules  
**Implementation Ready:** Yes - All specifications complete for development

---

**Document Status:** Initial Framework Created  
**Next Steps:** Complete module API designs through subtasks ST-2 through ST-9