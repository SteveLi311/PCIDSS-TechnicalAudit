# GCP PCI DSS Shared Library Integration Guide

## Overview

This guide covers integration with the complete GCP PCI DSS shared library framework consisting of **4 specialized libraries**:

- **`gcp_common.sh`** - Core functionality and environment management (11 functions)
- **`gcp_permissions.sh`** - Authentication and permission management (9 functions)
- **`gcp_html_report.sh`** - HTML report generation and formatting (11 functions)
- **`gcp_scope_mgmt.sh`** - Assessment scope management and validation (5 functions)

**Total Framework:** 32 functions providing unified infrastructure for all 8 PCI DSS requirement scripts.

## Quick Start

### 1. Complete Framework Integration Pattern

```bash
#!/usr/bin/env bash

# Load complete shared library framework
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh"         # Core functionality
source "$LIB_DIR/gcp_permissions.sh"    # Permission management
source "$LIB_DIR/gcp_html_report.sh"    # HTML reporting
source "$LIB_DIR/gcp_scope_mgmt.sh"     # Scope management

# Setup environment and parse arguments
setup_environment "my_assessment.log"
parse_common_arguments "$@"

# Initialize permission framework
init_permissions_framework

# Setup assessment scope (project or organization)
setup_assessment_scope

# Register required permissions
register_required_permissions "1" \
    "compute.instances.list" \
    "compute.firewalls.list" \
    "resourcemanager.projects.get"

# Check permissions and handle limited access
if ! check_all_permissions; then
    if ! prompt_continue_limited; then
        exit 1
    fi
fi

# Initialize HTML report with scope-aware context
OUTPUT_FILE="pci_requirement1_$(date +%Y%m%d_%H%M%S).html"
initialize_report "PCI DSS Requirement 1 Assessment" "$ASSESSMENT_SCOPE"

# Your assessment logic with reporting integration here...
projects=$(get_projects_in_scope)
for project in $projects; do
    add_section "project_${project}" "Project: ${project}" "Assessment for project ${project}"
    # ... perform checks and add results ...
    close_section
done

# Finalize report with metrics
add_summary_metrics 10 8 1 1 0
finalize_report

print_status "PASS" "Assessment completed: $OUTPUT_FILE"
```

### 2. Basic Integration Pattern (Legacy 2-Library)

For simpler scripts that don't need HTML reporting or scope management:

```bash
#!/usr/bin/env bash

# Load core libraries only
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh"
source "$LIB_DIR/gcp_permissions.sh"

# Setup environment
setup_environment "my_assessment.log"
parse_common_arguments "$@"

# Register required permissions
register_required_permissions "1" \
    "compute.instances.list" \
    "compute.firewalls.list" \
    "resourcemanager.projects.get"

# Check permissions and handle limited access
if ! check_all_permissions; then
    if ! prompt_continue_limited; then
        exit 1
    fi
fi

# Validate scope
validate_scope_permissions

# Your assessment logic here...
```

## Advanced Integration Patterns

### 1. Organization-Wide Assessment with Complete Framework

```bash
#!/usr/bin/env bash
# Complete framework organization assessment example

# Load complete shared library framework
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh"
source "$LIB_DIR/gcp_permissions.sh"
source "$LIB_DIR/gcp_html_report.sh"
source "$LIB_DIR/gcp_scope_mgmt.sh"

main() {
    # 1. Environment and argument setup
    setup_environment "org_assessment.log"
    parse_common_arguments "$@"
    
    # 2. Initialize frameworks
    init_permissions_framework
    
    # 3. Setup organization scope
    setup_assessment_scope
    
    # 4. Register comprehensive permissions for multi-project assessment
    local permissions=(
        "compute.instances.list"
        "compute.firewalls.list"
        "compute.networks.list"
        "resourcemanager.projects.list"
        "resourcemanager.organizations.get"
    )
    register_required_permissions "1" "${permissions[@]}"
    
    # 5. Handle permission scenarios gracefully
    if ! check_all_permissions; then
        local coverage=$(get_permission_coverage)
        print_status "WARN" "Limited permissions: ${coverage}% coverage"
        
        if [[ $coverage -lt 70 ]]; then
            print_status "FAIL" "Insufficient permissions for organization assessment"
            display_permission_guidance
            exit 1
        fi
        
        if ! prompt_continue_limited; then
            exit 0
        fi
    fi
    
    # 6. Initialize HTML report for organization scope
    OUTPUT_FILE="organization_pci_assessment_$(date +%Y%m%d_%H%M%S).html"
    initialize_report "Organization PCI DSS Assessment" "organization"
    
    # 7. Get all projects in organization scope
    local projects=$(get_projects_in_scope)
    local total_projects=$(echo "$projects" | wc -w)
    print_status "INFO" "Assessing $total_projects projects in organization"
    
    # 8. Process each project with cross-library integration
    local passed=0 failed=0 warnings=0 manual=0
    
    for project in $projects; do
        print_status "INFO" "Processing project: $project"
        
        # Create project section in HTML report
        add_section "project_${project}" "Project: ${project}" "Assessment results for project ${project}"
        
        # Build scope-aware gcloud commands
        local instances_cmd=$(build_gcloud_command "gcloud compute instances list --format='json'" "$project")
        local firewall_cmd=$(build_gcloud_command "gcloud compute firewall-rules list --format='json'" "$project")
        
        # Execute assessment checks with error handling
        if eval "$instances_cmd" >/dev/null 2>&1; then
            add_check_result "Instance Inventory" "PASS" "Successfully accessed compute instances" ""
            ((passed++))
        else
            add_check_result "Instance Inventory" "FAIL" "Cannot access compute instances" "Check compute.instances.list permission"
            ((failed++))
        fi
        
        if eval "$firewall_cmd" >/dev/null 2>&1; then
            add_check_result "Firewall Rules Access" "PASS" "Successfully accessed firewall rules" ""
            ((passed++))
        else
            add_check_result "Firewall Rules Access" "WARN" "Limited firewall access" "May impact assessment completeness"
            ((warnings++))
        fi
        
        # Add manual verification requirements
        add_manual_check "Network Segmentation" "PCI DSS 1.2.1" "Manually verify network segmentation between projects"
        ((manual++))
        
        close_section
    done
    
    # 9. Add organization-level summary with aggregated data
    add_section "organization_summary" "Organization Summary" "Cross-project assessment summary"
    
    # Aggregate cross-project data
    aggregate_cross_project_data "instances" "json" > /tmp/org_instances.json
    local total_instances=$(jq -s 'add | length' /tmp/org_instances.json 2>/dev/null || echo "Unknown")
    
    add_check_result "Total Infrastructure" "INFO" "Organization has $total_instances total instances across $total_projects projects" ""
    add_check_result "Organization Scope" "PASS" "Successfully assessed all projects in organization" ""
    
    close_section
    
    # 10. Finalize report with comprehensive metrics
    local total_checks=$((passed + failed + warnings + manual))
    add_summary_metrics $total_checks $passed $failed $warnings $manual
    finalize_report
    
    # 11. Cleanup and final status
    cleanup_temp_files
    print_status "PASS" "Organization assessment completed: $OUTPUT_FILE"
    print_status "INFO" "Summary: $passed passed, $failed failed, $warnings warnings, $manual manual checks"
}

main "$@"
```

### 2. Project-Scope Assessment with HTML Reporting

```bash
#!/usr/bin/env bash
# Project-focused assessment with detailed HTML reporting

LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh"
source "$LIB_DIR/gcp_permissions.sh"
source "$LIB_DIR/gcp_html_report.sh"

main() {
    # Basic setup
    setup_environment "project_assessment.log"
    parse_common_arguments "$@"
    
    # Permission setup
    init_permissions_framework
    register_required_permissions "1" \
        "compute.instances.list" \
        "compute.firewalls.list" \
        "compute.networks.list"
    
    check_all_permissions || prompt_continue_limited || exit 1
    
    # HTML report initialization
    OUTPUT_FILE="project_assessment_$(date +%Y%m%d_%H%M%S).html"
    initialize_report "Project PCI DSS Assessment" "project"
    
    # Network Security Assessment Section
    add_section "network_security" "Network Security Controls" "PCI DSS Requirement 1 - Network Security"
    
    # Perform detailed checks with comprehensive reporting
    assess_firewall_rules
    assess_network_configuration
    assess_instance_security
    
    close_section
    
    # Finalize with metrics
    add_summary_metrics 15 12 2 1 0
    finalize_report
    
    print_status "PASS" "Project assessment completed: $OUTPUT_FILE"
}

assess_firewall_rules() {
    print_status "INFO" "Assessing firewall rules..."
    
    local firewall_rules=$(gcloud compute firewall-rules list --format='json' 2>/dev/null)
    
    if [[ $? -eq 0 && -n "$firewall_rules" ]]; then
        local rule_count=$(echo "$firewall_rules" | jq length 2>/dev/null || echo "0")
        add_check_result "Firewall Rules Inventory" "PASS" "Found $rule_count firewall rules" ""
        
        # Check for insecure rules
        local insecure_rules=$(echo "$firewall_rules" | jq -r '.[] | select(.sourceRanges[]? == "0.0.0.0/0") | .name' 2>/dev/null)
        
        if [[ -n "$insecure_rules" ]]; then
            add_check_result "Public Access Check" "FAIL" "Found rules allowing access from 0.0.0.0/0: $insecure_rules" "Restrict source IP ranges"
        else
            add_check_result "Public Access Check" "PASS" "No overly permissive firewall rules found" ""
        fi
    else
        add_check_result "Firewall Rules Inventory" "FAIL" "Cannot access firewall rules" "Check compute.firewalls.list permission"
    fi
}

assess_network_configuration() {
    print_status "INFO" "Assessing network configuration..."
    
    local networks=$(gcloud compute networks list --format='json' 2>/dev/null)
    
    if [[ $? -eq 0 && -n "$networks" ]]; then
        local network_count=$(echo "$networks" | jq length 2>/dev/null || echo "0")
        add_check_result "Network Inventory" "PASS" "Found $network_count networks" ""
        
        # Check for default network
        local has_default=$(echo "$networks" | jq -r '.[] | select(.name == "default") | .name' 2>/dev/null)
        
        if [[ -n "$has_default" ]]; then
            add_check_result "Default Network Check" "WARN" "Default network exists" "Consider using custom networks for better security"
        else
            add_check_result "Default Network Check" "PASS" "No default network found - using custom networks" ""
        fi
    else
        add_check_result "Network Inventory" "FAIL" "Cannot access network information" "Check compute.networks.list permission"
    fi
}

assess_instance_security() {
    print_status "INFO" "Assessing instance security..."
    
    local instances=$(gcloud compute instances list --format='json' 2>/dev/null)
    
    if [[ $? -eq 0 && -n "$instances" ]]; then
        local instance_count=$(echo "$instances" | jq length 2>/dev/null || echo "0")
        add_check_result "Instance Inventory" "PASS" "Found $instance_count compute instances" ""
        
        # Check for instances with external IPs
        local external_instances=$(echo "$instances" | jq -r '.[] | select(.networkInterfaces[]?.accessConfigs[]?.type == "ONE_TO_ONE_NAT") | .name' 2>/dev/null)
        
        if [[ -n "$external_instances" ]]; then
            add_check_result "External IP Check" "WARN" "Instances with external IPs: $(echo $external_instances | tr '\n' ' ')" "Review necessity of external IP addresses"
        else
            add_check_result "External IP Check" "PASS" "No instances with external IP addresses" ""
        fi
    else
        add_check_result "Instance Inventory" "FAIL" "Cannot access instance information" "Check compute.instances.list permission"
    fi
}

main "$@"
```

### 3. Selective Library Loading for Performance

```bash
#!/usr/bin/env bash
# Performance-optimized integration with selective library loading

LIB_DIR="$(dirname "$0")/lib"

# Always load core library first
source "$LIB_DIR/gcp_common.sh"

# Conditionally load additional libraries based on script needs
if [[ "$ENABLE_PERMISSION_CHECKS" == "true" ]]; then
    source "$LIB_DIR/gcp_permissions.sh"
fi

if [[ "$GENERATE_HTML_REPORT" == "true" ]]; then
    source "$LIB_DIR/gcp_html_report.sh"
fi

if [[ "$MULTI_PROJECT_SCOPE" == "true" ]]; then
    source "$LIB_DIR/gcp_scope_mgmt.sh"
fi

main() {
    setup_environment "selective_assessment.log"
    parse_common_arguments "$@"
    
    # Use framework features based on loaded libraries
    if [[ "$GCP_PERMISSIONS_LOADED" == "true" ]]; then
        init_permissions_framework
        register_required_permissions "1" "compute.instances.list"
        check_all_permissions || exit 1
    fi
    
    if [[ "$GCP_SCOPE_MGMT_LOADED" == "true" ]]; then
        setup_assessment_scope
        projects=$(get_projects_in_scope)
    else
        projects="$PROJECT_ID"
    fi
    
    if [[ "$GCP_HTML_REPORT_LOADED" == "true" ]]; then
        OUTPUT_FILE="assessment_$(date +%Y%m%d_%H%M%S).html"
        initialize_report "PCI DSS Assessment" "project"
    fi
    
    # Perform assessment...
    for project in $projects; do
        print_status "INFO" "Assessing project: $project"
        # Assessment logic here...
    done
    
    if [[ "$GCP_HTML_REPORT_LOADED" == "true" ]]; then
        finalize_report
        print_status "PASS" "HTML report generated: $OUTPUT_FILE"
    fi
}

main "$@"
```

## Migration from Legacy Scripts

### Complete Migration: Legacy to 4-Library Framework

#### Before (Legacy Pattern):
```bash
#!/usr/bin/env bash
# Legacy script with duplicated functionality

# Manual color definitions and logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_message() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error_message() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Manual argument parsing
PROJECT_ID=""
SCOPE=""
OUTPUT_DIR=""
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--project) PROJECT_ID="$2"; shift 2 ;;
        -s|--scope) SCOPE="$2"; shift 2 ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -h|--help) show_help; exit 0 ;;
        *) error_message "Unknown option: $1"; exit 1 ;;
    esac
done

# Manual permission checking
check_permissions() {
    if ! gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
        error_message "Cannot access project $PROJECT_ID"
        return 1
    fi
    
    if ! gcloud compute instances list --project="$PROJECT_ID" >/dev/null 2>&1; then
        error_message "Missing compute.instances.list permission"
        return 1
    fi
}

# Manual HTML generation
generate_html_report() {
    local output_file="$1"
    cat > "$output_file" << EOF
<!DOCTYPE html>
<html>
<head><title>Assessment Report</title></head>
<body>
<h1>PCI DSS Assessment Report</h1>
<!-- Manual HTML construction -->
EOF
}

# Manual project enumeration for organization scope
get_organization_projects() {
    if [[ "$SCOPE" == "organization" ]]; then
        gcloud projects list --format="value(projectId)" 2>/dev/null
    else
        echo "$PROJECT_ID"
    fi
}

# Main assessment logic
main() {
    log_message "Starting assessment..."
    
    check_permissions || exit 1
    
    local projects=$(get_organization_projects)
    local output_file="assessment_$(date +%Y%m%d_%H%M%S).html"
    
    generate_html_report "$output_file"
    
    for project in $projects; do
        log_message "Assessing project: $project"
        # Assessment logic with manual error handling...
    done
    
    log_message "Assessment completed: $output_file"
}

main "$@"
```

#### After (Complete 4-Library Framework):
```bash
#!/usr/bin/env bash
# Modern framework integration - same functionality, much cleaner

# Load complete shared library framework
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh"         # Replaces manual colors, logging, args
source "$LIB_DIR/gcp_permissions.sh"    # Replaces manual permission checking
source "$LIB_DIR/gcp_html_report.sh"    # Replaces manual HTML generation
source "$LIB_DIR/gcp_scope_mgmt.sh"     # Replaces manual project enumeration

main() {
    # Replaces manual environment setup
    setup_environment "assessment.log"
    parse_common_arguments "$@"           # Replaces manual argument parsing
    
    # Replaces manual permission management
    init_permissions_framework
    register_required_permissions "1" \
        "compute.instances.list" \
        "resourcemanager.projects.get"
    
    check_all_permissions || prompt_continue_limited || exit 1
    
    # Replaces manual scope management
    setup_assessment_scope
    projects=$(get_projects_in_scope)     # Replaces get_organization_projects()
    
    # Replaces manual HTML generation
    OUTPUT_FILE="assessment_$(date +%Y%m%d_%H%M%S).html"
    initialize_report "PCI DSS Assessment" "$ASSESSMENT_SCOPE"
    
    # Assessment logic with integrated reporting
    for project in $projects; do
        print_status "INFO" "Assessing project: $project"  # Replaces log_message
        
        add_section "project_${project}" "Project: ${project}" "Assessment for project ${project}"
        # Assessment logic with add_check_result() calls...
        close_section
    done
    
    add_summary_metrics 10 8 1 1 0
    finalize_report                       # Replaces manual HTML finalization
    
    print_status "PASS" "Assessment completed: $OUTPUT_FILE"
    cleanup_temp_files                    # Automatic cleanup
}

main "$@"
```

### Migration Benefits

**Code Reduction:** ~70% reduction in boilerplate code (250+ lines → 75 lines)

**Feature Enhancement:**
- Professional HTML reports with interactive features
- Comprehensive permission handling with graceful degradation
- Organization-scope support with automatic project enumeration
- Unified error handling and logging
- Automatic resource cleanup
- Consistent CLI argument parsing across all scripts

**Maintenance Improvement:**
- Centralized updates through shared libraries
- Consistent behavior across all assessment scripts
- Comprehensive testing through shared library test suites
- Better error messages and user guidance

### Step-by-Step Migration Process

#### 1. Basic Framework Migration (Core + Permissions)
```bash
# Step 1: Replace environment setup and argument parsing
- # Manual setup code...
+ LIB_DIR="$(dirname "$0")/lib"
+ source "$LIB_DIR/gcp_common.sh"
+ source "$LIB_DIR/gcp_permissions.sh"
+ 
+ setup_environment "script.log"
+ parse_common_arguments "$@"
```

#### 2. Add HTML Reporting Capability
```bash
# Step 2: Add HTML reporting
+ source "$LIB_DIR/gcp_html_report.sh"
+ 
+ OUTPUT_FILE="assessment_$(date +%Y%m%d_%H%M%S).html"
+ initialize_report "Assessment Title" "project"
+ 
+ # Replace manual output with add_check_result()
- echo "PASS: Check succeeded"
+ add_check_result "Check Name" "PASS" "Check succeeded" ""
```

#### 3. Add Scope Management for Multi-Project Support
```bash
# Step 3: Add scope management
+ source "$LIB_DIR/gcp_scope_mgmt.sh"
+ 
+ setup_assessment_scope
+ projects=$(get_projects_in_scope)
+ 
+ # Replace manual project handling
- if [[ "$SCOPE" == "organization" ]]; then
-     projects=$(gcloud projects list --format="value(projectId)")
- else
-     projects="$PROJECT_ID"
- fi
```

#### 4. Integration Testing and Validation
```bash
# Step 4: Validate migration
./migrated_script.sh -h                    # Test help output
./migrated_script.sh -p PROJECT_ID         # Test project scope
./migrated_script.sh -p ORG_ID -O          # Test organization scope
./migrated_script.sh -v -p PROJECT_ID      # Test verbose mode
```

### Legacy Pattern Mapping

| Legacy Pattern | Framework Replacement | Library |
|---------------|----------------------|---------|
| Manual color definitions | `print_status()` with built-in colors | gcp_common.sh |
| Custom argument parsing | `parse_common_arguments()` | gcp_common.sh |
| Manual permission checks | `register_required_permissions()` + `check_all_permissions()` | gcp_permissions.sh |
| Manual HTML generation | `initialize_report()` + `add_check_result()` + `finalize_report()` | gcp_html_report.sh |
| Manual project enumeration | `setup_assessment_scope()` + `get_projects_in_scope()` | gcp_scope_mgmt.sh |
| Custom logging | `log_debug()` + environment setup | gcp_common.sh |
| Manual cleanup | `cleanup_temp_files()` | gcp_common.sh |
| Manual error handling | Unified error patterns + `prompt_continue_limited()` | All libraries |

## Integration Examples

### Example 1: Basic Requirement Script

```bash
#!/usr/bin/env bash
# check_gcp_pci_requirement_example.sh

# Load shared libraries
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh"
source "$LIB_DIR/gcp_permissions.sh"

main() {
    # Setup
    setup_environment "requirement_x.log"
    parse_common_arguments "$@"
    
    # Validate prerequisites
    validate_prerequisites || exit 1
    
    # Register and check permissions
    register_required_permissions "X" \
        "compute.instances.list" \
        "compute.networks.list"
    
    if ! check_all_permissions; then
        prompt_continue_limited || exit 1
    fi
    
    # Validate scope
    validate_scope_permissions || exit 1
    
    # Your assessment logic here
    print_status "INFO" "Starting Requirement X assessment..."
    
    # Cleanup
    cleanup_temp_files
}

# Help function using shared pattern
show_help() {
    cat << EOF
GCP PCI DSS Requirement X Assessment Script

Usage: $0 [OPTIONS]

Options:
    -s, --scope SCOPE       Assessment scope (project|organization)
    -p, --project ID        Target project ID
    -o, --output DIR        Output directory for reports
    -r, --report-only       Generate reports only
    -v, --verbose           Enable verbose output
    -h, --help              Display this help

Examples:
    $0 -s project -p my-project-id
    $0 -s organization -p my-org-id -v
EOF
}

# Run main function
main "$@"
```

### Example 2: Advanced Integration with Error Handling

```bash
#!/usr/bin/env bash
# Advanced integration example

# Load shared libraries with error handling
LIB_DIR="$(dirname "$0")/lib"
if [[ ! -f "$LIB_DIR/gcp_common.sh" ]]; then
    echo "Error: Shared libraries not found in $LIB_DIR" >&2
    exit 1
fi

source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1

main() {
    # Error handling for setup
    if ! setup_environment "advanced_assessment.log"; then
        print_status "FAIL" "Environment setup failed"
        exit 1
    fi
    
    # Parse arguments with error handling
    if ! parse_common_arguments "$@"; then
        show_help
        exit 1
    fi
    
    # Comprehensive permission setup
    local permissions=(
        "compute.instances.list"
        "compute.networks.list"
        "compute.firewalls.list"
        "resourcemanager.projects.get"
    )
    
    register_required_permissions "1" "${permissions[@]}"
    
    # Handle permission scenarios
    if check_all_permissions; then
        print_status "PASS" "All permissions available"
    else
        local coverage=$(get_permission_coverage)
        print_status "WARN" "Limited permissions: ${coverage}% coverage"
        
        if [[ $coverage -lt 50 ]]; then
            print_status "FAIL" "Insufficient permissions for reliable assessment"
            exit 1
        fi
        
        if ! prompt_continue_limited; then
            print_status "INFO" "Assessment cancelled by user"
            exit 0
        fi
    fi
    
    # Your assessment logic with comprehensive error handling
    perform_assessment || {
        print_status "FAIL" "Assessment failed"
        cleanup_temp_files
        exit 1
    }
    
    print_status "PASS" "Assessment completed successfully"
    cleanup_temp_files
}

perform_assessment() {
    print_status "INFO" "Performing comprehensive assessment..."
    
    # Validate scope first
    validate_scope_permissions || return 1
    
    # Your actual assessment code here
    return 0
}

main "$@"
```

## Best Practices

### 1. Library Loading Order
Always load `gcp_common.sh` first, then other libraries:
```bash
source "$LIB_DIR/gcp_common.sh"    # Must be first
source "$LIB_DIR/gcp_permissions.sh"
# source other libraries as needed
```

### 2. Error Handling
Use consistent error handling patterns:
```bash
# Good: Check return codes
if ! check_all_permissions; then
    # Handle error
fi

# Good: Use || for error handling
validate_scope_permissions || exit 1

# Avoid: Ignoring errors
check_all_permissions  # Bad - no error handling
```

### 3. Environment Setup
Always setup environment early:
```bash
main() {
    setup_environment "script_name.log"  # First thing
    parse_common_arguments "$@"           # Second thing
    # ... rest of script
}
```

### 4. Permission Management
Register all permissions at once:
```bash
# Good: All permissions registered together
register_required_permissions "1" \
    "compute.instances.list" \
    "compute.networks.list" \
    "storage.buckets.list"

# Avoid: Multiple registration calls
register_required_permissions "1" "compute.instances.list"
register_required_permissions "1" "compute.networks.list"  # Overwrites previous
```

## Troubleshooting

### Common Issues

#### 1. Library Not Found
```
Error: gcp_common.sh not found
```
**Solution:** Check LIB_DIR path and ensure libraries are in `lib/` directory.

#### 2. Function Not Available
```
bash: register_required_permissions: command not found
```
**Solution:** Ensure `gcp_permissions.sh` is loaded after `gcp_common.sh`.

#### 3. Permission Errors
```
Error: Cannot access project 'my-project'
```
**Solution:** Verify gcloud authentication and project access permissions.

### Debugging

Enable verbose mode for detailed output:
```bash
./your_script.sh -v  # Enables verbose logging
```

Check library loading:
```bash
# Verify functions are available
declare -F | grep -E "(setup_environment|check_all_permissions)"
```

## Performance Optimization

### 1. Minimal Overhead
Shared libraries add only ~0.012s overhead for loading, well within performance targets.

### 2. Function Caching
Some functions cache results to avoid repeated API calls:
```bash
# Permission checks are cached within single script execution
check_all_permissions  # Makes API calls
check_all_permissions  # Uses cached results
```

### 3. Conditional Loading
Load only required libraries:
```bash
# Only load what you need
source "$LIB_DIR/gcp_common.sh"
# Skip gcp_permissions.sh if not doing permission checks
```

## Migration Checklist

- [ ] Replace manual color definitions with shared library
- [ ] Replace custom argument parsing with `parse_common_arguments`
- [ ] Replace manual permission checking with `register_required_permissions`
- [ ] Replace custom environment setup with `setup_environment`
- [ ] Use consistent error handling with `print_status`
- [ ] Add proper cleanup with `cleanup_temp_files`
- [ ] Test all command-line options work correctly
- [ ] Verify output format matches original script
- [ ] Confirm performance is within 10% of original

## Support

For additional help:
- Check `lib/README_PERMISSIONS.md` for detailed API documentation
- Review `lib/SHARED_LIBRARY_ARCHITECTURE_DESIGN.md` for architecture details
- Examine existing integrated scripts as examples
- Run unit tests in `tests/` directory for validation