# GCP Scope Management Library Documentation

## Overview

The `gcp_scope_mgmt.sh` library provides standardized assessment scope management across all GCP PCI DSS assessment scripts. It enables seamless project and organization-level assessments with unified scope validation, project enumeration, and cross-project command execution capabilities.

## Core Functions

### Scope Configuration and Validation

#### `setup_assessment_scope()`
Configures and validates assessment scope based on CLI arguments and available permissions.
- **Returns:** 0 on success, 1 on validation failure
- **Side Effects:** Sets `ASSESSMENT_SCOPE` global variable, validates organization/project access
- **Dependencies:** Requires `gcp_common.sh` for CLI parsing and `gcloud` CLI for validation
- **Example:**
```bash
#!/usr/bin/env bash
source "$(dirname "$0")/lib/gcp_common.sh"
source "$(dirname "$0")/lib/gcp_scope_mgmt.sh"

# Parse arguments and setup scope
parse_common_arguments "$@"

# Configure assessment scope based on provided arguments
if ! setup_assessment_scope; then
    print_status "FAIL" "Failed to setup assessment scope"
    exit 1
fi

print_status "INFO" "Assessment scope configured: $ASSESSMENT_SCOPE"
```

#### `get_projects_in_scope()`
Retrieves list of projects within the configured assessment scope.
- **Returns:** 0 on success, 1 on project enumeration failure
- **Side Effects:** Outputs space-separated list of project IDs to stdout, caches results
- **Dependencies:** Requires validated assessment scope and appropriate GCP permissions
- **Example:**
```bash
# Get projects for assessment
projects=$(get_projects_in_scope)
if [[ $? -ne 0 ]]; then
    print_status "FAIL" "Failed to enumerate projects in scope"
    exit 1
fi

# Process each project
for project in $projects; do
    print_status "INFO" "Processing project: $project"
    # ... assessment logic ...
done
```

### Command Execution and Project Management

#### `build_gcloud_command(base_command, project_id)`
Constructs scope-aware gcloud commands with proper project context.
- **Parameters:**
  - `base_command`: Base gcloud command without project specification
  - `project_id`: Target project ID for command execution
- **Returns:** 0 on success, 1 on command construction failure
- **Side Effects:** Outputs properly formatted gcloud command to stdout
- **Dependencies:** Requires valid project ID and gcloud CLI availability
- **Example:**
```bash
# Build project-specific compute instances list command
project="my-gcp-project"
base_cmd="gcloud compute instances list --format='table(name,zone,status)'"
full_command=$(build_gcloud_command "$base_cmd" "$project")

print_status "INFO" "Executing: $full_command"
eval "$full_command"
```

#### `run_across_projects(command_template)`
Executes a command template across all projects in the current assessment scope.
- **Parameters:**
  - `command_template`: Command template with {PROJECT_ID} placeholder
- **Returns:** 0 if all projects succeed, 1 if any project fails
- **Side Effects:** Executes commands across projects, outputs results with project context
- **Dependencies:** Requires configured scope and project enumeration
- **Example:**
```bash
# Run firewall rules check across all projects in scope
command_template="gcloud compute firewall-rules list --project={PROJECT_ID} --format='table(name,direction,sourceRanges[])'"

if ! run_across_projects "$command_template"; then
    print_status "WARN" "Some projects failed during firewall rules assessment"
fi
```

### Data Aggregation and Results Management

#### `aggregate_cross_project_data(data_type, output_format)`
Aggregates and consolidates assessment data across multiple projects.
- **Parameters:**
  - `data_type`: Type of data to aggregate (firewall-rules, instances, etc.)
  - `output_format`: Output format (json, table, csv)
- **Returns:** 0 on success, 1 on aggregation failure
- **Side Effects:** Outputs consolidated data in specified format, creates temporary aggregation files
- **Dependencies:** Requires project-specific data collection completion
- **Example:**
```bash
# Aggregate firewall rules data across all projects
if ! aggregate_cross_project_data "firewall-rules" "json"; then
    print_status "FAIL" "Failed to aggregate firewall rules data"
    exit 1
fi

# Aggregate compute instances for summary reporting
aggregate_cross_project_data "instances" "table" > instances_summary.txt
```

## Usage Examples

### Project Scope Assessment

```bash
#!/usr/bin/env bash

# Load required libraries
source "$(dirname "$0")/lib/gcp_common.sh"
source "$(dirname "$0")/lib/gcp_scope_mgmt.sh"

# Setup environment and parse arguments
setup_environment
parse_common_arguments "$@"

# Configure project scope
if ! setup_assessment_scope; then
    print_status "FAIL" "Scope configuration failed"
    exit 1
fi

# Verify single project scope
projects=$(get_projects_in_scope)
project_count=$(echo "$projects" | wc -w)

if [[ $project_count -eq 1 ]]; then
    print_status "INFO" "Project scope assessment: $projects"
    
    # Build and execute project-specific commands
    firewall_cmd=$(build_gcloud_command "gcloud compute firewall-rules list" "$projects")
    eval "$firewall_cmd"
else
    print_status "FAIL" "Expected single project, found $project_count projects"
    exit 1
fi
```

### Organization Scope Assessment

```bash
#!/usr/bin/env bash

# Load required libraries
source "$(dirname "$0")/lib/gcp_common.sh"
source "$(dirname "$0")/lib/gcp_scope_mgmt.sh"

# Setup for organization-wide assessment
setup_environment
parse_common_arguments "$@"

# Configure organization scope
if ! setup_assessment_scope; then
    print_status "FAIL" "Organization scope configuration failed"
    exit 1
fi

# Get all projects in organization
projects=$(get_projects_in_scope)
total_projects=$(echo "$projects" | wc -w)

print_status "INFO" "Organization assessment covering $total_projects projects"

# Run assessment across all projects
firewall_template="gcloud compute firewall-rules list --project={PROJECT_ID} --format='json'"

print_status "INFO" "Collecting firewall rules across all projects..."
if ! run_across_projects "$firewall_template"; then
    print_status "WARN" "Some projects encountered errors during assessment"
fi

# Aggregate results for organization-level reporting
print_status "INFO" "Aggregating organization-wide results..."
aggregate_cross_project_data "firewall-rules" "json" > org_firewall_rules.json
```

### Integration with HTML Reporting

```bash
#!/usr/bin/env bash

# Load complete framework
source "$(dirname "$0")/lib/gcp_common.sh"
source "$(dirname "$0")/lib/gcp_scope_mgmt.sh"
source "$(dirname "$0")/lib/gcp_html_report.sh"

# Setup scope and reporting
setup_environment
parse_common_arguments "$@"
setup_assessment_scope

# Initialize HTML report based on scope
if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
    initialize_report "Organization PCI DSS Assessment" "organization"
else
    initialize_report "Project PCI DSS Assessment" "project"
fi

# Process each project with HTML reporting
projects=$(get_projects_in_scope)
for project in $projects; do
    add_section "project_${project}" "Project: ${project}" "Assessment results for project ${project}"
    
    # Build project-specific assessment commands
    instances_cmd=$(build_gcloud_command "gcloud compute instances list --format='json'" "$project")
    instances_data=$(eval "$instances_cmd" 2>/dev/null)
    
    if [[ $? -eq 0 && -n "$instances_data" ]]; then
        instance_count=$(echo "$instances_data" | jq length 2>/dev/null || echo "0")
        add_check_result \
            "Compute Instances Inventory" \
            "INFO" \
            "Found $instance_count compute instances in project $project" \
            ""
    else
        add_check_result \
            "Compute Instances Inventory" \
            "WARN" \
            "Could not retrieve instance data for project $project" \
            "Verify compute.instances.list permission"
    fi
    
    close_section
done

# Finalize report with cross-project summary
if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
    aggregate_cross_project_data "instances" "json" > /tmp/org_instances.json
    total_instances=$(jq -s 'add | length' /tmp/org_instances.json 2>/dev/null || echo "Unknown")
    
    add_section "organization_summary" "Organization Summary" "Cross-project assessment summary"
    add_check_result \
        "Total Instance Count" \
        "INFO" \
        "Organization has $total_instances total compute instances across all projects" \
        ""
    close_section
fi

finalize_report
```

## Scope Types and Behavior

### Project Scope
- **Configuration**: Requires `-p PROJECT_ID` argument
- **Validation**: Verifies project exists and is accessible
- **Project List**: Returns single project ID
- **Use Case**: Single project assessments, development environments

### Organization Scope  
- **Configuration**: Requires `-p ORG_ID` and `-O` flag
- **Validation**: Verifies organization access and enumeration permissions
- **Project List**: Returns all accessible projects in organization
- **Use Case**: Enterprise-wide assessments, compliance audits

### Auto-Detection Scope
- **Configuration**: No explicit scope arguments provided
- **Validation**: Attempts to detect current project context
- **Project List**: Returns detected project or fails with guidance
- **Use Case**: Interactive script execution, development testing

## Performance Considerations

### Project Enumeration
- **Caching**: Project lists cached during session to avoid repeated API calls
- **Large Organizations**: Organizations with >100 projects may experience slower enumeration
- **Rate Limiting**: Implements automatic retry and backoff for API rate limits
- **Parallel Execution**: `run_across_projects` uses parallel execution for improved performance

### Resource Management
- **Memory Usage**: Minimal memory footprint with streaming data processing
- **Temporary Files**: Automatic cleanup of temporary aggregation files
- **API Quotas**: Respectful of GCP API quotas with built-in throttling
- **Error Recovery**: Graceful handling of project-level failures without stopping organization assessment

## Error Handling and Recovery

### Common Error Scenarios
- **Permission Denied**: Clear guidance on required permissions for scope access
- **Project Not Found**: Validation with helpful error messages and recovery suggestions
- **Organization Access**: Specific error handling for organization enumeration failures
- **API Limitations**: Automatic retry logic for transient API failures

### Recovery Strategies
- **Partial Failures**: Continue organization assessment even if individual projects fail
- **Permission Fallbacks**: Graceful degradation when full permissions unavailable
- **Manual Override**: Support for explicit project lists when auto-enumeration fails
- **Audit Logging**: Comprehensive logging of scope decisions and failures

## Security Considerations

### Principle of Least Privilege
- **Permission Validation**: Only requests minimum required permissions for scope operations
- **Scope Boundaries**: Strict enforcement of assessment scope boundaries
- **Project Isolation**: No cross-project data leakage during aggregation
- **Credential Safety**: No credential storage or logging in scope management

### Access Control
- **Organization Access**: Validates organization-level permissions before enumeration
- **Project Access**: Per-project permission validation with graceful degradation
- **API Security**: Secure API call patterns with proper error handling
- **Audit Trail**: Complete audit trail of scope decisions and access patterns

## Cross-Library Integration

### Related Functions Across Libraries

#### Permission-Aware Scope Management  
- **`setup_assessment_scope()`** integrates with **`validate_scope_permissions()`** (gcp_permissions.sh) for scope access validation
- **`get_projects_in_scope()`** uses **`check_all_permissions()`** (gcp_permissions.sh) to validate project enumeration permissions
- **`run_across_projects()`** leverages **`prompt_continue_limited()`** (gcp_permissions.sh) for graceful permission failure handling

#### HTML Report Integration
- **`setup_assessment_scope()`** provides scope context for **`initialize_report()`** (gcp_html_report.sh) report headers
- **`get_projects_in_scope()`** enables **`add_section()`** (gcp_html_report.sh) for project-based report organization
- **`aggregate_cross_project_data()`** feeds **`add_summary_metrics()`** (gcp_html_report.sh) for organization-level metrics

#### Core Framework Integration
- **All scope functions** use **`print_status()`** (gcp_common.sh) for consistent status reporting
- **`build_gcloud_command()`** leverages **`log_debug()`** (gcp_common.sh) for command construction debugging
- **Error handling** integrates with **`cleanup_temp_files()`** (gcp_common.sh) for resource cleanup

### Recommended Function Combinations

```bash
# Complete scope-aware assessment workflow
parse_common_arguments "$@"           # gcp_common.sh - CLI argument parsing
init_permissions_framework            # gcp_permissions.sh - Permission system init
setup_assessment_scope                # gcp_scope_mgmt.sh (this library)
check_all_permissions                 # gcp_permissions.sh - Validate scope permissions
initialize_report "Assessment" "$SCOPE" # gcp_html_report.sh - Scope-aware reporting
```

### Cross-Project Assessment Pattern

```bash
# Multi-project assessment with full framework integration
setup_assessment_scope                # This library - Configure scope
projects=$(get_projects_in_scope)     # This library - Get project list
initialize_report "Org Assessment" "organization" # gcp_html_report.sh

for project in $projects; do
    # Cross-library integration per project
    add_section "project_$project" "Project: $project" # gcp_html_report.sh
    
    cmd=$(build_gcloud_command "gcloud compute instances list" "$project") # This library
    if eval "$cmd" >/dev/null 2>&1; then
        add_check_result "Instance Access" "PASS" "Project accessible" # gcp_html_report.sh
    else
        add_check_result "Instance Access" "FAIL" "Access denied" # gcp_html_report.sh
    fi
    
    close_section # gcp_html_report.sh
done

aggregate_cross_project_data "instances" "json" # This library
finalize_report # gcp_html_report.sh
```

## Dependencies

- **gcp_common.sh**: Required for environment setup, CLI parsing, and logging
- **gcp_permissions.sh**: Optional, provides scope permission validation and graceful degradation
- **gcp_html_report.sh**: Optional, enables scope-aware HTML report generation
- **gcloud CLI**: Required for GCP API interactions and authentication
- **jq**: Optional, enhances JSON data processing capabilities
- **GCP Permissions**: Specific permissions required based on scope type:
  - Project scope: `resourcemanager.projects.get`
  - Organization scope: `resourcemanager.organization.get`, `resourcemanager.projects.list`

## Integration Points

- **CLI Arguments**: Seamless integration with `gcp_common.sh` argument parsing
- **HTML Reporting**: Native integration with `gcp_html_report.sh` for scope-aware reporting
- **Permission Framework**: Coordinated with `gcp_permissions.sh` for scope-specific permission validation
- **Assessment Scripts**: Standardized interface for all PCI DSS requirement scripts