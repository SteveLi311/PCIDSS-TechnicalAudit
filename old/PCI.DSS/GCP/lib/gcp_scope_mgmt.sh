#!/usr/bin/env bash

# =============================================================================
# GCP Scope Management Library - Unified Assessment Scope Handling
# =============================================================================
# Description: Provides standardized scope management across all GCP PCI DSS assessment scripts
# Version: 1.0
# Author: PCI DSS Assessment Framework
# Created: 2025-06-09
# =============================================================================

# Ensure gcp_common.sh is loaded first
if [[ "${GCP_COMMON_LOADED}" != "true" ]]; then
    echo "Error: gcp_common.sh must be loaded before gcp_scope_mgmt.sh" >&2
    exit 1
fi

# Global Variables for Scope Management
ASSESSMENT_SCOPE=""
PROJECTS_CACHE=""
SCOPE_VALIDATION_DONE=false

# =============================================================================
# Core Scope Management Functions
# =============================================================================

# Configure and validate assessment scope
# Usage: setup_assessment_scope
# Input: Uses global variables from parse_common_arguments
# Output: Sets ASSESSMENT_SCOPE, validates permissions
# Returns: 0 on success, 1 on validation failure
setup_assessment_scope() {
    print_status "INFO" "Setting up assessment scope..."
    
    # Set assessment scope based on CLI arguments
    if [[ "$SCOPE_TYPE" == "organization" ]]; then
        ASSESSMENT_SCOPE="organization"
        
        # Validate organization ID is provided
        if [[ -z "$ORG_ID" ]]; then
            print_status "FAIL" "Organization scope requires an organization ID (-p ORG_ID)"
            return 1
        fi
        
        # Validate organization access
        if ! gcloud organizations describe "$ORG_ID" >/dev/null 2>&1; then
            print_status "FAIL" "Cannot access organization: $ORG_ID"
            print_status "INFO" "Ensure you have resourcemanager.organizations.get permission"
            return 1
        fi
        
        print_status "PASS" "Organization scope configured: $ORG_ID"
    else
        ASSESSMENT_SCOPE="project"
        
        # Use provided project ID or current default
        if [[ -z "$PROJECT_ID" ]]; then
            PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
            if [[ -z "$PROJECT_ID" ]]; then
                print_status "FAIL" "No project ID specified and no default project configured"
                print_status "INFO" "Use: -p PROJECT_ID or 'gcloud config set project PROJECT_ID'"
                return 1
            fi
        fi
        
        # Validate project access
        if ! gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
            print_status "FAIL" "Cannot access project: $PROJECT_ID"
            print_status "INFO" "Ensure project exists and you have resourcemanager.projects.get permission"
            return 1
        fi
        
        print_status "PASS" "Project scope configured: $PROJECT_ID"
    fi
    
    SCOPE_VALIDATION_DONE=true
    return 0
}

# Return list of projects based on scope configuration
# Usage: get_projects_in_scope
# Input: None (uses global scope variables)
# Output: Project IDs (one per line)
# Returns: 0 on success, 1 on enumeration failure
get_projects_in_scope() {
    if [[ "$SCOPE_VALIDATION_DONE" != "true" ]]; then
        print_status "FAIL" "Scope not configured. Call setup_assessment_scope first"
        return 1
    fi
    
    local projects=""
    
    if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
        # Cache projects list for efficiency
        if [[ -z "$PROJECTS_CACHE" ]]; then
            print_status "INFO" "Enumerating projects in organization: $ORG_ID"
            
            PROJECTS_CACHE=$(gcloud projects list \
                --filter="parent.id:$ORG_ID" \
                --format="value(projectId)" 2>/dev/null)
            
            if [[ -z "$PROJECTS_CACHE" ]]; then
                print_status "FAIL" "No projects found in organization: $ORG_ID"
                print_status "INFO" "Ensure you have resourcemanager.projects.list permission"
                return 1
            fi
            
            local project_count=$(echo "$PROJECTS_CACHE" | wc -l)
            print_status "PASS" "Found $project_count projects in organization"
        fi
        
        echo "$PROJECTS_CACHE"
    else
        # Single project scope
        echo "$PROJECT_ID"
    fi
    
    return 0
}

# Construct scope-aware gcloud command
# Usage: build_gcloud_command "base_command" [project_override]
# Input: base command string, optional project override
# Output: Complete gcloud command with appropriate --project flag
# Returns: Constructed command string
build_gcloud_command() {
    local base_command="$1"
    local project_override="$2"
    
    if [[ -z "$base_command" ]]; then
        echo "Error: base_command is required" >&2
        return 1
    fi
    
    local target_project=""
    if [[ -n "$project_override" ]]; then
        target_project="$project_override"
    elif [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
        echo "Error: project must be specified for organization scope" >&2
        return 1
    else
        target_project="$PROJECT_ID"
    fi
    
    # Insert --project flag into gcloud command
    if [[ "$base_command" =~ ^gcloud[[:space:]] ]]; then
        # Split gcloud command and insert --project flag
        local gcloud_part=$(echo "$base_command" | cut -d' ' -f1-2)
        local remaining_command=$(echo "$base_command" | cut -d' ' -f3-)
        echo "$gcloud_part --project=\"$target_project\" $remaining_command"
    else
        echo "Error: Command must start with 'gcloud'" >&2
        return 1
    fi
}

# Execute command across all projects in scope
# Usage: run_across_projects "base_command" [format_option]
# Input: base gcloud command, optional format parameter
# Output: Aggregated results with project prefixes for org scope
# Returns: 0 on success, 1 on execution failure
run_across_projects() {
    local base_command="$1"
    local format_option="$2"
    
    if [[ -z "$base_command" ]]; then
        print_status "FAIL" "Base command is required for cross-project execution"
        return 1
    fi
    
    local projects
    projects=$(get_projects_in_scope)
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    
    local results=""
    local successful_projects=0
    local failed_projects=0
    
    while IFS= read -r project; do
        if [[ -n "$project" ]]; then
            local full_command
            full_command=$(build_gcloud_command "$base_command" "$project")
            
            if [[ $? -eq 0 ]]; then
                print_status "INFO" "Executing on project: $project"
                local project_results
                project_results=$(eval "$full_command" 2>/dev/null)
                
                if [[ $? -eq 0 && -n "$project_results" ]]; then
                    if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
                        # Add project prefix for organization scope
                        while IFS= read -r line; do
                            if [[ -n "$line" ]]; then
                                results="${results}${project}/${line}"$'\n'
                            fi
                        done <<< "$project_results"
                    else
                        # Direct output for project scope
                        results="${results}${project_results}"$'\n'
                    fi
                    ((successful_projects++))
                else
                    print_status "WARN" "No results or command failed for project: $project"
                    ((failed_projects++))
                fi
            else
                print_status "FAIL" "Failed to build command for project: $project"
                ((failed_projects++))
            fi
        fi
    done <<< "$projects"
    
    # Output results
    if [[ -n "$results" ]]; then
        echo -n "$results"
    fi
    
    # Summary reporting
    total_projects=$((successful_projects + failed_projects))
    if [[ $successful_projects -gt 0 ]]; then
        print_status "PASS" "Command executed on $successful_projects/$total_projects projects"
        return 0
    else
        print_status "FAIL" "Command failed on all $total_projects projects"
        return 1
    fi
}

# Process and format cross-project results
# Usage: aggregate_cross_project_data "raw_data" [delimiter]
# Input: Raw command output, optional delimiter
# Output: Formatted results with project context
# Returns: Processed data suitable for analysis
aggregate_cross_project_data() {
    local raw_data="$1"
    local delimiter="${2:-/}"
    
    if [[ -z "$raw_data" ]]; then
        return 0
    fi
    
    local processed_results=""
    local project_count=0
    local resource_count=0
    
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            if [[ "$ASSESSMENT_SCOPE" == "organization" && "$line" =~ ^[^/]+/.+ ]]; then
                # Extract project and resource from org scope format
                local project_part=$(echo "$line" | cut -d"$delimiter" -f1)
                local resource_part=$(echo "$line" | cut -d"$delimiter" -f2-)
                
                # Format with consistent project context
                processed_results="${processed_results}Project: $project_part | Resource: $resource_part"$'\n'
                ((resource_count++))
            else
                # Direct formatting for project scope
                processed_results="${processed_results}Resource: $line"$'\n'
                ((resource_count++))
            fi
        fi
    done <<< "$raw_data"
    
    # Output aggregated results
    if [[ -n "$processed_results" ]]; then
        echo -n "$processed_results"
    fi
    
    # Summary statistics for logging
    if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
        local unique_projects=$(echo "$raw_data" | grep -E '^[^/]+/' | cut -d'/' -f1 | sort -u | wc -l)
        print_status "INFO" "Aggregated $resource_count resources across $unique_projects projects"
    else
        print_status "INFO" "Aggregated $resource_count resources from project: $PROJECT_ID"
    fi
    
    return 0
}

# =============================================================================
# Export Functions for Use by Assessment Scripts
# =============================================================================

export -f setup_assessment_scope
export -f get_projects_in_scope
export -f build_gcloud_command
export -f run_across_projects
export -f aggregate_cross_project_data

# Mark library as loaded
export GCP_SCOPE_LOADED="true"

print_status "PASS" "GCP Scope Management Library v1.0 loaded successfully"