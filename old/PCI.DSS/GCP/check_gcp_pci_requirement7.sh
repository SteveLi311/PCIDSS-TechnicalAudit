#!/usr/bin/env bash

# PCI DSS Requirement 7 Compliance Check Script for GCP
# Restrict Access to System Components and Cardholder Data by Business Need to Know

# Load shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1
source "$LIB_DIR/gcp_scope_mgmt.sh" || exit 1
source "$LIB_DIR/gcp_html_report.sh" || exit 1

# Script-specific variables
REQUIREMENT_NUMBER="7"

# Counters for checks  
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

# Define required permissions for Requirement 7
declare -a REQ7_PERMISSIONS=(
    "resourcemanager.projects.getIamPolicy"
    "iam.serviceAccounts.list"
    "iam.roles.list"
    "compute.networks.list"
    "compute.subnetworks.list"
    "iap.web.getIamPolicy"
    "compute.firewalls.list"
    "storage.buckets.getIamPolicy"
    "resourcemanager.projects.get"
    "resourcemanager.organizations.get"
    "iam.serviceAccounts.getIamPolicy"
    "compute.instances.list"
)

# Function to show help
show_help() {
    echo "GCP PCI DSS Requirement 7 Assessment Script (Framework Version)"
    echo "=============================================================="
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -s, --scope SCOPE          Assessment scope: 'project' or 'organization' (default: project)"
    echo "  -p, --project PROJECT_ID   Specific project to assess (overrides current gcloud config)"
    echo "  -o, --org ORG_ID          Specific organization ID to assess (required for organization scope)"
    echo "  -f, --format FORMAT       Output format: 'html' or 'text' (default: html)"
    echo "  -v, --verbose             Enable verbose output"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Assess current project"
    echo "  $0 --scope project --project my-proj # Assess specific project" 
    echo "  $0 --scope organization --org 123456 # Assess entire organization"
    echo ""
    echo "Note: Organization scope requires appropriate permissions across all projects in the organization."
}

# Note: Initialization moved to main function to follow modern framework pattern

# Note: Report initialization moved to main function

# Function to assess access governance and overly permissive policies
assess_access_governance() {
    local project_id="$1"
    log_debug "Assessing access governance for project: $project_id"
    
    # 7.1.1 - Security policies and operational procedures for access control
    add_check_result "$OUTPUT_FILE" "info" "7.1.1 - Access control policies documentation" \
        "Verify documented security policies for Requirement 7 access controls are maintained, up to date, in use, and known to affected parties"
    ((total_checks++))
    
    # 7.1.2 - Roles and responsibilities for access control
    add_check_result "$OUTPUT_FILE" "info" "7.1.2 - Access control roles and responsibilities" \
        "Verify roles and responsibilities for Requirement 7 activities are documented, assigned, and understood"
    ((total_checks++))
    
    # Check for overly permissive IAM policies
    local project_policy
    project_policy=$(gcloud projects get-iam-policy "$project_id" --format="json" 2>/dev/null)
    
    if [[ -n "$project_policy" ]]; then
        # Check for project owner roles
        local owner_count
        owner_count=$(echo "$project_policy" | jq -r '.bindings[] | select(.role=="roles/owner") | .members[]' 2>/dev/null | wc -l)
        
        # Ensure owner_count is a clean number
        owner_count=$(echo "$owner_count" | tr -d '\n\r' | grep -o '[0-9]*' | head -1)
        [[ -z "$owner_count" ]] && owner_count=0
        
        if [[ "$owner_count" -gt 2 ]]; then
            add_check_result "$OUTPUT_FILE" "fail" "Project owner role assignment" \
                "Project has $owner_count owners (recommend ≤2) - excessive administrative privileges violate least privilege principle"
            ((failed_checks++))
        else
            add_check_result "$OUTPUT_FILE" "pass" "Project owner role assignment" \
                "Project owner roles appropriately limited ($owner_count owners)"
            ((passed_checks++))
        fi
        ((total_checks++))
        
        # Check for project editor roles
        local editor_count
        editor_count=$(echo "$project_policy" | jq -r '.bindings[] | select(.role=="roles/editor") | .members[]' 2>/dev/null | wc -l)
        
        if [[ "$editor_count" -gt 5 ]]; then
            add_check_result "Project editor role assignment" "WARN" \
                "Project has $editor_count editors (recommend ≤5) - consider using more specific roles for access control"
        else
            add_check_result "Project editor role assignment" "PASS" \
                "Project editor roles appropriately managed ($editor_count editors)"
        fi
        
        # Check for external users
        local external_users
        external_users=$(echo "$project_policy" | jq -r '.bindings[].members[]' 2>/dev/null | grep -v "@.*\\.gserviceaccount\\.com" | grep -v "group:" | grep -v "domain:" | wc -l)
        
        if [[ "$external_users" -gt 3 ]]; then
            add_check_result "External user access" "WARN" \
                "Project has $external_users external users - review access controls for external entities per 7.2.1"
        else
            add_check_result "External user access" "PASS" \
                "External user access appropriately limited ($external_users external users)"
        fi
    else
        add_check_result "IAM policy analysis" "FAIL" \
            "Cannot retrieve IAM policy for project $project_id - verify permissions"
    fi
}

# Function to assess role-based access control and service account management
assess_role_based_access() {
    local project_id="$1"
    log_debug "Assessing role-based access control for project: $project_id"
    
    # 7.2.1 - Role-based access control implementation
    add_check_result "$OUTPUT_FILE" "warning" "7.2.1 - Role-based access control system" \
        "Verify role-based access control is implemented and enforced across all system components"
    ((total_checks++))
    ((warning_checks++))
    
    # Check service account management and lifecycle
    local service_accounts
    service_accounts=$(gcloud iam service-accounts list --project="$project_id" --format="value(email,displayName,disabled)" 2>/dev/null)
    
    if [[ -n "$service_accounts" ]]; then
        local total_accounts=0
        local disabled_accounts=0
        local accounts_with_old_keys=0
        local threshold_days=90
        local current_time=$(date +%s)
        
        while IFS=$'\t' read -r sa_email display_name disabled; do
            ((total_accounts++))
            
            if [[ "$disabled" == "True" ]]; then
                ((disabled_accounts++))
                continue
            fi
            
            # Check for old service account keys
            local sa_keys
            sa_keys=$(gcloud iam service-accounts keys list --iam-account="$sa_email" --format="json" 2>/dev/null)
            
            if [[ -n "$sa_keys" ]]; then
                local old_keys=0
                for key_info in $(echo "$sa_keys" | jq -c '.[]' 2>/dev/null); do
                    local key_type
                    key_type=$(echo "$key_info" | jq -r '.keyType' 2>/dev/null)
                    
                    if [[ "$key_type" != "SYSTEM_MANAGED" ]]; then
                        local create_time
                        create_time=$(echo "$key_info" | jq -r '.validAfterTime' 2>/dev/null)
                        local create_epoch
                        create_epoch=$(date -d "$create_time" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$create_time" +%s 2>/dev/null)
                        
                        if [[ -n "$create_epoch" ]]; then
                            local days_old=$(( (current_time - create_epoch) / 86400 ))
                            if [[ "$days_old" -gt "$threshold_days" ]]; then
                                ((old_keys++))
                            fi
                        fi
                    fi
                done
                
                if [[ "$old_keys" -gt 0 ]]; then
                    ((accounts_with_old_keys++))
                fi
            fi
        done <<< "$service_accounts"
        
        # Report service account management results
        add_check_result "Service account inventory" "INFO" \
            "Project has $total_accounts service accounts ($disabled_accounts disabled)"
        
        if [[ "$accounts_with_old_keys" -gt 0 ]]; then
            add_check_result "Service account key rotation" "FAIL" \
                "$accounts_with_old_keys service accounts have keys older than $threshold_days days - violates access management requirements"
        else
            add_check_result "Service account key rotation" "PASS" \
                "All service account keys are within acceptable age limits (≤$threshold_days days)"
        fi
        
        # Check for excessive service accounts
        if [[ "$total_accounts" -gt 20 ]]; then
            add_check_result "Service account proliferation" "WARN" \
                "Project has $total_accounts service accounts - review for compliance with least privilege principle"
        else
            add_check_result "Service account proliferation" "PASS" \
                "Service account count within reasonable limits ($total_accounts accounts)"
        fi
    else
        add_check_result "Service account analysis" "WARN" \
            "No service accounts found in project $project_id - verify service configuration"
    fi
}

# Function to assess access control systems with VPC and IAP integration
assess_access_control_systems() {
    local project_id="$1"
    log_debug "Assessing access control systems for project: $project_id"
    
    # 7.2.2 - Access is assigned based on job classification and function
    add_check_result "$OUTPUT_FILE" "warning" "7.2.2 - Job function-based access assignment" \
        "Verify access is assigned to users based on job classification and function with documented approval"
    ((total_checks++))
    ((warning_checks++))
    
    # 7.2.3 - Default deny access control
    add_check_result "$OUTPUT_FILE" "warning" "7.2.3 - Default deny access control" \
        "Verify access control systems are configured with default-deny rule"
    ((total_checks++))
    ((warning_checks++))
    
    # Check VPC firewall rules for default-deny implementation
    local firewall_rules
    firewall_rules=$(gcloud compute firewall-rules list --project="$project_id" --format="json" 2>/dev/null)
    
    if [[ -n "$firewall_rules" ]]; then
        local allow_rules_count
        allow_rules_count=$(echo "$firewall_rules" | jq -r '.[] | select(.direction=="INGRESS" and .action=="allow") | .name' 2>/dev/null | wc -l)
        
        local deny_rules_count
        deny_rules_count=$(echo "$firewall_rules" | jq -r '.[] | select(.direction=="INGRESS" and .action=="deny") | .name' 2>/dev/null | wc -l)
        
        # Check for overly permissive rules (0.0.0.0/0)
        local permissive_rules
        permissive_rules=$(echo "$firewall_rules" | jq -r '.[] | select(.direction=="INGRESS" and .action=="allow" and (.sourceRanges[]? == "0.0.0.0/0")) | .name' 2>/dev/null | wc -l)
        
        if [[ "$permissive_rules" -gt 0 ]]; then
            add_check_result "VPC firewall default-deny implementation" "FAIL" \
                "Found $permissive_rules firewall rules allowing 0.0.0.0/0 - violates default-deny access control principle"
        else
            add_check_result "VPC firewall default-deny implementation" "PASS" \
                "VPC firewall rules implement appropriate access restrictions ($allow_rules_count allow, $deny_rules_count deny rules)"
        fi
    else
        add_check_result "VPC firewall analysis" "WARN" \
            "Cannot retrieve firewall rules for project $project_id - verify network permissions"
    fi
    
    # Check Identity-Aware Proxy configuration
    local iap_resources
    iap_resources=$(gcloud iap web get-iam-policy --project="$project_id" 2>/dev/null)
    
    if [[ -n "$iap_resources" ]]; then
        add_check_result "Identity-Aware Proxy configuration" "PASS" \
            "Identity-Aware Proxy is configured for project $project_id - enhances access control"
    else
        add_check_result "Identity-Aware Proxy configuration" "INFO" \
            "Identity-Aware Proxy not configured - consider for enhanced access control per 7.2.1"
    fi
    
    # Check for privileged access monitoring
    local privileged_roles
    privileged_roles=$(gcloud projects get-iam-policy "$project_id" --format="json" 2>/dev/null | \
        jq -r '.bindings[] | select(.role | contains("admin") or contains("owner") or contains("editor")) | .role' 2>/dev/null | \
        sort -u | wc -l)
    
    if [[ "$privileged_roles" -gt 10 ]]; then
        add_check_result "Privileged access role distribution" "WARN" \
            "Project has $privileged_roles privileged role types - review for least privilege compliance per 7.2.1"
    else
        add_check_result "Privileged access role distribution" "PASS" \
            "Privileged access roles appropriately limited ($privileged_roles role types)"
    fi
}

# Function to assess least privilege implementation
assess_least_privilege() {
    local project_id="$1"
    log_debug "Assessing least privilege implementation for project: $project_id"
    
    # 7.2.4 - Least privilege access controls
    add_check_result "$OUTPUT_FILE" "warning" "7.2.4 - Least privilege implementation" \
        "Verify access control systems implement least privilege and limit access to the minimum required"
    ((total_checks++))
    ((warning_checks++))
    
    # 7.2.5 - Assignment of access rights and privileges
    add_check_result "$OUTPUT_FILE" "warning" "7.2.5 - Access rights assignment process" \
        "Verify all access rights and privileges are assigned based on individual personnel's job classification and function"
    ((total_checks++))
    ((warning_checks++))
    
    # Check for primitive roles usage (discouraged in favor of predefined/custom roles)
    local project_policy
    project_policy=$(gcloud projects get-iam-policy "$project_id" --format="json" 2>/dev/null)
    
    if [[ -n "$project_policy" ]]; then
        local primitive_roles
        primitive_roles=$(echo "$project_policy" | jq -r '.bindings[] | select(.role | startswith("roles/")) | select(.role | contains("owner") or contains("editor") or contains("viewer")) | .role' 2>/dev/null | sort -u | wc -l)
        
        local total_bindings
        total_bindings=$(echo "$project_policy" | jq -r '.bindings[] | .role' 2>/dev/null | wc -l)
        
        if [[ "$primitive_roles" -gt 0 && "$total_bindings" -gt 0 ]]; then
            local primitive_percentage=$(( (primitive_roles * 100) / total_bindings ))
            
            if [[ "$primitive_percentage" -gt 30 ]]; then
                add_check_result "Primitive roles usage" "FAIL" \
                    "$primitive_percentage% of bindings use primitive roles - violates least privilege principle (recommend <20%)"
            elif [[ "$primitive_percentage" -gt 20 ]]; then
                add_check_result "Primitive roles usage" "WARN" \
                    "$primitive_percentage% of bindings use primitive roles - consider using predefined/custom roles for better access control"
            else
                add_check_result "Primitive roles usage" "PASS" \
                    "Primitive roles usage within acceptable limits ($primitive_percentage% of bindings)"
            fi
        fi
        
        # Check for custom roles implementation
        local custom_roles
        custom_roles=$(gcloud iam roles list --project="$project_id" --format="value(name)" 2>/dev/null | wc -l)
        
        if [[ "$custom_roles" -gt 0 ]]; then
            add_check_result "Custom roles implementation" "PASS" \
                "Project implements $custom_roles custom roles - supports fine-grained access control"
        else
            add_check_result "Custom roles implementation" "INFO" \
                "No custom roles found - consider implementing for enhanced least privilege access control"
        fi
    else
        add_check_result "Least privilege analysis" "FAIL" \
            "Cannot retrieve IAM policy for project $project_id - verify permissions"
    fi
}

# Main assessment function for project iteration
assess_project() {
    local project_data="$1"
    local project_id
    
    if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
        project_id=$(echo "$project_data" | cut -d'|' -f1)
        local project_name=$(echo "$project_data" | cut -d'|' -f2)
        
        print_status "INFO" "Assessing project: $project_name ($project_id)"
        add_section "$OUTPUT_FILE" "project_${project_id}" "Project: $project_name ($project_id)" "Assessment results for project $project_name ($project_id)"
    else
        project_id="$PROJECT_ID"
        print_status "INFO" "Assessing project: $project_id"
        add_section "$OUTPUT_FILE" "requirement7_assessment" "PCI DSS Requirement 7 Assessment" "Access control assessment for project $project_id"
    fi
    
    # Execute all assessment functions
    assess_access_governance "$project_id"
    assess_role_based_access "$project_id"
    assess_access_control_systems "$project_id"
    assess_least_privilege "$project_id"
}

# Main execution function
main() {
    # Setup environment and parse command line arguments
    setup_environment "requirement7_assessment.log"
    parse_common_arguments "$@"
    case $? in
        1) exit 1 ;;  # Error
        2) exit 0 ;;  # Help displayed
    esac
    
    # Validate GCP environment
    validate_prerequisites || exit 1
    
    # Check permissions using the comprehensive permission check
    if ! check_required_permissions "${REQ7_PERMISSIONS[@]}"; then
        exit 1
    fi
    
    # Setup assessment scope
    setup_assessment_scope || exit 1
    
    # Configure HTML report
    OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"
    initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report" "${REQUIREMENT_NUMBER}"
    
    print_status "info" "============================================="
    print_status "info" "  PCI DSS 4.0.1 - Requirement 7 (GCP)"
    print_status "info" "============================================="
    echo ""
    
    # Display scope information
    print_status "info" "Assessment scope: ${ASSESSMENT_SCOPE:-project}"
    if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
        print_status "info" "Organization ID: ${ORG_ID}"
    else
        print_status "info" "Project ID: ${PROJECT_ID}"
    fi
    
    echo ""
    echo "Starting assessment at $(date)"
    echo ""
    
    log_debug "Starting PCI DSS Requirement 7 assessment"
    
    # Main execution logic with project iteration pattern
    if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
        local projects_data
        projects_data=$(get_projects_in_scope | format_project_data)
        
        if [[ -z "$projects_data" ]]; then
            print_status "ERROR" "No projects found in organization scope"
            exit 1
        fi
        
        print_status "INFO" "Found $(echo "$projects_data" | wc -l) projects in scope"
        
        while IFS= read -r project_data; do
            [[ -n "$project_data" ]] && assess_project "$project_data"
        done <<< "$projects_data"
    else
        assess_project "$PROJECT_ID"
    fi
    
    # Close the last section before adding summary
    html_append "$OUTPUT_FILE" "            </div> <!-- Close final section content -->
        </div> <!-- Close final section -->"
    
    # Add summary metrics before finalizing
    add_summary_metrics "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks"
    
    # Finalize the HTML report
    finalize_report "$OUTPUT_FILE" "$REQUIREMENT_NUMBER"
    
    echo ""
    print_status "PASS" "======================= ASSESSMENT SUMMARY ======================="
    echo "Total checks performed: $total_checks"
    echo "Passed checks: $passed_checks"
    echo "Failed checks: $failed_checks"
    echo "Warning checks: $warning_checks"
    print_status "PASS" "=================================================================="
    echo ""
    print_status "INFO" "Report has been generated: $OUTPUT_FILE"
    print_status "PASS" "=================================================================="
    
    return 0
}

# Execute main function
main "$@"