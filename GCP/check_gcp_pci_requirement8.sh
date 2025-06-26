#!/usr/bin/env bash

# PCI DSS Requirement 8 Compliance Check Script for GCP
# Identify Users and Authenticate Access to System Components

# Load shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1
source "$LIB_DIR/gcp_scope_mgmt.sh" || exit 1
source "$LIB_DIR/gcp_html_report.sh" || exit 1

# Script-specific variables
REQUIREMENT_NUMBER="8"

# Counters for checks  
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

# Define required permissions for Requirement 8
declare -a REQ8_PERMISSIONS=(
    "iam.serviceAccounts.list"
    "resourcemanager.projects.getIamPolicy"
    "iam.roles.list"
    "admin.directory.users.readonly"
    "admin.directory.groups.readonly"
    "logging.logEntries.list"
    "monitoring.alertPolicies.list"
    "cloudasset.assets.searchAllResources"
    "resourcemanager.projects.get"
    "resourcemanager.organizations.get"
    "iam.serviceAccounts.getIamPolicy"
    "compute.instances.osLogin"
)

# Function to show help
show_help() {
    echo "GCP PCI DSS Requirement 8 Assessment Script (Framework Version)"
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

# Core Assessment Functions

# 8.1 - Authentication governance and procedures
assess_authentication_governance() {
    local project_id="$1"
    log_debug "Assessing authentication governance for project: $project_id"
    
    # 8.1.1 - Security policies and operational procedures documentation
    add_check_result "$OUTPUT_FILE" "info" "8.1.1 - Security policies documentation" \
        "Verify documented security policies for Requirement 8 are maintained, up to date, in use, and known to affected parties"
    ((total_checks++))
    
    # 8.1.2 - Roles and responsibilities documentation
    add_check_result "$OUTPUT_FILE" "info" "8.1.2 - Roles and responsibilities" \
        "Verify roles and responsibilities for Requirement 8 activities are documented, assigned, and understood"
    ((total_checks++))
    
    # Check for automated policy enforcement via Organization Policy
    local policy_violations
    policy_violations=$(gcloud resource-manager org-policies list \
        --project="$project_id" \
        --filter="constraint:constraints/iam.disableServiceAccountKeyCreation OR constraint:constraints/iam.automaticIamGrantsForDefaultServiceAccounts" \
        --format="value(constraint)" 2>/dev/null || echo "")
    
    if [[ -n "$policy_violations" ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "8.1 - Organization policy enforcement" \
            "Organization policies detected for authentication governance: $policy_violations"
        ((passed_checks++))
    else
        add_check_result "$OUTPUT_FILE" "warning" "8.1 - Organization policy enforcement" \
            "No organization policies detected for authentication governance. Consider implementing constraints for service account management."
        ((warning_checks++))
    fi
    ((total_checks++))
}

# 8.2 - User identification and account lifecycle management
assess_user_identification() {
    local project_id="$1"
    log_debug "Assessing user identification for project: $project_id"
    
    # Check Cloud Identity users configuration
    local users
    users=$(gcloud identity users list --format="value(name,primaryEmail)" 2>/dev/null || echo "")
    
    if [[ -n "$users" ]]; then
        local shared_accounts=""
        local total_users=0
        
        while IFS=$'\t' read -r user_name email; do
            ((total_users++))
            # Check for potential shared/generic accounts
            if [[ "$email" == *"admin"* ]] || [[ "$email" == *"shared"* ]] || [[ "$email" == *"service"* ]] || [[ "$email" == *"system"* ]]; then
                shared_accounts+="$email, "
            fi
        done <<< "$users"
        
        if [[ -n "$shared_accounts" ]]; then
            add_check_result "$OUTPUT_FILE" "warning" "8.2.1 - Individual user identification" \
                "Potential shared accounts detected: ${shared_accounts%, }. Verify these accounts comply with individual identification requirements."
        else
            add_check_result "$OUTPUT_FILE" "pass" "8.2.1 - Individual user identification" \
                "Cloud Identity users appear to follow individual identification practices ($total_users users found)"
        fi
    else
        add_check_result "$OUTPUT_FILE" "info" "8.2.1 - Individual user identification" \
            "No Cloud Identity users found. Using project-level IAM for user management."
    fi
    
    # 8.2.2 - Check service account management
    local service_accounts
    service_accounts=$(gcloud iam service-accounts list \
        --project="$project_id" \
        --format="value(email,displayName)" 2>/dev/null || echo "")
    
    if [[ -n "$service_accounts" ]]; then
        local sa_count=0
        local default_sa_count=0
        
        while IFS=$'\t' read -r sa_email sa_name; do
            ((sa_count++))
            if [[ "$sa_email" == *"-compute@developer.gserviceaccount.com" ]]; then
                ((default_sa_count++))
            fi
        done <<< "$service_accounts"
        
        add_check_result "$OUTPUT_FILE" "info" "8.2.2 - Service account management" \
            "Service accounts found: $sa_count total ($default_sa_count default service accounts)"
        
        if [[ $default_sa_count -gt 0 ]]; then
            add_check_result "$OUTPUT_FILE" "warning" "8.2.3 - Default service account usage" \
                "Default service accounts detected. Consider using custom service accounts with minimal permissions."
        fi
    else
        add_check_result "$OUTPUT_FILE" "info" "8.2.2 - Service account management" \
            "No service accounts found in project"
    fi
    
    # 8.2.4-8.2.8 - Account lifecycle management (manual verification)
    add_check_result "$OUTPUT_FILE" "info" "8.2.4-8.2.8 - Account lifecycle management" \
        "Verify account provisioning, modification, review, and removal processes are documented and followed"
}

# 8.3 - Strong authentication factors and policies
assess_strong_authentication() {
    local project_id="$1"
    log_debug "Assessing strong authentication for project: $project_id"
    
    # 8.3.1 - Check password/authentication policies via Organization Policy
    local auth_policies
    auth_policies=$(gcloud resource-manager org-policies list \
        --project="$project_id" \
        --filter="constraint:constraints/iam.allowedPolicyMemberDomains" \
        --format="value(constraint)" 2>/dev/null || echo "")
    
    if [[ -n "$auth_policies" ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "8.3.1 - Authentication policy enforcement" \
            "Organization policy for allowed domains detected: $auth_policies"
    else
        add_check_result "$OUTPUT_FILE" "warning" "8.3.1 - Authentication policy enforcement" \
            "No organization policy for domain restrictions detected. Consider implementing allowed policy member domains."
    fi
    
    # 8.3.2 - Check service account key management
    local sa_keys_check
    sa_keys_check=$(gcloud resource-manager org-policies describe constraints/iam.disableServiceAccountKeyCreation \
        --project="$project_id" 2>/dev/null || echo "")
    
    if [[ "$sa_keys_check" == *"rules"* ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "8.3.2 - Service account key restrictions" \
            "Service account key creation restrictions are configured"
    else
        add_check_result "$OUTPUT_FILE" "warning" "8.3.2 - Service account key restrictions" \
            "No restrictions on service account key creation detected. Consider disabling key creation where possible."
    fi
    
    # 8.3.3-8.3.11 - Authentication mechanisms (manual verification)
    add_check_result "$OUTPUT_FILE" "info" "8.3.3-8.3.11 - Authentication mechanisms" \
        "Verify password policies, encryption, transmission security, and authentication factor requirements"
}

# 8.4-8.5 - Multi-factor authentication implementation and enforcement
assess_mfa_implementation() {
    local project_id="$1"
    log_debug "Assessing MFA implementation for project: $project_id"
    
    # Check for OS Login configuration
    local os_login_check
    os_login_check=$(gcloud compute project-info describe \
        --project="$project_id" \
        --format="value(commonInstanceMetadata.items[key='enable-oslogin'].value)" 2>/dev/null || echo "")
    
    if [[ "$os_login_check" == "TRUE" ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "8.4.1 - OS Login MFA configuration" \
            "OS Login is enabled, supporting centralized MFA for compute instances"
    else
        add_check_result "$OUTPUT_FILE" "warning" "8.4.1 - OS Login MFA configuration" \
            "OS Login is not enabled. Consider enabling for centralized MFA on compute instances."
    fi
    
    # Check for IAP (Identity-Aware Proxy) configuration
    local iap_check
    iap_check=$(gcloud iap web get-iam-policy 2>/dev/null | grep -c "members" 2>/dev/null || echo "0")
    iap_check=$(echo "$iap_check" | tr -d '\n\r')
    
    if [[ "$iap_check" -gt 0 ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "8.4.2 - Identity-Aware Proxy MFA" \
            "Identity-Aware Proxy configuration detected, supporting application-level MFA"
    else
        add_check_result "$OUTPUT_FILE" "info" "8.4.2 - Identity-Aware Proxy MFA" \
            "No Identity-Aware Proxy configuration detected. Consider IAP for application-level MFA."
    fi
    
    # 8.4.3 and 8.5 - MFA requirements and configuration (manual verification)
    add_check_result "$OUTPUT_FILE" "info" "8.4.3 - MFA for all access to CDE" \
        "Verify MFA is implemented for all access to cardholder data environment"
    
    add_check_result "$OUTPUT_FILE" "info" "8.5.1 - MFA system configuration" \
        "Verify MFA systems meet replay resistance and factor requirements per PCI DSS"
}

# 8.6 - System and application account management
assess_account_management() {
    local project_id="$1"
    log_debug "Assessing account management for project: $project_id"
    
    # Check for automated service account management
    local sa_list
    sa_list=$(gcloud iam service-accounts list \
        --project="$project_id" \
        --format="value(email,description)" 2>/dev/null || echo "")
    
    if [[ -n "$sa_list" ]]; then
        local documented_accounts=0
        local total_accounts=0
        
        while IFS=$'\t' read -r sa_email sa_desc; do
            ((total_accounts++))
            if [[ -n "$sa_desc" ]]; then
                ((documented_accounts++))
            fi
        done <<< "$sa_list"
        
        local documentation_percentage=$((documented_accounts * 100 / total_accounts))
        
        if [[ $documentation_percentage -ge 80 ]]; then
            add_check_result "$OUTPUT_FILE" "pass" "8.6.1 - Service account documentation" \
                "Service accounts are well documented ($documented_accounts/$total_accounts have descriptions)"
        else
            add_check_result "$OUTPUT_FILE" "warning" "8.6.1 - Service account documentation" \
                "Service account documentation needs improvement ($documented_accounts/$total_accounts have descriptions)"
        fi
    fi
    
    # Check for audit logging configuration
    local audit_logs
    audit_logs=$(gcloud logging sinks list \
        --project="$project_id" \
        --filter="name:audit*" \
        --format="value(name)" 2>/dev/null || echo "")
    
    if [[ -n "$audit_logs" ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "8.6.2 - Authentication event logging" \
            "Audit logging sinks detected: $audit_logs"
    else
        add_check_result "$OUTPUT_FILE" "warning" "8.6.2 - Authentication event logging" \
            "No audit logging sinks detected. Consider implementing Cloud Audit Logs for authentication monitoring."
    fi
    
    # 8.6.3 - Session management and timeout controls (manual verification)
    add_check_result "$OUTPUT_FILE" "info" "8.6.3 - Session management controls" \
        "Verify session timeout controls (15-minute inactivity timeout) are implemented for all access"
}

# Main project assessment function
assess_project() {
    local project_id="$1"
    log_debug "Starting Requirement 8 assessment for project: $project_id"
    
    add_section "$OUTPUT_FILE" "project_assessment" "Project Assessment: $project_id" "Detailed assessment of authentication and identity management controls"
    
    # Run all assessment functions
    assess_authentication_governance "$project_id"
    assess_user_identification "$project_id"
    assess_strong_authentication "$project_id"
    assess_mfa_implementation "$project_id"
    assess_account_management "$project_id"
    
    log_debug "Completed Requirement 8 assessment for project: $project_id"
}

# Main execution function
main() {
    # Setup environment and parse command line arguments
    setup_environment "requirement8_assessment.log"
    parse_common_arguments "$@"
    case $? in
        1) exit 1 ;;  # Error
        2) exit 0 ;;  # Help displayed
    esac
    
    # Validate GCP environment
    validate_prerequisites || exit 1
    
    # Check permissions using the comprehensive permission check
    if ! check_required_permissions "${REQ8_PERMISSIONS[@]}"; then
        exit 1
    fi
    
    # Setup assessment scope
    setup_assessment_scope || exit 1
    
    # Configure HTML report
    OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"
    initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report" "${REQUIREMENT_NUMBER}"
    
    print_status "info" "============================================="
    print_status "info" "  PCI DSS 4.0.1 - Requirement 8 (GCP)"
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
    
    # Add assessment introduction
    add_section "$OUTPUT_FILE" "authentication_governance" "Authentication and Identity Management Assessment" "Assessment of user identification and authentication access controls"
    
    log_debug "Starting PCI DSS Requirement 8 assessment"
    
    # Execute assessment based on scope
    if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
        # Organization-wide assessment
        log_debug "Starting organization-wide assessment for org: $ORG_ID"
        
        # Get all projects in organization
        projects=$(get_projects_in_scope)
        
        if [[ -z "$projects" ]]; then
            print_status "ERROR" "No projects found in organization $ORG_ID"
            exit 1
        fi
        
        while read -r project_id; do
            [[ -z "$project_id" ]] && continue
            assess_project "$project_id"
        done <<< "$projects"
        
    else
        # Single project assessment
        log_debug "Starting single project assessment for: $PROJECT_ID"
        assess_project "$PROJECT_ID"
    fi
    
    # Add manual verification requirements
    manual_requirements="
<h3>Manual Verification Requirements</h3>
<p>The following items require manual verification for complete PCI DSS Requirement 8 compliance:</p>
<ul>
    <li><strong>8.1:</strong> Authentication policies and procedures documentation</li>
    <li><strong>8.3:</strong> Password/passphrase policies (12+ characters, complexity, history)</li>
    <li><strong>8.5.1:</strong> MFA system anti-replay protection and factor requirements</li>
    <li><strong>8.6:</strong> Session timeout controls (15-minute inactivity)</li>
    <li><strong>Account lockout:</strong> Implementation after 10 invalid authentication attempts</li>
</ul>

<h4>GCP Recommendations:</h4>
<ul>
    <li>Enable Advanced Protection Program for high-risk users</li>
    <li>Implement Security Keys (FIDO2) for phishing-resistant authentication</li>
    <li>Configure Context-Aware Access for conditional authentication</li>
    <li>Use Cloud Identity for centralized MFA management</li>
    <li>Enable OS Login for centralized authentication on Compute Engine</li>
    <li>Configure Identity-Aware Proxy for application-level authentication</li>
</ul>
"
    
    add_section "$OUTPUT_FILE" "manual_verification" "Manual Verification Requirements" "$manual_requirements"
    
    # Close the manual verification section before adding summary
    echo "
            </div> <!-- Close manual_verification section content -->
        </div> <!-- Close manual_verification section -->
        " >> "$OUTPUT_FILE"
    
    # Add summary metrics before finalizing
    add_summary_metrics "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks"
    
    # Finalize the report
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
    
    log_debug "PCI DSS Requirement 8 assessment completed"
    
    return 0
}

# Execute main function
main "$@"