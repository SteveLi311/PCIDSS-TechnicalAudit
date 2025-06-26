#!/usr/bin/env bash

# PCI DSS Requirement 5 Compliance Check Script for GCP (Framework-Migrated Version)
# This script evaluates GCP controls for PCI DSS Requirement 5 compliance
# Requirements covered: 5.1-5.4 (Protect All Systems Against Malware)

# Framework Integration - Load all 4 shared libraries
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh"
source "$LIB_DIR/gcp_permissions.sh"
source "$LIB_DIR/gcp_html_report.sh"
source "$LIB_DIR/gcp_scope_mgmt.sh"

# Script-specific configuration
REQUIREMENT_NUMBER="5"
REQUIREMENT_TITLE="Protect All Systems Against Malware"

# Function to show help
show_help() {
    echo "GCP PCI DSS Requirement 5 Assessment Script (Framework Version)"
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

# Register required permissions for Requirement 5
register_required_permissions "$REQUIREMENT_NUMBER" \
    "compute.instances.list" \
    "compute.instanceTemplates.list" \
    "compute.instanceGroupManagers.list" \
    "compute.autoscalers.list" \
    "compute.metadata.get" \
    "compute.projects.get" \
    "resourcemanager.projects.getIamPolicy"

# Initialize framework
setup_environment || exit 1

# Parse arguments
parse_common_arguments "$@"
case $? in
    1) exit 1 ;;  # Error
    2) exit 0 ;;  # Help displayed
esac

# Validate prerequisites
validate_prerequisites || exit 1

# Setup assessment scope
setup_assessment_scope || exit 1

# Check required permissions
check_required_permissions || exit 1

# Set output file path
OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"

# Initialize HTML report
initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report" "${REQUIREMENT_NUMBER}" || exit 1

# Assessment Functions

# 5.1 - Processes and mechanisms for protecting systems from malicious software
assess_antimalware_solutions() {
    local project_id="$1"
    local section_title="5.1 - Anti-malware Solutions"
    local check_title="Compute Engine Anti-malware Protection"
    
    log_debug "Assessing anti-malware solutions for project: $project_id"
    
    # Get Compute Engine instances
    local instances
    instances=$(gcloud compute instances list --project="$project_id" --format="value(name,zone,status)" 2>/dev/null)
    
    if [[ -z "$instances" ]]; then
        add_check_result "$OUTPUT_FILE" "info" "$check_title" "No Compute Engine instances found in project $project_id"
        return 0
    fi
    
    local total_instances=0
    local protected_instances=0
    local details=""
    
    while IFS=$'\t' read -r name zone status; do
        [[ -z "$name" || "$status" == "TERMINATED" ]] && continue
        ((total_instances++))
        
        # Check for anti-malware metadata
        local metadata
        metadata=$(gcloud compute instances describe "$name" --zone="$zone" --project="$project_id" --format="value(metadata.items)" 2>/dev/null)
        
        local antimalware_found=false
        
        # Check for anti-malware related metadata
        if echo "$metadata" | grep -qi "antimalware\|anti-malware\|antivirus\|security-agent"; then
            antimalware_found=true
        fi
        
        # Check for Shielded VM features
        local shielded_config
        shielded_config=$(gcloud compute instances describe "$name" --zone="$zone" --project="$project_id" --format="value(shieldedInstanceConfig)" 2>/dev/null)
        
        if echo "$shielded_config" | grep -q "enableIntegrityMonitoring: true\|enableSecureBoot: true\|enableVtpm: true"; then
            antimalware_found=true
        fi
        
        if [[ "$antimalware_found" == "true" ]]; then
            ((protected_instances++))
            details+="Instance $name: Protected\n"
        else
            details+="Instance $name: No anti-malware configuration detected\n"
        fi
        
    done <<< "$instances"
    
    local status="pass"
    local message="Anti-malware protection: $protected_instances/$total_instances instances protected"
    
    if [[ $protected_instances -lt $total_instances ]]; then
        status="fail"
        message="Anti-malware protection gaps: $((total_instances - protected_instances)) unprotected instances"
    fi
    
    add_check_result "$OUTPUT_FILE" "$status" "$check_title" "$message" "$details"
}

# 5.2 - Malware prevention, detection, and addressing mechanisms  
assess_malware_detection() {
    local project_id="$1"
    local section_title="5.2 - Malware Detection"
    local check_title="OS Config Patch Management"
    
    log_debug "Assessing malware detection mechanisms for project: $project_id"
    
    # Check for OS Config patch policies
    local patch_policies
    patch_policies=$(gcloud compute os-config patch-policies list --project="$project_id" --format="value(name)" 2>/dev/null)
    
    if [[ -z "$patch_policies" ]]; then
        add_check_result "$OUTPUT_FILE" "fail" "$check_title" "No OS Config patch policies found" "Consider creating patch policies for regular security updates"
        return 1
    fi
    
    local policy_count
    policy_count=$(echo "$patch_policies" | wc -l)
    
    add_check_result "$OUTPUT_FILE" "pass" "$check_title" "OS Config patch policies configured: $policy_count policies" "Found patch management policies for automated security updates"
    
    # Check Container Analysis for vulnerability scanning
    local check_title2="Container Analysis Vulnerability Scanning"
    local images
    images=$(gcloud container images list --project="$project_id" --format="value(name)" --limit=5 2>/dev/null)
    
    if [[ -n "$images" ]]; then
        add_check_result "$OUTPUT_FILE" "info" "$check_title2" "Container images detected" "Container Analysis should be enabled for vulnerability scanning"
    else
        add_check_result "$OUTPUT_FILE" "info" "$check_title2" "No container images found" "Container Analysis not applicable"
    fi
}

# 5.3 - Anti-malware mechanisms maintenance and monitoring
assess_antimalware_monitoring() {
    local project_id="$1"
    local section_title="5.3 - Anti-malware Monitoring"
    local check_title="Cloud Scheduler Monitoring Jobs"
    
    log_debug "Assessing anti-malware monitoring for project: $project_id"
    
    # Check for Cloud Scheduler jobs for monitoring
    local scheduler_jobs
    scheduler_jobs=$(gcloud scheduler jobs list --project="$project_id" --format="value(name)" 2>/dev/null)
    
    if [[ -z "$scheduler_jobs" ]]; then
        add_check_result "$OUTPUT_FILE" "warning" "$check_title" "No Cloud Scheduler jobs found" "Consider implementing automated monitoring schedules"
    else
        local job_count
        job_count=$(echo "$scheduler_jobs" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "$check_title" "Scheduled monitoring jobs: $job_count jobs" "Cloud Scheduler jobs configured for automated tasks"
    fi
    
    # Check for Cloud Functions for monitoring
    local check_title2="Cloud Functions Monitoring"
    local functions
    functions=$(gcloud functions list --project="$project_id" --format="value(name)" 2>/dev/null)
    
    if [[ -z "$functions" ]]; then
        add_check_result "$OUTPUT_FILE" "info" "$check_title2" "No Cloud Functions found" "No serverless monitoring functions detected"
    else
        local function_count
        function_count=$(echo "$functions" | wc -l)
        add_check_result "$OUTPUT_FILE" "info" "$check_title2" "Cloud Functions detected: $function_count functions" "Serverless functions available for monitoring tasks"
    fi
}

# 5.4 - Anti-phishing mechanisms implementation and monitoring
assess_antiphishing_mechanisms() {
    local project_id="$1"
    local section_title="5.4 - Anti-phishing Mechanisms"
    local check_title="Cloud Armor Security Policies"
    
    log_debug "Assessing anti-phishing mechanisms for project: $project_id"
    
    # Check for Cloud Armor security policies
    local armor_policies
    armor_policies=$(gcloud compute security-policies list --project="$project_id" --format="value(name)" 2>/dev/null)
    
    if [[ -z "$armor_policies" ]]; then
        add_check_result "$OUTPUT_FILE" "warning" "$check_title" "No Cloud Armor security policies found" "Consider implementing Cloud Armor for DDoS and application-layer protection"
    else
        local policy_count
        policy_count=$(echo "$armor_policies" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "$check_title" "Cloud Armor policies: $policy_count policies" "Security policies configured for web application protection"
    fi
    
    # Check for firewall rules with anti-phishing considerations
    local check_title2="Firewall Rules Configuration"
    local firewall_rules
    firewall_rules=$(gcloud compute firewall-rules list --project="$project_id" --format="value(name,direction,action)" 2>/dev/null)
    
    if [[ -z "$firewall_rules" ]]; then
        add_check_result "$OUTPUT_FILE" "fail" "$check_title2" "No firewall rules found" "Firewall rules are required for network security"
    else
        local rule_count
        rule_count=$(echo "$firewall_rules" | wc -l)
        local deny_rules
        deny_rules=$(echo "$firewall_rules" | grep -c "DENY" 2>/dev/null || echo "0")
        deny_rules=$(echo "$deny_rules" | tr -d '\n\r ')
        
        if [[ $deny_rules -gt 0 ]]; then
            add_check_result "$OUTPUT_FILE" "pass" "$check_title2" "Firewall rules configured: $rule_count total, $deny_rules deny rules" "Restrictive firewall rules help prevent malicious traffic"
        else
            add_check_result "$OUTPUT_FILE" "warning" "$check_title2" "Firewall rules found but no explicit deny rules: $rule_count rules" "Consider implementing explicit deny rules for better security"
        fi
    fi
}

# Core assessment function for project iteration
assess_project() {
    local project_id="$1"
    log_debug "Starting Requirement 5 assessment for project: $project_id"
    
    add_section "$OUTPUT_FILE" "malware_protection" "PCI DSS Requirement 5: Malware Protection Assessment"
    
    # Run all assessment functions for this project
    assess_antimalware_solutions "$project_id"
    assess_malware_detection "$project_id"
    assess_antimalware_monitoring "$project_id"
    assess_antiphishing_mechanisms "$project_id"
}

# Main execution logic
main() {
    log_debug "Starting PCI DSS Requirement 5 assessment"
    
    # Get projects in scope
    local projects
    projects=$(get_projects_in_scope)
    
    if [[ -z "$projects" ]]; then
        print_status "ERROR" "No projects found in assessment scope"
        exit 1
    fi
    
    log_debug "Found projects in scope: $(echo "$projects" | wc -l)"
    
    # Assess each project
    while IFS= read -r project_id; do
        [[ -z "$project_id" ]] && continue
        log_debug "Processing project: $project_id"
        assess_project "$project_id"
    done <<< "$projects"
    
    # Finalize the report
    finalize_report "$OUTPUT_FILE" "5"
    
    print_status "INFO" "PCI DSS Requirement 5 assessment completed"
    print_status "INFO" "Report generated: $OUTPUT_FILE"
}

# Execute main function
main "$@"