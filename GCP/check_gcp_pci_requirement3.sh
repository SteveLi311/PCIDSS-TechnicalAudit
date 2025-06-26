#!/usr/bin/env bash

# =============================================================================
# PCI DSS Requirement 3 Compliance Check Script for GCP (Refactored)
# =============================================================================
# Description: Framework-compliant assessment for PCI DSS Requirement 3
# Requirements: 3.2-3.7 (Protect Stored Account Data)
# Version: 2.0 (Shared Architecture)
# =============================================================================

# Load shared libraries
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1
source "$LIB_DIR/gcp_scope_mgmt.sh" || exit 1
source "$LIB_DIR/gcp_html_report.sh" || exit 1

# Script configuration
readonly REQUIREMENT_NUMBER="3"
readonly REQUIREMENT_TITLE="Protect Stored Account Data"

# Counters for checks  
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

# Define required permissions for Requirement 3
declare -a REQ3_PERMISSIONS=(
    "storage.buckets.list"
    "storage.buckets.getIamPolicy"
    "cloudsql.instances.list"
    "cloudkms.cryptoKeys.list"
    "compute.disks.list"
    "cloudkms.keyRings.list"
    "compute.instances.list"
    "storage.objects.list"
    "resourcemanager.projects.get"
    "resourcemanager.organizations.get"
)

# Function to show help
show_help() {
    echo "GCP PCI DSS Requirement 3 Assessment Script (Framework Version)"
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

# =============================================================================
# Assessment Functions
# =============================================================================

assess_storage_encryption() {
    local projects=("$@")
    
    print_status "INFO" "Starting storage encryption assessment..."
    add_section "$OUTPUT_FILE" "storage_encryption" "Storage Encryption Assessment (3.2-3.3)"
    
    for project in "${projects[@]}"; do
        print_status "INFO" "Assessing storage encryption in project: $project"
        
        local buckets
        if ! buckets=$(gcloud storage buckets list --project="$project" --format="value(name)" 2>/dev/null); then
            print_status "WARN" "Failed to list storage buckets in project $project"
            add_check_result "$OUTPUT_FILE" "warning" "Project $project" "Unable to access storage buckets"
            ((warning_checks++))
            ((total_checks++))
            continue
        fi
        
        local bucket_count=0
        while IFS= read -r bucket; do
            [[ -z "$bucket" ]] && continue
            bucket_count=$((bucket_count + 1))
            
            local encryption_status
            if ! encryption_status=$(gcloud storage buckets describe "gs://$bucket" --format="value(encryption.defaultKmsKeyName)" 2>/dev/null); then
                print_status "WARN" "Failed to describe bucket $bucket"
                add_check_result "$OUTPUT_FILE" "warning" "Bucket $bucket" "Unable to verify encryption status"
                ((warning_checks++))
                ((total_checks++))
                continue
            fi
            
            if [[ -n "$encryption_status" ]]; then
                add_check_result "$OUTPUT_FILE" "pass" "Bucket $bucket" "CMEK encryption enabled"
                ((passed_checks++))
                ((total_checks++))
            else
                add_check_result "$OUTPUT_FILE" "fail" "Bucket $bucket" "Default encryption only - consider CMEK" "Consider implementing Customer-Managed Encryption Keys (CMEK) for enhanced security"
                ((failed_checks++))
                ((total_checks++))
            fi
        done <<< "$buckets"
        
        print_status "INFO" "Processed $bucket_count storage buckets in project $project"
    done
    
    print_status "PASS" "Storage encryption assessment completed"
}

assess_database_encryption() {
    local projects=("$@")
    
    print_status "INFO" "Starting database encryption assessment..."
    add_section "$OUTPUT_FILE" "database_encryption" "Database Encryption Assessment (3.4-3.5)"
    
    for project in "${projects[@]}"; do
        print_status "INFO" "Assessing database encryption in project: $project"
        
        local instances
        if ! instances=$(gcloud sql instances list --project="$project" --format="value(name)" 2>/dev/null); then
            print_status "WARN" "Failed to list SQL instances in project $project"
            add_check_result "$OUTPUT_FILE" "warning" "Project $project" "Unable to access SQL instances"
            ((warning_checks++))
            ((total_checks++))
            continue
        fi
        
        local instance_count=0
        while IFS= read -r instance; do
            [[ -z "$instance" ]] && continue
            instance_count=$((instance_count + 1))
            
            local encryption
            if ! encryption=$(gcloud sql instances describe "$instance" --project="$project" --format="value(diskEncryptionConfiguration.kmsKeyName)" 2>/dev/null); then
                print_status "WARN" "Failed to describe SQL instance $instance"
                add_check_result "$OUTPUT_FILE" "warning" "SQL Instance $instance" "Unable to verify encryption status"
                ((warning_checks++))
                ((total_checks++))
                continue
            fi
            
            if [[ -n "$encryption" ]]; then
                add_check_result "$OUTPUT_FILE" "pass" "SQL Instance $instance" "CMEK encryption configured"
                ((passed_checks++))
                ((total_checks++))
            else
                add_check_result "$OUTPUT_FILE" "warning" "SQL Instance $instance" "Using default encryption" "Consider implementing Customer-Managed Encryption Keys (CMEK) for enhanced security"
                ((warning_checks++))
                ((total_checks++))
            fi
        done <<< "$instances"
        
        print_status "INFO" "Processed $instance_count SQL instances in project $project"
    done
    
    print_status "PASS" "Database encryption assessment completed"
}

assess_key_management() {
    local projects=("$@")
    
    print_status "INFO" "Starting key management assessment..."
    add_section "$OUTPUT_FILE" "key_management" "Key Management Assessment (3.6-3.7)"
    
    for project in "${projects[@]}"; do
        print_status "INFO" "Assessing key management in project: $project"
        
        local keyrings
        if ! keyrings=$(gcloud kms keyrings list --location=global --project="$project" --format="value(name)" 2>/dev/null); then
            print_status "WARN" "Failed to list KMS keyrings in project $project"
            add_check_result "$OUTPUT_FILE" "warning" "Project $project" "Unable to access KMS keyrings"
            ((warning_checks++))
            ((total_checks++))
            continue
        fi
        
        local keyring_count=0
        while IFS= read -r keyring; do
            [[ -z "$keyring" ]] && continue
            keyring_count=$((keyring_count + 1))
        done <<< "$keyrings"
        
        if [[ $keyring_count -gt 0 ]]; then
            add_check_result "$OUTPUT_FILE" "pass" "Key Management" "Found $keyring_count KMS keyrings in project $project"
            ((passed_checks++))
            ((total_checks++))
        else
            add_check_result "$OUTPUT_FILE" "info" "Key Management" "No KMS keyrings found in project $project"
            ((total_checks++))
        fi
        
        print_status "INFO" "Processed $keyring_count KMS keyrings in project $project"
    done
    
    print_status "PASS" "Key management assessment completed"
}

# =============================================================================
# Main Assessment Orchestration
# =============================================================================

main() {
    print_status "INFO" "Starting PCI DSS Requirement $REQUIREMENT_NUMBER assessment..."
    
    # Framework initialization pattern with error handling
    if ! setup_environment; then
        print_status "FAIL" "Failed to setup environment"
        exit 1
    fi
    
    # Set output file path
    OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"
    
    if ! parse_common_arguments "$@"; then
        case $? in
            1) exit 1 ;;  # Error
            2) exit 0 ;;  # Help displayed
        esac
    fi
    
    if ! validate_prerequisites; then
        print_status "FAIL" "Prerequisites validation failed"
        exit 1
    fi
    
    # Setup assessment scope using framework
    if ! setup_assessment_scope; then
        print_status "FAIL" "Failed to setup assessment scope"
        exit 1
    fi
    
    # Check permissions using framework
    if ! check_required_permissions "${REQ3_PERMISSIONS[@]}"; then
        exit 1
    fi
    
    # Get projects in scope using framework
    local projects
    if ! projects=($(get_projects_in_scope)); then
        print_status "FAIL" "Failed to get projects in scope"
        exit 1
    fi
    
    if [[ ${#projects[@]} -eq 0 ]]; then
        print_status "FAIL" "No projects found in assessment scope"
        exit 1
    fi
    
    print_status "INFO" "Assessment scope includes ${#projects[@]} project(s): ${projects[*]}"
    
    # Initialize report using framework
    if ! initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment" "$REQUIREMENT_NUMBER" "$GCP_PROJECT"; then
        print_status "FAIL" "Failed to initialize HTML report"
        exit 1
    fi
    
    print_status "INFO" "Starting modular assessments..."
    
    # Execute modular assessments with error handling
    if ! assess_storage_encryption "${projects[@]}"; then
        print_status "WARN" "Storage encryption assessment encountered issues"
    fi
    
    if ! assess_database_encryption "${projects[@]}"; then
        print_status "WARN" "Database encryption assessment encountered issues"
    fi
    
    if ! assess_key_management "${projects[@]}"; then
        print_status "WARN" "Key management assessment encountered issues"
    fi
    
    # Close the last section before adding summary
    html_append "$OUTPUT_FILE" "            </div> <!-- Close final section content -->
        </div> <!-- Close final section -->"
    
    # Add summary metrics before finalizing
    add_summary_metrics "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks"
    
    # Finalize report using framework
    if ! finalize_report "$OUTPUT_FILE" "$REQUIREMENT_NUMBER"; then
        print_status "FAIL" "Failed to finalize HTML report"
        exit 1
    fi
    
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
}

# Execute main function
main "$@"