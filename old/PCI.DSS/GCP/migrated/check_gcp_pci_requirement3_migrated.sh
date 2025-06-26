#!/usr/bin/env bash

# PCI DSS Requirement 3 Compliance Check Script for GCP (Framework-Migrated Version)
# This script evaluates GCP controls for PCI DSS Requirement 3 compliance
# Requirements covered: 3.2 - 3.7 (Protect Stored Account Data)
# Requirement 3.1 removed - requires manual verification

# Framework Integration - Load all 4 shared libraries
LIB_DIR="$(dirname "$0")/../lib"
source "$LIB_DIR/gcp_common.sh"
source "$LIB_DIR/gcp_permissions.sh"
source "$LIB_DIR/gcp_html_report.sh"
source "$LIB_DIR/gcp_scope_mgmt.sh"

# Script-specific configuration
REQUIREMENT_NUMBER="3"
REQUIREMENT_TITLE="Protect Stored Account Data"

# Function to show help
show_help() {
    echo "GCP PCI DSS Requirement 3 Assessment Script (Framework Version)"
    echo "============================================================="
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

# Register required permissions for Requirement 3
register_required_permissions "$REQUIREMENT_NUMBER" \
    "storage.buckets.list" \
    "storage.buckets.get" \
    "storage.objects.list" \
    "compute.disks.list" \
    "compute.disks.get" \
    "compute.instances.list" \
    "compute.snapshots.list" \
    "cloudkms.keyRings.list" \
    "cloudkms.cryptoKeys.list" \
    "cloudkms.cryptoKeyVersions.list" \
    "cloudsql.instances.list" \
    "spanner.instances.list" \
    "spanner.databases.list" \
    "resourcemanager.projects.get"

# Setup environment and parse command line arguments
setup_environment "requirement3_assessment.log"
parse_common_arguments "$@"

# Validate GCP environment
validate_prerequisites || exit 1

# Check permissions
if ! check_all_permissions; then
    prompt_continue_limited || exit 1
fi

# Setup assessment scope
setup_assessment_scope "$SCOPE" "$PROJECT_ID" "$ORG_ID"

# Configure HTML report
initialize_report "PCI DSS Requirement $REQUIREMENT_NUMBER Assessment" "$ASSESSMENT_SCOPE"

# Add assessment introduction
add_section "data_protection" "Data Protection Controls Assessment" "Assessment of data protection and encryption controls"

debug_log "Starting PCI DSS Requirement 3 assessment"

# Core Assessment Functions
assess_storage_encryption() {
    local project_id="$1"
    debug_log "Assessing storage encryption for project: $project_id"
    
    # Assess Cloud Storage buckets
    local buckets
    buckets=$(gsutil ls -p "$project_id" 2>/dev/null | grep "gs://" | sed 's|gs://||' | sed 's|/||')
    
    if [[ -z "$buckets" ]]; then
        add_check_result "Cloud Storage encryption assessment" "INFO" "No Cloud Storage buckets found in project $project_id"
    else
        local total_buckets=0
        local encrypted_buckets=0
        
        while IFS= read -r bucket; do
            [[ -z "$bucket" ]] && continue
            ((total_buckets++))
            
            # Check encryption configuration
            local encryption_info
            encryption_info=$(gsutil kms encryption -p "$project_id" "gs://$bucket" 2>/dev/null)
            
            if [[ "$encryption_info" == *"KMS key"* ]] || [[ "$encryption_info" == *"Customer-managed"* ]]; then
                add_check_result "Storage bucket encryption" "PASS" \
                    "Bucket '$bucket' uses customer-managed encryption"
                ((encrypted_buckets++))
            elif [[ "$encryption_info" == *"Google-managed"* ]]; then
                add_check_result "Storage bucket encryption" "WARN" \
                    "Bucket '$bucket' uses Google-managed encryption (consider customer-managed keys)"
            else
                add_check_result "Storage bucket encryption" "FAIL" \
                    "Bucket '$bucket' encryption status unclear or not configured"
            fi
            
        done <<< "$buckets"
        
        add_check_result "Cloud Storage encryption summary" "INFO" \
            "$encrypted_buckets out of $total_buckets buckets use customer-managed encryption"
    fi
}

assess_disk_encryption() {
    local project_id="$1"
    debug_log "Assessing disk encryption for project: $project_id"
    
    # Get compute disks
    local disks
    disks=$(gcloud compute disks list \
        --project="$project_id" \
        --format="value(name,zone,diskEncryptionKey.kmsKeyName)" \
        2>/dev/null)
    
    if [[ -z "$disks" ]]; then
        add_check_result "Compute disk encryption assessment" "INFO" "No compute disks found in project $project_id"
        return
    fi
    
    local total_disks=0
    local encrypted_disks=0
    
    while IFS= read -r disk; do
        [[ -z "$disk" ]] && continue
        ((total_disks++))
        
        local disk_name=$(echo "$disk" | cut -d$'\t' -f1)
        local zone=$(echo "$disk" | cut -d$'\t' -f2)
        local kms_key=$(echo "$disk" | cut -d$'\t' -f3)
        
        if [[ -n "$kms_key" ]] && [[ "$kms_key" != "None" ]]; then
            add_check_result "Compute disk encryption" "PASS" \
                "Disk '$disk_name' in zone '$zone' uses customer-managed encryption: $kms_key"
            ((encrypted_disks++))
        else
            add_check_result "Compute disk encryption" "WARN" \
                "Disk '$disk_name' in zone '$zone' uses Google-managed encryption (consider customer-managed keys)"
        fi
        
    done <<< "$disks"
    
    add_check_result "Compute disk encryption summary" "INFO" \
        "$encrypted_disks out of $total_disks disks use customer-managed encryption"
}

assess_database_encryption() {
    local project_id="$1"
    debug_log "Assessing database encryption for project: $project_id"
    
    # Check Cloud SQL instances
    local sql_instances
    sql_instances=$(gcloud sql instances list \
        --project="$project_id" \
        --format="value(name,region,settings.dataDiskEncryptionConfiguration.kmsKeyName)" \
        2>/dev/null)
    
    local sql_count=0
    local sql_encrypted=0
    
    if [[ -n "$sql_instances" ]]; then
        while IFS= read -r instance; do
            [[ -z "$instance" ]] && continue
            ((sql_count++))
            
            local instance_name=$(echo "$instance" | cut -d$'\t' -f1)
            local region=$(echo "$instance" | cut -d$'\t' -f2)
            local kms_key=$(echo "$instance" | cut -d$'\t' -f3)
            
            if [[ -n "$kms_key" ]] && [[ "$kms_key" != "None" ]]; then
                add_check_result "Cloud SQL encryption" "PASS" \
                    "Instance '$instance_name' in region '$region' uses customer-managed encryption"
                ((sql_encrypted++))
            else
                add_check_result "Cloud SQL encryption" "WARN" \
                    "Instance '$instance_name' in region '$region' uses Google-managed encryption"
            fi
            
        done <<< "$sql_instances"
    fi
    
    # Check Spanner instances
    local spanner_instances
    spanner_instances=$(gcloud spanner instances list \
        --project="$project_id" \
        --format="value(name,config)" \
        2>/dev/null)
    
    local spanner_count=0
    
    if [[ -n "$spanner_instances" ]]; then
        while IFS= read -r instance; do
            [[ -z "$instance" ]] && continue
            ((spanner_count++))
            
            local instance_name=$(echo "$instance" | cut -d$'\t' -f1)
            local config=$(echo "$instance" | cut -d$'\t' -f2)
            
            add_check_result "Spanner encryption" "INFO" \
                "Spanner instance '$instance_name' uses Google-managed encryption by default"
            
        done <<< "$spanner_instances"
    fi
    
    if [[ $sql_count -eq 0 ]] && [[ $spanner_count -eq 0 ]]; then
        add_check_result "Database encryption assessment" "INFO" "No database instances found in project $project_id"
    else
        add_check_result "Database encryption summary" "INFO" \
            "Found $sql_count Cloud SQL instances and $spanner_count Spanner instances"
    fi
}

assess_kms_key_management() {
    local project_id="$1"
    debug_log "Assessing KMS key management for project: $project_id"
    
    # Get KMS key rings
    local key_rings
    key_rings=$(gcloud kms keyrings list \
        --project="$project_id" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -z "$key_rings" ]]; then
        add_check_result "KMS key management" "WARN" \
            "No KMS key rings found in project $project_id - consider using customer-managed encryption keys"
        return
    fi
    
    local total_keys=0
    local active_keys=0
    
    while IFS= read -r keyring; do
        [[ -z "$keyring" ]] && continue
        
        local keyring_name=$(basename "$keyring")
        local location=$(echo "$keyring" | sed 's|.*/locations/\([^/]*\)/.*|\1|')
        
        # Get keys in this keyring
        local keys
        keys=$(gcloud kms keys list \
            --keyring="$keyring_name" \
            --location="$location" \
            --project="$project_id" \
            --format="value(name,primary.state)" \
            2>/dev/null)
        
        while IFS= read -r key; do
            [[ -z "$key" ]] && continue
            ((total_keys++))
            
            local key_name=$(echo "$key" | cut -d$'\t' -f1 | xargs basename)
            local state=$(echo "$key" | cut -d$'\t' -f2)
            
            if [[ "$state" == "ENABLED" ]]; then
                add_check_result "KMS key status" "PASS" \
                    "Key '$key_name' in keyring '$keyring_name' is active"
                ((active_keys++))
            else
                add_check_result "KMS key status" "WARN" \
                    "Key '$key_name' in keyring '$keyring_name' state: $state"
            fi
            
        done <<< "$keys"
        
    done <<< "$key_rings"
    
    add_check_result "KMS key management summary" "INFO" \
        "$active_keys out of $total_keys KMS keys are active in project $project_id"
}

assess_access_controls() {
    local project_id="$1"
    debug_log "Assessing data access controls for project: $project_id"
    
    # Check IAM bindings for sensitive roles
    local iam_policy
    iam_policy=$(gcloud projects get-iam-policy "$project_id" \
        --format="value(bindings.role,bindings.members.list())" \
        2>/dev/null)
    
    local sensitive_roles=(
        "roles/storage.admin"
        "roles/compute.storageAdmin" 
        "roles/cloudkms.admin"
        "roles/cloudsql.admin"
        "roles/spanner.admin"
        "roles/editor"
        "roles/owner"
    )
    
    local high_privilege_assignments=0
    
    for role in "${sensitive_roles[@]}"; do
        local members
        members=$(echo "$iam_policy" | grep "$role" | cut -d$'\t' -f2 2>/dev/null)
        
        if [[ -n "$members" ]]; then
            local member_count
            member_count=$(echo "$members" | wc -w)
            
            if [[ $member_count -gt 3 ]]; then
                add_check_result "Excessive privileged access" "WARN" \
                    "Role '$role' assigned to $member_count members - review for least privilege"
                ((high_privilege_assignments++))
            else
                add_check_result "Privileged access review" "PASS" \
                    "Role '$role' appropriately assigned to $member_count members"
            fi
        fi
    done
    
    add_check_result "Access control assessment" "INFO" \
        "$high_privilege_assignments potentially excessive privilege assignments found"
}

# Main assessment function
assess_project() {
    local project_id="$1"
    
    info_log "Assessing project: $project_id"
    
    # Add project section to report
    add_section "project_$project_id" "Project: $project_id" "Assessment results for project $project_id"
    
    # Perform assessments
    assess_storage_encryption "$project_id"
    assess_disk_encryption "$project_id"
    assess_database_encryption "$project_id"
    assess_kms_key_management "$project_id"
    assess_access_controls "$project_id"
    
    debug_log "Completed assessment for project: $project_id"
}

# Main execution
main() {
    info_log "Starting PCI DSS Requirement 3 assessment"
    
    # Initialize scope management and enumerate projects
    local projects
    projects=$(get_projects_in_scope)
    
    local project_count=0
    while IFS= read -r project_data; do
        [[ -z "$project_data" ]] && continue
        
        # Setup project context using scope management
        assess_project "$project_data"
        ((project_count++))
        
    done <<< "$projects"
    
    # Generate final report
    local output_file="pci_requirement3_assessment_$(date +%Y%m%d_%H%M%S).html"
    finalize_report "$output_file" "$REQUIREMENT_NUMBER"
    
    success_log "Assessment complete! Report saved to: $output_file"
    success_log "Projects assessed: $project_count"
    
    return 0
}

# Execute main function
main "$@"