#!/usr/bin/env bash

# PCI DSS Requirement 12 Compliance Check Script for GCP (Framework-Migrated Version)
# This script evaluates GCP organizational policies and programs for PCI DSS Requirement 12 compliance
# Requirements covered: 12.1 - 12.10 (Support Information Security with Organizational Policies and Programs)

# Load shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1
source "$LIB_DIR/gcp_scope_mgmt.sh" || exit 1
source "$LIB_DIR/gcp_html_report.sh" || exit 1

# Script-specific variables
REQUIREMENT_NUMBER="12"

# Counters for checks  
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0


# Function to show help
show_help() {
    echo "GCP PCI DSS Requirement 12 Assessment Script (Framework Version)"
    echo "================================================================"
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

# Define required permissions for Requirement 12
declare -a REQ12_PERMISSIONS=(
    "resourcemanager.projects.get"
    "resourcemanager.organizations.get"
    "resourcemanager.folders.list"
    "orgpolicy.policies.list"
    "iam.roles.list"
    "iam.serviceAccounts.list"
    "cloudasset.assets.searchAllResources"
    "cloudasset.assets.searchAllIamPolicies"
    "securitycenter.findings.list"
    "logging.logEntries.list"
    "monitoring.alertPolicies.list"
    "cloudkms.keyRings.list"
    "storage.buckets.list"
    "compute.instances.list"
    "container.clusters.list"
    "dns.managedZones.list"
    "pubsub.topics.list"
)

# Core Assessment Functions

# 12.1 - Comprehensive information security policy
assess_information_security_policy() {
    local project_id="$1"
    log_debug "Assessing information security policy for project: $project_id"
    
    # 12.1.1 - Security policy establishment and dissemination
    add_check_result "$OUTPUT_FILE" "info" "12.1.1 - Security policy documentation" \
        "Verify overall information security policy is established, published, maintained, and disseminated to all relevant personnel"
    
    # 12.1.2 - Policy review and updates
    add_check_result "$OUTPUT_FILE" "info" "12.1.2 - Policy review schedule" \
        "Verify information security policy is reviewed at least once every 12 months and updated as needed"
    
    # 12.1.3 - Security roles and responsibilities
    add_check_result "$OUTPUT_FILE" "info" "12.1.3 - Security roles definition" \
        "Verify security policy defines information security roles and responsibilities for all personnel"
    
    # 12.1.4 - CISO or security executive assignment
    add_check_result "$OUTPUT_FILE" "info" "12.1.4 - Security executive assignment" \
        "Verify responsibility for information security is formally assigned to a CISO or security-knowledgeable executive"
    
    # Check for organization-level policies that support security governance
    local org_policies
    org_policies=$(gcloud resource-manager org-policies list \
        --project="$project_id" \
        --format="value(constraint,etag)" \
        2>/dev/null)
    
    if [[ -n "$org_policies" ]]; then
        local policy_count=$(echo "$org_policies" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Organization policy framework" \
            "Found $policy_count organization policies providing governance structure"
        
        # Check for security-related policies
        local security_policies
        security_policies=$(echo "$org_policies" | grep -i -E "(security|iam|compute|storage)" | wc -l)
        
        if [[ $security_policies -gt 0 ]]; then
            add_check_result "$OUTPUT_FILE" "pass" "Security-focused policies" \
                "Found $security_policies security-related organization policies"
        else
            add_check_result "$OUTPUT_FILE" "warning" "Security-focused policies" \
                "No security-specific organization policies found"
        fi
    else
        add_check_result "$OUTPUT_FILE" "warning" "Organization policy framework" \
            "No organization policies found - consider implementing organizational policy constraints"
    fi
    
    # Check for IAM conditions and policies that enforce security
    local iam_conditions
    iam_conditions=$(gcloud projects get-iam-policy "$project_id" \
        --format="json" 2>/dev/null | \
        jq -r '.bindings[] | select(.condition != null) | .condition.title' 2>/dev/null | wc -l)
    
    if [[ $iam_conditions -gt 0 ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "Conditional IAM policies" \
            "Found $iam_conditions conditional IAM policies supporting security governance"
    else
        add_check_result "$OUTPUT_FILE" "info" "Conditional IAM policies" \
            "No conditional IAM policies found - consider using for enhanced access control"
    fi
}

# 12.2 - Acceptable use policies for end-user technologies
assess_acceptable_use_policies() {
    local project_id="$1"
    log_debug "Assessing acceptable use policies for project: $project_id"
    
    # 12.2.1 - End-user technology policies
    add_check_result "$OUTPUT_FILE" "info" "12.2.1 - Acceptable use policies" \
        "Verify acceptable use policies for end-user technologies are documented and implemented"
    
    # Check for organization policies that restrict technology usage
    local restriction_policies
    restriction_policies=$(gcloud resource-manager org-policies list \
        --project="$project_id" \
        --filter="constraint:(constraints/compute.restrictVpcPeering OR constraints/compute.vmExternalIpAccess OR constraints/iam.disableServiceAccountKeyCreation)" \
        --format="value(constraint)" \
        2>/dev/null)
    
    if [[ -n "$restriction_policies" ]]; then
        local restriction_count=$(echo "$restriction_policies" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Technology restriction policies" \
            "Found $restriction_count organization policies restricting technology usage"
    else
        add_check_result "$OUTPUT_FILE" "warning" "Technology restriction policies" \
            "No technology restriction policies found - consider implementing usage controls"
    fi
    
    # Check for approved service accounts (representing approved technology usage)
    local service_accounts
    service_accounts=$(gcloud iam service-accounts list \
        --project="$project_id" \
        --format="value(email,description)" \
        2>/dev/null)
    
    if [[ -n "$service_accounts" ]]; then
        local account_count=$(echo "$service_accounts" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Approved service accounts" \
            "Found $account_count service accounts - ensure all are approved per acceptable use policy"
        
        # Check for service accounts with descriptions (indicating documented approval)
        local documented_accounts
        documented_accounts=$(echo "$service_accounts" | grep -v "^[^[:space:]]*$" | wc -l)
        
        if [[ $documented_accounts -gt 0 ]]; then
            add_check_result "$OUTPUT_FILE" "pass" "Documented service accounts" \
                "$documented_accounts out of $account_count service accounts have descriptions"
        else
            add_check_result "$OUTPUT_FILE" "warning" "Documented service accounts" \
                "No service accounts have descriptions - consider documenting business justification"
        fi
    fi
    
    # Check for approved images and templates
    local custom_images
    custom_images=$(gcloud compute images list \
        --project="$project_id" \
        --no-standard-images \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -n "$custom_images" ]]; then
        local image_count=$(echo "$custom_images" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Approved custom images" \
            "Found $image_count custom images - ensure all are approved per policy"
    else
        add_check_result "$OUTPUT_FILE" "info" "Custom images" \
            "No custom images found - using standard Google images"
    fi
}

# 12.3 - Risk management
assess_risk_management() {
    local project_id="$1"
    log_debug "Assessing risk management for project: $project_id"
    
    # 12.3.1 - Targeted risk analysis
    add_check_result "$OUTPUT_FILE" "info" "12.3.1 - Targeted risk analysis" \
        "Verify targeted risk analysis is documented for each PCI DSS requirement specifying risk analysis"
    
    # 12.3.2 - Customized approach risk analysis
    add_check_result "$OUTPUT_FILE" "info" "12.3.2 - Customized approach analysis" \
        "If using customized approach: Verify targeted risk analysis is performed with senior management approval"
    
    # 12.3.3 - Cryptographic cipher suites review
    add_check_result "$OUTPUT_FILE" "info" "12.3.3 - Cryptographic review" \
        "Verify cryptographic cipher suites and protocols are documented and reviewed annually"
    
    # Check for KMS keys and their management (cryptographic inventory)
    local kms_keys
    kms_keys=$(gcloud kms keys list \
        --location=global \
        --project="$project_id" \
        --format="value(name,purpose)" \
        2>/dev/null)
    
    if [[ -z "$kms_keys" ]]; then
        # Try common locations if global doesn't work
        local locations=("us-central1" "us-east1" "europe-west1")
        for location in "${locations[@]}"; do
            kms_keys=$(gcloud kms keys list \
                --location="$location" \
                --project="$project_id" \
                --format="value(name,purpose)" \
                2>/dev/null)
            [[ -n "$kms_keys" ]] && break
        done
    fi
    
    if [[ -n "$kms_keys" ]]; then
        local key_count=$(echo "$kms_keys" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Cryptographic key inventory" \
            "Found $key_count KMS keys - ensure cryptographic review includes all keys"
    else
        add_check_result "$OUTPUT_FILE" "info" "Cryptographic key inventory" \
            "No KMS keys found - using Google-managed encryption"
    fi
    
    # 12.3.4 - Hardware and software technology review
    add_check_result "$OUTPUT_FILE" "info" "12.3.4 - Technology review" \
        "Verify hardware and software technologies are reviewed annually for security support and compliance"
    
    # Check for asset inventory that supports technology review
    local compute_instances
    compute_instances=$(gcloud compute instances list \
        --project="$project_id" \
        --format="value(name,machineType,status)" \
        2>/dev/null)
    
    if [[ -n "$compute_instances" ]]; then
        local instance_count=$(echo "$compute_instances" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Compute instance inventory" \
            "Found $instance_count compute instances for technology review"
    fi
    
    # Check for container images and their versions
    local container_images
    container_images=$(gcloud container images list \
        --project="$project_id" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -n "$container_images" ]]; then
        local image_count=$(echo "$container_images" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Container image inventory" \
            "Found $image_count container images for technology review"
    fi
    
    # Check Security Command Center for risk findings
    local risk_findings
    risk_findings=$(gcloud scc findings list \
        --organization="$(gcloud organizations list --format='value(name)' | head -1)" \
        --filter="resourceName:projects/$project_id AND state:ACTIVE" \
        --format="value(category,severity)" \
        2>/dev/null)
    
    if [[ -n "$risk_findings" ]]; then
        local finding_count=$(echo "$risk_findings" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Risk identification (SCC)" \
            "Security Command Center identified $finding_count risks for management"
    else
        add_check_result "$OUTPUT_FILE" "info" "Risk identification (SCC)" \
            "No active Security Command Center findings - environment may be secure or SCC not configured"
    fi
}

# 12.4 - PCI DSS compliance management
assess_compliance_management() {
    local project_id="$1"
    log_debug "Assessing PCI DSS compliance management for project: $project_id"
    
    # 12.4.1 - Service provider compliance responsibility (if applicable)
    add_check_result "$OUTPUT_FILE" "info" "12.4.1 - Service provider compliance" \
        "If service provider: Verify executive management establishes responsibility for cardholder data protection"
    
    # 12.4.2 - Service provider operational reviews (if applicable)
    add_check_result "$OUTPUT_FILE" "info" "12.4.2 - Service provider reviews" \
        "If service provider: Verify quarterly reviews of security tasks performance"
    
    # Check for audit logging that supports compliance monitoring
    local audit_logs
    audit_logs=$(gcloud logging logs list \
        --project="$project_id" \
        --filter="name:cloudaudit" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -n "$audit_logs" ]]; then
        local log_count=$(echo "$audit_logs" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Audit logging for compliance" \
            "Found $log_count audit log streams supporting compliance monitoring"
    else
        add_check_result "$OUTPUT_FILE" "fail" "Audit logging for compliance" \
            "No audit logs found - critical for compliance monitoring"
    fi
    
    # Check for monitoring and alerting that supports compliance
    local monitoring_policies
    monitoring_policies=$(gcloud alpha monitoring policies list \
        --project="$project_id" \
        --format="value(displayName)" \
        2>/dev/null)
    
    if [[ -n "$monitoring_policies" ]]; then
        local policy_count=$(echo "$monitoring_policies" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Compliance monitoring policies" \
            "Found $policy_count monitoring policies supporting compliance oversight"
    else
        add_check_result "$OUTPUT_FILE" "warning" "Compliance monitoring policies" \
            "No monitoring policies found - consider implementing compliance monitoring"
    fi
    
    # Check for security-related IAM roles (indicating compliance roles)
    local security_roles
    security_roles=$(gcloud iam roles list \
        --project="$project_id" \
        --filter="name:*security* OR name:*audit* OR name:*compliance*" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -n "$security_roles" ]]; then
        local role_count=$(echo "$security_roles" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Security compliance roles" \
            "Found $role_count custom security/compliance roles"
    else
        add_check_result "$OUTPUT_FILE" "info" "Security compliance roles" \
            "No custom security/compliance roles found - using predefined roles"
    fi
}

# 12.5 - PCI DSS scope documentation and validation
assess_scope_management() {
    local project_id="$1"
    log_debug "Assessing PCI DSS scope management for project: $project_id"
    
    # 12.5.1 - System component inventory
    add_check_result "$OUTPUT_FILE" "info" "12.5.1 - System component inventory" \
        "Verify inventory of system components in PCI DSS scope is maintained and current"
    
    # 12.5.2 - Scope documentation and validation
    add_check_result "$OUTPUT_FILE" "info" "12.5.2 - Scope validation" \
        "Verify PCI DSS scope is documented and confirmed annually and upon significant changes"
    
    # Use Cloud Asset Inventory for scope documentation support
    local asset_inventory
    asset_inventory=$(gcloud asset search-all-resources \
        --scope="projects/$project_id" \
        --asset-types="compute.googleapis.com/Instance,storage.googleapis.com/Bucket,cloudkms.googleapis.com/CryptoKey" \
        --format="value(assetType,name)" \
        2>/dev/null)
    
    if [[ -n "$asset_inventory" ]]; then
        local asset_count=$(echo "$asset_inventory" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Asset inventory support" \
            "Cloud Asset Inventory tracking $asset_count assets to support scope documentation"
        
        # Analyze asset types
        local compute_assets=$(echo "$asset_inventory" | grep "compute.googleapis.com" | wc -l)
        local storage_assets=$(echo "$asset_inventory" | grep "storage.googleapis.com" | wc -l)
        local kms_assets=$(echo "$asset_inventory" | grep "cloudkms.googleapis.com" | wc -l)
        
        add_check_result "$OUTPUT_FILE" "info" "Scope asset breakdown" \
            "Assets by type: Compute=$compute_assets, Storage=$storage_assets, KMS=$kms_assets"
    else
        add_check_result "$OUTPUT_FILE" "warning" "Asset inventory support" \
            "No assets found in Cloud Asset Inventory"
    fi
    
    # Check for network topology information
    local vpc_networks
    vpc_networks=$(gcloud compute networks list \
        --project="$project_id" \
        --format="value(name,mode)" \
        2>/dev/null)
    
    if [[ -n "$vpc_networks" ]]; then
        local network_count=$(echo "$vpc_networks" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Network topology documentation" \
            "Found $network_count VPC networks for scope and data flow documentation"
    fi
    
    # Check for interconnects or VPN connections (third-party connections)
    local vpn_tunnels
    vpn_tunnels=$(gcloud compute vpn-tunnels list \
        --project="$project_id" \
        --format="value(name,status)" \
        2>/dev/null)
    
    if [[ -n "$vpn_tunnels" ]]; then
        local tunnel_count=$(echo "$vpn_tunnels" | wc -l)
        add_check_result "$OUTPUT_FILE" "info" "Third-party connections" \
            "Found $tunnel_count VPN tunnels - ensure documented in scope assessment"
    fi
    
    # 12.5.2.1 & 12.5.3 - Service provider additional requirements
    add_check_result "$OUTPUT_FILE" "info" "12.5.2.1 - Service provider scope validation" \
        "If service provider: Verify scope validation occurs at least every 6 months"
    
    add_check_result "$OUTPUT_FILE" "info" "12.5.3 - Organizational change review" \
        "If service provider: Verify organizational changes trigger scope impact review"
}

# 12.6 - Security awareness education
assess_security_awareness() {
    local project_id="$1"
    log_debug "Assessing security awareness education for project: $project_id"
    
    # 12.6.1 - Formal security awareness program
    add_check_result "$OUTPUT_FILE" "info" "12.6.1 - Security awareness program" \
        "Verify formal security awareness program is implemented for all personnel"
    
    # 12.6.2 - Program review and updates
    add_check_result "$OUTPUT_FILE" "info" "12.6.2 - Awareness program review" \
        "Verify security awareness program is reviewed annually and updated for new threats"
    
    # 12.6.3 - Personnel training requirements
    add_check_result "$OUTPUT_FILE" "info" "12.6.3 - Personnel training" \
        "Verify personnel receive security awareness training upon hire and annually"
    
    # 12.6.3.1 - Threat awareness training
    add_check_result "$OUTPUT_FILE" "info" "12.6.3.1 - Threat awareness" \
        "Verify security training includes phishing and social engineering awareness"
    
    # 12.6.3.2 - Acceptable use training
    add_check_result "$OUTPUT_FILE" "info" "12.6.3.2 - Acceptable use training" \
        "Verify security training includes acceptable use of end-user technologies"
    
    # Check for security-related monitoring that could indicate awareness needs
    local security_incidents
    security_incidents=$(gcloud scc findings list \
        --organization="$(gcloud organizations list --format='value(name)' | head -1)" \
        --filter="resourceName:projects/$project_id AND category:SOCIAL_ENGINEERING" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -n "$security_incidents" ]]; then
        local incident_count=$(echo "$security_incidents" | wc -l)
        add_check_result "$OUTPUT_FILE" "warning" "Social engineering threats" \
            "Found $incident_count social engineering threats - ensure awareness training addresses these"
    else
        add_check_result "$OUTPUT_FILE" "pass" "Social engineering threats" \
            "No social engineering threats detected"
    fi
    
    # Check for phishing protection services
    local security_policies
    security_policies=$(gcloud resource-manager org-policies list \
        --project="$project_id" \
        --filter="constraint:constraints/iam.allowedPolicyMemberDomains" \
        --format="value(constraint)" \
        2>/dev/null)
    
    if [[ -n "$security_policies" ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "Domain restriction policies" \
            "Organization policies restrict external domains - supports phishing protection"
    else
        add_check_result "$OUTPUT_FILE" "info" "Domain restriction policies" \
            "No domain restriction policies found"
    fi
}

# 12.7 - Personnel screening
assess_personnel_screening() {
    local project_id="$1"
    log_debug "Assessing personnel screening for project: $project_id"
    
    # 12.7.1 - Background checks for CDE access
    add_check_result "$OUTPUT_FILE" "info" "12.7.1 - Personnel screening" \
        "Verify personnel with CDE access are screened prior to hire per local laws"
    
    # Check for IAM policies that support access control
    local privileged_users
    privileged_users=$(gcloud projects get-iam-policy "$project_id" \
        --format="json" 2>/dev/null | \
        jq -r '.bindings[] | select(.role | contains("owner") or contains("editor")) | .members[]' 2>/dev/null | \
        grep "user:" | wc -l)
    
    if [[ $privileged_users -gt 0 ]]; then
        add_check_result "$OUTPUT_FILE" "info" "Privileged user access" \
            "Found $privileged_users users with privileged access - ensure all are properly screened"
    fi
    
    # Check for service account usage patterns (indicating access controls)
    local service_accounts
    service_accounts=$(gcloud iam service-accounts list \
        --project="$project_id" \
        --format="value(email)" \
        2>/dev/null)
    
    if [[ -n "$service_accounts" ]]; then
        local sa_count=$(echo "$service_accounts" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Service account governance" \
            "Found $sa_count service accounts - ensure proper approval process for creation"
    fi
}

# 12.8 - Third-party service provider management
assess_third_party_management() {
    local project_id="$1"
    log_debug "Assessing third-party service provider management for project: $project_id"
    
    # 12.8.1 - TPSP inventory
    add_check_result "$OUTPUT_FILE" "info" "12.8.1 - TPSP inventory" \
        "Verify list of all third-party service providers with account data access is maintained"
    
    # 12.8.2 - Written agreements with TPSPs
    add_check_result "$OUTPUT_FILE" "info" "12.8.2 - TPSP agreements" \
        "Verify written agreements exist with all TPSPs acknowledging security responsibilities"
    
    # 12.8.3 - TPSP engagement process
    add_check_result "$OUTPUT_FILE" "info" "12.8.3 - TPSP due diligence" \
        "Verify established process for engaging TPSPs with proper due diligence"
    
    # 12.8.4 - TPSP compliance monitoring
    add_check_result "$OUTPUT_FILE" "info" "12.8.4 - TPSP compliance monitoring" \
        "Verify program to monitor TPSPs' PCI DSS compliance status annually"
    
    # 12.8.5 - TPSP responsibility matrix
    add_check_result "$OUTPUT_FILE" "info" "12.8.5 - TPSP responsibility matrix" \
        "Verify information is maintained about which PCI DSS requirements are managed by each TPSP"
    
    # Check for external connections that might indicate third-party relationships
    local external_ips
    external_ips=$(gcloud compute instances list \
        --project="$project_id" \
        --format="value(name,networkInterfaces[0].accessConfigs[0].natIP)" \
        2>/dev/null | grep -v "^[^[:space:]]*$" | wc -l)
    
    if [[ $external_ips -gt 0 ]]; then
        add_check_result "$OUTPUT_FILE" "info" "External connectivity" \
            "Found $external_ips instances with external IPs - review for third-party connections"
    fi
    
    # Check for Cloud SQL instances (potential third-party data sharing)
    local sql_instances
    sql_instances=$(gcloud sql instances list \
        --project="$project_id" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -n "$sql_instances" ]]; then
        local db_count=$(echo "$sql_instances" | wc -l)
        add_check_result "$OUTPUT_FILE" "info" "Database instances" \
            "Found $db_count SQL instances - ensure TPSP agreements cover database services"
    fi
    
    # Note: Google Cloud is itself a TPSP that should be covered
    add_check_result "$OUTPUT_FILE" "info" "Google Cloud as TPSP" \
        "Ensure Google Cloud is included in TPSP inventory with appropriate agreements"
}

# 12.9 - Service provider customer support (if applicable)
assess_service_provider_support() {
    local project_id="$1"
    log_debug "Assessing service provider customer support for project: $project_id"
    
    # 12.9.1 - Customer agreements
    add_check_result "$OUTPUT_FILE" "info" "12.9.1 - Customer agreements" \
        "If service provider: Verify written agreements with customers acknowledge security responsibilities"
    
    # 12.9.2 - Customer compliance support
    add_check_result "$OUTPUT_FILE" "info" "12.9.2 - Customer compliance support" \
        "If service provider: Verify support for customer compliance information requests"
    
    # Check for multi-tenancy indicators
    local projects_in_org
    if [[ "$SCOPE" == "organization" && -n "$ORG_ID" ]]; then
        projects_in_org=$(gcloud projects list \
            --filter="parent.id:$ORG_ID" \
            --format="value(projectId)" \
            2>/dev/null | wc -l)
        
        if [[ $projects_in_org -gt 1 ]]; then
            add_check_result "$OUTPUT_FILE" "info" "Multi-tenant environment" \
                "Found $projects_in_org projects in organization - may indicate service provider model"
        fi
    fi
}

# 12.10 - Incident response
assess_incident_response() {
    local project_id="$1"
    log_debug "Assessing incident response for project: $project_id"
    
    # 12.10.1 - Incident response plan
    add_check_result "$OUTPUT_FILE" "info" "12.10.1 - Incident response plan" \
        "Verify incident response plan exists and includes all required elements"
    
    # 12.10.2 - Plan testing and updates
    add_check_result "$OUTPUT_FILE" "info" "12.10.2 - Plan testing" \
        "Verify incident response plan is reviewed and tested annually"
    
    # 12.10.3 - 24/7 incident response capability
    add_check_result "$OUTPUT_FILE" "info" "12.10.3 - 24/7 response capability" \
        "Verify specific personnel are designated for 24/7 incident response"
    
    # 12.10.4 - Incident response training
    add_check_result "$OUTPUT_FILE" "info" "12.10.4 - Response personnel training" \
        "Verify incident response personnel are appropriately trained"
    
    # Check for Security Command Center integration (incident detection)
    local active_findings
    active_findings=$(gcloud scc findings list \
        --organization="$(gcloud organizations list --format='value(name)' | head -1)" \
        --filter="resourceName:projects/$project_id AND state:ACTIVE" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -n "$active_findings" ]]; then
        local finding_count=$(echo "$active_findings" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Incident detection capability" \
            "Security Command Center provides incident detection with $finding_count active findings"
    else
        add_check_result "$OUTPUT_FILE" "info" "Incident detection capability" \
            "No active Security Command Center findings"
    fi
    
    # Check for monitoring and alerting (incident response support)
    local notification_channels
    notification_channels=$(gcloud alpha monitoring channels list \
        --project="$project_id" \
        --format="value(displayName)" \
        2>/dev/null)
    
    if [[ -n "$notification_channels" ]]; then
        local channel_count=$(echo "$notification_channels" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Incident notification channels" \
            "Found $channel_count notification channels for incident response"
    else
        add_check_result "$OUTPUT_FILE" "warning" "Incident notification channels" \
            "No notification channels found - ensure incident response team can be alerted"
    fi
    
    # 12.10.5 - Security monitoring system alerts
    add_check_result "$OUTPUT_FILE" "info" "12.10.5 - Security monitoring alerts" \
        "Verify incident response plan includes monitoring and responding to security system alerts"
    
    # 12.10.6 - Plan evolution
    add_check_result "$OUTPUT_FILE" "info" "12.10.6 - Plan evolution" \
        "Verify incident response plan is modified based on lessons learned and industry developments"
    
    # 12.10.7 - PAN discovery procedures
    add_check_result "$OUTPUT_FILE" "info" "12.10.7 - PAN discovery procedures" \
        "Verify procedures exist for incidents involving discovery of stored PAN in unexpected locations"
    
    # Check for Cloud Functions that might support incident response
    local response_functions
    response_functions=$(gcloud functions list \
        --project="$project_id" \
        --format="value(name)" \
        2>/dev/null | grep -i -E "(incident|response|alert|security)")
    
    if [[ -n "$response_functions" ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "Automated incident response" \
            "Found Cloud Functions that may support automated incident response"
    else
        add_check_result "$OUTPUT_FILE" "info" "Automated incident response" \
            "No automated incident response functions detected"
    fi
}

# Manual verification guidance
add_manual_verification_guidance() {
    log_debug "Adding manual verification guidance"
    
    add_section "$OUTPUT_FILE" "manual_verification" "Manual Verification Required" "Organizational controls requiring manual assessment"
    
    add_check_result "$OUTPUT_FILE" "info" "Information security policy framework" \
        "Verify comprehensive information security policy is established, maintained, and disseminated"
    
    add_check_result "$OUTPUT_FILE" "info" "Acceptable use policy implementation" \
        "Verify acceptable use policies for end-user technologies are documented and enforced"
    
    add_check_result "$OUTPUT_FILE" "info" "Risk management program" \
        "Verify formal risk management program with documented risk analyses and annual reviews"
    
    add_check_result "$OUTPUT_FILE" "info" "PCI DSS compliance program" \
        "Verify PCI DSS compliance is managed with appropriate oversight and documentation"
    
    add_check_result "$OUTPUT_FILE" "info" "Scope documentation maintenance" \
        "Verify PCI DSS scope is documented, validated annually, and updated with changes"
    
    add_check_result "$OUTPUT_FILE" "info" "Security awareness training program" \
        "Verify formal security awareness program with annual training and acknowledgments"
    
    add_check_result "$OUTPUT_FILE" "info" "Personnel screening program" \
        "Verify personnel with CDE access are screened prior to hire per local laws"
    
    add_check_result "$OUTPUT_FILE" "info" "Third-party risk management" \
        "Verify comprehensive third-party service provider risk management program"
    
    add_check_result "$OUTPUT_FILE" "info" "Incident response preparedness" \
        "Verify incident response plan is comprehensive, tested, and personnel are trained"
    
    add_check_result "$OUTPUT_FILE" "info" "Executive security oversight" \
        "Verify executive management oversight of information security program"
}

# Main assessment function
assess_project() {
    local project_id="$1"
    
    log_debug "Assessing project: $project_id"
    
    # Add project section to report
    add_section "$OUTPUT_FILE" "project_$project_id" "Project: $project_id" "Assessment results for project $project_id"
    
    # Perform assessments
    assess_information_security_policy "$project_id"
    assess_acceptable_use_policies "$project_id"
    assess_risk_management "$project_id"
    assess_compliance_management "$project_id"
    assess_scope_management "$project_id"
    assess_security_awareness "$project_id"
    assess_personnel_screening "$project_id"
    assess_third_party_management "$project_id"
    assess_service_provider_support "$project_id"
    assess_incident_response "$project_id"
    
    log_debug "Completed assessment for project: $project_id"
}

# Main execution
main() {
    # Setup environment and parse command line arguments
    setup_environment "requirement12_assessment.log"
    parse_common_arguments "$@"
    case $? in
        1) exit 1 ;;  # Error
        2) exit 0 ;;  # Help displayed
    esac
    
    # Validate GCP environment
    validate_prerequisites || exit 1
    
    # Check permissions using the new comprehensive permission check
    if ! check_required_permissions "${REQ12_PERMISSIONS[@]}"; then
        exit 1
    fi
    
    # Setup assessment scope
    setup_assessment_scope || exit 1
    
    # Configure HTML report
    OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"
    initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report" "${REQUIREMENT_NUMBER}"
    
    # Add assessment introduction
    add_section "$OUTPUT_FILE" "organizational_policies" "Organizational Policies and Programs Assessment" "Assessment of information security policies and organizational controls"
    
    print_status "info" "============================================="
    print_status "info" "  PCI DSS 4.0.1 - Requirement 12 (GCP)"
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
    
    log_debug "Starting PCI DSS Requirement 12 assessment"
    
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
    
    # Add manual verification guidance
    add_manual_verification_guidance
    
    # Add summary metrics before finalizing
    add_summary_metrics "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks"
    
    # Generate final report
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
    print_status "INFO" "Projects assessed: $project_count"
    print_status "PASS" "=================================================================="
    
    return 0
}

# Execute main function
main "$@"