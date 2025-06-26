#!/usr/bin/env bash

# PCI DSS Requirement 4 Compliance Check Script for GCP (Framework-Migrated Version)
# This script evaluates GCP controls for PCI DSS Requirement 4 compliance
# Requirements covered: 4.2 (Protect Cardholder Data with Strong Cryptography During Transmission)
# Requirement 4.1 removed - requires manual verification

# Framework Integration - Load all 4 shared libraries
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh"
source "$LIB_DIR/gcp_permissions.sh"
source "$LIB_DIR/gcp_html_report.sh"
source "$LIB_DIR/gcp_scope_mgmt.sh"

# Define missing log functions
log_info() {
    print_status "INFO" "$1"
}

log_error() {
    print_status "FAIL" "$1"
}

# Script-specific configuration
REQUIREMENT_NUMBER="4"
REQUIREMENT_TITLE="Protect Cardholder Data with Strong Cryptography During Transmission"

# Function to show help
show_help() {
    echo "GCP PCI DSS Requirement 4 Assessment Script (Framework Version)"
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

# Register required permissions for Requirement 4
register_required_permissions "$REQUIREMENT_NUMBER" \
    "compute.sslPolicies.list" \
    "compute.targetHttpsProxies.list" \
    "compute.urlMaps.list" \
    "compute.forwardingRules.list" \
    "compute.backendServices.list" \
    "compute.securityPolicies.list" \
    "compute.sslCertificates.list" \
    "compute.firewalls.list"

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

# 4.2.1 - Strong cryptography and security protocols for PAN transmission
assess_tls_configurations() {
    local project_id="$1"
    local section_title="4.2.1 - Strong Cryptography and Security Protocols"
    local check_title="TLS/SSL Configuration Analysis"
    local details=""
    local status="PASS"
    local findings_count=0
    
    log_info "Assessing TLS configurations for project: $project_id"
    
    details+="<h4>Analysis of TLS/SSL configurations in project $project_id:</h4><ul>"
    
    # Check SSL Policies
    log_debug "Checking SSL policies..."
    local ssl_policies
    ssl_policies=$(gcloud compute ssl-policies list --project="$project_id" --format="value(name,profile,minTlsVersion)" 2>/dev/null)
    
    if [[ -n "$ssl_policies" ]]; then
        details+="<li><strong>SSL Policies Found:</strong><ul>"
        while IFS=$'\t' read -r name profile min_tls; do
            details+="<li>Policy: $name, Profile: $profile, Min TLS: $min_tls"
            if [[ "$min_tls" =~ ^TLS_1_[01]$ ]]; then
                details+=" <span class='warning'>⚠️ Warning: Weak TLS version</span>"
                status="WARNING"
                ((findings_count++))
            else
                details+=" ✅ Strong TLS version"
            fi
            details+="</li>"
        done <<< "$ssl_policies"
        details+="</ul></li>"
    else
        details+="<li>No SSL policies found - using default configurations</li>"
    fi
    
    # Check HTTPS Load Balancers
    log_debug "Checking HTTPS Load Balancers..."
    local https_proxies
    https_proxies=$(gcloud compute target-https-proxies list --project="$project_id" --format="value(name,sslPolicy)" 2>/dev/null)
    
    if [[ -n "$https_proxies" ]]; then
        details+="<li><strong>HTTPS Load Balancers:</strong><ul>"
        while IFS=$'\t' read -r name ssl_policy; do
            details+="<li>Proxy: $name"
            if [[ -n "$ssl_policy" ]]; then
                details+=" - SSL Policy: $ssl_policy ✅"
            else
                details+=" - No SSL Policy configured <span class='warning'>⚠️</span>"
                status="WARNING"
                ((findings_count++))
            fi
            details+="</li>"
        done <<< "$https_proxies"
        details+="</ul></li>"
    else
        details+="<li>No HTTPS Load Balancers found</li>"
    fi
    
    details+="</ul>"
    
    if [[ $findings_count -gt 0 ]]; then
        details+="<p><strong>Findings:</strong> $findings_count TLS configuration issues require attention.</p>"
    else
        details+="<p><strong>Result:</strong> All TLS configurations use strong cryptography.</p>"
    fi
    
    add_check_result "$OUTPUT_FILE" "$(echo "$status" | tr '[:upper:]' '[:lower:]')" "$check_title" "$details"
}

# 4.2.1.1 - Inventory of trusted keys and certificates
assess_ssl_certificates() {
    local project_id="$1"
    local section_title="4.2.1.1 - Inventory of Trusted Keys and Certificates"
    local check_title="SSL Certificate Inventory and Management"
    local details=""
    local status="PASS"
    local cert_count=0
    local expiring_count=0
    
    log_info "Assessing SSL certificates for project: $project_id"
    
    details+="<h4>SSL Certificate inventory for project $project_id:</h4><ul>"
    
    # Get SSL certificates
    local certificates
    certificates=$(gcloud compute ssl-certificates list --project="$project_id" --format="value(name,type,creationTimestamp,expireTime)" 2>/dev/null)
    
    if [[ -n "$certificates" ]]; then
        while IFS=$'\t' read -r name cert_type created expire_time; do
            ((cert_count++))
            details+="<li><strong>Certificate:</strong> $name<ul>"
            details+="<li>Type: $cert_type</li>"
            details+="<li>Created: $created</li>"
            
            if [[ -n "$expire_time" && "$expire_time" != "null" ]]; then
                details+="<li>Expires: $expire_time"
                
                # Check if certificate expires within 30 days
                local expire_timestamp
                expire_timestamp=$(date -d "$expire_time" +%s 2>/dev/null || echo "0")
                local current_timestamp
                current_timestamp=$(date +%s)
                local days_until_expiry
                days_until_expiry=$(( (expire_timestamp - current_timestamp) / 86400 ))
                
                if [[ $days_until_expiry -lt 30 && $days_until_expiry -gt 0 ]]; then
                    details+=" <span class='warning'>⚠️ Expires in $days_until_expiry days</span>"
                    status="WARNING"
                    ((expiring_count++))
                elif [[ $days_until_expiry -le 0 ]]; then
                    details+=" <span class='fail'>❌ EXPIRED</span>"
                    status="FAIL"
                    ((expiring_count++))
                else
                    details+=" ✅ Valid"
                fi
                details+="</li>"
            else
                details+="<li>Expires: Managed certificate (auto-renewal)</li>"
            fi
            details+="</ul></li>"
        done <<< "$certificates"
    else
        details+="<li>No SSL certificates found in this project</li>"
    fi
    
    details+="</ul>"
    details+="<p><strong>Summary:</strong> Found $cert_count SSL certificates"
    if [[ $expiring_count -gt 0 ]]; then
        details+=" ($expiring_count expiring/expired certificates require attention)"
    fi
    details+="</p>"
    
    add_check_result "$OUTPUT_FILE" "$(echo "$status" | tr '[:upper:]' '[:lower:]')" "$check_title" "$details"
}

# 4.2.1.2 - Wireless network security
assess_unencrypted_services() {
    local project_id="$1"
    local section_title="4.2.1.2 - Unencrypted Communication Analysis"
    local check_title="Firewall Rules for Unencrypted Protocols"
    local details=""
    local status="PASS"
    local insecure_count=0
    
    log_info "Assessing firewall rules for unencrypted protocols: $project_id"
    
    details+="<h4>Analysis of firewall rules allowing unencrypted protocols in project $project_id:</h4><ul>"
    
    # Check for firewall rules allowing insecure protocols
    local insecure_protocols=("80" "23" "21" "143" "110" "993" "995")
    
    for port in "${insecure_protocols[@]}"; do
        local rules
        rules=$(gcloud compute firewall-rules list --project="$project_id" \
                --filter="allowed.ports:($port) AND direction=INGRESS" \
                --format="value(name,sourceRanges.list(),allowed.list())" 2>/dev/null)
        
        if [[ -n "$rules" ]]; then
            while IFS=$'\t' read -r rule_name sources allowed; do
                if [[ "$sources" == *"0.0.0.0/0"* ]]; then
                    details+="<li><span class='fail'>❌ RISK:</span> Rule '$rule_name' allows port $port from internet (0.0.0.0/0)</li>"
                    status="FAIL"
                    ((insecure_count++))
                else
                    details+="<li><span class='warning'>⚠️ Warning:</span> Rule '$rule_name' allows port $port from restricted sources</li>"
                    if [[ "$status" != "FAIL" ]]; then
                        status="WARNING"
                    fi
                fi
            done <<< "$rules"
        fi
    done
    
    if [[ $insecure_count -eq 0 ]]; then
        details+="<li>✅ No firewall rules found allowing unencrypted protocols from the internet</li>"
    fi
    
    details+="</ul>"
    
    if [[ $insecure_count -gt 0 ]]; then
        details+="<p><strong>Critical:</strong> $insecure_count firewall rules allow unencrypted protocols from the internet.</p>"
    fi
    
    add_check_result "$OUTPUT_FILE" "$(echo "$status" | tr '[:upper:]' '[:lower:]')" "$check_title" "$details"
}

# 4.2.2 - End-user messaging technologies security
assess_cloud_cdn_armor() {
    local project_id="$1"
    local section_title="4.2.2 - End-user Messaging Technologies Security"
    local check_title="Cloud CDN and Cloud Armor Security Analysis"
    local details=""
    local status="PASS"
    
    log_info "Assessing Cloud CDN and Cloud Armor security: $project_id"
    
    details+="<h4>Cloud CDN and Cloud Armor security analysis for project $project_id:</h4><ul>"
    
    # Check Backend Services with CDN
    local backend_services
    backend_services=$(gcloud compute backend-services list --project="$project_id" \
                      --format="value(name,enableCDN,securityPolicy)" 2>/dev/null)
    
    if [[ -n "$backend_services" ]]; then
        while IFS=$'\t' read -r name cdn_enabled security_policy; do
            details+="<li><strong>Backend Service:</strong> $name<ul>"
            
            if [[ "$cdn_enabled" == "True" ]]; then
                details+="<li>CDN: Enabled ✅</li>"
            else
                details+="<li>CDN: Disabled</li>"
            fi
            
            if [[ -n "$security_policy" && "$security_policy" != "null" ]]; then
                details+="<li>Security Policy: $security_policy ✅</li>"
            else
                details+="<li>Security Policy: None configured <span class='warning'>⚠️</span></li>"
                status="WARNING"
            fi
            details+="</ul></li>"
        done <<< "$backend_services"
    else
        details+="<li>No backend services found</li>"
    fi
    
    # Check Security Policies
    local security_policies
    security_policies=$(gcloud compute security-policies list --project="$project_id" \
                       --format="value(name,rules.list().length())" 2>/dev/null)
    
    if [[ -n "$security_policies" ]]; then
        details+="<li><strong>Cloud Armor Security Policies:</strong><ul>"
        while IFS=$'\t' read -r policy_name rule_count; do
            details+="<li>Policy: $policy_name ($rule_count rules) ✅</li>"
        done <<< "$security_policies"
        details+="</ul></li>"
    else
        details+="<li>No Cloud Armor security policies configured</li>"
    fi
    
    details+="</ul>"
    
    add_check_result "$OUTPUT_FILE" "$(echo "$status" | tr '[:upper:]' '[:lower:]')" "$check_title" "$details"
}

# Main assessment loop
main() {
    log_info "Starting PCI DSS Requirement 4 assessment"
    
    # Get projects to assess
    local projects
    projects=$(get_projects_in_scope)
    
    if [[ -z "$projects" ]]; then
        log_error "No projects found in scope"
        exit 1
    fi
    
    # Process each project
    while IFS= read -r project_id; do
        [[ -z "$project_id" ]] && continue
        
        log_info "Processing project: $project_id"
        add_section "$OUTPUT_FILE" "project_$project_id" "Project: $project_id"
        
        # Run all assessments for this project
        assess_tls_configurations "$project_id"
        assess_ssl_certificates "$project_id"
        assess_unencrypted_services "$project_id"
        assess_cloud_cdn_armor "$project_id"
        
    done <<< "$projects"
    
    # Finalize report
    finalize_report "$OUTPUT_FILE" "$REQUIREMENT_NUMBER"
    
    log_info "Assessment completed. Report generated: $OUTPUT_FILE"
    echo "Report location: $OUTPUT_FILE"
}

# Execute main function
main "$@"