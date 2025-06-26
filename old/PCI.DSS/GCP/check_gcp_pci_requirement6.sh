#!/usr/bin/env bash

# PCI DSS Requirement 6 Compliance Check Script for GCP
# Develop and Maintain Secure Systems and Software

# Load shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1
source "$LIB_DIR/gcp_scope_mgmt.sh" || exit 1
source "$LIB_DIR/gcp_html_report.sh" || exit 1

# Script-specific variables
REQUIREMENT_NUMBER="6"

# Counters for checks  
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

# Note: Initialization moved to main function to follow modern framework pattern

# Define required permissions for Requirement 6
declare -a REQ6_PERMISSIONS=(
    "cloudbuild.builds.list"
    "container.images.list"
    "compute.securityPolicies.list"
    "appengine.applications.get"
    "run.services.list"
    "compute.urlMaps.list"
    "storage.buckets.list"
    "source.repos.list"
    "compute.backendServices.list"
    "artifactregistry.repositories.list"
    "secretmanager.secrets.list"
    "cloudkms.keyRings.list"
    "binaryauthorization.policy.getIamPolicy"
    "resourcemanager.projects.get"
    "resourcemanager.organizations.get"
)

# Function to show help
show_help() {
    echo "GCP PCI DSS Requirement 6 Assessment Script (Framework Version)"
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

# Note: Report initialization moved to main function


# Assessment function for secure development processes (PCI DSS 6.1, 6.2)
assess_secure_development() {
    local project_id="$1"
    
    log_debug "Assessing secure development processes for project: $project_id"
    
    local check_status="PASS"
    local details=""
    local issues_found=0
    
    # Set project context if provided
    local gcloud_cmd_prefix=""
    if [[ -n "$project_id" ]]; then
        gcloud_cmd_prefix="--project=$project_id"
    fi
    
    details+="<h4>Secure CI/CD Pipeline Assessment</h4>"
    details+="<p>Analyzing Cloud Build for secure development practices:</p><ul>"
    
    # Get Cloud Build triggers
    local triggers
    triggers=$(gcloud builds triggers list $gcloud_cmd_prefix --format="value(name,github.name,substitutions)" 2>/dev/null)
    
    if [[ -z "$triggers" ]]; then
        details+="<li>No Cloud Build triggers found - Manual verification required for secure development processes</li>"
        check_status="MANUAL"
    else
        while IFS=$'\t' read -r trigger_name repo_name substitutions; do
            [[ -z "$trigger_name" ]] && continue
            
            details+="<li><strong>Trigger:</strong> $trigger_name"
            [[ -n "$repo_name" ]] && details+=" (Repository: $repo_name)"
            
            # Check for security scanning steps
            local trigger_config
            trigger_config=$(gcloud builds triggers describe "$trigger_name" $gcloud_cmd_prefix --format="value(build)" 2>/dev/null)
            
            if echo "$trigger_config" | grep -qiE "security|scan|test|sast|dast|sonar|snyk|twistlock"; then
                details+=" - <span class='check-pass'>Security scanning integrated</span>"
            else
                details+=" - <span class='check-warning'>No security scanning detected</span>"
                ((issues_found++))
                check_status="WARNING"
            fi
            
            # Check for sensitive substitutions
            if echo "$substitutions" | grep -qiE "key|secret|password|token"; then
                details+=" - <span class='check-fail'>Sensitive variables in substitutions</span>"
                ((issues_found++))
                check_status="FAIL"
            fi
            
            details+="</li>"
        done <<< "$triggers"
    fi
    
    details+="</ul>"
    
    # Add secure development guidance
    details+="<h4>Secure Development Requirements</h4>"
    details+="<ul><li>Security training for developers</li>"
    details+="<li>Secure coding standards implementation</li>"
    details+="<li>Code review processes for security</li>"
    details+="<li>Static and dynamic application security testing</li></ul>"
    
    add_check_result "$OUTPUT_FILE" "info" "Secure Development Processes" "$details"
    ((total_checks++))
    
    log_debug "Secure development assessment complete: $check_status ($issues_found issues)"
}

# Assessment function for vulnerability management (PCI DSS 6.3)
assess_vulnerability_management() {
    local project_id="$1"
    
    log_debug "Assessing vulnerability management for project: $project_id"
    
    local check_status="PASS"
    local details=""
    local critical_vulns=0
    
    # Set project context if provided
    local gcloud_cmd_prefix=""
    if [[ -n "$project_id" ]]; then
        gcloud_cmd_prefix="--project=$project_id"
    fi
    
    details+="<h4>Container Vulnerability Management</h4>"
    
    # Check Artifact Registry repositories
    local ar_repos
    ar_repos=$(gcloud artifacts repositories list $gcloud_cmd_prefix --format="value(name,format)" 2>/dev/null)
    
    if [[ -n "$ar_repos" ]]; then
        details+="<p><strong>Artifact Registry Repositories:</strong></p><ul>"
        
        while IFS=$'\t' read -r repo_name format; do
            [[ -z "$repo_name" ]] && continue
            
            if [[ "$format" == "DOCKER" ]]; then
                details+="<li><strong>Repository:</strong> $repo_name"
                
                # Check vulnerability scanning configuration
                local scan_config
                scan_config=$(gcloud artifacts repositories describe "$repo_name" $gcloud_cmd_prefix --format="value(vulnerabilityScanningConfig)" 2>/dev/null)
                
                if [[ -n "$scan_config" ]]; then
                    details+=" - <span class='check-pass'>Vulnerability scanning enabled</span>"
                else
                    details+=" - <span class='check-warning'>Vulnerability scanning not configured</span>"
                    check_status="WARNING"
                fi
                details+="</li>"
            fi
        done <<< "$ar_repos"
        details+="</ul>"
    fi
    
    # Check Container Registry images
    local gcr_images
    gcr_images=$(gcloud container images list $gcloud_cmd_prefix --format="value(name)" 2>/dev/null)
    
    if [[ -n "$gcr_images" ]]; then
        details+="<p><strong>Container Registry Images:</strong></p><ul>"
        
        while IFS= read -r image; do
            [[ -z "$image" ]] && continue
            
            # Check for vulnerabilities
            local vulns
            vulns=$(gcloud container images scan "$image" $gcloud_cmd_prefix --format="value(vulnerabilities.discovery.vulnerability)" 2>/dev/null | grep -c "CRITICAL\|HIGH" 2>/dev/null || echo "0")
            # Ensure vulns is a single number
            vulns=$(echo "$vulns" | head -1 | tr -d '\n\r' | grep -o '[0-9]*' | head -1)
            [[ -z "$vulns" ]] && vulns=0
            
            if [[ "$vulns" -gt 0 ]]; then
                details+="<li><span class='check-fail'>$image - $vulns high/critical vulnerabilities</span></li>"
                ((critical_vulns += vulns))
                check_status="FAIL"
            else
                details+="<li><span class='check-pass'>$image - No critical vulnerabilities detected</span></li>"
            fi
        done <<< "$gcr_images"
        details+="</ul>"
    fi
    
    if [[ -z "$ar_repos" && -z "$gcr_images" ]]; then
        details+="<p>No container repositories found - Manual verification required</p>"
        check_status="MANUAL"
    fi
    
    # Add vulnerability management guidance
    details+="<h4>Vulnerability Management Requirements</h4>"
    details+="<ul><li>Regular vulnerability scanning of all container images</li>"
    details+="<li>Automated vulnerability detection in CI/CD pipelines</li>"
    details+="<li>Timely remediation of critical and high vulnerabilities</li>"
    details+="<li>Security monitoring and alerting for new vulnerabilities</li></ul>"
    
    add_check_result "$OUTPUT_FILE" "info" "Vulnerability Management" "$details"
    ((total_checks++))
    
    log_debug "Vulnerability management assessment complete: $check_status ($critical_vulns critical vulnerabilities)"
}

# Assessment function for web application protection (PCI DSS 6.4)
assess_web_protection() {
    local project_id="$1"
    
    log_debug "Assessing web application protection for project: $project_id"
    
    local check_status="PASS"
    local details=""
    local unprotected_services=0
    
    # Set project context if provided
    local gcloud_cmd_prefix=""
    if [[ -n "$project_id" ]]; then
        gcloud_cmd_prefix="--project=$project_id"
    fi
    
    details+="<h4>Web Application Protection Assessment</h4>"
    
    # Check Cloud Armor security policies with detailed rule analysis
    local armor_policies
    armor_policies=$(gcloud compute security-policies list $gcloud_cmd_prefix --format="value(name,description)" 2>/dev/null)
    
    if [[ -z "$armor_policies" ]]; then
        details+="<p><span class='check-fail'>No Cloud Armor security policies found</span></p>"
        details+="<p>Web applications must be protected by Web Application Firewall (WAF) for PCI DSS compliance</p>"
        check_status="FAIL"
    else
        details+="<p><strong>Cloud Armor Security Policies Analysis:</strong></p>"
        local policy_count=0
        local effective_policies=0
        
        while IFS=$'\t' read -r policy_name description; do
            [[ -z "$policy_name" ]] && continue
            ((policy_count++))
            
            # Get detailed policy rules
            local policy_rules
            policy_rules=$(gcloud compute security-policies describe "$policy_name" $gcloud_cmd_prefix --format="json" 2>/dev/null)
            
            if [[ -n "$policy_rules" ]]; then
                local rule_count
                rule_count=$(echo "$policy_rules" | jq -r '.rules | length' 2>/dev/null || echo "0")
                
                local owasp_rules
                owasp_rules=$(echo "$policy_rules" | jq -r '.rules[] | select(.preconfiguredWafConfig != null) | .preconfiguredWafConfig.exclusions[]?.targetRuleSet' 2>/dev/null | grep -c "owasp" || echo "0")
                
                local rate_limit_rules
                rate_limit_rules=$(echo "$policy_rules" | jq -r '.rules[] | select(.rateLimitOptions != null)' 2>/dev/null | wc -l || echo "0")
                
                details+="<ul><li><strong>Policy: $policy_name</strong>"
                [[ -n "$description" ]] && details+=" - $description"
                details+="<ul>"
                details+="<li>Total Rules: $rule_count</li>"
                
                if [[ "$owasp_rules" -gt 0 ]]; then
                    details+="<li><span class='check-pass'>OWASP Protection: $owasp_rules rules configured</span></li>"
                    ((effective_policies++))
                else
                    details+="<li><span class='check-warning'>No OWASP protection rules found</span></li>"
                fi
                
                if [[ "$rate_limit_rules" -gt 0 ]]; then
                    details+="<li><span class='check-pass'>Rate Limiting: $rate_limit_rules rules configured</span></li>"
                else
                    details+="<li><span class='check-warning'>No rate limiting rules configured</span></li>"
                fi
                
                details+="</ul></li></ul>"
            else
                details+="<ul><li><span class='check-warning'>Policy: $policy_name - Unable to analyze rules</span></li></ul>"
            fi
        done <<< "$armor_policies"
        
        # Overall assessment
        if [[ "$effective_policies" -eq 0 ]]; then
            details+="<p><span class='check-warning'>Cloud Armor policies exist but lack comprehensive WAF protection</span></p>"
            check_status="WARNING"
        elif [[ "$effective_policies" -lt "$policy_count" ]]; then
            details+="<p><span class='check-warning'>Some Cloud Armor policies need enhanced WAF configuration</span></p>"
            [[ "$check_status" == "PASS" ]] && check_status="WARNING"
        fi
    fi
    
    # Check backend services for security policy attachment
    local backend_services
    backend_services=$(gcloud compute backend-services list $gcloud_cmd_prefix --format="value(name,securityPolicy)" 2>/dev/null)
    
    if [[ -n "$backend_services" ]]; then
        details+="<p><strong>Backend Services Security:</strong></p><ul>"
        
        while IFS=$'\t' read -r service_name security_policy; do
            [[ -z "$service_name" ]] && continue
            
            if [[ -n "$security_policy" ]]; then
                details+="<li><span class='check-pass'>$service_name - Protected by: $security_policy</span></li>"
            else
                details+="<li><span class='check-warning'>$service_name - No security policy attached</span></li>"
                ((unprotected_services++))
                check_status="WARNING"
            fi
        done <<< "$backend_services"
        details+="</ul>"
    fi
    
    # Check App Engine applications
    local app_info
    app_info=$(gcloud app describe $gcloud_cmd_prefix --format="value(id,servingStatus)" 2>/dev/null)
    
    if [[ -n "$app_info" ]]; then
        details+="<p><strong>App Engine Applications:</strong></p><ul>"
        details+="<li>App Engine detected - Ensure firewall rules restrict access appropriately</li>"
        details+="<li>Manual verification required for App Engine security configuration</li>"
        details+="</ul>"
        [[ "$check_status" == "PASS" ]] && check_status="MANUAL"
    fi
    
    # Add web protection guidance
    details+="<h4>Web Application Protection Requirements</h4>"
    details+="<ul><li>Web Application Firewall (WAF) protection for public applications</li>"
    details+="<li>Input validation and output encoding</li>"
    details+="<li>Secure coding practices for web applications</li>"
    details+="<li>Regular security testing and penetration testing</li>"
    details+="<li>SSL/TLS encryption for data transmission</li></ul>"
    
    add_check_result "$OUTPUT_FILE" "info" "Web Application Protection" "$details"
    ((total_checks++))
    
    log_debug "Web protection assessment complete: $check_status ($unprotected_services unprotected services)"
}

# Assessment function for change management (PCI DSS 6.5)
assess_change_management() {
    local project_id="$1"
    
    log_debug "Assessing change management processes for project: $project_id"
    
    local check_status="PASS"
    local details=""
    local change_mgmt_issues=0
    
    # Set project context if provided
    local gcloud_cmd_prefix=""
    if [[ -n "$project_id" ]]; then
        gcloud_cmd_prefix="--project=$project_id"
    fi
    
    details+="<h4>Change Management Assessment</h4>"
    
    # Check Cloud Source Repositories for version control
    local repos
    repos=$(gcloud source repos list $gcloud_cmd_prefix --format="value(name)" 2>/dev/null)
    
    if [[ -n "$repos" ]]; then
        details+="<p><strong>Source Code Management:</strong></p><ul>"
        while IFS= read -r repo; do
            [[ -z "$repo" ]] && continue
            details+="<li><span class='check-pass'>Repository: $repo</span></li>"
        done <<< "$repos"
        details+="</ul>"
    else
        details+="<p><span class='check-warning'>No Cloud Source Repositories found</span></p>"
        details+="<p>Version control is essential for change management</p>"
        ((change_mgmt_issues++))
        check_status="WARNING"
    fi
    
    # Check App Engine versions for deployment management
    local app_versions
    app_versions=$(gcloud app versions list $gcloud_cmd_prefix --format="value(service,version,traffic_split)" 2>/dev/null)
    
    if [[ -n "$app_versions" ]]; then
        details+="<p><strong>App Engine Version Management:</strong></p><ul>"
        
        local services
        services=$(echo "$app_versions" | cut -d$'\t' -f1 | sort | uniq)
        
        for service in $services; do
            local versions_count
            versions_count=$(echo "$app_versions" | grep "^$service" | wc -l)
            versions_count=$(echo "$versions_count" | tr -d '\n\r' | grep -o '[0-9]*' | head -1)
            [[ -z "$versions_count" ]] && versions_count=0
            details+="<li><span class='check-pass'>Service $service: $versions_count versions</span></li>"
        done
        details+="</ul>"
    fi
    
    # Check Cloud Functions for environment patterns
    local functions
    functions=$(gcloud functions list $gcloud_cmd_prefix --format="value(name,status)" 2>/dev/null)
    
    if [[ -n "$functions" ]]; then
        details+="<p><strong>Cloud Functions Environment Analysis:</strong></p>"
        
        local env_patterns
        env_patterns=$(echo "$functions" | cut -d$'\t' -f1 | grep -oE '(dev|test|stage|staging|prod|production)' | sort | uniq -c)
        
        if [[ -n "$env_patterns" ]]; then
            details+="<ul>"
            while read -r count env; do
                details+="<li><span class='check-pass'>$env environment: $count functions</span></li>"
            done <<< "$env_patterns"
            details+="</ul>"
        else
            details+="<p><span class='check-warning'>No environment naming patterns detected</span></p>"
            ((change_mgmt_issues++))
            [[ "$check_status" == "PASS" ]] && check_status="WARNING"
        fi
    fi
    
    # Check Cloud Build for CI/CD processes
    local builds
    builds=$(gcloud builds list $gcloud_cmd_prefix --limit=10 --format="value(id,status)" 2>/dev/null)
    
    if [[ -n "$builds" ]]; then
        details+="<p><strong>CI/CD Pipeline Activity:</strong></p>"
        local recent_builds
        recent_builds=$(echo "$builds" | wc -l)
        recent_builds=$(echo "$recent_builds" | tr -d '\n\r' | grep -o '[0-9]*' | head -1)
        [[ -z "$recent_builds" ]] && recent_builds=0
        details+="<p>Recent builds detected ($recent_builds) - Indicates active CI/CD processes</p>"
    fi
    
    # Add change management guidance
    details+="<h4>Change Management Requirements</h4>"
    details+="<ul><li>Version control for all code changes</li>"
    details+="<li>Environment separation (dev, test, prod)</li>"
    details+="<li>Formal change approval processes</li>"
    details+="<li>Automated testing before production deployment</li>"
    details+="<li>Rollback procedures for failed deployments</li></ul>"
    
    add_check_result "$OUTPUT_FILE" "info" "Change Management" "$details"
    ((total_checks++))
    
    log_debug "Change management assessment complete: $check_status ($change_mgmt_issues issues)"
}

# Assessment function for secure development lifecycle practices
assess_secure_development_lifecycle() {
    local project_id="$1"
    
    log_debug "Assessing secure development lifecycle for project: $project_id"
    
    local check_status="PASS"
    local details=""
    local security_gaps=0
    
    # Set project context if provided
    local gcloud_cmd_prefix=""
    if [[ -n "$project_id" ]]; then
        gcloud_cmd_prefix="--project=$project_id"
    fi
    
    details+="<h4>Secure Development Lifecycle Assessment</h4>"
    
    # Check Secret Manager for secure credential management
    local secrets
    secrets=$(gcloud secrets list $gcloud_cmd_prefix --format="value(name)" 2>/dev/null)
    
    if [[ -n "$secrets" ]]; then
        local secrets_count
        secrets_count=$(echo "$secrets" | wc -l)
        secrets_count=$(echo "$secrets_count" | tr -d '\n\r' | grep -o '[0-9]*' | head -1)
        [[ -z "$secrets_count" ]] && secrets_count=0
        details+="<p><strong>Secret Management:</strong></p>"
        details+="<p><span class='check-pass'>Secret Manager in use: $secrets_count secrets managed</span></p>"
    else
        details+="<p><span class='check-warning'>No Secret Manager usage detected</span></p>"
        details+="<p>Secure credential management is essential for development security</p>"
        ((security_gaps++))
        check_status="WARNING"
    fi
    
    # Check Cloud KMS for encryption key management
    local kms_keyrings
    kms_keyrings=$(gcloud kms keyrings list $gcloud_cmd_prefix --location=global --format="value(name)" 2>/dev/null)
    
    if [[ -n "$kms_keyrings" ]]; then
        details+="<p><strong>Encryption Key Management:</strong></p>"
        details+="<p><span class='check-pass'>Cloud KMS in use for key management</span></p>"
    else
        details+="<p><span class='check-warning'>No Cloud KMS keyrings found</span></p>"
        details+="<p>Consider using Cloud KMS for encryption key management</p>"
        ((security_gaps++))
        [[ "$check_status" == "PASS" ]] && check_status="WARNING"
    fi
    
    # Check for Binary Authorization (secure container deployment)
    local binary_auth
    binary_auth=$(gcloud container binauthz policy export $gcloud_cmd_prefix 2>/dev/null)
    
    if [[ -n "$binary_auth" ]] && echo "$binary_auth" | grep -q "requireAttestationsBy"; then
        details+="<p><strong>Binary Authorization:</strong></p>"
        details+="<p><span class='check-pass'>Binary Authorization policy configured</span></p>"
    else
        details+="<p><span class='check-info'>Binary Authorization not configured</span></p>"
        details+="<p>Consider Binary Authorization for secure container deployment</p>"
    fi
    
    # Add secure development requirements
    details+="<h4>Secure Development Lifecycle Requirements</h4>"
    details+="<ul><li><strong>Security Training:</strong> Annual developer security training</li>"
    details+="<li><strong>Secure Coding:</strong> Implementation of secure coding standards</li>"
    details+="<li><strong>Code Review:</strong> Security-focused code review processes</li>"
    details+="<li><strong>Security Testing:</strong> SAST/DAST integration in CI/CD</li>"
    details+="<li><strong>Dependency Management:</strong> Third-party component vulnerability scanning</li>"
    details+="<li><strong>Secret Management:</strong> No hardcoded credentials in code</li></ul>"
    
    add_check_result "$OUTPUT_FILE" "info" "Secure Development Lifecycle" "$details"
    ((total_checks++))
    
    log_debug "Secure development lifecycle assessment complete: $check_status ($security_gaps gaps)"
}

# Main project assessment function
assess_project() {
    local project_id="$1"
    
    log_debug "Assessing project: $project_id"
    
    # Add project section to report
    add_section "$OUTPUT_FILE" "project_$project_id" "Project: $project_id" "Assessment results for project $project_id"
    
    # Perform all assessments for this project
    assess_secure_development "$project_id"
    assess_vulnerability_management "$project_id"
    assess_web_protection "$project_id"
    assess_change_management "$project_id"
    assess_secure_development_lifecycle "$project_id"
    
    log_debug "Completed assessment for project: $project_id"
}

# Main execution function
main() {
    # Setup environment and parse command line arguments
    setup_environment "requirement6_assessment.log"
    parse_common_arguments "$@"
    case $? in
        1) exit 1 ;;  # Error
        2) exit 0 ;;  # Help displayed
    esac
    
    # Validate GCP environment
    validate_prerequisites || exit 1
    
    # Check permissions using the comprehensive permission check
    if ! check_required_permissions "${REQ6_PERMISSIONS[@]}"; then
        exit 1
    fi
    
    # Setup assessment scope
    setup_assessment_scope || exit 1
    
    # Configure HTML report
    OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"
    initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report" "${REQUIREMENT_NUMBER}"
    
    print_status "info" "============================================="
    print_status "info" "  PCI DSS 4.0.1 - Requirement 6 (GCP)"
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
    
    log_debug "Starting PCI DSS Requirement 6 assessment"
    
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
    
    # Add manual verification guidance section
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

# Add manual verification guidance
add_manual_verification_guidance() {
    local manual_guidance="<h3>Manual Verification Requirements</h3>
<p>The following items require manual verification to ensure full PCI DSS Requirement 6 compliance:</p>
<ul>
<li><strong>6.1:</strong> Secure development processes and governance framework</li>
<li><strong>6.2.1:</strong> Bespoke software developed according to PCI DSS requirements</li>
<li><strong>6.2.2:</strong> Software components and security vulnerabilities reviewed</li>
<li><strong>6.2.3:</strong> Code review processes before production release</li>
<li><strong>6.2.4:</strong> Protection against common software attacks</li>
<li><strong>6.3.1:</strong> Inventory of software components and vulnerabilities</li>
<li><strong>6.3.3:</strong> Patch management for critical vulnerabilities</li>
<li><strong>6.4.3:</strong> Payment page script management and integrity</li>
<li><strong>6.5:</strong> Change control procedures with documentation</li>
</ul>
<p><strong>GCP Best Practices:</strong></p>
<ul>
<li>Use Cloud Security Scanner for web application testing</li>
<li>Implement Binary Authorization for deployment security</li>
<li>Use separate GCP projects for different environments</li>
<li>Implement IAM policies for role separation</li>
</ul>"
    
    add_section "$OUTPUT_FILE" "manual_verification" "Manual Verification Required" "Manual verification requirements for PCI DSS compliance"
    add_check_result "$OUTPUT_FILE" "info" "Manual Verification Required" "$manual_guidance"
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

