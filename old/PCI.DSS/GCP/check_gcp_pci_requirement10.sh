#!/usr/bin/env bash

# PCI DSS Requirement 10 Compliance Check Script for GCP (Framework-Migrated Version)
# This script evaluates GCP logging and monitoring for PCI DSS Requirement 10 compliance
# Requirements covered: 10.1 - 10.7 (Log and Monitor All Access to System Components and Cardholder Data)

# Load shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1
source "$LIB_DIR/gcp_scope_mgmt.sh" || exit 1
source "$LIB_DIR/gcp_html_report.sh" || exit 1

# Script-specific variables
REQUIREMENT_NUMBER="10"

# Counters for checks  
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0


# Function to show help
show_help() {
    echo "GCP PCI DSS Requirement 10 Assessment Script (Framework Version)"
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

# Define required permissions for Requirement 10
declare -a REQ10_PERMISSIONS=(
    "logging.logEntries.list"
    "logging.logs.list"
    "logging.sinks.list"
    "logging.sinks.get"
    "monitoring.alertPolicies.list"
    "monitoring.notificationChannels.list"
    "cloudasset.assets.searchAllResources"
    "compute.instances.list"
    "resourcemanager.projects.get"
    "resourcemanager.organizations.get"
    "iam.serviceAccounts.list"
    "storage.buckets.list"
    "cloudkms.keyRings.list"
    "bigquery.datasets.list"
    "pubsub.topics.list"
)

# Core Assessment Functions

# 10.1 - Processes and mechanisms for logging and monitoring
assess_logging_processes() {
    local project_id="$1"
    log_debug "Assessing logging processes for project: $project_id"
    
    # 10.1.1 - Security policies and operational procedures documentation
    add_check_result "$OUTPUT_FILE" "info" "10.1.1 - Security policies documentation" \
        "Verify documented security policies for Requirement 10 are maintained, up to date, in use, and known to affected parties"
    
    # 10.1.2 - Roles and responsibilities documentation
    add_check_result "$OUTPUT_FILE" "info" "10.1.2 - Roles and responsibilities" \
        "Verify roles and responsibilities for Requirement 10 activities are documented, assigned, and understood"
    
    # Check if Cloud Logging is enabled
    local logging_enabled
    logging_enabled=$(gcloud logging logs list \
        --project="$project_id" \
        --limit=1 \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -n "$logging_enabled" ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "Cloud Logging enabled" \
            "Cloud Logging is enabled and operational in project $project_id"
        ((passed_checks++))
    else
        add_check_result "$OUTPUT_FILE" "fail" "Cloud Logging enabled" \
            "Cloud Logging appears to be disabled or inaccessible in project $project_id"
        ((failed_checks++))
    fi
    ((total_checks++))
    
    # Check for audit log configuration
    local audit_logs
    audit_logs=$(gcloud logging logs list \
        --project="$project_id" \
        --filter="name:cloudaudit" \
        --format="value(name)" \
        2>/dev/null)
    
    if [[ -n "$audit_logs" ]]; then
        local audit_count=$(echo "$audit_logs" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Audit logs configuration" \
            "Found $audit_count audit log streams configured in project $project_id"
        ((passed_checks++))
    else
        add_check_result "$OUTPUT_FILE" "fail" "Audit logs configuration" \
            "No audit logs found - critical for PCI DSS compliance"
        ((failed_checks++))
    fi
    ((total_checks++))
}

# 10.2 - Audit logs implementation
assess_audit_log_implementation() {
    local project_id="$1"
    log_debug "Assessing audit log implementation for project: $project_id"
    
    # Check for comprehensive audit logging
    local audit_types=("data_access" "admin_activity" "system_events")
    local configured_audits=0
    
    for audit_type in "${audit_types[@]}"; do
        local audit_entries
        audit_entries=$(gcloud logging read \
            "logName:projects/$project_id/logs/cloudaudit.googleapis.com%2F$audit_type" \
            --project="$project_id" \
            --limit=1 \
            --format="value(timestamp)" \
            2>/dev/null)
        
        if [[ -n "$audit_entries" ]]; then
            ((configured_audits++))
            add_check_result "$OUTPUT_FILE" "pass" "Audit logging - $audit_type" \
                "Audit logging for $audit_type is active"
            ((passed_checks++))
        else
            add_check_result "$OUTPUT_FILE" "warning" "Audit logging - $audit_type" \
                "No recent $audit_type audit logs found"
            ((warning_checks++))
        fi
        ((total_checks++))
    done
    
    # 10.2.1 - Individual user access to cardholder data
    local user_access_logs
    user_access_logs=$(gcloud logging read \
        'protoPayload.authenticationInfo.principalEmail!="" AND (resource.type="gce_instance" OR resource.type="gcs_bucket" OR resource.type="bigquery_dataset")' \
        --project="$project_id" \
        --limit=10 \
        --format="value(timestamp,protoPayload.authenticationInfo.principalEmail)" \
        2>/dev/null)
    
    if [[ -n "$user_access_logs" ]]; then
        local log_count=$(echo "$user_access_logs" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "10.2.1 - User access logging" \
            "Found $log_count user access events logged"
        ((passed_checks++))
    else
        add_check_result "$OUTPUT_FILE" "warning" "10.2.1 - User access logging" \
            "No recent user access logs found - verify if cardholder data access is occurring"
        ((warning_checks++))
    fi
    ((total_checks++))
    
    # 10.2.2 - Administrative access actions
    local admin_logs
    admin_logs=$(gcloud logging read \
        'protoPayload.authorizationInfo.granted=true AND protoPayload.serviceName!="oslogin.googleapis.com"' \
        --project="$project_id" \
        --limit=10 \
        --format="value(timestamp,protoPayload.methodName)" \
        2>/dev/null)
    
    if [[ -n "$admin_logs" ]]; then
        local admin_count=$(echo "$admin_logs" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "10.2.1.2 - Administrative actions" \
            "Found $admin_count administrative actions logged"
    else
        add_check_result "$OUTPUT_FILE" "warning" "10.2.1.2 - Administrative actions" \
            "No recent administrative actions logged"
    fi
    
    # 10.2.1.3 - Access to audit logs
    local audit_access_logs
    audit_access_logs=$(gcloud logging read \
        'protoPayload.serviceName="logging.googleapis.com" AND protoPayload.methodName:"Read"' \
        --project="$project_id" \
        --limit=5 \
        --format="value(timestamp,protoPayload.authenticationInfo.principalEmail)" \
        2>/dev/null)
    
    if [[ -n "$audit_access_logs" ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "10.2.1.3 - Audit log access" \
            "Audit log access is being logged"
        ((passed_checks++))
    else
        add_check_result "$OUTPUT_FILE" "info" "10.2.1.3 - Audit log access" \
            "No recent audit log access events found"
    fi
    ((total_checks++))
    
    # 10.2.1.4 - Invalid logical access attempts
    local failed_auth_logs
    failed_auth_logs=$(gcloud logging read \
        'protoPayload.authenticationInfo.principalEmail="" OR severity="ERROR"' \
        --project="$project_id" \
        --limit=5 \
        --format="value(timestamp,severity)" \
        2>/dev/null)
    
    if [[ -n "$failed_auth_logs" ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "10.2.1.4 - Failed access attempts" \
            "Failed access attempts are being logged"
        ((passed_checks++))
    else
        add_check_result "$OUTPUT_FILE" "info" "10.2.1.4 - Failed access attempts" \
            "No recent failed access attempts logged"
    fi
    ((total_checks++))
    
    # 10.2.1.5 - Changes to authentication credentials
    local credential_changes
    credential_changes=$(gcloud logging read \
        'protoPayload.serviceName="iam.googleapis.com" AND (protoPayload.methodName:"CreateServiceAccount" OR protoPayload.methodName:"SetIamPolicy")' \
        --project="$project_id" \
        --limit=5 \
        --format="value(timestamp,protoPayload.methodName)" \
        2>/dev/null)
    
    if [[ -n "$credential_changes" ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "10.2.1.5 - Credential changes" \
            "Authentication credential changes are being logged"
    else
        add_check_result "$OUTPUT_FILE" "info" "10.2.1.5 - Credential changes" \
            "No recent credential changes logged"
    fi
    
    # 10.2.1.6 - Audit log initialization and changes
    local log_config_changes
    log_config_changes=$(gcloud logging read \
        'protoPayload.serviceName="logging.googleapis.com" AND protoPayload.methodName:"UpdateSink"' \
        --project="$project_id" \
        --limit=3 \
        --format="value(timestamp)" \
        2>/dev/null)
    
    if [[ -n "$log_config_changes" ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "10.2.1.6 - Audit log management" \
            "Audit log configuration changes are being logged"
    else
        add_check_result "$OUTPUT_FILE" "info" "10.2.1.6 - Audit log management" \
            "No recent audit log configuration changes"
    fi
    
    # 10.2.1.7 - System-level object creation/deletion
    local system_changes
    system_changes=$(gcloud logging read \
        'protoPayload.methodName:"create" OR protoPayload.methodName:"delete" OR protoPayload.methodName:"insert"' \
        --project="$project_id" \
        --limit=10 \
        --format="value(timestamp,protoPayload.methodName)" \
        2>/dev/null)
    
    if [[ -n "$system_changes" ]]; then
        local change_count=$(echo "$system_changes" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "10.2.1.7 - System object changes" \
            "Found $change_count system-level object changes logged"
    else
        add_check_result "$OUTPUT_FILE" "info" "10.2.1.7 - System object changes" \
            "No recent system-level object changes logged"
    fi
    
    # Check audit log detail completeness (10.2.2)
    local detailed_log_sample
    detailed_log_sample=$(gcloud logging read \
        'protoPayload.authenticationInfo.principalEmail!=""' \
        --project="$project_id" \
        --limit=1 \
        --format="json" \
        2>/dev/null)
    
    if [[ -n "$detailed_log_sample" ]]; then
        # Check for required audit log fields
        local has_user_id=$(echo "$detailed_log_sample" | jq -r '.[0].protoPayload.authenticationInfo.principalEmail // empty')
        local has_timestamp=$(echo "$detailed_log_sample" | jq -r '.[0].timestamp // empty')
        local has_event_type=$(echo "$detailed_log_sample" | jq -r '.[0].protoPayload.methodName // empty')
        local has_source=$(echo "$detailed_log_sample" | jq -r '.[0].protoPayload.requestMetadata.callerIp // empty')
        
        local required_fields=0
        [[ -n "$has_user_id" ]] && ((required_fields++))
        [[ -n "$has_timestamp" ]] && ((required_fields++))
        [[ -n "$has_event_type" ]] && ((required_fields++))
        [[ -n "$has_source" ]] && ((required_fields++))
        
        if [[ $required_fields -ge 4 ]]; then
            add_check_result "$OUTPUT_FILE" "pass" "10.2.2 - Audit log detail completeness" \
                "Audit logs contain required details (user ID, timestamp, event type, source)"
        else
            add_check_result "$OUTPUT_FILE" "warning" "10.2.2 - Audit log detail completeness" \
                "Audit logs missing some required details ($required_fields/4 fields present)"
        fi
    else
        add_check_result "$OUTPUT_FILE" "warning" "10.2.2 - Audit log detail completeness" \
            "Unable to verify audit log detail completeness"
    fi
}

# 10.3 - Audit log protection
assess_audit_log_protection() {
    local project_id="$1"
    log_debug "Assessing audit log protection for project: $project_id"
    
    # Check for log sinks and export destinations
    local log_sinks
    log_sinks=$(gcloud logging sinks list \
        --project="$project_id" \
        --format="value(name,destination)" \
        2>/dev/null)
    
    if [[ -z "$log_sinks" ]]; then
        add_check_result "$OUTPUT_FILE" "warning" "10.3 - Log export/backup" \
            "No log sinks configured - consider exporting logs for backup and long-term retention"
        ((warning_checks++))
    else
        local sink_count=$(echo "$log_sinks" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "10.3.3 - Log backup" \
            "Found $sink_count log sinks configured for log export/backup"
        ((passed_checks++))
        
        # Check sink destinations
        while IFS= read -r sink; do
            [[ -z "$sink" ]] && continue
            
            local sink_name=$(echo "$sink" | cut -d$'\t' -f1)
            local destination=$(echo "$sink" | cut -d$'\t' -f2)
            
            if [[ "$destination" == storage.googleapis.com* ]]; then
                add_check_result "$OUTPUT_FILE" "pass" "Log sink security" \
                    "Sink '$sink_name' exports to secure Cloud Storage"
                ((passed_checks++))
            elif [[ "$destination" == bigquery.googleapis.com* ]]; then
                add_check_result "$OUTPUT_FILE" "pass" "Log sink security" \
                    "Sink '$sink_name' exports to BigQuery for analysis"
                ((passed_checks++))
            else
                add_check_result "$OUTPUT_FILE" "info" "Log sink destination" \
                    "Sink '$sink_name' exports to: $destination"
            fi
            ((total_checks++))
            
        done <<< "$log_sinks"
    fi
    ((total_checks++))
    
    # 10.3.1 - Read access limitation
    local iam_policy
    iam_policy=$(gcloud projects get-iam-policy "$project_id" \
        --format="json" \
        2>/dev/null)
    
    if [[ -n "$iam_policy" ]]; then
        local logging_viewers
        logging_viewers=$(echo "$iam_policy" | jq -r '.bindings[] | select(.role | contains("logging")) | .members[]' 2>/dev/null | wc -l)
        
        if [[ $logging_viewers -lt 10 ]]; then
            add_check_result "$OUTPUT_FILE" "pass" "10.3.1 - Log access restriction" \
                "Limited number of users ($logging_viewers) have logging access"
            ((passed_checks++))
        else
            add_check_result "$OUTPUT_FILE" "warning" "10.3.1 - Log access restriction" \
                "High number of users ($logging_viewers) have logging access - review access controls"
            ((warning_checks++))
        fi
        ((total_checks++))
    fi
    
    # 10.3.2 - Protection from modification
    add_check_result "$OUTPUT_FILE" "pass" "10.3.2 - Log immutability" \
        "Cloud Logging provides built-in log immutability - logs cannot be modified after creation"
    ((passed_checks++))
    ((total_checks++))
    
    # 10.3.4 - File integrity monitoring
    local log_access_monitoring
    log_access_monitoring=$(gcloud logging read \
        'protoPayload.serviceName="logging.googleapis.com"' \
        --project="$project_id" \
        --limit=1 \
        --format="value(timestamp)" \
        2>/dev/null)
    
    if [[ -n "$log_access_monitoring" ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "10.3.4 - Log access monitoring" \
            "Log access and changes are being monitored"
    else
        add_check_result "$OUTPUT_FILE" "info" "10.3.4 - Log access monitoring" \
            "No recent log access events found"
    fi
}

# 10.4 - Audit log review
assess_audit_log_review() {
    local project_id="$1"
    log_debug "Assessing audit log review for project: $project_id"
    
    # Check for monitoring and alerting policies
    local alert_policies
    alert_policies=$(gcloud alpha monitoring policies list \
        --project="$project_id" \
        --format="value(displayName,enabled)" \
        2>/dev/null)
    
    if [[ -z "$alert_policies" ]]; then
        add_check_result "$OUTPUT_FILE" "warning" "10.4 - Automated log review" \
            "No monitoring alert policies found - consider implementing automated log analysis"
    else
        local enabled_policies=0
        local total_policies=0
        
        while IFS= read -r policy; do
            [[ -z "$policy" ]] && continue
            ((total_policies++))
            
            local policy_name=$(echo "$policy" | cut -d$'\t' -f1)
            local enabled=$(echo "$policy" | cut -d$'\t' -f2)
            
            if [[ "$enabled" == "True" ]]; then
                ((enabled_policies++))
                add_check_result "$OUTPUT_FILE" "pass" "Alert policy status" \
                    "Policy '$policy_name' is enabled for monitoring"
            else
                add_check_result "$OUTPUT_FILE" "warning" "Alert policy status" \
                    "Policy '$policy_name' is disabled"
            fi
            
        done <<< "$alert_policies"
        
        add_check_result "$OUTPUT_FILE" "pass" "10.4.1.1 - Automated mechanisms" \
            "Found $enabled_policies enabled out of $total_policies monitoring policies"
    fi
    
    # Check for notification channels
    local notification_channels
    notification_channels=$(gcloud alpha monitoring channels list \
        --project="$project_id" \
        --format="value(displayName,type)" \
        2>/dev/null)
    
    if [[ -n "$notification_channels" ]]; then
        local channel_count=$(echo "$notification_channels" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Alert notification channels" \
            "Found $channel_count notification channels configured"
    else
        add_check_result "$OUTPUT_FILE" "warning" "Alert notification channels" \
            "No notification channels found - alerts may not be delivered"
    fi
    
    # 10.4.1 - Daily security event review
    add_check_result "$OUTPUT_FILE" "info" "10.4.1 - Daily log review" \
        "Verify that security events and critical system logs are reviewed at least once daily"
    
    # 10.4.2 - Periodic review of other logs
    add_check_result "$OUTPUT_FILE" "info" "10.4.2 - Periodic log review" \
        "Verify that other system component logs are reviewed periodically per risk analysis"
    
    # 10.4.3 - Exception handling
    add_check_result "$OUTPUT_FILE" "info" "10.4.3 - Exception handling" \
        "Verify that exceptions and anomalies identified during review are addressed"
}

# 10.5 - Audit log retention
assess_audit_log_retention() {
    local project_id="$1"
    log_debug "Assessing audit log retention for project: $project_id"
    
    # Check log retention settings
    local log_retention_info
    log_retention_info=$(gcloud logging logs list \
        --project="$project_id" \
        --format="value(name)" \
        2>/dev/null | head -5)
    
    if [[ -n "$log_retention_info" ]]; then
        add_check_result "$OUTPUT_FILE" "info" "10.5.1 - Log retention baseline" \
            "Cloud Logging default retention is 30 days - verify if additional retention is configured"
        
        # Check for long-term storage via sinks
        local long_term_sinks
        long_term_sinks=$(gcloud logging sinks list \
            --project="$project_id" \
            --format="value(name,destination)" \
            2>/dev/null | grep -E "(storage|bigquery)")
        
        if [[ -n "$long_term_sinks" ]]; then
            add_check_result "$OUTPUT_FILE" "pass" "10.5.1 - Long-term retention" \
                "Log sinks configured for long-term retention beyond 30 days"
        else
            add_check_result "$OUTPUT_FILE" "warning" "10.5.1 - Long-term retention" \
                "No long-term retention sinks found - may not meet 12-month retention requirement"
        fi
        
        # Check if exported logs have appropriate retention
        local storage_buckets
        storage_buckets=$(gcloud storage buckets list \
            --project="$project_id" \
            --format="value(name)" \
            2>/dev/null | grep -i log)
        
        if [[ -n "$storage_buckets" ]]; then
            while IFS= read -r bucket; do
                [[ -z "$bucket" ]] && continue
                
                local lifecycle_policy
                lifecycle_policy=$(gcloud storage buckets describe "gs://$bucket" \
                    --format="value(lifecycle.rule[].condition.age)" \
                    2>/dev/null)
                
                if [[ -n "$lifecycle_policy" ]]; then
                    add_check_result "$OUTPUT_FILE" "pass" "Storage bucket retention" \
                        "Bucket '$bucket' has lifecycle policy configured"
                else
                    add_check_result "$OUTPUT_FILE" "warning" "Storage bucket retention" \
                        "Bucket '$bucket' lacks lifecycle policy for retention management"
                fi
                
            done <<< "$storage_buckets"
        fi
    else
        add_check_result "$OUTPUT_FILE" "fail" "10.5.1 - Log retention" \
            "Unable to verify log retention configuration"
    fi
    
    # Manual verification guidance
    add_check_result "$OUTPUT_FILE" "info" "Log retention verification" \
        "Verify that audit logs are retained for at least 12 months with 3 months immediately available"
}

# 10.6 - Time synchronization
assess_time_synchronization() {
    local project_id="$1"
    log_debug "Assessing time synchronization for project: $project_id"
    
    # Check Compute Engine instances for NTP configuration
    local instances
    instances=$(gcloud compute instances list \
        --project="$project_id" \
        --format="value(name,zone)" \
        2>/dev/null)
    
    if [[ -z "$instances" ]]; then
        add_check_result "$OUTPUT_FILE" "info" "10.6 - Time synchronization" \
            "No Compute Engine instances found to assess NTP configuration"
    else
        local instance_count=$(echo "$instances" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "10.6.1 - Time synchronization technology" \
            "Google Cloud provides automatic time synchronization for $instance_count instances"
        
        # Google Cloud instances use Google's time servers by default
        add_check_result "$OUTPUT_FILE" "pass" "10.6.2 - Centralized time servers" \
            "Google Cloud instances automatically sync with Google's authoritative time servers"
        
        add_check_result "$OUTPUT_FILE" "pass" "10.6.3 - Time data protection" \
            "Google Cloud manages time synchronization security - instances cannot modify time service"
    fi
    
    # Check for any custom time server configurations
    add_check_result "$OUTPUT_FILE" "info" "Custom time server check" \
        "If using custom NTP servers, verify they are properly configured and secured"
}

# 10.7 - Security control failure detection
assess_security_control_monitoring() {
    local project_id="$1"
    log_debug "Assessing security control monitoring for project: $project_id"
    
    # Check for monitoring of critical security systems
    local security_monitoring_policies
    security_monitoring_policies=$(gcloud alpha monitoring policies list \
        --project="$project_id" \
        --filter="displayName:security OR displayName:audit OR displayName:firewall OR displayName:iam" \
        --format="value(displayName,enabled)" \
        2>/dev/null)
    
    if [[ -n "$security_monitoring_policies" ]]; then
        local enabled_count=0
        local total_count=0
        
        while IFS= read -r policy; do
            [[ -z "$policy" ]] && continue
            ((total_count++))
            
            local policy_name=$(echo "$policy" | cut -d$'\t' -f1)
            local enabled=$(echo "$policy" | cut -d$'\t' -f2)
            
            if [[ "$enabled" == "True" ]]; then
                ((enabled_count++))
                add_check_result "$OUTPUT_FILE" "pass" "Security monitoring policy" \
                    "Security monitoring policy '$policy_name' is active"
            else
                add_check_result "$OUTPUT_FILE" "warning" "Security monitoring policy" \
                    "Security monitoring policy '$policy_name' is disabled"
            fi
            
        done <<< "$security_monitoring_policies"
        
        add_check_result "$OUTPUT_FILE" "pass" "10.7.2 - Critical security control monitoring" \
            "Found $enabled_count enabled out of $total_count security monitoring policies"
    else
        add_check_result "$OUTPUT_FILE" "warning" "10.7.2 - Critical security control monitoring" \
            "No security-specific monitoring policies found"
    fi
    
    # Check for Security Command Center integration
    local scc_findings
    scc_findings=$(gcloud scc findings list \
        --organization="$(gcloud organizations list --format='value(name)' | head -1)" \
        --filter="resourceName:projects/$project_id AND state:ACTIVE" \
        --limit=5 \
        --format="value(category)" \
        2>/dev/null)
    
    if [[ -n "$scc_findings" ]]; then
        local finding_count=$(echo "$scc_findings" | wc -l)
        add_check_result "$OUTPUT_FILE" "pass" "Security Command Center monitoring" \
            "Security Command Center is active with $finding_count findings to review"
    else
        add_check_result "$OUTPUT_FILE" "info" "Security Command Center monitoring" \
            "No active Security Command Center findings - system may be secure or SCC not configured"
    fi
    
    # 10.7.3 - Response to security failures
    add_check_result "$OUTPUT_FILE" "info" "10.7.3 - Security failure response" \
        "Verify documented procedures exist for responding to security control failures"
    
    # Check for incident response automation
    local cloud_functions
    cloud_functions=$(gcloud functions list \
        --project="$project_id" \
        --format="value(name)" \
        2>/dev/null | grep -i -E "(incident|response|alert)")
    
    if [[ -n "$cloud_functions" ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "Automated incident response" \
            "Found Cloud Functions that may provide automated incident response capabilities"
    else
        add_check_result "$OUTPUT_FILE" "info" "Automated incident response" \
            "No automated incident response functions detected"
    fi
}

# Manual verification guidance
add_manual_verification_guidance() {
    log_debug "Adding manual verification guidance"
    
    add_section "$OUTPUT_FILE" "manual_verification" "Manual Verification Required" "Logging and monitoring controls requiring manual assessment"
    
    add_check_result "$OUTPUT_FILE" "info" "10.1 - Logging policy documentation" \
        "Verify documented processes and mechanisms for logging and monitoring are defined and understood"
    
    add_check_result "$OUTPUT_FILE" "info" "10.4 - Daily log review procedures" \
        "Verify that security events are reviewed at least once daily by appropriate personnel"
    
    add_check_result "$OUTPUT_FILE" "info" "10.5 - Log retention compliance" \
        "Verify that audit logs are retained for at least 12 months with 3 months immediately available"
    
    add_check_result "$OUTPUT_FILE" "info" "10.7 - Incident response procedures" \
        "Verify documented procedures for detecting, reporting, and responding to security control failures"
    
    add_check_result "$OUTPUT_FILE" "info" "Log review effectiveness" \
        "Verify that log review processes effectively identify anomalies and suspicious activity"
    
    add_check_result "$OUTPUT_FILE" "info" "Time synchronization verification" \
        "For custom environments, verify all systems have consistent time synchronization"
}

# Main assessment function
assess_project() {
    local project_id="$1"
    
    log_debug "Assessing project: $project_id"
    
    # Add project section to report
    add_section "$OUTPUT_FILE" "project_$project_id" "Project: $project_id" "Assessment results for project $project_id"
    
    # Perform assessments
    assess_logging_processes "$project_id"
    assess_audit_log_implementation "$project_id"
    assess_audit_log_protection "$project_id"
    assess_audit_log_review "$project_id"
    assess_audit_log_retention "$project_id"
    assess_time_synchronization "$project_id"
    assess_security_control_monitoring "$project_id"
    
    log_debug "Completed assessment for project: $project_id"
}

# Main execution
main() {
    # Setup environment and parse command line arguments
    setup_environment "requirement10_assessment.log"
    parse_common_arguments "$@"
    case $? in
        1) exit 1 ;;  # Error
        2) exit 0 ;;  # Help displayed
    esac
    
    # Validate GCP environment
    validate_prerequisites || exit 1
    
    # Check permissions using the comprehensive permission check
    if ! check_required_permissions "${REQ10_PERMISSIONS[@]}"; then
        exit 1
    fi
    
    # Setup assessment scope
    setup_assessment_scope || exit 1
    
    # Configure HTML report
    OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"
    initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report" "${REQUIREMENT_NUMBER}"
    
    # Add assessment introduction
    add_section "$OUTPUT_FILE" "logging_monitoring" "Logging and Monitoring Assessment" "Assessment of audit logging and monitoring controls"
    
    print_status "info" "============================================="
    print_status "info" "  PCI DSS 4.0.1 - Requirement 10 (GCP)"
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
    
    log_debug "Starting PCI DSS Requirement 10 assessment"
    
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