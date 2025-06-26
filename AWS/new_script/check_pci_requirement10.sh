#!/bin/bash
# check_pci_requirement10.sh - Checks for PCI DSS Requirement 10 compliance in AWS
# Requirement 10: Track and monitor all access to network resources and cardholder data

# Set reasonable error handling, but don't exit on errors
set -u
set -o pipefail
# NOT setting -e because we want the script to continue even if some commands fail

# Script variables
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REQUIREMENT_NUMBER="10"
REPORT_TITLE="PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report"
REPORT_DIR="./reports"
OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_${TIMESTAMP}.html"

# Counters for report summary
total_checks=0
passed_checks=0
failed_checks=0
warning_checks=0

# Source the shared HTML report library
source "$(dirname "$0")/pci_html_report_lib.sh"

# Function to check AWS CLI is installed and configured
check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        echo "Error: AWS CLI is not installed. Please install it before running this script."
        exit 1
    fi

    # Check if AWS CLI is configured
    if ! aws sts get-caller-identity &> /dev/null; then
        echo "Error: AWS CLI is not properly configured. Please run 'aws configure' and try again."
        exit 1
    fi
}

# Function to check CloudTrail is enabled
check_cloudtrail_enabled() {
    local region="$1"
    local details=""
    local status="pass"
    
    # Get CloudTrail trails
    trails=$(aws cloudtrail describe-trails --region $region)
    trail_count=$(echo "$trails" | jq '.trailList | length')
    
    if [ "$trail_count" -eq 0 ]; then
        status="fail"
        details="<p class=\"red\">No CloudTrail trails found in region $region. CloudTrail is required to track user activities and API usage.</p>"
    else
        details="<p>CloudTrail trails found in region $region:</p><ul>"
        
        for ((i=0; i<$trail_count; i++)); do
            trail_name=$(echo "$trails" | jq -r ".trailList[$i].Name")
            trail_home_region=$(echo "$trails" | jq -r ".trailList[$i].HomeRegion")
            is_multi_region=$(echo "$trails" | jq -r ".trailList[$i].IsMultiRegionTrail")
            
            # Check if trail is logging
            trail_status=$(aws cloudtrail get-trail-status --name $trail_name --region $region 2>/dev/null || echo '{"IsLogging": false}')
            is_logging=$(echo "$trail_status" | jq -r '.IsLogging')
            
            if [ "$is_logging" = "true" ]; then
                details+="<li class=\"green\">Trail: $trail_name (Home Region: $trail_home_region, Multi-Region: $is_multi_region) - <strong>Logging is enabled</strong></li>"
            else
                details+="<li class=\"red\">Trail: $trail_name (Home Region: $trail_home_region, Multi-Region: $is_multi_region) - <strong>Logging is disabled</strong></li>"
                status="fail"
            fi
        done
        
        details+="</ul>"
        
        # Check for multi-region coverage
        has_multi_region=$(echo "$trails" | jq '.trailList[] | select(.IsMultiRegionTrail==true) | .Name' | wc -l)
        if [ "$has_multi_region" -eq 0 ]; then
            details+="<p class=\"red\">Warning: No multi-region trails found. PCI DSS recommends logging across all regions.</p>"
            status="fail"
        else
            details+="<p class=\"green\">Multi-region trail(s) found, providing coverage across all AWS regions.</p>"
        fi
    fi
    
    echo "$status:$details"
}

# Function to check CloudTrail log file validation
check_cloudtrail_validation() {
    local region="$1"
    local details=""
    local status="pass"
    
    # Get CloudTrail trails
    trails=$(aws cloudtrail describe-trails --region $region)
    trail_count=$(echo "$trails" | jq '.trailList | length')
    
    if [ "$trail_count" -eq 0 ]; then
        status="fail"
        details="<p class=\"red\">No CloudTrail trails found in region $region.</p>"
    else
        details="<p>CloudTrail log file validation status:</p><ul>"
        
        for ((i=0; i<$trail_count; i++)); do
            trail_name=$(echo "$trails" | jq -r ".trailList[$i].Name")
            log_validation=$(echo "$trails" | jq -r ".trailList[$i].LogFileValidationEnabled")
            
            if [ "$log_validation" = "true" ]; then
                details+="<li class=\"green\">Trail: $trail_name - <strong>Log file validation is enabled</strong></li>"
            else
                details+="<li class=\"red\">Trail: $trail_name - <strong>Log file validation is disabled</strong></li>"
                status="fail"
            fi
        done
        
        details+="</ul>"
        details+="<p>File validation creates a digitally signed digest file containing hashes of log files, enabling detection of log file modification, deletion, or forgery after delivery.</p>"
    fi
    
    echo "$status:$details"
}

# Function to check log file integrity monitoring
check_log_integrity_monitoring() {
    local region="$1"
    local details=""
    local status="warning"
    
    # Check for CloudTrail log file validation (already done in another function, but checking here as well)
    trails=$(aws cloudtrail describe-trails --region $region)
    trail_count=$(echo "$trails" | jq '.trailList | length')
    
    if [ "$trail_count" -eq 0 ]; then
        status="fail"
        details="<p class=\"red\">No CloudTrail trails found in region $region.</p>"
    else
        details="<p>Log file integrity monitoring:</p><ul>"
        
        # Check for CloudTrail log file validation
        validation_enabled=false
        for ((i=0; i<$trail_count; i++)); do
            trail_name=$(echo "$trails" | jq -r ".trailList[$i].Name")
            log_validation=$(echo "$trails" | jq -r ".trailList[$i].LogFileValidationEnabled")
            
            if [ "$log_validation" = "true" ]; then
                validation_enabled=true
                details+="<li class=\"green\">CloudTrail log file validation is enabled for trail: $trail_name</li>"
            fi
        done
        
        if [ "$validation_enabled" = false ]; then
            details+="<li class=\"red\">CloudTrail log file validation is not enabled for any trails.</li>"
            status="fail"
        fi
        
        # Check for AWS Config rules that might monitor CloudTrail logs
        config_rules=$(aws configservice describe-config-rules --region $region 2>/dev/null || echo '{"ConfigRules": []}')
        cloudtrail_monitoring_rule=$(echo "$config_rules" | jq -r '.ConfigRules[] | select(.Source.SourceIdentifier=="CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED" or .Source.SourceIdentifier=="CLOUDTRAIL_ENABLED") | .ConfigRuleName' | head -1)
        
        if [ -n "$cloudtrail_monitoring_rule" ]; then
            details+="<li class=\"green\">AWS Config has rules to monitor CloudTrail configuration: $cloudtrail_monitoring_rule</li>"
        else
            details+="<li class=\"yellow\">No AWS Config rules found specifically for CloudTrail monitoring. Consider implementing Config rules to continuously monitor log integrity.</li>"
        fi
        
        details+="</ul>"
        details+="<p>PCI DSS Requirement 10.3.4 requires file integrity monitoring or change-detection mechanisms to alert personnel to unauthorized modification of audit log files.</p>"
    fi
    
    echo "$status:$details"
}

# Function to check CloudTrail S3 bucket access control
check_cloudtrail_s3_access() {
    local region="$1"
    local details=""
    local status="pass"
    
    # Get CloudTrail trails
    trails=$(aws cloudtrail describe-trails --region $region)
    trail_count=$(echo "$trails" | jq '.trailList | length')
    
    if [ "$trail_count" -eq 0 ]; then
        status="fail"
        details="<p class=\"red\">No CloudTrail trails found in region $region.</p>"
    else
        details="<p>CloudTrail S3 bucket access control:</p><ul>"
        
        for ((i=0; i<$trail_count; i++)); do
            trail_name=$(echo "$trails" | jq -r ".trailList[$i].Name")
            s3_bucket=$(echo "$trails" | jq -r ".trailList[$i].S3BucketName")
            
            # Get bucket policy
            bucket_policy=$(aws s3api get-bucket-policy --bucket $s3_bucket 2>/dev/null || echo '{"Policy": "No policy found"}')
            
            if [ "$bucket_policy" = '{"Policy": "No policy found"}' ]; then
                details+="<li class=\"red\">Trail: $trail_name - S3 bucket: $s3_bucket - <strong>No bucket policy found</strong></li>"
                status="fail"
            else
                # Check if policy restricts access appropriately
                policy=$(echo "$bucket_policy" | jq -r '.Policy')
                
                # Look for broad access grants that might be problematic
                public_access=$(echo "$policy" | grep -i "Principal.*\"*:*\"*" | grep -i "\"AWS\":\"*\"" || echo "")
                
                if [ -n "$public_access" ]; then
                    details+="<li class=\"red\">Trail: $trail_name - S3 bucket: $s3_bucket - <strong>Policy may allow overly broad access</strong></li>"
                    status="fail"
                else
                    details+="<li class=\"green\">Trail: $trail_name - S3 bucket: $s3_bucket - <strong>Bucket policy appears to restrict access appropriately</strong></li>"
                fi
                
                # Get bucket ACL
                bucket_acl=$(aws s3api get-bucket-acl --bucket $s3_bucket 2>/dev/null || echo '[]')
                
                # Check for public ACL grants
                public_grants=$(echo "$bucket_acl" | jq '.Grants[] | select(.Grantee.URI != null)' | grep -i "AllUsers\|AuthenticatedUsers" || echo "")
                
                if [ -n "$public_grants" ]; then
                    details+="<li class=\"red\">Trail: $trail_name - S3 bucket: $s3_bucket - <strong>ACL grants public access</strong></li>"
                    status="fail"
                else
                    details+="<li class=\"green\">Trail: $trail_name - S3 bucket: $s3_bucket - <strong>ACL does not grant public access</strong></li>"
                fi
            fi
        done
        
        details+="</ul>"
    fi
    
    echo "$status:$details"
}

# Function to check CloudWatch log metric filters and alarms
check_cloudwatch_alarms() {
    local region="$1"
    local details=""
    local status="pass"
    
    # Get CloudTrail trails
    trails=$(aws cloudtrail describe-trails --region $region)
    trail_count=$(echo "$trails" | jq '.trailList | length')
    
    if [ "$trail_count" -eq 0 ]; then
        status="fail"
        details="<p class=\"red\">No CloudTrail trails found in region $region.</p>"
    else
        details="<p>CloudWatch metric filters and alarms for security events:</p><ul>"
        
        # Key security events to check for
        security_events=(
            "Root account usage"
            "IAM policy changes"
            "CloudTrail configuration changes"
            "Console authentication failures"
            "Network ACL changes"
            "Security group changes"
        )
        
        # Patterns to match security events
        patterns=(
            "{$.userIdentity.type=\"Root\"}"
            "{($.eventName=DeletePolicy)|($.eventName=DeleteRolePolicy)|($.eventName=DeleteUserPolicy)|($.eventName=PutGroupPolicy)|($.eventName=PutRolePolicy)|($.eventName=PutUserPolicy)|($.eventName=CreatePolicy)|($.eventName=CreatePolicyVersion)}"
            "{($.eventName=CreateTrail)|($.eventName=UpdateTrail)|($.eventName=DeleteTrail)|($.eventName=StartLogging)|($.eventName=StopLogging)}"
            "{($.eventName=ConsoleLogin) && ($.errorMessage=\"Failed authentication\")}"
            "{($.eventName=CreateNetworkAcl)|($.eventName=CreateNetworkAclEntry)|($.eventName=DeleteNetworkAcl)|($.eventName=DeleteNetworkAclEntry)|($.eventName=ReplaceNetworkAclEntry)|($.eventName=ReplaceNetworkAclAssociation)}"
            "{($.eventName=AuthorizeSecurityGroupIngress)|($.eventName=AuthorizeSecurityGroupEgress)|($.eventName=RevokeSecurityGroupIngress)|($.eventName=RevokeSecurityGroupEgress)|($.eventName=CreateSecurityGroup)|($.eventName=DeleteSecurityGroup)}"
        )
        
        # For each trail that logs to CloudWatch
        for ((i=0; i<$trail_count; i++)); do
            trail_name=$(echo "$trails" | jq -r ".trailList[$i].Name")
            cloudwatch_logs_enabled=$(echo "$trails" | jq -r ".trailList[$i].CloudWatchLogsLogGroupArn")
            
            if [ -z "$cloudwatch_logs_enabled" ] || [ "$cloudwatch_logs_enabled" = "null" ]; then
                details+="<li class=\"yellow\">Trail: $trail_name - <strong>Not configured to send logs to CloudWatch</strong></li>"
                continue
            fi
            
            log_group_name=$(echo "$cloudwatch_logs_enabled" | cut -d':' -f7)
            
            details+="<li>Trail: $trail_name - CloudWatch Log Group: $log_group_name<ul>"
            
            # Check for metric filters and alarms for each security event
            for j in "${!security_events[@]}"; do
                event_name="${security_events[$j]}"
                pattern="${patterns[$j]}"
                
                # Get metric filters for this log group
                metric_filters=$(aws logs describe-metric-filters --log-group-name "$log_group_name" --region $region 2>/dev/null || echo '{"metricFilters": []}')
                filter_count=$(echo "$metric_filters" | jq '.metricFilters | length')
                
                filter_found=false
                alarm_found=false
                
                for ((k=0; k<$filter_count; k++)); do
                    filter_pattern=$(echo "$metric_filters" | jq -r ".metricFilters[$k].filterPattern")
                    
                    # Simple pattern matching - this is a basic check and might need refinement
                    if [[ "$filter_pattern" == *"${pattern:1:-1}"* ]]; then
                        filter_found=true
                        metric_name=$(echo "$metric_filters" | jq -r ".metricFilters[$k].metricTransformations[0].metricName")
                        metric_namespace=$(echo "$metric_filters" | jq -r ".metricFilters[$k].metricTransformations[0].metricNamespace")
                        
                        # Check if there's an alarm for this metric
                        alarms=$(aws cloudwatch describe-alarms --metric-name "$metric_name" --namespace "$metric_namespace" --region $region 2>/dev/null || echo '{"MetricAlarms": []}')
                        alarm_count=$(echo "$alarms" | jq '.MetricAlarms | length')
                        
                        if [ "$alarm_count" -gt 0 ]; then
                            alarm_found=true
                            alarm_name=$(echo "$alarms" | jq -r '.MetricAlarms[0].AlarmName')
                            details+="<li class=\"green\">$event_name - <strong>Metric filter and alarm configured</strong> (Alarm: $alarm_name)</li>"
                        else
                            details+="<li class=\"red\">$event_name - <strong>Metric filter found but no alarm configured</strong></li>"
                            status="fail"
                        fi
                        
                        break
                    fi
                done
                
                if [ "$filter_found" = false ]; then
                    details+="<li class=\"red\">$event_name - <strong>No metric filter configured</strong></li>"
                    status="fail"
                fi
            done
            
            details+="</ul></li>"
        done
        
        details+="</ul>"
        details+="<p>PCI DSS requires automated monitoring and alerting for suspicious activities, unauthorized access, and modification of critical system files.</p>"
    fi
    
    echo "$status:$details"
}

# Function to check log retention settings
check_log_retention() {
    local region="$1"
    local details=""
    local status="pass"
    
    # Get CloudWatch log groups
    log_groups=$(aws logs describe-log-groups --region $region)
    group_count=$(echo "$log_groups" | jq '.logGroups | length')
    
    if [ "$group_count" -eq 0 ]; then
        status="warning"
        details="<p class=\"yellow\">No CloudWatch log groups found in region $region.</p>"
    else
        details="<p>CloudWatch log groups retention settings:</p><ul>"
        
        for ((i=0; i<$group_count; i++)); do
            group_name=$(echo "$log_groups" | jq -r ".logGroups[$i].logGroupName")
            retention_days=$(echo "$log_groups" | jq -r ".logGroups[$i].retentionInDays")
            
            if [ "$retention_days" = "null" ]; then
                details+="<li class=\"red\">Log Group: $group_name - <strong>No retention period set (logs never expire)</strong></li>"
                status="fail"
            elif [ "$retention_days" -lt 90 ]; then
                details+="<li class=\"red\">Log Group: $group_name - <strong>Retention period: $retention_days days (less than recommended 90 days)</strong></li>"
                status="fail"
            else
                details+="<li class=\"green\">Log Group: $group_name - <strong>Retention period: $retention_days days</strong></li>"
            fi
        done
        
        details+="</ul>"
        details+="<p>PCI DSS requires log retention for at least 90 days with at least the most recent 3 months available for analysis.</p>"
    fi
    
    echo "$status:$details"
}

# Function to check VPC Flow Logs
check_vpc_flow_logs() {
    local region="$1"
    local details=""
    local status="pass"
    
    # Get all VPCs
    vpcs=$(aws ec2 describe-vpcs --region $region)
    vpc_count=$(echo "$vpcs" | jq '.Vpcs | length')
    
    if [ "$vpc_count" -eq 0 ]; then
        status="info"
        details="<p>No VPCs found in region $region.</p>"
    else
        details="<p>VPC Flow Logs status for each VPC:</p><ul>"
        
        for ((i=0; i<$vpc_count; i++)); do
            vpc_id=$(echo "$vpcs" | jq -r ".Vpcs[$i].VpcId")
            vpc_cidr=$(echo "$vpcs" | jq -r ".Vpcs[$i].CidrBlock")
            
            # Check if flow logs are enabled for this VPC
            flow_logs=$(aws ec2 describe-flow-logs --region $region --filter "Name=resource-id,Values=$vpc_id")
            flow_log_count=$(echo "$flow_logs" | jq '.FlowLogs | length')
            
            if [ "$flow_log_count" -eq 0 ]; then
                details+="<li class=\"red\">VPC: $vpc_id ($vpc_cidr) - <strong>Flow logs not enabled</strong></li>"
                status="fail"
            else
                details+="<li class=\"green\">VPC: $vpc_id ($vpc_cidr) - <strong>Flow logs enabled</strong><ul>"
                
                for ((j=0; j<$flow_log_count; j++)); do
                    flow_log_id=$(echo "$flow_logs" | jq -r ".FlowLogs[$j].FlowLogId")
                    log_destination=$(echo "$flow_logs" | jq -r ".FlowLogs[$j].LogDestination")
                    traffic_type=$(echo "$flow_logs" | jq -r ".FlowLogs[$j].TrafficType")
                    
                    details+="<li>Flow Log ID: $flow_log_id - Traffic Type: $traffic_type - Destination: $log_destination</li>"
                done
                
                details+="</ul></li>"
            fi
        done
        
        details+="</ul>"
        details+="<p>VPC Flow Logs capture information about the IP traffic going to and from network interfaces in your VPC, which is crucial for network monitoring and security analysis.</p>"
    fi
    
    echo "$status:$details"
}

# Function to check Database logging
check_database_logging() {
    local region="$1"
    local details=""
    local status="pass"
    
    # Check RDS logging
    rds_instances=$(aws rds describe-db-instances --region $region 2>/dev/null || echo '{"DBInstances": []}')
    instance_count=$(echo "$rds_instances" | jq '.DBInstances | length')
    
    details="<p>Database audit logging configuration:</p>"
    
    if [ "$instance_count" -eq 0 ]; then
        details+="<p>No RDS database instances found in region $region.</p>"
    else
        details+="<h4>RDS Instances:</h4><ul>"
        
        for ((i=0; i<$instance_count; i++)); do
            db_identifier=$(echo "$rds_instances" | jq -r ".DBInstances[$i].DBInstanceIdentifier")
            db_engine=$(echo "$rds_instances" | jq -r ".DBInstances[$i].Engine")
            
            details+="<li>Instance: $db_identifier (Engine: $db_engine)<ul>"
            
            # Check logging based on engine type
            case "$db_engine" in
                "mysql"|"mariadb")
                    parameter_group=$(echo "$rds_instances" | jq -r ".DBInstances[$i].DBParameterGroups[0].DBParameterGroupName")
                    parameters=$(aws rds describe-db-parameters --db-parameter-group-name "$parameter_group" --region $region)
                    
                    general_log=$(echo "$parameters" | jq -r '.Parameters[] | select(.ParameterName=="general_log") | .ParameterValue')
                    slow_query_log=$(echo "$parameters" | jq -r '.Parameters[] | select(.ParameterName=="slow_query_log") | .ParameterValue')
                    
                    if [ "$general_log" = "1" ] || [ "$general_log" = "ON" ]; then
                        details+="<li class=\"green\">General Query Log: Enabled</li>"
                    else
                        details+="<li class=\"red\">General Query Log: Disabled</li>"
                        status="fail"
                    fi
                    
                    if [ "$slow_query_log" = "1" ] || [ "$slow_query_log" = "ON" ]; then
                        details+="<li class=\"green\">Slow Query Log: Enabled</li>"
                    else
                        details+="<li class=\"red\">Slow Query Log: Disabled</li>"
                        status="fail"
                    fi
                    ;;
                
                "postgres"|"postgresql")
                    parameter_group=$(echo "$rds_instances" | jq -r ".DBInstances[$i].DBParameterGroups[0].DBParameterGroupName")
                    parameters=$(aws rds describe-db-parameters --db-parameter-group-name "$parameter_group" --region $region)
                    
                    log_statement=$(echo "$parameters" | jq -r '.Parameters[] | select(.ParameterName=="log_statement") | .ParameterValue')
                    
                    if [ "$log_statement" = "all" ] || [ "$log_statement" = "mod" ]; then
                        details+="<li class=\"green\">Statement Logging: $log_statement</li>"
                    else
                        details+="<li class=\"red\">Statement Logging: $log_statement (not set to 'all' or 'mod')</li>"
                        status="fail"
                    fi
                    ;;
                
                "sqlserver-se"|"sqlserver-ee"|"sqlserver-ex"|"sqlserver-web")
                    # For SQL Server, we need to check if audit is enabled
                    options=$(aws rds describe-option-groups --region $region)
                    
                    # This is a simplified check - in reality, you'd need to check the specific option group
                    # assigned to this instance and verify SQL Server Audit is enabled
                    details+="<li class=\"yellow\">SQL Server auditing requires manual verification. Verify SQL Server Audit is enabled.</li>"
                    status="warning"
                    ;;
                
                "oracle-ee"|"oracle-se"|"oracle-se1"|"oracle-se2")
                    # For Oracle, check if audit trail is enabled
                    parameter_group=$(echo "$rds_instances" | jq -r ".DBInstances[$i].DBParameterGroups[0].DBParameterGroupName")
                    parameters=$(aws rds describe-db-parameters --db-parameter-group-name "$parameter_group" --region $region)
                    
                    audit_trail=$(echo "$parameters" | jq -r '.Parameters[] | select(.ParameterName=="audit_trail") | .ParameterValue')
                    
                    if [ "$audit_trail" = "DB" ] || [ "$audit_trail" = "OS" ] || [ "$audit_trail" = "XML" ]; then
                        details+="<li class=\"green\">Audit Trail: $audit_trail</li>"
                    else
                        details+="<li class=\"red\">Audit Trail: Not properly configured</li>"
                        status="fail"
                    fi
                    ;;
                
                *)
                    details+="<li class=\"yellow\">Unknown engine type: $db_engine. Manual verification required.</li>"
                    status="warning"
                    ;;
            esac
            
            details+="</ul></li>"
        done
        
        details+="</ul>"
    fi
    
    # Check DynamoDB logging
    details+="<h4>DynamoDB Tables:</h4>"
    
    dynamo_tables=$(aws dynamodb list-tables --region $region 2>/dev/null || echo '{"TableNames": []}')
    table_count=$(echo "$dynamo_tables" | jq '.TableNames | length')
    
    if [ "$table_count" -eq 0 ]; then
        details+="<p>No DynamoDB tables found in region $region.</p>"
    else
        details+="<ul>"
        
        # Check if CloudTrail data events are enabled for DynamoDB
        trails=$(aws cloudtrail describe-trails --region $region)
        trail_count=$(echo "$trails" | jq '.trailList | length')
        
        dynamo_events_enabled=false
        
        for ((i=0; i<$trail_count; i++)); do
            trail_name=$(echo "$trails" | jq -r ".trailList[$i].Name")
            event_selectors=$(aws cloudtrail get-event-selectors --trail-name $trail_name --region $region)
            
            # Check for DynamoDB data events
            data_resources=$(echo "$event_selectors" | jq -r '.EventSelectors[].DataResources[] | select(.Type=="AWS::DynamoDB::Table") | .Values[]')
            
            if [ -n "$data_resources" ]; then
                dynamo_events_enabled=true
                details+="<li class=\"green\">CloudTrail data event logging enabled for DynamoDB tables in trail: $trail_name</li>"
            fi
        done
        
        if [ "$dynamo_events_enabled" = false ]; then
            details+="<li class=\"red\">No CloudTrail data event logging configured for DynamoDB tables.</li>"
            status="fail"
        fi
        
        details+="</ul>"
    fi
    
    details+="<p>PCI DSS requires logging of all user access to cardholder data, which includes database access.</p>"
    
    echo "$status:$details"
}

# Function to check time synchronization
check_time_synchronization() {
    local region="$1"
    local details=""
    local status="warning"
    
    details="<p class=\"yellow\">Time synchronization settings require manual verification on each system.</p>"
    details+="<p>PCI DSS requires that:</p><ul>"
    details+="<li>Time synchronization technology is used and kept current on all systems.</li>"
    details+="<li>Time data is protected and received from industry-accepted time sources.</li>"
    details+="<li>Systems have the correct and consistent time (critical for security, log analysis, and audit trails).</li>"
    details+="</ul>"
    
    details+="<p>Verify the following in your AWS environment:</p><ul>"
    details+="<li>EC2 instances are configured to use NTP with appropriate time sources</li>"
    details+="<li>Systems are synchronized to the correct time zone</li>"
    details+="<li>Time settings are configured in a way that they cannot be altered by users</li>"
    details+="</ul>"
    
    echo "$status:$details"
}

# Function to check log anomaly detection
check_log_anomaly_detection() {
    local region="$1"
    local details=""
    local status="warning"
    
    # Check for GuardDuty (which includes log anomaly detection)
    guardduty=$(aws guardduty list-detectors --region $region 2>/dev/null || echo '{"DetectorIds": []}')
    detector_count=$(echo "$guardduty" | jq '.DetectorIds | length')
    
    if [ "$detector_count" -eq 0 ]; then
        details="<p class=\"red\">GuardDuty is not enabled in region $region. GuardDuty provides automated threat detection including log analysis.</p>"
        status="fail"
    else
        details="<p class=\"green\">GuardDuty is enabled in region $region, which provides log anomaly detection and threat monitoring.</p>"
        
        for detector_id in $(echo "$guardduty" | jq -r '.DetectorIds[]'); do
            detector_status=$(aws guardduty get-detector --detector-id $detector_id --region $region)
            finding_status=$(echo "$detector_status" | jq -r '.Status')
            
            if [ "$finding_status" = "ENABLED" ]; then
                details+="<p class=\"green\">GuardDuty detector $detector_id is enabled and actively monitoring.</p>"
            else
                details+="<p class=\"red\">GuardDuty detector $detector_id is disabled. Please enable for proper threat monitoring.</p>"
                status="fail"
            fi
        done
    fi
    
    # Check for Security Hub (which aggregates security findings)
    security_hub=$(aws securityhub describe-hub --region $region 2>/dev/null || echo '{"HubArn": ""}')
    
    if [ -z "$(echo "$security_hub" | jq -r '.HubArn')" ]; then
        details+="<p class=\"yellow\">AWS Security Hub is not enabled in region $region. Security Hub can help aggregate security findings, including log-based alerts.</p>"
    else
        details+="<p class=\"green\">AWS Security Hub is enabled in region $region, which helps aggregate security findings, including log-based alerts.</p>"
    fi
    
    details+="<p>PCI DSS requires mechanisms to detect unauthorized modifications to logs and alerts for anomalous or suspicious activities.</p>"
    
    echo "$status:$details"
}

# Main function
main() {
    echo "PCI DSS 4.0 - Requirement 10 Compliance Check"
    echo "=============================================="
    echo "This script will check compliance with Requirement 10: Track and monitor all access to network resources and cardholder data."
    echo
    
    # Check for AWS CLI
    check_aws_cli
    
    # Prompt for AWS region
    
	read -p "Enter AWS region to test (e.g., us-east-1): " REGION
	if [ -z "$REGION" ]; then
		REGION="us-east-1"
		echo -e "${YELLOW}Using default region: $REGION${NC}"
	fi

    
    # Create report directory if it doesn't exist
    mkdir -p "$REPORT_DIR"
    
    # Initialize HTML report
    initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE" "$REQUIREMENT_NUMBER" "$REGION"
    
    # Add section to report about required permissions
    echo "Checking AWS CLI permissions..."
    add_section "$OUTPUT_FILE" "permissions" "AWS CLI Permissions Check" "active"
    
    # Check permissions for CloudTrail, CloudWatch and other required services
    # Using a more resilient approach that will continue even if some checks fail
    echo "Checking AWS API access permissions..."
    
    # Function to safely check command access
    safe_check_command() {
        local output_file="$1"
        local service="$2" 
        local command="$3"
        local region="$4"
        
        echo -n "Checking $service $command... "
        if check_command_access "$output_file" "$service" "$command" "$region"; then
            echo "✓"
        else
            echo "✗ (continuing with assessment)"
        fi
    }
    
    # CloudTrail checks
    safe_check_command "$OUTPUT_FILE" "cloudtrail" "describe-trails" "$REGION"
    
    # For get-trail-status, we need to first get a trail name
    trails=$(aws cloudtrail describe-trails --region $REGION 2>/dev/null)
    trail_count=$(echo "$trails" | jq '.trailList | length')
    
    if [ "$trail_count" -gt 0 ]; then
        trail_name=$(echo "$trails" | jq -r '.trailList[0].Name')
        safe_check_command "$OUTPUT_FILE" "cloudtrail" "get-trail-status --name $trail_name" "$REGION"
    else
        add_check_item "$OUTPUT_FILE" "warning" "AWS API Access: cloudtrail get-trail-status" "Could not check this API because no trails were found." "Create a CloudTrail trail to enable full audit logging capabilities."
    fi
    
    # CloudWatch and logs checks
    safe_check_command "$OUTPUT_FILE" "logs" "describe-log-groups" "$REGION"
    safe_check_command "$OUTPUT_FILE" "logs" "describe-metric-filters" "$REGION"
    safe_check_command "$OUTPUT_FILE" "cloudwatch" "describe-alarms" "$REGION"
    
    # EC2 and networking checks
    safe_check_command "$OUTPUT_FILE" "ec2" "describe-vpcs" "$REGION"
    safe_check_command "$OUTPUT_FILE" "ec2" "describe-flow-logs" "$REGION"
    
    # Database checks
    safe_check_command "$OUTPUT_FILE" "rds" "describe-db-instances" "$REGION"
    safe_check_command "$OUTPUT_FILE" "dynamodb" "list-tables" "$REGION"
    
    # Security services checks
    safe_check_command "$OUTPUT_FILE" "guardduty" "list-detectors" "$REGION"
    safe_check_command "$OUTPUT_FILE" "securityhub" "describe-hub" "$REGION"
    safe_check_command "$OUTPUT_FILE" "configservice" "describe-config-rules" "$REGION"
    
    close_section "$OUTPUT_FILE"
    
    # Section 10.1: Audit logging mechanisms are in place
    echo "Checking Requirement 10.1 - Audit logging mechanisms..."
    add_section "$OUTPUT_FILE" "req-10.1" "Requirement 10.1: Audit logging mechanisms are in place" "active"
    
    # Helper function to safely execute check functions and handle errors
    safe_check() {
        local check_function="$1"
        local region="$2"
        
        echo "Running check: $check_function"
        result=$($check_function "$region" 2>/dev/null || echo "error:Error running $check_function, check AWS permissions")
        status=$(echo "$result" | cut -d':' -f1 | xargs)
        details=$(echo "$result" | cut -d':' -f2-)
        
        if [ "$status" = "error" ]; then
            status="warning"
            echo "  ⚠️ Warning: $details"
        else
            echo "  ✓ Check completed with status: $status"
        fi
        
        echo "$status:$details"
    }
    
    # Check 10.1.1 - Implementation of audit trails
    echo "Checking CloudTrail configuration..."
    cloudtrail_result=$("check_cloudtrail_enabled" "$REGION")
    status=$(echo "$cloudtrail_result" | cut -d':' -f1 | xargs)
    details=$(echo "$cloudtrail_result" | cut -d':' -f2-)
    
    add_check_item "$OUTPUT_FILE" "$status" "10.1.1 - Implementation of audit trails" \
        "$details" \
        "Ensure CloudTrail is enabled in all regions with at least one multi-region trail."
    
    if [ "$status" = "pass" ]; then
        ((passed_checks++))
    elif [ "$status" = "fail" ]; then
        ((failed_checks++))
    else
        ((warning_checks++))
    fi
    ((total_checks++))
    
    # Section 10.2 - Audit logs capture all user activities
    # For this example, we're including it in 10.1 section as it's closely related
    # In a full implementation, you might have a separate section
    
    # Check CloudWatch log metric filters for key security events
    echo "Checking CloudWatch log metric filters..."
    cloudwatch_result=$("check_cloudwatch_alarms" "$REGION")
    status=$(echo "$cloudwatch_result" | cut -d':' -f1 | xargs)
    details=$(echo "$cloudwatch_result" | cut -d':' -f2-)
    
    add_check_item "$OUTPUT_FILE" "$status" "10.2.1.1-10.2.1.7 - Specific audit log requirements" \
        "$details" \
        "Configure CloudWatch metric filters and alarms for all required security events including: individual user access to cardholder data, administrative actions, access to audit logs, invalid access attempts, changes to authentication credentials, initialization/stopping of audit logs, and creation/deletion of system-level objects."
    
    if [ "$status" = "pass" ]; then
        ((passed_checks++))
    elif [ "$status" = "fail" ]; then
        ((failed_checks++))
    else
        ((warning_checks++))
    fi
    ((total_checks++))
    
    # Check VPC Flow Logs for network traffic monitoring
    echo "Checking VPC Flow Logs..."
    vpc_flow_result=$("check_vpc_flow_logs" "$REGION") 
    status=$(echo "$vpc_flow_result" | cut -d':' -f1 | xargs)
    details=$(echo "$vpc_flow_result" | cut -d':' -f2-)
    
    add_check_item "$OUTPUT_FILE" "$status" "10.2.1.a - Network access is logged" \
        "$details" \
        "Enable VPC Flow Logs for all VPCs to capture network traffic information."
    
    if [ "$status" = "pass" ]; then
        ((passed_checks++))
    elif [ "$status" = "fail" ]; then
        ((failed_checks++))
    else
        ((warning_checks++))
    fi
    ((total_checks++))
    
    # Check database logging
    echo "Checking database logging..."
    db_logging_result=$("check_database_logging" "$REGION")
    status=$(echo "$db_logging_result" | cut -d':' -f1 | xargs)
    details=$(echo "$db_logging_result" | cut -d':' -f2-)
    
    add_check_item "$OUTPUT_FILE" "$status" "10.2.1.b - Database access is logged" \
        "$details" \
        "Enable appropriate logging for all database systems that may contain cardholder data."
    
    if [ "$status" = "pass" ]; then
        ((passed_checks++))
    elif [ "$status" = "fail" ]; then
        ((failed_checks++))
    else
        ((warning_checks++))
    fi
    ((total_checks++))
    
    close_section "$OUTPUT_FILE"
    
    # Section 10.3: Audit logs record specific details
    echo "Checking Requirement 10.3 - Audit log details..."
    add_section "$OUTPUT_FILE" "req-10.3" "Requirement 10.3: Audit logs record specific details" "none"
    
    # This would typically be a detailed check of log formats
    # For this script, we'll make it a warning with manual verification steps
    
    add_check_item "$OUTPUT_FILE" "warning" "10.3.1-10.3.2 - Required audit log content and format" \
        "<p class=\"yellow\">Manual verification required. CloudTrail logs should contain all required audit trail entries.</p>
        <p>Verify that your CloudTrail and other AWS logs include the following for each event (per Requirement 10.2.2):</p>
        <ul>
            <li>User identification</li>
            <li>Type of event</li>
            <li>Date and time</li>
            <li>Success or failure indication</li>
            <li>Origination of event</li>
            <li>Identity or name of affected data, system component, or resource</li>
        </ul>
        <p>CloudTrail logs typically include these elements by default, but custom applications may require additional configuration.</p>" \
        "Review CloudTrail log structure to ensure all required elements are captured. For custom applications, implement logging that captures all required elements."
    
    ((warning_checks++))
    ((total_checks++))
    
    close_section "$OUTPUT_FILE"
    
    # Section 10.4: Log storage and integrity
    echo "Checking Requirement 10.4 - Log storage and integrity..."
    add_section "$OUTPUT_FILE" "req-10.4" "Requirement 10.4: Log storage and integrity" "none"
    
    # Check CloudTrail log file validation
    echo "Checking CloudTrail log file validation..."
    validation_result=$("check_cloudtrail_validation" "$REGION")
    status=$(echo "$validation_result" | cut -d':' -f1 | xargs)
    details=$(echo "$validation_result" | cut -d':' -f2-)
    
    add_check_item "$OUTPUT_FILE" "$status" "10.4.1.b - Log file integrity validation" \
        "$details" \
        "Enable log file validation for all CloudTrail trails."
    
    if [ "$status" = "pass" ]; then
        ((passed_checks++))
    elif [ "$status" = "fail" ]; then
        ((failed_checks++))
    else
        ((warning_checks++))
    fi
    ((total_checks++))
    
    # Check log file integrity monitoring
    echo "Checking log file integrity monitoring..."
    integrity_result=$("check_log_integrity_monitoring" "$REGION")
    status=$(echo "$integrity_result" | cut -d':' -f1 | xargs)
    details=$(echo "$integrity_result" | cut -d':' -f2-)
    
    add_check_item "$OUTPUT_FILE" "$status" "10.3.4 - File integrity monitoring for logs" \
        "$details" \
        "Implement file integrity monitoring or change-detection mechanisms for audit logs."
    
    if [ "$status" = "pass" ]; then
        ((passed_checks++))
    elif [ "$status" = "fail" ]; then
        ((failed_checks++))
    else
        ((warning_checks++))
    fi
    ((total_checks++))
    
    # Check CloudTrail S3 bucket access controls
    echo "Checking CloudTrail S3 bucket access controls..."
    s3_access_result=$("check_cloudtrail_s3_access" "$REGION")
    status=$(echo "$s3_access_result" | cut -d':' -f1 | xargs)
    details=$(echo "$s3_access_result" | cut -d':' -f2-)
    
    add_check_item "$OUTPUT_FILE" "$status" "10.3.1-10.3.2 - Log access controls" \
        "$details" \
        "Configure S3 bucket policies and ACLs to prevent unauthorized access to log files. According to Requirement 10.3.1 and 10.3.2, read access must be limited to those with a job-related need, and logs must be protected from modifications by individuals."
    
    if [ "$status" = "pass" ]; then
        ((passed_checks++))
    elif [ "$status" = "fail" ]; then
        ((failed_checks++))
    else
        ((warning_checks++))
    fi
    ((total_checks++))
    
    # Check log retention settings
    echo "Checking log retention settings..."
    retention_result=$("check_log_retention" "$REGION")
    status=$(echo "$retention_result" | cut -d':' -f1 | xargs)
    details=$(echo "$retention_result" | cut -d':' -f2-)
    
    add_check_item "$OUTPUT_FILE" "$status" "10.4.3 - Audit log retention" \
        "$details" \
        "Configure CloudWatch Log Groups to retain logs for at least 90 days, with at least 3 months immediately available for analysis."
    
    if [ "$status" = "pass" ]; then
        ((passed_checks++))
    elif [ "$status" = "fail" ]; then
        ((failed_checks++))
    else
        ((warning_checks++))
    fi
    ((total_checks++))
    
    close_section "$OUTPUT_FILE"
    
    # Section 10.5: Time synchronization
    echo "Checking Requirement 10.5 - Time synchronization..."
    echo "Checking Requirement 10.5 - Time synchronization..."
    add_section "$OUTPUT_FILE" "req-10.5" "Requirement 10.5: Time synchronization" "none"
    
    # Check time synchronization
    echo "Checking time synchronization..."
    time_sync_result=$("check_time_synchronization" "$REGION")
    status=$(echo "$time_sync_result" | cut -d':' -f1 | xargs)
    details=$(echo "$time_sync_result" | cut -d':' -f2-)
    
    add_check_item "$OUTPUT_FILE" "$status" "10.6.1-10.6.3 - Time synchronization" \
        "$details" \
        "Configure all systems to use NTP or similar technology for time synchronization. Requirement 10.6.1 requires time-synchronization technology. Requirement 10.6.2 requires correct and consistent time settings using designated time servers. Requirement 10.6.3 requires protecting time data and monitoring changes to time settings."
    
    if [ "$status" = "pass" ]; then
        ((passed_checks++))
    elif [ "$status" = "fail" ]; then
        ((failed_checks++))
    else
        ((warning_checks++))
    fi
    ((total_checks++))
    
    close_section "$OUTPUT_FILE"
    
    # Section 10.6: Log monitoring and anomaly detection
    echo "Checking Requirement 10.6 - Log monitoring and anomaly detection..."
    add_section "$OUTPUT_FILE" "req-10.6" "Requirement 10.6: Log monitoring and anomaly detection" "none"
    
    # Check log anomaly detection
    echo "Checking log anomaly detection mechanisms..."
    anomaly_result=$("check_log_anomaly_detection" "$REGION")
    status=$(echo "$anomaly_result" | cut -d':' -f1 | xargs)
    details=$(echo "$anomaly_result" | cut -d':' -f2-)
    
    add_check_item "$OUTPUT_FILE" "$status" "10.4.1-10.4.3 - Log review and monitoring process" \
        "$details" \
        "Enable GuardDuty and Security Hub for automated log analysis and threat detection. Requirement 10.4.1 requires daily review of security events and logs from critical systems. Requirement 10.4.1.1 requires using automated mechanisms for log reviews. Requirement 10.4.2 requires periodic review of all other logs. Requirement 10.4.3 requires addressing exceptions and anomalies."
    
    if [ "$status" = "pass" ]; then
        ((passed_checks++))
    elif [ "$status" = "fail" ]; then
        ((failed_checks++))
    else
        ((warning_checks++))
    fi
    ((total_checks++))
    
    close_section "$OUTPUT_FILE"
    
    # Section 10.7: Detection and response to security control failures
    echo "Checking Requirement 10.7 - Detection and response to security control failures..."
    add_section "$OUTPUT_FILE" "req-10.7" "Requirement 10.7: Detection and response to security control failures" "none"
    
    # This is typically implemented through organizational procedures
    # We'll add this as a warning that requires manual verification
    
    add_check_item "$OUTPUT_FILE" "warning" "10.7.1 - 10.7.3 - Detection and response processes" \
        "<p class=\"yellow\">Manual verification required. These requirements relate to organizational processes.</p>
        <p>PCI DSS requires:</p>
        <ul>
            <li>A process to respond to critical security control failures promptly</li>
            <li>Restoring security functions</li>
            <li>Identifying and documenting the duration of the security failure</li>
            <li>Identifying and addressing causes of the failure</li>
            <li>Implementing corrective actions</li>
            <li>Resuming monitoring of security controls</li>
        </ul>" \
        "Develop and document processes for detecting and responding to security control failures. Ensure these processes are tested periodically."
    
    ((warning_checks++))
    ((total_checks++))
    
    close_section "$OUTPUT_FILE"
    
    # Finalize the HTML report
    finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"
    
    # Show summary
    echo
    echo "Assessment Complete!"
    echo "===================="
    echo "Total checks:   $total_checks"
    echo "Passed checks:  $passed_checks"
    echo "Failed checks:  $failed_checks"
    echo "Warning checks: $warning_checks"
    echo
    echo "Report saved to: $OUTPUT_FILE"
    
    # On macOS, open the report automatically
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open "$OUTPUT_FILE"
    else
        echo "Please open the report file in your web browser to view the results."
    fi
}

# Run the main function
main
