#!/usr/bin/env bash
#
# PCI DSS v4.0 Compliance Assessment Script for Requirement 5
# Protect all systems against malware and regularly update anti-malware software or programs
#

# Variables
REQUIREMENT_NUMBER="5"
SCRIPT_DIR="$(dirname "$0")"
REPORT_DIR="$SCRIPT_DIR/reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="$REPORT_DIR/pci_req${REQUIREMENT_NUMBER}_report_${TIMESTAMP}.html"
REPORT_TITLE="PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report"
# Initialize counters
total_checks=0
passed_checks=0
failed_checks=0
warning_checks=0

# Source the HTML report library
source "$SCRIPT_DIR/pci_html_report_lib.sh" || {
    echo "Error: Required library file pci_html_report_lib.sh not found."
    exit 1
}

# Function to validate AWS CLI is installed and configured
validate_aws_cli() {
    which aws > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: AWS CLI is not installed or not in PATH. Please install AWS CLI."
        exit 1
    fi
    
    aws sts get-caller-identity > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: AWS CLI is not configured properly. Please run 'aws configure'."
        exit 1
    fi
    
    # Check AWS CLI version
    aws_version=$(aws --version 2>&1 | cut -d " " -f1 | cut -d "/" -f2)
    echo "Using AWS CLI version: $aws_version"
}

# Function to check if a command is available for a specific AWS service
check_command_access() {
    local output_file="$1"
    local service="$2"
    local command="$3"
    local region="$4"
    local log_output="${5:-true}"  # 預設會記錄

    echo "Checking access to AWS $service $command..."

    local result
    result=$(aws $service $command --region "$region" --max-items 1 2>&1)

    local api_name="AWS API Access: $service $command"
    local message="The AWS API command aws $service $command executed successfully."

    if [[ $result == *"command not found"* ]]; then
        [[ "$log_output" == "true" ]] && add_check_item "$output_file" "warning" "$api_name" \
            "<p><code>aws $service $command</code> is not available (command not found).</p>" \
            "Ensure AWS CLI is installed and supports this command."
		((warning_checks++))
        ((total_checks++))
        return 2

    elif [[ $result == *"AccessDenied"* || $result == *"UnauthorizedOperation"* ]]; then
        [[ "$log_output" == "true" ]] && add_check_item "$output_file" "fail" "$api_name" \
            "<p><code>aws $service $command</code> - access denied.</p>" \
            "Check IAM policies for permission: $service:$command."
		((failed_checks++))
        ((total_checks++))
        return 1

    else
        [[ "$log_output" == "true" ]] && add_check_item "$output_file" "pass" "$api_name" \
            "<p>$message</p>" \
            "AWS CLI permissions are sufficient for $service:$command."
		((passed_checks++))
        ((total_checks++))
        return 0
    fi
}



# Function to check EC2 instances for anti-malware protection
check_ec2_antimalware() {
    local region="$1"
    local details=""
    local found_unprotected=false
    
    # Get all EC2 instances
    instance_list=$(aws ec2 describe-instances --region $region --query 'Reservations[*].Instances[*].[InstanceId]' --output text 2>/dev/null)
    
    details+="<p>Analysis of EC2 instances in region $region for anti-malware protection:</p>"
    
    if [ -z "$instance_list" ]; then
        details+="<p>No EC2 instances found in region $region.</p>"
        echo "$details"
        return
    fi
    
    details+="<ul>"
    
    for instance_id in $instance_list; do
        # Get instance details
        instance_info=$(aws ec2 describe-instances --region $region --instance-ids $instance_id 2>/dev/null)
        
        # Get instance state
        instance_state=$(echo "$instance_info" | grep '"Name":' | head -1 | awk -F '"' '{print $4}')
        
        # Skip terminated instances
        if [ "$instance_state" == "terminated" ]; then
            continue
        fi
        
        # Get instance platform (Windows or Linux)
        platform=$(echo "$instance_info" | grep '"Platform":' | awk -F '"' '{print $4}')
        if [ -z "$platform" ]; then
            platform="Linux/UNIX" # Default to Linux if platform is not specified
        fi
        
        # Get tags to check for anti-malware software
        antimalware_tag=$(echo "$instance_info" | grep -A 1 '"Key": "AntiMalware"' | grep 'Value' | awk -F '"' '{print $4}')
        
        instance_name=$(echo "$instance_info" | grep -A 1 '"Key": "Name"' | grep 'Value' | awk -F '"' '{print $4}')
        if [ -z "$instance_name" ]; then
            instance_name="Unnamed"
        fi
        
        if [ -z "$antimalware_tag" ]; then
            details+="<li class=\"red\">Instance $instance_id ($instance_name) - Platform: $platform - No anti-malware tag found. Unable to determine if anti-malware is installed.</li>"
            found_unprotected=true
        else
            details+="<li class=\"green\">Instance $instance_id ($instance_name) - Platform: $platform - Anti-malware: $antimalware_tag</li>"
        fi
    done
    
    details+="</ul>"
    
    # Check for SSM managed instances with anti-malware
    if check_command_access "$OUTPUT_FILE" "ssm" "describe-instance-information" "$region" false; then
        details+="<p>Checking for SSM managed instances with anti-malware:</p>"
        
        # Get all SSM managed instances
        ssm_instances=$(aws ssm describe-instance-information --region $region --query 'InstanceInformationList[*].[InstanceId]' --output text 2>/dev/null)
        
        if [ -z "$ssm_instances" ]; then
            details+="<p>No SSM managed instances found in region $region.</p>"
        else
            details+="<ul>"
            
            for instance_id in $ssm_instances; do
                # Check for anti-malware software using SSM inventory
                if check_command_access "$OUTPUT_FILE" "ssm" "list-inventory-entries" "$region" false; then
                    inventory=$(aws ssm list-inventory-entries --region $region --instance-id $instance_id --type-name "AWS:Application" 2>/dev/null)
                    
                    # Check for common anti-malware software
                    antimalware_found=false
                    for software in "Trend Micro" "Symantec" "McAfee" "CrowdStrike" "Sophos" "Windows Defender" "Kaspersky" "Avast" "AVG" "ESET" "Bitdefender" "Malwarebytes" "Clam" "Antivirus" "Anti-Virus" "Anti-Malware"; do
                        if echo "$inventory" | grep -i "$software" > /dev/null; then
                            antimalware_name=$(echo "$inventory" | grep -i -A 2 "$software" | grep "Name" | head -1 | awk -F '"' '{print $4}')
                            antimalware_version=$(echo "$inventory" | grep -i -A 4 "$software" | grep "Version" | head -1 | awk -F '"' '{print $4}')
                            details+="<li class=\"green\">Instance $instance_id - Anti-malware: $antimalware_name ($antimalware_version)</li>"
                            antimalware_found=true
                            break
                        fi
                    done
                    
                    if [ "$antimalware_found" = false ]; then
                        # Get instance details for additional context
                        instance_name=$(aws ec2 describe-instances --region $region --instance-ids $instance_id --query 'Reservations[*].Instances[*].Tags[?Key==`Name`].Value' --output text 2>/dev/null)
                        platform=$(aws ec2 describe-instances --region $region --instance-ids $instance_id --query 'Reservations[*].Instances[*].Platform' --output text 2>/dev/null)
                        if [ -z "$platform" ]; then
                            platform="Linux/UNIX"
                        fi
                        if [ -z "$instance_name" ]; then
                            instance_name="Unnamed"
                        fi
                        
                        details+="<li class=\"red\">Instance $instance_id ($instance_name) - Platform: $platform - No known anti-malware software found in SSM inventory.</li>"
                        found_unprotected=true
                    fi
                else
                    details+="<li class=\"yellow\">Instance $instance_id - Unable to check inventory due to permission restrictions.</li>"
                    found_unprotected=true
                fi
            done
            
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check SSM managed instances due to permission restrictions.</p>"
        found_unprotected=true
    fi
    
    # Check for GuardDuty
    if check_command_access "$OUTPUT_FILE" "guardduty" "list-detectors" "$region" false; then
        details+="<p>Checking for GuardDuty malware protection:</p>"
        
        # Check if GuardDuty is enabled
        detectors=$(aws guardduty list-detectors --region $region --query 'DetectorIds' --output text 2>/dev/null)
        
        if [ -z "$detectors" ]; then
            details+="<p class=\"red\">GuardDuty is not enabled in region $region. GuardDuty can provide additional malware detection capabilities.</p>"
            found_unprotected=true
        else
            # Check if Malware Protection is enabled for each detector
            for detector_id in $detectors; do
                if check_command_access "$OUTPUT_FILE" "guardduty" "get-malware-protection-plan" "$region" false; then
                    malware_plan=$(aws guardduty get-malware-protection-plan --region $region --detector-id $detector_id 2>/dev/null)
                    if [ $? -eq 0 ]; then
                        plan_status=$(echo "$malware_plan" | grep '"Status":' | awk -F '"' '{print $4}')
                        if [ "$plan_status" == "ENABLED" ]; then
                            details+="<p class=\"green\">GuardDuty Malware Protection is enabled for detector $detector_id in region $region.</p>"
                        else
                            details+="<p class=\"red\">GuardDuty Malware Protection is disabled for detector $detector_id in region $region.</p>"
                            found_unprotected=true
                        fi
                    else
                        details+="<p class=\"red\">GuardDuty Malware Protection plan not found for detector $detector_id in region $region.</p>"
                        found_unprotected=true
                    fi
                else
                    details+="<p class=\"yellow\">Unable to check GuardDuty Malware Protection status due to permission restrictions.</p>"
                    found_unprotected=true
                fi
            done
        fi
    else
        details+="<p class=\"yellow\">Unable to check GuardDuty status due to permission restrictions.</p>"
        found_unprotected=true
    fi
    
    echo "$details"
    if [ "$found_unprotected" = true ]; then
        return 1
    else
        return 0
    fi
}

# Function to check if anti-malware is regularly updated
check_antimalware_updates() {
    local region="$1"
    local details=""
    local found_outdated=false
    
    details+="<p>Checking for anti-malware update mechanisms:</p>"
    
    # Check for Systems Manager Patch Manager
    if check_command_access "$OUTPUT_FILE" "ssm" "describe-patch-baselines" "$region" false; then
        # Get patch baselines without filtering (avoid using PRODUCT filter which causes errors)
        patch_baselines=$(aws ssm describe-patch-baselines --region $region --query 'BaselineIdentities[*].[BaselineId,BaselineName]' --output text 2>/dev/null)
        
        if [ $? -ne 0 ]; then
            details+="<p class=\"yellow\">Error accessing patch baselines. Check AWS CLI permissions.</p>"
            found_outdated=true
        elif [ -z "$patch_baselines" ]; then
            details+="<p class=\"yellow\">No patch baselines found in SSM Patch Manager. Consider creating dedicated baselines for anti-malware updates.</p>"
        else
            details+="<p class=\"green\">Found the following patch baselines in SSM Patch Manager (review for anti-malware applicability):</p><ul>"
            echo "$patch_baselines" | head -5 | while read -r baseline_id baseline_name; do
                details+="<li>$baseline_name ($baseline_id)</li>"
            done
            if [ $(echo "$patch_baselines" | wc -l) -gt 5 ]; then
                details+="<li>... (additional baselines not shown)</li>"
            fi
            details+="</ul>"
        fi
        
        # Check for patch groups
        patch_groups=$(aws ssm describe-patch-groups --region $region --query 'Mappings[*].[PatchGroup]' --output text 2>/dev/null)
        
        if [ -z "$patch_groups" ]; then
            details+="<p class=\"yellow\">No patch groups found in SSM Patch Manager. Consider configuring patch groups for anti-malware updates.</p>"
        else
            details+="<p>Patch groups configured in SSM:</p><ul>"
            for group in $patch_groups; do
                details+="<li>$group</li>"
            done
            details+="</ul>"
        fi
        
        # Check for maintenance windows that might be used for updates
        maint_windows=$(aws ssm describe-maintenance-windows --region $region --filters "Key=Name,Values=*antivirus*,*anti-virus*,*malware*,*security*" --query 'WindowIdentities[*].[WindowId,Name]' --output text 2>/dev/null)
        
        if [ -z "$maint_windows" ]; then
            details+="<p class=\"yellow\">No maintenance windows found specifically for anti-malware updates. Consider creating dedicated maintenance windows.</p>"
            found_outdated=true
        else
            details+="<p class=\"green\">Found maintenance windows that may be used for anti-malware updates:</p><ul>"
            echo "$maint_windows" | while read -r window_id window_name; do
                details+="<li>$window_name ($window_id)</li>"
            done
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check SSM Patch Manager due to permission restrictions.</p>"
        found_outdated=true
    fi
    
    # Check for AWS Config rules - properly handle permission errors
    if check_command_access "$OUTPUT_FILE" "configservice" "describe-config-rules" "$region" false; then
        config_output=$(aws configservice describe-config-rules --region $region 2>&1)
        
        if [[ "$config_output" == *"AccessDeniedException"* ]] || [[ "$config_output" == *"UnauthorizedOperation"* ]]; then
            details+="<p class=\"yellow\">Unable to check AWS Config rules due to access denied. The IAM user lacks required permissions.</p>"
            found_outdated=true
        else
            # Try to extract config rules if access was successful
            config_rules=$(echo "$config_output" | grep -E "APPROVED_AMIS_BY_ID|EC2_MANAGEDINSTANCE_APPLICATIONS_REQUIRED|EC2_MANAGEDINSTANCE_PATCH_COMPLIANCE_STATUS" | grep -o '"ConfigRuleName": "[^"]*' | cut -d'"' -f4)
            
            if [ -z "$config_rules" ]; then
                details+="<p class=\"yellow\">No AWS Config rules found that might enforce anti-malware requirements. Consider implementing rules for approved AMIs and required applications.</p>"
                found_outdated=true
            else
                details+="<p class=\"green\">Found AWS Config rules that may relate to anti-malware requirements:</p><ul>"
                for rule in $config_rules; do
                    details+="<li>$rule</li>"
                done
                details+="</ul>"
            fi
        fi
    else
        details+="<p class=\"yellow\">Unable to check AWS Config rules due to permission restrictions.</p>"
        found_outdated=true
    fi
    
    # Check for Inspector findings - handle validation errors
    if check_command_access "$OUTPUT_FILE" "inspector2" "list-findings" "$region" false; then
        # Use a more generic approach without problematic filters
        inspector_output=$(aws inspector2 list-findings --region $region --max-results 10 2>&1)
        
        if [[ "$inspector_output" == *"ValidationException"* ]] || [[ "$inspector_output" == *"AccessDeniedException"* ]]; then
            details+="<p class=\"yellow\">Unable to check Inspector findings due to validation errors or permission issues.</p>"
            found_outdated=true
        else
            # Look for keywords in the output
            malware_matches=$(echo "$inspector_output" | grep -i -E "malware|virus|antivirus|anti-virus" | wc -l)
            outdated_matches=$(echo "$inspector_output" | grep -i -E "outdated|update|patch" | wc -l)
            
            if [ $malware_matches -gt 0 ] || [ $outdated_matches -gt 0 ]; then
                details+="<p class=\"red\">Found Inspector findings that may relate to malware or outdated software. Review in AWS console.</p>"
                finding_count=$(echo "$inspector_output" | grep -c "findingArn")
                
                details+="<p>Summary: $finding_count findings found, approximately $malware_matches malware-related and $outdated_matches update-related findings.</p>"
                found_outdated=true
            else
                details+="<p class=\"green\">No obvious malware or outdated software findings in Inspector results.</p>"
            fi
        fi
    else
        details+="<p class=\"yellow\">Unable to check Inspector findings due to permission restrictions.</p>"
        found_outdated=true
    fi
    
    echo "$details"
    if [ "$found_outdated" = true ]; then
        return 1
    else
        return 0
    fi
}

# Function to check for periodic malware scans
check_periodic_scans() {
    local region="$1"
    local details=""
    local found_issues=false
    
    details+="<p>Checking for evidence of periodic malware scans:</p>"
    
    # Check for EventBridge rules that might trigger scans
    if check_command_access "$OUTPUT_FILE" "events" "list-rules" "$region" false; then
        scan_rules=$(aws events list-rules --region $region --name-prefix "Malware" --query 'Rules[*].[Name,ScheduleExpression]' --output text 2>/dev/null)
        
        if [ -z "$scan_rules" ]; then
            details+="<p class=\"yellow\">No EventBridge rules found with 'Malware' in the name. Consider implementing scheduled malware scans.</p>"
            found_issues=true
            
            # Check for other security-related rules
            security_rules=$(aws events list-rules --region $region --name-prefix "Security" --query 'Rules[*].[Name,ScheduleExpression]' --output text 2>/dev/null)
            
            if [ -n "$security_rules" ]; then
                details+="<p>Found security-related EventBridge rules that might include malware scanning:</p><ul>"
                echo "$security_rules" | while read -r name schedule; do
                    details+="<li>$name (Schedule: $schedule)</li>"
                done
                details+="</ul>"
            fi
        else
            details+="<p class=\"green\">Found EventBridge rules that may trigger malware scans:</p><ul>"
            echo "$scan_rules" | while read -r name schedule; do
                details+="<li>$name (Schedule: $schedule)</li>"
            done
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check EventBridge rules due to permission restrictions.</p>"
        found_issues=true
    fi
    
    # Check for GuardDuty scan configurations
    if check_command_access "$OUTPUT_FILE" "guardduty" "list-detectors" "$region" false; then
        detectors=$(aws guardduty list-detectors --region $region --query 'DetectorIds' --output text 2>/dev/null)
        
        if [ -n "$detectors" ]; then
            details+="<p>Checking GuardDuty scan settings:</p><ul>"
            
            for detector_id in $detectors; do
                if check_command_access "$OUTPUT_FILE" "guardduty" "get-detector" "$region" false; then
                    detector_settings=$(aws guardduty get-detector --region $region --detector-id $detector_id 2>/dev/null)
                    
                    # Check if data sources for malware detection are enabled
                    malware_protection=$(echo "$detector_settings" | grep -A 5 '"MalwareProtection"' | grep '"Status":' | awk -F '"' '{print $4}')
                    ebs_scanning=$(echo "$detector_settings" | grep -A 5 '"ScanEc2InstanceWithFindings"' | grep '"Status":' | awk -F '"' '{print $4}')
                    
                    if [ "$malware_protection" == "ENABLED" ] && [ "$ebs_scanning" == "ENABLED" ]; then
                        details+="<li class=\"green\">GuardDuty detector $detector_id has malware protection and EBS scanning enabled.</li>"
                    else
                        details+="<li class=\"red\">GuardDuty detector $detector_id has malware protection or EBS scanning disabled.</li>"
                        found_issues=true
                    fi
                else
                    details+="<li class=\"yellow\">Unable to check GuardDuty detector settings due to permission restrictions.</li>"
                    found_issues=true
                fi
            done
            
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check GuardDuty detectors due to permission restrictions.</p>"
        found_issues=true
    fi
    
    # Check for SSM Commands for malware scans
    if check_command_access "$OUTPUT_FILE" "ssm" "list-commands" "$region" false; then
        # Look for scan commands in the last 30 days (handle date command differences)
        thirty_days_ago=$(date -d "30 days ago" +%Y-%m-%dT%H:%M:%S 2>/dev/null || date -v-30d +%Y-%m-%dT%H:%M:%S 2>/dev/null)
        
        if [ -n "$thirty_days_ago" ]; then
            # Use a more resilient approach without filters that might cause problems
            scan_commands=$(aws ssm list-commands --region $region --query 'Commands[*].[CommandId,DocumentName]' --output json 2>/dev/null | grep -i -E "scan|malware|virus|antivirus|anti-virus")
            
            if [ -z "$scan_commands" ]; then
                details+="<p class=\"yellow\">No recent SSM commands found that appear to run malware scans. Verify if scans are being executed through other mechanisms.</p>"
                found_issues=true
            else
                details+="<p class=\"green\">Found recent SSM commands that may be running malware scans:</p><pre>$scan_commands</pre>"
            fi
        else
            details+="<p class=\"yellow\">Could not determine date format for checking recent SSM commands. Manual verification required.</p>"
            found_issues=true
        fi
    else
        details+="<p class=\"yellow\">Unable to check SSM commands due to permission restrictions.</p>"
        found_issues=true
    fi
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

# Function to check for anti-malware mechanisms at CDE boundaries
check_boundary_protection() {
    local region="$1"
    local details=""
    local found_issues=false
    
    details+="<p>Checking for anti-malware mechanisms at CDE boundaries:</p>"
    
    # Check for WAF usage
    if check_command_access "$OUTPUT_FILE" "wafv2" "list-web-acls" "$region" false; then
        web_acls=$(aws wafv2 list-web-acls --region $region --scope REGIONAL --query 'WebACLs[*].[Name,Id]' --output text 2>/dev/null)
        
        if [ -z "$web_acls" ]; then
            details+="<p class=\"yellow\">No WAF Web ACLs found in region $region. WAF can provide protection against malicious web traffic.</p>"
            found_issues=true
        else
            details+="<p>Found WAF Web ACLs in region $region:</p><ul>"
            
            echo "$web_acls" | while read -r name id; do
                details+="<li>$name (ID: $id)</li>"
                
                # Check for malware/AV related rule groups in each ACL
                acl_details=$(aws wafv2 get-web-acl --region $region --name "$name" --scope REGIONAL --id "$id" 2>/dev/null)
                
                # Look for managed rule groups related to security
                managed_rules=$(echo "$acl_details" | grep -A 2 '"ManagedRuleGroupStatement"' | grep '"Name":' | awk -F '"' '{print $4}')
                
                # Look for specific rules that might be related to malware
                av_rules=""
                for rule in "AWSManagedRulesKnownBadInputsRuleSet" "AWSManagedRulesCommonRuleSet" "AWSManagedRulesAmazonIpReputationList"; do
                    if echo "$managed_rules" | grep -q "$rule"; then
                        av_rules+="$rule, "
                    fi
                done
                
                if [ -n "$av_rules" ]; then
                    details+="<ul><li class=\"green\">Using security-related managed rule groups: ${av_rules%, }</li></ul>"
                else
                    details+="<ul><li class=\"yellow\">No security-related managed rule groups detected in this Web ACL.</li></ul>"
                    found_issues=true
                fi
            done
            
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check WAF web ACLs due to permission restrictions.</p>"
        found_issues=true
    fi
    
    # Check for Shield Advanced protection
    if check_command_access "$OUTPUT_FILE" "shield" "describe-subscription" "$region" false; then
        shield_subscription=$(aws shield describe-subscription 2>/dev/null)
        
        if [ $? -eq 0 ]; then
            shield_active=$(echo "$shield_subscription" | grep '"SubscriptionArn"')
            
            if [ -n "$shield_active" ]; then
                details+="<p class=\"green\">AWS Shield Advanced is active, providing additional protection against DDoS and malicious traffic.</p>"
                
                # Check for protected resources
                if check_command_access "$OUTPUT_FILE" "shield" "list-protections" "$region" false; then
                    protected_resources=$(aws shield list-protections --query 'Protections[*].[ResourceArn,Name]' --output text 2>/dev/null)
                    
                    if [ -n "$protected_resources" ]; then
                        details+="<p>Shield Advanced protection is configured for the following resources:</p><ul>"
                        echo "$protected_resources" | while read -r arn name; do
                            details+="<li>$name (ARN: $arn)</li>"
                        done
                        details+="</ul>"
                    else
                        details+="<p class=\"yellow\">No resources are currently protected by Shield Advanced. Consider adding protection to key resources.</p>"
                        found_issues=true
                    fi
                fi
            else
                details+="<p class=\"yellow\">AWS Shield Advanced is not enabled. Consider enabling it for enhanced protection.</p>"
                found_issues=true
            fi
        else
            details+="<p class=\"yellow\">AWS Shield Advanced is not enabled. Consider enabling it for enhanced protection.</p>"
            found_issues=true
        fi
    else
        details+="<p class=\"yellow\">Unable to check Shield Advanced status due to permission restrictions.</p>"
        found_issues=true
    fi
    
    # Check for Network Firewall usage
    if check_command_access "$OUTPUT_FILE" "network-firewall" "list-firewalls" "$region" false; then
        firewalls=$(aws network-firewall list-firewalls --region $region --query 'Firewalls[*].[FirewallName]' --output text 2>/dev/null)
        
        if [ -z "$firewalls" ]; then
            details+="<p class=\"yellow\">No AWS Network Firewalls found in region $region. Network Firewalls can provide additional protection.</p>"
            found_issues=true
        else
            details+="<p class=\"green\">Found AWS Network Firewalls in region $region:</p><ul>"
            
            for firewall in $firewalls; do
                details+="<li>$firewall</li>"
                
                # Check for firewall policy details
                firewall_details=$(aws network-firewall describe-firewall --region $region --firewall-name "$firewall" 2>/dev/null)
                policy_arn=$(echo "$firewall_details" | grep '"FirewallPolicyArn":' | awk -F '"' '{print $4}')
                
                if [ -n "$policy_arn" ]; then
                    policy_details=$(aws network-firewall describe-firewall-policy --region $region --firewall-policy-arn "$policy_arn" 2>/dev/null)
                    
                    # Check for stateful rule groups that might relate to malware/security
                    stateful_groups=$(echo "$policy_details" | grep -A 10 '"StatefulRuleGroupReferences"' | grep '"ResourceArn":' | awk -F '"' '{print $4}')
                    
                    if [ -n "$stateful_groups" ]; then
                        details+="<ul><li>Using stateful rule groups for inspection</li></ul>"
                    else
                        details+="<ul><li class=\"yellow\">No stateful rule groups found in firewall policy.</li></ul>"
                        found_issues=true
                    fi
                fi
            done
            
            details+="</ul>"
        fi
    else
        details+="<p class=\"yellow\">Unable to check Network Firewalls due to permission restrictions.</p>"
        found_issues=true
    fi
    
    echo "$details"
    if [ "$found_issues" = true ]; then
        return 1
    else
        return 0
    fi
}

# Main script

# Create report directory if it doesn't exist
mkdir -p "$REPORT_DIR"

# Validate AWS CLI
validate_aws_cli

# Get AWS CLI configured region as default
REGION=$(aws configure get region 2>/dev/null)
if [ -z "$REGION" ]; then
    # Fallback to asking user for region if not configured in AWS CLI
    echo "No default region configured in AWS CLI."
    echo "Enter AWS region to assess (e.g., us-east-1):"
    read -r REGION
    
    # Validate region
    aws ec2 describe-regions --query "Regions[?RegionName=='$REGION'].RegionName" --output text > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "Error: Invalid region specified. Please enter a valid AWS region."
        exit 1
    fi
else
    echo "Using AWS CLI configured region: $REGION"
fi

# Initialize HTML report
initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE" "$REQUIREMENT_NUMBER" "$REGION"

# Check AWS CLI permissions
echo "Checking AWS CLI permissions..."
add_section "$OUTPUT_FILE" "permissions" "AWS CLI Permissions Check" "active"
check_command_access "$OUTPUT_FILE" "ec2" "describe-instances" "$REGION"
check_command_access "$OUTPUT_FILE" "ssm" "describe-instance-information" "$REGION"
check_command_access "$OUTPUT_FILE" "guardduty" "list-detectors" "$REGION"
check_command_access "$OUTPUT_FILE" "inspector2" "list-findings" "$REGION"
check_command_access "$OUTPUT_FILE" "wafv2" "list-web-acls" "$REGION"
check_command_access "$OUTPUT_FILE" "configservice" "describe-config-rules" "$REGION"
check_command_access "$OUTPUT_FILE" "ssm" "list-inventory-entries" "$region" 
check_command_access "$OUTPUT_FILE" "guardduty" "list-detectors" "$region"
check_command_access "$OUTPUT_FILE" "guardduty" "get-malware-protection-plan" "$region"
check_command_access "$OUTPUT_FILE" "ssm" "describe-patch-baselines" "$region"
check_command_access "$OUTPUT_FILE" "configservice" "describe-config-rules" "$region"
check_command_access "$OUTPUT_FILE" "events" "list-rules" "$region"
check_command_access "$OUTPUT_FILE" "guardduty" "get-detector" "$region"
check_command_access "$OUTPUT_FILE" "ssm" "list-commands" "$region" 
check_command_access "$OUTPUT_FILE" "shield" "describe-subscription" "$region"
check_command_access "$OUTPUT_FILE" "shield" "list-protections" "$region"
check_command_access "$OUTPUT_FILE" "network-firewall" "list-firewalls" "$region"
close_section "$OUTPUT_FILE"

# Requirement 5.1 has been removed as requested

# Requirement 5.2: Anti-malware mechanisms and processes to protect all systems against malware are defined and implemented
add_section "$OUTPUT_FILE" "req-5.2" "Requirement 5.2: Anti-malware mechanisms and processes to protect all systems against malware are defined and implemented" "active"

# Check 5.2.1 - Anti-malware protection is deployed
echo "Checking for anti-malware protection deployment..."
am_details=$(check_ec2_antimalware "$REGION")
if [[ "$am_details" == *"class=\"red\""* ]]; then
    add_check_item "$OUTPUT_FILE" "fail" "5.2.1 - Anti-malware protection deployment" \
        "$am_details" \
        "Deploy anti-malware software on all systems commonly affected by malware, including servers, workstations, and other applicable systems."
    ((failed_checks++))
else
    add_check_item "$OUTPUT_FILE" "pass" "5.2.1 - Anti-malware protection deployment" \
        "$am_details"
    ((passed_checks++))
fi
((total_checks++))

# Check 5.2.2 - Periodic malware scans
echo "Checking for periodic malware scans..."
scan_details=$(check_periodic_scans "$REGION")
if [[ "$scan_details" == *"class=\"red\""* ]] || [[ "$scan_details" == *"class=\"yellow\""* ]]; then
    add_check_item "$OUTPUT_FILE" "warning" "5.2.2 - Periodic scans and active scanning" \
        "$scan_details" \
        "Ensure anti-malware mechanisms perform periodic scans and active or real-time scanning. Schedule automatic malware scans and configure real-time protection."
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "pass" "5.2.2 - Periodic scans and active scanning" \
        "$scan_details"
    ((passed_checks++))
fi
((total_checks++))

# Check 5.2.3 - Anti-malware updates
echo "Checking anti-malware update mechanisms..."
update_details=$(check_antimalware_updates "$REGION")
if [[ "$update_details" == *"class=\"red\""* ]] || [[ "$update_details" == *"class=\"yellow\""* ]]; then
    add_check_item "$OUTPUT_FILE" "warning" "5.2.3 - Anti-malware mechanism updates" \
        "$update_details" \
        "Ensure anti-malware mechanisms are kept current. Implement automatic updates where possible or establish manual update processes with regular verification."
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "pass" "5.2.3 - Anti-malware mechanism updates" \
        "$update_details"
    ((passed_checks++))
fi
((total_checks++))

close_section "$OUTPUT_FILE"

# Requirement 5.3: Anti-malware mechanisms and processes are active, maintained, and monitored
add_section "$OUTPUT_FILE" "req-5.3" "Requirement 5.3: Anti-malware mechanisms and processes are active, maintained, and monitored" "active"

# Check 5.3.2 - Periodic scans and active/real-time scans (previously 5.2.2)
echo "Checking for periodic malware scans..."
scan_details=$(check_periodic_scans "$REGION")
if [[ "$scan_details" == *"class=\"red\""* ]] || [[ "$scan_details" == *"class=\"yellow\""* ]]; then
    add_check_item "$OUTPUT_FILE" "warning" "5.3.2 - Periodic scans and active scanning" \
        "$scan_details" \
        "Ensure anti-malware mechanisms perform periodic scans and active or real-time scanning OR perform continuous behavioral analysis of systems or processes. Schedule automatic malware scans and configure real-time protection."
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "pass" "5.3.2 - Periodic scans and active scanning" \
        "$scan_details"
    ((passed_checks++))
fi
((total_checks++))

close_section "$OUTPUT_FILE"

# Requirement 5.4: Anti-phishing mechanisms protect users against phishing attacks
add_section "$OUTPUT_FILE" "req-5.4" "Requirement 5.4: Anti-phishing mechanisms protect users against phishing attacks" "active"

# Add a check for boundary protection, which can include anti-phishing
echo "Checking for boundary protection mechanisms..."
boundary_details=$(check_boundary_protection "$REGION")
add_check_item "$OUTPUT_FILE" "info" "5.4 - Boundary Protection" \
    "$boundary_details" \
    "Review boundary protections for potential anti-phishing capabilities in WAF, Shield, and Network Firewalls."
((total_checks++))

close_section "$OUTPUT_FILE"

# Add a separate section for CDE boundary protection (which is included in the scope of requirement 5)
add_section "$OUTPUT_FILE" "cde-boundaries" "Malware Protection at CDE Boundaries" "active"

# Check for anti-malware at system entry/exit points
echo "Checking for anti-malware at CDE boundaries..."
boundary_details=$(check_boundary_protection "$REGION")
if [[ "$boundary_details" == *"class=\"red\""* ]]; then
    add_check_item "$OUTPUT_FILE" "fail" "Malware Protection at CDE Boundaries" \
        "$boundary_details" \
        "Implement anti-malware mechanisms at system components that provide entry and exit points to/from the CDE, and at data transfer locations."
    ((failed_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "Malware Protection at CDE Boundaries" \
        "$boundary_details" \
        "Implement anti-malware mechanisms at system components that provide entry and exit points to/from the CDE, and at data transfer locations."
    ((warning_checks++))
fi
((total_checks++))

close_section "$OUTPUT_FILE"

# Requirement 5.5 and 5.6 have been removed as they require manual verification

# Finalize the report
finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"

# Open the report
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$OUTPUT_FILE"
else
    echo -e "\nReport generated: $OUTPUT_FILE"
fi

echo "Assessment completed!"
echo "Total checks: $total_checks"
echo "Passed: $passed_checks"
echo "Failed: $failed_checks"
echo "Warnings (manual verification required): $warning_checks"