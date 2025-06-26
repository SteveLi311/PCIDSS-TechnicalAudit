#!/usr/bin/env bash
# check_pci_requirement7.sh
# PCI DSS 4.0 Requirement 7 compliance check script for AWS environments
# This script assesses AWS IAM configurations for compliance with Requirement 7:
# "Restrict Access to System Components and Cardholder Data by Business Need to Know"

# Set script variables
SCRIPT_DIR="$(dirname "$0")"
REQUIREMENT_NUMBER="7"
REPORT_TITLE="PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="./reports/pci_req${REQUIREMENT_NUMBER}_report_${TIMESTAMP}.html"
# Use the AWS CLI configured region by default
REGION=$(aws configure get region)
if [ -z "$REGION" ]; then
    REGION="us-east-1"
fi

# Stats counters
total_checks=0
passed_checks=0
failed_checks=0
warning_checks=0
info_checks=0

# Source the HTML report library
source "$SCRIPT_DIR/pci_html_report_lib.sh"

# Function to check if a command is available
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to run a command with timeout (macOS compatible)
run_with_timeout() {
    local timeout_sec="$1"
    shift
    
    # On macOS, timeout command isn't available by default
    # Try using perl as a fallback
    (
        # Set a trap to kill the process after the timeout
        perl -e "alarm $timeout_sec; exec @ARGV" "$@" 2>&1
    ) & pid=$!
    
    # Wait for the process to finish or timeout
    wait $pid 2>/dev/null
    local exitcode=$?
    
    # Exit code 142 typically indicates the process was killed by alarm
    if [ $exitcode -eq 142 ] || [ $exitcode -eq 137 ] || [ $exitcode -eq 124 ]; then
        echo "TIMEOUT_ERROR"
        return 124
    fi
    
    return $exitcode
}

# Function to check AWS resources
check_aws_resource_existence() {
    local resource_type="$1"
    local region="$2"
    local command="$3"
    local output
    
    output=$(aws $resource_type $command --region $region 2>&1)
    if [[ $? -eq 0 && -n "$output" && "$output" != "[]" && "$output" != "{}" ]]; then
        return 0  # Resources exist
    else
        return 1  # No resources or error
    fi
}

# Function to check policies with full admin permissions
check_admin_policies() {
    local region="$1"
    local details=""
    local found_admin_policies=false
    
    echo -e "\nChecking for IAM policies with administrative privileges..."
    
    # Get all policies with admin privileges
    admin_policies=$(aws iam list-policies --region $region --scope Local --output json 2>/dev/null)
    
    details+="<p>Analysis of IAM policies with administrative privileges:</p>"
    
    # Check if admin_policies is valid JSON
    if ! echo "$admin_policies" | jq . >/dev/null 2>&1; then
        details+="<p class='red'>Error retrieving IAM policies. Check IAM permissions.</p>"
        return 0
    fi
    
    # Loop through each policy
    for policy_arn in $(echo "$admin_policies" | jq -r '.Policies[].Arn' 2>/dev/null || echo ""); do
        # Skip if policy_arn is empty (error in jq)
        [ -z "$policy_arn" ] && continue
        
        policy_name=$(echo "$admin_policies" | jq -r ".Policies[] | select(.Arn==\"$policy_arn\") | .PolicyName")
        
        # Get policy details
        policy_details=$(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy' --output json 2>/dev/null)
        policy_version=$(echo "$policy_details" | jq -r '.DefaultVersionId')
        
        # Get policy document
        policy_doc=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$policy_version" --query 'PolicyVersion.Document' --output json 2>/dev/null)
        
        # Check for wildcards or admin permissions
        if [[ $(echo "$policy_doc" | jq -r '.Statement[].Action' 2>/dev/null) == *"*"* || 
              $(echo "$policy_doc" | jq -r '.Statement[].Effect' 2>/dev/null) == *"Allow"* && 
              $(echo "$policy_doc" | jq -r '.Statement[].Resource' 2>/dev/null) == *"*"* ]]; then
            
            # Add details about this policy
            details+="<div style='margin-bottom: 15px; padding: 10px; border-left: 3px solid #f44336;'>"
            details+="<strong>Policy Name:</strong> $policy_name<br>"
            details+="<strong>Policy ARN:</strong> $policy_arn<br>"
            details+="<strong>Issue:</strong> This policy contains wildcard permissions or administrative access<br>"
            details+="<strong>Policy Document:</strong><br>"
            details+="<pre style='background-color: #f5f5f5; padding: 10px; overflow: auto;'>"
            details+="$(echo "$policy_doc" | jq -r '.' | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g')"
            details+="</pre>"
            details+="</div>"
            
            found_admin_policies=true
        fi
    done
    
    if [ "$found_admin_policies" = false ]; then
        details="<p class='green'>No policies with full administrative privileges or overly permissive wildcards were detected.</p>"
    fi
    
    echo "$details"
}

# Function to check IAM roles with suspicious trust relationships
check_suspicious_trust_relationships() {
    local region="$1"
    local details=""
    local suspicious_found=false
    
    echo -e "\nChecking for IAM roles with suspicious trust relationships..."
    
    # Get all roles
    roles=$(aws iam list-roles --region $region --query 'Roles[*].[RoleName,Arn]' --output json 2>/dev/null)
    
    # Check if roles is valid JSON
    if ! echo "$roles" | jq . >/dev/null 2>&1; then
        details+="<p class='red'>Error retrieving IAM roles. Check IAM permissions.</p>"
        return "$details"
    fi
    
    details+="<p>Analysis of IAM roles trust relationships:</p>"
    
    # Loop through each role safely
    for role_info in $(echo "$roles" | jq -c '.[]' 2>/dev/null || echo ""); do
        # Skip if role_info is empty or invalid
        [ -z "$role_info" ] && continue
        
        # Extract role name and ARN safely
        role_name=$(echo "$role_info" | jq -r '.[0]' 2>/dev/null)
        role_arn=$(echo "$role_info" | jq -r '.[1]' 2>/dev/null)
        
        # Skip if role_name or role_arn couldn't be extracted
        [ -z "$role_name" ] || [ -z "$role_arn" ] && continue
        
        # Skip AWS service roles
        if [[ "$role_name" == *"service-role"* || "$role_name" == *"AWSServiceRole"* ]]; then
            continue
        fi
        
        # Get role details
        role_details=$(aws iam get-role --role-name "$role_name" --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null)
        
        # Check for suspicious trust relationships (public access, wildcards)
        if [[ $(echo "$role_details" | jq -r '.Statement[].Principal.AWS' 2>/dev/null) == *"*"* || 
              $(echo "$role_details" | jq -r '.Statement[].Principal' 2>/dev/null) == *"\"*\""* ]]; then
            
            # Add details about this role
            details+="<div style='margin-bottom: 15px; padding: 10px; border-left: 3px solid #f44336;'>"
            details+="<strong>Role Name:</strong> $role_name<br>"
            details+="<strong>Role ARN:</strong> $role_arn<br>"
            details+="<strong>Issue:</strong> This role has a suspicious trust relationship that may allow anyone to assume the role<br>"
            details+="<strong>Trust Relationship:</strong><br>"
            details+="<pre style='background-color: #f5f5f5; padding: 10px; overflow: auto;'>"
            details+="$(echo "$role_details" | jq -r '.' | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g')"
            details+="</pre>"
            details+="</div>"
            
            suspicious_found=true
        fi
    done
    
    if [ "$suspicious_found" = false ]; then
        details="<p class='green'>No IAM roles with suspicious trust relationships were detected.</p>"
    fi
    
    echo "$details"
}

# Function to check inactive IAM users
check_inactive_users() {
    local region="$1"
    local details=""
    local inactive_found=false
    local threshold_days=90
    
    echo -e "\nChecking for inactive IAM users..."
    
    # Get all users
    users=$(aws iam list-users --region $region --query 'Users[*].[UserName,Arn,CreateDate,PasswordLastUsed]' --output json 2>/dev/null)
    
    # Check if users is valid JSON
    if ! echo "$users" | jq . >/dev/null 2>&1; then
        details+="<p class='red'>Error retrieving IAM users. Check IAM permissions.</p>"
        return "$details"
    fi
    
    details+="<p>Analysis of inactive IAM users (no login for more than $threshold_days days):</p>"
    details+="<table style='width: 100%; border-collapse: collapse; margin-bottom: 15px;'>"
    details+="<tr style='background-color: #f0f0f0;'>"
    details+="<th style='padding: 8px; border: 1px solid #ddd; text-align: left;'>User Name</th>"
    details+="<th style='padding: 8px; border: 1px solid #ddd; text-align: left;'>Last Activity</th>"
    details+="<th style='padding: 8px; border: 1px solid #ddd; text-align: left;'>Days Inactive</th>"
    details+="<th style='padding: 8px; border: 1px solid #ddd; text-align: left;'>Access Keys</th>"
    details+="</tr>"
    
    current_time=$(date +%s)
    
    # Loop through each user safely
    for user_info in $(echo "$users" | jq -c '.[]' 2>/dev/null || echo ""); do
        # Skip if user_info is empty
        [ -z "$user_info" ] && continue
        
        # Extract user data safely
        user_name=$(echo "$user_info" | jq -r '.[0]' 2>/dev/null)
        last_used=$(echo "$user_info" | jq -r '.[3] // "null"' 2>/dev/null)
        create_date=$(echo "$user_info" | jq -r '.[2]' 2>/dev/null)
        
        # Skip if we couldn't get the user name
        [ -z "$user_name" ] && continue
        
        # Get access key info
        access_keys=$(aws iam list-access-keys --user-name "$user_name" --query 'AccessKeyMetadata[*].[AccessKeyId,Status,CreateDate]' --output json 2>/dev/null)
        
        # Determine last activity date (either password or access key)
        if [ "$last_used" = "null" ]; then
            # If no password login, use creation date
            last_activity="$create_date"
            last_activity_type="Created (never logged in)"
        else
            last_activity="$last_used"
            last_activity_type="Last login"
        fi
        
        # Check access keys for last use
        for key_info in $(echo "$access_keys" | jq -c '.[]' 2>/dev/null); do
            key_id=$(echo "$key_info" | jq -r '.[0]')
            key_status=$(echo "$key_info" | jq -r '.[1]')
            
            if [ "$key_status" = "Active" ]; then
                # Get last used info for key
                key_last_used=$(aws iam get-access-key-last-used --access-key-id "$key_id" --query 'AccessKeyLastUsed.LastUsedDate' --output text 2>/dev/null)
                
                if [ "$key_last_used" != "None" ] && [ "$key_last_used" != "null" ]; then
                    # Compare with current last activity
                    key_last_used_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%S+00:00" "${key_last_used}" "+%s" 2>/dev/null || date -d "${key_last_used}" "+%s" 2>/dev/null)
                    last_activity_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%S+00:00" "${last_activity}" "+%s" 2>/dev/null || date -d "${last_activity}" "+%s" 2>/dev/null)
                    
                    if [ "$key_last_used_epoch" -gt "$last_activity_epoch" ]; then
                        last_activity="$key_last_used"
                        last_activity_type="Access Key ($key_id) last used"
                    fi
                fi
            fi
        done
        
        # Calculate days inactive
        last_activity_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%S+00:00" "${last_activity}" "+%s" 2>/dev/null || date -d "${last_activity}" "+%s" 2>/dev/null)
        days_inactive=$(( (current_time - last_activity_epoch) / 86400 ))
        
        # Format key information
        key_info_formatted=""
        for key_info in $(echo "$access_keys" | jq -c '.[]' 2>/dev/null); do
            key_id=$(echo "$key_info" | jq -r '.[0]')
            key_status=$(echo "$key_info" | jq -r '.[1]')
            key_info_formatted+="$key_id ($key_status)<br>"
        done
        
        # If no keys
        if [ -z "$key_info_formatted" ]; then
            key_info_formatted="No access keys"
        fi
        
        # If inactive for more than threshold
        if [ "$days_inactive" -gt "$threshold_days" ]; then
            inactive_found=true
            
            # Add row with red highlight
            details+="<tr style='background-color: #ffebee;'>"
            details+="<td style='padding: 8px; border: 1px solid #ddd;'>$user_name</td>"
            details+="<td style='padding: 8px; border: 1px solid #ddd;'>$last_activity_type: $last_activity</td>"
            details+="<td style='padding: 8px; border: 1px solid #ddd;'>$days_inactive</td>"
            details+="<td style='padding: 8px; border: 1px solid #ddd;'>$key_info_formatted</td>"
            details+="</tr>"
        fi
    done
    
    details+="</table>"
    
    if [ "$inactive_found" = false ]; then
        details="<p class='green'>No IAM users inactive for more than $threshold_days days were detected.</p>"
    fi
    
    echo "$details"
}

# Function to check direct policy attachments to users
check_direct_user_policies() {
    local region="$1"
    local details=""
    local direct_policies_found=false
    
    echo -e "\nChecking for direct policy attachments to IAM users..."
    
    # Get all users
    users=$(aws iam list-users --region $region --query 'Users[*].[UserName,Arn]' --output json 2>/dev/null)
    
    details+="<p>Analysis of IAM users with direct policy attachments:</p>"
    details+="<ul>"
    
    # Loop through each user
    for user_info in $(echo "$users" | jq -c '.[]'); do
        user_name=$(echo "$user_info" | jq -r '.[0]')
        user_arn=$(echo "$user_info" | jq -r '.[1]')
        
        # Check for attached policies
        attached_policies=$(aws iam list-attached-user-policies --user-name "$user_name" --query 'AttachedPolicies[*].[PolicyName,PolicyArn]' --output json 2>/dev/null)
        
        # Check for inline policies
        inline_policies=$(aws iam list-user-policies --user-name "$user_name" --query 'PolicyNames' --output json 2>/dev/null)
        
        # If either attached or inline policies exist
        # Make sure JSON is valid before parsing
        if ! echo "$attached_policies" | jq -e . >/dev/null 2>&1; then
            attached_policies="[]"
        fi
        if ! echo "$inline_policies" | jq -e . >/dev/null 2>&1; then
            inline_policies="[]"
        fi
        
        # Get counts with fallback to 0 for invalid values
        attached_count=$(echo "$attached_policies" | jq -e 'length' 2>/dev/null || echo "0")
        inline_count=$(echo "$inline_policies" | jq -e 'length' 2>/dev/null || echo "0")
        
        # Ensure counts are valid integers
        if ! [[ "$attached_count" =~ ^[0-9]+$ ]]; then
            attached_count=0
        fi
        if ! [[ "$inline_count" =~ ^[0-9]+$ ]]; then
            inline_count=0
        fi
        
        if [ "$attached_count" -gt 0 ] || [ "$inline_count" -gt 0 ]; then
            direct_policies_found=true
            
            details+="<li style='margin-bottom: 15px;'>"
            details+="<strong>User:</strong> $user_name ($user_arn)<br>"
            
            # List attached policies
            if [ "$attached_count" -gt 0 ]; then
                details+="<strong>Attached Policies:</strong><ul>"
                for policy in $(echo "$attached_policies" | jq -c '.[]'); do
                    policy_name=$(echo "$policy" | jq -r '.[0]')
                    policy_arn=$(echo "$policy" | jq -r '.[1]')
                    details+="<li>$policy_name ($policy_arn)</li>"
                done
                details+="</ul>"
            fi
            
            # List inline policies
            if [ "$inline_count" -gt 0 ]; then
                details+="<strong>Inline Policies:</strong><ul>"
                for policy_name in $(echo "$inline_policies" | jq -r '.[]'); do
                    policy_doc=$(aws iam get-user-policy --user-name "$user_name" --policy-name "$policy_name" --query 'PolicyDocument' --output json 2>/dev/null)
                    
                    details+="<li>$policy_name<br>"
                    details+="<details>"
                    details+="<summary>View Policy JSON</summary>"
                    details+="<pre style='background-color: #f5f5f5; padding: 10px; overflow: auto;'>"
                    details+="$(echo "$policy_doc" | jq -r '.' | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g')"
                    details+="</pre>"
                    details+="</details>"
                    details+="</li>"
                done
                details+="</ul>"
            fi
            
            details+="</li>"
        fi
    done
    
    details+="</ul>"
    
    if [ "$direct_policies_found" = false ]; then
        details="<p class='green'>No IAM users with direct policy attachments were detected. This is a good practice - using groups for policy management is preferred.</p>"
    else
        details+="<p class='yellow'><strong>Note:</strong> Direct policy attachments to users can make access management more difficult. Consider using IAM groups for policy management instead.</p>"
    fi
    
    echo "$details"
}

# Function to check if permission boundaries are used
check_permission_boundaries() {
    local region="$1"
    local details=""
    local boundaries_used=false
    
    echo -e "\nChecking for permission boundary usage..."
    
    # Check if any permission boundary policy exists - use safer query
    boundary_policies=$(aws iam list-policies --region $region --scope Local --output json 2>/dev/null)
    
    # Check if boundary_policies is valid JSON
    if ! echo "$boundary_policies" | jq . >/dev/null 2>&1; then
        details+="<p class='red'>Error retrieving IAM policies for permission boundaries. Check IAM permissions.</p>"
        return "$details"
    fi
    
    # Filter for boundary policies using jq instead of AWS query
    # Make sure output is valid JSON with echo empty JSON as fallback
    boundary_policies=$(echo "$boundary_policies" | jq -e '.Policies[] | select(.PolicyName=="Boundary")' 2>/dev/null || echo "{}")
    
    # Check if boundary_policies is valid JSON
    if ! echo "$boundary_policies" | jq -e . >/dev/null 2>&1; then
        boundary_policies="{}"
    fi
    
    # Count policies - default to 0 if parsing fails
    boundary_count=0
    if [[ -n "$boundary_policies" && "$boundary_policies" != "{}" ]]; then
        boundary_count=1
    fi
    
    if [ "$boundary_count" -gt 0 ]; then
        boundaries_used=true
        details+="<p class='green'>Permission boundary policies are defined in the AWS account.</p>"
        
        # List the boundary policies (with safeguards against parsing errors)
        details+="<p>Boundary policies configured:</p><ul>"
        # Only try to parse if it has Policies array
        if echo "$boundary_policies" | jq -e '.Policies' >/dev/null 2>&1; then
            for policy in $(echo "$boundary_policies" | jq -e -c '.Policies[]' 2>/dev/null || echo "{}"); do
                # Skip invalid JSON
                if ! echo "$policy" | jq -e . >/dev/null 2>&1; then
                    continue
                fi
                policy_name=$(echo "$policy" | jq -r '.PolicyName // "Unknown"')
                policy_arn=$(echo "$policy" | jq -r '.Arn // "Unknown"')
                details+="<li>$policy_name ($policy_arn)</li>"
            done
        else
            # Just add the policy we found
            policy_name=$(echo "$boundary_policies" | jq -r '.PolicyName // "Boundary Policy"')
            policy_arn=$(echo "$boundary_policies" | jq -r '.Arn // "Unknown ARN"')
            details+="<li>$policy_name ($policy_arn)</li>"
        fi
        details+="</ul>"
    else
        details+="<p class='yellow'>No permission boundary policies were detected in the AWS account.</p>"
        details+="<p>Permission boundaries are an important feature for limiting maximum permissions that can be granted, even if policies attached to a user or role have broader permissions. This is especially important for delegated administration.</p>"
    fi
    
    # Check if any roles or users have boundaries attached
    roles_with_boundaries=0
    users_with_boundaries=0
    
    # Check roles
    roles=$(aws iam list-roles --region $region --query 'Roles[*].RoleName' --output json 2>/dev/null)
    for role_name in $(echo "$roles" | jq -r '.[]'); do
        role_details=$(aws iam get-role --role-name "$role_name" --query 'Role.PermissionsBoundary.PermissionsBoundaryArn' --output text 2>/dev/null)
        if [ "$role_details" != "None" ] && [ -n "$role_details" ]; then
            boundaries_used=true
            ((roles_with_boundaries++))
        fi
    done
    
    # Check users
    users=$(aws iam list-users --region $region --query 'Users[*].UserName' --output json 2>/dev/null)
    for user_name in $(echo "$users" | jq -r '.[]'); do
        user_details=$(aws iam get-user --user-name "$user_name" --query 'User.PermissionsBoundary.PermissionsBoundaryArn' --output text 2>/dev/null)
        if [ "$user_details" != "None" ] && [ -n "$user_details" ]; then
            boundaries_used=true
            ((users_with_boundaries++))
        fi
    done
    
    # Add stats about boundary usage
    if [ "$boundaries_used" = true ]; then
        details+="<p><strong>Permission Boundary Usage:</strong></p>"
        details+="<ul>"
        details+="<li>Roles with permission boundaries: $roles_with_boundaries</li>"
        details+="<li>Users with permission boundaries: $users_with_boundaries</li>"
        details+="</ul>"
    fi
    
    echo "$details"
}

# Function to check if access is reviewed
check_access_reviews() {
    local region="$1"
    local details=""
    
    echo -e "\nChecking for evidence of access reviews..."
    
    # Check if AWS CloudTrail has events related to IAM access review
    # First, get trail names
    trails=$(aws cloudtrail list-trails --region $region --query 'Trails[*].Name' --output json 2>/dev/null)
    
    # Check if trails is valid JSON
    if ! echo "$trails" | jq . >/dev/null 2>&1; then
        details+="<p class='yellow'>Error retrieving CloudTrail trails. Check CloudTrail permissions.</p>"
        details+="<p>CloudTrail access is required to verify if regular access reviews are performed.</p>"
        # Continue with Access Analyzer check
    elif [ -z "$trails" ] || [ "$trails" = "[]" ]; then
        details+="<p class='yellow'>No CloudTrail trails found. Unable to verify if access reviews are performed.</p>"
        details+="<p>AWS CloudTrail should be enabled to track user activity and administrative actions.</p>"
    else
        # Check for access review related events in last 180 days
        access_review_found=false
        review_events=0
        
        for trail_name in $(echo "$trails" | jq -r '.[]' 2>/dev/null || echo ""); do
            # Skip if trail_name is empty
            [ -z "$trail_name" ] && continue
            
            # Look for IAM access review related events (policy attachments/detachments, user creation/deletion)
            # Set start time to 180 days ago
            start_time=$(date -v-180d "+%Y-%m-%dT%H:%M:%S" 2>/dev/null || date -d "180 days ago" "+%Y-%m-%dT%H:%M:%S" 2>/dev/null)
            
            # CloudTrail LookupEvents is limited, so we check for specific IAM actions that might indicate a review
            # Use try/catch approach to handle potential permission issues with timeout to prevent hanging
            echo -e "Checking CloudTrail events for DeleteUserPolicy..."
            events=$(run_with_timeout 10 aws cloudtrail lookup-events --region $region --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteUserPolicy --start-time "$start_time" --max-results 10 2>/dev/null || echo "{\"Events\":[]}")
            
            # Check for timeout
            if [ "$events" = "TIMEOUT_ERROR" ]; then
                echo "CloudTrail lookup-events timed out, continuing..."
                events="{\"Events\":[]}"
            fi
            
            # Ensure events is valid JSON
            if ! echo "$events" | jq -e . >/dev/null 2>&1; then
                echo "CloudTrail returned invalid JSON, using empty results..."
                events="{\"Events\":[]}"
            fi
            
            # Process events
            event_count=$(echo "$events" | jq -e '.Events | length' 2>/dev/null || echo "0")
            if ! [[ "$event_count" =~ ^[0-9]+$ ]]; then
                event_count=0
            fi
            
            if [ "$event_count" -gt 0 ]; then
                access_review_found=true
                ((review_events += event_count))
            fi
            
            # Try for DetachUserPolicy with timeout to prevent hanging
            echo -e "Checking CloudTrail events for DetachUserPolicy..."
            events=$(run_with_timeout 10 aws cloudtrail lookup-events --region $region --lookup-attributes AttributeKey=EventName,AttributeValue=DetachUserPolicy --start-time "$start_time" --max-results 10 2>/dev/null || echo "{\"Events\":[]}")
            
            # Check for timeout
            if [ "$events" = "TIMEOUT_ERROR" ]; then
                echo "CloudTrail lookup-events timed out, continuing..."
                events="{\"Events\":[]}"
            fi
            
            # Ensure events is valid JSON
            if ! echo "$events" | jq -e . >/dev/null 2>&1; then
                echo "CloudTrail returned invalid JSON, using empty results..."
                events="{\"Events\":[]}"
            fi
            
            # Process events
            event_count=$(echo "$events" | jq -e '.Events | length' 2>/dev/null || echo "0")
            if ! [[ "$event_count" =~ ^[0-9]+$ ]]; then
                event_count=0
            fi
            
            if [ "$event_count" -gt 0 ]; then
                access_review_found=true
                ((review_events += event_count))
            fi
            
            # Try for DetachRolePolicy with timeout to prevent hanging
            echo -e "Checking CloudTrail events for DetachRolePolicy..."
            events=$(run_with_timeout 10 aws cloudtrail lookup-events --region $region --lookup-attributes AttributeKey=EventName,AttributeValue=DetachRolePolicy --start-time "$start_time" --max-results 10 2>/dev/null || echo "{\"Events\":[]}")
            
            # Check for timeout
            if [ "$events" = "TIMEOUT_ERROR" ]; then
                echo "CloudTrail lookup-events timed out, continuing..."
                events="{\"Events\":[]}"
            fi
            
            # Ensure events is valid JSON
            if ! echo "$events" | jq -e . >/dev/null 2>&1; then
                echo "CloudTrail returned invalid JSON, using empty results..."
                events="{\"Events\":[]}"
            fi
            
            # Process events
            event_count=$(echo "$events" | jq -e '.Events | length' 2>/dev/null || echo "0")
            if ! [[ "$event_count" =~ ^[0-9]+$ ]]; then
                event_count=0
            fi
            
            if [ "$event_count" -gt 0 ]; then
                access_review_found=true
                ((review_events += event_count))
            fi
        done
        
        if [ "$access_review_found" = true ]; then
            details+="<p class='green'>Evidence of possible access reviews found in CloudTrail events.</p>"
            details+="<p>Detected $review_events events related to policy changes in the last 180 days, which may indicate access reviews are being performed.</p>"
        else
            details+="<p class='yellow'>No clear evidence of access reviews found in CloudTrail events in the last 180 days.</p>"
            details+="<p>PCI DSS requires that all user accounts and related access privileges be reviewed at least once every six months.</p>"
        fi
    fi
    
    # Check if AWS Access Analyzer is enabled
    access_analyzers=$(aws accessanalyzer list-analyzers --region $region --query 'analyzers[*].[name,status]' --output json 2>/dev/null)
    
    # Check if access_analyzers is valid JSON
    if ! echo "$access_analyzers" | jq . >/dev/null 2>&1; then
        details+="<p class='yellow'>Error retrieving IAM Access Analyzer information. Check permissions.</p>"
    elif [ -z "$access_analyzers" ] || [ "$access_analyzers" = "[]" ]; then
        details+="<p class='yellow'>AWS IAM Access Analyzer is not enabled.</p>"
        details+="<p>IAM Access Analyzer helps identify resources that are shared with external entities and can be used as part of the access review process.</p>"
    else
        active_analyzers=0
        for analyzer in $(echo "$access_analyzers" | jq -c '.[]' 2>/dev/null || echo ""); do
            # Skip if analyzer is empty
            [ -z "$analyzer" ] && continue
            
            status=$(echo "$analyzer" | jq -r '.[1]' 2>/dev/null)
            if [ "$status" = "ACTIVE" ]; then
                ((active_analyzers++))
            fi
        done
        
        if [ "$active_analyzers" -gt 0 ]; then
            details+="<p class='green'>AWS IAM Access Analyzer is enabled and active.</p>"
            details+="<p>IAM Access Analyzer helps identify resources that are shared with external entities and can support regular access reviews.</p>"
        else
            details+="<p class='yellow'>AWS IAM Access Analyzer is configured but not active.</p>"
            details+="<p>Ensure Access Analyzer is properly configured and active to support access reviews.</p>"
        fi
    fi
    
    echo "$details"
}

# Function to check default-deny in ACLs
check_default_deny() {
    local region="$1"
    local details=""
    local issues_found=false
    
    echo -e "\nChecking for default-deny configuration in security groups..."
    
    # Get all VPCs
    vpcs=$(aws ec2 describe-vpcs --region $region --query 'Vpcs[*].[VpcId,Tags]' --output json 2>/dev/null)
    
    details+="<p>Analysis of default Security Group configurations:</p>"
    details+="<ul>"
    
    # Check the default security group for each VPC
    for vpc_info in $(echo "$vpcs" | jq -c '.[]'); do
        vpc_id=$(echo "$vpc_info" | jq -r '.[0]')
        
        # Get the default security group
        default_sg=$(aws ec2 describe-security-groups --region $region --filters "Name=vpc-id,Values=$vpc_id" "Name=group-name,Values=default" --query 'SecurityGroups[0]' --output json 2>/dev/null)
        
        if [ -n "$default_sg" ] && [ "$default_sg" != "null" ]; then
            sg_id=$(echo "$default_sg" | jq -r '.GroupId')
            
            # Check inbound rules
            inbound_rules=$(echo "$default_sg" | jq -r '.IpPermissions | length')
            
            # Check outbound rules
            outbound_rules=$(echo "$default_sg" | jq -r '.IpPermissionsEgress | length')
            
            details+="<li>VPC: $vpc_id - Default Security Group: $sg_id<br>"
            
            if [ "$inbound_rules" -gt 0 ]; then
                issues_found=true
                details+="<span class='red'>⚠️ Default security group has $inbound_rules inbound rules. Default security groups should have no inbound rules.</span><br>"
                
                # Show the inbound rules
                details+="<strong>Inbound Rules:</strong><ul>"
                for rule in $(echo "$default_sg" | jq -c '.IpPermissions[]'); do
                    from_port=$(echo "$rule" | jq -r '.FromPort // "All"')
                    to_port=$(echo "$rule" | jq -r '.ToPort // "All"')
                    protocol=$(echo "$rule" | jq -r '.IpProtocol')
                    
                    if [ "$protocol" = "-1" ]; then
                        protocol="All"
                    fi
                    
                    cidr_ranges=""
                    for cidr in $(echo "$rule" | jq -c '.IpRanges[]' 2>/dev/null); do
                        cidr_ip=$(echo "$cidr" | jq -r '.CidrIp')
                        cidr_ranges+="$cidr_ip, "
                    done
                    
                    if [ -n "$cidr_ranges" ]; then
                        cidr_ranges=${cidr_ranges%, }
                        details+="<li>Protocol: $protocol, Ports: $from_port-$to_port, Source: $cidr_ranges</li>"
                    fi
                    
                    # Check for security group sources
                    sg_sources=""
                    for sg_source in $(echo "$rule" | jq -c '.UserIdGroupPairs[]' 2>/dev/null); do
                        source_sg=$(echo "$sg_source" | jq -r '.GroupId')
                        sg_sources+="$source_sg, "
                    done
                    
                    if [ -n "$sg_sources" ]; then
                        sg_sources=${sg_sources%, }
                        details+="<li>Protocol: $protocol, Ports: $from_port-$to_port, Source Security Groups: $sg_sources</li>"
                    fi
                done
                details+="</ul>"
            else
                details+="<span class='green'>✓ Default security group has no inbound rules (good configuration).</span><br>"
            fi
            
            # Report on outbound rules - in a strict default-deny, outbound should also be restricted
            if [ "$outbound_rules" -gt 0 ]; then
                # Check if it's just the default "allow all outbound" rule
                if [ "$outbound_rules" -eq 1 ]; then
                    outbound_all=$(echo "$default_sg" | jq -r '.IpPermissionsEgress[0].IpProtocol')
                    outbound_cidr=$(echo "$default_sg" | jq -r '.IpPermissionsEgress[0].IpRanges[0].CidrIp // "none"')
                    
                    if [ "$outbound_all" = "-1" ] && [ "$outbound_cidr" = "0.0.0.0/0" ]; then
                        details+="<span class='yellow'>⚠️ Default security group allows all outbound traffic. For stricter security, consider limiting outbound traffic as well.</span>"
                    else
                        details+="<span class='green'>✓ Default security group has restricted outbound rules.</span>"
                    fi
                else
                    details+="<span class='green'>✓ Default security group has custom outbound rules.</span>"
                fi
            else
                details+="<span class='green'>✓ Default security group has no outbound rules (most restrictive configuration).</span>"
            fi
            
            details+="</li>"
        fi
    done
    
    details+="</ul>"
    
    # Check NACLs for default deny
    details+="<p>Analysis of Network ACL configurations:</p>"
    details+="<ul>"
    
    # Get all NACLs
    nacls=$(aws ec2 describe-network-acls --region $region --query 'NetworkAcls[*]' --output json 2>/dev/null)
    
    for nacl in $(echo "$nacls" | jq -c '.[]'); do
        nacl_id=$(echo "$nacl" | jq -r '.NetworkAclId')
        vpc_id=$(echo "$nacl" | jq -r '.VpcId')
        is_default=$(echo "$nacl" | jq -r '.IsDefault')
        
        details+="<li>NACL: $nacl_id - VPC: $vpc_id (Default: $is_default)<br>"
        
        # Check for a deny all rule at the end of inbound rules
        inbound_entries=$(echo "$nacl" | jq -r '.Entries | map(select(.Egress == false)) | sort_by(.RuleNumber)')
        highest_rule=$(echo "$inbound_entries" | jq -r '.[-1].RuleNumber')
        highest_action=$(echo "$inbound_entries" | jq -r '.[-1].RuleAction')
        
        if [ "$highest_rule" = "32767" ] && [ "$highest_action" = "deny" ]; then
            details+="<span class='green'>✓ Inbound NACL has a default deny rule (Rule #32767).</span><br>"
        else
            issues_found=true
            details+="<span class='red'>⚠️ Inbound NACL does not end with a default deny rule.</span><br>"
        fi
        
        # Check for a deny all rule at the end of outbound rules
        outbound_entries=$(echo "$nacl" | jq -r '.Entries | map(select(.Egress == true)) | sort_by(.RuleNumber)')
        highest_rule=$(echo "$outbound_entries" | jq -r '.[-1].RuleNumber')
        highest_action=$(echo "$outbound_entries" | jq -r '.[-1].RuleAction')
        
        if [ "$highest_rule" = "32767" ] && [ "$highest_action" = "deny" ]; then
            details+="<span class='green'>✓ Outbound NACL has a default deny rule (Rule #32767).</span>"
        else
            issues_found=true
            details+="<span class='red'>⚠️ Outbound NACL does not end with a default deny rule.</span>"
        fi
        
        details+="</li>"
    done
    
    details+="</ul>"
    
    if [ "$issues_found" = false ]; then
        details+="<p class='green'>All security controls follow default-deny principles, which is an excellent security practice.</p>"
    fi
    
    echo "$details"
}

# Function to check for appropriate least privilege setup
check_least_privilege() {
    local region="$1"
    local details=""
    local violations_found=false
    
    echo -e "\nChecking for least privilege principles in IAM policies..."
    
    # Get customer managed policies
    managed_policies=$(aws iam list-policies --region $region --scope Local --query 'Policies[*].[PolicyName,Arn,DefaultVersionId]' --output json 2>/dev/null)
    
    # Check if managed_policies is valid JSON
    if ! echo "$managed_policies" | jq . >/dev/null 2>&1; then
        details+="<p class='red'>Error retrieving IAM policies. Check IAM permissions.</p>"
        return "$details"
    fi
    
    details+="<p>Analysis of IAM policies for least privilege violations:</p>"
    details+="<ul>"
    
    # Check each policy for overly permissive statements
    for policy_info in $(echo "$managed_policies" | jq -c '.[]'); do
        policy_name=$(echo "$policy_info" | jq -r '.[0]')
        policy_arn=$(echo "$policy_info" | jq -r '.[1]')
        policy_version=$(echo "$policy_info" | jq -r '.[2]')
        
        # Get policy document
        policy_doc=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$policy_version" --query 'PolicyVersion.Document' --output json 2>/dev/null)
        
        # Patterns that violate least privilege
        violations=0
        violation_details=""
        
        # Check for Action: "*"
        if [[ $(echo "$policy_doc" | jq -r '.Statement[].Action' 2>/dev/null) == "*" || 
              $(echo "$policy_doc" | jq -r '.Statement[].Action[]' 2>/dev/null) == "*" ]]; then
            ((violations++))
            violation_details+="<li>Policy allows all actions ('Action': '*')</li>"
        fi
        
        # Check for Resource: "*" combined with broad Action
        broad_actions_with_all_resources=false
        for statement in $(echo "$policy_doc" | jq -c '.Statement[]' 2>/dev/null); do
            action=$(echo "$statement" | jq -r '.Action // .Action[]' 2>/dev/null)
            resource=$(echo "$statement" | jq -r '.Resource // .Resource[]' 2>/dev/null)
            effect=$(echo "$statement" | jq -r '.Effect' 2>/dev/null)
            
            if [ "$effect" = "Allow" ] && [ "$resource" = "*" ]; then
                if [[ "$action" == "*" || "$action" == *":*" ]]; then
                    broad_actions_with_all_resources=true
                    violation_details+="<li>Policy allows broad actions ('$action') on all resources ('Resource': '*')</li>"
                    ((violations++))
                fi
            fi
        done
        
        # Only add to the details if violations are found
        if [ "$violations" -gt 0 ]; then
            violations_found=true
            
            details+="<li style='margin-bottom: 15px;'>"
            details+="<strong>Policy:</strong> $policy_name ($policy_arn)<br>"
            details+="<strong>Violations:</strong> $violations<br>"
            details+="<ul>$violation_details</ul>"
            details+="<details>"
            details+="<summary>View Policy JSON</summary>"
            details+="<pre style='background-color: #f5f5f5; padding: 10px; overflow: auto;'>"
            details+="$(echo "$policy_doc" | jq -r '.' | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g')"
            details+="</pre>"
            details+="</details>"
            details+="</li>"
        fi
    done
    
    details+="</ul>"
    
    if [ "$violations_found" = false ]; then
        details="<p class='green'>No major least privilege violations detected in customer managed policies.</p>"
        details+="<p>Note: This check only examines customer managed policies for obvious violations. You should also review AWS managed policies and inline policies.</p>"
    else
        details+="<p class='yellow'>Note: This check detects obvious violations of least privilege principles. A complete review should include all policies including inline and AWS managed policies.</p>"
    fi
    
    echo "$details"
}

# Main function
main() {
    # Check if required commands are available
    for cmd in aws jq perl; do
        if ! command_exists "$cmd"; then
            echo "Error: Required command '$cmd' is not installed or not in the PATH."
            exit 1
        fi
    done
    
    # Use the region already set from AWS CLI configuration
    echo "Using AWS region: $REGION"
    
    # Create reports directory if it doesn't exist
    mkdir -p "$(dirname "$OUTPUT_FILE")"
    
    # Initialize HTML report
    initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE" "$REQUIREMENT_NUMBER" "$REGION"
    
    # Add intro section
    add_section "$OUTPUT_FILE" "intro" "Introduction" "active"
    add_check_item "$OUTPUT_FILE" "info" "PCI DSS Requirement 7" \
        "<p>Requirement 7: Restrict Access to System Components and Cardholder Data by Business Need to Know</p><p>To ensure critical data can only be accessed by authorized personnel, systems and processes must be in place to limit access based on need to know and according to job responsibilities. Need to know is when access rights are granted to only the least amount of data and privileges needed to perform a job.</p>"
    close_section "$OUTPUT_FILE"
    
    # Section for permissions check
    add_section "$OUTPUT_FILE" "permissions" "AWS API Access Check" "none"
    
    # Test AWS access and permissions
    check_command_access "$OUTPUT_FILE" "iam" "list-roles" "$REGION"
    check_command_access "$OUTPUT_FILE" "iam" "list-users" "$REGION"
    check_command_access "$OUTPUT_FILE" "iam" "list-policies" "$REGION"
    check_command_access "$OUTPUT_FILE" "iam" "list-groups" "$REGION"
    check_command_access "$OUTPUT_FILE" "ec2" "describe-security-groups" "$REGION"
    check_command_access "$OUTPUT_FILE" "ec2" "describe-network-acls" "$REGION"
    
    # Add timeout to the cloudtrail command to prevent hanging
    echo -ne "Checking access to AWS cloudtrail lookup-events... "
    output=$(run_with_timeout 10 aws cloudtrail lookup-events --region $REGION --max-results 1 --query 'Events[0]' 2>&1 || echo "ERROR")
    exit_code=$?
    
    if [ "$output" = "TIMEOUT_ERROR" ] || [ $exit_code -eq 124 ]; then
        echo -e "\033[0;33mWARNING\033[0m - Timed out (continuing without CloudTrail checks)"
        add_check_item "$OUTPUT_FILE" "warning" "AWS API Access: cloudtrail lookup-events" "The command timed out after 10 seconds. CloudTrail checks will be skipped." "Check your AWS CloudTrail configuration or network connectivity"
    elif [[ $output == *"AccessDenied"* ]] || [[ $output == *"UnauthorizedOperation"* ]] || [[ $output == *"operation: You are not authorized"* ]]; then
        echo -e "\033[0;31mFAILED\033[0m - Access Denied"
        add_check_item "$OUTPUT_FILE" "fail" "AWS API Access: cloudtrail lookup-events" "Access Denied. Your AWS account does not have permission to perform this operation." "Ensure your AWS account has read permissions for cloudtrail:lookup-events"
    elif [[ $output == *"jq: parse error"* ]] || [[ $output == *"JSON"* ]] || [[ "$output" == "ERROR" ]]; then
        echo -e "\033[0;33mWARNING\033[0m - Error parsing response (continuing without CloudTrail checks)"
        add_check_item "$OUTPUT_FILE" "warning" "AWS API Access: cloudtrail lookup-events" "Error parsing response. CloudTrail checks will be skipped." "Check your AWS CloudTrail configuration"
    else
        echo -e "\033[0;32mSUCCESS\033[0m"
        add_check_item "$OUTPUT_FILE" "pass" "AWS API Access: cloudtrail lookup-events" "Successfully verified access to this AWS API." ""
    fi
    
    check_command_access "$OUTPUT_FILE" "accessanalyzer" "list-analyzers" "$REGION"
    
    close_section "$OUTPUT_FILE"
    
    
    # Section 7.2: Access definition and assignment
    add_section "$OUTPUT_FILE" "req-7.2" "Requirement 7.2: Access to system components and data is appropriately defined and assigned" "none"
    
    
    # 7.2.2 Least privilege check
    least_privilege_details=$(check_least_privilege "$REGION")
    if [[ "$least_privilege_details" == *"No major least privilege violations"* ]]; then
        add_check_item "$OUTPUT_FILE" "pass" "7.2.2 - Least Privilege Assignment" "$least_privilege_details"
    else
        add_check_item "$OUTPUT_FILE" "fail" "7.2.2 - Least Privilege Assignment" "$least_privilege_details" \
            "Revise IAM policies to follow least privilege principles. Remove broad permissions and restrict access to only what's necessary for each role or function."
    fi
    
    
    # 7.2.4 User account reviews - handle CloudTrail access denied gracefully
    access_review_details=$(check_access_reviews "$REGION" 2>/dev/null || echo "<p class='yellow'>Unable to check for access reviews. CloudTrail access denied.</p><p>CloudTrail access is required to verify if regular access reviews are performed. Please ensure the IAM role used has appropriate permissions or manually verify that accounts are reviewed at least once every six months.</p>")
    
    if [[ "$access_review_details" == *"Evidence of possible access reviews found"* ]]; then
        add_check_item "$OUTPUT_FILE" "pass" "7.2.4 - User Account Reviews" "$access_review_details"
    else
        add_check_item "$OUTPUT_FILE" "fail" "7.2.4 - User Account Reviews" "$access_review_details" \
            "Implement a process to review all user accounts and related access privileges at least once every six months. Document these reviews and ensure management acknowledges that access remains appropriate."
    fi
    
    # 7.2.5 System account management
    # Check inactive users first as part of account management
    inactive_users_details=$(check_inactive_users "$REGION")

    if [[ "$inactive_users_details" == *"No IAM users inactive"* ]]; then
        add_check_item "$OUTPUT_FILE" "pass" "7.2.5 - System Account Management (Inactive Users)" "$inactive_users_details"
    else
        add_check_item "$OUTPUT_FILE" "fail" "7.2.5 - System Account Management (Inactive Users)" "$inactive_users_details" \
            "Remove or disable inactive user accounts. Establish a process to regularly review and disable accounts that have been inactive for more than 90 days."
    fi

    # Additional check for service accounts 
    service_roles=$(aws iam list-roles --region $REGION --query "Roles[?contains(RoleName, 'service') || contains(RoleName, 'Service')].RoleName" --output text 2>/dev/null)
    if [ -n "$service_roles" ]; then
        service_roles_html="<p>The following service/system roles were identified:</p><ul>"
        for role in $service_roles; do
            service_roles_html+="<li>$role</li>"
        done
        service_roles_html+="</ul><p>These system accounts should be reviewed to ensure they have least privilege access.</p>"
        add_check_item "$OUTPUT_FILE" "warning" "7.2.5 - System Account Management (Service Accounts)" "$service_roles_html" \
            "Review all system and service accounts to ensure they have the minimum privileges necessary for operation."
    else 
        add_check_item "$OUTPUT_FILE" "info" "7.2.5 - System Account Management (Service Accounts)" \
            "<p>No service/system roles were identified. If you use system accounts, ensure they're configured with least privilege permissions.</p>"
    fi

    
    close_section "$OUTPUT_FILE"
    
    # Section 7.3: Access Control Systems
    add_section "$OUTPUT_FILE" "req-7.3" "Requirement 7.3: Access to system components and data is managed via an access control system(s)" "none"
    
    
    # 7.3.2 Access control system configuration
    direct_policy_details=$(check_direct_user_policies "$REGION")
    
    if [[ "$direct_policy_details" == *"No IAM users with direct policy attachments were detected"* ]]; then
        add_check_item "$OUTPUT_FILE" "pass" "7.3.2 - Access Control System Configuration (Direct Policies)" "$direct_policy_details"
    else
        add_check_item "$OUTPUT_FILE" "fail" "7.3.2 - Access Control System Configuration (Direct Policies)" "$direct_policy_details" \
            "Reorganize your IAM structure to use groups for policy management instead of direct user policy attachments. This aligns with job classification and function-based access principles."
    fi
    
    # Admin policy check
    admin_policy_details=$(check_admin_policies "$REGION")
    
    if [[ "$admin_policy_details" == *"No policies with full administrative privileges"* ]]; then
        add_check_item "$OUTPUT_FILE" "pass" "7.3.2 - Access Control System Configuration (Admin Policies)" "$admin_policy_details"
    else
        add_check_item "$OUTPUT_FILE" "fail" "7.3.2 - Access Control System Configuration (Admin Policies)" "$admin_policy_details" \
            "Revise policies to limit administrative access. Replace wildcard permissions with specific permissions required for each role."
    fi
    
    # Permissions boundary check
    boundary_details=$(check_permission_boundaries "$REGION")
    
    if [[ "$boundary_details" == *"Permission boundary policies are defined"* ]]; then
        add_check_item "$OUTPUT_FILE" "pass" "7.3.2 - Access Control System Configuration (Permission Boundaries)" "$boundary_details"
    else
        add_check_item "$OUTPUT_FILE" "warning" "7.3.2 - Access Control System Configuration (Permission Boundaries)" "$boundary_details" \
            "Implement permission boundaries to set maximum permissions for IAM entities, which can help enforce your access control model."
    fi
    
    # 7.3.3 Default-deny configuration
    default_deny_details=$(check_default_deny "$REGION")
    
    if [[ "$default_deny_details" == *"issues_found"* ]]; then
        add_check_item "$OUTPUT_FILE" "fail" "7.3.3 - Default-Deny Configuration" "$default_deny_details" \
            "Configure security groups and NACLs to follow default-deny principles. Remove any permissive rules from default security groups and ensure NACLs have appropriate deny rules."
    else
        add_check_item "$OUTPUT_FILE" "pass" "7.3.3 - Default-Deny Configuration" "$default_deny_details"
    fi
    
    # Additional check for suspicious trust relationships
    trust_relationship_details=$(check_suspicious_trust_relationships "$REGION")
    
    if [[ "$trust_relationship_details" == *"No IAM roles with suspicious trust relationships"* ]]; then
        add_check_item "$OUTPUT_FILE" "pass" "Additional Check - Trust Relationships" "$trust_relationship_details"
    else
        add_check_item "$OUTPUT_FILE" "fail" "Additional Check - Trust Relationships" "$trust_relationship_details" \
            "Review and revise IAM role trust relationships that use wildcards or public access. Restrict trust relationships to specific entities that require access."
    fi
    
    close_section "$OUTPUT_FILE"
    
    # Finalize the report
    finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"
    
    # Open the report if possible
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open "$OUTPUT_FILE"
    else
        echo -e "\nReport generated: $OUTPUT_FILE"
    fi
}

# Call the main function
main
