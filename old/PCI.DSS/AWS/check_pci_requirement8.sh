#!/bin/bash
#
# PCI DSS v4.0.1 Requirement 8 Compliance Check Script for AWS
# Requirement 8: Identify and Authenticate Access to System Components
#

# Source the HTML report library
source "$(dirname "$0")/pci_html_report_lib.sh"

# Script variables
SCRIPT_NAME=$(basename "$0")
REQUIREMENT_NUMBER="8"
DATE_TIME=$(date +"%Y-%m-%d_%H-%M-%S")
OUTPUT_DIR="./reports"
OUTPUT_FILE="${OUTPUT_DIR}/pci_requirement${REQUIREMENT_NUMBER}_report_${DATE_TIME}.html"
REPORT_TITLE="PCI DSS v4.0.1 - Requirement ${REQUIREMENT_NUMBER} Compliance Assessment Report"

# Initialize counters
total_checks=0
passed_checks=0
failed_checks=0
warning_checks=0
info_checks=0

# Check if output directory exists, if not create it
if [ ! -d "$OUTPUT_DIR" ]; then
    mkdir -p "$OUTPUT_DIR"
fi

# Always use AWS CLI configured region
REGION=$(aws configure get region)
if [ -z "$REGION" ]; then
    echo "Error: No AWS region configured. Please configure AWS CLI with 'aws configure'."
    exit 1
fi
echo "Using configured AWS region: $REGION"

# Validate region
if ! aws ec2 describe-regions --region "$REGION" --query "Regions[?RegionName=='$REGION']" --output text &> /dev/null; then
    echo "Error: Invalid AWS region specified."
    exit 1
fi

# Initialize HTML report
initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE" "$REQUIREMENT_NUMBER" "$REGION"

# Function to check AWS CLI command access
check_command_access() {
    local output_file="$1"
    local service="$2"
    local command="$3"
    local region="$4"
    
    echo "Checking access to AWS $service $command..."
    
    if aws $service help | grep -q "$command"; then
        # Try to execute the command with a harmless parameter
        case "$service" in
            iam)
                if [ "$command" == "list-users" ]; then
                    aws $service $command --max-items 1 --region "$region" &> /dev/null
                elif [ "$command" == "list-roles" ]; then
                    aws $service $command --max-items 1 --region "$region" &> /dev/null
                else
                    aws $service $command --region "$region" &> /dev/null
                fi
                ;;
            *)
                aws $service $command --region "$region" &> /dev/null
                ;;
        esac
        
        if [ $? -eq 0 ]; then
            add_check_item "$output_file" "pass" "AWS CLI Access: $service $command" \
                "<p>Successfully verified access to <code>aws $service $command</code>.</p>"
            return 0
        else
            add_check_item "$output_file" "fail" "AWS CLI Access: $service $command" \
                "<p>You do not have sufficient permissions to execute <code>aws $service $command</code>.</p>" \
                "Ensure your AWS credentials have the necessary permissions to perform this assessment."
            return 1
        fi
    else
        add_check_item "$output_file" "fail" "AWS CLI Access: $service $command" \
            "<p>The command <code>aws $service $command</code> does not exist or is not accessible.</p>" \
            "Ensure you have the latest version of AWS CLI installed."
        return 1
    fi
}

# Function to check IAM password policy
check_iam_password_policy() {
    local OUTPUT_FILE="$1"
    local policy_details=""
    local password_policy_exists=false
    local policy_meets_requirements=true
    local issues=""
    
    echo "Checking IAM password policy..."
    
    # Get password policy
    local password_policy=$(aws iam get-account-password-policy --region "$REGION" 2>&1)
    
    if [[ "$password_policy" == *"NoSuchEntity"* ]]; then
        add_check_item "$OUTPUT_FILE" "fail" "8.3.6 - Password/Passphrase Requirements" \
            "<p>No password policy is configured for the AWS account.</p>" \
            "Configure an IAM password policy that meets or exceeds PCI DSS requirements."
        return 1
    else
        password_policy_exists=true
        policy_details="<p>Current IAM password policy settings:</p><ul>"
        
        # Extract the policy details
        if [[ "$password_policy" == *"MinimumPasswordLength"* ]]; then
            min_length=$(echo "$password_policy" | grep "MinimumPasswordLength" | sed 's/.*: \([0-9]*\).*/\1/')
            policy_details+="<li>Minimum password length: $min_length characters"
            if [ "$min_length" -lt 12 ]; then
                policy_details+=" <span class='red'>(FAIL: PCI DSS requires at least 12 characters)</span>"
                policy_meets_requirements=false
                issues+="<li>Increase minimum password length to at least 12 characters</li>"
            else
                policy_details+=" <span class='green'>(PASS)</span>"
            fi
            policy_details+="</li>"
        else
            policy_details+="<li>Minimum password length: Not set <span class='red'>(FAIL: PCI DSS requires at least 12 characters)</span></li>"
            policy_meets_requirements=false
            issues+="<li>Set minimum password length to at least 12 characters</li>"
        fi
        
        # Check for password complexity requirements
        if [[ "$password_policy" == *"RequireSymbols"* ]]; then
            require_symbols=$(echo "$password_policy" | grep "RequireSymbols" | sed 's/.*: \(true\|false\).*/\1/')
            policy_details+="<li>Require symbols: $require_symbols"
            if [ "$require_symbols" == "false" ]; then
                policy_details+=" <span class='red'>(FAIL: PCI DSS requires both upper and lowercase letters, numbers, and special characters)</span>"
                policy_meets_requirements=false
                issues+="<li>Enable symbol requirement in password policy</li>"
            else
                policy_details+=" <span class='green'>(PASS)</span>"
            fi
            policy_details+="</li>"
        else
            policy_details+="<li>Require symbols: Not set <span class='red'>(FAIL)</span></li>"
            policy_meets_requirements=false
            issues+="<li>Enable symbol requirement in password policy</li>"
        fi
        
        if [[ "$password_policy" == *"RequireNumbers"* ]]; then
            require_numbers=$(echo "$password_policy" | grep "RequireNumbers" | sed 's/.*: \(true\|false\).*/\1/')
            policy_details+="<li>Require numbers: $require_numbers"
            if [ "$require_numbers" == "false" ]; then
                policy_details+=" <span class='red'>(FAIL)</span>"
                policy_meets_requirements=false
                issues+="<li>Enable numeric character requirement in password policy</li>"
            else
                policy_details+=" <span class='green'>(PASS)</span>"
            fi
            policy_details+="</li>"
        else
            policy_details+="<li>Require numbers: Not set <span class='red'>(FAIL)</span></li>"
            policy_meets_requirements=false
            issues+="<li>Enable numeric character requirement in password policy</li>"
        fi
        
        if [[ "$password_policy" == *"RequireUppercaseCharacters"* ]]; then
            require_uppercase=$(echo "$password_policy" | grep "RequireUppercaseCharacters" | sed 's/.*: \(true\|false\).*/\1/')
            policy_details+="<li>Require uppercase characters: $require_uppercase"
            if [ "$require_uppercase" == "false" ]; then
                policy_details+=" <span class='red'>(FAIL)</span>"
                policy_meets_requirements=false
                issues+="<li>Enable uppercase character requirement in password policy</li>"
            else
                policy_details+=" <span class='green'>(PASS)</span>"
            fi
            policy_details+="</li>"
        else
            policy_details+="<li>Require uppercase characters: Not set <span class='red'>(FAIL)</span></li>"
            policy_meets_requirements=false
            issues+="<li>Enable uppercase character requirement in password policy</li>"
        fi
        
        if [[ "$password_policy" == *"RequireLowercaseCharacters"* ]]; then
            require_lowercase=$(echo "$password_policy" | grep "RequireLowercaseCharacters" | sed 's/.*: \(true\|false\).*/\1/')
            policy_details+="<li>Require lowercase characters: $require_lowercase"
            if [ "$require_lowercase" == "false" ]; then
                policy_details+=" <span class='red'>(FAIL)</span>"
                policy_meets_requirements=false
                issues+="<li>Enable lowercase character requirement in password policy</li>"
            else
                policy_details+=" <span class='green'>(PASS)</span>"
            fi
            policy_details+="</li>"
        else
            policy_details+="<li>Require lowercase characters: Not set <span class='red'>(FAIL)</span></li>"
            policy_meets_requirements=false
            issues+="<li>Enable lowercase character requirement in password policy</li>"
        fi
        
        # Check for password history
        if [[ "$password_policy" == *"PasswordReusePrevention"* ]]; then
            reuse_prevention=$(echo "$password_policy" | grep "PasswordReusePrevention" | sed 's/.*: \([0-9]*\).*/\1/')
            policy_details+="<li>Password reuse prevention: Last $reuse_prevention passwords remembered"
            if [ "$reuse_prevention" -lt 4 ]; then
                policy_details+=" <span class='red'>(FAIL: PCI DSS requires at least 4)</span>"
                policy_meets_requirements=false
                issues+="<li>Increase password history to remember at least 4 previous passwords</li>"
            else
                policy_details+=" <span class='green'>(PASS)</span>"
            fi
            policy_details+="</li>"
        else
            policy_details+="<li>Password reuse prevention: Not set <span class='red'>(FAIL: PCI DSS requires remembering at least 4 previous passwords)</span></li>"
            policy_meets_requirements=false
            issues+="<li>Enable password history to remember at least 4 previous passwords</li>"
        fi
        
        # Check for password expiration
        if [[ "$password_policy" == *"MaxPasswordAge"* ]]; then
            max_age=$(echo "$password_policy" | grep "MaxPasswordAge" | sed 's/.*: \([0-9]*\).*/\1/')
            policy_details+="<li>Maximum password age: $max_age days"
            if [ "$max_age" -gt 90 ]; then
                policy_details+=" <span class='red'>(FAIL: PCI DSS requires passwords to be changed at least every 90 days)</span>"
                policy_meets_requirements=false
                issues+="<li>Reduce maximum password age to 90 days or less</li>"
            else
                policy_details+=" <span class='green'>(PASS)</span>"
            fi
            policy_details+="</li>"
        else
            policy_details+="<li>Maximum password age: Not set <span class='red'>(FAIL: PCI DSS requires passwords to be changed at least every 90 days)</span></li>"
            policy_meets_requirements=false
            issues+="<li>Set maximum password age to 90 days or less</li>"
        fi
        
        # Check for temporary password settings
        if [[ "$password_policy" == *"HardExpiry"* ]]; then
            hard_expiry=$(echo "$password_policy" | grep "HardExpiry" | sed 's/.*: \(true\|false\).*/\1/')
            policy_details+="<li>Require password reset on first login: $hard_expiry"
            if [ "$hard_expiry" == "false" ]; then
                policy_details+=" <span class='yellow'>(WARNING: Consider requiring password change upon first login)</span>"
            else
                policy_details+=" <span class='green'>(PASS)</span>"
            fi
            policy_details+="</li>"
        else
            policy_details+="<li>Require password reset on first login: Not set <span class='yellow'>(WARNING)</span></li>"
        fi
        
        policy_details+="</ul>"
        
        if [ "$policy_meets_requirements" = false ]; then
            policy_details+="<p><strong>Recommendations:</strong></p><ul>$issues</ul>"
            add_check_item "$OUTPUT_FILE" "fail" "8.3.6 - Password/Passphrase Requirements" \
                "$policy_details" \
                "Update the IAM password policy to meet all PCI DSS requirements."
            return 1
        else
            add_check_item "$OUTPUT_FILE" "pass" "8.3.6 - Password/Passphrase Requirements" \
                "$policy_details"
            return 0
        fi
    fi
}

# Function to check for multi-factor authentication
check_mfa() {
    local OUTPUT_FILE="$1"
    local details=""
    local problems_found=false
    
    echo "Checking MFA configuration..."
    
    # Check for root account MFA
    echo "Checking root account MFA..."
    root_mfa_status=$(aws iam get-account-summary --region "$REGION" --query 'SummaryMap.AccountMFAEnabled' --output text)
    
    if [ "$root_mfa_status" == "1" ]; then
        details+="<p><span class='green'>✓ Root account has MFA enabled.</span></p>"
    else
        details+="<p><span class='red'>✗ Root account does not have MFA enabled.</span></p>"
        problems_found=true
    fi
    
    # Check for console users without MFA
    echo "Checking IAM users MFA status..."
    details+="<p>IAM User MFA Status:</p>"
    
    users_without_mfa=""
    user_count=0
    mfa_enabled_count=0
    
    # Get all IAM users
    users=$(aws iam list-users --region "$REGION" --query 'Users[*].[UserName,UserId,CreateDate]' --output text)
    
    if [ -n "$users" ]; then
        details+="<table border='1' cellpadding='5'>
        <tr>
            <th>Username</th>
            <th>MFA Enabled</th>
            <th>Password Enabled</th>
            <th>Access Keys</th>
            <th>Last Activity</th>
        </tr>"
        
        while IFS=$'\t' read -r username user_id create_date; do
            ((user_count++))
            
            # Check if user has console access
            login_profile=$(aws iam get-login-profile --user-name "$username" --region "$REGION" 2>&1)
            has_console_access="No"
            if [[ "$login_profile" != *"NoSuchEntity"* ]]; then
                has_console_access="Yes"
            fi
            
            # Check for MFA devices
            mfa_devices=$(aws iam list-mfa-devices --user-name "$username" --region "$REGION" --query 'MFADevices[*]' --output text)
            mfa_enabled="No"
            if [ -n "$mfa_devices" ]; then
                mfa_enabled="Yes"
                ((mfa_enabled_count++))
            fi
            
            # Check for access keys
            access_keys=$(aws iam list-access-keys --user-name "$username" --region "$REGION" --query 'AccessKeyMetadata[*].[AccessKeyId,Status]' --output text)
            access_key_info="None"
            if [ -n "$access_keys" ]; then
                access_key_info=""
                while IFS=$'\t' read -r key_id key_status; do
                    if [ -n "$key_id" ]; then
                        # Get last used info
                        key_last_used=$(aws iam get-access-key-last-used --access-key-id "$key_id" --region "$REGION" --query 'AccessKeyLastUsed.LastUsedDate' --output text)
                        if [ "$key_last_used" == "None" ]; then
                            key_last_used="Never used"
                        fi
                        
                        if [ -n "$access_key_info" ]; then
                            access_key_info+="<br>"
                        fi
                        access_key_info+="$key_id ($key_status) - Last used: $key_last_used"
                    fi
                done <<< "$access_keys"
            fi
            
            # Get user's last activity
            last_activity="Unknown"
            
            # Add row to table with proper styling
            row_style=""
            if [ "$has_console_access" == "Yes" ] && [ "$mfa_enabled" == "No" ]; then
                row_style=" class='red'"
                problems_found=true
                if [ -n "$users_without_mfa" ]; then
                    users_without_mfa+=", "
                fi
                users_without_mfa+="$username"
            fi
            
            details+="<tr$row_style>
                <td>$username</td>
                <td>$mfa_enabled</td>
                <td>$has_console_access</td>
                <td>$access_key_info</td>
                <td>$last_activity</td>
            </tr>"
            
        done <<< "$users"
        
        details+="</table>"
        
        details+="<p>Summary: $mfa_enabled_count out of $user_count users have MFA enabled.</p>"
        
        if [ -n "$users_without_mfa" ]; then
            details+="<p><span class='red'>The following users have console access but do not have MFA enabled: $users_without_mfa</span></p>"
        fi
    else
        details+="<p>No IAM users found in the account.</p>"
    fi
    
    # Check for roles that don't enforce MFA
    echo "Checking IAM roles for MFA requirements..."
    roles_without_mfa=""
    role_count=0
    roles_with_mfa_count=0
    
    # Get all IAM roles
    roles=$(aws iam list-roles --region "$REGION" --query 'Roles[?starts_with(Path, `/`) == `true`].[RoleName,Arn]' --output text)
    
    if [ -n "$roles" ]; then
        details+="<p>Analyzing IAM roles for MFA enforcement in trust policies:</p>"
        details+="<ul>"
        
        while IFS=$'\t' read -r role_name role_arn; do
            ((role_count++))
            
            # Get role trust policy
            trust_policy=$(aws iam get-role --role-name "$role_name" --region "$REGION" --query 'Role.AssumeRolePolicyDocument' --output json)
            
            # Check if trust policy enforces MFA
            enforces_mfa=false
            if [[ "$trust_policy" == *"aws:MultiFactorAuthPresent"* ]] || 
               [[ "$trust_policy" == *"aws:MultiFactorAuthAge"* ]]; then
                enforces_mfa=true
                ((roles_with_mfa_count++))
                details+="<li><span class='green'>Role: $role_name - MFA is enforced in trust policy</span></li>"
            else
                # Check if this role is a service role (not used by humans)
                if [[ "$trust_policy" == *"amazonaws.com"* ]]; then
                    # Service role, MFA not applicable
                    details+="<li>Role: $role_name - Service role, MFA not applicable</li>"
                else
                    # Human role without MFA enforcement
                    details+="<li><span class='yellow'>Role: $role_name - Used by humans but does not enforce MFA</span></li>"
                    if [ -n "$roles_without_mfa" ]; then
                        roles_without_mfa+=", "
                    fi
                    roles_without_mfa+="$role_name"
                    # Not failing the check since some roles may not need MFA
                    problems_found=true
                fi
            fi
            
        done <<< "$roles"
        
        details+="</ul>"
        
        if [ -n "$roles_without_mfa" ]; then
            details+="<p><span class='yellow'>The following roles may be assumed by users but do not enforce MFA: $roles_without_mfa</span></p>"
            details+="<p>Note: This is a warning because some role assumptions may happen through trusted services, but you should verify any roles that allow human access.</p>"
        fi
    else
        details+="<p>No IAM roles found in the account.</p>"
    fi
    
# Final check result
    if [ "$problems_found" = true ]; then
        add_check_item "$OUTPUT_FILE" "fail" "8.4.2 - Multi-Factor Authentication" \
            "$details" \
            "Ensure MFA is enabled for the root account and all IAM users with console access. Consider enforcing MFA in trust policies for roles used by humans."
        return 1
    else
        add_check_item "$OUTPUT_FILE" "pass" "8.4.2 - Multi-Factor Authentication" \
            "$details"
        return 0
    fi
}

# Function for session timeout removed as it requires manual check

# Function to check for security access
check_security_access() {
    local OUTPUT_FILE="$1"
    local details=""
    local sensitive_policies_found=false
    
    echo "Checking access to security functions..."
    
    # Define sensitive actions to check for
    sensitive_actions=(
        "iam:*"
        "cloudtrail:StopLogging"
        "cloudtrail:DeleteTrail"
        "aws-portal:ModifyBilling"
        "aws-portal:ModifyAccount"
        "account:*"
        "organizations:*"
        "kms:*"
    )
    
    # Get all IAM policies
    policies=$(aws iam list-policies --scope Local --region "$REGION" --query 'Policies[*].[PolicyName,Arn]' --output text)
    
    details+="<p>Checking IAM policies that grant access to sensitive security functions:</p>"
    
    policy_details=""
    if [ -n "$policies" ]; then
        while IFS=$'\t' read -r policy_name policy_arn; do
            # Get policy details and version
            policy_versions=$(aws iam list-policy-versions --policy-arn "$policy_arn" --region "$REGION" --query 'Versions[?IsDefaultVersion==`true`].VersionId' --output text)
            
            for version in $policy_versions; do
                policy_document=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$version" --region "$REGION" --query 'PolicyVersion.Document' --output json)
                
                # Check for sensitive actions
                sensitive_actions_found=""
                for action in "${sensitive_actions[@]}"; do
                    if [[ "$policy_document" == *"\"$action\""* ]]; then
                        if [ -n "$sensitive_actions_found" ]; then
                            sensitive_actions_found+=", "
                        fi
                        sensitive_actions_found+="$action"
                    fi
                done
                
                if [ -n "$sensitive_actions_found" ]; then
                    sensitive_policies_found=true
                    policy_details+="<li><strong>$policy_name</strong>: Grants access to sensitive actions: $sensitive_actions_found</li>"
                fi
            done
            
        done <<< "$policies"
        
        if [ -n "$policy_details" ]; then
            details+="<p><span class='yellow'>The following custom IAM policies grant access to sensitive security functions:</span></p><ul>"
            details+="$policy_details"
            details+="</ul>"
            details+="<p>Note: These policies should be reviewed to ensure they follow the principle of least privilege.</p>"
        else
            details+="<p><span class='green'>No custom IAM policies found that grant broad access to sensitive security functions.</span></p>"
        fi
    else
        details+="<p>No custom IAM policies found in the account.</p>"
    fi
    
    # Check IAM users with administrator access
    admins=$(aws iam list-users --region "$REGION" --query 'Users[*].UserName' --output text | xargs -I {} aws iam list-attached-user-policies --user-name {} --region "$REGION" --query 'AttachedPolicies[?PolicyName==`AdministratorAccess`].PolicyName' --output text | xargs -I {} echo {})
    
    if [ -n "$admins" ]; then
        details+="<p><span class='yellow'>The following IAM users have Administrator access:</span></p><ul>"
        
        for admin in $admins; do
            details+="<li>$admin</li>"
        done
        
        details+="</ul>"
        details+="<p>Ensure these administrative accounts are carefully controlled and monitored.</p>"
        sensitive_policies_found=true
    else
        details+="<p><span class='green'>No IAM users found with direct Administrator access.</span></p>"
    fi
    
    if [ "$sensitive_policies_found" = true ]; then
        add_check_item "$OUTPUT_FILE" "warning" "7.2.5 - Access to Security Functions" \
            "$details" \
            "Review the identified policies that grant access to sensitive security functions and ensure they adhere to the principle of least privilege."
    else
        add_check_item "$OUTPUT_FILE" "pass" "7.2.5 - Access to Security Functions" \
            "$details"
    fi
}

# Function to check for IAM user access reviews
check_user_access_reviews() {
    local OUTPUT_FILE="$1"
    local details=""
    local warning=false
    
    echo "Checking user access review mechanisms..."
    
    # Check if AWS IAM Access Analyzer is enabled
    analyzer_status=$(aws accessanalyzer list-analyzers --region "$REGION" --query 'analyzers[?status==`ACTIVE`]' --output text 2>/dev/null)
    
    if [ -n "$analyzer_status" ]; then
        details+="<p><span class='green'>AWS IAM Access Analyzer is active in this region, which can help identify resources shared with external entities.</span></p>"
        
        # Check analyzers in the account
        analyzers=$(aws accessanalyzer list-analyzers --region "$REGION" --query 'analyzers[*].[name,type]' --output text)
        
        if [ -n "$analyzers" ]; then
            details+="<p>Configured analyzers:</p><ul>"
            while IFS=$'\t' read -r analyzer_name analyzer_type; do
                details+="<li>$analyzer_name (Type: $analyzer_type)</li>"
            done <<< "$analyzers"
            details+="</ul>"
        fi
    else
        details+="<p><span class='yellow'>AWS IAM Access Analyzer is not enabled in this region. Consider enabling it to help identify resources shared with external entities.</span></p>"
        warning=true
    fi
    
    # Check for CloudTrail trails that monitor IAM events
    iam_trails=$(aws cloudtrail describe-trails --region "$REGION" --query 'trailList[?*]' --output json)
    
    if [ -n "$iam_trails" ] && [ "$iam_trails" != "[]" ]; then
        details+="<p>CloudTrail trails that can be used for user activity monitoring:</p><ul>"
        
        echo "$iam_trails" | jq -c '.[]' | while read -r trail; do
            trail_name=$(echo "$trail" | jq -r '.Name')
            trail_arn=$(echo "$trail" | jq -r '.TrailARN')
            is_multi_region=$(echo "$trail" | jq -r '.IsMultiRegionTrail')
            
            # Check if trail is logging
            trail_status=$(aws cloudtrail get-trail-status --name "$trail_arn" --region "$REGION" 2>/dev/null)
            is_logging=$(echo "$trail_status" | jq -r '.IsLogging')
            
            if [ "$is_logging" == "true" ]; then
                # Check if management events are being recorded
                event_selectors=$(aws cloudtrail get-event-selectors --trail-name "$trail_arn" --region "$REGION" 2>/dev/null)
                records_management=$(echo "$event_selectors" | grep -c '"ReadWriteType": "All"')
                
                if [ "$records_management" -gt 0 ]; then
                    details+="<li><span class='green'>$trail_name - Active, recording management events</span> (Multi-region: $is_multi_region)</li>"
                else
                    details+="<li><span class='yellow'>$trail_name - Active, but may not be recording all management events</span> (Multi-region: $is_multi_region)</li>"
                    warning=true
                fi
            else
                details+="<li><span class='red'>$trail_name - Inactive (not currently logging)</span> (Multi-region: $is_multi_region)</li>"
                warning=true
            fi
        done
        
        details+="</ul>"
    else
        details+="<p><span class='red'>No CloudTrail trails found in this region. User activity monitoring may be insufficient.</span></p>"
        warning=true
    fi
    
    # Check AWS Config recorders for IAM changes
    config_recorders=$(aws configservice describe-configuration-recorders --region "$REGION" 2>/dev/null)
    
    if [ $? -eq 0 ] && [ -n "$config_recorders" ]; then
        records_iam_resources=$(echo "$config_recorders" | grep -c "resourceTypes.*iam")
        
        if [ "$records_iam_resources" -gt 0 ]; then
            details+="<p><span class='green'>AWS Config is recording IAM resource changes, which is useful for user access reviews.</span></p>"
        else
            details+="<p><span class='yellow'>AWS Config is enabled but may not be recording IAM resource changes. Configure AWS Config to record IAM resources.</span></p>"
            warning=true
        fi
    else
        details+="<p><span class='yellow'>AWS Config is not enabled in this region. Consider enabling it to track IAM resource configurations and changes.</span></p>"
        warning=true
    fi
    
    # Check for old or unused credentials
    details+="<h4>Credential Usage Analysis</h4>"
    
    # Check for old access keys
    old_access_keys_found=false
    access_keys=$(aws iam list-users --region "$REGION" --query 'Users[*].UserName' --output text | xargs -I {} aws iam list-access-keys --user-name {} --region "$REGION" --query 'AccessKeyMetadata[*].[UserName,AccessKeyId,Status,CreateDate]' --output text)
    
    if [ -n "$access_keys" ]; then
        details+="<p>Access key analysis:</p><table border='1' cellpadding='5'>
        <tr>
            <th>Username</th>
            <th>Access Key ID</th>
            <th>Status</th>
            <th>Created</th>
            <th>Last Used</th>
            <th>Age (days)</th>
        </tr>"
        
        current_date=$(date +%s)
        
        while IFS=$'\t' read -r username key_id status create_date; do
            # Get last used timestamp
            key_last_used=$(aws iam get-access-key-last-used --access-key-id "$key_id" --region "$REGION" --query 'AccessKeyLastUsed.LastUsedDate' --output text)
            
            if [ "$key_last_used" == "None" ] || [ "$key_last_used" == "null" ]; then
                key_last_used="Never used"
            fi
            
            # Calculate age in days
            create_date_epoch=$(date -d "$create_date" +%s 2>/dev/null)
            if [ $? -ne 0 ]; then
                # Try different date format if the first one fails
                create_date_epoch=$(date -d "$(echo $create_date | sed 's/T/ /g' | cut -d '+' -f1)" +%s 2>/dev/null)
            fi
            
            if [ -n "$create_date_epoch" ]; then
                age_days=$(( (current_date - create_date_epoch) / 86400 ))
            else
                age_days="Unknown"
            fi
            
            # Apply styling based on age and status
            row_style=""
            if [ "$status" == "Active" ] && [ "$age_days" != "Unknown" ] && [ $age_days -gt 90 ]; then
                row_style=" class='red'"
                old_access_keys_found=true
            fi
            
            details+="<tr$row_style>
                <td>$username</td>
                <td>$key_id</td>
                <td>$status</td>
                <td>$create_date</td>
                <td>$key_last_used</td>
                <td>$age_days</td>
            </tr>"
            
        done <<< "$access_keys"
        
        details+="</table>"
        
        if [ "$old_access_keys_found" = true ]; then
            details+="<p><span class='red'>Warning: Some access keys are over 90 days old. Consider rotating these keys.</span></p>"
            warning=true
        fi
    else
        details+="<p>No access keys found in the account.</p>"
    fi
    
    # Final check result
    if [ "$warning" = true ]; then
        add_check_item "$OUTPUT_FILE" "warning" "8.6.1-3 - Review User Access" \
            "$details" \
            "Implement access review processes and monitoring tools to periodically validate all access to CDE and resources."
    else
        add_check_item "$OUTPUT_FILE" "pass" "8.6.1-3 - Review User Access" \
            "$details"
    fi
}

# Check for hardcoded credentials
check_hardcoded_credentials() {
    local OUTPUT_FILE="$1"
    local hardcoded_creds_details=""
    local warning=false
    
    echo "Checking for potential hardcoded credentials..."
    
    # Define patterns to check for
    sensitive_patterns=(
        "AWS_ACCESS_KEY"
        "AWS_SECRET"
        "password[[:space:]]*=[[:space:]]*"
        "passwd[[:space:]]*=[[:space:]]*"
        "auth_token[[:space:]]*=[[:space:]]*"
        "api_key[[:space:]]*=[[:space:]]*"
    )
    
    # Check Lambda functions for environment variables containing credentials
    lambdas=$(aws lambda list-functions --region "$REGION" --query 'Functions[*].[FunctionName]' --output text 2>/dev/null)
    
    found_lambdas=""
    if [ -n "$lambdas" ]; then
        hardcoded_creds_details+="<p>Checking Lambda functions for potential hardcoded credentials in environment variables:</p>"
        
        for lambda in $lambdas; do
            # Get function config
            lambda_config=$(aws lambda get-function --function-name "$lambda" --region "$REGION" 2>/dev/null)
            env_vars=$(echo "$lambda_config" | jq -r '.Configuration.Environment.Variables' 2>/dev/null)
            
            if [ -n "$env_vars" ] && [ "$env_vars" != "null" ]; then
                # Search for sensitive patterns
                for pattern in "${sensitive_patterns[@]}"; do
                    if echo "$env_vars" | grep -i "$pattern" > /dev/null; then
                        if [ -n "$found_lambdas" ]; then
                            found_lambdas+=", "
                        fi
                        found_lambdas+="$lambda"
                        warning=true
                        break
                    fi
                done
            fi
        done
        
        if [ -n "$found_lambdas" ]; then
            hardcoded_creds_details+="<p><span class='yellow'>Potential sensitive data found in environment variables of Lambda functions: $found_lambdas</span></p>"
        else
            hardcoded_creds_details+="<p><span class='green'>No obvious sensitive data found in Lambda environment variables.</span></p>"
        fi
    else
        hardcoded_creds_details+="<p>No Lambda functions found in this region.</p>"
    fi
    
    # Check CodeBuild projects
    projects=$(aws codebuild list-projects --region "$REGION" --output text 2>/dev/null)
    
    found_projects=""
    if [ -n "$projects" ]; then
        hardcoded_creds_details+="<p>Checking CodeBuild projects for potential hardcoded credentials in environment variables:</p>"
        
        for project in $projects; do
            # Get project details
            project_details=$(aws codebuild batch-get-projects --names "$project" --region "$REGION" 2>/dev/null)
            env_vars=$(echo "$project_details" | jq -r '.projects[0].environment.environmentVariables' 2>/dev/null)
            
            if [ -n "$env_vars" ] && [ "$env_vars" != "null" ]; then
                # Search for sensitive patterns
                for pattern in "${sensitive_patterns[@]}"; do
                    if echo "$env_vars" | grep -i "$pattern" > /dev/null; then
                        if [ -n "$found_projects" ]; then
                            found_projects+=", "
                        fi
                        found_projects+="$project"
                        warning=true
                        break
                    fi
                done
            fi
        done
        
        if [ -n "$found_projects" ]; then
            hardcoded_creds_details+="<p><span class='yellow'>Potential sensitive data found in environment variables of CodeBuild projects: $found_projects</span></p>"
        else
            hardcoded_creds_details+="<p><span class='green'>No obvious sensitive data found in CodeBuild environment variables.</span></p>"
        fi
    else
        hardcoded_creds_details+="<p>No CodeBuild projects found in this region.</p>"
    fi
    
    hardcoded_creds_details+="<p>Note: This check only identifies potential areas of risk. A complete review requires manual code examination.</p>"
    
    # Final check result
    add_check_item "$OUTPUT_FILE" "info" "8.2.3 - Hardcoded Credentials" \
        "$hardcoded_creds_details" \
        "Review the identified resources for any hardcoded credentials and remove them in favor of secure storage solutions like AWS Secrets Manager or Parameter Store."
}

# Main function to run checks
main() {
    # Check necessary permissions
    add_section "$OUTPUT_FILE" "permissions" "Permissions Check" "active"
    check_command_access "$OUTPUT_FILE" "iam" "list-users" "$REGION"
    check_command_access "$OUTPUT_FILE" "iam" "list-roles" "$REGION"
    check_command_access "$OUTPUT_FILE" "iam" "get-account-password-policy" "$REGION"
    check_command_access "$OUTPUT_FILE" "accessanalyzer" "list-analyzers" "$REGION"
    check_command_access "$OUTPUT_FILE" "cloudtrail" "describe-trails" "$REGION"
    check_command_access "$OUTPUT_FILE" "configservice" "describe-configuration-recorders" "$REGION"
    close_section "$OUTPUT_FILE"

    # Check security access
    check_security_access "$OUTPUT_FILE"

    # Check for shared/generic accounts
    echo "Checking for shared/generic IAM users..."
    shared_accounts=""
    users=$(aws iam list-users --region "$REGION" --query 'Users[*].UserName' --output text)

    for username in $users; do
        # Check if username appears to be a shared account
        if [[ "$username" == *"shared"* ]] || [[ "$username" == *"admin"* ]] || [[ "$username" == *"service"* ]] || [[ "$username" == *"system"* ]]; then
            if [ -n "$shared_accounts" ]; then
                shared_accounts+=", "
            fi
            shared_accounts+="$username"
        fi
    done

    shared_account_details=""
    if [ -n "$shared_accounts" ]; then
        shared_account_details="<p><span class='yellow'>Potential shared/generic accounts detected: $shared_accounts</span></p>"
    else
        shared_account_details="<p><span class='green'>No potential shared/generic accounts detected based on naming patterns.</span></p>"
    fi

    # Add automated checks for Requirement 8.3
    add_section "$OUTPUT_FILE" "req-8.3" "Requirement 8.3: Strong authentication is implemented" "active"
    
    # Check password policy
    check_iam_password_policy "$OUTPUT_FILE"
    
    close_section "$OUTPUT_FILE"
    
    # Add automated checks for Requirement 8.4
    add_section "$OUTPUT_FILE" "req-8.4" "Requirement 8.4: Multi-factor authentication (MFA) is implemented" "active"
    
    # Check MFA
    check_mfa "$OUTPUT_FILE"
    
    close_section "$OUTPUT_FILE"
    
    # Add automated checks for Requirement 8.6
    add_section "$OUTPUT_FILE" "req-8.6" "Requirement 8.6: Access to system components is monitored and controlled" "active"
    
    # Check user access reviews
    check_user_access_reviews "$OUTPUT_FILE"
    
    # Check for hardcoded credentials
    check_hardcoded_credentials "$OUTPUT_FILE"
    
    close_section "$OUTPUT_FILE"

    # Finalize the report
    finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$info_checks"

    echo "Assessment complete. Report saved to $OUTPUT_FILE"
    echo "Summary: $passed_checks passed, $failed_checks failed, $warning_checks warnings, $info_checks informational"
}

# Execute main function
main
