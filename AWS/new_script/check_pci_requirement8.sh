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
DATE_TIME=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="./reports"
OUTPUT_FILE="${OUTPUT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_${DATE_TIME}.html"
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

# Prompt for AWS region if not provided
if [ -z "$REGION" ]; then
    read -p "Enter AWS region to test (e.g., us-east-1): " REGION
    if [ -z "$REGION" ]; then
        REGION="us-east-1"
        echo -e "${YELLOW}Using default region: $REGION${NC}"
    fi
fi


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

# Function to check user account management
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
    
    # Check for unused credentials
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
    
    # Check for inactive users
    inactive_users_found=false
    user_details=$(aws iam list-users --region "$REGION" --query 'Users[*].[UserName,CreateDate,PasswordLastUsed]' --output text)
    
    if [ -n "$user_details" ]; then
        details+="<p>User activity analysis:</p><table border='1' cellpadding='5'>
        <tr>
            <th>Username</th>
            <th>Created</th>
            <th>Password Last Used</th>
            <th>Inactive Days</th>
        </tr>"
        
        current_date=$(date +%s)
        
        while IFS=$'\t' read -r username create_date last_used; do
            if [ "$last_used" == "None" ] || [ "$last_used" == "null" ]; then
                last_used="Never used"
                inactive_days="N/A"
            else
                # Calculate inactive days
                last_used_epoch=$(date -d "$last_used" +%s 2>/dev/null)
                if [ $? -ne 0 ]; then
                    # Try different date format if the first one fails
                    last_used_epoch=$(date -d "$(echo $last_used | sed 's/T/ /g' | cut -d '+' -f1)" +%s 2>/dev/null)
                fi
                
                if [ -n "$last_used_epoch" ]; then
                    inactive_days=$(( (current_date - last_used_epoch) / 86400 ))
                else
                    inactive_days="Unknown"
                fi
            fi
            
            # Apply styling based on inactivity
            row_style=""
            if [ "$inactive_days" != "N/A" ] && [ "$inactive_days" != "Unknown" ] && [ $inactive_days -gt 90 ]; then
                row_style=" class='red'"
                inactive_users_found=true
            fi
            
            details+="<tr$row_style>
                <td>$username</td>
                <td>$create_date</td>
                <td>$last_used</td>
                <td>$inactive_days</td>
            </tr>"
            
        done <<< "$user_details"
        
        details+="</table>"
        
        if [ "$inactive_users_found" = true ]; then
            details+="<p><span class='red'>Warning: Some users have been inactive for over 90 days. Consider disabling or removing these accounts.</span></p>"
            warning=true
        fi
    else
        details+="<p>No IAM users found in the account.</p>"
    fi
    
# Final recommendation
    details+="<p>Note: AWS only maintains limited historical information about user activity. For comprehensive access reviews, implement 
    additional logging and monitoring solutions.</p>"
    
    if [ "$warning" = true ]; then
        add_check_item "$OUTPUT_FILE" "warning" "8.6.1-3 - Review User Access" \
            "$details" \
            "Implement a formal process to review user accounts and access privileges at least once every six months. Enable AWS IAM Access Analyzer, CloudTrail, and AWS Config to support access reviews. Rotate credentials regularly and remove inactive accounts."
    else
        add_check_item "$OUTPUT_FILE" "pass" "8.6.1-3 - Review User Access" \
            "$details" \
            "Continue to review user accounts and access privileges at least once every six months. Maintain your current monitoring configuration."
    fi
}

# Function to check session timeout settings
check_session_timeout() {
    local OUTPUT_FILE="$1"
    local details=""
    local issues_found=false
    
    echo "Checking session timeout settings..."
    
    # Check for Console Session Duration
    console_timeout_set=false
    
    # Check IAM account settings for session duration
    iam_account_settings=$(aws iam get-account-summary --region "$REGION" 2>/dev/null)
    
    # Unfortunately, AWS CLI doesn't expose console session timeout settings directly
    # We'll need to provide guidance on how to check this manually
    
    details+="<p><strong>Console Session Timeout:</strong></p>"
    details+="<p><span class='yellow'>Console session timeout settings cannot be checked via AWS CLI. 
    Please manually verify that the AWS Console session timeout is set to 15 minutes or less in the IAM Account Settings.</span></p>"
    details+="<p>Steps to verify:</p>
    <ol>
        <li>Navigate to the AWS Management Console</li>
        <li>Go to IAM service</li>
        <li>Select 'Account settings'</li>
        <li>Check the 'Console session duration' setting (should be 15 minutes or less)</li>
    </ol>"
    
    # Check timeouts for roles
    details+="<p><strong>IAM Role Session Duration:</strong></p>"
    
    roles=$(aws iam list-roles --region "$REGION" --query 'Roles[?starts_with(Path, `/`) == `true`].[RoleName,MaxSessionDuration]' --output text)
    
    if [ -n "$roles" ]; then
        details+="<table border='1' cellpadding='5'>
        <tr>
            <th>Role Name</th>
            <th>Max Session Duration (hours)</th>
            <th>Status</th>
        </tr>"
        
        while IFS=$'\t' read -r role_name max_duration; do
            max_duration_hours=$(echo "scale=1; $max_duration / 3600" | bc)
            
            status="<span class='green'>OK</span>"
            if (( $(echo "$max_duration_hours > 8" | bc -l) )); then
                status="<span class='yellow'>Warning - Greater than 8 hours</span>"
                issues_found=true
            fi
            if (( $(echo "$max_duration_hours > 12" | bc -l) )); then
                status="<span class='red'>Exceeds Recommended Limit</span>"
                issues_found=true
            fi
            
            details+="<tr>
                <td>$role_name</td>
                <td>$max_duration_hours</td>
                <td>$status</td>
            </tr>"
            
        done <<< "$roles"
        
        details+="</table>"
    else
        details+="<p>No IAM roles found in the account.</p>"
    fi
    
    # Check for APIs and SDK session policies
    details+="<p><strong>API and SDK Sessions:</strong></p>"
    details+="<p>Review SDK implementations to ensure appropriate session timeouts are set.</p>"
    details+="<p>For best practice, API keys should have appropriate expiration periods and application code should:</p>
    <ul>
        <li>Refresh temporary credentials before they expire</li>
        <li>Implement appropriate error handling for expired credentials</li>
        <li>Not use long-lived access keys when temporary credentials can be used</li>
    </ul>"
    
# Final recommendation
    if [ "$issues_found" = true ]; then
        add_check_item "$OUTPUT_FILE" "warning" "8.2.8 - Session Timeout" \
            "$details" \
            "Configure console session timeout to 15 minutes or less. For roles with extended session durations, evaluate if business requirements justify the extended timeout and consider reducing to 8 hours or less when possible."
    else
        add_check_item "$OUTPUT_FILE" "warning" "8.2.8 - Session Timeout" \
            "$details" \
            "Manually verify console session timeout is set to 15 minutes or less. Continue monitoring role session durations."
    fi
}

# Function to check for user access to security functions
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
        "config:DeleteConfigRule"
        "config:DeleteConfigurationRecorder"
        "guardduty:DeleteDetector"
        "kms:ScheduleKeyDeletion"
        "kms:DisableKey"
        "s3:DeleteBucket"
        "ec2:ModifyInstanceAttribute"
        "ec2:AuthorizeSecurityGroupIngress"
        "ec2:AuthorizeSecurityGroupEgress"
    )
    
    # Get all policies
    managed_policies=$(aws iam list-policies --only-attached --scope Local --region "$REGION" --query 'Policies[*].[PolicyName,Arn]' --output text)
    
    details+="<p><strong>Analysis of IAM Policies with Security-Critical Permissions:</strong></p>"
    
    if [ -n "$managed_policies" ]; then
        details+="<ul>"
        
        while IFS=$'\t' read -r policy_name policy_arn; do
            sensitive_actions_found=""
            
            # Get policy details
            policy_version=$(aws iam get-policy --policy-arn "$policy_arn" --region "$REGION" --query 'Policy.DefaultVersionId' --output text)
            policy_document=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$policy_version" --region "$REGION" --query 'PolicyVersion.Document' --output json)
            
            # Check for sensitive actions
            for action in "${sensitive_actions[@]}"; do
                if [[ "$policy_document" == *"\"$action\""* ]] || [[ "$policy_document" == *"\"*:*\""* ]]; then
                    if [ -n "$sensitive_actions_found" ]; then
                        sensitive_actions_found+=", "
                    fi
                    sensitive_actions_found+="$action"
                fi
            done
            
            if [ -n "$sensitive_actions_found" ]; then
                sensitive_policies_found=true
                
                # Get the entities this policy is attached to
                attached_to=$(aws iam list-entities-for-policy --policy-arn "$policy_arn" --region "$REGION" --output json)
                users=$(echo "$attached_to" | jq -r '.PolicyUsers[].UserName' | tr '\n' ', ' | sed 's/,$//')
                groups=$(echo "$attached_to" | jq -r '.PolicyGroups[].GroupName' | tr '\n' ', ' | sed 's/,$//')
                roles=$(echo "$attached_to" | jq -r '.PolicyRoles[].RoleName' | tr '\n' ', ' | sed 's/,$//')
                
                attachment_info=""
                if [ -n "$users" ]; then
                    attachment_info+="<br><strong>Users:</strong> $users"
                fi
                if [ -n "$groups" ]; then
                    attachment_info+="<br><strong>Groups:</strong> $groups"
                fi
                if [ -n "$roles" ]; then
                    attachment_info+="<br><strong>Roles:</strong> $roles"
                fi
                
                details+="<li><span class='yellow'>Policy <strong>$policy_name</strong> contains sensitive actions: $sensitive_actions_found$attachment_info</span></li>"
            fi
            
        done <<< "$managed_policies"
        
        details+="</ul>"
    else
        details+="<p>No managed policies found in the account.</p>"
    fi
    
    # Check inline policies
    details+="<p><strong>Inline policies with security-critical permissions:</strong></p>"
    
    # Get all users with inline policies
    users_with_policies=$(aws iam list-users --region "$REGION" --query 'Users[*].UserName' --output text)
    
    if [ -n "$users_with_policies" ]; then
        details+="<ul>"
        
        for username in $users_with_policies; do
            user_policy_names=$(aws iam list-user-policies --user-name "$username" --region "$REGION" --query 'PolicyNames' --output text)
            
            for policy_name in $user_policy_names; do
                policy_document=$(aws iam get-user-policy --user-name "$username" --policy-name "$policy_name" --region "$REGION" --query 'PolicyDocument' --output json)
                
                sensitive_actions_found=""
                for action in "${sensitive_actions[@]}"; do
                    if [[ "$policy_document" == *"\"$action\""* ]] || [[ "$policy_document" == *"\"*:*\""* ]]; then
                        if [ -n "$sensitive_actions_found" ]; then
                            sensitive_actions_found+=", "
                        fi
                        sensitive_actions_found+="$action"
                    fi
                done
                
                if [ -n "$sensitive_actions_found" ]; then
                    sensitive_policies_found=true
                    details+="<li><span class='yellow'>User <strong>$username</strong> has inline policy <strong>$policy_name</strong> with sensitive actions: $sensitive_actions_found</span></li>"
                fi
            done
        done
        
        details+="</ul>"
    else
        details+="<p>No users with inline policies found.</p>"
    fi
    
    # Check for admin-level access through groups
    admin_groups=""
    groups=$(aws iam list-groups --region "$REGION" --query 'Groups[*].GroupName' --output text)
    
    if [ -n "$groups" ]; then
        for group_name in $groups; do
            # Check group policies
            group_managed_policies=$(aws iam list-attached-group-policies --group-name "$group_name" --region "$REGION" --query 'AttachedPolicies[*].PolicyArn' --output text)
            
            if [[ "$group_managed_policies" == *"arn:aws:iam::aws:policy/AdministratorAccess"* ]]; then
                if [ -n "$admin_groups" ]; then
                    admin_groups+=", "
                fi
                admin_groups+="$group_name"
            fi
        done
    fi
    
    if [ -n "$admin_groups" ]; then
        sensitive_policies_found=true
        details+="<p><span class='yellow'>The following groups have administrative access (AdministratorAccess policy): $admin_groups</span></p>"
        
        # Check membership of these groups
        details+="<p>Users with administrative access through group membership:</p><ul>"
        
        for group_name in $(echo "$admin_groups" | tr ',' ' '); do
            group_users=$(aws iam get-group --group-name "$group_name" --region "$REGION" --query 'Users[*].UserName' --output text)
            
            if [ -n "$group_users" ]; then
#!/bin/bash

# Fixed section for the problematic part
            if [ -n "$group_users" ]; then
                for username in $group_users; do
                    details+="<li><span class='yellow'>User <strong>$username</strong> has administrative access through group <strong>$group_name</strong></span></li>"
                done
            else
                details+="<li>Group <strong>$group_name</strong> has no members</li>"
            fi
            fi
        done
        
        details+="</ul>"
    fi
    
# Final recommendation
    if [ "$sensitive_policies_found" = true ]; then
        add_check_item "$OUTPUT_FILE" "warning" "8.1.3 - Access to Security Functions" \
            "$details" \
            "Review the policies identified and ensure that only authorized personnel have access to security functions. Consider implementing least privilege by limiting permissions to specific actions rather than using wildcards. Use IAM Access Analyzer to identify potentially overly permissive policies."
    else
        add_check_item "$OUTPUT_FILE" "pass" "8.1.3 - Access to Security Functions" \
            "$details" \
            "Continue to limit access to security functions to authorized personnel only."
    fi
}

# Main script execution

echo "PCI DSS v4.0.1 Requirement $REQUIREMENT_NUMBER Compliance Assessment"
echo "=====================================================================================================>"
echo "Region: $REGION"
echo ""

# Check necessary permissions
add_section "$OUTPUT_FILE" "permissions" "Permissions Check" "active"
check_command_access "$OUTPUT_FILE" "iam" "list-users" "$REGION"
check_command_access "$OUTPUT_FILE" "iam" "list-roles" "$REGION"
check_command_access "$OUTPUT_FILE" "iam" "get-account-password-policy" "$REGION"
check_command_access "$OUTPUT_FILE" "accessanalyzer" "list-analyzers" "$REGION"
check_command_access "$OUTPUT_FILE" "cloudtrail" "describe-trails" "$REGION"
check_command_access "$OUTPUT_FILE" "configservice" "describe-configuration-recorders" "$REGION"
close_section "$OUTPUT_FILE"

# Requirement 8.1: Processes and mechanisms for identifying users and authenticating access
add_section "$OUTPUT_FILE" "req-8.1" "Requirement 8.1: Processes and mechanisms for identifying users and authenticating access" "none"

add_check_item "$OUTPUT_FILE" "warning" "8.1.1 - Security Policies and Procedures" \
    "<p>This check requires manual verification of documented security policies and procedures for Requirement 8:</p>
    <ul>
        <li>Policies and procedures must be documented</li>
        <li>Policies must be kept up to date</li>
        <li>Policies must be in use</li>
        <li>Policies must be known to all affected parties</li>
    </ul>
    <p>AWS provides the technical capabilities to implement strong identification and authentication systems, but organizational policies and procedures must be manually verified.</p>" \
    "Develop and maintain comprehensive documentation for user identification and authentication policies and procedures. Ensure these documents are regularly reviewed, updated, and communicated to all relevant staff."

add_check_item "$OUTPUT_FILE" "warning" "8.1.2 - Roles and Responsibilities" \
    "<p>This check requires manual verification that roles and responsibilities for identification and authentication are:</p>
    <ul>
        <li>Clearly documented</li>
        <li>Formally assigned</li>
        <li>Understood by the assigned personnel</li>
    </ul>
    <p>Review IAM roles and permission sets to confirm appropriate separation of duties.</p>" \
    "Document and assign clear roles and responsibilities for managing user identification and authentication within the AWS environment. Implement a formal process for reviewing these assignments periodically."

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
    shared_account_details="<p><span class='yellow'>Potential shared/generic accounts detected: $shared_accounts</span></p>
    <p>Note: These accounts were identified based on naming patterns only and require manual verification.</p>"
else
    shared_account_details="<p><span class='green'>No potential shared/generic accounts detected based on naming patterns.</span></p>"
fi

add_check_item "$OUTPUT_FILE" "warning" "8.1.4 - Unique ID for each user" \
    "<p>Checking for unique user identification for each user account.</p>
    <p>This check cannot be fully automated as it requires verification of processes and procedures to ensure:</p>
    <ul>
        <li>Each user is assigned a unique ID before access to system components is granted.</li>
        <li>Generic or shared accounts are not used for administration or access to cardholder data.</li>
        <li>Shared accounts for system or application access are properly inventoried and managed.</li>
    </ul>
    <p>AWS IAM inherently supports unique IDs for all IAM users. However, application-level authentication mechanisms must also be reviewed manually.</p>
    $shared_account_details" \
    "Ensure all access to systems is via unique user IDs. Review any shared service accounts to ensure they are properly inventoried, managed, and not used for direct user access."

add_check_item "$OUTPUT_FILE" "warning" "8.1.5 - Third-party access" \
    "<p>Checking for third-party/vendor remote access controls.</p>
    <p>This check requires manual verification to ensure:</p>
    <ul>
        <li>Multi-factor authentication is required for all third-party/vendor remote access.</li>
        <li>Third-party/vendor remote access is activated only when needed and deactivated immediately after use.</li>
        <li>Third-party access accounts are properly monitored.</li>
    </ul>
    <p>Review cross-account roles, IAM users assigned to vendors, and any other access mechanisms provided to third parties.</p>" \
    "Implement specific IAM roles for third-party access with appropriate permissions and MFA enforcement. Consider using AWS IAM Access Analyzer to monitor for unintended external access."

close_section "$OUTPUT_FILE"

# Requirement 8.2: Account credentials are properly managed
add_section "$OUTPUT_FILE" "req-8.2" "Requirement 8.2: Account credentials are properly managed" "none"

add_check_item "$OUTPUT_FILE" "warning" "8.2.1 - Credential Management Processes" \
    "<p>Checking for processes that manage credentials for users and application service accounts.</p>
    <p>This check requires manual verification to ensure:</p>
    <ul>
        <li>Procedures exist for proper assignment, modification, and revocation of credentials.</li>
        <li>Application service accounts are managed according to documented procedures.</li>
        <li>Cloud service provider-managed accounts are properly controlled.</li>
    </ul>
    <p>AWS provides the mechanisms for credential management, but organizational processes must be reviewed manually.</p>" \
    "Implement formal processes for managing credentials including initial assignment, modifications, and revocation. Consider using AWS Organizations and Service Control Policies to enforce credential management policies."

add_check_item "$OUTPUT_FILE" "warning" "8.2.2 - Knowledge-based Authentication" \
    "<p>Verification of knowledge-based authentication methods.</p>
    <p>This check requires manual review to ensure:</p>
    <ul>
        <li>If knowledge-based authentication (KBA) methods are used, they are resistant to guessing attacks.</li>
        <li>Static questions are not used as a verification method.</li>
        <li>If implemented, dynamic KBA uses a sufficiently large question pool and prevents replay attacks.</li>
    </ul>
    <p>AWS IAM uses standard password authentication and does not rely on KBA methods. However, any custom authentication systems used in AWS must be reviewed manually.</p>" \
    "If using knowledge-based authentication in any custom applications, ensure questions are dynamic and drawn from a large pool of possible questions."

close_section "$OUTPUT_FILE"

# Requirement 8.3: Authentication systems and methods
add_section "$OUTPUT_FILE" "req-8.3" "Requirement 8.3: Authentication systems and mechanisms" "none"

add_check_item "$OUTPUT_FILE" "warning" "8.3.1 - Authentication Mechanisms" \
    "<p>Verification of authentication mechanisms</p>
    <p>This check requires manual verification to ensure:</p>
    <ul>
        <li>All user access is authenticated via username and password or other authentication methods.</li>
        <li>Authentication methods are implemented correctly for all system components.</li>
        <li>Authentication mechanisms are suitable for the level of access provided.</li>
    </ul>
    <p>AWS IAM provides strong authentication mechanisms, but custom applications deployed in AWS must be reviewed separately.</p>" \
    "Ensure all access to CDE components requires authentication. Review any guest or anonymous access configurations in deployed applications."

add_check_item "$OUTPUT_FILE" "warning" "8.3.2 - Changes to Authentication Mechanisms" \
    "<p>Management of changes to authentication mechanisms.</p>
    <p>This check requires manual verification to ensure:</p>
    <ul>
        <li>Changes to authentication mechanisms are properly documented and tested.</li>
        <li>Any changes to authenticator settings are managed via change control procedures.</li>
        <li>Security impact of authentication changes is assessed.</li>
    </ul>
    <p>AWS change management processes for IAM settings need to be verified manually.</p>" \
    "Implement and document change control procedures for authentication mechanism changes. Use AWS CloudTrail to monitor changes to IAM authentication settings."

# Check IAM password policy
check_iam_password_policy "$OUTPUT_FILE"
((total_checks++))

add_check_item "$OUTPUT_FILE" "warning" "8.3.10 - Authentication Factors" \
    "<p>Verification of authentication factors security.</p>
    <p>This check requires manual verification to ensure authentication factors:</p>
    <ul>
        <li>Cannot be easily determined via social engineering (e.g., family names).</li>
        <li>Cannot be determined from public information (e.g., social media).</li>
        <li>Provide sufficient strength to resist attacks.</li>
    </ul>
    <p>AWS IAM provides strong authentication mechanisms, but password policy strength and user education must be reviewed manually.</p>" \
    "Implement user education on secure password creation. Consider implementing a password blacklist for common or easily guessed passwords."

close_section "$OUTPUT_FILE"

# Requirement 8.4: MFA and other authentication elements
add_section "$OUTPUT_FILE" "req-8.4" "Requirement 8.4: Multi-factor authentication and other authentication elements" "none"

check_mfa "$OUTPUT_FILE"
((total_checks++))

add_check_item "$OUTPUT_FILE" "warning" "8.4.1 - Multi-factor Authentication for Non-console Access" \
    "<p>Verification of MFA for remote network access to CDE.</p>
    <p>This check requires manual verification to ensure MFA is properly implemented for:</p>
    <ul>
        <li>All remote network access to the CDE for personnel with administrative access.</li>
        <li>All remote network access to the CDE for all personnel.</li>
        <li>All remote access from outside the entity's network.</li>
    </ul>
    <p>AWS IAM supports MFA enforcement via policies, but verification of implementation for all remote access scenarios is needed.</p>" \
    "Implement IAM policies that enforce MFA for all API and console access. Use SCPs in AWS Organizations to enforce MFA usage organization-wide."

close_section "$OUTPUT_FILE"

# Requirement 8.5: System accounts and access methods
add_section "$OUTPUT_FILE" "req-8.5" "Requirement 8.5: System accounts and access methods" "none"

add_check_item "$OUTPUT_FILE" "warning" "8.5.1 - Service Account Usage" \
    "<p>Verification of service account usage.</p>
    <p>This check requires manual verification to ensure:</p>
    <ul>
        <li>Service accounts are only used for the intended purpose.</li>
        <li>Service accounts are not used for interactive login.</li>
        <li>Service account credentials are properly secured.</li>
    </ul>
    <p>In AWS, this involves reviewing IAM roles used by applications and ensuring proper permissions and usage.</p>" \
    "Use IAM roles for EC2 instances and AWS services instead of IAM users with access keys. Implement strict policies that prevent service accounts from being used for interactive access."

add_check_item "$OUTPUT_FILE" "warning" "8.5.2 - Credentials for Integration/Automation" \
    "<p>Verification of credentials used for application integrations.</p>
    <p>This check requires manual verification to ensure:</p>
    <ul>
        <li>Credentials used by applications are secure.</li>
        <li>Application secrets are not stored in cleartext.</li>
        <li>Appropriate secret management solutions are used.</li>
    </ul>
    <p>In AWS, this involves reviewing how AWS credentials are stored and managed in applications and automation.</p>" \
    "Use AWS Secrets Manager or AWS Systems Manager Parameter Store to securely store and manage credentials. Rotate application credentials regularly and implement least privilege access."

check_session_timeout "$OUTPUT_FILE"
((total_checks++))

# Check for failed login attempts in CloudTrail
echo "Checking for failed login attempts in CloudTrail..."
failed_login_details=""
failed_login_monitoring=false

# Check if CloudTrail is enabled
trails=$(aws cloudtrail describe-trails --region "$REGION" --query 'trailList[*].[Name,IsMultiRegionTrail]' --output text 2>/dev/null)

if [ -n "$trails" ]; then
    trail_count=0
    active_trail_count=0
    failed_login_details+="<p>CloudTrail trail analysis for login failure monitoring:</p><ul>"
    
    while IFS=$'\t' read -r trail_name is_multi_region; do
        ((trail_count++))
        
        # Check if trail is logging
        trail_status=$(aws cloudtrail get-trail-status --name "$trail_name" --region "$REGION" 2>/dev/null)
        is_logging=$(echo "$trail_status" | grep -c "\"IsLogging\": true")
        
        if [ "$is_logging" -gt 0 ]; then
            ((active_trail_count++))
            
            # Check if management events are being recorded
            event_selectors=$(aws cloudtrail get-event-selectors --trail-name "$trail_name" --region "$REGION" 2>/dev/null)
            records_management=$(echo "$event_selectors" | grep -c "\"ReadWriteType\"")
            
            if [ "$records_management" -gt 0 ]; then
                failed_login_details+="<li><span class='green'>$trail_name - Active, recording authentication events</span> (Multi-region: $is_multi_region)</li>"
                failed_login_monitoring=true
            else
                failed_login_details+="<li><span class='yellow'>$trail_name - Active, but may not be recording all authentication events</span> (Multi-region: $is_multi_region)</li>"
            fi
        else
            failed_login_details+="<li><span class='red'>$trail_name - Inactive (not currently logging)</span> (Multi-region: $is_multi_region)</li>"
        fi
    done <<< "$trails"
    
    failed_login_details+="</ul>"
    
    if [ "$failed_login_monitoring" = true ]; then
        failed_login_details+="<p><span class='green'>CloudTrail is configured to record authentication events, which can be used to monitor failed login attempts.</span></p>"
    else
        failed_login_details+="<p><span class='yellow'>CloudTrail may not be properly configured to monitor all authentication events. Verify CloudTrail settings.</span></p>"
    fi
else
    failed_login_details+="<p><span class='red'>No CloudTrail trails found in this region. Failed login attempt monitoring may be insufficient.</span></p>"
fi

failed_login_details+="<p><strong>AWS Console Lockout Information:</strong></p>
<p>AWS Management Console has built-in protection that temporarily locks accounts after too many failed login attempts. However, this does not apply to API access using access keys.</p>
<p>For comprehensive protection:</p>
<ul>
    <li>Use CloudWatch Alarms to monitor CloudTrail events for multiple failed authentication attempts</li>
    <li>Implement automated responses via AWS Lambda functions</li>
    <li>Consider implementing a custom solution that can enforce lockout for API access</li>
</ul>"

add_check_item "$OUTPUT_FILE" "warning" "8.3.4 - Invalid Authentication Attempts" \
    "<p>Verification of account lockout mechanisms.</p>
    <p>This check requires manual verification to ensure:</p>
    <ul>
        <li>Accounts are locked after a maximum of 10 failed authentication attempts.</li>
        <li>Lockout duration is a minimum of 30 minutes or until reset by an administrator.</li>
        <li>Authentication attempts are properly tracked and logged.</li>
    </ul>
    $failed_login_details" \
    "Monitor failed login attempts using CloudTrail. Consider implementing a custom solution to detect and respond to multiple failed authentication attempts."

close_section "$OUTPUT_FILE"

# Requirement 8.6: Application and system account management
add_section "$OUTPUT_FILE" "req-8.6" "Requirement 8.6: Use of application and system accounts and associated authentication factors is strictly managed" "none"

add_check_item "$OUTPUT_FILE" "warning" "8.6.1 - Interactive Use of System Accounts" \
    "<p>Verification that accounts used by systems or applications that can be used for interactive login are properly managed.</p>
    <p>This check requires manual verification that:</p>
    <ul>
        <li>Interactive use is prevented unless needed for exceptional circumstances</li>
        <li>Interactive use is limited to the time needed for the exceptional circumstance</li>
        <li>Business justification for interactive use is documented</li>
        <li>Interactive use is explicitly approved by management</li>
        <li>Individual user identity is confirmed before access is granted</li>
        <li>Every action taken is attributable to an individual user</li>
    </ul>
    <p>AWS IAM roles and service accounts should be configured to prevent interactive use.</p>" \
    "Use IAM roles for EC2 instances and AWS services instead of IAM users with access keys. Restrict permission boundaries on all service roles and implement logging to track any interactive use of service accounts."

check_user_access_reviews "$OUTPUT_FILE"
((total_checks++))

# Check for hardcoded credentials in automation
echo "Checking for potential hardcoded credentials in AWS resources..."

# Check Lambda functions for potential hardcoded credentials
lambda_functions=$(aws lambda list-functions --region "$REGION" --query 'Functions[*].FunctionName' --output text 2>/dev/null)
lambda_count=$(echo "$lambda_functions" | wc -w)
has_hardcoded_risk=false
hardcoded_creds_details="<p><strong>Analysis of potential locations for hardcoded credentials:</strong></p>"

if [ -n "$lambda_functions" ]; then
    hardcoded_creds_details+="<p>Lambda Functions: Found ${lambda_count} Lambda functions that may contain application code.</p>"
    hardcoded_creds_details+="<p><span class='yellow'>Lambda functions may contain hardcoded credentials in environment variables or function code. Manual review of Lambda environment variables and code is recommended.</span></p>"
    has_hardcoded_risk=true
else
    hardcoded_creds_details+="<p>Lambda Functions: No Lambda functions found in this region.</p>"
fi

# Check CloudFormation stacks for potential hardcoded credentials
cf_stacks=$(aws cloudformation list-stacks --region "$REGION" --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE --query 'StackSummaries[*].[StackName]' --output text 2>/dev/null)

if [ -n "$cf_stacks" ]; then
    hardcoded_creds_details+="<p>CloudFormation Stacks: Found CloudFormation stacks that may contain hardcoded secrets.</p>"
    hardcoded_creds_details+="<p><span class='yellow'>CloudFormation templates may contain hardcoded credentials. Manual review of templates is recommended.</span></p>"
    has_hardcoded_risk=true
else
    hardcoded_creds_details+="<p>CloudFormation Stacks: No active CloudFormation stacks found in this region.</p>"
fi

# Check for usage of AWS Secrets Manager and Parameter Store
secrets_manager=$(aws secretsmanager list-secrets --region "$REGION" --query 'SecretList[*].[Name]' --output text 2>/dev/null)
parameter_store=$(aws ssm describe-parameters --region "$REGION" --query 'Parameters[*].[Name]' --output text 2>/dev/null)

if [ -n "$secrets_manager" ] || [ -n "$parameter_store" ]; then
    hardcoded_creds_details+="<p><span class='green'>The following secure credential storage services are in use:</span></p><ul>"
    
    if [ -n "$secrets_manager" ]; then
        secret_count=$(echo "$secrets_manager" | wc -l)
        hardcoded_creds_details+="<li>AWS Secrets Manager: $secret_count secrets found</li>"
    fi
    
    if [ -n "$parameter_store" ]; then
        param_count=$(echo "$parameter_store" | wc -l)
        hardcoded_creds_details+="<li>AWS Systems Manager Parameter Store: $param_count parameters found</li>"
    fi
    
    hardcoded_creds_details+="</ul>"
else
    hardcoded_creds_details+="<p><span class='yellow'>No usage of AWS Secrets Manager or Parameter Store detected. This may indicate that application credentials are not being stored securely.</span></p>"
    has_hardcoded_risk=true
fi

hardcoded_creds_details+="<p>Note: This check only identifies potential areas of risk. A complete review requires manual code examination.</p>"

add_check_item "$OUTPUT_FILE" "warning" "8.6.2 - Hardcoded Credentials" \
    "<p>Verification that passwords/passphrases for application and system accounts are not hardcoded.</p>
    <p>This check identifies potential areas where hardcoded credentials might exist, but a complete assessment requires manual code review.</p>
    $hardcoded_creds_details" \
    "Use AWS Secrets Manager or AWS Systems Manager Parameter Store to securely store and manage application credentials. Conduct a code review to identify and remediate any hardcoded credentials in application code, configuration files, or infrastructure templates."

close_section "$OUTPUT_FILE"

# Calculate check statistics
if [ $total_checks -eq 0 ]; then
    total_checks=4  # Include manual checks in the count
    passed_checks=0
    failed_checks=0
    warning_checks=4
fi

# Finalize the report
finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"

# Display completion message
echo -e "\nCompleted PCI DSS v4.0.1 Requirement $REQUIREMENT_NUMBER assessment."
echo "Total checks: $total_checks"
echo "Passed: $passed_checks"
echo "Failed: $failed_checks"
echo "Warning: $warning_checks"
echo "Report saved to: $OUTPUT_FILE"

# Open the report in the default browser (macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$OUTPUT_FILE"
else
    echo "Please open the report file in your browser to view the results."
fi
