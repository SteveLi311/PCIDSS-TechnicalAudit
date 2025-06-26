#!/usr/bin/env bash

# PCI DSS v4.0 AWS Compliance Audit Script
# This script checks AWS configurations for compliance with PCI DSS v4.0 requirements

# Set output colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create output directory if it doesn't exist
REPORT_DIR="pci_audit_results"
mkdir -p "$REPORT_DIR"

# Main report file
REPORT_FILE="$REPORT_DIR/pci_dss_v4_audit_report_$(date +%Y%m%d_%H%M%S).txt"

# Log function
log() {
  echo -e "$1" | tee -a "$REPORT_FILE"
}

# Section header function
section_header() {
  log "\n${BLUE}====================================================================${NC}"
  log "${BLUE}= $1${NC}"
  log "${BLUE}====================================================================${NC}"
}

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
  log "${RED}AWS CLI is not installed. Please install it first.${NC}"
  exit 1
fi

# Check AWS credentials
if ! aws sts get-caller-identity &> /dev/null; then
  log "${RED}AWS credentials are not properly configured. Please run 'aws configure'.${NC}"
  exit 1
fi

# Get account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)

# Get current region from AWS CLI configuration
CURRENT_REGION=$(aws configure get region 2>/dev/null || echo "unknown")

# Get all available regions
AVAILABLE_REGIONS=$(aws ec2 describe-regions --query "Regions[].RegionName" --output text)

# Create an array of regions to check
if [[ "$1" == "--all-regions" ]]; then
  # Use all available regions if --all-regions flag is provided
  readarray -t REGIONS_TO_CHECK <<< "$AVAILABLE_REGIONS"
  REGIONS_MESSAGE="All AWS regions"
else
  # Use only the current region by default
  REGIONS_TO_CHECK=("$CURRENT_REGION")
  REGIONS_MESSAGE="Current region ($CURRENT_REGION only). Use --all-regions for a complete scan."
fi

# Start report
log "PCI DSS v4.0 AWS Compliance Audit Report"
log "Generated on: $(date)"
log "AWS Account: $ACCOUNT_ID"
log "Checking: $REGIONS_MESSAGE"
log "-------------------------------------------------------------------"

##################################################################################
# Requirement 1: Install and maintain network security controls
##################################################################################
section_header "PCI DSS Requirement 1: Network Security Controls"

# Check security groups with open ports
check_open_security_groups() {
  log "\n${YELLOW}1.i Checking for security groups allowing all IPs on any port...${NC}"
  
  # Create a temporary file to store detailed results
  sg_details_file="$REPORT_DIR/open_security_groups.txt"
  echo "Security Groups allowing all IPs on any port:" > "$sg_details_file"
  
  # Counter for non-compliant security groups
  open_sg_count=0
  
  # Check each region
  for region in "${REGIONS_TO_CHECK[@]}"; do
    log "  Checking region: $region..."
    
    # Get all security groups in this region
    security_groups=$(aws ec2 describe-security-groups --region "$region" --query 'SecurityGroups[*].[GroupId,GroupName]' --output text 2>/dev/null || echo "")
    
    # Skip if no security groups found in this region
    if [[ -z "$security_groups" ]]; then
      continue
    fi
    
    while read -r sg_id sg_name; do
      # Skip if line is empty
      if [[ -z "$sg_id" ]]; then
        continue
      fi
      
      # Check for inbound rules with 0.0.0.0/0
      inbound_rules=$(aws ec2 describe-security-groups --region "$region" --group-ids "$sg_id" --query 'SecurityGroups[*].IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]' --output json 2>/dev/null || echo "[]")
      
      # Skip if no open inbound rules
      if [[ "$inbound_rules" == "[]" ]]; then
        continue
      fi
      
      # Process each rule
      open_rules=$(echo "$inbound_rules" | jq -r '.[].[] | "\(.IpProtocol) \(.FromPort) \(.ToPort)"')
      
      if [[ -n "$open_rules" ]]; then
        ((open_sg_count++))
        echo "- Security Group: $sg_id ($sg_name) [Region: $region]" >> "$sg_details_file"
        echo "  Open inbound rules:" >> "$sg_details_file"
        
        while read -r protocol from_port to_port; do
          # Handle special case for all traffic
          if [[ "$protocol" == "-1" ]]; then
            echo "    * ALL TRAFFIC (ALL PORTS)" >> "$sg_details_file"
          # Handle single port
          elif [[ "$from_port" == "$to_port" ]]; then
            echo "    * $protocol port $from_port" >> "$sg_details_file"
          # Handle port range
          else
            echo "    * $protocol ports $from_port-$to_port" >> "$sg_details_file"
          fi
        done <<< "$open_rules"
        
        echo "" >> "$sg_details_file"
      fi
    done <<< "$security_groups"
  done
  
  if [[ $open_sg_count -gt 0 ]]; then
    log "${RED}FAIL: Found $open_sg_count security groups with open access to all IPs.${NC}"
    log "      See $sg_details_file for details."
  else
    log "${GREEN}PASS: No security groups allow unrestricted access from all IPs.${NC}"
  fi
}

# Check for protocols with unrestricted public access
check_public_protocols() {
  log "\n${YELLOW}1.ii Checking for protocols with unrestricted public access...${NC}"
  
  # List of sensitive administrative and database ports to monitor
  declare -A monitored_ports=(
    ["21"]="FTP"
    ["23"]="Telnet"
    ["3306"]="MySQL"
    ["1433"]="MSSQL"
    ["3389"]="RDP"
    ["20"]="FTP-Data"
    ["22"]="SSH"
    ["25"]="SMTP"
    ["110"]="POP3"
    ["143"]="IMAP"
  )
  
  # Create a temporary file to store detailed results
  public_protocols_file="$REPORT_DIR/public_protocols.txt"
  echo "Security Groups allowing sensitive protocols with unrestricted public access:" > "$public_protocols_file"
  
  # Counter for non-compliant rules
  public_protocol_count=0
  
  # Check each region
  for region in "${REGIONS_TO_CHECK[@]}"; do
    log "  Checking region: $region..."
    
    # Get all security groups in this region
    security_groups=$(aws ec2 describe-security-groups --region "$region" --query 'SecurityGroups[*].[GroupId,GroupName]' --output text 2>/dev/null || echo "")
    
    # Skip if no security groups found in this region
    if [[ -z "$security_groups" ]]; then
      continue
    fi
    
    while read -r sg_id sg_name; do
      # Skip if line is empty
      if [[ -z "$sg_id" ]]; then
        continue
      fi
      
      # Check for inbound rules with 0.0.0.0/0
      inbound_rules=$(aws ec2 describe-security-groups --region "$region" --group-ids "$sg_id" --query 'SecurityGroups[*].IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]' --output json 2>/dev/null || echo "[]")
      
      # Skip if no open inbound rules
      if [[ "$inbound_rules" == "[]" ]]; then
        continue
      fi
      
      has_public_protocol=false
      public_protocols=""
      
      # Process each rule
      rule_details=$(echo "$inbound_rules" | jq -r '.[].[] | "\(.IpProtocol) \(.FromPort) \(.ToPort)"')
      
      while read -r protocol from_port to_port; do
        # Skip if line is empty
        if [[ -z "$protocol" ]]; then
          continue
        fi
        
        # Skip if not TCP or UDP
        if [[ "$protocol" != "tcp" && "$protocol" != "udp" && "$protocol" != "-1" ]]; then
          continue
        fi
        
        # Check all traffic rule
        if [[ "$protocol" == "-1" ]]; then
          has_public_protocol=true
          public_protocols+="    * ALL TRAFFIC (Including all administrative protocols)\n"
          break
        fi
        
        # Check port range
        if [[ -n "$from_port" && -n "$to_port" ]]; then
          for port in "${!monitored_ports[@]}"; do
            if (( from_port <= port && port <= to_port )); then
              has_public_protocol=true
              public_protocols+="    * ${monitored_ports[$port]} ($protocol/$port)\n"
            fi
          done
        fi
      done <<< "$rule_details"
      
      if [[ "$has_public_protocol" == "true" ]]; then
        ((public_protocol_count++))
        echo "- Security Group: $sg_id ($sg_name) [Region: $region]" >> "$public_protocols_file"
        echo "  Publicly exposed protocols:" >> "$public_protocols_file"
        echo -e "$public_protocols" >> "$public_protocols_file"
        echo "" >> "$public_protocols_file"
      fi
    done <<< "$security_groups"
  done
  
  if [[ $public_protocol_count -gt 0 ]]; then
    log "${RED}FAIL: Found $public_protocol_count security groups allowing sensitive protocols with unrestricted public access.${NC}"
    log "      See $public_protocols_file for details."
  else
    log "${GREEN}PASS: No security groups allow sensitive protocols with unrestricted public access.${NC}"
  fi
}

# Execute Requirement 1 checks
check_open_security_groups
check_public_protocols

##################################################################################
# Requirement 3: Protect stored account data
##################################################################################
section_header "PCI DSS Requirement 3: Key Management"

# Check for keys without rotation enabled
check_key_rotation() {
  log "\n${YELLOW}3.i Checking for KMS keys without rotation settings...${NC}"
  
  # Create a temporary file to store detailed results
  rotation_details_file="$REPORT_DIR/keys_without_rotation.txt"
  echo "KMS Keys without rotation enabled:" > "$rotation_details_file"
  
  # Counter for non-compliant keys
  no_rotation_count=0
  
  # Check each region
  for region in "${REGIONS_TO_CHECK[@]}"; do
    log "  Checking region: $region..."
    
    # Get all customer-managed KMS keys (excluding AWS managed keys)
    kms_keys=$(aws kms list-keys --region "$region" --query 'Keys[*].KeyId' --output text 2>/dev/null || echo "")
    
    # Skip if no keys found in this region
    if [[ -z "$kms_keys" ]]; then
      continue
    fi
    
    while read -r key_id; do
      # Skip if line is empty
      if [[ -z "$key_id" ]]; then
        continue
      fi
      
      # Skip AWS managed keys
      key_info=$(aws kms describe-key --region "$region" --key-id "$key_id" --query 'KeyMetadata.[Description,KeyManager,KeyState]' --output text 2>/dev/null || echo "")
      read -r description key_manager key_state <<< "$key_info"
      
      if [[ "$key_manager" == "AWS" || "$key_state" != "Enabled" ]]; then
        continue
      fi
      
      # Check rotation status
      rotation_enabled=$(aws kms get-key-rotation-status --region "$region" --key-id "$key_id" --query 'KeyRotationEnabled' --output text 2>/dev/null || echo "false")
      
      if [[ "$rotation_enabled" == "false" ]]; then
        ((no_rotation_count++))
        key_name=$(aws kms list-aliases --region "$region" --key-id "$key_id" --query 'Aliases[0].AliasName' --output text 2>/dev/null || echo "No alias")
        echo "- Key ID: $key_id [Region: $region]" >> "$rotation_details_file"
        echo "  Alias: $key_name" >> "$rotation_details_file"
        echo "  Description: $description" >> "$rotation_details_file"
        echo "" >> "$rotation_details_file"
      fi
    done <<< "$kms_keys"
  done
  
  if [[ $no_rotation_count -gt 0 ]]; then
    log "${RED}FAIL: Found $no_rotation_count KMS keys without rotation enabled.${NC}"
    log "      See $rotation_details_file for details."
  else
    log "${GREEN}PASS: All customer-managed KMS keys have rotation enabled.${NC}"
  fi
}

# Check for unprotected secrets
check_unprotected_secrets() {
  log "\n${YELLOW}3.ii Checking for secrets not protected by KMS...${NC}"
  
  # Create a temporary file to store detailed results
  unprotected_secrets_file="$REPORT_DIR/unprotected_secrets.txt"
  echo "Secrets not protected by a custom KMS key:" > "$unprotected_secrets_file"
  
  # Counter for non-compliant secrets
  unprotected_count=0
  
  # Check each region
  for region in "${REGIONS_TO_CHECK[@]}"; do
    log "  Checking region: $region..."
    
    # Check AWS Secrets Manager
    secrets=$(aws secretsmanager list-secrets --region "$region" --query 'SecretList[*].[ARN,Name,KmsKeyId]' --output text 2>/dev/null || echo "")
    
    if [[ -n "$secrets" ]]; then
      while read -r arn name kms_key_id; do
        # Skip if line is empty
        if [[ -z "$arn" ]]; then
          continue
        fi
        
        # If KmsKeyId is empty or equals to "alias/aws/secretsmanager" (default key)
        if [[ -z "$kms_key_id" || "$kms_key_id" == "alias/aws/secretsmanager" ]]; then
          ((unprotected_count++))
          echo "- Secret: $name [Region: $region]" >> "$unprotected_secrets_file"
          echo "  ARN: $arn" >> "$unprotected_secrets_file"
          echo "  KMS Key: Default AWS managed key (not customized)" >> "$unprotected_secrets_file"
          echo "" >> "$unprotected_secrets_file"
        fi
      done <<< "$secrets"
    fi
    
    # Check SSM Parameter Store for SecureString parameters
    parameters=$(aws ssm describe-parameters --region "$region" --parameter-filters "Key=Type,Values=SecureString" --query 'Parameters[*].[Name,KeyId]' --output text 2>/dev/null || echo "")
    
    if [[ -n "$parameters" ]]; then
      while read -r param_name key_id; do
        # Skip if line is empty
        if [[ -z "$param_name" ]]; then
          continue
        fi
        
        # If KeyId is empty or equals to "alias/aws/ssm" (default key)
        if [[ -z "$key_id" || "$key_id" == "alias/aws/ssm" ]]; then
          ((unprotected_count++))
          echo "- SSM Parameter: $param_name [Region: $region]" >> "$unprotected_secrets_file"
          echo "  KMS Key: Default AWS managed key (not customized)" >> "$unprotected_secrets_file"
          echo "" >> "$unprotected_secrets_file"
        fi
      done <<< "$parameters"
    fi
  done
  
  if [[ $unprotected_count -gt 0 ]]; then
    log "${RED}FAIL: Found $unprotected_count secrets not protected by custom KMS keys.${NC}"
    log "      See $unprotected_secrets_file for details."
  else
    log "${GREEN}PASS: All secrets are protected by custom KMS keys.${NC}"
  fi
}

# Execute Requirement 3 checks
check_key_rotation
check_unprotected_secrets

##################################################################################
# Requirement 4: Protect cardholder data with strong cryptography during transmission
##################################################################################
section_header "PCI DSS Requirement 4: Open, Public Transfer"

# Check for ELBs using outdated TLS
check_outdated_tls() {
  log "\n${YELLOW}4.i Checking for load balancers using TLS 1.0...${NC}"
  
  # Create a temporary file to store detailed results
  outdated_tls_file="$REPORT_DIR/outdated_tls.txt"
  echo "Load Balancers using TLS 1.0:" > "$outdated_tls_file"
  
  # Counter for non-compliant LBs
  outdated_tls_count=0
  
  # Check each region
  for region in "${REGIONS_TO_CHECK[@]}"; do
    log "  Checking region: $region..."
    
    # Check Classic Load Balancers
    classic_lbs=$(aws elb describe-load-balancers --region "$region" --query 'LoadBalancerDescriptions[*].LoadBalancerName' --output text 2>/dev/null || echo "")
    
    if [[ -n "$classic_lbs" ]]; then
      while read -r lb_name; do
        # Skip if line is empty
        if [[ -z "$lb_name" ]]; then
          continue
        fi
        
        # Get the SSL policies
        policies=$(aws elb describe-load-balancer-policies --region "$region" --load-balancer-name "$lb_name" --query 'PolicyDescriptions[?PolicyTypeName==`SSLNegotiationPolicyType`].PolicyAttributeDescriptions[?AttributeName==`Protocol-TLSv1`].AttributeValue' --output text 2>/dev/null || echo "")
        
        if [[ "$policies" == *"true"* ]]; then
          ((outdated_tls_count++))
          echo "- Classic Load Balancer: $lb_name [Region: $region]" >> "$outdated_tls_file"
          echo "  Protocol: TLSv1.0 enabled" >> "$outdated_tls_file"
          echo "" >> "$outdated_tls_file"
        fi
      done <<< "$classic_lbs"
    fi
    
    # Check Application Load Balancers and Network Load Balancers
    v2_lbs=$(aws elbv2 describe-load-balancers --region "$region" --query 'LoadBalancers[*].[LoadBalancerArn,LoadBalancerName,Type]' --output text 2>/dev/null || echo "")
    
    if [[ -n "$v2_lbs" ]]; then
      while read -r lb_arn lb_name lb_type; do
        # Skip if line is empty
        if [[ -z "$lb_arn" ]]; then
          continue
        fi
        
        # Skip Network Load Balancers (they terminate TLS at the target level)
        if [[ "$lb_type" == "network" ]]; then
          continue
        fi
        
        # Get the listeners
        listeners=$(aws elbv2 describe-listeners --region "$region" --load-balancer-arn "$lb_arn" --query 'Listeners[?Protocol==`HTTPS`].ListenerArn' --output text 2>/dev/null || echo "")
        
        while read -r listener_arn; do
          # Skip if no HTTPS listeners or line is empty
          if [[ -z "$listener_arn" ]]; then
            continue
          fi
          
          # Get SSL policy
          policy_name=$(aws elbv2 describe-listeners --region "$region" --listener-arn "$listener_arn" --query 'Listeners[0].SslPolicy' --output text 2>/dev/null || echo "")
          
          # Check if policy allows TLS 1.0
          if [[ "$policy_name" == "ELBSecurityPolicy-TLS-1-0"* || "$policy_name" == "ELBSecurityPolicy-2015-05" ]]; then
            ((outdated_tls_count++))
            echo "- Application Load Balancer: $lb_name [Region: $region]" >> "$outdated_tls_file"
            echo "  SSL Policy: $policy_name (supports TLSv1.0)" >> "$outdated_tls_file"
            echo "" >> "$outdated_tls_file"
          fi
        done <<< "$listeners"
      done <<< "$v2_lbs"
    fi
  done
  
  if [[ $outdated_tls_count -gt 0 ]]; then
    log "${RED}FAIL: Found $outdated_tls_count load balancers using TLS 1.0.${NC}"
    log "      See $outdated_tls_file for details."
  else
    log "${GREEN}PASS: No load balancers are using TLS 1.0.${NC}"
  fi
}

# Check for weak ciphers
check_weak_ciphers() {
  log "\n${YELLOW}4.ii Checking for load balancers using weak ciphers...${NC}"
  
  # List of weak ciphers to check
  weak_ciphers=(
    "DES-CBC3-SHA"
    "RC4-MD5"
    "EXP-RC4-MD5"
    "EXP-DES-CBC-SHA"
    "EXP-EDH-RSA-DES-CBC-SHA"
    "EXP-RC2-CBC-MD5"
  )
  
  # Create a temporary file to store detailed results
  weak_cipher_file="$REPORT_DIR/weak_ciphers.txt"
  echo "Load Balancers using weak ciphers:" > "$weak_cipher_file"
  
  # Counter for non-compliant LBs
  weak_cipher_count=0
  
  # Check each region
  for region in "${REGIONS_TO_CHECK[@]}"; do
    log "  Checking region: $region..."
    
    # Check Classic Load Balancers
    classic_lbs=$(aws elb describe-load-balancers --region "$region" --query 'LoadBalancerDescriptions[*].LoadBalancerName' --output text 2>/dev/null || echo "")
    
    if [[ -n "$classic_lbs" ]]; then
      while read -r lb_name; do
        # Skip if line is empty
        if [[ -z "$lb_name" ]]; then
          continue
        fi
        
        # Get all SSL policies for this load balancer
        policy_names=$(aws elb describe-load-balancer-policies --region "$region" --load-balancer-name "$lb_name" --query 'PolicyDescriptions[?PolicyTypeName==`SSLNegotiationPolicyType`].PolicyName' --output text 2>/dev/null || echo "")
        
        for policy_name in $policy_names; do
          # Skip if policy name is empty
          if [[ -z "$policy_name" ]]; then
            continue
          fi
          
          weak_found=false
          policy_weak_ciphers=""
          
          # Check each weak cipher
          for cipher in "${weak_ciphers[@]}"; do
            cipher_enabled=$(aws elb describe-load-balancer-policies --region "$region" --load-balancer-name "$lb_name" --policy-names "$policy_name" --query "PolicyDescriptions[0].PolicyAttributeDescriptions[?AttributeName=='$cipher'].AttributeValue" --output text 2>/dev/null || echo "")
            
            if [[ "$cipher_enabled" == "true" ]]; then
              weak_found=true
              policy_weak_ciphers+="    * $cipher\n"
            fi
          done
          
          if [[ "$weak_found" == "true" ]]; then
            ((weak_cipher_count++))
            echo "- Classic Load Balancer: $lb_name [Region: $region]" >> "$weak_cipher_file"
            echo "  Policy: $policy_name" >> "$weak_cipher_file"
            echo "  Weak ciphers:" >> "$weak_cipher_file"
            echo -e "$policy_weak_ciphers" >> "$weak_cipher_file"
            echo "" >> "$weak_cipher_file"
          fi
        done
      done <<< "$classic_lbs"
    fi
    
    # Check Application Load Balancers
    v2_lbs=$(aws elbv2 describe-load-balancers --region "$region" --query 'LoadBalancers[*].[LoadBalancerArn,LoadBalancerName,Type]' --output text 2>/dev/null || echo "")
    
    if [[ -n "$v2_lbs" ]]; then
      while read -r lb_arn lb_name lb_type; do
        # Skip if line is empty
        if [[ -z "$lb_arn" ]]; then
          continue
        fi
        
        # Skip Network Load Balancers
        if [[ "$lb_type" == "network" ]]; then
          continue
        fi
        
        # Get the listeners
        listeners=$(aws elbv2 describe-listeners --region "$region" --load-balancer-arn "$lb_arn" --query 'Listeners[?Protocol==`HTTPS`].[ListenerArn,SslPolicy]' --output text 2>/dev/null || echo "")
        
        while read -r listener_arn policy_name; do
          # Skip if no HTTPS listeners or line is empty
          if [[ -z "$listener_arn" || -z "$policy_name" ]]; then
            continue
          fi
          
          # Check for potentially weak policies
          if [[ "$policy_name" == "ELBSecurityPolicy-TLS-1-0"* || 
                "$policy_name" == "ELBSecurityPolicy-2015-05" || 
                "$policy_name" == "ELBSecurityPolicy-2016-08" ]]; then
            ((weak_cipher_count++))
            echo "- Application Load Balancer: $lb_name [Region: $region]" >> "$weak_cipher_file"
            echo "  SSL Policy: $policy_name" >> "$weak_cipher_file"
            echo "  Note: This policy may include weak ciphers." >> "$weak_cipher_file"
            echo "" >> "$weak_cipher_file"
          fi
        done <<< "$listeners"
      done <<< "$v2_lbs"
    fi
  done
  
  if [[ $weak_cipher_count -gt 0 ]]; then
    log "${RED}FAIL: Found $weak_cipher_count load balancers using weak ciphers.${NC}"
    log "      See $weak_cipher_file for details."
  else
    log "${GREEN}PASS: No load balancers are using weak ciphers.${NC}"
  fi
}

# Execute Requirement 4 checks
check_outdated_tls
check_weak_ciphers

##################################################################################
# Requirement 8: Identify users and authenticate access
##################################################################################
section_header "PCI DSS Requirement 8: User Password/2FA"

# Check for IAM password policy
check_password_policy() {
  log "\n${YELLOW}8.i Checking IAM password policy for minimum length of 12 characters...${NC}"
  
  # Get the password policy
  password_policy=$(aws iam get-account-password-policy --query 'PasswordPolicy.MinimumPasswordLength' --output text 2>/dev/null || echo "No password policy")
  
  # Create a temporary file to store detailed results
  password_policy_file="$REPORT_DIR/password_policy.txt"
  echo "IAM Password Policy:" > "$password_policy_file"
  
  if [[ "$password_policy" == "No password policy" ]]; then
    log "${RED}FAIL: No IAM password policy is configured.${NC}"
    echo "- No password policy is configured for this account." >> "$password_policy_file"
  else
    echo "- Minimum password length: $password_policy characters" >> "$password_policy_file"
    
    # Check if password policy meets requirements
    if [[ $password_policy -lt 12 ]]; then
      log "${RED}FAIL: IAM password policy minimum length ($password_policy) is less than required (12).${NC}"
    else
      log "${GREEN}PASS: IAM password policy minimum length ($password_policy) meets or exceeds required length (12).${NC}"
    fi
    
    # Get additional password policy details
    full_policy=$(aws iam get-account-password-policy --output json)
    
    # Extract and display additional policy settings
    require_symbols=$(echo "$full_policy" | jq -r '.PasswordPolicy.RequireSymbols')
    require_numbers=$(echo "$full_policy" | jq -r '.PasswordPolicy.RequireNumbers')
    require_uppercase=$(echo "$full_policy" | jq -r '.PasswordPolicy.RequireUppercaseCharacters')
    require_lowercase=$(echo "$full_policy" | jq -r '.PasswordPolicy.RequireLowercaseCharacters')
    allow_users_change=$(echo "$full_policy" | jq -r '.PasswordPolicy.AllowUsersToChangePassword')
    max_age=$(echo "$full_policy" | jq -r '.PasswordPolicy.MaxPasswordAge // "No maximum age"')
    password_reuse=$(echo "$full_policy" | jq -r '.PasswordPolicy.PasswordReusePrevention // "No reuse prevention"')
    
    echo "- Require symbols: $require_symbols" >> "$password_policy_file"
    echo "- Require numbers: $require_numbers" >> "$password_policy_file"
    echo "- Require uppercase characters: $require_uppercase" >> "$password_policy_file"
    echo "- Require lowercase characters: $require_lowercase" >> "$password_policy_file"
    echo "- Allow users to change password: $allow_users_change" >> "$password_policy_file"
    echo "- Maximum password age: $max_age" >> "$password_policy_file"
    echo "- Password reuse prevention: $password_reuse" >> "$password_policy_file"
  fi
  
  log "      See $password_policy_file for complete password policy details."
}

# Check for IAM users without MFA
check_mfa_enabled() {
  log "\n${YELLOW}8.ii Checking for IAM users without MFA enabled...${NC}"
  
  # Get all IAM users
  iam_users=$(aws iam list-users --query 'Users[*].[UserName,Arn,UserId]' --output text)
  
  # Counter for non-compliant users
  no_mfa_count=0
  
  # Create a temporary file to store detailed results
  no_mfa_file="$REPORT_DIR/users_without_mfa.txt"
  echo "IAM Users without MFA enabled:" > "$no_mfa_file"
  
  while read -r username arn user_id; do
    # Skip if line is empty
    if [[ -z "$username" ]]; then
      continue
    fi
    
    # Check if MFA is enabled
    mfa_devices=$(aws iam list-mfa-devices --user-name "$username" --query 'MFADevices[0].SerialNumber' --output text 2>/dev/null || echo "")
    
    if [[ -z "$mfa_devices" || "$mfa_devices" == "None" ]]; then
      ((no_mfa_count++))
      echo "- User: $username" >> "$no_mfa_file"
      echo "  ARN: $arn" >> "$no_mfa_file"
      
      # Check if user has a password (console access)
      has_password=$(aws iam get-login-profile --user-name "$username" --query 'LoginProfile.UserName' --output text 2>/dev/null || echo "")
      
      if [[ -n "$has_password" ]]; then
        echo "  Console Access: Yes (has password)" >> "$no_mfa_file"
      else
        echo "  Console Access: No (programmatic access only)" >> "$no_mfa_file"
      fi
      
      # Check last activity date
      last_used=$(aws iam get-user --user-name "$username" --query 'User.PasswordLastUsed' --output text 2>/dev/null || echo "Never used")
      echo "  Last Console Login: $last_used" >> "$no_mfa_file"
      
      # Check access keys
      access_keys=$(aws iam list-access-keys --user-name "$username" --query 'AccessKeyMetadata[*].[AccessKeyId,Status,CreateDate]' --output text)
      
      if [[ -n "$access_keys" ]]; then
        echo "  Access Keys:" >> "$no_mfa_file"
        while read -r key_id key_status key_create_date; do
          # Skip if line is empty
          if [[ -z "$key_id" ]]; then
            continue
          fi
          
          echo "    * Key ID: $key_id (Status: $key_status, Created: $key_create_date)" >> "$no_mfa_file"
          
          # Get last used info for this key
          key_last_used=$(aws iam get-access-key-last-used --access-key-id "$key_id" --query 'AccessKeyLastUsed.LastUsedDate' --output text 2>/dev/null || echo "Never used")
          echo "      Last Used: $key_last_used" >> "$no_mfa_file"
        done <<< "$access_keys"
      else
        echo "  Access Keys: None" >> "$no_mfa_file"
      fi
      
      echo "" >> "$no_mfa_file"
    fi
  done <<< "$iam_users"
  
  if [[ $no_mfa_count -gt 0 ]]; then
    log "${RED}FAIL: Found $no_mfa_count IAM users without MFA enabled.${NC}"
    log "      See $no_mfa_file for details."
  else
    log "${GREEN}PASS: All IAM users have MFA enabled.${NC}"
  fi
}

# Execute Requirement 8 checks
check_password_policy
check_mfa_enabled

##################################################################################
# Requirement 10: Log and monitor all access to system components
##################################################################################
section_header "PCI DSS Requirement 10: Log Management"

# Check S3 bucket retention policies for logs
check_log_retention() {
  log "\n${YELLOW}10.i Checking for log buckets without 1-year retention...${NC}"
  
  # Create a temporary file to store detailed results
  retention_file="$REPORT_DIR/log_retention.txt"
  echo "Log buckets without 1-year retention:" > "$retention_file"
  
  # Counter for non-compliant buckets
  insufficient_retention_count=0
  
  # Check each region
  for region in "${REGIONS_TO_CHECK[@]}"; do
    log "  Checking region: $region..."
    
    # Find buckets that might contain logs
    log_buckets=$(aws s3api list-buckets --region "$region" --query 'Buckets[?contains(Name, `log`) || contains(Name, `audit`) || contains(Name, `trail`)].Name' --output text 2>/dev/null || echo "")
    
    # Add CloudTrail buckets to the list
    cloudtrail_buckets=$(aws cloudtrail describe-trails --region "$region" --query 'trailList[*].S3BucketName' --output text 2>/dev/null || echo "")
    if [[ -n "$cloudtrail_buckets" ]]; then
      log_buckets+=" $cloudtrail_buckets"
    fi
    
    # Add buckets from CloudWatch Logs exports
    cwl_buckets=$(aws logs describe-export-tasks --region "$region" --query 'exportTasks[*].destination' --output text 2>/dev/null || echo "")
    if [[ -n "$cwl_buckets" ]]; then
      log_buckets+=" $cwl_buckets"
    fi
    
    # Remove duplicates
    log_buckets=$(echo "$log_buckets" | tr ' ' '\n' | sort -u | tr '\n' ' ')
    
    for bucket in $log_buckets; do
      # Skip if bucket is empty
      if [[ -z "$bucket" ]]; then
        continue
      fi
      
      # Check if bucket has a lifecycle policy
      lifecycle_rules=$(aws s3api get-bucket-lifecycle-configuration --region "$region" --bucket "$bucket" 2>/dev/null || echo "")
      
      if [[ -z "$lifecycle_rules" ]]; then
        ((insufficient_retention_count++))
        echo "- Bucket: $bucket [Region likely: $region]" >> "$retention_file"
        echo "  Issue: No lifecycle configuration found" >> "$retention_file"
        echo "" >> "$retention_file"
        continue
      fi
      
      # Check if any rule keeps objects for at least 1 year (365 days)
      has_sufficient_retention=false
      rule_details=""
      
      # Extract expiration days from each rule
      expiration_days=$(echo "$lifecycle_rules" | jq -r '.Rules[].Expiration.Days // 0')
      
      for days in $expiration_days; do
        if [[ $days -eq 0 || $days -ge 365 ]]; then
          has_sufficient_retention=true
          break
        fi
        rule_details+="    * Retention: $days days (less than required 365 days)\n"
      done
      
      # Check for transition to glacier (considered long-term retention)
      glacier_transitions=$(echo "$lifecycle_rules" | jq -r '.Rules[].Transitions[] | select(.StorageClass == "GLACIER" or .StorageClass == "DEEP_ARCHIVE") | .Days // 0')
      
      for days in $glacier_transitions; do
        if [[ $days -gt 0 ]]; then
          has_sufficient_retention=true
          break
        fi
      done
      
      if [[ "$has_sufficient_retention" == "false" ]]; then
        ((insufficient_retention_count++))
        echo "- Bucket: $bucket [Region likely: $region]" >> "$retention_file"
        echo "  Issue: Insufficient retention period" >> "$retention_file"
        echo -e "$rule_details" >> "$retention_file"
        echo "" >> "$retention_file"
      fi
    done
  done
  
  if [[ $insufficient_retention_count -gt 0 ]]; then
    log "${RED}FAIL: Found $insufficient_retention_count log buckets without 1-year retention.${NC}"
    log "      See $retention_file for details."
  else
    log "${GREEN}PASS: All log buckets have sufficient retention periods.${NC}"
  fi
}

# Execute Requirement 10 checks
check_log_retention

##################################################################################
# Summary report
##################################################################################
section_header "PCI DSS v4.0 Compliance Summary"

log "\nAudit completed. See detailed results in the '$REPORT_DIR' directory."
log "Full report saved to: $REPORT_FILE"
log "\nYou may want to address any failed compliance checks identified in this report."
log "Remember that this script provides an initial assessment and is not a substitute for a comprehensive PCI DSS audit."

echo
echo "USAGE:"
echo "  ./$(basename "$0")               # Check current region only"
echo "  ./$(basename "$0") --all-regions # Check all AWS regions (comprehensive)"
echo

exit 0
