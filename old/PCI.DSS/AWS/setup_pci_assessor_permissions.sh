#!/bin/bash

# Bash Script to Setup PCI DSS 4.0.1 Assessor Permissions
# This script creates an IAM user with the necessary permissions for PCI DSS assessment

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
USER_NAME="${USER_NAME:-pci-dss-assessor}"
POLICY_NAME="${POLICY_NAME:-PCI_DSS_4_0_1_Assessor}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI is not installed. Please install it first.${NC}"
    exit 1
fi

# Get Account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
if [ -z "$ACCOUNT_ID" ]; then
    echo -e "${RED}Error: Unable to get AWS Account ID. Please configure AWS credentials.${NC}"
    exit 1
fi

echo -e "${GREEN}Setting up PCI DSS 4.0.1 Assessor IAM User and Permissions${NC}"
echo -e "${YELLOW}Account ID: $ACCOUNT_ID${NC}"
echo -e "${YELLOW}User Name: $USER_NAME${NC}"
echo -e "${YELLOW}Policy Name: $POLICY_NAME${NC}"
echo -e "${YELLOW}Region: $REGION${NC}"

# Create temporary policy file
POLICY_FILE=$(mktemp /tmp/pci-assessor-policy.XXXXXX.json)
cat > "$POLICY_FILE" << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PCIDSSAssessorReadOnly",
      "Effect": "Allow",
      "Action": [
        "acm:Describe*",
        "acm:Get*",
        "acm:List*",
        "apigateway:GET",
        "apigateway:Get*",
        "apigateway:List*",
        "cloudformation:Describe*",
        "cloudformation:Get*",
        "cloudformation:List*",
        "cloudfront:Describe*",
        "cloudfront:Get*",
        "cloudfront:List*",
        "cloudtrail:Describe*",
        "cloudtrail:Get*",
        "cloudtrail:List*",
        "cloudtrail:LookupEvents",
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "config:BatchGetResourceConfig",
        "config:Describe*",
        "config:Get*",
        "config:List*",
        "config:SelectResourceConfig",
        "dms:Describe*",
        "dms:List*",
        "ec2:Describe*",
        "ec2:Get*",
        "ecr:BatchGetImage",
        "ecr:Describe*",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetLifecyclePolicy",
        "ecr:GetRepositoryPolicy",
        "ecr:List*",
        "ecs:Describe*",
        "ecs:List*",
        "eks:Describe*",
        "eks:List*",
        "elasticloadbalancing:Describe*",
        "events:Describe*",
        "events:List*",
        "guardduty:Get*",
        "guardduty:List*",
        "iam:GenerateCredentialReport",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:Get*",
        "iam:List*",
        "iam:SimulateCustomPolicy",
        "iam:SimulatePrincipalPolicy",
        "inspector:Describe*",
        "inspector:Get*",
        "inspector:List*",
        "inspector2:BatchGet*",
        "inspector2:Describe*",
        "inspector2:Get*",
        "inspector2:List*",
        "kms:Describe*",
        "kms:Get*",
        "kms:List*",
        "lambda:Get*",
        "lambda:List*",
        "logs:Describe*",
        "logs:FilterLogEvents",
        "logs:Get*",
        "logs:List*",
        "logs:StartQuery",
        "logs:StopQuery",
        "logs:TestMetricFilter",
        "macie2:Describe*",
        "macie2:Get*",
        "macie2:List*",
        "network-firewall:Describe*",
        "network-firewall:List*",
        "organizations:Describe*",
        "organizations:List*",
        "rds:Describe*",
        "rds:List*",
        "redshift:Describe*",
        "redshift:List*",
        "redshift:View*",
        "route53:Get*",
        "route53:List*",
        "route53:Test*",
        "route53domains:Get*",
        "route53domains:List*",
        "route53resolver:Get*",
        "route53resolver:List*",
        "s3:Get*",
        "s3:List*",
        "secretsmanager:Describe*",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:List*",
        "securityhub:BatchGet*",
        "securityhub:Describe*",
        "securityhub:Get*",
        "securityhub:List*",
        "shield:Describe*",
        "shield:Get*",
        "shield:List*",
        "sns:Get*",
        "sns:List*",
        "sqs:Get*",
        "sqs:List*",
        "ssm:Describe*",
        "ssm:Get*",
        "ssm:List*",
        "tag:Get*",
        "tag:List*",
        "trustedadvisor:Describe*",
        "trustedadvisor:Get*",
        "trustedadvisor:List*",
        "waf:Get*",
        "waf:List*",
        "waf-regional:Get*",
        "waf-regional:List*",
        "wafv2:Describe*",
        "wafv2:Get*",
        "wafv2:List*",
        "xray:Get*",
        "xray:List*"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# Function to check if a resource exists
check_exists() {
    local resource_type=$1
    local check_command=$2
    
    if $check_command 2>/dev/null | grep -q .; then
        return 0
    else
        return 1
    fi
}

# Create or verify IAM User
echo -e "\n${CYAN}Checking if user already exists...${NC}"
if check_exists "user" "aws iam get-user --user-name $USER_NAME"; then
    echo -e "${YELLOW}User '$USER_NAME' already exists. Skipping user creation.${NC}"
else
    echo -e "${CYAN}Creating IAM user '$USER_NAME'...${NC}"
    if aws iam create-user --user-name "$USER_NAME"; then
        echo -e "${GREEN}User created successfully.${NC}"
    else
        echo -e "${RED}Failed to create IAM user.${NC}"
        exit 1
    fi
fi

# Create or update IAM Policy
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"
echo -e "\n${CYAN}Checking if policy already exists...${NC}"

if check_exists "policy" "aws iam get-policy --policy-arn $POLICY_ARN"; then
    echo -e "${YELLOW}Policy '$POLICY_NAME' already exists.${NC}"
    echo -e "${CYAN}Creating new version of the policy...${NC}"
    
    if aws iam create-policy-version \
        --policy-arn "$POLICY_ARN" \
        --policy-document "file://$POLICY_FILE" \
        --set-as-default; then
        echo -e "${GREEN}Policy updated successfully.${NC}"
    else
        echo -e "${YELLOW}Note: Policy update may have failed due to version limit. Consider deleting old versions.${NC}"
    fi
else
    echo -e "${CYAN}Creating IAM policy '$POLICY_NAME'...${NC}"
    if aws iam create-policy \
        --policy-name "$POLICY_NAME" \
        --policy-document "file://$POLICY_FILE" \
        --description "Read-only permissions for PCI DSS 4.0.1 compliance assessment"; then
        echo -e "${GREEN}Policy created successfully.${NC}"
    else
        echo -e "${RED}Failed to create IAM policy.${NC}"
        exit 1
    fi
fi

# Attach Policy to User
echo -e "\n${CYAN}Attaching policy to user...${NC}"
if aws iam attach-user-policy \
    --user-name "$USER_NAME" \
    --policy-arn "$POLICY_ARN"; then
    echo -e "${GREEN}Policy attached successfully.${NC}"
else
    echo -e "${YELLOW}Policy may already be attached.${NC}"
fi

# Create Access Keys
echo -e "\n${CYAN}Creating access keys for programmatic access...${NC}"
ACCESS_KEY_OUTPUT=$(aws iam create-access-key --user-name "$USER_NAME" 2>/dev/null)

if [ $? -eq 0 ]; then
    ACCESS_KEY_ID=$(echo "$ACCESS_KEY_OUTPUT" | jq -r '.AccessKey.AccessKeyId')
    SECRET_ACCESS_KEY=$(echo "$ACCESS_KEY_OUTPUT" | jq -r '.AccessKey.SecretAccessKey')
    
    echo -e "${GREEN}Access Key Created Successfully:${NC}"
    echo -e "${YELLOW}Access Key ID: $ACCESS_KEY_ID${NC}"
    echo -e "${YELLOW}Secret Access Key: $SECRET_ACCESS_KEY${NC}"
    echo -e "${RED}IMPORTANT: Save these credentials securely. The secret access key will not be shown again.${NC}"
else
    echo -e "${YELLOW}Note: Access keys may already exist for this user (limit is 2 per user).${NC}"
fi

# Optional: Create Console Access
echo -e "\n${CYAN}Do you want to create console access for this user? (y/n)${NC}"
read -r CREATE_CONSOLE

if [[ "$CREATE_CONSOLE" =~ ^[Yy]$ ]]; then
    TEMP_PASSWORD="PCI-Temp-$(date +%s)!"
    
    echo -e "${CYAN}Creating console access...${NC}"
    if aws iam create-login-profile \
        --user-name "$USER_NAME" \
        --password "$TEMP_PASSWORD" \
        --password-reset-required 2>/dev/null; then
        echo -e "${GREEN}Console access created successfully.${NC}"
        echo -e "${YELLOW}Temporary Password: $TEMP_PASSWORD${NC}"
        echo -e "${YELLOW}Console URL: https://${ACCOUNT_ID}.signin.aws.amazon.com/console${NC}"
        echo -e "${CYAN}The user will be required to change the password on first login.${NC}"
    else
        echo -e "${YELLOW}Console access may already exist for this user.${NC}"
    fi
fi

# Summary
echo -e "\n${GREEN}========================================"
echo -e "PCI DSS 4.0.1 Assessor Setup Complete!"
echo -e "========================================${NC}"
echo -e "User Name: $USER_NAME"
echo -e "Policy ARN: $POLICY_ARN"
echo -e "\n${CYAN}Next Steps:${NC}"
echo -e "1. Run the permission verification script: ./check_pci_permissions.sh"
echo -e "2. Configure AWS CLI with the access keys: aws configure"
echo -e "3. (Optional) Enable MFA for additional security"
echo -e "4. Document the assessment account details for audit purposes"

# Offer to test permissions
echo -e "\n${CYAN}Do you want to run a quick permission test? (y/n)${NC}"
read -r TEST_PERMISSIONS

if [[ "$TEST_PERMISSIONS" =~ ^[Yy]$ ]]; then
    echo -e "\n${CYAN}Testing basic permissions...${NC}"
    
    # Test EC2 permissions
    echo -ne "Testing EC2 access... "
    if aws ec2 describe-instances --max-items 1 &>/dev/null; then
        echo -e "${GREEN}✓ EC2 access verified${NC}"
    else
        echo -e "${RED}✗ EC2 access failed${NC}"
    fi
    
    # Test IAM permissions
    echo -ne "Testing IAM access... "
    if aws iam list-users --max-items 1 &>/dev/null; then
        echo -e "${GREEN}✓ IAM access verified${NC}"
    else
        echo -e "${RED}✗ IAM access failed${NC}"
    fi
    
    # Test CloudTrail permissions
    echo -ne "Testing CloudTrail access... "
    if aws cloudtrail describe-trails &>/dev/null; then
        echo -e "${GREEN}✓ CloudTrail access verified${NC}"
    else
        echo -e "${RED}✗ CloudTrail access failed${NC}"
    fi
    
    # Test S3 permissions
    echo -ne "Testing S3 access... "
    if aws s3 ls --page-size 1 &>/dev/null; then
        echo -e "${GREEN}✓ S3 access verified${NC}"
    else
        echo -e "${RED}✗ S3 access failed${NC}"
    fi
    
    # Test KMS permissions
    echo -ne "Testing KMS access... "
    if aws kms list-keys --max-items 1 &>/dev/null; then
        echo -e "${GREEN}✓ KMS access verified${NC}"
    else
        echo -e "${RED}✗ KMS access failed${NC}"
    fi
fi

# Clean up
rm -f "$POLICY_FILE"

echo -e "\n${GREEN}Script completed successfully!${NC}"

# Offer to save credentials to a file
if [ -n "$ACCESS_KEY_ID" ] && [ -n "$SECRET_ACCESS_KEY" ]; then
    echo -e "\n${CYAN}Do you want to save the credentials to a secure file? (y/n)${NC}"
    read -r SAVE_CREDS
    
    if [[ "$SAVE_CREDS" =~ ^[Yy]$ ]]; then
        CRED_FILE="pci-assessor-credentials-$(date +%Y%m%d-%H%M%S).txt"
        cat > "$CRED_FILE" << EOF
PCI DSS 4.0.1 Assessor AWS Credentials
======================================
Created: $(date)
Account ID: $ACCOUNT_ID
User Name: $USER_NAME

AWS Access Key ID: $ACCESS_KEY_ID
AWS Secret Access Key: $SECRET_ACCESS_KEY
Default Region: $REGION

AWS CLI Configuration:
aws configure set aws_access_key_id $ACCESS_KEY_ID
aws configure set aws_secret_access_key $SECRET_ACCESS_KEY
aws configure set region $REGION

IMPORTANT: Keep this file secure and delete after use.
EOF
        chmod 600 "$CRED_FILE"
        echo -e "${GREEN}Credentials saved to: $CRED_FILE${NC}"
        echo -e "${RED}Remember to secure or delete this file after use!${NC}"
    fi
fi
