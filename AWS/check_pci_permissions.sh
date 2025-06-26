#!/bin/bash

# PCI DSS Assessor Permission Check Script
# This script verifies AWS permissions by attempting read-only actions
# defined in the PCI_DSS_Assessor policy

# Set output colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo "============================================="
echo "  PCI DSS 4.0 Assessor Permission Check"
echo "============================================="

# Ask user to specify region
if [ -z "$REGION" ]; then
    read -p "Enter AWS region to test (e.g., us-east-1): " REGION
    if [ -z "$REGION" ]; then
        REGION="us-east-1"
        echo -e "${YELLOW}Using default region: $REGION${NC}"
    fi
fi


# Function to check permission
check_permission() {
    service=$1
    command=$2
    description=$3
    additional_args=$4

    echo -ne "Testing $service ($description)... "
    
    # Run command with error output redirected
    if [ -z "$additional_args" ]; then
        output=$(aws $service $command --region $REGION 2>&1)
    else
        output=$(aws $service $command $additional_args --region $REGION 2>&1)
    fi
    
    # Check if the command was successful or if it was an access denied error
    if [[ $output == *"AccessDenied"* ]]; then
        echo -e "${RED}FAILED${NC} - Access Denied"
        return 1
    elif [[ $output == *"UnauthorizedOperation"* ]]; then
        echo -e "${RED}FAILED${NC} - Unauthorized"
        return 1
    elif [[ $output == *"operation: You are not authorized"* ]]; then
        echo -e "${RED}FAILED${NC} - Not Authorized"
        return 1
    elif [[ $output == *"An error occurred"* ]]; then
        # This might be a resource not found error, which is ok
        echo -e "${YELLOW}WARNING${NC} - Error: $output"
        return 0
    else
        echo -e "${GREEN}SUCCESS${NC}"
        return 0
    fi
}

# Initialize counters
total_checks=0
passed_checks=0

echo -e "\n${YELLOW}Network Security Controls (Requirements 1.x)${NC}"
check_permission "ec2" "describe-security-groups" "Security Group Rules" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "ec2" "describe-network-acls" "Network ACLs" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "ec2" "describe-vpcs" "VPC Configuration" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "ec2" "describe-subnets" "Subnet Configuration" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "ec2" "describe-vpc-endpoints" "VPC Endpoints" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

echo -e "\n${YELLOW}System Configuration Standards (Requirements 2.x)${NC}"
check_permission "ec2" "describe-instances" "EC2 Instances" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "rds" "describe-db-instances" "RDS Instances" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "ssm" "describe-instance-information" "System Configuration" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

echo -e "\n${YELLOW}Data Protection Mechanisms (Requirements 3.x, 4.x)${NC}"
check_permission "kms" "list-keys" "KMS Keys" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "s3" "list-buckets" "S3 Buckets" ""
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "acm" "list-certificates" "ACM Certificates" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

echo -e "\n${YELLOW}Access Control Assessment (Requirements 7.x, 8.x)${NC}"
check_permission "iam" "list-users" "IAM Users" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "iam" "list-roles" "IAM Roles" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "iam" "get-account-password-policy" "Password Policy" ""
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "iam" "list-virtual-mfa-devices" "MFA Devices" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

echo -e "\n${YELLOW}Vulnerability Management (Requirements 6.x, 11.x)${NC}"
check_permission "inspector2" "list-findings" "Inspector Findings" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "ecr" "describe-repositories" "Container Repositories" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "ssm" "describe-patch-baselines" "Patch Management" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "wafv2" "list-web-acls" "WAF Configuration" "--scope REGIONAL"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

echo -e "\n${YELLOW}Logging and Monitoring (Requirements 10.x, 11.x)${NC}"
check_permission "cloudtrail" "describe-trails" "CloudTrail Trails" ""
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "logs" "describe-log-groups" "CloudWatch Logs" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "cloudwatch" "describe-alarms" "CloudWatch Alarms" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "securityhub" "list-findings" "Security Hub Findings" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "guardduty" "list-detectors" "GuardDuty Detectors" ""
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "ec2" "describe-flow-logs" "VPC Flow Logs" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

echo -e "\n${YELLOW}DNS Security Assessment${NC}"
check_permission "route53" "list-hosted-zones" "Route53 Hosted Zones" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

check_permission "route53domains" "list-domains" "Route53 Domains" "--max-items 1"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++))

# Calculate percentage of passed checks
percentage=$(( (passed_checks * 100) / total_checks ))

echo -e "\n============================================="
echo -e "Permission Check Results:"
echo -e "============================================="
echo -e "Total checks: $total_checks"
echo -e "Passed checks: $passed_checks"
echo -e "Success rate: $percentage%"

if [ $percentage -eq 100 ]; then
    echo -e "\n${GREEN}All permissions are correctly configured for PCI DSS 4.0 assessment.${NC}"
elif [ $percentage -ge 80 ]; then
    echo -e "\n${YELLOW}Most permissions are configured, but some are missing.${NC}"
    echo -e "${YELLOW}Review the results and update the policy as needed.${NC}"
else
    echo -e "\n${RED}Significant permissions are missing.${NC}"
    echo -e "${RED}Please review your policy and ensure it matches the PCI_DSS_Assessor policy.${NC}"
fi

echo -e "\nTo see which permissions your IAM user actually has, run:"
echo -e "aws iam get-user-policy --user-name YOUR_USERNAME --policy-name PCI_DSS_Assessor"
echo -e "or check the policy in the AWS Management Console."
