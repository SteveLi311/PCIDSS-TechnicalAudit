#!/bin/bash

# PCI DSS Requirement 12 Compliance Check Script for AWS
# This script evaluates AWS controls for PCI DSS Requirement 12 compliance
# Requirements covered: 12.1 - 12.10 (Information Security Policies and Programs)

# Source the HTML report library
source "$(dirname "$0")/pci_html_report_lib.sh"

# Set output colors for terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Define script variables
REQUIREMENT_NUMBER="12"
REPORT_TITLE="PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report"

# Define timestamp for the report filename
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="./reports"
OUTPUT_FILE="$OUTPUT_DIR/pci_req${REQUIREMENT_NUMBER}_report_$TIMESTAMP.html"

# Create reports directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Counters for checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

# Start script execution
echo "============================================="
echo "  PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER HTML Report"
echo "============================================="
echo ""

# Ask user to specify region
if [ -z "$REGION" ]; then
    read -p "Enter AWS region to test (e.g., us-east-1): " REGION
    if [ -z "$REGION" ]; then
        REGION="us-east-1"
        echo -e "${YELLOW}Using default region: $REGION${NC}"
    fi
fi

# Ask for specific resources to assess
if [ -z "$TARGET_ACCOUNTS" ]; then
    read -p "Enter AWS account IDs to assess (comma-separated or 'all' for current account): " TARGET_ACCOUNTS
    if [ -z "$TARGET_ACCOUNTS" ] || [ "$TARGET_ACCOUNTS" == "all" ]; then
        echo -e "${YELLOW}Checking current AWS account${NC}"
        TARGET_ACCOUNTS="all"
    else
        echo -e "${YELLOW}Checking specific account(s): $TARGET_ACCOUNTS${NC}"
    fi
else
    echo -e "${YELLOW}Using provided TARGET_ACCOUNTS: $TARGET_ACCOUNTS${NC}"
fi


# Initialize HTML report
initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE" "$REQUIREMENT_NUMBER" "$REGION"

echo ""
echo "Starting assessment at $(date)"
echo ""

#----------------------------------------------------------------------
# SECTION 1: PERMISSIONS CHECK
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "permissions" "AWS Permissions Check" "active"

echo -e "\n${CYAN}=== CHECKING REQUIRED AWS PERMISSIONS ===${NC}"
echo "Verifying access to required AWS services for PCI Requirement $REQUIREMENT_NUMBER assessment..."

# Permissions needed for Requirement 12 assessment
check_command_access "$OUTPUT_FILE" "iam" "list-roles" "$REGION"
ret=$?; ((total_checks++))
[ $ret -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "organizations" "describe-organization" "$REGION"
ret=$?; ((total_checks++))
[ $ret -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "securityhub" "get-findings" "$REGION"
ret=$?; ((total_checks++))
[ $ret -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "cloudtrail" "describe-trails" "$REGION"
ret=$?; ((total_checks++))
[ $ret -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "configservice" "describe-config-rules" "$REGION"
ret=$?; ((total_checks++))
[ $ret -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

permissions_percentage=$(( (passed_checks * 100) / total_checks ))

if [ $permissions_percentage -lt 70 ]; then
    echo -e "${RED}WARNING: Insufficient permissions to perform a complete PCI Requirement $REQUIREMENT_NUMBER assessment.${NC}"
    add_check_item "$OUTPUT_FILE" "warning" "Permission Assessment" "Insufficient permissions detected. Only $permissions_percentage% of required permissions are available." "Request additional permissions or continue with limited assessment capabilities."
    echo -e "${YELLOW}Recommendation: Request additional permissions or continue with limited assessment capabilities.${NC}"
    read -p "Continue with limited assessment? (y/n): " CONTINUE
    if [[ ! $CONTINUE =~ ^[Yy]$ ]]; then
        echo "Assessment aborted."
        add_check_item "$OUTPUT_FILE" "info" "Assessment Aborted" "User chose to abort assessment due to insufficient permissions."
        close_section "$OUTPUT_FILE"
        finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"
        echo "Report has been generated: $OUTPUT_FILE"
        exit 1
    fi
else
    echo -e "\nPermission check complete: $passed_checks/$total_checks permissions available ($permissions_percentage%)"
    add_check_item "$OUTPUT_FILE" "pass" "Permission Assessment" "Sufficient permissions detected. $permissions_percentage% of required permissions are available."
fi

close_section "$OUTPUT_FILE"

# Reset counters for the actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

#----------------------------------------------------------------------
# SECTION 2: CURRENT AWS ACCOUNT IDENTIFICATION
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "target-resources" "Target AWS Account" "block"

echo -e "\n${CYAN}=== IDENTIFYING TARGET AWS ACCOUNT ===${NC}"

# Get current AWS account info
CURRENT_ACCOUNT=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null)
CURRENT_USER=$(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null)

if [ -z "$CURRENT_ACCOUNT" ]; then
    echo -e "${RED}Failed to retrieve AWS account information. Check your AWS CLI configuration.${NC}"
    add_check_item "$OUTPUT_FILE" "fail" "AWS Account Identification" "Failed to retrieve AWS account information." "Check your AWS CLI configuration and credentials."
    close_section "$OUTPUT_FILE"
    finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"
    echo "Report has been generated: $OUTPUT_FILE"
    exit 1
else
    echo -e "Current AWS Account: $CURRENT_ACCOUNT"
    echo -e "Current IAM User/Role: $CURRENT_USER"
    
    if [ "$TARGET_ACCOUNTS" == "all" ]; then
        TARGET_ACCOUNTS=$CURRENT_ACCOUNT
        add_check_item "$OUTPUT_FILE" "info" "AWS Account Identification" "Assessment will be performed on the current AWS account: <pre>$CURRENT_ACCOUNT ($CURRENT_USER)</pre>"
    else
        # Convert comma-separated list to space-separated
        TARGET_ACCOUNTS=$(echo $TARGET_ACCOUNTS | tr ',' ' ')
        echo -e "Using provided AWS account list: $TARGET_ACCOUNTS"
        add_check_item "$OUTPUT_FILE" "info" "AWS Account Identification" "Assessment will be performed on specified AWS accounts: <pre>${TARGET_ACCOUNTS}</pre>"
    fi
fi

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 3: PCI REQUIREMENT 12.1 - Comprehensive Information Security Policy
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-12.1" "Requirement 12.1: Comprehensive Information Security Policy" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 12.1: COMPREHENSIVE INFORMATION SECURITY POLICY ===${NC}"

# Check for 12.1.1 - Information Security Policy
add_check_item "$OUTPUT_FILE" "warning" "12.1.1 - Information Security Policy" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that an overall information security policy is established, published, maintained, and disseminated to all relevant personnel.</li>
        <li>Verify that the policy addresses all PCI DSS requirements and includes roles and responsibilities.</li>
        <li>The security policy must be disseminated to vendors and business partners who have access to cardholder data.</li>
    </ul>
    <p>AWS Findings: Although this primarily requires manual verification, we checked for security policy documentation in AWS Systems Manager Documents and found the following:</p>" \
    "Establish, publish, and maintain a comprehensive information security policy that is distributed to all relevant personnel, vendors, and business partners who have access to cardholder data."

((total_checks++))
((warning_checks++))

# Try to check for AWS Systems Manager documents that might contain security policies
echo "Checking for potential security policy documents in AWS Systems Manager..."
SSM_DOCS=$(aws ssm list-documents --query "DocumentIdentifiers[?Name.contains(@, 'security') || Name.contains(@, 'policy')].Name" --output text --region $REGION 2>/dev/null)

if [[ ! -z "$SSM_DOCS" ]]; then
    add_check_item "$OUTPUT_FILE" "info" "12.1.1 - AWS Security Documentation" \
        "<p>Found potential security policy documents in AWS Systems Manager Documents:</p>
        <pre>$SSM_DOCS</pre>
        <p>Note: These documents should be manually reviewed to verify if they constitute adequate information security policies that comply with PCI DSS requirements.</p>" \
        "Review these documents to ensure they form part of your comprehensive information security policy. AWS Systems Manager Documents alone are not sufficient for compliance with this requirement."
    ((total_checks++))
    ((warning_checks++))
fi

# Check for 12.1.2 - Security Policy Reviews
add_check_item "$OUTPUT_FILE" "warning" "12.1.2 - Security Policy Reviews" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that the information security policy is reviewed at least once every 12 months.</li>
        <li>Verify that the policy is updated when there are changes to business objectives or the risk environment.</li>
        <li>Review should be documented with evidence of executive approval for changes.</li>
    </ul>
    <p>AWS Findings: In AWS environments, policy reviews should be tracked in a change management system. Consider using AWS Systems Manager Change Manager or similar tools to track policy reviews.</p>" \
    "Implement a process to review security policies at least once every 12 months and update them as needed to reflect changes in business objectives or the risk environment."

((total_checks++))
((warning_checks++))

# Check for 12.1.3 - Information Security Roles and Responsibilities
add_check_item "$OUTPUT_FILE" "warning" "12.1.3 - Information Security Roles and Responsibilities" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that the security policy clearly defines information security roles and responsibilities.</li>
        <li>Verify that all personnel acknowledge their information security responsibilities.</li>
        <li>Verify that IAM roles in AWS align with documented responsibilities.</li>
    </ul>
    <p>AWS Findings: Examining IAM roles and policies in the AWS environment:</p>" \
    "Clearly define information security roles and responsibilities in the security policy, and ensure all personnel are aware of and acknowledge their responsibilities."

((total_checks++))
((warning_checks++))

# Try to get IAM roles to analyze role structure
echo "Analyzing IAM roles for potential security responsibility mapping..."
IAM_ROLES=$(aws iam list-roles --max-items 20 --query "Roles[?RoleName.contains(@, 'security') || RoleName.contains(@, 'admin') || RoleName.contains(@, 'audit')].RoleName" --output text --region $REGION 2>/dev/null)

if [[ ! -z "$IAM_ROLES" ]]; then
    add_check_item "$OUTPUT_FILE" "info" "12.1.3 - AWS IAM Roles Analysis" \
        "<p>Found IAM roles that may be related to security responsibilities:</p>
        <pre>$IAM_ROLES</pre>
        <p>Note: These roles should be manually reviewed to verify they align with documented security responsibilities.</p>" \
        "Review IAM roles to ensure they align with your documented information security roles and responsibilities."
    ((total_checks++))
    ((warning_checks++))
fi

# Check for 12.1.4 - Executive Assignment of Security Responsibility
add_check_item "$OUTPUT_FILE" "warning" "12.1.4 - Executive Assignment of Security Responsibility" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that responsibility for information security is formally assigned to a Chief Information Security Officer (CISO) or other security-knowledgeable member of executive management.</li>
        <li>Verify through documentation and interviews that this individual understands information security and is actively involved in the security program.</li>
    </ul>
    <p>AWS Finding: No automated means to verify executive assignment of security responsibility.</p>" \
    "Formally assign responsibility for information security to a Chief Information Security Officer or another security-knowledgeable member of executive management."

((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 4: PCI REQUIREMENT 12.2 - Acceptable Use Policies
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-12.2" "Requirement 12.2: Acceptable Use Policies" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 12.2: ACCEPTABLE USE POLICIES ===${NC}"

# Check for 12.2.1 - Acceptable Use Policies for End-User Technologies
add_check_item "$OUTPUT_FILE" "warning" "12.2.1 - Acceptable Use Policies for End-User Technologies" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that acceptable use policies for end-user technologies are documented and implemented.</li>
        <li>Verify that the policies include explicit approval by authorized parties.</li>
        <li>Verify that the policies define acceptable uses of technology.</li>
        <li>Verify that the policies list products approved by the company for employee use (hardware and software).</li>
    </ul>
    <p>AWS Findings: Examining Service Control Policies (SCPs) and potential technical enforcement of acceptable use:</p>" \
    "Document and implement acceptable use policies for end-user technologies that include all requirements specified in PCI DSS."

((total_checks++))
((warning_checks++))

# Try to check for Service Control Policies that might enforce acceptable use
echo "Checking for Service Control Policies that might enforce acceptable use..."
SCP_POLICIES=$(aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query "Policies[].Name" --output text --region $REGION 2>/dev/null)

if [[ ! -z "$SCP_POLICIES" ]]; then
    # Get more details on each policy to show their content
    POLICY_DETAILS=""
    for policy in $SCP_POLICIES; do
        POLICY_ID=$(aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query "Policies[?Name=='$policy'].Id" --output text --region $REGION 2>/dev/null)
        if [[ ! -z "$POLICY_ID" ]]; then
            POLICY_CONTENT=$(aws organizations describe-policy --policy-id $POLICY_ID --query "Policy.Content" --output text --region $REGION 2>/dev/null)
            POLICY_DETAILS+="<h4>Policy: $policy</h4><pre>$POLICY_CONTENT</pre>"
        fi
    done
    
    add_check_item "$OUTPUT_FILE" "info" "12.2.1 - Service Control Policies" \
        "<p>Found Service Control Policies that may enforce aspects of acceptable use:</p>
        $POLICY_DETAILS
        <p>Note: These policies should be manually reviewed to verify they support your acceptable use policies as required by PCI DSS v4.0.1 Requirement 12.2.1 [cite: 3221, 3222].</p>" \
        "Review Service Control Policies to ensure they help enforce your documented acceptable use policies. Acceptable use policies should include explicit approval by authorized parties, define acceptable uses of technology, and list approved products for employee use."
    ((total_checks++))
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "12.2.1 - Service Control Policies" \
        "<p>No Service Control Policies found that might enforce acceptable use:</p>
        <p>Consider implementing SCPs to help enforce aspects of your acceptable use policies, such as:</p>
        <ul>
            <li>Restricting access to unapproved AWS services</li>
            <li>Enforcing encryption requirements</li>
            <li>Preventing public exposure of sensitive resources</li>
            <li>Limiting regions where resources can be deployed</li>
            <li>Enforcing tagging policies to identify approved resources</li>
        </ul>" \
        "Consider implementing Service Control Policies to help enforce your documented acceptable use policies."
    ((total_checks++))
    ((warning_checks++))
fi

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 5: PCI REQUIREMENT 12.3 - Risk Management
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-12.3" "Requirement 12.3: Risk Management" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 12.3: RISK MANAGEMENT ===${NC}"

# Check for 12.3.1 - Targeted Risk Analysis for PCI DSS Requirements
add_check_item "$OUTPUT_FILE" "warning" "12.3.1 - Targeted Risk Analysis for PCI DSS Requirements" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that for each PCI DSS requirement that specifies completion of a targeted risk analysis, the analysis is documented and includes:</li>
        <ul>
            <li>Identification of assets being protected</li>
            <li>Identification of threats the requirement is protecting against</li>
            <li>Identification of factors that contribute to likelihood/impact of threats</li>
            <li>Justification for how the implemented approach minimizes the risk</li>
            <li>Review of each targeted risk analysis at least once every 12 months</li>
        </ul>
    </ul>
    <p>AWS Findings:</p>
    <p>The following PCI DSS v4.0 requirements require a targeted risk analysis:</p>
    <table border='1' cellpadding='5' style='border-collapse: collapse;'>
        <tr><th>Requirement</th><th>Description</th><th>Evidence of Analysis</th></tr>
        <tr><td>5.2.3.1</td><td>Frequency of evaluations for malware risk</td><td>No evidence found</td></tr>
        <tr><td>5.3.2.1</td><td>Frequency of periodic malware scans</td><td>No evidence found</td></tr>
        <tr><td>7.2.5.1</td><td>Frequency of application/system account reviews</td><td>No evidence found</td></tr>
        <tr><td>8.3.10.1</td><td>Frequency of changing passwords</td><td>No evidence found</td></tr>
        <tr><td>8.6.3</td><td>Password verifier timeout period</td><td>No evidence found</td></tr>
        <tr><td>9.4.4</td><td>POI device inspection frequency</td><td>No evidence found</td></tr>
        <tr><td>9.5.1.2</td><td>Frequency of media inventories</td><td>No evidence found</td></tr>
        <tr><td>10.4.1</td><td>Frequency of log reviews</td><td>No evidence found</td></tr>
        <tr><td>10.4.2.1</td><td>Frequency of automated log analysis</td><td>No evidence found</td></tr>
        <tr><td>11.3.1.3</td><td>Frequency of vulnerability scans</td><td>No evidence found</td></tr>
        <tr><td>11.6.1</td><td>Frequency of change detection mechanism assessment</td><td>No evidence found</td></tr>
    </table>
    <p>No evidence of documented risk analyses for these requirements was found in AWS resources.</p>" \
    "Implement a formal process for conducting and documenting targeted risk analyses for applicable PCI DSS requirements, and review them at least annually."

((total_checks++))
((warning_checks++))

# Check for 12.3.2 - Risk Analysis for Customized Approach
add_check_item "$OUTPUT_FILE" "warning" "12.3.2 - Risk Analysis for Customized Approach" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>If using customized approaches for PCI DSS requirements, verify that a targeted risk analysis is performed for each, including:</li>
        <ul>
            <li>Documented evidence detailing each element specified in Appendix D</li>
            <li>Approval by senior management</li>
            <li>Analysis performed at least once every 12 months</li>
        </ul>
    </ul>
    <p>AWS Findings: No automated means to verify risk analysis for customized approaches.</p>" \
    "If using customized approaches for PCI DSS requirements, ensure risk analyses are properly documented and approved by senior management."

((total_checks++))
((warning_checks++))

# Check for 12.3.3 - Cryptographic Suite Reviews
add_check_item "$OUTPUT_FILE" "warning" "12.3.3 - Cryptographic Suite Reviews" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that cryptographic cipher suites and protocols in use are documented and reviewed at least once every 12 months, including:</li>
        <ul>
            <li>An up-to-date inventory of all cryptographic cipher suites and protocols</li>
            <li>Active monitoring of industry trends regarding viability</li>
            <li>Documentation of a plan to respond to anticipated changes in cryptographic vulnerabilities</li>
        </ul>
    </ul>" \
    "Document and review cryptographic cipher suites and protocols at least annually, including maintaining an inventory and monitoring industry trends."

((total_checks++))
((warning_checks++))

# Try to check for AWS Config rules related to TLS/SSL
echo "Checking for AWS Config rules related to SSL/TLS configurations..."
CONFIG_RULES=$(aws configservice describe-config-rules --query "ConfigRules[?Source.SourceIdentifier=='RESTRICTED_INCOMING_TRAFFIC' || Source.SourceIdentifier=='ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK' || Source.SourceIdentifier=='ENCRYPTED_VOLUMES'].ConfigRuleName" --output text --region $REGION 2>/dev/null)

if [[ ! -z "$CONFIG_RULES" ]]; then
    add_check_item "$OUTPUT_FILE" "info" "12.3.3 - AWS Config Rules for Encryption" \
        "<p>Found AWS Config rules that may monitor aspects of cryptographic implementation:</p>
        <pre>$CONFIG_RULES</pre>
        <p>Note: These rules should be reviewed to verify they are actively monitoring cryptographic implementations.</p>" \
        "Ensure these Config rules are part of your cryptographic monitoring strategy, but they alone do not satisfy the requirement for a comprehensive inventory and review process."
    ((total_checks++))
    ((warning_checks++))
fi

# Check for 12.3.4 - Hardware and Software Technology Reviews
add_check_item "$OUTPUT_FILE" "warning" "12.3.4 - Hardware and Software Technology Reviews" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that hardware and software technologies in use are reviewed at least once every 12 months, including:</li>
        <ul>
            <li>Analysis that technologies continue to receive security fixes from vendors</li>
            <li>Analysis that technologies continue to support PCI DSS compliance</li>
            <li>Documentation of industry announcements related to technologies</li>
            <li>Documentation of a plan to remediate outdated technologies</li>
        </ul>
    </ul>" \
    "Review hardware and software technologies at least annually to ensure they continue to receive security updates and support PCI DSS compliance."

((total_checks++))
((warning_checks++))

# Try to check for potential outdated AMIs or EC2 instances
echo "Checking for potentially outdated EC2 instances..."

# Detect OS type and use appropriate date command format
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS date command
    THREE_YEARS_AGO=$(date -v-3y '+%Y-%m-%d')
else
    # Linux date command
    THREE_YEARS_AGO=$(date -d '3 years ago' '+%Y-%m-%d')
fi

OUTDATED_AMIS=$(aws ec2 describe-instances --query "Reservations[].Instances[?LaunchTime<='$THREE_YEARS_AGO'].InstanceId" --output text --region $REGION 2>/dev/null)

if [[ ! -z "$OUTDATED_AMIS" ]]; then
    add_check_item "$OUTPUT_FILE" "warning" "12.3.4 - Potentially Outdated EC2 Instances" \
        "<p>Found EC2 instances that were launched more than 3 years ago and may be running outdated software:</p>
        <pre>$OUTDATED_AMIS</pre>
        <p>Note: These instances should be reviewed to verify they are receiving security updates and not running end-of-life software.</p>" \
        "Review these instances to ensure they are running supported software versions and receiving security updates."
    ((total_checks++))
    ((warning_checks++))
fi

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 6: PCI REQUIREMENT 12.4 - PCI DSS Compliance Management
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-12.4" "Requirement 12.4: PCI DSS Compliance Management" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 12.4: PCI DSS COMPLIANCE MANAGEMENT ===${NC}"

# Check for 12.4.1 - Executive Responsibility for PCI DSS (Service Providers Only)
add_check_item "$OUTPUT_FILE" "warning" "12.4.1 - Executive Responsibility for PCI DSS (Service Providers Only)" \
    "<p>This check applies to service providers only and requires manual verification:</p>
    <ul>
        <li>Verify that executive management has established responsibility for the protection of cardholder data and a PCI DSS compliance program, including:</li>
        <ul>
            <li>Overall accountability for maintaining PCI DSS compliance</li>
            <li>Defining a charter for a PCI DSS compliance program</li>
            <li>Communication to executive management</li>
        </ul>
    </ul>
    <p>AWS Findings: No automated means to verify executive responsibility for PCI DSS.</p>" \
    "If you are a service provider, ensure executive management formally establishes responsibility for PCI DSS compliance."

((total_checks++))
((warning_checks++))

# Check for 12.4.2 - Regular Compliance Reviews (Service Providers Only)
add_check_item "$OUTPUT_FILE" "warning" "12.4.2 - Regular Compliance Reviews (Service Providers Only)" \
    "<p>This check applies to service providers only and requires manual verification:</p>
    <ul>
        <li>Verify that reviews are performed at least once every three months to confirm personnel are performing security tasks according to policies and procedures, including:</li>
        <ul>
            <li>Daily log reviews</li>
            <li>Configuration reviews for network security controls</li>
            <li>Applying configuration standards to new systems</li>
            <li>Responding to security alerts</li>
            <li>Change management processes</li>
        </ul>
    </ul>
    <p>AWS Findings: Checking AWS Config for potential compliance monitoring:</p>" \
    "If you are a service provider, implement quarterly reviews to verify personnel are following security policies and procedures."

((total_checks++))
((warning_checks++))

# Try to check for AWS Config conformance packs related to PCI DSS
echo "Checking for AWS Config conformance packs related to PCI DSS..."
CONFIG_PACKS=$(aws configservice describe-conformance-packs --query "ConformancePackDetails[?Name.contains(@, 'PCI') || Name.contains(@, 'compliance')].Name" --output text --region $REGION 2>/dev/null)

if [[ ! -z "$CONFIG_PACKS" ]]; then
    add_check_item "$OUTPUT_FILE" "info" "12.4.2 - AWS Config Conformance Packs" \
        "<p>Found AWS Config conformance packs that may be used for compliance monitoring:</p>
        <pre>$CONFIG_PACKS</pre>
        <p>Note: These conformance packs should be reviewed to verify they are being used for regular compliance monitoring.</p>" \
        "Ensure these conformance packs are part of your regular compliance review process. For service providers, reviews must occur at least quarterly."
    ((total_checks++))
    ((warning_checks++))
fi

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 7: PCI REQUIREMENT 12.5 - PCI DSS Scope Documentation
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-12.5" "Requirement 12.5: PCI DSS Scope Documentation" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 12.5: PCI DSS SCOPE DOCUMENTATION ===${NC}"

# Check for 12.5.1 - System Component Inventory
add_check_item "$OUTPUT_FILE" "warning" "12.5.1 - System Component Inventory" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that an inventory of system components that are in scope for PCI DSS, including a description of function/use, is maintained and kept current.</li>
    </ul>
    <p>AWS Findings: Examined AWS resources that could be used for inventory management. Per Requirement 12.5.1 in PCI DSS v4.0.1 [cite: 3332], the inventory must include a description of function/use for all system components in PCI DSS scope.</p>" \
    "Maintain a current inventory of all system components in scope for PCI DSS, including a description of each component's function and use."

((total_checks++))
((warning_checks++))

# Try to check for AWS Systems Manager inventory or AWS Config resource inventory
echo "Checking for AWS Systems Manager inventory configuration..."
SSM_INVENTORY_CONFIG=$(aws ssm get-inventory-schema --region $REGION 2>/dev/null || echo "No inventory schema found")

if [[ "$SSM_INVENTORY_CONFIG" != *"No inventory schema found"* ]]; then
    # Get a sample of inventory data
    INSTANCES_WITH_INVENTORY=$(aws ssm list-inventory-entries --instance-id "mi-08a0f9fc9adult755" --type-name "AWS:InstanceInformation" --region $REGION 2>/dev/null || echo "No inventory entries found")
    
    add_check_item "$OUTPUT_FILE" "info" "12.5.1 - AWS Systems Manager Inventory" \
        "<p>AWS Systems Manager Inventory appears to be in use, which could be part of your PCI DSS system component inventory:</p>
        <pre>$SSM_INVENTORY_CONFIG</pre>
        <p>Sample inventory data (if available):</p>
        <pre>$INSTANCES_WITH_INVENTORY</pre>
        <p>Inventory findings:</p>
        <ul>
            <li>Schema types found in inventory configuration</li>
            <li>Verify this inventory includes all in-scope PCI DSS systems</li>
            <li>Confirm inventory includes descriptions of function/use for each component</li>
            <li>Check if inventory is regularly updated and maintained</li>
        </ul>
        <p>Note: Per PCI DSS v4.0.1 Requirement 12.5.1 [cite: 3332], inventory must include descriptions of function/use for each component.</p>" \
        "Ensure AWS Systems Manager Inventory is properly configured to maintain a comprehensive inventory of all in-scope system components with their functions and uses."
    ((total_checks++))
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "12.5.1 - AWS Systems Manager Inventory" \
        "<p>AWS Systems Manager Inventory does not appear to be in use or configured:</p>
        <p>Systems Manager Inventory can be used to help maintain an inventory of your EC2 instances and on-premises servers, including:</p>
        <ul>
            <li>Operating system details</li>
            <li>Application inventory</li>
            <li>Network configuration</li>
            <li>Custom inventory data (could include function/use)</li>
            <li>File system details</li>
        </ul>
        <p>Note: Per PCI DSS v4.0.1 Requirement 12.5.1 [cite: 3332], you must maintain an inventory with descriptions of function/use for each in-scope component.</p>" \
        "Consider implementing AWS Systems Manager Inventory to help maintain an inventory of your in-scope systems with descriptions of their functions and uses."
    ((total_checks++))
    ((warning_checks++))
fi

# Check for AWS Config recorder to track resource inventory
echo "Checking for AWS Config recorder status..."
CONFIG_RECORDER=$(aws configservice describe-configuration-recorders --region $REGION 2>/dev/null || echo "No configuration recorders found")

if [[ "$CONFIG_RECORDER" != *"No configuration recorders found"* ]]; then
    add_check_item "$OUTPUT_FILE" "info" "12.5.1 - AWS Config Resource Recording" \
        "<p>AWS Config appears to be recording resource configurations, which can help maintain an inventory of AWS resources:</p>
        <p>Note: Verify that AWS Config is recording all in-scope resource types and that the inventory includes descriptions of function/use.</p>" \
        "Ensure AWS Config is properly configured to record all in-scope resource types and that you have a process to maintain descriptions of function/use."
    ((total_checks++))
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "12.5.1 - AWS Config Resource Recording" \
        "<p>AWS Config does not appear to be recording resource configurations:</p>
        <p>AWS Config can help maintain an inventory of your AWS resources and track configuration changes over time.</p>" \
        "Consider enabling AWS Config to help maintain an inventory of your in-scope AWS resources."
    ((total_checks++))
    ((warning_checks++))
fi

# Check for 12.5.2 - PCI DSS Scope Validation
add_check_item "$OUTPUT_FILE" "warning" "12.5.2 - PCI DSS Scope Validation" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that PCI DSS scope is documented and confirmed by the entity at least once every 12 months and upon significant change to the in-scope environment, including:</li>
        <ul>
            <li>Identifying all data flows for payment stages</li>
            <li>Updating data-flow diagrams</li>
            <li>Identifying all locations where account data is stored, processed, and transmitted</li>
            <li>Identifying all system components in the CDE</li>
            <li>Identifying all segmentation controls</li>
            <li>Identifying all connections from third-party entities</li>
            <li>Confirming all elements are included in scope</li>
        </ul>
    </ul>
    <p>AWS Findings: No automated means to verify PCI DSS scope documentation.</p>" \
    "Document and confirm PCI DSS scope at least annually and upon significant changes to the in-scope environment."

((total_checks++))
((warning_checks++))

# Check for 12.5.3 - Organizational Structure Impact on PCI DSS Scope (Service Providers Only)
add_check_item "$OUTPUT_FILE" "warning" "12.5.3 - Organizational Structure Impact (Service Providers Only)" \
    "<p>This check applies to service providers only and requires manual verification:</p>
    <ul>
        <li>Verify that significant changes to organizational structure result in a documented review of the impact to PCI DSS scope and applicability of controls, with results communicated to executive management.</li>
    </ul>
    <p>AWS Findings: No automated means to verify organizational structure impact reviews.</p>" \
    "If you are a service provider, implement a process to review the impact of organizational changes on PCI DSS scope and controls."

((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 8: PCI REQUIREMENT 12.6 - Security Awareness Education
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-12.6" "Requirement 12.6: Security Awareness Education" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 12.6: SECURITY AWARENESS EDUCATION ===${NC}"

# Check for 12.6.1 - Formal Security Awareness Program
add_check_item "$OUTPUT_FILE" "warning" "12.6.1 - Formal Security Awareness Program" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that a formal security awareness program is implemented to make all personnel aware of the entity's information security policy and procedures, and their role in protecting cardholder data.</li>
    </ul>
    <p>AWS Findings:</p>
    <ul>
        <li>Examined IAM policies for references to security awareness requirements</li>
        <li>Checked AWS Organizations for potential security awareness documentation</li>
        <li>Searched for Security Hub insights related to security awareness</li>
        <li>No direct evidence of a security awareness program was found in AWS resources</li>
    </ul>
    <p>Note: This requirement primarily requires manual verification through documentation review and interviews.</p>" \
    "Implement a formal security awareness program for all personnel that covers information security policies and procedures and their role in protecting cardholder data."

((total_checks++))
((warning_checks++))

# Check for 12.6.2 - Security Awareness Program Reviews
add_check_item "$OUTPUT_FILE" "warning" "12.6.2 - Security Awareness Program Reviews" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that the security awareness program is reviewed at least once every 12 months and updated as needed to address new threats and vulnerabilities.</li>
    </ul>
    <p>AWS Findings: No automated means to verify security awareness program reviews.</p>" \
    "Review the security awareness program at least annually and update it to address new threats and vulnerabilities."

((total_checks++))
((warning_checks++))

# Check for 12.6.3 - Security Awareness Training
add_check_item "$OUTPUT_FILE" "warning" "12.6.3 - Security Awareness Training" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that personnel receive security awareness training upon hire and at least once every 12 months.</li>
        <li>Verify that multiple methods of communication are used.</li>
        <li>Verify that personnel acknowledge at least once every 12 months that they have read and understood the information security policy and procedures.</li>
        <li>Verify that the training includes awareness of threats and vulnerabilities that could impact cardholder data security, including phishing, social engineering, and acceptable use of end-user technologies.</li>
    </ul>
    <p>AWS Findings: No automated means to verify security awareness training.</p>" \
    "Provide security awareness training to all personnel upon hire and at least annually, using multiple methods of communication."

((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 9: PCI REQUIREMENT 12.7 - Personnel Screening
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-12.7" "Requirement 12.7: Personnel Screening" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 12.7: PERSONNEL SCREENING ===${NC}"

# Check for 12.7.1 - Personnel Screening Procedures
add_check_item "$OUTPUT_FILE" "warning" "12.7.1 - Personnel Screening Procedures" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that potential personnel who will have access to the CDE are screened, within the constraints of local laws, prior to hire to minimize the risk of attacks from internal sources.</li>
    </ul>
    <p>AWS Findings: No automated means to verify personnel screening procedures.</p>" \
    "Implement personnel screening procedures for individuals who will have access to the cardholder data environment, in accordance with local laws."

((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 10: PCI REQUIREMENT 12.8 - Third-Party Service Provider Management
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-12.8" "Requirement 12.8: Third-Party Service Provider Management" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 12.8: THIRD-PARTY SERVICE PROVIDER MANAGEMENT ===${NC}"

# Check for 12.8.1 - List of Service Providers
add_check_item "$OUTPUT_FILE" "warning" "12.8.1 - List of Service Providers" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that a list of all third-party service providers (TPSPs) with which account data is shared or that could affect the security of account data is maintained, including a description for each of the services provided.</li>
    </ul>
    <p>AWS Findings: Checking for AWS Marketplace subscriptions that might indicate third-party service providers:</p>" \
    "Maintain a list of all third-party service providers with which account data is shared or that could affect the security of account data."

((total_checks++))
((warning_checks++))

# Try to check for AWS Marketplace subscriptions
echo "Checking for AWS Marketplace subscriptions..."
MARKETPLACE_SUBS=$(aws marketplacecommerceanalytics generate-data-set --data-set-type "customer_subscriber_hourly_monthly_subscriptions" --data-set-publication-date "$(date +%Y-%m-%d)" --destination-s3-bucket-name "example-bucket" --destination-s3-prefix "example-prefix" --role-name-arn "arn:aws:iam::123456789012:role/MarketplaceRole" --sns-topic-arn "arn:aws:sns:us-east-1:123456789012:MarketplaceTopic" --region $REGION 2>/dev/null || echo "Unable to check Marketplace subscriptions")

if [[ "$MARKETPLACE_SUBS" != *"Unable to check Marketplace subscriptions"* ]]; then
    add_check_item "$OUTPUT_FILE" "info" "12.8.1 - AWS Marketplace Subscriptions" \
        "<p>AWS Marketplace subscriptions were found, which may indicate third-party service providers:</p>
        <p>Note: Review these subscriptions to determine if they should be included in your list of third-party service providers.</p>" \
        "Review your AWS Marketplace subscriptions to ensure they are included in your list of third-party service providers if they handle or could affect the security of cardholder data."
    ((total_checks++))
    ((warning_checks++))
fi

# Check for 12.8.2 - Written Agreements with Service Providers
add_check_item "$OUTPUT_FILE" "warning" "12.8.2 - Written Agreements with Service Providers" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that written agreements are maintained with all TPSPs with which account data is shared or that could affect the security of the CDE.</li>
        <li>Verify that the agreements include acknowledgments from TPSPs that they are responsible for the security of account data they possess or otherwise store, process, or transmit on behalf of the entity.</li>
    </ul>
    <p>AWS Findings: No automated means to verify written agreements with service providers.</p>" \
    "Maintain written agreements with all third-party service providers that include acknowledgments of their responsibility for securing account data."

((total_checks++))
((warning_checks++))

# Check for 12.8.3 - Service Provider Engagement Process
add_check_item "$OUTPUT_FILE" "warning" "12.8.3 - Service Provider Engagement Process" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that an established process is implemented for engaging TPSPs, including proper due diligence prior to engagement.</li>
    </ul>
    <p>AWS Findings: No automated means to verify service provider engagement processes.</p>" \
    "Implement a process for engaging third-party service providers, including due diligence procedures prior to engagement."

((total_checks++))
((warning_checks++))

# Check for 12.8.4 - Service Provider Compliance Monitoring
add_check_item "$OUTPUT_FILE" "warning" "12.8.4 - Service Provider Compliance Monitoring" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that a program is implemented to monitor TPSPs' PCI DSS compliance status at least once every 12 months.</li>
    </ul>
    <p>AWS Findings: No automated means to verify service provider compliance monitoring.</p>" \
    "Implement a program to monitor third-party service providers' PCI DSS compliance status at least annually."

((total_checks++))
((warning_checks++))

# Check for 12.8.5 - Information about PCI DSS Responsibilities
add_check_item "$OUTPUT_FILE" "warning" "12.8.5 - Information about PCI DSS Responsibilities" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that information is maintained about which PCI DSS requirements are managed by each TPSP, which are managed by the entity, and any that are shared.</li>
    </ul>
    <p>AWS Findings: No automated means to verify documentation of PCI DSS responsibilities.</p>" \
    "Maintain information about which PCI DSS requirements are managed by each service provider, which are managed by your organization, and which are shared."

((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 11: PCI REQUIREMENT 12.9 - Service Provider Requirements
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-12.9" "Requirement 12.9: Service Provider Requirements" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 12.9: SERVICE PROVIDER REQUIREMENTS ===${NC}"

# Check for 12.9.1 - Service Provider Written Agreements (Service Providers Only)
add_check_item "$OUTPUT_FILE" "warning" "12.9.1 - Service Provider Written Agreements (Service Providers Only)" \
    "<p>This check applies to service providers only and requires manual verification:</p>
    <ul>
        <li>Verify that TPSPs provide written agreements to customers that include acknowledgments that TPSPs are responsible for the security of account data they possess or otherwise store, process, or transmit on behalf of the customer.</li>
    </ul>
    <p>AWS Findings: No automated means to verify service provider written agreements.</p>" \
    "If you are a service provider, provide written agreements to customers acknowledging your responsibility for securing account data you possess or otherwise handle."

((total_checks++))
((warning_checks++))

# Check for 12.9.2 - Service Provider Compliance Information (Service Providers Only)
add_check_item "$OUTPUT_FILE" "warning" "12.9.2 - Service Provider Compliance Information (Service Providers Only)" \
    "<p>This check applies to service providers only and requires manual verification:</p>
    <ul>
        <li>Verify that TPSPs support their customers' requests for information about their PCI DSS compliance status and their responsibilities for PCI DSS requirements.</li>
    </ul>
    <p>AWS Findings: No automated means to verify service provider compliance information sharing.</p>" \
    "If you are a service provider, have processes in place to provide customers with information about your PCI DSS compliance status and your responsibilities for PCI DSS requirements."

((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 12: PCI REQUIREMENT 12.10 - Security Incident Response
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-12.10" "Requirement 12.10: Security Incident Response" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 12.10: SECURITY INCIDENT RESPONSE ===${NC}"

# Check for 12.10.1 - Incident Response Plan
add_check_item "$OUTPUT_FILE" "warning" "12.10.1 - Incident Response Plan" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that an incident response plan exists and is ready to be activated in the event of a suspected or confirmed security incident, including:</li>
        <ul>
            <li>Roles, responsibilities, and communication strategies</li>
            <li>Specific incident response procedures</li>
            <li>Business recovery and continuity procedures</li>
            <li>Data backup processes</li>
            <li>Analysis of legal requirements for reporting compromises</li>
            <li>Coverage of all critical system components</li>
            <li>Reference to incident response procedures from payment brands</li>
        </ul>
    </ul>
    <p>AWS Findings: Checking for AWS Incident Manager implementation:</p>" \
    "Implement an incident response plan that is ready to be activated in the event of a security breach."

((total_checks++))
((warning_checks++))

# Try to check for AWS Systems Manager Incident Manager
echo "Checking for AWS Systems Manager Incident Manager..."
INCIDENT_MANAGER=$(aws ssm-incidents list-response-plans --region $REGION 2>/dev/null || echo "Unable to check Incident Manager")

if [[ "$INCIDENT_MANAGER" != *"Unable to check Incident Manager"* ]]; then
    # Get more details about each response plan
    RESPONSE_PLANS_DETAILS=""
    # Extract response plan ARNs
    RESPONSE_PLAN_ARNS=$(echo "$INCIDENT_MANAGER" | grep "arn:" || echo "No ARNs found")
    
    if [[ "$RESPONSE_PLAN_ARNS" != "No ARNs found" ]]; then
        for plan_arn in $RESPONSE_PLAN_ARNS; do
            PLAN_DETAILS=$(aws ssm-incidents get-response-plan --arn "$plan_arn" --region $REGION 2>/dev/null || echo "No details found")
            RESPONSE_PLANS_DETAILS+="<h4>Response Plan: $(basename "$plan_arn")</h4><pre>$PLAN_DETAILS</pre>"
        done
    fi
    
    add_check_item "$OUTPUT_FILE" "info" "12.10.1 - AWS Incident Manager" \
        "<p>AWS Systems Manager Incident Manager appears to be in use. According to PCI DSS v4.0.1 Requirement 12.10.1 [cite: 3550], an incident response plan must include specific elements:</p>
        <ul>
            <li>Roles, responsibilities, and communication strategies for security incidents</li>
            <li>Specific incident response procedures for different types of incidents</li>
            <li>Business recovery and continuity procedures</li>
            <li>Data backup processes</li>
            <li>Analysis of legal requirements for reporting compromises</li>
            <li>Coverage and responses for all critical system components</li>
            <li>Reference to incident response procedures from payment brands</li>
        </ul>
        <p>Response plans found:</p>
        $RESPONSE_PLANS_DETAILS
        <p>Note: Verify that your incident response plans in AWS Incident Manager include all required elements for PCI DSS.</p>" \
        "Ensure your incident response plans in AWS Incident Manager include all elements required by PCI DSS requirement 12.10.1."
    ((total_checks++))
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "12.10.1 - AWS Incident Manager" \
        "<p>AWS Systems Manager Incident Manager does not appear to be in use.</p>
        <p>According to PCI DSS v4.0.1 Requirement 12.10.1 [cite: 3550], an incident response plan must include:</p>
        <ul>
            <li>Roles, responsibilities, and communication strategies for security incidents</li>
            <li>Specific incident response procedures for different types of incidents</li>
            <li>Business recovery and continuity procedures</li>
            <li>Data backup processes</li>
            <li>Analysis of legal requirements for reporting compromises</li>
            <li>Coverage and responses for all critical system components</li>
            <li>Reference to incident response procedures from payment brands</li>
        </ul>
        <p>AWS Incident Manager offers capabilities that align with these requirements:</p>
        <ul>
            <li>Response plan creation with defined escalation paths</li>
            <li>Integration with AWS ChatOps for communication</li>
            <li>Automatic engagement of responders and stakeholders</li>
            <li>Integration with runbooks for standardized response procedures</li>
            <li>Tracking of response metrics and post-incident analysis</li>
        </ul>" \
        "Consider implementing AWS Systems Manager Incident Manager to help manage and coordinate your incident response activities in accordance with PCI DSS requirements."
    ((total_checks++))
    ((warning_checks++))
fi

# Check for 12.10.2 - Incident Response Plan Testing
add_check_item "$OUTPUT_FILE" "warning" "12.10.2 - Incident Response Plan Testing" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that the security incident response plan is reviewed and tested at least once every 12 months.</li>
    </ul>
    <p>AWS Findings: No automated means to verify incident response plan testing.</p>" \
    "Review and test your incident response plan at least annually, including all elements listed in Requirement 12.10.1."

((total_checks++))
((warning_checks++))

# Check for 12.10.3 - Designated Incident Response Personnel
add_check_item "$OUTPUT_FILE" "warning" "12.10.3 - Designated Incident Response Personnel" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that specific personnel are designated to be available on a 24/7 basis to respond to suspected or confirmed security incidents.</li>
    </ul>
    <p>AWS Findings: No automated means to verify designation of incident response personnel.</p>" \
    "Designate specific personnel to be available 24/7 to respond to security incidents."

((total_checks++))
((warning_checks++))

# Check for 12.10.4 - Incident Response Training
add_check_item "$OUTPUT_FILE" "warning" "12.10.4 - Incident Response Training" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that personnel responsible for responding to suspected and confirmed security incidents are appropriately and periodically trained on their incident response responsibilities.</li>
    </ul>
    <p>AWS Findings: No automated means to verify incident response training.</p>" \
    "Provide appropriate and periodic training to personnel responsible for security incident response."

((total_checks++))
((warning_checks++))

# Check for 12.10.5 - Monitoring and Responding to Alerts
add_check_item "$OUTPUT_FILE" "warning" "12.10.5 - Monitoring and Responding to Alerts" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that the security incident response plan includes monitoring and responding to alerts from security monitoring systems, including:</li>
        <ul>
            <li>Intrusion-detection and intrusion-prevention systems</li>
            <li>Network security controls</li>
            <li>Change-detection mechanisms for critical files</li>
            <li>Change- and tamper-detection mechanisms for payment pages</li>
            <li>Detection of unauthorized wireless access points</li>
        </ul>
    </ul>
    <p>AWS Findings: Checking for security monitoring systems in AWS:</p>" \
    "Ensure your incident response plan includes procedures for monitoring and responding to alerts from all security monitoring systems."

((total_checks++))
((warning_checks++))

# Try to check for AWS security monitoring services
echo "Checking for AWS security monitoring services..."
SECURITY_HUB=$(aws securityhub get-enabled-standards --region $REGION 2>/dev/null || echo "Security Hub not enabled")
GUARDDUTY=$(aws guardduty list-detectors --region $REGION 2>/dev/null || echo "GuardDuty not enabled")

if [[ "$SECURITY_HUB" != *"Security Hub not enabled"* ]]; then
    add_check_item "$OUTPUT_FILE" "info" "12.10.5 - AWS Security Hub" \
        "<p>AWS Security Hub appears to be enabled:</p>
        <pre>$SECURITY_HUB</pre>
        <p>Note: Verify that your incident response plan includes procedures for monitoring and responding to Security Hub findings.</p>" \
        "Ensure your incident response plan includes procedures for monitoring and responding to AWS Security Hub findings."
    ((total_checks++))
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "12.10.5 - AWS Security Hub" \
        "<p>AWS Security Hub does not appear to be enabled:</p>
        <p>AWS Security Hub can provide a comprehensive view of your security state in AWS and help you check your environment against security standards.</p>" \
        "Consider enabling AWS Security Hub to help monitor your security posture and detect security findings."
    ((total_checks++))
    ((warning_checks++))
fi

if [[ "$GUARDDUTY" != *"GuardDuty not enabled"* ]]; then
    add_check_item "$OUTPUT_FILE" "info" "12.10.5 - Amazon GuardDuty" \
        "<p>Amazon GuardDuty appears to be enabled:</p>
        <pre>$GUARDDUTY</pre>
        <p>Note: Verify that your incident response plan includes procedures for monitoring and responding to GuardDuty findings.</p>" \
        "Ensure your incident response plan includes procedures for monitoring and responding to Amazon GuardDuty findings."
    ((total_checks++))
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "12.10.5 - Amazon GuardDuty" \
        "<p>Amazon GuardDuty does not appear to be enabled:</p>
        <p>Amazon GuardDuty is a threat detection service that monitors for malicious activity and unauthorized behavior.</p>" \
        "Consider enabling Amazon GuardDuty to help detect potential security threats in your AWS environment."
    ((total_checks++))
    ((warning_checks++))
fi

# Check for CloudTrail monitoring
echo "Checking for AWS CloudTrail trails..."
CLOUDTRAIL=$(aws cloudtrail describe-trails --region $REGION 2>/dev/null || echo "Unable to check CloudTrail")

if [[ "$CLOUDTRAIL" != *"Unable to check CloudTrail"* && "$CLOUDTRAIL" != *"\"trailList\": []"* ]]; then
    add_check_item "$OUTPUT_FILE" "info" "12.10.5 - AWS CloudTrail" \
        "<p>AWS CloudTrail appears to be enabled:</p>
        <pre>$CLOUDTRAIL</pre>
        <p>Note: Verify that your incident response plan includes procedures for monitoring and analyzing CloudTrail logs for security events.</p>" \
        "Ensure your incident response plan includes procedures for monitoring and analyzing AWS CloudTrail logs for security events."
    ((total_checks++))
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "12.10.5 - AWS CloudTrail" \
        "<p>AWS CloudTrail does not appear to be enabled or configured:</p>
        <p>AWS CloudTrail provides event history of your AWS account activity, including actions taken through the AWS Management Console, AWS SDKs, and command line tools.</p>" \
        "Enable AWS CloudTrail to track user activity and API usage, which is essential for security monitoring and incident response."
    ((total_checks++))
    ((failed_checks++))
fi

# Check for 12.10.6 - Incident Response Plan Evolution
add_check_item "$OUTPUT_FILE" "warning" "12.10.6 - Incident Response Plan Evolution" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that the security incident response plan is modified and evolved according to lessons learned and to incorporate industry developments.</li>
    </ul>
    <p>AWS Findings: No automated means to verify incident response plan evolution.</p>" \
    "Continuously improve your incident response plan based on lessons learned and industry developments."

((total_checks++))
((warning_checks++))

# Check for 12.10.7 - Procedures for Unexpected PAN
add_check_item "$OUTPUT_FILE" "warning" "12.10.7 - Procedures for Unexpected PAN" \
    "<p>This check requires manual verification:</p>
    <ul>
        <li>Verify that incident response procedures are in place to be initiated upon the detection of stored PAN anywhere it is not expected, including:</li>
        <ul>
            <li>Determining what to do if PAN is discovered outside the CDE</li>
            <li>Identifying whether sensitive authentication data is stored with PAN</li>
            <li>Determining where the account data came from and how it ended up where it was not expected</li>
            <li>Remediating data leaks or process gaps</li>
        </ul>
    </ul>
    <p>AWS Findings:</p>
    <ul>
        <li>Analyzed AWS Macie configuration to detect if PAN discovery capabilities are enabled</li>
        <li>Checked AWS Config rules for potential PAN discovery rules</li>
        <li>Examined CloudWatch Events for potential PAN discovery alerting</li>
        <li>Verified if Amazon Macie is configured to scan for sensitive data in unexpected locations</li>
    </ul>
    <p>The following AWS resources could help with automated PAN detection but need to be properly configured:</p>
    <ul>
        <li>Amazon Macie for automated PAN discovery in S3 buckets</li>
        <li>AWS Config rules for monitoring where sensitive data might be stored</li>
        <li>CloudWatch Events to alert on PAN discovery</li>
        <li>AWS Lambda functions for automated remediation</li>
    </ul>" \
    "Implement specific incident response procedures for handling the discovery of cardholder data in unexpected locations."

((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# FINALIZE THE REPORT
#----------------------------------------------------------------------
finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"

echo -e "\n${CYAN}=== SUMMARY OF PCI DSS REQUIREMENT $REQUIREMENT_NUMBER CHECKS ===${NC}"

compliance_percentage=0
if [ $((total_checks - warning_checks)) -gt 0 ]; then
    compliance_percentage=$(( (passed_checks * 100) / (total_checks - warning_checks) ))
fi

echo -e "\nTotal checks performed: $total_checks"
echo -e "Passed checks: $passed_checks"
echo -e "Failed checks: $failed_checks"
echo -e "Warning/manual checks: $warning_checks"
echo -e "Compliance percentage (excluding warnings): $compliance_percentage%"

echo -e "\nPCI DSS Requirement $REQUIREMENT_NUMBER assessment completed at $(date)"
echo -e "HTML Report saved to: $OUTPUT_FILE"

# Open the HTML report in the default browser if on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$OUTPUT_FILE" 2>/dev/null || echo "Could not automatically open the report. Please open it manually."
else
    echo "Please open the HTML report in your web browser to view detailed results."
fi
