#!/bin/bash
#
# PCI DSS Requirement 9: Restrict Physical Access to Cardholder Data
# 
# This script assesses AWS environments against PCI DSS Requirement 9 controls.
# While many physical security controls require manual verification, this script 
# checks relevant AWS configurations that support physical security compliance.
#
# Usage: ./check_pci_requirement9.sh

# Get the directory of the script
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# Source the shared HTML report library
source "$SCRIPT_DIR/pci_html_report_lib.sh"

# Set output colors for terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Set requirement specific variables
REQUIREMENT_NUMBER="9"
REPORT_TITLE="PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
OUTPUT_DIR="$SCRIPT_DIR/reports"
OUTPUT_FILE="$OUTPUT_DIR/pci_requirement${REQUIREMENT_NUMBER}_report_${TIMESTAMP}.html"

# Start script execution
echo "============================================="
echo "  PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER HTML Report"
echo "============================================="
echo ""

# Get the current AWS CLI configured region or use a default
REGION=$(aws configure get region 2>/dev/null)
if [ -z "$REGION" ]; then
    REGION="us-east-1"
    echo -e "${YELLOW}Using default region: $REGION${NC}"
else
    echo -e "${GREEN}Using AWS CLI configured region: $REGION${NC}"
fi

# Ask for specific resources to assess
read -p "Enter VPC IDs to assess (comma-separated or 'all' for all): " TARGET_VPCS
if [ -z "$TARGET_VPCS" ] || [ "$TARGET_VPCS" == "all" ]; then
    echo -e "${YELLOW}Checking all VPCs${NC}"
    TARGET_VPCS="all"
else
    echo -e "${YELLOW}Checking specific VPC(s): $TARGET_VPCS${NC}"
fi

# Ensure the output directory exists
mkdir -p "$OUTPUT_DIR"

# Initialize counters for check statistics
total_checks=0
passed_checks=0
failed_checks=0
warning_checks=0
info_checks=0

# Initialize the HTML report
initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE" "$REQUIREMENT_NUMBER" "$REGION"

# Add script information section
add_section "$OUTPUT_FILE" "script-info" "Script Information" "active"
html_append "$OUTPUT_FILE" "<p>This script assesses AWS environments against PCI DSS Requirement 9 - Restrict Physical Access to Cardholder Data.</p>"
html_append "$OUTPUT_FILE" "<p>Some checks require manual verification as they involve physical security controls that cannot be assessed automatically through AWS APIs.</p>"
html_append "$OUTPUT_FILE" "<p><strong>AWS Region:</strong> $REGION</p>"
html_append "$OUTPUT_FILE" "<p><strong>Target VPCs:</strong> $TARGET_VPCS</p>"
html_append "$OUTPUT_FILE" "<p><strong>Assessment Date:</strong> $(date)</p>"
html_append "$OUTPUT_FILE" "<p><strong>Note:</strong> This assessment follows PCI DSS v4.0.1 requirements.</p>"
close_section "$OUTPUT_FILE"

# Check AWS CLI access and required permissions
add_section "$OUTPUT_FILE" "permissions-check" "AWS Permissions Check" "none"

check_command_access "$OUTPUT_FILE" "ec2" "describe-vpcs" "$REGION"
check_command_access "$OUTPUT_FILE" "s3" "list-buckets" "$REGION"
check_command_access "$OUTPUT_FILE" "cloudtrail" "describe-trails" "$REGION"
check_command_access "$OUTPUT_FILE" "cloudwatch" "describe-alarms" "$REGION"
check_command_access "$OUTPUT_FILE" "iam" "list-roles" "$REGION"
check_command_access "$OUTPUT_FILE" "kms" "list-keys" "$REGION"
check_command_access "$OUTPUT_FILE" "config" "describe-config-rules" "$REGION"
check_command_access "$OUTPUT_FILE" "guardduty" "list-detectors" "$REGION"
check_command_access "$OUTPUT_FILE" "securityhub" "describe-hub" "$REGION"

close_section "$OUTPUT_FILE"

# Note: Requirement 9.1 checks removed as requested

# --------------------------------------------------------------------------
# REQUIREMENT 9.2: Physical access controls manage entry into facilities and systems containing cardholder data
# --------------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-9.2" "Requirement 9.2: Physical access controls manage entry into facilities and systems containing cardholder data" "none"

echo -e "\n${CYAN}=== CHECKING REQUIREMENT 9.2: PHYSICAL ACCESS CONTROLS ===${NC}"

# Check for AWS Config rules related to physical security
config_rules=$(aws configservice describe-config-rules --region $REGION 2>/dev/null | grep -E "PHYSICAL_SECURITY|MEDIA_PROTECTION" || echo "")

if [ -n "$config_rules" ]; then
    add_check_item "$OUTPUT_FILE" "info" "9.2.x - AWS Config Rules for Physical Security" \
        "<p>AWS Config rules related to physical security were found:</p><pre>$config_rules</pre>" \
        "Review these Config rules to ensure they properly monitor compliance with physical security requirements."
    ((info_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "9.2.x - AWS Config Rules for Physical Security" \
        "<p>No AWS Config rules specifically related to physical security were found.</p>" \
        "Consider creating custom AWS Config rules to monitor aspects of your environment related to physical security compliance."
    ((warning_checks++))
fi
((total_checks++))

close_section "$OUTPUT_FILE"

# --------------------------------------------------------------------------
# REQUIREMENT 9.3: Physical access to sensitive areas is controlled
# --------------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-9.3" "Requirement 9.3: Physical access to sensitive areas is controlled" "none"

# Check for KMS Customer Managed Keys (physical equivalent of key management)
kms_keys=$(aws kms list-keys --region $REGION 2>/dev/null)
customer_managed_keys=$(aws kms list-aliases --region $REGION 2>/dev/null | grep -v "alias/aws/" | wc -l)

if [ $customer_managed_keys -gt 0 ]; then
    key_details="<p>Found $customer_managed_keys customer-managed KMS keys that can be used for encrypting sensitive data.</p>"
    
    # Get rotation status for customer managed keys
    key_ids=$(echo "$kms_keys" | grep "KeyId" | awk -F'"' '{print $4}')
    rotation_enabled=0
    rotation_disabled=0
    
    key_details+="<p>Key rotation status:</p><ul>"
    for key_id in $key_ids; do
        # Skip AWS managed keys
        alias_check=$(aws kms list-aliases --key-id "$key_id" --region $REGION 2>/dev/null | grep "AliasName" | grep "alias/aws/")
        if [ -n "$alias_check" ]; then
            continue
        fi
        
        rotation=$(aws kms get-key-rotation-status --key-id "$key_id" --region $REGION 2>/dev/null | grep "KeyRotationEnabled" || echo "")
        if [[ "$rotation" == *"true"* ]]; then
            rotation_enabled=$((rotation_enabled+1))
            key_details+="<li>Key $key_id: Rotation ENABLED</li>"
        else
            rotation_disabled=$((rotation_disabled+1))
            key_details+="<li class=\"red\">Key $key_id: Rotation DISABLED</li>"
        fi
    done
    key_details+="</ul>"
    
    if [ $rotation_disabled -gt 0 ]; then
        add_check_item "$OUTPUT_FILE" "fail" "9.3.x - KMS Key Management (equivalent to physical key control)" \
            "$key_details" \
            "Enable automatic key rotation for all customer-managed KMS keys to ensure cryptographic key security."
        ((failed_checks++))
    else
        add_check_item "$OUTPUT_FILE" "pass" "9.3.x - KMS Key Management (equivalent to physical key control)" \
            "$key_details" \
            "All customer-managed KMS keys have rotation enabled, which is a good practice for key management."
        ((passed_checks++))
    fi
else
    add_check_item "$OUTPUT_FILE" "info" "9.3.x - KMS Key Management (equivalent to physical key control)" \
        "<p>No customer-managed KMS keys were found. This may be acceptable if you're not using KMS for encryption or only using AWS-managed keys.</p>" \
        "Consider implementing customer-managed KMS keys with proper key rotation for sensitive data encryption."
    ((info_checks++))
fi
((total_checks++))

close_section "$OUTPUT_FILE"

# --------------------------------------------------------------------------
# REQUIREMENT 9.4: Media with cardholder data is securely stored, accessed, distributed, and destroyed
# --------------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-9.4" "Requirement 9.4: Media with cardholder data is securely stored, accessed, distributed, and destroyed" "none"

echo -e "\n${CYAN}=== CHECKING REQUIREMENT 9.4: MEDIA SECURITY ===${NC}"

# Check for S3 bucket encryption
s3_buckets=$(aws s3api list-buckets --query 'Buckets[*].Name' --output text --region $REGION 2>/dev/null)
if [ -n "$s3_buckets" ]; then
    bucket_count=0
    encrypted_buckets=0
    unencrypted_buckets=0
    bucket_details="<p>S3 Bucket Encryption Status:</p><ul>"
    
    for bucket in $s3_buckets; do
        bucket_count=$((bucket_count+1))
        
        # Check for default encryption
        encryption=$(aws s3api get-bucket-encryption --bucket "$bucket" --region $REGION 2>/dev/null || echo "")
        
        if [ -n "$encryption" ]; then
            encrypted_buckets=$((encrypted_buckets+1))
            bucket_details+="<li>Bucket $bucket: Encryption ENABLED</li>"
        else
            unencrypted_buckets=$((unencrypted_buckets+1))
            bucket_details+="<li class=\"red\">Bucket $bucket: Encryption NOT ENABLED</li>"
        fi
    done
    bucket_details+="</ul>"
    
    if [ $unencrypted_buckets -gt 0 ]; then
        add_check_item "$OUTPUT_FILE" "fail" "9.4.x - S3 Bucket Encryption (for secure media storage)" \
            "$bucket_details" \
            "Enable default encryption for all S3 buckets, preferably using KMS with customer-managed keys. Verify no cardholder data is stored in unencrypted buckets."
        ((failed_checks++))
    else
        add_check_item "$OUTPUT_FILE" "pass" "9.4.x - S3 Bucket Encryption (for secure media storage)" \
            "$bucket_details" \
            "All S3 buckets have encryption enabled, which is a good practice for secure storage."
        ((passed_checks++))
    fi
else
    add_check_item "$OUTPUT_FILE" "info" "9.4.x - S3 Bucket Encryption (for secure media storage)" \
        "<p>No S3 buckets were found or the credentials don't have permission to list buckets.</p>" \
        "Ensure all S3 buckets that store cardholder data or backups have default encryption enabled."
    ((info_checks++))
fi
((total_checks++))

# Check for AWS Config Service - Enhanced with more detail
config_status=$(aws configservice describe-configuration-recorders --region $REGION 2>/dev/null || echo "")
if [ -n "$config_status" ]; then
    config_recorder_status=$(aws configservice describe-configuration-recorder-status --region $REGION 2>/dev/null || echo "")
    
    # Get the list of resource types being recorded
    resource_types=$(echo "$config_status" | grep -o '"ResourceTypes": \[[^]]*\]' || echo "No resource types specified")
    
    if [[ "$config_recorder_status" == *"\"recording\":true"* ]]; then
        add_check_item "$OUTPUT_FILE" "pass" "9.4.5 - Resource Inventory with AWS Config" \
            "<p>AWS Config is enabled and recording, which helps maintain inventory of AWS resources that may contain cardholder data.</p>
            <p><strong>Config recorder details:</strong></p>
            <pre>$config_status</pre>
            <p><strong>Resource types being tracked:</strong></p>
            <pre>$resource_types</pre>
            <p>AWS Config supports requirement 9.4.5 by providing automated inventory tracking of electronic media (AWS resources) that may contain cardholder data.</p>" \
            "Ensure AWS Config is configured to track all resource types that might contain cardholder data, especially: EC2 instances, EBS volumes, S3 buckets, RDS instances, DynamoDB tables, and Lambda functions. Tag all resources containing cardholder data for easy identification."
        ((passed_checks++))
    else
        add_check_item "$OUTPUT_FILE" "fail" "9.4.5 - Resource Inventory with AWS Config" \
            "<p>AWS Config is set up but not actively recording. This means inventory of AWS resources that may contain cardholder data is not being maintained.</p>
            <p><strong>Config recorder details:</strong></p>
            <pre>$config_status</pre>
            <p><strong>Recorder status:</strong></p>
            <pre>$config_recorder_status</pre>" \
            "Enable AWS Config recording immediately to maintain an inventory of AWS resources that may contain cardholder data. Configure it to track all resource types relevant to your cardholder data environment."
        ((failed_checks++))
    fi
else
    add_check_item "$OUTPUT_FILE" "fail" "9.4.5 - Resource Inventory with AWS Config" \
        "<p>AWS Config is not set up in this region. AWS Config is essential for maintaining an inventory of resources that may contain cardholder data as required by PCI DSS 9.4.5.</p>
        <p>Without AWS Config:</p>
        <ul>
            <li>No automated inventory of AWS resources is maintained</li>
            <li>Changes to resource configurations aren't tracked</li>
            <li>Compliance with configuration rules can't be monitored</li>
        </ul>" \
        "Set up AWS Config immediately to track all resource types that may contain cardholder data, including EC2 instances, EBS volumes, S3 buckets, RDS instances, DynamoDB tables, and Lambda functions. Implement resource tagging to identify resources that contain cardholder data."
    ((failed_checks++))
fi
((total_checks++))

close_section "$OUTPUT_FILE"

# --------------------------------------------------------------------------
# REQUIREMENT 9.5: Point of interaction (POI) devices are protected from tampering and unauthorized substitution
# --------------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-9.5" "Requirement 9.5: Point of interaction (POI) devices are protected from tampering and unauthorized substitution" "none"

echo -e "\n${CYAN}=== CHECKING REQUIREMENT 9.5: POI DEVICE SECURITY ===${NC}"

# Check for IoT Core usage (potential POI device management)
iot_things=$(aws iot list-things --region $REGION 2>/dev/null || echo "")
if [ -n "$iot_things" ] && [[ "$iot_things" != *"\"things\": \[\]"* ]]; then
    add_check_item "$OUTPUT_FILE" "info" "9.5.x - AWS IoT Core Usage (potential POI device management)" \
        "<p>AWS IoT Core is being used, which may indicate the presence of connected devices:</p><pre>$iot_things</pre>
        <p>If these include payment terminals or POI devices, additional security controls are required.</p>" \
        "If AWS IoT Core is used for POI devices, implement strong authentication, encryption, and monitoring for these devices. Ensure device certificates are properly managed and secured."
    ((info_checks++))
else
    add_check_item "$OUTPUT_FILE" "info" "9.5.x - AWS IoT Core Usage (potential POI device management)" \
        "<p>No AWS IoT Core devices were found, or permissions are insufficient to list them.</p>" \
        "If your organization manages POI devices outside of AWS, ensure those devices are properly inventoried and secured."
    ((info_checks++))
fi
((total_checks++))

close_section "$OUTPUT_FILE"

# --------------------------------------------------------------------------
# REQUIREMENT 9.6: Access to racks and cabinets with systems in the CDE is physically secure
# --------------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-9.6" "Requirement 9.6: Racks and cabinets are physically secure" "none"

add_check_item "$OUTPUT_FILE" "info" "9.6.x - Physical Security of Racks and Cabinets" \
    "<p>This requirement is managed by AWS under the shared responsibility model.</p>
    <p>In AWS environments, physical security of racks and cabinets is fully managed by AWS and covered in their compliance certifications.</p>" \
    "Review AWS compliance documentation to verify AWS's implementation of physical security controls for data center racks and cabinets."
((info_checks++))
((total_checks++))

close_section "$OUTPUT_FILE"

# --------------------------------------------------------------------------
# REQUIREMENT 9.7: Information on payment cards and cardholder data is protected during transportation
# --------------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-9.7" "Requirement 9.7: Cardholder data is protected during transportation" "none"

# Check for VPN connections (secure transit method)
vpn_connections=$(aws ec2 describe-vpn-connections --region $REGION 2>/dev/null || echo "")
if [ -n "$vpn_connections" ] && [[ "$vpn_connections" != *"\"VpnConnections\": \[\]"* ]]; then
    add_check_item "$OUTPUT_FILE" "info" "9.7.x - VPN Connections (for secure data transit)" \
        "<p>VPN connections are in use, which can provide secure transit paths for cardholder data:</p><pre>$vpn_connections</pre>" \
        "Ensure VPN connections use strong encryption and are properly documented in your security policies."
    ((info_checks++))
else
    add_check_item "$OUTPUT_FILE" "info" "9.7.x - VPN Connections (for secure data transit)" \
        "<p>No VPN connections were found. If cardholder data is transferred between networks, secure methods should be implemented.</p>" \
        "Consider implementing VPN, Direct Connect, or other secure transit methods if cardholder data needs to be transferred between networks."
    ((info_checks++))
fi
((total_checks++))

# Check for Direct Connect (secure transit method)
direct_connect=$(aws directconnect describe-connections --region $REGION 2>/dev/null || echo "")
if [ -n "$direct_connect" ] && [[ "$direct_connect" != *"\"connections\": \[\]"* ]]; then
    add_check_item "$OUTPUT_FILE" "info" "9.7.x - Direct Connect (for secure data transit)" \
        "<p>AWS Direct Connect is in use, which provides a dedicated private connection for data transit:</p><pre>$direct_connect</pre>" \
        "Ensure Direct Connect links are properly documented in your security policies and included in your network diagrams."
    ((info_checks++))
else
    add_check_item "$OUTPUT_FILE" "info" "9.7.x - Direct Connect (for secure data transit)" \
        "<p>No Direct Connect connections were found. This is informational only.</p>" \
        "Direct Connect provides a dedicated private connection to AWS, which can be beneficial for secure transfer of sensitive data."
    ((info_checks++))
fi
((total_checks++))

close_section "$OUTPUT_FILE"

# --------------------------------------------------------------------------
# REQUIREMENT 9.8: Processes for protecting operational technology from unauthorized access
# --------------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-9.8" "Requirement 9.8: Processes for protecting operational technology" "none"

add_check_item "$OUTPUT_FILE" "info" "9.8.x - Operational Technology Security" \
    "<p>This requirement typically applies to specialized operational technology that may exist in your environment.</p>
    <p>AWS environments may include IoT or specialized operational technology that needs to be protected from physical attacks.</p>" \
    "If you maintain operational technology connected to AWS, implement appropriate security controls and protection measures."
((info_checks++))
((total_checks++))

close_section "$OUTPUT_FILE"

# --------------------------------------------------------------------------
# REQUIREMENT 9.9: Equipment containing payment card data is protected from unauthorized access
# --------------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-9.9" "Requirement 9.9: Equipment with cardholder data is protected" "none"

# Check IAM policies with PCI references
iam_policies=$(aws iam list-policies --scope Local --region $REGION 2>/dev/null | grep -E "PCI|CDE|Cardholder" || echo "")
if [ -n "$iam_policies" ]; then
    add_check_item "$OUTPUT_FILE" "info" "9.9.x - IAM Policies for Cardholder Data Access" \
        "<p>Found IAM policies that may be related to PCI compliance:</p><pre>$iam_policies</pre>" \
        "Review these IAM policies to ensure they properly restrict access to resources containing cardholder data."
    ((info_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "9.9.x - IAM Policies for Cardholder Data Access" \
        "<p>No IAM policies specifically mentioning PCI, CDE, or cardholder data were found.</p>" \
        "Consider implementing specific IAM policies for resources containing cardholder data, with clear naming conventions that identify their PCI relevance."
    ((warning_checks++))
fi
((total_checks++))

close_section "$OUTPUT_FILE"

# --------------------------------------------------------------------------
# AWS Specific Implementation Considerations for Requirement 9
# --------------------------------------------------------------------------
add_section "$OUTPUT_FILE" "aws-specific" "AWS Specific Implementation Considerations" "none"

# General AWS Physical Control Considerations
add_check_item "$OUTPUT_FILE" "info" "AWS Shared Responsibility Model for Physical Security" \
    "<p>Under the AWS Shared Responsibility Model, AWS is responsible for the physical security of the infrastructure that runs AWS services.</p>
    <p>Key considerations for AWS customers:</p>
    <ul>
        <li>Responsibility for physical security of the cloud infrastructure lies with AWS</li>
        <li>Customers are responsible for implementing logical security controls for their AWS resources</li>
        <li>Customers should document AWS's physical security controls in their PCI DSS documentation</li>
        <li>Customers should obtain and review AWS compliance reports (e.g., SOC 2, PCI AOC)</li>
    </ul>" \
    "Document the AWS Shared Responsibility Model in your security policies, clearly delineating AWS's physical security responsibilities and your own logical security responsibilities."
((info_checks++))
((total_checks++))

# AWS Artifact for Compliance Documentation
artifact_check=$(aws artifact list-agreements --region $REGION 2>/dev/null || echo "Error: AWS Artifact access requires Console")
if [[ "$artifact_check" == *"Error"* ]]; then
    add_check_item "$OUTPUT_FILE" "info" "AWS Artifact Access for Compliance Documentation" \
        "<p>AWS Artifact access couldn't be verified through the CLI. AWS Artifact provides access to AWS's compliance documentation.</p>
        <p>Action: Access AWS Artifact through the AWS Console and download the relevant compliance reports.</p>" \
        "Access AWS Artifact through the AWS Console and download the PCI DSS Attestation of Compliance (AOC) and Responsibility Summary."
    ((info_checks++))
else
    add_check_item "$OUTPUT_FILE" "info" "AWS Artifact Access for Compliance Documentation" \
        "<p>AWS Artifact access appears to be available. AWS Artifact provides access to AWS's compliance documentation.</p>
        <p>Action: Download the relevant compliance reports from AWS Artifact.</p>" \
        "Download and review the PCI DSS Attestation of Compliance (AOC) and Responsibility Summary from AWS Artifact."
    ((info_checks++))
fi
((total_checks++))

# Check for resource tags related to PCI
tags_check=$(aws resourcegroupstaggingapi get-resources --region $REGION 2>/dev/null | grep -E "\"Key\":\s*\"PCI|\"Key\":\s*\"CDE|\"Key\":\s*\"Cardholder" || echo "")
if [ -n "$tags_check" ]; then
    add_check_item "$OUTPUT_FILE" "pass" "Resource Tagging for PCI Scope Identification" \
        "<p>Found resources tagged with PCI or CDE related tags, which helps identify PCI scope:</p><pre>$tags_check</pre>" \
        "Continue using a consistent tagging strategy to identify resources within PCI scope."
    ((passed_checks++))
else
    add_check_item "$OUTPUT_FILE" "info" "Resource Tagging for PCI Scope Identification" \
        "<p>No resources tagged with PCI or CDE related tags were found. Tagging is recommended to clearly identify resources within PCI scope.</p>" \
        "Implement a tagging strategy for all resources in PCI scope, using tags such as 'PCI-Scope=Yes', 'Environment=CDE', or similar."
    ((info_checks++))
fi
((total_checks++))

close_section "$OUTPUT_FILE"

# Finalize the HTML report
finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"

echo -e "\nPCI DSS Requirement $REQUIREMENT_NUMBER assessment completed."
echo -e "Results: $passed_checks passed, $failed_checks failed, $warning_checks warnings, $info_checks info out of $total_checks total checks."
echo -e "Report saved to: $OUTPUT_FILE"

# Optional: Open the report automatically on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$OUTPUT_FILE"
fi

exit 0