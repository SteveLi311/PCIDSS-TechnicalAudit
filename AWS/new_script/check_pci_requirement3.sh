#!/bin/bash

# PCI DSS Requirement 3 Compliance Check Script for AWS
# This script evaluates AWS controls for PCI DSS Requirement 3 compliance
# Requirements covered: 3.1 - 3.7 (Protect Stored Account Data)

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
REQUIREMENT_NUMBER="3"
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
if [ -z "$TARGET_RESOURCES" ]; then
    read -p "Enter resource IDs to assess (comma-separated or 'all' for all): " TARGET_RESOURCES
    if [ -z "$TARGET_RESOURCES" ] || [ "$TARGET_RESOURCES" == "all" ]; then
        echo -e "${YELLOW}Checking all resources${NC}"
        TARGET_RESOURCES="all"
    else
        echo -e "${YELLOW}Checking specific resource(s): $TARGET_RESOURCES${NC}"
    fi
else
    echo -e "${YELLOW}Using provided TARGET_RESOURCES: $TARGET_RESOURCES${NC}"
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

# Check permissions for services needed to evaluate Requirement 3
check_command_access "$OUTPUT_FILE" "rds" "describe-db-instances" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "dynamodb" "list-tables" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "s3" "list-buckets" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "ec2" "describe-instances" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "kms" "list-keys" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "cloudtrail" "describe-trails" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

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
# SECTION 2: DETERMINE RESOURCES TO CHECK
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "target-resources" "Target Resources" "block"

echo -e "\n${CYAN}=== IDENTIFYING TARGET RESOURCES ===${NC}"

# Initialize resource arrays
declare -a DB_INSTANCES=()
declare -a S3_BUCKETS=()
declare -a DYNAMO_TABLES=()
declare -a EC2_INSTANCES=()

# Retrieve resources based on user input
if [ "$TARGET_RESOURCES" == "all" ]; then
    # Get RDS instances
    echo -e "Retrieving RDS instances..."
    RDS_INSTANCES=$(aws rds describe-db-instances --region $REGION --query 'DBInstances[*].DBInstanceIdentifier' --output text 2>/dev/null)
    if [ -n "$RDS_INSTANCES" ]; then
        readarray -t DB_INSTANCES <<< "$RDS_INSTANCES"
        echo -e "Found ${#DB_INSTANCES[@]} RDS instances"
    else
        echo -e "No RDS instances found or access denied"
    fi
    
    # Get S3 buckets
    echo -e "Retrieving S3 buckets..."
    S3_BUCKETS_LIST=$(aws s3 ls --region $REGION 2>/dev/null | awk '{print $3}')
    if [ -n "$S3_BUCKETS_LIST" ]; then
        readarray -t S3_BUCKETS <<< "$S3_BUCKETS_LIST"
        echo -e "Found ${#S3_BUCKETS[@]} S3 buckets"
    else
        echo -e "No S3 buckets found or access denied"
    fi
    
    # Get DynamoDB tables
    echo -e "Retrieving DynamoDB tables..."
    DYNAMO_TABLES_LIST=$(aws dynamodb list-tables --region $REGION --query 'TableNames[*]' --output text 2>/dev/null)
    if [ -n "$DYNAMO_TABLES_LIST" ]; then
        readarray -t DYNAMO_TABLES <<< "$DYNAMO_TABLES_LIST"
        echo -e "Found ${#DYNAMO_TABLES[@]} DynamoDB tables"
    else
        echo -e "No DynamoDB tables found or access denied"
    fi
    
    # Get EC2 instances
    echo -e "Retrieving EC2 instances..."
    EC2_INSTANCES_LIST=$(aws ec2 describe-instances --region $REGION --query 'Reservations[*].Instances[*].InstanceId' --output text 2>/dev/null)
    if [ -n "$EC2_INSTANCES_LIST" ]; then
        readarray -t EC2_INSTANCES <<< "$EC2_INSTANCES_LIST"
        echo -e "Found ${#EC2_INSTANCES[@]} EC2 instances"
    else
        echo -e "No EC2 instances found or access denied"
    fi
    
    add_check_item "$OUTPUT_FILE" "info" "Resource Identification" "Assessment will include:<br>
    - RDS Instances: ${#DB_INSTANCES[@]}<br>
    - S3 Buckets: ${#S3_BUCKETS[@]}<br>
    - DynamoDB Tables: ${#DYNAMO_TABLES[@]}<br>
    - EC2 Instances: ${#EC2_INSTANCES[@]}"
else
    # Parse specified resources
    echo -e "Using specified resources: $TARGET_RESOURCES"
    # Implement logic to parse specific resource IDs if needed
    add_check_item "$OUTPUT_FILE" "info" "Resource Identification" "Assessment will be performed on specified resources: <pre>${TARGET_RESOURCES}</pre>"
fi

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 3: PCI REQUIREMENT 3.1 - PROCESSES AND MECHANISMS
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-3.1" "Requirement 3.1: Processes and mechanisms for protecting stored account data are defined and understood" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 3.1: PROCESSES AND MECHANISMS ===${NC}"

# Requirement 3.1.1
add_check_item "$OUTPUT_FILE" "warning" "3.1.1 - Security Policies and Procedures" "This check verifies if all security policies and operational procedures for protecting stored account data are documented, up to date, in use, and known to all affected parties." "Ensure documentation of policies and procedures for protecting stored account data is current, accessible, and covers all aspects of Requirement 3. Verify that relevant personnel are aware of and following these procedures."
((total_checks++))
((warning_checks++))

# Requirement 3.1.2
add_check_item "$OUTPUT_FILE" "warning" "3.1.2 - Roles and Responsibilities" "This check verifies if roles and responsibilities for performing activities in Requirement 3 are documented, assigned, and understood." "Document and assign roles and responsibilities for protection of stored account data. Ensure personnel understand their responsibilities."
((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 4: PCI REQUIREMENT 3.2 - STORAGE OF ACCOUNT DATA
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-3.2" "Requirement 3.2: Storage of account data is kept to a minimum" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 3.2: STORAGE OF ACCOUNT DATA ===${NC}"

# Requirement 3.2.1
add_check_item "$OUTPUT_FILE" "warning" "3.2.1 - Data Retention and Disposal" "Check for implementation of data retention and disposal policies that minimize storage of account data. Manual verification required to confirm policies that cover: all locations of stored data, retention periods with business justification, secure deletion methods, and quarterly verification processes." "Implement data retention and disposal policies that include all locations of stored data, limit storage amount and retention time, define specific retention requirements with business justification, and include secure deletion processes. Verify quarterly that data exceeding retention periods is removed."
((total_checks++))
((warning_checks++))

# Check for S3 lifecycle policies
echo -e "Checking S3 buckets for lifecycle policies..."
s3_with_lifecycle=0
s3_without_lifecycle=0

for bucket in "${S3_BUCKETS[@]}"; do
    echo -e "Checking lifecycle policy for bucket: $bucket"
    LIFECYCLE=$(aws s3api get-bucket-lifecycle-configuration --bucket "$bucket" --region $REGION 2>&1)
    
    if [[ $LIFECYCLE == *"NoSuchLifecycleConfiguration"* ]]; then
        echo -e "${YELLOW}No lifecycle policy found for bucket: $bucket${NC}"
        ((s3_without_lifecycle++))
    elif [[ $LIFECYCLE == *"AccessDenied"* ]]; then
        echo -e "${RED}Access denied when checking lifecycle policy for bucket: $bucket${NC}"
    else
        echo -e "${GREEN}Lifecycle policy found for bucket: $bucket${NC}"
        ((s3_with_lifecycle++))
    fi
done

if [ $s3_with_lifecycle -gt 0 ]; then
    if [ $s3_without_lifecycle -eq 0 ]; then
        add_check_item "$OUTPUT_FILE" "pass" "3.2.1 - S3 Data Lifecycle Policies" "All S3 buckets have lifecycle policies configured ($s3_with_lifecycle of ${#S3_BUCKETS[@]})."
        ((total_checks++))
        ((passed_checks++))
    else
        # Create a detailed list of buckets without lifecycle policies
        bucket_details="<p>The following S3 buckets do not have lifecycle policies configured:</p><ul>"
        for bucket in "${S3_BUCKETS[@]}"; do
            LIFECYCLE=$(aws s3api get-bucket-lifecycle-configuration --bucket "$bucket" --region $REGION 2>&1)
            if [[ $LIFECYCLE == *"NoSuchLifecycleConfiguration"* ]]; then
                bucket_details+="<li>$bucket</li>"
            fi
        done
        bucket_details+="</ul><p>Lifecycle policies are essential for ensuring that data is retained only as long as necessary for business purposes, in accordance with PCI DSS requirement 3.2.1.</p>"
        
        add_check_item "$OUTPUT_FILE" "warning" "3.2.1 - S3 Data Lifecycle Policies" "$bucket_details" "Configure lifecycle policies for all S3 buckets that may contain account data to ensure data is retained only as long as necessary and to automatically enforce retention policies."
        ((total_checks++))
        ((warning_checks++))
    fi
else
    if [ ${#S3_BUCKETS[@]} -gt 0 ]; then
        add_check_item "$OUTPUT_FILE" "warning" "3.2.1 - S3 Data Lifecycle Policies" "No S3 buckets were found to have lifecycle policies configured." "Configure lifecycle policies for all S3 buckets that may contain account data to ensure data is retained only as long as necessary."
        ((total_checks++))
        ((warning_checks++))
    fi
fi

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 5: PCI REQUIREMENT 3.3 - SENSITIVE AUTHENTICATION DATA
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-3.3" "Requirement 3.3: Sensitive authentication data (SAD) is not stored after authorization" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 3.3: SENSITIVE AUTHENTICATION DATA ===${NC}"

# Requirement 3.3.1
add_check_item "$OUTPUT_FILE" "warning" "3.3.1 - SAD Storage Prohibition" "This check verifies that sensitive authentication data (SAD) is not stored after authorization, even if encrypted." "Implement processes to ensure that full track data, card verification codes, and PINs/PIN blocks are not stored after authorization is complete. Any storage of SAD before authorization must be encrypted and securely deleted when no longer needed."
((total_checks++))
((warning_checks++))

# Check for database parameter groups that might indicate logging levels
if [ ${#DB_INSTANCES[@]} -gt 0 ]; then
    echo -e "Checking RDS parameter groups for potential issues with sensitive data..."
    
    for db in "${DB_INSTANCES[@]}"; do
        # Get DB details including engine type
        DB_DETAILS=$(aws rds describe-db-instances --db-instance-identifier "$db" --region $REGION 2>/dev/null)
        ENGINE=$(echo "$DB_DETAILS" | grep -o '"Engine": "[^"]*' | cut -d'"' -f4)
        
        if [[ "$ENGINE" == "mysql" || "$ENGINE" == "mariadb" ]]; then
            PG_NAME=$(echo "$DB_DETAILS" | grep -o '"DBParameterGroupName": "[^"]*' | cut -d'"' -f4)
            
            if [ -n "$PG_NAME" ]; then
                # Check for parameters related to logging that might capture SAD
                PARAMS=$(aws rds describe-db-parameters --db-parameter-group-name "$PG_NAME" --region $REGION 2>/dev/null)
                
                # Check specific parameters
                GQL=$(echo "$PARAMS" | grep -A5 '"ParameterName": "general_log"' | grep -o '"ParameterValue": "[^"]*' | cut -d'"' -f4)
                
                if [[ "$GQL" == "1" || "$GQL" == "ON" ]]; then
                    add_check_item "$OUTPUT_FILE" "warning" "3.3.1 - MySQL/MariaDB Logging Settings" "The database instance $db has general query logging enabled, which might capture sensitive authentication data." "Disable general query logging or ensure it doesn't capture SAD. Review query logs to confirm they don't contain sensitive data."
                    ((total_checks++))
                    ((warning_checks++))
                fi
            fi
        fi
    done
fi

# Requirement 3.3.2
add_check_item "$OUTPUT_FILE" "warning" "3.3.2 - SAD Pre-Authorization Encryption" "This check verifies that any SAD stored electronically prior to authorization is encrypted using strong cryptography." "If SAD must be stored before authorization is complete, ensure it is encrypted with strong cryptography."
((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 6: PCI REQUIREMENT 3.4 - PAN DISPLAY
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-3.4" "Requirement 3.4: Access to displays of full PAN and ability to copy PAN are restricted" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 3.4: PAN DISPLAY ===${NC}"

# Requirement 3.4.1
add_check_item "$OUTPUT_FILE" "warning" "3.4.1 - PAN Masking" "This check verifies if PAN is masked when displayed (the BIN and last four digits are the maximum number of digits to be displayed)" "Ensure that all systems displaying PAN implement proper masking, showing only the BIN and last four digits. Verify that only personnel with a legitimate business need can see the full PAN."
((total_checks++))
((warning_checks++))

# Requirement 3.4.2
add_check_item "$OUTPUT_FILE" "warning" "3.4.2 - Remote-Access PAN Controls" "This check verifies if technical controls are in place to prevent copying of PAN when using remote-access technologies" "Implement technical controls to prevent copying or relocating of PAN during remote access sessions, except for personnel with documented, explicit authorization and legitimate business need."
((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 7: PCI REQUIREMENT 3.5 - PAN SECURITY
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-3.5" "Requirement 3.5: Primary account number (PAN) is secured wherever it is stored" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 3.5: PAN SECURITY ===${NC}"

# Requirement 3.5.1
add_check_item "$OUTPUT_FILE" "warning" "3.5.1 - PAN Unreadability" "This check verifies if PAN is rendered unreadable anywhere it is stored using appropriate methods (hashing, truncation, tokens, or encryption)" "Ensure PAN is unreadable using one of these methods: one-way hashes based on strong cryptography, truncation, index tokens, or strong cryptography with key management."
((total_checks++))
((warning_checks++))

# Check for KMS keys usage
echo -e "Checking KMS key usage..."
KMS_KEYS_LIST=$(aws kms list-keys --region $REGION 2>/dev/null)
if [ -n "$KMS_KEYS_LIST" ]; then
    KEY_COUNT=$(echo "$KMS_KEYS_LIST" | grep -c "KeyId")
    if [ $KEY_COUNT -gt 0 ]; then
        # Store KMS keys in the array for later use
        readarray -t KMS_KEYS < <(echo "$KMS_KEYS_LIST" | grep -o '"KeyId": "[^"]*' | cut -d'"' -f4)
        
        # Count customer-managed vs AWS-managed keys
        CUSTOMER_KEYS=0
        AWS_KEYS=0
        
        for key_id in "${KMS_KEYS[@]}"; do
            key_manager=$(aws kms describe-key --key-id "$key_id" --region $REGION --query 'KeyMetadata.KeyManager' --output text 2>/dev/null)
            
            if [ "$key_manager" == "CUSTOMER" ]; then
                ((CUSTOMER_KEYS++))
            elif [ "$key_manager" == "AWS" ]; then
                ((AWS_KEYS++))
            fi
        done
        
        key_details="<p>Found $KEY_COUNT KMS keys:</p><ul>
            <li>Customer-managed keys: $CUSTOMER_KEYS</li>
            <li>AWS-managed keys: $AWS_KEYS</li>
        </ul>
        <p>These keys could be used for encryption of sensitive data. Manual verification is needed to ensure they are properly used for PAN encryption.</p>"
        
        add_check_item "$OUTPUT_FILE" "info" "3.5.1 - KMS Key Availability" "$key_details"
    else
        add_check_item "$OUTPUT_FILE" "warning" "3.5.1 - KMS Key Availability" "<p>No KMS keys were found. If storing PAN, ensure proper encryption methods are used.</p>" "Create and use KMS keys to encrypt sensitive data if storing PAN in AWS services."
    fi
    ((total_checks++))
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "3.5.1 - KMS Key Availability" "<p>Unable to retrieve KMS keys. Ensure proper encryption methods are used for PAN data.</p>" "Create and use KMS keys to encrypt sensitive data if storing PAN in AWS services."
    ((total_checks++))
    ((warning_checks++))
fi

# Check EBS Encryption
echo -e "Checking EC2 EBS volume encryption..."
ENCRYPTED_VOLUMES=0
UNENCRYPTED_VOLUMES=0
TOTAL_VOLUMES=0

for instance in "${EC2_INSTANCES[@]}"; do
    # Get volumes attached to the instance
    VOLUMES=$(aws ec2 describe-instances --instance-ids "$instance" --region $REGION --query 'Reservations[*].Instances[*].BlockDeviceMappings[*].Ebs.VolumeId' --output text 2>/dev/null)
    
    for volume in $VOLUMES; do
        ((TOTAL_VOLUMES++))
        # Check if volume is encrypted
        ENCRYPTION=$(aws ec2 describe-volumes --volume-ids "$volume" --region $REGION --query 'Volumes[*].Encrypted' --output text 2>/dev/null)
        
        if [[ "$ENCRYPTION" == "True" ]]; then
            ((ENCRYPTED_VOLUMES++))
        else
            ((UNENCRYPTED_VOLUMES++))
        fi
    done
done

if [ $TOTAL_VOLUMES -gt 0 ]; then
    ENCRYPTION_PERCENTAGE=$(( (ENCRYPTED_VOLUMES * 100) / TOTAL_VOLUMES ))
    
    if [ $ENCRYPTION_PERCENTAGE -eq 100 ]; then
        add_check_item "$OUTPUT_FILE" "pass" "3.5.1 - EBS Volume Encryption" "All EBS volumes ($ENCRYPTED_VOLUMES of $TOTAL_VOLUMES) are encrypted."
        ((total_checks++))
        ((passed_checks++))
    else
        add_check_item "$OUTPUT_FILE" "warning" "3.5.1 - EBS Volume Encryption" "$UNENCRYPTED_VOLUMES of $TOTAL_VOLUMES EBS volumes are not encrypted. If these volumes store PAN, they must be encrypted." "Encrypt all EBS volumes that may contain PAN or migrate data to encrypted volumes."
        ((total_checks++))
        ((warning_checks++))
    fi
fi

# Check RDS Encryption
echo -e "Checking RDS instance encryption..."
ENCRYPTED_RDS=0
UNENCRYPTED_RDS=0

for db in "${DB_INSTANCES[@]}"; do
    # Check if RDS instance is encrypted
    ENCRYPTION=$(aws rds describe-db-instances --db-instance-identifier "$db" --region $REGION --query 'DBInstances[*].StorageEncrypted' --output text 2>/dev/null)
    
    if [[ "$ENCRYPTION" == "True" ]]; then
        ((ENCRYPTED_RDS++))
    else
        ((UNENCRYPTED_RDS++))
    fi
done

if [ ${#DB_INSTANCES[@]} -gt 0 ]; then
    if [ $UNENCRYPTED_RDS -eq 0 ]; then
        add_check_item "$OUTPUT_FILE" "pass" "3.5.1 - RDS Encryption" "All RDS instances ($ENCRYPTED_RDS of ${#DB_INSTANCES[@]}) are encrypted."
        ((total_checks++))
        ((passed_checks++))
    else
        # Create a detailed list of unencrypted RDS instances
        rds_details="<p>The following RDS instances are not encrypted:</p><ul>"
        for db in "${DB_INSTANCES[@]}"; do
            ENCRYPTION=$(aws rds describe-db-instances --db-instance-identifier "$db" --region $REGION --query 'DBInstances[*].StorageEncrypted' --output text 2>/dev/null)
            if [[ "$ENCRYPTION" != "True" ]]; then
                # Get additional details about the instance
                DB_ENGINE=$(aws rds describe-db-instances --db-instance-identifier "$db" --region $REGION --query 'DBInstances[*].Engine' --output text 2>/dev/null)
                DB_SIZE=$(aws rds describe-db-instances --db-instance-identifier "$db" --region $REGION --query 'DBInstances[*].AllocatedStorage' --output text 2>/dev/null)
                rds_details+="<li>$db (Engine: $DB_ENGINE, Storage: ${DB_SIZE}GB)</li>"
            fi
        done
        rds_details+="</ul><p>Unencrypted RDS instances that store PAN do not comply with PCI DSS requirement 3.5.1, which requires PAN to be rendered unreadable.</p>"
        
        add_check_item "$OUTPUT_FILE" "warning" "3.5.1 - RDS Encryption" "$rds_details" "Encrypt all RDS instances that may contain PAN or migrate data to encrypted instances. AWS RDS supports encryption using AWS KMS keys. Consider creating snapshots of your unencrypted instances, encrypting them, and restoring to new encrypted instances."
        ((total_checks++))
        ((warning_checks++))
    fi
fi

# Requirements 3.5.1.2 and 3.5.1.3 - Disk Encryption Controls
# Check for evidence of specialized key management 

# Check CloudHSM usage (hardware security module)
cloudhsm_info=$(aws cloudhsm describe-clusters --region $REGION 2>/dev/null)
cloudhsm_clusters=0
if [ $? -eq 0 ]; then
    cloudhsm_clusters=$(echo "$cloudhsm_info" | grep -c "ClusterId")
fi

# Check for custom KMS key stores
key_stores_info=$(aws kms describe-custom-key-stores --region $REGION 2>/dev/null) 
key_stores=0
if [ $? -eq 0 ]; then
    key_stores=$(echo "$key_stores_info" | grep -c "CustomKeyStoreId")
fi

# Check key rotation status for customer-managed keys
rotated_keys=0
non_rotated_keys=0
customer_keys=0

for key_id in "${KMS_KEYS[@]}"; do
    key_manager=$(aws kms describe-key --key-id "$key_id" --region $REGION --query 'KeyMetadata.KeyManager' --output text 2>/dev/null)
    
    if [ "$key_manager" == "CUSTOMER" ]; then
        ((customer_keys++))
        
        rotation=$(aws kms get-key-rotation-status --key-id "$key_id" --region $REGION --query 'KeyRotationEnabled' --output text 2>/dev/null)
        if [ "$rotation" == "True" ]; then
            ((rotated_keys++))
        else
            ((non_rotated_keys++))
        fi
    fi
done

# Prepare detailed information
key_management_details="<h4>Analysis of Key Management Practices for Disk-Level Encryption</h4>"

if [ $cloudhsm_clusters -gt 0 ]; then
    key_management_details+="<p class=\"green\">Found $cloudhsm_clusters CloudHSM clusters for hardware-based key management</p>"
else
    key_management_details+="<p>No CloudHSM clusters found for hardware-based key management</p>"
fi

if [ $key_stores -gt 0 ]; then
    key_management_details+="<p class=\"green\">Found $key_stores custom KMS key stores</p>"
else
    key_management_details+="<p>No custom KMS key stores found</p>"
fi

if [ $customer_keys -gt 0 ]; then
    rotation_percentage=$(( (rotated_keys * 100) / customer_keys ))
    key_management_details+="<p>Found $customer_keys customer-managed KMS keys:</p>
    <ul>
        <li>Keys with rotation enabled: $rotated_keys ($rotation_percentage%)</li>
        <li>Keys without rotation: $non_rotated_keys</li>
    </ul>"
else
    key_management_details+="<p>No customer-managed KMS keys found</p>"
fi

key_management_details+="<p>These automated findings provide evidence of key management practices for disk-level encryption, but manual verification is required to confirm:</p>
<ul>
    <li>Whether logical access to disk-level encryption is managed separately from OS/host-level access mechanisms</li>
    <li>Whether disk encryption on non-removable media is combined with another method of PAN protection</li>
    <li>Whether cryptographic keys are stored securely and separately from the data they protect</li>
</ul>"

# Determine whether this is a pass or warning
if [ $cloudhsm_clusters -gt 0 ] || [ $key_stores -gt 0 ] || [ $rotated_keys -gt 0 ]; then
    finding_evidence="some"
else
    finding_evidence="limited"
fi

add_check_item "$OUTPUT_FILE" "warning" "3.5.1.2/3.5.1.3 - Disk-Level Encryption Controls" \
    "<p>Automated assessment found $finding_evidence evidence of specialized key management for disk-level encryption.</p>
    $key_management_details" \
    "If using disk-level encryption for PAN protection, ensure it is only used on removable media OR combined with another method for non-removable media. Verify logical access is managed independently from OS controls, decryption keys are not associated with user accounts, and authentication factors are stored securely."
((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 8: PCI REQUIREMENT 3.6 - CRYPTOGRAPHIC KEY SECURITY
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-3.6" "Requirement 3.6: Cryptographic keys used to protect stored account data are secured" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 3.6: CRYPTOGRAPHIC KEY SECURITY ===${NC}"

# Function to analyze KMS key policies for security
analyze_key_policies() {
    echo -e "Analyzing KMS key policies for security..."
    
    policy_details="<h4>Analysis of KMS Key Policies</h4><ul>"
    secure_policies=0
    potentially_insecure_policies=0
    
    for key_id in "${KMS_KEYS[@]}"; do
        # Get key details
        key_info=$(aws kms describe-key --key-id "$key_id" --region $REGION 2>/dev/null)
        key_manager=$(echo "$key_info" | grep -o '"KeyManager": "[^"]*' | cut -d'"' -f4)
        
        # Only analyze customer-managed keys
        if [ "$key_manager" == "CUSTOMER" ]; then
            # Get key policy
            key_policy=$(aws kms get-key-policy --key-id "$key_id" --policy-name default --region $REGION --output json 2>/dev/null)
            key_alias=$(aws kms list-aliases --key-id "$key_id" --region $REGION --query 'Aliases[0].AliasName' --output text 2>/dev/null)
            
            policy_details+="<li>Key ID: $key_id"
            if [ -n "$key_alias" ] && [ "$key_alias" != "None" ]; then
                policy_details+=" (Alias: $key_alias)"
            fi
            policy_details+="<ul>"
            
            # Check for potentially insecure policy elements
            if [[ "$key_policy" == *"\"Principal\": \"*\""* || "$key_policy" == *"\"Principal\": {\"AWS\": \"*\"}"* ]]; then
                policy_details+="<li class=\"red\">Policy contains wildcard principal, which might allow broad access</li>"
                potentially_insecure=true
            else
                potentially_insecure=false
            fi
            
            # Check for restrictive conditions
            if [[ "$key_policy" == *"Condition"* ]]; then
                policy_details+="<li class=\"green\">Policy contains conditional access restrictions</li>"
            fi
            
            # Check for separation of key administrative permissions from usage permissions
            admin_stmt=$(echo "$key_policy" | grep -A10 -B10 "kms:Create" | grep -A10 -B10 "kms:Delete")
            use_stmt=$(echo "$key_policy" | grep -A10 -B10 "kms:Encrypt" | grep -A10 -B10 "kms:Decrypt")
            
            if [ -n "$admin_stmt" ] && [ -n "$use_stmt" ] && [[ "$admin_stmt" != "$use_stmt" ]]; then
                policy_details+="<li class=\"green\">Policy appears to separate administrative from usage permissions</li>"
            else
                policy_details+="<li class=\"yellow\">Policy may not clearly separate administrative from usage permissions</li>"
            fi
            
            # Include a sample of the policy
            policy_sample=$(echo "$key_policy" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&#39;/g' | head -20)
            
            policy_details+="<li>Policy excerpt:<pre class=\"code-block\">$policy_sample</pre></li>"
            
            policy_details+="</ul></li>"
            
            if [ "$potentially_insecure" = true ]; then
                ((potentially_insecure_policies++))
            else
                ((secure_policies++))
            fi
        fi
    done
    
    total_analyzed=$((secure_policies + potentially_insecure_policies))
    
    if [ $total_analyzed -eq 0 ]; then
        policy_details+="<li>No customer-managed KMS keys found for policy analysis.</li>"
    else
        policy_details+="<li>Overall: $secure_policies of $total_analyzed customer-managed keys have restrictive policies</li>"
    fi
    
    policy_details+="</ul>"
    
    echo -e "Key policy analysis complete: $secure_policies of $total_analyzed have restrictive policies"
    
    if [ $potentially_insecure_policies -eq 0 ]; then
        return 0
    else
        return 1
    fi
}

# Function to check for KMS key usage in CloudTrail
check_key_usage_patterns() {
    echo -e "Checking for KMS key usage patterns in CloudTrail..."
    
    # Look for key usage events over the past week
    start_date=$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')
    
    usage_details="<h4>Analysis of Cryptographic Key Usage Patterns</h4>"
    
    # Get CloudTrail trails
    trails=$(aws cloudtrail describe-trails --region $REGION 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        usage_details+="<p>Unable to check CloudTrail trails - permission denied or service not available.</p>"
        echo -e "${YELLOW}Unable to check CloudTrail trails - permission denied${NC}"
        return 1
    fi
    
    trail_count=$(echo "$trails" | grep -c "TrailARN")
    
    if [ $trail_count -eq 0 ]; then
        usage_details+="<p>No CloudTrail trails found to analyze key usage patterns.</p>"
        echo -e "${YELLOW}No CloudTrail trails found${NC}"
        return 1
    fi
    
    # Check for KMS events
    kms_events=$(aws cloudtrail lookup-events --region $REGION --lookup-attributes AttributeKey=EventSource,AttributeValue=kms.amazonaws.com --start-time "$start_date" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        usage_details+="<p>Unable to query CloudTrail for KMS events - permission denied or service configuration issue.</p>"
        echo -e "${YELLOW}Unable to query CloudTrail for KMS events${NC}"
        return 1
    fi
    
    event_count=$(echo "$kms_events" | grep -c "EventId")
    
    if [ $event_count -gt 0 ]; then
        usage_details+="<p>Found $event_count KMS-related events in CloudTrail from the past week.</p><ul>"
        
        # Count events by type
        encrypt_count=$(echo "$kms_events" | grep -c "\"EventName\": \"Encrypt\"")
        decrypt_count=$(echo "$kms_events" | grep -c "\"EventName\": \"Decrypt\"")
        create_count=$(echo "$kms_events" | grep -c "\"EventName\": \"CreateKey\"")
        delete_count=$(echo "$kms_events" | grep -c "\"EventName\": \"ScheduleKeyDeletion\"")
        
        usage_details+="<li>Encrypt operations: $encrypt_count</li>"
        usage_details+="<li>Decrypt operations: $decrypt_count</li>"
        usage_details+="<li>Key creation events: $create_count</li>"
        usage_details+="<li>Key deletion events: $delete_count</li>"
        
        # Sample of events
        usage_details+="<li>Sample of recent key operations:<ul>"
        
        event_sample=$(echo "$kms_events" | grep -o '"EventName": "[^"]*\|"EventTime": "[^"]*\|"Username": "[^"]*' | head -15)
        
        while read -r line; do
            if [[ "$line" == *"EventName"* ]]; then
                event_name=$(echo "$line" | cut -d'"' -f4)
            elif [[ "$line" == *"EventTime"* ]]; then
                event_time=$(echo "$line" | cut -d'"' -f4)
            elif [[ "$line" == *"Username"* ]]; then
                username=$(echo "$line" | cut -d'"' -f4)
                usage_details+="<li>$event_time - $event_name by $username</li>"
            fi
        done <<< "$event_sample"
        
        usage_details+="</ul></li></ul>"
        
        echo -e "${GREEN}Found $event_count KMS-related events in CloudTrail${NC}"
        return 0
    else
        usage_details+="<p>No KMS-related events found in CloudTrail from the past week, which is unusual if cryptographic keys are actively used to protect data.</p>"
        echo -e "${YELLOW}No KMS-related events found in CloudTrail${NC}"
        return 1
    fi
}

# Analyze KMS key policies
analyze_key_policies
policy_result=$?

# Check key usage patterns
check_key_usage_patterns
usage_result=$?

# Combine findings
key_protection_details="<h4>Analysis of Cryptographic Key Protection</h4>
$policy_details
$usage_details

<p>These automated findings provide evidence of cryptographic key protection mechanisms, but manual verification is required to confirm:</p>
<ul>
    <li>Whether comprehensive key management procedures are documented</li>
    <li>Whether access to cryptographic keys is restricted to the fewest custodians necessary</li>
    <li>Whether key-encrypting keys are at least as strong as data-encrypting keys</li>
    <li>Whether keys are stored securely and separately from the data they protect</li>
</ul>"

# Requirement 3.6.1 - Key Protection Procedures
# Add more specific details about key policy evaluation
if [ $policy_result -eq 0 ] && [ $usage_result -eq 0 ]; then
    # Create enhanced details with specific policy strengths found
    enhanced_policy_details="<p>Analysis shows the following key management security practices are in place:</p><ul>"
    
    # Check for key administration separation
    admin_separation=$(echo "$policy_details" | grep -c "separates administrative from usage permissions")
    if [ $admin_separation -gt 0 ]; then
        enhanced_policy_details+="<li class=\"green\">Administrative key operations are separated from usage operations</li>"
    fi
    
    # Check for conditional restrictions
    conditional_restrictions=$(echo "$policy_details" | grep -c "conditional access restrictions")
    if [ $conditional_restrictions -gt 0 ]; then
        enhanced_policy_details+="<li class=\"green\">Conditional access restrictions are applied to key operations</li>"
    fi
    
    # Check for key rotation
    if [ $rotated_keys -gt 0 ]; then
        enhanced_policy_details+="<li class=\"green\">$rotated_keys keys have automatic rotation enabled</li>"
    fi
    
    enhanced_policy_details+="</ul>"
    
    add_check_item "$OUTPUT_FILE" "pass" "3.6.1 - Key Protection Procedures" \
        "<p>Automated assessment found evidence of secure key management practices:</p>
        <ul>
            <li>KMS key policies appear to implement restrictive access controls</li>
            <li>Key usage patterns indicate active cryptographic operations</li>
        </ul>
        $enhanced_policy_details
        $key_protection_details" \
        "While automated evidence is positive, verify through documentation that comprehensive key management procedures exist and include: restriction of access to the fewest custodians necessary, key-encrypting keys at least as strong as data-encrypting keys, secure storage of keys in the fewest possible locations, and separation of key-encrypting keys from data-encrypting keys. AWS KMS handles many of these requirements automatically by design."
    ((total_checks++))
    ((passed_checks++))
else
    finding_type="limited"
    if [ $policy_result -eq 0 ] || [ $usage_result -eq 0 ]; then
        finding_type="partial"
    fi
    
    # Format key policy status based on results
    if [ $policy_result -eq 0 ]; then
        policy_status="Appear secure"
    else
        policy_status="Potential issues identified"
    fi
    
    # Format key usage status based on results
    if [ $usage_result -eq 0 ]; then
        usage_status="Active cryptographic operations detected"
    else
        usage_status="Limited evidence of active key usage"
    fi
    
    add_check_item "$OUTPUT_FILE" "warning" "3.6.1 - Key Protection Procedures" \
        "<p>Automated assessment found $finding_type evidence of secure key management practices:</p>
        <ul>
            <li>KMS key policies: $policy_status</li>
            <li>Key usage patterns: $usage_status</li>
        </ul>
        $key_protection_details" \
        "Implement comprehensive procedures to protect cryptographic keys against disclosure and misuse, including: restricting access to the fewest custodians necessary, ensuring key-encrypting keys are at least as strong as data-encrypting keys, storing key-encrypting keys separately from data-encrypting keys, and storing keys securely in the fewest possible locations."
    ((total_checks++))
    ((warning_checks++))
fi

# Check for KMS usage and security
echo -e "Checking KMS key policy security..."
KMS_KEYS_DETAILS=$(aws kms list-keys --region $REGION --query 'Keys[*].KeyId' --output text 2>/dev/null)

if [ -n "$KMS_KEYS_DETAILS" ]; then
    INSECURE_KEY_POLICIES=0
    SECURE_KEY_POLICIES=0
    
    for key_id in $KMS_KEYS_DETAILS; do
        # Get key policy
        KEY_POLICY=$(aws kms get-key-policy --key-id "$key_id" --policy-name default --region $REGION 2>/dev/null)
        
        # Simple check for overly permissive policies (This is a basic check and would need enhancement)
        if [[ "$KEY_POLICY" == *"\"Principal\": \"*\""* || "$KEY_POLICY" == *"\"Principal\": {\"AWS\": \"*\"}"* ]]; then
            ((INSECURE_KEY_POLICIES++))
        else
            ((SECURE_KEY_POLICIES++))
        fi
    done
    
    if [ $INSECURE_KEY_POLICIES -gt 0 ]; then
        add_check_item "$OUTPUT_FILE" "warning" "3.6.1 - KMS Key Policies" "$INSECURE_KEY_POLICIES of $(($INSECURE_KEY_POLICIES + $SECURE_KEY_POLICIES)) KMS keys have potentially insecure key policies." "Review and restrict KMS key policies to ensure they grant access only to the minimum necessary principals."
        ((total_checks++))
        ((warning_checks++))
    else
        add_check_item "$OUTPUT_FILE" "pass" "3.6.1 - KMS Key Policies" "All $(($INSECURE_KEY_POLICIES + $SECURE_KEY_POLICIES)) KMS keys have properly restricted key policies."
        ((total_checks++))
        ((passed_checks++))
    fi
fi

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 9: PCI REQUIREMENT 3.7 - KEY MANAGEMENT
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-3.7" "Requirement 3.7: Where cryptography is used to protect stored account data, key management processes and procedures covering all aspects of the key lifecycle are defined and implemented" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 3.7: KEY MANAGEMENT ===${NC}"

# Function to check AWS CloudHSM key generation capabilities
check_cloudhsm_key_generation() {
    echo -e "Checking for CloudHSM capabilities for strong key generation..."
    
    # Check for CloudHSM clusters
    cloudhsm_clusters=$(aws cloudhsm describe-clusters --region $REGION 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}Unable to check CloudHSM clusters - permission denied or service not available${NC}"
        cloudhsm_details="<p>Unable to check CloudHSM clusters - permission denied or service not available.</p>"
        return 1
    fi
    
    cluster_count=$(echo "$cloudhsm_clusters" | grep -c "ClusterId")
    
    if [ $cluster_count -gt 0 ]; then
        cloudhsm_details="<p class=\"green\">Found $cluster_count CloudHSM clusters that provide hardware-based cryptographic key generation:</p><ul>"
        
        # Extract cluster details
        cluster_ids=$(echo "$cloudhsm_clusters" | grep -o '"ClusterId": "[^"]*' | cut -d'"' -f4)
        
        for cluster_id in $cluster_ids; do
            # Check cluster state
            state=$(echo "$cloudhsm_clusters" | grep -A5 "\"ClusterId\": \"$cluster_id\"" | grep -o '"State": "[^"]*' | cut -d'"' -f4)
            hsm_count=$(echo "$cloudhsm_clusters" | grep -A20 "\"ClusterId\": \"$cluster_id\"" | grep -c "HsmId")
            
            cloudhsm_details+="<li>Cluster ID: $cluster_id - State: $state, HSMs: $hsm_count</li>"
        done
        
        cloudhsm_details+="</ul>
        <p>CloudHSM provides hardware-based cryptographic key generation that complies with industry standards including FIPS 140-2 Level 3.</p>"
        
        echo -e "${GREEN}Found CloudHSM clusters for hardware-based key generation${NC}"
        return 0
    else
        cloudhsm_details="<p>No CloudHSM clusters found. CloudHSM provides hardware-based cryptographic key generation that complies with industry standards including FIPS 140-2 Level 3.</p>"
        echo -e "${YELLOW}No CloudHSM clusters found${NC}"
        return 1
    fi
}

# Function to check KMS key generation capabilities
check_kms_key_generation() {
    echo -e "Checking KMS key generation capabilities..."
    
    # Check for KMS keys
    kms_details="<h4>KMS Key Generation Capabilities</h4>"
    
    if [ ${#KMS_KEYS[@]} -eq 0 ]; then
        kms_details+="<p>No KMS keys found to analyze.</p>"
        echo -e "${YELLOW}No KMS keys found${NC}"
        return 1
    fi
    
    # Count customer managed vs AWS managed keys
    customer_keys=0
    aws_keys=0
    
    for key_id in "${KMS_KEYS[@]}"; do
        key_manager=$(aws kms describe-key --key-id "$key_id" --region $REGION --query 'KeyMetadata.KeyManager' --output text 2>/dev/null)
        
        if [ "$key_manager" == "CUSTOMER" ]; then
            ((customer_keys++))
        elif [ "$key_manager" == "AWS" ]; then
            ((aws_keys++))
        fi
    done
    
    # Check if custom key stores are being used
    custom_stores=$(aws kms describe-custom-key-stores --region $REGION 2>/dev/null)
    store_count=0
    
    if [ $? -eq 0 ]; then
        store_count=$(echo "$custom_stores" | grep -c "CustomKeyStoreId")
    fi
    
    kms_details+="<p>Analysis of AWS KMS key generation:</p><ul>
        <li>Customer-managed KMS keys: $customer_keys</li>
        <li>AWS-managed KMS keys: $aws_keys</li>
        <li>Custom key stores: $store_count</li>
    </ul>
    
    <p>AWS KMS provides the following key generation capabilities:</p>
    <ul>
        <li>Symmetric keys (AES-256) that are FIPS 140-2 compliant</li>
        <li>Asymmetric keys (RSA and ECC) with various key lengths</li>
        <li>Hardware security module (HSM) backing for keys when using custom key stores</li>
        <li>Cryptographically secure random number generation</li>
    </ul>"
    
    echo -e "${GREEN}Found evidence of KMS key generation capabilities${NC}"
    
    if [ $customer_keys -gt 0 ]; then
        return 0
    else
        return 1
    fi
}

# Check key generation capabilities
check_cloudhsm_key_generation
cloudhsm_result=$?

check_kms_key_generation
kms_result=$?

# Combine findings
key_generation_details="<h4>Analysis of Cryptographic Key Generation</h4>
$cloudhsm_details
$kms_details

<p>These automated findings provide evidence of key generation capabilities, but manual verification is required to confirm:</p>
<ul>
    <li>Whether formal key generation procedures are documented</li>
    <li>Whether the implemented key generation methods produce cryptographically strong keys</li>
    <li>Whether key generation follows industry-accepted standards and best practices</li>
</ul>"

# Requirement 3.7.1 - Key Generation
if [ $cloudhsm_result -eq 0 ] || [ $kms_result -eq 0 ]; then
    add_check_item "$OUTPUT_FILE" "pass" "3.7.1 - Strong Key Generation" \
        "<p>Automated assessment found evidence of secure key generation capabilities:</p>
        <ul>
            <li>CloudHSM: $([ $cloudhsm_result -eq 0 ] && echo "Available" || echo "Not found")</li>
            <li>AWS KMS: $([ $kms_result -eq 0 ] && echo "Customer-managed keys in use" || echo "Limited evidence of customer key management")</li>
        </ul>
        $key_generation_details" \
        "While automated evidence is positive, verify through documentation that key-management policies and procedures specifically address the generation of strong cryptographic keys and compliance with industry standards."
    ((total_checks++))
    ((passed_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "3.7.1 - Strong Key Generation" \
        "<p>Automated assessment found limited evidence of secure key generation capabilities.</p>
        $key_generation_details" \
        "Implement key-management policies and procedures that address the generation of strong cryptographic keys. Consider using AWS CloudHSM for hardware-based key generation or ensure proper configuration of AWS KMS for software-based key generation."
    ((total_checks++))
    ((warning_checks++))
fi

# Add remaining requirement checks with more detailed context
# Requirement 3.7.2 - Key Distribution
add_check_item "$OUTPUT_FILE" "warning" "3.7.2 - Secure Key Distribution" \
    "<p>Automated assessment provides limited evidence of cryptographic key distribution practices.</p>
    <p>AWS provides secure key distribution mechanisms through TLS-encrypted API calls, IAM role-based access control, VPC Endpoints for private network paths to KMS, and CloudHSM integration for hardware-based key management.</p>
    <p>Manual verification is required to confirm formal key distribution procedures.</p>" \
    "Implement key-management policies and procedures that address secure distribution of cryptographic keys. Configure secure channels for key distribution and ensure methods maintain the integrity and confidentiality of keys."
((total_checks++))
((warning_checks++))

# Requirement 3.7.3 - Key Storage
add_check_item "$OUTPUT_FILE" "warning" "3.7.3 - Secure Key Storage" \
    "<p>Automated assessment provides limited evidence of cryptographic key storage practices.</p>
    <p>AWS KMS stores keys in FIPS 140-2 validated HSMs, and master keys in KMS never leave the HSMs unencrypted. CloudHSM provides dedicated hardware security modules for enhanced security.</p>
    <p>Manual verification is required to confirm formal key storage procedures.</p>" \
    "Implement key-management policies and procedures that address secure storage of cryptographic keys. Ensure keys are stored securely in the fewest possible locations and protected against unauthorized access."
((total_checks++))
((warning_checks++))

# Requirement 3.7.4 - Key Cryptoperiod
rotated_count=0
non_rotated_count=0
customer_keys_details=""

# Enhanced key rotation analysis with specific key details
for key_id in "${KMS_KEYS[@]}"; do
    key_manager=$(aws kms describe-key --key-id "$key_id" --region $REGION --query 'KeyMetadata.KeyManager' --output text 2>/dev/null)
    if [ "$key_manager" == "CUSTOMER" ]; then
        # Get key alias for better identification
        key_alias=$(aws kms list-aliases --key-id "$key_id" --region $REGION --query 'Aliases[0].AliasName' --output text 2>/dev/null)
        
        rotation=$(aws kms get-key-rotation-status --key-id "$key_id" --region $REGION --query 'KeyRotationEnabled' --output text 2>/dev/null)
        if [ "$rotation" == "True" ]; then
            ((rotated_count++))
            if [ -n "$key_alias" ] && [ "$key_alias" != "None" ]; then
                customer_keys_details+="<li class=\"green\">Key $key_id ($key_alias): Rotation ENABLED</li>"
            else
                customer_keys_details+="<li class=\"green\">Key $key_id: Rotation ENABLED</li>"
            fi
        else
            ((non_rotated_count++))
            if [ -n "$key_alias" ] && [ "$key_alias" != "None" ]; then
                customer_keys_details+="<li class=\"red\">Key $key_id ($key_alias): Rotation DISABLED</li>"
            else
                customer_keys_details+="<li class=\"red\">Key $key_id: Rotation DISABLED</li>"
            fi
        fi
    fi
done

rotation_details="<p>AWS KMS provides automatic key rotation for symmetric keys if enabled:</p><ul>$customer_keys_details</ul>"

# Set rotation status text based on result
rotation_status="limited"
if [ $rotated_count -gt 0 ]; then
    rotation_status="some"
fi

# Add information about AWS KMS key rotation behavior
rotation_details+="<p>With AWS KMS key rotation:</p><ul>
    <li>When enabled, AWS automatically rotates symmetric KMS keys once every year</li>
    <li>Previous key material is retained to decrypt data encrypted before rotation</li>
    <li>New encryptions use the latest key material</li>
    <li>Applications don't need to change how they use the key</li>
    <li>Asymmetric KMS keys cannot be automatically rotated</li>
</ul>"

add_check_item "$OUTPUT_FILE" "warning" "3.7.4 - Key Cryptoperiod and Changes" \
    "<p>Automated assessment found $rotation_status evidence of key rotation practices.</p>
    $rotation_details
    <p>Manual verification is required to confirm whether cryptoperiods are defined for each key type and whether procedures for key changes at defined intervals exist.</p>" \
    "Implement key-management policies that define cryptoperiods for each key type and include processes for key changes at the end of those periods. Enable automatic key rotation for AWS KMS keys where supported."
((total_checks++))
((warning_checks++))

# Requirement 3.7.5 - Key Retirement
# Check for scheduled key deletions
deletion_count=0
scheduled_keys=$(aws kms list-keys --region $REGION | grep -o '"KeyId": "[^"]*' | cut -d'"' -f4 | xargs -I{} aws kms describe-key --key-id {} --region $REGION 2>/dev/null | grep -B5 -A5 '"KeyState": "PendingDeletion"')
if [ -n "$scheduled_keys" ]; then
    deletion_count=$(echo "$scheduled_keys" | grep -c "PendingDeletion")
fi

deletion_details="<p>AWS KMS provides key retirement capabilities through scheduled deletions with customizable waiting periods. Found $deletion_count keys scheduled for deletion.</p>"

# Set deletion status text based on result
deletion_status="limited"
if [ $deletion_count -gt 0 ]; then
    deletion_status="some"
fi

add_check_item "$OUTPUT_FILE" "warning" "3.7.5 - Key Retirement and Replacement" \
    "<p>Automated assessment found $deletion_status evidence of key retirement practices.</p>
    $deletion_details
    <p>Manual verification is required to confirm whether policies for key retirement or replacement exist for various scenarios.</p>" \
    "Implement policies for key retirement or replacement when keys reach cryptoperiod end, key integrity is weakened, or key is compromised. Ensure retired keys are not used for encryption."
((total_checks++))
((warning_checks++))

# Requirement 3.7.6 - Manual Key Operations
add_check_item "$OUTPUT_FILE" "warning" "3.7.6 - Manual Key Operations" \
    "<p>Manual verification required. Automated assessment cannot determine if manual cleartext key operations are performed or how they are managed.</p>
    <p>AWS Key Management Service (KMS) generally handles keys in a way that prevents exposure of cleartext key material to users. However, some scenarios might involve manual key operations:</p>
    <ul>
        <li>Import of external key material into AWS KMS</li>
        <li>Use of CloudHSM key management utilities</li>
        <li>On-premises key management systems integrated with AWS</li>
    </ul>" \
    "If manual cleartext key-management operations are performed, ensure they are managed using split knowledge and dual control. This typically requires implementing procedures where at least two people (each with partial knowledge) are required for key operations, and documenting these procedures formally."
((total_checks++))
((warning_checks++))

# Requirement 3.7.7 - Unauthorized Key Substitution
add_check_item "$OUTPUT_FILE" "warning" "3.7.7 - Prevention of Unauthorized Key Substitution" \
    "<p>Manual verification required. Automated assessment provides limited insight into controls preventing unauthorized key substitution.</p>
    <p>AWS KMS implements several controls that can help prevent unauthorized key substitution:</p>
    <ul>
        <li>IAM policies controlling who can use specific keys</li>
        <li>Key policies defining permissions at the key level</li>
        <li>AWS CloudTrail logging of all key operations</li>
        <li>KMS grants for granular access control</li>
    </ul>
    <p>Manual review of these controls and related documentation is needed to verify proper implementation.</p>" \
    "Implement key-management policies and procedures that prevent unauthorized substitution of cryptographic keys. This typically includes access controls, role separation, oversight mechanisms, and audit procedures to detect and prevent unauthorized key changes."
((total_checks++))
((warning_checks++))

# Requirement 3.7.8 - Key Custodian Acknowledgment
# Check for IAM roles that might be used for key custodians
key_roles=$(aws iam list-roles --region $REGION --query "Roles[?contains(RoleName, 'key') || contains(RoleName, 'crypto') || contains(RoleName, 'kms') || contains(RoleName, 'custodian')].RoleName" --output text 2>/dev/null)

role_count=0
if [ -n "$key_roles" ]; then
    role_count=$(echo "$key_roles" | wc -w)
    custodian_details="<p>Found $role_count IAM roles with names suggesting they might be used for key custodians. Manual verification is needed to confirm formal acknowledgment procedures.</p>"
else
    custodian_details="<p>No IAM roles found with names suggesting they might be used for key custodians. Manual verification is needed to identify key custodians and their acknowledgment procedures.</p>"
fi

add_check_item "$OUTPUT_FILE" "warning" "3.7.8 - Key Custodian Acknowledgment" \
    "<p>Automated assessment provides limited evidence of key custodian acknowledgment procedures.</p>
    $custodian_details" \
    "Ensure all key custodians formally acknowledge (in writing or electronically) that they understand and accept their key-custodian responsibilities. This typically involves documented roles and responsibilities, specific procedures for each custodian role, and a formal acknowledgment process."
((total_checks++))
((warning_checks++))



#----------------------------------------------------------------------
# FINALIZE THE REPORT
#----------------------------------------------------------------------
finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"

echo -e "\n${CYAN}=== SUMMARY OF PCI DSS REQUIREMENT $REQUIREMENT_NUMBER CHECKS ===${NC}"

compliance_percentage=0
if [ $((total_checks - warning_checks)) -gt 0 ]; then
    compliance_percentage=$(( (passed_checks * 100) / (total_checks - warning_checks) ))
fi

# Generate a detailed summary
summary="<p>A total of $total_checks checks were performed:</p>
<ul>
    <li class=\"green\">Passed checks: $passed_checks</li>
    <li class=\"red\">Failed checks: $failed_checks</li>
    <li class=\"yellow\">Warning/manual checks: $warning_checks</li>
</ul>
<p>Automated compliance percentage (excluding warnings): $compliance_percentage%</p>

<p><strong>Next Steps:</strong></p>
<ol>
    <li>Review all warning items that require manual verification</li>
    <li>Address failed checks as a priority</li>
    <li>Implement recommendations provided in the report</li>
    <li>Document compensating controls where applicable</li>
    <li>Perform a follow-up assessment after remediation</li>
</ol>"

add_check_item "$OUTPUT_FILE" "info" "Assessment Summary" "$summary"

# Console output summary
echo -e "\nTotal checks performed: $total_checks"
echo -e "Passed checks: $passed_checks"
echo -e "Failed checks: $failed_checks"
echo -e "Warning/manual checks: $warning_checks"
echo -e "Compliance percentage (excluding warnings): $compliance_percentage%"

echo -e "\nPCI DSS Requirement $REQUIREMENT_NUMBER assessment completed at $(date)"
echo -e "HTML Report saved to: $OUTPUT_FILE"

close_section "$OUTPUT_FILE"
# Open the HTML report in the default browser if on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$OUTPUT_FILE" 2>/dev/null || echo "Could not automatically open the report. Please open it manually."
else
    echo "Please open the HTML report in your web browser to view detailed results."
fi