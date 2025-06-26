#!/bin/bash
#
# PCI DSS 4.0.1 - Requirement 2 Compliance Assessment Script
# Description: Checks AWS environment for compliance with PCI DSS Requirement 2
#              (Apply Secure Configurations to All System Components)
#
# Implementation Notes:
# - Warning checks for manual testing are not counted toward compliance percentage
# - Failed checks due to access denied errors are not counted toward compliance percentage
# - The script uses finalize_html_report with a custom parameter for access_denied_checks
#

# Set variables
REQUIREMENT_NUMBER="2"
REPORT_TITLE="PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DIR="$(dirname "$0")"
OUTPUT_DIR="${DIR}/reports"
OUTPUT_FILE="${OUTPUT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_${TIMESTAMP}.html"

# Source the shared HTML report library
source "${DIR}/pci_html_report_lib.sh"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Check AWS CLI availability
if ! command -v aws &> /dev/null; then
    echo "Error: AWS CLI is not installed or not in PATH"
    exit 1
fi

# Function to check if we have access to a specific AWS CLI command
check_command_access() {
    local output_file="$1"
    local service="$2"
    local command="$3"
    local region="$4"

    echo "Checking access to AWS $service $command..."

    local result
    result=$(aws $service $command --region "$region" --max-items 1 2>&1)

    if [[ $result == *"AccessDenied"* || $result == *"UnauthorizedOperation"* ]]; then
        add_check_item "$output_file" "fail" "Permissions Check: $service $command" "Insufficient permissions to access <code>$service $command</code>" "Ensure the AWS credentials have appropriate permissions"
        access_denied_checks=$((access_denied_checks + 1))
        return 1
    elif [[ $result == *"is not a valid command"* || $result == *"Unknown options"* || $result == *"Invalid choice"* ]]; then
        add_check_item "$output_file" "warning" "AWS CLI Capability: $service $command" "The installed AWS CLI doesn't support <code>$service $command</code>" "Update AWS CLI to the latest version"
        return 2
    else
        add_check_item "$output_file" "pass" "Permissions Check: $service $command" "Access to <code>$service $command</code> is available" ""
        return 0
    fi
}



# Function to add a manual check that won't affect compliance percentage
add_manual_check() {
    local output_file="$1"
    local title="$2"
    local details="$3"
    local recommendation="$4"
    
    add_check_item "$output_file" "warning" "$title" "$details" "$recommendation"
    warning_checks=$((warning_checks + 1))
    return 0
}

# Main function
main() {
    # Get AWS region
    if [ -z "$REGION" ]; then
		read -p "Enter AWS region to test (e.g., us-east-1): " REGION
		if [ -z "$REGION" ]; then
			REGION="us-east-1"
			echo -e "${YELLOW}Using default region: $REGION${NC}"
		fi
	fi

    
    # Initialize counters
    total_checks=0
    passed_checks=0
    failed_checks=0
    warning_checks=0
    access_denied_checks=0  # Counter for checks that failed due to access denied
    
    # Initialize HTML report
    initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE" "$REQUIREMENT_NUMBER" "$REGION"
    
    
    
    # Add Permission Checks section
	add_section "$OUTPUT_FILE" "permission-checks" "Permission Checks" "active"

	check_command_access "$OUTPUT_FILE" "ec2" "describe-security-groups" "$REGION"
	check_command_access "$OUTPUT_FILE" "ec2" "describe-instances" "$REGION"
	check_command_access "$OUTPUT_FILE" "rds" "describe-db-instances" "$REGION"
	check_command_access "$OUTPUT_FILE" "s3" "list-buckets" "$REGION"
	check_command_access "$OUTPUT_FILE" "lambda" "list-functions" "$REGION"
	check_command_access "$OUTPUT_FILE" "iam" "list-users" "$REGION"
	check_command_access "$OUTPUT_FILE" "cloudtrail" "describe-trails" "$REGION"
	check_command_access "$OUTPUT_FILE" "kms" "list-keys" "$REGION"

	# Close Permission Checks section
	close_section "$OUTPUT_FILE"
    
    # Requirement 2.1: Processes and mechanisms for applying secure configurations to all system components are defined and understood
    add_section "$OUTPUT_FILE" "req-2.1" "Requirement 2.1: Processes and mechanisms for applying secure configurations" "active"
    
    # Check 2.1.1: Security Policies and Operational Procedures
    echo "Checking for security policies documentation..."
    # This is a check that would typically require manual review, but we can check for documentation
    # We'll look for security policy documents in S3 buckets
    
    policy_docs=$(aws s3 ls --recursive "s3://*/policies/" --region "$REGION" 2>/dev/null | grep -i "security\|configuration" | wc -l)
    
    total_checks=$((total_checks + 1))
    if [ "$policy_docs" -gt 0 ]; then
        add_manual_check "$OUTPUT_FILE" "Security Policies Documentation" "Found $policy_docs potential security policy documents in S3" "Ensure these documents cover all security policies and operational procedures identified in Requirement 2"
    else
        add_manual_check "$OUTPUT_FILE" "Security Policies Documentation" "No security policy documents found in S3 'policies' folders" "Ensure all security policies and operational procedures for Requirement 2 are documented, kept up to date, in use, and known to all affected parties"
    fi
    
    # Check 2.1.2: Roles and Responsibilities
    echo "Checking for roles and responsibilities documentation..."
    # This is also a manual check, but we can check for IAM roles with policy documents
    
    iam_roles=$(aws iam list-roles --query "Roles[?contains(RoleName, 'security') || contains(RoleName, 'compliance')].RoleName" --output json)
    role_count=$(echo "$iam_roles" | jq 'length')
    
    total_checks=$((total_checks + 1))
    if [ "$role_count" -gt 0 ]; then
        add_manual_check "$OUTPUT_FILE" "Security Roles" "Found $role_count IAM roles related to security or compliance" "Ensure roles and responsibilities for Requirement 2 are documented, assigned, and understood"
    else
        add_manual_check "$OUTPUT_FILE" "Security Roles" "No security or compliance-related IAM roles found" "Consider creating specific IAM roles for security responsibilities and ensure they are documented"
    fi
    
    close_section "$OUTPUT_FILE"
    
    # Requirement 2.2: System components are configured and managed securely
    add_section "$OUTPUT_FILE" "req-2.2" "Requirement 2.2: System components are configured and managed securely" "active"
    
    # Check 2.2.1: Configuration Standards
    echo "Checking for system hardening and configuration standards..."
    # Check for security groups with overly permissive rules as an indicator of configuration standards
    
    # Check 2.2.2: Vendor Default Accounts
    echo "Checking for vendor default accounts..."
    default_sgs=$(aws ec2 describe-security-groups \
        --region "$REGION" \
        --filters "Name=group-name,Values=default" \
        --query "SecurityGroups[*].{ID:GroupId,VpcId:VpcId,Inbound:IpPermissions,Outbound:IpPermissionsEgress}" \
        --output json)
    
    # Count default SGs with non-restrictive rules
    sg_count=$(echo "$default_sgs" | jq 'length')
    non_restrictive_sg_count=0
    problem_sgs=""
    
    # Make sure sg_count is a valid integer
    if [[ "$sg_count" =~ ^[0-9]+$ ]]; then
        for ((i=0; i<$sg_count; i++)); do
            inbound_rules=$(echo "$default_sgs" | jq -r ".[$i].Inbound | length")
            sg_id=$(echo "$default_sgs" | jq -r ".[$i].ID")
            vpc_id=$(echo "$default_sgs" | jq -r ".[$i].VpcId")
            
            if [ "$inbound_rules" -gt 0 ]; then
                non_restrictive_sg_count=$((non_restrictive_sg_count + 1))
                
                # Extract details about the inbound rules for this security group
                rule_details=$(aws ec2 describe-security-group-rules --filters "Name=group-id,Values=$sg_id" --query "SecurityGroupRules[?IsEgress==\`false\`].[SecurityGroupRuleId,IpProtocol,FromPort,ToPort,CidrIpv4]" --output json --region "$REGION")
                
                # Format the details for display
                rule_summary=""
                rule_count=$(echo "$rule_details" | jq 'length')
                
                # Make sure rule_count is a valid integer
                if [[ "$rule_count" =~ ^[0-9]+$ ]]; then
                    for ((j=0; j<$rule_count; j++)); do
                        rule_id=$(echo "$rule_details" | jq -r ".[$j][0]")
                        protocol=$(echo "$rule_details" | jq -r ".[$j][1]")
                        from_port=$(echo "$rule_details" | jq -r ".[$j][2]")
                        to_port=$(echo "$rule_details" | jq -r ".[$j][3]")
                        cidr=$(echo "$rule_details" | jq -r ".[$j][4]")
                        
                        # Handle 'all protocols' case
                        if [ "$protocol" == "-1" ]; then
                            protocol="All"
                            port_range="All"
                        else
                            if [ "$from_port" == "$to_port" ]; then
                                port_range="$from_port"
                            else
                                port_range="$from_port-$to_port"
                            fi
                        fi
                        
                        rule_summary="$rule_summary<br>- Rule ID: $rule_id, Protocol: $protocol, Ports: $port_range, Source: $cidr"
                    done
                fi
                
                problem_sgs="$problem_sgs<br><br><strong>Security Group ID:</strong> $sg_id (VPC: $vpc_id)<br><strong>Inbound Rules:</strong>$rule_summary"
            fi
        done
    fi
    
    total_checks=$((total_checks + 1))
    if [ "$non_restrictive_sg_count" -eq 0 ]; then
        add_check_item "$OUTPUT_FILE" "pass" "Default Security Groups" "All default security groups have restrictive inbound rules" ""
        passed_checks=$((passed_checks + 1))
    else
        violation_detail="$non_restrictive_sg_count default security groups have non-restrictive inbound rules.<br><br><strong>Problem Security Groups:</strong>$problem_sgs<br><br><strong>Risk:</strong> Default security groups with non-restrictive inbound rules can allow unauthorized access to resources."
        add_check_item "$OUTPUT_FILE" "fail" "Default Security Groups" "$violation_detail" "Modify default security groups to restrict all traffic or avoid using them. Add specific rules only for required traffic."
        failed_checks=$((failed_checks + 1))
    fi
    
    # Check 2.2.2: Vendor default accounts/configurations for RDS
    echo "Checking RDS instances for vendor default configurations..."
    rds_instances=$(aws rds describe-db-instances \
        --region "$REGION" \
        --query "DBInstances[*].{Identifier:DBInstanceIdentifier,Encrypted:StorageEncrypted,Port:Endpoint.Port,PublicAccess:PubliclyAccessible}" \
        --output json)
    
    rds_count=$(echo "$rds_instances" | jq 'length')
    unencrypted_count=0
    default_port_count=0
    public_access_count=0
    
    # Make sure rds_count is a valid integer
    if [[ "$rds_count" =~ ^[0-9]+$ ]]; then
        for ((i=0; i<$rds_count; i++)); do
            is_encrypted=$(echo "$rds_instances" | jq -r ".[$i].Encrypted")
            port=$(echo "$rds_instances" | jq -r ".[$i].Port")
            is_public=$(echo "$rds_instances" | jq -r ".[$i].PublicAccess")
            
            if [ "$is_encrypted" == "false" ]; then
                unencrypted_count=$((unencrypted_count + 1))
            fi
            
            # Check for default ports (MySQL:3306, PostgreSQL:5432, SQL Server:1433, etc.)
            if [ "$port" == "3306" ] || [ "$port" == "5432" ] || [ "$port" == "1433" ] || [ "$port" == "1521" ]; then
                default_port_count=$((default_port_count + 1))
            fi
            
            if [ "$is_public" == "true" ]; then
                public_access_count=$((public_access_count + 1))
            fi
        done
    fi
    
    # RDS Encryption Check
    total_checks=$((total_checks + 1))
    if [ "$unencrypted_count" -eq 0 ]; then
        add_check_item "$OUTPUT_FILE" "pass" "RDS Encryption" "All RDS instances are encrypted" ""
        passed_checks=$((passed_checks + 1))
    else
        add_check_item "$OUTPUT_FILE" "fail" "RDS Encryption" "$unencrypted_count RDS instances are not encrypted" "Enable encryption for all RDS instances"
        failed_checks=$((failed_checks + 1))
    fi
    
    # RDS Default Port Check
    total_checks=$((total_checks + 1))
    if [ "$default_port_count" -eq 0 ]; then
        add_check_item "$OUTPUT_FILE" "pass" "RDS Default Ports" "No RDS instances using default ports" ""
        passed_checks=$((passed_checks + 1))
    else
        # This is a real warning that should be addressed but not an immediate fail
        add_check_item "$OUTPUT_FILE" "warning" "RDS Default Ports" "$default_port_count RDS instances using default ports" "Consider changing default ports for RDS instances"
        warning_checks=$((warning_checks + 1))
    fi
    
    # RDS Public Access Check
    total_checks=$((total_checks + 1))
    if [ "$public_access_count" -eq 0 ]; then
        add_check_item "$OUTPUT_FILE" "pass" "RDS Public Access" "No RDS instances with public access" ""
        passed_checks=$((passed_checks + 1))
    else
        add_check_item "$OUTPUT_FILE" "fail" "RDS Public Access" "$public_access_count RDS instances have public access enabled" "Disable public access for RDS instances in production environments"
        failed_checks=$((failed_checks + 1))
    fi
    
    # Requirement 2.2 continued
    # Check 2.2.3: Primary Functions with Different Security Levels
    echo "Checking for separation of primary functions..."
    # This is mostly a manual check, but we can check for instances with multiple roles
    
    # Check if EC2 instances have multiple roles/tagged purposes
    instances_with_tags=$(aws ec2 describe-instances --region "$REGION" --query "Reservations[*].Instances[*].[InstanceId,Tags]" --output json)
    multi_function_count=0
    
    # This is a simplified check - in reality, a more sophisticated analysis would be needed
    for instance in $(echo "$instances_with_tags" | jq -r '.[][][0]'); do
        tags=$(aws ec2 describe-instances --instance-ids "$instance" --region "$REGION" --query "Reservations[].Instances[].Tags[?Key=='Role' || Key=='Function' || Key=='Application'].Value" --output json)
        count=$(echo "$tags" | jq 'length')
        if [ "$count" -gt 1 ]; then
            multi_function_count=$((multi_function_count + 1))
        fi
    done
    
    total_checks=$((total_checks + 1))
    if [ "$multi_function_count" -eq 0 ]; then
        add_manual_check "$OUTPUT_FILE" "Function Separation" "No EC2 instances detected with multiple functions/roles" "Manual verification required to confirm proper separation of primary functions"
    else
        add_manual_check "$OUTPUT_FILE" "Function Separation" "$multi_function_count EC2 instances may have multiple functions" "Verify these instances properly isolate functions with differing security levels"
    fi
    
    # Check 2.2.4: Unnecessary Services, Protocols, and Functions
    echo "Checking for unnecessary services and ports..."
    
    # Check for Internet-Exposed Ports
    echo "Checking for instances with high-risk ports exposed to the internet..."
    
    # Get all security groups with high-risk ports exposed to the internet (0.0.0.0/0)
    high_risk_ports=("22" "3389" "1433" "3306" "5432" "27017" "27018" "6379" "9200" "9300" "8080" "8443")
    exposed_instances=()
    exposed_details=""
    exposed_count=0
    
    # Get all instances and their security groups
    instances=$(aws ec2 describe-instances --region "$REGION" --query "Reservations[*].Instances[*].[InstanceId,SecurityGroups,PublicIpAddress,Tags]" --output json)
    instance_count=$(echo "$instances" | jq 'length')
    
    # Make sure instance_count is a valid integer
    if [[ "$instance_count" =~ ^[0-9]+$ ]]; then
        for ((i=0; i<$instance_count; i++)); do
            instance_id=$(echo "$instances" | jq -r ".[$i][][0]")
            public_ip=$(echo "$instances" | jq -r ".[$i][][2]")
            
            # Skip instances without public IPs
            if [ "$public_ip" == "null" ]; then
                continue
            fi
            
            # Get name tag if available
            instance_name="Unnamed"
            tags=$(echo "$instances" | jq -r ".[$i][][3]")
            tag_count=$(echo "$tags" | jq 'length')
            
            # Make sure tag_count is a valid integer
            if [[ "$tag_count" =~ ^[0-9]+$ ]]; then
                for ((t=0; t<$tag_count; t++)); do
                    key=$(echo "$tags" | jq -r ".[$t].Key")
                    if [ "$key" == "Name" ]; then
                        instance_name=$(echo "$tags" | jq -r ".[$t].Value")
                        break
                    fi
                done
            fi
            
            # Get security groups for this instance
            security_groups=$(echo "$instances" | jq -r ".[$i][][1]")
            sg_count=$(echo "$security_groups" | jq 'length')
            
            is_exposed=false
            instance_exposed_ports=""
            
            # Make sure sg_count is a valid integer
            if [[ "$sg_count" =~ ^[0-9]+$ ]]; then
                for ((j=0; j<$sg_count; j++)); do
                    sg_id=$(echo "$security_groups" | jq -r ".[$j].GroupId")
                    
                    # Check each security group for high-risk ports open to the internet
                    for port in "${high_risk_ports[@]}"; do
                        # Get inbound rules for this security group for the specific port
                        # Get security group rules and filter for inbound rules on the client side
                        inbound_rules=$(aws ec2 describe-security-group-rules --region "$REGION" --filters "Name=group-id,Values=$sg_id" --query "SecurityGroupRules[?IsEgress==\`false\` && (FromPort=='$port' || ToPort=='$port' || (FromPort==null && ToPort==null))]" --output json)
                        rule_count=$(echo "$inbound_rules" | jq 'length')
                        
                        # Make sure rule_count is a valid integer
                        if [[ "$rule_count" =~ ^[0-9]+$ ]]; then
                            for ((r=0; r<$rule_count; r++)); do
                                cidr=$(echo "$inbound_rules" | jq -r ".[$r].CidrIpv4")
                                from_port=$(echo "$inbound_rules" | jq -r ".[$r].FromPort")
                                to_port=$(echo "$inbound_rules" | jq -r ".[$r].ToPort")
                                
                                # If CIDR is 0.0.0.0/0, it's exposed to the internet
                                if [ "$cidr" == "0.0.0.0/0" ]; then
                                    is_exposed=true
                                    
                                    # Get port description
                                    port_desc=""
                                    case "$port" in
                                        "22") port_desc="SSH" ;;
                                        "3389") port_desc="RDP" ;;
                                        "1433") port_desc="MS SQL" ;;
                                        "3306") port_desc="MySQL" ;;
                                        "5432") port_desc="PostgreSQL" ;;
                                        "27017"|"27018") port_desc="MongoDB" ;;
                                        "6379") port_desc="Redis" ;;
                                        "9200"|"9300") port_desc="Elasticsearch" ;;
                                        "8080") port_desc="HTTP Alt" ;;
                                        "8443") port_desc="HTTPS Alt" ;;
                                        *) port_desc="Port $port" ;;
                                    esac
                                    
                                    instance_exposed_ports+="<br>- $port_desc (Port $port) via Security Group $sg_id"
                                    
                                    # Only count each instance once
                                    if [[ ! " ${exposed_instances[@]} " =~ " ${instance_id} " ]]; then
                                        exposed_instances+=("$instance_id")
                                        exposed_count=$((exposed_count + 1))
                                    fi
                                fi
                            done
                        fi
                    done
                done
            fi
            
            # Add detailed information about this exposed instance
            if [ "$is_exposed" = true ]; then
                exposed_details+="<br><br><strong>Instance ID:</strong> $instance_id"
                exposed_details+="<br><strong>Name:</strong> $instance_name"
                exposed_details+="<br><strong>Public IP:</strong> $public_ip"
                exposed_details+="<br><strong>Exposed Ports:</strong> $instance_exposed_ports"
            fi
        done
    fi
    
    # Internet-Exposed Ports Check
    total_checks=$((total_checks + 1))
    if [ "$exposed_count" -eq 0 ]; then
        add_check_item "$OUTPUT_FILE" "pass" "Internet-Exposed Ports" "No instances with high-risk ports exposed to the internet" ""
        passed_checks=$((passed_checks + 1))
    else
        violation_detail="$exposed_count instances with high-risk ports exposed to the internet<br><br><strong>Risk:</strong> High-risk ports exposed to the internet can allow unauthorized access attempts from anywhere in the world.<br><br><strong>Exposed Instances:</strong>$exposed_details"
        add_check_item "$OUTPUT_FILE" "fail" "Internet-Exposed Ports" "$violation_detail" "Restrict access to high-risk ports to specific IP ranges. Consider using VPN, AWS Systems Manager Session Manager, or bastion hosts for administrative access."
        failed_checks=$((failed_checks + 1))
    fi
    
    # Check 2.2.1: S3 Bucket Default Settings
    echo "Checking S3 buckets for default configurations..."
    buckets=$(aws s3api list-buckets --query "Buckets[*].Name" --output json --region "$REGION")
    bucket_count=$(echo "$buckets" | jq 'length')
    insecure_acl_count=0
    no_encryption_count=0
    public_buckets=""
    unencrypted_buckets=""
    
    # Make sure bucket_count is a valid integer
    if [[ "$bucket_count" =~ ^[0-9]+$ ]]; then
        for ((i=0; i<$bucket_count; i++)); do
            bucket_name=$(echo "$buckets" | jq -r ".[$i]")
            
            # Check for public access
            acl=$(aws s3api get-bucket-acl --bucket "$bucket_name" --region "$REGION" 2>/dev/null)
            public_access=false
            public_reason=""
            
            if [[ "$acl" == *"AllUsers"* ]]; then
                insecure_acl_count=$((insecure_acl_count + 1))
                public_access=true
                public_reason="AllUsers granted access"
            elif [[ "$acl" == *"AuthenticatedUsers"* ]]; then
                insecure_acl_count=$((insecure_acl_count + 1))
                public_access=true
                public_reason="AuthenticatedUsers granted access"
            fi
            
            # Get bucket policy
            policy=$(aws s3api get-bucket-policy --bucket "$bucket_name" --region "$REGION" 2>/dev/null)
            if [ $? -eq 0 ]; then
                # Check if policy contains "Effect": "Allow" and "Principal": "*"
                if [[ "$policy" == *"\"Effect\": \"Allow\""* && "$policy" == *"\"Principal\": \"*\""* ]]; then
                    if [ "$public_access" = false ]; then
                        insecure_acl_count=$((insecure_acl_count + 1))
                        public_access=true
                    fi
                    public_reason="$public_reason Bucket policy with public access"
                fi
            fi
            
            # Check for block public access settings
            block_public=$(aws s3api get-public-access-block --bucket "$bucket_name" --region "$REGION" 2>/dev/null)
            block_status="Not configured"
            
            if [ $? -eq 0 ]; then
                block_all=$(echo "$block_public" | jq -r ".PublicAccessBlockConfiguration.BlockPublicAcls")
                block_policy=$(echo "$block_public" | jq -r ".PublicAccessBlockConfiguration.BlockPublicPolicy")
                
                if [ "$block_all" == "true" ] && [ "$block_policy" == "true" ]; then
                    block_status="Enabled"
                else
                    block_status="Partially enabled"
                fi
            fi
            
            # Check for encryption
            encryption=$(aws s3api get-bucket-encryption --bucket "$bucket_name" --region "$REGION" 2>/dev/null)
            encrypted=true
            encryption_type="None"
            
            if [ $? -ne 0 ]; then
                no_encryption_count=$((no_encryption_count + 1))
                encrypted=false
            else
                encryption_type=$(echo "$encryption" | jq -r '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm')
            fi
            
            # Add detailed information for public buckets
            if [ "$public_access" = true ]; then
                public_buckets+="<br><br><strong>Bucket:</strong> $bucket_name"
                public_buckets+="<br><strong>Public Access:</strong> Yes ($public_reason)"
                public_buckets+="<br><strong>Block Public Access:</strong> $block_status"
            fi
            
            # Add detailed information for unencrypted buckets
            if [ "$encrypted" = false ]; then
                unencrypted_buckets+="<br><br><strong>Bucket:</strong> $bucket_name"
                unencrypted_buckets+="<br><strong>Encryption:</strong> Not enabled"
                unencrypted_buckets+="<br><strong>Block Public Access:</strong> $block_status"
            fi
        done
    fi
    
    # S3 Public Access Check
    total_checks=$((total_checks + 1))
    if [ "$insecure_acl_count" -eq 0 ]; then
        add_check_item "$OUTPUT_FILE" "pass" "S3 Public Access" "No S3 buckets with public access" ""
        passed_checks=$((passed_checks + 1))
    else
        violation_detail="$insecure_acl_count S3 buckets have public access<br><br><strong>Risk:</strong> Public S3 buckets can expose sensitive data and are frequently targeted by attackers.<br><br><strong>Public Buckets:</strong>$public_buckets"
        add_check_item "$OUTPUT_FILE" "fail" "S3 Public Access" "$violation_detail" "1. Enable S3 Block Public Access at the account level<br>2. Remove public ACLs from the identified buckets<br>3. Review and restrict bucket policies<br>4. Use pre-signed URLs for temporary access when needed"
        failed_checks=$((failed_checks + 1))
    fi
    
    # S3 Encryption Check
    total_checks=$((total_checks + 1))
    if [ "$no_encryption_count" -eq 0 ]; then
        add_check_item "$OUTPUT_FILE" "pass" "S3 Encryption" "All S3 buckets have encryption enabled" ""
        passed_checks=$((passed_checks + 1))
    else
        violation_detail="$no_encryption_count S3 buckets don't have encryption enabled<br><br><strong>Risk:</strong> Unencrypted data storage violates PCI DSS requirements and may expose sensitive information.<br><br><strong>Unencrypted Buckets:</strong>$unencrypted_buckets"
        add_check_item "$OUTPUT_FILE" "fail" "S3 Encryption" "$violation_detail" "1. Enable default encryption for all S3 buckets using AES-256 or AWS KMS<br>2. Consider using AWS Organizations to enforce encryption policies<br>3. Review data classification to ensure appropriate controls"
        failed_checks=$((failed_checks + 1))
    fi
    
    # Check 2.2.5: Insecure Services with Justification
    echo "Checking for insecure services with business justification..."
    total_checks=$((total_checks + 1))
    
    # Check for insecure services like Telnet (23), FTP (21), etc.
    insecure_services=("21" "23" "25" "110" "143")
    insecure_service_names=("FTP" "Telnet" "SMTP" "POP3" "IMAP")
    insecure_sg_found=false
    insecure_service_details=""
    
    for ((i=0; i<${#insecure_services[@]}; i++)); do
        port="${insecure_services[$i]}"
        service_name="${insecure_service_names[$i]}"
        
        # Find security groups that allow this insecure service
        insecure_sgs=$(aws ec2 describe-security-groups --region "$REGION" \
            --filters "Name=ip-permission.from-port,Values=$port" "Name=ip-permission.to-port,Values=$port" \
            --query "SecurityGroups[*].{ID:GroupId,Name:GroupName,VPC:VpcId}" --output json)
        
        sg_count=$(echo "$insecure_sgs" | jq 'length')
        
        if [[ -n "$sg_count" && "$sg_count" -gt 0 ]]; then
            insecure_sg_found=true
            
            # Make sure sg_count is a valid integer
            if [[ "$sg_count" =~ ^[0-9]+$ ]]; then
                for ((j=0; j<$sg_count; j++)); do
                    sg_id=$(echo "$insecure_sgs" | jq -r ".[$j].ID")
                    sg_name=$(echo "$insecure_sgs" | jq -r ".[$j].Name")
                    vpc_id=$(echo "$insecure_sgs" | jq -r ".[$j].VPC")
                    
                    # Check for tags that might indicate business justification
                    tags=$(aws ec2 describe-tags --region "$REGION" \
                        --filters "Name=resource-id,Values=$sg_id" \
                        "Name=key,Values=BusinessJustification,Justification,Reason,PCI-Justification" \
                        --query "Tags[*].{Key:Key,Value:Value}" --output json)
                    
                    tag_count=$(echo "$tags" | jq 'length')
                    has_justification=false
                    justification=""
                    
                    if [[ -n "$tag_count" && "$tag_count" -gt 0 ]]; then
                        has_justification=true
                        
                        # Make sure tag_count is a valid integer
                        if [[ "$tag_count" =~ ^[0-9]+$ ]]; then
                            for ((t=0; t<$tag_count; t++)); do
                                tag_key=$(echo "$tags" | jq -r ".[$t].Key")
                                tag_value=$(echo "$tags" | jq -r ".[$t].Value")
                                justification+="$tag_key: $tag_value<br>"
                            done
                        fi
                    fi
                    
                    # Add to the details
                    insecure_service_details+="<br><br><strong>Security Group:</strong> $sg_id ($sg_name) in VPC $vpc_id"
                    insecure_service_details+="<br><strong>Insecure Service:</strong> $service_name (Port $port)"
                    
                    if [ "$has_justification" = true ]; then
                        insecure_service_details+="<br><strong>Business Justification:</strong><br>$justification"
                    else
                        insecure_service_details+="<br><strong>Business Justification:</strong> Not documented"
                    fi
                done
            fi
        fi
    done
    
    if [ "$insecure_sg_found" = false ]; then
        add_check_item "$OUTPUT_FILE" "pass" "2.2.5 - Insecure Services with Justification" "No insecure services detected in security groups" ""
        passed_checks=$((passed_checks + 1))
    else
        violation_detail="Insecure services detected in security groups<br><br><strong>Requirement:</strong> If any insecure services are present, business justification must be documented and additional security features implemented.<br><br><strong>Details:</strong>$insecure_service_details"
        add_check_item "$OUTPUT_FILE" "fail" "2.2.5 - Insecure Services with Justification" "$violation_detail" "1. Document business justification for each insecure service using AWS resource tags<br>2. Implement additional security features such as IP restrictions or VPN<br>3. If possible, replace insecure services with secure alternatives (SSH instead of Telnet, SFTP instead of FTP, etc.)"
        failed_checks=$((failed_checks + 1))
    fi
    
    # Check 2.2.6: System Security Parameters
    echo "Checking system security parameters..."
    # Check for password policies as an indicator
    password_policy=$(aws iam get-account-password-policy 2>/dev/null)
    if [ $? -eq 0 ]; then
        min_length=$(echo "$password_policy" | jq -r '.PasswordPolicy.MinimumPasswordLength')
        require_symbols=$(echo "$password_policy" | jq -r '.PasswordPolicy.RequireSymbols')
        require_numbers=$(echo "$password_policy" | jq -r '.PasswordPolicy.RequireNumbers')
        require_uppercase=$(echo "$password_policy" | jq -r '.PasswordPolicy.RequireUppercaseCharacters')
        require_lowercase=$(echo "$password_policy" | jq -r '.PasswordPolicy.RequireLowercaseCharacters')
        
        total_checks=$((total_checks + 1))
        if [ "$min_length" -ge 12 ] && [ "$require_symbols" == "true" ] && [ "$require_numbers" == "true" ] && [ "$require_uppercase" == "true" ] && [ "$require_lowercase" == "true" ]; then
            add_check_item "$OUTPUT_FILE" "pass" "Password Policy" "Strong IAM password policy is configured" ""
            passed_checks=$((passed_checks + 1))
        else
            add_check_item "$OUTPUT_FILE" "fail" "Password Policy" "IAM password policy does not meet PCI DSS requirements" "Configure password policy to require minimum length of 12, symbols, numbers, uppercase and lowercase characters"
            failed_checks=$((failed_checks + 1))
        fi
    else
        total_checks=$((total_checks + 1))
        add_check_item "$OUTPUT_FILE" "fail" "Password Policy" "No IAM password policy defined" "Define an IAM password policy that meets PCI DSS requirements"
        failed_checks=$((failed_checks + 1))
    fi
    
    # Check 2.2.7: Non-console Administrative Access Encryption
    echo "Checking for encryption of non-console access..."
    # Check for API Gateway with HTTPS
    api_gateways=$(aws apigateway get-rest-apis --region "$REGION" --query "items[*].{ID:id,Name:name}" --output json 2>/dev/null)
    if [ $? -eq 0 ]; then
        api_count=$(echo "$api_gateways" | jq 'length')
        http_count=0
        
        # Make sure api_count is a valid integer
        if [[ "$api_count" =~ ^[0-9]+$ ]]; then
            for ((i=0; i<$api_count; i++)); do
                api_id=$(echo "$api_gateways" | jq -r ".[$i].ID")
                stages=$(aws apigateway get-stages --rest-api-id "$api_id" --region "$REGION" --query "item[*].{Name:stageName}" --output json 2>/dev/null)
                
                if [[ "$stages" == *"http://"* ]]; then
                    http_count=$((http_count + 1))
                fi
            done
        fi
        
        total_checks=$((total_checks + 1))
        if [ "$http_count" -eq 0 ]; then
            add_check_item "$OUTPUT_FILE" "pass" "API Gateway HTTPS" "All API Gateway endpoints use HTTPS" ""
            passed_checks=$((passed_checks + 1))
        else
            add_check_item "$OUTPUT_FILE" "fail" "API Gateway HTTPS" "$http_count API Gateway endpoints may not enforce HTTPS" "Configure all API Gateway endpoints to use HTTPS"
            failed_checks=$((failed_checks + 1))
        fi
    else
        total_checks=$((total_checks + 1))
        add_check_item "$OUTPUT_FILE" "info" "API Gateway HTTPS" "No API Gateway endpoints found" "No action needed"
        passed_checks=$((passed_checks + 1))
    fi
    
    close_section "$OUTPUT_FILE"
    
    # Requirement 2.3: Wireless environments are configured and managed securely
    add_section "$OUTPUT_FILE" "req-2.3" "Requirement 2.3: Wireless environments are configured and managed securely" "none"
    
    # Check 2.3.1: Wireless Vendor Defaults
    echo "Checking for wireless settings..."
    # This is primarily for on-premises, but we can check for AWS IoT Wireless or similar services
    wireless_things=$(aws iot list-things --region "$REGION" --query "things[*].thingName" --output json 2>/dev/null)
    if [ $? -eq 0 ]; then
        wireless_count=$(echo "$wireless_things" | jq 'length')
        
        total_checks=$((total_checks + 1))
        if [[ -n "$wireless_count" && "$wireless_count" -gt 0 ]]; then
            add_check_item "$OUTPUT_FILE" "warning" "IoT Wireless Devices" "$wireless_count IoT devices found" "Verify all wireless vendor defaults are changed, including encryption keys and passwords"
            warning_checks=$((warning_checks + 1))
        else
            add_check_item "$OUTPUT_FILE" "info" "IoT Wireless Devices" "No AWS IoT devices found" "If wireless networks exist in your environment, verify vendor defaults are changed"
            passed_checks=$((passed_checks + 1))
        fi
    else
        total_checks=$((total_checks + 1))
        add_check_item "$OUTPUT_FILE" "info" "IoT Wireless Devices" "No AWS IoT devices found or insufficient permissions" "If wireless networks exist in your environment, verify vendor defaults are changed"
        passed_checks=$((passed_checks + 1))
    fi
    
    # Check 2.3.2: Wireless Encryption Keys
    echo "Checking for wireless encryption key management..."
    # This is primarily an on-premises check, but we can check for related documentation
    # or AWS IoT/WiFi policies if available
    
    # For AWS IoT Core, check wireless policies
    iot_policies=$(aws iot list-policies --region "$REGION" --query "policies[*].policyName" --output json 2>/dev/null)
    if [ $? -eq 0 ]; then
        policy_count=$(echo "$iot_policies" | jq 'length')
        
        total_checks=$((total_checks + 1))
        if [[ -n "$policy_count" && "$policy_count" -gt 0 ]]; then
            add_check_item "$OUTPUT_FILE" "info" "IoT Security Policies" "$policy_count IoT policies found" "Verify these policies enforce proper encryption and key rotation for wireless devices"
            warning_checks=$((warning_checks + 1))
        else
            if [[ -n "$wireless_count" && "$wireless_count" -gt 0 ]]; then
                add_check_item "$OUTPUT_FILE" "warning" "IoT Security Policies" "No IoT policies found, but IoT devices exist" "Create IoT policies to enforce encryption and key rotation"
                warning_checks=$((warning_checks + 1))
            else
                add_check_item "$OUTPUT_FILE" "info" "IoT Security Policies" "No IoT policies or devices found" "If wireless networks exist in your environment, verify encryption keys are rotated when personnel leave or keys are compromised"
                passed_checks=$((passed_checks + 1))
            fi
        fi
    else
        total_checks=$((total_checks + 1))
        add_check_item "$OUTPUT_FILE" "info" "IoT Security Policies" "No IoT policies found or insufficient permissions" "If wireless networks exist, verify encryption keys are rotated when needed"
        passed_checks=$((passed_checks + 1))
    fi
    
    # Check 2.3.1: IAM Users with Default Names
    echo "Checking IAM users for default/vendor names..."
    default_names=("admin" "administrator" "root" "user" "guest" "test" "demo")
    
    iam_users=$(aws iam list-users --query "Users[*].UserName" --output json)
    user_count=$(echo "$iam_users" | jq 'length')
    default_user_count=0
    
    # Make sure user_count is a valid integer
    if [[ "$user_count" =~ ^[0-9]+$ ]]; then
        for ((i=0; i<$user_count; i++)); do
            username=$(echo "$iam_users" | jq -r ".[$i]" | tr '[:upper:]' '[:lower:]')
            for default_name in "${default_names[@]}"; do
                if [ "$username" == "$default_name" ]; then
                    default_user_count=$((default_user_count + 1))
                    break
                fi
            done
        done
    fi
    
    total_checks=$((total_checks + 1))
    if [ "$default_user_count" -eq 0 ]; then
        add_check_item "$OUTPUT_FILE" "pass" "IAM Default Usernames" "No IAM users with common default usernames" ""
        passed_checks=$((passed_checks + 1))
    else
        add_check_item "$OUTPUT_FILE" "warning" "IAM Default Usernames" "$default_user_count IAM users with common default usernames" "Rename or remove IAM users with default names"
        warning_checks=$((warning_checks + 1))
    fi
    
    # Check 2.3.2: Root Account Usage
    echo "Checking root account usage..."
    # Note: Requires CloudTrail to be enabled and accessible
    
    cloudtrail_trails=$(aws cloudtrail describe-trails --region "$REGION" --query "trailList[*].Name" --output json)
    trail_count=$(echo "$cloudtrail_trails" | jq 'length')
    
    if [[ -n "$trail_count" && "$trail_count" -gt 0 ]]; then
        # Use the first trail for simplicity
        trail_name=$(echo "$cloudtrail_trails" | jq -r ".[0]")
        
        # Get events for the past 90 days
        end_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        start_time=$(date -u -d "-90 days" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null)
        
        # Handle potential date command difference in macOS
        if [ $? -ne 0 ]; then
            start_time=$(date -u -v-90d +"%Y-%m-%dT%H:%M:%SZ")
        fi
        
        root_events=$(aws cloudtrail lookup-events \
            --lookup-attributes AttributeKey=Username,AttributeValue=root \
            --start-time "$start_time" \
            --end-time "$end_time" \
            --region "$REGION" \
            --query "Events[*]" \
            --output json)
        
        root_event_count=$(echo "$root_events" | jq 'length')
        
        total_checks=$((total_checks + 1))
        if [ "$root_event_count" -eq 0 ]; then
            add_check_item "$OUTPUT_FILE" "pass" "Root Account Usage" "No recent Root account usage detected" ""
            passed_checks=$((passed_checks + 1))
        else
            add_check_item "$OUTPUT_FILE" "fail" "Root Account Usage" "Root account used $root_event_count times in the last 90 days" "Use IAM users with appropriate permissions instead of the Root account"
            failed_checks=$((failed_checks + 1))
        fi
    else
        add_check_item "$OUTPUT_FILE" "warning" "Root Account Usage" "Unable to check Root account usage - No CloudTrail trails configured" "Enable CloudTrail to monitor Root account usage"
        total_checks=$((total_checks + 1))
        warning_checks=$((warning_checks + 1))
    fi
    
    
    
    # Check 2.4.1: TLS Configuration for ELBs
    echo "Checking TLS configurations for load balancers..."
    
    elbs=$(aws elbv2 describe-load-balancers --region "$REGION" --query "LoadBalancers[*].{ARN:LoadBalancerArn,Type:Type}" --output json 2>/dev/null)
    if [ $? -eq 0 ]; then
        elb_count=$(echo "$elbs" | jq 'length')
        insecure_tls_count=0
        
        # Make sure elb_count is a valid integer
        if [[ "$elb_count" =~ ^[0-9]+$ ]]; then
            for ((i=0; i<$elb_count; i++)); do
                elb_arn=$(echo "$elbs" | jq -r ".[$i].ARN")
                elb_type=$(echo "$elbs" | jq -r ".[$i].Type")
                
                if [ "$elb_type" == "application" ]; then
                    listeners=$(aws elbv2 describe-listeners --load-balancer-arn "$elb_arn" --region "$REGION" --query "Listeners[?Protocol=='HTTPS']" --output json)
                    listener_count=$(echo "$listeners" | jq 'length')
                    
                    # Make sure listener_count is a valid integer
                    if [[ "$listener_count" =~ ^[0-9]+$ ]]; then
                        for ((j=0; j<$listener_count; j++)); do
                            ssl_policy=$(echo "$listeners" | jq -r ".[$j].SslPolicy")
                            
                            # Check for insecure TLS policies
                            if [[ "$ssl_policy" == *"ELBSecurityPolicy-TLS-1-0"* || "$ssl_policy" == *"ELBSecurityPolicy-2016-08"* ]]; then
                                insecure_tls_count=$((insecure_tls_count + 1))
                            fi
                        done
                    fi
                fi
            done
        fi
        
        total_checks=$((total_checks + 1))
        if [ "$elb_count" -eq 0 ]; then
            add_check_item "$OUTPUT_FILE" "info" "TLS Configuration" "No load balancers found" "No action needed"
            passed_checks=$((passed_checks + 1))
        elif [ "$insecure_tls_count" -eq 0 ]; then
            add_check_item "$OUTPUT_FILE" "pass" "TLS Configuration" "All load balancers use secure TLS configurations" ""
            passed_checks=$((passed_checks + 1))
        else
            add_check_item "$OUTPUT_FILE" "fail" "TLS Configuration" "$insecure_tls_count load balancers using insecure TLS policies" "Update TLS policies to use TLS 1.2 or later"
            failed_checks=$((failed_checks + 1))
        fi
    else
        add_check_item "$OUTPUT_FILE" "info" "TLS Configuration" "Unable to check load balancer TLS configurations" "Ensure your IAM permissions include elbv2:DescribeLoadBalancers"
        total_checks=$((total_checks + 1))
        warning_checks=$((warning_checks + 1))
    fi
    
	close_section "$OUTPUT_FILE"
	
    # Requirement 2.5: Security policies and procedures are documented
    add_section "$OUTPUT_FILE" "req-2.5" "Requirement 2.5: Security policies and documentation" "none"
    
    # Check 2.5.1: CloudTrail Enabled for Change Management
    echo "Checking if CloudTrail is enabled for change tracking..."
    
    if [[ -n "$trail_count" && "$trail_count" -gt 0 ]]; then
        # Check if at least one trail is multi-region and logging
        multi_region_trails=0
        logging_trails=0
        
        # Make sure trail_count is a valid integer
        if [[ "$trail_count" =~ ^[0-9]+$ ]]; then
            for ((i=0; i<$trail_count; i++)); do
                trail_name=$(echo "$cloudtrail_trails" | jq -r ".[$i]")
                
                trail_status=$(aws cloudtrail get-trail-status --name "$trail_name" --region "$REGION")
                is_logging=$(echo "$trail_status" | jq -r ".IsLogging")
                
                trail_info=$(aws cloudtrail describe-trails --trail-name-list "$trail_name" --region "$REGION")
                is_multi_region=$(echo "$trail_info" | jq -r ".trailList[0].IsMultiRegionTrail")
                
                if [ "$is_multi_region" == "true" ]; then
                    multi_region_trails=$((multi_region_trails + 1))
                fi
                
                if [ "$is_logging" == "true" ]; then
                    logging_trails=$((logging_trails + 1))
                fi
            done
        fi
        
        # CloudTrail Multi-Region Check
        total_checks=$((total_checks + 1))
        if [ "$multi_region_trails" -gt 0 ]; then
            add_check_item "$OUTPUT_FILE" "pass" "CloudTrail Multi-Region" "$multi_region_trails multi-region trail(s) configured" ""
            passed_checks=$((passed_checks + 1))
        else
            add_check_item "$OUTPUT_FILE" "fail" "CloudTrail Multi-Region" "No multi-region trails configured" "Configure at least one multi-region CloudTrail trail"
            failed_checks=$((failed_checks + 1))
        fi
        
        # CloudTrail Logging Check
        total_checks=$((total_checks + 1))
        if [ "$logging_trails" -gt 0 ]; then
            add_check_item "$OUTPUT_FILE" "pass" "CloudTrail Logging" "$logging_trails trail(s) actively logging" ""
            passed_checks=$((passed_checks + 1))
        else
            add_check_item "$OUTPUT_FILE" "fail" "CloudTrail Logging" "No CloudTrail trails actively logging" "Enable logging for at least one CloudTrail trail"
            failed_checks=$((failed_checks + 1))
        fi
    else
        # CloudTrail Enabled Check
        total_checks=$((total_checks + 1))
        add_check_item "$OUTPUT_FILE" "fail" "CloudTrail Enabled" "No CloudTrail trails configured" "Configure CloudTrail to track API calls and changes"
        failed_checks=$((failed_checks + 1))
    fi
    
    close_section "$OUTPUT_FILE"
    
    # Requirement 2.6: Unnecessary functionality is removed or disabled
    add_section "$OUTPUT_FILE" "req-2.6" "Requirement 2.6: Unnecessary functionality is removed or disabled" "none"
    
    # Check 2.6.1: Unused Security Groups
    echo "Checking for unused security groups..."
    all_sgs=$(aws ec2 describe-security-groups --region "$REGION" --query "SecurityGroups[*].GroupId" --output json)
    sg_count=$(echo "$all_sgs" | jq 'length')
    
    # Get all security groups used by EC2 instances
    used_sgs_by_ec2=$(aws ec2 describe-instances --region "$REGION" --query "Reservations[*].Instances[*].SecurityGroups[*].GroupId" --output json)
    used_sgs_by_ec2_flat=$(echo "$used_sgs_by_ec2" | jq 'flatten | unique')
    
    # Get all security groups used by RDS instances
    used_sgs_by_rds=$(aws rds describe-db-instances --region "$REGION" --query "DBInstances[*].VpcSecurityGroups[*].VpcSecurityGroupId" --output json)
    used_sgs_by_rds_flat=$(echo "$used_sgs_by_rds" | jq 'flatten | unique')
    
    # Get all security groups used by Elastic Load Balancers
    used_sgs_by_elb=$(aws elbv2 describe-load-balancers --region "$REGION" --query "LoadBalancers[*].SecurityGroups" --output json 2>/dev/null)
    if [ $? -eq 0 ]; then
        used_sgs_by_elb_flat=$(echo "$used_sgs_by_elb" | jq 'flatten | unique')
        
        # Combine all used security groups
        all_used_sgs=$(echo "$used_sgs_by_ec2_flat" "$used_sgs_by_rds_flat" "$used_sgs_by_elb_flat" | jq -s 'add | unique')
    else
        # If ELB command fails (maybe permissions), just combine EC2 and RDS
        all_used_sgs=$(echo "$used_sgs_by_ec2_flat" "$used_sgs_by_rds_flat" | jq -s 'add | unique')
    fi
    
    # Check for unused security groups with detailed information
    unused_sgs=0
    unused_sgs_details=""
    
    # Make sure sg_count is a valid integer
    if [[ "$sg_count" =~ ^[0-9]+$ ]]; then
        for ((i=0; i<$sg_count; i++)); do
            sg_id=$(echo "$all_sgs" | jq -r ".[$i]")
            
            # Get security group details
            sg_details=$(aws ec2 describe-security-groups --group-ids "$sg_id" --region "$REGION" --query "SecurityGroups[0].[GroupName,VpcId,Description]" --output json)
            sg_name=$(echo "$sg_details" | jq -r ".[0]")
            vpc_id=$(echo "$sg_details" | jq -r ".[1]")
            sg_desc=$(echo "$sg_details" | jq -r ".[2]")
            
            # Skip default security groups
            if [ "$sg_name" == "default" ]; then
                continue
            fi
            
            is_used=$(echo "$all_used_sgs" | jq -r "contains([\"$sg_id\"])")
            if [ "$is_used" == "false" ]; then
                unused_sgs=$((unused_sgs + 1))
                
                # Get inbound rules for this security group
                # Get security group rules and filter for inbound rules on the client side
                inbound_rules=$(aws ec2 describe-security-group-rules --filters "Name=group-id,Values=$sg_id" --region "$REGION" --query "SecurityGroupRules[?IsEgress==\`false\`].[IpProtocol,FromPort,ToPort,CidrIpv4]" --output json)
                rule_count=$(echo "$inbound_rules" | jq 'length')
                
                rule_summary=""
                if [[ -n "$rule_count" && "$rule_count" -gt 0 ]]; then
                    rule_summary="<br><strong>Inbound Rules:</strong>"
                    
                    # Make sure rule_count is a valid integer
                    if [[ "$rule_count" =~ ^[0-9]+$ ]]; then
                        for ((r=0; r<$rule_count; r++)); do
                            protocol=$(echo "$inbound_rules" | jq -r ".[$r][0]")
                            from_port=$(echo "$inbound_rules" | jq -r ".[$r][1]")
                            to_port=$(echo "$inbound_rules" | jq -r ".[$r][2]")
                            cidr=$(echo "$inbound_rules" | jq -r ".[$r][3]")
                            
                            # Handle 'all protocols' case
                            if [ "$protocol" == "-1" ]; then
                                protocol="All"
                                port_range="All"
                            else
                                if [ "$from_port" == "$to_port" ]; then
                                    port_range="$from_port"
                                else
                                    port_range="$from_port-$to_port"
                                fi
                            fi
                            
                            rule_summary="$rule_summary<br>- Protocol: $protocol, Ports: $port_range, Source: $cidr"
                        done
                    fi
                else
                    rule_summary="<br><strong>Inbound Rules:</strong> None"
                fi
                
                # Add this security group to the details
                unused_sgs_details+="<br><br><strong>Security Group ID:</strong> $sg_id"
                unused_sgs_details+="<br><strong>Name:</strong> $sg_name"
                unused_sgs_details+="<br><strong>VPC:</strong> $vpc_id"
                if [ "$sg_desc" != "null" ]; then
                    unused_sgs_details+="<br><strong>Description:</strong> $sg_desc"
                fi
                unused_sgs_details+="$rule_summary"
            fi
        done
    fi
    
    total_checks=$((total_checks + 1))
    if [ "$unused_sgs" -eq 0 ]; then
        add_check_item "$OUTPUT_FILE" "pass" "Unused Security Groups" "No unused security groups found" ""
        passed_checks=$((passed_checks + 1))
    else
        violation_detail="$unused_sgs unused security groups found<br><br><strong>Risk:</strong> Unused security groups increase complexity, reduce visibility, and may pose a security risk if accidentally used or misconfigured.<br><br><strong>Unused Security Groups:</strong>$unused_sgs_details"
        add_check_item "$OUTPUT_FILE" "warning" "Unused Security Groups" "$violation_detail" "1. Delete unused security groups to reduce complexity and attack surface<br>2. Implement a regular cleanup process for security groups<br>3. Consider using AWS Config rules to detect and alert on unused security groups"
        warning_checks=$((warning_checks + 1))
    fi
    
    # Check 2.6.2: Unnecessary Ports Open
    echo "Checking for unnecessary open ports in security groups..."
    
    high_risk_ports=(21 22 23 25 53 110 135 137 138 139 445 1433 1434 3306 3389 5432 5500)
    internet_exposed_count=0
    
    # Make sure sg_count is a valid integer
    if [[ "$sg_count" =~ ^[0-9]+$ ]]; then
        for ((i=0; i<$sg_count; i++)); do
            sg_id=$(echo "$all_sgs" | jq -r ".[$i]")
            
            sg_rules=$(aws ec2 describe-security-groups --group-ids "$sg_id" --region "$REGION" --query "SecurityGroups[0].IpPermissions" --output json)
            rule_count=$(echo "$sg_rules" | jq 'length')
            
            # Make sure rule_count is a valid integer
            if [[ "$rule_count" =~ ^[0-9]+$ ]]; then
                for ((j=0; j<$rule_count; j++)); do
                    from_port=$(echo "$sg_rules" | jq -r ".[$j].FromPort")
                    to_port=$(echo "$sg_rules" | jq -r ".[$j].ToPort")
                    ip_ranges=$(echo "$sg_rules" | jq -r ".[$j].IpRanges")
                    
                    # Skip if FromPort/ToPort is null (which means all ports)
                    if [ "$from_port" == "null" ] || [ "$to_port" == "null" ]; then
                        continue
                    fi
                    
                    # Check if any high-risk port is open to the internet
                    for port in "${high_risk_ports[@]}"; do
                        if (( $from_port <= $port && $port <= $to_port )); then
                            # Check if open to internet (0.0.0.0/0)
                            if [[ "$ip_ranges" == *"0.0.0.0/0"* ]]; then
                                internet_exposed_count=$((internet_exposed_count + 1))
                                break
                            fi
                        fi
                    done
                done
            fi
        done
    fi
    
    total_checks=$((total_checks + 1))
    if [ "$internet_exposed_count" -eq 0 ]; then
        add_check_item "$OUTPUT_FILE" "pass" "Internet-Exposed Ports" "No high-risk ports exposed to the internet" ""
        passed_checks=$((passed_checks + 1))
    else
        # Gather detailed information about exposed ports
        exposed_ports_details=""
        
        # Make sure sg_count is a valid integer
        if [[ "$sg_count" =~ ^[0-9]+$ ]]; then
            for ((i=0; i<$sg_count; i++)); do
                sg_id=$(echo "$all_sgs" | jq -r ".[$i]")
                
                # Get security group details
                sg_details=$(aws ec2 describe-security-groups --group-ids "$sg_id" --region "$REGION" --query "SecurityGroups[0].[GroupName,VpcId,Description]" --output json)
                sg_name=$(echo "$sg_details" | jq -r ".[0]")
                vpc_id=$(echo "$sg_details" | jq -r ".[1]")
                
                sg_rules=$(aws ec2 describe-security-groups --group-ids "$sg_id" --region "$REGION" --query "SecurityGroups[0].IpPermissions" --output json)
                rule_count=$(echo "$sg_rules" | jq 'length')
                
                sg_has_exposed_ports=false
                sg_exposed_ports=""
                
                # Make sure rule_count is a valid integer
                if [[ "$rule_count" =~ ^[0-9]+$ ]]; then
                    for ((j=0; j<$rule_count; j++)); do
                        from_port=$(echo "$sg_rules" | jq -r ".[$j].FromPort")
                        to_port=$(echo "$sg_rules" | jq -r ".[$j].ToPort")
                        ip_ranges=$(echo "$sg_rules" | jq -r ".[$j].IpRanges")
                        protocol=$(echo "$sg_rules" | jq -r ".[$j].IpProtocol")
                        
                        # Check for internet exposure (0.0.0.0/0)
                        if [[ "$ip_ranges" == *"0.0.0.0/0"* ]]; then
                            # Handle 'all protocols' case
                            if [ "$protocol" == "-1" ]; then
                                sg_has_exposed_ports=true
                                sg_exposed_ports+="<br>- All Ports (All Protocols) exposed to 0.0.0.0/0"
                                continue
                            fi
                            
                            # Skip if FromPort/ToPort is null
                            if [ "$from_port" == "null" ] || [ "$to_port" == "null" ]; then
                                continue
                            fi
                            
                            # Check specific high-risk ports
                            for port in "${high_risk_ports[@]}"; do
                                if (( $from_port <= $port && $port <= $to_port )); then
                                    sg_has_exposed_ports=true
                                    port_name=""
                                    case "$port" in
                                        21) port_name="FTP" ;;
                                        22) port_name="SSH" ;;
                                        23) port_name="Telnet" ;;
                                        25) port_name="SMTP" ;;
                                        53) port_name="DNS" ;;
                                        110) port_name="POP3" ;;
                                        135) port_name="RPC" ;;
                                        137|138|139) port_name="NetBIOS" ;;
                                        445) port_name="SMB" ;;
                                        1433|1434) port_name="MS SQL" ;;
                                        3306) port_name="MySQL" ;;
                                        3389) port_name="RDP" ;;
                                        5432) port_name="PostgreSQL" ;;
                                        5500) port_name="VNC" ;;
                                        *) port_name="Port $port" ;;
                                    esac
                                    sg_exposed_ports+="<br>- $port_name (Port $port) exposed to 0.0.0.0/0"
                                fi
                            done
                        fi
                    done
                fi
                
                # If this security group has exposed ports, add to details
                if [ "$sg_has_exposed_ports" = true ]; then
                    # Check which resources use this security group
                    resources=""
                    
                    # Check EC2 instances
                    ec2_instances=$(aws ec2 describe-instances --filters "Name=instance.group-id,Values=$sg_id" --region "$REGION" --query "Reservations[*].Instances[*].[InstanceId,PublicIpAddress]" --output json)
                    ec2_count=$(echo "$ec2_instances" | jq 'length')
                    
                    if [[ -n "$ec2_count" && "$ec2_count" -gt 0 ]]; then
                        resources+="<br><strong>EC2 Instances:</strong>"
                        
                        # Make sure ec2_count is a valid integer
                        if [[ "$ec2_count" =~ ^[0-9]+$ ]]; then
                            for ((e=0; e<$ec2_count; e++)); do
                                instance_id=$(echo "$ec2_instances" | jq -r ".[$e][][0]")
                                public_ip=$(echo "$ec2_instances" | jq -r ".[$e][][1]")
                                
                                if [ "$public_ip" == "null" ]; then
                                    public_ip="No public IP"
                                fi
                                
                                resources+="<br>- $instance_id - Public IP: $public_ip"
                            done
                        fi
                    fi
                    
                    exposed_ports_details+="<br><br><strong>Security Group ID:</strong> $sg_id"
                    exposed_ports_details+="<br><strong>Name:</strong> $sg_name"
                    exposed_ports_details+="<br><strong>VPC:</strong> $vpc_id"
                    exposed_ports_details+="<br><strong>Exposed Ports:</strong>$sg_exposed_ports"
                    
                    if [ -n "$resources" ]; then
                        exposed_ports_details+="<br><strong>Affected Resources:</strong>$resources"
                    fi
                fi
            done
        fi
        
        violation_detail="$internet_exposed_count instances of high-risk ports exposed to the internet<br><br><strong>Risk:</strong> High-risk ports exposed to the internet are common targets for attackers and can lead to unauthorized access if not properly secured.<br><br><strong>Exposed Ports Details:</strong>$exposed_ports_details"
        add_check_item "$OUTPUT_FILE" "fail" "Internet-Exposed Ports" "$violation_detail" "1. Restrict access to high-risk ports to specific IP ranges<br>2. Use VPN or AWS Systems Manager Session Manager for administrative access<br>3. Consider implementing a bastion host for secure access<br>4. Enable enhanced network security with AWS Network Firewall or third-party solutions"
        failed_checks=$((failed_checks + 1))
    fi
    
    close_section "$OUTPUT_FILE"
    
    # Finalize the HTML report
    # Calculate compliance percentage excluding warnings and access denied checks
    echo -e "\n${CYAN}=== SUMMARY OF PCI DSS REQUIREMENT $REQUIREMENT_NUMBER CHECKS ===${NC}"
    echo "Total checks: $total_checks"
    echo "Passed checks: $passed_checks"
    echo "Failed checks: $failed_checks"
    echo "Warning/manual checks: $warning_checks"
    echo "Access denied checks: $access_denied_checks"
    
    # Calculate compliance percentage manually to verify
    effective_checks=$((total_checks - warning_checks - access_denied_checks))
    if [ $effective_checks -gt 0 ]; then
        manual_compliance_percentage=$(( (passed_checks * 100) / effective_checks ))
        echo "Compliance percentage (excluding warnings and access denied): $manual_compliance_percentage%"
    else
        echo "No effective checks were performed (all were warnings or access denied)"
        manual_compliance_percentage=0
    fi
    
    # Pass the access_denied_checks parameter to finalize_html_report
    finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER" "$access_denied_checks"

    echo "Assessment complete. Report saved to: $OUTPUT_FILE"

    # Open the report in the default browser (macOS only)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open "$OUTPUT_FILE"
    else
        echo "To view the report, open it in your web browser."
    fi
}

# Execute the main function
main