#!/bin/bash

# PCI DSS Requirement 1 Compliance Check Script for AWS
# This script evaluates AWS network security controls for PCI DSS Requirement 1 compliance
# Requirements covered: 1.1 - 1.5 (Network Security Controls, CDE isolation, etc.)

# Set output colors for terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Source the shared HTML report library
source "$(dirname "$0")/pci_html_report_lib.sh"

# Define variables
REQUIREMENT_NUMBER="1"
REPORT_TITLE="PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report"
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
access_denied_checks=0
manual_checks=0

# Reset PCI tracking variables
export PCI_ACCESS_DENIED=0
export PCI_MANUAL_CHECK=0

# Function to get all VPC IDs
get_all_vpcs() {
    echo -ne "Retrieving VPC information... " >&2  # 印到 stderr
    VPC_LIST=$(aws ec2 describe-vpcs --region $REGION --query 'Vpcs[*].VpcId' --output text 2>/dev/null)
    
    if [ -z "$VPC_LIST" ]; then
        echo -e "${RED}FAILED${NC} - No VPCs found or access denied" >&2
        add_check_item "$OUTPUT_FILE" "fail" "VPC Retrieval" "No VPCs found or access denied. Cannot proceed with VPC assessment." "Verify AWS credentials and permissions to describe VPCs."
        return 1
    else
        echo -e "${GREEN}SUCCESS${NC} - Found $(echo $VPC_LIST | wc -w) VPCs" >&2
        add_check_item "$OUTPUT_FILE" "pass" "VPC Retrieval" "Successfully retrieved $(echo $VPC_LIST | wc -w) VPCs for assessment."
        echo "$VPC_LIST"  # 只有這裡用 stdout 回傳值
        return 0
    fi
}

# Start script execution
echo "============================================="
echo "  PCI DSS 4.0 - Requirement 1 HTML Report"
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


# Ask for CDE VPC(s) - (Cardholder Data Environment)
if [ -z "$CDE_VPCS" ]; then
    read -p "Enter CDE VPC IDs (comma-separated or 'all' for all VPCs): " CDE_VPCS
    if [ -z "$CDE_VPCS" ] || [ "$CDE_VPCS" == "all" ]; then
        echo -e "${YELLOW}Checking all VPCs${NC}"
        CDE_VPCS="all"
    else
        echo -e "${YELLOW}Checking specific VPC(s): $CDE_VPCS${NC}"
    fi
else
    echo -e "${YELLOW}Using provided CDE_VPCS: $CDE_VPCS${NC}"
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
echo "Verifying access to required AWS services for PCI Requirement 1 assessment..."

# Function to check permissions with proper tracking
check_permission() {
    local service="$1"
    local command="$2"
    
    check_command_access "$OUTPUT_FILE" "$service" "$command" "$REGION"
    ((total_checks++))
    
    if [ $PCI_ACCESS_DENIED -eq 1 ]; then
        ((failed_checks++))
        ((access_denied_checks++))
    else
        ((passed_checks++))
    fi
}

# Check all required permissions
check_permission "ec2" "describe-vpcs"
check_permission "ec2" "describe-security-groups"
check_permission "ec2" "describe-network-acls"
check_permission "ec2" "describe-subnets"
check_permission "ec2" "describe-route-tables"
check_permission "ec2" "describe-vpc-endpoints"
check_permission "ec2" "describe-vpc-peering-connections"
check_permission "ec2" "describe-nat-gateways"
check_permission "ec2" "describe-internet-gateways"
check_permission "ec2" "describe-flow-logs"
check_permission "wafv2" "list-web-acls"
check_permission "ec2" "describe-transit-gateways"

# Calculate permissions percentage excluding access denied errors
available_permissions=$((total_checks - access_denied_checks))
if [ $available_permissions -gt 0 ]; then
    permissions_percentage=$(( (passed_checks * 100) / available_permissions ))
else
    permissions_percentage=0
fi

if [ $permissions_percentage -lt 70 ]; then
    echo -e "${RED}WARNING: Insufficient permissions to perform a complete PCI Requirement 1 assessment.${NC}"
    add_check_item "$OUTPUT_FILE" "warning" "Permission Assessment" "<p>Insufficient permissions detected. Only $permissions_percentage% of required permissions are available.</p><p>Without these permissions, the assessment will be incomplete and may not accurately reflect your PCI DSS compliance status.</p>" "Request additional permissions or continue with limited assessment capabilities."
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
    add_check_item "$OUTPUT_FILE" "pass" "Permission Assessment" "<p>Sufficient permissions detected. $permissions_percentage% of required permissions are available.</p><p>All necessary AWS API calls can be performed for a comprehensive assessment.</p>"
fi

close_section "$OUTPUT_FILE"

# Reset counters for the actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

#----------------------------------------------------------------------
# SECTION 2: DETERMINE VPCS TO CHECK
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "target-vpcs" "Target VPC Environments" "block"

echo -e "\n${CYAN}=== IDENTIFYING TARGET VPC ENVIRONMENTS ===${NC}"

if [ "$CDE_VPCS" == "all" ]; then
    TARGET_VPCS=$(get_all_vpcs)
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to retrieve VPC information. Check your permissions.${NC}"
        add_check_item "$OUTPUT_FILE" "fail" "VPC Environment Identification" "<p>Failed to retrieve VPC information.</p><p>This is a critical error that prevents further assessment of network security controls.</p>" "Check your AWS permissions for VPC access."
        close_section "$OUTPUT_FILE"
        finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"
        echo "Report has been generated: $OUTPUT_FILE"
        exit 1
    else
        vpc_count=$(echo $TARGET_VPCS | wc -w)
        add_check_item "$OUTPUT_FILE" "info" "VPC Environment Identification" "<p>All $vpc_count VPCs will be assessed:</p><pre>${TARGET_VPCS}</pre><p>For an accurate assessment, you should identify which of these VPCs are part of your Cardholder Data Environment (CDE).</p>"
    fi
else
    # Convert comma-separated list to space-separated
    TARGET_VPCS=$(echo $CDE_VPCS | tr ',' ' ')
    echo -e "Using provided VPC list: $TARGET_VPCS"
    vpc_count=$(echo $TARGET_VPCS | wc -w)
    add_check_item "$OUTPUT_FILE" "info" "VPC Environment Identification" "<p>Assessment will be performed on $vpc_count specified VPCs:</p><pre>${TARGET_VPCS}</pre><p>These VPCs were specified as potentially containing Cardholder Data Environment (CDE) components.</p>"
fi

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 3: PCI REQUIREMENT 1.1 - NETWORK SECURITY CONTROL PROCESSES
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-1.1" "Requirement 1.1: Processes and mechanisms for installing and maintaining network security controls are defined and understood" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 1.1: NETWORK SECURITY CONTROL PROCESSES ===${NC}"

manual_check_details="
<p>Requirement 1.1 focuses on documenting and maintaining processes for network security controls.</p>
<p>This requirement covers:</p>
<ul>
    <li><strong>1.1.1</strong> - Security policies and operational procedures for network security controls must be:
        <ul>
            <li>Documented</li>
            <li>Kept up to date</li>
            <li>In use</li>
            <li>Known to all affected parties</li>
        </ul>
    </li>
    <li><strong>1.1.2</strong> - Roles and responsibilities for performing activities in Requirement 1 must be documented, assigned, and understood</li>
</ul>

<p>This requires manual verification through documentation review and interviews. AWS artifacts that may assist with this assessment include:</p>
<ul>
    <li>AWS Organizations Service Control Policies (SCPs) documentation</li>
    <li>AWS Identity and Access Management (IAM) role documentation</li>
    <li>Network security control documentation, runbooks, and procedures</li>
    <li>Change management documentation related to network controls</li>
</ul>
"

add_manual_check "$OUTPUT_FILE" "1.1.1 & 1.1.2 - Network Security Control Processes" "$manual_check_details" "Review network security control documentation to ensure it meets PCI DSS 4.0 requirements 1.1.1 and 1.1.2. Ensure documentation is accessible to all relevant personnel and that roles are clearly defined."

((total_checks++))
((warning_checks++))
((manual_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 4: PCI REQUIREMENT 1.2 - NETWORK SECURITY CONTROLS CONFIG
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-1.2" "Requirement 1.2: Network Security Controls Configuration" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 1.2: NETWORK SECURITY CONTROLS CONFIGURATION ===${NC}"

# Function to add a manual warning check
add_manual_warning_check() {
    local title="$1"
    local details="$2"
    local recommendation="$3"
    
    echo -e "\n${BLUE}$title${NC}"
    add_manual_check "$OUTPUT_FILE" "$title" "$details" "$recommendation"
    ((total_checks++))
    ((warning_checks++))
    ((manual_checks++))
}

# Check 1.2.1 - Configuration standards for NSC rulesets
add_manual_warning_check "1.2.1 - Configuration standards for NSC rulesets" "<p>This requirement needs manual verification of defined configuration standards for all network security controls.</p>
<p>Per PCI DSS Requirement 1.2.1, configuration standards for NSC rulesets must be:</p>
<ul>
    <li>Defined</li>
    <li>Implemented</li>
    <li>Maintained</li>
</ul>
<p>AWS resources to examine:</p>
<ul>
    <li>Security group policies and standards</li>
    <li>Network ACL configuration standards</li>
    <li>VPC configuration documentation</li>
    <li>AWS WAF rule documentation</li>
    <li>AWS Config rules for NSC validation</li>
</ul>" "Review documentation to verify configuration standards exist for firewalls (Security Groups, NACLs) and other network security controls. Standards should include default deny rules and documentation of all permitted traffic flows."

# Check 1.2.2 - Change control processes for NSCs
add_manual_warning_check "1.2.2 - Change control processes for network connections and NSCs" "This requirement needs manual verification of change control processes for network security controls." "Review CloudTrail logs for changes to Security Groups, NACLs, and other network controls to verify proper change management processes."

# Check 1.2.3 - Network Peering Connections
echo -e "\n${BLUE}1.2.3 - Network Peering Connections${NC}"
echo -e "Retrieving all VPC Peering Connections for region: $REGION..."

peering_connections=$(aws ec2 describe-vpc-peering-connections --region $REGION --query 'VpcPeeringConnections[*]' --output json 2>/dev/null)

peering_details="<p>VPC Peering Connections in region $REGION:</p><ul>"

if [ -z "$peering_connections" ] || [ "$peering_connections" == "[]" ]; then
    echo -e "${GREEN}No VPC Peering Connections found in this region${NC}"
    peering_details+="<li class=\"green\">No VPC Peering Connections found</li></ul>"
    add_check_item "$OUTPUT_FILE" "info" "1.2.3 - Network Peering Connections" "$peering_details" "No VPC Peering Connections were detected in this region. No additional peering-related risks identified."
    ((passed_checks++))
else
    echo -e "${CYAN}Found VPC Peering Connections, analyzing...${NC}"

    for row in $(echo "$peering_connections" | jq -c '.[]'); do
        pcx_id=$(echo "$row" | jq -r '.VpcPeeringConnectionId')
        status=$(echo "$row" | jq -r '.Status.Code')
        accepter_vpc=$(echo "$row" | jq -r '.AccepterVpcInfo.VpcId')
        requester_vpc=$(echo "$row" | jq -r '.RequesterVpcInfo.VpcId')
        tags=$(echo "$row" | jq -r '.Tags[]?.Value' | paste -sd "," -)

        [ -z "$tags" ] && tags="(No Tags)"

        peering_details+="<li>Peering ID: $pcx_id , Tags: $tags<br>"
        peering_details+="Status: $status<br>"
        peering_details+="Accepter VPC: $accepter_vpc<br>"
        peering_details+="Requester VPC: $requester_vpc</li>"
    done

    peering_details+="</ul>"
    add_check_item "$OUTPUT_FILE" "warning" "1.2.3 - Network Peering Connections" "$peering_details" "Verify all VPC Peering Connections are authorized and have proper security controls (NACLs, Security Groups, Route Tables)."
    ((warning_checks++))
fi
((total_checks++))



# Check 1.2.4 - Data-flow diagrams
add_manual_warning_check "1.2.4 - Data-flow diagrams" "This requirement needs manual verification of data-flow diagrams showing account data flows." "Review data-flow diagrams and compare with actual AWS infrastructure and data flows to ensure accuracy and completeness."

# Check 1.2.5 - Ports, protocols, and services inventory (Security Groups)
echo -e "\n${BLUE}1.2.5 - Ports, protocols, and services inventory${NC}"
echo -e "Checking security groups for allowed ports, protocols, and services..."

sg_check_details="<p>Findings for allowed ports, protocols, and services:</p><ul>"

for vpc_id in $TARGET_VPCS; do
    echo -e "\nChecking Security Groups in VPC: $vpc_id"
    sg_list=$(aws ec2 describe-security-groups --region $REGION --filters "Name=vpc-id,Values=$vpc_id" --query 'SecurityGroups[*].GroupId' --output text 2>/dev/null)
    
    if [ -z "$sg_list" ]; then
        echo -e "${YELLOW}No security groups found in VPC $vpc_id${NC}"
        sg_check_details+="<li>No security groups found in VPC $vpc_id</li>"
        continue
    fi
    
    sg_check_details+="<li>VPC: $vpc_id</li><ul>"
    
    for sg_id in $sg_list; do
        echo -e "\nAnalyzing Security Group: $sg_id"
        sg_details=$(aws ec2 describe-security-groups --region $REGION --group-ids $sg_id --output json 2>/dev/null)
        sg_name=$(echo "$sg_details" | jq -r '.SecurityGroups[0].GroupName')
        
        sg_check_details+="<li>Security Group: $sg_id ($sg_name)</li><ul>"
        
        # Count and list public inbound rules
        public_inbound=$(echo "$sg_details" | jq '[.SecurityGroups[].IpPermissions[] | select(.IpRanges[].CidrIp=="0.0.0.0/0")] | length')
        if [ "$public_inbound" -gt 0 ]; then
            echo -e "${RED}WARNING: Security group $sg_id has $public_inbound public inbound rules (0.0.0.0/0)${NC}"
            sg_check_details+="<li class=\"red\">WARNING: Has $public_inbound public inbound rules (0.0.0.0/0)</li>"
            
            # Get detailed rule info (Protocol, Ports)
            public_rules=$(echo "$sg_details" | jq -r '.SecurityGroups[].IpPermissions[] 
                | select(.IpRanges[].CidrIp=="0.0.0.0/0") 
                | "Protocol: \(.IpProtocol) | FromPort: \(.FromPort // "all") | ToPort: \(.ToPort // "all")"' 2>/dev/null)
            
            [ -z "$public_rules" ] && public_rules="(No detailed rule data)"
            sg_check_details+="<li><pre>$public_rules</pre></li>"
        else
            echo -e "${GREEN}No public inbound rules (0.0.0.0/0) found in Security Group $sg_id${NC}"
            sg_check_details+="<li class=\"green\">No public inbound rules (0.0.0.0/0) found</li>"
        fi
        
        sg_check_details+="</ul>"
    done
    
    sg_check_details+="</ul>"
done

sg_check_details+="</ul>"

add_manual_check "$OUTPUT_FILE" "1.2.5 - Ports, protocols, and services inventory" "$sg_check_details" "Document business justification for all allowed ports, protocols, and services. Ensure all allowed services, protocols, and ports are identified and have defined business needs."
((total_checks++))
((warning_checks++))
((manual_checks++))


# Check 1.2.6 - Security features for insecure services/protocols
echo -e "\n${BLUE}1.2.6 - Security features for insecure services/protocols${NC}"
echo -e "Checking for common insecure services/protocols in security groups..."

insecure_services=false
insecure_details="<p>Analysis of insecure services/protocols in security groups:</p><ul>"

for vpc_id in $TARGET_VPCS; do
    sg_list=$(aws ec2 describe-security-groups --region $REGION --filters "Name=vpc-id,Values=$vpc_id" --query 'SecurityGroups[*].GroupId' --output text 2>/dev/null)
    
    if [ -z "$sg_list" ]; then
        continue
    fi
    
    insecure_details+="<li>VPC: $vpc_id</li><ul>"
    
    for sg_id in $sg_list; do
        sg_details=$(aws ec2 describe-security-groups --region $REGION --group-ids $sg_id 2>/dev/null)
        sg_name=$(echo "$sg_details" | grep "GroupName" | head -1 | awk -F '"' '{print $4}')
        
        sg_found_insecure=false
        sg_insecure_list="<ul>"
        
        # Check for telnet (port 23)
        telnet_check=$(echo "$sg_details" | grep -A 5 '"FromPort": 23' | grep -c '"ToPort": 23')
        if [ $telnet_check -gt 0 ]; then
            # Get source details for better reporting
            telnet_sources=$(echo "$sg_details" | grep -A 10 '"FromPort": 23' | grep -B 5 '"ToPort": 23' | grep "CidrIp" | awk -F '"' '{print $4}')
            echo -e "${RED}WARNING: Security group $sg_id allows Telnet (port 23)${NC}"
            sg_insecure_list+="<li class=\"red\">Allows Telnet (port 23) - Insecure cleartext protocol from:</li><ul>"
            for source in $telnet_sources; do
                sg_insecure_list+="<li>$source</li>"
            done
            sg_insecure_list+="</ul>"
            insecure_services=true
            sg_found_insecure=true
        fi
        
        # Check for FTP (port 21)
        ftp_check=$(echo "$sg_details" | grep -A 5 '"FromPort": 21' | grep -c '"ToPort": 21')
        if [ $ftp_check -gt 0 ]; then
            # Get source details for better reporting
            ftp_sources=$(echo "$sg_details" | grep -A 10 '"FromPort": 21' | grep -B 5 '"ToPort": 21' | grep "CidrIp" | awk -F '"' '{print $4}')
            echo -e "${RED}WARNING: Security group $sg_id allows FTP (port 21)${NC}"
            sg_insecure_list+="<li class=\"red\">Allows FTP (port 21) - Insecure cleartext protocol from:</li><ul>"
            for source in $ftp_sources; do
                sg_insecure_list+="<li>$source</li>"
            done
            sg_insecure_list+="</ul>"
            insecure_services=true
            sg_found_insecure=true
        fi
        
        # Check for non-encrypted SQL Server (port 1433)
        sql_check=$(echo "$sg_details" | grep -A 5 '"FromPort": 1433' | grep -c '"ToPort": 1433')
        if [ $sql_check -gt 0 ]; then
            # Get source details for better reporting
            sql_sources=$(echo "$sg_details" | grep -A 10 '"FromPort": 1433' | grep -B 5 '"ToPort": 1433' | grep "CidrIp" | awk -F '"' '{print $4}')
            echo -e "${YELLOW}NOTE: Security group $sg_id allows SQL Server (port 1433) - ensure encryption is in use${NC}"
            sg_insecure_list+="<li class=\"yellow\">Allows SQL Server (port 1433) - Ensure encryption is in use from:</li><ul>"
            for source in $sql_sources; do
                sg_insecure_list+="<li>$source</li>"
            done
            sg_insecure_list+="</ul>"
            insecure_services=true
            sg_found_insecure=true
        fi
        
        # Check for non-encrypted MySQL/MariaDB (port 3306)
        mysql_check=$(echo "$sg_details" | grep -A 5 '"FromPort": 3306' | grep -c '"ToPort": 3306')
        if [ $mysql_check -gt 0 ]; then
            # Get source details for better reporting
            mysql_sources=$(echo "$sg_details" | grep -A 10 '"FromPort": 3306' | grep -B 5 '"ToPort": 3306' | grep "CidrIp" | awk -F '"' '{print $4}')
            echo -e "${YELLOW}NOTE: Security group $sg_id allows MySQL/MariaDB (port 3306) - ensure encryption is in use${NC}"
            sg_insecure_list+="<li class=\"yellow\">Allows MySQL/MariaDB (port 3306) - Ensure encryption is in use from:</li><ul>"
            for source in $mysql_sources; do
                sg_insecure_list+="<li>$source</li>"
            done
            sg_insecure_list+="</ul>"
            insecure_services=true
            sg_found_insecure=true
        fi
		
		# Check for SAMBA Service (port 445)
		samba_check=$(echo "$sg_details" | grep -A 5 '"FromPort": 445' | grep -c '"ToPort": 445')
        if [ $samba_check -gt 0 ]; then
            # Get source details for better reporting
            samba_sources=$(echo "$sg_details" | grep -A 10 '"FromPort": 445' | grep -B 5 '"ToPort": 445' | grep "CidrIp" | awk -F '"' '{print $4}')
            echo -e "${YELLOW}NOTE: Security group $sg_id allows SAMBA Service (port 445) - ensure encryption is in use${NC}"
            sg_insecure_list+="<li class=\"yellow\">Allows SAMBA Service (port 445) - Ensure encryption is in use from:</li><ul>"
            for source in $samba_sources; do
                sg_insecure_list+="<li>$source</li>"
            done
            sg_insecure_list+="</ul>"
            insecure_services=true
            sg_found_insecure=true
        fi
        
        sg_insecure_list+="</ul>"
        
        if [ "$sg_found_insecure" = true ]; then
            insecure_details+="<li>Security Group: $sg_id ($sg_name)$sg_insecure_list</li>"
        fi
    done
    
    insecure_details+="</ul>"
done

insecure_details+="</ul>"

if [ "$insecure_services" = false ]; then
    echo -e "${GREEN}No common insecure services/protocols detected in security groups${NC}"
    add_check_item "$OUTPUT_FILE" "pass" "1.2.6 - Security features for insecure services/protocols" "<p class=\"green\">No common insecure services/protocols detected in security groups</p><p>All examined security groups appear to be using secure services and protocols, or have appropriate restrictions in place.</p>"
    ((passed_checks++))
else
    echo -e "${RED}Insecure services/protocols detected in security groups${NC}"
    add_check_item "$OUTPUT_FILE" "fail" "1.2.6 - Security features for insecure services/protocols" "$insecure_details" "Per PCI DSS requirement 1.2.6, security features must be defined and implemented for all services, protocols, and ports that are in use and considered to be insecure. Implement additional security features or remove insecure services. If insecure services must be used, document business justification and implement additional security features to mitigate risk such as restricting source IPs, implementing TLS, or using encrypted tunnels."
    ((failed_checks++))
fi
((total_checks++))

# Check 1.2.7 - Regular review of NSC configurations
echo -e "\n${BLUE}1.2.7 - Regular review of NSC configurations${NC}"
echo -e "(Manual check) Verify NSC configurations are reviewed at least once every six months"

# Check for AWS Config
config_check=$(aws configservice describe-configuration-recorders --region $REGION 2>/dev/null)
if [ -z "$config_check" ]; then
    echo -e "${RED}AWS Config is not enabled in this region. Cannot automatically verify NSC configuration monitoring.${NC}"
    add_manual_check "$OUTPUT_FILE" "1.2.7 - Regular review of NSC configurations" "<p>AWS Config is not enabled in this region. Cannot automatically verify NSC configuration monitoring.</p><p>Manual verification is required to ensure network security control configurations are reviewed at least once every six months.</p>" "Enable AWS Config to help with automated monitoring of NSC configurations. Implement a process for regular review (at least once every six months) of network security control configurations."
    ((warning_checks++))
    ((manual_checks++))
else
    echo -e "${GREEN}AWS Config is enabled in this region. This can help with monitoring NSC configurations.${NC}"
    
    # Check for specific PCI-related config rules
    pci_rules=$(aws configservice describe-config-rules --region $REGION 2>/dev/null | grep -c "PCI")
    if [ $pci_rules -gt 0 ]; then
        echo -e "${GREEN}PCI-related AWS Config Rules detected.${NC}"
        add_check_item "$OUTPUT_FILE" "pass" "1.2.7 - Regular review of NSC configurations" "<p>AWS Config is enabled in this region, and PCI-related AWS Config Rules are detected.</p><p>This can assist with continuous monitoring of network security control configurations.</p><p>Note: Manual verification is still required to ensure formal reviews occur at least once every six months.</p>"
        ((passed_checks++))
    else
        echo -e "${YELLOW}No PCI-specific AWS Config Rules detected.${NC}"
        add_manual_check "$OUTPUT_FILE" "1.2.7 - Regular review of NSC configurations" "<p>AWS Config is enabled, but no PCI-specific AWS Config Rules were detected.</p><p>Manual verification is required to ensure network security control configurations are reviewed at least once every six months.</p>" "Deploy AWS Config Rules specific to PCI DSS compliance. Implement a process for regular review (at least once every six months) of network security control configurations."
        ((warning_checks++))
        ((manual_checks++))
    fi
fi
((total_checks++))

# Check 1.2.8 - NSC configuration files security
echo -e "\n${BLUE}1.2.8 - NSC configuration files security${NC}"
echo -e "(Manual check) Verify NSC configuration files are secured from unauthorized access"

# Check for overly permissive IAM policies related to network security controls
echo -e "Checking for IAM policies that might allow overly permissive network control modifications..."
overly_permissive=$(aws iam list-policies --scope Local --region $REGION 2>/dev/null | grep -E 'ec2:Authorize|ec2:Create|ec2:Modify' | wc -l)
if [ $overly_permissive -gt 0 ]; then
    echo -e "${YELLOW}Found potential policies with broad network security control permissions.${NC}"
    add_manual_check "$OUTPUT_FILE" "1.2.8 - NSC configuration files security" "<p>Found potential IAM policies with broad network security control permissions.</p><p>In AWS, network security control configurations are protected through IAM permissions.</p><p>Manual verification is required to ensure proper access controls are in place.</p>" "Review IAM policies to ensure least privilege for network security controls. Restrict permissions to modify Security Groups, NACLs, and other network security controls to authorized personnel only."
    ((warning_checks++))
    ((manual_checks++))
else
    echo -e "${GREEN}No obviously overly permissive network security control IAM policies detected.${NC}"
    add_check_item "$OUTPUT_FILE" "pass" "1.2.8 - NSC configuration files security" "<p>No obviously overly permissive network security control IAM policies detected.</p><p>In AWS, network security control configurations are protected through IAM permissions.</p><p>Note: Additional manual verification of IAM permissions is recommended.</p>"
    ((passed_checks++))
fi
((total_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 5: PCI REQUIREMENT 1.3 - CDE NETWORK ACCESS RESTRICTION
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-1.3" "Requirement 1.3: Network access to and from the cardholder data environment is restricted" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 1.3: CDE NETWORK ACCESS RESTRICTION ===${NC}"

# Check 1.3.1 - Inbound traffic to CDE restriction (NACL & Security Groups)
echo -e "\n${BLUE}1.3.1 - Inbound traffic to CDE restriction (NACL & Security Groups)${NC}"
echo -e "Checking for properly restricted inbound traffic to CDE subnets and security groups..."

inbound_details="<p>Analysis of inbound traffic controls for potential CDE subnets:</p>"

overall_warning=false

# --- Part 1: NACL Checks ---
inbound_details+="<h4>NACL Rules</h4><ul>"

for vpc_id in $TARGET_VPCS; do
    inbound_details+="<li>VPC: $vpc_id</li><ul>"
    
    subnets=$(aws ec2 describe-subnets --region $REGION --filters "Name=vpc-id,Values=$vpc_id" --query 'Subnets[*].SubnetId' --output text 2>/dev/null)
    
    for subnet_id in $subnets; do
        inbound_details+="<li>Subnet: $subnet_id</li><ul>"
        
        nacl_id=$(aws ec2 describe-network-acls --region $REGION --filters "Name=association.subnet-id,Values=$subnet_id" --query 'NetworkAcls[0].NetworkAclId' --output text 2>/dev/null)
        
        if [ -z "$nacl_id" ] || [ "$nacl_id" == "None" ]; then
            inbound_details+="<li class=\"yellow\">No NACL associated with this subnet</li>"
            overall_warning=true
            continue
        fi
        
        inbound_details+="<li>Associated NACL: $nacl_id</li>"
        
        permissive_rules=$(aws ec2 describe-network-acls --region $REGION --network-acl-ids $nacl_id --query 'NetworkAcls[0].Entries[?Egress==`false` && CidrBlock==`0.0.0.0/0` && RuleAction==`allow`]' --output text 2>/dev/null)
        
        if [ -n "$permissive_rules" ]; then
            inbound_details+="<li class=\"red\">WARNING: NACL has permissive inbound rules (0.0.0.0/0 allow)</li>"
            inbound_details+="<li><pre>$permissive_rules</pre></li>"
            overall_warning=true
        else
            inbound_details+="<li class=\"green\">NACL has properly restricted inbound rules</li>"
        fi
        
        inbound_details+="</ul>"
    done
    
    inbound_details+="</ul>"
done

inbound_details+="</ul>"

# --- Part 2: Security Group Checks ---
inbound_details+="<h4>Security Group Rules</h4><ul>"

for vpc_id in $TARGET_VPCS; do
    inbound_details+="<li>VPC: $vpc_id</li><ul>"
    
    sg_list=$(aws ec2 describe-security-groups --region $REGION --filters "Name=vpc-id,Values=$vpc_id" --query 'SecurityGroups[*].GroupId' --output text 2>/dev/null)
    
    if [ -z "$sg_list" ]; then
        inbound_details+="<li class=\"yellow\">No Security Groups found in this VPC</li>"
        continue
    fi
    
    for sg_id in $sg_list; do
        sg_details=$(aws ec2 describe-security-groups --region $REGION --group-ids $sg_id --output json 2>/dev/null)
        sg_name=$(echo "$sg_details" | jq -r '.SecurityGroups[0].GroupName')
        
        inbound_details+="<li>Security Group: $sg_id ($sg_name)</li><ul>"
        
        # Count and list public inbound rules
        public_inbound=$(echo "$sg_details" | jq '[.SecurityGroups[].IpPermissions[] | select(.IpRanges[].CidrIp=="0.0.0.0/0")] | length')
        if [ "$public_inbound" -gt 0 ]; then
            inbound_details+="<li class=\"red\">WARNING: $public_inbound public inbound rules (0.0.0.0/0)</li>"
            
            # Get detailed rule info (Protocol, Ports)
            public_rules=$(echo "$sg_details" | jq -r '.SecurityGroups[].IpPermissions[] 
                | select(.IpRanges[].CidrIp=="0.0.0.0/0") 
                | "Protocol: \(.IpProtocol) | FromPort: \(.FromPort // "all") | ToPort: \(.ToPort // "all")"' 2>/dev/null)
            
            [ -z "$public_rules" ] && public_rules="(No detailed rule data)"
            inbound_details+="<li><pre>$public_rules</pre></li>"
            overall_warning=true
        else
            inbound_details+="<li class=\"green\">No public inbound rules (0.0.0.0/0)</li>"
        fi
        
        inbound_details+="</ul>"
    done
    
    inbound_details+="</ul>"
done

inbound_details+="</ul><p class=\"yellow\">NOTE: A complete assessment requires identifying all CDE subnets, Security Groups, and analyzing detailed traffic flows.</p>"

# --- Finalize result ---
if [ "$overall_warning" = true ]; then
    add_check_item "$OUTPUT_FILE" "warning" "1.3.1 - Inbound traffic to CDE restriction (NACL & Security Groups)" "$inbound_details" "Review NACL and Security Group rules. Restrict any rules allowing 0.0.0.0/0 unless explicitly required and documented. Ensure inbound traffic to the CDE is limited to only necessary, secure sources."
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "pass" "1.3.1 - Inbound traffic to CDE restriction (NACL & Security Groups)" "$inbound_details" "All examined NACLs and Security Groups have properly restricted inbound rules. No public (0.0.0.0/0) access detected."
    ((passed_checks++))
fi

((total_checks++))



# Check 1.3.2 - Outbound traffic from CDE restriction (NACL & Security Groups)
echo -e "\n${BLUE}1.3.2 - Outbound traffic from CDE restriction (NACL & Security Groups)${NC}"
echo -e "Checking for properly restricted outbound traffic from CDE subnets and security groups..."

outbound_details="<p>Analysis of outbound traffic controls for potential CDE subnets:</p>"

overall_warning=false

# --- Part 1: NACL Outbound Checks ---
outbound_details+="<h4>NACL Rules</h4><ul>"

for vpc_id in $TARGET_VPCS; do
    outbound_details+="<li>VPC: $vpc_id</li><ul>"
    
    subnets=$(aws ec2 describe-subnets --region $REGION --filters "Name=vpc-id,Values=$vpc_id" --query 'Subnets[*].SubnetId' --output text 2>/dev/null)
    
    for subnet_id in $subnets; do
        outbound_details+="<li>Subnet: $subnet_id</li><ul>"
        
        nacl_id=$(aws ec2 describe-network-acls --region $REGION --filters "Name=association.subnet-id,Values=$subnet_id" --query 'NetworkAcls[0].NetworkAclId' --output text 2>/dev/null)
        
        if [ -z "$nacl_id" ] || [ "$nacl_id" == "None" ]; then
            outbound_details+="<li class=\"yellow\">No NACL associated with this subnet</li>"
            overall_warning=true
            continue
        fi
        
        outbound_details+="<li>Associated NACL: $nacl_id</li>"
        
        permissive_rules=$(aws ec2 describe-network-acls --region $REGION --network-acl-ids $nacl_id --query 'NetworkAcls[0].Entries[?Egress==`true` && CidrBlock==`0.0.0.0/0` && RuleAction==`allow`]' --output text 2>/dev/null)
        
        if [ -n "$permissive_rules" ]; then
            outbound_details+="<li class=\"red\">WARNING: NACL has permissive outbound rules (0.0.0.0/0 allow)</li>"
            outbound_details+="<li><pre>$permissive_rules</pre></li>"
            overall_warning=true
        else
            outbound_details+="<li class=\"green\">NACL has properly restricted outbound rules</li>"
        fi
        
        outbound_details+="</ul>"
    done
    
    outbound_details+="</ul>"
done

outbound_details+="</ul>"

# --- Part 2: Security Group Outbound Checks ---
outbound_details+="<h4>Security Group Rules</h4><ul>"

for vpc_id in $TARGET_VPCS; do
    outbound_details+="<li>VPC: $vpc_id</li><ul>"
    
    sg_list=$(aws ec2 describe-security-groups --region $REGION --filters "Name=vpc-id,Values=$vpc_id" --query 'SecurityGroups[*].GroupId' --output text 2>/dev/null)
    
    if [ -z "$sg_list" ]; then
        outbound_details+="<li class=\"yellow\">No Security Groups found in this VPC</li>"
        continue
    fi
    
    for sg_id in $sg_list; do
        sg_details=$(aws ec2 describe-security-groups --region $REGION --group-ids $sg_id --output json 2>/dev/null)
        sg_name=$(echo "$sg_details" | jq -r '.SecurityGroups[0].GroupName')
        
        outbound_details+="<li>Security Group: $sg_id ($sg_name)</li><ul>"
        
        # Count and list public outbound rules
        public_outbound=$(echo "$sg_details" | jq '[.SecurityGroups[].IpPermissionsEgress[] | select(.IpRanges[].CidrIp=="0.0.0.0/0")] | length')
        if [ "$public_outbound" -gt 0 ]; then
            outbound_details+="<li class=\"red\">WARNING: $public_outbound public outbound rules (0.0.0.0/0)</li>"
            
            # Get detailed rule info (Protocol, Ports)
            outbound_rules=$(echo "$sg_details" | jq -r '.SecurityGroups[].IpPermissionsEgress[] 
                | select(.IpRanges[].CidrIp=="0.0.0.0/0") 
                | "Protocol: \(.IpProtocol) | FromPort: \(.FromPort // "all") | ToPort: \(.ToPort // "all")"' 2>/dev/null)
            
            [ -z "$outbound_rules" ] && outbound_rules="(No detailed rule data)"
            outbound_details+="<li><pre>$outbound_rules</pre></li>"
            overall_warning=true
        else
            outbound_details+="<li class=\"green\">No public outbound rules (0.0.0.0/0)</li>"
        fi
        
        outbound_details+="</ul>"
    done
    
    outbound_details+="</ul>"
done

outbound_details+="</ul><p class=\"yellow\">NOTE: Verify all outbound connections from the CDE are restricted to authorized destinations only.</p>"

# --- Finalize result ---
if [ "$overall_warning" = true ]; then
    add_check_item "$OUTPUT_FILE" "warning" "1.3.2 - Outbound traffic from CDE restriction (NACL & Security Groups)" "$outbound_details" "Review NACL and Security Group outbound rules. Restrict any rules allowing 0.0.0.0/0 unless explicitly required and documented. Outbound traffic from the CDE must be limited to known, secure destinations."
    ((warning_checks++))
else
    add_check_item "$OUTPUT_FILE" "pass" "1.3.2 - Outbound traffic from CDE restriction (NACL & Security Groups)" "$outbound_details" "All examined NACLs and Security Groups have properly restricted outbound rules. No public (0.0.0.0/0) access detected."
    ((passed_checks++))
fi

((total_checks++))


# Check 1.3.3 - Wireless networks and CDE
echo -e "\n${BLUE}1.3.3 - Wireless networks and CDE${NC}"
echo -e "(Manual check) Verify NSCs are installed between wireless networks and the CDE"

wireless_details="<p>AWS Client VPN and Direct Connect assessment:</p>"

# Check for AWS Client VPN
vpn_check=$(aws ec2 describe-client-vpn-endpoints --region $REGION 2>/dev/null)
if [ -n "$vpn_check" ]; then
    echo -e "${YELLOW}AWS Client VPN endpoints detected. Verify proper security controls between VPN and CDE.${NC}"
    wireless_details+="<p class=\"yellow\">AWS Client VPN endpoints detected. Verify proper security controls between VPN and CDE.</p>"
    
    # Check for VPN security groups
    vpn_sg=$(echo "$vpn_check" | grep "SecurityGroupIds" | wc -l)
    if [ $vpn_sg -gt 0 ]; then
        echo -e "${GREEN}Security groups detected for VPN connections.${NC}"
        wireless_details+="<p class=\"green\">Security groups detected for VPN connections.</p>"
    else
        echo -e "${RED}No security groups detected for VPN connections.${NC}"
        wireless_details+="<p class=\"red\">No security groups detected for VPN connections.</p>"
    fi
    
    # Check for VPN logging
    vpn_logs=$(echo "$vpn_check" | grep "ConnectionLogOptions" | grep "Enabled" | grep "true" | wc -l)
    if [ $vpn_logs -gt 0 ]; then
        echo -e "${GREEN}VPN connection logging is enabled.${NC}"
        wireless_details+="<p class=\"green\">VPN connection logging is enabled.</p>"
    else
        echo -e "${RED}VPN connection logging may not be enabled.${NC}"
        wireless_details+="<p class=\"red\">VPN connection logging may not be enabled.</p>"
    fi
else
    echo -e "${GREEN}No AWS Client VPN endpoints detected.${NC}"
    wireless_details+="<p class=\"green\">No AWS Client VPN endpoints detected.</p>"
fi

wireless_details+="<p class=\"yellow\">NOTE: This requirement primarily applies to on-premises environments but consider AWS Client VPN and Direct Connect connections to your AWS environment</p>"

add_check_item "$OUTPUT_FILE" "warning" "1.3.3 - Wireless networks and CDE" "$wireless_details" "Ensure proper security controls are in place between any wireless networks and the CDE. If using AWS Client VPN or Direct Connect, verify proper security controls, including security groups and logging."
((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 6: PCI REQUIREMENT 1.4 - NETWORK CONNECTIONS BETWEEN TRUSTED/UNTRUSTED NETWORKS
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-1.4" "Requirement 1.4: Network Connections Between Trusted/Untrusted Networks" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 1.4: NETWORK CONNECTIONS BETWEEN TRUSTED/UNTRUSTED NETWORKS ===${NC}"

# Check 1.4.1 - NSCs between trusted and untrusted networks
echo -e "\n${BLUE}1.4.1 - NSCs between trusted and untrusted networks${NC}"
echo -e "Checking for NSCs between trusted and untrusted networks..."

network_connections_details="<p>Analysis of connections between trusted and untrusted networks:</p><ul>"

for vpc_id in $TARGET_VPCS; do
    network_connections_details+="<li>VPC: $vpc_id</li><ul>"
    
    # Check for Internet Gateways (untrusted connection)
    igw=$(aws ec2 describe-internet-gateways --region $REGION --filters "Name=attachment.vpc-id,Values=$vpc_id" --query 'InternetGateways[*].InternetGatewayId' --output text 2>/dev/null)
    
    if [ -n "$igw" ]; then
        echo -e "\nInternet Gateway detected for VPC $vpc_id: $igw"
        network_connections_details+="<li>Internet Gateway detected: $igw</li>"
        
        # Check for proper security groups for instances with public IPs
        public_instances=$(aws ec2 describe-instances --region $REGION --filters "Name=vpc-id,Values=$vpc_id" "Name=network-interface.association.public-ip,Values=*" --query 'Reservations[*].Instances[*].InstanceId' --output text 2>/dev/null)
        
        if [ -n "$public_instances" ]; then
            echo -e "${YELLOW}Found instances with public IPs in VPC $vpc_id:${NC}"
            network_connections_details+="<li class=\"yellow\">Found instances with public IPs:</li><ul>"
            
            for instance in $public_instances; do
                echo -e "Instance ID: $instance"
                network_connections_details+="<li>Instance ID: $instance</li>"
                
                instance_sg=$(aws ec2 describe-instances --region $REGION --instance-ids $instance --query 'Reservations[*].Instances[*].SecurityGroups[*].GroupId' --output text 2>/dev/null)
                
                echo -e "Security Groups: $instance_sg"
                network_connections_details+="<li>Security Groups: $instance_sg</li><ul>"
                
                # Check if security groups have restrictive inbound rules
                for sg in $instance_sg; do
                    open_ports=$(aws ec2 describe-security-groups --region $REGION --group-ids $sg --query 'SecurityGroups[*].IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]' --output text | wc -l)
                    
                    if [ $open_ports -gt 0 ]; then
                        echo -e "${RED}WARNING: Security group $sg has open ports to the internet (0.0.0.0/0)${NC}"
                        network_connections_details+="<li class=\"red\">WARNING: Security group $sg has open ports to the internet (0.0.0.0/0)</li>"
                    else
                        echo -e "${GREEN}Security group $sg has properly restricted inbound rules${NC}"
                        network_connections_details+="<li class=\"green\">Security group $sg has properly restricted inbound rules</li>"
                    fi
                done
                
                network_connections_details+="</ul>"
            done
            
            network_connections_details+="</ul>"
        else
            echo -e "${GREEN}No instances with public IPs found in VPC $vpc_id${NC}"
            network_connections_details+="<li class=\"green\">No instances with public IPs found</li>"
        fi
    else
        echo -e "\nNo Internet Gateway detected for VPC $vpc_id - isolation from untrusted networks appears maintained"
        network_connections_details+="<li class=\"green\">No Internet Gateway detected - isolation from untrusted networks appears maintained</li>"
    fi
    
    # Check for VPC Peering connections (potential trusted/untrusted boundary)
    peering=$(aws ec2 describe-vpc-peering-connections --region $REGION --filters "Name=requester-vpc-info.vpc-id,Values=$vpc_id" --query 'VpcPeeringConnections[*].VpcPeeringConnectionId' --output text 2>/dev/null)
    
    if [ -n "$peering" ]; then
        echo -e "\nVPC Peering connections detected for VPC $vpc_id:"
        network_connections_details+="<li class=\"yellow\">VPC Peering connections detected:</li><ul>"
        
        for peer in $peering; do
            network_connections_details+="<li>$peer</li>"
        done
        
        network_connections_details+="</ul>"
        
        echo -e "${YELLOW}Recommendation: Verify proper security controls between peered VPCs${NC}"
    else
        network_connections_details+="<li>No VPC Peering connections detected</li>"
    fi
    
    # Check for Transit Gateways (potential trusted/untrusted boundary)
    tgw_check=$(aws ec2 describe-transit-gateway-attachments --region $REGION --filters "Name=resource-id,Values=$vpc_id" --query 'TransitGatewayAttachments[*].TransitGatewayId' --output text 2>/dev/null)
    
    if [ -n "$tgw_check" ]; then
        echo -e "\nTransit Gateway connections detected for VPC $vpc_id:"
        network_connections_details+="<li class=\"yellow\">Transit Gateway connections detected:</li><ul>"
        
        for tgw in $tgw_check; do
            network_connections_details+="<li>$tgw</li>"
        done
        
        network_connections_details+="</ul>"
        
        echo -e "${YELLOW}Recommendation: Verify proper security controls for Transit Gateway routing${NC}"
    else
        network_connections_details+="<li>No Transit Gateway connections detected</li>"
    fi
    
    network_connections_details+="</ul>"
done

network_connections_details+="</ul><p class=\"yellow\">NOTE: A complete assessment requires understanding of which networks are trusted vs. untrusted</p>"

add_check_item "$OUTPUT_FILE" "info" "1.4.1 - NSCs between trusted and untrusted networks" "$network_connections_details" "Ensure proper network security controls are implemented between trusted and untrusted networks. Identify and classify all networks as trusted or untrusted, and verify appropriate security controls at boundaries."
((total_checks++))
((warning_checks++))

# Check 1.4.2 - Inbound traffic from untrusted networks
echo -e "\n${BLUE}1.4.2 - Inbound traffic from untrusted networks${NC}"
echo -e "Checking for restrictions on inbound traffic from untrusted networks..."

inbound_untrusted_details="<p>Analysis of inbound traffic from untrusted networks:</p><ul>"

for vpc_id in $TARGET_VPCS; do
    inbound_untrusted_details+="<li>VPC: $vpc_id</li><ul>"
    
    # Check for public-facing resources (Load Balancers)
    elbs=$(aws elbv2 describe-load-balancers --region $REGION --query 'LoadBalancers[?VpcId==`'$vpc_id'`].LoadBalancerArn' --output text 2>/dev/null)
    
    if [ -n "$elbs" ]; then
        echo -e "\nPublic-facing Load Balancers detected in VPC $vpc_id:"
        inbound_untrusted_details+="<li>Public-facing Load Balancers detected:</li><ul>"
        
        for elb in $elbs; do
            elb_name=$(aws elbv2 describe-load-balancers --region $REGION --load-balancer-arns $elb --query 'LoadBalancers[0].LoadBalancerName' --output text 2>/dev/null)
            elb_type=$(aws elbv2 describe-load-balancers --region $REGION --load-balancer-arns $elb --query 'LoadBalancers[0].Scheme' --output text 2>/dev/null)
            
            echo -e "Load Balancer: $elb_name (Type: $elb_type)"
            inbound_untrusted_details+="<li>Load Balancer: $elb_name (Type: $elb_type)</li>"
            
            if [ "$elb_type" == "internet-facing" ]; then
                # Check for security groups
                elb_sg=$(aws elbv2 describe-load-balancers --region $REGION --load-balancer-arns $elb --query 'LoadBalancers[0].SecurityGroups' --output text 2>/dev/null)
                
                echo -e "Security Groups: $elb_sg"
                inbound_untrusted_details+="<li>Security Groups: $elb_sg</li>"
                
                # Check if a WAF is associated
                waf_check=$(aws wafv2 list-resources-for-web-acl --region $REGION --resource-type APPLICATION_LOAD_BALANCER --web-acl-arn "arn:aws:wafv2:$REGION:$(aws sts get-caller-identity --query 'Account' --output text):*" 2>/dev/null | grep -c "$elb")
                
                if [ $waf_check -gt 0 ]; then
                    echo -e "${GREEN}WAF is associated with this load balancer${NC}"
                    inbound_untrusted_details+="<li class=\"green\">WAF is associated with this load balancer</li>"
                else
                    echo -e "${YELLOW}No WAF detected for this internet-facing load balancer${NC}"
                    inbound_untrusted_details+="<li class=\"yellow\">No WAF detected for this internet-facing load balancer</li>"
                fi
            fi
        done
        
        inbound_untrusted_details+="</ul>"
    else
        echo -e "\nNo Load Balancers detected in VPC $vpc_id"
        inbound_untrusted_details+="<li>No Load Balancers detected</li>"
    fi
    
    inbound_untrusted_details+="</ul>"
done

inbound_untrusted_details+="</ul><p class=\"yellow\">NOTE: A complete assessment requires detailed analysis of all public endpoints</p>"

add_check_item "$OUTPUT_FILE" "warning" "1.4.2 - Inbound traffic from untrusted networks" "$inbound_untrusted_details" "Restrict inbound traffic from untrusted networks to only communications with authorized publicly accessible system components. Consider using AWS WAF for additional protection of internet-facing load balancers."
((total_checks++))
((warning_checks++))

# Check 1.4.3 - Anti-spoofing measures
echo -e "\n${BLUE}1.4.3 - Anti-spoofing measures${NC}"
echo -e "Checking for anti-spoofing measures..."

antispoofing_details="<p>AWS VPC provides anti-spoofing by default through source/destination checks on EC2 instances.</p>"
antispoofing_details+="<p>Analysis of source/destination checks on EC2 instances:</p><ul>"

disabled_checks_total=0

for vpc_id in $TARGET_VPCS; do
    antispoofing_details+="<li>VPC: $vpc_id</li>"
    
    instances=$(aws ec2 describe-instances --region $REGION --filters "Name=vpc-id,Values=$vpc_id" --query 'Reservations[*].Instances[*].InstanceId' --output text 2>/dev/null)
    
    if [ -z "$instances" ]; then
        echo -e "No instances found in VPC $vpc_id"
        antispoofing_details+="<ul><li>No instances found</li></ul>"
        continue
    fi
    
    disabled_checks=0
    antispoofing_details+="<ul>"
    
    for instance in $instances; do
        src_dst_check=$(aws ec2 describe-instances --region $REGION --instance-ids $instance --query 'Reservations[*].Instances[*].SourceDestCheck' --output text 2>/dev/null)
        
        if [ "$src_dst_check" == "False" ]; then
            echo -e "${YELLOW}WARNING: Instance $instance has source/destination check disabled${NC}"
            antispoofing_details+="<li class=\"yellow\">Instance $instance has source/destination check disabled</li>"
            disabled_checks=$((disabled_checks+1))
            disabled_checks_total=$((disabled_checks_total+1))
        fi
    done
    
    if [ $disabled_checks -eq 0 ]; then
        echo -e "${GREEN}All instances in VPC $vpc_id have source/destination checks enabled${NC}"
        antispoofing_details+="<li class=\"green\">All instances have source/destination checks enabled</li>"
    else
        echo -e "${YELLOW}$disabled_checks instances in VPC $vpc_id have source/destination checks disabled${NC}"
        antispoofing_details+="<li class=\"yellow\">$disabled_checks instances have source/destination checks disabled</li>"
    fi
    
    antispoofing_details+="</ul>"
done

antispoofing_details+="</ul>"

if [ $disabled_checks_total -eq 0 ]; then
    add_check_item "$OUTPUT_FILE" "pass" "1.4.3 - Anti-spoofing measures" "$antispoofing_details"
    ((passed_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "1.4.3 - Anti-spoofing measures" "$antispoofing_details" "Verify instances with disabled source/destination checks require this configuration (typically only needed for NAT, VPN, or load balancing instances). Ensure proper anti-spoofing measures are in place."
    ((warning_checks++))
fi
((total_checks++))

# Check 1.4.4 - CHD system components not directly accessible from untrusted networks
echo -e "\n${BLUE}1.4.4 - CHD system components not directly accessible from untrusted networks${NC}"
echo -e "Checking for CHD systems directly accessible from untrusted networks..."

chd_accessibility_details="<p>Analysis of potential direct access to CHD systems from untrusted networks:</p><ul>"

has_public_rds=false

for vpc_id in $TARGET_VPCS; do
    chd_accessibility_details+="<li>VPC: $vpc_id</li><ul>"
    
    # Check for instances with public IPs (simplified check - actual check should identify CHD systems)
    public_instances=$(aws ec2 describe-instances --region $REGION --filters "Name=vpc-id,Values=$vpc_id" "Name=network-interface.association.public-ip,Values=*" --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,Tags[?Key==`Name`].Value|[0]]' --output text 2>/dev/null)
    
    if [ -n "$public_instances" ]; then
        echo -e "${YELLOW}WARNING: Instances with public IPs found in VPC $vpc_id:${NC}"
        public_instance_count=$(echo "$public_instances" | wc -l)
        chd_accessibility_details+="<li class=\"yellow\">WARNING: $public_instance_count instances with public IPs found:</li><ul>"
        
        # Format the instances with better detail
        while IFS=$'\t' read -r instance_id instance_type instance_name; do
            if [ -z "$instance_name" ]; then
                instance_name="(No Name)"
            fi
            
            # Get the public IP for better reporting
            public_ip=$(aws ec2 describe-instances --region $REGION --instance-ids $instance_id --query 'Reservations[*].Instances[*].PublicIpAddress' --output text 2>/dev/null)
            
            chd_accessibility_details+="<li>Instance: $instance_id ($instance_name) - Type: $instance_type - Public IP: $public_ip</li>"
            echo -e "Instance: $instance_id ($instance_name) - Type: $instance_type - Public IP: $public_ip"
        done <<< "$public_instances"
        
        chd_accessibility_details+="</ul>"
    else
        echo -e "${GREEN}No instances with public IPs found in VPC $vpc_id${NC}"
        chd_accessibility_details+="<li class=\"green\">No instances with public IPs found</li>"
    fi
    
    # Check for RDS instances with public accessibility
    public_rds=$(aws rds describe-db-instances --region $REGION --filters "Name=vpc-id,Values=$vpc_id" --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier,Engine,EngineVersion]' --output text 2>/dev/null)
    
    if [ -n "$public_rds" ]; then
        echo -e "${RED}WARNING: Publicly accessible RDS instances found in VPC $vpc_id:${NC}"
        public_rds_count=$(echo "$public_rds" | wc -l)
        chd_accessibility_details+="<li class=\"red\">WARNING: $public_rds_count publicly accessible RDS instances found:</li><ul>"
        
        # Format the RDS instances with better detail
        while IFS=$'\t' read -r db_id engine version; do
            chd_accessibility_details+="<li>RDS Instance: $db_id - Engine: $engine $version</li>"
            echo -e "RDS Instance: $db_id - Engine: $engine $version"
        done <<< "$public_rds"
        
        chd_accessibility_details+="</ul>"
        has_public_rds=true
    else
        echo -e "${GREEN}No publicly accessible RDS instances found in VPC $vpc_id${NC}"
        chd_accessibility_details+="<li class=\"green\">No publicly accessible RDS instances found</li>"
    fi
    
    # Also check ElastiCache clusters which could store sensitive data
    elasticache_clusters=$(aws elasticache describe-cache-clusters --region $REGION --query 'CacheClusters[?VpcId==`'$vpc_id'`].[CacheClusterId]' --output text 2>/dev/null)
    if [ -n "$elasticache_clusters" ]; then
        chd_accessibility_details+="<li>ElastiCache clusters (verify these are not publicly accessible):</li><ul>"
        for cluster in $elasticache_clusters; do
            chd_accessibility_details+="<li>$cluster</li>"
        done
        chd_accessibility_details+="</ul>"
    fi
    
    chd_accessibility_details+="</ul>"
done

chd_accessibility_details+="</ul><p>According to PCI DSS requirement 1.4.4, system components that store cardholder data must not be directly accessible from untrusted networks such as the Internet.</p>"

if [ "$has_public_rds" = true ]; then
    add_check_item "$OUTPUT_FILE" "fail" "1.4.4 - CHD system components not directly accessible from untrusted networks" "$chd_accessibility_details" "CRITICAL: Publicly accessible database instances could expose cardholder data if they contain it. Verify none of these publicly accessible resources store cardholder data. If they do, immediately reconfigure them to not be publicly accessible. System components that store cardholder data must not be directly accessible from untrusted networks."
    ((failed_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "1.4.4 - CHD system components not directly accessible from untrusted networks" "$chd_accessibility_details" "Verify none of the instances with public IPs store cardholder data. If they do, implement security controls to ensure they are not directly accessible from untrusted networks, such as using a WAF, VPN, or jump box architecture."
    ((warning_checks++))
fi
((total_checks++))

# Check 1.4.5 - Disclosure of internal IP addresses and routing information
echo -e "\n${BLUE}1.4.5 - Disclosure of internal IP addresses and routing information${NC}"
echo -e "Checking for potential disclosure of internal IP addresses..."

ip_disclosure_details="<p>Analysis of potential internal IP address disclosure:</p><ul>"

# Check public load balancers for internal IP disclosure
elbs=$(aws elbv2 describe-load-balancers --region $REGION --query 'LoadBalancers[?Scheme==`internet-facing`].LoadBalancerArn' --output text 2>/dev/null)

if [ -n "$elbs" ]; then
    echo -e "${YELLOW}Checking internet-facing Load Balancers for potential IP disclosure:${NC}"
    ip_disclosure_details+="<li class=\"yellow\">Internet-facing Load Balancers detected (potential IP disclosure risk):</li><ul>"
    
    for elb in $elbs; do
        elb_name=$(aws elbv2 describe-load-balancers --region $REGION --load-balancer-arns $elb --query 'LoadBalancers[0].LoadBalancerName' --output text 2>/dev/null)
        
        echo -e "Load Balancer: $elb_name"
        ip_disclosure_details+="<li>$elb_name</li>"
    done
    
    ip_disclosure_details+="</ul><li class=\"yellow\">Recommendation: Verify that proper response headers are configured to prevent IP disclosure</li>"
else
    ip_disclosure_details+="<li class=\"green\">No internet-facing Load Balancers detected</li>"
fi

# Check for public S3 buckets that might contain network information
s3_buckets=$(aws s3api list-buckets --query 'Buckets[*].Name' --output text 2>/dev/null)

if [ -n "$s3_buckets" ]; then
    public_buckets_found=false
    public_buckets_list="<ul>"
    
    for bucket in $s3_buckets; do
        bucket_acl=$(aws s3api get-bucket-acl --bucket $bucket 2>/dev/null | grep -c "AllUsers")
        
        if [ $bucket_acl -gt 0 ]; then
            echo -e "${YELLOW}Public S3 bucket detected: $bucket${NC}"
            public_buckets_list+="<li>$bucket</li>"
            public_buckets_found=true
        fi
    done
    
    public_buckets_list+="</ul>"
    
    if [ "$public_buckets_found" = true ]; then
        ip_disclosure_details+="<li class=\"yellow\">Public S3 buckets detected (potential risk if they contain network information):$public_buckets_list</li>"
    else
        ip_disclosure_details+="<li class=\"green\">No public S3 buckets detected</li>"
    fi
else
    ip_disclosure_details+="<li>No S3 buckets found or insufficient permissions to check</li>"
fi

ip_disclosure_details+="</ul><p class=\"yellow\">NOTE: A complete assessment requires checking for IP disclosure in application responses</p>"

add_manual_check "$OUTPUT_FILE" "1.4.5 - Disclosure of internal IP addresses and routing information" "$ip_disclosure_details" "Limit disclosure of internal IP addresses and routing information to only authorized parties. Verify application responses do not contain internal IP addresses and routing information."
((total_checks++))
((warning_checks++))
((manual_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 7: PCI REQUIREMENT 1.5 - CDE RISK MITIGATION
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-1.5" "Requirement 1.5: CDE Risk Mitigation" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 1.5: CDE RISK MITIGATION ===${NC}"

# Check 1.5.1 - Security controls for computing devices that connect to both untrusted networks and the CDE
echo -e "\n${BLUE}1.5.1 - Security controls for computing devices connecting to both untrusted networks and the CDE${NC}"
echo -e "(Manual check) Verify security controls for computing devices that connect to both untrusted networks and the CDE"

cde_risk_details="<p>Analysis of computing devices that may connect to both untrusted networks and the CDE:</p><ul>"

for vpc_id in $TARGET_VPCS; do
    cde_risk_details+="<li>VPC: $vpc_id</li>"
    
    # Check if the VPC has an internet gateway (path to untrusted network)
    igw=$(aws ec2 describe-internet-gateways --region $REGION --filters "Name=attachment.vpc-id,Values=$vpc_id" --query 'InternetGateways[*].InternetGatewayId' --output text 2>/dev/null)
    
    if [ -n "$igw" ]; then
        echo -e "\nVPC $vpc_id has internet connectivity through gateway: $igw"
        cde_risk_details+="<ul><li class=\"yellow\">VPC has internet connectivity through gateway: $igw</li>"
        
        # Check instances in the VPC
        instances=$(aws ec2 describe-instances --region $REGION --filters "Name=vpc-id,Values=$vpc_id" --query 'Reservations[*].Instances[*].[InstanceId,Tags[?Key==`Name`].Value]' --output text 2>/dev/null)
        
        if [ -n "$instances" ]; then
            echo -e "${YELLOW}Instances in this VPC may have connectivity to both CDE and untrusted networks:${NC}"
            cde_risk_details+="<li class=\"yellow\">Instances in this VPC may have connectivity to both CDE and untrusted networks</li>"
            cde_risk_details+="<li>Instances: $instances</li>"
            
            # Check if instances have security agents (Systems Manager)
            ssm_check=$(aws ssm describe-instance-information --region $REGION --filters "Name=InstanceIds,Values=$instances" 2>/dev/null | grep -c "InstanceId")
            
            if [ $ssm_check -gt 0 ]; then
                echo -e "${GREEN}Some instances have Systems Manager agent installed, which can help with security controls${NC}"
                cde_risk_details+="<li class=\"green\">Some instances have Systems Manager agent installed, which can help with security controls</li>"
            else
                echo -e "${YELLOW}No evidence of Systems Manager agent found for these instances${NC}"
                cde_risk_details+="<li class=\"yellow\">No evidence of Systems Manager agent found for these instances</li>"
            fi
        else
            cde_risk_details+="<li>No instances found in this VPC</li>"
        fi
        
        cde_risk_details+="</ul>"
    else
        echo -e "\nVPC $vpc_id does not have direct internet connectivity"
        cde_risk_details+="<ul><li class=\"green\">VPC does not have direct internet connectivity</li></ul>"
    fi
done

cde_risk_details+="</ul><p class=\"yellow\">NOTE: A complete assessment requires identifying all devices that connect to both the CDE and untrusted networks</p>"

add_manual_check "$OUTPUT_FILE" "1.5.1 - Security controls for computing devices connecting to both untrusted networks and the CDE" "$cde_risk_details" "Implement security controls on computing devices that connect to both untrusted networks and the CDE. Consider using AWS Systems Manager, Inspector, or GuardDuty for additional security."
((total_checks++))
((warning_checks++))
((manual_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# FINALIZE THE REPORT
#----------------------------------------------------------------------

# Adjust final counts for the report
effective_total_checks=$((total_checks))
effective_failed_checks=$((failed_checks - access_denied_checks))
effective_warning_checks=$((warning_checks - manual_checks))

# Calculate compliance percentage excluding both access denied failures and manual check warnings
countable_checks=$((effective_total_checks - access_denied_checks - manual_checks))
if [ $countable_checks -gt 0 ]; then
    compliance_percentage=$(( (passed_checks * 100) / countable_checks ))
else
    compliance_percentage=0
fi

finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$effective_failed_checks" "$effective_warning_checks" "$REQUIREMENT_NUMBER" "$access_denied_checks"

echo -e "\n${CYAN}=== SUMMARY OF PCI DSS REQUIREMENT 1 CHECKS ===${NC}"

echo -e "\nTotal checks performed: $total_checks"
echo -e "Passed checks: $passed_checks"
echo -e "Failed checks (total): $failed_checks"
echo -e "Failed checks (excluding access denied): $effective_failed_checks"
echo -e "Access denied errors: $access_denied_checks"
echo -e "Warning checks (total): $warning_checks"
echo -e "Manual check warnings: $manual_checks"
echo -e "Compliance percentage (excluding access denied and manual checks): $compliance_percentage%"

echo -e "\nPCI DSS Requirement 1 assessment completed at $(date)"
echo -e "HTML Report saved to: $OUTPUT_FILE"

# Open the HTML report in the default browser if on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$OUTPUT_FILE" 2>/dev/null || echo "Could not automatically open the report. Please open it manually."
else
    echo "Please open the HTML report in your web browser to view detailed results."
fi