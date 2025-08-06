#!/bin/bash

# PCI DSS Requirement 11 Compliance Check Script for AWS
# This script evaluates AWS controls for PCI DSS Requirement 11 compliance
# Requirements covered: 11.1 - 11.6 - Testing Security of Systems and Networks Regularly

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
REQUIREMENT_NUMBER="11"
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


# Ask for specific resources to assess (VPCs for network testing)
if [ -z "$TARGET_VPCS" ]; then
    read -p "Enter VPC IDs to assess (comma-separated or 'all' for all): " TARGET_VPCS
    if [ -z "$TARGET_VPCS" ] || [ "$TARGET_VPCS" == "all" ]; then
        TARGET_VPCS="all"
        echo -e "${YELLOW}Checking all VPCs${NC}"
    else
        echo -e "${YELLOW}Checking specific VPC(s): $TARGET_VPCS${NC}"
    fi
else
    echo -e "${YELLOW}Using provided TARGET_VPCS: $TARGET_VPCS${NC}"
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

# Permission checks relevant to Requirement 11
check_command_access "$OUTPUT_FILE" "ec2" "describe-vpcs" "$REGION"
ret=$?; ((total_checks++))
[ $ret -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "ec2" "describe-security-groups" "$REGION"
ret=$?; ((total_checks++))
[ $ret -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "ec2" "describe-instances" "$REGION"
ret=$?; ((total_checks++))
[ $ret -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "guardduty" "list-detectors" "$REGION"
ret=$?; ((total_checks++))
[ $ret -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "inspector2" "list-findings" "$REGION"
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
# SECTION 2: DETERMINE RESOURCES TO CHECK
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "target-resources" "Target Resources" "block"

echo -e "\n${CYAN}=== IDENTIFYING TARGET RESOURCES ===${NC}"

# Get all VPCs if needed
if [ "$TARGET_VPCS" == "all" ]; then
    # Retrieve list of VPCs
    TARGET_VPCS=$(aws ec2 describe-vpcs --region $REGION --query 'Vpcs[*].VpcId' --output text 2>/dev/null)
    
    if [ -z "$TARGET_VPCS" ]; then
        echo -e "${RED}Failed to retrieve VPCs. Check your permissions.${NC}"
        add_check_item "$OUTPUT_FILE" "fail" "Resource Identification" "Failed to retrieve VPCs." "Check your AWS EC2 permissions."
        close_section "$OUTPUT_FILE"
        finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"
        echo "Report has been generated: $OUTPUT_FILE"
        exit 1
    else
        add_check_item "$OUTPUT_FILE" "info" "Resource Identification" "All VPCs will be assessed: <pre>${TARGET_VPCS}</pre>"
    fi
else
    # Convert comma-separated list to space-separated
    TARGET_VPCS=$(echo $TARGET_VPCS | tr ',' ' ')
    echo -e "Using provided VPC list: $TARGET_VPCS"
    add_check_item "$OUTPUT_FILE" "info" "Resource Identification" "Assessment will be performed on specified VPCs: <pre>${TARGET_VPCS}</pre>"
fi

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 3: PCI REQUIREMENT 11.1 - PROCESSES AND MECHANISMS
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-11.1" "Requirement 11.1: Processes and mechanisms for regularly testing security of systems and networks" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 11.1: PROCESSES AND MECHANISMS ===${NC}"

# This mostly requires documentation review
add_check_item "$OUTPUT_FILE" "warning" "11.1.1 - Security Policies and Procedures Documentation" \
    "This check requires manual verification that all security policies and operational procedures for regularly testing security of systems and networks are documented, kept up to date, in use, and known to all affected parties." \
    "Maintain documented security policies and procedures for regularly testing system and network security. Ensure they are accessible to relevant personnel and regularly reviewed."
((total_checks++))
((warning_checks++))

add_check_item "$OUTPUT_FILE" "warning" "11.1.2 - Roles and Responsibilities Assignment" \
    "This check requires manual verification that roles and responsibilities for performing activities in Requirement 11 are documented, assigned, and understood." \
    "Document and assign specific roles and responsibilities for security testing activities, including vulnerability scanning, penetration testing, and intrusion detection monitoring."
((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 4: PCI REQUIREMENT 11.2 - WIRELESS ACCESS POINTS
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-11.2" "Requirement 11.2: Wireless access points are identified and monitored" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 11.2: WIRELESS ACCESS POINTS ===${NC}"

# Function to check for Wi-Fi monitoring capabilities
check_wifi_monitoring() {
    local vpc_id="$1"
    local details=""
    local has_monitoring=false
    
    # Check for WIDS/WIPS or other wireless monitoring in Config rules
    config_rules=$(aws configservice describe-config-rules --region $REGION 2>/dev/null | grep -i wireless)
    
    # Check for GuardDuty (might detect rogue wireless APs in certain cases)
    guardduty_detectors=$(aws guardduty list-detectors --region $REGION --query 'DetectorIds' --output text 2>/dev/null)
    
    if [ -n "$guardduty_detectors" ]; then
        has_monitoring=true
        details+="<p>GuardDuty is enabled in this region, which can help detect some unusual network activity that might indicate rogue wireless access points.</p>"
        details+="<p>Detector IDs: $guardduty_detectors</p>"
    else
        details+="<p>GuardDuty is not enabled in this region. Consider enabling GuardDuty for enhanced threat detection.</p>"
    fi
    
    # Check for VPC Flow Logs (can help in detecting unusual network patterns)
    flow_logs=$(aws ec2 describe-flow-logs --region $REGION --filter "Name=resource-id,Values=$vpc_id" --query 'FlowLogs[*].FlowLogId' --output text 2>/dev/null)
    
    if [ -n "$flow_logs" ]; then
        has_monitoring=true
        details+="<p>VPC Flow Logs are enabled for VPC $vpc_id, which can help identify unusual network traffic patterns:</p>"
        details+="<pre>$flow_logs</pre>"
    else
        details+="<p>VPC Flow Logs are not enabled for VPC $vpc_id. Consider enabling flow logs to monitor network traffic patterns.</p>"
    fi
    
    if [ "$has_monitoring" = true ]; then
        echo "pass|$details"
    else
        echo "warning|$details"
    fi
}

for vpc_id in $TARGET_VPCS; do
    echo -e "\nChecking VPC: $vpc_id for wireless monitoring capabilities..."
    
    # Call the function and capture results
    result=$(check_wifi_monitoring "$vpc_id")
    status=$(echo "$result" | cut -d'|' -f1)
    details=$(echo "$result" | cut -d'|' -f2)
    
    if [ "$status" = "pass" ]; then
        add_check_item "$OUTPUT_FILE" "pass" "11.2.1 - Wireless Access Point Monitoring (VPC: $vpc_id)" \
            "$details"
        ((passed_checks++))
    else
        add_check_item "$OUTPUT_FILE" "warning" "11.2.1 - Wireless Access Point Monitoring (VPC: $vpc_id)" \
            "$details" \
            "Implement automated wireless scanning tools or processes to detect and identify all wireless access points at least once every three months. Consider implementing a Wireless Intrusion Detection/Prevention System (WIDS/WIPS)."
        ((warning_checks++))
    fi
    ((total_checks++))
    
    # For 11.2.2 - This requires documentation review
    add_check_item "$OUTPUT_FILE" "warning" "11.2.2 - Wireless Access Point Inventory (VPC: $vpc_id)" \
        "This check requires manual verification that an inventory of authorized wireless access points is maintained with business justification." \
        "Maintain an up-to-date inventory of all authorized wireless access points. Document business justification for each wireless access point."
    ((total_checks++))
    ((warning_checks++))
done

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 5: PCI REQUIREMENT 11.3 - VULNERABILITY MANAGEMENT
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-11.3" "Requirement 11.3: External and internal vulnerabilities are regularly identified and addressed" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 11.3: VULNERABILITY MANAGEMENT ===${NC}"

# Function to check for vulnerability scanning capabilities
check_vulnerability_scanning() {
    local details=""
    local has_internal_scanning=false
    local has_external_scanning=false
    
    # Check for AWS Inspector
    inspector_status=$(aws inspector2 list-findings --region $REGION --max-results 1 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        has_internal_scanning=true
        findings_count=$(aws inspector2 list-findings --region $REGION --query 'findings | length(@)' 2>/dev/null)
        details+="<p>AWS Inspector is enabled, which provides automated vulnerability assessments:</p>"
        details+="<ul>"
        details+="<li>Active findings: $findings_count</li>"
        
        # Get severity breakdown
        critical_count=$(aws inspector2 list-findings --region $REGION --filter 'severities={CRITICAL}' --query 'findings | length(@)' 2>/dev/null)
        high_count=$(aws inspector2 list-findings --region $REGION --filter 'severities={HIGH}' --query 'findings | length(@)' 2>/dev/null)
        medium_count=$(aws inspector2 list-findings --region $REGION --filter 'severities={MEDIUM}' --query 'findings | length(@)' 2>/dev/null)
        
        details+="<li>Critical vulnerabilities: $critical_count</li>"
        details+="<li>High vulnerabilities: $high_count</li>"
        details+="<li>Medium vulnerabilities: $medium_count</li>"
        details+="</ul>"
        
        # Check if there are critical or high findings
		critical_count=${critical_count:-0}
		high_count=${high_count:-0}
        if [ "$critical_count" -gt 0 ] || [ "$high_count" -gt 0 ]; then
            details+="<p class='red'>WARNING: There are unresolved critical or high vulnerabilities. PCI DSS requires that high-risk and critical vulnerabilities be resolved.</p>"
            has_critical_high=true
        else
            details+="<p class='green'>No critical or high vulnerabilities detected in AWS Inspector findings.</p>"
            has_critical_high=false
        fi
    else
        details+="<p>AWS Inspector is not enabled in this region. Consider enabling AWS Inspector for automated vulnerability assessments.</p>"
    fi
    
    # Check for AWS ECR Scan (for container vulnerabilities)
    if aws ecr describe-registry --region $REGION 2>/dev/null; then
        ecr_repos=$(aws ecr describe-repositories --region $REGION --query 'repositories[*].repositoryName' --output text 2>/dev/null)
        
        if [ -n "$ecr_repos" ]; then
            details+="<p>AWS ECR repositories found. ECR supports image scanning for vulnerabilities:</p><ul>"
            
            for repo in $ecr_repos; do
                scan_config=$(aws ecr get-repository-scanning-configuration --repository-name "$repo" --region $REGION 2>/dev/null)
                if echo "$scan_config" | grep -q "ACTIVE"; then
                    details+="<li>Repository $repo has scanning enabled</li>"
                    has_internal_scanning=true
                else
                    details+="<li>Repository $repo does not have scanning enabled</li>"
                fi
            done
            
            details+="</ul>"
        fi
    fi
    
    # Check for AWS Config rules that might help with compliance
    config_rules=$(aws configservice describe-config-rules --region $REGION 2>/dev/null | grep -i "vuln\|security")
    
    if [ -n "$config_rules" ]; then
        details+="<p>AWS Config has rules related to security/vulnerabilities:</p>"
        details+="<pre>$config_rules</pre>"
    fi
    
    if [ "$has_internal_scanning" = true ]; then
        if [ "$has_critical_high" = true ]; then
            echo "fail|$details"
        else
            echo "pass|$details"
        fi
    else
        echo "warning|$details"
    fi
}

# Call the vulnerability scanning check function
result=$(check_vulnerability_scanning)
status=$(echo "$result" | cut -d'|' -f1)
details=$(echo "$result" | cut -d'|' -f2)

if [ "$status" = "pass" ]; then
    add_check_item "$OUTPUT_FILE" "pass" "11.3.1 - Internal Vulnerability Scanning" \
        "$details"
    ((passed_checks++))
elif [ "$status" = "fail" ]; then
    add_check_item "$OUTPUT_FILE" "fail" "11.3.1 - Internal Vulnerability Scanning" \
        "$details" \
        "Resolve all high-risk and critical vulnerabilities identified in vulnerability scans. Perform rescans to confirm resolution. Ensure scans are performed at least once every three months and after significant changes."
    ((failed_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "11.3.1 - Internal Vulnerability Scanning" \
        "$details" \
        "Implement a vulnerability scanning solution that performs internal scans at least once every three months. Ensure scans are performed by qualified personnel and address high-risk and critical vulnerabilities promptly."
    ((warning_checks++))
fi
((total_checks++))

# External Vulnerability Scanning - This typically requires a PCI ASV and manual review
add_check_item "$OUTPUT_FILE" "warning" "11.3.2 - External Vulnerability Scanning" \
    "This check requires manual verification that external vulnerability scans are performed quarterly by a PCI SSC Approved Scanning Vendor (ASV). The scans must meet ASV Program Guide requirements for a passing scan, with vulnerabilities properly resolved and verified through rescans. Per Requirement 11.3.2.1, scans must also be performed after any significant infrastructure or application change." \
    "Engage a PCI SSC Approved Scanning Vendor (ASV) to perform external vulnerability scans at least once every three months and after significant changes. Ensure all vulnerabilities are resolved according to ASV Program Guide requirements, and verified through rescans. For significant changes outside of quarterly scans, ensure vulnerabilities scored 4.0 or higher by CVSS are resolved."
((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 6: PCI REQUIREMENT 11.4 - PENETRATION TESTING
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-11.4" "Requirement 11.4: External and internal penetration testing is regularly performed" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 11.4: PENETRATION TESTING ===${NC}"

# Penetration Testing Methodology Documentation check
add_check_item "$OUTPUT_FILE" "warning" "11.4.1 - Penetration Testing Methodology" \
    "This check requires manual verification that a penetration testing methodology is defined, documented, and implemented. The methodology must include: industry-accepted approaches, coverage for the entire CDE perimeter and critical systems, testing from both inside and outside the network, testing to validate segmentation controls, application-layer testing covering vulnerabilities in Requirement 6.2.4, network-layer testing, review of threats and vulnerabilities from the last 12 months, documented approach for risk assessment, and retention of test results for at least 12 months." \
    "Document a penetration testing methodology that includes industry-accepted approaches, covers the entire CDE perimeter and critical systems, includes testing from both inside and outside the network, validates segmentation controls, and includes application-layer and network-layer testing. Review threats from the last 12 months and retain results for at least 12 months."
((total_checks++))
((warning_checks++))

# Internal Penetration Testing check
add_check_item "$OUTPUT_FILE" "warning" "11.4.2 - Internal Penetration Testing" \
    "This check requires manual verification that internal penetration testing is performed at least once every 12 months and after significant changes. AWS does not provide built-in penetration testing services, though AWS does allow penetration testing with prior approval." \
    "Perform internal penetration testing at least once every 12 months and after significant infrastructure or application upgrades or changes. Use qualified testers with organizational independence. For testing on AWS, follow AWS penetration testing guidelines and request permissions: https://aws.amazon.com/security/penetration-testing/"
((total_checks++))
((warning_checks++))

# External Penetration Testing check
add_check_item "$OUTPUT_FILE" "warning" "11.4.3/11.4.4 - External Penetration Testing" \
    "This check requires manual verification that external penetration testing is performed at least once every 12 months and after significant changes. AWS does not provide built-in penetration testing services, though AWS does allow penetration testing with prior approval." \
    "Perform external penetration testing at least once every 12 months and after significant infrastructure or application upgrades or changes. Use qualified testers with organizational independence. Correct all exploitable vulnerabilities and security weaknesses, and perform retesting to verify corrections."
((total_checks++))
((warning_checks++))

# Function to check for network segmentation between VPCs
check_vpc_segmentation() {
    local vpc_id="$1"
    local details=""
    local has_segmentation=false
    
    # Check for VPC peering connections
    peer_connections=$(aws ec2 describe-vpc-peering-connections --region $REGION --filters "Name=accepter-vpc-info.vpc-id,Values=$vpc_id" "Name=requester-vpc-info.vpc-id,Values=$vpc_id" --query 'VpcPeeringConnections[*].VpcPeeringConnectionId' --output text 2>/dev/null)
    
    if [ -n "$peer_connections" ]; then
        details+="<p>VPC $vpc_id has the following VPC peering connections:</p><ul>"
        for conn in $peer_connections; do
            details+="<li>$conn</li>"
            peer_info=$(aws ec2 describe-vpc-peering-connections --region $REGION --vpc-peering-connection-ids "$conn" --query 'VpcPeeringConnections[0]' --output json 2>/dev/null)
            details+="<pre>$peer_info</pre>"
        done
        details+="</ul>"
        details+="<p>VPC peering connections should be assessed to ensure proper segmentation of the CDE from other networks.</p>"
        has_segmentation=true
    else
        details+="<p>No VPC peering connections found for VPC $vpc_id.</p>"
    fi
    
    # Check for Transit Gateway attachments
    transit_gateways=$(aws ec2 describe-transit-gateway-attachments --region $REGION --filters "Name=resource-id,Values=$vpc_id" --query 'TransitGatewayAttachments[*].TransitGatewayId' --output text 2>/dev/null)
    
    if [ -n "$transit_gateways" ]; then
        details+="<p>VPC $vpc_id is attached to the following Transit Gateways:</p><ul>"
        for tgw in $transit_gateways; do
            details+="<li>$tgw</li>"
        done
        details+="</ul>"
        details+="<p>Transit Gateway connections should be assessed to ensure proper segmentation of the CDE from other networks.</p>"
        has_segmentation=true
    else
        details+="<p>No Transit Gateway attachments found for VPC $vpc_id.</p>"
    fi
    
    # Check for Network ACLs and analyze them
    nacls=$(aws ec2 describe-network-acls --region $REGION --filters "Name=vpc-id,Values=$vpc_id" --query 'NetworkAcls[*].NetworkAclId' --output text 2>/dev/null)
    
    if [ -n "$nacls" ]; then
        details+="<p>VPC $vpc_id has the following Network ACLs:</p><ul>"
        for nacl in $nacls; do
            nacl_details=$(aws ec2 describe-network-acls --region $REGION --network-acl-ids "$nacl" --output json 2>/dev/null)
            details+="<li>NACL ID: $nacl</li>"
            
            # Check if default deny rule exists
            if echo "$nacl_details" | grep -q '"RuleNumber": 32767'; then
                details+="<li class='green'>Has default deny rule (32767)</li>"
            else
                details+="<li class='red'>Missing default deny rule</li>"
            fi
        done
        details+="</ul>"
        has_segmentation=true
    else
        details+="<p>No Network ACLs found for VPC $vpc_id.</p>"
    fi
    
    # Check for Security Groups
    sgs=$(aws ec2 describe-security-groups --region $REGION --filters "Name=vpc-id,Values=$vpc_id" --query 'SecurityGroups[*].GroupId' --output text 2>/dev/null)
    
    if [ -n "$sgs" ]; then
        sg_count=$(echo "$sgs" | wc -w)
        details+="<p>VPC $vpc_id has $sg_count Security Groups.</p>"
        
        # Check for overly permissive security groups
        open_sgs=$(aws ec2 describe-security-groups --region $REGION --filters "Name=vpc-id,Values=$vpc_id" --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].GroupId' --output text 2>/dev/null)
        
        if [ -n "$open_sgs" ]; then
            details+="<p class='red'>WARNING: The following Security Groups allow traffic from 0.0.0.0/0 (any source):</p><ul>"
            for sg in $open_sgs; do
                details+="<li>$sg</li>"
                
                # Get the open ports for this security group
                open_ports=$(aws ec2 describe-security-groups --region $REGION --group-ids "$sg" --query 'SecurityGroups[0].IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]].[FromPort,ToPort,IpProtocol]' --output text 2>/dev/null)
                
                if [ -n "$open_ports" ]; then
                    details+="<pre>Open to 0.0.0.0/0: $open_ports</pre>"
                fi
            done
            details+="</ul>"
        else
            details+="<p class='green'>No Security Groups with 0.0.0.0/0 sources found.</p>"
        fi
        
        has_segmentation=true
    else
        details+="<p>No Security Groups found for VPC $vpc_id.</p>"
    fi
    
    if [ "$has_segmentation" = true ]; then
        if [[ "$details" == *"class='red'"* ]]; then
            echo "fail|$details"
        else
            echo "pass|$details"
        fi
    else
        echo "warning|$details"
    fi
}

for vpc_id in $TARGET_VPCS; do
    echo -e "\nChecking VPC: $vpc_id for segmentation controls..."
    
    # Call the function and capture results
    result=$(check_vpc_segmentation "$vpc_id")
    status=$(echo "$result" | cut -d'|' -f1)
    details=$(echo "$result" | cut -d'|' -f2)
    
    if [ "$status" = "pass" ]; then
        add_check_item "$OUTPUT_FILE" "pass" "11.4.5 - Segmentation Controls Testing (VPC: $vpc_id)" \
            "$details"
        ((passed_checks++))
    elif [ "$status" = "fail" ]; then
        add_check_item "$OUTPUT_FILE" "fail" "11.4.5 - Segmentation Controls Testing (VPC: $vpc_id)" \
            "$details" \
            "Review and update network segmentation controls (security groups, NACLs, etc.) to ensure proper isolation of the CDE from other networks. Remove overly permissive rules (e.g., 0.0.0.0/0) where not absolutely necessary. Perform penetration testing to validate segmentation controls at least once every 12 months and after any changes."
        ((failed_checks++))
    else
        add_check_item "$OUTPUT_FILE" "warning" "11.4.5 - Segmentation Controls Testing (VPC: $vpc_id)" \
            "$details" \
            "Implement network segmentation controls and perform penetration testing to validate them at least once every 12 months and after any changes to segmentation controls/methods."
        ((warning_checks++))
    fi
    ((total_checks++))
done

# Service provider-specific requirements
add_check_item "$OUTPUT_FILE" "warning" "11.4.6/11.4.7 - Additional Service Provider Requirements" \
    "These checks apply only to service providers and multi-tenant service providers, requiring more frequent segmentation testing (every six months) and support for customer penetration testing." \
    "If you are a service provider, ensure segmentation testing is performed every six months rather than annually. If you are a multi-tenant service provider, ensure you support customers' external penetration testing requirements."
((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 7: PCI REQUIREMENT 11.5 - INTRUSION DETECTION AND FILE INTEGRITY MONITORING
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-11.5" "Requirement 11.5: Network intrusions and unexpected file changes are detected and responded to" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 11.5: INTRUSION DETECTION AND FILE INTEGRITY MONITORING ===${NC}"

# Function to check for intrusion detection capabilities
check_intrusion_detection() {
    local vpc_id="$1"
    local details=""
    local has_ids=false
    
    # Check for GuardDuty (AWS's threat detection service) - PCI Req 11.5.1
    guardduty_detectors=$(aws guardduty list-detectors --region $REGION --query 'DetectorIds' --output text 2>/dev/null)
    
    if [ -n "$guardduty_detectors" ]; then
        has_ids=true
        details+="<p class='green'>Amazon GuardDuty is enabled in this region, which provides intrusion detection capabilities:</p>"
        details+="<ul>"
        
        for detector in $guardduty_detectors; do
            detector_details=$(aws guardduty get-detector --detector-id "$detector" --region $REGION --output json 2>/dev/null)
            details+="<li>Detector ID: $detector</li>"
            
            # Check if it's enabled
            if echo "$detector_details" | grep -q '"Status": "ENABLED"'; then
                details+="<li class='green'>Status: ENABLED</li>"
            else
                details+="<li class='red'>Status: DISABLED</li>"
                has_ids=false
            fi
            
            # Check finding statistics
            findings_stats=$(aws guardduty get-findings-statistics --detector-id "$detector" --region $REGION --finding-statistics-type COUNT_BY_SEVERITY 2>/dev/null)
            
            if [ -n "$findings_stats" ]; then
                details+="<li>Finding statistics: $findings_stats</li>"
            fi
        done
        details+="</ul>"
    else
        details+="<p class='yellow'>Amazon GuardDuty is not enabled in this region. GuardDuty provides threat detection and intrusion detection capabilities.</p>"
    fi
    
    # Check for Network Firewall
    nfw_firewalls=$(aws network-firewall list-firewalls --region $REGION 2>/dev/null | grep -i "firewall")
    
    if [ -n "$nfw_firewalls" ]; then
        has_ids=true
        details+="<p class='green'>AWS Network Firewall is deployed in this region, which can provide network threat detection and prevention:</p>"
        details+="<pre>$nfw_firewalls</pre>"
    else
        details+="<p>AWS Network Firewall is not detected in this region.</p>"
    fi
    
    # Check for VPC Flow Logs (helpful for network traffic analysis)
    flow_logs=$(aws ec2 describe-flow-logs --region $REGION --filter "Name=resource-id,Values=$vpc_id" --query 'FlowLogs[*].[FlowLogId,LogDestination]' --output text 2>/dev/null)
    
    if [ -n "$flow_logs" ]; then
        details+="<p class='green'>VPC Flow Logs are enabled for VPC $vpc_id, which can help with network traffic analysis:</p>"
        details+="<pre>$flow_logs</pre>"
    else
        details+="<p>VPC Flow Logs are not enabled for VPC $vpc_id. Consider enabling flow logs to aid in network traffic analysis.</p>"
    fi
    
    # Check for CloudTrail (helpful for API activity monitoring)
    trails=$(aws cloudtrail describe-trails --region $REGION --query 'trailList[*].[Name,HomeRegion,IsMultiRegionTrail]' --output text 2>/dev/null)
    
    if [ -n "$trails" ]; then
        details+="<p class='green'>AWS CloudTrail is configured, which logs AWS API activity:</p>"
        details+="<pre>$trails</pre>"
    else
        details+="<p>AWS CloudTrail is not detected in this region. CloudTrail is essential for API activity monitoring.</p>"
    fi
    
    if [ "$has_ids" = true ]; then
        echo "pass|$details"
    else
        echo "fail|$details"
    fi
}

# Function to check for file integrity monitoring capabilities - PCI Req 11.5.2
check_file_integrity_monitoring() {
    local details=""
    local has_fim=false
    
    # Check for AWS Config (can monitor configuration changes)
    config_rules=$(aws configservice describe-config-rules --region $REGION 2>/dev/null | grep -i "rule")
    
    if [ -n "$config_rules" ]; then
        has_fim=true
        details+="<p class='green'>AWS Config is enabled in this region, which can monitor for configuration changes:</p>"
        details+="<pre>$config_rules</pre>"
    else
        details+="<p>AWS Config is not detected in this region. Config can help with monitoring configuration changes.</p>"
    fi
    
    # Check for CloudTrail (monitors API activity, including file changes via AWS API)
    trails=$(aws cloudtrail describe-trails --region $REGION --query 'trailList[*].[Name,HomeRegion,IsMultiRegionTrail]' --output text 2>/dev/null)
    
    if [ -n "$trails" ]; then
        has_fim=true
        details+="<p class='green'>AWS CloudTrail is configured, which logs AWS API activity including file changes via AWS APIs:</p>"
        details+="<pre>$trails</pre>"
        
        # Check if CloudTrail is actually logging
        for trail in $trails; do
            trail_name=$(echo "$trail" | awk '{print $1}')
            trail_status=$(aws cloudtrail get-trail-status --name "$trail_name" --region $REGION 2>/dev/null)
            
            if echo "$trail_status" | grep -q '"IsLogging": true'; then
                details+="<p class='green'>Trail $trail_name is actively logging.</p>"
            else
                details+="<p class='red'>Trail $trail_name is NOT actively logging.</p>"
                has_fim=false
            fi
        done
    else
        details+="<p>AWS CloudTrail is not detected in this region. CloudTrail is essential for API activity monitoring including file changes via AWS APIs.</p>"
    fi
    
    # Amazon EC2 Systems Manager can be used for file integrity monitoring but requires more specific checks
    ssm_associations=$(aws ssm list-associations --region $REGION 2>/dev/null | grep -i "file-integrity-monitoring\|fim")
    
    if [ -n "$ssm_associations" ]; then
        has_fim=true
        details+="<p class='green'>AWS Systems Manager appears to be configured with file integrity monitoring associations:</p>"
        details+="<pre>$ssm_associations</pre>"
    else
        details+="<p>No explicit file integrity monitoring configurations found in AWS Systems Manager. Consider implementing file integrity monitoring using SSM or another solution.</p>"
    fi
    
    if [ "$has_fim" = true ]; then
        echo "pass|$details"
    else
        echo "warning|$details"
    fi
}

for vpc_id in $TARGET_VPCS; do
    echo -e "\nChecking VPC: $vpc_id for intrusion detection capabilities..."
    
    # Call the intrusion detection function and capture results
    result=$(check_intrusion_detection "$vpc_id")
    status=$(echo "$result" | cut -d'|' -f1)
    details=$(echo "$result" | cut -d'|' -f2)
    
    if [ "$status" = "pass" ]; then
        add_check_item "$OUTPUT_FILE" "pass" "11.5.1 - Intrusion Detection Systems (VPC: $vpc_id)" \
            "$details"
        ((passed_checks++))
    else
        add_check_item "$OUTPUT_FILE" "warning" "11.5.1 - Intrusion Detection Systems (VPC: $vpc_id)" \
            "$details" \
            "Implement intrusion-detection techniques such as AWS GuardDuty to monitor all traffic at the perimeter of the CDE and at critical points within the CDE. Ensure alerts are generated for suspected compromises and intrusion-detection mechanisms are kept up to date."
        ((failed_checks++))
    fi
    ((total_checks++))
done

# Check File Integrity Monitoring
echo -e "\nChecking for file integrity monitoring capabilities..."

# Call the file integrity monitoring function and capture results
result=$(check_file_integrity_monitoring)
status=$(echo "$result" | cut -d'|' -f1)
details=$(echo "$result" | cut -d'|' -f2)

if [ "$status" = "pass" ]; then
    add_check_item "$OUTPUT_FILE" "pass" "11.5.2 - File Integrity Monitoring" \
        "$details"
    ((passed_checks++))
else
    add_check_item "$OUTPUT_FILE" "warning" "11.5.2 - File Integrity Monitoring" \
        "$details" \
        "Implement a change-detection mechanism (file integrity monitoring) to alert personnel to unauthorized modification of critical files. Configure the system to perform critical file comparisons at least once weekly. Consider using AWS Systems Manager, CloudTrail, or a third-party file integrity monitoring solution."
    ((warning_checks++))
fi
((total_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 8: PCI REQUIREMENT 11.6 - PAYMENT PAGE SECURITY
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-11.6" "Requirement 11.6: Unauthorized changes on payment pages are detected and responded to" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 11.6: PAYMENT PAGE SECURITY ===${NC}"

# This requires application-specific implementation and manual verification
add_check_item "$OUTPUT_FILE" "warning" "11.6.1 - Payment Page Change and Tamper Detection" \
    "This check requires manual verification that a change- and tamper-detection mechanism is deployed to alert personnel to unauthorized modifications (including indicators of compromise, changes, additions, and deletions) to the HTTP headers and script contents of payment pages as received by the consumer browser. The mechanism must be configured to evaluate the received HTTP headers and payment pages at least weekly (or at a frequency defined in a targeted risk analysis)." \
    "Implement a change- and tamper-detection mechanism to alert personnel to unauthorized modification of payment page contents and HTTP headers as received by consumers. Configure the mechanism to perform checks at least weekly or at a frequency defined in a targeted risk analysis as specified in Requirement 12.3.1."
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