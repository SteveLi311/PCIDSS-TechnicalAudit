#!/bin/bash

# Script to check for security groups with open ports to the internet (0.0.0.0/0)
# Specifically addressing PCI DSS 4.0 Requirement 1.2.5 and 1.2.1
# This script properly identifies and reports which specific ports are open to the internet

# Set output colors for terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

REPORT_FILE="./reports/pci_sg_internet_access_report.txt"
mkdir -p ./reports

echo "======================================================================================" | tee -a "$REPORT_FILE"
echo "  PCI DSS 4.0 - Requirement 1 - Security Group Internet Access Check ($(date))" | tee -a "$REPORT_FILE"
echo "======================================================================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# Ask user to specify region
read -p "Enter AWS region to test (e.g., us-east-1, press enter for default): " REGION
if [ -z "$REGION" ]; then
    REGION="us-east-1"
    echo -e "${YELLOW}Using default region: $REGION${NC}"
fi
echo "Region: $REGION" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

echo -e "${CYAN}Checking for security groups with internet access (0.0.0.0/0)...${NC}"
echo "Checking for security groups with internet access (0.0.0.0/0)..." >> "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# Get all security groups with 0.0.0.0/0 inbound rules
echo "Retrieving security groups with internet access..." | tee -a "$REPORT_FILE"
PUBLIC_SGS=$(aws ec2 describe-security-groups --region "$REGION" --filters "Name=ip-permission.cidr,Values=0.0.0.0/0" --query 'SecurityGroups[*].GroupId' --output text)

if [ -z "$PUBLIC_SGS" ]; then
    echo -e "${GREEN}No security groups with internet access found. This is compliant with PCI DSS Requirement 1.${NC}" | tee -a "$REPORT_FILE"
    exit 0
fi

echo -e "${RED}WARNING: Found $(echo $PUBLIC_SGS | wc -w | tr -d '[:space:]') security groups with internet access.${NC}" | tee -a "$REPORT_FILE"
echo "This violates PCI DSS 4.0 Requirement 1.2.1 which requires proper network security control implementation." | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "Detailed analysis of each security group:" | tee -a "$REPORT_FILE"
echo "--------------------------------------------------------------" | tee -a "$REPORT_FILE"

for sg_id in $PUBLIC_SGS; do
    echo -e "${YELLOW}Analyzing Security Group: $sg_id${NC}" | tee -a "$REPORT_FILE"
    
    # Get security group details
    sg_details=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$sg_id" --output json)
    sg_name=$(echo "$sg_details" | jq -r '.SecurityGroups[0].GroupName')
    sg_desc=$(echo "$sg_details" | jq -r '.SecurityGroups[0].Description')
    vpc_id=$(echo "$sg_details" | jq -r '.SecurityGroups[0].VpcId')
    
    echo "  Group Name: $sg_name" | tee -a "$REPORT_FILE"
    echo "  Description: $sg_desc" | tee -a "$REPORT_FILE"
    echo "  VPC: $vpc_id" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
    
    echo "  INTERNET ACCESSIBLE PORTS:" | tee -a "$REPORT_FILE"
    
    # Get all inbound permissions
    permissions=$(echo "$sg_details" | jq -c '.SecurityGroups[0].IpPermissions[]')
    
    has_all_ports=false
    open_ports_count=0
    
    echo "$permissions" | while read -r permission; do
        # Check if this permission has 0.0.0.0/0 access
        if echo "$permission" | jq -e '.IpRanges[] | select(.CidrIp == "0.0.0.0/0")' > /dev/null; then
            protocol=$(echo "$permission" | jq -r '.IpProtocol')
            open_ports_count=$((open_ports_count + 1))
            
            # Handle "all protocols" case (-1)
            if [ "$protocol" == "-1" ]; then
                echo -e "  ${RED}* ALL PROTOCOLS AND PORTS${NC} open to the internet (0.0.0.0/0)" | tee -a "$REPORT_FILE"
                has_all_ports=true
            else
                # Handle specific protocols
                fromPort=$(echo "$permission" | jq -r 'if has("FromPort") then .FromPort | tostring else "N/A" end')
                toPort=$(echo "$permission" | jq -r 'if has("ToPort") then .ToPort | tostring else "N/A" end')
                
                # Service identification for common ports
                service_info=""
                if [ "$protocol" == "tcp" ]; then
                    case $fromPort in
                        22) service_info="(SSH)" ;;
                        23) service_info="(TELNET - INSECURE!)" ;;
                        25) service_info="(SMTP)" ;;
                        80) service_info="(HTTP)" ;;
                        443) service_info="(HTTPS)" ;;
                        3389) service_info="(RDP)" ;;
                        3306) service_info="(MySQL/MariaDB)" ;;
                        1433) service_info="(MS SQL)" ;;
                        21) service_info="(FTP - INSECURE!)" ;;
                    esac
                fi
                
                # Handle port range
                if [ "$fromPort" == "$toPort" ]; then
                    echo -e "  ${RED}* $protocol Port $fromPort ${service_info}${NC} open to the internet (0.0.0.0/0)" | tee -a "$REPORT_FILE"
                else
                    echo -e "  ${RED}* $protocol Ports $fromPort-$toPort${NC} open to the internet (0.0.0.0/0)" | tee -a "$REPORT_FILE"
                fi
            fi
        fi
    done
    
    echo "" | tee -a "$REPORT_FILE"
    echo "  PCI DSS COMPLIANCE ISSUE:" | tee -a "$REPORT_FILE"
    echo "  * Security group allows unrestricted access from the internet (0.0.0.0/0)" | tee -a "$REPORT_FILE"
    echo "  * This violates PCI DSS 4.0 Requirement 1.2.1 (Network security controls must be properly implemented)" | tee -a "$REPORT_FILE"
    echo "  * This violates PCI DSS 4.0 Requirement 1.3.1 (Inbound traffic to the CDE must be restricted)" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
    echo "  REMEDIATION:" | tee -a "$REPORT_FILE"
    echo "  * Restrict access to only necessary IP addresses/ranges" | tee -a "$REPORT_FILE"
    echo "  * Implement the principle of least privilege for network access" | tee -a "$REPORT_FILE"
    echo "  * Document business justification for any required internet access" | tee -a "$REPORT_FILE"
    echo "  * Consider implementing a Web Application Firewall for HTTP/HTTPS traffic" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
    echo "--------------------------------------------------------------" | tee -a "$REPORT_FILE"
done

echo "" | tee -a "$REPORT_FILE"
echo "SUMMARY:" | tee -a "$REPORT_FILE"
echo "* Found $(echo $PUBLIC_SGS | wc -w | tr -d '[:space:]') security groups with internet access (0.0.0.0/0)" | tee -a "$REPORT_FILE"
echo "* PCI DSS 4.0 Requirement 1 compliance status: FAILED" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "Report saved to: $REPORT_FILE" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "NOTE: This is a targeted check specifically for security groups with internet access." | tee -a "$REPORT_FILE"
echo "A full PCI DSS Requirement 1 assessment requires additional checks." | tee -a "$REPORT_FILE"
