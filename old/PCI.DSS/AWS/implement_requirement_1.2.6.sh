#!/bin/bash

# PCI DSS Requirement 1.2.6 Implementation Example
# This script shows how to properly implement and integrate the check_insecure_services function
# for a thorough assessment of Requirement 1.2.6

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

# Set output colors for terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Counters for checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

# Source the check_insecure_services function
source "$(dirname "$0")/check_insecure_services.sh"

# Main function to implement Requirement 1.2.6 check
implement_requirement_1_2_6() {
    local region="$1"
    local vpcs="$2"
    
    echo -e "\n${CYAN}=== PCI REQUIREMENT 1.2.6: SECURITY FEATURES FOR INSECURE SERVICES/PROTOCOLS ===${NC}"
    echo -e "Checking for insecure services/protocols in security groups..."
    
    # Initialize HTML report if it doesn't exist yet
    if [ ! -f "$OUTPUT_FILE" ]; then
        initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE" "$REQUIREMENT_NUMBER" "$region"
    fi
    
    # Add a specific section for requirement 1.2.6
    add_section "$OUTPUT_FILE" "req-1.2.6" "Requirement 1.2.6: Security features for insecure services/protocols" "active"
    
    # Iterate through each VPC and check for insecure services
    insecure_services_found=false
    all_details="<p>Detailed analysis of security features for insecure services/protocols:</p>"
    
    for vpc_id in $vpcs; do
        echo -e "\nChecking VPC: $vpc_id for insecure services/protocols..."
        
        # Call the check_insecure_services function
        vpc_details=$(check_insecure_services "$vpc_id")
        
        # Append the VPC details to the overall details
        all_details+="<h4>VPC: $vpc_id</h4>$vpc_details"
        
        # Check if insecure services were found in this VPC
        if [[ "$vpc_details" == *"class=\"red\""* || "$vpc_details" == *"class=\"yellow\""* ]]; then
            insecure_services_found=true
        fi
    done
    
    ((total_checks++))
    
    # Determine the check status and add appropriate check item
    if [ "$insecure_services_found" = true ]; then
        echo -e "${RED}FAIL: Insecure services/protocols detected in security groups${NC}"
        
        add_check_item "$OUTPUT_FILE" "fail" "1.2.6 - Security features for insecure services/protocols" \
            "$all_details" \
            "Per PCI DSS requirement 1.2.6, security features must be defined and implemented for all services, protocols, and ports that are in use and considered to be insecure. Action items:
            <ol>
                <li>Replace insecure protocols with secure alternatives where possible (e.g., Telnet→SSH, FTP→SFTP/FTPS).</li>
                <li>For insecure services that must be used for business reasons, implement additional security features such as:
                    <ul>
                        <li>Restrict source IP addresses to specific trusted hosts or networks</li>
                        <li>Implement encrypted tunnels (e.g., VPN or SSH tunneling)</li>
                        <li>Use TLS/SSL for database connections</li>
                        <li>Enable strong authentication mechanisms</li>
                        <li>Implement network segmentation</li>
                    </ul>
                </li>
                <li>Document business justification for any insecure services that must remain in use</li>
                <li>Document the security features implemented to mitigate risks of insecure services</li>
            </ol>"
        
        ((failed_checks++))
    else
        echo -e "${GREEN}PASS: No insecure services/protocols detected in security groups${NC}"
        
        add_check_item "$OUTPUT_FILE" "pass" "1.2.6 - Security features for insecure services/protocols" \
            "$all_details"
        
        ((passed_checks++))
    fi
    
    close_section "$OUTPUT_FILE"
    
    # Finalize the report
    finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"
    
    echo -e "\nCheck completed. Passed: $passed_checks, Failed: $failed_checks, Total: $total_checks"
    echo -e "Report saved to: $OUTPUT_FILE"
}

# Usage example (commented out):
# REGION="us-east-1"
# TARGET_VPCS="vpc-12345678 vpc-87654321"
# implement_requirement_1_2_6 "$REGION" "$TARGET_VPCS"
