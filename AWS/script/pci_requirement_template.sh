#!/bin/bash

# PCI DSS Requirement X Compliance Check Script for AWS
# This script evaluates AWS controls for PCI DSS Requirement X compliance
# Requirements covered: X.1 - X.X [REPLACE WITH APPROPRIATE CONTENT]

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
REQUIREMENT_NUMBER="X" # REPLACE WITH APPROPRIATE NUMBER (e.g., 2, 3, etc.)
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
read -p "Enter AWS region to test (e.g., us-east-1): " REGION
if [ -z "$REGION" ]; then
    REGION="us-east-1"
    echo -e "${YELLOW}Using default region: $REGION${NC}"
fi

# Ask for specific resources to assess (e.g., VPCs, RDS instances, etc.)
# CUSTOMIZE THIS SECTION BASED ON REQUIREMENT NEEDS
read -p "Enter resource IDs to assess (comma-separated or 'all' for all): " TARGET_RESOURCES
if [ -z "$TARGET_RESOURCES" ] || [ "$TARGET_RESOURCES" == "all" ]; then
    echo -e "${YELLOW}Checking all resources${NC}"
    TARGET_RESOURCES="all"
else
    echo -e "${YELLOW}Checking specific resource(s): $TARGET_RESOURCES${NC}"
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

# CUSTOMIZE PERMISSION CHECKS BASED ON REQUIREMENT NEEDS
check_command_access "$OUTPUT_FILE" "ec2" "describe-vpcs" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

# ADD MORE PERMISSION CHECKS AS NEEDED

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

# CUSTOMIZE RESOURCE IDENTIFICATION BASED ON REQUIREMENT NEEDS

# Example: Get all VPCs if needed
if [ "$TARGET_RESOURCES" == "all" ]; then
    # Example: Retrieve list of resources (e.g., VPCs)
    RESOURCES=$(aws ec2 describe-vpcs --region $REGION --query 'Vpcs[*].VpcId' --output text 2>/dev/null)
    
    if [ -z "$RESOURCES" ]; then
        echo -e "${RED}Failed to retrieve resources. Check your permissions.${NC}"
        add_check_item "$OUTPUT_FILE" "fail" "Resource Identification" "Failed to retrieve resources." "Check your AWS permissions."
        close_section "$OUTPUT_FILE"
        finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"
        echo "Report has been generated: $OUTPUT_FILE"
        exit 1
    else
        add_check_item "$OUTPUT_FILE" "info" "Resource Identification" "All resources will be assessed: <pre>${RESOURCES}</pre>"
    fi
else
    # Convert comma-separated list to space-separated
    RESOURCES=$(echo $TARGET_RESOURCES | tr ',' ' ')
    echo -e "Using provided resource list: $RESOURCES"
    add_check_item "$OUTPUT_FILE" "info" "Resource Identification" "Assessment will be performed on specified resources: <pre>${RESOURCES}</pre>"
fi

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 3: PCI REQUIREMENT X.1
#----------------------------------------------------------------------
# CUSTOMIZE SECTIONS BASED ON SPECIFIC REQUIREMENTS
add_section "$OUTPUT_FILE" "req-x.1" "Requirement X.1: [TITLE]" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT X.1: [TITLE] ===${NC}"

# Example check
add_check_item "$OUTPUT_FILE" "warning" "X.1.1 - [Check Title]" "This is a placeholder for a real check. Replace with actual check logic." "Replace with actual recommendation."
((total_checks++))
((warning_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 4: PCI REQUIREMENT X.2
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-x.2" "Requirement X.2: [TITLE]" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT X.2: [TITLE] ===${NC}"

# Example check that passes
add_check_item "$OUTPUT_FILE" "pass" "X.2.1 - [Check Title]" "This is a placeholder for a passing check. Replace with actual check logic."
((total_checks++))
((passed_checks++))

# Example check that fails
add_check_item "$OUTPUT_FILE" "fail" "X.2.2 - [Check Title]" "This is a placeholder for a failing check. Replace with actual check logic." "Replace with actual recommendation."
((total_checks++))
((failed_checks++))

close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# ADD MORE SECTIONS FOR EACH SUB-REQUIREMENT (X.3, X.4, etc.)
#----------------------------------------------------------------------

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