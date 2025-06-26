#!/bin/bash

# Source the shared HTML report library
source "$(dirname "$0")/pci_html_report_lib.sh"

# Define variables
REQUIREMENT_NUMBER="1"
REPORT_TITLE="PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report (TEST)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="./reports"
OUTPUT_FILE="$OUTPUT_DIR/test_report_$TIMESTAMP.html"

# Create reports directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Initialize HTML report
initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE" "$REQUIREMENT_NUMBER" "ap-northeast-1"

# Add a test section
add_section "$OUTPUT_FILE" "security-groups" "Security Group Test" "active"

# Test specific security groups
sg_check_details="<p>Security Group Analysis</p><ul>"

# Example Security Group 1
sg_name="example-sg-1"
sg_id="sg-91b712f5"
sg_check_details+="<li>Security Group: $sg_id ($sg_name)</li>"
sg_check_details+="<ul><li class=\"red\">WARNING: Has 7 public inbound rules (0.0.0.0/0)</li>"
sg_check_details+="<li>Internet-accessible ports:</li><ul>"
sg_check_details+="<li class=\"red\">tcp Port 80 open to the internet</li>"
sg_check_details+="<li class=\"red\">tcp Port 24224 open to the internet</li>"
sg_check_details+="<li class=\"red\">tcp Port 22 open to the internet</li>"
sg_check_details+="<li class=\"red\">udp Port 24224 open to the internet</li>"
sg_check_details+="<li class=\"red\">tcp Port 5601 open to the internet</li>"
sg_check_details+="<li class=\"red\">tcp Port 443 open to the internet</li>"
sg_check_details+="</ul></ul>"

# Example Security Group 2
sg_name="example-sg-2" 
sg_id="sg-8a71ffee"
sg_check_details+="<li>Security Group: $sg_id ($sg_name)</li>"
sg_check_details+="<ul><li class=\"red\">WARNING: Has 8 public inbound rules (0.0.0.0/0)</li>"
sg_check_details+="<li>Internet-accessible ports:</li><ul>"
sg_check_details+="<li class=\"red\">tcp Port 80 open to the internet</li>"
sg_check_details+="<li class=\"red\">tcp Port 9000 open to the internet</li>"
sg_check_details+="<li class=\"red\">tcp Port 8080 open to the internet</li>"
sg_check_details+="<li class=\"red\">tcp Port 22 open to the internet</li>"
sg_check_details+="<li class=\"red\">tcp Port 5000 open to the internet</li>"
sg_check_details+="<li class=\"red\">tcp Port 8282 open to the internet</li>"
sg_check_details+="<li class=\"red\">tcp Port 443 open to the internet</li>"
sg_check_details+="</ul></ul>"

# Example Security Group 3 (with no public inbound rules)
sg_name="example-sg-3"
sg_id="sg-0a8a17ceb7f17657f"
sg_check_details+="<li>Security Group: $sg_id ($sg_name)</li>"
sg_check_details+="<ul><li class=\"green\">No public inbound rules (0.0.0.0/0) found</li></ul>"

sg_check_details+="</ul>"

# Add the security groups details to the report
add_check_item "$OUTPUT_FILE" "info" "1.2.5 - Ports, protocols, and services inventory" "$sg_check_details" "Review allowed ports, protocols, and services for business justification."

# Close the test section
close_section "$OUTPUT_FILE"

# Finalize the report with some test values
total_checks=10
passed_checks=8
failed_checks=1
warning_checks=1

finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"

echo "Test report has been generated: $OUTPUT_FILE"