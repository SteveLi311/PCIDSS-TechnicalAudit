#!/bin/bash

# Source the shared HTML report library
source "$(dirname "$0")/pci_html_report_lib.sh"

# Define variables
REQUIREMENT_NUMBER="1"
REPORT_TITLE="PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report (TEST)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="./reports"
OUTPUT_FILE="$OUTPUT_DIR/pci_sg_test_report_$TIMESTAMP.html"
REGION="ap-northeast-1"
SG_ID="sg-91b712f5"

# Create reports directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Initialize HTML report
initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE" "$REQUIREMENT_NUMBER" "$REGION"

# Add a test section
add_section "$OUTPUT_FILE" "security-groups" "Security Group Test" "active"

# Get security group details
sg_details=$(aws ec2 describe-security-groups --region $REGION --group-ids $SG_ID 2>/dev/null)
sg_name=$(echo "$sg_details" | grep "GroupName" | head -1 | awk -F '"' '{print $4}')

echo "Analyzing Security Group: $SG_ID ($sg_name)"

# Check for overly permissive inbound rules (0.0.0.0/0)
public_inbound=$(echo "$sg_details" | grep -c '"CidrIp": "0.0.0.0/0"')

# Initialize report details
sg_check_details="<p>Security Group Analysis</p><ul>"
sg_check_details+="<li>Security Group: $SG_ID ($sg_name)</li>"

if [ $public_inbound -gt 0 ]; then
    echo "WARNING: Security group $SG_ID has $public_inbound public inbound rules (0.0.0.0/0)"
    sg_check_details+="<ul><li class=\"red\">WARNING: Has $public_inbound public inbound rules (0.0.0.0/0)</li>"
    sg_check_details+="<li>Internet-accessible ports:</li><ul>"
    
    # Initialize port list
    port_list=""
    
    # Use jq for extraction if available
    if command -v jq &> /dev/null; then
        echo "Using jq for extraction"
        
        # Create temporary files to store permissions
        TMP_FILE=$(mktemp)
        TMP_PERMISSIONS=$(mktemp)
        
        # Extract permissions with public access
        echo "$sg_details" > "$TMP_FILE"
        jq -c '.SecurityGroups[0].IpPermissions[] | select(.IpRanges[].CidrIp == "0.0.0.0/0")' < "$TMP_FILE" > "$TMP_PERMISSIONS" 2>/dev/null
        
        # Process each permission line by line (works in all shells)
        while IFS= read -r permission; do
            if [ -n "$permission" ]; then
                protocol=$(echo "$permission" | jq -r '.IpProtocol')
                
                # Handle "all protocols" case (-1)
                if [ "$protocol" == "-1" ]; then
                    echo "  ALL PROTOCOLS AND PORTS open to the internet (0.0.0.0/0)"
                    port_list+="<li class=\"red\">ALL PROTOCOLS AND PORTS open to the internet</li>"
                else
                    # Handle specific protocols
                    fromPort=$(echo "$permission" | jq -r 'if has("FromPort") then .FromPort | tostring else "N/A" end')
                    toPort=$(echo "$permission" | jq -r 'if has("ToPort") then .ToPort | tostring else "N/A" end')
                    
                    # Handle port range
                    if [ "$fromPort" == "$toPort" ]; then
                        echo "  $protocol Port $fromPort open to the internet (0.0.0.0/0)"
                        port_list+="<li class=\"red\">$protocol Port $fromPort open to the internet</li>"
                    else
                        echo "  $protocol Ports $fromPort-$toPort open to the internet (0.0.0.0/0)"
                        port_list+="<li class=\"red\">$protocol Ports $fromPort-$toPort open to the internet</li>"
                    fi
                fi
            fi
        done < "$TMP_PERMISSIONS"
        
        # Clean up
        rm -f "$TMP_FILE" "$TMP_PERMISSIONS"
    else
        # Fallback to grep-based parsing if jq is not available
        echo "Using grep-based parsing (jq not available)"
        
        # Create temp file to store full details
        TMP_FILE=$(mktemp)
        echo "$sg_details" > "$TMP_FILE"
        
        # Process each rule
        protocol=""
        fromPort=""
        toPort=""
        cidr_found=false
        
        while IFS= read -r line; do
            if [[ $line == *"IpProtocol"* ]]; then
                # If we found a new IpProtocol, output any previous rule
                if [ "$cidr_found" = true ] && [ -n "$protocol" ]; then
                    if [ "$protocol" == "-1" ]; then
                        echo "  ALL PROTOCOLS AND PORTS open to the internet (0.0.0.0/0)"
                        port_list+="<li class=\"red\">ALL PROTOCOLS AND PORTS open to the internet</li>"
                    elif [ -n "$fromPort" ] && [ -n "$toPort" ]; then
                        if [ "$fromPort" == "$toPort" ]; then
                            echo "  $protocol Port $fromPort open to the internet (0.0.0.0/0)"
                            port_list+="<li class=\"red\">$protocol Port $fromPort open to the internet</li>"
                        else
                            echo "  $protocol Ports $fromPort-$toPort open to the internet (0.0.0.0/0)"
                            port_list+="<li class=\"red\">$protocol Ports $fromPort-$toPort open to the internet</li>"
                        fi
                    else
                        echo "  $protocol (port unspecified) open to the internet (0.0.0.0/0)"
                        port_list+="<li class=\"red\">$protocol (port unspecified) open to the internet</li>"
                    fi
                fi
                
                # Reset for new protocol
                protocol=$(echo "$line" | sed -E 's/.*: "([^"]+)".*/\1/')
                fromPort=""
                toPort=""
                cidr_found=false
            elif [[ $line == *"FromPort"* ]]; then
                fromPort=$(echo "$line" | sed -E 's/.*: ([0-9-]+).*/\1/')
            elif [[ $line == *"ToPort"* ]]; then
                toPort=$(echo "$line" | sed -E 's/.*: ([0-9-]+).*/\1/')
            elif [[ $line == *'"CidrIp": "0.0.0.0/0"'* ]]; then
                cidr_found=true
            fi
        done < "$TMP_FILE"
        
        # Process the last rule if we found one
        if [ "$cidr_found" = true ] && [ -n "$protocol" ]; then
            if [ "$protocol" == "-1" ]; then
                echo "  ALL PROTOCOLS AND PORTS open to the internet (0.0.0.0/0)"
                port_list+="<li class=\"red\">ALL PROTOCOLS AND PORTS open to the internet</li>"
            elif [ -n "$fromPort" ] && [ -n "$toPort" ]; then
                if [ "$fromPort" == "$toPort" ]; then
                    echo "  $protocol Port $fromPort open to the internet (0.0.0.0/0)"
                    port_list+="<li class=\"red\">$protocol Port $fromPort open to the internet</li>"
                else
                    echo "  $protocol Ports $fromPort-$toPort open to the internet (0.0.0.0/0)"
                    port_list+="<li class=\"red\">$protocol Ports $fromPort-$toPort open to the internet</li>"
                fi
            else
                echo "  $protocol (port unspecified) open to the internet (0.0.0.0/0)"
                port_list+="<li class=\"red\">$protocol (port unspecified) open to the internet</li>"
            fi
        fi
        
        # Clean up
        rm -f "$TMP_FILE"
    fi
    
    # If no specific ports were found but public rules exist
    if [ -z "$port_list" ] && [ $public_inbound -gt 0 ]; then
        echo "  Unspecified ports/protocols open to the internet (0.0.0.0/0)"
        port_list+="<li class=\"red\">Unspecified ports/protocols open to the internet</li>"
    fi
    
    # Debug output
    echo "Port list: $port_list"
    
    # Add the port list to the HTML output
    sg_check_details+="$port_list"
    sg_check_details+="</ul></ul>"
else
    echo "No public inbound rules (0.0.0.0/0) found in Security Group $SG_ID"
    sg_check_details+="<ul><li class=\"green\">No public inbound rules (0.0.0.0/0) found</li></ul>"
fi

sg_check_details+="</ul>"

# Add the security groups details to the report
add_check_item "$OUTPUT_FILE" "info" "1.2.5 - Ports, protocols, and services inventory" "$sg_check_details" "Review allowed ports, protocols, and services for business justification."

# Close the test section
close_section "$OUTPUT_FILE"

# Finalize the report
finalize_html_report "$OUTPUT_FILE" 1 0 0 1 "$REQUIREMENT_NUMBER"

echo "Test report has been generated: $OUTPUT_FILE"
echo "Please open this file in a browser to check the formatting"