#!/bin/bash

# Script to generate a clear report of security groups with internet access
# Specifically addressing the issue where ports are not displayed in the report

# Set output colors for terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Define region - you can edit this or pass it as a parameter
REGION="${1:-us-east-1}"

echo "============================================="
echo "  PCI DSS 4.0 - Security Group Port Scanner"
echo "============================================="
echo ""
echo "Using region: $REGION"
echo ""

# Get all security groups
echo -e "${CYAN}Retrieving all security groups...${NC}"
ALL_SGS=$(aws ec2 describe-security-groups --region "$REGION" --output json)

# Create HTML report file
REPORT_FILE="./reports/security_group_port_report.html"
mkdir -p ./reports

# Create basic HTML structure
cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>PCI DSS 4.0 - Security Group Internet Access Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333366; }
        h2 { color: #336699; margin-top: 20px; }
        .warning { color: #cc0000; font-weight: bold; }
        .safe { color: #007700; font-weight: bold; }
        .group { margin: 20px 0; padding: 10px; border: 1px solid #dddddd; background: #f8f8f8; }
        .port-list { margin-left: 30px; }
        table { border-collapse: collapse; width: 100%; margin: 15px 0; }
        th, td { padding: 8px; text-align: left; border: 1px solid #dddddd; }
        th { background-color: #f2f2f2; }
        .all-ports { color: #cc0000; font-weight: bold; }
        .insecure { color: #cc0000; }
    </style>
</head>
<body>
    <h1>PCI DSS 4.0 - Security Group Internet Access Report</h1>
    <p>Report generated on $(date)</p>
    <p>AWS Region: $REGION</p>
    
    <h2>Security Groups with Internet Access (0.0.0.0/0)</h2>
EOF

# Process each security group
INTERNET_ACCESS_COUNT=0

echo "$ALL_SGS" | jq -c '.SecurityGroups[]' | while read -r sg; do
    SG_ID=$(echo "$sg" | jq -r '.GroupId')
    SG_NAME=$(echo "$sg" | jq -r '.GroupName')
    SG_VPC=$(echo "$sg" | jq -r '.VpcId')
    
    # Check if this SG has any rules with 0.0.0.0/0 access
    HAS_PUBLIC_ACCESS=$(echo "$sg" | jq '.IpPermissions[].IpRanges[] | select(.CidrIp == "0.0.0.0/0")' | wc -l)
    
    if [ "$HAS_PUBLIC_ACCESS" -gt 0 ]; then
        INTERNET_ACCESS_COUNT=$((INTERNET_ACCESS_COUNT + 1))
        echo -e "${RED}Security Group: $SG_ID ($SG_NAME) has internet access${NC}"
        
        # Add security group to HTML report
        cat >> "$REPORT_FILE" << EOF
        <div class="group">
            <h3>○ Security Group: $SG_ID ($SG_NAME)</h3>
            <p>VPC: $SG_VPC</p>
            <p class="warning">■ WARNING: Has $HAS_PUBLIC_ACCESS public inbound rules (0.0.0.0/0)</p>
            <p>■ Internet-accessible ports:</p>
            <div class="port-list">
                <table>
                    <tr>
                        <th>Protocol</th>
                        <th>Ports</th>
                        <th>Service</th>
                        <th>Risk Level</th>
                    </tr>
EOF
        
        # Process each permission with 0.0.0.0/0 access
        echo "$sg" | jq -c '.IpPermissions[]' | while read -r perm; do
            # Check if this permission has 0.0.0.0/0 access
            HAS_PUBLIC=$(echo "$perm" | jq '.IpRanges[] | select(.CidrIp == "0.0.0.0/0")' | wc -l)
            
            if [ "$HAS_PUBLIC" -gt 0 ]; then
                PROTOCOL=$(echo "$perm" | jq -r '.IpProtocol')
                
                # Handle all traffic case (-1)
                if [ "$PROTOCOL" == "-1" ]; then
                    echo -e "${RED}  ALL PROTOCOLS AND PORTS open to the internet${NC}"
                    cat >> "$REPORT_FILE" << EOF
                    <tr>
                        <td>ALL</td>
                        <td class="all-ports">ALL PORTS</td>
                        <td>All Services</td>
                        <td class="insecure">CRITICAL</td>
                    </tr>
EOF
                else
                    # Handle specific protocols
                    FROM_PORT=$(echo "$perm" | jq -r 'if has("FromPort") then .FromPort | tostring else "N/A" end')
                    TO_PORT=$(echo "$perm" | jq -r 'if has("ToPort") then .ToPort | tostring else "N/A" end')
                    
                    # Service identification
                    SERVICE=""
                    RISK="Medium"
                    
                    if [ "$PROTOCOL" == "tcp" ]; then
                        if [ "$FROM_PORT" == "$TO_PORT" ]; then
                            case $FROM_PORT in
                                22) SERVICE="SSH"; RISK="High" ;;
                                23) SERVICE="TELNET"; RISK="Critical (Insecure)" ;;
                                25) SERVICE="SMTP"; RISK="High" ;;
                                80) SERVICE="HTTP"; RISK="Medium" ;;
                                443) SERVICE="HTTPS"; RISK="Medium" ;;
                                3389) SERVICE="RDP"; RISK="High" ;;
                                3306) SERVICE="MySQL/MariaDB"; RISK="High" ;;
                                1433) SERVICE="MS SQL"; RISK="High" ;;
                                21) SERVICE="FTP"; RISK="Critical (Insecure)" ;;
                                *) SERVICE="" ;;
                            esac
                        fi
                    fi
                    
                    # Port display
                    PORT_DISPLAY=""
                    if [ "$FROM_PORT" == "$TO_PORT" ]; then
                        PORT_DISPLAY="$FROM_PORT"
                        echo -e "${RED}  $PROTOCOL Port $FROM_PORT ${SERVICE} open to the internet${NC}"
                    else
                        PORT_DISPLAY="$FROM_PORT-$TO_PORT"
                        echo -e "${RED}  $PROTOCOL Ports $FROM_PORT-$TO_PORT open to the internet${NC}"
                    fi
                    
                    # Add to report
                    RISK_CLASS=""
                    if [ "$RISK" == "Critical (Insecure)" ] || [ "$RISK" == "High" ]; then
                        RISK_CLASS="class=\"insecure\""
                    fi
                    
                    cat >> "$REPORT_FILE" << EOF
                    <tr>
                        <td>$PROTOCOL</td>
                        <td>$PORT_DISPLAY</td>
                        <td>$SERVICE</td>
                        <td $RISK_CLASS>$RISK</td>
                    </tr>
EOF
                fi
            fi
        done
        
        # Close the port table and add PCI DSS violation info
        cat >> "$REPORT_FILE" << EOF
                </table>
            </div>
            
            <p><strong>PCI DSS Violation:</strong> This security group configuration violates PCI DSS 4.0 Requirement 1.2.1 and 1.3.1 by allowing unrestricted access from the internet.</p>
            
            <p><strong>Remediation:</strong></p>
            <ul>
                <li>Restrict access to specific IP addresses/ranges</li>
                <li>Remove unnecessary open ports</li>
                <li>Follow the principle of least privilege</li>
                <li>Document business justification for any required internet access</li>
            </ul>
        </div>
EOF
    fi
done

# Add summary to HTML
cat >> "$REPORT_FILE" << EOF
    <h2>Summary</h2>
    <p>Total security groups with internet access (0.0.0.0/0): $INTERNET_ACCESS_COUNT</p>
    <p>PCI DSS 4.0 Requirement 1 status: 
EOF

if [ "$INTERNET_ACCESS_COUNT" -gt 0 ]; then
    echo "<span class=\"warning\">FAILED</span>" >> "$REPORT_FILE"
else
    echo "<span class=\"safe\">PASSED</span>" >> "$REPORT_FILE"
fi

# Close HTML
cat >> "$REPORT_FILE" << EOF
    </p>
    <p>This report specifically checks for internet access to security groups. A complete PCI DSS Requirement 1 assessment requires additional checks.</p>
</body>
</html>
EOF

echo ""
if [ "$INTERNET_ACCESS_COUNT" -gt 0 ]; then
    echo -e "${RED}Found $INTERNET_ACCESS_COUNT security groups with internet access.${NC}"
    echo -e "${RED}PCI DSS 4.0 Requirement 1 status: FAILED${NC}"
else
    echo -e "${GREEN}No security groups with internet access found.${NC}"
    echo -e "${GREEN}PCI DSS 4.0 Requirement 1 status: PASSED${NC}"
fi

echo ""
echo "Report generated: $REPORT_FILE"
echo ""
