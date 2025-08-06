#!/bin/bash
# PCI DSS v4.0.1 Requirement 4 - Protect Cardholder Data with Strong Cryptography During Transmission Over Open, Public Networks
# This script checks AWS resources for compliance with Requirement 4

# Source the shared HTML report library
source "$(dirname "$0")/pci_html_report_lib.sh"

# Set requirement-specific variables
REQUIREMENT_NUMBER="4"
REPORT_TITLE="PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="./reports"
OUTPUT_FILE="$OUTPUT_DIR/pci_req${REQUIREMENT_NUMBER}_report_${TIMESTAMP}.html"

# Counter variables
total_checks=0
passed_checks=0
failed_checks=0
warning_checks=0
info_checks=0

# Function to check if a specific AWS command can be executed
check_command_access() {
    local output_file="$1"
    local service="$2"
    local command="$3"
    local region="$4"
    
    if ! aws $service help | grep -q "$command"; then
        add_check_item "$output_file" "warning" "AWS Command Access" \
            "<p>The command '$service $command' doesn't appear to be valid. This script may be using outdated commands.</p>" \
            "Update the script or AWS CLI version."
        return 1
    fi
    
    # Try to execute the command with dry-run or list operations when possible
    case "$service $command" in
        "ec2 describe-vpcs"|"ec2 describe-subnets"|"ec2 describe-route-tables"|"ec2 describe-security-groups"|"elb describe-load-balancers"|"elbv2 describe-load-balancers"|"acm list-certificates"|"apigateway get-rest-apis"|"cloudfront list-distributions")
            if ! aws $service $command --region $region --max-items 1 &> /dev/null; then
                add_check_item "$output_file" "warning" "AWS API Access" \
                    "<p>Unable to execute '$service $command'. You may not have sufficient permissions.</p>" \
                    "Ensure your AWS credentials have the necessary permissions for $service $command."
                return 1
            fi
            ;;
        *)
            # For other commands, we'll just assume they'll work if the command exists
            ;;
    esac
    
    return 0
}

# Function to check TLS configurations for load balancers
check_elb_tls_configuration() {
    local region=$1
    local lb_arns
    local output="<p>ELB/ALB TLS Configuration:</p>"
    local tls_issue_found=false

    # 取得所有 Load Balancer
    lb_arns=$(aws elbv2 describe-load-balancers --region "$region" --query 'LoadBalancers[*].LoadBalancerArn' --output text 2>/dev/null)

    if [ -z "$lb_arns" ]; then
        output+="<div class=\"green\"><ul><li>No Load Balancers found in region $region</li></ul></div>"
        echo "$output"
        return
    fi

    for lb_arn in $lb_arns; do
        lb_name=$(echo "$lb_arn" | awk -F'/' '{print $3}')
        lb_output="<ul><li>Load Balancer: $lb_name<ul>"
        lb_tls_issue_found=false

        # 找 Listener
        listeners=$(aws elbv2 describe-listeners --region "$region" --load-balancer-arn "$lb_arn" \
            --query 'Listeners[*].{Port:Port,ARN:ListenerArn,SslPolicy:SslPolicy}' --output json 2>/dev/null)

        if [ -z "$listeners" ] || [ "$listeners" == "[]" ]; then
            lb_output+="<li class=\"yellow\">No Listeners found</li></ul></li></ul>"
            output+="<div class=\"yellow\">$lb_output</div>"
            tls_issue_found=true
            continue
        fi

        for listener in $(echo "$listeners" | jq -c '.[]'); do
            port=$(echo "$listener" | jq -r '.Port')
            ssl_policy=$(echo "$listener" | jq -r '.SslPolicy // "None"')
            listener_arn=$(echo "$listener" | jq -r '.ARN')

            lb_output+="<li>Listener Port: $port<br>SSL Policy: $ssl_policy<ul>"

            if [ "$ssl_policy" != "None" ]; then
                # 查 Policy 詳細內容 (Protocols, Ciphers)
                policy_details=$(aws elbv2 describe-ssl-policies --region "$region" --names "$ssl_policy" \
                    --query 'SslPolicies[0]' --output json 2>/dev/null)

                protocols=$(echo "$policy_details" | jq -r '.SslProtocols[]?' | paste -sd "," -)
                lb_output+="<li>Supported Protocols: $protocols</li>"

                # 列出所有 Ciphers
                ciphers=$(echo "$policy_details" | jq -r '.Ciphers[].Name')
                if [ -n "$ciphers" ]; then
                    lb_output+="<li>Supported Ciphers:<ul>"
                    while IFS= read -r cipher; do
                        lb_output+="<li>$cipher</li>"
                    done <<< "$ciphers"
                    lb_output+="</ul></li>"
                else
                    lb_output+="<li class=\"yellow\">No Ciphers found in policy</li>"
                    lb_tls_issue_found=true
                fi

                # 檢查弱 TLS 版本
                if [[ "$protocols" == *"TLSv1.0"* || "$protocols" == *"TLSv1.1"* ]]; then
                    lb_tls_issue_found=true
                    lb_output+="<li class=\"red\">WARNING: Weak TLS versions (TLS1.0/TLS1.1) allowed!</li>"
                else
                    lb_output+="<li class=\"green\">Only strong TLS versions (1.2/1.3) detected</li>"
                fi
            else
                lb_tls_issue_found=true
                lb_output+="<li class=\"yellow\">No SSL Policy (Listener not using HTTPS)</li>"
            fi

            lb_output+="</ul></li>"
        done

        lb_output+="</ul></li></ul>"

        # 單一 Load Balancer 的結果顏色包裝
        if [ "$lb_tls_issue_found" = true ]; then
            output+="<div class=\"red\">$lb_output</div>"
            tls_issue_found=true
        else
            output+="<div class=\"green\">$lb_output</div>"
        fi
    done

    echo "$output"
}

# Function to check for certificate expiration and maintain inventory
check_certificates_inventory() {
    local region="$1"
    local details=""
    local found_issues=false
    
    # Get all ACM certificates
    certs=$(aws acm list-certificates --region $region --query 'CertificateSummaryList[*].CertificateArn' --output text)
    
    if [ -n "$certs" ]; then
        details+="<p>Analysis of ACM certificates:</p><ul>"
        
        for cert_arn in $certs; do
            # Get certificate details
            cert_details=$(aws acm describe-certificate --region $region --certificate-arn $cert_arn)
            
            # Extract domain name and expiration date
            domain=$(echo "$cert_details" | grep "DomainName" | head -1 | awk -F'"' '{print $4}')
            expiration=$(echo "$cert_details" | grep "NotAfter" | awk -F'"' '{print $4}')
            
            # Calculate days until expiration
            if [ -n "$expiration" ]; then
                # Convert to timestamp
                expiration_ts=$(date -d "$expiration" +%s)
                current_ts=$(date +%s)
                days_remaining=$(( (expiration_ts - current_ts) / 86400 ))
                
                cert_info="<li>Certificate for $domain ($(echo $cert_arn | awk -F'/' '{print $2}'))<ul>"
                
                if [ $days_remaining -lt 30 ]; then
                    cert_info+="<li class=\"red\">Expires in $days_remaining days ($expiration)</li>"
                    found_issues=true
                elif [ $days_remaining -lt 90 ]; then
                    cert_info+="<li class=\"yellow\">Expires in $days_remaining days ($expiration)</li>"
                    found_issues=true
                else
                    cert_info+="<li class=\"green\">Expires in $days_remaining days ($expiration)</li>"
                fi
                
                # Check if renewal eligibility
                renewal_eligibility=$(echo "$cert_details" | grep "RenewalEligibility" | awk -F'"' '{print $4}')
                if [ "$renewal_eligibility" == "INELIGIBLE" ]; then
                    cert_info+="<li class=\"yellow\">Certificate is not eligible for automatic renewal</li>"
                    found_issues=true
                fi
                
                cert_info+="</ul></li>"
                
                # Only add certificates with issues or if we want to show all
                if [[ "$cert_info" == *"class=\"red\""* || "$cert_info" == *"class=\"yellow\""* ]]; then
                    details+="$cert_info"
                else
                    details+="<li>Certificate for $domain - No issues detected</li>"
                fi
            else
                details+="<li>Certificate for $domain - Unable to determine expiration date</li>"
            fi
        done
        
        details+="</ul>"
    else
        details+="<p>No ACM certificates found in region $region.</p>"
    fi
    
    # Return the results
    if [ "$found_issues" = true ]; then
        echo "$details"
        return 1
    else
        echo "<p class=\"green\">No certificate expiration issues detected in region $region.</p>"
        return 0
    fi
}

# Function to check for unencrypted data in transit
check_unencrypted_data_transit() {
    local region="$1"
    local details=""
    local found_issues=false
    
    # Check security groups for any rules that allow unencrypted services
    echo "Checking security groups for unencrypted services..."
    sg_list=$(aws ec2 describe-security-groups --region $region --query 'SecurityGroups[*].GroupId' --output text)
    
    if [ -n "$sg_list" ]; then
        details+="<p>Analysis of security groups for unencrypted services:</p><ul>"
        
        for sg_id in $sg_list; do
            # Get security group details
            sg_info=$(aws ec2 describe-security-groups --region $region --group-ids $sg_id)
            sg_name=$(echo "$sg_info" | grep "GroupName" | head -1 | awk -F'"' '{print $4}')
            vpc_id=$(echo "$sg_info" | grep "VpcId" | awk -F'"' '{print $4}')
            
            # Initialize security group details
            sg_details="<li>Security Group: $sg_id ($sg_name) in VPC $vpc_id<ul>"
            sg_has_issues=false
            
            # Check for HTTP (port 80)
            http_rules=$(echo "$sg_info" | grep -A 8 '"FromPort": 80' | grep -B 3 '"ToPort": 80')
            if [ -n "$http_rules" ]; then
                http_sources=$(echo "$http_rules" | grep "CidrIp" | awk -F'"' '{print $4}')
                if [ -n "$http_sources" ]; then
                    sg_details+="<li class=\"yellow\">Allows HTTP (port 80) from:<ul>"
                    for source in $http_sources; do
                        sg_details+="<li>$source</li>"
                    done
                    sg_details+="</ul></li>"
                    sg_has_issues=true
                    found_issues=true
                fi
            fi
            
            # Check for FTP (port 21)
            ftp_rules=$(echo "$sg_info" | grep -A 8 '"FromPort": 21' | grep -B 3 '"ToPort": 21')
            if [ -n "$ftp_rules" ]; then
                ftp_sources=$(echo "$ftp_rules" | grep "CidrIp" | awk -F'"' '{print $4}')
                if [ -n "$ftp_sources" ]; then
                    sg_details+="<li class=\"red\">Allows FTP (port 21) from:<ul>"
                    for source in $ftp_sources; do
                        sg_details+="<li>$source</li>"
                    done
                    sg_details+="</ul></li>"
                    sg_has_issues=true
                    found_issues=true
                fi
            fi
            
            # Check for Telnet (port 23)
            telnet_rules=$(echo "$sg_info" | grep -A 8 '"FromPort": 23' | grep -B 3 '"ToPort": 23')
            if [ -n "$telnet_rules" ]; then
                telnet_sources=$(echo "$telnet_rules" | grep "CidrIp" | awk -F'"' '{print $4}')
                if [ -n "$telnet_sources" ]; then
                    sg_details+="<li class=\"red\">Allows Telnet (port 23) from:<ul>"
                    for source in $telnet_sources; do
                        sg_details+="<li>$source</li>"
                    done
                    sg_details+="</ul></li>"
                    sg_has_issues=true
                    found_issues=true
                fi
            fi
            
            # Check for SMTP (port 25)
            smtp_rules=$(echo "$sg_info" | grep -A 8 '"FromPort": 25' | grep -B 3 '"ToPort": 25')
            if [ -n "$smtp_rules" ]; then
                smtp_sources=$(echo "$smtp_rules" | grep "CidrIp" | awk -F'"' '{print $4}')
                if [ -n "$smtp_sources" ]; then
                    sg_details+="<li class=\"yellow\">Allows SMTP (port 25) from:<ul>"
                    for source in $smtp_sources; do
                        sg_details+="<li>$source</li>"
                    done
                    sg_details+="</ul></li>"
                    sg_has_issues=true
                    found_issues=true
                fi
            fi
            
            # Check for POP3 (port 110)
            pop3_rules=$(echo "$sg_info" | grep -A 8 '"FromPort": 110' | grep -B 3 '"ToPort": 110')
            if [ -n "$pop3_rules" ]; then
                pop3_sources=$(echo "$pop3_rules" | grep "CidrIp" | awk -F'"' '{print $4}')
                if [ -n "$pop3_sources" ]; then
                    sg_details+="<li class=\"red\">Allows POP3 (port 110) from:<ul>"
                    for source in $pop3_sources; do
                        sg_details+="<li>$source</li>"
                    done
                    sg_details+="</ul></li>"
                    sg_has_issues=true
                    found_issues=true
                fi
            fi
            
            # Check for IMAP (port 143)
            imap_rules=$(echo "$sg_info" | grep -A 8 '"FromPort": 143' | grep -B 3 '"ToPort": 143')
            if [ -n "$imap_rules" ]; then
                imap_sources=$(echo "$imap_rules" | grep "CidrIp" | awk -F'"' '{print $4}')
                if [ -n "$imap_sources" ]; then
                    sg_details+="<li class=\"red\">Allows IMAP (port 143) from:<ul>"
                    for source in $imap_sources; do
                        sg_details+="<li>$source</li>"
                    done
                    sg_details+="</ul></li>"
                    sg_has_issues=true
                    found_issues=true
                fi
            fi
            
            sg_details+="</ul></li>"
            
            # Only add this security group to the details if it had issues
            if [ "$sg_has_issues" = true ]; then
                details+="$sg_details"
            fi
        done
        
        details+="</ul>"
    else
        details+="<p>No security groups found in region $region.</p>"
    fi
    
    # Return the results
    if [ "$found_issues" = true ]; then
        echo "$details"
        return 1
    else
        echo "<p class=\"green\">No security group rules allowing unencrypted services found in region $region.</p>"
        return 0
    fi
}

# Main function
main() {
    clear
    echo "PCI DSS v4.0.1 Requirement $REQUIREMENT_NUMBER Compliance Check Script"
    echo "==============================================================="
    
    # Prompt for AWS region
    if [ -z "$REGION" ]; then
		read -p "Enter AWS region to test (e.g., us-east-1): " REGION
		if [ -z "$REGION" ]; then
			REGION="us-east-1"
			echo -e "${YELLOW}Using default region: $REGION${NC}"
		fi
	fi

    
    # Create output directory if it doesn't exist
    mkdir -p "$OUTPUT_DIR"
    
    # Initialize HTML report
    initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE" "$REQUIREMENT_NUMBER" "$REGION"
    
    # Check necessary AWS commands
    add_section "$OUTPUT_FILE" "aws-commands" "AWS Command Verification" "none"
    echo "Checking AWS command access..."
    
    # List of required commands for PCI Requirement 4
    required_commands=(
        "ec2 describe-security-groups"
        "ec2 describe-vpcs"
        "elb describe-load-balancers"
        "elb describe-load-balancer-policies"
        "elbv2 describe-load-balancers"
        "elbv2 describe-listeners"
        "acm list-certificates"
        "acm describe-certificate"
        "cloudfront list-distributions"
        "cloudfront get-distribution"
        "apigateway get-rest-apis"
        "apigateway get-rest-api"
    )
    
    commands_ok=true
    for cmd in "${required_commands[@]}"; do
        service=$(echo $cmd | cut -d' ' -f1)
        command=$(echo $cmd | cut -d' ' -f2)
        
        echo "  Checking $service $command..."
        if ! check_command_access "$OUTPUT_FILE" "$service" "$command" "$REGION"; then
            commands_ok=false
        fi
    done
    
    if [ "$commands_ok" = false ]; then
        add_check_item "$OUTPUT_FILE" "warning" "AWS Commands Access Summary" \
            "<p>Some required AWS commands are not available. This may limit the effectiveness of the assessment.</p>" \
            "Ensure your AWS credentials have the necessary permissions for all required services."
        ((warning_checks++))
    else
        add_check_item "$OUTPUT_FILE" "pass" "AWS Commands Access Summary" \
            "<p>All required AWS commands are available.</p>"
        ((passed_checks++))
    fi
    ((total_checks++))
    
    close_section "$OUTPUT_FILE"
    
    # Section for Requirement 4.1
    add_section "$OUTPUT_FILE" "req-4.1" "Requirement 4.1: Processes and mechanisms for protecting cardholder data with strong cryptography during transmission over open, public networks are defined and understood." "none"
    
add_check_item "$OUTPUT_FILE" "warning" "4.1.1 - Security Policies and Operational Procedures" \
        "<p>This check requires manual verification of documentation and processes for protecting cardholder data during transmission.</p><p>According to PCI DSS Requirement 4.1.1 [cite: 1209, 1210], verify that all security policies and operational procedures for protecting cardholder data with strong cryptography during transmission are:</p><ul><li>Documented</li><li>Kept up to date</li><li>In use</li><li>Known to all affected parties</li></ul>" \
        "Ensure that security policies and operational procedures for transmission security are documented, maintained, and communicated to all relevant personnel."
    ((warning_checks++))
    ((total_checks++))
    
add_check_item "$OUTPUT_FILE" "warning" "4.1.2 - Defined Roles and Responsibilities" \
        "<p>This check requires manual verification that roles and responsibilities for performing transmission security activities are properly defined.</p><p>According to PCI DSS Requirement 4.1.2 [cite: 1218], verify that roles and responsibilities for protecting cardholder data during transmission are:</p><ul><li>Documented</li><li>Assigned to specific individuals or teams</li><li>Understood by the assigned individuals</li></ul>" \
        "Document and assign specific roles and responsibilities for managing cryptography, certificates, and transmission security."
    ((warning_checks++))
    ((total_checks++))
    
    close_section "$OUTPUT_FILE"
    
    # Section for Requirement 4.2
    add_section "$OUTPUT_FILE" "req-4.2" "Requirement 4.2: Strong cryptography and security protocols are implemented to safeguard PAN during transmission over open, public networks." "active"
    
    # Check 4.2.1 - TLS Implementation
    # Check 4.2.1 - TLS Implementation
	echo "Checking 4.2.1 - TLS Implementation..."
	tls_details=$(check_elb_tls_configuration "$REGION")

	if [[ "$tls_details" == *"class=\"red\""* || "$tls_details" == *"class=\"yellow\""* ]]; then
		add_check_item "$OUTPUT_FILE" "fail" "4.2.1 - TLS Implementation" \
			"<p>According to PCI DSS Requirement 4.2.1 [cite: 1232-1236], strong cryptography and security protocols must be implemented to safeguard PAN during transmission over open, public networks, including:</p><ul><li>Only trusted keys and certificates are accepted</li><li>The protocol supports only secure versions or configurations</li><li>The encryption strength is appropriate for the encryption methodology in use</li></ul>$tls_details" \
			"Implement strong cryptography and security protocols that provide strong encryption, meet industry best practices, and support only secure versions and configurations."
		((failed_checks++))
	else
		add_check_item "$OUTPUT_FILE" "pass" "4.2.1 - TLS Implementation" \
			"$tls_details"
		((passed_checks++))
	fi
	((total_checks++))

    
    # Check 4.2.1.1 - Certificate Inventory
    echo "Checking 4.2.1.1 - Certificate Inventory..."
    cert_details=$(check_certificates_inventory "$REGION")

    add_check_item "$OUTPUT_FILE" "info" "4.2.1.1 - Inventory of Trusted Keys and Certificates" \
        "<p>According to PCI DSS Requirement 4.2.1.1 [cite: 1262], an accurate inventory of the entity's trusted keys and certificates used to protect PAN during transmission must be maintained.</p>$cert_details" \
        "Maintain an inventory of all certificates used to protect PAN during transmission. Regularly review and update the inventory."
    ((info_checks++))
    ((total_checks++))
    
    # Check 4.2.2 - Prevent Unencrypted Data Transmission
    echo "Checking 4.2.2 - Prevent Unencrypted Data Transmission..."
    unencrypted_details=$(check_unencrypted_data_transit "$REGION")
    
    if [[ "$unencrypted_details" == *"class=\"red\""* || "$unencrypted_details" == *"class=\"yellow\""* ]]; then
        add_check_item "$OUTPUT_FILE" "fail" "Unencrypted Transmission Detection" \
            "<p>Analysis of potential unencrypted data transmission over open, public networks - this contradicts PCI DSS requirements for protecting cardholder data with strong cryptography during transmission.</p>$unencrypted_details" \
            "Replace unencrypted services with encrypted alternatives. If cleartext transmission is necessary, implement additional security controls."
        ((failed_checks++))
    else
        add_check_item "$OUTPUT_FILE" "pass" "4.2.2 - Prevent Unencrypted Data Transmission" \
            "$unencrypted_details"
        ((passed_checks++))
    fi
    ((total_checks++))
    
    
    # Note: PCI DSS v4.0.1 doesn't have a Requirement 4.3 section. The following sections were created in error
    # and have been removed to conform with the actual PCI DSS v4.0.1 requirements.
    
    # We proceed directly to Requirement 4.2.2 for Wireless Networks and End-user Messaging

    # Check 4.2.1.2 - Wireless Networks
    add_check_item "$OUTPUT_FILE" "warning" "4.2.1.2 - Wireless Networks Security" \
        "<p>This check requires manual verification of wireless networks security if applicable.</p><p>Verify that:</p><ul><li>Wireless networks transmitting PAN or connected to the CDE use industry best practices for authentication and transmission</li><li>Strong encryption is implemented for authentication and transmission</li></ul>" \
        "Implement industry best practices (e.g., IEEE 802.11i/WPA2, WPA3) for wireless networks if they transmit cardholder data or connect to the CDE."
    ((warning_checks++))
    ((total_checks++))
    
    # Check 4.2.2 - End-user Messaging Technologies
    add_check_item "$OUTPUT_FILE" "warning" "4.2.2 - End-user Messaging Technologies" \
        "<p>This check requires manual verification of PAN transmission through end-user messaging technologies.</p><p>Verify that PAN is secured with strong cryptography whenever it is sent via end-user messaging technologies including but not limited to:</p><ul><li>Email</li><li>Instant messaging</li><li>SMS/text</li><li>Chat</li></ul>" \
        "Ensure strong cryptography is used when sending PAN through any messaging technology. Consider using secure file transfer solutions instead of messaging for PAN transmission."
    ((warning_checks++))
    ((total_checks++))
    
    close_section "$OUTPUT_FILE"
    
    # Finalize the report
    finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"
    
    echo -e "\nCompliance check completed:"
    echo "Total checks: $total_checks"
    echo "Passed: $passed_checks"
    echo "Failed: $failed_checks"
    echo "Warnings: $warning_checks"
    echo -e "\nReport saved to: $OUTPUT_FILE"
    
    # Open the report if on a Mac
    if [[ "$OSTYPE" == "darwin"* ]]; then
        open "$OUTPUT_FILE"
    else
        echo "To view the report, open it in your web browser."
    fi
}

# Run the main function
main
