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
    local region="$1"
    local details=""
    local found_issues=false
    
    # Check Classic Load Balancers
    echo "Checking Classic Load Balancers..."
    classic_lbs=$(aws elb describe-load-balancers --region $region --query 'LoadBalancerDescriptions[*].LoadBalancerName' --output text)
    
    if [ -n "$classic_lbs" ]; then
        details+="<p>Analysis of Classic Load Balancers:</p><ul>"
        
        for lb in $classic_lbs; do
            # Get listener configurations
            listeners=$(aws elb describe-load-balancers --region $region --load-balancer-name $lb --query 'LoadBalancerDescriptions[0].ListenerDescriptions[*].Listener')
            
            # Check if this is a HTTPS/SSL LB
            if [[ "$listeners" == *"HTTPS"* || "$listeners" == *"SSL"* ]]; then
                lb_details="<li>Load Balancer: $lb<ul>"
                
                # Get SSL policies for this LB
                policies=$(aws elb describe-load-balancer-policies --region $region --load-balancer-name $lb)
                
                # Find SSL negotiation policies
                ssl_policies=$(echo "$policies" | grep -A 2 "SSLNegotiationPolicyType" | grep "PolicyName" | awk -F'"' '{print $4}')
                
                if [ -z "$ssl_policies" ]; then
                    # No custom SSL policy, using default
                    lb_details+="<li class=\"red\">Using default SSL policy which may not enforce strong TLS.</li>"
                    found_issues=true
                else
                    for policy in $ssl_policies; do
                        # Get policy details
                        policy_details=$(aws elb describe-load-balancer-policies --region $region --load-balancer-name $lb --policy-names $policy)
                        
                        # Check if weak protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1) are enabled
                        if [[ "$policy_details" == *"Protocol-SSLv2"* && "$policy_details" == *"true"* ]]; then
                            lb_details+="<li class=\"red\">Policy $policy allows insecure SSLv2 protocol</li>"
                            found_issues=true
                        fi
                        
                        if [[ "$policy_details" == *"Protocol-SSLv3"* && "$policy_details" == *"true"* ]]; then
                            lb_details+="<li class=\"red\">Policy $policy allows insecure SSLv3 protocol</li>"
                            found_issues=true
                        fi
                        
                        if [[ "$policy_details" == *"Protocol-TLSv1"* && "$policy_details" == *"true"* ]]; then
                            lb_details+="<li class=\"yellow\">Policy $policy allows TLSv1.0 protocol (deprecated)</li>"
                            found_issues=true
                        fi
                        
                        if [[ "$policy_details" == *"Protocol-TLSv1.1"* && "$policy_details" == *"true"* ]]; then
                            lb_details+="<li class=\"yellow\">Policy $policy allows TLSv1.1 protocol (deprecated)</li>"
                            found_issues=true
                        fi
                        
                        # Check for weak ciphers
                        weak_ciphers=$(echo "$policy_details" | grep -E 'RC4|DES|MD5|EXPORT' | grep -B 1 "true" | grep "Name" | awk -F'"' '{print $4}')
                        if [ -n "$weak_ciphers" ]; then
                            lb_details+="<li class=\"red\">Policy $policy allows weak ciphers:<ul>"
                            for cipher in $weak_ciphers; do
                                lb_details+="<li>$cipher</li>"
                            done
                            lb_details+="</ul></li>"
                            found_issues=true
                        fi
                    done
                fi
                
                lb_details+="</ul></li>"
                
                # Only add this LB to the details if it had issues
                if [[ "$lb_details" == *"class=\"red\""* || "$lb_details" == *"class=\"yellow\""* ]]; then
                    details+="$lb_details"
                else
                    details+="<li>Load Balancer: $lb - No TLS issues detected</li>"
                fi
            else
                # Not an HTTPS/SSL load balancer, so not relevant for this check
                details+="<li>Load Balancer: $lb - Not using HTTPS/SSL (not applicable)</li>"
            fi
        done
        
        details+="</ul>"
    else
        details+="<p>No Classic Load Balancers found in region $region.</p>"
    fi
    
    # Check Application Load Balancers
    echo "Checking Application Load Balancers..."
    albs=$(aws elbv2 describe-load-balancers --region $region --query 'LoadBalancers[?Type==`application`].LoadBalancerArn' --output text)
    
    if [ -n "$albs" ]; then
        details+="<p>Analysis of Application Load Balancers:</p><ul>"
        
        for alb_arn in $albs; do
            alb_name=$(echo "$alb_arn" | awk -F'/' '{print $3}')
            
            # Get listener configurations
            listeners=$(aws elbv2 describe-listeners --region $region --load-balancer-arn $alb_arn --query 'Listeners[*]')
            
            # Check if this ALB has HTTPS listeners
            https_listeners=$(echo "$listeners" | grep -A 2 '"Protocol": "HTTPS"' | grep "ListenerArn" | awk -F'"' '{print $4}')
            
            if [ -n "$https_listeners" ]; then
                alb_details="<li>Application Load Balancer: $alb_name<ul>"
                
                for listener_arn in $https_listeners; do
                    # Get SSL policy for this listener
                    ssl_policy=$(aws elbv2 describe-listeners --region $region --listener-arns $listener_arn --query 'Listeners[0].SslPolicy' --output text)
                    
                    # Check if using a deprecated or weak policy
                    case "$ssl_policy" in
                        "ELBSecurityPolicy-TLS-1-0-2015-04")
                            alb_details+="<li class=\"red\">Listener $(echo $listener_arn | awk -F'/' '{print $NF}') uses deprecated policy $ssl_policy that allows TLSv1.0</li>"
                            found_issues=true
                            ;;
                        "ELBSecurityPolicy-TLS-1-1-2017-01")
                            alb_details+="<li class=\"yellow\">Listener $(echo $listener_arn | awk -F'/' '{print $NF}') uses policy $ssl_policy that allows TLSv1.1 (deprecated)</li>"
                            found_issues=true
                            ;;
                        "ELBSecurityPolicy-2016-08"|"ELBSecurityPolicy-FS-2018-06"|"ELBSecurityPolicy-FS-1-2-2019-08"|"ELBSecurityPolicy-FS-1-1-2019-08"|"ELBSecurityPolicy-2015-05")
                            # These are recent policies that are considered secure
                            alb_details+="<li class=\"green\">Listener $(echo $listener_arn | awk -F'/' '{print $NF}') uses secure policy $ssl_policy</li>"
                            ;;
                        *)
                            # For custom or unknown policies, flag as warning
                            alb_details+="<li class=\"yellow\">Listener $(echo $listener_arn | awk -F'/' '{print $NF}') uses custom or unknown policy $ssl_policy - manual verification needed</li>"
                            found_issues=true
                            ;;
                    esac
                done
                
                alb_details+="</ul></li>"
                
                # Only add this ALB to the details if it had issues or if we want to show all
                if [[ "$alb_details" == *"class=\"red\""* || "$alb_details" == *"class=\"yellow\""* ]]; then
                    details+="$alb_details"
                else
                    details+="<li>Application Load Balancer: $alb_name - Using secure TLS configurations</li>"
                fi
            else
                # Not using HTTPS
                details+="<li>Application Load Balancer: $alb_name - Not using HTTPS (not applicable)</li>"
            fi
        done
        
        details+="</ul>"
    else
        details+="<p>No Application Load Balancers found in region $region.</p>"
    fi
    
    # Check Network Load Balancers with TLS listeners
    echo "Checking Network Load Balancers..."
    nlbs=$(aws elbv2 describe-load-balancers --region $region --query 'LoadBalancers[?Type==`network`].LoadBalancerArn' --output text)
    
    if [ -n "$nlbs" ]; then
        details+="<p>Analysis of Network Load Balancers:</p><ul>"
        
        for nlb_arn in $nlbs; do
            nlb_name=$(echo "$nlb_arn" | awk -F'/' '{print $3}')
            
            # Get listener configurations
            listeners=$(aws elbv2 describe-listeners --region $region --load-balancer-arn $nlb_arn --query 'Listeners[*]')
            
            # Check if this NLB has TLS listeners
            tls_listeners=$(echo "$listeners" | grep -A 2 '"Protocol": "TLS"' | grep "ListenerArn" | awk -F'"' '{print $4}')
            
            if [ -n "$tls_listeners" ]; then
                nlb_details="<li>Network Load Balancer: $nlb_name<ul>"
                
                for listener_arn in $tls_listeners; do
                    # Get SSL policy for this listener
                    ssl_policy=$(aws elbv2 describe-listeners --region $region --listener-arns $listener_arn --query 'Listeners[0].SslPolicy' --output text)
                    
                    # Check if using a deprecated or weak policy
                    case "$ssl_policy" in
                        *"TLS-1-0"*)
                            nlb_details+="<li class=\"red\">Listener $(echo $listener_arn | awk -F'/' '{print $NF}') uses deprecated policy $ssl_policy that allows TLSv1.0</li>"
                            found_issues=true
                            ;;
                        *"TLS-1-1"*)
                            nlb_details+="<li class=\"yellow\">Listener $(echo $listener_arn | awk -F'/' '{print $NF}') uses policy $ssl_policy that allows TLSv1.1 (deprecated)</li>"
                            found_issues=true
                            ;;
                        *)
                            # For other policies, assume they're secure
                            nlb_details+="<li class=\"green\">Listener $(echo $listener_arn | awk -F'/' '{print $NF}') uses policy $ssl_policy</li>"
                            ;;
                    esac
                done
                
                nlb_details+="</ul></li>"
                
                # Only add this NLB to the details if it had issues
                if [[ "$nlb_details" == *"class=\"red\""* || "$nlb_details" == *"class=\"yellow\""* ]]; then
                    details+="$nlb_details"
                else
                    details+="<li>Network Load Balancer: $nlb_name - Using secure TLS configurations</li>"
                fi
            else
                # Not using TLS
                details+="<li>Network Load Balancer: $nlb_name - Not using TLS (not applicable)</li>"
            fi
        done
        
        details+="</ul>"
    else
        details+="<p>No Network Load Balancers found in region $region.</p>"
    fi
    
    # Check CloudFront Distributions
    echo "Checking CloudFront Distributions..."
    cf_distributions=$(aws cloudfront list-distributions --region $region --query 'DistributionList.Items[*].Id' --output text 2>/dev/null)
    
    # If the command failed (CloudFront is global but accessed from us-east-1), try again with us-east-1
    if [ $? -ne 0 ]; then
        cf_distributions=$(aws cloudfront list-distributions --region us-east-1 --query 'DistributionList.Items[*].Id' --output text 2>/dev/null)
    fi
    
    if [ -n "$cf_distributions" ]; then
        details+="<p>Analysis of CloudFront Distributions:</p><ul>"
        
        for dist_id in $cf_distributions; do
            # Get distribution config
            if ! dist_config=$(aws cloudfront get-distribution --region us-east-1 --id $dist_id 2>/dev/null); then
                dist_config=$(aws cloudfront get-distribution --region $region --id $dist_id 2>/dev/null)
            fi
            
            # Extract viewer certificate info
            minimum_protocol_version=$(echo "$dist_config" | grep -A 5 "ViewerCertificate" | grep "MinimumProtocolVersion" | awk -F'"' '{print $4}')
            
            if [ -n "$minimum_protocol_version" ]; then
                dist_details="<li>CloudFront Distribution: $dist_id<ul>"
                
                # Check TLS protocol version
                case "$minimum_protocol_version" in
                    "SSLv3")
                        dist_details+="<li class=\"red\">Uses insecure minimum protocol version: $minimum_protocol_version</li>"
                        found_issues=true
                        ;;
                    "TLSv1")
                        dist_details+="<li class=\"red\">Uses deprecated minimum protocol version: $minimum_protocol_version</li>"
                        found_issues=true
                        ;;
                    "TLSv1_2016")
                        dist_details+="<li class=\"red\">Uses deprecated minimum protocol version: $minimum_protocol_version (TLSv1)</li>"
                        found_issues=true
                        ;;
                    "TLSv1.1_2016")
                        dist_details+="<li class=\"yellow\">Uses deprecated minimum protocol version: $minimum_protocol_version (TLSv1.1)</li>"
                        found_issues=true
                        ;;
                    *)
                        # TLSv1.2 or higher is good
                        dist_details+="<li class=\"green\">Uses secure minimum protocol version: $minimum_protocol_version</li>"
                        ;;
                esac
                
                dist_details+="</ul></li>"
                
                # Only add this distribution to the details if it had issues
                if [[ "$dist_details" == *"class=\"red\""* || "$dist_details" == *"class=\"yellow\""* ]]; then
                    details+="$dist_details"
                else
                    details+="<li>CloudFront Distribution: $dist_id - Using secure TLS configuration</li>"
                fi
            else
                details+="<li>CloudFront Distribution: $dist_id - Unable to determine TLS configuration</li>"
            fi
        done
        
        details+="</ul>"
    else
        details+="<p>No CloudFront Distributions found.</p>"
    fi
    
    # Check API Gateway APIs
    echo "Checking API Gateway APIs..."
    apis=$(aws apigateway get-rest-apis --region $region --query 'items[*].id' --output text 2>/dev/null)
    
    if [ -n "$apis" ]; then
        details+="<p>Analysis of API Gateway APIs:</p><ul>"
        
        for api_id in $apis; do
            # Get API details
            api_name=$(aws apigateway get-rest-api --region $region --rest-api-id $api_id --query 'name' --output text)
            
            # Get security policy
            security_policy=$(aws apigateway get-rest-api --region $region --rest-api-id $api_id --query 'securityPolicy' --output text)
            
            api_details="<li>API Gateway: $api_name ($api_id)<ul>"
            
            if [ "$security_policy" == "TLS_1_0" ]; then
                api_details+="<li class=\"red\">Uses deprecated security policy: $security_policy</li>"
                found_issues=true
            elif [ "$security_policy" == "TLS_1_1" ]; then
                api_details+="<li class=\"yellow\">Uses deprecated security policy: $security_policy</li>"
                found_issues=true
            elif [ "$security_policy" == "TLS_1_2" ]; then
                api_details+="<li class=\"green\">Uses secure security policy: $security_policy</li>"
            else
                api_details+="<li class=\"yellow\">Unknown security policy: $security_policy</li>"
                found_issues=true
            fi
            
            api_details+="</ul></li>"
            
            # Only add this API to the details if it had issues
            if [[ "$api_details" == *"class=\"red\""* || "$api_details" == *"class=\"yellow\""* ]]; then
                details+="$api_details"
            else
                details+="<li>API Gateway: $api_name ($api_id) - Using secure TLS configuration</li>"
            fi
        done
        
        details+="</ul>"
    else
        details+="<p>No API Gateway APIs found in region $region.</p>"
    fi
    
    # Return the results
    if [ "$found_issues" = true ]; then
        echo "$details"
        return 1
    else
        echo "<p class=\"green\">No TLS configuration issues detected across load balancers, CloudFront distributions, and API Gateway APIs in region $region.</p>"
        return 0
    fi
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
