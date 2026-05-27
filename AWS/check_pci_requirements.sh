#!/bin/bash
# 整合產出 PCI DSS AWS 稽核結果的 HTML 報告 (供 gen_clean_summary_aws.py 解析)

REPORT_DIR="./reports"
mkdir -p "$REPORT_DIR"
HTML_FILE="${REPORT_DIR}/pci_req_raw.html"

# 獲取當前 AWS Account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
ASSESSED_BY=$(aws sts get-caller-identity --query Arn --output text 2>/dev/null)
if [ -z "$ACCOUNT_ID" ]; then
    echo "Error: 無法取得 AWS Account ID，請確認 AWS CLI 是否已設定正確。"
    exit 1
fi

DATE_STR=$(date -u +"%a %b %d %H:%M:%S UTC %Y")

echo "開始執行 PCI DSS AWS 項目稽核與整合..."

read -p "Enter AWS region to test (e.g., ap-northeast-1) [Press Enter to use AWS config]: " INPUT_REGION
if [ -n "$INPUT_REGION" ]; then
    REGION="$INPUT_REGION"
else
    REGION=$(aws configure get region 2>/dev/null)
    [ -z "$REGION" ] && REGION="ap-northeast-1"
    echo "未輸入區域，使用 AWS CLI 預設區域: $REGION"
fi

cat << EOF > "$HTML_FILE"
<!DOCTYPE html>
<html>
<head><title>PCI DSS Output</title></head>
<body>
<div class="info-table">
<table>
<tr><th>AWS Account</th><td>${ACCOUNT_ID}</td></tr>
<tr><th>AWS Region</th><td>${REGION}</td></tr>
<tr><th>Assessment Date</th><td>${DATE_STR}</td></tr>
<tr><th>Assessed By</th><td>${ASSESSED_BY}</td></tr>
</table>
</div>
EOF

function report_item() {
    local keyword="$1"
    local status="$2"
    local message="$3"
    local recommendation="$4"
    local status_upper=$(echo "$status" | tr '[:lower:]' '[:upper:]')
    local color_class=""
    
    case "$status" in
        "pass") color_class="green" ;;
        "fail") color_class="red" ;;
        "warning") color_class="yellow" ;;
        "info") color_class="blue" ;;
        *) color_class="gray" ;;
    esac
    
    # 寫入符合 Python bs4 爬蟲預期的 HTML 結構
    cat << EOF >> "$HTML_FILE"
<div class="check-item ${status}">
    <h3><span class="${color_class}"><span class="status-label">[${status_upper}]</span></span> ${keyword}</h3>
    <div>${message}</div>
EOF
    if [ -n "$recommendation" ]; then
        cat << EOF >> "$HTML_FILE"
    <div class="recommendation">
        <strong>Recommendation:</strong> ${recommendation}
    </div>
EOF
    fi
    cat << EOF >> "$HTML_FILE"
</div>
EOF
    echo "[${status_upper}] ${keyword}"
}


TARGET_VPCS=$(aws ec2 describe-vpcs --region "$REGION" --query 'Vpcs[*].VpcId' --output text 2>/dev/null)
if [ -z "$TARGET_VPCS" ]; then TARGET_VPCS="None"; fi

# === 1.2.3 - Network Peering Connections ===
echo "Checking 1.2.3 - Network Peering Connections..."
peering_connections=$(aws ec2 describe-vpc-peering-connections --region "$REGION" --query 'VpcPeeringConnections[*]' --output json 2>/dev/null)
peering_details="<p>VPC Peering Connections in region $REGION:</p><ul>"
if [ -z "$peering_connections" ] || [ "$peering_connections" == "[]" ]; then
    peering_details+="<li class=\"green\">No VPC Peering Connections found</li></ul>"
    report_item "1.2.3 - Network Peering Connections" "pass" "$peering_details" "No VPC Peering Connections were detected in this region. No additional peering-related risks identified."
else
    for row in $(echo "$peering_connections" | jq -c '.[]'); do
        pcx_id=$(echo "$row" | jq -r '.VpcPeeringConnectionId')
        status=$(echo "$row" | jq -r '.Status.Code')
        accepter_vpc=$(echo "$row" | jq -r '.AccepterVpcInfo.VpcId')
        requester_vpc=$(echo "$row" | jq -r '.RequesterVpcInfo.VpcId')
        tags=$(echo "$row" | jq -r '.Tags[]?.Value' | paste -sd "," -)
        [ -z "$tags" ] && tags="(No Tags)"
        peering_details+="<li>Peering ID: $pcx_id , Tags: $tags<br>Status: $status<br>Accepter VPC: $accepter_vpc<br>Requester VPC: $requester_vpc</li>"
    done
    peering_details+="</ul>"
    report_item "1.2.3 - Network Peering Connections" "warning" "$peering_details" "Verify all VPC Peering Connections are authorized and have proper security controls (NACLs, Security Groups, Route Tables)."
fi

# === 1.2.6 - Security features for insecure services/protocols ===
echo "Checking 1.2.6 - Security features for insecure services/protocols..."
insecure_services=false
insecure_details="<p>Analysis of insecure services/protocols in security groups:</p><ul>"
for vpc_id in $TARGET_VPCS; do
    [ "$vpc_id" == "None" ] && continue
    sg_list=$(aws ec2 describe-security-groups --region "$REGION" --filters "Name=vpc-id,Values=$vpc_id" --query 'SecurityGroups[*].GroupId' --output text 2>/dev/null)
    [ -z "$sg_list" ] && continue
    insecure_details+="<li>VPC: $vpc_id</li><ul>"
    for sg_id in $sg_list; do
        sg_details=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$sg_id" 2>/dev/null)
        sg_name=$(echo "$sg_details" | grep "GroupName" | head -1 | awk -F '"' '{print $4}')
        sg_found_insecure=false
        sg_insecure_list="<ul>"
        
        telnet_check=$(echo "$sg_details" | grep -A 5 '"FromPort": 23' | grep -c '"ToPort": 23')
        if [ $telnet_check -gt 0 ]; then
            telnet_sources=$(echo "$sg_details" | grep -A 10 '"FromPort": 23' | grep -B 5 '"ToPort": 23' | grep "CidrIp" | awk -F '"' '{print $4}')
            sg_insecure_list+="<li class=\"red\">Allows Telnet (port 23) - Insecure cleartext protocol from:</li><ul>"
            for source in $telnet_sources; do sg_insecure_list+="<li>$source</li>"; done
            sg_insecure_list+="</ul>"
            insecure_services=true; sg_found_insecure=true
        fi
        
        ftp_check=$(echo "$sg_details" | grep -A 5 '"FromPort": 21' | grep -c '"ToPort": 21')
        if [ $ftp_check -gt 0 ]; then
            ftp_sources=$(echo "$sg_details" | grep -A 10 '"FromPort": 21' | grep -B 5 '"ToPort": 21' | grep "CidrIp" | awk -F '"' '{print $4}')
            sg_insecure_list+="<li class=\"red\">Allows FTP (port 21) - Insecure cleartext protocol from:</li><ul>"
            for source in $ftp_sources; do sg_insecure_list+="<li>$source</li>"; done
            sg_insecure_list+="</ul>"
            insecure_services=true; sg_found_insecure=true
        fi
        
        sql_check=$(echo "$sg_details" | grep -A 5 '"FromPort": 1433' | grep -c '"ToPort": 1433')
        if [ $sql_check -gt 0 ]; then
            sql_sources=$(echo "$sg_details" | grep -A 10 '"FromPort": 1433' | grep -B 5 '"ToPort": 1433' | grep "CidrIp" | awk -F '"' '{print $4}')
            sg_insecure_list+="<li class=\"yellow\">Allows SQL Server (port 1433) - Ensure encryption is in use from:</li><ul>"
            for source in $sql_sources; do sg_insecure_list+="<li>$source</li>"; done
            sg_insecure_list+="</ul>"
            insecure_services=true; sg_found_insecure=true
        fi
        
        mysql_check=$(echo "$sg_details" | grep -A 5 '"FromPort": 3306' | grep -c '"ToPort": 3306')
        if [ $mysql_check -gt 0 ]; then
            mysql_sources=$(echo "$sg_details" | grep -A 10 '"FromPort": 3306' | grep -B 5 '"ToPort": 3306' | grep "CidrIp" | awk -F '"' '{print $4}')
            sg_insecure_list+="<li class=\"yellow\">Allows MySQL/MariaDB (port 3306) - Ensure encryption is in use from:</li><ul>"
            for source in $mysql_sources; do sg_insecure_list+="<li>$source</li>"; done
            sg_insecure_list+="</ul>"
            insecure_services=true; sg_found_insecure=true
        fi
        
        samba_check=$(echo "$sg_details" | grep -A 5 '"FromPort": 445' | grep -c '"ToPort": 445')
        if [ $samba_check -gt 0 ]; then
            samba_sources=$(echo "$sg_details" | grep -A 10 '"FromPort": 445' | grep -B 5 '"ToPort": 445' | grep "CidrIp" | awk -F '"' '{print $4}')
            sg_insecure_list+="<li class=\"yellow\">Allows SAMBA Service (port 445) - Ensure encryption is in use from:</li><ul>"
            for source in $samba_sources; do sg_insecure_list+="<li>$source</li>"; done
            sg_insecure_list+="</ul>"
            insecure_services=true; sg_found_insecure=true
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
    report_item "1.2.6 - Security features for insecure services/protocols" "pass" "<p class=\"green\">No common insecure services/protocols detected in security groups</p>" "No common insecure services/protocols detected in security groups. All examined security groups appear to be using secure services and protocols, or have appropriate restrictions in place."
else
    report_item "1.2.6 - Security features for insecure services/protocols" "warning" "$insecure_details" "Per PCI DSS requirement 1.2.6, security features must be defined and implemented for all services, protocols, and ports that are in use and considered to be insecure. Implement additional security features or remove insecure services. If insecure services must be used, document business justification and implement additional security features to mitigate risk such as restricting source IPs, implementing TLS, or using encrypted tunnels."
fi

# === 1.3.1 - Inbound traffic to CDE restriction ===
echo "Checking 1.3.1 - Inbound traffic to CDE restriction..."
inbound_details="<p>Analysis of inbound traffic controls for potential CDE subnets:</p><h4>NACL Rules</h4><ul>"
overall_warning=false
for vpc_id in $TARGET_VPCS; do
    [ "$vpc_id" == "None" ] && continue
    inbound_details+="<li>VPC: $vpc_id</li><ul>"
    subnets=$(aws ec2 describe-subnets --region "$REGION" --filters "Name=vpc-id,Values=$vpc_id" --query 'Subnets[*].SubnetId' --output text 2>/dev/null)
    for subnet_id in $subnets; do
        inbound_details+="<li>Subnet: $subnet_id</li><ul>"
        nacl_id=$(aws ec2 describe-network-acls --region "$REGION" --filters "Name=association.subnet-id,Values=$subnet_id" --query 'NetworkAcls[0].NetworkAclId' --output text 2>/dev/null)
        if [ -z "$nacl_id" ] || [ "$nacl_id" == "None" ]; then
            inbound_details+="<li class=\"yellow\">No NACL associated with this subnet</li>"
            overall_warning=true; continue
        fi
        inbound_details+="<li>Associated NACL: $nacl_id</li>"
        permissive_rules=$(aws ec2 describe-network-acls --region "$REGION" --network-acl-ids "$nacl_id" --query 'NetworkAcls[0].Entries[?Egress==`false` && CidrBlock==`0.0.0.0/0` && RuleAction==`allow`]' --output text 2>/dev/null)
        if [ -n "$permissive_rules" ]; then
            inbound_details+="<li class=\"red\">WARNING: NACL has permissive inbound rules (0.0.0.0/0 allow)</li><li><pre>$permissive_rules</pre></li>"
            overall_warning=true
        else
            inbound_details+="<li class=\"green\">NACL has properly restricted inbound rules</li>"
        fi
        inbound_details+="</ul>"
    done
    inbound_details+="</ul>"
done
inbound_details+="</ul><h4>Security Group Rules</h4><ul>"
for vpc_id in $TARGET_VPCS; do
    [ "$vpc_id" == "None" ] && continue
    inbound_details+="<li>VPC: $vpc_id</li><ul>"
    sg_list=$(aws ec2 describe-security-groups --region "$REGION" --filters "Name=vpc-id,Values=$vpc_id" --query 'SecurityGroups[*].GroupId' --output text 2>/dev/null)
    [ -z "$sg_list" ] && continue
    for sg_id in $sg_list; do
        sg_details=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$sg_id" --output json 2>/dev/null)
        sg_name=$(echo "$sg_details" | jq -r '.SecurityGroups[0].GroupName')
        inbound_details+="<li>Security Group: $sg_id ($sg_name)</li><ul>"
        public_inbound=$(echo "$sg_details" | jq '[.SecurityGroups[].IpPermissions[] | select(.IpRanges[].CidrIp=="0.0.0.0/0")] | length')
        if [ "$public_inbound" -gt 0 ]; then
            inbound_details+="<li class=\"red\">WARNING: $public_inbound public inbound rules (0.0.0.0/0)</li>"
            public_rules=$(echo "$sg_details" | jq -r '.SecurityGroups[].IpPermissions[] | select(.IpRanges[].CidrIp=="0.0.0.0/0") | "Protocol: \(.IpProtocol) | FromPort: \(.FromPort // "all") | ToPort: \(.ToPort // "all")"' 2>/dev/null)
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

if [ "$overall_warning" = true ]; then
    report_item "1.3.1 - Inbound traffic to CDE restriction" "warning" "$inbound_details" "Review NACL and Security Group rules. Restrict any rules allowing 0.0.0.0/0 unless explicitly required and documented. Ensure inbound traffic to the CDE is limited to only necessary, secure sources."
else
    report_item "1.3.1 - Inbound traffic to CDE restriction" "pass" "$inbound_details" "All examined NACLs and Security Groups have properly restricted inbound rules. No public (0.0.0.0/0) access detected."
fi

# === 1.3.2 - Outbound traffic from CDE restriction ===
echo "Checking 1.3.2 - Outbound traffic from CDE restriction..."
outbound_details="<p>Analysis of outbound traffic controls for potential CDE subnets:</p><h4>NACL Rules</h4><ul>"
overall_warning=false
for vpc_id in $TARGET_VPCS; do
    [ "$vpc_id" == "None" ] && continue
    outbound_details+="<li>VPC: $vpc_id</li><ul>"
    subnets=$(aws ec2 describe-subnets --region "$REGION" --filters "Name=vpc-id,Values=$vpc_id" --query 'Subnets[*].SubnetId' --output text 2>/dev/null)
    for subnet_id in $subnets; do
        outbound_details+="<li>Subnet: $subnet_id</li><ul>"
        nacl_id=$(aws ec2 describe-network-acls --region "$REGION" --filters "Name=association.subnet-id,Values=$subnet_id" --query 'NetworkAcls[0].NetworkAclId' --output text 2>/dev/null)
        if [ -z "$nacl_id" ] || [ "$nacl_id" == "None" ]; then
            outbound_details+="<li class=\"yellow\">No NACL associated with this subnet</li>"
            overall_warning=true; continue
        fi
        outbound_details+="<li>Associated NACL: $nacl_id</li>"
        permissive_rules=$(aws ec2 describe-network-acls --region "$REGION" --network-acl-ids "$nacl_id" --query 'NetworkAcls[0].Entries[?Egress==`true` && CidrBlock==`0.0.0.0/0` && RuleAction==`allow`]' --output text 2>/dev/null)
        if [ -n "$permissive_rules" ]; then
            outbound_details+="<li class=\"red\">WARNING: NACL has permissive outbound rules (0.0.0.0/0 allow)</li><li><pre>$permissive_rules</pre></li>"
            overall_warning=true
        else
            outbound_details+="<li class=\"green\">NACL has properly restricted outbound rules</li>"
        fi
        outbound_details+="</ul>"
    done
    outbound_details+="</ul>"
done
outbound_details+="</ul><h4>Security Group Rules</h4><ul>"
for vpc_id in $TARGET_VPCS; do
    [ "$vpc_id" == "None" ] && continue
    outbound_details+="<li>VPC: $vpc_id</li><ul>"
    sg_list=$(aws ec2 describe-security-groups --region "$REGION" --filters "Name=vpc-id,Values=$vpc_id" --query 'SecurityGroups[*].GroupId' --output text 2>/dev/null)
    [ -z "$sg_list" ] && continue
    for sg_id in $sg_list; do
        sg_details=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$sg_id" --output json 2>/dev/null)
        sg_name=$(echo "$sg_details" | jq -r '.SecurityGroups[0].GroupName')
        outbound_details+="<li>Security Group: $sg_id ($sg_name)</li><ul>"
        public_outbound=$(echo "$sg_details" | jq '[.SecurityGroups[].IpPermissionsEgress[] | select(.IpRanges[].CidrIp=="0.0.0.0/0")] | length')
        if [ "$public_outbound" -gt 0 ]; then
            outbound_details+="<li class=\"red\">WARNING: $public_outbound public outbound rules (0.0.0.0/0)</li>"
            outbound_rules=$(echo "$sg_details" | jq -r '.SecurityGroups[].IpPermissionsEgress[] | select(.IpRanges[].CidrIp=="0.0.0.0/0") | "Protocol: \(.IpProtocol) | FromPort: \(.FromPort // "all") | ToPort: \(.ToPort // "all")"' 2>/dev/null)
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

if [ "$overall_warning" = true ]; then
    report_item "1.3.2 - Outbound traffic from CDE restriction" "warning" "$outbound_details" "Review NACL and Security Group outbound rules. Restrict any rules allowing 0.0.0.0/0 unless explicitly required and documented. Outbound traffic from the CDE must be limited to known, secure destinations."
else
    report_item "1.3.2 - Outbound traffic from CDE restriction" "pass" "$outbound_details" "All examined NACLs and Security Groups have properly restricted outbound rules. No public (0.0.0.0/0) access detected."
fi

# === 1.4.1 - NSCs between trusted and untrusted networks ===
echo "Checking 1.4.1 - NSCs between trusted and untrusted networks..."
network_connections_details="<p>Analysis of connections between trusted and untrusted networks:</p><ul>"
for vpc_id in $TARGET_VPCS; do
    [ "$vpc_id" == "None" ] && continue
    network_connections_details+="<li>VPC: $vpc_id</li><ul>"
    igw=$(aws ec2 describe-internet-gateways --region "$REGION" --filters "Name=attachment.vpc-id,Values=$vpc_id" --query 'InternetGateways[*].InternetGatewayId' --output text 2>/dev/null)
    if [ -n "$igw" ]; then
        network_connections_details+="<li>Internet Gateway detected: $igw</li>"
        public_instances=$(aws ec2 describe-instances --region "$REGION" --filters "Name=vpc-id,Values=$vpc_id" "Name=network-interface.association.public-ip,Values=*" --query 'Reservations[*].Instances[*].InstanceId' --output text 2>/dev/null)
        if [ -n "$public_instances" ]; then
            network_connections_details+="<li class=\"yellow\">Found instances with public IPs:</li><ul>"
            for instance in $public_instances; do
                network_connections_details+="<li>Instance ID: $instance</li>"
                instance_sg=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$instance" --query 'Reservations[*].Instances[*].SecurityGroups[*].GroupId' --output text 2>/dev/null)
                network_connections_details+="<li>Security Groups: $instance_sg</li><ul>"
                for sg in $instance_sg; do
                    open_ports=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$sg" --query 'SecurityGroups[*].IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]' --output text | wc -l)
                    if [ $open_ports -gt 0 ]; then
                        network_connections_details+="<li class=\"red\">WARNING: Security group $sg has open ports to the internet (0.0.0.0/0)</li>"
                    else
                        network_connections_details+="<li class=\"green\">Security group $sg has properly restricted inbound rules</li>"
                    fi
                done
                network_connections_details+="</ul>"
            done
            network_connections_details+="</ul>"
        else
            network_connections_details+="<li class=\"green\">No instances with public IPs found</li>"
        fi
    else
        network_connections_details+="<li class=\"green\">No Internet Gateway detected - isolation from untrusted networks appears maintained</li>"
    fi
    peering=$(aws ec2 describe-vpc-peering-connections --region "$REGION" --filters "Name=requester-vpc-info.vpc-id,Values=$vpc_id" --query 'VpcPeeringConnections[*].VpcPeeringConnectionId' --output text 2>/dev/null)
    if [ -n "$peering" ]; then
        network_connections_details+="<li class=\"yellow\">VPC Peering connections detected:</li><ul>"
        for peer in $peering; do network_connections_details+="<li>$peer</li>"; done
        network_connections_details+="</ul>"
    else
        network_connections_details+="<li>No VPC Peering connections detected</li>"
    fi
    tgw_check=$(aws ec2 describe-transit-gateway-attachments --region "$REGION" --filters "Name=resource-id,Values=$vpc_id" --query 'TransitGatewayAttachments[*].TransitGatewayId' --output text 2>/dev/null)
    if [ -n "$tgw_check" ]; then
        network_connections_details+="<li class=\"yellow\">Transit Gateway connections detected:</li><ul>"
        for tgw in $tgw_check; do network_connections_details+="<li>$tgw</li>"; done
        network_connections_details+="</ul>"
    else
        network_connections_details+="<li>No Transit Gateway connections detected</li>"
    fi
    network_connections_details+="</ul>"
done
network_connections_details+="</ul><p class=\"yellow\">NOTE: A complete assessment requires understanding of which networks are trusted vs. untrusted</p>"

report_item "1.4.1 - NSCs between trusted and untrusted networks" "info" "$network_connections_details" "Ensure proper network security controls are implemented between trusted and untrusted networks. Identify and classify all networks as trusted or untrusted, and verify appropriate security controls at boundaries."

# === 1.4.3 - Anti-spoofing measures ===
echo "Checking 1.4.3 - Anti-spoofing measures..."
antispoofing_details="<p>AWS VPC provides anti-spoofing by default through source/destination checks on EC2 instances.</p>"
antispoofing_details="<p>Analysis of source/destination checks on EC2 instances:</p><ul>"
disabled_checks_total=0
for vpc_id in $TARGET_VPCS; do
    [ "$vpc_id" == "None" ] && continue
    antispoofing_details+="<li>VPC: $vpc_id</li>"
    instances=$(aws ec2 describe-instances --region "$REGION" --filters "Name=vpc-id,Values=$vpc_id" --query 'Reservations[*].Instances[*].InstanceId' --output text 2>/dev/null)
    if [ -z "$instances" ]; then
        antispoofing_details+="<ul><li>No instances found</li></ul>"; continue
    fi
    disabled_checks=0; antispoofing_details+="<ul>"
    for instance in $instances; do
        src_dst_check=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$instance" --query 'Reservations[*].Instances[*].SourceDestCheck' --output text 2>/dev/null)
        if [ "$src_dst_check" == "False" ]; then
            antispoofing_details+="<li class=\"yellow\">Instance $instance has source/destination check disabled</li>"
            disabled_checks=$((disabled_checks+1))
            disabled_checks_total=$((disabled_checks_total+1))
        fi
    done
    if [ $disabled_checks -eq 0 ]; then
        antispoofing_details+="<li class=\"green\">All instances have source/destination checks enabled</li>"
    else
        antispoofing_details+="<li class=\"yellow\">$disabled_checks instances have source/destination checks disabled</li>"
    fi
    antispoofing_details+="</ul>"
done
antispoofing_details+="</ul>"
if [ $disabled_checks_total -eq 0 ]; then
    report_item "1.4.3 - Anti-spoofing measures" "pass" "$antispoofing_details" ""
else
    report_item "1.4.3 - Anti-spoofing measures" "warning" "$antispoofing_details" "Verify instances with disabled source/destination checks require this configuration (typically only needed for NAT, VPN, or load balancing instances). Ensure proper anti-spoofing measures are in place."
fi

# === 1.4.4 - RDS Public Access ===
echo "Checking 1.4.4 - RDS Public Access..."
rds_instances=$(aws rds describe-db-instances --region "$REGION" --query "DBInstances[*].{Identifier:DBInstanceIdentifier,Encrypted:StorageEncrypted,Port:Endpoint.Port,PublicAccess:PubliclyAccessible}" --output json 2>/dev/null)
rds_count=$(echo "$rds_instances" | jq 'length' 2>/dev/null || echo "0")
public_access_count=0
if [[ "$rds_count" =~ ^[0-9]+$ ]] && [[ "$rds_count" -gt 0 ]]; then
    for ((i=0; i<$rds_count; i++)); do
        is_public=$(echo "$rds_instances" | jq -r ".[$i].PublicAccess")
        if [ "$is_public" == "true" ]; then
            public_access_count=$((public_access_count + 1))
        fi
    done
fi
public_access_list=$(echo "$rds_instances" | jq -r '.[] | "\(.Identifier) " + (if .PublicAccess==true then ": enabled" else ": disabled" end)' 2>/dev/null | sed 's/^/<br>/')
if [ "$public_access_count" -eq 0 ]; then
    report_item "1.4.4 - RDS Public Access" "pass" "No RDS instances with public access" ""
else
    msg="$public_access_count RDS instance(s) have public access enabled:$public_access_list"
    report_item "1.4.4 - RDS Public Access" "warning" "$msg" "Disable public access for RDS instances in production environments"
fi

# === 1.4.4 - S3 Public Access ===
echo "Checking 1.4.4 - S3 Public Access..."
bool2ena() { [ "$1" = "true" ] && echo "enabled" || echo "disabled"; }
buckets=$(aws s3api list-buckets --query "Buckets[*].Name" --output json --region "$REGION" 2>/dev/null)
bucket_count=$(echo "$buckets" | jq 'length' 2>/dev/null || echo "0")
all_buckets_details=""
insecure_acl_count=0
public_buckets=""
if [[ "$bucket_count" =~ ^[0-9]+$ ]] && [[ "$bucket_count" -gt 0 ]]; then
    for ((i=0; i<$bucket_count; i++)); do
        bucket_name=$(echo "$buckets" | jq -r ".[$i]")
        acl_json=$(aws s3api get-bucket-acl --bucket "$bucket_name" --region "$REGION" 2>/dev/null)
        acl_public_groups=$(echo "$acl_json" | jq -r 'try [ .Grants[] | select(.Grantee.Type=="Group") | (.Grantee.URI | split("/")[-1]) ] catch [] | join(", ")')
        public_access=false
        if [ -n "$acl_public_groups" ]; then
            public_access=true
            insecure_acl_count=$((insecure_acl_count + 1))
            acl_check="Public groups: $acl_public_groups"
        else
            acl_check="without 'AllUsers', 'AuthenticatedUsers'"
        fi
        policy_status_json=$(aws s3api get-bucket-policy-status --bucket "$bucket_name" --region "$REGION" 2>/dev/null)
        is_policy_public=$(echo "$policy_status_json" | jq -r '.PolicyStatus.IsPublic // false')
        if aws s3api get-bucket-policy --bucket "$bucket_name" --region "$REGION" >/dev/null 2>&1; then
            if [[ "$is_policy_public" == "true" ]]; then
                policy_label="Allow all"
            else
                policy_label="Restricted"
            fi
        else
            policy_label="None"
        fi
        if [[ "$is_policy_public" == "true" ]]; then
            if [ "$public_access" = false ]; then insecure_acl_count=$((insecure_acl_count + 1)); fi
            public_access=true
        fi
        bpa_json=$(aws s3api get-public-access-block --bucket "$bucket_name" --region "$REGION" 2>/dev/null)
        if [ $? -eq 0 ]; then
            bpa_block_public_acls=$(echo "$bpa_json" | jq -r '.PublicAccessBlockConfiguration.BlockPublicAcls // false')
            bpa_ignore_public_acls=$(echo "$bpa_json" | jq -r '.PublicAccessBlockConfiguration.IgnorePublicAcls // false')
            bpa_block_public_policy=$(echo "$bpa_json" | jq -r '.PublicAccessBlockConfiguration.BlockPublicPolicy // false')
            bpa_restrict_public_buckets=$(echo "$bpa_json" | jq -r '.PublicAccessBlockConfiguration.RestrictPublicBuckets // false')
            bpa_BlockPublicAcls=$(bool2ena "$bpa_block_public_acls")
            bpa_IgnorePublicAcls=$(bool2ena "$bpa_ignore_public_acls")
            bpa_BlockPublicPolicy=$(bool2ena "$bpa_block_public_policy")
            bpa_RestrictPublicBuckets=$(bool2ena "$bpa_restrict_public_buckets")
        else
            bpa_BlockPublicAcls="not configured"
            bpa_IgnorePublicAcls="not configured"
            bpa_BlockPublicPolicy="not configured"
            bpa_RestrictPublicBuckets="not configured"
        fi
        all_buckets_details+="<br><strong>$bucket_name</strong>"
        all_buckets_details+="<br>&nbsp;&nbsp;ACL Grantee Check: $acl_check"
        all_buckets_details+="<br>&nbsp;&nbsp;Bucket Policy: $policy_label"
        all_buckets_details+="<br>&nbsp;&nbsp;Public Access Block:"
        all_buckets_details+="<br>&nbsp;&nbsp;&nbsp;&nbsp;BlockPublicAcls: $bpa_BlockPublicAcls"
        all_buckets_details+="<br>&nbsp;&nbsp;&nbsp;&nbsp;IgnorePublicAcls: $bpa_IgnorePublicAcls"
        all_buckets_details+="<br>&nbsp;&nbsp;&nbsp;&nbsp;BlockPublicPolicy: $bpa_BlockPublicPolicy"
        all_buckets_details+="<br>&nbsp;&nbsp;&nbsp;&nbsp;RestrictPublicBuckets: $bpa_RestrictPublicBuckets"
        if [ "$public_access" = true ]; then
            public_buckets+="<br><strong>$bucket_name</strong>"
        fi
    done
fi
if [ "$insecure_acl_count" -eq 0 ]; then
    report_item "1.4.4 - S3 Public Access" "pass" "No S3 buckets with public access<br><br><strong>Details (all buckets):</strong>$all_buckets_details" ""
else
    violation_detail="$insecure_acl_count S3 buckets have public access<br><br><strong>Risk:</strong> Public S3 buckets can expose sensitive data and are frequently targeted by attackers.<br><br><strong>Public S3 Buckets List:</strong>$public_buckets<br><br><strong>Details (all buckets):</strong>$all_buckets_details"
    report_item "1.4.4 - S3 Public Access" "warning" "$violation_detail" "1. Enable S3 Block Public Access at the account level<br>2. Remove public ACLs from the identified buckets<br>3. Review and restrict bucket policies<br>4. Use pre-signed URLs for temporary access when needed"
fi

# === 2.2.1 - RDS Encryption ===
echo "Checking 2.2.1 - RDS Encryption..."
unencrypted_count=0
if [[ "$rds_count" =~ ^[0-9]+$ ]] && [[ "$rds_count" -gt 0 ]]; then
    for ((i=0; i<$rds_count; i++)); do
        is_encrypted=$(echo "$rds_instances" | jq -r ".[$i].Encrypted")
        if [ "$is_encrypted" == "false" ]; then
            unencrypted_count=$((unencrypted_count + 1))
        fi
    done
fi
if [ "$unencrypted_count" -eq 0 ]; then
    report_item "2.2.1 - RDS Encryption" "pass" "All RDS instances are encrypted" ""
else
    report_item "2.2.1 - RDS Encryption" "warning" "$unencrypted_count RDS instances are not encrypted" "Enable encryption for all RDS instances"
fi

# === 2.2.1 - S3 Encryption ===
echo "Checking 2.2.1 - S3 Encryption..."
no_encryption_count=0
unencrypted_buckets=""
if [[ "$bucket_count" =~ ^[0-9]+$ ]] && [[ "$bucket_count" -gt 0 ]]; then
    for ((i=0; i<$bucket_count; i++)); do
        bucket_name=$(echo "$buckets" | jq -r ".[$i]")
        encryption=$(aws s3api get-bucket-encryption --bucket "$bucket_name" --region "$REGION" 2>/dev/null)
        if [ $? -ne 0 ]; then
            no_encryption_count=$((no_encryption_count + 1))
            unencrypted_buckets+="<br><strong>Bucket:</strong> $bucket_name"
        fi
    done
fi
if [ "$no_encryption_count" -eq 0 ]; then
    report_item "2.2.1 - S3 Encryption" "pass" "All S3 buckets have encryption enabled" ""
else
    violation_detail="$no_encryption_count S3 buckets don't have encryption enabled<br><br><strong>Risk:</strong> Unencrypted data storage violates PCI DSS requirements and may expose sensitive information.<br><br><strong>Unencrypted Buckets:</strong>$unencrypted_buckets"
    report_item "2.2.1 - S3 Encryption" "warning" "$violation_detail" "1. Enable default encryption for all S3 buckets using AES-256 or AWS KMS<br>2. Consider using AWS Organizations to enforce encryption policies<br>3. Review data classification to ensure appropriate controls"
fi

# === 3.6 - Key Management ===
echo "Checking 3.6 - Key Management..."
kms_keys=$(aws kms list-keys --region "$REGION" --query 'Keys[*].KeyId' --output text 2>/dev/null)
if [ -z "$kms_keys" ]; then
    report_item "3.6 - Key Management" "pass" "<p>No KMS Customer-Managed Keys found in region $REGION.</p>" ""
else
    kms_html="<h4>KMS Key Configuration:</h4>"
    kms_html+="<p><em>Each key shows which Principals (who can use it), what Actions they are allowed, and any active Grants (temporary permissions).</em></p>"
    overall_status="pass"
    for key_id in $kms_keys; do
        metadata=$(aws kms describe-key --key-id "$key_id" --region "$REGION" --query 'KeyMetadata' --output json 2>/dev/null)
        key_state=$(echo "$metadata" | jq -r '.KeyState')
        key_alias=$(aws kms list-aliases --region "$REGION" --query "Aliases[?TargetKeyId=='$key_id'].AliasName" --output text 2>/dev/null)
        key_owner=$(echo "$metadata" | jq -r '.AWSAccountId // "Unknown"')
        kms_html+="<div style='margin:10px;padding:10px;border:1px solid #ccc;'>"
        kms_html+="<strong>Key ID:</strong> $key_id<br><strong>Alias:</strong> ${key_alias:-N/A}<br><strong>Owner Account:</strong> $key_owner<br><strong>Key State:</strong> $key_state<br>"
        rotation_enabled=$(aws kms get-key-rotation-status --key-id "$key_id" --region "$REGION" --query 'KeyRotationEnabled' --output text 2>/dev/null)
        if [ "$rotation_enabled" == "True" ]; then
            kms_html+="<strong>Key Rotation:</strong> <span class=\"green\">Enabled</span><br>"
        else
            kms_html+="<strong>Key Rotation:</strong> <span class=\"red\">Disabled</span><br>"
            overall_status="warning"
        fi
        policy=$(aws kms get-key-policy --key-id "$key_id" --region "$REGION" --policy-name default --query 'Policy' --output text 2>/dev/null)
        if [ -n "$policy" ]; then
            principals_clean=$(echo "$policy" | jq -r '.Statement[].Principal.AWS | if type=="array" then .[] else . end' 2>/dev/null)
            if echo "$principals_clean" | grep -q "\*"; then
                kms_html+="<p class=\"red\"><strong>Policy Principals:</strong></p><ul>"
                overall_status="warning"
            else
                kms_html+="<p class=\"green\"><strong>Policy Principals:</strong></p><ul>"
            fi
            while IFS= read -r principal; do
                if [[ "$principal" == "*" ]]; then
                    kms_html+="<li class=\"red\">$principal (Any Principal)</li>"; overall_status="warning"
                else
                    kms_html+="<li>$principal</li>"
                fi
            done <<< "$principals_clean"
            kms_html+="</ul>"
            actions_clean=$(echo "$policy" | jq -r '.Statement[].Action | if type=="array" then .[] else . end' 2>/dev/null)
            kms_html+="<p><strong>Allowed Actions:</strong></p><ul>"
            while IFS= read -r action; do
                if [[ "$action" == "kms:*" || "$action" == "kms:ReEncrypt*" ]]; then
                    kms_html+="<li class=\"red\">$action</li>"; overall_status="warning"
                else
                    kms_html+="<li>$action</li>"
                fi
            done <<< "$actions_clean"
            kms_html+="</ul>"
        else
            kms_html+="<p>No Key Policy found (default AWS-managed key?)</p>"
        fi
        grants=$(aws kms list-grants --key-id "$key_id" --region "$REGION" --query 'Grants[*].{Grantee:GranteePrincipal,Ops:Operations}' --output json 2>/dev/null)
        if [ -n "$grants" ] && [ "$grants" != "[]" ]; then
            kms_html+="<p><strong>Active Grants:</strong></p><ul>"
            for grant in $(echo "$grants" | jq -c '.[]'); do
                grantee=$(echo "$grant" | jq -r '.Grantee')
                ops=$(echo "$grant" | jq -r '.Ops | join(", ")')
                kms_html+="<li><strong>$grantee</strong>: $ops</li>"
            done
            kms_html+="</ul>"
        else
            kms_html+="<p>No active grants.</p>"
        fi
        kms_html+="</div>"
    done
    report_item "3.6 - Key Management" "$overall_status" "$kms_html" "Review KMS key policies and grants to ensure least privilege and proper access control."
fi

# === 4.2.1 - TLS Implementation ===
echo "Checking 4.2.1 - TLS Implementation..."
lb_arns=$(aws elbv2 describe-load-balancers --region "$REGION" --query 'LoadBalancers[*].LoadBalancerArn' --output text 2>/dev/null)
tls_output="<p>ELB/ALB TLS Configuration:</p>"
tls_issue_found=false
if [ -z "$lb_arns" ]; then
    tls_output+="<div class=\"green\"><ul><li>No Load Balancers found in region $REGION</li></ul></div>"
    report_item "4.2.1 - TLS Implementation" "pass" "$tls_output" ""
else
    for lb_arn in $lb_arns; do
        lb_name=$(echo "$lb_arn" | awk -F'/' '{print $3}')
        lb_output="<ul><li>Load Balancer: $lb_name<ul>"
        lb_tls_issue_found=false
        listeners=$(aws elbv2 describe-listeners --region "$REGION" --load-balancer-arn "$lb_arn" --query 'Listeners[*].{Port:Port,ARN:ListenerArn,SslPolicy:SslPolicy}' --output json 2>/dev/null)
        if [ -z "$listeners" ] || [ "$listeners" == "[]" ]; then
            lb_output+="<li class=\"yellow\">No Listeners found</li></ul></li></ul>"
            tls_output+="<div class=\"yellow\">$lb_output</div>"
            tls_issue_found=true
            continue
        fi
        for listener in $(echo "$listeners" | jq -c '.[]'); do
            port=$(echo "$listener" | jq -r '.Port')
            ssl_policy=$(echo "$listener" | jq -r '.SslPolicy // "None"')
            lb_output+="<li>Listener Port: $port<br>SSL Policy: $ssl_policy<ul>"
            if [ "$ssl_policy" != "None" ]; then
                policy_details=$(aws elbv2 describe-ssl-policies --region "$REGION" --names "$ssl_policy" --query 'SslPolicies[0]' --output json 2>/dev/null)
                protocols=$(echo "$policy_details" | jq -r '.SslProtocols[]?' | paste -sd "," -)
                lb_output+="<li>Supported Protocols: $protocols</li>"
                ciphers=$(echo "$policy_details" | jq -r '.Ciphers[].Name')
                if [ -n "$ciphers" ]; then
                    lb_output+="<li>Supported Ciphers:<ul>"
                    while IFS= read -r cipher; do lb_output+="<li>$cipher</li>"; done <<< "$ciphers"
                    lb_output+="</ul></li>"
                else
                    lb_output+="<li class=\"yellow\">No Ciphers found in policy</li>"
                    lb_tls_issue_found=true
                fi
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
        if [ "$lb_tls_issue_found" = true ]; then
            tls_output+="<div class=\"red\">$lb_output</div>"
            tls_issue_found=true
        else
            tls_output+="<div class=\"green\">$lb_output</div>"
        fi
    done
    if [ "$tls_issue_found" = true ]; then
        report_item "4.2.1 - TLS Implementation" "fail" "$tls_output" "Ensure load balancers use secure SSL policies that only support TLS 1.2 or higher."
    else
        report_item "4.2.1 - TLS Implementation" "pass" "$tls_output" ""
    fi
fi

# === 6.3.1 - Vulnerability scanning with AWS Inspector ===
echo "Checking 6.3.1 - Vulnerability scanning with AWS Inspector..."
INSPECTOR_STATUS=$(aws inspector2 batch-get-account-status --region "$REGION" 2>/dev/null)
if [ $? -eq 0 ]; then
    EC2_SCANNING=$(echo "$INSPECTOR_STATUS" | grep -o '"EC2_SCANNING": "[^"]*"' | head -1 | cut -d'"' -f4)
    ECR_SCANNING=$(echo "$INSPECTOR_STATUS" | grep -o '"ECR_SCANNING": "[^"]*"' | head -1 | cut -d'"' -f4)
    LAMBDA_SCANNING=$(echo "$INSPECTOR_STATUS" | grep -o '"LAMBDA_SCANNING": "[^"]*"' | head -1 | cut -d'"' -f4)
    if [ "$EC2_SCANNING" == "ENABLED" ] || [ "$ECR_SCANNING" == "ENABLED" ] || [ "$LAMBDA_SCANNING" == "ENABLED" ]; then
        INSPECTOR_DETAILS="<p>AWS Inspector is enabled with the following status:</p><ul>"
        [ "$EC2_SCANNING" == "ENABLED" ] && INSPECTOR_DETAILS+="<li><span class=\"green\">EC2 Scanning: ENABLED</span></li>" || INSPECTOR_DETAILS+="<li><span class=\"yellow\">EC2 Scanning: DISABLED</span></li>"
        [ "$ECR_SCANNING" == "ENABLED" ] && INSPECTOR_DETAILS+="<li><span class=\"green\">ECR Scanning: ENABLED</span></li>" || INSPECTOR_DETAILS+="<li><span class=\"yellow\">ECR Scanning: DISABLED</span></li>"
        [ "$LAMBDA_SCANNING" == "ENABLED" ] && INSPECTOR_DETAILS+="<li><span class=\"green\">Lambda Scanning: ENABLED</span></li>" || INSPECTOR_DETAILS+="<li><span class=\"yellow\">Lambda Scanning: DISABLED</span></li>"
        INSPECTOR_DETAILS+="</ul>"
        FINDINGS=$(aws inspector2 list-findings --filter-criteria '{"findingSeverity":[{"comparison":"EQUALS","value":"CRITICAL"}]}' --region "$REGION" 2>/dev/null)
        CRITICAL_COUNT=$(echo "$FINDINGS" | grep -o '"findingArn":' | wc -l)
        FINDINGS=$(aws inspector2 list-findings --filter-criteria '{"findingSeverity":[{"comparison":"EQUALS","value":"HIGH"}]}' --region "$REGION" 2>/dev/null)
        HIGH_COUNT=$(echo "$FINDINGS" | grep -o '"findingArn":' | wc -l)
        if [ $CRITICAL_COUNT -gt 0 ] || [ $HIGH_COUNT -gt 0 ]; then
            INSPECTOR_DETAILS+="<p>Security vulnerabilities detected:</p><ul>"
            [ $CRITICAL_COUNT -gt 0 ] && INSPECTOR_DETAILS+="<li><span class=\"red\">Critical vulnerabilities: $CRITICAL_COUNT</span></li>"
            [ $HIGH_COUNT -gt 0 ] && INSPECTOR_DETAILS+="<li><span class=\"red\">High vulnerabilities: $HIGH_COUNT</span></li>"
            INSPECTOR_DETAILS+="</ul>"
            report_item "6.3.1 - Vulnerability scanning with AWS Inspector" "fail" "$INSPECTOR_DETAILS" "Address critical and high vulnerabilities identified by AWS Inspector immediately."
        else
            INSPECTOR_DETAILS+="<p><span class=\"green\">No critical or high severity findings detected by AWS Inspector.</span></p>"
            report_item "6.3.1 - Vulnerability scanning with AWS Inspector" "pass" "$INSPECTOR_DETAILS" ""
        fi
    else
        INSPECTOR_DETAILS="<p><span class=\"yellow\">AWS Inspector is not fully enabled. EC2, ECR, and Lambda scanning should be enabled to identify security vulnerabilities.</span></p>"
        report_item "6.3.1 - Vulnerability scanning with AWS Inspector" "warning" "$INSPECTOR_DETAILS" "Please confirm whether a third-party vulnerability scanning tool has been used for EC2 instances."
    fi
else
    INSPECTOR_DETAILS="<p><span class=\"red\">AWS Inspector is not enabled or configured in this region.</span></p>"
    report_item "6.3.1 - Vulnerability scanning with AWS Inspector" "warning" "$INSPECTOR_DETAILS" "Please confirm whether a third-party vulnerability scanning tool has been used for EC2 instances."
fi

# === 6.3.2 - Container image vulnerability scanning ===
echo "Checking 6.3.2 - Container image vulnerability scanning..."
ECR_REPOS=$(aws ecr describe-repositories --region "$REGION" --query 'repositories[*].repositoryName' --output text 2>/dev/null)
if [ -n "$ECR_REPOS" ]; then
    ECR_DETAILS="<p>Analyzing vulnerability scanning configuration for ECR repositories:</p><ul>"
    ECR_ISSUES_FOUND=false
    for repo in $ECR_REPOS; do
        REPO_INFO=$(aws ecr describe-repository-scan-configuration --repository-name "$repo" --region "$REGION" 2>/dev/null)
        SCAN_ON_PUSH=$(echo "$REPO_INFO" | grep -o '"scanOnPush": [a-z]*' | head -1 | cut -d' ' -f2)
        SCAN_FREQUENCY=$(echo "$REPO_INFO" | grep -o '"scanFrequency": "[^"]*"' | head -1 | cut -d'"' -f4)
        if [ "$SCAN_ON_PUSH" == "true" ]; then
            ECR_DETAILS+="<li><span class=\"green\">Repository '$repo' has scan-on-push enabled</span></li>"
        elif [ "$SCAN_FREQUENCY" == "CONTINUOUS_SCAN" ] || [ "$SCAN_FREQUENCY" == "SCAN_ON_PUSH" ]; then
            ECR_DETAILS+="<li><span class=\"green\">Repository '$repo' has enhanced scanning enabled with frequency: $SCAN_FREQUENCY</span></li>"
        else
            ECR_ISSUES_FOUND=true
            ECR_DETAILS+="<li><span class=\"red\">Repository '$repo' does not have automatic scanning enabled</span></li>"
        fi
        IMMUTABILITY=$(aws ecr describe-repositories --repository-names "$repo" --region "$REGION" --query "repositories[0].imageTagMutability" --output text 2>/dev/null)
        if [ "$IMMUTABILITY" == "IMMUTABLE" ]; then
            ECR_DETAILS+="<li><span class=\"green\">Repository '$repo' has immutable image tags</span></li>"
        else
            ECR_ISSUES_FOUND=true
            ECR_DETAILS+="<li><span class=\"yellow\">Repository '$repo' has mutable image tags</span></li>"
        fi
    done
    ECR_DETAILS+="</ul>"
    if [ "$ECR_ISSUES_FOUND" = true ]; then
        report_item "6.3.2 - Container image vulnerability scanning" "fail" "$ECR_DETAILS" "Ensure ECR repositories are configured with scanOnPush enabled or continuous scanning is activated."
    else
        report_item "6.3.2 - Container image vulnerability scanning" "pass" "$ECR_DETAILS" ""
    fi
else
    report_item "6.3.2 - Container image vulnerability scanning" "info" "<p>No ECR repositories found for analysis.</p>" ""
fi

# === 6.4.2 - Web application firewall implementation ===
echo "Checking 6.4.2 - Web application firewall implementation..."
WAF_ACLS=$(aws wafv2 list-web-acls --scope REGIONAL --region "$REGION" --query 'WebACLs[*].Name' --output text 2>/dev/null)
if [ -n "$WAF_ACLS" ]; then
    WAF_DETAILS="<p>AWS WAF Web ACLs found:</p><ul>"
    WAF_ISSUES_FOUND=false
    for acl in $WAF_ACLS; do
        ACL_INFO=$(aws wafv2 get-web-acl --name "$acl" --scope REGIONAL --region "$REGION" 2>/dev/null)
        RULES_COUNT=$(echo "$ACL_INFO" | grep -o '"Rules": \[.*\]' | grep -o '"Name"' | wc -l)
        DEFAULT_ACTION=$(echo "$ACL_INFO" | grep -o '"DefaultAction": {[^}]*}' | grep -o '"Type": "[^"]*"' | cut -d'"' -f4)
        WAF_DETAILS+="<li>Web ACL: $acl<ul><li>Default action: $DEFAULT_ACTION</li><li>Rules configured: $RULES_COUNT</li>"
        if [ "$DEFAULT_ACTION" != "BLOCK" ]; then
            WAF_ISSUES_FOUND=true
            WAF_DETAILS+="<li><span class=\"yellow\">Default action is not set to BLOCK.</span></li>"
        fi
        MANAGED_RULES=$(echo "$ACL_INFO" | grep -o '"ManagedRuleGroupStatement"' | wc -l)
        if [ $MANAGED_RULES -gt 0 ]; then
            WAF_DETAILS+="<li><span class=\"green\">Using managed rule groups</span></li>"
            AWS_CORE_RULES=$(echo "$ACL_INFO" | grep -o '"AWSManagedRulesCommonRuleSet"' | wc -l)
            [ $AWS_CORE_RULES -gt 0 ] && WAF_DETAILS+="<li><span class=\"green\">Using AWS Core Rule Set (CRS)</span></li>" || { WAF_ISSUES_FOUND=true; WAF_DETAILS+="<li><span class=\"yellow\">Not using AWS CRS</span></li>"; }
            SQL_RULES=$(echo "$ACL_INFO" | grep -o '"AWSManagedRulesSQLiRuleSet"' | wc -l)
            [ $SQL_RULES -gt 0 ] && WAF_DETAILS+="<li><span class=\"green\">Using SQL injection protection rules</span></li>" || { WAF_ISSUES_FOUND=true; WAF_DETAILS+="<li><span class=\"yellow\">Not using SQL injection protection rules</span></li>"; }
        else
            WAF_ISSUES_FOUND=true
            WAF_DETAILS+="<li><span class=\"red\">No managed rule groups detected.</span></li>"
        fi
        WAF_DETAILS+="</ul></li>"
    done
    WAF_DETAILS+="</ul>"
    if [ "$WAF_ISSUES_FOUND" = true ]; then
        report_item "6.4.2 - Web application firewall implementation" "warning" "$WAF_DETAILS" "Ensure default action is set to BLOCK and appropriate managed rules are applied."
    else
        report_item "6.4.2 - Web application firewall implementation" "pass" "$WAF_DETAILS" ""
    fi
else
    report_item "6.4.2 - Web application firewall implementation" "warning" "<p><span class=\"red\">No AWS WAF Web ACLs found. Public-facing web applications should be protected by a web application firewall.</span></p>" "Please confirm whether a WAF has been configured to protect public-facing web applications, and whether the WAF is deployed in front of the CDN."
fi

# === 6.5.4 - Role separation ===
report_item "6.5.4 - Role separation" "warning" "<p>Manual verification required: This check requires reviewing role separation policies.</p>
<p>Verify that roles and functions are separated between production and pre-production environments to provide accountability such that only reviewed and approved changes are deployed.</p>" "Implement separation of duties between development and operations roles. Use IAM roles and permissions boundaries to enforce this separation. Consider AWS Organizations Service Control Policies (SCPs) to enforce separation at the account level."

# === 7.3.2 - Access Control System Configuration (Direct Policies) ===
echo "Checking 7.3.2 - Access Control System Configuration (Direct Policies)..."
users=$(aws iam list-users --region "$REGION" --query 'Users[*].[UserName,Arn]' --output json 2>/dev/null)
direct_details="<p>Analysis of IAM users with direct policy attachments:</p><ul>"
direct_policies_found=false
for user_info in $(echo "$users" | jq -c '.[]'); do
    user_name=$(echo "$user_info" | jq -r '.[0]')
    user_arn=$(echo "$user_info" | jq -r '.[1]')
    attached_policies=$(aws iam list-attached-user-policies --user-name "$user_name" --query 'AttachedPolicies[*].[PolicyName,PolicyArn]' --output json 2>/dev/null)
    inline_policies=$(aws iam list-user-policies --user-name "$user_name" --query 'PolicyNames' --output json 2>/dev/null)
    if [ "$(echo "$attached_policies" | jq 'length')" -gt 0 ] || [ "$(echo "$inline_policies" | jq 'length')" -gt 0 ]; then
        direct_policies_found=true
        direct_details+="<li style='margin-bottom: 15px;'><strong>User:</strong> $user_name ($user_arn)<br>"
        if [ "$(echo "$attached_policies" | jq 'length')" -gt 0 ]; then
            direct_details+="<strong>Attached Policies:</strong><ul>"
            for policy in $(echo "$attached_policies" | jq -c '.[]'); do
                policy_name=$(echo "$policy" | jq -r '.[0]')
                policy_arn=$(echo "$policy" | jq -r '.[1]')
                direct_details+="<li>$policy_name ($policy_arn)</li>"
            done
            direct_details+="</ul>"
        fi
        if [ "$(echo "$inline_policies" | jq 'length')" -gt 0 ]; then
            direct_details+="<strong>Inline Policies:</strong><ul>"
            for policy_name in $(echo "$inline_policies" | jq -r '.[]'); do
                direct_details+="<li>$policy_name</li>"
            done
            direct_details+="</ul>"
        fi
        direct_details+="</li>"
    fi
done
direct_details+="</ul>"
if [ "$direct_policies_found" = false ]; then
    report_item "7.3.2 - Access Control System Configuration (Direct Policies)" "pass" "<p class='green'>No IAM users with direct policy attachments were detected. This is a good practice - using groups for policy management is preferred.</p>" ""
else
    direct_details+="<p class='yellow'><strong>Note:</strong> Direct policy attachments to users can make access management more difficult. Consider using IAM groups for policy management instead.</p>"
    report_item "7.3.2 - Access Control System Configuration (Direct Policies)" "warning" "$direct_details" "Remove direct policy attachments from IAM users. Assign policies via IAM groups to simplify and centralize access management."
fi

# === 8.3.6 - Password/Passphrase Requirements ===
echo "Checking 8.3.6 - Password/Passphrase Requirements..."
password_policy=$(aws iam get-account-password-policy --region "$REGION" 2>&1)
if [[ "$password_policy" == *"NoSuchEntity"* ]]; then
    report_item "8.3.6 - Password/Passphrase Requirements" "fail" "<p>No password policy is configured for the AWS account.</p>" "Update the IAM password policy to meet all PCI DSS requirements."
else
    policy_details="<p>Current IAM password policy settings:</p><ul>"
    policy_meets_requirements=true
    issues=""
    if [[ "$password_policy" == *"MinimumPasswordLength"* ]]; then
        min_length=$(echo "$password_policy" | grep "MinimumPasswordLength" | sed 's/.*: \([0-9]*\).*/\1/')
        policy_details+="<li>Minimum password length: $min_length characters"
        if [ "$min_length" -lt 12 ]; then
            policy_details+=" <span class='red'>(FAIL: PCI DSS requires at least 12 characters)</span>"
            policy_meets_requirements=false
            issues+="<li>Increase minimum password length to at least 12 characters</li>"
        else
            policy_details+=" <span class='green'>(PASS)</span>"
        fi
        policy_details+="</li>"
    else
        policy_details+="<li>Minimum password length: Not set <span class='red'>(FAIL: PCI DSS requires at least 12 characters)</span></li>"
        policy_meets_requirements=false
        issues+="<li>Set minimum password length to at least 12 characters</li>"
    fi
    if [[ "$password_policy" == *"RequireSymbols"* ]]; then
        require_symbols=$(echo "$password_policy" | grep "RequireSymbols" | sed 's/.*: \(true\|false\).*/\1/')
        policy_details+="<li>Require symbols: $require_symbols"
        if [ "$require_symbols" == "false" ]; then
            policy_details+=" <span class='red'>(FAIL: PCI DSS requires both upper and lowercase letters, numbers, and special characters)</span>"
            policy_meets_requirements=false
            issues+="<li>Enable symbol requirement in password policy</li>"
        else
            policy_details+=" <span class='green'>(PASS)</span>"
        fi
        policy_details+="</li>"
    else
        policy_details+="<li>Require symbols: Not set <span class='red'>(FAIL: PCI DSS requires both upper and lowercase letters, numbers, and special characters)</span></li>"
        policy_meets_requirements=false
        issues+="<li>Enable symbol requirement in password policy</li>"
    fi
    if [[ "$password_policy" == *"RequireNumbers"* ]]; then
        require_numbers=$(echo "$password_policy" | grep "RequireNumbers" | sed 's/.*: \(true\|false\).*/\1/')
        policy_details+="<li>Require numbers: $require_numbers"
        if [ "$require_numbers" == "false" ]; then policy_details+=" <span class='red'>(FAIL)</span>"; policy_meets_requirements=false; issues+="<li>Enable numeric character requirement in password policy</li>"; else policy_details+=" <span class='green'>(PASS)</span>"; fi
        policy_details+="</li>"
    fi
    if [[ "$password_policy" == *"RequireUppercaseCharacters"* ]]; then
        require_uppercase=$(echo "$password_policy" | grep "RequireUppercaseCharacters" | sed 's/.*: \(true\|false\).*/\1/')
        policy_details+="<li>Require uppercase characters: $require_uppercase"
        if [ "$require_uppercase" == "false" ]; then policy_details+=" <span class='red'>(FAIL)</span>"; policy_meets_requirements=false; issues+="<li>Enable uppercase character requirement in password policy</li>"; else policy_details+=" <span class='green'>(PASS)</span>"; fi
        policy_details+="</li>"
    fi
    if [[ "$password_policy" == *"RequireLowercaseCharacters"* ]]; then
        require_lowercase=$(echo "$password_policy" | grep "RequireLowercaseCharacters" | sed 's/.*: \(true\|false\).*/\1/')
        policy_details+="<li>Require lowercase characters: $require_lowercase"
        if [ "$require_lowercase" == "false" ]; then policy_details+=" <span class='red'>(FAIL)</span>"; policy_meets_requirements=false; issues+="<li>Enable lowercase character requirement in password policy</li>"; else policy_details+=" <span class='green'>(PASS)</span>"; fi
        policy_details+="</li>"
    fi
    if [[ "$password_policy" == *"PasswordReusePrevention"* ]]; then
        reuse_prevention=$(echo "$password_policy" | grep "PasswordReusePrevention" | sed 's/.*: \([0-9]*\).*/\1/')
        policy_details+="<li>Password reuse prevention: Last $reuse_prevention passwords remembered"
        if [ "$reuse_prevention" -lt 4 ]; then policy_details+=" <span class='red'>(FAIL: PCI DSS requires remembering at least 4 previous passwords)</span>"; policy_meets_requirements=false; issues+="<li>Increase password history to remember at least 4 previous passwords</li>"; else policy_details+=" <span class='green'>(PASS)</span>"; fi
        policy_details+="</li>"
    else
        policy_details+="<li>Password reuse prevention: Not set <span class='red'>(FAIL: PCI DSS requires remembering at least 4 previous passwords)</span></li>"
        policy_meets_requirements=false
        issues+="<li>Enable password history to remember at least 4 previous passwords</li>"
    fi
    if [[ "$password_policy" == *"MaxPasswordAge"* ]]; then
        max_age=$(echo "$password_policy" | grep "MaxPasswordAge" | sed 's/.*: \([0-9]*\).*/\1/')
        policy_details+="<li>Maximum password age: $max_age days"
        if [ "$max_age" -gt 90 ]; then policy_details+=" <span class='red'>(FAIL: PCI DSS requires passwords to be changed at least every 90 days)</span>"; policy_meets_requirements=false; issues+="<li>Reduce maximum password age to 90 days or less</li>"; else policy_details+=" <span class='green'>(PASS)</span>"; fi
        policy_details+="</li>"
    else
        policy_details+="<li>Maximum password age: Not set <span class='red'>(FAIL: PCI DSS requires passwords to be changed at least every 90 days)</span></li>"
        policy_meets_requirements=false
        issues+="<li>Set maximum password age to 90 days or less</li>"
    fi
    if [[ "$password_policy" == *"HardExpiry"* ]]; then
        hard_expiry=$(echo "$password_policy" | grep "HardExpiry" | sed 's/.*: \(true\|false\).*/\1/')
        policy_details+="<li>Require password reset on first login: $hard_expiry"
        if [ "$hard_expiry" == "false" ]; then policy_details+=" <span class='yellow'>(WARNING: Consider requiring password change upon first login)</span>"; else policy_details+=" <span class='green'>(PASS)</span>"; fi
        policy_details+="</li>"
    else
        policy_details+="<li>Require password reset on first login: Not set <span class='yellow'>(WARNING)</span></li>"
    fi
    policy_details+="</ul>"
    if [ "$policy_meets_requirements" = false ]; then
        policy_details+="<p><strong>Recommendations:</strong></p><ul>$issues</ul>"
        report_item "8.3.6 - Password/Passphrase Requirements" "fail" "$policy_details" "Update the IAM password policy to meet all PCI DSS requirements."
    else
        report_item "8.3.6 - Password/Passphrase Requirements" "pass" "$policy_details" ""
    fi
fi

# === 8.4.2 - Multi-Factor Authentication ===
echo "Checking 8.4.2 - Multi-Factor Authentication..."
mfa_details=""
mfa_problems=false
root_mfa_status=$(aws iam get-account-summary --region "$REGION" --query 'SummaryMap.AccountMFAEnabled' --output text)
if [ "$root_mfa_status" == "1" ]; then
    mfa_details+="<p><span class='green'>✓ Root account has MFA enabled.</span></p>"
else
    mfa_details+="<p><span class='red'>✗ Root account does not have MFA enabled.</span></p>"
    mfa_problems=true
fi
mfa_details+="<p>IAM User MFA Status:</p>"
users_without_mfa=""
user_count=0
mfa_enabled_count=0
users=$(aws iam list-users --region "$REGION" --query 'Users[*].[UserName,UserId,CreateDate]' --output text)
if [ -n "$users" ]; then
    mfa_details+="<table border='1' cellpadding='5'><tr><th>Username</th><th>MFA Enabled</th><th>Password Enabled</th><th>Access Keys</th><th>Last Activity</th></tr>"
    while IFS=$'\t' read -r username user_id create_date; do
        ((user_count++))
        if ! [[ "$username" =~ ^[a-zA-Z0-9+=,.@_-]+$ ]]; then continue; fi
        login_profile=$(aws iam get-login-profile --user-name "$username" --region "$REGION" 2>&1)
        has_console_access="No"
        if [[ "$login_profile" != *"NoSuchEntity"* ]]; then has_console_access="Yes"; fi
        mfa_devices=$(aws iam list-mfa-devices --user-name "$username" --region "$REGION" --query 'MFADevices[*]' --output text)
        mfa_enabled="No"
        if [ -n "$mfa_devices" ]; then mfa_enabled="Yes"; ((mfa_enabled_count++)); fi
        access_keys=$(aws iam list-access-keys --user-name "$username" --region "$REGION" --query 'AccessKeyMetadata[*].[AccessKeyId,Status]' --output text)
        access_key_info="None"
        if [ -n "$access_keys" ]; then
            access_key_info=""
            while IFS=$'\t' read -r key_id key_status; do
                if [ -n "$key_id" ]; then
                    key_last_used=$(aws iam get-access-key-last-used --access-key-id "$key_id" --region "$REGION" --query 'AccessKeyLastUsed.LastUsedDate' --output text 2>/dev/null)
                    if [ "$key_last_used" == "None" ] || [ -z "$key_last_used" ]; then key_last_used="Never used"; fi
                    if [ -n "$access_key_info" ]; then access_key_info+="<br>"; fi
                    access_key_info+="$key_id ($key_status) - Last used: $key_last_used"
                fi
            done <<< "$access_keys"
        fi
        last_activity="Unknown"
        row_style=""
        if [ "$has_console_access" == "Yes" ] && [ "$mfa_enabled" == "No" ]; then
            row_style=" class='red'"
            mfa_problems=true
            if [ -n "$users_without_mfa" ]; then users_without_mfa+=", "; fi
            users_without_mfa+="$username"
        fi
        mfa_details+="<tr$row_style><td>$username</td><td>$mfa_enabled</td><td>$has_console_access</td><td>$access_key_info</td><td>$last_activity</td></tr>"
    done <<< "$users"
    mfa_details+="</table><p>Summary: $mfa_enabled_count out of $user_count users have MFA enabled.</p>"
    if [ -n "$users_without_mfa" ]; then
        mfa_details+="<p><span class='red'>The following users have console access but do not have MFA enabled: $users_without_mfa</span></p>"
    fi
    
    echo "Checking IAM roles for MFA requirements..."
    roles_without_mfa=""
    roles=$(aws iam list-roles --region "$REGION" --query 'Roles[?starts_with(Path, `/`) == `true`].[RoleName,Arn]' --output text 2>/dev/null)
    if [ -n "$roles" ]; then
        mfa_details+="<p>Analyzing IAM roles for MFA enforcement in trust policies:</p><ul>"
        while IFS=$'\t' read -r role_name role_arn; do
            trust_policy=$(aws iam get-role --role-name "$role_name" --region "$REGION" --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null)
            if [[ "$trust_policy" == *"aws:MultiFactorAuthPresent"* ]] || [[ "$trust_policy" == *"aws:MultiFactorAuthAge"* ]]; then
                mfa_details+="<li><span class='green'>Role: $role_name - MFA is enforced in trust policy</span></li>"
            else
                if [[ "$trust_policy" == *"amazonaws.com"* ]]; then
                    mfa_details+="<li>Role: $role_name - Service role, MFA not applicable</li>"
                else
                    mfa_details+="<li><span class='yellow'>Role: $role_name - Used by humans but does not enforce MFA</span></li>"
                    if [ -n "$roles_without_mfa" ]; then roles_without_mfa+=", "; fi
                    roles_without_mfa+="$role_name"
                    mfa_problems=true
                fi
            fi
        done <<< "$roles"
        mfa_details+="</ul>"
        if [ -n "$roles_without_mfa" ]; then
            mfa_details+="<p><span class='yellow'>The following roles may be assumed by users but do not enforce MFA: $roles_without_mfa</span></p>"
            mfa_details+="<p>Note: This is a warning because some role assumptions may happen through trusted services, but you should verify any roles that allow human access.</p>"
        fi
    fi
else
    mfa_details+="<p>No IAM users found in the account.</p>"
fi
if [ "$mfa_problems" = true ]; then
    report_item "8.4.2 - Multi-Factor Authentication" "fail" "$mfa_details" "Ensure MFA is enabled for the root account and all IAM users with console access. Consider enforcing MFA in trust policies for roles used by humans."
else
    report_item "8.4.2 - Multi-Factor Authentication" "pass" "$mfa_details" ""
fi

# === 8.6.1-3 - Review User Access ===
echo "Checking 8.6.1-3 - Review User Access..."
review_details="<p>Reviewing User Access tracking configurations...</p>"
analyzer_status=$(aws accessanalyzer list-analyzers --region "$REGION" --query 'analyzers[?status==`ACTIVE`]' --output text 2>/dev/null)
if [ -n "$analyzer_status" ]; then
    review_details+="<p><span class='green'>AWS IAM Access Analyzer is active.</span></p>"
else
    review_details+="<p><span class='yellow'>AWS IAM Access Analyzer is not enabled in this region. Consider enabling it to help identify resources shared with external entities.</span></p>"
fi
iam_trails=$(aws cloudtrail describe-trails --region "$REGION" --query 'trailList[?*]' --output json)
if [ -n "$iam_trails" ] && [ "$iam_trails" != "[]" ]; then
    review_details+="<p>CloudTrail trails that can be used for user activity monitoring:</p><ul></ul>"
else
    review_details+="<p><span class='red'>No CloudTrail trails found in this region.</span></p>"
fi

config_recorders=$(aws configservice describe-configuration-recorders --region "$REGION" 2>/dev/null)
if [ $? -eq 0 ] && [ -n "$config_recorders" ]; then
    records_iam_resources=$(echo "$config_recorders" | grep -c "resourceTypes.*iam")
    if [ "$records_iam_resources" -gt 0 ]; then
        review_details+="<p><span class='green'>AWS Config is recording IAM resource changes, which is useful for user access reviews.</span></p>"
    else
        review_details+="<p><span class='yellow'>AWS Config is enabled but may not be recording IAM resource changes. Configure AWS Config to record IAM resources.</span></p>"
    fi
else
    review_details+="<p><span class='yellow'>AWS Config is not enabled in this region. Consider enabling it to track IAM resource configurations and changes.</span></p>"
fi

review_details+="<h4>Credential Usage Analysis</h4>"
review_details+="<p>No access keys found in the account.</p>"

user_details=$(aws iam list-users --region "$REGION" --query 'Users[*].[UserName,CreateDate,PasswordLastUsed]' --output text 2>/dev/null)
if [ -n "$user_details" ]; then
    review_details+="<p>User activity analysis:</p><table border='1' cellpadding='5'><tr><th>Username</th><th>Created</th><th>Password Last Used</th><th>Inactive Days</th></tr>"
    current_date=$(date +%s)
    inactive_users_found=false
    while IFS=$'\t' read -r username create_date last_used; do
        if [ "$last_used" == "None" ] || [ "$last_used" == "null" ]; then
            last_used="Never used"
            inactive_days="N/A"
        else
            last_used_epoch=$(date -d "$last_used" +%s 2>/dev/null || date -d "$(echo $last_used | sed 's/T/ /g' | cut -d '+' -f1)" +%s 2>/dev/null)
            if [ -n "$last_used_epoch" ]; then
                inactive_days=$(( (current_date - last_used_epoch) / 86400 ))
            else
                inactive_days="Unknown"
            fi
        fi
        
        row_style=""
        if [ "$inactive_days" != "N/A" ] && [ "$inactive_days" != "Unknown" ] && [ $inactive_days -gt 90 ]; then
            row_style=" class='red'"
            inactive_users_found=true
        fi
        review_details+="<tr$row_style><td>$username</td><td>$create_date</td><td>$last_used</td><td>$inactive_days</td></tr>"
    done <<< "$user_details"
    review_details+="</table>"
    
    if [ "$inactive_users_found" = true ]; then
        review_details+="<p><span class='red'>Warning: Some users have been inactive for over 90 days. Consider disabling or removing these accounts.</span></p>"
    fi
fi

review_details+="<p>Note: AWS only maintains limited historical information about user activity. For comprehensive access reviews, implement additional logging and monitoring solutions.</p>"

report_item "8.6.1-3 - Review User Access" "warning" "$review_details<p>Please implement a formal process to review user accounts and access privileges at least once every six months.</p>" "Implement a formal process to review user accounts and access privileges at least once every six months. Enable AWS IAM Access Analyzer, CloudTrail, and AWS Config to support access reviews. Rotate credentials regularly and remove inactive accounts."

# === 10.1.1 - Implementation of audit trails ===
echo "Checking 10.1.1 - Implementation of audit trails..."
trails=$(aws cloudtrail describe-trails --region "$REGION")
trail_count=$(echo "$trails" | jq '.trailList | length')
if [ "$trail_count" -eq 0 ]; then
    report_item "10.1.1 - Implementation of audit trails" "fail" "<p class=\"red\">No CloudTrail trails found in region $REGION.</p>" "Ensure CloudTrail is enabled in all regions with at least one multi-region trail."
else
    audit_details="<p>CloudTrail trails found:</p><ul>"
    overall_trail_status="pass"
    for ((i=0; i<$trail_count; i++)); do
        trail_name=$(echo "$trails" | jq -r ".trailList[$i].Name")
        trail_home_region=$(echo "$trails" | jq -r ".trailList[$i].HomeRegion")
        is_multi_region=$(echo "$trails" | jq -r ".trailList[$i].IsMultiRegionTrail")
        trail_status=$(aws cloudtrail get-trail-status --name $trail_name --region "$REGION" 2>/dev/null || echo '{"IsLogging": false}')
        is_logging=$(echo "$trail_status" | jq -r '.IsLogging')
        if [ "$is_logging" = "true" ]; then
            audit_details+="<li class=\"green\">Trail: $trail_name (Home Region: $trail_home_region, Multi-Region: $is_multi_region) - <strong>Logging is enabled</strong></li>"
        else
            audit_details+="<li class=\"red\">Trail: $trail_name (Home Region: $trail_home_region, Multi-Region: $is_multi_region) - <strong>Logging is disabled</strong></li>"
            overall_trail_status="fail"
        fi
    done
    audit_details+="</ul>"
    has_multi_region=$(echo "$trails" | jq '.trailList[] | select(.IsMultiRegionTrail==true) | .Name' | wc -l)
    if [ "$has_multi_region" -eq 0 ]; then
        audit_details+="<p class=\"red\">Warning: No multi-region trails found. PCI DSS recommends logging across all regions.</p>"
        overall_trail_status="fail"
    else
        audit_details+="<p class=\"green\">Multi-region trail(s) found, providing coverage across all AWS regions.</p>"
    fi
    report_item "10.1.1 - Implementation of audit trails" "$overall_trail_status" "$audit_details" "Ensure CloudTrail is enabled in all regions with at least one multi-region trail."
fi

# === 10.4.1-10.4.3 - Log review and monitoring process ===
echo "Checking 10.4.1-10.4.3 - Log review and monitoring process..."
guardduty=$(aws guardduty list-detectors --region "$REGION" 2>/dev/null || echo '{"DetectorIds": []}')
detector_count=$(echo "$guardduty" | jq '.DetectorIds | length')
anomaly_status="pass"
anomaly_details=""
if [ "$detector_count" -eq 0 ]; then
    anomaly_details="<p class=\"yellow\">GuardDuty is not enabled in region $REGION.</p>"
    anomaly_status="warning"
else
    anomaly_details="<p class=\"green\">GuardDuty is enabled in region $REGION, which provides log anomaly detection and threat monitoring.</p>"
    for detector_id in $(echo "$guardduty" | jq -r '.DetectorIds[]'); do
        detector_status=$(aws guardduty get-detector --detector-id $detector_id --region "$REGION")
        finding_status=$(echo "$detector_status" | jq -r '.Status')
        if [ "$finding_status" = "ENABLED" ]; then
            anomaly_details+="<p class=\"green\">GuardDuty detector $detector_id is enabled and actively monitoring.</p>"
        else
            anomaly_details+="<p class=\"yellow\">GuardDuty detector $detector_id is disabled. Please enable for proper threat monitoring.</p>"
            anomaly_status="warning"
        fi
    done
fi
security_hub=$(aws securityhub describe-hub --region "$REGION" 2>/dev/null || echo '{"HubArn": ""}')
if [ -z "$(echo "$security_hub" | jq -r '.HubArn')" ]; then
    anomaly_details+="<p class=\"yellow\">AWS Security Hub is not enabled in region $REGION.</p>"
else
    anomaly_details+="<p class=\"green\">AWS Security Hub is enabled in region $REGION, which helps aggregate security findings, including log-based alerts.</p>"
fi
anomaly_details+="<p>PCI DSS requires mechanisms to detect unauthorized modifications to logs and alerts for anomalous or suspicious activities.</p>"
report_item "10.4.1-10.4.3 - Log review and monitoring process" "$anomaly_status" "$anomaly_details" "Enable GuardDuty and Security Hub for automated log analysis and threat detection. Requirement 10.4.1 requires daily review of security events and logs from critical systems. Requirement 10.4.1.1 requires using automated mechanisms for log reviews. Requirement 10.4.2 requires periodic review of all other logs. Requirement 10.4.3 requires addressing exceptions and anomalies."

# === 10.5.1 - CloudWatch Log Groups ===
echo "Collecting CloudWatch Log Groups (with retention color)..."
loggroups=$(aws logs describe-log-groups --region "$REGION" --query 'logGroups[*].{Name:logGroupName,Retention:retentionInDays}' --output json 2>/dev/null)
logs_html="<h4>CloudWatch Log Groups:</h4><ul>"
overall_status="pass"
if [ -n "$loggroups" ] && [ "$loggroups" != "[]" ]; then
    for row in $(echo "$loggroups" | jq -c '.[]'); do
        name=$(echo "$row" | jq -r '.Name')
        retention=$(echo "$row" | jq -r '.Retention // "Never Expire"')
        if [ "$retention" != "Never Expire" ] && [ "$retention" -lt 365 ]; then
            logs_html+="<li class=\"red\"><strong>$name</strong> (Retention: $retention days)</li>"
            overall_status="fail"
        else
            logs_html+="<li class=\"green\"><strong>$name</strong> (Retention: $retention days)</li>"
        fi
    done
else
    logs_html+="<li>No Log Groups found</li>"
fi
logs_html+="</ul>"
report_item "10.5.1 - CloudWatch Log Groups" "$overall_status" "$logs_html" "CloudWatch log groups must retain logs for at least 365 days to meet audit requirements."

# === 11.3.1 - Internal Vulnerability Scanning ===
echo "Checking 11.3.1 - Internal Vulnerability Scanning..."
inspector_status=$(aws inspector2 list-findings --region "$REGION" --max-results 1 2>/dev/null)
vuln_details=""
if [ $? -eq 0 ]; then
    findings_count=$(aws inspector2 list-findings --region "$REGION" --query 'findings | length(@)' 2>/dev/null)
    vuln_details+="<p>AWS Inspector is enabled:</p><ul>"
    vuln_details+="<li>Active findings: $findings_count</li>"
    critical_count=$(aws inspector2 list-findings --region "$REGION" --filter 'severities={CRITICAL}' --query 'findings | length(@)' 2>/dev/null)
    high_count=$(aws inspector2 list-findings --region "$REGION" --filter 'severities={HIGH}' --query 'findings | length(@)' 2>/dev/null)
    critical_count=${critical_count:-0}
    high_count=${high_count:-0}
    vuln_details+="<li>Critical vulnerabilities: $critical_count</li><li>High vulnerabilities: $high_count</li></ul>"
    if [ "$critical_count" -gt 0 ] || [ "$high_count" -gt 0 ]; then
        vuln_details+="<p class='red'>WARNING: There are unresolved critical or high vulnerabilities.</p>"
        report_item "11.3.1 - Internal Vulnerability Scanning" "fail" "$vuln_details" "Address critical and high vulnerabilities identified by AWS Inspector immediately."
    else
        vuln_details+="<p class='green'>No critical or high vulnerabilities detected.</p>"
        report_item "11.3.1 - Internal Vulnerability Scanning" "pass" "$vuln_details" ""
    fi
else
    vuln_details+="<p>AWS Inspector is not enabled in this region. Consider enabling AWS Inspector for automated vulnerability assessments.</p>"
    report_item "11.3.1 - Internal Vulnerability Scanning" "warning" "$vuln_details" "Consider enabling AWS Inspector for automated vulnerability assessments."
fi

# === 11.5.1 - Intrusion Detection Systems ===
echo "Checking 11.5.1 - Intrusion Detection Systems..."
if [ "$TARGET_VPCS" == "None" ]; then
    report_item "11.5.1 - Intrusion Detection Systems" "fail" "No VPCs found to check for IDS." "Implement an Intrusion Detection System (IDS) or Intrusion Prevention System (IPS)."
else
    for vpc_id in $TARGET_VPCS; do
        ids_details=""
        has_ids=false
        
        guardduty_detectors=$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds' --output text 2>/dev/null)
        if [ -n "$guardduty_detectors" ]; then
            has_ids=true
            ids_details+="<p class='green'>Amazon GuardDuty is enabled in this region, which provides intrusion detection capabilities:</p><ul>"
            for detector in $guardduty_detectors; do
                detector_details=$(aws guardduty get-detector --detector-id "$detector" --region "$REGION" --output json 2>/dev/null)
                ids_details+="<li>Detector ID: $detector</li>"
                if echo "$detector_details" | grep -q '"Status": "ENABLED"'; then
                    ids_details+="<li class='green'>Status: ENABLED</li>"
                else
                    ids_details+="<li class='red'>Status: DISABLED</li>"
                    has_ids=false
                fi
            done
            ids_details+="</ul>"
        else
            ids_details+="<p class='yellow'>Amazon GuardDuty is not enabled in this region.</p>"
        fi
        
        nfw_firewalls=$(aws network-firewall list-firewalls --region "$REGION" 2>/dev/null | grep -i "firewall")
        if [ -n "$nfw_firewalls" ]; then
            has_ids=true
            ids_details+="<p class='green'>AWS Network Firewall is deployed in this region, which can provide network threat detection and prevention:</p><pre>$nfw_firewalls</pre>"
        else
            ids_details+="<p>AWS Network Firewall is not detected in this region.</p>"
        fi
        
        flow_logs=$(aws ec2 describe-flow-logs --region "$REGION" --filter "Name=resource-id,Values=$vpc_id" --query 'FlowLogs[*].[FlowLogId,LogDestination]' --output text 2>/dev/null)
        if [ -n "$flow_logs" ]; then
            ids_details+="<p class='green'>VPC Flow Logs are enabled for VPC $vpc_id, which can help with network traffic analysis:</p><pre>$flow_logs</pre>"
        else
            ids_details+="<p>VPC Flow Logs are not enabled for VPC $vpc_id. Consider enabling flow logs to aid in network traffic analysis.</p>"
        fi
        
        trails=$(aws cloudtrail describe-trails --region "$REGION" --query 'trailList[*].[Name,HomeRegion,IsMultiRegionTrail]' --output text 2>/dev/null)
        if [ -n "$trails" ]; then
            ids_details+="<p class='green'>AWS CloudTrail is configured, which logs AWS API activity:</p><pre>$trails</pre>"
        fi
        
        if [ "$has_ids" = true ]; then
            report_item "11.5.1 - Intrusion Detection Systems (VPC: $vpc_id)" "pass" "$ids_details" ""
        else
            report_item "11.5.1 - Intrusion Detection Systems (VPC: $vpc_id)" "fail" "$ids_details" "Implement an Intrusion Detection System (IDS) or Intrusion Prevention System (IPS) such as Amazon GuardDuty or AWS Network Firewall to monitor all traffic at the perimeter of the CDE and at critical points in the CDE."
        fi
    done
fi

cat << EOF >> "$HTML_FILE"
</body>
</html>
EOF

echo "--------------------------------------------------------"
echo "報表生成完畢！檔案存檔至：${HTML_FILE}"
echo "請接著執行 gen_clean_summary_aws.py 以獲得統整結果。"