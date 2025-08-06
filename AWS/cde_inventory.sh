#!/bin/bash
OUTPUT_FILE="cde_inventory_report.html"
FILTER_VPC="$1"  # 第一個參數 (VPC ID 或 Name)，空值時查全部

# Ask user to specify region
if [ -z "$REGION" ]; then
    read -p "Enter AWS region to test (e.g., us-east-1): " REGION
    if [ -z "$REGION" ]; then
        REGION="ap-southeast-1"
        echo -e "${YELLOW}Using default region: $REGION${NC}"
    fi
fi
# 初始化 HTML 報告
echo "<html><head><meta charset='UTF-8'><style>
body { font-family: Arial, sans-serif; }
h2 { color: #2c3e50; margin-top: 30px; }
h3 { color: #34495e; margin-top: 20px; }
table { border-collapse: collapse; width: 100%; margin-bottom: 20px; font-size: 14px; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f4f4f4; }
.green { color: green; font-weight: bold; }
.red { color: red; font-weight: bold; }
div.section { margin: 20px 0; padding: 10px; border: 1px solid #ccc; background: #fafafa; }
</style></head><body>" > "$OUTPUT_FILE"

echo "<h1>AWS CDE Inventory Report</h1>" >> "$OUTPUT_FILE"
echo "<p>Region: $REGION</p>" >> "$OUTPUT_FILE"

FILTER_VPCS=()
for arg in "$@"; do
    if [[ "$arg" == vpc-* ]]; then
        # 直接是 VPC ID
        FILTER_VPCS+=("$arg")
    else
        # 先嘗試用 tag:Name 查
        matched=$(aws ec2 describe-vpcs --region "$REGION" \
			--filters "Name=tag:Name,Values=*$arg*" \
			--query 'Vpcs[*].VpcId' --output text 2>/dev/null | tr -d '\r')


        # 如果沒找到，直接把輸入當作 VPC ID 再查一次
        if [[ -z "$matched" ]]; then
            matched=$(aws ec2 describe-vpcs --region "$REGION" \
                --vpc-ids "$arg" \
                --query 'Vpcs[*].VpcId' --output text 2>/dev/null)
        fi

        if [[ -z "$matched" ]]; then
            echo "Warning: No VPC found for: $arg" >&2
        else
            for vpc_id in $matched; do
                FILTER_VPCS+=("$vpc_id")
            done
        fi
    fi
done

# 初始化 vpcs JSON 陣列
vpcs="[]"

if [[ ${#FILTER_VPCS[@]} -eq 0 ]]; then
    echo "No VPC specified, querying all VPCs..."
    result=$(aws ec2 describe-vpcs --region "$REGION" \
        --query 'Vpcs[*].{VpcId:VpcId,CIDR:CidrBlock,Name:Tags[?Key==`Name`]|[0].Value}' \
        --output json 2>/dev/null)
    vpcs="$result"
else
    for vpc_id in "${FILTER_VPCS[@]}"; do
        result=$(aws ec2 describe-vpcs --region "$REGION" \
            --vpc-ids "$vpc_id" \
            --query 'Vpcs[*].{VpcId:VpcId,CIDR:CidrBlock,Name:Tags[?Key==`Name`]|[0].Value}' \
            --output json 2>/dev/null)

        # 確保 result 不是空的
        if [[ -n "$result" && "$result" != "[]" ]]; then
            vpcs=$(jq -s 'add' <(echo "$vpcs") <(echo "$result"))
        fi
    done
fi

# Debug 輸出：看實際抓到哪些 VPC
echo "DEBUG: Collected VPCs:" >&2
echo "$vpcs" | jq . >&2



# === 1. CDE VPC & 子網路資訊 ===
echo -e "\n===== [ 1 ] 處理 VPC 清單與子網路資訊 ====="
echo "<h2>1. CDE VPCs and Subnets</h2>" >> "$OUTPUT_FILE"

if [ -z "$vpcs" ] || [ "$vpcs" == "[]" ]; then
    echo "<p>No matching VPCs found.</p>" >> "$OUTPUT_FILE"
else
    echo "$vpcs" | jq -c '.[]' | while read vpc; do
        vpc_id=$(echo "$vpc" | jq -r '.VpcId')
        vpc_name=$(echo "$vpc" | jq -r '.Name // "N/A"')
        vpc_cidr=$(echo "$vpc" | jq -r '.CIDR // "-"')

        echo "<div class='section'>" >> "$OUTPUT_FILE"
        echo "<strong>VPC:</strong> $vpc_name ($vpc_id)<br>" >> "$OUTPUT_FILE"
        echo "<strong>CIDR:</strong> $vpc_cidr<br>" >> "$OUTPUT_FILE"

        # 列出該 VPC 子網路
        subnets=$(aws ec2 describe-subnets --region "$REGION" \
            --filters "Name=vpc-id,Values=$vpc_id" \
            --query 'Subnets[*].{SubnetId:SubnetId,CIDR:CidrBlock,AZ:AvailabilityZone}' \
            --output json 2>/dev/null)

        if [ -z "$subnets" ] || [ "$subnets" == "[]" ]; then
            echo "<p>No subnets found.</p>" >> "$OUTPUT_FILE"
        else
            echo "<table><tr><th>Subnet ID</th><th>CIDR Block</th><th>Availability Zone</th></tr>" >> "$OUTPUT_FILE"
            echo "$subnets" | jq -c '.[]' | while read subnet; do
                subnet_id=$(echo "$subnet" | jq -r '.SubnetId // "-"')
                subnet_cidr=$(echo "$subnet" | jq -r '.CIDR // "-"')
                subnet_az=$(echo "$subnet" | jq -r '.AZ // "-"')
                echo "<tr><td>$subnet_id</td><td>$subnet_cidr</td><td>$subnet_az</td></tr>" >> "$OUTPUT_FILE"
            done
            echo "</table>" >> "$OUTPUT_FILE"
        fi
        echo "</div>" >> "$OUTPUT_FILE"
    done
fi

# === 2. 列出特定 VPC 內所有 EC2 執行個體 ===
echo -e "\n===== [ 2 ] 列出 EC2 實例資訊 ====="
echo "<h2>2. EC2 Instances by VPC</h2>" >> "$OUTPUT_FILE"

if [ -n "$vpcs" ] && [ "$vpcs" != "[]" ]; then
    echo "$vpcs" | jq -c '.[]' | while read vpc; do
        vpc_id=$(echo "$vpc" | jq -r '.VpcId')
        vpc_name=$(echo "$vpc" | jq -r '.Name // "N/A"')

        echo "<h3>VPC: $vpc_name ($vpc_id)</h3>" >> "$OUTPUT_FILE"

        # 查詢所有 Instance，抓 Name, PrivateIP, PublicIP, State
        instances=$(aws ec2 describe-instances --region "$REGION" \
            --filters "Name=vpc-id,Values=$vpc_id" \
            --query "Reservations[*].Instances[*].{InstanceId:InstanceId,Name:Tags[?Key=='Name']|[0].Value,PrivateIP:PrivateIpAddress,PublicIP:PublicIpAddress,State:State.Name}" \
            --output json 2>/dev/null)

        if [ -z "$instances" ] || [ "$instances" == "[]" ]; then
            echo "<p>No EC2 instances found.</p>" >> "$OUTPUT_FILE"
            continue
        fi

        echo "<table><tr><th>Instance ID</th><th>Name</th><th>Private IP</th><th>Public IP</th><th>State</th></tr>" >> "$OUTPUT_FILE"

        echo "$instances" | jq -c '.[][]? // empty' | while read inst; do
            inst_id=$(echo "$inst" | jq -r '.InstanceId')
            inst_name=$(echo "$inst" | jq -r '.Name // "N/A"')
            private_ip=$(echo "$inst" | jq -r '.PrivateIP // "N/A"')
            public_ip=$(echo "$inst" | jq -r '.PublicIP // "N/A"')
            state=$(echo "$inst" | jq -r '.State')

            # 狀態加上顏色
            case "$state" in
                running) state_disp="<span class='green'>$state</span>" ;;
                stopped|terminated) state_disp="<span class='red'>$state</span>" ;;
                *) state_disp="<span class='orange'>$state</span>" ;;
            esac

            echo "<tr><td>$inst_id</td><td>$inst_name</td><td>$private_ip</td><td>$public_ip</td><td>$state_disp</td></tr>" >> "$OUTPUT_FILE"
        done

        echo "</table>" >> "$OUTPUT_FILE"
    done
else
    echo "<p>No VPCs found to check instances.</p>" >> "$OUTPUT_FILE"
fi



# === 3. 檢查 VPC 中 EC2 是否暴露到 Internet (SG 規則檢查) ===
echo -e "\n===== [ 3 ] 分析 EC2 是否暴露至 Internet ====="
echo "<h2>3. Internet-Exposed EC2 Instances (0.0.0.0/0 or ::/0 Inbound)</h2>" >> "$OUTPUT_FILE"

if [ -n "$vpcs" ] && [ "$vpcs" != "[]" ]; then
    echo "$vpcs" | jq -c '.[]' | while read vpc; do
        vpc_id=$(echo "$vpc" | jq -r '.VpcId')
        vpc_name=$(echo "$vpc" | jq -r '.Name // "N/A"')

        echo "<h3>VPC: $vpc_name ($vpc_id)</h3>" >> "$OUTPUT_FILE"

        # 抓取 VPC 內所有 Instance 和 Security Groups (Name + ID)
        instances=$(aws ec2 describe-instances --region "$REGION" \
            --filters "Name=vpc-id,Values=$vpc_id" \
            --query "Reservations[*].Instances[*].{InstanceId:InstanceId,Name:Tags[?Key=='Name']|[0].Value,SGs:SecurityGroups[*].{Name:GroupName,Id:GroupId}}" \
            --output json 2>/dev/null)

        if [ -z "$instances" ] || [ "$instances" == "[]" ]; then
            echo "<p>No EC2 instances found.</p>" >> "$OUTPUT_FILE"
            continue
        fi

        echo "<table><tr><th>Instance ID</th><th>Name</th><th>Security Groups</th><th>Risk (Open Ports)</th></tr>" >> "$OUTPUT_FILE"

        echo "$instances" | jq -c '.[][]? // empty' | while read inst; do
            inst_id=$(echo "$inst" | jq -r '.InstanceId')
            inst_name=$(echo "$inst" | jq -r '.Name // "N/A"')

            # 將 Security Groups 轉成每行一個 "Name (ID)"
            sgs_lines=$(echo "$inst" | jq -r '.SGs[]? | "\(.Name) (\(.Id))"' | sed 's/^/<div>/; s/$/<\/div>/' | tr -d '\r')

            # SG ID 清單 (用於檢查 inbound 規則)
            sg_ids=$(echo "$inst" | jq -r '.SGs[].Id')

            risk_details=""
            for sg in $sg_ids; do
                sg_name=$(echo "$inst" | jq -r ".SGs[] | select(.Id==\"$sg\") | .Name")
                sg_display="$sg_name ($sg)"

                inbound=$(aws ec2 describe-security-groups --region "$REGION" \
                    --group-ids "$sg" \
                    --query "SecurityGroups[*].IpPermissions[]" \
                    --output json 2>/dev/null)

                open_rules=$(echo "$inbound" | jq -c '
                    map(select((.IpRanges[]?.CidrIp=="0.0.0.0/0") or (.Ipv6Ranges[]?.CidrIpv6=="::/0")))
                    | map({Protocol: .IpProtocol, From: .FromPort, To: .ToPort})')

                if [ -n "$open_rules" ] && [ "$open_rules" != "[]" ]; then
                    rule_text=$(echo "$open_rules" | jq -r '.[] | "\(.Protocol):\(.From)-\(.To)"' | paste -sd ", " -)
                    risk_details+="$sg_display [$rule_text];<br>"
                fi
            done

            if [ -n "$risk_details" ]; then
                risk="<span class='red'>$risk_details</span>"
            else
                risk="<span class='green'>None</span>"
            fi

            echo "<tr><td>$inst_id</td><td>$inst_name</td><td>$sgs_lines</td><td>$risk</td></tr>" >> "$OUTPUT_FILE"
        done

        echo "</table>" >> "$OUTPUT_FILE"
    done
else
    echo "<p>No VPCs to analyze for Internet exposure.</p>" >> "$OUTPUT_FILE"
fi


# === 4. 檢查 Load Balancer 配置 ===
echo -e "\n===== [ 4 ] 檢查 Load Balancer 設定與 WAF 綁定 ====="
echo "<h2>4. Load Balancer Configuration</h2>" >> "$OUTPUT_FILE"

fail_flag=false

# 抓取所有對外 ALB
albs=$(aws elbv2 describe-load-balancers --region "$REGION" \
    --query "LoadBalancers[?Scheme=='internet-facing']" --output json 2>/dev/null)

# 抓取所有對外 CLB
clbs=$(aws elb describe-load-balancers --region "$REGION" \
    --query "LoadBalancerDescriptions[?Scheme=='internet-facing']" --output json 2>/dev/null)

if { [ -z "$albs" ] || [ "$albs" == "[]" ]; } && { [ -z "$clbs" ] || [ "$clbs" == "[]" ]; }; then
    echo "<p>No internet-facing Load Balancers found.</p>" >> "$OUTPUT_FILE"
else
    # 處理 ALBs
    if [ -n "$albs" ] && [ "$albs" != "[]" ]; then
        echo "<h3>Application Load Balancers (ALB)</h3>" >> "$OUTPUT_FILE"
        echo "$albs" | jq -c '.[]' | while read alb; do
            alb_name=$(echo "$alb" | jq -r '.LoadBalancerName')
            alb_arn=$(echo "$alb" | jq -r '.LoadBalancerArn')
            alb_dns=$(echo "$alb" | jq -r '.DNSName')

            echo "<div style='border:1px solid #ccc; padding:10px; margin:10px 0;'>" >> "$OUTPUT_FILE"
            echo "<strong>ALB Name:</strong> $alb_name<br>" >> "$OUTPUT_FILE"
            echo "<strong>DNS:</strong> $alb_dns<br>" >> "$OUTPUT_FILE"

            # 查 Listener
            listeners=$(aws elbv2 describe-listeners --region "$REGION" \
                --load-balancer-arn "$alb_arn" \
                --query "Listeners[*].{Port:Port,Protocol:Protocol,SslPolicy:SslPolicy}" \
                --output json 2>/dev/null)

            if [ -n "$listeners" ] && [ "$listeners" != "[]" ]; then
                echo "<strong>Listeners:</strong><ul>" >> "$OUTPUT_FILE"
                echo "$listeners" | jq -c '.[]' | while read lst; do
                    port=$(echo "$lst" | jq -r '.Port')
                    proto=$(echo "$lst" | jq -r '.Protocol')
                    policy=$(echo "$lst" | jq -r '.SslPolicy // "N/A"')
                    echo "<li>Port $port - $proto<br><small>SSL Policy: $policy</small></li>" >> "$OUTPUT_FILE"
                done
                echo "</ul>" >> "$OUTPUT_FILE"
            fi

            # 查 WAF 綁定
            web_acls=$(aws wafv2 list-resources-for-web-acl --region "$REGION" \
                --resource-arn "$alb_arn" --scope REGIONAL \
                --query 'ResourceArns' --output json 2>/dev/null)

            if [ -n "$web_acls" ] && [ "$web_acls" != "[]" ]; then
                echo "<div style='color:green; font-weight:bold;'>WAF Attached</div>" >> "$OUTPUT_FILE"
            else
                echo "<div style='color:red; font-weight:bold;'>No WAF Attached</div>" >> "$OUTPUT_FILE"
                fail_flag=true
            fi

            echo "</div>" >> "$OUTPUT_FILE"
        done
    fi

    # 處理 CLBs
    if [ -n "$clbs" ] && [ "$clbs" != "[]" ]; then
        echo "<h3>Classic Load Balancers (CLB)</h3>" >> "$OUTPUT_FILE"
        echo "$clbs" | jq -c '.[]' | while read clb; do
            clb_name=$(echo "$clb" | jq -r '.LoadBalancerName')
            clb_dns=$(echo "$clb" | jq -r '.DNSName')
            echo "<div style='border:1px solid #ccc; padding:10px; margin:10px 0;'>" >> "$OUTPUT_FILE"
            echo "<strong>CLB Name:</strong> $clb_name<br>" >> "$OUTPUT_FILE"
            echo "<strong>DNS:</strong> $clb_dns<br>" >> "$OUTPUT_FILE"
            echo "<div style='color:blue;'>Note: CLBs cannot attach WAF directly. Verify application-level protections.</div>" >> "$OUTPUT_FILE"
            echo "</div>" >> "$OUTPUT_FILE"
        done
    fi
fi

# === 5. 檢查 IAM 帳號是否啟用 MFA 認證機制 ===
echo -e "\n===== [ 5 ] 檢查 IAM 使用者 MFA 設定 ====="
echo "<h2>5. IAM Users MFA Enforcement</h2>" >> "$OUTPUT_FILE"

fail_flag=false

# 抓取所有 IAM 使用者
users=$(aws iam list-users --query 'Users[*].UserName' --output json 2>/dev/null)

if [ -z "$users" ] || [ "$users" == "[]" ]; then
    echo "<p>No IAM users found.</p>" >> "$OUTPUT_FILE"
else
    echo "<table><tr><th>User Name</th><th>MFA Devices</th><th>Status</th></tr>" >> "$OUTPUT_FILE"

    echo "$users" | jq -r '.[]' | while read user; do
        # 列出該使用者的 MFA 裝置
        mfa_devices=$(aws iam list-mfa-devices --user-name "$user" \
            --query 'MFADevices[*].SerialNumber' --output json 2>/dev/null)

        if [ -n "$mfa_devices" ] && [ "$mfa_devices" != "[]" ]; then
            mfa_list=$(echo "$mfa_devices" | jq -r '.[]' | paste -sd ", " -)
            status="<span class='green'>MFA Enabled</span>"
        else
            mfa_list="None"
            status="<span class='red'>MFA Missing</span>"
            fail_flag=true
        fi

        echo "<tr><td>$user</td><td>$mfa_list</td><td>$status</td></tr>" >> "$OUTPUT_FILE"
    done

    echo "</table>" >> "$OUTPUT_FILE"
fi

# === 6. 列出所有 S3 儲存桶及其訪問控制 ===
echo -e "\n===== [ 6 ] 檢查 S3 Bucket 的 ACL 與 Public Access 設定 ====="
echo "<h2>6. S3 Buckets and Access Control</h2>" >> "$OUTPUT_FILE"

# 列出所有 S3 buckets
buckets=$(aws s3api list-buckets --query "Buckets[*].Name" --output json 2>/dev/null)

if [ -z "$buckets" ] || [ "$buckets" == "[]" ]; then
    echo "<p>No S3 buckets found.</p>" >> "$OUTPUT_FILE"
else
    echo "<table><tr><th>Bucket Name</th><th>Public Access Block</th><th>ACL Grantees</th></tr>" >> "$OUTPUT_FILE"

    echo "$buckets" | jq -r '.[]' | while read bucket; do
        # 取得 Public Access Block 設定
        pab=$(aws s3api get-public-access-block --bucket "$bucket" --output json 2>/dev/null || echo "{}")
        pab_value=$(echo "$pab" | jq -r '.PublicAccessBlockConfiguration.BlockPublicAcls // false')

        # 顯示顏色
        if [ "$pab_value" == "true" ]; then
            pab_display="<span class='green'>true</span>"
        else
            pab_display="<span class='red'>false</span>"
        fi

        # 取得 ACL，列出授權對象 (只顯示 AllUsers/AuthenticatedUsers，其他 canonical user 忽略)
        acl=$(aws s3api get-bucket-acl --bucket "$bucket" --output json 2>/dev/null)
        acl_grantees=$(echo "$acl" | jq -r '.Grants[]?.Grantee.URI? // empty' | sed 's#.*/##' | paste -sd ", " -)

        if [ -z "$acl_grantees" ]; then
            acl_grantees="None"
        fi

        echo "<tr><td>$bucket</td><td>$pab_display</td><td>$acl_grantees</td></tr>" >> "$OUTPUT_FILE"
    done

    echo "</table>" >> "$OUTPUT_FILE"
fi

# === 7. 檢查 VPC 對等連接 ===
echo -e "\n===== [ 7 ] 檢查 VPC Peering 設定 ====="
echo "<h2>7. VPC Peering Connections</h2>" >> "$OUTPUT_FILE"

# 查詢所有 VPC Peering Connections
peerings=$(aws ec2 describe-vpc-peering-connections --region "$REGION" \
    --query 'VpcPeeringConnections[*].{Id:VpcPeeringConnectionId,Name:Tags[?Key==`Name`]|[0].Value,Status:Status.Code,Requester:RequesterVpcInfo.VpcId,RequesterCIDR:RequesterVpcInfo.CidrBlock,Accepter:AccepterVpcInfo.VpcId,AccepterCIDR:AccepterVpcInfo.CidrBlock}' \
    --output json 2>/dev/null)

if [ -z "$peerings" ] || [ "$peerings" == "[]" ]; then
    echo "<p>No VPC Peering Connections found.</p>" >> "$OUTPUT_FILE"
else
    echo "<table><tr><th>Name</th><th>Peering ID</th><th>Requester VPC</th><th>Accepter VPC</th><th>Status</th></tr>" >> "$OUTPUT_FILE"

    echo "$peerings" | jq -c '.[]' | while read peering; do
        name=$(echo "$peering" | jq -r '.Name // "N/A"')
        peer_id=$(echo "$peering" | jq -r '.Id')
        requester_vpc=$(echo "$peering" | jq -r '.Requester')
        requester_cidr=$(echo "$peering" | jq -r '.RequesterCIDR // "N/A"')
        accepter_vpc=$(echo "$peering" | jq -r '.Accepter')
        accepter_cidr=$(echo "$peering" | jq -r '.AccepterCIDR // "N/A"')
        status=$(echo "$peering" | jq -r '.Status')

        # 查詢 VPC Name (tag:Name)
        requester_name=$(aws ec2 describe-vpcs --region "$REGION" \
            --vpc-ids "$requester_vpc" \
            --query 'Vpcs[0].Tags[?Key==`Name`]|[0].Value' --output text 2>/dev/null)
        accepter_name=$(aws ec2 describe-vpcs --region "$REGION" \
            --vpc-ids "$accepter_vpc" \
            --query 'Vpcs[0].Tags[?Key==`Name`]|[0].Value' --output text 2>/dev/null)

        if [ -z "$requester_name" ] || [ "$requester_name" == "None" ]; then requester_name="N/A"; fi
        if [ -z "$accepter_name" ] || [ "$accepter_name" == "None" ]; then accepter_name="N/A"; fi

        # 狀態顏色
        case "$status" in
            active) status_disp="<span class='green'>$status</span>" ;;
            pending-acceptance|provisioning) status_disp="<span class='orange'>$status</span>" ;;
            *) status_disp="<span class='red'>$status</span>" ;;
        esac

        echo "<tr>
                <td>$name</td>
                <td>$peer_id</td>
                <td>$requester_name ($requester_vpc)<br>CIDR: $requester_cidr</td>
                <td>$accepter_name ($accepter_vpc)<br>CIDR: $accepter_cidr</td>
                <td>$status_disp</td>
              </tr>" >> "$OUTPUT_FILE"
    done

    echo "</table>" >> "$OUTPUT_FILE"
fi


echo "</body></html>" >> "$OUTPUT_FILE"
echo "CDE Inventory report generated: $OUTPUT_FILE"

