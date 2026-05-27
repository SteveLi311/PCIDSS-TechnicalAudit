#!/usr/bin/env bash

# GCP PCI DSS 綜合檢測腳本 (完整版 1-12，針對 Python 摘要腳本優化)
# 此腳本整合了 Requirement 1 到 12 中所有被 target_keywords 標記的特定檢查項目，
# 並輸出成單一 HTML 報告，以利後續由 gen_clean_summary_gcp.py 進行解析。
# 輸出的報告內容已優化為包含各項細節（如具體 IP 網段、詳細 IAM 清單與金鑰狀態）。
# 終端提示與註解皆保留繁體中文。

# 載入共享函式庫 (沿用原有框架)
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh" || { echo "Cannot load gcp_common.sh"; exit 1; }
source "$LIB_DIR/gcp_permissions.sh" || { echo "Cannot load gcp_permissions.sh"; exit 1; }
source "$LIB_DIR/gcp_scope_mgmt.sh" || { echo "Cannot load gcp_scope_mgmt.sh"; exit 1; }
source "$LIB_DIR/gcp_html_report.sh" || { echo "Cannot load gcp_html_report.sh"; exit 1; }

# 腳本特定變數設定
REQUIREMENT_NUMBER="Consolidated_All"
REQUIREMENT_TITLE="PCI DSS Requirement 1-12 Consolidated Assessment"

# 定義 1-12 完整檢測所需的所有 GCP 權限清單
REQUIRED_PERMISSIONS=(
    "compute.networks.list"
    "compute.firewalls.list"
    "compute.instances.list"
    "compute.routes.list"
    "compute.routers.list"
    "compute.sslPolicies.list"
    "compute.targetHttpsProxies.list"
    "compute.sslCertificates.list"
    "compute.backendServices.list"
    "resourcemanager.projects.getIamPolicy"
    "iam.serviceAccounts.list"
    "cloudkms.keyRings.list"
    "cloudkms.cryptoKeys.list"
    "iap.web.getIamPolicy"
    "storage.buckets.list"
    "storage.buckets.getIamPolicy"
    "logging.sinks.list"
    "logging.logs.list"
)

# 顯示說明的函式
show_help() {
    echo "GCP PCI DSS Consolidated Assessment Script (Python Parser Ready)"
    echo "============================================================="
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -s, --scope SCOPE          Assessment scope: 'project' or 'organization' (default: project)"
    echo "  -p, --project PROJECT_ID   Specific project to assess (overrides current gcloud config)"
    echo "  -o, --org ORG_ID           Specific organization ID to assess (required for organization scope)"
    echo "  -h, --help                 Show this help message"
    echo ""
}

# 取得專案中的網路列表 (Req 1 使用)
get_project_networks() {
    local project_id="$1"
    gcloud compute networks list --project="$project_id" --format="value(name)" 2>/dev/null | grep -v "^$"
}

# =============================================================================
# 評估函式 (對應 Target Keywords 1-13 項)
# 確保標題與 HTML 內容完全為英文，以符合原始 Python 腳本的要求
# =============================================================================

# 1. 檢查不安全服務/通訊協定 (Req 1)
assess_insecure_services() {
    local project_id="$1"
    local check_title="Security features for insecure services/protocols"
    local details="<p>Detailed analysis of insecure services/protocols in firewall rules ($project_id):</p><ul>"
    local insecure_services=false
    local failed=0
    local warning=0

    # 取得防火牆規則詳情
    local firewall_rules
    firewall_rules=$(gcloud compute firewall-rules list --project="$project_id" --format="value(name,direction,sourceRanges.join(','),allowed[].map().firewall_rule().list():label=ALLOW,targetTags.join(','),network)" 2>/dev/null)

    while IFS=$'\t' read -r name direction sources allowed tags network; do
        [[ -z "$name" ]] && continue
        
        # 深度檢查不安全通訊協定
        if [[ "$allowed" == *"tcp:21"* ]]; then
            details+="<li><span class='text-fail'>Rule <strong>$name</strong></span> allows FTP (port 21) on network <em>$network</em>. Source ranges: [${sources}].</li>"
            insecure_services=true; ((failed++))
        fi
        if [[ "$allowed" == *"tcp:23"* ]]; then
            details+="<li><span class='text-fail'>Rule <strong>$name</strong></span> allows Telnet (port 23) on network <em>$network</em>. Source ranges: [${sources}].</li>"
            insecure_services=true; ((failed++))
        fi
        if [[ "$allowed" == *"tcp:1433"* ]]; then
            details+="<li><span class='text-warning'>Rule <strong>$name</strong></span> allows SQL Server (port 1433) on network <em>$network</em>. Source ranges: [${sources}].</li>"
            insecure_services=true; ((warning++))
        fi
        if [[ "$allowed" == *"tcp:3306"* ]]; then
            details+="<li><span class='text-warning'>Rule <strong>$name</strong></span> allows MySQL (port 3306) on network <em>$network</em>. Source ranges: [${sources}].</li>"
            insecure_services=true; ((warning++))
        fi
    done <<< "$firewall_rules"

    details+="</ul>"

    if [ "$insecure_services" = false ]; then
        add_check_result "$OUTPUT_FILE" "pass" "$check_title" "<p class='text-pass'>No common insecure services/protocols detected in firewall rules.</p>"
    elif [ $failed -gt 0 ]; then
        add_check_result "$OUTPUT_FILE" "fail" "$check_title" "$details"
    else
        add_check_result "$OUTPUT_FILE" "warning" "$check_title" "$details"
    fi
}

# 2 & 3. 檢查 CDE 的連入與連出限制 (Req 1)
assess_cde_restrictions() {
    local project_id="$1"
    local target_networks
    target_networks=$(get_project_networks "$project_id")

    # 連入檢查變數
    local in_title="Inbound traffic to CDE restriction"
    local in_details="<p>Detailed analysis of inbound traffic controls for CDE networks ($project_id):</p><ul>"
    local in_warn=0

    # 連出檢查變數
    local out_title="Outbound traffic from CDE restriction"
    local out_details="<p>Detailed analysis of outbound traffic controls for CDE networks ($project_id):</p><ul>"
    local out_warn=0

    for network in $target_networks; do
        [[ -z "$network" ]] && continue

        # 處理連入邏輯 (INGRESS)
        in_details+="<li><strong>Network: $network</strong></li><ul>"
        local in_rules
        in_rules=$(gcloud compute firewall-rules list --project="$project_id" --filter="network:$network AND direction:INGRESS" --format="value(name,sourceRanges.join(','),allowed[].map().firewall_rule().list():label=ALLOW)" 2>/dev/null)
        
        if [[ -n "$in_rules" ]]; then
            while IFS=$'\t' read -r fw_name sources allowed; do
                [[ -z "$fw_name" ]] && continue
                if [[ "$sources" == *"0.0.0.0/0"* ]]; then
                    in_details+="<li><span class='text-fail'>WARNING: Rule <strong>$fw_name</strong> allows traffic from ANYWHERE (0.0.0.0/0)</span> for <code>$allowed</code></li>"
                    ((in_warn++))
                else
                    in_details+="<li>Rule <strong>$fw_name</strong> allows <code>$allowed</code> from restricted range: <code>$sources</code> ✅</li>"
                fi
            done <<< "$in_rules"
        else
            in_details+="<li><span class='text-pass'>No active ingress firewall rules found for this network.</span></li>"
        fi
        in_details+="</ul>"

        # 處理連出邏輯 (EGRESS)
        out_details+="<li><strong>Network: $network</strong></li><ul>"
        local out_rules
        out_rules=$(gcloud compute firewall-rules list --project="$project_id" --filter="network:$network AND direction:EGRESS" --format="value(name,destinationRanges.join(','),allowed[].map().firewall_rule().list():label=ALLOW)" 2>/dev/null)
        
        if [[ -n "$out_rules" ]]; then
            while IFS=$'\t' read -r fw_name dests allowed; do
                [[ -z "$fw_name" ]] && continue
                if [[ "$dests" == *"0.0.0.0/0"* ]]; then
                    out_details+="<li><span class='text-warning'>Rule <strong>$fw_name</strong> allows egress to ANYWHERE (0.0.0.0/0)</span> for <code>$allowed</code></li>"
                    ((out_warn++))
                else
                    out_details+="<li>Rule <strong>$fw_name</strong> allows egress to: <code>$dests</code> for <code>$allowed</code> ✅</li>"
                fi
            done <<< "$out_rules"
        else
            out_details+="<li><span class='text-warning'>No explicit egress rules found (Default GCP egress rule allows all outbound traffic).</span></li>"
            ((out_warn++))
        fi
        out_details+="</ul>"
    done

    in_details+="</ul>"
    out_details+="</ul>"

    if [ $in_warn -gt 0 ]; then
        add_check_result "$OUTPUT_FILE" "warning" "$in_title" "$in_details"
    else
        add_check_result "$OUTPUT_FILE" "pass" "$in_title" "$in_details"
    fi

    if [ $out_warn -gt 0 ]; then
        add_check_result "$OUTPUT_FILE" "warning" "$out_title" "$out_details"
    else
        add_check_result "$OUTPUT_FILE" "pass" "$out_title" "$out_details"
    fi
}

# 4. 檢查私有 IP 過濾 (Req 1)
assess_private_ip() {
    local project_id="$1"
    local title="Private IP filtering"
    local details="<p>Detailed analysis of private IP exposure & boundary routing ($project_id):</p><ul>"
    local warn=0

    # 深度列出 VPC Peering 連線
    local peerings
    peerings=$(gcloud compute networks list --project="$project_id" --format="value(name)" 2>/dev/null | while read net; do
        gcloud compute networks describe "$net" --project="$project_id" --format="json" 2>/dev/null | jq -r ".peerings? // [] | .[] | \"\(.name)\t$net\t\(.network | split(\"/\") | last)\t\(.state)\""
    done)

    if [[ -n "$peerings" ]]; then
        details+="<li><strong>Active VPC Peering Connections:</strong></li><ul>"
        while IFS=$'\t' read -r peering_name network peer_network state; do
            [[ -z "$peering_name" ]] && continue
            details+="<li>Peering: <strong>$peering_name</strong> (Local: <code>$network</code> ↔ Remote Project/VPC: <code>$peer_network</code>) - State: <span class='text-warning'>$state</span></li>"
            ((warn++))
        done <<< "$peerings"
        details+="</ul>"
    else
        details+="<li><span class='text-pass'>No VPC Peering connections detected.</span></li>"
    fi

    # 深度列出 VPN Gateways 與 Tunnels
    local vpn_gateways
    vpn_gateways=$(gcloud compute vpn-gateways list --project="$project_id" --format="value(name,region)" 2>/dev/null)
    if [[ -n "$vpn_gateways" ]]; then
        details+="<li><strong>VPN Gateways & Tunnels Details:</strong></li><ul>"
        while IFS=$'\t' read -r gw_name region; do
            [[ -z "$gw_name" ]] && continue
            details+="<li>Gateway: <strong>$gw_name</strong> (Region: <code>$region</code>)</li>"
            
            # 列出屬於此 Gateway 的 VPN Tunnels
            local tunnels
            tunnels=$(gcloud compute vpn-tunnels list --project="$project_id" --filter="vpnGateway:$gw_name" --format="value(name,peerIp,status)" 2>/dev/null)
            if [[ -n "$tunnels" ]]; then
                details+="<ul>"
                while IFS=$'\t' read -r tunnel_name peer_ip status; do
                    details+="<li>Tunnel: <code>$tunnel_name</code> to Remote IP: <code>$peer_ip</code> - Status: <strong>$status</strong></li>"
                done <<< "$tunnels"
                details+="</ul>"
            else
                details+="<ul><li>No active tunnels connected to this gateway.</li></ul>"
            fi
            ((warn++))
        done <<< "$vpn_gateways"
        details+="</ul>"
    else
        details+="<li><span class='text-pass'>No VPN Gateways detected.</span></li>"
    fi
    details+="</ul>"

    if [ $warn -gt 0 ]; then
        add_check_result "$OUTPUT_FILE" "warning" "$title" "$details"
    else
        add_check_result "$OUTPUT_FILE" "pass" "$title" "$details"
    fi
}

# 5. 檢查預設帳戶分析 (Req 2)
assess_vendor_defaults() {
    local project_id="$1"
    local title="Vendor default accounts analysis"
    local details="<p>Detailed analysis of default service accounts and VM mappings ($project_id):</p><ul>"
    local failed=0
    local warning=0

    # 1. 條列預設服務帳戶
    local default_sa_list
    default_sa_list=$(gcloud iam service-accounts list --project="$project_id" --format="value(email)" 2>/dev/null | grep -E "(compute@developer|appspot)")
    
    if [[ -n "$default_sa_list" ]]; then
        details+="<li><strong>Default Service Accounts in Project:</strong></li><ul>"
        while read -r sa_email; do
            details+="<li><code>$sa_email</code> <span class='text-warning'>(Warning: Default account)</span></li>"
            ((warning++))
        done <<< "$default_sa_list"
        details+="</ul>"
    else
        details+="<li><span class='text-pass'>No default service accounts found in IAM list.</span></li>"
    fi

    # 2. 條列各 VM 執行個體及其服務帳戶綁定細項
    local vm_sa_mappings
    vm_sa_mappings=$(gcloud compute instances list --project="$project_id" --format="value(name,zone,serviceAccounts[0].email)" 2>/dev/null)
    
    if [[ -n "$vm_sa_mappings" ]]; then
        details+="<li><strong>Compute Engine VM Service Account Bindings:</strong></li><ul>"
        while IFS=$'\t' read -r vm_name zone sa_email; do
            if [[ -z "$sa_email" || "$sa_email" == "None" ]]; then
                details+="<li>VM: <strong>$vm_name</strong> ($zone) - <span class='text-warning'>No Service Account bound</span></li>"
            elif [[ "$sa_email" =~ (compute@developer|appspot) ]]; then
                details+="<li>VM: <strong>$vm_name</strong> ($zone) - Bound to default SA: <span class='text-fail'>$sa_email</span> <span class='text-fail'>[HIGH RISK]</span></li>"
                ((failed++))
            else
                details+="<li>VM: <strong>$vm_name</strong> ($zone) - Bound to secure SA: <code>$sa_email</code> ✅</li>"
            fi
        done <<< "$vm_sa_mappings"
        details+="</ul>"
    else
        details+="<li>No active Compute Engine instances found in this project.</li>"
    fi
    details+="</ul>"

    if [ $failed -gt 0 ]; then
        add_check_result "$OUTPUT_FILE" "fail" "$title" "$details"
    elif [ $warning -gt 0 ]; then
        add_check_result "$OUTPUT_FILE" "warning" "$title" "$details"
    else
        add_check_result "$OUTPUT_FILE" "pass" "$title" "$details"
    fi
}

# 6. 檢查密鑰管理 (Req 3)
assess_key_management() {
    local project_id="$1"
    local title="Key Management"
    local details="<p>Detailed Cloud KMS keyrings and cryptographic keys analysis ($project_id):</p><ul>"
    local total_keys=0

    # 尋找所有全域和區域的 Keyrings
    local locations=("global" "us" "asia" "europe") # 可依實際環境延伸
    local keyrings=""
    for loc in "${locations[@]}"; do
        local kr_list
        kr_list=$(gcloud kms keyrings list --location="$loc" --project="$project_id" --format="value(name)" 2>/dev/null)
        if [[ -n "$kr_list" ]]; then
            keyrings+="$kr_list"$'\n'
        fi
    done

    # 清除多餘空行
    keyrings=$(echo "$keyrings" | grep -v '^$')

    if [[ -n "$keyrings" ]]; then
        while read -r keyring; do
            [[ -z "$keyring" ]] && continue
            details+="<li>Keyring: <strong>$keyring</strong></li>"
            
            # 詳列該 Keyring 底下的所有 CryptoKeys 及其輪轉週期與狀態
            local keys
            keys=$(gcloud kms keys list --keyring="$keyring" --format="value(name,primary.state,rotationPeriod)" 2>/dev/null)
            if [[ -n "$keys" ]]; then
                details+="<ul>"
                while IFS=$'\t' read -r key_name state rot_period; do
                    ((total_keys++))
                    local short_name
                    short_name=$(basename "$key_name")
                    local rot_info="${rot_period:-No auto-rotation configured ⚠️}"
                    details+="<li>CryptoKey: <code>$short_name</code> - Status: <strong>$state</strong> (Rotation: <em>$rot_info</em>)</li>"
                done <<< "$keys"
                details+="</ul>"
            else
                details+="<ul><li>No cryptographic keys created in this keyring.</li></ul>"
            fi
        done <<< "$keyrings"
        details+="</ul>"
        
        add_check_result "$OUTPUT_FILE" "pass" "$title" "$details"
    else
        add_check_result "$OUTPUT_FILE" "info" "$title" "<p>No KMS Keyrings found in project $project_id.</p>"
    fi
}

# 7. 檢查 TLS/SSL 設定分析 (Req 4)
assess_tls_ssl() {
    local project_id="$1"
    local title="TLS/SSL Configuration Analysis"
    local details="<p>Detailed analysis of load balancer SSL policies and TLS profiles ($project_id):</p><ul>"
    local warn=0

    # 詳列 SSL 政策
    local ssl_policies
    ssl_policies=$(gcloud compute ssl-policies list --project="$project_id" --format="value(name,profile,minTlsVersion)" 2>/dev/null)
    
    if [[ -n "$ssl_policies" ]]; then
        details+="<li><strong>Configured SSL Policies:</strong></li><ul>"
        while IFS=$'\t' read -r name profile min_tls; do
            details+="<li>Policy: <strong>$name</strong>"
            details+="<ul>"
            details+="<li>Profile: <code>$profile</code></li>"
            details+="<li>Minimum TLS Version: "
            if [[ "$min_tls" =~ ^TLS_1_[01]$ ]]; then
                details+="<span class='text-warning'>$min_tls (Weak Version - Upgrade to TLS 1.2+ recommended) ⚠️</span>"
                ((warn++))
            else
                details+="<span class='text-pass'>$min_tls ✅</span>"
            fi
            details+="</li></ul></li>"
        done <<< "$ssl_policies"
        details+="</ul>"
    else
        details+="<li>No custom SSL policies found - GCP HTTPS Load Balancers are operating under default SSL profiles (TLS 1.0+ allowed).</li>"
    fi

    # 詳列 HTTPS 負載平衡器的 Target HTTPS Proxies
    local https_proxies
    https_proxies=$(gcloud compute target-https-proxies list --project="$project_id" --format="value(name,sslPolicy)" 2>/dev/null)
    
    if [[ -n "$https_proxies" ]]; then
        details+="<li><strong>Target HTTPS Proxies & Attached Policies:</strong></li><ul>"
        while IFS=$'\t' read -r name ssl_policy; do
            details+="<li>Proxy: <strong>$name</strong>"
            if [[ -n "$ssl_policy" && "$ssl_policy" != "None" ]]; then
                details+=" - SSL Policy Attached: <code>$ssl_policy</code> ✅"
            else
                details+=" - <span class='text-warning'>No custom SSL Policy configured (Defaulting to permissive TLS 1.0 profile) ⚠️</span>"
                ((warn++))
            fi
            details+="</li>"
        done <<< "$https_proxies"
        details+="</ul>"
    else
        details+="<li>No active HTTPS Load Balancers detected in this project.</li>"
    fi
    details+="</ul>"

    if [ $warn -gt 0 ]; then
        add_check_result "$OUTPUT_FILE" "warning" "$title" "$details"
    else
        add_check_result "$OUTPUT_FILE" "pass" "$title" "$details"
    fi
}

# 8. 檢查 SSL 憑證清單與管理 (Req 4)
assess_ssl_certs() {
    local project_id="$1"
    local title="SSL Certificate Inventory and Management"
    local details="<p>Detailed SSL Certificate inventory and lifecycle tracking ($project_id):</p><ul>"
    local fail=0
    local warn=0

    # 條列所有 SSL 憑證
    local certificates
    certificates=$(gcloud compute ssl-certificates list --project="$project_id" --format="value(name,type,creationTimestamp,expireTime)" 2>/dev/null)
    
    if [[ -n "$certificates" ]]; then
        while IFS=$'\t' read -r name cert_type created expire_time; do
            details+="<li>Certificate Name: <strong>$name</strong><ul>"
            details+="<li>Type: <code>$cert_type</code></li>"
            details+="<li>Creation Time: <code>$created</code></li>"

            if [[ -n "$expire_time" && "$expire_time" != "null" ]]; then
                local expire_ts
                expire_ts=$(date -d "$expire_time" +%s 2>/dev/null || echo "0")
                local now_ts
                now_ts=$(date +%s)
                local days=$(( (expire_ts - now_ts) / 86400 ))

                if [[ $days -lt 30 && $days -gt 0 ]]; then
                    details+="<li>Expiry: <span class='text-warning'>$expire_time (⚠️ Warning: Expiring in $days days)</span></li>"
                    ((warn++))
                elif [[ $days -le 0 ]]; then
                    details+="<li>Expiry: <span class='text-fail'>$expire_time (❌ EXPIRED)</span></li>"
                    ((fail++))
                else
                    details+="<li>Expiry: <span class='text-pass'>$expire_time ($days days remaining) ✅</span></li>"
                fi
            else
                details+="<li>Expiry: Managed certificate (Automatic renew)</li>"
            fi
            details+="</ul></li>"
        done <<< "$certificates"
    else
        details+="<li>No SSL certificates found in this project.</li>"
    fi
    details+="</ul>"

    if [ $fail -gt 0 ]; then
        add_check_result "$OUTPUT_FILE" "fail" "$title" "$details"
    elif [ $warn -gt 0 ]; then
        add_check_result "$OUTPUT_FILE" "warning" "$title" "$details"
    else
        add_check_result "$OUTPUT_FILE" "pass" "$title" "$details"
    fi
}

# 9. 檢查未加密通訊協定的防火牆規則 (Req 4)
# 優化項目：在 HTML 報告中，將所有受限來源（Restricted Sources）的網段（IP Ranges）與規則細節完全羅列出來。
assess_unencrypted_firewall() {
    local project_id="$1"
    local title="Firewall Rules for Unencrypted Protocols"
    local details="<p>Detailed analysis of firewall rules allowing cleartext/unencrypted protocols ($project_id):</p><ul>"
    local fail=0
    local warn=0
    local insecure_protocols=("80" "23" "21" "143" "110" "993" "995")

    for port in "${insecure_protocols[@]}"; do
        local rules
        rules=$(gcloud compute firewall-rules list --project="$project_id" --filter="allowed.ports:($port) AND direction=INGRESS" --format="value(name,sourceRanges.join(','),allowed[].map().firewall_rule().list():label=ALLOW,network)" 2>/dev/null)
        if [[ -n "$rules" ]]; then
            while IFS=$'\t' read -r rule_name sources allowed network; do
                local protocol_desc="Port $port"
                case "$port" in
                    "80") protocol_desc="HTTP (Port 80)" ;;
                    "23") protocol_desc="Telnet (Port 23)" ;;
                    "21") protocol_desc="FTP (Port 21)" ;;
                    "143") protocol_desc="IMAP (Port 143)" ;;
                    "110") protocol_desc="POP3 (Port 110)" ;;
                    "993") protocol_desc="IMAPS (Port 993)" ;;
                    "995") protocol_desc="POP3S (Port 995)" ;;
                esac
                
                if [[ "$sources" == *"0.0.0.0/0"* ]]; then
                    details+="<li><span class='text-fail'>❌ CRITICAL RISK [Open to Internet]:</span> Rule <strong>$rule_name</strong> on network <em>$network</em> allows <code>$protocol_desc</code> from <strong>anywhere (0.0.0.0/0)</strong>.</li>"
                    ((fail++))
                else
                    details+="<li><span class='text-warning'>⚠️ Alert [Permitted from Restricted Source]:</span> Rule <strong>$rule_name</strong> on network <em>$network</em> allows <code>$protocol_desc</code> from restricted ranges: [<code>$sources</code>].</li>"
                    ((warn++))
                fi
            done <<< "$rules"
        fi
    done

    if [[ $fail -eq 0 && $warn -eq 0 ]]; then
        details+="<li>✅ No firewall rules found allowing unencrypted cleartext protocols from any source.</li>"
    fi
    details+="</ul>"

    if [ $fail -gt 0 ]; then
        add_check_result "$OUTPUT_FILE" "fail" "$title" "$details"
    elif [ $warn -gt 0 ]; then
        add_check_result "$OUTPUT_FILE" "warning" "$title" "$details"
    else
        add_check_result "$OUTPUT_FILE" "pass" "$title" "$details"
    fi
}

# 10. 檢查專案擁有者角色配置 (Req 7)
assess_project_owner_role() {
    local project_id="$1"
    local check_title="Project owner role assignment"
    local project_policy
    local details="<p>Detailed analysis of Project Owner role assignments and IAM permissions mapping for <strong>$project_id</strong>:</p><ul>"
    
    project_policy=$(gcloud projects get-iam-policy "$project_id" --format="json" 2>/dev/null)
    
    if [[ -n "$project_policy" ]]; then
        # 1. 取得並計算擁有者 (Owner) 列表
        local owners
        owners=$(echo "$project_policy" | jq -r '.bindings[]? | select(.role=="roles/owner") | .members[]?' 2>/dev/null)
        
        local owner_count
        owner_count=$(echo "$owners" | grep -v '^$' | wc -l)
        owner_count=$(echo "$owner_count" | tr -d '\n\r' | grep -o '[0-9]*' | head -1)
        [[ -z "$owner_count" ]] && owner_count=0
        
        if [[ "$owner_count" -gt 2 ]]; then
            details+="<li><span class='text-fail'>Project has $owner_count owners (recommend ≤ 2) - excessive administrative privileges violate least privilege principle</span></li>"
        else
            details+="<li><span class='text-pass'>Project owner roles appropriately limited ($owner_count owners)</span></li>"
        fi

        # 列出明確的 Owners
        if [[ "$owner_count" -gt 0 ]]; then
            details+="<li><strong>List of Owners:</strong><ul>"
            while IFS= read -r owner; do
                [[ -n "$owner" ]] && details+="<li>$owner</li>"
            done <<< "$owners"
            details+="</ul></li>"
        fi
        
        # 2. 列出所有 IAM 使用者與其對應的權限 (User-to-Role Mapping)
        details+="<li><strong>Detailed IAM Users and Permissions:</strong><ul>"
        local iam_summary
        iam_summary=$(echo "$project_policy" | jq -r '
          [ .bindings[]? | select(.members != null) | {role: .role, member: .members[]} ]
          | group_by(.member)
          | map({member: .[0].member, roles: map(.role)})
          | .[] | "<li><strong>" + .member + "</strong>: " + (.roles | join(", ")) + "</li>"
        ' 2>/dev/null)
        
        if [[ -n "$iam_summary" ]]; then
            details+="$iam_summary"
        else
            details+="<li>No IAM bindings found.</li>"
        fi
        details+="</ul></li>"

        details+="</ul>"
        
        if [[ "$owner_count" -gt 2 ]]; then
            add_check_result "$OUTPUT_FILE" "fail" "$check_title" "$details"
        else
            add_check_result "$OUTPUT_FILE" "pass" "$check_title" "$details"
        fi
    else
        details+="<li><span class='text-fail'>Cannot retrieve IAM policy for project $project_id - verify permissions</span></li></ul>"
        add_check_result "$OUTPUT_FILE" "fail" "$check_title" "$details"
    fi
}

# 11. 檢查 Identity-Aware Proxy MFA (Req 8)
assess_iap_mfa() {
    local project_id="$1"
    local check_title="Identity-Aware Proxy MFA"
    local details="<p>Detailed Identity-Aware Proxy (IAP) resources and IAM policies ($project_id):</p><ul>"
    
    # 檢查 IAP Web 服務配置
    local iap_web_policy
    iap_web_policy=$(gcloud iap web get-iam-policy --project="$project_id" --format="json" 2>/dev/null)
    
    # 檢查是否有任何成員綁定在 IAP Web 角色中 (代表已啟用且有存取設定)
    local bindings_count=0
    if [[ -n "$iap_web_policy" ]]; then
        bindings_count=$(echo "$iap_web_policy" | jq -r '.bindings[]? | .members[]?' 2>/dev/null | wc -l)
        bindings_count=$(echo "$bindings_count" | tr -d '\n\r')
    fi

    # 詳列後端服務
    local backend_services
    backend_services=$(gcloud compute backend-services list --project="$project_id" --format="value(name,iap.enabled)" 2>/dev/null)

    if [[ -n "$backend_services" ]]; then
        details+="<li><strong>Compute Engine Backend Services with IAP status:</strong></li><ul>"
        while IFS=$'\t' read -r service_name iap_enabled; do
            if [[ "$iap_enabled" == "True" ]]; then
                details+="<li>Backend: <code>$service_name</code> - IAP Status: <span class='text-pass'>Enabled ✅ (Enforcing MFA)</span></li>"
                bindings_count=$((bindings_count + 1))
            else
                details+="<li>Backend: <code>$service_name</code> - IAP Status: <span class='text-warning'>Disabled ⚠️</span></li>"
            fi
        done <<< "$backend_services"
        details+="</ul>"
    fi

    details+="</ul>"

    if [[ "$bindings_count" -gt 0 ]]; then
        add_check_result "$OUTPUT_FILE" "pass" "$check_title" \
            "<p class='text-pass'>Identity-Aware Proxy (IAP) configuration detected, supporting application-level MFA.</p>$details"
    else
        add_check_result "$OUTPUT_FILE" "info" "$check_title" \
            "<p class='text-info'>No Identity-Aware Proxy configurations detected. Consider implementing IAP to enforce strong multi-factor authentication (MFA) for administrative Web access.</p>$details"
    fi
}

# 12. 檢查 Cloud Storage 公開存取 (Req 9)
assess_storage_public_access() {
    local project_id="$1"
    local check_title="Storage public access"
    local details="<p>Detailed Cloud Storage public access prevention and security settings ($project_id):</p><ul>"
    local fail=0
    local buckets
    
    buckets=$(gcloud storage buckets list --project="$project_id" --format="value(name)" 2>/dev/null)
    
    if [[ -z "$buckets" ]]; then
        add_check_result "$OUTPUT_FILE" "info" "$check_title" "<p>No Cloud Storage buckets found in project $project_id.</p>"
        return
    fi
    
    while IFS= read -r bucket; do
        [[ -z "$bucket" ]] && continue
        
        # 深度查詢 Bucket 配置項目：公開存取預防 (PAP)、統一值區級存取 (ubla)、以及客戶經理金鑰 (CMEK)
        local bucket_desc
        bucket_desc=$(gcloud storage buckets describe "gs://$bucket" --format="json" 2>/dev/null)
        
        local pap="N/A"
        local ubla="Disabled"
        local cmek="Google-managed"

        if [[ -n "$bucket_desc" ]]; then
            pap=$(echo "$bucket_desc" | jq -r '.iamConfiguration.publicAccessPrevention // "N/A"' 2>/dev/null)
            ubla_status=$(echo "$bucket_desc" | jq -r '.iamConfiguration.uniformBucketLevelAccess.enabled // "false"' 2>/dev/null)
            if [[ "$ubla_status" == "true" ]]; then ubla="Enabled"; fi
            
            local kms_key
            kms_key=$(echo "$bucket_desc" | jq -r '.encryption.defaultKmsKeyName // empty' 2>/dev/null)
            if [[ -n "$kms_key" ]]; then
                cmek="CMEK Enabled (Key: $(basename "$kms_key"))"
            fi
        fi
        
        details+="<li>Bucket: <strong>gs://$bucket</strong><ul>"
        
        # 檢查 Public Access Prevention
        if [[ "$pap" == "enforced" ]]; then
            details+="<li>Public Access Prevention: <span class='text-pass'>Enforced ✅</span></li>"
        else
            ((fail++))
            details+="<li>Public Access Prevention: <span class='text-fail'>Not Enforced (Inherited/Subject to public access) ❌</span></li>"
        fi
        
        details+="<li>Uniform Bucket-Level Access: <code>$ubla</code></li>"
        details+="<li>Encryption Management: <code>$cmek</code></li>"
        details+="</ul></li>"
    done <<< "$buckets"
    details+="</ul>"
    
    if [[ $fail -gt 0 ]]; then
        add_check_result "$OUTPUT_FILE" "fail" "$check_title" "$details"
    else
        add_check_result "$OUTPUT_FILE" "pass" "$check_title" "$details"
    fi
}

# 13. 檢查 Cloud Logging 啟用狀態 (Req 10)
assess_cloud_logging() {
    local project_id="$1"
    local check_title="Cloud Logging enabled"
    local details="<p>Detailed Cloud Logging audit sinks and logs configuration ($project_id):</p><ul>"
    local logging_enabled
    
    # 查詢現有日誌匯出 (Logging Sinks) 的細項與目的地
    local sinks
    sinks=$(gcloud logging sinks list --project="$project_id" --format="value(name,destination,filter)" 2>/dev/null)
    
    if [[ -n "$sinks" ]]; then
        details+="<li><strong>Active Log Sinks & Destinations:</strong></li><ul>"
        while IFS=$'\t' read -r sink_name destination filter; do
            local short_dest
            short_dest=$(echo "$destination" | cut -d'/' -f1-2)
            details+="<li>Sink: <strong>$sink_name</strong> ➡️ Destination: <code>$destination</code>"
            if [[ -n "$filter" ]]; then
                details+="<br><em>Filter: <code>$filter</code></em>"
            fi
            details+="</li>"
        done <<< "$sinks"
        details+="</ul>"
    else
        details+="<li><span class='text-warning'>No custom log sinks configured in this project. All logs are retained locally in basic bucket storage.</span></li>"
    fi

    # 檢查是否有日誌流產生，以確認 Logging 正常運作
    logging_enabled=$(gcloud logging logs list --project="$project_id" --limit=1 2>/dev/null)
    
    if [[ -n "$logging_enabled" ]]; then
        details+="<li>Cloud Logging Service Status: <span class='text-pass'>Active (Log records are actively ingested) ✅</span></li>"
        details+="</ul>"
        add_check_result "$OUTPUT_FILE" "pass" "$check_title" "$details"
    else
        details+="<li>Cloud Logging Service Status: <span class='text-fail'>Inactive/No Logs detected ❌</span></li>"
        details+="</ul>"
        add_check_result "$OUTPUT_FILE" "fail" "$check_title" "$details"
    fi
}

# =============================================================================
# 主程式執行邏輯
# =============================================================================
main() {
    # 初始化框架與環境
    setup_environment || { echo "Environment setup failed"; exit 1; }
    
    # 解析命令列參數
    parse_common_arguments "$@"
    case $? in
        1) exit 1 ;;
        2) exit 0 ;;
    esac

    # 驗證先決條件
    validate_prerequisites || { echo "Prerequisites validation failed"; exit 1; }

    # 設定評估範圍
    setup_assessment_scope || { echo "Scope setup failed"; exit 1; }

    # 驗證所需之所有 IAM 權限 (滿足：前面的權限檢查要留著)
    print_status "INFO" "Checking required GCP permissions..."
    check_required_permissions "${REQUIRED_PERMISSIONS[@]}" || {
        print_status "FAIL" "Permission check failed! Please ensure you have appropriate IAM permissions."
        exit 1
    }

    # 確保輸出檔案名稱符合 Python 腳本的過濾條件 ("pci_req*.html")
    OUTPUT_FILE="${REPORT_DIR}/pci_req_consolidated_all_$(date +%Y%m%d_%H%M%S).html"

    # 初始化 HTML 報告
    initialize_report "$OUTPUT_FILE" "PCI DSS Consolidated Assessment (All Requirements)" "$REQUIREMENT_NUMBER" "$PROJECT_ID" || exit 1

    print_status "INFO" "=========================================================="
    print_status "INFO" "  Starting PCI DSS Consolidated Assessment (Req 1-12 All)"
    print_status "INFO" "=========================================================="
    echo ""

    # 取得範圍內的專案清單
    local projects
    projects=$(get_projects_in_scope)

    if [[ -z "$projects" ]]; then
        print_status "FAIL" "No projects found in assessment scope"
        exit 1
    fi

    # 遍歷專案並執行檢查
    while IFS= read -r project_id; do
        [[ -z "$project_id" ]] && continue

        print_status "INFO" "Processing project: $project_id"
        add_section "$OUTPUT_FILE" "project_$project_id" "Project: $project_id Assessment Results"

        # 呼叫針對所有 13 個目標關鍵字的詳細檢查項目
        assess_insecure_services "$project_id"
        assess_cde_restrictions "$project_id"
        assess_private_ip "$project_id"
        assess_vendor_defaults "$project_id"
        assess_key_management "$project_id"
        assess_tls_ssl "$project_id"
        assess_ssl_certs "$project_id"
        assess_unencrypted_firewall "$project_id"
        assess_project_owner_role "$project_id"
        assess_iap_mfa "$project_id"
        assess_storage_public_access "$project_id"
        assess_cloud_logging "$project_id"

    done <<< "$projects"

    # 關閉最後一個區塊並結束 HTML
    html_append "$OUTPUT_FILE" "            </div> <!-- Close final section content -->
        </div> <!-- Close final section -->"

    finalize_report "$OUTPUT_FILE" "$REQUIREMENT_NUMBER"

    echo ""
    print_status "PASS" "======================= ASSESSMENT SUMMARY ======================="
    print_status "INFO" "Report has been generated: $OUTPUT_FILE"
    print_status "INFO" "This consolidated report contains all 13 target keywords with deep details, ready for gen_clean_summary_gcp.py parsing."
    print_status "PASS" "=================================================================="
}

# 啟動主程式
main "$@"
