#!/bin/bash

# consolidate_system_checks.sh
# Script to consolidate PCI DSS version 4.0 system check reports
# from the 'System Checks' folder

# Set up constants
SYSTEM_CHECKS_DIR="$HOME/AWS.PCI.DSS/System Checks"
OUTPUT_DIR="$HOME/AWS.PCI.DSS/reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="$OUTPUT_DIR/consolidated_system_check_report_$TIMESTAMP.txt"
OUTPUT_HTML="$OUTPUT_DIR/consolidated_system_check_report_$TIMESTAMP.html"
PCI_VERSION="4.0"
TEMP_DIR="/tmp/system_checks_temp_$$"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"
mkdir -p "$TEMP_DIR"

# Initialize counters for statistics
total_systems=0
systems_with_issues=0
total_checks=0
failed_checks=0

# Function to extract computer name from a report file
extract_computer_name() {
    local file="$1"
    grep -m 1 "電腦名稱:" "$file" | awk -F": " '{print $2}'
}

# Function to extract IP address from a report file
extract_ip_address() {
    local file="$1"
    grep -A 4 "作用中的網路介面卡" "$file" | grep "IPv4 位址" | head -1 | awk -F": " '{print $2}'
}

# Function to extract check results
extract_check_result() {
    local file="$1"
    local computer_name=$(extract_computer_name "$file")
    local ip_address=$(extract_ip_address "$file")
    local domain=$(grep -m 1 "隸屬於網域:" "$file" | awk -F": " '{print $2}')
    local os=$(grep -m 1 "Windows 版本:" "$file" | awk -F": " '{print $2}')
    local issues=""
    local check_fail_count=0
    
    # Create system data file
    echo "$ip_address" > "$TEMP_DIR/${computer_name}_IP.txt"
    echo "$domain" > "$TEMP_DIR/${computer_name}_Domain.txt"
    echo "$os" > "$TEMP_DIR/${computer_name}_OS.txt"
    
    # Extract UAC status
    if grep -q "UAC (EnableLUA) 狀態: 已啟用" "$file"; then
        if grep -q "管理員提示行為: 不提示直接提升" "$file" || grep -q "在安全桌面上提示: 否" "$file"; then
            echo "警告" > "$TEMP_DIR/${computer_name}_UAC.txt"
            ((check_fail_count++))
            issues="${issues}UAC 設定存在風險; "
        else
            echo "良好" > "$TEMP_DIR/${computer_name}_UAC.txt"
        fi
    else
        echo "風險" > "$TEMP_DIR/${computer_name}_UAC.txt"
        ((check_fail_count++))
        issues="${issues}UAC 已停用; "
    fi
    ((total_checks++))
    
    # Extract BitLocker status
    if grep -q "BitLocker 保護狀態: 已開啟" "$file"; then
        echo "良好" > "$TEMP_DIR/${computer_name}_BitLocker.txt"
    else
        echo "風險" > "$TEMP_DIR/${computer_name}_BitLocker.txt"
        ((check_fail_count++))
        issues="${issues}BitLocker 未啟用; "
    fi
    ((total_checks++))
    
    # Extract Firewall status
    if grep -q "設定檔: 網域 | 狀態: 啟用" "$file" && 
       grep -q "設定檔: 私人 | 狀態: 啟用" "$file" && 
       grep -q "設定檔: 公用 | 狀態: 啟用" "$file"; then
        echo "良好" > "$TEMP_DIR/${computer_name}_Firewall.txt"
    else
        echo "風險" > "$TEMP_DIR/${computer_name}_Firewall.txt"
        ((check_fail_count++))
        issues="${issues}防火牆未完全啟用; "
    fi
    ((total_checks++))
    
    # Extract Antivirus status
    if grep -q "已啟用: 是 \[良好\] | 病毒碼最新: 是 \[良好\]" "$file"; then
        echo "良好" > "$TEMP_DIR/${computer_name}_Antivirus.txt"
    else
        echo "風險" > "$TEMP_DIR/${computer_name}_Antivirus.txt"
        ((check_fail_count++))
        issues="${issues}防毒軟體存在問題; "
    fi
    ((total_checks++))
    
    # Extract Windows Update status
    if grep -q "最近 30 天內有 Windows Update 活動" "$file"; then
        echo "良好" > "$TEMP_DIR/${computer_name}_Updates.txt"
    else
        echo "風險" > "$TEMP_DIR/${computer_name}_Updates.txt"
        ((check_fail_count++))
        issues="${issues}Windows更新不活躍; "
    fi
    ((total_checks++))
    
    # Extract RDP status
    if grep -q "遠端桌面 (RDP): 已停用" "$file"; then
        echo "良好" > "$TEMP_DIR/${computer_name}_RDP.txt"
    else
        echo "風險" > "$TEMP_DIR/${computer_name}_RDP.txt"
        ((check_fail_count++))
        issues="${issues}RDP已啟用; "
    fi
    ((total_checks++))
    
    # Extract Secure Boot status
    if grep -q "安全開機 (Secure Boot).*: 已啟用" "$file"; then
        echo "良好" > "$TEMP_DIR/${computer_name}_SecureBoot.txt"
    else
        echo "風險" > "$TEMP_DIR/${computer_name}_SecureBoot.txt"
        ((check_fail_count++))
        issues="${issues}安全開機未啟用; "
    fi
    ((total_checks++))
    
    # Extract SMBv1 status
    if grep -q "SMBv1 功能狀態.*: 已停用" "$file"; then
        echo "良好" > "$TEMP_DIR/${computer_name}_SMBv1.txt"
    else
        echo "風險" > "$TEMP_DIR/${computer_name}_SMBv1.txt"
        ((check_fail_count++))
        issues="${issues}SMBv1協議未停用; "
    fi
    ((total_checks++))
    
    # Extract PowerShell execution policy
    if grep -q "目前的有效 PowerShell 執行原則: Bypass" "$file" || 
       grep -q "目前的有效 PowerShell 執行原則: Unrestricted" "$file"; then
        echo "風險" > "$TEMP_DIR/${computer_name}_PowerShell.txt"
        ((check_fail_count++))
        issues="${issues}PowerShell執行原則過於寬鬆; "
    else
        echo "良好" > "$TEMP_DIR/${computer_name}_PowerShell.txt"
    fi
    ((total_checks++))
    
    # Extract Remote Registry status
    if grep -q "\[良好 - 服務已停用\]" "$file" && grep -q "啟動類型: Disabled" "$file"; then
        echo "良好" > "$TEMP_DIR/${computer_name}_RemoteRegistry.txt"
    else
        echo "風險" > "$TEMP_DIR/${computer_name}_RemoteRegistry.txt"
        ((check_fail_count++))
        issues="${issues}遠端登錄服務未停用; "
    fi
    ((total_checks++))
    
    # Extract Guest account status
    if grep -q "內建 Guest 帳戶狀態: 已停用" "$file"; then
        echo "良好" > "$TEMP_DIR/${computer_name}_Guest.txt"
    else
        echo "風險" > "$TEMP_DIR/${computer_name}_Guest.txt"
        ((check_fail_count++))
        issues="${issues}Guest帳戶未停用; "
    fi
    ((total_checks++))
    
    # Extract TPM status
    if grep -q "TPM 是否存在.*: True" "$file" && grep -q "TPM 是否就緒.*: True" "$file"; then
        echo "良好" > "$TEMP_DIR/${computer_name}_TPM.txt"
    else
        echo "風險" > "$TEMP_DIR/${computer_name}_TPM.txt"
        ((check_fail_count++))
        issues="${issues}TPM未啟用或不存在; "
    fi
    ((total_checks++))
    
    # Extract unsafe ports
    if grep -q "檢查結果: 發現以下潛在不安全的連接埠正在接聽: " "$file"; then
        echo "警告" > "$TEMP_DIR/${computer_name}_UnsafePorts.txt"
        unsafe_ports=$(grep -m 1 "檢查結果: 發現以下潛在不安全的連接埠正在接聽: " "$file" | sed 's/.*接聽: \(.*\) \[.*/\1/')
        issues="${issues}不安全連接埠開放: $unsafe_ports; "
        ((check_fail_count++))
    else
        echo "良好" > "$TEMP_DIR/${computer_name}_UnsafePorts.txt"
    fi
    ((total_checks++))
    
    # Extract screen lock settings
    if grep -q "螢幕保護程式已啟用，但未設定『於恢復時顯示登入畫面』" "$file"; then
        echo "警告" > "$TEMP_DIR/${computer_name}_ScreenLock.txt"
        ((check_fail_count++))
        issues="${issues}螢幕鎖定不安全; "
    elif grep -q "螢幕保護程式已啟用.*於恢復時顯示登入畫面" "$file"; then
        echo "良好" > "$TEMP_DIR/${computer_name}_ScreenLock.txt"
    else
        echo "風險" > "$TEMP_DIR/${computer_name}_ScreenLock.txt"
        ((check_fail_count++))
        issues="${issues}螢幕保護程式未啟用; "
    fi
    ((total_checks++))
    
    # Save issues if any
    if [ -n "$issues" ]; then
        echo "$issues" > "$TEMP_DIR/${computer_name}_Issues.txt"
        ((systems_with_issues++))
    fi
    
    # Update failed checks counter
    failed_checks=$((failed_checks + check_fail_count))
}

# Function to generate consolidated text report
generate_text_report() {
    echo "PCI DSS v$PCI_VERSION 系統安全檢查 - 合併報告" > "$OUTPUT_FILE"
    echo "==============================================" >> "$OUTPUT_FILE"
    echo "報告產生時間: $(date '+%Y-%m-%d %H:%M:%S')" >> "$OUTPUT_FILE"
    echo "檢查項目合規版本: PCI DSS v$PCI_VERSION" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    echo "--- 摘要 ---" >> "$OUTPUT_FILE"
    echo "檢查總系統數: $total_systems" >> "$OUTPUT_FILE"
    echo "有問題的系統數: $systems_with_issues" >> "$OUTPUT_FILE"
    echo "檢查項目總數: $total_checks" >> "$OUTPUT_FILE"
    echo "未通過的檢查項目數: $failed_checks" >> "$OUTPUT_FILE"
    local compliance_rate=$((($total_checks - $failed_checks) * 100 / $total_checks))
    echo "合規比率: ${compliance_rate}%" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"
    
    echo "--- 系統詳細資訊 ---" >> "$OUTPUT_FILE"
    
    # Get all unique computer names
    all_computers=$(ls "$TEMP_DIR" | grep "_OS.txt" | sed 's/_OS.txt//' | sort)
    
    for computer in $all_computers; do
        echo "電腦名稱: $computer" >> "$OUTPUT_FILE"
        echo "  IPv4 位址: $(cat "$TEMP_DIR/${computer}_IP.txt")" >> "$OUTPUT_FILE"
        echo "  作業系統: $(cat "$TEMP_DIR/${computer}_OS.txt")" >> "$OUTPUT_FILE"
        echo "  隸屬網域: $(cat "$TEMP_DIR/${computer}_Domain.txt")" >> "$OUTPUT_FILE"
        
        if [ -f "$TEMP_DIR/${computer}_Issues.txt" ]; then
            echo "  發現的問題:" >> "$OUTPUT_FILE"
            # Split the issues and format them
            issues=$(cat "$TEMP_DIR/${computer}_Issues.txt")
            IFS=';' 
            for issue in $issues; do
                if [ -n "$issue" ] && [ "$issue" != " " ]; then
                    echo "    - $issue" >> "$OUTPUT_FILE"
                fi
            done
            unset IFS
        else
            echo "  狀態: 所有檢查均已通過" >> "$OUTPUT_FILE"
        fi
        echo "" >> "$OUTPUT_FILE"
    done
    
    echo "--- 詳細檢查結果 ---" >> "$OUTPUT_FILE"
    
    # Define check descriptions
    declare -a check_names=("UAC" "BitLocker" "Firewall" "Antivirus" "Updates" "RDP" "SecureBoot" "SMBv1" "PowerShell" "RemoteRegistry" "Guest" "TPM" "UnsafePorts" "ScreenLock")
    declare -a check_descriptions=("User Account Control (UAC) Status" "BitLocker Disk Encryption Status" "Windows Firewall Status" "Antivirus Software Status" "Windows Update Recent Activity" "Remote Desktop (RDP) Status" "Secure Boot Status" "SMBv1 Protocol Status" "PowerShell Execution Policy" "Remote Registry Service Status" "Built-in Guest Account Status" "TPM (Trusted Platform Module) Status" "Potentially Unsafe Listening Ports" "Screen Auto-Lock")
    
    for i in "${!check_names[@]}"; do
        check_name="${check_names[$i]}"
        description="${check_descriptions[$i]}"
        
        echo "$description:" >> "$OUTPUT_FILE"
        
        for computer in $all_computers; do
            if [ -f "$TEMP_DIR/${computer}_${check_name}.txt" ]; then
                status=$(cat "$TEMP_DIR/${computer}_${check_name}.txt")
                printf "  %-35s | %s\n" "$computer" "$status" >> "$OUTPUT_FILE"
            fi
        done
        echo "" >> "$OUTPUT_FILE"
    done
    
    echo "--- 報告結束 ---" >> "$OUTPUT_FILE"
}

# Function to generate HTML report
generate_html_report() {
    local compliance_rate=$((($total_checks - $failed_checks) * 100 / $total_checks))
    
    cat > "$OUTPUT_HTML" << EOF
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCI DSS v$PCI_VERSION 系統安全檢查合併報告</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #0066cc;
        }
        .summary {
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .system-card {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
            background-color: #fff;
        }
        .system-header {
            display: flex;
            justify-content: space-between;
        }
        .issues {
            background-color: #fff8f8;
            padding: 10px;
            border-left: 3px solid #cc0000;
            margin-top: 10px;
        }
        .no-issues {
            background-color: #f1f8e9;
            padding: 10px;
            border-left: 3px solid #4caf50;
            margin-top: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        .good {
            color: #4caf50;
        }
        .warning {
            color: #ff9800;
        }
        .risk {
            color: #cc0000;
        }
        .compliance-meter {
            height: 20px;
            background-color: #f2f2f2;
            border-radius: 10px;
            overflow: hidden;
            margin-bottom: 10px;
        }
        .compliance-value {
            height: 100%;
            background-color: #4caf50;
            text-align: center;
            color: white;
            line-height: 20px;
        }
    </style>
</head>
<body>
    <h1>PCI DSS v$PCI_VERSION 系統安全檢查 - 合併報告</h1>
    <p>報告產生時間: $(date '+%Y-%m-%d %H:%M:%S')</p>
    <p>檢查項目合規版本: PCI DSS v$PCI_VERSION</p>
    
    <div class="summary">
        <h2>摘要</h2>
        <p>檢查總系統數: $total_systems</p>
        <p>有問題的系統數: $systems_with_issues</p>
        <p>檢查項目總數: $total_checks</p>
        <p>未通過的檢查項目數: $failed_checks</p>
        <p>合規比率: $compliance_rate%</p>
        <div class="compliance-meter">
            <div class="compliance-value" style="width: $compliance_rate%;">
                $compliance_rate%
            </div>
        </div>
    </div>
    
    <h2>系統詳細資訊</h2>
    <div class="systems-container">
EOF

    # Get all unique computer names
    all_computers=$(ls "$TEMP_DIR" | grep "_OS.txt" | sed 's/_OS.txt//' | sort)
    
    for computer in $all_computers; do
        issues_class="no-issues"
        issues_text="所有檢查均已通過"
        issues_html=""
        
        if [ -f "$TEMP_DIR/${computer}_Issues.txt" ]; then
            issues_class="issues"
            issues_text="發現的問題:"
            issues_html="<ul>"
            
            issues=$(cat "$TEMP_DIR/${computer}_Issues.txt")
            IFS=';' 
            for issue in $issues; do
                if [ -n "$issue" ] && [ "$issue" != " " ]; then
                    issues_html+="<li>$issue</li>"
                fi
            done
            unset IFS
            
            issues_html+="</ul>"
        fi
        
        ip=$(cat "$TEMP_DIR/${computer}_IP.txt")
        os=$(cat "$TEMP_DIR/${computer}_OS.txt")
        domain=$(cat "$TEMP_DIR/${computer}_Domain.txt")
        
        cat >> "$OUTPUT_HTML" << EOF
        <div class="system-card">
            <div class="system-header">
                <h3>$computer</h3>
                <span>$ip</span>
            </div>
            <p>作業系統: $os</p>
            <p>隸屬網域: $domain</p>
            <div class="$issues_class">
                <strong>$issues_text</strong>
                $issues_html
            </div>
        </div>
EOF
    done

    cat >> "$OUTPUT_HTML" << EOF
    </div>
    
    <h2>詳細檢查結果</h2>
EOF

    # Define check descriptions
    declare -a check_names=("UAC" "BitLocker" "Firewall" "Antivirus" "Updates" "RDP" "SecureBoot" "SMBv1" "PowerShell" "RemoteRegistry" "Guest" "TPM" "UnsafePorts" "ScreenLock")
    declare -a check_descriptions=("User Account Control (UAC) Status" "BitLocker Disk Encryption Status" "Windows Firewall Status" "Antivirus Software Status" "Windows Update Recent Activity" "Remote Desktop (RDP) Status" "Secure Boot Status" "SMBv1 Protocol Status" "PowerShell Execution Policy" "Remote Registry Service Status" "Built-in Guest Account Status" "TPM (Trusted Platform Module) Status" "Potentially Unsafe Listening Ports" "Screen Auto-Lock")
    
    for i in "${!check_names[@]}"; do
        check_name="${check_names[$i]}"
        description="${check_descriptions[$i]}"
        
        cat >> "$OUTPUT_HTML" << EOF
    <h3>$description</h3>
    <table>
        <tr>
            <th>系統名稱</th>
            <th>結果</th>
        </tr>
EOF

        for computer in $all_computers; do
            if [ -f "$TEMP_DIR/${computer}_${check_name}.txt" ]; then
                status=$(cat "$TEMP_DIR/${computer}_${check_name}.txt")
                
                status_class="good"
                if [ "$status" = "警告" ]; then
                    status_class="warning"
                elif [ "$status" = "風險" ]; then
                    status_class="risk"
                fi
                
                cat >> "$OUTPUT_HTML" << EOF
        <tr>
            <td>$computer</td>
            <td class="$status_class">$status</td>
        </tr>
EOF
            fi
        done
        
        cat >> "$OUTPUT_HTML" << EOF
    </table>
EOF
    done

    cat >> "$OUTPUT_HTML" << EOF
</body>
</html>
EOF
}

# Main function
main() {
    echo "Starting consolidation of system check reports..."
    echo "Looking in directory: $SYSTEM_CHECKS_DIR"
    
    # Get all system check report files
    files=("$SYSTEM_CHECKS_DIR"/SystemCheck_Report_*.txt)
    total_systems=${#files[@]}
    
    echo "Found $total_systems system check reports to consolidate."
    
    # Extract check results from each file
    for file in "${files[@]}"; do
        echo "Processing: $(basename "$file")"
        extract_check_result "$file"
    done
    
    # Generate the reports
    echo "Generating text report..."
    generate_text_report
    
    echo "Generating HTML report..."
    generate_html_report
    
    # Clean up temporary files
    rm -rf "$TEMP_DIR"
    
    echo "Reports generated successfully!"
    echo "- Text report: $OUTPUT_FILE"
    echo "- HTML report: $OUTPUT_HTML"
}

# Execute the main function
main
