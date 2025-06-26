#!/bin/bash

echo "▶️ 開始執行 PCI DSS 檢查流程"

# 設定全域環境變數
read -p "請輸入 AWS region (預設 us-east-1): " REGION
if [ -z "$REGION" ]; then
    REGION="us-east-1"
fi
export REGION
echo "✅ 設定 REGION=$REGION"

export TARGET_VPCS="all"
echo "✅ 設定 TARGET_VPCS=$TARGET_VPCS"

export TARGET_RESOURCES="all"
echo "✅ 設定 TARGET_RESOURCES=$TARGET_RESOURCES"

export CDE_VPCS="all"
echo "✅ 設定 CDE_VPCS=$CDE_VPCS"

export TARGET_ACCOUNTS="all"
echo "✅ 設定 TARGET_ACCOUNTS=$TARGET_ACCOUNTS"

echo

# 執行權限檢查
if [ -f "check_pci_permissions.sh" ]; then
    echo "🔍 執行 check_pci_permissions.sh"
    chmod +x check_pci_permissions.sh
    bash check_pci_permissions.sh
    echo "✅ 權限檢查完成"
    echo
fi

# 執行 requirement1~12
for i in {1..12}; do
    script="check_pci_requirement${i}.sh"
    if [ -f "$script" ]; then
        echo "🚀 執行 $script"
        chmod +x "$script"
        bash "$script"
        echo "✅ 執行完成 $script"
        echo
    else
        echo "⚠️ 找不到 $script，略過。"
    fi
done

# 執行總結
if [ -f "generate_executive_summary.sh" ]; then
    echo "📝 執行 generate_executive_summary.sh"
    chmod +x generate_executive_summary.sh
    bash generate_executive_summary.sh
    echo "✅ 報告產出完成"
    echo
fi

echo "🎉 全部 PCI 檢查作業完成！"
