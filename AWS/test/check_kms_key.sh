#!/bin/bash

REGION=$(aws ec2 describe-availability-zones --query 'AvailabilityZones[0].RegionName' --output text 2>/dev/null)
if [ -z "$REGION" ]; then
  echo "❌ 找不到 region，請確認 AWS CLI 設定或權限。"
  exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

mkdir -p report/key

KEYS=$(aws kms list-keys --region "$REGION" --query 'Keys[*].KeyId' --output text)
for key_id in $KEYS; do
  alias_full=$(aws kms list-aliases --region "$REGION" --query "Aliases[?TargetKeyId=='$key_id'].AliasName" --output text)
  alias_clean=${alias_full#alias/}
  [ -z "$alias_clean" ] && alias_clean="unnamed"

  desc=$(aws kms describe-key --region "$REGION" --key-id "$key_id")
  key_state=$(echo "$desc" | jq -r '.KeyMetadata.KeyState')
  key_usage=$(echo "$desc" | jq -r '.KeyMetadata.KeyUsage')
  key_spec=$(echo "$desc" | jq -r '.KeyMetadata.KeySpec')
  key_origin=$(echo "$desc" | jq -r '.KeyMetadata.Origin')
  key_create_raw=$(echo "$desc" | jq -r '.KeyMetadata.CreationDate')
  key_create_fmt=$(date -d "$key_create_raw" +"%Y%m%d %H:%M")
  key_expire_model=$(echo "$desc" | jq -r '.KeyMetadata.ExpirationModel // "N/A"')

  policy=$(aws kms get-key-policy --region "$REGION" --key-id "$key_id" --policy-name default --output text)
  wildcard=$(echo "$policy" | grep -q '"Principal".*"\*"' && echo "yes" || echo "no")
  has_condition=$(echo "$policy" | grep -q '"Condition"' && echo "yes" || echo "no")
  admin_separated=$(echo "$policy" | grep -q 'kms:CreateKey' && echo "$policy" | grep -q 'kms:Decrypt' && echo "yes" || echo "no")

  events=$(aws cloudtrail lookup-events --region "$REGION" --lookup-attributes AttributeKey=ResourceName,AttributeValue="$key_id" --max-results 50 2>/dev/null | jq '.Events | length')
  rotation_status=$(aws kms get-key-rotation-status --region "$REGION" --key-id "$key_id" --query 'KeyRotationEnabled' --output text)

  CURRENT_DATE=$(TZ=Asia/Taipei date +"%Y%m%d")
  CURRENT_TIME=$(TZ=Asia/Taipei date +"%H:%M")
  
  safe_alias_clean=$(echo "$alias_clean" | tr ' ' '-')
  mkdir -p "report/key/${safe_alias_clean}"
  OUTPUT_FILE="report/key/${safe_alias_clean}/${safe_alias_clean}_kms_key.xml"

  cat <<EOF > "$OUTPUT_FILE"
<getinfo>
  <project>$ACCOUNT_ID</project>
  <region>$REGION</region>
  <date>$CURRENT_DATE</date>
  <time>$CURRENT_TIME</time>
  <requirement>3.6.1 - Key Protection Procedures</requirement>
  <evidence>
    <key id="$key_id" name="$alias_clean">
      <state>$key_state</state>
      <usage>$key_usage</usage>
      <spec>$key_spec</spec>
      <origin>$key_origin</origin>
      <created>$key_create_fmt</created>
      <expiration_model>$key_expire_model</expiration_model>
      <policy>
        <wildcard_principal>$wildcard</wildcard_principal>
        <condition>$has_condition</condition>
        <admin_use_separated>$admin_separated</admin_use_separated>
      </policy>
      <activity>
        <cloudtrail_event_count>$events</cloudtrail_event_count>
      </activity>
      <rotation>$rotation_status</rotation>
    </key>
  </evidence>
</getinfo>
EOF

  echo "✅ Output saved to $OUTPUT_FILE"
done

