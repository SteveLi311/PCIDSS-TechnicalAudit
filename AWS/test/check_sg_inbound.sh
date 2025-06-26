#!/bin/bash

REGION=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)
[ -z "$REGION" ] && REGION="ap-southeast-1"

TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60")

INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/instance-id)

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

RAW_JSON=$(aws ec2 describe-instances --region "$REGION" \
  --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0]' --output json)

NAME=$(echo "$RAW_JSON" | jq -r '.Tags[] | select(.Key=="Name") | .Value')
OS=$(echo "$RAW_JSON" | jq -r '.PlatformDetails')
PRIVATE_IP=$(echo "$RAW_JSON" | jq -r '.PrivateIpAddress')
PUBLIC_IP=$(echo "$RAW_JSON" | jq -r '.PublicIpAddress // "N/A"')
LAUNCH_TIME=$(echo "$RAW_JSON" | jq -r '.LaunchTime')
INSTANCE_TYPE=$(echo "$RAW_JSON" | jq -r '.InstanceType')
AZ=$(echo "$RAW_JSON" | jq -r '.Placement.AvailabilityZone')
LAUNCH_TIME_FORMATTED=$(date -d "$LAUNCH_TIME" +"%Y/%m/%d %p %I:%M (%Z%:z)" | sed 's/AM/上午/;s/PM/下午/')
CURRENT_TIME=$(date +"%Y/%m/%d %p %I:%M (%Z%:z)" | sed 's/AM/上午/;s/PM/下午/')

mkdir -p report
OUTPUT_FILE="report/check_sg_inbound.xml"

TARGET_VPCS=$(aws ec2 describe-vpcs --region "$REGION" --query 'Vpcs[*].VpcId' --output text)
EVIDENCE_XML=""

for vpc_id in $TARGET_VPCS; do
  sg_list=$(aws ec2 describe-security-groups --region "$REGION" \
    --filters "Name=vpc-id,Values=$vpc_id" --query 'SecurityGroups[*].GroupId' --output text)

  for sg_id in $sg_list; do
    sg_details=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$sg_id" --output json 2>/dev/null)
    sg_name=$(echo "$sg_details" | jq -r '.SecurityGroups[0].GroupName // "Unnamed"')
    ingress_rules=$(echo "$sg_details" | jq -c '.SecurityGroups[0].IpPermissions[]?')

    rule_lines=""
    found=0

    while IFS= read -r rule; do
      cidrs=$(echo "$rule" | jq -r '.IpRanges[].CidrIp? // empty')
      proto=$(echo "$rule" | jq -r '.IpProtocol')
      from=$(echo "$rule" | jq -r '.FromPort // "all"')
      to=$(echo "$rule" | jq -r '.ToPort // "all"')

      for cidr in $cidrs; do
        if [ "$cidr" = "0.0.0.0/0" ]; then
          rule_lines="${rule_lines}    <rules>${proto} ${from}→${to}</rules>
"
          found=1
        fi
      done
    done <<< "$ingress_rules"

    if [ "$found" -eq 1 ]; then
      EVIDENCE_XML="${EVIDENCE_XML}
  <vpc_id>${vpc_id}</vpc_id>
    <sg_id>${sg_id}</sg_id>
    <sg_name>${sg_name}</sg_name>
${rule_lines}"
    fi
  done
done

# 輸出 XML，注意 rules 使用 echo -e 處理換行
{
echo "<getinfo>"
echo "  <project>$ACCOUNT_ID</project>"
echo "  <instanceid>$INSTANCE_ID</instanceid>"
echo "  <hostname>$NAME</hostname>"
echo "  <system>$OS</system>"
echo "  <ip>$PRIVATE_IP</ip>"
echo "  <publicip>$PUBLIC_IP</publicip>"
echo "  <instancetype>$INSTANCE_TYPE</instancetype>"
echo "  <availabilityzone>$AZ</availabilityzone>"
echo "  <launch_time>$LAUNCH_TIME_FORMATTED</launch_time>"
echo "  <current_time>$CURRENT_TIME</current_time>"
echo "  <requirement>1.2.5 - Ports, protocols, and services inventory</requirement>"
echo "  <evidence>"
echo -e "$EVIDENCE_XML"
echo "  </evidence>"
echo "</getinfo>"
} > "$OUTPUT_FILE"

echo "✅ Output written to $OUTPUT_FILE"

