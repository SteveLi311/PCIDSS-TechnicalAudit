#!/bin/bash

REGION=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)
[ -z "$REGION" ] && REGION="ap-southeast-1"

TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60")

INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/instance-id)

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

RAW_JSON=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0]' --output json)

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
OUTPUT_FILE="report/check_sg_unencrypted.xml"
EVIDENCE_XML=""

declare -A PROTOCOL_PORTS=(
  ["HTTP"]=80
  ["TELNET"]=23
  ["FTP"]=21
  ["SMTP"]=25
)

SG_IDS=$(aws ec2 describe-security-groups --region "$REGION" --query 'SecurityGroups[*].GroupId' --output text)

for sg_id in $SG_IDS; do
  sg_json=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$sg_id" --output json)
  sg_name=$(echo "$sg_json" | jq -r '.SecurityGroups[0].GroupName // "Unnamed"')
  vpc_id=$(echo "$sg_json" | jq -r '.SecurityGroups[0].VpcId')

  for proto in "${!PROTOCOL_PORTS[@]}"; do
    port=${PROTOCOL_PORTS[$proto]}
    found=$(echo "$sg_json" | jq --argjson port "$port" '.SecurityGroups[0].IpPermissions[]? | select(.FromPort == $port and .ToPort == $port) | .IpRanges[]?.CidrIp' | grep -c "0.0.0.0/0")

    if [ "$found" -gt 0 ]; then
      EVIDENCE_XML="${EVIDENCE_XML}
  <vpc_id>$vpc_id</vpc_id>
    <sg_id>$sg_id</sg_id>
    <sg_name>$sg_name</sg_name>
    <unencrypted_protocol>$proto</unencrypted_protocol>
    <port>$port</port>"
    fi
  done
done

cat <<EOF > "$OUTPUT_FILE"
<getinfo>
  <project>$ACCOUNT_ID</project>
  <instanceid>$INSTANCE_ID</instanceid>
  <hostname>$NAME</hostname>
  <system>$OS</system>
  <ip>$PRIVATE_IP</ip>
  <publicip>$PUBLIC_IP</publicip>
  <instancetype>$INSTANCE_TYPE</instancetype>
  <availabilityzone>$AZ</availabilityzone>
  <launch_time>$LAUNCH_TIME_FORMATTED</launch_time>
  <current_time>$CURRENT_TIME</current_time>
  <requirement>4.2.2 - Unencrypted Protocol Detection</requirement>
  <evidence>
$EVIDENCE_XML
  </evidence>
</getinfo>
EOF

echo "✅ Output saved to $OUTPUT_FILE"

