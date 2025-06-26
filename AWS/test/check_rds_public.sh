#!/bin/bash

REGION=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)
[ -z "$REGION" ] && REGION="ap-southeast-1"

TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token"   -H "X-aws-ec2-metadata-token-ttl-seconds: 60")

INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN"   http://169.254.169.254/latest/meta-data/instance-id)

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
OUTPUT_FILE="report/check_rds_public.xml"

PUBLIC_RDS=$(aws rds describe-db-instances --region "$REGION" --query 'DBInstances[?PubliclyAccessible==`true`]' --output json)

RDS_XML=""
for row in $(echo "$PUBLIC_RDS" | jq -c '.[]'); do
  db_id=$(echo "$row" | jq -r '.DBInstanceIdentifier')
  endpoint=$(echo "$row" | jq -r '.Endpoint.Address')
  vpc_id=$(echo "$row" | jq -r '.DBSubnetGroup.VpcId')
  RDS_XML+="    <instance>
      <db_identifier>$db_id</db_identifier>
      <endpoint>$endpoint</endpoint>
      <vpc_id>$vpc_id</vpc_id>
    </instance>
"
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
  <requirement>1.4.4 - Publicly Accessible RDS Instances</requirement>
  <public_rds_instances>
$RDS_XML  </public_rds_instances>
</getinfo>
EOF

echo "✅ Output saved to $OUTPUT_FILE"

