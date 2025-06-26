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
OUTPUT_FILE="report/check_sg_all.xml"

EVIDENCE_XML=""

VPCS=$(aws ec2 describe-vpcs --region "$REGION" --query 'Vpcs[*].VpcId' --output text)

for vpc_id in $VPCS; do
  SG_IDS=$(aws ec2 describe-security-groups --region "$REGION" --filters "Name=vpc-id,Values=$vpc_id" --query 'SecurityGroups[*].GroupId' --output text)
  
  EVIDENCE_XML+="
    <vpc>
      <vpc_id>$vpc_id</vpc_id>"
  
  for sg_id in $SG_IDS; do
    sg_details=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$sg_id" --output json)
    sg_name=$(echo "$sg_details" | jq -r '.SecurityGroups[0].GroupName')
    ingress_rules=$(echo "$sg_details" | jq -c '.SecurityGroups[0].IpPermissions[]')

    EVIDENCE_XML+="
      <security_group>
        <sg_id>$sg_id</sg_id>
        <sg_name>$sg_name</sg_name>"
    
    while IFS= read -r rule; do
      ip_protocol=$(echo "$rule" | jq -r '.IpProtocol')
      from_port=$(echo "$rule" | jq -r '.FromPort // "All"')
      to_port=$(echo "$rule" | jq -r '.ToPort // "All"')
      cidrs=$(echo "$rule" | jq -r '.IpRanges[].CidrIp')
      
      for cidr in $cidrs; do
        EVIDENCE_XML+="
        <rule>
          <protocol>$ip_protocol</protocol>
          <from_port>$from_port</from_port>
          <to_port>$to_port</to_port>
          <cidr>$cidr</cidr>
        </rule>"
      done
    done <<< "$ingress_rules"

    EVIDENCE_XML+="
      </security_group>"
  done

  EVIDENCE_XML+="
    </vpc>"
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
  <requirement>1.2.5 - Allowed Ports/Protocols/Services</requirement>
  <evidence>$EVIDENCE_XML
  </evidence>
</getinfo>
EOF

echo "✅ Output saved to $OUTPUT_FILE"

