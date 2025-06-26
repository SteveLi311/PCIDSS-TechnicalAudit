#!/bin/bash

# Get region using DescribeAvailabilityZones, if fail, exit with message
REGION=$(aws ec2 describe-availability-zones --query 'AvailabilityZones[0].RegionName' --output text 2>/dev/null)
if [ -z "$REGION" ]; then
  echo "❌ 找不到 region，請確認 AWS CLI 設定或權限。"
  exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
mkdir -p report/ec2

ALL_INSTANCE_IDS=$(aws ec2 describe-instances --region "$REGION" \
  --query 'Reservations[*].Instances[*].InstanceId' --output text)

for INSTANCE_ID in $ALL_INSTANCE_IDS; do
  RAW_JSON=$(aws ec2 describe-instances --region "$REGION" \
    --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0]' --output json)

  NAME=$(echo "$RAW_JSON" | jq -r '.Tags[] | select(.Key=="Name") | .Value // "NoName"')
  OS=$(echo "$RAW_JSON" | jq -r '.PlatformDetails')
  PRIVATE_IP=$(echo "$RAW_JSON" | jq -r '.PrivateIpAddress')
  PUBLIC_IP=$(echo "$RAW_JSON" | jq -r '.PublicIpAddress // "N/A"')

  # If no public IP, set to NA for filename
  if [ "$PUBLIC_IP" == "N/A" ]; then
    PUBLIC_IP="NA"
  fi

  INSTANCE_TYPE=$(echo "$RAW_JSON" | jq -r '.InstanceType')
  AZ=$(echo "$RAW_JSON" | jq -r '.Placement.AvailabilityZone')

  # Get current date and time in Taipei timezone
  CURRENT_DATE=$(TZ=Asia/Taipei date +"%Y%m%d")
  CURRENT_TIME=$(TZ=Asia/Taipei date +"%H:%M")
  
  safe_name=$(echo "$NAME" | tr ' ' '-')
  mkdir -p "report/ec2/${safe_name}"
  OUTPUT_FILE="report/ec2/${safe_name}/${PUBLIC_IP}-${safe_name}-ec2_sg.xml"
  EVIDENCE_XML=""

  SG_IDS=$(echo "$RAW_JSON" | jq -r '.SecurityGroups[].GroupId')

  for sg_id in $SG_IDS; do
    sg_details=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$sg_id" --output json)
    sg_name=$(echo "$sg_details" | jq -r '.SecurityGroups[0].GroupName // "Unnamed"')

    SG_RULES=""

    # Ingress rules
    ingress_rules=$(echo "$sg_details" | jq -c '.SecurityGroups[0].IpPermissions[]?')
    while IFS= read -r rule; do
      ip_protocol=$(echo "$rule" | jq -r '.IpProtocol')
      from_port=$(echo "$rule" | jq -r '.FromPort // "All"')
      to_port=$(echo "$rule" | jq -r '.ToPort // "All"')
      cidrs=$(echo "$rule" | jq -r '.IpRanges[].CidrIp')

      for cidr in $cidrs; do
        SG_RULES+="
        <ingress_rule>
          <protocol>$ip_protocol</protocol>
          <from_port>$from_port</from_port>
          <to_port>$to_port</to_port>
          <cidr>$cidr</cidr>
        </ingress_rule>"
      done
    done <<< "$ingress_rules"

    # Egress rules
    egress_rules=$(echo "$sg_details" | jq -c '.SecurityGroups[0].IpPermissionsEgress[]?')
    while IFS= read -r rule; do
      ip_protocol=$(echo "$rule" | jq -r '.IpProtocol')
      from_port=$(echo "$rule" | jq -r '.FromPort // "All"')
      to_port=$(echo "$rule" | jq -r '.ToPort // "All"')
      cidrs=$(echo "$rule" | jq -r '.IpRanges[].CidrIp')

      for cidr in $cidrs; do
        SG_RULES+="
        <egress_rule>
          <protocol>$ip_protocol</protocol>
          <from_port>$from_port</from_port>
          <to_port>$to_port</to_port>
          <cidr>$cidr</cidr>
        </egress_rule>"
      done
    done <<< "$egress_rules"

    EVIDENCE_XML+="
      <security_group id=\"$sg_id\" name=\"$sg_name\">$SG_RULES
      </security_group>"
  done

  {
  echo "<getinfo>"
  echo "  <project>$ACCOUNT_ID</project>"
  echo "  <instanceid>$INSTANCE_ID</instanceid>"
  echo "  <hostname>$NAME</hostname>"
  echo "  <system>$OS</system>"
  echo "  <ip>$PRIVATE_IP</ip>"
  echo "  <public_ip>$PUBLIC_IP</public_ip>"
  echo "  <instancetype>$INSTANCE_TYPE</instancetype>"
  echo "  <availabilityzone>$AZ</availabilityzone>"
  echo "  <date>$CURRENT_DATE</date>"
  echo "  <time>$CURRENT_TIME</time>"
  echo "  <evidence>"
  echo "    <instance id=\"$INSTANCE_ID\" name=\"$NAME\">"
  echo "$EVIDENCE_XML"
  echo "    </instance>"
  echo "  </evidence>"
  echo "</getinfo>"
  } > "$OUTPUT_FILE"

  echo "✅ Output written to $OUTPUT_FILE"
done
