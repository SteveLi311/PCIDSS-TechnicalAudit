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
OUTPUT_FILE="report/check_nacl_outbound.xml"

EVIDENCE_XML=""

VPCS=$(aws ec2 describe-vpcs --region "$REGION" --query 'Vpcs[*].VpcId' --output text)

for vpc_id in $VPCS; do
  EVIDENCE_XML+="
    <vpc>
      <vpc_id>$vpc_id</vpc_id>"
  
  SUBNETS=$(aws ec2 describe-subnets --region "$REGION" --filters "Name=vpc-id,Values=$vpc_id" --query 'Subnets[*].SubnetId' --output text)
  
  for subnet_id in $SUBNETS; do
    nacl_id=$(aws ec2 describe-network-acls --region "$REGION" --filters "Name=association.subnet-id,Values=$subnet_id" --query 'NetworkAcls[0].NetworkAclId' --output text)
    
    if [ -z "$nacl_id" ] || [ "$nacl_id" == "None" ]; then
      continue
    fi
    
    rules=$(aws ec2 describe-network-acls --region "$REGION" --network-acl-ids $nacl_id --query 'NetworkAcls[0].Entries[?Egress==`true` && CidrBlock==`0.0.0.0/0` && RuleAction==`allow`]' --output text)
    
    if [ -n "$rules" ]; then
      formatted_rules=$(echo "$rules" | awk '{print "<rule>" $0 "</rule>"}')
      EVIDENCE_XML+="
      <subnet>
        <subnet_id>$subnet_id</subnet_id>
        <nacl>$nacl_id</nacl>
        $formatted_rules
      </subnet>"
    fi
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
  <requirement>1.3.2 - NACL outbound</requirement>
  <evidence>$EVIDENCE_XML
  </evidence>
</getinfo>
EOF

echo "✅ Output saved to $OUTPUT_FILE"

