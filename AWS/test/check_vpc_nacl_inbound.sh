#!/bin/bash

REGION=$(aws ec2 describe-availability-zones --query 'AvailabilityZones[0].RegionName' --output text 2>/dev/null)
if [ -z "$REGION" ]; then
  echo "❌ 找不到 region，請確認 AWS CLI 設定或權限。"
  exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

mkdir -p report/vpc

VPCS=$(aws ec2 describe-vpcs --region "$REGION" --query 'Vpcs[*].VpcId' --output text)

for vpc_id in $VPCS; do
  vpc_name=$(aws ec2 describe-vpcs --vpc-ids "$vpc_id" --region "$REGION" \
    --query 'Vpcs[0].Tags[?Key==`Name`].Value' --output text)
  [ -z "$vpc_name" ] && vpc_name="Unnamed"

  EVIDENCE_XML="  <vpc id=\"$vpc_id\" name=\"$vpc_name\">"

  SUBNETS=$(aws ec2 describe-subnets --region "$REGION" --filters "Name=vpc-id,Values=$vpc_id" --query 'Subnets[*].SubnetId' --output text)

  for subnet_id in $SUBNETS; do
    subnet_name=$(aws ec2 describe-subnets --subnet-ids "$subnet_id" --region "$REGION" \
      --query 'Subnets[0].Tags[?Key==`Name`].Value' --output text)
    [ -z "$subnet_name" ] && subnet_name="Unnamed"

    nacl_id=$(aws ec2 describe-network-acls --region "$REGION" \
      --filters "Name=association.subnet-id,Values=$subnet_id" \
      --query 'NetworkAcls[0].NetworkAclId' --output text)

    if [ -z "$nacl_id" ] || [ "$nacl_id" == "None" ]; then
      continue
    fi

    nacl_name=$(aws ec2 describe-network-acls --network-acl-ids "$nacl_id" --region "$REGION" \
      --query 'NetworkAcls[0].Tags[?Key==`Name`].Value' --output text)
    [ -z "$nacl_name" ] && nacl_name="Unnamed"

    nacl_entries=$(aws ec2 describe-network-acls --region "$REGION" --network-acl-ids "$nacl_id" \
      --query 'NetworkAcls[0].Entries[?Egress==`false`]' --output json)

    RULES_XML=""
    for row in $(echo "$nacl_entries" | jq -c '.[] | select(.RuleAction == "allow")'); do
      rule_number=$(echo "$row" | jq -r '.RuleNumber')
      protocol=$(echo "$row" | jq -r '.Protocol')
      rule_action=$(echo "$row" | jq -r '.RuleAction')
      cidr=$(echo "$row" | jq -r '.CidrBlock // empty')
      from_port=$(echo "$row" | jq -r '.PortRange.From // "All"')
      to_port=$(echo "$row" | jq -r '.PortRange.To // "All"')

      RULES_XML+="
        <rule>
          <rule_number>$rule_number</rule_number>
          <protocol>$protocol</protocol>
          <from_port>$from_port</from_port>
          <to_port>$to_port</to_port>
          <rule_action>$rule_action</rule_action>
          <cidr>$cidr</cidr>
        </rule>"
    done

    EVIDENCE_XML+="
    <subnet id=\"$subnet_id\" name=\"$subnet_name\">
      <nacl id=\"$nacl_id\" name=\"$nacl_name\">$RULES_XML
      </nacl>
    </subnet>"
  done

  EVIDENCE_XML+="
  </vpc>"

  CURRENT_DATE=$(TZ=Asia/Taipei date +"%Y%m%d")
  CURRENT_TIME=$(TZ=Asia/Taipei date +"%H:%M")
  
  safe_vpc_name=$(echo "$vpc_name" | tr ' ' '-')
  mkdir -p "report/vpc/${safe_vpc_name}"
  OUTPUT_FILE="report/vpc/${safe_vpc_name}/${safe_vpc_name}_vpc_nacl_inbound.xml"

  cat <<EOF > "$OUTPUT_FILE"
<getinfo>
  <project>$ACCOUNT_ID</project>
  <region>$REGION</region>
  <date>$CURRENT_DATE</date>
  <time>$CURRENT_TIME</time>
  <requirement>1.3.1 - NACL inbound</requirement>
  <evidence>
$EVIDENCE_XML
  </evidence>
</getinfo>
EOF

  echo "✅ Output saved to $OUTPUT_FILE"
done

