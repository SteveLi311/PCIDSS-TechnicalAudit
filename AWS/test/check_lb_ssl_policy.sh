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
OUTPUT_FILE="report/check_lb_ssl_policy.xml"
EVIDENCE_XML=""

LB_ARNS=$(aws elbv2 describe-load-balancers --region "$REGION" --query 'LoadBalancers[*].LoadBalancerArn' --output text)

for lb_arn in $LB_ARNS; do
  LB_NAME=$(aws elbv2 describe-load-balancers --region "$REGION" --load-balancer-arns "$lb_arn" --query 'LoadBalancers[0].LoadBalancerName' --output text)
  LISTENER_ARNS=$(aws elbv2 describe-listeners --region "$REGION" --load-balancer-arn "$lb_arn" --query 'Listeners[*].ListenerArn' --output text)

  for listener_arn in $LISTENER_ARNS; do
    proto=$(aws elbv2 describe-listeners --region "$REGION" --listener-arns "$listener_arn" --query 'Listeners[0].Protocol' --output text)
    ssl_policy=$(aws elbv2 describe-listeners --region "$REGION" --listener-arns "$listener_arn" --query 'Listeners[0].SslPolicy' --output text 2>/dev/null)
    cert_arn=$(aws elbv2 describe-listeners --region "$REGION" --listener-arns "$listener_arn" --query 'Listeners[0].Certificates[0].CertificateArn' --output text 2>/dev/null)

    if [[ "$proto" == "HTTPS" || "$proto" == "TLS" ]]; then
      not_after=$(aws acm describe-certificate --region "$REGION" --certificate-arn "$cert_arn" --query 'Certificate.NotAfter' --output text 2>/dev/null)
      cert_status="unknown"
      if [ -n "$not_after" ]; then
        expiry_epoch=$(date -d "$not_after" +%s)
        now_epoch=$(date +%s)
        if [ "$expiry_epoch" -gt "$now_epoch" ]; then
          cert_status="valid"
        else
          cert_status="expired"
        fi
      else
        not_after="N/A"
        cert_status="AccessDenied"
      fi

      EVIDENCE_XML="${EVIDENCE_XML}
  <elb>
    <name>$LB_NAME</name>
    <listener_protocol>$proto</listener_protocol>
    <ssl_policy>$ssl_policy</ssl_policy>
    <certificate_arn>$cert_arn</certificate_arn>
    <not_after>$not_after</not_after>
    <status>$cert_status</status>
  </elb>"
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
  <requirement>4.2.1 / 4.2.1.1 - TLS Policy & Certificate Validation</requirement>
  <evidence>
$EVIDENCE_XML
  </evidence>
</getinfo>
EOF

echo "✅ Output saved to $OUTPUT_FILE"

