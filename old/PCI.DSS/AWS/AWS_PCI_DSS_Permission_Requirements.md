# AWS Permissions Required for PCI DSS 4.0.1 Compliance Assessment

## Overview

This document outlines the AWS IAM permissions required to perform a comprehensive PCI DSS 4.0.1 compliance assessment on AWS infrastructure. The permissions follow the principle of least privilege while ensuring access to all necessary resources for a complete assessment.

**Last Updated:** May 2025

## Important Updates for PCI DSS 4.0.1

AWS is certified as a PCI DSS Level 1 Service Provider, the highest level of assessment available. AWS has published the Payment Card Industry Data Security Standard (PCI DSS) v4.0 on AWS Compliance Guide to help customers understand compliance requirements in the cloud environment.

AWS Identity and Access Management (IAM) provides the tools needed to manage access to AWS services and resources securely, which is critical for PCI DSS assessments.

## Permission Structure

### 1. IAM Policy Options

You have three options for setting up the required permissions:

#### Option A: AWS Managed Policies (Recommended for Assessors)

AWS managed policies for job functions are designed to closely align to common job functions in the IT industry. For PCI DSS assessors, the following combination is recommended:

- **`SecurityAudit`** - This policy grants permissions to view configuration data for many AWS services and to review their logs
- `ReadOnlyAccess` - Base read-only access to most AWS resources
- `AmazonInspector2ReadOnlyAccess` - Access to Inspector vulnerability findings
- `AmazonGuardDutyReadOnlyAccess` - Access to GuardDuty security findings
- `CloudWatchReadOnlyAccess` - Access to monitoring and metrics
- `AWSCloudTrailReadOnlyAccess` - Access to audit log data
- `AWSConfigUserAccess` - Access to AWS Config compliance data
- `IAMReadOnlyAccess` - Access to IAM configurations
- `AmazonS3ReadOnlyAccess` - Access to S3 bucket configurations
- `AWSSecurityHubReadOnlyAccess` - Security Hub supports v.3.2.1 and v4.0.1 of the Payment Card Industry Data Security Standard (PCI DSS)

#### Option B: Custom PCI DSS Assessor Policy (Most Secure)
Use the custom policy in `aws_pci_dss_assessor_policy.json` which provides exactly the permissions needed for PCI DSS assessment while following least privilege principles.

#### Option C: Temporary Access for External Assessors
You can also provide your assessor temporary access to your in-scope AWS environment to allow them to independently gather evidence and validate requirements. You can limit the assessor's access by using an IAM role with time or source IP restrictions.

## Permission Categories by PCI DSS Requirement

### Network Security Controls (Requirements 1.x)

**Required Permissions:**
```
ec2:Describe*
elasticloadbalancing:Describe*
network-firewall:Describe*
network-firewall:List*
waf:Get*
waf:List*
wafv2:Get*
wafv2:List*
route53:Get*
route53:List*
```

**Purpose:** 
- Review security group rules and network ACLs
- Verify network segmentation
- Assess VPC configurations and endpoints
- Review load balancer configurations
- Analyze WAF rules and network firewall policies

### System Configuration Standards (Requirements 2.x)

**Required Permissions:**
```
ec2:Describe*
rds:Describe*
redshift:Describe*
ecs:Describe*
eks:Describe*
lambda:Get*
lambda:List*
ssm:Describe*
ssm:Get*
ssm:List*
```

**Purpose:**
- Assess EC2 instance configurations
- Review database configurations
- Verify container and serverless configurations
- Check system patch management status

### Data Protection Mechanisms (Requirements 3.x, 4.x)

**Required Permissions:**
```
kms:Describe*
kms:Get*
kms:List*
s3:GetBucketEncryption
s3:GetEncryptionConfiguration
acm:Describe*
acm:Get*
acm:List*
secretsmanager:Describe*
secretsmanager:List*
```

**Purpose:**
- Verify encryption at rest configurations
- Review key management practices
- Assess certificate management
- Check secrets management

### Malware Protection (Requirements 5.x)

**Required Permissions:**
```
guardduty:Get*
guardduty:List*
inspector2:Get*
inspector2:List*
macie2:Get*
macie2:List*
```

**Purpose:**
- Review threat detection configurations
- Assess vulnerability scanning setup
- Verify malware detection capabilities

### Secure Development (Requirements 6.x)

**Required Permissions:**
```
ecr:Describe*
ecr:List*
ecr:GetRepositoryPolicy
codebuild:BatchGetProjects
codebuild:List*
codepipeline:Get*
codepipeline:List*
```

**Purpose:**
- Review container security configurations
- Assess CI/CD pipeline security
- Verify secure development practices

### Access Control (Requirements 7.x, 8.x)

**Required Permissions:**
```
iam:Get*
iam:List*
iam:GenerateCredentialReport
iam:SimulatePrincipalPolicy
organizations:Describe*
organizations:List*
sso:Describe*
sso:List*
```

**Purpose:**
- Review IAM policies and roles
- Assess user access permissions
- Verify authentication mechanisms
- Check password policies and MFA

### Physical Security (Requirements 9.x)

**Note:** Physical security for AWS data centers is AWS's responsibility. No specific permissions needed for shared responsibility model validation.

### Logging and Monitoring (Requirements 10.x)

**Required Permissions:**
```
cloudtrail:Describe*
cloudtrail:Get*
cloudtrail:List*
cloudtrail:LookupEvents
logs:Describe*
logs:FilterLogEvents
logs:Get*
cloudwatch:Describe*
cloudwatch:Get*
cloudwatch:List*
ec2:DescribeFlowLogs
```

**Purpose:**
- Verify audit logging configurations
- Review log retention policies
- Assess monitoring and alerting
- Check VPC flow logs

### Security Testing (Requirements 11.x)

**Required Permissions:**
```
securityhub:Get*
securityhub:List*
inspector2:List*
inspector2:Get*
guardduty:Get*
guardduty:List*
config:Get*
config:List*
trustedadvisor:Get*
trustedadvisor:List*
```

**Purpose:**
- Review vulnerability scanning results
- Assess security findings
- Verify compliance monitoring
- Check security testing configurations

### Supporting AWS Services

**Required Permissions:**
```
apigateway:GET
apigateway:Get*
cloudformation:Describe*
cloudformation:Get*
cloudformation:List*
cloudfront:Get*
cloudfront:List*
events:Describe*
events:List*
sns:Get*
sns:List*
sqs:Get*
sqs:List*
tag:Get*
tag:List*
xray:Get*
xray:List*
```

**Purpose:**
- Review API configurations
- Assess infrastructure as code
- Check CDN configurations
- Review event processing
- Verify tagging compliance

## Setting Up the Assessment Account

### Step 1: Create the IAM Policy

```bash
# Save the policy to a file
aws iam create-policy \
  --policy-name PCI_DSS_4_0_1_Assessor \
  --policy-document file://aws_pci_dss_assessor_policy.json \
  --description "Read-only permissions for PCI DSS 4.0.1 compliance assessment"
```

### Step 2: Create the IAM User

```bash
# Create the assessment user
aws iam create-user --user-name pci-dss-assessor

# Attach the policy
aws iam attach-user-policy \
  --user-name pci-dss-assessor \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/PCI_DSS_4_0_1_Assessor

# Create access keys
aws iam create-access-key --user-name pci-dss-assessor
```

### Step 3: Enable Console Access (Optional)

```bash
# Set a console password
aws iam create-login-profile \
  --user-name pci-dss-assessor \
  --password "TemporaryPassword123!" \
  --password-reset-required
```

### Step 4: Configure MFA (Recommended)

For additional security, enable MFA for the assessment account:

```bash
# After the user logs in and configures MFA
aws iam enable-mfa-device \
  --user-name pci-dss-assessor \
  --serial-number arn:aws:iam::ACCOUNT_ID:mfa/pci-dss-assessor \
  --authentication-code1 123456 \
  --authentication-code2 789012
```

## Verification Script

Use the `check_pci_permissions.sh` script to verify all permissions are correctly configured:

```bash
./check_pci_permissions.sh
```

This script will test access to all required AWS services and report any missing permissions.

## Security Considerations

1. **Temporary Access**: Create assessment accounts only for the duration of the assessment
2. **Audit Trail**: All API calls made by the assessment account are logged in CloudTrail
3. **No Write Access**: The policy provides read-only access to prevent any modifications
4. **Regional Scope**: Some services require region-specific access - ensure all regions in scope are accessible
5. **Cross-Account Access**: For multi-account environments, set up cross-account roles with the same permissions

## Compliance Notes

- These permissions align with PCI DSS 4.0.1 Requirement 7.2.1 (least privilege)
- The assessment process is non-intrusive and uses only read operations
- External vulnerability scanning (Requirement 11.3.2) requires separate ASV-approved tools
- Physical security assessments (Requirements 9.x) rely on AWS compliance attestations

## AWS Services in Scope for PCI DSS 4.0.1

As of May 2025, AWS has added several new services to the scope of PCI DSS v4.0 certification:
- AWS AppFabric
- Amazon Bedrock
- AWS Clean Rooms
- AWS HealthImaging
- AWS IoT Device Defender
- AWS IoT TwinMaker
- AWS Resilience Hub
- AWS User Notifications
- Amazon DataZone
- Amazon DevOps Guru
- Amazon Managed Grafana

For the full list of services in scope, refer to AWS Services in Scope by Compliance Program.

## Additional Resources

- AWS Security Audit Guidelines: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html#jf_security-auditor
- AWS Managed Policy Reference - SecurityAudit: https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html
- PCI DSS on AWS Compliance Guide: https://docs.aws.amazon.com/compliance/latest/pcidss-guide/welcome.html
- AWS Config Rules for PCI DSS: https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-pci-dss.html
- AWS Services in Scope by Compliance Program: https://aws.amazon.com/compliance/services-in-scope/
- Payment Card Industry Data Security Standard (PCI DSS) v4.0 on AWS Compliance Guide: Available in AWS Artifact
- AWS Audit Manager PCI DSS frameworks: Supports both v3.2.1 and v4.0.1
