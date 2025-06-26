# PCI DSS 4.0.1 AWS Permissions Summary

## Quick Reference Guide

### For External Assessors (QSAs)

The recommended approach for external PCI DSS assessors is to use a combination of AWS managed policies:

1. **Primary Policy**: `SecurityAudit` 
   - Provides comprehensive read-only access to security configurations
   - Includes permissions to view logs and configuration data

2. **Supporting Policies** (as needed):
   - `AWSCloudTrailReadOnlyAccess` - For audit trail analysis
   - `AmazonGuardDutyReadOnlyAccess` - For threat detection findings
   - `AmazonInspector2ReadOnlyAccess` - For vulnerability assessment data
   - `AWSSecurityHubReadOnlyAccess` - For PCI DSS compliance checks

### For Internal Teams

Use the custom `PCI_DSS_4_0_1_Assessor` policy (see `aws_pci_dss_assessor_policy.json`) which includes:
- All SecurityAudit permissions
- Additional permissions for new AWS services in PCI DSS scope
- Specific permissions for PCI DSS 4.0.1 requirements

### Key Permissions by PCI DSS Requirement

| PCI DSS Requirement | Required AWS Permissions |
|---------------------|-------------------------|
| **1.x Network Security** | `ec2:Describe*`, `wafv2:*`, `network-firewall:*` |
| **2.x System Configuration** | `ssm:*`, `ec2:Describe*`, `rds:Describe*` |
| **3.x Data Protection** | `kms:*`, `s3:GetEncryption*` |
| **4.x Transmission Security** | `acm:*`, `apigateway:GET` |
| **5.x Malware Protection** | `guardduty:*`, `inspector2:*` |
| **6.x Secure Development** | `ecr:*`, `codebuild:*`, `waf:*` |
| **7.x & 8.x Access Control** | `iam:*`, `sso:*`, `identitystore:*` |
| **10.x Logging** | `cloudtrail:*`, `logs:*`, `cloudwatch:*` |
| **11.x Security Testing** | `securityhub:*`, `inspector2:*`, `config:*` |

### Setup Commands

#### Quick Setup (AWS CLI)
```bash
# For external assessor
aws iam attach-user-policy --user-name pci-assessor --policy-arn arn:aws:iam::aws:policy/SecurityAudit

# For custom policy
aws iam create-policy --policy-name PCI_DSS_4_0_1_Assessor --policy-document file://aws_pci_dss_assessor_policy.json
aws iam attach-user-policy --user-name pci-assessor --policy-arn arn:aws:iam::ACCOUNT_ID:policy/PCI_DSS_4_0_1_Assessor
```

#### Verification
```bash
# Run the permission check script
./check_pci_permissions.sh

# Or manually verify key permissions
aws ec2 describe-security-groups --max-items 1
aws iam get-account-password-policy
aws cloudtrail describe-trails
```

### Important Notes

1. **AWS Artifact**: Access the PCI DSS Attestation of Compliance (AOC) and Responsibility Summary through AWS Artifact
2. **Security Hub**: Enable AWS Security Hub for automated PCI DSS compliance checks
3. **Temporary Access**: For external assessors, use time-limited IAM roles with IP restrictions
4. **MFA Required**: Enable MFA for all assessment accounts per PCI DSS requirements

### Latest Updates (May 2025)

- AWS Security Hub now supports PCI DSS v4.0.1
- New services added to PCI DSS scope include Amazon Bedrock, AWS Clean Rooms, and AWS AppFabric
- AWS Audit Manager provides prebuilt frameworks for both PCI DSS v3.2.1 and v4.0.1

### Resources

- [AWS PCI DSS Compliance Package](https://aws.amazon.com/artifact/) - Available in AWS Artifact
- [AWS Services in Scope](https://aws.amazon.com/compliance/services-in-scope/PCI/)
- [Security Audit Policy Documentation](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html)
