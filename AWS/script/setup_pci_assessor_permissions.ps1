# PowerShell Script to Setup PCI DSS 4.0.1 Assessor Permissions
# This script creates an IAM user with the necessary permissions for PCI DSS assessment

param(
    [Parameter(Mandatory=$true)]
    [string]$AccountId,
    
    [Parameter(Mandatory=$false)]
    [string]$UserName = "pci-dss-assessor",
    
    [Parameter(Mandatory=$false)]
    [string]$PolicyName = "PCI_DSS_4_0_1_Assessor",
    
    [Parameter(Mandatory=$false)]
    [string]$Region = "us-east-1"
)

# Set AWS region
$env:AWS_DEFAULT_REGION = $Region

Write-Host "Setting up PCI DSS 4.0.1 Assessor IAM User and Permissions" -ForegroundColor Green
Write-Host "Account ID: $AccountId" -ForegroundColor Yellow
Write-Host "User Name: $UserName" -ForegroundColor Yellow
Write-Host "Policy Name: $PolicyName" -ForegroundColor Yellow
Write-Host "Region: $Region" -ForegroundColor Yellow

# Create the policy document
$policyDocument = @'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PCIDSSAssessorReadOnly",
      "Effect": "Allow",
      "Action": [
        "acm:Describe*",
        "acm:Get*",
        "acm:List*",
        "apigateway:GET",
        "apigateway:Get*",
        "apigateway:List*",
        "cloudformation:Describe*",
        "cloudformation:Get*",
        "cloudformation:List*",
        "cloudfront:Describe*",
        "cloudfront:Get*",
        "cloudfront:List*",
        "cloudtrail:Describe*",
        "cloudtrail:Get*",
        "cloudtrail:List*",
        "cloudtrail:LookupEvents",
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "config:BatchGetResourceConfig",
        "config:Describe*",
        "config:Get*",
        "config:List*",
        "config:SelectResourceConfig",
        "dms:Describe*",
        "dms:List*",
        "ec2:Describe*",
        "ec2:Get*",
        "ecr:BatchGetImage",
        "ecr:Describe*",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetLifecyclePolicy",
        "ecr:GetRepositoryPolicy",
        "ecr:List*",
        "ecs:Describe*",
        "ecs:List*",
        "eks:Describe*",
        "eks:List*",
        "elasticloadbalancing:Describe*",
        "events:Describe*",
        "events:List*",
        "guardduty:Get*",
        "guardduty:List*",
        "iam:GenerateCredentialReport",
        "iam:GenerateServiceLastAccessedDetails",
        "iam:Get*",
        "iam:List*",
        "iam:SimulateCustomPolicy",
        "iam:SimulatePrincipalPolicy",
        "inspector:Describe*",
        "inspector:Get*",
        "inspector:List*",
        "inspector2:BatchGet*",
        "inspector2:Describe*",
        "inspector2:Get*",
        "inspector2:List*",
        "kms:Describe*",
        "kms:Get*",
        "kms:List*",
        "lambda:Get*",
        "lambda:List*",
        "logs:Describe*",
        "logs:FilterLogEvents",
        "logs:Get*",
        "logs:List*",
        "logs:StartQuery",
        "logs:StopQuery",
        "logs:TestMetricFilter",
        "macie2:Describe*",
        "macie2:Get*",
        "macie2:List*",
        "network-firewall:Describe*",
        "network-firewall:List*",
        "organizations:Describe*",
        "organizations:List*",
        "rds:Describe*",
        "rds:List*",
        "redshift:Describe*",
        "redshift:List*",
        "redshift:View*",
        "route53:Get*",
        "route53:List*",
        "route53:Test*",
        "route53domains:Get*",
        "route53domains:List*",
        "route53resolver:Get*",
        "route53resolver:List*",
        "s3:Get*",
        "s3:List*",
        "secretsmanager:Describe*",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:List*",
        "securityhub:BatchGet*",
        "securityhub:Describe*",
        "securityhub:Get*",
        "securityhub:List*",
        "shield:Describe*",
        "shield:Get*",
        "shield:List*",
        "sns:Get*",
        "sns:List*",
        "sqs:Get*",
        "sqs:List*",
        "ssm:Describe*",
        "ssm:Get*",
        "ssm:List*",
        "tag:Get*",
        "tag:List*",
        "trustedadvisor:Describe*",
        "trustedadvisor:Get*",
        "trustedadvisor:List*",
        "waf:Get*",
        "waf:List*",
        "waf-regional:Get*",
        "waf-regional:List*",
        "wafv2:Describe*",
        "wafv2:Get*",
        "wafv2:List*",
        "xray:Get*",
        "xray:List*"
      ],
      "Resource": "*"
    }
  ]
}
'@

# Save policy document to temporary file
$policyFile = "$env:TEMP\pci-assessor-policy.json"
$policyDocument | Out-File -FilePath $policyFile -Encoding UTF8

try {
    # Check if user already exists
    Write-Host "`nChecking if user already exists..." -ForegroundColor Cyan
    $existingUser = aws iam get-user --user-name $UserName 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "User '$UserName' already exists. Skipping user creation." -ForegroundColor Yellow
    } else {
        # Create IAM User
        Write-Host "`nCreating IAM user '$UserName'..." -ForegroundColor Cyan
        aws iam create-user --user-name $UserName
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create IAM user"
        }
        Write-Host "User created successfully." -ForegroundColor Green
    }

    # Check if policy already exists
    Write-Host "`nChecking if policy already exists..." -ForegroundColor Cyan
    $policyArn = "arn:aws:iam::${AccountId}:policy/${PolicyName}"
    $existingPolicy = aws iam get-policy --policy-arn $policyArn 2>$null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Policy '$PolicyName' already exists." -ForegroundColor Yellow
        
        # Create new version of the policy
        Write-Host "Creating new version of the policy..." -ForegroundColor Cyan
        aws iam create-policy-version `
            --policy-arn $policyArn `
            --policy-document file://$policyFile `
            --set-as-default
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Policy updated successfully." -ForegroundColor Green
        }
    } else {
        # Create IAM Policy
        Write-Host "`nCreating IAM policy '$PolicyName'..." -ForegroundColor Cyan
        aws iam create-policy `
            --policy-name $PolicyName `
            --policy-document file://$policyFile `
            --description "Read-only permissions for PCI DSS 4.0.1 compliance assessment"
        
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create IAM policy"
        }
        Write-Host "Policy created successfully." -ForegroundColor Green
    }

    # Attach Policy to User
    Write-Host "`nAttaching policy to user..." -ForegroundColor Cyan
    aws iam attach-user-policy `
        --user-name $UserName `
        --policy-arn $policyArn
    
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to attach policy to user"
    }
    Write-Host "Policy attached successfully." -ForegroundColor Green

    # Create Access Keys
    Write-Host "`nCreating access keys for programmatic access..." -ForegroundColor Cyan
    $accessKeyResult = aws iam create-access-key --user-name $UserName | ConvertFrom-Json
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Note: Access keys may already exist for this user." -ForegroundColor Yellow
    } else {
        Write-Host "`nAccess Key Created Successfully:" -ForegroundColor Green
        Write-Host "Access Key ID: $($accessKeyResult.AccessKey.AccessKeyId)" -ForegroundColor Yellow
        Write-Host "Secret Access Key: $($accessKeyResult.AccessKey.SecretAccessKey)" -ForegroundColor Yellow
        Write-Host "`nIMPORTANT: Save these credentials securely. The secret access key will not be shown again." -ForegroundColor Red
    }

    # Optional: Create Console Access
    $createConsoleAccess = Read-Host "`nDo you want to create console access for this user? (y/n)"
    if ($createConsoleAccess -eq 'y') {
        $tempPassword = "PCI-Temp-" + (Get-Random -Maximum 9999) + "!"
        
        Write-Host "`nCreating console access..." -ForegroundColor Cyan
        aws iam create-login-profile `
            --user-name $UserName `
            --password $tempPassword `
            --password-reset-required
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Console access created successfully." -ForegroundColor Green
            Write-Host "Temporary Password: $tempPassword" -ForegroundColor Yellow
            Write-Host "Console URL: https://$AccountId.signin.aws.amazon.com/console" -ForegroundColor Yellow
            Write-Host "The user will be required to change the password on first login." -ForegroundColor Cyan
        } else {
            Write-Host "Console access may already exist for this user." -ForegroundColor Yellow
        }
    }

    # Summary
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "PCI DSS 4.0.1 Assessor Setup Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "User Name: $UserName"
    Write-Host "Policy ARN: $policyArn"
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Run the permission verification script: ./check_pci_permissions.sh"
    Write-Host "2. Configure AWS CLI with the access keys: aws configure"
    Write-Host "3. (Optional) Enable MFA for additional security"
    Write-Host "4. Document the assessment account details for audit purposes"
    
    # Offer to test permissions
    $testPermissions = Read-Host "`nDo you want to run a quick permission test? (y/n)"
    if ($testPermissions -eq 'y') {
        Write-Host "`nTesting basic permissions..." -ForegroundColor Cyan
        
        # Configure temporary profile
        if ($accessKeyResult) {
            aws configure set aws_access_key_id $accessKeyResult.AccessKey.AccessKeyId --profile pci-test
            aws configure set aws_secret_access_key $accessKeyResult.AccessKey.SecretAccessKey --profile pci-test
            aws configure set region $Region --profile pci-test
            
            # Test EC2 permissions
            Write-Host "Testing EC2 access..." -ForegroundColor Cyan
            aws ec2 describe-instances --max-items 1 --profile pci-test > $null 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✓ EC2 access verified" -ForegroundColor Green
            } else {
                Write-Host "✗ EC2 access failed" -ForegroundColor Red
            }
            
            # Test IAM permissions
            Write-Host "Testing IAM access..." -ForegroundColor Cyan
            aws iam list-users --max-items 1 --profile pci-test > $null 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✓ IAM access verified" -ForegroundColor Green
            } else {
                Write-Host "✗ IAM access failed" -ForegroundColor Red
            }
            
            # Test CloudTrail permissions
            Write-Host "Testing CloudTrail access..." -ForegroundColor Cyan
            aws cloudtrail describe-trails --profile pci-test > $null 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✓ CloudTrail access verified" -ForegroundColor Green
            } else {
                Write-Host "✗ CloudTrail access failed" -ForegroundColor Red
            }
            
            # Clean up test profile
            aws configure --profile pci-test set aws_access_key_id ""
            aws configure --profile pci-test set aws_secret_access_key ""
        }
    }

} catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    exit 1
} finally {
    # Clean up temporary file
    if (Test-Path $policyFile) {
        Remove-Item $policyFile -Force
    }
}

Write-Host "`nScript completed successfully!" -ForegroundColor Green
