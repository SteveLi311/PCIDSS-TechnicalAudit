#!/usr/bin/env bash

# PCI DSS Requirement 6 Compliance Check Script for AWS
# This script evaluates AWS controls for PCI DSS Requirement 6 compliance
# Requirement 6: Develop and Maintain Secure Systems and Software

# Source the HTML report library
source "$(dirname "$0")/pci_html_report_lib.sh"

# Set output colors for terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Define script variables
REQUIREMENT_NUMBER="6"
REPORT_TITLE="PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report"

# Define timestamp for the report filename
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="./reports"
OUTPUT_FILE="$OUTPUT_DIR/pci_req${REQUIREMENT_NUMBER}_report_$TIMESTAMP.html"

# Create reports directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Counters for checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

# Start script execution
echo "============================================="
echo "  PCI DSS 4.0 - Requirement $REQUIREMENT_NUMBER HTML Report"
echo "  (Develop and Maintain Secure Systems and Software)"
echo "============================================="
echo ""

# Use default region from AWS CLI configuration or fall back to us-east-1
REGION=$(aws configure get region 2>/dev/null)
if [ -z "$REGION" ]; then
    REGION="us-east-1"
    echo -e "${YELLOW}Using default region: $REGION${NC}"
else
    echo -e "${YELLOW}Using configured region from AWS CLI: $REGION${NC}"
fi

# Ask for specific resources to assess
read -p "Enter resource IDs to assess (comma-separated or 'all' for all): " TARGET_RESOURCES
if [ -z "$TARGET_RESOURCES" ] || [ "$TARGET_RESOURCES" == "all" ]; then
    echo -e "${YELLOW}Checking all resources${NC}"
    TARGET_RESOURCES="all"
else
    echo -e "${YELLOW}Checking specific resource(s): $TARGET_RESOURCES${NC}"
fi

# Initialize HTML report
initialize_html_report "$OUTPUT_FILE" "$REPORT_TITLE" "$REQUIREMENT_NUMBER" "$REGION"

echo ""
echo "Starting assessment at $(date)"
echo ""

#----------------------------------------------------------------------
# SECTION 1: PERMISSIONS CHECK
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "permissions" "AWS Permissions Check" "active"

echo -e "\n${CYAN}=== CHECKING REQUIRED AWS PERMISSIONS ===${NC}"
echo "Verifying access to required AWS services for PCI Requirement $REQUIREMENT_NUMBER assessment..."

# Check for required permissions
check_command_access "$OUTPUT_FILE" "codebuild" "list-projects" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "codepipeline" "list-pipelines" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "ecr" "describe-repositories" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "inspector2" "list-findings" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "guardduty" "list-detectors" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "lambda" "list-functions" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "s3api" "list-buckets" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "wafv2" "list-web-acls" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "securityhub" "get-findings" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

check_command_access "$OUTPUT_FILE" "cloudformation" "list-stacks" "$REGION"
((total_checks++))
[ $? -eq 0 ] && ((passed_checks++)) || ((failed_checks++))

permissions_percentage=$(( (passed_checks * 100) / total_checks ))

if [ $permissions_percentage -lt 70 ]; then
    echo -e "${RED}WARNING: Insufficient permissions to perform a complete PCI Requirement $REQUIREMENT_NUMBER assessment.${NC}"
    add_check_item "$OUTPUT_FILE" "warning" "Permission Assessment" "Insufficient permissions detected. Only $permissions_percentage% of required permissions are available." "Request additional permissions or continue with limited assessment capabilities."
    echo -e "${YELLOW}Recommendation: Request additional permissions or continue with limited assessment capabilities.${NC}"
    read -p "Continue with limited assessment? (y/n): " CONTINUE
    if [[ ! $CONTINUE =~ ^[Yy]$ ]]; then
        echo "Assessment aborted."
        add_check_item "$OUTPUT_FILE" "info" "Assessment Aborted" "User chose to abort assessment due to insufficient permissions."
        close_section "$OUTPUT_FILE"
        finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"
        echo "Report has been generated: $OUTPUT_FILE"
        exit 1
    fi
else
    echo -e "\nPermission check complete: $passed_checks/$total_checks permissions available ($permissions_percentage%)"
    add_check_item "$OUTPUT_FILE" "pass" "Permission Assessment" "Sufficient permissions detected. $permissions_percentage% of required permissions are available."
fi

close_section "$OUTPUT_FILE"

# Reset counters for the actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

#----------------------------------------------------------------------
# SECTION 2: DETERMINE RESOURCES TO CHECK
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "target-resources" "Target Resources" "block"

echo -e "\n${CYAN}=== IDENTIFYING TARGET RESOURCES ===${NC}"

# Check resources to assess
# For Requirement 6, we primarily need to check:
# - CodeBuild projects for secure CI/CD
# - CodePipeline pipelines for CI/CD workflow
# - ECR repositories for container security
# - Lambda functions for serverless security
# - S3 buckets for static content
# - WAFv2 for web application security
# - CloudFormation for infrastructure as code

if [ "$TARGET_RESOURCES" == "all" ]; then
    # Identify all relevant resources 
    echo "Identifying all relevant resources for Requirement 6 assessment..."
    
    # Get CodeBuild projects
    CODEBUILD_PROJECTS=$(aws codebuild list-projects --region $REGION --query 'projects[*]' --output text 2>/dev/null)
    
    # Get CodePipeline pipelines
    CODEPIPELINE_PIPELINES=$(aws codepipeline list-pipelines --region $REGION --query 'pipelines[*].name' --output text 2>/dev/null)
    
    # Get ECR repositories
    ECR_REPOS=$(aws ecr describe-repositories --region $REGION --query 'repositories[*].repositoryName' --output text 2>/dev/null)
    
    # Get Lambda functions
    LAMBDA_FUNCTIONS=$(aws lambda list-functions --region $REGION --query 'Functions[*].FunctionName' --output text 2>/dev/null)
    
    # Get S3 buckets
    S3_BUCKETS=$(aws s3api list-buckets --query 'Buckets[*].Name' --output text 2>/dev/null)
    
    # Get WAFv2 web ACLs
    WAF_ACLS=$(aws wafv2 list-web-acls --scope REGIONAL --region $REGION --query 'WebACLs[*].Name' --output text 2>/dev/null)
    
    # Get CloudFormation stacks
    CF_STACKS=$(aws cloudformation list-stacks --region $REGION --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE --query 'StackSummaries[*].StackName' --output text 2>/dev/null)
    
    if [ -z "$CODEBUILD_PROJECTS" ] && [ -z "$CODEPIPELINE_PIPELINES" ] && [ -z "$ECR_REPOS" ] && [ -z "$LAMBDA_FUNCTIONS" ] && [ -z "$S3_BUCKETS" ] && [ -z "$WAF_ACLS" ] && [ -z "$CF_STACKS" ]; then
        echo -e "${RED}Failed to retrieve any resources. Check your permissions.${NC}"
        add_check_item "$OUTPUT_FILE" "warning" "Resource Identification" "Failed to retrieve resources." "Check your AWS permissions and ensure you have resources in the specified region."
    else
        RESOURCES_SUMMARY="<h4>Resources identified for assessment:</h4>"
        
        # Add CodeBuild projects
        if [ -n "$CODEBUILD_PROJECTS" ]; then
            RESOURCES_SUMMARY+="<p><strong>CodeBuild Projects:</strong> $(echo $CODEBUILD_PROJECTS | wc -w) projects</p>"
            if [ $(echo $CODEBUILD_PROJECTS | wc -w) -le 10 ]; then
                RESOURCES_SUMMARY+="<ul>"
                for project in $CODEBUILD_PROJECTS; do
                    RESOURCES_SUMMARY+="<li>$project</li>"
                done
                RESOURCES_SUMMARY+="</ul>"
            fi
        else
            RESOURCES_SUMMARY+="<p><strong>CodeBuild Projects:</strong> None found</p>"
        fi
        
        # Add CodePipeline pipelines
        if [ -n "$CODEPIPELINE_PIPELINES" ]; then
            RESOURCES_SUMMARY+="<p><strong>CodePipeline Pipelines:</strong> $(echo $CODEPIPELINE_PIPELINES | wc -w) pipelines</p>"
            if [ $(echo $CODEPIPELINE_PIPELINES | wc -w) -le 10 ]; then
                RESOURCES_SUMMARY+="<ul>"
                for pipeline in $CODEPIPELINE_PIPELINES; do
                    RESOURCES_SUMMARY+="<li>$pipeline</li>"
                done
                RESOURCES_SUMMARY+="</ul>"
            fi
        else
            RESOURCES_SUMMARY+="<p><strong>CodePipeline Pipelines:</strong> None found</p>"
        fi
        
        # Add ECR repositories
        if [ -n "$ECR_REPOS" ]; then
            RESOURCES_SUMMARY+="<p><strong>ECR Repositories:</strong> $(echo $ECR_REPOS | wc -w) repositories</p>"
            if [ $(echo $ECR_REPOS | wc -w) -le 10 ]; then
                RESOURCES_SUMMARY+="<ul>"
                for repo in $ECR_REPOS; do
                    RESOURCES_SUMMARY+="<li>$repo</li>"
                done
                RESOURCES_SUMMARY+="</ul>"
            fi
        else
            RESOURCES_SUMMARY+="<p><strong>ECR Repositories:</strong> None found</p>"
        fi
        
        # Add Lambda functions
        if [ -n "$LAMBDA_FUNCTIONS" ]; then
            RESOURCES_SUMMARY+="<p><strong>Lambda Functions:</strong> $(echo $LAMBDA_FUNCTIONS | wc -w) functions</p>"
            if [ $(echo $LAMBDA_FUNCTIONS | wc -w) -le 10 ]; then
                RESOURCES_SUMMARY+="<ul>"
                for func in $LAMBDA_FUNCTIONS; do
                    RESOURCES_SUMMARY+="<li>$func</li>"
                done
                RESOURCES_SUMMARY+="</ul>"
            fi
        else
            RESOURCES_SUMMARY+="<p><strong>Lambda Functions:</strong> None found</p>"
        fi
        
        # Add S3 buckets
        if [ -n "$S3_BUCKETS" ]; then
            RESOURCES_SUMMARY+="<p><strong>S3 Buckets:</strong> $(echo $S3_BUCKETS | wc -w) buckets</p>"
            if [ $(echo $S3_BUCKETS | wc -w) -le 10 ]; then
                RESOURCES_SUMMARY+="<ul>"
                for bucket in $S3_BUCKETS; do
                    RESOURCES_SUMMARY+="<li>$bucket</li>"
                done
                RESOURCES_SUMMARY+="</ul>"
            fi
        else
            RESOURCES_SUMMARY+="<p><strong>S3 Buckets:</strong> None found</p>"
        fi
        
        # Add WAF ACLs
        if [ -n "$WAF_ACLS" ]; then
            RESOURCES_SUMMARY+="<p><strong>WAF Web ACLs:</strong> $(echo $WAF_ACLS | wc -w) ACLs</p>"
            if [ $(echo $WAF_ACLS | wc -w) -le 10 ]; then
                RESOURCES_SUMMARY+="<ul>"
                for acl in $WAF_ACLS; do
                    RESOURCES_SUMMARY+="<li>$acl</li>"
                done
                RESOURCES_SUMMARY+="</ul>"
            fi
        else
            RESOURCES_SUMMARY+="<p><strong>WAF Web ACLs:</strong> None found</p>"
        fi
        
        # Add CloudFormation stacks
        if [ -n "$CF_STACKS" ]; then
            RESOURCES_SUMMARY+="<p><strong>CloudFormation Stacks:</strong> $(echo $CF_STACKS | wc -w) stacks</p>"
            if [ $(echo $CF_STACKS | wc -w) -le 10 ]; then
                RESOURCES_SUMMARY+="<ul>"
                for stack in $CF_STACKS; do
                    RESOURCES_SUMMARY+="<li>$stack</li>"
                done
                RESOURCES_SUMMARY+="</ul>"
            fi
        else
            RESOURCES_SUMMARY+="<p><strong>CloudFormation Stacks:</strong> None found</p>"
        fi
        
        add_check_item "$OUTPUT_FILE" "info" "Resource Identification" "$RESOURCES_SUMMARY"
    fi
else
    # Convert comma-separated list to space-separated
    RESOURCES=$(echo $TARGET_RESOURCES | tr ',' ' ')
    echo -e "Using provided resource list: $RESOURCES"
    add_check_item "$OUTPUT_FILE" "info" "Resource Identification" "Assessment will be performed on specified resources: <pre>${RESOURCES}</pre>"
fi

close_section "$OUTPUT_FILE"


#----------------------------------------------------------------------
# SECTION 4: PCI REQUIREMENT 6.2 - BESPOKE AND CUSTOM SOFTWARE
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-6.2" "Requirement 6.2: Bespoke and custom software are developed securely" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 6.2: BESPOKE AND CUSTOM SOFTWARE ===${NC}"


# Check for CodeBuild projects with security scanning
echo "Checking CodeBuild projects for secure build configurations..."
if [ -n "$CODEBUILD_PROJECTS" ]; then
    CB_DETAILS="<p>Examining CI/CD pipeline security for CodeBuild projects:</p><ul>"
    CB_ISSUES_FOUND=false
    
    for project in $CODEBUILD_PROJECTS; do
        echo "  Checking project: $project"
        PROJECT_INFO=$(aws codebuild batch-get-projects --names $project --region $REGION 2>/dev/null)
        
        # Extract security-relevant details
        ENV_TYPE=$(echo "$PROJECT_INFO" | grep -o '"type": "[^"]*"' | head -1 | cut -d'"' -f4)
        PRIVILEGED_MODE=$(echo "$PROJECT_INFO" | grep -o '"privilegedMode": [^,}]*' | head -1 | cut -d' ' -f2)
        
        if [ "$PRIVILEGED_MODE" == "true" ]; then
            CB_ISSUES_FOUND=true
            CB_DETAILS+="<li><span class=\"red\">Project $project uses privileged mode, which grants extended permissions to the build container</span></li>"
        fi
        
        # Check for buildspec file with security scanning steps
        BUILDSPEC=$(echo "$PROJECT_INFO" | grep -o '"buildspec": "[^"]*"' | head -1 | cut -d'"' -f4)
        if [ -z "$BUILDSPEC" ] || [ "$BUILDSPEC" == "null" ]; then
            CB_ISSUES_FOUND=true
            CB_DETAILS+="<li><span class=\"yellow\">Project $project does not have an inline buildspec defined. Security scanning configuration may be in the source repository.</span></li>"
        else
            # Check for common security scanning tools in buildspec
            if [[ "$BUILDSPEC" == *"security"* || "$BUILDSPEC" == *"scan"* || "$BUILDSPEC" == *"test"* ]]; then
                CB_DETAILS+="<li><span class=\"green\">Project $project buildspec contains keywords suggesting security scanning may be configured</span></li>"
            else
                CB_ISSUES_FOUND=true
                CB_DETAILS+="<li><span class=\"yellow\">Project $project buildspec does not contain obvious security scanning keywords</span></li>"
            fi
        fi
        
        # Check for environment variables with sensitive information
        ENV_VARS=$(echo "$PROJECT_INFO" | grep -o '"environmentVariables": \[.*\]' | grep -o '"name": "[^"]*"' | cut -d'"' -f4)
        if [[ "$ENV_VARS" == *"KEY"* || "$ENV_VARS" == *"SECRET"* || "$ENV_VARS" == *"PASSWORD"* || "$ENV_VARS" == *"TOKEN"* ]]; then
            CB_ISSUES_FOUND=true
            CB_DETAILS+="<li><span class=\"red\">Project $project may have sensitive information in environment variables. Environment variables contain keywords like KEY, SECRET, PASSWORD, or TOKEN.</span></li>"
        fi
    done
    
    CB_DETAILS+="</ul>"
    
    if [ "$CB_ISSUES_FOUND" = true ]; then
        add_check_item "$OUTPUT_FILE" "warning" "6.2.1 - CodeBuild Pipeline Analysis" \
            "$CB_DETAILS" \
            "Enhance CodeBuild projects with security scanning steps. Restrict use of privileged mode when possible. Include security testing such as SAST, DAST, or SCA tools in your build pipeline. Use AWS Secrets Manager or Parameter Store for sensitive information instead of environment variables."
        ((warning_checks++))
    else
        add_check_item "$OUTPUT_FILE" "pass" "6.2.1 - CodeBuild Pipeline Analysis" \
            "$CB_DETAILS"
        ((passed_checks++))
    fi
else
    add_check_item "$OUTPUT_FILE" "info" "6.2.1 - CodeBuild Pipeline Analysis" \
        "<p>No CodeBuild projects found for analysis.</p>"
    ((warning_checks++))
fi
((total_checks++))

# Check for CodePipeline pipelines
echo "Checking CodePipeline pipelines for secure CI/CD workflow..."
if [ -n "$CODEPIPELINE_PIPELINES" ]; then
    CP_DETAILS="<p>Analyzing CI/CD workflow security for CodePipeline pipelines:</p><ul>"
    CP_ISSUES_FOUND=false
    
    for pipeline in $CODEPIPELINE_PIPELINES; do
        echo "  Checking pipeline: $pipeline"
        PIPELINE_INFO=$(aws codepipeline get-pipeline --name "$pipeline" --region $REGION 2>/dev/null)
        
        # Check for security testing stages
        STAGE_NAMES=$(echo "$PIPELINE_INFO" | grep -o '"name": "[^"]*"' | cut -d'"' -f4)
        
        SECURITY_STAGES_FOUND=false
        for stage in $STAGE_NAMES; do
            if [[ "$stage" == *"security"* || "$stage" == *"test"* || "$stage" == *"scan"* || "$stage" == *"validate"* ]]; then
                SECURITY_STAGES_FOUND=true
                CP_DETAILS+="<li><span class=\"green\">Pipeline $pipeline includes a potential security testing stage: $stage</span></li>"
                break
            fi
        done
        
        if [ "$SECURITY_STAGES_FOUND" = false ]; then
            CP_ISSUES_FOUND=true
            CP_DETAILS+="<li><span class=\"yellow\">Pipeline $pipeline does not appear to have dedicated security testing stages</span></li>"
        fi
        
        # Check for manual approval stages (important for change control)
        APPROVAL_STAGES=$(echo "$PIPELINE_INFO" | grep -o '"type": "Approval"' | wc -l)
        if [ $APPROVAL_STAGES -eq 0 ]; then
            CP_ISSUES_FOUND=true
            CP_DETAILS+="<li><span class=\"yellow\">Pipeline $pipeline does not include manual approval stages for change control</span></li>"
        else
            CP_DETAILS+="<li><span class=\"green\">Pipeline $pipeline includes manual approval stages for change control</span></li>"
        fi
    done
    
    CP_DETAILS+="</ul>"
    
    if [ "$CP_ISSUES_FOUND" = true ]; then
        add_check_item "$OUTPUT_FILE" "warning" "6.2.1 - CodePipeline CI/CD Workflow Analysis" \
            "$CP_DETAILS" \
            "Add dedicated security testing stages to your CI/CD pipelines. Include manual approval stages before deployment to production to ensure proper change control. Consider integrating AWS CodeStar Notifications to alert security teams of pipeline activities."
        ((warning_checks++))
    else
        add_check_item "$OUTPUT_FILE" "pass" "6.2.1 - CodePipeline CI/CD Workflow Analysis" \
            "$CP_DETAILS"
        ((passed_checks++))
    fi
else
    add_check_item "$OUTPUT_FILE" "info" "6.2.1 - CodePipeline CI/CD Workflow Analysis" \
        "<p>No CodePipeline pipelines found for analysis.</p>"
    ((warning_checks++))
fi
((total_checks++))


close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 5: PCI REQUIREMENT 6.3 - SECURITY VULNERABILITIES
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-6.3" "Requirement 6.3: Security vulnerabilities are identified and addressed" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 6.3: SECURITY VULNERABILITIES ===${NC}"


# Check for AWS Inspector usage
echo "Checking AWS Inspector for security vulnerability findings..."
INSPECTOR_ENABLED=false
INSPECTOR_DETAILS=""

# Check if Inspector is enabled for the account
INSPECTOR_STATUS=$(aws inspector2 batch-get-account-status --region $REGION 2>/dev/null)
if [ $? -eq 0 ]; then
    # Extract Inspector status
    EC2_SCANNING=$(echo "$INSPECTOR_STATUS" | grep -o '"EC2_SCANNING": "[^"]*"' | head -1 | cut -d'"' -f4)
    ECR_SCANNING=$(echo "$INSPECTOR_STATUS" | grep -o '"ECR_SCANNING": "[^"]*"' | head -1 | cut -d'"' -f4)
    LAMBDA_SCANNING=$(echo "$INSPECTOR_STATUS" | grep -o '"LAMBDA_SCANNING": "[^"]*"' | head -1 | cut -d'"' -f4)
    
    if [ "$EC2_SCANNING" == "ENABLED" ] || [ "$ECR_SCANNING" == "ENABLED" ] || [ "$LAMBDA_SCANNING" == "ENABLED" ]; then
        INSPECTOR_ENABLED=true
        INSPECTOR_DETAILS="<p>AWS Inspector is enabled with the following status:</p><ul>"
        
        if [ "$EC2_SCANNING" == "ENABLED" ]; then
            INSPECTOR_DETAILS+="<li><span class=\"green\">EC2 Scanning: ENABLED</span></li>"
        else
            INSPECTOR_DETAILS+="<li><span class=\"yellow\">EC2 Scanning: DISABLED</span></li>"
        fi
        
        if [ "$ECR_SCANNING" == "ENABLED" ]; then
            INSPECTOR_DETAILS+="<li><span class=\"green\">ECR Scanning: ENABLED</span></li>"
        else
            INSPECTOR_DETAILS+="<li><span class=\"yellow\">ECR Scanning: DISABLED</span></li>"
        fi
        
        if [ "$LAMBDA_SCANNING" == "ENABLED" ]; then
            INSPECTOR_DETAILS+="<li><span class=\"green\">Lambda Scanning: ENABLED</span></li>"
        else
            INSPECTOR_DETAILS+="<li><span class=\"yellow\">Lambda Scanning: DISABLED</span></li>"
        fi
        
        INSPECTOR_DETAILS+="</ul>"
        
        # Check for critical findings
        FINDINGS=$(aws inspector2 list-findings --filter-criteria '{"findingSeverity":[{"comparison":"EQUALS","value":"CRITICAL"}]}' --region $REGION 2>/dev/null)
        CRITICAL_COUNT=$(echo "$FINDINGS" | grep -o '"findingArn":' | wc -l)
        
        FINDINGS=$(aws inspector2 list-findings --filter-criteria '{"findingSeverity":[{"comparison":"EQUALS","value":"HIGH"}]}' --region $REGION 2>/dev/null)
        HIGH_COUNT=$(echo "$FINDINGS" | grep -o '"findingArn":' | wc -l)
        
        if [ $CRITICAL_COUNT -gt 0 ] || [ $HIGH_COUNT -gt 0 ]; then
            INSPECTOR_DETAILS+="<p>Security vulnerabilities detected:</p><ul>"
            
            if [ $CRITICAL_COUNT -gt 0 ]; then
                INSPECTOR_DETAILS+="<li><span class=\"red\">Critical vulnerabilities: $CRITICAL_COUNT</span></li>"
                
                # Get a sample of critical findings
                if [ $CRITICAL_COUNT -le 5 ]; then
                    SAMPLE_FINDINGS=$(echo "$FINDINGS" | grep -o '"title": "[^"]*"' | head -5 | cut -d'"' -f4)
                    INSPECTOR_DETAILS+="<li>Critical findings include:<ul>"
                    while read -r finding; do
                        INSPECTOR_DETAILS+="<li>$finding</li>"
                    done <<< "$SAMPLE_FINDINGS"
                    INSPECTOR_DETAILS+="</ul></li>"
                fi
            fi
            
            if [ $HIGH_COUNT -gt 0 ]; then
                INSPECTOR_DETAILS+="<li><span class=\"red\">High vulnerabilities: $HIGH_COUNT</span></li>"
                
                # Get a sample of high findings
                if [ $HIGH_COUNT -le 5 ]; then
                    SAMPLE_FINDINGS=$(echo "$FINDINGS" | grep -o '"title": "[^"]*"' | head -5 | cut -d'"' -f4)
                    INSPECTOR_DETAILS+="<li>High findings include:<ul>"
                    while read -r finding; do
                        INSPECTOR_DETAILS+="<li>$finding</li>"
                    done <<< "$SAMPLE_FINDINGS"
                    INSPECTOR_DETAILS+="</ul></li>"
                fi
            fi
            
            INSPECTOR_DETAILS+="</ul>"
            
            add_check_item "$OUTPUT_FILE" "fail" "6.3.1 - Vulnerability scanning with AWS Inspector" \
                "$INSPECTOR_DETAILS" \
                "Address critical and high severity vulnerabilities identified by AWS Inspector. Implement a patch management process to remediate vulnerabilities within the required timeframes (critical vulnerabilities within one month)."
            ((failed_checks++))
        else
            INSPECTOR_DETAILS+="<p><span class=\"green\">No critical or high severity findings detected by AWS Inspector.</span></p>"
            add_check_item "$OUTPUT_FILE" "pass" "6.3.1 - Vulnerability scanning with AWS Inspector" \
                "$INSPECTOR_DETAILS"
            ((passed_checks++))
        fi
    else
        INSPECTOR_DETAILS="<p><span class=\"yellow\">AWS Inspector is not fully enabled. EC2, ECR, and Lambda scanning should be enabled to identify security vulnerabilities.</span></p>"
        add_check_item "$OUTPUT_FILE" "warning" "6.3.1 - Vulnerability scanning with AWS Inspector" \
            "$INSPECTOR_DETAILS" \
            "Enable AWS Inspector for EC2 instances, ECR container images, and Lambda functions to automatically identify security vulnerabilities."
        ((warning_checks++))
    fi
else
    INSPECTOR_DETAILS="<p><span class=\"red\">AWS Inspector is not enabled or configured in this region.</span></p>"
    add_check_item "$OUTPUT_FILE" "fail" "6.3.1 - Vulnerability scanning with AWS Inspector" \
        "$INSPECTOR_DETAILS" \
        "Enable AWS Inspector to automatically scan for vulnerabilities in EC2 instances, container images, and Lambda functions. Inspector helps identify software vulnerabilities and network exposure."
    ((failed_checks++))
fi
((total_checks++))


# Check for ECR repositories with vulnerability scanning
echo "Checking ECR repositories for image scanning configuration..."
if [ -n "$ECR_REPOS" ]; then
    ECR_DETAILS="<p>Analyzing vulnerability scanning configuration for ECR repositories:</p><ul>"
    ECR_ISSUES_FOUND=false
    
    for repo in $ECR_REPOS; do
        echo "  Checking repository: $repo"
        REPO_INFO=$(aws ecr describe-repository-scan-configuration --repository-name "$repo" --region $REGION 2>/dev/null)
        
        # Check if scan on push is enabled
        SCAN_ON_PUSH=$(echo "$REPO_INFO" | grep -o '"scanOnPush": [a-z]*' | head -1 | cut -d' ' -f2)
        SCAN_FREQUENCY=$(echo "$REPO_INFO" | grep -o '"scanFrequency": "[^"]*"' | head -1 | cut -d'"' -f4)
        
        if [ "$SCAN_ON_PUSH" == "true" ]; then
            ECR_DETAILS+="<li><span class=\"green\">Repository '$repo' has scan-on-push enabled</span></li>"
        elif [ "$SCAN_FREQUENCY" == "CONTINUOUS_SCAN" ] || [ "$SCAN_FREQUENCY" == "SCAN_ON_PUSH" ]; then
            ECR_DETAILS+="<li><span class=\"green\">Repository '$repo' has enhanced scanning enabled with frequency: $SCAN_FREQUENCY</span></li>"
        else
            ECR_ISSUES_FOUND=true
            ECR_DETAILS+="<li><span class=\"red\">Repository '$repo' does not have automatic scanning enabled</span></li>"
        fi
        
        # Check for image tag immutability
        IMMUTABILITY=$(aws ecr describe-repositories --repository-names "$repo" --region $REGION --query "repositories[0].imageTagMutability" --output text 2>/dev/null)
        if [ "$IMMUTABILITY" == "IMMUTABLE" ]; then
            ECR_DETAILS+="<li><span class=\"green\">Repository '$repo' has immutable image tags, which improves security and traceability</span></li>"
        else
            ECR_ISSUES_FOUND=true
            ECR_DETAILS+="<li><span class=\"yellow\">Repository '$repo' has mutable image tags, which can introduce security risks</span></li>"
        fi
    done
    
    ECR_DETAILS+="</ul>"
    
    if [ "$ECR_ISSUES_FOUND" = true ]; then
        add_check_item "$OUTPUT_FILE" "fail" "6.3.2 - Container image vulnerability scanning" \
            "$ECR_DETAILS" \
            "Enable scan-on-push or enhanced scanning for all ECR repositories to identify vulnerabilities in container images. Also consider enabling immutable image tags to improve security and traceability."
        ((failed_checks++))
    else
        add_check_item "$OUTPUT_FILE" "pass" "6.3.2 - Container image vulnerability scanning" \
            "$ECR_DETAILS"
        ((passed_checks++))
    fi
else
    add_check_item "$OUTPUT_FILE" "info" "6.3.2 - Container image vulnerability scanning" \
        "<p>No ECR repositories found for analysis.</p>"
    ((warning_checks++))
fi
((total_checks++))

# Check for CloudFormation templates with security resources
echo "Checking CloudFormation stacks for security resources..."
if [ -n "$CF_STACKS" ]; then
    CF_DETAILS="<p>Analyzing CloudFormation stacks for security-related resources:</p><ul>"
    CF_ISSUES_FOUND=false
    
    for stack in $CF_STACKS; do
        echo "  Checking stack: $stack"
        STACK_RESOURCES=$(aws cloudformation list-stack-resources --stack-name "$stack" --region $REGION 2>/dev/null)
        
        # Look for security-related resources
        SECURITY_RESOURCES=$(echo "$STACK_RESOURCES" | grep -o '"ResourceType": "AWS::[^"]*"' | grep -i 'security\|waf\|guard\|config\|iam' | wc -l)
        
        if [ $SECURITY_RESOURCES -gt 0 ]; then
            CF_DETAILS+="<li><span class=\"green\">Stack '$stack' includes security-related resources</span></li>"
        else
            CF_ISSUES_FOUND=true
            CF_DETAILS+="<li><span class=\"yellow\">Stack '$stack' does not appear to include explicit security resources</span></li>"
        fi
    done
    
    CF_DETAILS+="</ul>"
    
    if [ "$CF_ISSUES_FOUND" = true ]; then
        add_check_item "$OUTPUT_FILE" "warning" "6.3.2 - Infrastructure as Code security" \
            "$CF_DETAILS" \
            "Include security-related resources in your CloudFormation templates. Consider using AWS CloudFormation Guard or cfn-nag to validate templates for security best practices before deployment."
        ((warning_checks++))
    else
        add_check_item "$OUTPUT_FILE" "pass" "6.3.2 - Infrastructure as Code security" \
            "$CF_DETAILS"
        ((passed_checks++))
    fi
else
    add_check_item "$OUTPUT_FILE" "info" "6.3.2 - Infrastructure as Code security" \
        "<p>No CloudFormation stacks found for analysis.</p>"
    ((warning_checks++))
fi
((total_checks++))


close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 6: PCI REQUIREMENT 6.4 - PUBLIC-FACING WEB APPLICATIONS
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-6.4" "Requirement 6.4: Public-facing web applications are protected against attacks" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 6.4: PUBLIC-FACING WEB APPLICATIONS ===${NC}"


# 6.4.2 Web application firewall - Automated technical solution
echo "Checking for WAF web ACLs to satisfy Requirement 6.4.2..."
if [ -n "$WAF_ACLS" ]; then
    WAF_DETAILS="<p>AWS WAF Web ACLs found:</p><ul>"
    WAF_ISSUES_FOUND=false
    
    for acl in $WAF_ACLS; do
        echo "  Checking WAF ACL: $acl"
        ACL_INFO=$(aws wafv2 get-web-acl --name "$acl" --scope REGIONAL --region $REGION 2>/dev/null)
        
        # Extract rules information
        RULES_COUNT=$(echo "$ACL_INFO" | grep -o '"Rules": \[.*\]' | grep -o '"Name"' | wc -l)
        DEFAULT_ACTION=$(echo "$ACL_INFO" | grep -o '"DefaultAction": {[^}]*}' | grep -o '"Type": "[^"]*"' | cut -d'"' -f4)
        
        WAF_DETAILS+="<li>Web ACL: $acl"
        WAF_DETAILS+="<ul>"
        WAF_DETAILS+="<li>Default action: $DEFAULT_ACTION</li>"
        WAF_DETAILS+="<li>Rules configured: $RULES_COUNT</li>"
        
        if [ "$DEFAULT_ACTION" != "BLOCK" ]; then
            WAF_ISSUES_FOUND=true
            WAF_DETAILS+="<li><span class=\"yellow\">Default action is not set to BLOCK. Consider using a default deny policy with explicit allow rules.</span></li>"
        fi
        
        # Check if managed rule groups (AWS or third party) are used
        MANAGED_RULES=$(echo "$ACL_INFO" | grep -o '"ManagedRuleGroupStatement"' | wc -l)
        if [ $MANAGED_RULES -gt 0 ]; then
            WAF_DETAILS+="<li><span class=\"green\">Using managed rule groups</span></li>"
            
            # Check specifically for AWS managed rules
            AWS_CORE_RULES=$(echo "$ACL_INFO" | grep -o '"AWSManagedRulesCommonRuleSet"' | wc -l)
            if [ $AWS_CORE_RULES -gt 0 ]; then
                WAF_DETAILS+="<li><span class=\"green\">Using AWS Core Rule Set (CRS)</span></li>"
            else
                WAF_ISSUES_FOUND=true
                WAF_DETAILS+="<li><span class=\"yellow\">Not using AWS Core Rule Set (CRS) which provides basic protection against common threats</span></li>"
            fi
            
            # Check for SQL injection rules
            SQL_RULES=$(echo "$ACL_INFO" | grep -o '"AWSManagedRulesSQLiRuleSet"' | wc -l)
            if [ $SQL_RULES -gt 0 ]; then
                WAF_DETAILS+="<li><span class=\"green\">Using SQL injection protection rules</span></li>"
            else
                WAF_ISSUES_FOUND=true
                WAF_DETAILS+="<li><span class=\"yellow\">Not using SQL injection protection rules</span></li>"
            fi
            
            # Check for XSS rules
            XSS_RULES=$(echo "$ACL_INFO" | grep -o '"AWSManagedRulesKnownBadInputsRuleSet\|AWSManagedRulesCoreRuleSet"' | wc -l)
            if [ $XSS_RULES -gt 0 ]; then
                WAF_DETAILS+="<li><span class=\"green\">Using XSS/common attacks protection rules</span></li>"
            else
                WAF_ISSUES_FOUND=true
                WAF_DETAILS+="<li><span class=\"yellow\">Not using cross-site scripting (XSS) protection rules</span></li>"
            fi
        else
            WAF_ISSUES_FOUND=true
            WAF_DETAILS+="<li><span class=\"red\">No managed rule groups detected. Consider using AWS WAF managed rules for protection against common vulnerabilities</span></li>"
        fi
        
        # Check for logging configuration
        LOGGING_CONFIG=$(aws wafv2 get-logging-configuration --resource-arn $(echo "$ACL_INFO" | grep -o '"ARN": "[^"]*"' | head -1 | cut -d'"' -f4) --region $REGION 2>/dev/null)
        if [ $? -eq 0 ]; then
            WAF_DETAILS+="<li><span class=\"green\">Logging is enabled for this Web ACL</span></li>"
        else
            WAF_ISSUES_FOUND=true
            WAF_DETAILS+="<li><span class=\"yellow\">Logging is not enabled for this Web ACL</span></li>"
        fi
        
        WAF_DETAILS+="</ul></li>"
    done
    
    WAF_DETAILS+="</ul>"
    
    if [ "$WAF_ISSUES_FOUND" = true ]; then
        add_check_item "$OUTPUT_FILE" "warning" "6.4.2 - Web application firewall implementation" \
            "$WAF_DETAILS" \
            "Configure AWS WAF with managed rule groups that protect against common web application vulnerabilities (OWASP Top 10) including SQL injection, XSS, and CSRF. Enable logging to capture and analyze potential attacks."
        ((warning_checks++))
    else
        add_check_item "$OUTPUT_FILE" "pass" "6.4.2 - Web application firewall implementation" \
            "$WAF_DETAILS"
        ((passed_checks++))
    fi
else
    add_check_item "$OUTPUT_FILE" "fail" "6.4.2 - Web application firewall implementation" \
        "<p><span class=\"red\">No AWS WAF Web ACLs found. Public-facing web applications should be protected by a web application firewall.</span></p>" \
        "Implement AWS WAF with appropriate rule sets to protect public-facing web applications. At minimum, use the AWS managed rule groups to protect against common vulnerabilities like SQL injection, XSS, and other OWASP Top 10 vulnerabilities."
    ((failed_checks++))
fi
((total_checks++))


close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# SECTION 7: PCI REQUIREMENT 6.5 - CHANGE MANAGEMENT
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req-6.5" "Requirement 6.5: Changes to all system components are managed securely" "none"

echo -e "\n${CYAN}=== PCI REQUIREMENT 6.5: CHANGE MANAGEMENT ===${NC}"


# 6.5.3 Separation of environments
# Check for Lambda functions for environment separation indicators
echo "Checking Lambda functions for environment separation..."
if [ -n "$LAMBDA_FUNCTIONS" ]; then
    LAMBDA_DETAILS="<p>Analyzing Lambda functions for environment separation indicators:</p>"
    LAMBDA_ENV_COUNTS=$(for func in $LAMBDA_FUNCTIONS; do
        aws lambda get-function --function-name "$func" --region $REGION --query 'Configuration.FunctionName' 2>/dev/null | grep -o "$func" | sed 's/.*-\([a-zA-Z]*\)$/\1/g' | grep -E 'dev|test|stage|prod|uat' || echo "unknown"
    done | sort | uniq -c)
    
    if [ -n "$LAMBDA_ENV_COUNTS" ]; then
        LAMBDA_DETAILS+="<p>Functions grouped by environment naming convention:</p><ul>"
        while read -r count env; do
            if [ "$env" == "prod" ] || [ "$env" == "production" ]; then
                LAMBDA_DETAILS+="<li>Production environment: $count functions</li>"
            elif [ "$env" == "dev" ] || [ "$env" == "development" ]; then
                LAMBDA_DETAILS+="<li>Development environment: $count functions</li>"
            elif [ "$env" == "test" ] || [ "$env" == "testing" ]; then
                LAMBDA_DETAILS+="<li>Test environment: $count functions</li>"
            elif [ "$env" == "stage" ] || [ "$env" == "staging" ]; then
                LAMBDA_DETAILS+="<li>Staging environment: $count functions</li>"
            else
                LAMBDA_DETAILS+="<li>Unknown/other environment: $count functions</li>"
            fi
        done <<< "$LAMBDA_ENV_COUNTS"
        LAMBDA_DETAILS+="</ul>"
        
        add_check_item "$OUTPUT_FILE" "info" "6.5.3 - Environment separation indicators" \
            "$LAMBDA_DETAILS" \
            "Ensure clear separation between production and non-production environments. Use separate AWS accounts for production and non-production environments when possible. Consider AWS Organizations for multi-account management."
    else
        add_check_item "$OUTPUT_FILE" "warning" "6.5.3 - Environment separation indicators" \
            "<p>Unable to clearly identify environment separation from Lambda function naming conventions.</p>" \
            "Implement consistent naming conventions that identify the environment (dev, test, prod) for all resources. Consider using separate AWS accounts for different environments."
        ((warning_checks++))
    fi
else
    add_check_item "$OUTPUT_FILE" "info" "6.5.3 - Environment separation indicators" \
        "<p>No Lambda functions found for environment separation analysis.</p>"
    ((warning_checks++))
fi
((total_checks++))


close_section "$OUTPUT_FILE"

#----------------------------------------------------------------------
# FINALIZE THE REPORT
#----------------------------------------------------------------------
finalize_html_report "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks" "$REQUIREMENT_NUMBER"

echo -e "\n${CYAN}=== SUMMARY OF PCI DSS REQUIREMENT $REQUIREMENT_NUMBER CHECKS ===${NC}"

compliance_percentage=0
if [ $((total_checks - warning_checks)) -gt 0 ]; then
    compliance_percentage=$(( (passed_checks * 100) / (total_checks - warning_checks) ))
fi

echo -e "\nTotal checks performed: $total_checks"
echo -e "Passed checks: $passed_checks"
echo -e "Failed checks: $failed_checks"
echo -e "Warning/manual checks: $warning_checks"
echo -e "Compliance percentage (excluding warnings): $compliance_percentage%"

echo -e "\nPCI DSS Requirement $REQUIREMENT_NUMBER assessment completed at $(date)"
echo -e "HTML Report saved to: $OUTPUT_FILE"

# Open the HTML report in the default browser if on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$OUTPUT_FILE" 2>/dev/null || echo "Could not automatically open the report. Please open it manually."
else
    echo "Please open the HTML report in your web browser to view detailed results."
fi
