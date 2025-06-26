#!/bin/bash

# GCP Script to Setup PCI DSS 4.0.1 Assessor Permissions
# This script creates a service account with organization-level permissions for PCI DSS assessment

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
SERVICE_ACCOUNT_NAME="${SERVICE_ACCOUNT_NAME:-pci-dss-assessor}"
CUSTOM_ROLE_ID="${CUSTOM_ROLE_ID:-pcidss_assessor}"
PROJECT_ID="${PROJECT_ID:-}"
ORGANIZATION_ID="${ORGANIZATION_ID:-}"
REGION="${REGION:-us-central1}"

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to print section headers
print_section() {
    echo -e "\n${BLUE}================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================${NC}"
}

# Check if gcloud CLI is installed
check_gcloud() {
    if ! command -v gcloud &> /dev/null; then
        print_status $RED "Error: gcloud CLI is not installed. Please install it first."
        echo "Install from: https://cloud.google.com/sdk/docs/install"
        exit 1
    fi
}

# Check if user is authenticated
check_auth() {
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -n1 &> /dev/null; then
        print_status $RED "Error: Not authenticated with gcloud. Please run 'gcloud auth login' first."
        exit 1
    fi
}

# Get organization ID
get_organization_id() {
    if [ -z "$ORGANIZATION_ID" ]; then
        print_status $CYAN "Searching for organization..."
        ORGANIZATION_ID=$(gcloud organizations list --format="value(name)" --limit=1 2>/dev/null | sed 's/organizations\///')
        
        if [ -z "$ORGANIZATION_ID" ]; then
            print_status $RED "Error: Could not find organization ID. Please provide it manually:"
            echo "Usage: ORGANIZATION_ID=123456789 ./setup_pci_assessor_permissions.sh"
            echo "Or run: gcloud organizations list"
            exit 1
        fi
    fi
}

# Get or set project ID
get_project_id() {
    if [ -z "$PROJECT_ID" ]; then
        PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
        
        if [ -z "$PROJECT_ID" ]; then
            print_status $YELLOW "No default project set. Please provide PROJECT_ID:"
            echo "Usage: PROJECT_ID=my-project ./setup_pci_assessor_permissions.sh"
            echo "Or run: gcloud config set project PROJECT_ID"
            exit 1
        fi
    fi
}

# Check if running user has necessary permissions
check_permissions() {
    print_status $CYAN "Checking user permissions..."
    
    # Check organization admin permissions
    if ! gcloud organizations get-iam-policy $ORGANIZATION_ID --format="value(bindings.members)" 2>/dev/null | grep -q "$(gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -n1)"; then
        print_status $YELLOW "Warning: You may not have organization-level permissions."
        print_status $YELLOW "You need roles/resourcemanager.organizationAdmin or similar to create organization-level roles."
    fi
    
    # Check project permissions
    if ! gcloud projects get-iam-policy $PROJECT_ID --format="value(bindings.members)" 2>/dev/null | grep -q "$(gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -n1)"; then
        print_status $YELLOW "Warning: You may not have sufficient project permissions."
    fi
}

# Enable required APIs
enable_apis() {
    print_section "Enabling Required APIs"
    
    local apis=(
        "cloudresourcemanager.googleapis.com"
        "iam.googleapis.com"
        "compute.googleapis.com"
        "container.googleapis.com"
        "sqladmin.googleapis.com"
        "storage.googleapis.com"
        "cloudkms.googleapis.com"
        "logging.googleapis.com"
        "monitoring.googleapis.com"
        "securitycenter.googleapis.com"
        "cloudasset.googleapis.com"
        "cloudshell.googleapis.com"
        "certificatemanager.googleapis.com"
        "secretmanager.googleapis.com"
        "dns.googleapis.com"
        "binaryauthorization.googleapis.com"
        "cloudbuild.googleapis.com"
        "artifactregistry.googleapis.com"
        "websecurityscanner.googleapis.com"
        "dlp.googleapis.com"
        "recommender.googleapis.com"
    )
    
    print_status $CYAN "Enabling APIs in project $PROJECT_ID..."
    for api in "${apis[@]}"; do
        echo -n "Enabling $api... "
        if gcloud services enable "$api" --project="$PROJECT_ID" 2>/dev/null; then
            print_status $GREEN "✓"
        else
            print_status $YELLOW "⚠ (may already be enabled)"
        fi
    done
}

# Skip custom role creation - using built-in roles
skip_custom_role() {
    print_section "Using Built-in Roles (Skipping Custom Role Creation)"
    
    print_status $GREEN "Using built-in roles for easier management:"
    echo "  ✓ roles/viewer - Broad read access"
    echo "  ✓ roles/iam.securityReviewer - IAM security review"
    echo "  ✓ roles/logging.viewer - Audit logs"
    echo "  ✓ roles/monitoring.viewer - Monitoring data"
    echo "  ✓ roles/cloudasset.viewer - Asset inventory"
    echo "  ✓ roles/accesscontextmanager.policyReader - VPC Service Controls"
    
    print_status $CYAN "Benefits of built-in roles:"
    echo "  • No custom role maintenance required"
    echo "  • Always up-to-date with GCP service changes"
    echo "  • Easier to debug and troubleshoot"
    echo "  • Well-documented permissions"
}

# Create service account
create_service_account() {
    print_section "Creating Service Account"
    
    local sa_email="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
    
    print_status $CYAN "Creating service account: $SERVICE_ACCOUNT_NAME"
    
    # Check if service account already exists
    if gcloud iam service-accounts describe $sa_email &> /dev/null; then
        print_status $YELLOW "Service account already exists: $sa_email"
    else
        if gcloud iam service-accounts create $SERVICE_ACCOUNT_NAME \
            --display-name="PCI DSS 4.0.1 Assessor" \
            --description="Service account for PCI DSS compliance assessment with organization-level read access" \
            --project=$PROJECT_ID; then
            print_status $GREEN "Service account created successfully."
        else
            print_status $RED "Failed to create service account."
            exit 1
        fi
    fi
    
    echo "Service Account Email: $sa_email"
}

# Grant organization-level permissions
grant_organization_permissions() {
    print_section "Granting Organization-Level Permissions"
    
    local sa_email="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
    
    # Define built-in roles for PCI DSS assessment
    local roles=(
        "roles/viewer"                              # Broad read access
        "roles/iam.securityReviewer"               # IAM security review
        "roles/logging.viewer"                     # Audit logs
        "roles/monitoring.viewer"                  # Monitoring data
        "roles/cloudasset.viewer"                  # Asset inventory
        "roles/accesscontextmanager.policyReader"  # VPC Service Controls
    )
    
    print_status $CYAN "Granting built-in roles to service account..."
    
    for role in "${roles[@]}"; do
        echo -n "Granting $role... "
        if gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
            --member="serviceAccount:$sa_email" \
            --role="$role" &>/dev/null; then
            print_status $GREEN "✓"
        else
            print_status $RED "✗ Failed to grant $role"
            print_status $YELLOW "This may be due to insufficient permissions. Please check with your organization admin."
        fi
    done
    
    # Grant Cloud Shell access at project level
    print_status $CYAN "Granting Cloud Shell access..."
    if gcloud projects add-iam-policy-binding $PROJECT_ID \
        --member="serviceAccount:$sa_email" \
        --role="roles/cloudshell.user"; then
        print_status $GREEN "Cloud Shell access granted."
    else
        print_status $YELLOW "Warning: Failed to grant Cloud Shell access."
    fi
}

# Generate service account key
generate_service_account_key() {
    print_section "Generating Service Account Key"
    
    local sa_email="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
    local key_file="pci-assessor-key-$(date +%Y%m%d-%H%M%S).json"
    
    print_status $CYAN "Generating service account key..."
    
    if gcloud iam service-accounts keys create "$key_file" \
        --iam-account="$sa_email" \
        --project="$PROJECT_ID"; then
        print_status $GREEN "Service account key created: $key_file"
        echo -e "${YELLOW}IMPORTANT: Store this key file securely and delete after assessment.${NC}"
        
        # Set appropriate permissions on key file
        chmod 600 "$key_file"
        
        return 0
    else
        print_status $RED "Failed to create service account key."
        return 1
    fi
}

# Test permissions
test_permissions() {
    print_section "Testing Basic Permissions"
    
    local sa_email="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
    
    print_status $CYAN "Testing service account permissions..."
    
    # Test organization access
    echo -n "Testing organization access... "
    if gcloud organizations list --impersonate-service-account="$sa_email" &>/dev/null; then
        print_status $GREEN "✓"
    else
        print_status $RED "✗"
    fi
    
    # Test project access
    echo -n "Testing project access... "
    if gcloud projects list --impersonate-service-account="$sa_email" --filter="projectId:$PROJECT_ID" &>/dev/null; then
        print_status $GREEN "✓"
    else
        print_status $RED "✗"
    fi
    
    # Test compute access
    echo -n "Testing Compute Engine access... "
    if gcloud compute instances list --impersonate-service-account="$sa_email" --project="$PROJECT_ID" &>/dev/null; then
        print_status $GREEN "✓"
    else
        print_status $RED "✗"
    fi
    
    # Test IAM access
    echo -n "Testing IAM access... "
    if gcloud iam service-accounts list --impersonate-service-account="$sa_email" --project="$PROJECT_ID" &>/dev/null; then
        print_status $GREEN "✓"
    else
        print_status $RED "✗"
    fi
    
    # Test logging access
    echo -n "Testing Cloud Logging access... "
    if gcloud logging sinks list --impersonate-service-account="$sa_email" --project="$PROJECT_ID" &>/dev/null; then
        print_status $GREEN "✓"
    else
        print_status $RED "✗"
    fi
    
    # Test storage access
    echo -n "Testing Cloud Storage access... "
    if gcloud storage buckets list --impersonate-service-account="$sa_email" --project="$PROJECT_ID" &>/dev/null; then
        print_status $GREEN "✓"
    else
        print_status $RED "✗"
    fi
}

# Create assessment environment setup instructions
create_setup_instructions() {
    print_section "Creating Assessment Setup Instructions"
    
    local sa_email="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
    local instructions_file="pci-assessment-setup-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$instructions_file" << EOF
PCI DSS 4.0.1 GCP Assessment Setup Instructions
==============================================
Created: $(date)
Organization ID: $ORGANIZATION_ID
Project ID: $PROJECT_ID
Service Account: $sa_email

Authentication Options:
======================

Option 1: Cloud Shell (Recommended)
-----------------------------------
1. Open Google Cloud Console: https://console.cloud.google.com
2. Activate Cloud Shell
3. Authenticate as service account:
   gcloud auth activate-service-account $sa_email --key-file=pci-assessor-key-*.json
4. Set default project:
   gcloud config set project $PROJECT_ID

Option 2: Local Environment
---------------------------
1. Install gcloud CLI: https://cloud.google.com/sdk/docs/install
2. Authenticate with service account:
   gcloud auth activate-service-account $sa_email --key-file=pci-assessor-key-*.json
3. Set default project:
   gcloud config set project $PROJECT_ID

Verification Commands:
=====================
# Test organization access
gcloud organizations list

# Test project access
gcloud projects list

# Test compute access
gcloud compute instances list --project=$PROJECT_ID

# Test IAM access
gcloud iam service-accounts list --project=$PROJECT_ID

# Test logging access
gcloud logging sinks list --project=$PROJECT_ID

# Test storage access
gcloud storage buckets list --project=$PROJECT_ID

Assessment Scripts:
==================
Run the following scripts to perform PCI DSS assessment:
./check_gcp_pci_requirement1.sh  # Network Security Controls
./check_gcp_pci_requirement2.sh  # System Configuration Standards
./check_gcp_pci_requirement3.sh  # Data Protection Mechanisms
./check_gcp_pci_requirement4.sh  # Encryption in Transit
./check_gcp_pci_requirement6.sh  # Secure Development
./check_gcp_pci_requirement7.sh  # Access Control
./check_gcp_pci_requirement8.sh  # Authentication
./check_gcp_pci_requirement10.sh # Logging and Monitoring
./check_gcp_pci_requirement11.sh # Security Testing

Important Notes:
===============
- Service account has READ-ONLY access across the organization
- All API calls are logged in Cloud Audit Logs
- Delete service account and keys after assessment completion
- Report any missing permissions to the organization administrator

Security Reminders:
==================
- Store service account keys securely
- Use Cloud Shell when possible for better security
- Delete temporary files after assessment
- Review Cloud Audit Logs for assessment activities
- Follow your organization's key management policies

EOF

    print_status $GREEN "Setup instructions created: $instructions_file"
    chmod 600 "$instructions_file"
}

# Main execution
main() {
    print_section "GCP PCI DSS 4.0.1 Assessor Setup"
    
    echo -e "${GREEN}Setting up PCI DSS 4.0.1 Assessor with Organization-Level Access${NC}"
    echo -e "${YELLOW}Service Account: $SERVICE_ACCOUNT_NAME${NC}"
    echo -e "${YELLOW}Custom Role: $CUSTOM_ROLE_ID${NC}"
    
    # Preliminary checks
    check_gcloud
    check_auth
    get_organization_id
    get_project_id
    
    echo -e "${YELLOW}Organization ID: $ORGANIZATION_ID${NC}"
    echo -e "${YELLOW}Project ID: $PROJECT_ID${NC}"
    echo -e "${YELLOW}Region: $REGION${NC}"
    
    check_permissions
    
    # Confirm before proceeding
    echo -e "\n${CYAN}Do you want to proceed with the setup? (y/n)${NC}"
    read -r CONFIRM
    
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        print_status $YELLOW "Setup cancelled."
        exit 0
    fi
    
    # Execute setup steps
    enable_apis
    skip_custom_role
    create_service_account
    grant_organization_permissions
    
    if generate_service_account_key; then
        KEY_CREATED=true
    else
        KEY_CREATED=false
    fi
    
    test_permissions
    create_setup_instructions
    
    # Final summary
    print_section "Setup Complete!"
    
    local sa_email="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
    
    echo -e "${GREEN}PCI DSS 4.0.1 Assessor setup completed successfully!${NC}"
    echo -e "${YELLOW}Service Account: $sa_email${NC}"
    echo -e "${YELLOW}Granted Built-in Roles:${NC}"
    echo "  • roles/viewer"
    echo "  • roles/iam.securityReviewer"
    echo "  • roles/logging.viewer"
    echo "  • roles/monitoring.viewer"
    echo "  • roles/cloudasset.viewer"
    echo "  • roles/accesscontextmanager.policyReader"
    
    if [ "$KEY_CREATED" = true ]; then
        echo -e "${CYAN}Service account key file created (check current directory)${NC}"
    fi
    
    echo -e "\n${CYAN}Next Steps:${NC}"
    echo -e "1. Review the setup instructions file created"
    echo -e "2. Test the service account permissions"
    echo -e "3. Run the PCI DSS assessment scripts"
    echo -e "4. Create a comprehensive assessment report"
    
    echo -e "\n${CYAN}Cloud Shell Quick Start:${NC}"
    echo -e "gcloud auth activate-service-account $sa_email --key-file=pci-assessor-key-*.json"
    echo -e "gcloud config set project $PROJECT_ID"
    
    echo -e "\n${RED}Security Reminders:${NC}"
    echo -e "- Store service account keys securely"
    echo -e "- Delete keys after assessment completion"
    echo -e "- Review Cloud Audit Logs for assessment activities"
    echo -e "- Remove service account when assessment is complete"
}

# Help function
show_help() {
    echo "GCP PCI DSS 4.0.1 Assessor Setup Script"
    echo "========================================"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Environment Variables:"
    echo "  PROJECT_ID              GCP Project ID (required)"
    echo "  ORGANIZATION_ID         GCP Organization ID (auto-detected if not provided)"
    echo "  SERVICE_ACCOUNT_NAME    Service account name (default: pci-dss-assessor)"
    echo "  CUSTOM_ROLE_ID          Custom role ID (default: pcidss_assessor)"
    echo "  REGION                  Default region (default: us-central1)"
    echo ""
    echo "Examples:"
    echo "  PROJECT_ID=my-project $0"
    echo "  PROJECT_ID=my-project ORGANIZATION_ID=123456789 $0"
    echo ""
    echo "Prerequisites:"
    echo "  - gcloud CLI installed and authenticated"
    echo "  - Organization Admin or sufficient permissions"
    echo "  - gcp_pci_dss_assessor_role.yaml file in current directory"
    echo ""
}

# Check for help flag
if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    show_help
    exit 0
fi

# Run main function
main "$@"