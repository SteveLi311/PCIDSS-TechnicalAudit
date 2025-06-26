# GCP PCI DSS 4.0.1 Compliance Assessment Scripts

This repository contains automated scripts for assessing Google Cloud Platform (GCP) infrastructure against PCI DSS 4.0.1 requirements. The scripts provide comprehensive analysis of network security controls, access management, data protection, and other critical compliance areas.

## 🚀 Quick Start

### Prerequisites

1. **Google Cloud SDK (gcloud)** - [Install Guide](https://cloud.google.com/sdk/docs/install)
2. **GCP Project or Organization Access** - With appropriate permissions
3. **Service Account** - For assessor access (recommended)

### 1. Authentication Setup

#### Option A: Cloud Shell (Recommended)
```bash
# Open Google Cloud Console and activate Cloud Shell
# Upload your service account key file
gcloud auth activate-service-account pci-dss-assessor@PROJECT_ID.iam.gserviceaccount.com --key-file=pci-assessor-key.json
gcloud config set project PROJECT_ID
```

#### Option B: Local Environment
```bash
# Install gcloud CLI first: https://cloud.google.com/sdk/docs/install
gcloud auth activate-service-account pci-dss-assessor@PROJECT_ID.iam.gserviceaccount.com --key-file=pci-assessor-key.json
gcloud config set project PROJECT_ID
```

#### Option C: User Account (For Testing)
```bash
gcloud auth login
gcloud config set project PROJECT_ID
```

### 2. Setup Service Account Permissions

#### Automated Setup (Recommended)
```bash
# Run the permission setup script
./setup_pci_assessor_permissions.sh

# Follow prompts to configure:
# - Organization ID (for org-wide assessment)
# - Project ID (for project-specific assessment)
# - Service account creation and permissions
```

#### Manual Setup (Built-in Roles - Recommended)
```bash
# Create service account
gcloud iam service-accounts create pci-dss-assessor \
  --display-name="PCI DSS 4.0.1 Assessor"

# Grant built-in roles at organization level
SA_EMAIL="pci-dss-assessor@PROJECT_ID.iam.gserviceaccount.com"

gcloud organizations add-iam-policy-binding ORG_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/viewer"

gcloud organizations add-iam-policy-binding ORG_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/iam.securityReviewer"

gcloud organizations add-iam-policy-binding ORG_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/logging.viewer"

gcloud organizations add-iam-policy-binding ORG_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/monitoring.viewer"

gcloud organizations add-iam-policy-binding ORG_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/cloudasset.viewer"

gcloud organizations add-iam-policy-binding ORG_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/accesscontextmanager.policyReader"
```

### 3. Run Assessment Scripts

#### Project-Specific Assessment
```bash
# Assess current project
./check_gcp_pci_requirement1.sh

# Assess specific project
./check_gcp_pci_requirement1.sh --project my-pci-project
```

#### Organization-Wide Assessment
```bash
# Assess entire organization
./check_gcp_pci_requirement1.sh --scope organization --org 123456789
```

## 📋 Available Scripts

| Script | PCI DSS Requirement | Description | Status | Template Version |
|--------|-------------------|-------------|--------|------------------|
| `check_gcp_pci_requirement1.sh` | **Requirement 1** | Install and Maintain Network Security Controls | ✅ Complete | Advanced Template |
| `check_gcp_pci_requirement2.sh` | **Requirement 2** | Apply Secure Configurations to All System Components | ✅ Complete | Advanced Template |
| `check_gcp_pci_requirement3.sh` | **Requirement 3** | Protect Stored Cardholder Data | ✅ Complete | Advanced Template |
| `check_gcp_pci_requirement4.sh` | **Requirement 4** | Protect Cardholder Data with Strong Cryptography | ✅ Complete | Advanced Template |
| `check_gcp_pci_requirement5.sh` | **Requirement 5** | Protect All Systems Against Malware | ✅ Complete | Advanced Template |
| `check_gcp_pci_requirement6.sh` | **Requirement 6** | Develop and Maintain Secure Systems and Software | ✅ Complete | Advanced Template |
| `check_gcp_pci_requirement7.sh` | **Requirement 7** | Restrict Access by Business Need to Know | ✅ Complete | Advanced Template |
| `check_gcp_pci_requirement8.sh` | **Requirement 8** | Identify Users and Authenticate Access | ✅ Complete | Advanced Template |
| `check_gcp_pci_requirement9.sh` | **Requirement 9** | Restrict Physical Access to Cardholder Data | 🚧 Planned | - |
| `check_gcp_pci_requirement10.sh` | **Requirement 10** | Log and Monitor All Access to System Components | 🚧 Planned | - |
| `check_gcp_pci_requirement11.sh` | **Requirement 11** | Test Security of Systems and Networks Regularly | 🚧 Planned | - |
| `check_gcp_pci_requirement12.sh` | **Requirement 12** | Support Information Security with Organizational Policies | 🚧 Planned | - |

## 🔧 Script Options

### Standardized Usage (Requirements 1-8)

All scripts support comprehensive command-line options:

```bash
Usage: ./check_gcp_pci_requirementX.sh [OPTIONS]

Options:
  -s, --scope SCOPE          Assessment scope: 'project' or 'organization' (default: project)
  -p, --project PROJECT_ID   Specific project to assess (overrides current gcloud config)
  -o, --org ORG_ID          Specific organization ID to assess (required for organization scope)
  -h, --help                Show help message

Examples:
  ./script.sh                                    # Assess current project
  ./script.sh --scope project --project my-proj # Assess specific project
  ./script.sh --scope organization --org 123456 # Assess entire organization
```

### Template Standardization Status

✅ **Complete**: All Requirements 1-8 now use the standardized advanced template providing:
- Organization-wide assessment capabilities
- Consistent command-line interface
- Standardized error handling and reporting
- Unified HTML report generation
- Sophisticated permission checking with percentage calculation

#### Standardized Template Features (Requirements 1-8)

**All scripts now include:**
- ✅ Full command-line argument parsing (`--scope`, `--project`, `--org`, `--help`)
- ✅ Organization and project scope support
- ✅ Sophisticated permission checking with percentage calculation
- ✅ Multi-project assessment capabilities
- ✅ Inline HTML report generation
- ✅ Standardized error handling and user interaction
- ✅ Consistent report naming and structure
- ✅ Scope-aware command execution
- ✅ Permission validation before assessment
- ✅ Unified summary reporting

#### Template Standardization Complete

All GCP PCI DSS assessment scripts (Requirements 1-8) have been updated to use the advanced template, providing:
1. **Consistent User Experience**: All scripts use identical command-line interfaces
2. **Flexible Scope**: Support for both project and organization-wide assessments
3. **Robust Permission Handling**: Comprehensive permission checking before assessment
4. **Standardized Reporting**: Consistent HTML report generation and naming
5. **Better Error Handling**: Graceful handling of permission issues and API errors

## 🏗️ Assessment Scopes

### Project Scope (Default)
- Assesses resources within a single GCP project
- Faster execution and simpler permissions
- Suitable for focused assessments

**Use Cases:**
- Single-project environments
- Specific application assessments
- Development/testing environments

### Organization Scope
- Assesses resources across all projects in a GCP organization
- Comprehensive view of entire GCP footprint
- Requires organization-level permissions

**Use Cases:**
- Enterprise-wide compliance assessments
- Multi-project environments
- Complete PCI DSS scope verification

## 📊 Report Generation

### HTML Reports
Scripts generate detailed HTML reports with:
- ✅ **Pass/Fail/Warning status** for each check
- 📈 **Compliance percentage** and summary metrics
- 🔍 **Detailed findings** with remediation guidance
- 🏢 **Scope information** (project/organization)

### Report Locations
```
./reports/
├── gcp_project_pci_req1_report_20250603_143022.html  # Project scope
├── gcp_org_pci_req1_report_20250603_143022.html      # Organization scope
└── ...
```

### Report Interpretation
- 🟢 **Green (Pass)**: Compliant with PCI DSS requirements
- 🟡 **Yellow (Warning)**: Potential compliance issues requiring review
- 🔴 **Red (Fail)**: Non-compliant, immediate action required
- 🔵 **Blue (Info)**: Informational findings for awareness

## 🔐 Required Permissions

### Built-in Roles (Recommended)
The service account needs these built-in roles for comprehensive assessment:

**Core Assessment Roles:**
- `roles/viewer` - Comprehensive read access to most resources
- `roles/iam.securityReviewer` - IAM and security-specific access
- `roles/logging.viewer` - Audit log access
- `roles/monitoring.viewer` - Monitoring data access
- `roles/cloudasset.viewer` - Asset inventory across organization
- `roles/accesscontextmanager.policyReader` - VPC Service Controls access

**Benefits:**
- ✅ No custom role maintenance required
- ✅ Always up-to-date with GCP service changes
- ✅ Easier to debug and troubleshoot
- ✅ Well-documented permissions

### Detailed Permission Matrix
See `GCP_PCI_DSS_Permission_Requirements.md` for comprehensive permission mapping by PCI DSS requirement.

## 🛠️ Troubleshooting

### Common Issues

#### Authentication Errors
```bash
# Error: Application Default Credentials not found
gcloud auth application-default login

# Error: Permission denied
# Check service account permissions or run permission setup script
./setup_pci_assessor_permissions.sh
```

#### Project/Organization Not Found
```bash
# List available projects
gcloud projects list

# List organizations (requires org access)
gcloud organizations list

# Set correct project
gcloud config set project CORRECT_PROJECT_ID
```

#### Permission Errors
```bash
# Test basic permissions
gcloud compute networks list --limit=1
gcloud iam service-accounts list --limit=1

# Check current authentication
gcloud auth list
```

#### Service Account Key Issues
```bash
# Verify key file path and format
cat pci-assessor-key.json | head -5

# Re-authenticate with correct key
gcloud auth activate-service-account --key-file=CORRECT_PATH/pci-assessor-key.json
```

### Getting Help

1. **Run with help flag**: `./script.sh --help`
2. **Check permissions**: Run `./setup_pci_assessor_permissions.sh` 
3. **Verify authentication**: `gcloud auth list`
4. **Test basic access**: `gcloud projects list`

## 📁 File Structure

```
GCP/
├── README.md                              # This file
├── gcp_pci_dss_assessor_role.yaml         # Custom IAM role definition (optional)
├── GCP_PCI_DSS_Permission_Requirements.md # Detailed permission documentation
├── setup_pci_assessor_permissions.sh      # Automated permission setup (uses built-in roles)
├── gcp_pci_dss_script_template.sh         # Template for new scripts
├── check_gcp_pci_requirement1.sh          # Requirement 1 assessment
├── check_gcp_pci_requirement2.sh          # Requirement 2 assessment
├── check_gcp_pci_requirement3.sh          # Requirement 3 assessment
├── check_gcp_pci_requirement4.sh          # Requirement 4 assessment
├── check_gcp_pci_requirement5.sh          # Requirement 5 assessment
├── check_gcp_pci_requirement6.sh          # Requirement 6 assessment
├── check_gcp_pci_requirement7.sh          # Requirement 7 assessment
├── check_gcp_pci_requirement8.sh          # Requirement 8 assessment
├── reports/                               # Generated assessment reports
│   ├── gcp_project_pci_req*_report_*.html # Project-scope reports
│   └── gcp_org_pci_req*_report_*.html     # Organization-scope reports
└── ...
```

## 🔄 Workflow Examples

### Daily Operations Team Assessment
```bash
# Quick project assessment
./check_gcp_pci_requirement1.sh

# View report in browser
open ./reports/gcp_project_pci_req*_report_$(date +%Y%m%d)*.html
```

### Quarterly Compliance Review
```bash
# Full organization assessment
./check_gcp_pci_requirement1.sh --scope organization --org 123456789
./check_gcp_pci_requirement2.sh --scope organization --org 123456789
./check_gcp_pci_requirement3.sh --scope organization --org 123456789
./check_gcp_pci_requirement4.sh --scope organization --org 123456789
./check_gcp_pci_requirement5.sh --scope organization --org 123456789
./check_gcp_pci_requirement6.sh --scope organization --org 123456789
./check_gcp_pci_requirement7.sh --scope organization --org 123456789
./check_gcp_pci_requirement8.sh --scope organization --org 123456789

# Consolidate findings for management review
```

### Complete PCI DSS Assessment
```bash
# Run all available requirement scripts
for req in {1..8}; do
    if [ -f "./check_gcp_pci_requirement${req}.sh" ]; then
        echo "Running Requirement ${req} assessment..."
        ./check_gcp_pci_requirement${req}.sh
    fi
done

# Package all reports
tar -czf pci_assessment_reports_$(date +%Y%m%d).tar.gz ./reports/
```

### External Auditor Assessment
```bash
# Authenticate with provided service account
gcloud auth activate-service-account auditor@client-project.iam.gserviceaccount.com --key-file=auditor-key.json

# Set target project/organization
gcloud config set project client-pci-project

# Run comprehensive assessment
./check_gcp_pci_requirement1.sh --scope organization --org 987654321

# Package reports for delivery
tar -czf pci_assessment_reports_$(date +%Y%m%d).tar.gz ./reports/
```

## 🚨 Security Considerations

### Service Account Security
- ✅ Use least privilege permissions
- ✅ Rotate service account keys regularly
- ✅ Store keys securely (not in version control)
- ✅ Delete keys after assessment completion

### Assessment Data
- ✅ Reports may contain sensitive configuration data
- ✅ Encrypt and secure report storage
- ✅ Delete reports after retention period
- ✅ Limit access to authorized personnel only

### Cloud Shell Advantages
- ✅ No local credential storage
- ✅ Ephemeral environment (auto-cleanup)
- ✅ Google-managed security
- ✅ Automatic audit logging

## 📞 Support

### Documentation
- **PCI DSS Requirements**: `../PCI_DSS_v4.0.1_Requirements.md`
- **Permission Details**: `GCP_PCI_DSS_Permission_Requirements.md`
- **Setup Guide**: Run `./setup_pci_assessor_permissions.sh --help`

### Common Resources
- [Google Cloud PCI DSS Compliance Guide](https://cloud.google.com/security/compliance/pci-dss)
- [GCP IAM Best Practices](https://cloud.google.com/iam/docs/using-iam-securely)
- [Cloud Asset Inventory](https://cloud.google.com/asset-inventory)
- [Security Command Center](https://cloud.google.com/security-command-center)

---

**Note**: These scripts are designed for compliance assessment and auditing purposes. They perform read-only operations and do not modify your GCP resources. All activities are logged in Cloud Audit Logs for transparency.