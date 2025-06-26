# GCP Permissions Required for PCI DSS 4.0.1 Compliance Assessment

## Overview

This document outlines the Google Cloud Platform (GCP) IAM permissions required to perform a comprehensive PCI DSS 4.0.1 compliance assessment on GCP infrastructure. The permissions follow the principle of least privilege while ensuring access to all necessary resources for a complete assessment at the organization level.

**Last Updated:** June 2025

## Important Notes for PCI DSS 4.0.1 on GCP

Google Cloud is certified as a PCI DSS Level 1 Service Provider. Google Cloud provides comprehensive compliance documentation and tools to help customers achieve PCI DSS compliance in cloud environments.

GCP Identity and Access Management (IAM) provides granular access controls necessary for PCI DSS assessments, with organization-level visibility for multi-project environments.

## Permission Structure

### Built-in Role vs Custom Role

**Recommended Approach: Built-in Role Combination** (Easier to manage)
- `roles/viewer` - Comprehensive read access to most resources
- `roles/iam.securityReviewer` - IAM and security-specific read access
- `roles/logging.viewer` - Audit log access
- `roles/monitoring.viewer` - Monitoring data access
- `roles/cloudasset.viewer` - Asset inventory across organization
- `roles/accesscontextmanager.policyReader` - VPC Service Controls access

**Alternative: Custom Role** (More complex to maintain)
- **`roles/pcidss_assessor`** - Custom role with exactly the permissions needed for PCI DSS assessment
- Follows stricter least privilege principle (PCI DSS Requirement 7.2.1)
- Requires custom role maintenance and updates
- More complex setup and debugging

## Permission Categories by PCI DSS Requirement

### Network Security Controls (Requirements 1.x)

**Required Permissions:**
```yaml
# VPC Networks and Firewalls
- compute.networks.get
- compute.networks.list
- compute.subnetworks.get
- compute.subnetworks.list
- compute.firewalls.get
- compute.firewalls.list
- compute.routes.get
- compute.routes.list

# Load Balancers and Security Policies
- compute.backendServices.get
- compute.backendServices.list
- compute.securityPolicies.get
- compute.securityPolicies.list
- compute.urlMaps.get
- compute.urlMaps.list

# VPC Service Controls
- accesscontextmanager.accessPolicies.get
- accesscontextmanager.accessPolicies.list
- accesscontextmanager.servicePerimeters.get
- accesscontextmanager.servicePerimeters.list
```

**Purpose:**
- Review VPC network configurations and segmentation
- Verify firewall rules and security groups
- Assess load balancer configurations
- Review Cloud Armor WAF policies
- Validate VPC Service Controls for data perimeters

### System Configuration Standards (Requirements 2.x)

**Required Permissions:**
```yaml
# Compute Instances
- compute.instances.get
- compute.instances.list
- compute.instances.getSerialPortOutput

# Container Services
- container.clusters.get
- container.clusters.list
- container.nodes.get
- container.nodes.list

# Serverless Platforms
- cloudfunctions.functions.get
- cloudfunctions.functions.list
- run.services.get
- run.services.list
- appengine.applications.get
- appengine.services.list
```

**Purpose:**
- Assess virtual machine configurations
- Review container orchestration security
- Verify serverless function configurations
- Check system hardening and patch management

### Data Protection Mechanisms (Requirements 3.x, 4.x)

**Required Permissions:**
```yaml
# Encryption and Key Management
- cloudkms.cryptoKeys.get
- cloudkms.cryptoKeys.list
- cloudkms.keyRings.get
- cloudkms.keyRings.list

# Storage Security
- storage.buckets.get
- storage.buckets.getIamPolicy
- storage.buckets.list

# Database Encryption
- cloudsql.instances.get
- cloudsql.instances.list
- spanner.databases.get
- spanner.databases.list
- bigquery.datasets.get
- bigquery.datasets.getIamPolicy

# TLS/SSL Certificates
- certificatemanager.certificates.get
- certificatemanager.certificates.list
```

**Purpose:**
- Verify encryption at rest configurations
- Review key management practices
- Assess database security configurations
- Check TLS/SSL certificate management
- Validate data classification and handling

### Malware Protection (Requirements 5.x)

**Required Permissions:**
```yaml
# Security Scanning and Detection
- securitycenter.findings.get
- securitycenter.findings.list
- websecurityscanner.scanconfigs.get
- websecurityscanner.scanruns.list

# Container Security
- binaryauthorization.policy.get
- artifactregistry.packages.get
- artifactregistry.repositories.list
```

**Purpose:**
- Review Security Command Center findings
- Assess vulnerability scanning configurations
- Verify container image security policies
- Check malware detection capabilities

### Secure Development (Requirements 6.x)

**Required Permissions:**
```yaml
# CI/CD Pipeline Security
- cloudbuild.builds.get
- cloudbuild.builds.list
- cloudbuild.triggers.get
- cloudbuild.triggers.list

# Container Registry Security
- artifactregistry.repositories.get
- artifactregistry.packages.list
- artifactregistry.versions.get

# Code and API Security
- servicemanagement.services.get
- servicemanagement.services.list
```

**Purpose:**
- Review CI/CD pipeline configurations
- Assess container registry security
- Verify secure development practices
- Check API security configurations

### Access Control (Requirements 7.x, 8.x)

**Required Permissions:**
```yaml
# Identity and Access Management
- iam.roles.get
- iam.roles.list
- iam.serviceAccounts.get
- iam.serviceAccounts.getIamPolicy
- iam.serviceAccounts.list

# Organization and Project Management
- resourcemanager.organizations.getIamPolicy
- resourcemanager.projects.getIamPolicy
- resourcemanager.folders.getIamPolicy

# Organization Policies
- orgpolicy.constraints.list
- orgpolicy.policies.list
```

**Purpose:**
- Review IAM policies and role assignments
- Assess service account configurations
- Verify organization-level access controls
- Check identity federation and SSO
- Validate organization policy constraints

### Physical Security (Requirements 9.x)

**Note:** Physical security for Google Cloud data centers is Google's responsibility under the shared responsibility model. Assessment focuses on:
- Google Cloud compliance certifications
- SOC 2 Type II reports
- Physical security attestations

### Logging and Monitoring (Requirements 10.x)

**Required Permissions:**
```yaml
# Cloud Logging
- logging.entries.list
- logging.sinks.get
- logging.sinks.list
- logging.buckets.get
- logging.buckets.list

# Cloud Monitoring
- monitoring.alertPolicies.get
- monitoring.alertPolicies.list
- monitoring.timeSeries.list
- monitoring.uptimeCheckConfigs.get

# Error Reporting and Tracing
- errorreporting.groups.list
- cloudtrace.traces.get
- cloudtrace.traces.list
```

**Purpose:**
- Verify audit logging configurations
- Review log retention and protection
- Assess monitoring and alerting
- Check security event detection
- Validate log integrity and tamper protection

### Security Testing (Requirements 11.x)

**Required Permissions:**
```yaml
# Security Command Center
- securitycenter.assets.get
- securitycenter.assets.list
- securitycenter.findings.get
- securitycenter.findings.list

# Vulnerability Assessment
- websecurityscanner.scanconfigs.get
- websecurityscanner.scanruns.list

# Recommendations
- recommender.iamPolicyRecommendations.get
- recommender.locations.list
```

**Purpose:**
- Review security findings and assessments
- Verify vulnerability scanning processes
- Check penetration testing documentation
- Assess security monitoring capabilities

### Information Security Management (Requirements 12.x)

**Required Permissions:**
```yaml
# Policy and Governance
- orgpolicy.constraints.list
- orgpolicy.policies.list

# Contact Management
- essentialcontacts.contacts.get
- essentialcontacts.contacts.list

# Asset Inventory
- cloudasset.assets.listResource
- cloudasset.assets.searchAllResources
```

**Purpose:**
- Review organizational policies
- Verify incident response contacts
- Assess asset management processes
- Check governance frameworks

## Setting Up the Assessment Service Account

### Step 1: No Custom Role Creation Required

**Using Built-in Roles (Recommended):**
- No custom role creation needed
- Google-managed roles stay automatically updated
- Easier to debug and troubleshoot permissions
- Well-documented role definitions

### Step 2: Create the Service Account

```bash
# Create service account in a dedicated project
gcloud iam service-accounts create pci-dss-assessor \
  --display-name="PCI DSS 4.0.1 Assessor" \
  --description="Service account for PCI DSS compliance assessment"
```

### Step 3: Grant Organization-Level Access

```bash
# Grant built-in roles at organization level
SA_EMAIL="pci-dss-assessor@PROJECT_ID.iam.gserviceaccount.com"

# Core assessment roles
gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/viewer"

gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/iam.securityReviewer"

gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/logging.viewer"

gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/monitoring.viewer"

gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/cloudasset.viewer"

gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/accesscontextmanager.policyReader"

# Optional: Grant Cloud Shell access
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/cloudshell.user"
```

### Step 4: Generate Service Account Keys

```bash
# Create and download service account key
gcloud iam service-accounts keys create pci-assessor-key.json \
  --iam-account=pci-dss-assessor@PROJECT_ID.iam.gserviceaccount.com
```

### Step 5: Enable Required APIs

```bash
# Enable necessary APIs for assessment
gcloud services enable \
  cloudresourcemanager.googleapis.com \
  compute.googleapis.com \
  container.googleapis.com \
  sql-component.googleapis.com \
  storage-component.googleapis.com \
  cloudkms.googleapis.com \
  logging.googleapis.com \
  monitoring.googleapis.com \
  securitycenter.googleapis.com \
  cloudasset.googleapis.com \
  cloudshell.googleapis.com
```

## Assessment Environment Setup

### Cloud Shell Access

**Benefits for PCI DSS Assessment:**
- Pre-authenticated environment
- All gcloud tools pre-installed
- Command history logged for audit
- No local credential storage
- Ephemeral environment (secure)

**Required Additional Permissions:**
```yaml
- cloudshell.environments.create
- cloudshell.environments.get
- cloudshell.environments.start
```

### Alternative: Local Environment

If using local tools instead of Cloud Shell:
```bash
# Authenticate with service account
gcloud auth activate-service-account \
  --key-file=pci-assessor-key.json

# Set default project
gcloud config set project PROJECT_ID
```

## Verification Script

Use the assessment verification script to test permissions:
```bash
./check_gcp_pci_permissions.sh
```

This script will:
- Test access to all required GCP services
- Verify organization-level permissions
- Report any missing permissions
- Generate a permission audit report

## Security Considerations

1. **Least Privilege**: Custom role provides only necessary read permissions
2. **Temporary Access**: Create service account only for assessment duration
3. **Audit Trail**: All API calls logged in Cloud Audit Logs
4. **Key Management**: Securely store and rotate service account keys
5. **Multi-Project Access**: Organization-level binding for comprehensive assessment
6. **Network Security**: Consider VPC Service Controls for additional protection

## Compliance Notes

- Permissions align with PCI DSS 4.0.1 Requirement 7.2.1 (least privilege)
- Assessment process is non-intrusive (read-only operations)
- External vulnerability scanning requires separate ASV-approved tools
- Physical security assessment relies on Google Cloud attestations

## GCP Services in Scope for PCI DSS 4.0.1

As of June 2025, the following GCP services are included in PCI DSS v4.0 scope:

**Compute Services:**
- Compute Engine
- Google Kubernetes Engine (GKE)
- Cloud Functions
- Cloud Run
- App Engine

**Storage Services:**
- Cloud Storage
- Cloud SQL
- Cloud Spanner
- Cloud Bigtable
- BigQuery
- Cloud Firestore

**Networking Services:**
- Virtual Private Cloud (VPC)
- Cloud Load Balancing
- Cloud CDN
- Cloud Armor
- Cloud DNS

**Security Services:**
- Cloud KMS
- Secret Manager
- Security Command Center
- Binary Authorization
- VPC Service Controls

**Operations Services:**
- Cloud Logging
- Cloud Monitoring
- Error Reporting
- Cloud Trace

**Developer Tools:**
- Cloud Build
- Artifact Registry
- Cloud Source Repositories

## Shared Responsibility Model

### Google's Responsibilities:
- Physical data center security
- Infrastructure security
- Platform security controls
- Compliance certifications

### Customer Responsibilities:
- Configuration security
- Access management
- Data encryption
- Application security
- Compliance monitoring

## Additional Resources

- [Google Cloud PCI DSS Compliance Guide](https://cloud.google.com/security/compliance/pci-dss)
- [Google Cloud Security Command Center](https://cloud.google.com/security-command-center)
- [GCP IAM Best Practices](https://cloud.google.com/iam/docs/using-iam-securely)
- [Cloud Asset Inventory](https://cloud.google.com/asset-inventory)
- [VPC Service Controls](https://cloud.google.com/vpc-service-controls)
- [Google Cloud Compliance Resource Center](https://cloud.google.com/security/compliance)
- [PCI DSS on Google Cloud Architecture Guide](https://cloud.google.com/architecture/pci-dss-compliance-in-gcp)