# GCP Permissions Library Documentation

## Overview

The `gcp_permissions.sh` library provides comprehensive authentication and permission management for GCP PCI DSS assessment scripts. It handles permission validation, coverage reporting, and standardized user interaction for limited access scenarios.

## Core Functions

### Authentication and Setup

#### `init_permissions_framework()`
Initialize the permissions framework with proper global arrays and counters.
- **Returns:** 0 on success, 1 on error
- **Dependencies:** Requires `gcp_common.sh` to be loaded first

#### `validate_authentication_setup()`
Validate GCP authentication and detect authentication type (user vs service account).
- **Returns:** 0 on success, 1 on error
- **Side Effects:** Sets `AUTH_TYPE` environment variable

#### `detect_and_validate_scope()`
Detect and validate assessment scope (project vs organization).
- **Returns:** 0 on success, 1 on error
- **Side Effects:** Sets `DETECTED_SCOPE`, `ASSESSMENT_PROJECT_ID`, or `ASSESSMENT_ORG_ID`

### Permission Management

#### `register_required_permissions(requirement_number, permissions...)`
Register API permissions required for a specific PCI DSS requirement.
- **Parameters:**
  - `requirement_number`: PCI DSS requirement number (1-8)
  - `permissions...`: Array of required GCP IAM permissions
- **Returns:** 0 on success, 1 on error
- **Side Effects:** Populates `REQUIRED_PERMISSIONS` global array

#### `check_single_permission(permission)`
Check if a single permission is available for the current authentication context.
- **Parameters:**
  - `permission`: GCP IAM permission to check
- **Returns:** 0 if available, 1 if missing

#### `check_all_permissions()`
Check all registered permissions and calculate coverage.
- **Returns:** 0 if all permissions available, 1 if any missing
- **Side Effects:** Populates `PERMISSION_RESULTS` associative array, updates counters

#### `get_permission_coverage()`
Get the current permission coverage percentage.
- **Returns:** Permission coverage percentage (0-100)

#### `validate_scope_permissions()`
Validate scope-specific permissions for project or organization assessment.
- **Returns:** 0 on success, 1 on error

### User Interaction

#### `prompt_continue_limited()`
Standardized user interaction for limited permission scenarios.
- **Returns:** 0 if user chooses to continue, 1 if user cancels
- **Behavior:** Shows missing permissions and asks user to proceed

#### `display_permission_guidance()`
Display permission requirement guidance based on authentication type.
- **Returns:** None (informational output only)

#### `log_permission_audit_trail()`
Create audit trail entries for permission checks.
- **Returns:** None
- **Side Effects:** Logs to file if `LOG_FILE` is configured

## Usage Examples

### Basic Permission Check

```bash
#!/usr/bin/env bash

# Load libraries
source "$(dirname "$0")/lib/gcp_common.sh"
source "$(dirname "$0")/lib/gcp_permissions.sh"

# Initialize
setup_environment
init_permissions_framework

# Define required permissions for PCI DSS Requirement 1
REQUIREMENT_1_PERMISSIONS=(
    "compute.instances.list"
    "compute.firewalls.list"
    "compute.networks.list"
    "compute.subnetworks.list"
)

# Register and check permissions
register_required_permissions "1" "${REQUIREMENT_1_PERMISSIONS[@]}"

if ! check_all_permissions; then
    coverage=$(get_permission_coverage)
    if [[ $coverage -lt 50 ]]; then
        print_status "FAIL" "Insufficient permissions (${coverage}% coverage)"
        display_permission_guidance
        exit 1
    else
        if ! prompt_continue_limited; then
            print_status "INFO" "Assessment cancelled by user"
            exit 0
        fi
    fi
fi

# Continue with assessment...
print_status "PASS" "Permission validation completed"
```

### Organization Scope Assessment

```bash
#!/usr/bin/env bash

# Set organization scope
export SCOPE="organization"
export ORG_ID="123456789012"

# Load and initialize
source "$(dirname "$0")/lib/gcp_common.sh"
source "$(dirname "$0")/lib/gcp_permissions.sh"

setup_environment
parse_common_arguments "$@"

# Validate authentication and scope
if ! validate_authentication_setup; then
    print_status "FAIL" "Authentication validation failed"
    exit 1
fi

if ! detect_and_validate_scope; then
    print_status "FAIL" "Scope validation failed"
    exit 1
fi

# Organization-level permissions
ORG_PERMISSIONS=(
    "resourcemanager.organizations.get"
    "resourcemanager.projects.list"
    "iam.roles.list"
    "orgpolicy.policies.list"
)

register_required_permissions "org" "${ORG_PERMISSIONS[@]}"
check_all_permissions

# Log audit trail
log_permission_audit_trail
```

## Permission Categories by PCI DSS Requirement

### Requirement 1: Network Security Controls
```bash
REQUIREMENT_1_PERMISSIONS=(
    "compute.instances.list"
    "compute.firewalls.list"
    "compute.networks.list"
    "compute.subnetworks.list"
    "compute.routers.list"
    "compute.vpnTunnels.list"
)
```

### Requirement 2: System Configuration
```bash
REQUIREMENT_2_PERMISSIONS=(
    "compute.instances.list"
    "container.clusters.list"
    "run.services.list"
    "cloudfunctions.functions.list"
)
```

### Requirement 3 & 4: Data Protection
```bash
REQUIREMENT_3_4_PERMISSIONS=(
    "cloudkms.cryptoKeys.list"
    "storage.buckets.list"
    "sql.instances.list"
    "compute.sslCertificates.list"
)
```

### Requirement 7 & 8: Access Control
```bash
REQUIREMENT_7_8_PERMISSIONS=(
    "iam.roles.list"
    "iam.serviceAccounts.list"
    "resourcemanager.projects.getIamPolicy"
    "orgpolicy.policies.list"
)
```

### Requirement 10: Logging and Monitoring
```bash
REQUIREMENT_10_PERMISSIONS=(
    "logging.logEntries.list"
    "monitoring.metricDescriptors.list"
    "cloudaudit.auditLogs.list"
)
```

## Built-in Role Combinations

For comprehensive PCI DSS assessments, the following built-in roles provide optimal coverage:

### Service Account Roles
```bash
# Grant these roles to your service account
roles/viewer                           # Comprehensive read access
roles/iam.securityReviewer            # IAM and security access
roles/logging.viewer                  # Audit log access
roles/monitoring.viewer               # Monitoring data access
roles/cloudasset.viewer               # Asset inventory
roles/accesscontextmanager.policyReader  # VPC Service Controls
```

### User Account Roles
```bash
# For user authentication
Viewer
Security Reviewer  
Logs Viewer
Monitoring Viewer
```

## Error Handling

The library provides consistent error handling patterns:

- **Authentication Errors:** Clear messages about gcloud authentication status
- **Permission Errors:** Detailed missing permission reports
- **Scope Errors:** Validation of project/organization access
- **Graceful Degradation:** Continued assessment with limited permissions when appropriate

## Integration with gcp_common.sh

The permissions library integrates seamlessly with `gcp_common.sh`:

- Uses common color and output functions
- Follows standard CLI argument patterns
- Integrates with logging and audit trail systems
- Respects verbose mode and debugging flags

## Testing

Run the test suite to validate library functionality:

```bash
./test_gcp_permissions.sh
```

Test coverage includes:
- Library loading and function exports
- Permission registration and validation
- Authentication detection
- Scope validation
- Integration workflows

## Security Considerations

- **No Credential Storage:** Library never stores credentials in logs or temporary files
- **Least Privilege:** Validates only read-only permissions required for assessment
- **Audit Trail:** Comprehensive logging of all permission checks and authentication events
- **Scope Validation:** Ensures assessments operate within authorized scope boundaries