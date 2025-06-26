# GCP PCI DSS Framework Troubleshooting Guide

## Overview

This guide provides comprehensive troubleshooting solutions for the complete GCP PCI DSS shared library framework, covering common issues, integration problems, and operational challenges encountered during production deployment and usage.

## Quick Diagnosis Checklist

### Framework Loading Issues
- [ ] Verify all 4 libraries exist in `lib/` directory
- [ ] Check file permissions (755 for directories, 644 for files)
- [ ] Confirm `gcp_common.sh` loads first before other libraries
- [ ] Validate bash version 4.0+ support for associative arrays

### Permission Issues
- [ ] Verify GCP authentication: `gcloud auth list`
- [ ] Check project access: `gcloud projects describe PROJECT_ID`
- [ ] Validate IAM permissions for assessment scope
- [ ] Confirm organization access if using organization scope

### HTML Report Issues
- [ ] Check OUTPUT_FILE environment variable is set
- [ ] Verify write permissions to output directory
- [ ] Confirm disk space availability
- [ ] Validate HTML content escaping for special characters

### Scope Management Issues
- [ ] Verify scope type matches available permissions
- [ ] Check organization ID format and access
- [ ] Confirm project enumeration permissions
- [ ] Validate network connectivity to GCP APIs

## Common Issues and Solutions

### 1. Library Loading Errors

#### Issue: `gcp_common.sh not found`
```
Error: gcp_common.sh not found at: ./lib/gcp_common.sh
```

**Root Cause:** Incorrect library path or missing shared libraries

**Solutions:**
```bash
# Check library location
ls -la "$(dirname "$0")/lib/"

# Verify correct path construction
LIB_DIR="$(dirname "$0")/lib"
echo "Library directory: $LIB_DIR"

# Use absolute path if relative path fails
LIB_DIR="/absolute/path/to/gcp/lib"
source "$LIB_DIR/gcp_common.sh"
```

#### Issue: `Function not available after library loading`
```
bash: register_required_permissions: command not found
```

**Root Cause:** Library loading order or source command failure

**Solutions:**
```bash
# Verify loading order - gcp_common.sh must be first
source "$LIB_DIR/gcp_common.sh" || {
    echo "Failed to load gcp_common.sh" >&2
    exit 1
}

# Check if library loaded successfully
if [[ "$GCP_PERMISSIONS_LOADED" != "true" ]]; then
    echo "gcp_permissions.sh failed to load" >&2
    exit 1
fi

# Verify function availability
declare -F register_required_permissions >/dev/null || {
    echo "Function not available" >&2
    exit 1
}
```

#### Issue: `Bash version compatibility`
```
Error: associative arrays not supported
```

**Root Cause:** Bash version < 4.0

**Solutions:**
```bash
# Check bash version
bash --version

# Use newer bash if available
#!/usr/bin/env bash
if [[ ${BASH_VERSION%%.*} -lt 4 ]]; then
    echo "Bash 4.0+ required, found: $BASH_VERSION" >&2
    exit 1
fi

# Alternative: Use indexed arrays for compatibility
```

### 2. Permission and Authentication Issues

#### Issue: `Authentication not configured`
```
Error: (gcloud.auth.list) Your current active account [...] does not have any valid credentials
```

**Root Cause:** GCP authentication not set up or expired

**Solutions:**
```bash
# Initialize authentication
gcloud auth login

# For service accounts
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
gcloud auth activate-service-account --key-file="$GOOGLE_APPLICATION_CREDENTIALS"

# Verify authentication
gcloud auth list --filter=status:ACTIVE
```

#### Issue: `Insufficient permissions for assessment`
```
Error: Cannot access project 'my-project'
```

**Root Cause:** Missing IAM permissions for assessment scope

**Solutions:**
```bash
# Check current permissions
gcloud projects get-iam-policy PROJECT_ID --flatten="bindings[].members" --format="table(bindings.role)" --filter="bindings.members:USER_EMAIL"

# Required permissions for project scope:
- resourcemanager.projects.get
- compute.instances.list
- compute.firewalls.list
- compute.networks.list

# Required permissions for organization scope:
- resourcemanager.organizations.get
- resourcemanager.projects.list
- All project-level permissions above

# Test specific permission
gcloud projects test-iam-permissions PROJECT_ID --permissions="compute.instances.list"
```

#### Issue: `Organization access denied`
```
Error: Cannot access organization: 123456789
```

**Root Cause:** Missing organization-level permissions or incorrect organization ID

**Solutions:**
```bash
# Verify organization ID format (numeric)
echo "Organization ID: $ORG_ID"

# Test organization access
gcloud organizations describe "$ORG_ID"

# Check organization permissions
gcloud organizations get-iam-policy "$ORG_ID" --flatten="bindings[].members" --format="table(bindings.role)" --filter="bindings.members:USER_EMAIL"

# Required organization roles:
- Organization Viewer (resourcemanager.organizations.get)
- Project Browser (resourcemanager.projects.list)
```

### 3. HTML Report Generation Issues

#### Issue: `HTML report not generated`
```
Error: Failed to initialize HTML report
```

**Root Cause:** Output file path issues or write permissions

**Solutions:**
```bash
# Check output directory permissions
OUTPUT_DIR="$(dirname "$OUTPUT_FILE")"
ls -ld "$OUTPUT_DIR"

# Create output directory if missing
mkdir -p "$OUTPUT_DIR"

# Test write permissions
touch "$OUTPUT_FILE" && rm "$OUTPUT_FILE" || {
    echo "Cannot write to: $OUTPUT_FILE" >&2
    exit 1
}

# Use absolute path
OUTPUT_FILE="/absolute/path/to/report.html"
```

#### Issue: `HTML content corruption`
```
Warning: HTML content appears corrupted or malformed
```

**Root Cause:** Special characters not properly escaped or encoding issues

**Solutions:**
```bash
# Use html_append() for all content addition
html_append "<p>Safe content: $(echo "$user_input" | html_escape)</p>"

# Verify file encoding
file -bi "$OUTPUT_FILE"
# Should show: text/html; charset=utf-8

# Check for binary content in HTML
hexdump -C "$OUTPUT_FILE" | head -5
```

#### Issue: `Large report performance`
```
Warning: HTML report generation slow or memory issues
```

**Root Cause:** Too many sections or large content blocks

**Solutions:**
```bash
# Monitor report size during generation
ls -lh "$OUTPUT_FILE"

# Limit section content size
MAX_CONTENT_SIZE=10000
if [[ ${#content} -gt $MAX_CONTENT_SIZE ]]; then
    content="${content:0:$MAX_CONTENT_SIZE}... [truncated]"
fi

# Use pagination for large result sets
if [[ $result_count -gt 1000 ]]; then
    add_check_result "Large Result Set" "INFO" "Found $result_count results (showing first 1000)" ""
fi
```

### 4. Scope Management Issues

#### Issue: `Project enumeration failure`
```
Error: Failed to enumerate projects in organization
```

**Root Cause:** Organization permissions or API rate limiting

**Solutions:**
```bash
# Test project enumeration manually
gcloud projects list --filter="parent.id:$ORG_ID" --format="value(projectId)"

# Handle rate limiting
retry_count=0
max_retries=3
while [[ $retry_count -lt $max_retries ]]; do
    if get_projects_in_scope; then
        break
    fi
    sleep $((2 ** retry_count))
    ((retry_count++))
done

# Use cached results if available
if [[ -n "$PROJECTS_CACHE" ]]; then
    echo "$PROJECTS_CACHE"
fi
```

#### Issue: `Cross-project command execution failure`
```
Error: Command failed for project 'project-123'
```

**Root Cause:** Project-specific permission issues or project state

**Solutions:**
```bash
# Validate project state before execution
if gcloud projects describe "$project" --format="value(lifecycleState)" 2>/dev/null | grep -q "ACTIVE"; then
    # Proceed with assessment
else
    add_check_result "Project Status" "WARN" "Project $project not active" "Skip inactive projects"
    continue
fi

# Test individual project access
if ! gcloud compute instances list --project="$project" >/dev/null 2>&1; then
    add_check_result "Project Access" "FAIL" "Cannot access project $project" "Check project-level permissions"
    continue
fi
```

### 5. Performance and Resource Issues

#### Issue: `Framework loading slow`
```
Warning: Library loading takes >5 seconds
```

**Root Cause:** Network latency or large library files

**Solutions:**
```bash
# Profile library loading time
time source "$LIB_DIR/gcp_common.sh"

# Use selective loading for performance
if [[ "$MINIMAL_MODE" == "true" ]]; then
    source "$LIB_DIR/gcp_common.sh"
    # Skip other libraries if not needed
fi

# Check network connectivity
curl -s -w "%{time_total}" -o /dev/null "https://cloud.google.com" || echo "Network connectivity issues"
```

#### Issue: `Memory usage high during assessment`
```
Warning: High memory usage detected
```

**Root Cause:** Large result sets or inefficient data processing

**Solutions:**
```bash
# Monitor memory usage
ps -o pid,vsz,rss,comm -p $$

# Process results in chunks
process_in_chunks() {
    local input="$1"
    local chunk_size=100
    
    echo "$input" | split -l "$chunk_size" - /tmp/chunk_
    for chunk_file in /tmp/chunk_*; do
        # Process each chunk
        rm "$chunk_file"
    done
}

# Use streaming for large datasets
gcloud compute instances list --format="json" | jq -c '.[]' | while read -r instance; do
    # Process each instance individually
done
```

### 6. Integration and Compatibility Issues

#### Issue: `Function name conflicts`
```
Error: Function 'print_status' already defined
```

**Root Cause:** Multiple script sources or function redefinition

**Solutions:**
```bash
# Check for existing function definitions
declare -F print_status

# Use namespaced functions if conflicts exist
gcp_print_status() {
    # Library function implementation
}

# Unset conflicting functions before loading
unset -f print_status 2>/dev/null
source "$LIB_DIR/gcp_common.sh"
```

#### Issue: `Environment variable conflicts`
```
Warning: Environment variable PROJECT_ID conflicts with existing value
```

**Root Cause:** External scripts setting conflicting variables

**Solutions:**
```bash
# Save original environment
ORIGINAL_PROJECT_ID="$PROJECT_ID"

# Use library-specific prefixes
GCP_ASSESSMENT_PROJECT_ID="$PROJECT_ID"

# Restore environment on exit
cleanup_environment() {
    PROJECT_ID="$ORIGINAL_PROJECT_ID"
}
trap cleanup_environment EXIT
```

## Debugging Techniques

### 1. Enable Debug Mode

```bash
# Enable comprehensive debugging
export GCP_DEBUG=true
export VERBOSE=true

# Enable bash debugging
set -x  # Show command execution
set -e  # Exit on error
set -u  # Error on undefined variables

# Run script with debugging
bash -x ./assessment_script.sh -v -p PROJECT_ID
```

### 2. Library Load Verification

```bash
# Verify all libraries loaded correctly
check_libraries() {
    local libraries=(
        "GCP_COMMON_LOADED"
        "GCP_PERMISSIONS_LOADED"
        "GCP_HTML_REPORT_LOADED"
        "GCP_SCOPE_MGMT_LOADED"
    )
    
    for lib in "${libraries[@]}"; do
        if [[ "${!lib}" == "true" ]]; then
            echo "✓ $lib"
        else
            echo "✗ $lib"
        fi
    done
}
```

### 3. Permission Diagnostic

```bash
# Comprehensive permission check
diagnose_permissions() {
    echo "=== GCP Authentication ==="
    gcloud auth list
    
    echo "=== Current Project ==="
    gcloud config get-value project
    
    echo "=== Available Projects ==="
    gcloud projects list --limit=5
    
    echo "=== Test Permissions ==="
    local test_permissions=(
        "resourcemanager.projects.get"
        "compute.instances.list"
        "compute.firewalls.list"
    )
    
    for permission in "${test_permissions[@]}"; do
        if gcloud projects test-iam-permissions "$PROJECT_ID" --permissions="$permission" >/dev/null 2>&1; then
            echo "✓ $permission"
        else
            echo "✗ $permission"
        fi
    done
}
```

### 4. Network Connectivity Test

```bash
# Test GCP API connectivity
test_gcp_connectivity() {
    local endpoints=(
        "https://compute.googleapis.com"
        "https://cloudresourcemanager.googleapis.com"
        "https://iam.googleapis.com"
    )
    
    for endpoint in "${endpoints[@]}"; do
        if curl -s --connect-timeout 5 "$endpoint" >/dev/null; then
            echo "✓ $endpoint"
        else
            echo "✗ $endpoint"
        fi
    done
}
```

## Error Recovery Strategies

### 1. Graceful Degradation

```bash
# Handle missing permissions gracefully
if ! check_all_permissions; then
    local coverage=$(get_permission_coverage)
    if [[ $coverage -ge 50 ]]; then
        print_status "WARN" "Limited permissions ($coverage%), continuing with reduced assessment"
    else
        print_status "FAIL" "Insufficient permissions ($coverage%), cannot continue"
        exit 1
    fi
fi
```

### 2. Retry Mechanisms

```bash
# Retry API calls with backoff
retry_with_backoff() {
    local command="$1"
    local max_attempts=3
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if eval "$command"; then
            return 0
        fi
        
        local delay=$((2 ** attempt))
        print_status "WARN" "Attempt $attempt failed, retrying in ${delay}s..."
        sleep "$delay"
        ((attempt++))
    done
    
    return 1
}
```

### 3. Fallback Mechanisms

```bash
# Fallback to alternative data sources
get_instance_data() {
    local project="$1"
    
    # Primary method
    if gcloud compute instances list --project="$project" --format="json" 2>/dev/null; then
        return 0
    fi
    
    # Fallback to manual enumeration
    print_status "WARN" "Using fallback method for instance enumeration"
    add_manual_check "Instance Inventory" "Manual" "Manually verify compute instances in project $project"
}
```

## Escalation Procedures

### Level 1: Self-Service Resolution
1. Check this troubleshooting guide
2. Verify basic prerequisites (authentication, permissions, network)
3. Enable debug mode and review error messages
4. Test with minimal configuration

### Level 2: Advanced Troubleshooting
1. Review library source code for specific error patterns
2. Check GCP service status: https://status.cloud.google.com/
3. Validate IAM policy inheritance and organization policies
4. Test with different authentication methods (user vs service account)

### Level 3: Expert Support
1. Collect comprehensive diagnostic information
2. Review GCP audit logs for permission denials
3. Engage GCP support for platform-specific issues
4. Consider framework modifications for edge cases

## Support Resources

- **Framework Documentation**: `lib/README_*.md` files
- **GCP IAM Documentation**: https://cloud.google.com/iam/docs
- **GCP CLI Reference**: https://cloud.google.com/sdk/gcloud/reference
- **PCI DSS Requirements**: `../PCI_DSS_v4.0.1_Requirements.md`
- **Integration Examples**: `INTEGRATION_GUIDE.md`