#!/usr/bin/env bash
# GCP Permissions Library - Core Permission Management
declare -A PERMISSION_RESULTS
declare -A ROLE_RESULTS
declare -a REQUIRED_PERMISSIONS
declare -a REQUIRED_ROLES
declare -a OPTIONAL_PERMISSIONS
PERMISSION_COVERAGE_PERCENTAGE=0
MISSING_PERMISSIONS_COUNT=0
AVAILABLE_PERMISSIONS_COUNT=0
MISSING_ROLES_COUNT=0
AVAILABLE_ROLES_COUNT=0

# Standard GCP permissions required for PCI DSS assessment
# Note: The actual permissions are defined locally in check_standard_permissions() function

# Function to test a specific gcloud command (like AWS method)
test_gcloud_command() {
    local service="$1"
    local command="$2"
    local description="$3"
    local additional_args="$4"
    
    local full_command="gcloud $service $command"
    if [[ -n "$additional_args" ]]; then
        full_command="$full_command $additional_args"
    fi
    
    # Add common parameters for scope
    if [[ -n "$PROJECT_ID" ]]; then
        full_command="$full_command --project=$PROJECT_ID"
    fi
    
    # Add format and limit parameters to minimize output and add timeout
    full_command="$full_command --format=value(name) --limit=1 --verbosity=error"
    
    # Execute command with timeout and capture output
    local output
    local exit_code
    
    # Use timeout to prevent hanging (15 seconds max)
    if command -v timeout >/dev/null 2>&1; then
        output=$(timeout 15s bash -c "$full_command" 2>&1)
        exit_code=$?
    else
        # Fallback if timeout command not available
        output=$($full_command 2>&1)
        exit_code=$?
    fi
    
    # Check for timeout
    if [[ $exit_code -eq 124 ]]; then
        return 1  # Timeout = permission issue
    fi
    
    # Check for permission-related errors (similar to AWS approach)
    if [[ $output == *"PERMISSION_DENIED"* ]] || \
       [[ $output == *"does not have permission"* ]] || \
       [[ $output == *"Insufficient Permission"* ]] || \
       [[ $output == *"Access denied"* ]] || \
       [[ $output == *"FORBIDDEN"* ]] || \
       [[ $exit_code -eq 1 && $output == *"permission"* ]]; then
        return 1
    elif [[ $output == *"not found"* ]] || \
         [[ $output == *"No resources found"* ]] || \
         [[ $output == *"Listed 0 items"* ]] || \
         [[ $exit_code -eq 0 ]]; then
        # Command succeeded or failed due to no resources (which is fine for permission testing)
        return 0
    else
        # Other errors might indicate permission issues, but let's be lenient
        return 0
    fi
}

# Check if current user has required permissions using functional testing
check_standard_permissions() {
    print_status "INFO" "Testing GCP permissions for PCI DSS assessment..."
    
    # Declare the permissions array locally to ensure proper scoping
    local -A standard_permissions=(
        ["compute_instances_list"]="List Compute Instances"
        ["compute_firewallRules_list"]="List Firewall Rules"
        ["compute_networks_list"]="List VPC Networks"
        ["storage_buckets_list"]="List Storage Buckets"
        ["cloudsql_instances_list"]="List Cloud SQL Instances"
        ["logging_sinks_list"]="List Logging Sinks"
        ["iam_serviceAccounts_list"]="List Service Accounts"
        ["monitoring_alertPolicies_list"]="List Monitoring Alerts"
    )
    
    # Get current user email
    local current_user
    current_user=$(gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>/dev/null | head -1)
    
    if [[ -z "$current_user" ]]; then
        print_status "FAIL" "Cannot determine current authenticated user"
        return 1
    fi
    
    print_status "INFO" "Testing permissions for user: $current_user"
    
    AVAILABLE_ROLES_COUNT=0
    MISSING_ROLES_COUNT=0
    ROLE_RESULTS=()
    
    # Test each standard permission by trying actual commands
    for permission in "${!standard_permissions[@]}"; do
        local description="${standard_permissions[$permission]}"
        
        # Map permissions to actual gcloud commands
        case "$permission" in
            "compute_instances_list")
                if test_gcloud_command "compute" "instances list" "$description" "--zones=$(gcloud config get-value compute/zone 2>/dev/null || echo 'us-central1-a')"; then
                    ROLE_RESULTS["$permission"]="AVAILABLE"
                    ((AVAILABLE_ROLES_COUNT++))
                    print_status "PASS" "✓ $description"
                else
                    ROLE_RESULTS["$permission"]="MISSING"
                    ((MISSING_ROLES_COUNT++))
                    print_status "FAIL" "✗ $description"
                fi
                ;;
            "compute_firewallRules_list")
                if test_gcloud_command "compute" "firewall-rules list" "$description"; then
                    ROLE_RESULTS["$permission"]="AVAILABLE"
                    ((AVAILABLE_ROLES_COUNT++))
                    print_status "PASS" "✓ $description"
                else
                    ROLE_RESULTS["$permission"]="MISSING"
                    ((MISSING_ROLES_COUNT++))
                    print_status "FAIL" "✗ $description"
                fi
                ;;
            "compute_networks_list")
                if test_gcloud_command "compute" "networks list" "$description"; then
                    ROLE_RESULTS["$permission"]="AVAILABLE"
                    ((AVAILABLE_ROLES_COUNT++))
                    print_status "PASS" "✓ $description"
                else
                    ROLE_RESULTS["$permission"]="MISSING"
                    ((MISSING_ROLES_COUNT++))
                    print_status "FAIL" "✗ $description"
                fi
                ;;
            "storage_buckets_list")
                if gsutil ls >/dev/null 2>&1; then
                    ROLE_RESULTS["$permission"]="AVAILABLE"
                    ((AVAILABLE_ROLES_COUNT++))
                    print_status "PASS" "✓ $description"
                else
                    ROLE_RESULTS["$permission"]="MISSING"
                    ((MISSING_ROLES_COUNT++))
                    print_status "FAIL" "✗ $description"
                fi
                ;;
            "cloudsql_instances_list")
                if test_gcloud_command "sql" "instances list" "$description"; then
                    ROLE_RESULTS["$permission"]="AVAILABLE"
                    ((AVAILABLE_ROLES_COUNT++))
                    print_status "PASS" "✓ $description"
                else
                    ROLE_RESULTS["$permission"]="MISSING"
                    ((MISSING_ROLES_COUNT++))
                    print_status "FAIL" "✗ $description"
                fi
                ;;
            "logging_sinks_list")
                if test_gcloud_command "logging" "sinks list" "$description"; then
                    ROLE_RESULTS["$permission"]="AVAILABLE"
                    ((AVAILABLE_ROLES_COUNT++))
                    print_status "PASS" "✓ $description"
                else
                    ROLE_RESULTS["$permission"]="MISSING"
                    ((MISSING_ROLES_COUNT++))
                    print_status "FAIL" "✗ $description"
                fi
                ;;
            "iam_serviceAccounts_list")
                if test_gcloud_command "iam" "service-accounts list" "$description"; then
                    ROLE_RESULTS["$permission"]="AVAILABLE"
                    ((AVAILABLE_ROLES_COUNT++))
                    print_status "PASS" "✓ $description"
                else
                    ROLE_RESULTS["$permission"]="MISSING"
                    ((MISSING_ROLES_COUNT++))
                    print_status "FAIL" "✗ $description"
                fi
                ;;
            "monitoring_alertPolicies_list")
                if test_gcloud_command "alpha monitoring" "policies list" "$description"; then
                    ROLE_RESULTS["$permission"]="AVAILABLE"
                    ((AVAILABLE_ROLES_COUNT++))
                    print_status "PASS" "✓ $description"
                else
                    ROLE_RESULTS["$permission"]="MISSING"
                    ((MISSING_ROLES_COUNT++))
                    print_status "FAIL" "✗ $description"
                fi
                ;;
        esac
    done
    
    local total_permissions=${#standard_permissions[@]}
    local permission_coverage_percentage=0
    
    if [[ $total_permissions -gt 0 ]]; then
        permission_coverage_percentage=$((AVAILABLE_ROLES_COUNT * 100 / total_permissions))
    fi
    
    print_status "INFO" "Permission check: ${AVAILABLE_ROLES_COUNT}/${total_permissions} available (${permission_coverage_percentage}%)"
    
    if [[ $MISSING_ROLES_COUNT -gt 0 ]]; then
        print_status "WARN" "Missing ${MISSING_ROLES_COUNT} required permissions"
        echo ""
        print_status "INFO" "Required permissions for PCI DSS assessment:"
        for permission in "${!standard_permissions[@]}"; do
            local description="${standard_permissions[$permission]}"
            local status="${ROLE_RESULTS[$permission]:-MISSING}"
            if [[ "$status" == "MISSING" ]]; then
                print_status "WARN" "  - $description"
            fi
        done
        echo ""
        
        # If we have most permissions (>= 75%), allow to continue
        if [[ $permission_coverage_percentage -ge 75 ]]; then
            print_status "INFO" "Most permissions available - assessment can proceed with some limitations"
            return 0
        else
            print_status "INFO" "Please ensure the current user has the required permissions"
            return 1
        fi
    fi
    
    print_status "PASS" "All required permissions are available"
    return 0
}

# Original role-based check for fast validation
check_role_assignments() {
    print_status "INFO" "Checking role assignments for PCI DSS assessment..."
    
    # Get current user email
    local current_user
    current_user=$(gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>/dev/null | head -1)
    
    if [[ -z "$current_user" ]]; then
        print_status "FAIL" "Cannot determine current authenticated user"
        return 1
    fi
    
    print_status "INFO" "Checking roles for user: $current_user"
    
    local available_roles=0
    local missing_roles=0
    
    # Standard GCP roles required for PCI DSS assessment
    local -A standard_roles=(
        ["roles/viewer"]="Viewer"
        ["roles/iam.securityReviewer"]="Security Reviewer"
        ["roles/logging.viewer"]="Logging Viewer"
        ["roles/monitoring.viewer"]="Monitoring Viewer"
        ["roles/cloudasset.viewer"]="Cloud Asset Viewer"
        ["roles/accesscontextmanager.policyReader"]="Access Context Manager Policy Reader"
        ["roles/owner"]="Owner"
        ["roles/editor"]="Editor"
    )
    
    # First, check for high-privilege roles (Owner/Editor) for fast exit
    print_status "INFO" "Checking for high-privilege roles first..."
    
    for role in "roles/owner" "roles/editor"; do
        local role_name="${standard_roles[$role]}"
        local has_role=false
        
        if [[ -n "$PROJECT_ID" ]]; then
            # Check project-level role binding
            if gcloud projects get-iam-policy "$PROJECT_ID" --format="value(bindings[role=$role].members)" 2>/dev/null | \
               grep -q "user:$current_user"; then
                has_role=true
            fi
        elif [[ -n "$ORG_ID" ]]; then
            # Check organization-level role binding
            if gcloud organizations get-iam-policy "$ORG_ID" --format="value(bindings[role=$role].members)" 2>/dev/null | \
               grep -q "user:$current_user"; then
                has_role=true
            fi
        fi
        
        if [[ "$has_role" == "true" ]]; then
            print_status "PASS" "✓ $role_name ($role)"
            print_status "PASS" "High-privilege role detected - has all required permissions"
            print_status "INFO" "Skipping individual role checks (not needed with $role_name)"
            return 0
        fi
    done
    
    print_status "INFO" "No high-privilege roles found - checking individual roles..."
    
    # Check each remaining standard role
    for role in "${!standard_roles[@]}"; do
        # Skip Owner/Editor since we already checked them
        if [[ "$role" == "roles/owner" || "$role" == "roles/editor" ]]; then
            continue
        fi
        
        local role_name="${standard_roles[$role]}"
        local has_role=false
        
        if [[ -n "$PROJECT_ID" ]]; then
            # Check project-level role binding
            if gcloud projects get-iam-policy "$PROJECT_ID" --format="value(bindings[role=$role].members)" 2>/dev/null | \
               grep -q "user:$current_user"; then
                has_role=true
            fi
        elif [[ -n "$ORG_ID" ]]; then
            # Check organization-level role binding
            if gcloud organizations get-iam-policy "$ORG_ID" --format="value(bindings[role=$role].members)" 2>/dev/null | \
               grep -q "user:$current_user"; then
                has_role=true
            fi
        fi
        
        if [[ "$has_role" == "true" ]]; then
            ((available_roles++))
            print_status "PASS" "✓ $role_name ($role)"
        else
            print_status "FAIL" "✗ $role_name ($role)"
        fi
    done
    
    # Check if we have enough standard roles (at least 4 out of 6 core roles)
    if [[ $available_roles -ge 4 ]]; then
        print_status "PASS" "Sufficient role assignments found ($available_roles roles)"
        return 0
    else
        print_status "WARN" "Insufficient role assignments found ($available_roles roles)"
        return 1
    fi
}

# Combined permission check: try roles first, fall back to functional testing
check_standard_roles() {
    print_status "INFO" "=== STEP 1: Quick Role Assignment Check ==="
    
    # Try role-based check first (fast)
    if check_role_assignments; then
        print_status "PASS" "Role-based validation successful - proceeding with assessment"
        return 0
    fi
    
    print_status "INFO" "Role assignment check failed - switching to functional testing..."
    echo ""
    print_status "INFO" "=== STEP 2: Functional Permission Testing ==="
    
    # Fall back to functional testing (slower but more accurate)
    if check_standard_permissions; then
        print_status "PASS" "Functional validation successful - proceeding with assessment"
        return 0
    else
        print_status "FAIL" "Both role assignment and functional testing failed"
        return 1
    fi
}

register_required_permissions() {
    local req_num="$1"
    shift
    local permissions=("$@")
    
    if [[ -z "$req_num" || ${#permissions[@]} -eq 0 ]]; then
        print_status "FAIL" "Invalid parameters for permission registration"
        return 1
    fi
    
    REQUIRED_PERMISSIONS=("${permissions[@]}")
    print_status "PASS" "Registered ${#REQUIRED_PERMISSIONS[@]} permissions for Requirement $req_num"
    
    if [[ "$VERBOSE" == "true" ]]; then
        for perm in "${REQUIRED_PERMISSIONS[@]}"; do
            print_status "INFO" "  - $perm"
        done
    fi
    return 0
}

check_all_permissions() {
    if [[ ${#REQUIRED_PERMISSIONS[@]} -eq 0 ]]; then
        print_status "WARN" "No permissions registered to check"
        return 0
    fi
    
    print_status "INFO" "Checking ${#REQUIRED_PERMISSIONS[@]} required permissions..."
    
    AVAILABLE_PERMISSIONS_COUNT=0
    MISSING_PERMISSIONS_COUNT=0
    PERMISSION_RESULTS=()
    
    for permission in "${REQUIRED_PERMISSIONS[@]}"; do
        # Convert dots to underscores for array key to avoid bash syntax errors
        local safe_key="${permission//\./_}"
        
        if [[ -n "$PROJECT_ID" ]] && \
           gcloud projects test-iam-permissions "$PROJECT_ID" \
           --permissions="$permission" --format="value(permissions)" 2>/dev/null | \
           grep -q "$permission"; then
            PERMISSION_RESULTS["$safe_key"]="AVAILABLE"
            ((AVAILABLE_PERMISSIONS_COUNT++))
            print_status "PASS" "✓ $permission"
        else
            PERMISSION_RESULTS["$safe_key"]="MISSING"
            ((MISSING_PERMISSIONS_COUNT++))
            print_status "FAIL" "✗ $permission"
        fi
    done
    
    if [[ ${#REQUIRED_PERMISSIONS[@]} -gt 0 ]]; then
        PERMISSION_COVERAGE_PERCENTAGE=$((AVAILABLE_PERMISSIONS_COUNT * 100 / ${#REQUIRED_PERMISSIONS[@]}))
    else
        PERMISSION_COVERAGE_PERCENTAGE=100
    fi
    
    print_status "INFO" "Permission check: ${AVAILABLE_PERMISSIONS_COUNT}/${#REQUIRED_PERMISSIONS[@]} available (${PERMISSION_COVERAGE_PERCENTAGE}%)"
    
    [[ $MISSING_PERMISSIONS_COUNT -eq 0 ]]
}

get_permission_coverage() {
    echo "$PERMISSION_COVERAGE_PERCENTAGE"
}

prompt_continue_limited() {
    local coverage=$(get_permission_coverage)
    
    echo
    print_status "WARN" "Limited permissions detected (${coverage}% coverage)"
    print_status "INFO" "Missing ${MISSING_PERMISSIONS_COUNT} of ${#REQUIRED_PERMISSIONS[@]} required permissions"
    
    if [[ "$VERBOSE" == "true" ]]; then
        echo
        print_status "INFO" "Missing permissions:"
        for permission in "${!PERMISSION_RESULTS[@]}"; do
            if [[ "${PERMISSION_RESULTS[$permission]}" == "MISSING" ]]; then
                print_status "INFO" "  - $permission"
            fi
        done
    fi
    
    echo
    print_status "INFO" "Assessment can continue with limited functionality"
    echo
    
    while true; do
        read -p "Continue with limited permissions? [y/N]: " response
        case "$response" in
            [Yy]|[Yy][Ee][Ss])
                print_status "PASS" "Continuing with limited permissions"
                return 0
                ;;
            [Nn]|[Nn][Oo]|"")
                print_status "INFO" "Assessment cancelled by user"
                return 1
                ;;
            *)
                echo "Please answer yes (y) or no (n)"
                ;;
        esac
    done
}

# Comprehensive permission check combining roles and specific permissions
check_required_permissions() {
    local requirement_permissions=("$@")
    
    print_status "INFO" "=== PCI DSS PERMISSION VALIDATION ==="
    echo ""
    
    # First check standard GCP roles
    print_status "INFO" "Step 1: Checking standard GCP roles..."
    local roles_ok=true
    if ! check_standard_roles; then
        roles_ok=false
    fi
    
    echo ""
    
    # If functional testing passed (roles_ok=true), we have sufficient permissions
    # Only do detailed permission testing if functional testing failed
    local detailed_permissions_ok=true
    local coverage=100
    
    if [[ "$roles_ok" == "false" && ${#requirement_permissions[@]} -gt 0 ]]; then
        print_status "INFO" "Step 2: Functional testing failed - checking requirement-specific permissions..."
        REQUIRED_PERMISSIONS=("${requirement_permissions[@]}")
        if ! check_all_permissions; then
            detailed_permissions_ok=false
            coverage=$(get_permission_coverage)
            if [[ $coverage -lt 80 ]]; then
                print_status "WARN" "Low permission coverage for requirement-specific checks"
            fi
        fi
    elif [[ "$roles_ok" == "true" ]]; then
        print_status "INFO" "Step 2: Functional testing passed - skipping detailed permission check"
        print_status "PASS" "Functional validation confirms sufficient permissions for assessment"
    else
        print_status "INFO" "Step 2: No requirement-specific permissions to check"
    fi
    
    echo ""
    print_status "INFO" "=== PERMISSION VALIDATION SUMMARY ==="
    
    # Determine overall status
    if [[ "$roles_ok" == "true" ]]; then
        print_status "PASS" "✓ Standard GCP roles: Functional testing passed (sufficient permissions)"
        print_status "PASS" "✓ Overall permission status: Assessment can proceed with full functionality"
    else
        print_status "FAIL" "✗ Standard GCP roles: Functional testing failed"
        
        if [[ ${#requirement_permissions[@]} -gt 0 ]]; then
            if [[ $coverage -eq 100 ]]; then
                print_status "PASS" "✓ Requirement permissions: All permissions available via detailed check"
            else
                print_status "WARN" "⚠ Requirement permissions: ${coverage}% coverage via detailed check"
            fi
        fi
    fi
    
    echo ""
    
    # Overall decision
    if [[ "$roles_ok" == "true" ]]; then
        print_status "PASS" "Permission validation successful - proceeding with assessment"
        return 0
    elif [[ "$detailed_permissions_ok" == "true" || $coverage -ge 80 ]]; then
        print_status "PASS" "Sufficient permissions available via detailed check - proceeding with assessment"
        return 0
    else
        print_status "WARN" "Limited permissions detected"
        if prompt_continue_limited; then
            return 0
        else
            return 1
        fi
    fi
}

validate_scope_permissions() {
    print_status "INFO" "Validating scope permissions..."
    if [[ -z "$PROJECT_ID" && -z "$ORG_ID" ]]; then
        print_status "FAIL" "No project or organization scope defined"
        return 1
    fi
    if [[ -n "$PROJECT_ID" ]]; then
        if gcloud projects describe "$PROJECT_ID" &> /dev/null; then
            print_status "PASS" "Project scope validated: $PROJECT_ID"
        else
            print_status "FAIL" "Cannot access project: $PROJECT_ID"
            return 1
        fi
    fi
    if [[ -n "$ORG_ID" ]]; then
        if gcloud organizations describe "$ORG_ID" &> /dev/null; then
            print_status "PASS" "Organization scope validated: $ORG_ID"
        else
            print_status "FAIL" "Cannot access organization: $ORG_ID"
            return 1
        fi
    fi
    return 0
}

if [[ "$GCP_COMMON_LOADED" != "true" ]]; then
    echo "Error: gcp_common.sh must be loaded before gcp_permissions.sh" >&2
    exit 1
fi
# Initialize global variables
PERMISSION_RESULTS=()
ROLE_RESULTS=()
REQUIRED_PERMISSIONS=()
REQUIRED_ROLES=()
OPTIONAL_PERMISSIONS=()
PERMISSION_COVERAGE_PERCENTAGE=0
MISSING_PERMISSIONS_COUNT=0
AVAILABLE_PERMISSIONS_COUNT=0
MISSING_ROLES_COUNT=0
AVAILABLE_ROLES_COUNT=0

# Export all functions
export -f check_standard_roles register_required_permissions check_all_permissions get_permission_coverage prompt_continue_limited check_required_permissions validate_scope_permissions
export GCP_PERMISSIONS_LOADED="true"