#!/usr/bin/env bash

# =============================================================================
# GCP Permissions Library Usage Example
# =============================================================================
# Description: Demonstrates how to use gcp_permissions.sh in assessment scripts
# Version: 1.0
# Author: PCI DSS Assessment Framework
# Created: 2025-06-05
# =============================================================================

# Get script directory and load libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load shared libraries
source "$SCRIPT_DIR/lib/gcp_common.sh" || {
    echo "Error: Failed to load gcp_common.sh" >&2
    exit 1
}

source "$SCRIPT_DIR/lib/gcp_permissions.sh" || {
    echo "Error: Failed to load gcp_permissions.sh" >&2
    exit 1
}

# =============================================================================
# Example 1: Basic Permission Check for PCI DSS Requirement 1
# =============================================================================

example_basic_permission_check() {
    print_status "INFO" "=== Example 1: Basic Permission Check ==="
    
    # Initialize framework
    setup_environment "example_permissions.log"
    init_permissions_framework
    
    # Define permissions for PCI DSS Requirement 1 (Network Security)
    local req1_permissions=(
        "compute.instances.list"
        "compute.firewalls.list"
        "compute.networks.list"
        "compute.subnetworks.list"
        "compute.routers.list"
    )
    
    # Register permissions
    register_required_permissions "1" "${req1_permissions[@]}"
    
    # Check permissions
    if check_all_permissions; then
        print_status "PASS" "All permissions available for Requirement 1"
        log_permission_audit_trail
    else
        local coverage=$(get_permission_coverage)
        print_status "WARN" "Limited permissions detected (${coverage}% coverage)"
        
        if [[ $coverage -lt 50 ]]; then
            print_status "FAIL" "Insufficient permissions for reliable assessment"
            display_permission_guidance
            return 1
        else
            if prompt_continue_limited; then
                print_status "INFO" "Continuing with limited permissions"
                log_permission_audit_trail
            else
                print_status "INFO" "Assessment cancelled by user"
                return 1
            fi
        fi
    fi
    
    return 0
}

# =============================================================================
# Example 2: Organization Scope Assessment
# =============================================================================

example_organization_assessment() {
    print_status "INFO" "=== Example 2: Organization Scope Assessment ==="
    
    # Set organization scope (normally from CLI arguments)
    export SCOPE="organization"
    export ORG_ID="${ORG_ID:-123456789012}"  # Use provided ORG_ID or default
    
    # Validate authentication
    if ! validate_authentication_setup; then
        print_status "FAIL" "Authentication validation failed"
        return 1
    fi
    
    # Detect and validate scope
    if ! detect_and_validate_scope; then
        print_status "WARN" "Organization scope validation failed (expected with demo ORG_ID)"
        print_status "INFO" "In real usage, provide valid organization ID"
        return 0
    fi
    
    # Organization-level permissions
    local org_permissions=(
        "resourcemanager.organizations.get"
        "resourcemanager.projects.list"
        "iam.roles.list"
        "orgpolicy.policies.list"
        "cloudasset.assets.searchAllResources"
    )
    
    register_required_permissions "org" "${org_permissions[@]}"
    
    if validate_scope_permissions; then
        print_status "PASS" "Organization scope permissions validated"
    else
        print_status "WARN" "Organization scope validation issues detected"
    fi
    
    check_all_permissions
    log_permission_audit_trail
    
    return 0
}

# =============================================================================
# Example 3: Multi-Requirement Permission Aggregation
# =============================================================================

example_multi_requirement_check() {
    print_status "INFO" "=== Example 3: Multi-Requirement Permission Check ==="
    
    # Aggregate permissions from multiple PCI DSS requirements
    local all_permissions=(
        # Requirement 1: Network Security
        "compute.instances.list"
        "compute.firewalls.list"
        "compute.networks.list"
        
        # Requirement 3: Data Protection
        "cloudkms.cryptoKeys.list"
        "storage.buckets.list"
        "sql.instances.list"
        
        # Requirement 7: Access Control
        "iam.roles.list"
        "iam.serviceAccounts.list"
        "resourcemanager.projects.getIamPolicy"
        
        # Requirement 10: Logging
        "logging.logEntries.list"
        "monitoring.metricDescriptors.list"
    )
    
    register_required_permissions "multi" "${all_permissions[@]}"
    
    print_status "INFO" "Checking ${#all_permissions[@]} permissions across multiple requirements"
    
    check_all_permissions
    
    local coverage=$(get_permission_coverage)
    print_status "INFO" "Overall permission coverage: ${coverage}%"
    
    if [[ $coverage -ge 80 ]]; then
        print_status "PASS" "Excellent permission coverage for comprehensive assessment"
    elif [[ $coverage -ge 60 ]]; then
        print_status "WARN" "Good permission coverage - some limitations expected"
    else
        print_status "WARN" "Limited permission coverage - assessment will be restricted"
        display_permission_guidance
    fi
    
    return 0
}

# =============================================================================
# Example 4: Service Account vs User Authentication
# =============================================================================

example_authentication_patterns() {
    print_status "INFO" "=== Example 4: Authentication Pattern Detection ==="
    
    # Validate and detect authentication type
    if validate_authentication_setup; then
        print_status "INFO" "Authentication Type: $AUTH_TYPE"
        print_status "INFO" "Detected Scope: ${DETECTED_SCOPE:-not detected}"
        
        case "$AUTH_TYPE" in
            "service_account")
                print_status "INFO" "Service account authentication detected"
                print_status "INFO" "Recommended for automated assessments"
                ;;
            "user_credential")
                print_status "INFO" "User credential authentication detected"
                print_status "INFO" "Suitable for interactive assessments"
                ;;
            *)
                print_status "WARN" "Unknown authentication type"
                ;;
        esac
    else
        print_status "FAIL" "Authentication validation failed"
        print_status "INFO" "Please run: gcloud auth login"
        return 1
    fi
    
    return 0
}

# =============================================================================
# Example 5: Error Handling and Recovery
# =============================================================================

example_error_handling() {
    print_status "INFO" "=== Example 5: Error Handling and Recovery ==="
    
    # Simulate missing permissions scenario
    local test_permissions=(
        "compute.instances.list"
        "nonexistent.permission.test"  # This will fail
        "iam.roles.list"
    )
    
    register_required_permissions "test" "${test_permissions[@]}"
    
    print_status "INFO" "Testing error handling with invalid permission"
    
    # This should show some failures
    if ! check_all_permissions; then
        print_status "INFO" "Permission check failed as expected"
        
        local coverage=$(get_permission_coverage)
        print_status "INFO" "Coverage: ${coverage}%"
        
        # Show how to handle different coverage levels
        if [[ $coverage -ge 75 ]]; then
            print_status "INFO" "High coverage - continue with minor limitations"
        elif [[ $coverage -ge 50 ]]; then
            print_status "INFO" "Moderate coverage - continue with some limitations"
        elif [[ $coverage -ge 25 ]]; then
            print_status "WARN" "Low coverage - major limitations expected"
        else
            print_status "FAIL" "Very low coverage - assessment may not be meaningful"
        fi
    fi
    
    return 0
}

# =============================================================================
# Main Execution
# =============================================================================

show_usage() {
    cat << EOF
GCP Permissions Library Usage Examples

USAGE:
    $0 [OPTIONS] [EXAMPLE]

OPTIONS:
    -s, --scope SCOPE       Assessment scope (project|organization)
    -p, --project ID        Project ID or Organization ID
    -v, --verbose           Enable verbose output
    -h, --help              Show this help

EXAMPLES:
    basic                   Basic permission check for single requirement
    organization           Organization scope assessment
    multi                  Multi-requirement permission aggregation
    auth                   Authentication pattern detection
    error                  Error handling and recovery patterns
    all                    Run all examples

EXAMPLES USAGE:
    $0 basic                # Run basic permission check
    $0 -v organization      # Run organization example with verbose output
    $0 -s project -p my-project-id multi  # Multi-requirement check for specific project
    $0 all                  # Run all examples
EOF
}

main() {
    # Parse arguments
    local example="basic"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--scope)
                SCOPE="$2"
                shift 2
                ;;
            -p|--project)
                if [[ "$SCOPE" == "organization" ]]; then
                    ORG_ID="$2"
                else
                    PROJECT_ID="$2"
                fi
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_usage
                return 0
                ;;
            *)
                example="$1"
                shift
                ;;
        esac
    done
    
    print_status "INFO" "GCP Permissions Library Usage Examples"
    print_status "INFO" "========================================"
    echo
    
    case "$example" in
        "basic")
            example_basic_permission_check
            ;;
        "organization")
            example_organization_assessment
            ;;
        "multi")
            example_multi_requirement_check
            ;;
        "auth")
            example_authentication_patterns
            ;;
        "error")
            example_error_handling
            ;;
        "all")
            example_basic_permission_check
            echo
            example_organization_assessment
            echo
            example_multi_requirement_check
            echo
            example_authentication_patterns
            echo
            example_error_handling
            ;;
        *)
            print_status "FAIL" "Unknown example: $example"
            show_usage
            return 1
            ;;
    esac
    
    echo
    print_status "INFO" "Example execution completed"
    
    # Clean up
    cleanup_temp_files
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi