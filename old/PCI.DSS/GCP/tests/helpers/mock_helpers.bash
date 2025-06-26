#!/bin/bash

# =============================================================================
# Mock Helper Functions for GCP Command and API Simulation
# =============================================================================

# Global mock state
MOCK_USER_INPUT_SEQUENCE=()
MOCK_USER_INPUT_INDEX=0

# =============================================================================
# Command Mocking Functions
# =============================================================================

# Mock successful command availability
mock_command_success() {
    local command="$1"
    eval "${command}() { return 0; }"
    export -f "${command}"
}

# Mock missing command
mock_command_missing() {
    local command="$1"
    eval "${command}() { return 127; }"
    export -f "${command}"
}

# Mock command with specific output
mock_command_with_output() {
    local command="$1"
    local output="$2"
    local exit_code="${3:-0}"
    
    eval "${command}() { echo '$output'; return $exit_code; }"
    export -f "${command}"
}

# =============================================================================
# GCP-Specific Mocking Functions
# =============================================================================

# Set up basic GCP environment mocking
setup_mock_gcp_environment() {
    # Create mock directory if it doesn't exist
    mkdir -p "$TEST_MOCKS_DIR"
    
    # Set up mock gcloud command
    create_mock_gcloud_command
    
    # Add mock directory to PATH
    export PATH="$TEST_MOCKS_DIR:$PATH"
    
    # Set default GCP environment variables
    export GOOGLE_CLOUD_PROJECT="${MOCK_PROJECT_ID:-test-project-123}"
    export GCLOUD_PROJECT="${MOCK_PROJECT_ID:-test-project-123}"
}

# Create comprehensive mock gcloud command
create_mock_gcloud_command() {
    cat > "$TEST_MOCKS_DIR/gcloud" << 'EOF'
#!/bin/bash

# Mock gcloud command for testing
# Simulates various GCP API responses based on command structure

# Parse command arguments
COMMAND_TYPE=""
RESOURCE_TYPE=""
ACTION=""

case "$1" in
    "compute")
        COMMAND_TYPE="compute"
        RESOURCE_TYPE="$2"
        ACTION="$3"
        ;;
    "config")
        COMMAND_TYPE="config"
        ACTION="$2"
        ;;
    "auth")
        COMMAND_TYPE="auth"
        ACTION="$2"
        ;;
    *)
        COMMAND_TYPE="unknown"
        ;;
esac

# Handle different mock scenarios
if [[ "$MOCK_AUTH_FAILURE" == "true" ]]; then
    echo "ERROR: Authentication failed" >&2
    exit 1
fi

if [[ "$MOCK_API_FAILURE" == "true" ]]; then
    echo "ERROR: API request failed" >&2
    exit 1
fi

if [[ "$MOCK_PERMISSION_DENIED" == "true" ]]; then
    echo "ERROR: Permission denied" >&2
    exit 1
fi

# Generate mock responses based on command type
case "$COMMAND_TYPE" in
    "compute")
        case "$RESOURCE_TYPE" in
            "networks")
                if [[ "$ACTION" == "list" ]]; then
                    echo '[
                        {
                            "name": "test-vpc-network",
                            "autoCreateSubnetworks": false,
                            "routingConfig": {"routingMode": "REGIONAL"},
                            "selfLink": "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/test-vpc-network"
                        },
                        {
                            "name": "default",
                            "autoCreateSubnetworks": true,
                            "routingConfig": {"routingMode": "GLOBAL"},
                            "selfLink": "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default"
                        }
                    ]'
                fi
                ;;
            "firewalls")
                if [[ "$ACTION" == "list" ]]; then
                    echo '[
                        {
                            "name": "default-allow-internal",
                            "direction": "INGRESS",
                            "priority": 65534,
                            "network": "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
                            "allowed": [
                                {"IPProtocol": "tcp", "ports": ["0-65535"]},
                                {"IPProtocol": "udp", "ports": ["0-65535"]},
                                {"IPProtocol": "icmp"}
                            ],
                            "sourceRanges": ["10.128.0.0/9"]
                        },
                        {
                            "name": "default-allow-ssh",
                            "direction": "INGRESS",
                            "priority": 65534,
                            "network": "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
                            "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                            "sourceRanges": ["0.0.0.0/0"]
                        }
                    ]'
                fi
                ;;
            "instances")
                if [[ "$ACTION" == "list" ]]; then
                    echo '[
                        {
                            "name": "test-instance-1",
                            "zone": "us-central1-a",
                            "status": "RUNNING",
                            "networkInterfaces": [
                                {
                                    "network": "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/default",
                                    "subnetwork": "https://www.googleapis.com/compute/v1/projects/test-project/regions/us-central1/subnetworks/default"
                                }
                            ]
                        }
                    ]'
                fi
                ;;
            *)
                echo '[]'
                ;;
        esac
        ;;
    "config")
        case "$ACTION" in
            "get-value")
                if [[ "$3" == "project" ]]; then
                    echo "${GOOGLE_CLOUD_PROJECT:-test-project-123}"
                else
                    echo "unknown-config-value"
                fi
                ;;
            *)
                echo "Configuration updated"
                ;;
        esac
        ;;
    "auth")
        echo "Authentication successful"
        ;;
    *)
        echo "{}"
        ;;
esac

exit 0
EOF
    
    chmod +x "$TEST_MOCKS_DIR/gcloud"
}

# Create mock that exits early for argument testing
create_mock_gcloud_with_early_exit() {
    cat > "$TEST_MOCKS_DIR/gcloud" << 'EOF'
#!/bin/bash
# Early exit mock for testing argument parsing
exit 0
EOF
    chmod +x "$TEST_MOCKS_DIR/gcloud"
}

# Mock command failure
mock_command_failure() {
    local command="$1"
    local exit_code="${2:-1}"
    eval "${command}() { return $exit_code; }"
    export -f "${command}"
}

# =============================================================================
# GCloud Command Mocking Functions
# =============================================================================

# Mock gcloud authentication as active
mock_gcloud_auth_active() {
    gcloud() {
        case "$*" in
            "auth list --filter=status:ACTIVE --format=value(account)")
                echo "test-user@example.com"
                return 0
                ;;
            *)
                echo "Mock gcloud: $*" >&2
                return 0
                ;;
        esac
    }
    export -f gcloud
}

# Mock gcloud authentication as inactive
mock_gcloud_auth_inactive() {
    gcloud() {
        case "$*" in
            "auth list --filter=status:ACTIVE --format=value(account)")
                return 1
                ;;
            *)
                echo "Mock gcloud: $*" >&2
                return 1
                ;;
        esac
    }
    export -f gcloud
}

# Mock gcloud projects list success
mock_gcloud_projects_list() {
    local existing_gcloud_func=""
    if declare -F gcloud >/dev/null; then
        existing_gcloud_func=$(declare -f gcloud)
    fi
    
    gcloud() {
        case "$*" in
            "projects list --limit=1 --format=value(projectId)")
                echo "test-project-123"
                return 0
                ;;
            *)
                if [[ -n "$existing_gcloud_func" ]]; then
                    eval "$existing_gcloud_func"
                    gcloud "$@"
                else
                    echo "Mock gcloud: $*" >&2
                    return 0
                fi
                ;;
        esac
    }
    export -f gcloud
}

# Mock gcloud project describe success
mock_gcloud_project_describe_success() {
    local project_id="$1"
    local existing_gcloud_func=""
    if declare -F gcloud >/dev/null; then
        existing_gcloud_func=$(declare -f gcloud)
    fi
    
    gcloud() {
        case "$*" in
            "projects describe $project_id")
                cat << EOF
name: projects/$project_id
projectId: $project_id
projectNumber: '123456789012'
lifecycleState: ACTIVE
createTime: '2023-01-01T00:00:00.000Z'
EOF
                return 0
                ;;
            *)
                if [[ -n "$existing_gcloud_func" ]]; then
                    eval "$existing_gcloud_func"
                    gcloud "$@"
                else
                    echo "Mock gcloud: $*" >&2
                    return 0
                fi
                ;;
        esac
    }
    export -f gcloud
}

# Mock gcloud project describe failure
mock_gcloud_project_describe_failure() {
    local project_id="$1"
    local existing_gcloud_func=""
    if declare -F gcloud >/dev/null; then
        existing_gcloud_func=$(declare -f gcloud)
    fi
    
    gcloud() {
        case "$*" in
            "projects describe $project_id")
                echo "ERROR: (gcloud.projects.describe) Project [$project_id] not found or access denied." >&2
                return 1
                ;;
            *)
                if [[ -n "$existing_gcloud_func" ]]; then
                    eval "$existing_gcloud_func"
                    gcloud "$@"
                else
                    echo "Mock gcloud: $*" >&2
                    return 0
                fi
                ;;
        esac
    }
    export -f gcloud
}

# Mock gcloud organization describe success
mock_gcloud_organization_describe_success() {
    local org_id="$1"
    local existing_gcloud_func=""
    if declare -F gcloud >/dev/null; then
        existing_gcloud_func=$(declare -f gcloud)
    fi
    
    gcloud() {
        case "$*" in
            "organizations describe $org_id")
                cat << EOF
name: organizations/$org_id
organizationId: '$org_id'
displayName: Test Organization
lifecycleState: ACTIVE
creationTime: '2023-01-01T00:00:00.000Z'
EOF
                return 0
                ;;
            *)
                if [[ -n "$existing_gcloud_func" ]]; then
                    eval "$existing_gcloud_func"
                    gcloud "$@"
                else
                    echo "Mock gcloud: $*" >&2
                    return 0
                fi
                ;;
        esac
    }
    export -f gcloud
}

# Mock gcloud organization describe failure
mock_gcloud_organization_describe_failure() {
    local org_id="$1"
    local existing_gcloud_func=""
    if declare -F gcloud >/dev/null; then
        existing_gcloud_func=$(declare -f gcloud)
    fi
    
    gcloud() {
        case "$*" in
            "organizations describe $org_id")
                echo "ERROR: (gcloud.organizations.describe) Organization [$org_id] not found or access denied." >&2
                return 1
                ;;
            *)
                if [[ -n "$existing_gcloud_func" ]]; then
                    eval "$existing_gcloud_func"
                    gcloud "$@"
                else
                    echo "Mock gcloud: $*" >&2
                    return 0
                fi
                ;;
        esac
    }
    export -f gcloud
}

# Mock gcloud IAM permissions test success
mock_gcloud_test_iam_permissions_success() {
    local project_id="$1"
    shift
    local permissions=("$@")
    local existing_gcloud_func=""
    if declare -F gcloud >/dev/null; then
        existing_gcloud_func=$(declare -f gcloud)
    fi
    
    gcloud() {
        case "$*" in
            "projects test-iam-permissions $project_id --permissions="*" --format=value(permissions)")
                # Extract permissions from command line
                local cmd_permissions=$(echo "$*" | sed -n 's/.*--permissions=\([^ ]*\).*/\1/p')
                echo "$cmd_permissions"
                return 0
                ;;
            *)
                if [[ -n "$existing_gcloud_func" ]]; then
                    eval "$existing_gcloud_func"
                    gcloud "$@"
                else
                    echo "Mock gcloud: $*" >&2
                    return 0
                fi
                ;;
        esac
    }
    export -f gcloud
}

# Mock gcloud IAM permissions test failure
mock_gcloud_test_iam_permissions_failure() {
    local project_id="$1"
    local existing_gcloud_func=""
    if declare -F gcloud >/dev/null; then
        existing_gcloud_func=$(declare -f gcloud)
    fi
    
    gcloud() {
        case "$*" in
            "projects test-iam-permissions $project_id --permissions="*" --format=value(permissions)")
                # Return empty - no permissions available
                return 0
                ;;
            *)
                if [[ -n "$existing_gcloud_func" ]]; then
                    eval "$existing_gcloud_func"
                    gcloud "$@"
                else
                    echo "Mock gcloud: $*" >&2
                    return 0
                fi
                ;;
        esac
    }
    export -f gcloud
}

# Mock gcloud IAM permissions test with mixed results
mock_gcloud_test_iam_permissions_mixed() {
    local project_id="$1"
    local available_permission="$2"
    local existing_gcloud_func=""
    if declare -F gcloud >/dev/null; then
        existing_gcloud_func=$(declare -f gcloud)
    fi
    
    gcloud() {
        case "$*" in
            "projects test-iam-permissions $project_id --permissions="*" --format=value(permissions)")
                # Extract permissions from command line
                local cmd_permissions=$(echo "$*" | sed -n 's/.*--permissions=\([^ ]*\).*/\1/p')
                if [[ "$cmd_permissions" == "$available_permission" ]]; then
                    echo "$available_permission"
                fi
                return 0
                ;;
            *)
                if [[ -n "$existing_gcloud_func" ]]; then
                    eval "$existing_gcloud_func"
                    gcloud "$@"
                else
                    echo "Mock gcloud: $*" >&2
                    return 0
                fi
                ;;
        esac
    }
    export -f gcloud
}

# Mock gcloud access token check
mock_gcloud_access_token() {
    local existing_gcloud_func=""
    if declare -F gcloud >/dev/null; then
        existing_gcloud_func=$(declare -f gcloud)
    fi
    
    gcloud() {
        case "$*" in
            "auth print-access-token")
                echo "ya29.mock-access-token-here"
                return 0
                ;;
            *)
                if [[ -n "$existing_gcloud_func" ]]; then
                    eval "$existing_gcloud_func"
                    gcloud "$@"
                else
                    echo "Mock gcloud: $*" >&2
                    return 0
                fi
                ;;
        esac
    }
    export -f gcloud
}

# =============================================================================
# Comprehensive Mock Setup Functions
# =============================================================================

# Mock all prerequisites as successful
mock_all_prerequisites_success() {
    mock_command_success "gcloud"
    mock_command_success "jq"
    mock_command_success "curl"
    mock_gcloud_auth_active
    mock_gcloud_projects_list
    mock_gcloud_access_token
}

# Mock all prerequisites as failed
mock_all_prerequisites_failure() {
    mock_command_missing "gcloud"
    mock_command_missing "jq"
    mock_command_missing "curl"
}

# =============================================================================
# User Input Mocking Functions
# =============================================================================

# Mock single user input
mock_user_input() {
    local input="$1"
    
    read() {
        if [[ "$*" =~ -p ]]; then
            # Extract prompt and display it
            local prompt=$(echo "$*" | sed -n 's/.*-p *"\([^"]*\)".*/\1/p')
            if [[ -n "$prompt" ]]; then
                echo -n "$prompt" >&2
            fi
        fi
        
        # Set the response variable
        if [[ "$*" =~ [[:space:]]([a-zA-Z_][a-zA-Z0-9_]*)[[:space:]]*$ ]]; then
            local var_name="${BASH_REMATCH[1]}"
            eval "$var_name='$input'"
        else
            # Default to 'response' if no variable specified
            response="$input"
        fi
        
        echo "$input" >&2
        return 0
    }
    export -f read
}

# Mock sequence of user inputs
mock_user_input_sequence() {
    MOCK_USER_INPUT_SEQUENCE=("$@")
    MOCK_USER_INPUT_INDEX=0
    
    read() {
        if [[ "$*" =~ -p ]]; then
            # Extract prompt and display it
            local prompt=$(echo "$*" | sed -n 's/.*-p *"\([^"]*\)".*/\1/p')
            if [[ -n "$prompt" ]]; then
                echo -n "$prompt" >&2
            fi
        fi
        
        # Get current input from sequence
        local current_input=""
        if [[ $MOCK_USER_INPUT_INDEX -lt ${#MOCK_USER_INPUT_SEQUENCE[@]} ]]; then
            current_input="${MOCK_USER_INPUT_SEQUENCE[$MOCK_USER_INPUT_INDEX]}"
            ((MOCK_USER_INPUT_INDEX++))
        fi
        
        # Set the response variable
        if [[ "$*" =~ [[:space:]]([a-zA-Z_][a-zA-Z0-9_]*)[[:space:]]*$ ]]; then
            local var_name="${BASH_REMATCH[1]}"
            eval "$var_name='$current_input'"
        else
            # Default to 'response' if no variable specified
            response="$current_input"
        fi
        
        echo "$current_input" >&2
        return 0
    }
    export -f read
}

# Reset user input mocking
reset_user_input_mock() {
    unset -f read
    MOCK_USER_INPUT_SEQUENCE=()
    MOCK_USER_INPUT_INDEX=0
}

# =============================================================================
# File System Mocking Functions
# =============================================================================

# Mock file existence check
mock_file_exists() {
    local file_path="$1"
    local should_exist="${2:-true}"
    
    local original_test=""
    if declare -F test >/dev/null; then
        original_test=$(declare -f test)
    fi
    
    test() {
        if [[ "$*" == "-f $file_path" ]]; then
            if [[ "$should_exist" == "true" ]]; then
                return 0
            else
                return 1
            fi
        elif [[ -n "$original_test" ]]; then
            eval "$original_test"
            test "$@"
        else
            # Default test behavior
            builtin test "$@"
        fi
    }
    export -f test
}

# Mock directory existence check
mock_directory_exists() {
    local dir_path="$1"
    local should_exist="${2:-true}"
    
    local original_test=""
    if declare -F test >/dev/null; then
        original_test=$(declare -f test)
    fi
    
    test() {
        if [[ "$*" == "-d $dir_path" ]]; then
            if [[ "$should_exist" == "true" ]]; then
                return 0
            else
                return 1
            fi
        elif [[ -n "$original_test" ]]; then
            eval "$original_test"
            test "$@"
        else
            # Default test behavior
            builtin test "$@"
        fi
    }
    export -f test
}

# =============================================================================
# JSON Processing Mocking Functions
# =============================================================================

# Mock jq command success
mock_jq_success() {
    local output="$1"
    
    jq() {
        echo "$output"
        return 0
    }
    export -f jq
}

# Mock jq command failure
mock_jq_failure() {
    jq() {
        echo "jq: error: mock failure" >&2
        return 1
    }
    export -f jq
}

# =============================================================================
# Network Mocking Functions
# =============================================================================

# Mock curl success
mock_curl_success() {
    local response="$1"
    local status_code="${2:-200}"
    
    curl() {
        echo "$response"
        return 0
    }
    export -f curl
}

# Mock curl failure
mock_curl_failure() {
    local error_message="${1:-curl: (7) Failed to connect}"
    
    curl() {
        echo "$error_message" >&2
        return 7
    }
    export -f curl
}

# =============================================================================
# Mock Data Generation Functions
# =============================================================================

# Generate mock GCP project response
generate_mock_project_response() {
    local project_id="$1"
    local project_name="${2:-Test Project}"
    local project_number="${3:-123456789012}"
    
    cat << EOF
{
  "projectId": "$project_id",
  "name": "$project_name",
  "projectNumber": "$project_number",
  "lifecycleState": "ACTIVE",
  "createTime": "2023-01-01T00:00:00.000Z"
}
EOF
}

# Generate mock IAM permissions response
generate_mock_permissions_response() {
    local permissions=("$@")
    local permissions_json=""
    
    for perm in "${permissions[@]}"; do
        if [[ -n "$permissions_json" ]]; then
            permissions_json+=","
        fi
        permissions_json+="\"$perm\""
    done
    
    cat << EOF
{
  "permissions": [$permissions_json]
}
EOF
}

# Generate mock organization response
generate_mock_organization_response() {
    local org_id="$1"
    local display_name="${2:-Test Organization}"
    
    cat << EOF
{
  "name": "organizations/$org_id",
  "organizationId": "$org_id",
  "displayName": "$display_name",
  "lifecycleState": "ACTIVE",
  "creationTime": "2023-01-01T00:00:00.000Z"
}
EOF
}

# =============================================================================
# Mock State Management Functions
# =============================================================================

# Save current function definitions
save_function_state() {
    local functions_to_save=("$@")
    
    for func in "${functions_to_save[@]}"; do
        if declare -F "$func" >/dev/null; then
            declare -f "$func" > "$TEST_TMPDIR/saved_${func}.bash"
        fi
    done
}

# Restore saved function definitions
restore_function_state() {
    local functions_to_restore=("$@")
    
    for func in "${functions_to_restore[@]}"; do
        if [[ -f "$TEST_TMPDIR/saved_${func}.bash" ]]; then
            source "$TEST_TMPDIR/saved_${func}.bash"
        fi
    done
}

# Clear all mocks
clear_all_mocks() {
    # Clear command mocks
    unset -f gcloud jq curl read test
    
    # Reset user input state
    MOCK_USER_INPUT_SEQUENCE=()
    MOCK_USER_INPUT_INDEX=0
    
    # Clear any environment variables set by mocks
    unset MOCK_GCLOUD_AUTH_ACTIVE MOCK_PROJECT_ID MOCK_ORG_ID
}

# =============================================================================
# Debugging and Verification Functions
# =============================================================================

# Verify mock function is active
verify_mock_active() {
    local function_name="$1"
    
    if declare -F "$function_name" >/dev/null; then
        echo "Mock for '$function_name' is active"
        return 0
    else
        echo "Mock for '$function_name' is NOT active" >&2
        return 1
    fi
}

# List all active mocks
list_active_mocks() {
    echo "Active mock functions:"
    for func in gcloud jq curl read test; do
        if declare -F "$func" >/dev/null; then
            echo "  - $func"
        fi
    done
}

# Export all mock functions
export -f mock_command_success mock_command_missing mock_command_with_output mock_command_failure
export -f setup_mock_gcp_environment create_mock_gcloud_command create_mock_gcloud_with_early_exit
export -f mock_gcloud_auth_active mock_gcloud_auth_inactive mock_gcloud_projects_list
export -f mock_gcloud_project_describe_success mock_gcloud_project_describe_failure
export -f mock_gcloud_organization_describe_success mock_gcloud_organization_describe_failure
export -f mock_gcloud_test_iam_permissions_success mock_gcloud_test_iam_permissions_failure
export -f mock_gcloud_test_iam_permissions_mixed mock_gcloud_access_token
export -f mock_all_prerequisites_success mock_all_prerequisites_failure
export -f mock_user_input mock_user_input_sequence reset_user_input_mock
export -f mock_file_exists mock_directory_exists
export -f mock_jq_success mock_jq_failure mock_curl_success mock_curl_failure
export -f generate_mock_project_response generate_mock_permissions_response generate_mock_organization_response
export -f save_function_state restore_function_state clear_all_mocks
export -f verify_mock_active list_active_mocks