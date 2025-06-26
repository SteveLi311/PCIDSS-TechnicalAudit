#!/bin/bash

# =============================================================================
# GCP Common Library - Core Shared Functions
# =============================================================================
# Description: Core shared library for GCP PCI DSS assessment scripts
# Version: 1.0
# Author: PCI DSS Assessment Framework
# Created: 2025-06-05
# =============================================================================

# Global Variables for Library State
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$(dirname "$SCRIPT_DIR")/lib"
GCP_COMMON_LOADED="true"

# Color Variables for Terminal Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global Configuration Variables
SCOPE=""
SCOPE_TYPE="project"
PROJECT_ID=""
ORG_ID=""
OUTPUT_DIR=""
VERBOSE=false
LOG_FILE=""
REPORT_ONLY=false

# Assessment Counters
passed_checks=0
failed_checks=0
total_projects=0

# =============================================================================
# Core Library Loading Functions
# =============================================================================

# Load all required libraries
# Usage: source_gcp_libraries
# Returns: 0 on success, 1 on error
source_gcp_libraries() {
    local lib_path="${LIB_DIR:-$(dirname "$0")/lib}"
    
    # Verify library directory exists
    if [[ ! -d "$lib_path" ]]; then
        echo -e "${RED}Error: Library directory not found at $lib_path${NC}" >&2
        return 1
    fi
    
    # Set global library path variable
    export GCP_LIB_PATH="$lib_path"
    
    # Load gcp_common.sh if not already loaded
    if [[ "$GCP_COMMON_LOADED" != "true" ]]; then
        if [[ -f "$lib_path/gcp_common.sh" ]]; then
            source "$lib_path/gcp_common.sh"
            export GCP_COMMON_LOADED="true"
        else
            echo -e "${RED}Error: gcp_common.sh not found${NC}" >&2
            return 1
        fi
    fi
    
    # Load additional libraries as they become available
    for lib_file in "$lib_path"/*.sh; do
        if [[ -f "$lib_file" && "$lib_file" != "$lib_path/gcp_common.sh" ]]; then
            source "$lib_file" || {
                echo -e "${YELLOW}Warning: Failed to load library $(basename "$lib_file")${NC}" >&2
            }
        fi
    done
    
    return 0
}

# =============================================================================
# Environment Management Functions
# =============================================================================

# Initialize colors, variables, directories
# Usage: setup_environment [log_file]
# Returns: 0 on success, 1 on error
setup_environment() {
    local log_file="${1:-}"
    
    # Initialize color variables (already defined above)
    export RED GREEN YELLOW BLUE CYAN NC
    
    # Set default directories (using WORK_DIR pattern from architecture)
    export WORK_DIR="${TMPDIR:-/tmp}/gcp_pci_assessment_$$"
    export REPORT_DIR="${OUTPUT_DIR:-$(pwd)/reports}"
    export LOG_DIR="${OUTPUT_DIR:-$(pwd)/logs}"
    
    # Create required directories
    for dir in "$REPORT_DIR" "$LOG_DIR" "$WORK_DIR"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir" || {
                echo -e "${RED}Error: Failed to create directory $dir${NC}" >&2
                return 1
            }
        fi
    done
    
    # Set up logging
    if [[ -n "$log_file" ]]; then
        export LOG_FILE="$LOG_DIR/$log_file"
        touch "$LOG_FILE" || {
            echo -e "${RED}Error: Failed to create log file $LOG_FILE${NC}" >&2
            return 1
        }
    fi
    
    # Set script execution defaults
    export SCRIPT_START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
    export SCRIPT_PID=$$
    
    return 0
}

# =============================================================================
# CLI Argument Processing Functions
# =============================================================================

# Standard CLI parsing (-s, -p, -o, -h)
# Usage: parse_common_arguments "$@"
# Returns: 0 on success, 1 on error, 2 if help displayed
parse_common_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--scope)
                SCOPE="$2"
                SCOPE_TYPE="$2"
                if [[ "$SCOPE" != "project" && "$SCOPE" != "organization" ]]; then
                    echo -e "${RED}Error: Scope must be 'project' or 'organization'${NC}" >&2
                    return 1
                fi
                shift 2
                ;;
            -p|--project)
                if [[ "$SCOPE_TYPE" == "organization" ]]; then
                    ORG_ID="$2"
                else
                    PROJECT_ID="$2"
                fi
                if [[ -z "$2" ]]; then
                    echo -e "${RED}Error: Project/Organization ID cannot be empty${NC}" >&2
                    return 1
                fi
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                if [[ -z "$OUTPUT_DIR" ]]; then
                    echo -e "${RED}Error: Output directory cannot be empty${NC}" >&2
                    return 1
                fi
                shift 2
                ;;
            -r|--report-only)
                REPORT_ONLY=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                return 2
                ;;
            *)
                echo -e "${RED}Error: Unknown option $1${NC}" >&2
                echo "Use -h or --help for usage information"
                return 1
                ;;
        esac
    done
    
    # Export parsed variables
    export SCOPE SCOPE_TYPE PROJECT_ID ORG_ID OUTPUT_DIR VERBOSE REPORT_ONLY
    export passed_checks failed_checks total_projects
    
    # Set defaults if not provided
    if [[ -z "$SCOPE" ]]; then
        SCOPE="project"
        export SCOPE
    fi
    
    return 0
}

# Display help information and usage examples
# Usage: show_help
show_help() {
    cat << EOF
${BLUE}GCP PCI DSS Assessment Script${NC}

${CYAN}USAGE:${NC}
    $0 [OPTIONS]

${CYAN}OPTIONS:${NC}
    -s, --scope SCOPE       Assessment scope (project|organization) [default: project]
    -p, --project ID        Target project ID or organization ID
    -o, --output DIR        Output directory for reports [default: ./reports]
    -r, --report-only       Generate reports only, skip assessments
    -v, --verbose           Enable verbose output
    -h, --help              Display this help message

${CYAN}EXAMPLES:${NC}
    # Assess a specific project
    $0 -s project -p my-project-id -o ./reports

    # Assess organization with verbose output
    $0 -s organization -p my-org-id -v

    # Use default settings (current project)
    $0

${CYAN}REQUIREMENTS:${NC}
    - gcloud CLI tool installed and authenticated
    - jq tool for JSON processing
    - Appropriate GCP permissions for assessment scope

EOF
}

# =============================================================================
# Validation Functions
# =============================================================================

# Check gcloud, permissions, connectivity
# Usage: validate_prerequisites
# Returns: 0 on success, 1 on error
validate_prerequisites() {
    local error_count=0
    
    print_status "INFO" "Validating prerequisites..."
    
    # Check for required tools
    for tool in gcloud jq curl; do
        if ! command -v "$tool" &> /dev/null; then
            print_status "FAIL" "Required tool '$tool' not found"
            ((error_count++))
        else
            print_status "PASS" "Tool '$tool' found"
        fi
    done
    
    # Check gcloud authentication
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
        print_status "FAIL" "gcloud not authenticated. Run 'gcloud auth login'"
        ((error_count++))
    else
        local active_account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1)
        print_status "PASS" "gcloud authenticated as: $active_account"
    fi
    
    # Test basic GCP API connectivity
    if ! gcloud projects list --limit=1 --format="value(projectId)" &> /dev/null; then
        print_status "FAIL" "Cannot connect to GCP APIs. Check authentication and network"
        ((error_count++))
    else
        print_status "PASS" "GCP API connectivity verified"
    fi
    
    # Validate project access if PROJECT_ID is set
    if [[ -n "$PROJECT_ID" ]]; then
        if ! gcloud projects describe "$PROJECT_ID" &> /dev/null; then
            print_status "FAIL" "Cannot access project '$PROJECT_ID'. Check permissions"
            ((error_count++))
        else
            print_status "PASS" "Project '$PROJECT_ID' accessible"
        fi
    fi
    
    if [[ $error_count -gt 0 ]]; then
        print_status "FAIL" "Prerequisites validation failed with $error_count errors"
        return 1
    fi
    
    print_status "PASS" "All prerequisites validated successfully"
    return 0
}

# =============================================================================
# Output and Logging Functions
# =============================================================================

# Colored output formatting
# Usage: print_status LEVEL MESSAGE
# Levels: info, success, warning, error
# Returns: 0 always
print_status() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local prefix=""
    local color=""
    
    case "$level" in
        "INFO")
            prefix="[INFO]"
            color="$BLUE"
            ;;
        "PASS")
            prefix="[PASS]"
            color="$GREEN"
            ;;
        "WARN")
            prefix="[WARN]"
            color="$YELLOW"
            ;;
        "FAIL")
            prefix="[FAIL]"
            color="$RED"
            ;;
        # Backward compatibility aliases
        "info")
            prefix="[INFO]"
            color="$BLUE"
            ;;
        "success")
            prefix="[PASS]"
            color="$GREEN"
            ;;
        "warning")
            prefix="[WARN]"
            color="$YELLOW"
            ;;
        "error")
            prefix="[FAIL]"
            color="$RED"
            ;;
        *)
            prefix="[INFO]"
            color="$NC"
            ;;
    esac
    
    local formatted_message="${color}${prefix}${NC} $message"
    
    # Output to console
    echo -e "$formatted_message"
    
    # Output to log file if configured
    if [[ -n "$LOG_FILE" ]]; then
        echo "[$timestamp] $prefix $message" >> "$LOG_FILE"
    fi
    
    # Handle verbose output
    if [[ "$VERBOSE" == "true" && ("$level" == "info" || "$level" == "INFO") ]]; then
        echo -e "  ${CYAN}Debug:${NC} $message" >&2
    fi
    
    return 0
}

# Log function for detailed debugging
# Usage: log_debug MESSAGE
log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        print_status "INFO" "DEBUG: $1"
    fi
}

# =============================================================================
# Configuration Management Functions
# =============================================================================

# Load requirement-specific configuration
# Usage: load_requirement_config [requirement_number|config_file_path]
# Returns: 0 on success, 1 on error
load_requirement_config() {
    local requirement="${1:-}"
    local config_file=""
    
    if [[ -z "$requirement" ]]; then
        print_status "WARN" "No requirement specified for configuration loading"
        return 0
    fi
    
    # Determine config file path
    if [[ -f "$requirement" ]]; then
        config_file="$requirement"
    elif [[ "$requirement" =~ ^[0-9]+$ ]]; then
        config_file="$(dirname "$LIB_DIR")/config/requirement_${requirement}.conf"
    else
        config_file="$(dirname "$LIB_DIR")/config/${requirement}.conf"
    fi
    
    # Check if config file exists
    if [[ ! -f "$config_file" ]]; then
        print_status "WARN" "Configuration file not found: $config_file"
        return 1
    fi
    
    print_status "INFO" "Loading configuration from: $config_file"
    
    # Source the configuration file
    if source "$config_file"; then
        print_status "PASS" "Configuration loaded successfully"
        return 0
    else
        print_status "FAIL" "Failed to load configuration file: $config_file"
        return 1
    fi
}

# =============================================================================
# Utility Functions
# =============================================================================

# Check if script is being run with appropriate permissions
# Usage: check_script_permissions
check_script_permissions() {
    if [[ $EUID -eq 0 ]]; then
        print_status "WARN" "Running as root - consider using regular user account"
    fi
    return 0
}

# Clean up temporary files and directories
# Usage: cleanup_temp_files
cleanup_temp_files() {
    if [[ -d "$WORK_DIR" ]]; then
        print_status "INFO" "Cleaning up temporary files..."
        rm -rf "$WORK_DIR"/* 2>/dev/null || true
    fi
    return 0
}

# Get current script name for logging
# Usage: get_script_name
get_script_name() {
    basename "${BASH_SOURCE[1]:-$0}"
}

# =============================================================================
# Library Initialization
# =============================================================================

# Auto-initialize environment when library is sourced
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    # Library is being sourced, not executed directly
    log_debug "gcp_common.sh library loaded"
fi

# Export all functions for use in other scripts
export -f source_gcp_libraries
export -f setup_environment
export -f parse_common_arguments
export -f show_help
export -f validate_prerequisites
export -f print_status
export -f log_debug
export -f load_requirement_config
export -f check_script_permissions
export -f cleanup_temp_files
export -f get_script_name

# Mark library as loaded
export GCP_COMMON_LOADED="true"

print_status "PASS" "GCP Common Library v1.0 loaded successfully"