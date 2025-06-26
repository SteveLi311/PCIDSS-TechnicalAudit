#!/usr/bin/env bash

# =============================================================================
# Optimized Library Loading Template
# Implements lazy loading and conditional loading strategies
# Target: <5% framework loading overhead
# =============================================================================

# Performance tracking
LOAD_START_TIME=$(date +%s.%N)

# Library directory
LIB_DIR="${LIB_DIR:-$(dirname "$0")/lib}"

# Function registry for lazy loading
declare -A FUNCTION_REGISTRY
declare -A LOADED_LIBRARIES

# Lazy loading function
load_function_on_demand() {
    local func_name="$1"
    
    # Check if function already loaded
    if declare -f "$func_name" >/dev/null 2>&1; then
        return 0
    fi
    
    # Check function registry
    if [[ -n "${FUNCTION_REGISTRY[$func_name]}" ]]; then
        local lib_file="${FUNCTION_REGISTRY[$func_name]}"
        if [[ -z "${LOADED_LIBRARIES[$lib_file]}" ]]; then
            source "$lib_file"
            LOADED_LIBRARIES["$lib_file"]=1
        fi
    else
        echo "WARNING: Function $func_name not found in registry" >&2
        return 1
    fi
}

# Build function registry (lightweight operation)
build_function_registry() {
    # Scan libraries for function definitions without loading them
    for lib_file in "$LIB_DIR"/*.sh; do
        if [[ -f "$lib_file" ]]; then
            while IFS= read -r line; do
                if [[ "$line" =~ ^[[:space:]]*([a-zA-Z_][a-zA-Z0-9_]*)[[:space:]]*\(\) ]]; then
                    local func_name="${BASH_REMATCH[1]}"
                    FUNCTION_REGISTRY["$func_name"]="$lib_file"
                fi
            done < "$lib_file"
        fi
    done
}

# Conditional library loading based on script type
load_libraries_conditional() {
    local script_type="${1:-full}"
    
    case "$script_type" in
        "minimal"|"basic")
            # Load only essential functions
            source "$LIB_DIR/gcp_common.sh"
            ;;
        "assessment"|"requirement")
            # Load assessment-specific libraries
            source "$LIB_DIR/gcp_common.sh"
            source "$LIB_DIR/gcp_permissions.sh"
            ;;
        "reporting")
            # Load reporting libraries
            source "$LIB_DIR/gcp_common.sh"
            source "$LIB_DIR/gcp_html_report.sh"
            ;;
        "organization")
            # Load organization scope libraries
            source "$LIB_DIR/gcp_common.sh"
            source "$LIB_DIR/gcp_permissions.sh"
            source "$LIB_DIR/gcp_scope_mgmt.sh"
            ;;
        "full"|*)
            # Load all libraries (current behavior)
            source "$LIB_DIR/gcp_common.sh"
            source "$LIB_DIR/gcp_permissions.sh"
            source "$LIB_DIR/gcp_html_report.sh"
            source "$LIB_DIR/gcp_scope_mgmt.sh"
            ;;
    esac
}

# Optimized initialization
initialize_framework() {
    local script_type="${1:-full}"
    local use_lazy_loading="${2:-false}"
    
    if [[ "$use_lazy_loading" == "true" ]]; then
        # Build function registry for lazy loading
        build_function_registry
        echo "Framework initialized with lazy loading ($(date +%s.%N) seconds)" >&2
    else
        # Use conditional loading
        load_libraries_conditional "$script_type"
        local load_end_time=$(date +%s.%N)
        local load_duration=$(echo "$load_end_time - $LOAD_START_TIME" | bc -l)
        echo "Framework loaded in ${load_duration} seconds" >&2
    fi
}

# Function wrapper for lazy loading
call_function() {
    local func_name="$1"
    shift
    
    # Load function on demand if using lazy loading
    if [[ "${FUNCTION_REGISTRY[$func_name]}" ]]; then
        load_function_on_demand "$func_name"
    fi
    
    # Call the function
    if declare -f "$func_name" >/dev/null 2>&1; then
        "$func_name" "$@"
    else
        echo "ERROR: Function $func_name not available" >&2
        return 1
    fi
}

# Export optimized loading functions
export -f load_function_on_demand
export -f call_function
export -f initialize_framework
