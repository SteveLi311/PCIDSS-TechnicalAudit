#!/usr/bin/env bats

# Unit tests for gcp_common.sh core functions

load ../../helpers/test_helpers
load ../../helpers/mock_helpers

setup() {
    setup_test_environment
    load_gcp_common_library
}

teardown() {
    cleanup_test_environment
}

# =============================================================================
# source_gcp_libraries function tests
# =============================================================================

@test "source_gcp_libraries: successfully loads libraries when directory exists" {
    # Setup
    create_mock_lib_directory
    
    # Execute
    run source_gcp_libraries
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "GCP Common Library v1.0 loaded successfully" ]]
    [ "$GCP_COMMON_LOADED" = "true" ]
}

@test "source_gcp_libraries: fails when library directory missing" {
    # Setup
    export LIB_DIR="/nonexistent/path"
    
    # Execute
    run source_gcp_libraries
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Error: Library directory not found" ]]
}

@test "source_gcp_libraries: sets GCP_LIB_PATH correctly" {
    # Setup
    create_mock_lib_directory
    
    # Execute
    source_gcp_libraries
    
    # Assert
    [ -n "$GCP_LIB_PATH" ]
    [ -d "$GCP_LIB_PATH" ]
}

# =============================================================================
# setup_environment function tests
# =============================================================================

@test "setup_environment: initializes global variables correctly" {
    # Execute
    run setup_environment
    
    # Assert
    [ "$status" -eq 0 ]
    [ -n "$WORK_DIR" ]
    [ -n "$REPORT_DIR" ]
    [ -n "$LOG_DIR" ]
    [ -n "$SCRIPT_START_TIME" ]
    [ -n "$SCRIPT_PID" ]
}

@test "setup_environment: creates required directories" {
    # Execute
    setup_environment
    
    # Assert
    [ -d "$WORK_DIR" ]
    [ -d "$REPORT_DIR" ]
    [ -d "$LOG_DIR" ]
}

@test "setup_environment: sets up logging when log file specified" {
    # Setup
    local test_log="test_log.log"
    
    # Execute
    setup_environment "$test_log"
    
    # Assert
    [ -n "$LOG_FILE" ]
    [ -f "$LOG_FILE" ]
    [[ "$LOG_FILE" =~ "$test_log" ]]
}

@test "setup_environment: fails when directory creation fails" {
    # Setup
    export OUTPUT_DIR="/root/readonly_dir"
    
    # Execute
    run setup_environment
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Error: Failed to create directory" ]]
}

# =============================================================================
# validate_prerequisites function tests  
# =============================================================================

@test "validate_prerequisites: succeeds with proper setup" {
    # Setup
    mock_command_success "gcloud"
    mock_command_success "jq"
    mock_command_success "curl"
    mock_gcloud_auth_active
    mock_gcloud_projects_list
    
    # Execute
    run validate_prerequisites
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "All prerequisites validated successfully" ]]
}

@test "validate_prerequisites: fails when gcloud missing" {
    # Setup
    mock_command_missing "gcloud"
    mock_command_success "jq"
    mock_command_success "curl"
    
    # Execute
    run validate_prerequisites
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Required tool 'gcloud' not found" ]]
}

@test "validate_prerequisites: fails when not authenticated" {
    # Setup
    mock_command_success "gcloud"
    mock_command_success "jq"
    mock_command_success "curl"
    mock_gcloud_auth_inactive
    
    # Execute
    run validate_prerequisites
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "gcloud not authenticated" ]]
}

@test "validate_prerequisites: validates specific project when PROJECT_ID set" {
    # Setup
    export PROJECT_ID="test-project-123"
    mock_all_prerequisites_success
    mock_gcloud_project_describe_success "$PROJECT_ID"
    
    # Execute
    run validate_prerequisites
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Project 'test-project-123' accessible" ]]
}

@test "validate_prerequisites: fails when project inaccessible" {
    # Setup
    export PROJECT_ID="invalid-project"
    mock_all_prerequisites_success
    mock_gcloud_project_describe_failure "$PROJECT_ID"
    
    # Execute
    run validate_prerequisites
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Cannot access project 'invalid-project'" ]]
}

# =============================================================================
# print_status function tests
# =============================================================================

@test "print_status: formats INFO messages correctly" {
    # Execute
    run print_status "INFO" "Test message"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "\[INFO\]" ]]
    [[ "$output" =~ "Test message" ]]
}

@test "print_status: formats PASS messages correctly" {
    # Execute
    run print_status "PASS" "Test success"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "\[PASS\]" ]]
    [[ "$output" =~ "Test success" ]]
}

@test "print_status: formats WARN messages correctly" {
    # Execute
    run print_status "WARN" "Test warning"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "\[WARN\]" ]]
    [[ "$output" =~ "Test warning" ]]
}

@test "print_status: formats FAIL messages correctly" {
    # Execute
    run print_status "FAIL" "Test failure"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "\[FAIL\]" ]]
    [[ "$output" =~ "Test failure" ]]
}

@test "print_status: handles backward compatibility aliases" {
    # Execute
    run print_status "info" "Test info"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "\[INFO\]" ]]
    [[ "$output" =~ "Test info" ]]
}

@test "print_status: logs to file when LOG_FILE set" {
    # Setup
    setup_environment "test_log.log"
    
    # Execute
    print_status "INFO" "Test log message"
    
    # Assert
    [ -f "$LOG_FILE" ]
    grep -q "Test log message" "$LOG_FILE"
}

@test "print_status: outputs verbose debug when VERBOSE=true" {
    # Setup
    export VERBOSE=true
    
    # Execute
    run print_status "INFO" "Verbose test"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Verbose test" ]]
}

# =============================================================================
# log_debug function tests
# =============================================================================

@test "log_debug: outputs debug message when VERBOSE=true" {
    # Setup
    export VERBOSE=true
    
    # Execute
    run log_debug "Debug test message"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "DEBUG: Debug test message" ]]
}

@test "log_debug: silent when VERBOSE=false" {
    # Setup
    export VERBOSE=false
    
    # Execute
    run log_debug "Debug test message"
    
    # Assert
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

# =============================================================================
# Utility function tests
# =============================================================================

@test "check_script_permissions: warns when running as root" {
    # Setup - Mock EUID to simulate root
    export EUID=0
    
    # Execute
    run check_script_permissions
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Running as root" ]]
}

@test "cleanup_temp_files: cleans up work directory" {
    # Setup
    setup_environment
    mkdir -p "$WORK_DIR/test_subdir"
    touch "$WORK_DIR/test_file.txt"
    
    # Execute
    run cleanup_temp_files
    
    # Assert
    [ "$status" -eq 0 ]
    [ ! -f "$WORK_DIR/test_file.txt" ]
}

@test "get_script_name: returns correct script name" {
    # Execute
    result=$(get_script_name)
    
    # Assert
    [[ "$result" =~ "test_gcp_common_core.bats" ]]
}