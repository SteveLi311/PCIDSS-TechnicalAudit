#!/usr/bin/env bats

# Unit tests for gcp_common.sh CLI parsing functions

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
# parse_common_arguments function tests
# =============================================================================

@test "parse_common_arguments: handles single project scope" {
    # Execute
    run parse_common_arguments -s project -p test-project-123
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$SCOPE" = "project" ]
    [ "$SCOPE_TYPE" = "project" ]
    [ "$PROJECT_ID" = "test-project-123" ]
}

@test "parse_common_arguments: handles organization scope" {
    # Execute
    run parse_common_arguments -s organization -p test-org-456
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$SCOPE" = "organization" ]
    [ "$SCOPE_TYPE" = "organization" ]
    [ "$ORG_ID" = "test-org-456" ]
}

@test "parse_common_arguments: handles output directory option" {
    # Execute
    run parse_common_arguments -o /custom/output/dir
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$OUTPUT_DIR" = "/custom/output/dir" ]
}

@test "parse_common_arguments: handles verbose flag" {
    # Execute
    run parse_common_arguments -v
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$VERBOSE" = "true" ]
}

@test "parse_common_arguments: handles report-only flag" {
    # Execute
    run parse_common_arguments -r
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$REPORT_ONLY" = "true" ]
}

@test "parse_common_arguments: handles long format options" {
    # Execute
    run parse_common_arguments --scope project --project test-proj --output /tmp/reports --verbose --report-only
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$SCOPE" = "project" ]
    [ "$PROJECT_ID" = "test-proj" ]
    [ "$OUTPUT_DIR" = "/tmp/reports" ]
    [ "$VERBOSE" = "true" ]
    [ "$REPORT_ONLY" = "true" ]
}

@test "parse_common_arguments: rejects invalid scope values" {
    # Execute
    run parse_common_arguments -s invalid_scope
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Error: Scope must be 'project' or 'organization'" ]]
}

@test "parse_common_arguments: rejects empty project ID" {
    # Execute
    run parse_common_arguments -p ""
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Error: Project/Organization ID cannot be empty" ]]
}

@test "parse_common_arguments: rejects empty output directory" {
    # Execute
    run parse_common_arguments -o ""
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Error: Output directory cannot be empty" ]]
}

@test "parse_common_arguments: rejects unknown options" {
    # Execute
    run parse_common_arguments --unknown-option
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Error: Unknown option" ]]
    [[ "$output" =~ "Use -h or --help for usage information" ]]
}

@test "parse_common_arguments: displays help when -h specified" {
    # Execute
    run parse_common_arguments -h
    
    # Assert
    [ "$status" -eq 2 ]
    [[ "$output" =~ "GCP PCI DSS Assessment Script" ]]
    [[ "$output" =~ "USAGE:" ]]
}

@test "parse_common_arguments: displays help when --help specified" {
    # Execute
    run parse_common_arguments --help
    
    # Assert
    [ "$status" -eq 2 ]
    [[ "$output" =~ "GCP PCI DSS Assessment Script" ]]
    [[ "$output" =~ "OPTIONS:" ]]
}

@test "parse_common_arguments: sets default scope when none provided" {
    # Execute
    parse_common_arguments
    
    # Assert
    [ "$SCOPE" = "project" ]
}

@test "parse_common_arguments: exports all parsed variables" {
    # Execute
    parse_common_arguments -s project -p test-proj -o /tmp -v -r
    
    # Assert variables are exported
    [ -n "$SCOPE" ]
    [ -n "$SCOPE_TYPE" ]
    [ -n "$PROJECT_ID" ]
    [ -n "$OUTPUT_DIR" ]
    [ -n "$VERBOSE" ]
    [ -n "$REPORT_ONLY" ]
}

@test "parse_common_arguments: handles mixed short and long options" {
    # Execute
    run parse_common_arguments -s project --project my-project --verbose -o /output
    
    # Assert
    [ "$status" -eq 0 ]
    [ "$SCOPE" = "project" ]
    [ "$PROJECT_ID" = "my-project" ]
    [ "$VERBOSE" = "true" ]
    [ "$OUTPUT_DIR" = "/output" ]
}

@test "parse_common_arguments: correctly assigns organization ID when org scope" {
    # Execute
    parse_common_arguments -s organization -p 123456789
    
    # Assert
    [ "$SCOPE_TYPE" = "organization" ]
    [ "$ORG_ID" = "123456789" ]
    [ -z "$PROJECT_ID" ]
}

@test "parse_common_arguments: correctly assigns project ID when project scope" {
    # Execute
    parse_common_arguments -s project -p my-project-id
    
    # Assert
    [ "$SCOPE_TYPE" = "project" ]
    [ "$PROJECT_ID" = "my-project-id" ]
    [ -z "$ORG_ID" ]
}

# =============================================================================
# show_help function tests
# =============================================================================

@test "show_help: displays complete help information" {
    # Execute
    run show_help
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "GCP PCI DSS Assessment Script" ]]
    [[ "$output" =~ "USAGE:" ]]
    [[ "$output" =~ "OPTIONS:" ]]
    [[ "$output" =~ "EXAMPLES:" ]]
    [[ "$output" =~ "REQUIREMENTS:" ]]
}

@test "show_help: includes all command line options" {
    # Execute
    run show_help
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "-s, --scope" ]]
    [[ "$output" =~ "-p, --project" ]]
    [[ "$output" =~ "-o, --output" ]]
    [[ "$output" =~ "-r, --report-only" ]]
    [[ "$output" =~ "-v, --verbose" ]]
    [[ "$output" =~ "-h, --help" ]]
}

@test "show_help: includes usage examples" {
    # Execute
    run show_help
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Assess a specific project" ]]
    [[ "$output" =~ "Assess organization with verbose output" ]]
    [[ "$output" =~ "Use default settings" ]]
}

@test "show_help: includes requirements section" {
    # Execute
    run show_help
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "gcloud CLI tool" ]]
    [[ "$output" =~ "jq tool for JSON processing" ]]
    [[ "$output" =~ "Appropriate GCP permissions" ]]
}

@test "show_help: includes color formatting" {
    # Execute
    run show_help
    
    # Assert
    [ "$status" -eq 0 ]
    # Check for ANSI color codes in output
    [[ "$output" =~ $'\033' ]]
}

# =============================================================================
# load_requirement_config function tests  
# =============================================================================

@test "load_requirement_config: loads config file by requirement number" {
    # Setup
    local config_dir="$(dirname "$LIB_DIR")/config"
    mkdir -p "$config_dir"
    echo 'export TEST_CONFIG_VAR="test_value"' > "$config_dir/requirement_1.conf"
    
    # Execute
    run load_requirement_config 1
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Configuration loaded successfully" ]]
    [ "$TEST_CONFIG_VAR" = "test_value" ]
}

@test "load_requirement_config: loads config file by direct path" {
    # Setup
    local test_config="/tmp/test_config.conf"
    echo 'export DIRECT_CONFIG_VAR="direct_value"' > "$test_config"
    
    # Execute
    run load_requirement_config "$test_config"
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Configuration loaded successfully" ]]
    [ "$DIRECT_CONFIG_VAR" = "direct_value" ]
}

@test "load_requirement_config: loads config file by name" {
    # Setup
    local config_dir="$(dirname "$LIB_DIR")/config"
    mkdir -p "$config_dir"
    echo 'export NAMED_CONFIG_VAR="named_value"' > "$config_dir/custom.conf"
    
    # Execute
    run load_requirement_config custom
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Configuration loaded successfully" ]]
    [ "$NAMED_CONFIG_VAR" = "named_value" ]
}

@test "load_requirement_config: warns when no requirement specified" {
    # Execute
    run load_requirement_config
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "No requirement specified for configuration loading" ]]
}

@test "load_requirement_config: fails when config file not found" {
    # Execute
    run load_requirement_config 999
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Configuration file not found" ]]
}

@test "load_requirement_config: fails when config file has syntax errors" {
    # Setup
    local config_dir="$(dirname "$LIB_DIR")/config"
    mkdir -p "$config_dir"
    echo 'invalid bash syntax here &@#$' > "$config_dir/requirement_2.conf"
    
    # Execute
    run load_requirement_config 2
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Failed to load configuration file" ]]
}