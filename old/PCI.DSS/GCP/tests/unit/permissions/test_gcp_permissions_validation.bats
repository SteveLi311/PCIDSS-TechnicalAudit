#!/usr/bin/env bats

# Unit tests for gcp_permissions.sh user interaction and validation functions

load ../../helpers/test_helpers
load ../../helpers/mock_helpers

setup() {
    setup_test_environment
    load_gcp_common_library
    load_gcp_permissions_library
}

teardown() {
    cleanup_test_environment
}

# =============================================================================
# prompt_continue_limited function tests
# =============================================================================

@test "prompt_continue_limited: displays coverage information" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=75
    export MISSING_PERMISSIONS_COUNT=2
    export REQUIRED_PERMISSIONS=("perm1" "perm2" "perm3" "perm4" "perm5" "perm6" "perm7" "perm8")
    declare -A PERMISSION_RESULTS
    PERMISSION_RESULTS["perm1"]="MISSING"
    PERMISSION_RESULTS["perm2"]="MISSING"
    export PERMISSION_RESULTS
    
    # Mock user input to continue
    mock_user_input "y"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Limited permissions detected (75% coverage)" ]]
    [[ "$output" =~ "Missing 2 of 8 required permissions" ]]
    [[ "$output" =~ "Assessment can continue with limited functionality" ]]
}

@test "prompt_continue_limited: shows missing permissions in verbose mode" {
    # Setup
    export VERBOSE=true
    export PERMISSION_COVERAGE_PERCENTAGE=50
    export MISSING_PERMISSIONS_COUNT=1
    export REQUIRED_PERMISSIONS=("available.perm" "missing.perm")
    declare -A PERMISSION_RESULTS
    PERMISSION_RESULTS["available.perm"]="AVAILABLE"
    PERMISSION_RESULTS["missing.perm"]="MISSING"
    export PERMISSION_RESULTS
    
    # Mock user input to continue
    mock_user_input "y"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Missing permissions:" ]]
    [[ "$output" =~ "missing.perm" ]]
    [[ ! "$output" =~ "available.perm" ]]
}

@test "prompt_continue_limited: accepts 'y' to continue" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=80
    export MISSING_PERMISSIONS_COUNT=1
    export REQUIRED_PERMISSIONS=("perm1")
    
    # Mock user input
    mock_user_input "y"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Continuing with limited permissions" ]]
}

@test "prompt_continue_limited: accepts 'yes' to continue" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=60
    export MISSING_PERMISSIONS_COUNT=2
    export REQUIRED_PERMISSIONS=("perm1" "perm2")
    
    # Mock user input
    mock_user_input "yes"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Continuing with limited permissions" ]]
}

@test "prompt_continue_limited: accepts 'Y' to continue (case insensitive)" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=90
    export MISSING_PERMISSIONS_COUNT=1
    export REQUIRED_PERMISSIONS=("perm1")
    
    # Mock user input
    mock_user_input "Y"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Continuing with limited permissions" ]]
}

@test "prompt_continue_limited: accepts 'YES' to continue (case insensitive)" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=70
    export MISSING_PERMISSIONS_COUNT=1
    export REQUIRED_PERMISSIONS=("perm1")
    
    # Mock user input
    mock_user_input "YES"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Continuing with limited permissions" ]]
}

@test "prompt_continue_limited: rejects 'n' and cancels" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=40
    export MISSING_PERMISSIONS_COUNT=3
    export REQUIRED_PERMISSIONS=("perm1" "perm2" "perm3")
    
    # Mock user input
    mock_user_input "n"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Assessment cancelled by user" ]]
}

@test "prompt_continue_limited: rejects 'no' and cancels" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=30
    export MISSING_PERMISSIONS_COUNT=2
    export REQUIRED_PERMISSIONS=("perm1" "perm2")
    
    # Mock user input
    mock_user_input "no"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Assessment cancelled by user" ]]
}

@test "prompt_continue_limited: defaults to 'no' on empty input" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=50
    export MISSING_PERMISSIONS_COUNT=1
    export REQUIRED_PERMISSIONS=("perm1")
    
    # Mock user input (empty string)
    mock_user_input ""
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Assessment cancelled by user" ]]
}

@test "prompt_continue_limited: rejects 'N' and cancels (case insensitive)" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=25
    export MISSING_PERMISSIONS_COUNT=3
    export REQUIRED_PERMISSIONS=("perm1" "perm2" "perm3")
    
    # Mock user input
    mock_user_input "N"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Assessment cancelled by user" ]]
}

@test "prompt_continue_limited: rejects 'NO' and cancels (case insensitive)" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=10
    export MISSING_PERMISSIONS_COUNT=4
    export REQUIRED_PERMISSIONS=("perm1" "perm2" "perm3" "perm4")
    
    # Mock user input
    mock_user_input "NO"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Assessment cancelled by user" ]]
}

@test "prompt_continue_limited: handles invalid input and reprompts" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=60
    export MISSING_PERMISSIONS_COUNT=2
    export REQUIRED_PERMISSIONS=("perm1" "perm2")
    
    # Mock user input sequence: invalid, then valid
    mock_user_input_sequence "invalid" "y"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Please enter 'y' for yes or 'n' for no" ]]
    [[ "$output" =~ "Continuing with limited permissions" ]]
}

@test "prompt_continue_limited: handles multiple invalid inputs before valid response" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=80
    export MISSING_PERMISSIONS_COUNT=1
    export REQUIRED_PERMISSIONS=("perm1")
    
    # Mock user input sequence: multiple invalid, then valid
    mock_user_input_sequence "invalid1" "invalid2" "maybe" "n"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Assessment cancelled by user" ]]
    # Should show multiple prompts for invalid inputs
    output_line_count=$(echo "$output" | grep -c "Please enter 'y' for yes or 'n' for no" || true)
    [ "$output_line_count" -ge 3 ]
}

@test "prompt_continue_limited: shows correct prompt message" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=70
    export MISSING_PERMISSIONS_COUNT=1
    export REQUIRED_PERMISSIONS=("perm1")
    
    # Mock user input
    mock_user_input "y"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Continue with limited permissions? [y/N]:" ]]
}

@test "prompt_continue_limited: handles zero missing permissions edge case" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=100
    export MISSING_PERMISSIONS_COUNT=0
    export REQUIRED_PERMISSIONS=("perm1" "perm2")
    
    # Mock user input
    mock_user_input "y"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Missing 0 of 2 required permissions" ]]
    [[ "$output" =~ "Limited permissions detected (100% coverage)" ]]
}

@test "prompt_continue_limited: handles single permission edge case" {
    # Setup
    export PERMISSION_COVERAGE_PERCENTAGE=0
    export MISSING_PERMISSIONS_COUNT=1
    export REQUIRED_PERMISSIONS=("single.perm")
    declare -A PERMISSION_RESULTS
    PERMISSION_RESULTS["single.perm"]="MISSING"
    export PERMISSION_RESULTS
    
    # Mock user input
    mock_user_input "n"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Missing 1 of 1 required permissions" ]]
    [[ "$output" =~ "Limited permissions detected (0% coverage)" ]]
}

@test "prompt_continue_limited: correctly filters missing permissions in verbose mode" {
    # Setup
    export VERBOSE=true
    export PERMISSION_COVERAGE_PERCENTAGE=33
    export MISSING_PERMISSIONS_COUNT=2
    export REQUIRED_PERMISSIONS=("available.perm" "missing.perm1" "missing.perm2")
    declare -A PERMISSION_RESULTS
    PERMISSION_RESULTS["available.perm"]="AVAILABLE"
    PERMISSION_RESULTS["missing.perm1"]="MISSING"
    PERMISSION_RESULTS["missing.perm2"]="MISSING"
    export PERMISSION_RESULTS
    
    # Mock user input
    mock_user_input "y"
    
    # Execute
    run prompt_continue_limited
    
    # Assert
    [ "$status" -eq 0 ]
    [[ "$output" =~ "missing.perm1" ]]
    [[ "$output" =~ "missing.perm2" ]]
    [[ ! "$output" =~ "available.perm" ]]
}