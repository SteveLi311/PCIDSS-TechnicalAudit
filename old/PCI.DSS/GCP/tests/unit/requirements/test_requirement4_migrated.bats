#!/usr/bin/env bats

# Unit tests for GCP PCI DSS Requirement 4 migrated script

setup() {
    # Set up test environment
    export BATS_TEST_DIRNAME="$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)"
    export PROJECT_ROOT="$(cd "$BATS_TEST_DIRNAME/../../.." && pwd)"
    export SCRIPT_PATH="$PROJECT_ROOT/check_gcp_pci_requirement4_migrated.sh"
    
    # Load test helpers
    load "$PROJECT_ROOT/tests/helpers/test_helpers.bash"
    load "$PROJECT_ROOT/tests/helpers/mock_helpers.bash"
    
    # Mock setup
    setup_mock_environment
    mock_gcloud_commands
}

teardown() {
    cleanup_mock_environment
}

@test "script exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "script shows help when called with --help" {
    run "$SCRIPT_PATH" --help
    [ "$status" -eq 0 ]
    [[ "$output" =~ "GCP PCI DSS Requirement 4 Assessment Script" ]]
    [[ "$output" =~ "Framework Version" ]]
}

@test "script loads all 4 shared libraries" {
    run bash -n "$SCRIPT_PATH"
    [ "$status" -eq 0 ]
    
    # Check library imports exist
    grep -q "source.*gcp_common.sh" "$SCRIPT_PATH"
    grep -q "source.*gcp_permissions.sh" "$SCRIPT_PATH"
    grep -q "source.*gcp_html_report.sh" "$SCRIPT_PATH"
    grep -q "source.*gcp_scope_mgmt.sh" "$SCRIPT_PATH"
}

@test "script registers required permissions for Requirement 4" {
    run grep -A 10 "register_required_permissions" "$SCRIPT_PATH"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "compute.sslPolicies.list" ]]
    [[ "$output" =~ "compute.targetHttpsProxies.list" ]]
    [[ "$output" =~ "compute.sslCertificates.list" ]]
    [[ "$output" =~ "compute.firewalls.list" ]]
}

@test "assess_tls_configurations function exists" {
    grep -q "assess_tls_configurations()" "$SCRIPT_PATH"
}

@test "assess_ssl_certificates function exists" {
    grep -q "assess_ssl_certificates()" "$SCRIPT_PATH"
}

@test "assess_unencrypted_services function exists" {
    grep -q "assess_unencrypted_services()" "$SCRIPT_PATH"
}

@test "assess_cloud_cdn_armor function exists" {
    grep -q "assess_cloud_cdn_armor()" "$SCRIPT_PATH"
}

@test "script uses framework initialization pattern" {
    grep -q "setup_environment" "$SCRIPT_PATH"
    grep -q "parse_common_arguments" "$SCRIPT_PATH"
    grep -q "validate_prerequisites" "$SCRIPT_PATH"
    grep -q "setup_assessment_scope" "$SCRIPT_PATH"
}

@test "script uses framework reporting pattern" {
    grep -q "initialize_report" "$SCRIPT_PATH"
    grep -q "add_section" "$SCRIPT_PATH"
    grep -q "add_check_result" "$SCRIPT_PATH"
    grep -q "finalize_report" "$SCRIPT_PATH"
}

@test "script follows PCI DSS Requirement 4 structure" {
    # Check for PCI DSS 4.2.x compliance sections
    grep -q "4.2.1.*Strong cryptography" "$SCRIPT_PATH"
    grep -q "4.2.1.1.*Inventory.*certificates" "$SCRIPT_PATH"
    grep -q "4.2.1.2.*Unencrypted" "$SCRIPT_PATH"
    grep -q "4.2.2.*End-user messaging" "$SCRIPT_PATH"
}

@test "script has proper shebang" {
    head -n1 "$SCRIPT_PATH" | grep -q "#!/usr/bin/env bash"
}

@test "script handles TLS version validation" {
    # Check for TLS version checking logic
    grep -q "TLS_1_" "$SCRIPT_PATH"
    grep -q "Warning.*Weak TLS" "$SCRIPT_PATH"
}

@test "script handles certificate expiration checking" {
    # Check for certificate expiration logic
    grep -q "expire_time" "$SCRIPT_PATH"
    grep -q "days_until_expiry" "$SCRIPT_PATH"
    grep -q "EXPIRED" "$SCRIPT_PATH"
}

@test "script checks for insecure protocols" {
    # Check for insecure protocol detection
    grep -q "insecure_protocols" "$SCRIPT_PATH"
    grep -q "0.0.0.0/0" "$SCRIPT_PATH"
}

@test "script validates firewall rules" {
    # Check for firewall rule analysis
    grep -q "firewall-rules list" "$SCRIPT_PATH"
    grep -q "direction=INGRESS" "$SCRIPT_PATH"
}

@test "script follows framework logging patterns" {
    grep -q "log_info" "$SCRIPT_PATH"
    grep -q "log_debug" "$SCRIPT_PATH"
    grep -q "log_error" "$SCRIPT_PATH"
}

@test "script uses proper project iteration" {
    grep -q "get_projects_in_scope" "$SCRIPT_PATH"
    grep -q "while IFS=" "$SCRIPT_PATH"
}

@test "script has significantly reduced line count" {
    line_count=$(wc -l < "$SCRIPT_PATH")
    # Should be around 359 lines, much less than original 792
    [ "$line_count" -lt 400 ]
    [ "$line_count" -gt 300 ]
}

@test "script passes syntax validation" {
    run bash -n "$SCRIPT_PATH"
    [ "$status" -eq 0 ]
}

@test "script defines requirement number and title" {
    grep -q 'REQUIREMENT_NUMBER="4"' "$SCRIPT_PATH"
    grep -q 'REQUIREMENT_TITLE=.*Cryptography.*Transmission' "$SCRIPT_PATH"
}