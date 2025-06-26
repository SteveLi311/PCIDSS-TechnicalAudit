#!/usr/bin/env bats

# Simple unit tests for GCP PCI DSS Requirement 4 migrated script (without broken helpers)

setup() {
    export SCRIPT_PATH="/Users/namhp/Resilio.Sync/PCI.DSS/GCP/check_gcp_pci_requirement4_migrated.sh"
}

@test "script exists and is executable" {
    [ -f "$SCRIPT_PATH" ]
    [ -x "$SCRIPT_PATH" ]
}

@test "script loads all 4 shared libraries" {
    grep -q "source.*gcp_common.sh" "$SCRIPT_PATH"
    grep -q "source.*gcp_permissions.sh" "$SCRIPT_PATH"
    grep -q "source.*gcp_html_report.sh" "$SCRIPT_PATH"
    grep -q "source.*gcp_scope_mgmt.sh" "$SCRIPT_PATH"
}

@test "script registers required permissions for Requirement 4" {
    grep -A 10 "register_required_permissions" "$SCRIPT_PATH" | grep -q "compute.sslPolicies.list"
    grep -A 10 "register_required_permissions" "$SCRIPT_PATH" | grep -q "compute.targetHttpsProxies.list"
    grep -A 10 "register_required_permissions" "$SCRIPT_PATH" | grep -q "compute.sslCertificates.list"
    grep -A 10 "register_required_permissions" "$SCRIPT_PATH" | grep -q "compute.firewalls.list"
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
    grep -q "4.2.1.*Strong cryptography" "$SCRIPT_PATH"
    grep -q "4.2.1.1.*Inventory.*certificates" "$SCRIPT_PATH"
    grep -q "4.2.1.2.*Unencrypted" "$SCRIPT_PATH"
    grep -q "4.2.2.*End-user messaging" "$SCRIPT_PATH"
}

@test "script has proper shebang" {
    head -n1 "$SCRIPT_PATH" | grep -q "#!/usr/bin/env bash"
}

@test "script handles TLS version validation" {
    grep -q "TLS_1_" "$SCRIPT_PATH"
    grep -q "Warning.*Weak TLS" "$SCRIPT_PATH"
}

@test "script handles certificate expiration checking" {
    grep -q "expire_time" "$SCRIPT_PATH"
    grep -q "days_until_expiry" "$SCRIPT_PATH"
    grep -q "EXPIRED" "$SCRIPT_PATH"
}

@test "script checks for insecure protocols" {
    grep -q "insecure_protocols" "$SCRIPT_PATH"
    grep -q "0.0.0.0/0" "$SCRIPT_PATH"
}

@test "script validates firewall rules" {
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
}

@test "script has significantly reduced line count" {
    line_count=$(wc -l < "$SCRIPT_PATH")
    [ "$line_count" -lt 400 ]
    [ "$line_count" -gt 300 ]
}

@test "script passes syntax validation" {
    bash -n "$SCRIPT_PATH"
}

@test "script defines requirement number and title" {
    grep -q 'REQUIREMENT_NUMBER="4"' "$SCRIPT_PATH"
    grep -q 'REQUIREMENT_TITLE=.*Cryptography.*Transmission' "$SCRIPT_PATH"
}