#!/usr/bin/env bash

# PCI DSS Requirement 2 Compliance Check Script for GCP
# This script evaluates GCP system component configurations for PCI DSS Requirement 2 compliance
# Requirements covered: 2.2 - 2.3 (Secure configurations, vendor defaults, wireless security)
# Requirement 2.1 removed - requires manual verification

# Load shared libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

source "$LIB_DIR/gcp_common.sh" || exit 1
source "$LIB_DIR/gcp_permissions.sh" || exit 1
source "$LIB_DIR/gcp_scope_mgmt.sh" || exit 1
source "$LIB_DIR/gcp_html_report.sh" || exit 1

# Script-specific variables
REQUIREMENT_NUMBER="2"

# Initialize environment
setup_environment || exit 1

# Parse command line arguments using shared function
parse_common_arguments "$@"
case $? in
    1) exit 1 ;;  # Error
    2) exit 0 ;;  # Help displayed
esac

# Setup report configuration using shared library
load_requirement_config "${REQUIREMENT_NUMBER}"

# Validate scope and setup project context using shared library
setup_assessment_scope || exit 1

# Check permissions using shared library
check_required_permissions "compute.instances.list" "compute.images.list" "container.clusters.list" || exit 1

# Set output file path
OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"

# Initialize HTML report using shared library
initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report" "${REQUIREMENT_NUMBER}"

# Begin main assessment logic




print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 2 (GCP)"
print_status "INFO" "============================================="
echo ""

# Display scope information using shared library - now handled in print_status calls
print_status "INFO" "Assessment scope: ${ASSESSMENT_SCOPE:-project}"
if [[ "$ASSESSMENT_SCOPE" == "organization" ]]; then
    print_status "INFO" "Organization ID: ${ORG_ID}"
else
    print_status "INFO" "Project ID: ${PROJECT_ID}"
fi

echo ""
echo "Starting assessment at $(date)"
echo ""

# Reset counters for actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

#----------------------------------------------------------------------
# SECTION 2: PCI REQUIREMENT 2.2 - SECURE SYSTEM COMPONENT CONFIG
#----------------------------------------------------------------------
print_status "INFO" "=== PCI REQUIREMENT 2.2: SYSTEM COMPONENTS CONFIGURED AND MANAGED SECURELY ==="

# Check 2.2.1 - Configuration standards
print_status "INFO" "2.2.1 - Configuration standards for system components"
print_status "INFO" "Checking for evidence of configuration standards implementation..."

config_standards_details="<p>Analysis of configuration standards implementation:</p><ul>"

# Check for OS Config policies (organization policy constraints)
if [[ "$ASSESSMENT_SCOPE" == "organization" && -n "$ORG_ID" ]]; then
    org_policies=$(gcloud resource-manager org-policies list --organization=$ORG_ID --format="value(constraint)" 2>/dev/null | grep -E "(compute|security)" | wc -l)
    
    if [ $org_policies -gt 0 ]; then
        print_status "PASS" "Organization policies for compute/security found"
        config_standards_details+="<li class='green'>Organization policies for compute/security found: $org_policies</li>"
    else
        print_status "WARN" "No organization policies for compute/security found"
        config_standards_details+="<li class='yellow'>No organization policies for compute/security found</li>"
    fi
fi

# Check for instance templates with secure configurations
instance_templates=$(run_across_projects "gcloud compute instance-templates list --format=value(name)")
template_count=$(echo "$instance_templates" | grep -v "^$" | wc -l)

config_standards_details+="<li>Compute instance templates found: $template_count</li>"

if [ $template_count -gt 0 ]; then
    config_standards_details+="<li class='green'>Instance templates can help enforce configuration standards</li>"
else
    config_standards_details+="<li class='yellow'>No instance templates found - consider using templates for consistent configurations</li>"
fi

config_standards_details+="</ul>"

add_section "$OUTPUT_FILE" "config-standards" "2.2.1 - Configuration Standards"
add_check_result "$OUTPUT_FILE" "info" "Configuration standards analysis" "$config_standards_details" ""
((total_checks++))

# Check 2.2.2 - Vendor default accounts
print_status "INFO" "2.2.2 - Vendor default accounts management"
print_status "INFO" "Checking for vendor default accounts and configurations..."

default_accounts_details="<p>Analysis of vendor default accounts:</p><ul>"

# Initialize section-specific counters
vendor_failed_checks=0
vendor_warning_checks=0  
vendor_passed_checks=0

# Check for default service accounts
default_sas=$(run_across_projects "gcloud iam service-accounts list --format=value(email)" | grep -E "(compute@developer|appspot)" | wc -l)

if [ $default_sas -gt 0 ]; then
    print_status "WARN" "Default service accounts detected"
    default_accounts_details+="<li class='yellow'>Default service accounts detected: $default_sas</li>"
    default_accounts_details+="<li>Review if these are necessary and properly secured</li>"
    ((vendor_warning_checks++))
    ((warning_checks++))
else
    print_status "PASS" "No default service accounts detected"
    default_accounts_details+="<li class='green'>No problematic default service accounts detected</li>"
    ((vendor_passed_checks++))
    ((passed_checks++))
fi

# Check for instances using default service accounts
instances_with_default_sa=$(run_across_projects "gcloud compute instances list --format=value(name,serviceAccounts.email)" | grep -E "(compute@developer|appspot)" | wc -l)

if [ $instances_with_default_sa -gt 0 ]; then
    print_status "FAIL" "Instances using default service accounts detected"
    default_accounts_details+="<li class='red'>Instances using default service accounts: $instances_with_default_sa</li>"
    ((vendor_failed_checks++))
    ((failed_checks++))
else
    print_status "PASS" "No instances using default service accounts"
    default_accounts_details+="<li class='green'>No instances using default service accounts</li>"
    ((vendor_passed_checks++))
    ((passed_checks++))
fi

default_accounts_details+="</ul>"

add_section "$OUTPUT_FILE" "vendor-defaults" "2.2.2 - Vendor Default Accounts"
if [ $vendor_failed_checks -gt 0 ]; then
    add_check_result "$OUTPUT_FILE" "fail" "Vendor default accounts analysis" "$default_accounts_details" ""
elif [ $vendor_warning_checks -gt 0 ]; then
    add_check_result "$OUTPUT_FILE" "warning" "Vendor default accounts analysis" "$default_accounts_details" ""
else
    add_check_result "$OUTPUT_FILE" "pass" "Vendor default accounts analysis" "$default_accounts_details" ""
fi
((total_checks++))

# Check 2.2.3 - Primary functions security isolation
print_status "INFO" "2.2.3 - Primary functions with different security levels"
print_status "INFO" "Checking for proper isolation of functions with different security levels..."

security_isolation_details="<p>Analysis of security function isolation:</p><ul>"

# Check for mixed-purpose instances (web + database on same instance)
mixed_instances=$(run_across_projects "gcloud compute instances list --format=value(name,tags.items)" | grep -i -E "(web.*db|db.*web|app.*db|db.*app)" | wc -l)

if [ $mixed_instances -gt 0 ]; then
    print_status "WARN" "Potential mixed-purpose instances detected"
    security_isolation_details+="<li class='yellow'>Potential mixed-purpose instances detected: $mixed_instances</li>"
    security_isolation_details+="<li>Review for proper security level isolation</li>"
    ((warning_checks++))
else
    print_status "PASS" "No obvious mixed-purpose instances detected"
    security_isolation_details+="<li class='green'>No obvious mixed-purpose instances detected</li>"
    ((passed_checks++))
fi

# Check for VPC separation
vpcs=$(run_across_projects "gcloud compute networks list --format=value(name)" | grep -v "^$" | wc -l)
security_isolation_details+="<li>VPC networks for isolation: $vpcs</li>"

if [ $vpcs -gt 1 ]; then
    security_isolation_details+="<li class='green'>Multiple VPCs can provide network isolation</li>"
else
    security_isolation_details+="<li class='yellow'>Single VPC - ensure proper subnet isolation</li>"
fi

security_isolation_details+="</ul>"

add_section "$OUTPUT_FILE" "security-isolation" "2.2.3 - Primary Functions Security Isolation"
add_check_result "$OUTPUT_FILE" "info" "Security isolation analysis" "$security_isolation_details" ""
((total_checks++))

# Check 2.2.4 - Unnecessary services/functions disabled
print_status "INFO" "2.2.4 - Unnecessary services, protocols, daemons disabled"
print_status "INFO" "Checking for unnecessary services and open ports..."

unnecessary_services_details="<p>Analysis of potentially unnecessary services:</p><ul>"

# Initialize section-specific counters
unnecessary_failed_checks=0
unnecessary_warning_checks=0  
unnecessary_passed_checks=0

# Check for instances with external IPs (potential unnecessary exposure)
external_ip_data=$(run_across_projects "gcloud compute instances list --format=value(name,networkInterfaces[0].accessConfigs[0].natIP)" | grep -v "None" | grep -v "^$" | grep -v "INFO\|WARN\|FAIL\|Executing\|project:")
external_ip_instances=$(echo "$external_ip_data" | wc -l)

if [ $external_ip_instances -gt 0 ]; then
    print_status "WARN" "Instances with external IPs detected"
    unnecessary_services_details+="<li class='yellow'>Instances with external IPs: $external_ip_instances</li>"
    unnecessary_services_details+="<ul>"
    if [ -n "$external_ip_data" ]; then
        while IFS=' ' read -r instance_name external_ip rest; do
            if [ -n "$instance_name" ] && [ -n "$external_ip" ]; then
                unnecessary_services_details+="<li>$instance_name: $external_ip</li>"
            fi
        done < <(echo "$external_ip_data")
    fi
    unnecessary_services_details+="</ul>"
    unnecessary_services_details+="<li>Review if external access is necessary</li>"
    ((unnecessary_warning_checks++))
    ((warning_checks++))
else
    print_status "PASS" "No instances with external IPs detected"
    unnecessary_services_details+="<li class='green'>No instances with external IPs detected</li>"
    ((unnecessary_passed_checks++))
    ((passed_checks++))
fi

# Check for overly permissive firewall rules with detailed analysis like AWS script
high_risk_ports=("22" "3389" "1433" "3306" "5432" "27017" "27018" "6379" "9200" "9300" "8080" "8443" "21" "23")
exposed_details=""
exposed_count=0

# Get firewall rules that expose high-risk ports to 0.0.0.0/0
permissive_fw_rules=$(run_across_projects "gcloud compute firewall-rules list --format=value(name,sourceRanges.join(','),allowed[].map().firewall_rule().list():label=ALLOW,targetTags.join(','),network)")

if [ -n "$permissive_fw_rules" ]; then
    while IFS=$'\t' read -r fw_name sources allowed tags network; do
        if [ -z "$fw_name" ]; then continue; fi
        
        if [[ "$sources" == *"0.0.0.0/0"* ]]; then
            rule_has_risk=false
            exposed_ports=""
            
            # Check for high-risk ports in allowed rules
            for port in "${high_risk_ports[@]}"; do
                if [[ "$allowed" == *"tcp:$port"* ]] || [[ "$allowed" == *"udp:$port"* ]]; then
                    rule_has_risk=true
                    port_desc=""
                    case "$port" in
                        "22") port_desc="SSH" ;;
                        "3389") port_desc="RDP" ;;
                        "1433") port_desc="MS SQL" ;;
                        "3306") port_desc="MySQL" ;;
                        "5432") port_desc="PostgreSQL" ;;
                        "27017"|"27018") port_desc="MongoDB" ;;
                        "6379") port_desc="Redis" ;;
                        "9200"|"9300") port_desc="Elasticsearch" ;;
                        "8080") port_desc="HTTP Alt" ;;
                        "8443") port_desc="HTTPS Alt" ;;
                        "21") port_desc="FTP" ;;
                        "23") port_desc="Telnet" ;;
                        *) port_desc="Port $port" ;;
                    esac
                    exposed_ports+="<br>- $port_desc (Port $port)"
                fi
            done
            
            if [ "$rule_has_risk" = true ]; then
                ((exposed_count++))
                exposed_details+="<br><br><strong>Firewall Rule:</strong> $fw_name"
                exposed_details+="<br><strong>Network:</strong> $network"
                exposed_details+="<br><strong>Exposed Ports:</strong> $exposed_ports"
                if [ -n "$tags" ]; then
                    exposed_details+="<br><strong>Target Tags:</strong> $tags"
                fi
            fi
        fi
    done <<< "$permissive_fw_rules"
fi

if [ $exposed_count -gt 0 ]; then
    print_status "FAIL" "High-risk ports exposed to internet detected"
    unnecessary_services_details+="<li class='red'>High-risk ports exposed to internet: $exposed_count firewall rules</li>"
    unnecessary_services_details+="<li><strong>Details:</strong>$exposed_details</li>"
    ((unnecessary_failed_checks++))
    ((failed_checks++))
else
    print_status "PASS" "No high-risk ports exposed to internet"
    unnecessary_services_details+="<li class='green'>No high-risk ports exposed to internet</li>"
    ((unnecessary_passed_checks++))
    ((passed_checks++))
fi

unnecessary_services_details+="</ul>"

add_section "$OUTPUT_FILE" "unnecessary-services" "2.2.4 - Unnecessary Services Disabled"
if [ $unnecessary_failed_checks -gt 0 ]; then
    add_check_result "$OUTPUT_FILE" "fail" "Unnecessary services analysis" "$unnecessary_services_details" ""
elif [ $unnecessary_warning_checks -gt 0 ]; then
    add_check_result "$OUTPUT_FILE" "warning" "Unnecessary services analysis" "$unnecessary_services_details" ""
else
    add_check_result "$OUTPUT_FILE" "pass" "Unnecessary services analysis" "$unnecessary_services_details" ""
fi
((total_checks++))

# Check 2.2.5 - Insecure services documentation and mitigation
print_status "INFO" "2.2.5 - Insecure services, protocols, daemons"
print_status "INFO" "Checking for insecure services and protocols..."

insecure_services_details="<p>Analysis of potentially insecure services:</p><ul>"

# Initialize section-specific counters
insecure_failed_checks=0
insecure_warning_checks=0  
insecure_passed_checks=0

# Check for Cloud SQL instances without SSL
cloud_sql_instances=$(run_across_projects "gcloud sql instances list --format=value(name)" | grep -v "^$" | grep -v "INFO\|WARN\|FAIL\|Executing\|project:")
insecure_sql_count=0
insecure_sql_details=""

if [ -n "$cloud_sql_instances" ]; then
    while IFS= read -r instance; do
        if [ -z "$instance" ]; then continue; fi
        
        # Extract project from instance name if in org scope
        if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
            project=$(echo "$instance" | cut -d'/' -f1)
            instance_name=$(echo "$instance" | cut -d'/' -f2)
        else
            project="$PROJECT_ID"
            instance_name="$instance"
        fi
        
        ssl_required=$(gcloud sql instances describe "$instance_name" --project="$project" --format="value(settings.ipConfiguration.requireSsl)" 2>/dev/null)
        
        if [ "$ssl_required" != "True" ]; then
            ((insecure_sql_count++))
            insecure_sql_details+="<li>$instance_name (Project: $project)</li>"
        fi
    done <<< "$cloud_sql_instances"
    
    if [ $insecure_sql_count -gt 0 ]; then
        print_status "FAIL" "Cloud SQL instances without required SSL detected"
        insecure_services_details+="<li class='red'>Cloud SQL instances without required SSL: $insecure_sql_count</li>"
        insecure_services_details+="<ul>$insecure_sql_details</ul>"
        ((failed_checks++))
        ((insecure_failed_checks++))
    else
        print_status "PASS" "All Cloud SQL instances require SSL"
        insecure_services_details+="<li class='green'>All Cloud SQL instances require SSL</li>"
        ((passed_checks++))
        ((insecure_passed_checks++))
    fi
else
    insecure_services_details+="<li>No Cloud SQL instances found</li>"
fi

# Check for firewall rules allowing insecure protocols
insecure_protocols=$(run_across_projects "gcloud compute firewall-rules list --format=value(name,allowed)" | grep -E "(tcp:21|tcp:23|tcp:53|udp:69)" | wc -l)

if [ $insecure_protocols -gt 0 ]; then
    print_status "FAIL" "Firewall rules allowing insecure protocols detected"
    insecure_services_details+="<li class='red'>Firewall rules allowing insecure protocols: $insecure_protocols</li>"
    ((failed_checks++))
    ((insecure_failed_checks++))
else
    print_status "PASS" "No firewall rules allowing common insecure protocols"
    insecure_services_details+="<li class='green'>No firewall rules allowing common insecure protocols</li>"
    ((passed_checks++))
    ((insecure_passed_checks++))
fi

insecure_services_details+="</ul>"

add_section "$OUTPUT_FILE" "insecure-services" "2.2.5 - Insecure Services Mitigation"
if [ $insecure_failed_checks -gt 0 ]; then
    add_check_result "$OUTPUT_FILE" "fail" "Insecure services analysis" "$insecure_services_details" ""
elif [ $insecure_warning_checks -gt 0 ]; then
    add_check_result "$OUTPUT_FILE" "warning" "Insecure services analysis" "$insecure_services_details" ""
else
    add_check_result "$OUTPUT_FILE" "pass" "Insecure services analysis" "$insecure_services_details" ""
fi
((total_checks++))

# Check 2.2.6 - System security parameters
print_status "INFO" "2.2.6 - System security parameters configured to prevent misuse"
print_status "INFO" "Checking system security parameters..."

security_params_details="<p>Analysis of system security parameters:</p><ul>"

# Check for OS Login enabled
os_login_enabled=0
if [[ "$ASSESSMENT_SCOPE" == "organization" && -n "$ORG_ID" ]]; then
    os_login_policy=$(gcloud resource-manager org-policies describe compute.requireOsLogin --organization=$ORG_ID --format="value(booleanPolicy.enforced)" 2>/dev/null)
    if [ "$os_login_policy" == "True" ]; then
        os_login_enabled=1
    fi
fi

if [ $os_login_enabled -eq 1 ]; then
    print_status "PASS" "OS Login enforced at organization level"
    security_params_details+="<li class='green'>OS Login enforced at organization level</li>"
    ((passed_checks++))
else
    print_status "WARN" "OS Login not enforced at organization level"
    security_params_details+="<li class='yellow'>OS Login not enforced at organization level</li>"
    ((warning_checks++))
fi

# Check for serial port access disabled
serial_port_disabled=0
if [[ "$ASSESSMENT_SCOPE" == "organization" && -n "$ORG_ID" ]]; then
    serial_port_policy=$(gcloud resource-manager org-policies describe compute.disableSerialPortAccess --organization=$ORG_ID --format="value(booleanPolicy.enforced)" 2>/dev/null)
    if [ "$serial_port_policy" == "True" ]; then
        serial_port_disabled=1
    fi
fi

if [ $serial_port_disabled -eq 1 ]; then
    print_status "PASS" "Serial port access disabled at organization level"
    security_params_details+="<li class='green'>Serial port access disabled at organization level</li>"
    ((passed_checks++))
else
    print_status "WARN" "Serial port access not disabled at organization level"
    security_params_details+="<li class='yellow'>Serial port access not disabled at organization level</li>"
    ((warning_checks++))
fi

security_params_details+="</ul>"

add_section "$OUTPUT_FILE" "security-parameters" "2.2.6 - System Security Parameters"
add_check_result "$OUTPUT_FILE" "warning" "Security parameters analysis" "$security_params_details" ""
((total_checks++))

# Check 2.2.7 - Non-console administrative access encryption
print_status "INFO" "2.2.7 - Non-console administrative access encryption"
print_status "INFO" "Checking for encrypted administrative access..."

admin_encryption_details="<p>Analysis of administrative access encryption:</p><ul>"

# Check for instances allowing SSH with passwords
ssh_password_instances=$(run_across_projects "gcloud compute instances list --format=value(name,metadata.items)" | grep -i "enable-oslogin.*false" | wc -l)

if [ $ssh_password_instances -gt 0 ]; then
    print_status "WARN" "Instances potentially allowing SSH password authentication"
    admin_encryption_details+="<li class='yellow'>Instances potentially allowing SSH password authentication: $ssh_password_instances</li>"
    ((warning_checks++))
else
    print_status "PASS" "No instances explicitly allowing SSH password authentication"
    admin_encryption_details+="<li class='green'>No instances explicitly allowing SSH password authentication</li>"
    ((passed_checks++))
fi

# GCP uses SSH keys by default, which provides encryption
admin_encryption_details+="<li class='green'>GCP uses SSH key-based authentication by default (encrypted)</li>"

admin_encryption_details+="</ul>"

add_section "$OUTPUT_FILE" "admin-encryption" "2.2.7 - Administrative Access Encryption"
add_check_result "$OUTPUT_FILE" "pass" "Administrative access encryption analysis" "$admin_encryption_details" ""
((total_checks++))

# Check for Cloud Storage (equivalent to S3) configurations
print_status "INFO" "2.2.4 continued - Cloud Storage bucket configurations"
print_status "INFO" "Checking Cloud Storage buckets for secure configurations..."

storage_details="<p>Analysis of Cloud Storage bucket configurations:</p><ul>"

# Get all Cloud Storage buckets
buckets=$(run_across_projects "gsutil ls" 2>/dev/null | grep "gs://" | sed 's|gs://||' | sed 's|/$||')
bucket_count=0

if [ -n "$buckets" ]; then
    bucket_count=$(echo "$buckets" | grep -v "^$" | wc -l)
    
    if [ $bucket_count -gt 0 ]; then
        public_buckets=0
        unencrypted_buckets=0
        
        while IFS= read -r bucket; do
            if [ -z "$bucket" ]; then continue; fi
            
            # Check for public access
            bucket_iam=$(gsutil iam get "gs://$bucket" 2>/dev/null | grep -E "(allUsers|allAuthenticatedUsers)")
            if [ -n "$bucket_iam" ]; then
                ((public_buckets++))
            fi
            
            # Check for encryption (default encryption is always enabled in GCP)
            # But we can check if customer-managed encryption keys are used
            encryption_info=$(gsutil kms encryption "gs://$bucket" 2>/dev/null)
            if [[ "$encryption_info" == *"No encryption key"* ]]; then
                # This uses Google-managed encryption, which is still secure
                storage_details+="<li>Bucket $bucket: Using Google-managed encryption</li>"
            else
                storage_details+="<li>Bucket $bucket: Using customer-managed encryption</li>"
            fi
            
        done <<< "$buckets"
        
        if [ $public_buckets -gt 0 ]; then
            print_status "FAIL" "Public Cloud Storage buckets detected"
            storage_details+="<li class='red'>Public buckets detected: $public_buckets</li>"
            ((failed_checks++))
        else
            print_status "PASS" "No public Cloud Storage buckets detected"
            storage_details+="<li class='green'>No public buckets detected</li>"
            ((passed_checks++))
        fi
    else
        storage_details+="<li>No Cloud Storage buckets found</li>"
        ((passed_checks++))
    fi
else
    storage_details+="<li>No Cloud Storage buckets found or gsutil not available</li>"
    ((passed_checks++))
fi

storage_details+="</ul>"

add_section "$OUTPUT_FILE" "storage-security" "2.2.4 - Cloud Storage Security"
add_check_result "$OUTPUT_FILE" "info" "Cloud storage security analysis" "$storage_details" ""
((total_checks++))

#----------------------------------------------------------------------
# SECTION 3: PCI REQUIREMENT 2.3 - WIRELESS ENVIRONMENTS  
#----------------------------------------------------------------------
print_status "INFO" "=== PCI REQUIREMENT 2.3: WIRELESS ENVIRONMENTS CONFIGURED SECURELY ==="

# Check 2.3.1 & 2.3.2 - Wireless security
print_status "INFO" "2.3.1 & 2.3.2 - Wireless environment security"
print_status "INFO" "Checking for wireless environment configurations..."

wireless_details="<p>Analysis of wireless environment security:</p><ul>"

# GCP doesn't have traditional wireless infrastructure, but check for related services
wireless_details+="<li class='green'>GCP cloud infrastructure doesn't include traditional wireless access points</li>"
wireless_details+="<li>Wireless security is the responsibility of client-side infrastructure</li>"
wireless_details+="<li>Consider reviewing any hybrid connectivity solutions for wireless security</li>"

# Check for VPN connections which might involve wireless
vpn_gateways=$(run_across_projects "gcloud compute vpn-gateways list --format=value(name)" | grep -v "^$" | wc -l)

if [ $vpn_gateways -gt 0 ]; then
    wireless_details+="<li>VPN gateways found: $vpn_gateways</li>"
    wireless_details+="<li class='yellow'>Ensure VPN connections have appropriate encryption</li>"
    ((warning_checks++))
else
    wireless_details+="<li>No VPN gateways found</li>"
    ((passed_checks++))
fi

# Check for default service accounts (similar to AWS IAM default users)
print_status "INFO" "2.3.1 continued - Default account management"
print_status "INFO" "Checking for usage of default service accounts..."

default_sa_usage=$(run_across_projects "gcloud compute instances list --format=value(name,serviceAccounts.email)" | grep -E "(compute@developer|appspot)" | wc -l)

if [ $default_sa_usage -gt 0 ]; then
    wireless_details+="<li class='red'>Instances using default service accounts: $default_sa_usage</li>"
    ((failed_checks++))
else
    wireless_details+="<li class='green'>No instances using default service accounts</li>"
    ((passed_checks++))
fi

wireless_details+="</ul>"

add_section "$OUTPUT_FILE" "wireless-security" "2.3.1 & 2.3.2 - Wireless Environment Security"
add_check_result "$OUTPUT_FILE" "warning" "Wireless environment security analysis" "$wireless_details" ""
((total_checks++))

#----------------------------------------------------------------------
# SECTION 4: ADDITIONAL CHECKS BASED ON AWS R2 SCRIPT
#----------------------------------------------------------------------

# Check for TLS configuration on Load Balancers (equivalent to AWS ELB)
print_status "INFO" "2.2.7 continued - Load Balancer TLS Configuration"
print_status "INFO" "Checking load balancer TLS configurations..."

tls_details="<p>Analysis of load balancer TLS configurations:</p><ul>"

# Check for Load Balancers
load_balancers=$(run_across_projects "gcloud compute forwarding-rules list --format=value(name,target,portRange)" | grep -E "(https|ssl)")
lb_count=$(echo "$load_balancers" | grep -v "^$" | wc -l)

if [ $lb_count -gt 0 ]; then
    tls_details+="<li>HTTPS/SSL load balancers found: $lb_count</li>"
    tls_details+="<li class='green'>Load balancers are using encrypted connections</li>"
    ((passed_checks++))
else
    # Check for HTTP load balancers that should be HTTPS
    http_lbs=$(run_across_projects "gcloud compute forwarding-rules list --format=value(name,target,portRange)" | grep -E "80|8080")
    http_count=$(echo "$http_lbs" | grep -v "^$" | wc -l)
    
    if [ $http_count -gt 0 ]; then
        tls_details+="<li class='yellow'>HTTP load balancers found: $http_count</li>"
        tls_details+="<li>Consider migrating to HTTPS for encrypted communication</li>"
        ((warning_checks++))
    else
        tls_details+="<li>No load balancers found or all use encrypted protocols</li>"
        ((passed_checks++))
    fi
fi

tls_details+="</ul>"

add_section "$OUTPUT_FILE" "load-balancer-tls" "2.2.7 - Load Balancer TLS Configuration"
add_check_result "$OUTPUT_FILE" "info" "Load balancer TLS configuration analysis" "$tls_details" ""
((total_checks++))

# Check for audit logging (equivalent to AWS CloudTrail)
print_status "INFO" "2.5.1 - Audit logging for change management"
print_status "INFO" "Checking for audit logging configurations..."

audit_details="<p>Analysis of audit logging configurations:</p><ul>"

# Check for Cloud Audit Logs
audit_logs_enabled=0
if [[ "$ASSESSMENT_SCOPE" == "organization" && -n "$ORG_ID" ]]; then
    # Check organization-level audit logging
    org_audit_config=$(gcloud logging sinks list --organization=$ORG_ID --format="value(name)" 2>/dev/null | wc -l)
    if [ $org_audit_config -gt 0 ]; then
        audit_logs_enabled=1
        audit_details+="<li class='green'>Organization-level audit logging sinks found: $org_audit_config</li>"
    fi
else
    # Check project-level audit logging
    project_audit_config=$(gcloud logging sinks list --project=$PROJECT_ID --format="value(name)" 2>/dev/null | wc -l)
    if [ $project_audit_config -gt 0 ]; then
        audit_logs_enabled=1
        audit_details+="<li class='green'>Project-level audit logging sinks found: $project_audit_config</li>"
    fi
fi

# Check for Cloud Audit Logs API
audit_logs_api=$(gcloud services list --enabled --filter="name:cloudaudit.googleapis.com" --format="value(name)" 2>/dev/null)
if [ -n "$audit_logs_api" ]; then
    audit_details+="<li class='green'>Cloud Audit Logs API is enabled</li>"
    ((passed_checks++))
else
    audit_details+="<li class='red'>Cloud Audit Logs API is not enabled</li>"
    ((failed_checks++))
fi

audit_details+="</ul>"

add_section "$OUTPUT_FILE" "audit-logging" "2.5.1 - Audit Logging for Change Management"
add_check_result "$OUTPUT_FILE" "info" "Audit logging analysis" "$audit_details" ""
((total_checks++))

# Check for unused/unnecessary resources (equivalent to AWS unused security groups)
print_status "INFO" "2.6.1 - Unused resources cleanup"
print_status "INFO" "Checking for unused firewall rules and other resources..."

cleanup_details="<p>Analysis of potentially unused resources:</p><ul>"

# Check for unused firewall rules (rules not applied to any instances)
all_fw_rules=$(run_across_projects "gcloud compute firewall-rules list --format=value(name,targetTags.join(','),targetServiceAccounts.join(','),network)")
unused_fw_rules=0

if [ -n "$all_fw_rules" ]; then
    while IFS=$'\t' read -r fw_name tags service_accounts network; do
        if [ -z "$fw_name" ]; then continue; fi
        
        # If rule has no target tags or service accounts, it applies to all instances
        if [ -z "$tags" ] && [ -z "$service_accounts" ]; then
            continue
        fi
        
        # Check if any instances use these tags
        if [ -n "$tags" ]; then
            IFS=',' read -ra TAG_ARRAY <<< "$tags"
            rule_in_use=false
            
            for tag in "${TAG_ARRAY[@]}"; do
                instances_with_tag=$(run_across_projects "gcloud compute instances list --format=value(name) --filter=tags.items:$tag" | wc -l)
                if [ $instances_with_tag -gt 0 ]; then
                    rule_in_use=true
                    break
                fi
            done
            
            if [ "$rule_in_use" = false ]; then
                ((unused_fw_rules++))
            fi
        fi
    done <<< "$all_fw_rules"
fi

if [ $unused_fw_rules -gt 0 ]; then
    cleanup_details+="<li class='yellow'>Potentially unused firewall rules: $unused_fw_rules</li>"
    cleanup_details+="<li>Review and remove unused firewall rules to reduce complexity</li>"
    ((warning_checks++))
else
    cleanup_details+="<li class='green'>No obviously unused firewall rules detected</li>"
    ((passed_checks++))
fi

# Check for unused static IP addresses
unused_static_ips=$(run_across_projects "gcloud compute addresses list --format=value(name,status)" | grep "RESERVED" | wc -l)

if [ $unused_static_ips -gt 0 ]; then
    cleanup_details+="<li class='yellow'>Unused static IP addresses: $unused_static_ips</li>"
    cleanup_details+="<li>Consider releasing unused static IP addresses</li>"
    ((warning_checks++))
else
    cleanup_details+="<li class='green'>No unused static IP addresses found</li>"
    ((passed_checks++))
fi

cleanup_details+="</ul>"

add_section "$OUTPUT_FILE" "resource-cleanup" "2.6.1 - Unused Resources Cleanup"
add_check_result "$OUTPUT_FILE" "info" "Resource cleanup analysis" "$cleanup_details" ""
((total_checks++))

#----------------------------------------------------------------------
# FINAL REPORT
#----------------------------------------------------------------------

# Close the last section before adding summary
html_append "$OUTPUT_FILE" "            </div> <!-- Close final section content -->
        </div> <!-- Close final section -->"

# Add final summary metrics
add_summary_metrics "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks"

# Finalize HTML report using shared library
finalize_report "$OUTPUT_FILE" "${REQUIREMENT_NUMBER}"

# Display final summary using shared library
print_status "INFO" "=== ASSESSMENT SUMMARY ==="
print_status "INFO" "Total checks: $total_checks"
print_status "PASS" "Passed: $passed_checks"
print_status "FAIL" "Failed: $failed_checks"
print_status "WARN" "Warnings: $warning_checks"
print_status "INFO" "Report has been generated: $OUTPUT_FILE"
print_status "PASS" "=================================================================="