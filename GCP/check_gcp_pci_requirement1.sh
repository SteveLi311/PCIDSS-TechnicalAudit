#!/usr/bin/env bash

# PCI DSS Requirement 1 Compliance Check Script for GCP
# This script evaluates GCP network security controls for PCI DSS Requirement 1 compliance
# Requirements covered: 1.2 - 1.5 (Network Security Controls, CDE isolation, etc.)
# Requirement 1.1 removed - requires manual verification

# Load shared libraries using framework pattern
LIB_DIR="$(dirname "$0")/lib"

# Source all 4 required libraries
source_gcp_libraries() {
    source "$LIB_DIR/gcp_common.sh"
    source "$LIB_DIR/gcp_permissions.sh"
    source "$LIB_DIR/gcp_scope_mgmt.sh"
    source "$LIB_DIR/gcp_html_report.sh"
}

# Initialize framework
source_gcp_libraries

# Variables for scope control (will use shared library parsing)
ASSESSMENT_SCOPE="project"  # Default to project scope
SPECIFIC_PROJECT=""
SPECIFIC_ORG=""

# Function to show help
show_help() {
    echo "GCP PCI DSS Requirement 1 Assessment Script"
    echo "==========================================="
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -s, --scope SCOPE          Assessment scope: 'project' or 'organization' (default: project)"
    echo "  -p, --project PROJECT_ID   Specific project to assess (overrides current gcloud config)"
    echo "  -o, --org ORG_ID          Specific organization ID to assess (required for organization scope)"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Assess current project"
    echo "  $0 --scope project --project my-proj # Assess specific project" 
    echo "  $0 --scope organization --org 123456 # Assess entire organization"
    echo ""
    echo "Note: Organization scope requires appropriate permissions across all projects in the organization."
}

# Initialize framework environment
setup_environment

# Define variables
REQUIREMENT_NUMBER="1"

# Parse command line arguments using shared framework
parse_common_arguments "$@"

# Setup report configuration using shared library
load_requirement_config "${REQUIREMENT_NUMBER}"

# Validate scope and setup project context using shared library
setup_assessment_scope || exit 1

# Check permissions using shared library
check_required_permissions "compute.networks.list" "compute.firewalls.list" "compute.instances.list" "compute.routes.list" "compute.routers.list" "dns.managedZones.list" || exit 1

# Set output file path
OUTPUT_FILE="${REPORT_DIR}/pci_req${REQUIREMENT_NUMBER}_report_$(date +%Y%m%d_%H%M%S).html"

# Initialize HTML report using shared library
initialize_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report" "${REQUIREMENT_NUMBER}"

# Counters for checks  
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

# The shared library already set PROJECT_ID and ORG_ID, so we use those
# For backward compatibility with existing code, create aliases
DEFAULT_PROJECT="$PROJECT_ID"
DEFAULT_ORG="$ORG_ID"

# Function to get clean network names only
get_clean_networks() {
    gcloud compute networks list --project="$DEFAULT_PROJECT" --format="value(name)" 2>/dev/null | \
    grep -E '^[a-z][a-z0-9-]*[a-z0-9]$|^[a-z]$' | \
    sort | \
    uniq
}

# print_status function provided by gcp_common.sh framework library
# HTML functions now provided by gcp_html_report.sh framework library

# Function to check GCP API access

# Function to build scope-aware gcloud commands
build_gcloud_command() {
    local base_command=$1
    local project_override=$2
    
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        if [ -n "$project_override" ]; then
            echo "$base_command --project=$project_override"
        else
            echo "$base_command"
        fi
    else
        echo "$base_command --project=$DEFAULT_PROJECT"
    fi
}

# Function to get all VPC networks based on assessment scope
get_all_networks() {
    print_status "INFO" "Retrieving VPC networks for $ASSESSMENT_SCOPE scope..."
    
    if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
        # Get all projects in organization and their networks
        PROJECTS=$(gcloud projects list --filter="parent.id:$DEFAULT_ORG" --format="value(projectId)" 2>/dev/null)
        
        if [ -z "$PROJECTS" ]; then
            print_status "FAIL" "FAILED - No projects found in organization or access denied"
            return 1
        fi
        
        NETWORK_LIST=""
        project_count=0
        network_count=0
        
        for project in $PROJECTS; do
            ((project_count++))
            print_status "INFO" "  Checking project: $project"
            
            # Get networks for this project
            project_networks=$(gcloud compute networks list --project="$project" --format="value(name)" 2>/dev/null)
            
            if [ -n "$project_networks" ]; then
                # Prefix network names with project for organization scope
                while IFS= read -r network; do
                    if [ -n "$network" ]; then
                        NETWORK_LIST="${NETWORK_LIST}${project}/${network}"$'\n'
                        ((network_count++))
                    fi
                done <<< "$project_networks"
            fi
        done
        
        if [ $network_count -eq 0 ]; then
            print_status "FAIL" "FAILED - No VPC networks found across $project_count projects"
            return 1
        else
            print_status "PASS" "SUCCESS - Found $network_count VPC networks across $project_count projects"
            echo "$NETWORK_LIST"
            return 0
        fi
    else
        # Project scope - get networks for current/specified project
        NETWORK_LIST=$(gcloud compute networks list --project="$DEFAULT_PROJECT" --format="value(name)" 2>/dev/null)
        
        if [ -z "$NETWORK_LIST" ]; then
            print_status "FAIL" "FAILED - No VPC networks found in project $DEFAULT_PROJECT or access denied"
            return 1
        else
            network_count=$(echo "$NETWORK_LIST" | wc -l)
            print_status "PASS" "SUCCESS - Found $network_count VPC networks in project $DEFAULT_PROJECT"
            echo "$NETWORK_LIST"
            return 0
        fi
    fi
}

# Validate scope and requirements
if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
    if [ -z "$DEFAULT_ORG" ]; then
        print_status "FAIL" "Error: Organization scope requires an organization ID."
        print_status "WARN" "Please provide organization ID with --org flag or ensure you have organization access."
        exit 1
    fi
else
    # Project scope validation
    if [ -z "$DEFAULT_PROJECT" ]; then
        print_status "FAIL" "Error: No project specified."
        print_status "WARN" "Please set a default project with: gcloud config set project PROJECT_ID"
        print_status "WARN" "Or specify a project with: --project PROJECT_ID"
        exit 1
    fi
fi

# Start script execution
print_status "INFO" "============================================="
print_status "INFO" "  PCI DSS 4.0.1 - Requirement 1 (GCP)"
print_status "INFO" "============================================="
echo ""

# Display scope information
print_status "INFO" "Assessment Scope: $ASSESSMENT_SCOPE"
if [ "$ASSESSMENT_SCOPE" == "organization" ]; then
    print_status "INFO" "Organization: $DEFAULT_ORG"
    print_status "WARN" "Note: Organization-wide assessment may take longer and requires broader permissions"
else
    print_status "INFO" "Project: $DEFAULT_PROJECT"
fi
echo ""

# Ask for CDE networks
read -p "Enter CDE VPC network names (comma-separated or 'all' for all networks): " CDE_NETWORKS
if [ -z "$CDE_NETWORKS" ] || [ "$CDE_NETWORKS" == "all" ]; then
    print_status "WARN" "Checking all VPC networks"
    CDE_NETWORKS="all"
else
    print_status "WARN" "Checking specific networks: $CDE_NETWORKS"
fi

# Begin main assessment logic

echo ""
echo "Starting assessment at $(date)"
echo ""

# Reset counters for actual compliance checks
total_checks=0
passed_checks=0
warning_checks=0
failed_checks=0

#----------------------------------------------------------------------
# SECTION 2: DETERMINE NETWORKS TO CHECK
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "networks" "VPC Network Identification"

print_status "INFO" "=== IDENTIFYING TARGET VPC NETWORKS ==="

if [ "$CDE_NETWORKS" == "all" ]; then
    # Show console output for user visibility
    get_all_networks
    GET_NETWORKS_RESULT=$?
    if [ $GET_NETWORKS_RESULT -ne 0 ]; then
        print_status "FAIL" "Failed to retrieve VPC network information. Check your permissions."
        add_check_result "$OUTPUT_FILE" "fail" "Network Identification" "<p class='red'>Failed to retrieve VPC network information.</p>"
        exit 1
    else
        # Get clean network names using the dedicated function
        TARGET_NETWORKS=$(get_clean_networks)
        
        if [ -z "$TARGET_NETWORKS" ]; then
            print_status "FAIL" "No valid VPC networks found"
            add_check_result "$OUTPUT_FILE" "fail" "Network Identification" "<p class='red'>No valid VPC networks found in project.</p>"
            exit 1
        fi
        
        network_count=$(echo "$TARGET_NETWORKS" | wc -l)
        
        # Format network list for HTML display
        network_list_html="<ul>"
        while IFS= read -r network; do
            if [ -n "$network" ]; then
                network_list_html+="<li><strong>$network</strong></li>"
            fi
        done <<< "$TARGET_NETWORKS"
        network_list_html+="</ul>"
        
        add_check_result "$OUTPUT_FILE" "info" "Network Identification" "<p>All $network_count VPC networks will be assessed:</p>$network_list_html"
    fi
else
    TARGET_NETWORKS=$(echo $CDE_NETWORKS | tr ',' '\n')
    
    # Clean the specified network list
    CLEAN_NETWORKS=""
    while IFS= read -r network; do
        # Trim whitespace and validate network name
        network=$(echo "$network" | tr -d '[:space:]')
        if [[ "$network" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ ]]; then
            if [ -z "$CLEAN_NETWORKS" ]; then
                CLEAN_NETWORKS="$network"
            else
                CLEAN_NETWORKS="$CLEAN_NETWORKS"$'\n'"$network"
            fi
        fi
    done <<< "$TARGET_NETWORKS"
    
    TARGET_NETWORKS="$CLEAN_NETWORKS"
    network_count=$(echo "$TARGET_NETWORKS" | wc -l)
    
    # Format specified networks for HTML display
    network_list_html="<ul>"
    while IFS= read -r network; do
        if [ -n "$network" ]; then
            network_list_html+="<li><strong>$network</strong></li>"
        fi
    done <<< "$TARGET_NETWORKS"
    network_list_html+="</ul>"
    
    add_check_result "$OUTPUT_FILE" "info" "Network Identification" "<p>Assessment will be performed on $network_count specified networks:</p>$network_list_html"
fi

#----------------------------------------------------------------------
# SECTION 3: PCI REQUIREMENT 1.2 - NETWORK SECURITY CONTROLS CONFIG
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req12" "PCI Requirement 1.2 - Network Security Controls Configuration"

print_status "INFO" "=== PCI REQUIREMENT 1.2: NETWORK SECURITY CONTROLS CONFIGURATION ==="

# Check 1.2.5 - Ports, protocols, and services inventory
print_status "INFO" "1.2.5 - Ports, protocols, and services inventory"
print_status "INFO" "Checking firewall rules for allowed ports, protocols, and services..."

firewall_details="<p>Findings for allowed ports, protocols, and services:</p><ul>"

# Get all firewall rules
firewall_rules=$(gcloud compute firewall-rules list --format="value(name,direction,sourceRanges.join(','),allowed[].map().firewall_rule().list():label=ALLOW,targetTags.join(','),network)" 2>/dev/null)

if [ -z "$firewall_rules" ]; then
    print_status "WARN" "No firewall rules found"
    firewall_details+="<li class='yellow'>No firewall rules found</li>"
else
    # Process firewall rules
    while IFS=$'\t' read -r name direction sources allowed tags network; do
        if [ -z "$name" ]; then continue; fi
        
        firewall_details+="<li><strong>Firewall Rule:</strong> $name</li><ul>"
        firewall_details+="<li><strong>Direction:</strong> $direction</li>"
        firewall_details+="<li><strong>Network:</strong> $network</li>"
        
        # Check for overly permissive rules (0.0.0.0/0)
        if [[ "$sources" == *"0.0.0.0/0"* ]]; then
            print_status "FAIL" "SECURITY ISSUE: Firewall rule $name allows traffic from anywhere (0.0.0.0/0)"
            firewall_details+="<li class='red'><strong>SECURITY ISSUE:</strong> Allows traffic from anywhere (0.0.0.0/0)</li>"
            
            if [ -n "$allowed" ]; then
                firewall_details+="<li><strong>Allowed protocols/ports:</strong></li><ul>"
                # Parse allowed protocols and ports
                IFS=',' read -ra PROTOCOLS <<< "$allowed"
                for protocol in "${PROTOCOLS[@]}"; do
                    print_status "FAIL" "  $protocol open to the internet"
                    firewall_details+="<li class='red'>$protocol open to the internet</li>"
                done
                firewall_details+="</ul>"
            fi
        else
            print_status "PASS" "Firewall rule $name has restricted source ranges"
            firewall_details+="<li class='green'>Has restricted source ranges: $sources</li>"
        fi
        
        if [ -n "$tags" ]; then
            firewall_details+="<li><strong>Target tags:</strong> $tags</li>"
        fi
        
        firewall_details+="</ul>"
        
    done <<< "$firewall_rules"
fi

firewall_details+="</ul>"

add_check_result "$OUTPUT_FILE" "info" "1.2.5 - Ports, protocols, and services inventory" "$firewall_details"
((total_checks++))

# Check 1.2.6 - Security features for insecure services/protocols
print_status "INFO" "1.2.6 - Security features for insecure services/protocols"
print_status "INFO" "Checking for common insecure services/protocols in firewall rules..."

insecure_services=false
insecure_details="<p>Analysis of insecure services/protocols in firewall rules:</p><ul>"

# Check for insecure protocols in firewall rules
while IFS=$'\t' read -r name direction sources allowed tags network; do
    if [ -z "$name" ]; then continue; fi
    
    rule_has_insecure=false
    
    # Check for common insecure ports/protocols
    if [[ "$allowed" == *"tcp:21"* ]]; then
        print_status "FAIL" "WARNING: Firewall rule $name allows FTP (port 21)"
        insecure_details+="<li class='red'>Rule $name allows FTP (port 21) - Insecure cleartext protocol</li>"
        insecure_services=true
        rule_has_insecure=true
    fi
    
    if [[ "$allowed" == *"tcp:23"* ]]; then
        print_status "FAIL" "WARNING: Firewall rule $name allows Telnet (port 23)"
        insecure_details+="<li class='red'>Rule $name allows Telnet (port 23) - Insecure cleartext protocol</li>"
        insecure_services=true
        rule_has_insecure=true
    fi
    
    if [[ "$allowed" == *"tcp:1433"* ]]; then
        print_status "WARN" "NOTE: Firewall rule $name allows SQL Server (port 1433) - ensure encryption is in use"
        insecure_details+="<li class='yellow'>Rule $name allows SQL Server (port 1433) - Ensure encryption is in use</li>"
        insecure_services=true
        rule_has_insecure=true
    fi
    
    if [[ "$allowed" == *"tcp:3306"* ]]; then
        print_status "WARN" "NOTE: Firewall rule $name allows MySQL (port 3306) - ensure encryption is in use"
        insecure_details+="<li class='yellow'>Rule $name allows MySQL (port 3306) - Ensure encryption is in use</li>"
        insecure_services=true
        rule_has_insecure=true
    fi
    
done <<< "$firewall_rules"

insecure_details+="</ul>"

if [ "$insecure_services" = false ]; then
    print_status "PASS" "No common insecure services/protocols detected in firewall rules"
    add_check_result "$OUTPUT_FILE" "pass" "1.2.6 - Security features for insecure services/protocols" "<p class='green'>No common insecure services/protocols detected in firewall rules</p>"
    ((passed_checks++))
else
    print_status "FAIL" "Insecure services/protocols detected in firewall rules"
    add_check_result "$OUTPUT_FILE" "fail" "1.2.6 - Security features for insecure services/protocols" "$insecure_details"
    ((failed_checks++))
fi
((total_checks++))

# Check 1.2.7 - Regular review of NSC configurations
print_status "INFO" "1.2.7 - Regular review of NSC configurations"
print_status "INFO" "Checking for Security Command Center and monitoring configurations"

# Check if Security Command Center is enabled
scc_enabled=$(gcloud security-center organizations list 2>/dev/null | wc -l)
if [ $scc_enabled -gt 0 ]; then
    print_status "PASS" "Security Command Center is available for monitoring"
    add_check_result "$OUTPUT_FILE" "pass" "1.2.7 - NSC configuration monitoring" "<p class='green'>Security Command Center is available for monitoring NSC configurations.</p>"
    ((passed_checks++))
else
    print_status "WARN" "Security Command Center not detected"
    add_check_result "$OUTPUT_FILE" "warning" "1.2.7 - NSC configuration monitoring" "<p class='yellow'>Security Command Center not detected. Consider enabling for automated monitoring.</p>"
    ((warning_checks++))
fi
((total_checks++))

# Check 1.2.8 - NSC configuration files security
print_status "INFO" "1.2.8 - NSC configuration files security"
print_status "INFO" "Checking for IAM policies affecting NSC configuration security"

# Check for overly permissive IAM policies
compute_admin_bindings=$(gcloud projects get-iam-policy $DEFAULT_PROJECT --format="value(bindings[?role=='roles/compute.admin'].members[])" 2>/dev/null | wc -l)
network_admin_bindings=$(gcloud projects get-iam-policy $DEFAULT_PROJECT --format="value(bindings[?role=='roles/compute.networkAdmin'].members[])" 2>/dev/null | wc -l)

total_admin_bindings=$((compute_admin_bindings + network_admin_bindings))

if [ $total_admin_bindings -gt 5 ]; then
    print_status "WARN" "Multiple users/service accounts have network administration privileges"
    add_check_result "$OUTPUT_FILE" "warning" "1.2.8 - NSC configuration files security" "<p class='yellow'>Multiple users/service accounts have network administration privileges ($total_admin_bindings total). Review for least privilege compliance.</p>"
    ((warning_checks++))
else
    print_status "PASS" "Limited number of network administrators detected"
    add_check_result "$OUTPUT_FILE" "pass" "1.2.8 - NSC configuration files security" "<p class='green'>Limited number of network administrators detected ($total_admin_bindings total).</p>"
    ((passed_checks++))
fi
((total_checks++))

#----------------------------------------------------------------------
# SECTION 4: PCI REQUIREMENT 1.3 - CDE NETWORK ACCESS RESTRICTION
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req13" "PCI Requirement 1.3 - CDE Network Access Restriction"

print_status "INFO" "=== PCI REQUIREMENT 1.3: CDE NETWORK ACCESS RESTRICTION ==="

# Check 1.3.1 - Inbound traffic to CDE restriction
print_status "INFO" "1.3.1 - Inbound traffic to CDE restriction"
print_status "INFO" "Checking for properly restricted inbound traffic to CDE networks..."

inbound_restriction_details="<p>Analysis of inbound traffic controls for CDE networks:</p><ul>"

for network in $TARGET_NETWORKS; do
    if [ -z "$network" ]; then continue; fi
    
    inbound_restriction_details+="<li><strong>Network:</strong> $network</li><ul>"
    
    # Get subnets for this network
    subnets=$(gcloud compute networks subnets list --filter="network:$network" --format="value(name,region)" 2>/dev/null)
    
    if [ -z "$subnets" ]; then
        inbound_restriction_details+="<li class='yellow'>No subnets found in network</li>"
        continue
    fi
    
    # Check firewall rules for this network
    network_fw_rules=$(gcloud compute firewall-rules list --filter="network:$network AND direction:INGRESS" --format="value(name,sourceRanges.join(','),allowed[].map().firewall_rule().list():label=ALLOW)" 2>/dev/null)
    
    if [ -n "$network_fw_rules" ]; then
        inbound_restriction_details+="<li><strong>Ingress firewall rules:</strong></li><ul>"
        
        while IFS=$'\t' read -r fw_name sources allowed; do
            if [ -z "$fw_name" ]; then continue; fi
            
            inbound_restriction_details+="<li>$fw_name</li>"
            
            if [[ "$sources" == *"0.0.0.0/0"* ]]; then
                inbound_restriction_details+="<li class='red'>WARNING: Allows traffic from anywhere (0.0.0.0/0)</li>"
            else
                inbound_restriction_details+="<li class='green'>Restricted sources: $sources</li>"
            fi
            
        done <<< "$network_fw_rules"
        
        inbound_restriction_details+="</ul>"
    else
        inbound_restriction_details+="<li class='green'>No permissive ingress rules found</li>"
    fi
    
    inbound_restriction_details+="</ul>"
done

inbound_restriction_details+="</ul>"

add_check_result "$OUTPUT_FILE" "warning" "1.3.1 - Inbound traffic to CDE restriction" "$inbound_restriction_details"
((total_checks++))
((warning_checks++))

# Check 1.3.2 - Outbound traffic from CDE restriction
print_status "INFO" "1.3.2 - Outbound traffic from CDE restriction"
print_status "INFO" "Checking for properly restricted outbound traffic from CDE networks..."

outbound_restriction_details="<p>Analysis of outbound traffic controls for CDE networks:</p><ul>"

for network in $TARGET_NETWORKS; do
    if [ -z "$network" ]; then continue; fi
    
    outbound_restriction_details+="<li><strong>Network:</strong> $network</li><ul>"
    
    # Check egress firewall rules for this network
    network_egress_rules=$(gcloud compute firewall-rules list --filter="network:$network AND direction:EGRESS" --format="value(name,destinationRanges.join(','),allowed[].map().firewall_rule().list():label=ALLOW)" 2>/dev/null)
    
    if [ -n "$network_egress_rules" ]; then
        outbound_restriction_details+="<li><strong>Egress firewall rules:</strong></li><ul>"
        
        while IFS=$'\t' read -r fw_name destinations allowed; do
            if [ -z "$fw_name" ]; then continue; fi
            
            outbound_restriction_details+="<li>$fw_name</li>"
            
            if [[ "$destinations" == *"0.0.0.0/0"* ]]; then
                outbound_restriction_details+="<li class='yellow'>Allows traffic to anywhere (0.0.0.0/0)</li>"
            else
                outbound_restriction_details+="<li class='green'>Restricted destinations: $destinations</li>"
            fi
            
        done <<< "$network_egress_rules"
        
        outbound_restriction_details+="</ul>"
    else
        outbound_restriction_details+="<li class='yellow'>No explicit egress rules found (default allow all)</li>"
    fi
    
    outbound_restriction_details+="</ul>"
done

outbound_restriction_details+="</ul>"

add_check_result "$OUTPUT_FILE" "warning" "1.3.2 - Outbound traffic from CDE restriction" "$outbound_restriction_details"
((total_checks++))
((warning_checks++))

# Check 1.3.3 - Private IP filtering
print_status "INFO" "1.3.3 - Private IP filtering"
print_status "INFO" "Checking for private IP filtering at network boundaries..."

private_ip_details="<p>Analysis of potential private IP exposure:</p><ul>"

# Check for VPC peering connections
vpc_peerings=$(
  gcloud compute networks list --project="$DEFAULT_PROJECT" --format="value(name)" | while read net; do
    gcloud compute networks describe "$net" --project="$DEFAULT_PROJECT" --format="json" 2>/dev/null | jq -r "
      .peerings? // [] |
      .[] |
      \"\(.name)\t$net\t\(.network | split(\"/\") | last)\t\(.state)\"
    "
  done
)

if [ -z "$vpc_peerings" ]; then
    print_status "PASS" "No VPC peering connections detected"
    private_ip_details+="<li class='green'>No VPC peering connections detected</li>"
else
    print_status "WARN" "VPC peering connections detected - potential private IP routing:"
    private_ip_details+="<li class='yellow'>VPC peering connections detected:</li><ul>"

    while IFS=$'\t' read -r peering_name network peer_network state; do
    	if [ -z "$peering_name" ]; then continue; fi
    	print_status "WARN" "  Peering: $peering_name ($network <-> $peer_network) [State: $state]"
    	private_ip_details+="<li>$peering_name: $network ↔ $peer_network (State: $state)</li>"
        done <<< "$vpc_peerings"

    private_ip_details+="</ul>"
fi

# Check for VPN connections
vpn_gateways=$(gcloud compute vpn-gateways list --format="value(name,region)" 2>/dev/null)

if [ -z "$vpn_gateways" ]; then
    print_status "PASS" "No VPN gateways detected"
    private_ip_details+="<li class='green'>No VPN gateways detected</li>"
else
    print_status "WARN" "VPN gateways detected - potential private IP routing:"
    private_ip_details+="<li class='yellow'>VPN gateways detected:</li><ul>"
    
    while IFS=$'\t' read -r gw_name region; do
        if [ -z "$gw_name" ]; then continue; fi
        
        print_status "WARN" "  VPN Gateway: $gw_name (region: $region)"
        private_ip_details+="<li>$gw_name (region: $region)</li>"
        
    done <<< "$vpn_gateways"
    
    private_ip_details+="</ul>"
fi

private_ip_details+="</ul>"

add_check_result "$OUTPUT_FILE" "info" "1.3.3 - Private IP filtering" "$private_ip_details"
((total_checks++))

#----------------------------------------------------------------------
# SECTION 5: PCI REQUIREMENT 1.4 - NETWORK CONNECTIONS
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req14" "PCI Requirement 1.4 - Network Connections"

print_status "INFO" "=== PCI REQUIREMENT 1.4: NETWORK CONNECTIONS BETWEEN TRUSTED/UNTRUSTED NETWORKS ==="

# Check 1.4.1 - Network connection controls
print_status "INFO" "1.4.1 - Network connection controls"
print_status "INFO" "Checking for controls on network connections between trusted and untrusted networks..."

connection_controls_details="<p>Analysis of network connections between trusted and untrusted networks:</p><ul>"

for network in $TARGET_NETWORKS; do
    if [ -z "$network" ]; then continue; fi
    
    connection_controls_details+="<li><strong>Network:</strong> $network</li><ul>"
    
    # Check for Cloud NAT
    cloud_nats=$(gcloud compute routers list --filter="network:$network" --format="value(name,region)" 2>/dev/null)
    
    if [ -n "$cloud_nats" ]; then
        connection_controls_details+="<li class='green'>Cloud NAT routers detected (controlled outbound access):</li><ul>"
        
        while IFS=$'\t' read -r router_name region; do
            if [ -z "$router_name" ]; then continue; fi
            
            connection_controls_details+="<li>$router_name (region: $region)</li>"
            
        done <<< "$cloud_nats"
        
        connection_controls_details+="</ul>"
    else
        connection_controls_details+="<li class='yellow'>No Cloud NAT routers detected</li>"
    fi
    
    # Check for external IP addresses on instances
    external_ips=$(gcloud compute instances list --filter="networkInterfaces.network:$network" --format="value(name,networkInterfaces[0].accessConfigs[0].natIP)" 2>/dev/null | grep -v "^[[:space:]]*$")
    
    if [ -n "$external_ips" ]; then
        connection_controls_details+="<li class='yellow'>Instances with external IP addresses:</li><ul>"
        
        while IFS=$'\t' read -r instance_name external_ip; do
            if [ -z "$instance_name" ]; then continue; fi
            
            if [ -n "$external_ip" ]; then
                connection_controls_details+="<li>$instance_name: $external_ip</li>"
            fi
            
        done <<< "$external_ips"
        
        connection_controls_details+="</ul>"
    else
        connection_controls_details+="<li class='green'>No instances with external IP addresses detected</li>"
    fi
    
    connection_controls_details+="</ul>"
done

connection_controls_details+="</ul>"

add_check_result "$OUTPUT_FILE" "info" "1.4.1 - Network connection controls" "$connection_controls_details"
((total_checks++))

# Check 1.4.2 - Private IP address filtering
print_status "INFO" "1.4.2 - Private IP address filtering"
print_status "INFO" "Checking for private IP address filtering controls..."

# Check for VPC Service Controls
vsc_perimeters=""
if [ -n "$DEFAULT_ORG" ]; then
    # Try to get access policies first
    access_policies=$(gcloud access-context-manager policies list --organization=$DEFAULT_ORG --format="value(name)" 2>/dev/null)
    
    if [ -n "$access_policies" ]; then
        for policy in $access_policies; do
            perimeters=$(gcloud access-context-manager perimeters list --policy=$policy --format="value(name,title)" 2>/dev/null)
            if [ -n "$perimeters" ]; then
                vsc_perimeters+="$perimeters"$'\n'
            fi
        done
    fi
fi

vsc_details="<p>Analysis of private IP address filtering controls:</p><ul>"

if [ -n "$vsc_perimeters" ]; then
    print_status "PASS" "VPC Service Controls perimeters detected"
    vsc_details+="<li class='green'>VPC Service Controls perimeters detected:</li><ul>"
    
    while IFS=$'\t' read -r perimeter_name title; do
        if [ -z "$perimeter_name" ]; then continue; fi
        
        vsc_details+="<li>$perimeter_name ($title)</li>"
        
    done <<< "$vsc_perimeters"
    
    vsc_details+="</ul>"
    vsc_details+="<li>These provide additional private IP filtering controls</li>"
    
    add_check_result "$OUTPUT_FILE" "pass" "1.4.2 - Private IP address filtering" "$vsc_details"
    ((passed_checks++))
else
    print_status "WARN" "No VPC Service Controls perimeters detected"
    vsc_details+="<li class='yellow'>No VPC Service Controls perimeters detected</li>"
    vsc_details+="<li>Consider implementing VPC Service Controls for enhanced private IP filtering</li>"
    
    add_check_result "$OUTPUT_FILE" "warning" "1.4.2 - Private IP address filtering" "$vsc_details"
    ((warning_checks++))
fi

vsc_details+="</ul>"
((total_checks++))

#----------------------------------------------------------------------
# SECTION 6: PCI REQUIREMENT 1.5 - FIREWALL RULE MANAGEMENT
#----------------------------------------------------------------------
add_section "$OUTPUT_FILE" "req15" "PCI Requirement 1.5 - Network Security Control Ruleset Management"

print_status "INFO" "=== PCI REQUIREMENT 1.5: NETWORK SECURITY CONTROL RULESET MANAGEMENT ==="

# Check 1.5.1 - Firewall rule management
print_status "INFO" "1.5.1 - Firewall rule management"
print_status "INFO" "Checking for proper firewall rule management..."

rule_management_details="<p>Analysis of firewall rule management:</p><ul>"

# Get all firewall rules and analyze them
all_fw_rules=$(gcloud compute firewall-rules list --format="value(name,disabled,priority,direction)" 2>/dev/null)

total_rules=0
disabled_rules=0
high_priority_rules=0

while IFS=$'\t' read -r rule_name disabled priority direction; do
    if [ -z "$rule_name" ]; then continue; fi
    
    ((total_rules++))
    
    if [ "$disabled" == "True" ]; then
        ((disabled_rules++))
    fi
    
    # Check for high priority rules (lower number = higher priority)
    if [ -n "$priority" ] && [ "$priority" -lt 1000 ]; then
        ((high_priority_rules++))
    fi
    
done <<< "$all_fw_rules"

rule_management_details+="<li><strong>Total firewall rules:</strong> $total_rules</li>"
rule_management_details+="<li><strong>Disabled rules:</strong> $disabled_rules</li>"
rule_management_details+="<li><strong>High priority rules:</strong> $high_priority_rules</li>"

if [ $disabled_rules -gt 0 ]; then
    rule_management_details+="<li class='yellow'>Consider removing disabled firewall rules to simplify management</li>"
fi

if [ $total_rules -gt 50 ]; then
    rule_management_details+="<li class='yellow'>Large number of firewall rules detected - review for consolidation opportunities</li>"
fi

# Check for default-allow rules
default_allow_rules=$(gcloud compute firewall-rules list --filter="name:default-allow*" --format="value(name)" 2>/dev/null | wc -l)

if [ $default_allow_rules -gt 0 ]; then
    rule_management_details+="<li class='red'>Default allow rules detected: $default_allow_rules</li>"
    rule_management_details+="<li>Review default allow rules for security implications</li>"
else
    rule_management_details+="<li class='green'>No default allow rules detected</li>"
fi

rule_management_details+="</ul>"

add_check_result "$OUTPUT_FILE" "info" "1.5.1 - Firewall rule management" "$rule_management_details"
((total_checks++))

#----------------------------------------------------------------------
# FINAL REPORT
#----------------------------------------------------------------------

# Close the last section before adding summary
html_append "$OUTPUT_FILE" "            </div> <!-- Close final section content -->
        </div> <!-- Close final section -->"

# Add summary metrics before finalizing
add_summary_metrics "$OUTPUT_FILE" "$total_checks" "$passed_checks" "$failed_checks" "$warning_checks"

# Finalize the report
finalize_report "$OUTPUT_FILE" "$REQUIREMENT_NUMBER"

echo ""
print_status "PASS" "======================= ASSESSMENT SUMMARY ======================="
echo "Total checks performed: $total_checks"
echo "Passed checks: $passed_checks"
echo "Failed checks: $failed_checks"
echo "Warning checks: $warning_checks"
print_status "PASS" "=================================================================="
echo ""
print_status "INFO" "Report has been generated: $OUTPUT_FILE"
print_status "PASS" "=================================================================="