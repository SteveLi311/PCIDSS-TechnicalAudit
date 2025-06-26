#!/usr/bin/env bash

# Function to convert a PCI requirement script to use shared libraries
convert_requirement_script() {
    local req_num=$1
    local permissions=$2
    local file_path="/Users/namhp/Resilio.Sync/PCI.DSS/GCP/check_gcp_pci_requirement${req_num}.sh"
    
    echo "Converting requirement $req_num..."
    
    # Create backup
    cp "$file_path" "${file_path}.backup"
    
    # Apply transformations using sed
    sed -i '' '
    # Replace the header and color definitions with shared library imports
    /^#!/,/^NC=/ {
        /^#!/ {
            a\
#!/usr/bin/env bash\
\
# PCI DSS Requirement '$req_num' Compliance Check Script for GCP\
\
# Load shared libraries\
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\
LIB_DIR="$SCRIPT_DIR/lib"\
\
source "$LIB_DIR/gcp_common.sh" || exit 1\
source "$LIB_DIR/gcp_permissions.sh" || exit 1\
source "$LIB_DIR/gcp_scope_mgmt.sh" || exit 1\
source "$LIB_DIR/gcp_html_report.sh" || exit 1\
\
# Script-specific variables\
REQUIREMENT_NUMBER="'$req_num'"\
\
# Initialize environment\
init_gcp_environment || exit 1
            d
        }
        /^# Set output colors/,/^NC=/ d
    }
    
    # Replace variables and argument parsing section
    /^# Variables for scope control/,/^done$/ {
        c\
# Parse command line arguments using shared function\
parse_common_arguments "$@"\
case $? in\
    1) exit 1 ;;  # Error\
    2) exit 0 ;;  # Help displayed\
esac
    }
    
    # Replace setup section
    /^# Define variables/,/^mkdir -p/ {
        c\
# Setup report configuration using shared library\
setup_report_config "req${REQUIREMENT_NUMBER}"\
\
# Validate scope and setup project context using shared library\
validate_scope_and_setup || exit 1\
\
# Check permissions using shared library\
check_required_permissions '$permissions' || exit 1\
\
# Initialize HTML report using shared library\
initialize_gcp_html_report "$OUTPUT_FILE" "PCI DSS 4.0.1 - Requirement $REQUIREMENT_NUMBER Compliance Assessment Report"\
# Begin main assessment logic
    }
    
    # Remove legacy function definitions
    /^# Function to print colored output/,/^}$/ d
    /^# Function to add HTML report sections/,/^}$/ d
    /^# Function to initialize HTML report/,/^}$/ d
    /^# Function to finalize HTML report/,/^}$/ d
    /^# Function to check GCP API access/,/^}$/ d
    /^# Function to build scope-aware gcloud commands/,/^}$/ d
    /^# Function to get all projects in scope/,/^}$/ d
    /^# Function to run command across all projects in scope/,/^}$/ d
    
    # Remove validation and setup sections
    /^# Validate scope and requirements/,/^echo ""$/ d
    /^# Get project and organization info/,/^fi$/ d
    /^# Check if gcloud is configured/,/^fi$/ d
    /^# Verify authentication/,/^fi$/ d
    /^# Start script execution/,/^echo ""$/ d
    /^# Display scope information/,/^echo ""$/ d
    /^# Initialize HTML report/,/^echo ""$/ d
    
    # Remove permissions check sections
    /^#.*PERMISSIONS CHECK/,/^# Reset counters/ {
        /^# Reset counters/ !d
    }
    
    ' "$file_path"
    
    # Replace run_across_projects calls
    sed -i '' 's/run_across_projects/run_gcp_command_across_projects/g' "$file_path"
    
    # Update finalization section if it exists
    if grep -q "finalize_html_report" "$file_path"; then
        sed -i '' '/finalize_html_report/,$ {
            c\
#----------------------------------------------------------------------\
# FINAL REPORT\
#----------------------------------------------------------------------\
\
# Finalize HTML report using shared library\
finalize_gcp_html_report "$OUTPUT_FILE"\
\
# Display final summary using shared library\
display_final_summary "PCI DSS Requirement $REQUIREMENT_NUMBER"\
print_status $CYAN "Report has been generated: $OUTPUT_FILE"\
print_status $GREEN "=================================================================="
        }' "$file_path"
    fi
    
    echo "Requirement $req_num converted successfully"
}

# Convert each requirement with appropriate permissions
convert_requirement_script "4" '"compute.sslPolicies.list" "compute.targetHttpsProxies.list" "compute.urlMaps.list"'
convert_requirement_script "5" '"compute.instances.list" "compute.instanceTemplates.list"'
convert_requirement_script "6" '"clouddeploy.deliveryPipelines.list" "run.services.list"'
convert_requirement_script "7" '"iam.roles.list" "iam.serviceAccounts.list"'
convert_requirement_script "8" '"iam.serviceAccounts.list" "compute.instances.list"'
convert_requirement_script "9" '"compute.instances.list" "compute.zones.list"'
convert_requirement_script "10" '"logging.logs.list" "logging.sinks.list"'
convert_requirement_script "11" '"compute.instanceGroups.list" "container.clusters.list"'
convert_requirement_script "12" '"resourcemanager.projects.getIamPolicy" "iam.serviceAccounts.list"'

echo "All requirements converted successfully!"