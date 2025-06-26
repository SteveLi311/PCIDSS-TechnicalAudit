# GCP PCI DSS Framework Migration Guide

## Overview

This guide provides detailed migration procedures for converting existing PCI DSS assessment scripts to use the complete 4-library GCP shared framework, ensuring backward compatibility while gaining enhanced functionality and maintainability.

## Migration Assessment

### Pre-Migration Checklist

Before starting migration, assess your current scripts:

- [ ] **Script Inventory**: Catalog all existing assessment scripts
- [ ] **Functionality Analysis**: Document current features and behaviors
- [ ] **Dependencies**: Identify external dependencies and integrations
- [ ] **Output Format**: Document expected output formats and report structures
- [ ] **Performance Baseline**: Measure current execution times and resource usage
- [ ] **Testing Strategy**: Plan validation approach for migrated scripts

### Current State Analysis

#### Script Categories
1. **Simple Assessment Scripts**: Basic checks with minimal functionality
2. **Complex Multi-Check Scripts**: Comprehensive assessments with detailed reporting
3. **Organization-Wide Scripts**: Multi-project assessment capabilities
4. **Custom Integration Scripts**: Scripts with external system integrations

#### Common Legacy Patterns to Replace
- Manual color and formatting definitions
- Custom CLI argument parsing
- Duplicated permission checking logic
- Manual HTML report generation
- Custom project enumeration for organization assessments
- Inconsistent error handling and logging

## Migration Strategies

### Strategy 1: Incremental Migration (Recommended)

Migrate functionality incrementally to minimize risk and enable validation at each step.

#### Phase 1: Core Framework Integration
**Objective**: Replace basic functionality with shared libraries
**Duration**: 1-2 days per script
**Risk**: Low

```bash
# Before: Legacy argument parsing
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--project) PROJECT_ID="$2"; shift 2 ;;
        -v|--verbose) VERBOSE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# After: Shared framework integration
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh"
parse_common_arguments "$@"
```

#### Phase 2: Permission Management Integration
**Objective**: Standardize permission handling
**Duration**: 2-3 days per script
**Risk**: Low-Medium

```bash
# Before: Manual permission checking
if ! gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
    echo "ERROR: Cannot access project $PROJECT_ID"
    exit 1
fi

if ! gcloud compute instances list --project="$PROJECT_ID" >/dev/null 2>&1; then
    echo "ERROR: Missing compute.instances.list permission"
    exit 1
fi

# After: Shared permission framework
source "$LIB_DIR/gcp_permissions.sh"
init_permissions_framework
register_required_permissions "1" \
    "compute.instances.list" \
    "resourcemanager.projects.get"

if ! check_all_permissions; then
    prompt_continue_limited || exit 1
fi
```

#### Phase 3: HTML Reporting Integration
**Objective**: Add professional HTML reporting capabilities
**Duration**: 3-5 days per script
**Risk**: Medium

```bash
# Before: Manual output formatting
echo "=== PCI DSS Requirement 1 Assessment ==="
echo "Project: $PROJECT_ID"
echo "Timestamp: $(date)"
echo ""
echo "PASS: Firewall rules configured"
echo "FAIL: Found open SSH access"

# After: HTML reporting integration
source "$LIB_DIR/gcp_html_report.sh"
OUTPUT_FILE="assessment_$(date +%Y%m%d_%H%M%S).html"
initialize_report "PCI DSS Requirement 1 Assessment" "project"

add_section "firewall_assessment" "Firewall Configuration" "Network security assessment"
add_check_result "Firewall Rules" "PASS" "Firewall rules configured correctly" ""
add_check_result "SSH Access" "FAIL" "Found open SSH access from 0.0.0.0/0" "Restrict source IP ranges"
close_section

add_summary_metrics 10 8 2 0 0
finalize_report
```

#### Phase 4: Scope Management Integration
**Objective**: Enable organization-wide assessments
**Duration**: 2-4 days per script
**Risk**: Medium

```bash
# Before: Manual organization handling
if [[ "$SCOPE" == "organization" ]]; then
    PROJECTS=$(gcloud projects list --filter="parent.id:$ORG_ID" --format="value(projectId)")
else
    PROJECTS="$PROJECT_ID"
fi

for project in $PROJECTS; do
    echo "Assessing project: $project"
    # Manual project-specific logic
done

# After: Scope management integration
source "$LIB_DIR/gcp_scope_mgmt.sh"
setup_assessment_scope
projects=$(get_projects_in_scope)

for project in $projects; do
    print_status "INFO" "Assessing project: $project"
    
    add_section "project_${project}" "Project: ${project}" "Assessment for project ${project}"
    
    # Use build_gcloud_command for scope-aware execution
    instances_cmd=$(build_gcloud_command "gcloud compute instances list" "$project")
    # ... assessment logic ...
    
    close_section
done
```

### Strategy 2: Complete Rewrite

For heavily customized or problematic legacy scripts, a complete rewrite may be more efficient.

#### When to Use Complete Rewrite
- Legacy script has significant technical debt
- Current functionality is poorly documented
- Script architecture doesn't align with framework patterns
- Performance requirements necessitate fundamental changes

#### Rewrite Process
1. **Document Current Behavior**: Capture all current functionality and edge cases
2. **Design New Architecture**: Plan integration with all 4 libraries
3. **Implement Core Logic**: Build assessment logic using framework patterns
4. **Add Enhanced Features**: Leverage framework capabilities for improvements
5. **Comprehensive Testing**: Validate against legacy script behavior

## Detailed Migration Procedures

### Step 1: Environment Setup

#### 1.1 Verify Framework Installation
```bash
# Check library availability
LIB_DIR="$(dirname "$0")/lib"
REQUIRED_LIBRARIES=(
    "gcp_common.sh"
    "gcp_permissions.sh"
    "gcp_html_report.sh"
    "gcp_scope_mgmt.sh"
)

for lib in "${REQUIRED_LIBRARIES[@]}"; do
    if [[ ! -f "$LIB_DIR/$lib" ]]; then
        echo "ERROR: Missing library: $lib"
        exit 1
    fi
    echo "✓ Found: $lib"
done
```

#### 1.2 Create Migration Backup
```bash
# Backup original script before migration
ORIGINAL_SCRIPT="$1"
BACKUP_DIR="./migration_backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp "$ORIGINAL_SCRIPT" "$BACKUP_DIR/"
echo "Original script backed up to: $BACKUP_DIR/"
```

### Step 2: Framework Integration

#### 2.1 Basic Library Loading
```bash
# Replace script header with framework loading
cat > script_header.sh << 'EOF'
#!/usr/bin/env bash
# Migrated to GCP PCI DSS Shared Framework

# Load shared library framework
LIB_DIR="$(dirname "$0")/lib"
source "$LIB_DIR/gcp_common.sh"
source "$LIB_DIR/gcp_permissions.sh"
source "$LIB_DIR/gcp_html_report.sh"
source "$LIB_DIR/gcp_scope_mgmt.sh"

# Main function with framework integration
main() {
    # Setup environment
    setup_environment "$(get_script_name).log"
    parse_common_arguments "$@"
    
    # Initialize frameworks
    init_permissions_framework
    setup_assessment_scope
    
    # Your migrated assessment logic here
    perform_assessment
    
    # Cleanup
    cleanup_temp_files
}

# Assessment logic function
perform_assessment() {
EOF
```

#### 2.2 Argument Parsing Migration
```bash
# Migration helper for argument parsing
migrate_argument_parsing() {
    local legacy_script="$1"
    
    # Extract legacy argument parsing
    local legacy_args=$(grep -A 20 "while.*getopts\|while.*\[\[.*#.*gt.*0" "$legacy_script" | head -20)
    
    echo "# Legacy argument parsing found:"
    echo "# $legacy_args"
    echo ""
    echo "# Replaced with:"
    echo "parse_common_arguments \"\$@\""
    echo ""
    echo "# Available variables after parsing:"
    echo "# PROJECT_ID, ORG_ID, SCOPE_TYPE, VERBOSE, OUTPUT_DIR, etc."
}
```

### Step 3: Permission Management Migration

#### 3.1 Extract Permission Requirements
```bash
# Analyze legacy script for permission usage
extract_permissions() {
    local script="$1"
    
    echo "# Analyzing permission requirements in: $script"
    
    # Find gcloud commands and extract required permissions
    grep -n "gcloud " "$script" | while read -r line; do
        local line_num=$(echo "$line" | cut -d: -f1)
        local command=$(echo "$line" | cut -d: -f2-)
        
        case "$command" in
            *"compute instances"*) echo "compute.instances.list" ;;
            *"compute firewall"*) echo "compute.firewalls.list" ;;
            *"compute networks"*) echo "compute.networks.list" ;;
            *"projects describe"*) echo "resourcemanager.projects.get" ;;
            *"projects list"*) echo "resourcemanager.projects.list" ;;
            *"organizations describe"*) echo "resourcemanager.organizations.get" ;;
        esac
    done | sort -u
}
```

#### 3.2 Generate Permission Registration Code
```bash
# Generate permission registration for migrated script
generate_permission_code() {
    local script="$1"
    local requirement_num="$2"
    local permissions=($(extract_permissions "$script"))
    
    echo "# Generated permission registration:"
    echo "register_required_permissions \"$requirement_num\" \\"
    
    for i in "${!permissions[@]}"; do
        if [[ $i -eq $((${#permissions[@]} - 1)) ]]; then
            echo "    \"${permissions[$i]}\""
        else
            echo "    \"${permissions[$i]}\" \\"
        fi
    done
    
    echo ""
    echo "if ! check_all_permissions; then"
    echo "    prompt_continue_limited || exit 1"
    echo "fi"
}
```

### Step 4: Output Format Migration

#### 4.1 Console Output to HTML Migration
```bash
# Convert console output to HTML reporting
migrate_output_format() {
    local legacy_script="$1"
    
    # Extract status messages
    grep -n "echo.*PASS\|echo.*FAIL\|echo.*WARN" "$legacy_script" | while read -r line; do
        local line_num=$(echo "$line" | cut -d: -f1)
        local message=$(echo "$line" | cut -d: -f2- | sed 's/echo//' | tr -d '"')
        
        # Parse status and message
        local status=$(echo "$message" | grep -o "PASS\|FAIL\|WARN\|INFO")
        local content=$(echo "$message" | sed "s/$status: //")
        
        echo "# Line $line_num: $message"
        echo "add_check_result \"Check Name\" \"$status\" \"$content\" \"\""
        echo ""
    done
}
```

#### 4.2 Report Structure Migration
```bash
# Generate HTML report structure
generate_report_structure() {
    local script_name="$1"
    local requirement_num="$2"
    
    cat << EOF
# HTML Report Generation
OUTPUT_FILE="${script_name}_\$(date +%Y%m%d_%H%M%S).html"
initialize_report "PCI DSS Requirement $requirement_num Assessment" "\$ASSESSMENT_SCOPE"

# Main assessment section
add_section "requirement_${requirement_num}" "PCI DSS Requirement $requirement_num" "Comprehensive assessment of requirement $requirement_num"

# Your migrated check results go here
# add_check_result "Check Name" "STATUS" "Details" "Recommendation"

close_section

# Add summary metrics (update counts based on actual results)
add_summary_metrics \$total_checks \$passed \$failed \$warnings \$manual
finalize_report

print_status "PASS" "Assessment completed: \$OUTPUT_FILE"
EOF
}
```

### Step 5: Testing and Validation

#### 5.1 Functionality Testing
```bash
# Comprehensive testing script for migrated functionality
test_migrated_script() {
    local original_script="$1"
    local migrated_script="$2"
    local test_project="$3"
    
    echo "=== Migration Testing ==="
    echo "Original: $original_script"
    echo "Migrated: $migrated_script"
    echo "Test Project: $test_project"
    echo ""
    
    # Test basic execution
    echo "Testing basic execution..."
    if bash "$migrated_script" -p "$test_project" -h >/dev/null 2>&1; then
        echo "✓ Help output works"
    else
        echo "✗ Help output failed"
    fi
    
    # Test permission handling
    echo "Testing permission handling..."
    if bash "$migrated_script" -p "$test_project" --dry-run 2>/dev/null; then
        echo "✓ Permission checking works"
    else
        echo "✗ Permission checking failed"
    fi
    
    # Test HTML report generation
    echo "Testing HTML report generation..."
    if bash "$migrated_script" -p "$test_project" >/dev/null 2>&1; then
        if [[ -f *.html ]]; then
            echo "✓ HTML report generated"
            rm *.html
        else
            echo "✗ HTML report not generated"
        fi
    else
        echo "✗ Script execution failed"
    fi
}
```

#### 5.2 Performance Comparison
```bash
# Compare performance between original and migrated scripts
compare_performance() {
    local original_script="$1"
    local migrated_script="$2"
    local test_project="$3"
    local iterations=5
    
    echo "=== Performance Comparison ==="
    
    # Test original script
    local original_times=()
    for i in $(seq 1 $iterations); do
        local start_time=$(date +%s.%N)
        bash "$original_script" -p "$test_project" >/dev/null 2>&1
        local end_time=$(date +%s.%N)
        local duration=$(echo "$end_time - $start_time" | bc -l)
        original_times+=($duration)
    done
    
    # Test migrated script
    local migrated_times=()
    for i in $(seq 1 $iterations); do
        local start_time=$(date +%s.%N)
        bash "$migrated_script" -p "$test_project" >/dev/null 2>&1
        local end_time=$(date +%s.%N)
        local duration=$(echo "$end_time - $start_time" | bc -l)
        migrated_times+=($duration)
    done
    
    # Calculate averages
    local original_avg=$(echo "${original_times[*]}" | awk '{sum=0; for(i=1;i<=NF;i++)sum+=$i; print sum/NF}')
    local migrated_avg=$(echo "${migrated_times[*]}" | awk '{sum=0; for(i=1;i<=NF;i++)sum+=$i; print sum/NF}')
    
    echo "Original script average: ${original_avg}s"
    echo "Migrated script average: ${migrated_avg}s"
    
    # Calculate overhead
    local overhead=$(echo "scale=2; ($migrated_avg - $original_avg) / $original_avg * 100" | bc -l)
    echo "Performance overhead: ${overhead}%"
    
    if (( $(echo "$overhead < 10" | bc -l) )); then
        echo "✓ Performance within acceptable limits"
    else
        echo "⚠ Performance overhead exceeds 10% - review optimization"
    fi
}
```

## Common Migration Patterns

### Pattern 1: Status Output Migration

#### Before (Legacy):
```bash
echo -e "${GREEN}[PASS]${NC} Firewall rules configured correctly"
echo -e "${RED}[FAIL]${NC} Found insecure SSH access"
echo -e "${YELLOW}[WARN]${NC} Default network detected"
```

#### After (Framework):
```bash
add_check_result "Firewall Configuration" "PASS" "Firewall rules configured correctly" ""
add_check_result "SSH Access Security" "FAIL" "Found insecure SSH access from 0.0.0.0/0" "Restrict source IP ranges"
add_check_result "Network Configuration" "WARN" "Default network detected" "Consider using custom networks"
```

### Pattern 2: Project Iteration Migration

#### Before (Legacy):
```bash
if [[ "$SCOPE" == "organization" ]]; then
    PROJECTS=$(gcloud projects list --filter="parent.id:$ORG_ID" --format="value(projectId)")
else
    PROJECTS="$PROJECT_ID"
fi

for project in $PROJECTS; do
    echo "Processing project: $project"
    gcloud compute instances list --project="$project"
done
```

#### After (Framework):
```bash
setup_assessment_scope
projects=$(get_projects_in_scope)

for project in $projects; do
    print_status "INFO" "Processing project: $project"
    
    add_section "project_${project}" "Project: ${project}" "Assessment for project ${project}"
    
    instances_cmd=$(build_gcloud_command "gcloud compute instances list" "$project")
    if eval "$instances_cmd" >/dev/null 2>&1; then
        add_check_result "Instance Access" "PASS" "Successfully accessed instances" ""
    else
        add_check_result "Instance Access" "FAIL" "Cannot access instances" "Check permissions"
    fi
    
    close_section
done
```

### Pattern 3: Error Handling Migration

#### Before (Legacy):
```bash
if ! gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
    echo "ERROR: Cannot access project $PROJECT_ID"
    echo "Please check:"
    echo "1. Project ID is correct"
    echo "2. You have appropriate permissions"
    exit 1
fi
```

#### After (Framework):
```bash
register_required_permissions "1" "resourcemanager.projects.get"

if ! check_all_permissions; then
    if ! prompt_continue_limited; then
        print_status "FAIL" "Insufficient permissions for assessment"
        display_permission_guidance
        exit 1
    fi
fi
```

## Migration Validation

### Acceptance Criteria

#### Functional Requirements
- [ ] All original functionality preserved
- [ ] HTML report generation working
- [ ] Permission handling improved
- [ ] Error messages clear and actionable
- [ ] Organization scope support (if applicable)

#### Performance Requirements
- [ ] Execution time within 110% of original
- [ ] Memory usage reasonable for target environment
- [ ] Network API calls optimized

#### Quality Requirements
- [ ] Code follows framework patterns
- [ ] Error handling comprehensive
- [ ] Logging and debugging enabled
- [ ] Documentation updated

### Post-Migration Checklist

#### Code Quality
- [ ] Remove commented legacy code
- [ ] Update script documentation
- [ ] Add function comments where needed
- [ ] Ensure consistent formatting

#### Testing
- [ ] Unit tests pass (if applicable)
- [ ] Integration tests with various project types
- [ ] Performance tests within acceptable limits
- [ ] Error scenario tests

#### Documentation
- [ ] Update script help text
- [ ] Document new features and capabilities
- [ ] Update any external documentation
- [ ] Create migration notes for team

## Rollback Procedures

### Rollback Triggers
- Performance degradation >20%
- Critical functionality loss
- Production issues affecting assessments
- Unresolvable integration problems

### Rollback Process
1. **Immediate**: Restore from backup
2. **Verify**: Test original script functionality
3. **Communicate**: Notify team of rollback
4. **Analyze**: Document issues for future resolution
5. **Plan**: Create remediation plan for re-migration

### Post-Rollback Actions
- Document specific issues encountered
- Plan incremental approach for re-migration
- Consider framework improvements needed
- Update migration procedures based on lessons learned

## Support and Resources

### Migration Assistance
- **Framework Documentation**: Complete API references in `lib/README_*.md`
- **Integration Examples**: Comprehensive examples in `INTEGRATION_GUIDE.md`
- **Troubleshooting**: Common issues and solutions in `TROUBLESHOOTING_GUIDE.md`
- **Performance**: Optimization strategies in `PERFORMANCE_GUIDE.md`

### Best Practices
1. **Start Simple**: Begin with basic functionality migration
2. **Test Early**: Validate each migration phase
3. **Document Changes**: Keep detailed migration notes
4. **Backup Everything**: Maintain rollback capabilities
5. **Incremental Approach**: Migrate in manageable phases
6. **Team Coordination**: Ensure team awareness and training

### Migration Timeline Estimation

| Script Complexity | Migration Effort | Testing Effort | Total Duration |
|-------------------|------------------|----------------|----------------|
| Simple (1-2 checks) | 1-2 days | 0.5-1 day | 2-3 days |
| Medium (5-10 checks) | 3-5 days | 1-2 days | 4-7 days |
| Complex (10+ checks) | 5-10 days | 2-3 days | 7-13 days |
| Organization-wide | 7-14 days | 3-5 days | 10-19 days |

*Note: Estimates include learning curve for first migration. Subsequent migrations will be faster.*