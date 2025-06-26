#!/usr/bin/env bats

# =============================================================================
# Performance Validation Framework
# Test performance benchmarks and regression detection for 4-library framework
# =============================================================================

# Load test framework and helpers
load '../test_config'
load '../helpers/test_helpers'
load '../helpers/mock_helpers'

# Test setup
setup() {
    # Initialize test environment
    setup_test_environment
    
    # Setup performance test environment
    setup_performance_test_environment
    
    # Load performance baseline configuration
    setup_performance_baseline
}

# Test teardown
teardown() {
    cleanup_test_environment
    cleanup_performance_data
}

# =============================================================================
# Core Performance Validation Tests
# =============================================================================

@test "performance: 4-library loading overhead validation against Sprint S01 baseline" {
    setup_performance_baseline
    
    # Measure baseline (no libraries)
    baseline_start=$(date +%s.%N)
    run bash -c "echo 'baseline test'"
    baseline_end=$(date +%s.%N)
    baseline_time=$(echo "$baseline_end - $baseline_start" | bc)
    
    # Measure with all 4 libraries
    library_start=$(date +%s.%N)
    run bash -c "
        source '$GCP_COMMON_LIB'
        source '$GCP_PERMISSIONS_LIB'
        source '$GCP_HTML_REPORT_LIB'
        source '$GCP_SCOPE_MGMT_LIB'
        echo 'libraries loaded'
    "
    library_end=$(date +%s.%N)
    library_time=$(echo "$library_end - $library_start" | bc)
    
    # Calculate overhead
    overhead=$(echo "$library_time - $baseline_time" | bc)
    overhead_percentage=$(echo "scale=2; ($overhead / $BASELINE_LIBRARY_LOAD_TIME) * 100" | bc)
    
    # Assert - Performance requirements met
    [ "$status" -eq 0 ]
    [[ "$output" =~ "libraries loaded" ]]
    
    # Validate <5% overhead requirement
    overhead_ok=$(echo "$overhead_percentage < $PERFORMANCE_THRESHOLD_PERCENTAGE" | bc)
    [ "$overhead_ok" -eq 1 ]
    
    # Log performance metrics
    echo "Library loading overhead: ${overhead}s (${overhead_percentage}%)" >&2
    echo "Sprint S01 baseline: ${BASELINE_LIBRARY_LOAD_TIME}s" >&2
    echo "Performance threshold: <${PERFORMANCE_THRESHOLD_PERCENTAGE}%" >&2
}

@test "performance: individual library loading time benchmarks" {
    # Test each library loading time individually
    declare -A library_load_times
    
    # Test gcp_common.sh loading
    measure_library_load_time "$GCP_COMMON_LIB" "gcp_common" library_load_times
    
    # Test gcp_permissions.sh loading
    measure_library_load_time "$GCP_PERMISSIONS_LIB" "gcp_permissions" library_load_times
    
    # Test gcp_html_report.sh loading
    measure_library_load_time "$GCP_HTML_REPORT_LIB" "gcp_html_report" library_load_times
    
    # Test gcp_scope_mgmt.sh loading
    measure_library_load_time "$GCP_SCOPE_MGMT_LIB" "gcp_scope_mgmt" library_load_times
    
    # Validate all libraries load within acceptable time
    for lib in "${!library_load_times[@]}"; do
        load_time="${library_load_times[$lib]}"
        echo "Library $lib load time: ${load_time}s" >&2
        
        # Each library should load in <0.020s (20ms)
        time_ok=$(echo "$load_time < 0.020" | bc)
        [ "$time_ok" -eq 1 ]
    done
}

@test "performance: function execution benchmarks across all libraries" {
    # Load all libraries
    source "$GCP_COMMON_LIB"
    source "$GCP_PERMISSIONS_LIB"
    source "$GCP_HTML_REPORT_LIB"
    source "$GCP_SCOPE_MGMT_LIB"
    
    # Setup test environment
    setup_environment
    export PROJECT_ID="test-project"
    
    # Benchmark core functions across libraries
    declare -A function_benchmarks
    
    # Test gcp_common functions
    time_function "setup_environment" function_benchmarks
    time_function "parse_common_arguments" function_benchmarks "-s project -p test-project"
    time_function "validate_prerequisites" function_benchmarks
    
    # Test gcp_permissions functions
    time_function "register_required_permissions" function_benchmarks "1 compute.instances.list"
    time_function "check_all_permissions" function_benchmarks
    
    # Test gcp_html_report functions (mock implementations)
    time_function "generate_html_report" function_benchmarks
    time_function "create_assessment_summary" function_benchmarks
    
    # Test gcp_scope_mgmt functions (mock implementations)
    time_function "setup_scope_management" function_benchmarks "project test-project"
    time_function "validate_organization_scope" function_benchmarks
    
    # Assert - All functions execute within performance thresholds
    for func in "${!function_benchmarks[@]}"; do
        execution_time="${function_benchmarks[$func]}"
        echo "Function $func execution time: ${execution_time}s" >&2
        
        time_ok=$(echo "$execution_time < 1.0" | bc)  # 1 second max per function
        [ "$time_ok" -eq 1 ]
    done
}

@test "performance: memory usage profiling for 4-library operations" {
    # Measure baseline memory usage
    baseline_memory=$(get_process_memory_usage $$)
    
    # Load all 4 libraries and measure memory
    run bash -c "
        source '$GCP_COMMON_LIB'
        source '$GCP_PERMISSIONS_LIB'
        source '$GCP_HTML_REPORT_LIB'
        source '$GCP_SCOPE_MGMT_LIB'
        
        # Perform typical operations
        setup_environment
        parse_common_arguments -s project -p test-project
        register_required_permissions 1 compute.instances.list
        
        # Report memory usage
        memory_kb=\$(ps -o rss= -p \$\$)
        echo \"Memory usage: \${memory_kb}KB\"
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Memory usage:" ]]
    
    # Extract memory usage from output
    memory_kb=$(echo "$output" | grep "Memory usage:" | grep -o '[0-9]*')
    
    # Calculate memory overhead
    memory_overhead=$((memory_kb - baseline_memory))
    memory_overhead_percentage=$(echo "scale=2; ($memory_overhead / $BASELINE_MEMORY_USAGE) * 100" | bc)
    
    echo "Baseline memory: ${baseline_memory}KB" >&2
    echo "4-library memory: ${memory_kb}KB" >&2
    echo "Memory overhead: ${memory_overhead}KB (${memory_overhead_percentage}%)" >&2
    
    # Assert <10% memory overhead requirement
    memory_ok=$(echo "$memory_overhead_percentage < 10" | bc)
    [ "$memory_ok" -eq 1 ]
}

# =============================================================================
# Concurrent Usage Performance Tests
# =============================================================================

@test "performance: concurrent usage performance with 3 parallel executions" {
    # Setup concurrent test environment
    setup_concurrent_test_environment
    
    # Measure sequential execution time
    sequential_start=$(date +%s.%N)
    run_sequential_assessments 3
    sequential_end=$(date +%s.%N)
    sequential_time=$(echo "$sequential_end - $sequential_start" | bc)
    
    # Measure concurrent execution time
    concurrent_start=$(date +%s.%N)
    run bash -c "
        # Launch 3 concurrent assessments
        (
            source '$GCP_COMMON_LIB' '$GCP_PERMISSIONS_LIB' '$GCP_HTML_REPORT_LIB' '$GCP_SCOPE_MGMT_LIB'
            setup_environment
            export PROJECT_ID='concurrent-test-1'
            parse_common_arguments -s project -p \$PROJECT_ID
            register_required_permissions 1 compute.instances.list
            check_all_permissions
        ) &
        
        (
            source '$GCP_COMMON_LIB' '$GCP_PERMISSIONS_LIB' '$GCP_HTML_REPORT_LIB' '$GCP_SCOPE_MGMT_LIB'
            setup_environment
            export PROJECT_ID='concurrent-test-2'
            parse_common_arguments -s project -p \$PROJECT_ID
            register_required_permissions 2 iam.roles.list
            check_all_permissions
        ) &
        
        (
            source '$GCP_COMMON_LIB' '$GCP_PERMISSIONS_LIB' '$GCP_HTML_REPORT_LIB' '$GCP_SCOPE_MGMT_LIB'
            setup_environment
            export PROJECT_ID='concurrent-test-3'
            parse_common_arguments -s project -p \$PROJECT_ID
            register_required_permissions 3 storage.buckets.list
            check_all_permissions
        ) &
        
        # Wait for all background processes
        wait
        echo 'Concurrent execution completed'
    "
    concurrent_end=$(date +%s.%N)
    concurrent_time=$(echo "$concurrent_end - $concurrent_start" | bc)
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Concurrent execution completed" ]]
    
    # Calculate efficiency - concurrent should be faster than sequential
    efficiency=$(echo "scale=2; ($sequential_time / $concurrent_time)" | bc)
    
    echo "Sequential time: ${sequential_time}s" >&2
    echo "Concurrent time: ${concurrent_time}s" >&2
    echo "Efficiency ratio: ${efficiency}x" >&2
    
    # Concurrent execution should show some improvement (>1.2x)
    efficiency_ok=$(echo "$efficiency > 1.2" | bc)
    [ "$efficiency_ok" -eq 1 ]
}

@test "performance: resource management under concurrent load" {
    # Test resource management with high concurrent load
    setup_resource_monitoring
    
    run bash -c "
        # Monitor resource usage during concurrent execution
        monitor_resources &
        monitor_pid=\$!
        
        # Launch multiple concurrent processes
        for i in {1..5}; do
            (
                source '$GCP_COMMON_LIB' '$GCP_PERMISSIONS_LIB' '$GCP_HTML_REPORT_LIB' '$GCP_SCOPE_MGMT_LIB'
                setup_environment
                export PROJECT_ID=\"load-test-\$i\"
                parse_common_arguments -s project -p \$PROJECT_ID
                register_required_permissions \$i compute.instances.list
                check_all_permissions
                sleep 1
            ) &
        done
        
        # Wait for all processes
        wait
        
        # Stop monitoring
        kill \$monitor_pid 2>/dev/null || true
        
        echo 'Resource management test completed'
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Resource management test completed" ]]
    
    # Verify no resource leaks
    assert_no_resource_leaks
}

# =============================================================================
# Performance Regression Detection Tests
# =============================================================================

@test "performance: automated regression detection against baseline" {
    # Setup regression test environment
    setup_regression_test_environment
    
    # Run current performance benchmark
    run_performance_benchmark > "$PERFORMANCE_RESULTS_FILE"
    
    # Compare against baseline
    run bash -c "
        # Load baseline and current results
        baseline_time='$BASELINE_LIBRARY_LOAD_TIME'
        current_time=\$(grep 'Library load time:' '$PERFORMANCE_RESULTS_FILE' | grep -o '[0-9]*\.[0-9]*')
        
        # Calculate regression percentage
        if [ -n \"\$current_time\" ]; then
            regression=\$(echo \"scale=2; ((\$current_time - \$baseline_time) / \$baseline_time) * 100\" | bc)
            echo \"Baseline: \${baseline_time}s\"
            echo \"Current: \${current_time}s\"
            echo \"Regression: \${regression}%\"
            
            # Fail if regression > 5%
            regression_ok=\$(echo \"\$regression < $PERFORMANCE_REGRESSION_THRESHOLD\" | bc)
            [ \"\$regression_ok\" -eq 1 ]
        else
            echo 'Could not extract performance timing'
            exit 1
        fi
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Baseline:" ]]
    [[ "$output" =~ "Current:" ]]
    [[ "$output" =~ "Regression:" ]]
}

@test "performance: performance benchmark history tracking" {
    # Create performance history
    create_performance_history
    
    # Add current benchmark to history
    run bash -c "
        current_benchmark=\$(run_quick_performance_benchmark)
        timestamp=\$(date '+%Y-%m-%d %H:%M:%S')
        
        echo \"\$timestamp,\$current_benchmark\" >> '$PERFORMANCE_HISTORY_FILE'
        
        # Verify history file exists and has entries
        line_count=\$(wc -l < '$PERFORMANCE_HISTORY_FILE')
        echo \"Performance history entries: \$line_count\"
        
        [ \"\$line_count\" -gt 0 ]
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Performance history entries:" ]]
    
    # Verify history file format
    assert_valid_performance_history_format
}

# =============================================================================
# Production Deployment Performance Tests
# =============================================================================

@test "performance: production deployment scenario simulation" {
    # Simulate production deployment scenario
    setup_production_simulation
    
    run bash -c "
        # Simulate production workload
        echo 'Starting production simulation...'
        start_time=\$(date +%s.%N)
        
        # Load libraries as would happen in production
        source '$GCP_COMMON_LIB'
        source '$GCP_PERMISSIONS_LIB'
        source '$GCP_HTML_REPORT_LIB'
        source '$GCP_SCOPE_MGMT_LIB'
        
        # Execute typical production workflow
        setup_environment
        parse_common_arguments -s organization -p production-org-123
        register_required_permissions 1 \
            compute.instances.list iam.roles.list storage.buckets.list
        
        # Simulate organization assessment
        setup_scope_management organization production-org-123
        validate_organization_scope_permissions
        aggregate_organization_permissions
        generate_organization_html_report
        
        end_time=\$(date +%s.%N)
        total_time=\$(echo \"\$end_time - \$start_time\" | bc)
        
        echo \"Production simulation completed in \${total_time}s\"
        
        # Production deployment should complete within 30 seconds
        time_ok=\$(echo \"\$total_time < 30.0\" | bc)
        [ \"\$time_ok\" -eq 1 ]
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Production simulation completed" ]]
}

@test "performance: large-scale organization performance validation" {
    # Test performance with large organization (50 projects)
    setup_large_scale_test_environment
    
    run bash -c "
        echo 'Starting large-scale performance test...'
        start_time=\$(date +%s.%N)
        
        # Load libraries
        source '$GCP_COMMON_LIB'
        source '$GCP_PERMISSIONS_LIB'
        source '$GCP_HTML_REPORT_LIB'
        source '$GCP_SCOPE_MGMT_LIB'
        
        # Setup large organization
        setup_environment
        export ORG_ID='large-scale-org-999'
        export PROJECT_COUNT=50
        
        # Simulate large-scale assessment
        parse_common_arguments -s organization -p \$ORG_ID
        register_required_permissions 1 compute.instances.list iam.roles.list
        setup_scope_management organization \$ORG_ID
        
        # Process organization (simulate large scale)
        for i in \$(seq 1 \$PROJECT_COUNT); do
            # Simulate processing each project
            export PROJECT_ID=\"large-proj-\$i\"
            check_all_permissions_for_project \"\$PROJECT_ID\" >/dev/null
        done
        
        aggregate_organization_permissions
        generate_organization_html_report
        
        end_time=\$(date +%s.%N)
        total_time=\$(echo \"\$end_time - \$start_time\" | bc)
        
        echo \"Large-scale test completed in \${total_time}s for \$PROJECT_COUNT projects\"
        echo \"Average time per project: \$(echo \"scale=3; \$total_time / \$PROJECT_COUNT\" | bc)s\"
        
        # Should process within 120 seconds (2 minutes) for 50 projects
        time_ok=\$(echo \"\$total_time < 120.0\" | bc)
        [ \"\$time_ok\" -eq 1 ]
    "
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Large-scale test completed" ]]
    [[ "$output" =~ "Average time per project:" ]]
}

# =============================================================================
# Performance Helper Functions
# =============================================================================

# Setup performance baseline
setup_performance_baseline() {
    # Sprint S01 baseline: 0.012s library loading overhead
    export BASELINE_LIBRARY_LOAD_TIME=${BASELINE_LIBRARY_LOAD_TIME:-0.012}
    export PERFORMANCE_THRESHOLD_PERCENTAGE=${PERFORMANCE_THRESHOLD_PERCENTAGE:-5}
    export BASELINE_MEMORY_USAGE=${BASELINE_MEMORY_USAGE:-1024}
}

# Setup performance test environment
setup_performance_test_environment() {
    export PERFORMANCE_TEST_DIR="$TEST_TEMP_DIR/performance"
    export PERFORMANCE_RESULTS_FILE="$PERFORMANCE_TEST_DIR/results.txt"
    export PERFORMANCE_HISTORY_FILE="$PERFORMANCE_TEST_DIR/history.csv"
    
    mkdir -p "$PERFORMANCE_TEST_DIR"
}

# Measure library load time
measure_library_load_time() {
    local lib_path="$1"
    local lib_name="$2"
    local -n results_ref="$3"
    
    local start_time end_time load_time
    start_time=$(date +%s.%N)
    source "$lib_path" >/dev/null 2>&1
    end_time=$(date +%s.%N)
    load_time=$(echo "$end_time - $start_time" | bc)
    
    results_ref["$lib_name"]="$load_time"
}

# Time function execution
time_function() {
    local func_name="$1"
    local -n results_ref="$2"
    shift 2
    local args=("$@")
    
    local start_time end_time execution_time
    start_time=$(date +%s.%N)
    "$func_name" "${args[@]}" >/dev/null 2>&1 || true
    end_time=$(date +%s.%N)
    execution_time=$(echo "$end_time - $start_time" | bc)
    
    results_ref["$func_name"]="$execution_time"
}

# Get process memory usage
get_process_memory_usage() {
    local pid="$1"
    ps -o rss= -p "$pid" 2>/dev/null || echo "1024"
}

# Setup concurrent test environment
setup_concurrent_test_environment() {
    export CONCURRENT_TEST_DIR="$TEST_TEMP_DIR/concurrent"
    mkdir -p "$CONCURRENT_TEST_DIR"
}

# Run sequential assessments
run_sequential_assessments() {
    local count="$1"
    for i in $(seq 1 "$count"); do
        source "$GCP_COMMON_LIB" "$GCP_PERMISSIONS_LIB" "$GCP_HTML_REPORT_LIB" "$GCP_SCOPE_MGMT_LIB"
        setup_environment
        export PROJECT_ID="sequential-test-$i"
        parse_common_arguments -s project -p "$PROJECT_ID"
        register_required_permissions "$i" "compute.instances.list"
        check_all_permissions >/dev/null 2>&1 || true
    done
}

# Setup resource monitoring
setup_resource_monitoring() {
    export RESOURCE_MONITOR_PID=""
}

# Monitor resources
monitor_resources() {
    while true; do
        echo "$(date): $(ps aux | grep -E '(gcp_|test)' | wc -l) processes" >> "$PERFORMANCE_TEST_DIR/resource_monitor.log"
        sleep 0.5
    done
}

# Assert no resource leaks
assert_no_resource_leaks() {
    # Check for any remaining test processes
    local remaining_processes
    remaining_processes=$(ps aux | grep -E "(test-project|concurrent-test|load-test)" | grep -v grep | wc -l)
    [ "$remaining_processes" -eq 0 ]
}

# Setup regression test environment
setup_regression_test_environment() {
    export REGRESSION_TEST_DIR="$PERFORMANCE_TEST_DIR/regression"
    mkdir -p "$REGRESSION_TEST_DIR"
}

# Run performance benchmark
run_performance_benchmark() {
    start_time=$(date +%s.%N)
    source "$GCP_COMMON_LIB" "$GCP_PERMISSIONS_LIB" "$GCP_HTML_REPORT_LIB" "$GCP_SCOPE_MGMT_LIB"
    end_time=$(date +%s.%N)
    load_time=$(echo "$end_time - $start_time" | bc)
    echo "Library load time: $load_time"
}

# Create performance history
create_performance_history() {
    echo "timestamp,load_time" > "$PERFORMANCE_HISTORY_FILE"
    # Add some historical data
    echo "2025-06-01 10:00:00,0.011" >> "$PERFORMANCE_HISTORY_FILE"
    echo "2025-06-02 10:00:00,0.012" >> "$PERFORMANCE_HISTORY_FILE"
    echo "2025-06-03 10:00:00,0.011" >> "$PERFORMANCE_HISTORY_FILE"
}

# Run quick performance benchmark
run_quick_performance_benchmark() {
    start_time=$(date +%s.%N)
    source "$GCP_COMMON_LIB" >/dev/null 2>&1
    end_time=$(date +%s.%N)
    echo "$end_time - $start_time" | bc
}

# Assert valid performance history format
assert_valid_performance_history_format() {
    # Check that history file has proper CSV format
    local header
    header=$(head -n 1 "$PERFORMANCE_HISTORY_FILE")
    [[ "$header" == "timestamp,load_time" ]] || return 1
    
    # Check that data lines have proper format
    local data_lines
    data_lines=$(tail -n +2 "$PERFORMANCE_HISTORY_FILE" | wc -l)
    [ "$data_lines" -gt 0 ] || return 1
}

# Setup production simulation
setup_production_simulation() {
    export PRODUCTION_SIM_DIR="$PERFORMANCE_TEST_DIR/production"
    mkdir -p "$PRODUCTION_SIM_DIR"
}

# Setup large scale test environment
setup_large_scale_test_environment() {
    export LARGE_SCALE_TEST_DIR="$PERFORMANCE_TEST_DIR/large_scale"
    mkdir -p "$LARGE_SCALE_TEST_DIR"
}

# Cleanup performance data
cleanup_performance_data() {
    if [[ -d "$PERFORMANCE_TEST_DIR" ]]; then
        rm -rf "$PERFORMANCE_TEST_DIR"
    fi
}

# Mock functions for performance testing
aggregate_organization_permissions() {
    sleep 0.1  # Simulate processing time
    return 0
}

validate_organization_scope_permissions() {
    sleep 0.05  # Simulate validation time
    return 0
}

generate_organization_html_report() {
    sleep 0.2   # Simulate report generation time
    echo "<html><body>Performance Test Report</body></html>" > "$PERFORMANCE_TEST_DIR/report.html"
    return 0
}

check_all_permissions_for_project() {
    local project_id="$1"
    sleep 0.01  # Simulate per-project processing time
    return 0
}

create_assessment_summary() {
    sleep 0.05
    return 0
}