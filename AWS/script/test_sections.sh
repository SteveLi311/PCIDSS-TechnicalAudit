#!/bin/bash

# A simple test script to check section structure without AWS API calls

# Source the shared HTML report library
source "$(dirname "$0")/pci_html_report_lib.sh"

# Define variables
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="./reports"
OUTPUT_FILE="$OUTPUT_DIR/section_test_$TIMESTAMP.html"

# Create reports directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Initialize HTML report
initialize_html_report "$OUTPUT_FILE" "Section Structure Test" "1" "test-region"

# First section
add_section "$OUTPUT_FILE" "req-1.3" "Requirement 1.3: Test Section" "none"
add_check_item "$OUTPUT_FILE" "info" "1.3.1 - Test Item" "This is a test for requirement 1.3" ""
# Close section 1.3
close_section "$OUTPUT_FILE"

# Second section
add_section "$OUTPUT_FILE" "req-1.4" "Requirement 1.4: Test Section" "none"
add_check_item "$OUTPUT_FILE" "info" "1.4.1 - Test Item" "This is a test for requirement 1.4" ""
# Close section 1.4
close_section "$OUTPUT_FILE"

# Third section
add_section "$OUTPUT_FILE" "req-1.5" "Requirement 1.5: Test Section" "none"
add_check_item "$OUTPUT_FILE" "info" "1.5.1 - Test Item" "This is a test for requirement 1.5" ""
# Close section 1.5
close_section "$OUTPUT_FILE"

# Finalize the HTML report with summary statistics
finalize_html_report "$OUTPUT_FILE" "3" "3" "0" "0" "1"

echo "Test report has been generated: $OUTPUT_FILE"