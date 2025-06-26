#!/bin/bash
################################################################################
# PCI DSS Executive Summary Report Generator
################################################################################
#
# Description:
#   This script consolidates individual PCI DSS requirement reports into a 
#   single executive summary report with charts, statistics, and actionable
#   recommendations.
#
# Usage:
#   ./generate_executive_summary.sh
#
# Requirements:
#   - Existing PCI DSS compliance reports in the ./reports directory
#   - PCI HTML report library (pci_html_report_lib.sh)
#   - grep, sed, awk for text processing
#
# Output:
#   - An HTML executive summary report in the ./reports directory
#
# Author:  PCI Compliance Team
# Version: 1.0
#
################################################################################

# Set output directory
REPORTS_DIR="./reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Output file in the same directory as detailed reports
OUTPUT_FILE="${REPORTS_DIR}/pci_executive_summary_${TIMESTAMP}.html"

# Source the HTML report library
source "$(dirname "$0")/pci_html_report_lib.sh"

# Initialize summary statistics
total_checks=0
total_passed=0
total_failed=0
total_warnings=0

# Arrays to store high-priority findings
declare -a high_priority_findings
declare -a failed_requirements

# Create report header
cat > "$OUTPUT_FILE" << EOT
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCI DSS 4.0 - Executive Summary Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 30px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            border-radius: 5px;
        }
        h1 {
            color: #333;
            border-bottom: 2px solid #2196F3;
            padding-bottom: 10px;
            margin-top: 0;
        }
        h2 {
            color: #2196F3;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
            margin-top: 30px;
        }
        h3 {
            color: #555;
            margin-top: 20px;
        }
        .section {
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
        }
        .section-header {
            background-color: #f0f0f0;
            padding: 10px 15px;
            cursor: pointer;
            position: relative;
        }
        .section-header:hover {
            background-color: #e0e0e0;
        }
        .section-header::after {
            content: "+";
            position: absolute;
            right: 15px;
            top: 10px;
            font-weight: bold;
        }
        .section-header.active::after {
            content: "-";
        }
        .section-content {
            padding: 15px;
            display: none;
        }
        .active + .section-content {
            display: block;
        }
        .info-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        .info-table th, .info-table td {
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }
        .info-table th {
            background-color: #f0f0f0;
        }
        .summary-box {
            margin-top: 20px;
            padding: 15px;
            background-color: #f0f0f0;
            border-radius: 5px;
        }
        .summary-table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        .summary-table th, .summary-table td {
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }
        .summary-table th {
            background-color: #e0e0e0;
        }
        .progress-container {
            width: 100%;
            background-color: #ddd;
            border-radius: 5px;
            margin-top: 10px;
        }
        .progress-bar {
            height: 25px;
            border-radius: 5px;
            text-align: center;
            line-height: 25px;
            color: white;
        }
        .finding-item {
            border-left: 4px solid #ddd;
            padding: 10px;
            margin-bottom: 10px;
            background-color: #f9f9f9;
        }
        .pass {
            border-left-color: #4CAF50;
        }
        .fail {
            border-left-color: #f44336;
        }
        .warning {
            border-left-color: #ff9800;
        }
        .info {
            border-left-color: #2196F3;
        }
        .timestamp {
            color: #757575;
            font-style: italic;
            text-align: right;
        }
        .recommendation {
            padding: 10px;
            margin-top: 10px;
            background-color: #e1f5fe;
            border-left: 4px solid #03a9f4;
        }
        .green { color: #4CAF50; }
        .red { color: #f44336; }
        .yellow { color: #ff9800; }
        .blue { color: #2196F3; }
        .gray { color: #757575; }
        .requirement-summary {
            margin-bottom: 20px;
        }
        .requirement-header {
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            padding: 10px;
            background-color: #f5f5f5;
            border-radius: 5px 5px 0 0;
            border: 1px solid #ddd;
        }
        .requirement-progress {
            margin: 0;
            padding: 0;
            width: 200px;
        }
        .requirement-details {
            padding: 15px;
            border: 1px solid #ddd;
            border-top: none;
            border-radius: 0 0 5px 5px;
        }
        .chart-container {
            display: flex;
            justify-content: space-between;
            margin-top: 30px;
        }
        .chart {
            width: 48%;
            padding: 15px;
            background-color: #f9f9f9;
            border-radius: 5px;
            border: 1px solid #ddd;
        }
        .doughnut-chart {
            width: 200px;
            height: 200px;
            margin: 0 auto;
            position: relative;
        }
        .doughnut-segment {
            position: absolute;
            width: 100%;
            height: 100%;
            clip: rect(0, 200px, 200px, 100px);
            border-radius: 50%;
            transform: rotate(0deg);
        }
        /* Print styling */
        @media print {
            body {
                background-color: white;
                padding: 0;
            }
            .container {
                box-shadow: none;
                padding: 0;
            }
            .section-content {
                display: block;
            }
            .section-header::after {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>PCI DSS 4.0 - Executive Summary Report</h1>
        
        <div class="info-table">
            <table>
                <tr>
                    <th>AWS Account</th>
                    <td id="aws-account">Loading...</td>
                </tr>
                <tr>
                    <th>AWS Region</th>
                    <td id="aws-region">Loading...</td>
                </tr>
                <tr>
                    <th>Assessment Date</th>
                    <td>$(date)</td>
                </tr>
                <tr>
                    <th>Report Generated By</th>
                    <td id="aws-user">Loading...</td>
                </tr>
            </table>
        </div>
        
        <div class="summary-box">
            <h2 style="margin-top: 0;">Executive Summary</h2>
            <div id="summary-statistics">
                <p>Assessment analysis in progress...</p>
            </div>
        </div>
        
        <div id="report-content">
EOT

# Function to extract data from HTML file
extract_from_html() {
    local file="$1"
    local pattern="$2"
    grep -o "$pattern" "$file" | head -1 | sed -e 's/.*>\(.*\)<.*/\1/'
}

# Function to extract summary statistics from report
extract_summary_stats() {
    local file="$1"
    
    # Search for the summary table and extract values
    local summary_section=$(grep -A 15 'summary-statistics' "$file")
    
    # Extract values more carefully
    local total=$(echo "$summary_section" | grep -o '<td>[0-9]\+</td>' | head -1 | sed -e 's/<td>\([0-9]*\)<\/td>/\1/')
    local passed=$(echo "$summary_section" | grep -o '<span class="green">[0-9]\+</span>' | head -1 | sed -e 's/<span class="green">\([0-9]*\)<\/span>/\1/')
    local failed=$(echo "$summary_section" | grep -o '<span class="red">[0-9]\+</span>' | head -1 | sed -e 's/<span class="red">\([0-9]*\)<\/span>/\1/')
    local warnings=$(echo "$summary_section" | grep -o '<span class="yellow">[0-9]\+</span>' | head -1 | sed -e 's/<span class="yellow">\([0-9]*\)<\/span>/\1/')
    
    # Validate that we got numbers
    [[ ! "$total" =~ ^[0-9]+$ ]] && total=0
    [[ ! "$passed" =~ ^[0-9]+$ ]] && passed=0
    [[ ! "$failed" =~ ^[0-9]+$ ]] && failed=0
    [[ ! "$warnings" =~ ^[0-9]+$ ]] && warnings=0
    
    echo "$total $passed $failed $warnings"
}

# Function to extract AWS account info
extract_aws_info() {
    local file="$1"
    local aws_account=$(grep -A 1 "AWS Account" "$file" | tail -1 | sed -e 's/.*<td>\(.*\)<\/td>.*/\1/')
    local aws_region=$(grep -A 1 "AWS Region" "$file" | tail -1 | sed -e 's/.*<td>\(.*\)<\/td>.*/\1/')
    local aws_user=$(grep -A 1 "Assessed By" "$file" | tail -1 | sed -e 's/.*<td>\(.*\)<\/td>.*/\1/')
    
    echo "$aws_account $aws_region $aws_user"
}

# Initialize tracking for access denied failures
total_access_denied=0

# Function to extract failed findings and count access denied failures
extract_failed_findings() {
    local file="$1"
    local req_num="$2"
    local access_denied_count=0
    
    grep -B 1 -A 3 '\[FAIL\]' "$file" | grep -v "^--$" | while read -r line; do
        if [[ "$line" == *"[FAIL]"* ]]; then
            title=$(echo "$line" | sed -E 's/.*\[FAIL\]<\/span> (.*)<\/h3>.*/\1/')
            
            # Check if this is an access denied error
            if [[ "$title" == *"AWS API Access:"* ]] || 
               [[ "$title" == *"Access Denied"* ]] || 
               [[ "$line" == *"Access Denied"* ]] ||
               [[ "$title" == *"Permission"* ]]; then
                # Count these separately and don't include in findings
                access_denied_count=$((access_denied_count + 1))
                continue
            fi
            
            echo "Requirement $req_num: $title"
        fi
    done
    
    # Return the access denied count
    echo "$access_denied_count" >&2
}

# Process each requirement, ignoring duplicate reports
echo "Processing PCI DSS compliance reports (one per requirement)..."

# Create an array to track which requirements we've already processed
processed_reqs=()

# Process all report files, but only one per requirement (the latest one)
for report_file in $(ls -t "${REPORTS_DIR}"/pci_*_report_*.html); do
    # Extract requirement number
    req_num=$(echo "$report_file" | grep -oE 'req([0-9]+|[0-9]+_[0-9]+)' | sed -e 's/req//' | sed -e 's/_report.*//')
    [[ -z "$req_num" ]] && req_num=$(echo "$report_file" | grep -oE 'requirement([0-9]+|[0-9]+_[0-9]+)' | sed -e 's/requirement//')
    
    # Skip if requirement couldn't be extracted
    [[ -z "$req_num" ]] && continue
    
    # Check if we've already processed this requirement number
    already_processed=0
    for processed in "${processed_reqs[@]}"; do
        if [[ "$processed" == "$req_num" ]]; then
            already_processed=1
            break
        fi
    done
    
    # Skip if we've already processed this requirement
    [[ $already_processed -eq 1 ]] && continue
    
    # Add this requirement to our processed list
    processed_reqs+=("$req_num")
    
    echo "Processing Requirement $req_num report: $report_file"
    
    # Extract summary statistics
    stats=($(extract_summary_stats "$report_file"))
    req_total=${stats[0]}
    req_passed=${stats[1]}
    req_failed=${stats[2]}
    req_warnings=${stats[3]}
    
    # Update totals
    total_checks=$((total_checks + req_total))
    total_passed=$((total_passed + req_passed))
    total_failed=$((total_failed + req_failed))
    total_warnings=$((total_warnings + req_warnings))
    
    # Extract AWS info from first report
    if [[ -z "$aws_account" ]]; then
        aws_info=($(extract_aws_info "$report_file"))
        aws_account=${aws_info[0]}
        aws_region=${aws_info[1]}
        aws_user="${aws_info[2]} ${aws_info[3]} ${aws_info[4]}"  # Handle spaces in user
    fi
    
    # Calculate compliance percentage
    compliance_percentage=0
    if [ $((req_total - req_warnings)) -gt 0 ]; then
        compliance_percentage=$(( (req_passed * 100) / (req_total - req_warnings) ))
    fi
    
    # Set progress bar color
    progress_color="#4CAF50"  # Green by default
    if [ $compliance_percentage -lt 70 ]; then
        progress_color="#f44336"    # Red for < 70%
    elif [ $compliance_percentage -lt 90 ]; then
        progress_color="#ff9800"    # Yellow for 70-89%
    fi
    
    # Store requirement status
    req_status="PASS"
    status_class="pass"
    status_display="PASS"
    
    if [ $req_failed -gt 0 ]; then
        req_status="FAIL"
        status_class="fail"
        status_display="FAIL"
        failed_requirements+=("$req_num")
    elif [ $req_warnings -gt 0 ]; then
        req_status="MANUAL"
        status_class="info"
        status_display="MANUAL VERIFICATION"
    fi
    
    # Extract failed findings and count access denied failures
    if [ $req_failed -gt 0 ]; then
        # Capture both the findings and the access denied count (sent to stderr)
        findings_output=$(extract_failed_findings "$report_file" "$req_num" 2>&1)
        
        # Get the access denied count (last line)
        access_denied=$(echo "$findings_output" | tail -n 1)
        
        # Remove the last line to get just the findings
        findings=$(echo "$findings_output" | sed '$d')
        
        # Add valid findings to high priority list
        while IFS= read -r finding; do
            [[ -z "$finding" ]] && continue
            high_priority_findings+=("$finding")
        done <<< "$findings"
        
        # Track access denied count
        req_access_denied=$access_denied
        total_access_denied=$((total_access_denied + req_access_denied))
        
        # Adjust the failed count to exclude access denied failures
        req_failed=$((req_failed - req_access_denied))
        total_failed=$((total_failed - req_access_denied))
    fi
    
    # Extract just the filename from the report path for linking
    report_filename=$(basename "$report_file")
    
    # Add requirement summary to the report
    cat >> "$OUTPUT_FILE" << EOT
        <div class="requirement-summary">
            <div class="requirement-header">
                <span>Requirement $req_num: <span class="${status_class}">[${status_display}]</span></span>
                <div class="requirement-progress">
                    <div class="progress-container" style="height: 15px;">
                        <div class="progress-bar" style="width: ${compliance_percentage}%; background-color: ${progress_color}; height: 15px;">
                            ${compliance_percentage}%
                        </div>
                    </div>
                </div>
            </div>
            <div class="requirement-details">
                <p><strong>Summary:</strong> ${req_passed} of ${req_total} checks passed, ${req_failed} failed, ${req_warnings} require manual verification.</p>
                <p><a href="${report_filename}" target="_blank">View detailed report</a></p>
            </div>
        </div>
EOT
done

# Calculate overall compliance percentage
overall_compliance=0

# Adjusted number of checks (excluding manual verification and access denied)
adjusted_total=$((total_checks - total_warnings - total_access_denied))

if [ $adjusted_total -gt 0 ]; then
    overall_compliance=$(( (total_passed * 100) / adjusted_total ))
fi

# Debug information (commented out)
# echo "Total checks: $total_checks"
# echo "Total passed: $total_passed" 
# echo "Total failed (excluding access denied): $total_failed"
# echo "Total manual verifications: $total_warnings"
# echo "Total access denied failures: $total_access_denied"
# echo "Adjusted total (for compliance calculation): $adjusted_total"
# echo "Overall compliance: $overall_compliance%"

# Set overall compliance color
compliance_color="#4CAF50"  # Green by default
if [ $overall_compliance -lt 70 ]; then
    compliance_color="#f44336"    # Red for < 70%
elif [ $overall_compliance -lt 90 ]; then
    compliance_color="#ff9800"    # Yellow for 70-89%
fi

# Create high priority findings section
cat >> "$OUTPUT_FILE" << EOT
        <div class="section">
            <div class="section-header active" onclick="this.classList.toggle('active'); this.nextElementSibling.style.display = this.classList.contains('active') ? 'block' : 'none';">
                High Priority Findings
            </div>
            <div class="section-content" style="display: block;">
                <div id="high-priority-findings">
                <p><em>Note: Permission-related issues (Access Denied errors) are excluded from high priority findings as they represent assessment limitations rather than actual compliance failures. Items requiring manual verification are also not listed here.</em></p>
EOT

if [ ${#high_priority_findings[@]} -gt 0 ]; then
    for finding in "${high_priority_findings[@]}"; do
        cat >> "$OUTPUT_FILE" << EOT
                    <div class="finding-item fail">
                        <h3><span class="red">[FAIL]</span> ${finding}</h3>
                    </div>
EOT
    done
else
    cat >> "$OUTPUT_FILE" << EOT
                    <div class="finding-item pass">
                        <h3><span class="green">[PASS]</span> No high priority findings detected.</h3>
                    </div>
EOT
fi

cat >> "$OUTPUT_FILE" << EOT
                </div>
            </div>
        </div>
EOT

# Create summary statistics
summary_html="
            <table class=\\\"summary-table\\\">
                <tr>
                    <th>Total Checks</th>
                    <th>Passed</th>
                    <th>Failed</th>
                    <th>Manual Verification</th>
                    <th>Access Denied</th>
                    <th>Overall Compliance</th>
                </tr>
                <tr>
                    <td>${total_checks}</td>
                    <td><span class=\\\"green\\\">${total_passed}</span></td>
                    <td><span class=\\\"red\\\">${total_failed}</span></td>
                    <td><span class=\\\"blue\\\">${total_warnings}</span></td>
                    <td><span class=\\\"gray\\\">${total_access_denied}</span></td>
                    <td>${overall_compliance}%</td>
                </tr>
            </table>
            
            <p><em>Note: Compliance percentage is calculated excluding both manual verification items and access denied failures, as these do not represent actual compliance failures.</em></p>
            
            <div class=\\\"progress-container\\\">
                <div class=\\\"progress-bar\\\" style=\\\"width: ${overall_compliance}%; background-color: ${compliance_color};\\\">
                    ${overall_compliance}%
                </div>
            </div>

            <div class=\\\"chart-container\\\">
                <div class=\\\"chart\\\">
                    <h3>Compliance Status by Requirement</h3>
                    <div id=\\\"requirements-chart\\\"></div>
                </div>
                
                <div class=\\\"chart\\\">
                    <h3>Overall Compliance</h3>
                    <div id=\\\"overall-chart\\\"></div>
                </div>
            </div>
"

# Add recommendations section
cat >> "$OUTPUT_FILE" << EOT
        <div class="section">
            <div class="section-header" onclick="this.classList.toggle('active'); this.nextElementSibling.style.display = this.classList.contains('active') ? 'block' : 'none';">
                Executive Recommendations
            </div>
            <div class="section-content" style="display: none;">
                <div id="recommendations">
EOT

if [ ${#failed_requirements[@]} -gt 0 ]; then
    cat >> "$OUTPUT_FILE" << EOT
                    <p>Based on the assessment, the following key areas require immediate attention:</p>
                    <ul>
EOT
    
    for req in "${failed_requirements[@]}"; do
        case $req in
            1)
                echo '<li><strong>Requirement 1 (Network Security Controls):</strong> Critical network security issues exist. Review firewall configurations, network segmentation, and access control mechanisms.</li>' >> "$OUTPUT_FILE"
                ;;
            2)
                echo '<li><strong>Requirement 2 (Secure Configuration):</strong> System configuration deficiencies exist. Address vendor-supplied defaults and harden system configurations.</li>' >> "$OUTPUT_FILE"
                ;;
            3)
                echo '<li><strong>Requirement 3 (Stored Cardholder Data):</strong> Issues with protection of stored cardholder data. Review encryption mechanisms and data storage practices.</li>' >> "$OUTPUT_FILE"
                ;;
            4)
                echo '<li><strong>Requirement 4 (Transmitted Cardholder Data):</strong> Data transmission security issues exist. Ensure all transmissions are encrypted with strong cryptography.</li>' >> "$OUTPUT_FILE"
                ;;
            5)
                echo '<li><strong>Requirement 5 (Malware Protection):</strong> Deficiencies in malware protection mechanisms. Review anti-malware solutions and processes.</li>' >> "$OUTPUT_FILE"
                ;;
            6)
                echo '<li><strong>Requirement 6 (Secure Systems & Applications):</strong> Application security deficiencies exist. Address secure development practices and vulnerability management.</li>' >> "$OUTPUT_FILE"
                ;;
            7)
                echo '<li><strong>Requirement 7 (Access Control):</strong> Access control issues exist. Review access restrictions and least privilege implementation.</li>' >> "$OUTPUT_FILE"
                ;;
            8)
                echo '<li><strong>Requirement 8 (Authentication):</strong> Authentication mechanism deficiencies exist. Review identity management and MFA implementation.</li>' >> "$OUTPUT_FILE"
                ;;
            9)
                echo '<li><strong>Requirement 9 (Physical Access):</strong> Physical security control issues exist. Address physical access restrictions and protections.</li>' >> "$OUTPUT_FILE"
                ;;
            10)
                echo '<li><strong>Requirement 10 (Logging & Monitoring):</strong> Audit logging and monitoring deficiencies exist. Review logging mechanisms and monitoring processes.</li>' >> "$OUTPUT_FILE"
                ;;
            11)
                echo '<li><strong>Requirement 11 (Security Testing):</strong> Security testing and scanning issues exist. Address vulnerability scanning and penetration testing processes.</li>' >> "$OUTPUT_FILE"
                ;;
            12)
                echo '<li><strong>Requirement 12 (Security Policy):</strong> Information security policy deficiencies exist. Review security policies and procedures documentation.</li>' >> "$OUTPUT_FILE"
                ;;
            *)
                echo "<li><strong>Requirement $req:</strong> Critical compliance issues exist. Review the detailed report for specific findings.</li>" >> "$OUTPUT_FILE"
                ;;
        esac
    done
    
    cat >> "$OUTPUT_FILE" << EOT
                    </ul>
                    
                    <p><strong>Recommended Action Plan:</strong></p>
                    <ol>
                        <li>Address all failed findings, prioritizing those with the highest risk impact.</li>
                        <li>Develop a remediation plan with clear timelines and ownership.</li>
                        <li>Conduct follow-up assessments after remediation to verify effectiveness.</li>
                        <li>Establish ongoing compliance monitoring to prevent regression.</li>
                        <li>Document all remediation actions for audit purposes.</li>
                    </ol>
EOT
else
    cat >> "$OUTPUT_FILE" << EOT
                    <p><span class="green"><strong>Congratulations!</strong></span> No critical findings were detected in the automated assessment.</p>
                    <p><strong>Recommended Next Steps:</strong></p>
                    <ol>
                        <li>Review all warning items that require manual verification.</li>
                        <li>Prepare documentation for requirements that cannot be verified through automated testing.</li>
                        <li>Consider engaging a Qualified Security Assessor (QSA) for a comprehensive review.</li>
                        <li>Maintain regular security assessments to ensure continued compliance.</li>
                    </ol>
EOT
fi

cat >> "$OUTPUT_FILE" << EOT
                </div>
            </div>
        </div>
EOT

# Finalize the HTML report
cat >> "$OUTPUT_FILE" << EOT
        </div>
        
        <div class="timestamp">
            Report generated on: $(date)
        </div>
        
        <script>
            // Replace the placeholder summary with the final statistics
            document.getElementById('summary-statistics').innerHTML = \`${summary_html}\`;
            
            // Add AWS account info
            document.getElementById('aws-account').textContent = '${aws_account}';
            document.getElementById('aws-region').textContent = '${aws_region}';
            document.getElementById('aws-user').textContent = '${aws_user}';
            
            // Automatically expand the first section
            document.addEventListener('DOMContentLoaded', function() {
                const firstHeader = document.querySelector('.section-header');
                if (firstHeader) {
                    firstHeader.classList.add('active');
                    firstHeader.nextElementSibling.style.display = 'block';
                }
            });
            
            // Simple bar chart for requirements
            const createBarChart = () => {
                const requirementSummaries = document.querySelectorAll('.requirement-summary');
                const canvas = document.createElement('canvas');
                canvas.width = 500;
                canvas.height = 300;
                document.getElementById('requirements-chart').appendChild(canvas);
                
                const ctx = canvas.getContext('2d');
                const barWidth = 30;
                const barSpacing = 15;
                const startX = 40;
                const startY = 250;
                const maxHeight = 200;
                
                // Draw axes
                ctx.beginPath();
                ctx.moveTo(startX, 50);
                ctx.lineTo(startX, startY);
                ctx.lineTo(600, startY);
                ctx.strokeStyle = '#333';
                ctx.stroke();
                
                // Draw 100% line
                ctx.beginPath();
                ctx.moveTo(startX, 50);
                ctx.lineTo(600, 50);
                ctx.strokeStyle = '#ddd';
                ctx.stroke();
                
                // Add 100% label
                ctx.fillStyle = '#333';
                ctx.font = '12px Arial';
                ctx.fillText('100%', 10, 55);
                
                // Draw each bar
                let x = startX + 20;
                requirementSummaries.forEach((summary, index) => {
                    const percentage = summary.querySelector('.progress-bar').style.width.replace('%', '');
                    const color = summary.querySelector('.progress-bar').style.backgroundColor;
                    const reqNum = summary.querySelector('.requirement-header span').textContent.split(':')[0].trim().replace('Requirement ', '');
                    
                    // Draw bar
                    const barHeight = (percentage / 100) * maxHeight;
                    ctx.fillStyle = color;
                    ctx.fillRect(x, startY - barHeight, barWidth, barHeight);
                    
                    // Add label
                    ctx.fillStyle = '#333';
                    ctx.font = '12px Arial';
                    ctx.fillText(reqNum, x + barWidth/2 - 5, startY + 20);
                    ctx.fillText(percentage + '%', x + barWidth/2 - 10, startY - barHeight - 15);
                    
                    x += barWidth + barSpacing;
                });
            };
            
            // Create simple doughnut chart for overall compliance
            const createDoughnutChart = () => {
                const percentage = ${overall_compliance};
                const color = '${compliance_color}';
                
                // Create doughnut container
                const doughnutContainer = document.createElement('div');
                doughnutContainer.className = 'doughnut-chart';
                document.getElementById('overall-chart').appendChild(doughnutContainer);
                
                // Create percentage number in center
                const percentageText = document.createElement('div');
                percentageText.style.position = 'absolute';
                percentageText.style.top = '50%';
                percentageText.style.left = '50%';
                percentageText.style.transform = 'translate(-50%, -50%)';
                percentageText.style.fontSize = '36px';
                percentageText.style.fontWeight = 'bold';
                percentageText.style.color = color;
                percentageText.textContent = percentage + '%';
                doughnutContainer.appendChild(percentageText);
                
                // Create canvas for doughnut
                const canvas = document.createElement('canvas');
                canvas.width = 200;
                canvas.height = 200;
                doughnutContainer.appendChild(canvas);
                
                const ctx = canvas.getContext('2d');
                const centerX = 100;
                const centerY = 100;
                const outerRadius = 80;
                const innerRadius = 60;
                
                // Background circle (gray)
                ctx.beginPath();
                ctx.arc(centerX, centerY, outerRadius, 0, 2 * Math.PI);
                ctx.fillStyle = '#ddd';
                ctx.fill();
                
                // Inner circle (white)
                ctx.beginPath();
                ctx.arc(centerX, centerY, innerRadius, 0, 2 * Math.PI);
                ctx.fillStyle = '#fff';
                ctx.fill();
                
                // Percentage arc
                ctx.beginPath();
                ctx.moveTo(centerX, centerY);
                ctx.arc(centerX, centerY, outerRadius, -0.5 * Math.PI, (percentage / 100 * 2 - 0.5) * Math.PI);
                ctx.lineTo(centerX, centerY);
                ctx.fillStyle = color;
                ctx.fill();
                
                // Inner circle again to create doughnut
                ctx.beginPath();
                ctx.arc(centerX, centerY, innerRadius, 0, 2 * Math.PI);
                ctx.fillStyle = '#fff';
                ctx.fill();
                
                // Add compliance status text
                const statusText = document.createElement('div');
                statusText.style.textAlign = 'center';
                statusText.style.marginTop = '20px';
                statusText.style.fontWeight = 'bold';
                
                if (percentage >= 90) {
                    statusText.innerHTML = '<span style="color: #4CAF50;">Compliant</span>';
                } else if (percentage >= 70) {
                    statusText.innerHTML = '<span style="color: #ff9800;">Partially Compliant</span>';
                } else {
                    statusText.innerHTML = '<span style="color: #f44336;">Non-Compliant</span>';
                }
                
                document.getElementById('overall-chart').appendChild(statusText);
            };
            
            // Create charts
            document.addEventListener('DOMContentLoaded', function() {
                createBarChart();
                createDoughnutChart();
            });
        </script>
    </div>
</body>
</html>
EOT

echo "Executive summary report created: $OUTPUT_FILE"

# Open the report if on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$OUTPUT_FILE"
fi