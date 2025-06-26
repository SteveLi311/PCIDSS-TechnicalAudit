#!/bin/bash
# PCI DSS HTML Report Library
# This script contains shared functions for generating HTML reports for PCI DSS compliance checks

# Set HTML color codes
HTML_RED="#f44336"
HTML_GREEN="#4CAF50"
HTML_YELLOW="#ff9800"
HTML_BLUE="#2196F3"
HTML_GRAY="#757575"

# Initialize HTML report content
initialize_html_report() {
    local output_file="$1"
    local report_title="$2"
    local requirement_number="$3"
    local region="$4"
    local assessment_date=$(date)
    local aws_account=$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null)
    local aws_user=$(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null)
    
    # If AWS account info couldn't be retrieved
    if [ -z "$aws_account" ]; then
        aws_account="Unknown (Check AWS CLI configuration)"
    fi
    
    if [ -z "$aws_user" ]; then
        aws_user="Unknown (Check AWS CLI configuration)"
    fi

    cat > "$output_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCI DSS 4.0 - Requirement $requirement_number Assessment Report</title>
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
        .check-item {
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
        }
        /* Detailed failure information styling */
        .detailed-info {
            margin-top: 15px;
        }
        details {
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 0.5em 0.5em 0;
            margin-bottom: 15px;
        }
        summary {
            font-weight: bold;
            margin: -0.5em -0.5em 0;
            padding: 0.5em;
            cursor: pointer;
            background-color: #f0f0f0;
        }
        details[open] {
            padding: 0.5em;
        }
        details[open] summary {
            border-bottom: 1px solid #ddd;
            margin-bottom: 0.5em;
        }
        .details-content {
            padding: 10px;
            background-color: #f9f9f9;
        }
        .summary-details {
            font-weight: bold;
            margin-bottom: 10px;
        }
        .recommendation {
            margin-top: 10px;
            padding: 10px;
            background-color: #f0f8ff;
            border-left: 3px solid #2196F3;
        }
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
            background-color: #4CAF50;
            text-align: center;
            line-height: 25px;
            color: white;
        }
        .recommendation {
            padding: 10px;
            margin-top: 10px;
            background-color: #e1f5fe;
            border-left: 4px solid #03a9f4;
        }
        .timestamp {
            color: #757575;
            font-style: italic;
            text-align: right;
        }
        pre {
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
        code {
            font-family: Consolas, Monaco, 'Andale Mono', monospace;
            font-size: 0.9em;
        }
        /* Color classes */
        .green { color: #4CAF50; }
        .red { color: #f44336; }
        .yellow { color: #ff9800; }
        .blue { color: #2196F3; }
        .gray { color: #757575; }
        
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
        <h1>$report_title</h1>
        
        <div class="info-table">
            <table>
                <tr>
                    <th>AWS Account</th>
                    <td>${aws_account}</td>
                </tr>
                <tr>
                    <th>AWS Region</th>
                    <td>${region}</td>
                </tr>
                <tr>
                    <th>Assessment Date</th>
                    <td>${assessment_date}</td>
                </tr>
                <tr>
                    <th>Assessed By</th>
                    <td>${aws_user}</td>
                </tr>
            </table>
        </div>
        
        <div class="summary-box">
            <h2 style="margin-top: 0;">Summary</h2>
            <div id="summary-statistics">
                <!-- Placeholder - will be filled at the end -->
                <p>Assessment in progress...</p>
            </div>
        </div>
        
        <!-- Report content will be added here -->
        <div id="report-content">
EOF
}

# Function to append to HTML report
html_append() {
    local output_file="$1"
    local content="$2"
    
    # Debug check for empty output file
    if [ -z "$output_file" ]; then
        echo "ERROR: Empty output file parameter in html_append"
        return 1
    fi
    
    echo "$content" >> "$output_file"
}

# Function to add a new section to the HTML report
add_section() {
    local output_file="$1"
    local section_id="$2"
    local section_title="$3"
    local is_active="$4"  # "active" or empty
    
    local active_class=""
    if [ "$is_active" = "active" ]; then
        active_class="active"
    fi
    
    local visibility="none"
    if [ "$is_active" = "active" ]; then
        visibility="block"
    fi
    
    local content="
        <div class=\"section\">
            <div class=\"section-header ${active_class}\" onclick=\"this.classList.toggle('active'); this.nextElementSibling.style.display = this.classList.contains('active') ? 'block' : 'none';\">
                ${section_title}
            </div>
            <div class=\"section-content\" style=\"display: ${visibility};\">
                <div id=\"${section_id}\">
    "
    
    html_append "$output_file" "$content"
}

# Function to close a section
close_section() {
    local output_file="$1"
    local content="
                </div>
            </div>
        </div>
    "
    html_append "$output_file" "$content"
}

# Function to add a check item to the HTML report
add_check_item() {
    local output_file="$1"
    local status="$2"     # "pass", "fail", "warning", or "info"
    local title="$3"
    local details="$4"
    local recommendation="$5"  # Optional
    
    local status_color=""
    local status_text=""
    
    case "$status" in
        "pass")
            status_color="green"
            status_text="PASS"
            ;;
        "fail")
            status_color="red"
            status_text="FAIL"
            ;;
        "warning")
            status_color="yellow"
            status_text="WARNING"
            ;;
        "info")
            status_color="blue"
            status_text="INFO"
            ;;
    esac
    
    # Add collapsible sections for detailed failure information
    local details_display="$details"
    if [ "$status" = "fail" ] && [[ "$details" == *"<br><br><strong>"* ]]; then
        local unique_id=$(date +%s%N)
        details_display="
            <div class=\"summary-details\">${details%%<br><br><strong>*}</div>
            <div class=\"detailed-info\">
                <details>
                    <summary>Click to view detailed information</summary>
                    <div class=\"details-content\">
                        ${details#*<br><br>}
                    </div>
                </details>
            </div>
        "
    fi
    
    local content="
                    <div class=\"check-item ${status}\">
                        <h3><span class=\"${status_color}\">[${status_text}]</span> ${title}</h3>
                        <div>${details_display}</div>
    "
    
    if [ -n "$recommendation" ]; then
        content+="
                        <div class=\"recommendation\">
                            <strong>Recommendation:</strong> ${recommendation}
                        </div>
        "
    fi
    
    content+="
                    </div>
    "
    
    html_append "$output_file" "$content"
}

# Function to finalize the HTML report
finalize_html_report() {
    local output_file="$1"
    local total="$2"
    local passed="$3"
    local failed="$4"
    local warnings="$5"
    local requirement_number="$6"
    local failed_access_denied=${7:-0}  # Optional parameter for access denied failures
    
    # Calculate compliance percentage (excluding warnings and access denied failures)
    local compliance_percentage=0
    if [ $((total - warnings - failed_access_denied)) -gt 0 ]; then
        compliance_percentage=$(( (passed * 100) / (total - warnings - failed_access_denied) ))
    fi
    
    # Set progress bar color based on compliance percentage
    local progress_color="#4CAF50"  # Green by default
    if [ $compliance_percentage -lt 70 ]; then
        progress_color="#f44336"    # Red for < 70%
    elif [ $compliance_percentage -lt 90 ]; then
        progress_color="#ff9800"    # Yellow for 70-89%
    fi
    
    # Create summary HTML
    local summary_html="
            <table class=\"summary-table\">
                <tr>
                    <th>Total Checks</th>
                    <th>Passed</th>
                    <th>Failed</th>
                    <th>Warnings/Manual</th>
                    <th>Compliance</th>
                </tr>
                <tr>
                    <td>${total}</td>
                    <td><span class=\"green\">${passed}</span></td>
                    <td><span class=\"red\">${failed}</span></td>
                    <td><span class=\"yellow\">${warnings}</span></td>
                    <td>${compliance_percentage}%</td>
                </tr>
            </table>
            
            <div class=\"progress-container\">
                <div class=\"progress-bar\" style=\"width: ${compliance_percentage}%; background-color: ${progress_color};\">
                    ${compliance_percentage}%
                </div>
            </div>
    "
    
    # Add summary information
    local important_notes="
            <h3>Important Notes</h3>
            <ol>
                <li>This report provides a high-level assessment of AWS controls for PCI DSS Requirement $requirement_number.</li>
                <li>Many checks require manual verification of documentation and procedures.</li>
                <li>A full PCI DSS assessment requires detailed analysis of all system components in the CDE.</li>
                <li>This report does not replace the need for a qualified security assessor (QSA).</li>
                <li>For a complete PCI DSS assessment, refer to the PCI DSS v4.0 standard.</li>
            </ol>
    "
    
    # Add final JavaScript and close HTML tags
    local content="
        </div>
        
        <div class=\"timestamp\">
            Report generated on: $(date)
        </div>
        
        <script>
            // Replace the placeholder summary with the final statistics
            document.getElementById('summary-statistics').innerHTML = \`${summary_html}\`;
            
            // Add important notes at the end
            document.getElementById('report-content').innerHTML += \`${important_notes}\`;
            
            // Automatically expand the first section
            document.addEventListener('DOMContentLoaded', function() {
                const firstHeader = document.querySelector('.section-header');
                if (firstHeader) {
                    firstHeader.classList.add('active');
                    firstHeader.nextElementSibling.style.display = 'block';
                }
            });
        </script>
    </div>
</body>
</html>
"
    
    html_append "$output_file" "$content"
}

# Function to check command availability and permissions
check_command_access() {
    local output_file="$1"
    local service="$2"
    local command="$3"
    local region="$4"
    
    echo -ne "Checking access to AWS $service $command... "
    
    output=$(aws $service $command --region $region 2>&1)
    
    if [[ $output == *"AccessDenied"* ]] || [[ $output == *"UnauthorizedOperation"* ]] || [[ $output == *"operation: You are not authorized"* ]]; then
        echo -e "\033[0;31mFAILED\033[0m - Access Denied"
        add_check_item "$output_file" "fail" "AWS API Access: $service $command" "Access Denied. Your AWS account does not have permission to perform this operation." "Ensure your AWS account has read permissions for $service:$command"
        # Set a global variable to track this as an access denied failure
        export PCI_ACCESS_DENIED=1
        return 1
    else
        echo -e "\033[0;32mSUCCESS\033[0m"
        add_check_item "$output_file" "pass" "AWS API Access: $service $command" "Successfully verified access to this AWS API." ""
        export PCI_ACCESS_DENIED=0
        return 0
    fi
}

# Function to add a manual check warning (these shouldn't count against compliance)
add_manual_check() {
    local output_file="$1"
    local title="$2"
    local details="$3"
    local recommendation="$4"
    
    add_check_item "$output_file" "warning" "$title" "$details" "$recommendation"
    # Set a global variable to track this as a manual check warning
    export PCI_MANUAL_CHECK=1
    return 0
}
