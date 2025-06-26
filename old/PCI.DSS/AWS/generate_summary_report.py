#!/usr/bin/env python3

"""
PCI DSS 4.0 Summary Report Generator
This script creates a concise summary report from all PCI DSS reports in the 'reports' folder.
"""

import os
import re
import glob
from datetime import datetime
import sys
import html

def main():
    print("Generating PCI DSS 4.0 summary report...")
    
    # Output file
    summary_report = "pci_dss_summary_report.html"
    
    # Get all report files
    report_files = sorted(glob.glob("reports/*.html"))
    
    if not report_files:
        print("Error: No HTML reports found in the 'reports' directory")
        sys.exit(1)
    
    # Process each report to extract summary data
    requirements_data = []
    
    # Track overall statistics
    overall_stats = {
        "total_checks": 0,
        "passed": 0, 
        "failed": 0,
        "warnings": 0,
        "critical_findings": []
    }
    
    for file_path in report_files:
        filename = os.path.basename(file_path)
        req_num = extract_requirement_number(filename)
        
        if req_num:
            print(f"Processing file: {file_path} for requirement {req_num}")
            req_data = extract_requirement_data(file_path, req_num)
            
            # Add to requirements data
            requirements_data.append(req_data)
            
            # Update overall statistics
            overall_stats["total_checks"] += req_data["total_checks"]
            overall_stats["passed"] += req_data["passed"]
            overall_stats["failed"] += req_data["failed"]
            overall_stats["warnings"] += req_data["warnings"]
            
            # Add critical findings
            for finding in req_data["critical_findings"]:
                overall_stats["critical_findings"].append({
                    "req": req_num,
                    "finding": finding
                })
    
    # Generate the summary report
    html_content = generate_summary_html(requirements_data, overall_stats)
    
    # Write the final HTML to file
    with open(summary_report, "w") as f:
        f.write(html_content)
    
    print(f"Summary report created successfully: {summary_report}")

def extract_requirement_number(filename):
    """Extract the requirement number from the filename"""
    patterns = [
        r'pci_req([0-9]+)',
        r'pci_r([0-9]+)',
        r'pci_requirement([0-9]+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, filename)
        if match:
            return match.group(1)
    
    return None

def extract_requirement_data(file_path, req_num):
    """Extract key data from a requirement report"""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            
            # Extract title
            title_match = re.search(r'<h1[^>]*>(.*?)</h1>', content, re.DOTALL)
            title = title_match.group(1).strip() if title_match else f"Requirement {req_num}"
            title = re.sub(r'<[^>]+>', '', title)
            
            # Extract findings
            findings = []
            
            # Pattern 1: Look for [FAIL] sections
            fail_matches = re.findall(r'<span class="red">\[FAIL\]</span>(.*?)</h3>', content, re.DOTALL)
            for match in fail_matches:
                finding = match.strip()
                # Clean up HTML tags
                finding = re.sub(r'<[^>]+>', '', finding)
                findings.append(finding)
            
            # Count checks
            checks, passed, failed, warnings = count_checks(content)
            
            # Calculate compliance percentage
            compliance_pct = (passed / checks * 100) if checks > 0 else 0
            
            # Determine status
            if compliance_pct >= 90:
                status = "Compliant"
                status_class = "compliant"
            elif compliance_pct >= 70:
                status = "Partially Compliant"
                status_class = "partial"
            else:
                status = "Non-Compliant"
                status_class = "non-compliant"
            
            return {
                "req_num": req_num,
                "title": title,
                "findings": findings,
                "critical_findings": findings[:3] if len(findings) > 0 else [],  # Top 3 findings
                "total_checks": checks,
                "passed": passed,
                "failed": failed,
                "warnings": warnings,
                "compliance_pct": compliance_pct,
                "status": status,
                "status_class": status_class
            }
            
    except Exception as e:
        print(f"Error processing file {file_path}: {e}")
        return {
            "req_num": req_num,
            "title": f"Requirement {req_num}",
            "findings": ["Error processing report"],
            "critical_findings": ["Error processing report"],
            "total_checks": 1,
            "passed": 0,
            "failed": 1,
            "warnings": 0,
            "compliance_pct": 0,
            "status": "Unknown",
            "status_class": "non-compliant"
        }

def count_checks(content):
    """Count the number of checks, passed, failed, and warnings"""
    # Count based on the [PASS], [FAIL], and [WARN] tags
    pass_count = len(re.findall(r'\[PASS\]', content, re.IGNORECASE))
    fail_count = len(re.findall(r'\[FAIL\]', content, re.IGNORECASE))
    warn_count = len(re.findall(r'\[WARN\]', content, re.IGNORECASE))
    
    # Alternative approach: Count based on div classes
    pass_count_alt = len(re.findall(r'<div class="check-item pass"', content, re.IGNORECASE))
    fail_count_alt = len(re.findall(r'<div class="check-item fail"', content, re.IGNORECASE))
    warn_count_alt = len(re.findall(r'<div class="check-item warning"', content, re.IGNORECASE))
    
    # Take the maximum of the two approaches
    pass_count = max(pass_count, pass_count_alt)
    fail_count = max(fail_count, fail_count_alt)
    warn_count = max(warn_count, warn_count_alt)
    
    total_checks = pass_count + fail_count + warn_count
    
    # If no checks were detected, set a base value of 1 check
    if total_checks == 0:
        total_checks = 1
        pass_count = 1
    
    return total_checks, pass_count, fail_count, warn_count

def generate_summary_html(requirements_data, overall_stats):
    """Generate the HTML for the summary report"""
    
    # Calculate overall compliance percentage
    overall_compliance = (overall_stats["passed"] / overall_stats["total_checks"] * 100) if overall_stats["total_checks"] > 0 else 0
    
    # Determine overall status
    if overall_compliance >= 90:
        overall_status = "Compliant"
        overall_status_class = "compliant"
    elif overall_compliance >= 70:
        overall_status = "Partially Compliant"
        overall_status_class = "partial"
    else:
        overall_status = "Non-Compliant"
        overall_status_class = "non-compliant"
    
    # Generate requirements table rows
    req_rows = ""
    for req in sorted(requirements_data, key=lambda x: int(x["req_num"])):
        # Format findings as bullet list
        findings_list = ""
        if req["findings"]:
            findings_list = "<ul class='findings-list'>"
            for finding in req["findings"][:3]:  # Show top 3 findings
                findings_list += f"<li>{finding}</li>"
            
            if len(req["findings"]) > 3:
                findings_list += f"<li>...plus {len(req['findings']) - 3} more findings</li>"
                
            findings_list += "</ul>"
        
        req_rows += f"""
        <tr>
            <td>{req["req_num"]}</td>
            <td>{req["title"]}</td>
            <td class="{req["status_class"]}">{req["status"]}</td>
            <td>{req["compliance_pct"]:.1f}%</td>
            <td>{req["passed"]}</td>
            <td>{req["failed"]}</td>
            <td>{req["warnings"]}</td>
            <td>{findings_list}</td>
        </tr>
        """
    
    # Generate critical findings list
    critical_findings_html = ""
    if overall_stats["critical_findings"]:
        critical_findings_html = "<h3>Critical Findings</h3><ul class='critical-findings-list'>"
        # Sort findings by requirement number
        sorted_findings = sorted(overall_stats["critical_findings"], key=lambda x: int(x["req"]))
        
        # Take top 10 findings
        top_findings = sorted_findings[:10] if len(sorted_findings) > 10 else sorted_findings
        
        for finding in top_findings:
            critical_findings_html += f"""<li><span class="finding-req">Req {finding["req"]}</span> {finding["finding"]}</li>"""
        
        if len(sorted_findings) > 10:
            critical_findings_html += f"<li>...plus {len(sorted_findings) - 10} more critical findings</li>"
            
        critical_findings_html += "</ul>"
    
    # Generate the final HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCI DSS 4.0 - Summary Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 30px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #2c3e50;
            margin-top: 30px;
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
        }}
        h3 {{
            color: #3498db;
            margin-top: 20px;
        }}
        .report-date {{
            text-align: right;
            color: #7f8c8d;
            font-style: italic;
            margin-bottom: 20px;
        }}
        .summary-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .summary-table th, .summary-table td {{
            padding: 12px;
            border: 1px solid #ddd;
            text-align: left;
        }}
        .summary-table th {{
            background-color: #f2f2f2;
            font-weight: bold;
        }}
        .summary-table tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .summary-table tr:hover {{
            background-color: #f0f7fd;
        }}
        .compliant {{
            color: green;
            font-weight: bold;
        }}
        .non-compliant {{
            color: red;
            font-weight: bold;
        }}
        .partial {{
            color: orange;
            font-weight: bold;
        }}
        .executive-summary {{
            background-color: #f0f7fd;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin: 20px 0;
        }}
        .findings-list {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        .findings-list li {{
            margin-bottom: 5px;
        }}
        .critical-findings-list {{
            list-style-type: none;
            padding-left: 0;
        }}
        .critical-findings-list li {{
            margin-bottom: 10px;
            padding-bottom: 10px;
            border-bottom: 1px solid #fad7d7;
        }}
        .finding-req {{
            background-color: #e74c3c;
            color: white;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 12px;
            margin-right: 10px;
            text-transform: uppercase;
        }}
        .summary-stats {{
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin: 20px 0;
        }}
        .stat-box {{
            background: white;
            border-radius: 5px;
            padding: 15px;
            width: 22%;
            margin-bottom: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-label {{
            font-size: 14px;
            color: #7f8c8d;
        }}
        .stat-value {{
            font-size: 24px;
            font-weight: bold;
            margin-top: 10px;
        }}
        .stat-value.passed {{
            color: #2ecc71;
        }}
        .stat-value.failed {{
            color: #e74c3c;
        }}
        .stat-value.warning {{
            color: #f39c12;
        }}
        .overall-status {{
            font-size: 18px;
            margin-top: 10px;
            padding: 5px 10px;
            border-radius: 5px;
            display: inline-block;
        }}
        .overall-status.compliant {{
            background-color: rgba(46, 204, 113, 0.1);
        }}
        .overall-status.non-compliant {{
            background-color: rgba(231, 76, 60, 0.1);
        }}
        .overall-status.partial {{
            background-color: rgba(243, 156, 18, 0.1);
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>PCI DSS 4.0 - Summary Report</h1>
        
        <div class="report-date">
            Generated on: {datetime.now().strftime("%B %d, %Y")}
        </div>
        
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <p>This report provides a summary of the PCI DSS 4.0 compliance assessment across all 12 requirements. It highlights key findings, compliance status, and areas requiring immediate attention.</p>
            
            <div class="summary-stats">
                <div class="stat-box">
                    <div class="stat-label">Compliance Status</div>
                    <div class="stat-value {overall_status_class}">{overall_compliance:.1f}%</div>
                    <div class="overall-status {overall_status_class}">{overall_status}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Total Checks</div>
                    <div class="stat-value">{overall_stats["total_checks"]}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Passed</div>
                    <div class="stat-value passed">{overall_stats["passed"]}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Failed</div>
                    <div class="stat-value failed">{overall_stats["failed"]}</div>
                </div>
            </div>
            
            {critical_findings_html}
        </div>
        
        <h2>Requirements Summary</h2>
        <table class="summary-table">
            <thead>
                <tr>
                    <th>Req #</th>
                    <th>Requirement</th>
                    <th>Status</th>
                    <th>Compliance</th>
                    <th>Passed</th>
                    <th>Failed</th>
                    <th>Warnings</th>
                    <th>Key Findings</th>
                </tr>
            </thead>
            <tbody>
                {req_rows}
            </tbody>
        </table>
        
        <h2>Recommendations</h2>
        <p>Based on the assessment results, the following actions are recommended:</p>
        <ol>
            <li>Address all critical findings identified in the report.</li>
            <li>Focus on requirements with the lowest compliance percentages.</li>
            <li>Implement remediation plans for all failed checks.</li>
            <li>Conduct regular reassessment to track compliance progress.</li>
            <li>Document all changes made to address compliance gaps.</li>
        </ol>
    </div>
</body>
</html>
"""
    
    return html

if __name__ == "__main__":
    main()