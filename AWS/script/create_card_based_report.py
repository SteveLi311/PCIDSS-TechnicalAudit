#!/usr/bin/env python3

"""
PCI DSS 4.0 Card-Based Summary Report Generator
This script creates a summary report with a card-based layout rather than a table,
ensuring all requirements appear visually as siblings at the same level.
"""

import os
import re
import glob
from datetime import datetime
import sys
import html

def main():
    print("Generating card-based PCI DSS 4.0 summary report...")
    
    # Output file
    summary_report = "pci_dss_card_summary.html"
    
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
            for i, finding in enumerate(req_data["detailed_findings"]):
                if i < 3:  # Limit to top 3 critical findings per requirement
                    overall_stats["critical_findings"].append({
                        "req": req_num,
                        "title": finding["title"],
                        "details": finding["details"],
                        "recommendation": finding["recommendation"]
                    })
    
    # Sort requirements data by requirement number
    requirements_data.sort(key=lambda x: int(x["req_num"]))
    
    # Generate the summary report
    html_content = generate_card_html(requirements_data, overall_stats)
    
    # Write the final HTML to file
    with open(summary_report, "w") as f:
        f.write(html_content)
    
    print(f"Card-based summary report created successfully: {summary_report}")

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
    """Extract key data from a requirement report including detailed findings"""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            
            # Extract title
            title_match = re.search(r'<h1[^>]*>(.*?)</h1>', content, re.DOTALL)
            title = title_match.group(1).strip() if title_match else f"Requirement {req_num}"
            title = re.sub(r'<[^>]+>', '', title)
            
            # Extract detailed findings
            detailed_findings = []
            
            # Pattern 1: Look for check-item fail divs with their content
            fail_blocks = re.findall(r'<div class="check-item fail">(.*?)</div>\s*</div>', content, re.DOTALL)
            for block in fail_blocks:
                # Extract title from h3
                title_match = re.search(r'<h3.*?>(.*?)</h3>', block, re.DOTALL)
                finding_title = "Failed Check" if not title_match else re.sub(r'<[^>]+>', '', title_match.group(1)).strip()
                
                # Extract details
                details_match = re.search(r'<div>(.*?)</div>', block, re.DOTALL)
                finding_details = "No details available" if not details_match else details_match.group(1).strip()
                
                # Extract recommendation if available
                recommendation = ""
                recommendation_match = re.search(r'<strong>Recommendation:</strong>(.*?)(?:<br>|</div>)', block, re.DOTALL)
                if recommendation_match:
                    recommendation = recommendation_match.group(1).strip()
                else:
                    # Alternative pattern for recommendation
                    recommendation_match = re.search(r'<div class="recommendation">(.*?)</div>', block, re.DOTALL)
                    if recommendation_match:
                        recommendation = recommendation_match.group(1).strip()
                    else:
                        recommendation = "No specific recommendation provided."
                
                detailed_findings.append({
                    "title": finding_title,
                    "details": finding_details,
                    "recommendation": recommendation
                })
            
            # If no detailed findings found, check for alternative patterns
            if not detailed_findings:
                # Look for red text or failure indicators
                fail_indicators = re.findall(r'<span class="red">(.*?)</span>', content, re.DOTALL)
                for indicator in fail_indicators:
                    if "[FAIL]" in indicator:
                        # Find surrounding text
                        pattern = f'<span class="red">{re.escape(indicator)}</span>(.*?)(?:<br>|</div>|</h3>)'
                        context_match = re.search(pattern, content, re.DOTALL)
                        context = context_match.group(1).strip() if context_match else "Failed check"
                        
                        detailed_findings.append({
                            "title": f"Failed: {context}",
                            "details": "Specific details not available",
                            "recommendation": "Review the full requirement report for more information."
                        })
            
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
            
            # Create a simple list of findings for display
            findings_list = [finding["title"] for finding in detailed_findings]
            
            return {
                "req_num": req_num,
                "title": title,
                "findings": findings_list,
                "detailed_findings": detailed_findings,
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
            "detailed_findings": [{
                "title": "Error processing report",
                "details": f"An error occurred while processing this report: {str(e)}",
                "recommendation": "Check the original report file for details."
            }],
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

def generate_card_html(requirements_data, overall_stats):
    """Generate HTML with a card-based layout instead of a table"""
    
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
    
    # Generate requirement cards
    req_cards = []
    for req in requirements_data:
        # Create expandable findings section
        findings_html = ""
        if req["detailed_findings"]:
            for i, finding in enumerate(req["detailed_findings"]):
                findings_html += f"""
                <div class="expandable-finding">
                    <div class="finding-header" onclick="toggleFinding('finding-{req['req_num']}-{i}')">
                        <span class="toggle-icon">+</span> {finding["title"]}
                    </div>
                    <div class="finding-content" id="finding-{req['req_num']}-{i}">
                        <div class="finding-details">
                            <h4>Issue Details:</h4>
                            <div>{finding["details"]}</div>
                        </div>
                        <div class="finding-recommendation">
                            <h4>Recommendation:</h4>
                            <div>{finding["recommendation"]}</div>
                        </div>
                    </div>
                </div>
                """
        
        # Create card for this requirement
        card = f"""
        <div class="req-card">
            <div class="req-card-header">
                <div class="req-number">REQ {req["req_num"]}</div>
                <div class="req-title">{req["title"]}</div>
            </div>
            <div class="req-card-body">
                <div class="req-stats">
                    <div class="req-stat">
                        <div class="stat-label">Status</div>
                        <div class="stat-value {req["status_class"]}">{req["status"]}</div>
                    </div>
                    <div class="req-stat">
                        <div class="stat-label">Compliance</div>
                        <div class="stat-value">{req["compliance_pct"]:.1f}%</div>
                    </div>
                    <div class="req-stat">
                        <div class="stat-label">Passed/Failed</div>
                        <div class="stat-value">{req["passed"]}/{req["failed"]}</div>
                    </div>
                </div>
                <div class="expandable-section">
                    <div class="section-header" onclick="toggleSection('req-{req['req_num']}')">
                        <span class="toggle-icon">+</span> View Findings ({len(req["detailed_findings"])})
                    </div>
                    <div class="section-content" id="req-{req['req_num']}">
                        {findings_html if findings_html else "<p>No detailed findings available for this requirement.</p>"}
                    </div>
                </div>
            </div>
        </div>
        """
        req_cards.append(card)
    
    # Join all cards
    all_cards = "\n".join(req_cards)
    
    # Generate critical findings section with expandable details
    critical_findings_html = ""
    if overall_stats["critical_findings"]:
        critical_findings_html = "<h3>Critical Findings</h3>"
        
        # Group findings by requirement
        findings_by_req = {}
        for i, finding in enumerate(overall_stats["critical_findings"]):
            req = finding["req"]
            if req not in findings_by_req:
                findings_by_req[req] = []
            findings_by_req[req].append({
                "index": i,
                "title": finding["title"],
                "details": finding["details"],
                "recommendation": finding["recommendation"]
            })
        
        # Create expandable sections for each requirement
        req_sections = []
        for req, findings in sorted(findings_by_req.items(), key=lambda x: int(x[0])):
            # Create the findings content
            findings_content = []
            for finding in findings:
                finding_html = f"""
                <div class="critical-finding">
                    <div class="critical-finding-header" onclick="toggleCriticalFinding('critical-{req}-{finding['index']}')">
                        <span class="toggle-icon">+</span> {finding["title"]}
                    </div>
                    <div class="critical-finding-content" id="critical-{req}-{finding['index']}">
                        <div class="finding-details">
                            <h4>Issue Details:</h4>
                            <div>{finding["details"]}</div>
                        </div>
                        <div class="finding-recommendation">
                            <h4>Recommendation:</h4>
                            <div>{finding["recommendation"]}</div>
                        </div>
                    </div>
                </div>
                """
                findings_content.append(finding_html)
            
            # Create the complete section for this requirement
            req_section = f"""
            <div class="critical-req-section">
                <div class="critical-req-header" onclick="toggleCritical('critical-req-{req}')">
                    <span class="toggle-icon">+</span> 
                    <span class="finding-req">Req {req}</span> ({len(findings)} findings)
                </div>
                <div class="critical-req-content" id="critical-req-{req}">
                    {"".join(findings_content)}
                </div>
            </div>
            """
            req_sections.append(req_section)
        
        # Join all requirement sections
        critical_findings_html += "".join(req_sections)
    
    # Generate the final HTML with JavaScript for interactivity
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCI DSS 4.0 - Card-Based Summary Report</title>
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
        h4 {{
            color: #2c3e50;
            margin: 10px 0;
        }}
        .report-date {{
            text-align: right;
            color: #7f8c8d;
            font-style: italic;
            margin-bottom: 20px;
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
        
        /* Card-based layout */
        .requirements-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .req-card {{
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            background-color: #fff;
        }}
        .req-card-header {{
            background-color: #f8f9fa;
            padding: 15px;
            border-bottom: 1px solid #ddd;
            display: flex;
            align-items: center;
        }}
        .req-number {{
            background-color: #3498db;
            color: white;
            font-weight: bold;
            padding: 5px 10px;
            border-radius: 5px;
            margin-right: 15px;
            font-size: 14px;
        }}
        .req-title {{
            font-weight: bold;
            color: #2c3e50;
        }}
        .req-card-body {{
            padding: 15px;
        }}
        .req-stats {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 15px;
        }}
        .req-stat {{
            text-align: center;
        }}
        
        /* Expandable sections styling */
        .expandable-section, .expandable-finding, .critical-req-section, .critical-finding {{
            margin-bottom: 10px;
        }}
        .section-header, .finding-header, .critical-req-header, .critical-finding-header {{
            padding: 10px;
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 4px;
            cursor: pointer;
            user-select: none;
            display: flex;
            align-items: center;
        }}
        .section-header:hover, .finding-header:hover, .critical-req-header:hover, .critical-finding-header:hover {{
            background-color: #e9ecef;
        }}
        .section-content, .finding-content, .critical-req-content, .critical-finding-content {{
            display: none;
            padding: 15px;
            border: 1px solid #ddd;
            border-top: none;
            border-radius: 0 0 4px 4px;
        }}
        .toggle-icon {{
            display: inline-block;
            width: 20px;
            height: 20px;
            text-align: center;
            line-height: 20px;
            margin-right: 10px;
            font-weight: bold;
        }}
        .finding-details, .finding-recommendation {{
            margin-bottom: 15px;
        }}
        .finding-details h4, .finding-recommendation h4 {{
            margin-bottom: 5px;
            color: #3498db;
        }}
        
        /* Critical findings styling */
        .critical-req-header {{
            background-color: #fdeded;
        }}
        .critical-req-header:hover {{
            background-color: #fad7d7;
        }}
        .critical-finding-header {{
            background-color: #fff;
            margin-left: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>PCI DSS 4.0 - Card-Based Summary Report</h1>
        
        <div class="report-date">
            Generated on: {datetime.now().strftime("%B %d, %Y")}
        </div>
        
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <p>This report provides a summary of the PCI DSS 4.0 compliance assessment across all 12 requirements. Click on the findings to expand and see detailed information about each issue and recommended remediation steps.</p>
            
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
        <div class="requirements-grid">
            {all_cards}
        </div>
        
        <h2>Recommendations</h2>
        <p>Based on the assessment results, the following actions are recommended:</p>
        <ol>
            <li>Address all critical findings identified in the report - click on each finding for detailed remediation steps.</li>
            <li>Focus on requirements with the lowest compliance percentages.</li>
            <li>Implement remediation plans for all failed checks.</li>
            <li>Conduct regular reassessment to track compliance progress.</li>
            <li>Document all changes made to address compliance gaps.</li>
        </ol>
    </div>
    
    <script>
        // JavaScript for expandable sections
        function toggleSection(id) {{
            const content = document.getElementById(id);
            const header = content.previousElementSibling;
            const icon = header.querySelector('.toggle-icon');
            
            if (content.style.display === 'block') {{
                content.style.display = 'none';
                icon.textContent = '+';
            }} else {{
                content.style.display = 'block';
                icon.textContent = '-';
            }}
        }}
        
        function toggleFinding(id) {{
            const content = document.getElementById(id);
            const header = content.previousElementSibling;
            const icon = header.querySelector('.toggle-icon');
            
            if (content.style.display === 'block') {{
                content.style.display = 'none';
                icon.textContent = '+';
            }} else {{
                content.style.display = 'block';
                icon.textContent = '-';
            }}
        }}
        
        function toggleCritical(id) {{
            const content = document.getElementById(id);
            const header = content.previousElementSibling;
            const icon = header.querySelector('.toggle-icon');
            
            if (content.style.display === 'block') {{
                content.style.display = 'none';
                icon.textContent = '+';
            }} else {{
                content.style.display = 'block';
                icon.textContent = '-';
            }}
        }}
        
        function toggleCriticalFinding(id) {{
            const content = document.getElementById(id);
            const header = content.previousElementSibling;
            const icon = header.querySelector('.toggle-icon');
            
            if (content.style.display === 'block') {{
                content.style.display = 'none';
                icon.textContent = '+';
            }} else {{
                content.style.display = 'block';
                icon.textContent = '-';
            }}
            
            // Stop event propagation to parent elements
            event.stopPropagation();
        }}
    </script>
</body>
</html>
"""
    
    return html

if __name__ == "__main__":
    main()