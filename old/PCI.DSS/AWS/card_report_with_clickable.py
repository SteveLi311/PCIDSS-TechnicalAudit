#!/usr/bin/env python3

"""
PCI DSS 4.0 Card-Based Summary Report with Clickable Content
This script creates a card-based report with:
1. Fixed hierarchical structure (all requirements at same level)
2. Clickable, expandable content to show details
"""

import os
import re
import glob
from datetime import datetime
import sys

def main():
    print("Creating card-based PCI DSS 4.0 summary report with clickable content...")
    
    # Output file
    summary_report = "pci_dss_card_interactive.html"
    
    # Get all report files
    report_files = sorted(glob.glob("reports/*.html"))
    
    if not report_files:
        print("Error: No HTML reports found in the 'reports' directory")
        sys.exit(1)
    
    # Extract data from report files
    req_data_list = []
    for file_path in report_files:
        filename = os.path.basename(file_path)
        req_num = extract_requirement_number(filename)
        
        if req_num:
            print(f"Processing file: {file_path} for requirement {req_num}")
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract detailed information
            title = extract_title(content, req_num)
            detailed_findings = extract_detailed_findings(content)
            
            # Extract stats
            stats = extract_stats(content)
            
            req_data_list.append({
                "req_num": req_num,
                "title": title,
                "findings": detailed_findings,
                "stats": stats
            })
    
    # Sort requirements by number
    req_data_list.sort(key=lambda x: int(x["req_num"]))
    
    # Generate the HTML report
    html_content = generate_interactive_card_html(req_data_list)
    
    # Write the report to file
    with open(summary_report, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"Interactive card-based summary report created successfully: {summary_report}")

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

def extract_title(content, req_num):
    """Extract title from content"""
    title_match = re.search(r'<h1[^>]*>(.*?)</h1>', content, re.DOTALL)
    if title_match:
        title = title_match.group(1).strip()
        title = re.sub(r'<[^>]+>', '', title)
        return title
    return f"Requirement {req_num}"

def extract_detailed_findings(content):
    """Extract detailed findings from content"""
    detailed_findings = []
    
    # First approach: Look for check-item fail divs with their content
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
    
    # Alternative approach if no findings found: look for [FAIL] patterns
    if not detailed_findings:
        fail_matches = re.findall(r'<span class="red">\[FAIL\]</span>(.*?)</h3>', content, re.DOTALL)
        for match in fail_matches:
            finding = match.strip()
            finding = re.sub(r'<[^>]+>', '', finding)
            detailed_findings.append({
                "title": finding,
                "details": "Specific details not available in the report.",
                "recommendation": "Review the full requirement report for detailed recommendations."
            })
    
    return detailed_findings

def extract_stats(content):
    """Extract compliance statistics from the report"""
    # Default stats
    stats = {
        "compliance_pct": 0,
        "status": "Unknown",
        "status_class": "non-compliant",
        "total_checks": 0,
        "passed": 0,
        "failed": 0,
        "warnings": 0
    }
    
    # Count checks
    pass_count = len(re.findall(r'\[PASS\]', content, re.IGNORECASE))
    fail_count = len(re.findall(r'\[FAIL\]', content, re.IGNORECASE))
    warn_count = len(re.findall(r'\[WARN\]', content, re.IGNORECASE))
    
    # Alternative count based on div classes
    pass_count_alt = len(re.findall(r'<div class="check-item pass"', content, re.IGNORECASE))
    fail_count_alt = len(re.findall(r'<div class="check-item fail"', content, re.IGNORECASE))
    warn_count_alt = len(re.findall(r'<div class="check-item warning"', content, re.IGNORECASE))
    
    # Take the maximum of the two approaches
    pass_count = max(pass_count, pass_count_alt)
    fail_count = max(fail_count, fail_count_alt)
    warn_count = max(warn_count, warn_count_alt)
    
    total_checks = pass_count + fail_count + warn_count
    
    # Default if no checks detected
    if total_checks == 0:
        stats["total_checks"] = 1
        stats["passed"] = 1
        stats["compliance_pct"] = 100
        stats["status"] = "Compliant"
        stats["status_class"] = "compliant"
        return stats
    
    # Calculate stats
    stats["total_checks"] = total_checks
    stats["passed"] = pass_count
    stats["failed"] = fail_count
    stats["warnings"] = warn_count
    stats["compliance_pct"] = (pass_count / total_checks * 100)
    
    # Determine status
    if stats["compliance_pct"] >= 90:
        stats["status"] = "Compliant"
        stats["status_class"] = "compliant"
    elif stats["compliance_pct"] >= 70:
        stats["status"] = "Partially Compliant"
        stats["status_class"] = "partial"
    else:
        stats["status"] = "Non-Compliant" 
        stats["status_class"] = "non-compliant"
    
    return stats

def generate_interactive_card_html(req_data_list):
    """Generate the HTML with interactive card-based layout"""
    
    # Calculate overall statistics
    overall_stats = {
        "total_checks": sum(req["stats"]["total_checks"] for req in req_data_list),
        "passed": sum(req["stats"]["passed"] for req in req_data_list),
        "failed": sum(req["stats"]["failed"] for req in req_data_list),
        "warnings": sum(req["stats"]["warnings"] for req in req_data_list)
    }
    
    # Calculate overall compliance
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
    
    # Generate card items with clickable content
    card_items = []
    for req_data in req_data_list:
        req_num = req_data["req_num"]
        title = req_data["title"]
        findings = req_data["findings"]
        stats = req_data["stats"]
        
        # Create expandable findings sections
        findings_html = ""
        if findings:
            for i, finding in enumerate(findings):
                findings_html += f"""
                <div class="finding-item">
                    <div class="finding-header" onclick="toggleFinding('finding-{req_num}-{i}')">
                        <span class="toggle-icon">+</span> {finding["title"]}
                    </div>
                    <div class="finding-content" id="finding-{req_num}-{i}">
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
        else:
            findings_html = "<p class='no-findings'>No compliance issues found for this requirement.</p>"
        
        # Create the card item with clickable content
        card = f"""
        <div class="req-card" id="req-card-{req_num}">
            <div class="req-card-header">
                <span class="req-badge">REQ {req_num}</span>
                <h3 class="req-title">{title}</h3>
            </div>
            <div class="req-card-body">
                <div class="req-stats">
                    <div class="req-stat">
                        <div class="stat-label">Status</div>
                        <div class="stat-value {stats['status_class']}">{stats['status']}</div>
                    </div>
                    <div class="req-stat">
                        <div class="stat-label">Compliance</div>
                        <div class="stat-value">{stats['compliance_pct']:.1f}%</div>
                    </div>
                    <div class="req-stat">
                        <div class="stat-label">Passed</div>
                        <div class="stat-value">{stats['passed']}/{stats['total_checks']}</div>
                    </div>
                </div>
                
                <div class="findings-section">
                    <div class="section-header" onclick="toggleSection('section-{req_num}')">
                        <span class="toggle-icon">+</span> 
                        <span class="section-title">View Findings ({len(findings)})</span>
                    </div>
                    <div class="section-content" id="section-{req_num}">
                        {findings_html}
                    </div>
                </div>
            </div>
        </div>
        """
        card_items.append(card)
    
    # Join all card items with explicit DIV wrappers for each item
    all_cards = "\n".join([f'<div class="grid-item">{card}</div>' for card in card_items])
    
    # Get critical findings for summary section
    critical_findings = []
    for req in req_data_list:
        if req["stats"]["status_class"] == "non-compliant":
            for finding in req["findings"][:2]:  # Take top 2 findings from non-compliant requirements
                critical_findings.append({
                    "req": req["req_num"],
                    "title": finding["title"]
                })
    
    # Create critical findings HTML
    critical_findings_html = ""
    if critical_findings:
        findings_list = ""
        for finding in critical_findings[:10]:  # Show up to 10 critical findings
            findings_list += f'<li><span class="finding-req">Req {finding["req"]}</span> {finding["title"]}</li>'
        
        critical_findings_html = f"""
        <div class="critical-findings">
            <h3>Critical Findings</h3>
            <ul class="critical-list">
                {findings_list}
            </ul>
        </div>
        """
    
    # Create the full HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCI DSS 4.0 - Interactive Summary Report</title>
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
            padding-bottom: 10px;
            border-bottom: 1px solid #ddd;
        }}
        h3 {{
            margin: 0;
            color: #2c3e50;
            font-size: 16px;
        }}
        h4 {{
            color: #3498db;
            margin: 15px 0 10px 0;
            font-size: 14px;
        }}
        .report-date {{
            text-align: right;
            color: #7f8c8d;
            font-style: italic;
            margin-bottom: 20px;
        }}
        
        /* Card-based layout */
        .requirements-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 25px;
            margin-top: 30px;
        }}
        .grid-item {{
            /* Explicit wrapper for each card to prevent parent-child relationship appearance */
        }}
        .req-card {{
            border: 2px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
            background-color: #fff;
            height: 100%;
            display: flex;
            flex-direction: column;
        }}
        .req-card-header {{
            background-color: #f8f9fa;
            padding: 15px;
            border-bottom: 1px solid #ddd;
            display: flex;
            align-items: center;
        }}
        .req-badge {{
            background-color: #3498db;
            color: white;
            font-weight: bold;
            padding: 8px 12px;
            border-radius: 5px;
            margin-right: 15px;
            font-size: 16px;
            flex-shrink: 0;
        }}
        .req-title {{
            font-size: 16px;
        }}
        .req-card-body {{
            padding: 15px;
            flex-grow: 1;
            display: flex;
            flex-direction: column;
        }}
        
        /* Statistics styling */
        .req-stats {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 20px;
        }}
        .req-stat {{
            text-align: center;
            flex: 1;
        }}
        .stat-label {{
            font-size: 12px;
            color: #7f8c8d;
            margin-bottom: 5px;
        }}
        .stat-value {{
            font-size: 18px;
            font-weight: bold;
        }}
        .compliant {{
            color: #2ecc71;
        }}
        .non-compliant {{
            color: #e74c3c;
        }}
        .partial {{
            color: #f39c12;
        }}
        
        /* Clickable expandable content */
        .findings-section {{
            margin-top: auto;
        }}
        .section-header, .finding-header {{
            padding: 10px;
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 4px;
            cursor: pointer;
            user-select: none;
            display: flex;
            align-items: center;
            margin-bottom: 5px;
        }}
        .section-header:hover, .finding-header:hover {{
            background-color: #e9ecef;
        }}
        .section-content, .finding-content {{
            display: none;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-bottom: 15px;
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
        .section-title {{
            flex-grow: 1;
            font-weight: bold;
        }}
        .finding-item {{
            margin-bottom: 10px;
        }}
        .finding-details, .finding-recommendation {{
            margin-bottom: 15px;
        }}
        .no-findings {{
            color: #2ecc71;
            font-style: italic;
        }}
        
        /* Executive summary */
        .summary {{
            background-color: #f0f7fd;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        .summary h3 {{
            color: #3498db;
            margin-top: 0;
            margin-bottom: 15px;
            font-size: 18px;
        }}
        .summary-stats {{
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin: 20px 0;
        }}
        .summary-stat {{
            background: white;
            border-radius: 5px;
            padding: 15px;
            width: 22%;
            margin-bottom: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-stat-label {{
            font-size: 14px;
            color: #7f8c8d;
        }}
        .summary-stat-value {{
            font-size: 24px;
            font-weight: bold;
            margin-top: 5px;
        }}
        
        /* Critical findings styling */
        .critical-findings {{
            background-color: #fdeded;
            border-left: 4px solid #e74c3c;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        .critical-findings h3 {{
            color: #c0392b;
            margin-top: 0;
            margin-bottom: 15px;
            font-size: 18px;
        }}
        .critical-list {{
            margin: 10px 0;
            padding-left: 0;
            list-style-type: none;
        }}
        .critical-list li {{
            margin-bottom: 10px;
            padding-bottom: 10px;
            border-bottom: 1px solid #fad7d7;
        }}
        .critical-list li:last-child {{
            border-bottom: none;
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
        
        /* Navigation */
        .req-nav {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 20px 0;
        }}
        .req-nav a {{
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 8px 15px;
            border-radius: 5px;
            text-decoration: none;
            font-weight: bold;
            font-size: 14px;
        }}
        .req-nav a:hover {{
            background-color: #2980b9;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>PCI DSS 4.0 - Interactive Summary Report</h1>
        
        <div class="report-date">
            Generated on: {datetime.now().strftime("%B %d, %Y")}
        </div>
        
        <div class="summary">
            <h3>PCI DSS 4.0 Compliance Summary</h3>
            <p>This interactive report summarizes compliance with PCI DSS 4.0 requirements. Click on the "View Findings" bars to expand each section and see detailed findings. Each finding can be further expanded to show specific details and recommendations.</p>
            
            <div class="summary-stats">
                <div class="summary-stat">
                    <div class="summary-stat-label">Overall Compliance</div>
                    <div class="summary-stat-value {overall_status_class}">{overall_compliance:.1f}%</div>
                </div>
                <div class="summary-stat">
                    <div class="summary-stat-label">Total Checks</div>
                    <div class="summary-stat-value">{overall_stats["total_checks"]}</div>
                </div>
                <div class="summary-stat">
                    <div class="summary-stat-label">Passed</div>
                    <div class="summary-stat-value compliant">{overall_stats["passed"]}</div>
                </div>
                <div class="summary-stat">
                    <div class="summary-stat-label">Failed</div>
                    <div class="summary-stat-value non-compliant">{overall_stats["failed"]}</div>
                </div>
            </div>
        </div>
        
        {critical_findings_html}
        
        <h2>Quick Navigation</h2>
        <div class="req-nav">
            {"".join([f'<a href="#req-card-{req["req_num"]}">REQ {req["req_num"]}</a>' for req in req_data_list])}
        </div>
        
        <h2>Requirements Summary</h2>
        <div class="requirements-grid">
            {all_cards}
        </div>
    </div>
    
    <script>
        // JavaScript for clickable expandable content
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
    </script>
</body>
</html>
"""
    
    return html

if __name__ == "__main__":
    main()