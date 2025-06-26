#!/usr/bin/env python3

"""
Fix for PCI DSS 4.0 Card-Based Summary Report
This script fixes the hierarchical structure issue in the card-based report
while maintaining its visual design.
"""

import os
import re
import glob
from datetime import datetime
import sys

def main():
    print("Fixing the card-based PCI DSS 4.0 summary report...")
    
    # Output file
    summary_report = "pci_dss_card_fixed.html"
    
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
            
            # Extract basic info
            title = extract_title(content, req_num)
            findings = extract_findings(content)
            
            req_data_list.append({
                "req_num": req_num,
                "title": title,
                "findings": findings
            })
    
    # Sort requirements by number
    req_data_list.sort(key=lambda x: int(x["req_num"]))
    
    # Generate the HTML report
    html_content = generate_fixed_card_html(req_data_list)
    
    # Write the report to file
    with open(summary_report, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"Fixed card-based summary report created successfully: {summary_report}")

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

def extract_findings(content):
    """Extract findings from content"""
    findings = []
    
    # Look for [FAIL] patterns
    fail_matches = re.findall(r'<span class="red">\[FAIL\]</span>(.*?)</h3>', content, re.DOTALL)
    for match in fail_matches:
        finding = match.strip()
        finding = re.sub(r'<[^>]+>', '', finding)
        findings.append({
            "title": finding,
            "details": "Click to see details in full report"
        })
    
    # Alternative approach: look for check-item fail divs
    if not findings:
        fail_blocks = re.findall(r'<div class="check-item fail">(.*?)</div>\s*</div>', content, re.DOTALL)
        for block in fail_blocks:
            title_match = re.search(r'<h3.*?>(.*?)</h3>', block, re.DOTALL)
            if title_match:
                title = re.sub(r'<[^>]+>', '', title_match.group(1)).strip()
                findings.append({
                    "title": title,
                    "details": "Click to see details in full report"
                })
    
    return findings

def generate_fixed_card_html(req_data_list):
    """Generate the HTML with fixed card-based layout"""
    
    # Generate card items individually
    card_items = []
    for req_data in req_data_list:
        req_num = req_data["req_num"]
        title = req_data["title"]
        findings = req_data["findings"]
        
        # Create findings list
        findings_html = ""
        if findings:
            findings_html = "<ul class='findings-list'>"
            for finding in findings[:3]:  # Show top 3 findings
                findings_html += f"<li>{finding['title']}</li>"
            
            if len(findings) > 3:
                findings_html += f"<li>...plus {len(findings) - 3} more findings</li>"
            
            findings_html += "</ul>"
        else:
            findings_html = "<p>No findings for this requirement</p>"
        
        # Create the card item
        card = f"""
        <div class="req-card">
            <div class="req-card-header">
                <span class="req-badge">REQ {req_num}</span>
                <h3 class="req-title">{title}</h3>
            </div>
            <div class="req-card-body">
                <h4>Key Findings:</h4>
                {findings_html}
                <div class="view-more">
                    <a href="javascript:void(0)" onclick="alert('Full report for Requirement {req_num} would open here')">View Full Report</a>
                </div>
            </div>
        </div>
        """
        card_items.append(card)
    
    # Join all card items
    all_cards = "\n".join(card_items)
    
    # Create the full HTML using CSS Grid for the layout
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCI DSS 4.0 - Card-Based Summary Report (Fixed)</title>
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
            flex-grow: 1;
        }}
        h4 {{
            color: #3498db;
            margin: 15px 0 10px 0;
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
        .findings-list {{
            margin: 10px 0;
            padding-left: 20px;
            flex-grow: 1;
        }}
        .findings-list li {{
            margin-bottom: 8px;
        }}
        .view-more {{
            margin-top: 15px;
            text-align: right;
        }}
        .view-more a {{
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 8px 15px;
            border-radius: 5px;
            text-decoration: none;
            font-size: 14px;
        }}
        .view-more a:hover {{
            background-color: #2980b9;
        }}
        
        /* Critical findings summary */
        .critical-summary {{
            background-color: #fdeded;
            border-left: 4px solid #e74c3c;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        .critical-summary h3 {{
            color: #c0392b;
            margin-top: 0;
        }}
        
        /* Requirements nav */
        .req-nav {{
            background-color: #f8f9fa;
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
            border-left: 4px solid #3498db;
        }}
        .req-nav h3 {{
            margin-top: 0;
            color: #3498db;
            margin-bottom: 15px;
        }}
        .req-nav-list {{
            display: flex;
            flex-wrap: wrap;
            list-style-type: none;
            padding: 0;
            margin: 0;
        }}
        .req-nav-item {{
            margin-right: 10px;
            margin-bottom: 10px;
        }}
        .req-nav-link {{
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 8px 15px;
            border-radius: 5px;
            text-decoration: none;
            font-weight: bold;
        }}
        .req-nav-link:hover {{
            background-color: #2980b9;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>PCI DSS 4.0 - Summary Report</h1>
        
        <div class="report-date">
            Generated on: {datetime.now().strftime("%B %d, %Y")}
        </div>
        
        <div class="critical-summary">
            <h3>PCI DSS 4.0 Compliance Summary</h3>
            <p>This report highlights key findings from the PCI DSS 4.0 compliance assessment. Each requirement is shown as a separate card below with its findings. Click "View Full Report" on any requirement to see detailed information.</p>
        </div>
        
        <div class="req-nav">
            <h3>Quick Navigation</h3>
            <ul class="req-nav-list">
                {" ".join([f'<li class="req-nav-item"><a class="req-nav-link" href="#" onclick="alert(\'Requirement {req["req_num"]} details would open here\')">REQ {req["req_num"]}</a></li>' for req in req_data_list])}
            </ul>
        </div>
        
        <h2>Requirements Summary</h2>
        
        <div class="requirements-grid">
            {all_cards}
        </div>
    </div>
</body>
</html>
"""
    
    return html

if __name__ == "__main__":
    main()