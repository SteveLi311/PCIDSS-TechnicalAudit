from bs4 import BeautifulSoup
import os
from datetime import datetime, timezone
import re

REPORT_DIR = "./reports"  # Update this path as needed
TARGET_KEYWORDS = [
    "1.2.3 - Network Peering Connections",
    "1.2.6 - Security features for insecure services/protocols",
    "1.3.1 - Inbound traffic to CDE restriction",
    "1.3.2 - Outbound traffic from CDE restriction",
    "1.4.1 - NSCs between trusted and untrusted networks",
    "1.4.3 - Anti-spoofing measures",
    "1.4.4 - RDS Public Access",
    "1.4.4 - S3 Public Access",
    "2.2.1 - RDS Encryption",
    "2.2.1 - S3 Encryption",
    "3.6 - Key Management",
    "4.2.1 - TLS Implementation",
    "6.3.1 - Vulnerability scanning with AWS Inspector",
    "6.3.2 - Container image vulnerability scanning",
    "6.4.2 - Web application firewall implementation",
    "6.5.4 - Role separation",
    "7.3.2 - Access Control System Configuration (Direct Policies)",
    "8.3.6 - Password/Passphrase Requirements",
    "8.4.2 - Multi-Factor Authentication",
    "8.6.1-3 - Review User Access",
    "10.1.1 - Implementation of audit trails",
    "10.4.1-10.4.3 - Log review and monitoring process",
    "10.5.1 - CloudWatch Log Groups",
    "11.3.1 - Internal Vulnerability Scanning",
    "11.5.1 - Intrusion Detection Systems",
]

def extract_metadata():
    now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")
    for filename in sorted(os.listdir(REPORT_DIR)):
        if filename.startswith("pci_req1") and filename.endswith(".html"):
            filepath = os.path.join(REPORT_DIR, filename)
            with open(filepath, "r", encoding="utf-8") as file:
                soup = BeautifulSoup(file, "html.parser")
                metadata_table = soup.find("table")
                if metadata_table:
                    for row in metadata_table.find_all("tr"):
                        cells = row.find_all("td")
                        # 使用原始報告內的 Assessment Date，不進行覆蓋
                    return str(metadata_table)
    return ""
    return ""

def extract_findings_by_keywords():
    findings_by_keyword = {kw: [] for kw in TARGET_KEYWORDS}
    for filename in sorted(os.listdir(REPORT_DIR)):
        if not (filename.startswith("pci_req") and filename.endswith(".html")):
            continue
        filepath = os.path.join(REPORT_DIR, filename)
        with open(filepath, "r", encoding="utf-8") as file:
            soup = BeautifulSoup(file, "html.parser")
            for section in soup.find_all("div", class_=lambda c: c and "check-item" in c):
                for label in section.find_all(string=re.compile(r"\[(PASS|FAIL|WARNING|INFO)\]")):
                    span = soup.new_tag("span", **{"class": "status-label"})
                    span.string = label
                    label.replace_with(span)
                text_content = section.get_text(strip=True)
                for kw in TARGET_KEYWORDS:
                    if kw in text_content:
                        findings_by_keyword[kw].append({
                            "text": text_content,
                            "file": filename,
                            "html": str(section),
                            "status": extract_status_class(section.get("class", []))
                        })
    return findings_by_keyword

def extract_status_class(class_list):
    for status in ["pass", "fail", "warning", "info"]:
        if status in class_list:
            return status
    return "unknown"

def generate_html_report(findings_by_keyword, output_file):
    now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")
    metadata_html = extract_metadata()
    html = f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>PCI DSS 4.0 - Summary</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #fff; padding: 30px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); border-radius: 5px; }}
        h1 {{ border-bottom: 2px solid #4285f4; padding-bottom: 10px; }}
        .section {{ margin-bottom: 30px; border: 1px solid #ddd; border-radius: 5px; overflow: hidden; }}
        .section-header {{ background-color: #f0f0f0; padding: 10px 15px; cursor: pointer; font-weight: bold; display: flex; justify-content: space-between; align-items: center; }}
        .status-badge {{ font-weight: bold; padding: 2px 10px; border-radius: 4px; }}
        .status-pass {{ color: #4CAF50; }}
        .status-fail {{ color: #f44336; }}
        .status-warning {{ color: #ff9800; }}
        .status-info {{ color: #2196F3; }}
        .section-content {{ padding: 15px; display: none; }}
        .active + .section-content {{ display: block; }}
        .file-label {{ font-style: italic; color: #555; margin-bottom: 5px; display: block; }}
        .timestamp {{ text-align: right; font-style: italic; color: #888; margin-top: 20px; }}

        .check-item {{ padding: 10px; margin-bottom: 10px; border-left: 4px solid #ccc; background-color: #f9f9f9; }}
        .check-item.pass {{ border-left-color: #4CAF50; }}
        .check-item.fail {{ border-left-color: #f44336; }}
        .check-item.warning {{ border-left-color: #ff9800; }}
        .check-item.info {{ border-left-color: #2196F3; }}

        .status-label {{ font-weight: bold; }}
        .check-item.pass .status-label {{ color: #4CAF50; }}
        .check-item.fail .status-label {{ color: #f44336; }}
        .check-item.warning .status-label {{ color: #ff9800; }}
        .check-item.info .status-label {{ color: #2196F3; }}

        .red {{ color: #f44336; font-weight: bold; }}
        .green {{ color: #4CAF50; font-weight: bold; }}
        .yellow {{ color: #ff9800; font-weight: bold; }}
        .blue {{ color: #2196F3; font-weight: bold; }}
        .note {{ color: #ff9800; font-style: italic; }}
        .recommendation {{ background-color: #e3f2fd; padding: 10px; border-left: 4px solid #03A9F4; }}

        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
    <script>
        function toggleSection(el) {{
            el.classList.toggle('active');
            var next = el.nextElementSibling;
            if (next) next.style.display = next.style.display === 'block' ? 'none' : 'block';
        }}
    </script>
</head>
<body>
    <div class=\"container\">
        <h1>PCI DSS AWS Assessment Summary</h1>
        {metadata_html}
        <br/>
"""

    for kw, findings in findings_by_keyword.items():
        status_label = "unknown"
        if findings:
            status_label = findings[0]['status']
        html += f'<div class="section">\n'
        html += f'<div class="section-header" onclick="toggleSection(this)">{kw}<span class="status-badge status-{status_label}">{status_label.upper()}</span></div>\n'
        html += f'<div class="section-content">\n'
        if findings:
            for finding in findings:
                html += f'<span class="file-label">{finding["file"]}</span>'
                html += finding["html"] + '\n'
        else:
            html += '<p>No findings for this keyword.</p>\n'
        html += '</div></div>\n'

    html += f'<div class="timestamp">Report generated on: {now}</div>\n'
    html += '</div></body></html>'

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

if __name__ == "__main__":
    findings = extract_findings_by_keywords()
    output_path = "./reports/pci_dss_summary_clean_aws.html"
    generate_html_report(findings, output_path)
    print(f"Report saved to: {output_path}")
