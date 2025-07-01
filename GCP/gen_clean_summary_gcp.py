import os
from bs4 import BeautifulSoup
from pathlib import Path
from datetime import datetime, timezone
import re

REPORT_DIR = "reports"
OUTPUT_FILE = "reports/pci_dss_summary_clean_gcp.html"

TARGET_KEYWORDS = [
    "Security features for insecure services/protocols",
    "Inbound traffic to CDE restriction",
    "Outbound traffic from CDE restriction",
    "Private IP filtering",
    "Vendor default accounts analysis",
    "Key Management",
    "TLS/SSL Configuration Analysis",
    "Firewall Rules for Unencrypted Protocols",
    "Project owner role assignment",
    "Identity-Aware Proxy MFA",
    "Storage public access",
    "Cloud Logging enabled"
]

def extract_metadata():
    for filename in sorted(os.listdir(REPORT_DIR)):
        if filename.startswith("pci_req1") and filename.endswith(".html"):
            filepath = os.path.join(REPORT_DIR, filename)
            with open(filepath, "r", encoding="utf-8") as file:
                soup = BeautifulSoup(file, "html.parser")
                gcp_account = soup.select_one('tr:has(th:-soup-contains("GCP Account")) td')
                project = soup.select_one('tr:has(th:-soup-contains("Project")) td')
                date_str = datetime.now().strftime("%a %b %d %H:%M:%S CST %Y")
                return f'''
                <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                  <tr><td style="background: #f2f2f2; padding: 8px; font-weight: bold; width: 220px;">Assessment Date</td><td style="padding: 8px;">{date_str}</td></tr>
                  <tr><td style="background: #f2f2f2; padding: 8px; font-weight: bold;">GCP Account</td><td style="padding: 8px;">{gcp_account.text.strip() if gcp_account else 'N/A'}</td></tr>
                  <tr><td style="background: #f2f2f2; padding: 8px; font-weight: bold;">Project</td><td style="padding: 8px;">{project.text.strip() if project else 'N/A'}</td></tr>
                </table>
                '''
    return ""

def extract_status_class(classes):
    for status in ["pass", "fail", "warning", "info"]:
        if status in classes:
            return status
    return "unknown"

def extract_findings_by_keywords():
    findings_by_keyword = {kw: [] for kw in TARGET_KEYWORDS}
    for filename in sorted(os.listdir(REPORT_DIR)):
        if not (filename.startswith("pci_req") and filename.endswith(".html")):
            continue
        filepath = os.path.join(REPORT_DIR, filename)
        with open(filepath, "r", encoding="utf-8") as file:
            soup = BeautifulSoup(file, "html.parser")
            for section in soup.find_all("div", class_=lambda c: c and "check-item" in c):
                label = section.select_one("strong")
                label_text = label.get_text(strip=True) if label else ""
                for kw in TARGET_KEYWORDS:
                    if kw.lower() in label_text.lower():
                        header_span = section.select_one("strong + span")
                        if header_span and header_span.get("class", [])[0] in ["pass", "fail", "warning", "info"]:
                            header_span.decompose()
                        inner_html = section.decode_contents()
                        inner_html = inner_html.replace('class="warning"', 'class="text-warning"')
                        inner_html = inner_html.replace('class="fail"', 'class="text-fail"')
                        inner_html = inner_html.replace('class="pass"', 'class="text-pass"')
                        inner_html = inner_html.replace('class="info"', 'class="text-info"')
                        findings_by_keyword[kw].append({
                            "text": label_text,
                            "file": filename,
                            "html": inner_html,
                            "status": extract_status_class(section.get("class", []))
                        })
    return findings_by_keyword

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

        .red {{ color: #f44336; font-weight: bold; }}
        .green {{ color: #4CAF50; font-weight: bold; }}
        .yellow {{ color: #ff9800; font-weight: bold; }}
        .blue {{ color: #2196F3; font-weight: bold; }}
        .text-warning {{ color: #ff9800; font-weight: bold; }}
        .text-fail {{ color: #f44336; font-weight: bold; }}
        .text-pass {{ color: #4CAF50; font-weight: bold; }}
        .text-info {{ color: #2196F3; font-weight: bold; }}
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
        <h1>PCI DSS GCP Assessment Summary</h1>
        {metadata_html}
        <br/>
"""

    for kw, findings in findings_by_keyword.items():
        if not findings:
            continue
        status_label = findings[0]['status']
        html += f'<div class="section">\n'
        html += f'<div class="section-header" onclick="toggleSection(this)">{kw}<span class="status-badge status-{status_label}">{status_label.upper()}</span></div>\n'
        html += f'<div class="section-content">\n'
        for finding in findings:
            html += f'<span class="file-label">{finding["file"]}</span>'
            html += f'<div class="check-item {finding["status"]}">{finding["html"]}</div>\n'
        html += '</div></div>\n'

    html += f'<div class="timestamp">Report generated on: {now}</div>\n'
    html += '</div></body></html>'

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

if __name__ == "__main__":
    findings = extract_findings_by_keywords()
    generate_html_report(findings, OUTPUT_FILE)
    print(f"✅ GCP Report saved to: {OUTPUT_FILE}")