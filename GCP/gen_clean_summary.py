import os
from bs4 import BeautifulSoup, Tag
from pathlib import Path
import re

report_dir = "reports"
output_file = "pci_dss_summary_clean.html"

included_titles = [
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

html = '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Filtered PCI DSS Summary</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; background-color: #f5f5f5; padding: 20px; color: #333; }
    .container { max-width: 1200px; margin: auto; background: #fff; padding: 30px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
    h1 { border-bottom: 2px solid #4285f4; padding-bottom: 10px; }
    .section { margin-bottom: 30px; border: 1px solid #ddd; border-radius: 5px; }
    .section-header { background: #f8f9fa; padding: 15px 20px; }
    .section-content { padding: 20px; }
    .check-item { border-left: 4px solid #ccc; background: #f9f9f9; padding: 10px; margin: 10px 0; }
    .fail { color: #f44336; font-weight: bold; border-left-color: #f44336; }
    .warning { color: #ff9800; font-weight: bold; border-left-color: #ff9800; }
    .pass { color: #4caf50; font-weight: bold; border-left-color: #4caf50; }
    .info { color: #2196F3; font-weight: bold; border-left-color: #2196F3; }
    a { color: #1565c0; }
    details summary { cursor: pointer; font-weight: bold; background: #f0f0f0; padding: 5px; border-radius: 4px; }
    pre, .pre-wrap { white-space: pre-wrap; background: #fff; padding: 10px; border-radius: 4px; line-height: 1.4; border: 1px solid #ddd; font-family: monospace; }
    .red { color: #f44336; font-weight: bold; }
    .green { color: #4caf50; font-weight: bold; }
    .yellow { color: #ff9800; font-weight: bold; }
    .blue { color: #2196F3; font-weight: bold; }
    .gray { color: #333; font-weight: bold; }
    .bold { color: #333; font-weight: bold; }
  </style>
</head>
<body>
  <div class="container">
    <h1>PCI DSS GCP Assessment Summary (Selected Items)</h1>

'''

def get_req_number(f):
    match = re.search(r"req(\d+)", f.name)
    return int(match.group(1)) if match else 999

files = sorted(Path(report_dir).glob("pci_req*.html"), key=get_req_number)

# 提取全域資訊
first_file = files[0] if files else None
if first_file:
    soup = BeautifulSoup(first_file.read_text(encoding='utf-8', errors='ignore'), 'html.parser')
    from datetime import datetime
    date_str = datetime.now().strftime("%a %b %d %H:%M:%S CST %Y")
    gcp_account = soup.select_one('tr:has(th:-soup-contains("GCP Account")) td')
    project = soup.select_one('tr:has(th:-soup-contains("Project")) td')
    html += f'''
    <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
      <tr><td style="background: #f2f2f2; padding: 8px; font-weight: bold; width: 220px;">Assessment Date</td><td style="padding: 8px;">{date_str}</td></tr>
      <tr><td style="background: #f2f2f2; padding: 8px; font-weight: bold;">GCP Account</td><td style="padding: 8px;">{gcp_account.text.strip() if gcp_account else 'N/A'}</td></tr>
      <tr><td style="background: #f2f2f2; padding: 8px; font-weight: bold;">Project</td><td style="padding: 8px;">{project.text.strip() if project else 'N/A'}</td></tr>
    </table>
    '''

for file in files:
    soup = BeautifulSoup(file.read_text(encoding='utf-8', errors='ignore'), 'html.parser')
    match = re.search(r"req(\d+)", file.name)
    req = match.group(1) if match else "?"
    title = soup.title.text if soup.title else "Untitled"
    compliance_tag = soup.select_one(".progress-bar")
    compliance = compliance_tag.text.strip() if compliance_tag else "N/A"

    section_html = f'''
    <div class="section" id="section-req{req}">
      <div class="section-header">
        <h3>Requirement {req} — {compliance}</h3>
      </div>
      <div class="section-content">
        <p><strong>{title}</strong></p>
        <p>🔗 <a href="{file}" target="_blank">View full report: {file.name}</a></p>
    '''

    block_count = 0
    for block in soup.select("div.check-item"):
        label = block.select_one("strong")
        label_text = label.get_text(strip=True) if label else "UNTITLED"
        label_content = re.sub(r"^[^\w]+", "", label_text).lower()
        if not any(sel.lower() in label_content for sel in included_titles):
            continue

        classes = block.get("class", [])
        if "info" in classes:
            label_class = "info"
        elif "warning" in classes:
            label_class = "warning"
        elif "pass" in classes:
            label_class = "pass"
        else:
            label_class = "fail"

        pre_tag = block.select_one("details pre")
        if pre_tag:
            for tag in pre_tag(["script", "style"]):
                tag.decompose()
            for span in pre_tag.find_all("span"):
                if 'class' in span.attrs:
                    continue  # 保留原始 class，不自動加入 gray
            from bs4 import NavigableString

            # 補上沒有標記的純文字項目為 gray
            
            
            

            detail = f"<div class='pre-wrap'>{pre_tag.decode_contents()}</div>"
        else:
            detail = "⚠ No detail found."

        section_html += (
            f"<div class='check-item'>"  # 不套用狀態色彩 class
            f"<div style='display: flex; justify-content: space-between; align-items: center;'>"
            f"<strong>{label_text}</strong> <span class='{label_class}' style='margin-left: 10px;'>{label_class.upper()}</span>"
            f"</div>"
            f"<details style='margin-top: 10px;'>"
            f"<summary>Show Details</summary>"
            f"<div>{detail}</div>"
            f"</details>"
            f"</div>"
        )
        block_count += 1

    section_html += "</div></div>"

    if block_count > 0:
        html += section_html

html += "</div></body></html>"

Path(output_file).write_text(html, encoding='utf-8')
print("✅ Clean summary with accurate status written to:", output_file)

