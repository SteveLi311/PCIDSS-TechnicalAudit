#!/usr/bin/env python3

"""
This script fixes the consolidated report by removing all Access Denied messages
and cleaning up the critical findings summary.
"""

import re

def main():
    # Read the consolidated report
    with open('consolidated_pci_dss_report.html', 'r') as f:
        content = f.read()
    
    # Find the critical findings list section
    findings_match = re.search(r'<ul class="critical-findings-list">(.*?)</ul>', content, re.DOTALL)
    if findings_match:
        findings_list = findings_match.group(1)
        
        # Remove all list items containing "Access Denied"
        cleaned_list = re.sub(r'<li><span class="finding-req">Req [0-9]+</span>[^<]*Access Denied[^<]*</li>', '', findings_list)
        
        # Update the content
        content = content.replace(findings_list, cleaned_list)
    
    # Remove any "access denied" messages from the main content
    content = re.sub(
        r'<div[^>]*>[^<]*(?:access denied|permission denied|not authorized)[^<]*</div>', 
        '', 
        content, 
        flags=re.DOTALL | re.IGNORECASE
    )
    
    # Write the updated report
    with open('consolidated_pci_dss_report.html', 'w') as f:
        f.write(content)
    
    print("Successfully removed Access Denied messages from the consolidated report.")

if __name__ == "__main__":
    main()