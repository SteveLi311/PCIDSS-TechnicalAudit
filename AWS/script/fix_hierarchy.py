#!/usr/bin/env python3

"""
Script to fix the PCI DSS 4.0 interactive summary report
Ensures requirements 3-10 appear as independent requirements 
at the same level as the others, not as children of requirement 2
"""

import re

def main():
    print("Fixing hierarchical issues in the interactive summary report...")
    
    # Read the current report
    with open('pci_dss_interactive_summary.html', 'r') as f:
        content = f.read()
    
    # Fix malformed table rows that cause nesting issues
    content = fix_nesting_issues(content)
    
    # Write the fixed content back
    with open('pci_dss_interactive_summary_fixed.html', 'w') as f:
        f.write(content)
    
    print("Fixed report created: pci_dss_interactive_summary_fixed.html")

def fix_nesting_issues(content):
    """Fix HTML nesting issues in the report"""
    
    # Fix 1: Correct malformed closing and opening TR tags
    content = re.sub(r'</tr>\s*<tr>', '</tr>\n<tr>', content)
    
    # Fix 2: Correct improper indentation that suggests hierarchy
    # Find the table body section
    tbody_match = re.search(r'<tbody>(.*?)</tbody>', content, re.DOTALL)
    if tbody_match:
        tbody_content = tbody_match.group(1)
        # Fix the indentation to make all requirements appear at the same level
        fixed_tbody_content = re.sub(r'\s+</tr><tr>', '</tr>\n        <tr>', tbody_content)
        # Replace the original tbody content with the fixed content
        content = content.replace(tbody_content, fixed_tbody_content)
    
    # Fix 3: Make sure all table rows have proper and consistent structure
    row_pattern = r'<tr[^>]*>(.*?)</tr>'
    rows = re.findall(row_pattern, content, re.DOTALL)
    
    # Check if we need to rebuild the table
    if len(rows) > 0:
        # This is a more aggressive fix that rebuilds the requirements table
        # Find the requirements table
        table_match = re.search(r'<table class="summary-table">(.*?)</table>', content, re.DOTALL)
        if table_match:
            table_content = table_match.group(1)
            # Extract the header row
            header_match = re.search(r'<thead>(.*?)</thead>', table_content, re.DOTALL)
            if header_match:
                header = header_match.group(1)
                # Extract all rows
                rows = re.findall(r'<tr[^>]*>(.*?)</tr>', table_content, re.DOTALL)
                # Remove the header row from the list if it's included
                if len(rows) > 0 and '<th>' in rows[0]:
                    rows = rows[1:]
                
                # Rebuild the table with proper structure
                new_tbody = "\n        <tbody>"
                for row in rows:
                    # Clean up any nested tr tags
                    cleaned_row = re.sub(r'</?tr[^>]*>', '', row)
                    new_tbody += f"\n            <tr>{cleaned_row}</tr>"
                new_tbody += "\n        </tbody>"
                
                # Create the new table
                new_table = f'<table class="summary-table">\n        {header}\n{new_tbody}\n    </table>'
                # Replace the old table
                content = content.replace(table_match.group(0), new_table)
    
    return content

if __name__ == "__main__":
    main()