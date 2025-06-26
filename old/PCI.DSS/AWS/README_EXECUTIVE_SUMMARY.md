# PCI DSS Executive Summary Generator

## Overview

The PCI DSS Executive Summary Generator is a tool that consolidates individual PCI DSS requirement reports into a comprehensive executive summary. This summary provides a high-level view of your AWS environment's compliance status across all PCI DSS requirements.

## Features

- **Consolidated View**: Combines all 12 PCI DSS requirement reports into a single dashboard
- **Compliance Statistics**: Shows pass/fail metrics for each requirement and overall compliance
- **High Priority Findings**: Lists critical compliance issues that need immediate attention
- **Visual Indicators**: Progress bars and charts to quickly assess compliance status
- **Executive Recommendations**: Actionable recommendations based on findings
- **Detailed Drilldown**: Links to individual requirement reports for detailed information

## Usage

Run the executive summary generator after completing individual PCI DSS requirement assessments:

```bash
./generate_executive_summary.sh
```

The script will:
1. Process all existing PCI DSS reports in the `./reports` directory
2. Extract requirement numbers, statistics, and findings
3. Generate a consolidated HTML report with a timestamp in the filename
4. Automatically open the report (on macOS) when complete

## Report Structure

The executive summary report contains the following sections:

1. **Account Information**: AWS account details and assessment metadata
2. **Compliance Summary**: Overall compliance statistics and charts
3. **Requirement Breakdown**: Status of each PCI DSS requirement
4. **High Priority Findings**: Critical compliance failures listed in one place
5. **Executive Recommendations**: Actionable next steps based on findings

## Requirement Integration

The tool automatically detects reports for all 12 PCI DSS requirements:

1. Install and Maintain Network Security Controls
2. Apply Secure Configurations
3. Protect Stored Account Data
4. Protect Cardholder Data with Strong Cryptography
5. Protect Systems from Malware
6. Develop and Maintain Secure Systems
7. Restrict Access to Cardholder Data
8. Identify Users and Authenticate Access
9. Restrict Physical Access
10. Log and Monitor All Access
11. Test Security Systems and Processes
12. Support Information Security with Policies

## Customization

You can customize the executive summary by modifying the following:

- **CSS Styles**: Update the CSS in the script to change the report appearance
- **Charts**: Modify the JavaScript functions to change chart appearance
- **Recommendations**: Edit the case statement to provide custom recommendations for each requirement

## Dependencies

- Bash shell
- Standard Unix utilities (grep, sed, awk)
- Individual PCI DSS requirement reports
- PCI HTML report library (pci_html_report_lib.sh)

## File Naming Conventions

The script processes files matching these patterns:
- `pci_req{N}_report_*.html`
- `pci_requirement{N}_report_*.html`

Where `{N}` is the requirement number (1-12).

## Example Output

```
Processing PCI DSS compliance reports...
Processing Requirement 1 report: ./reports/pci_req1_report_20250408_160818.html
Processing Requirement 2 report: ./reports/pci_req2_report_20250408_162427.html
...
Processing Requirement 12 report: ./reports/pci_req12_report_20250409_055954.html
Executive summary report created: ./reports/pci_executive_summary_20250409_084900.html
```