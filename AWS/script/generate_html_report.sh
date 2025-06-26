#!/usr/bin/env bash

# PCI DSS v4.0 HTML Report Generator
# This script generates an HTML report from the text-based audit results

# Set variables
REPORT_DIR="pci_audit_results"
LATEST_REPORT=$(ls -t "$REPORT_DIR"/pci_dss_v4_audit_report_*.txt 2>/dev/null | head -1)
HTML_REPORT="$REPORT_DIR/pci_dss_v4_compliance_report.html"

# Check if the report exists
if [[ ! -f "$LATEST_REPORT" ]]; then
  echo "Error: No audit report found in $REPORT_DIR directory."
  echo "Please run the PCI DSS v4.0 audit script first."
  exit 1
fi

# Extract report date from the latest report filename
REPORT_DATE=$(basename "$LATEST_REPORT" | sed 's/pci_dss_v4_audit_report_\([0-9]*\)_\([0-9]*\).txt/\1 \2/' | sed 's/\([0-9]\{4\}\)\([0-9]\{2\}\)\([0-9]\{2\}\) \([0-9]\{2\}\)\([0-9]\{2\}\)\([0-9]\{2\}\)/\1-\2-\3 \4:\5:\6/')

# Extract AWS account ID from the report
AWS_ACCOUNT=$(grep "AWS Account:" "$LATEST_REPORT" | cut -d':' -f2 | tr -d ' ')

# Extract regions being checked
REGIONS_CHECKED=$(grep "Checking:" "$LATEST_REPORT" | cut -d':' -f2)

# Parse compliance results
REQ1_STATUS=$(grep -A3 "1.i Checking for security groups" "$LATEST_REPORT" | grep -E 'PASS|FAIL' | head -1)
REQ1_2_STATUS=$(grep -A3 "1.ii Checking for protocols with unrestricted" "$LATEST_REPORT" | grep -E 'PASS|FAIL' | head -1)
REQ3_STATUS=$(grep -A3 "3.i Checking for KMS keys" "$LATEST_REPORT" | grep -E 'PASS|FAIL' | head -1)
REQ3_2_STATUS=$(grep -A3 "3.ii Checking for secrets" "$LATEST_REPORT" | grep -E 'PASS|FAIL' | head -1)
REQ4_STATUS=$(grep -A3 "4.i Checking for load balancers using TLS" "$LATEST_REPORT" | grep -E 'PASS|FAIL' | head -1)
REQ4_2_STATUS=$(grep -A3 "4.ii Checking for load balancers using weak ciphers" "$LATEST_REPORT" | grep -E 'PASS|FAIL' | head -1)
REQ8_STATUS=$(grep -A3 "8.i Checking IAM password" "$LATEST_REPORT" | grep -E 'PASS|FAIL' | head -1)
REQ8_2_STATUS=$(grep -A3 "8.ii Checking for IAM users" "$LATEST_REPORT" | grep -E 'PASS|FAIL' | head -1)
REQ10_STATUS=$(grep -A3 "10.i Checking for log buckets" "$LATEST_REPORT" | grep -E 'PASS|FAIL' | head -1)

# Determine overall status for each requirement
determine_req_status() {
  local status1="$1"
  local status2="$2"
  
  if [[ "$status1" == *"FAIL"* || "$status2" == *"FAIL"* ]]; then
    echo "fail"
  else
    echo "pass"
  fi
}

REQ1_OVERALL=$(determine_req_status "$REQ1_STATUS" "$REQ1_2_STATUS")
REQ3_OVERALL=$(determine_req_status "$REQ3_STATUS" "$REQ3_2_STATUS")
REQ4_OVERALL=$(determine_req_status "$REQ4_STATUS" "$REQ4_2_STATUS")
REQ8_OVERALL=$(determine_req_status "$REQ8_STATUS" "$REQ8_2_STATUS")
REQ10_OVERALL="pass"
if [[ "$REQ10_STATUS" == *"FAIL"* ]]; then
  REQ10_OVERALL="fail"
fi

# Helper function to format status with colors
format_status() {
  local status_line="$1"
  local detail="$2"
  
  if [[ "$status_line" == *"PASS"* ]]; then
    echo "<div class='status-pass'>✓ PASS: $detail</div>"
  elif [[ "$status_line" == *"FAIL"* ]]; then
    # Extract the failure count if available
    local count=$(echo "$status_line" | grep -o 'Found [0-9]* ' | grep -o '[0-9]*' || echo "Some")
    echo "<div class='status-fail'>✗ FAIL: Found $count non-compliant $detail</div>"
  else
    echo "<div class='status-unknown'>? UNKNOWN: $detail</div>"
  fi
}

# Create HTML content
cat > "$HTML_REPORT" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PCI DSS v4.0 Compliance Report</title>
  <style>
    :root {
      --primary-color: #1a56db;
      --primary-light: #e1effe;
      --success-color: #046c4e;
      --success-light: #def7ec;
      --danger-color: #c81e1e;
      --danger-light: #fde8e8;
      --warning-color: #c27803;
      --warning-light: #fdf6b2;
      --dark-color: #111827;
      --gray-color: #6b7280;
      --light-color: #f3f4f6;
    }
    
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      line-height: 1.5;
      color: var(--dark-color);
      margin: 0;
      padding: 0;
      background-color: #f9fafb;
    }
    
    header {
      background-color: var(--primary-color);
      color: white;
      padding: 1rem 2rem;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      position: sticky;
      top: 0;
      z-index: 10;
    }
    
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 1rem;
    }
    
    .summary-info {
      background-color: white;
      border-radius: 0.5rem;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    
    .dashboard {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    
    .dashboard-card {
      background-color: white;
      border-radius: 0.5rem;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
      padding: 1.5rem;
      transition: transform 0.2s;
      cursor: pointer;
    }
    
    .dashboard-card:hover {
      transform: translateY(-5px);
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    .dashboard-card h3 {
      margin-top: 0;
      font-size: 1.1rem;
      display: flex;
      align-items: center;
    }
    
    .dashboard-card.pass {
      border-left: 4px solid var(--success-color);
    }
    
    .dashboard-card.fail {
      border-left: 4px solid var(--danger-color);
    }
    
    .status-icon {
      display: inline-block;
      width: 24px;
      height: 24px;
      border-radius: 50%;
      margin-right: 0.5rem;
      font-weight: bold;
      text-align: center;
      line-height: 24px;
    }
    
    .status-icon.pass {
      background-color: var(--success-light);
      color: var(--success-color);
    }
    
    .status-icon.fail {
      background-color: var(--danger-light);
      color: var(--danger-color);
    }
    
    .requirement-section {
      background-color: white;
      border-radius: 0.5rem;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    
    .requirement-section h2 {
      margin-top: 0;
      color: var(--primary-color);
      border-bottom: 1px solid var(--light-color);
      padding-bottom: 0.5rem;
    }
    
    .requirement-item {
      margin-bottom: 1.5rem;
    }
    
    .requirement-item h3 {
      display: flex;
      align-items: center;
      margin-bottom: 0.5rem;
    }
    
    .status-pass {
      background-color: var(--success-light);
      color: var(--success-color);
      padding: 0.5rem 1rem;
      border-radius: 0.25rem;
      margin-bottom: 1rem;
      font-weight: 500;
    }
    
    .status-fail {
      background-color: var(--danger-light);
      color: var(--danger-color);
      padding: 0.5rem 1rem;
      border-radius: 0.25rem;
      margin-bottom: 1rem;
      font-weight: 500;
    }
    
    .status-unknown {
      background-color: var(--warning-light);
      color: var(--warning-color);
      padding: 0.5rem 1rem;
      border-radius: 0.25rem;
      margin-bottom: 1rem;
      font-weight: 500;
    }
    
    .details-card {
      border: 1px solid var(--light-color);
      border-radius: 0.25rem;
      padding: 1rem;
      margin-top: 1rem;
    }
    
    .details-card h4 {
      margin-top: 0;
      color: var(--gray-color);
      font-size: 0.9rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    
    .details-card pre {
      background-color: var(--light-color);
      padding: 1rem;
      border-radius: 0.25rem;
      overflow-x: auto;
      font-size: 0.9rem;
    }
    
    .collapsible {
      display: none;
    }
    
    .toggle-btn {
      background-color: var(--light-color);
      border: none;
      padding: 0.5rem 1rem;
      border-radius: 0.25rem;
      cursor: pointer;
      font-size: 0.9rem;
      font-weight: 500;
      color: var(--gray-color);
      margin-top: 0.5rem;
    }
    
    .toggle-btn:hover {
      background-color: #e5e7eb;
    }
    
    footer {
      text-align: center;
      padding: 1rem;
      color: var(--gray-color);
      font-size: 0.9rem;
      margin-top: 2rem;
    }
    
    /* Navigation */
    nav {
      position: sticky;
      top: 4rem;
      background-color: white;
      padding: 0.5rem 0;
      border-bottom: 1px solid var(--light-color);
      z-index: 9;
    }
    
    .nav-container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 1rem;
      display: flex;
      overflow-x: auto;
      white-space: nowrap;
      scrollbar-width: thin;
    }
    
    .nav-container::-webkit-scrollbar {
      height: 4px;
    }
    
    .nav-container::-webkit-scrollbar-thumb {
      background-color: var(--gray-color);
      border-radius: 2px;
    }
    
    .nav-link {
      padding: 0.5rem 1rem;
      margin-right: 0.5rem;
      color: var(--gray-color);
      text-decoration: none;
      border-radius: 0.25rem;
      font-weight: 500;
    }
    
    .nav-link:hover {
      background-color: var(--light-color);
    }
    
    .nav-link.active {
      color: var(--primary-color);
      border-bottom: 2px solid var(--primary-color);
    }

    /* Findings Table */
    .findings-table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 1rem;
      font-size: 0.9rem;
      border: 1px solid #eee;
    }
    
    .findings-table th {
      background-color: var(--light-color);
      padding: 0.75rem;
      text-align: left;
      border-bottom: 2px solid #ddd;
    }
    
    .findings-table td {
      padding: 0.75rem;
      border-bottom: 1px solid #eee;
      vertical-align: top;
    }
    
    .findings-table tr:hover {
      background-color: #f9fafb;
    }
    
    .findings-table tr:last-child td {
      border-bottom: none;
    }
    
    @media (max-width: 768px) {
      .dashboard {
        grid-template-columns: 1fr;
      }
      
      header {
        padding: 1rem;
      }
      
      .container {
        padding: 1rem 0.5rem;
      }
      
      .requirement-section {
        padding: 1rem;
      }
    }
  </style>
</head>
<body>
  <header>
    <h1>PCI DSS v4.0 Compliance Report</h1>
  </header>
  
  <nav>
    <div class="nav-container">
      <a href="#summary" class="nav-link active">Summary</a>
      <a href="#req1" class="nav-link">Req 1: Network Security</a>
      <a href="#req3" class="nav-link">Req 3: Key Management</a>
      <a href="#req4" class="nav-link">Req 4: Transfer Security</a>
      <a href="#req8" class="nav-link">Req 8: Authentication</a>
      <a href="#req10" class="nav-link">Req 10: Logging</a>
    </div>
  </nav>
  
  <div class="container">
    <div id="summary" class="summary-info">
      <h2>Audit Summary</h2>
      <p><strong>AWS Account:</strong> $AWS_ACCOUNT</p>
      <p><strong>Report Generated:</strong> $REPORT_DATE</p>
      <p><strong>Regions Checked:</strong> $REGIONS_CHECKED</p>
    </div>
    
    <div class="dashboard">
      <div onclick="document.location='#req1'" class="dashboard-card $REQ1_OVERALL">
        <h3>
          <span class="status-icon $REQ1_OVERALL">${REQ1_OVERALL:0:1}</span>
          Requirement 1
        </h3>
        <p>Network Security Controls</p>
      </div>
      
      <div onclick="document.location='#req3'" class="dashboard-card $REQ3_OVERALL">
        <h3>
          <span class="status-icon $REQ3_OVERALL">${REQ3_OVERALL:0:1}</span>
          Requirement 3
        </h3>
        <p>Key Management</p>
      </div>
      
      <div onclick="document.location='#req4'" class="dashboard-card $REQ4_OVERALL">
        <h3>
          <span class="status-icon $REQ4_OVERALL">${REQ4_OVERALL:0:1}</span>
          Requirement 4
        </h3>
        <p>Transfer Security</p>
      </div>
      
      <div onclick="document.location='#req8'" class="dashboard-card $REQ8_OVERALL">
        <h3>
          <span class="status-icon $REQ8_OVERALL">${REQ8_OVERALL:0:1}</span>
          Requirement 8
        </h3>
        <p>Authentication</p>
      </div>
      
      <div onclick="document.location='#req10'" class="dashboard-card $REQ10_OVERALL">
        <h3>
          <span class="status-icon $REQ10_OVERALL">${REQ10_OVERALL:0:1}</span>
          Requirement 10
        </h3>
        <p>Logging & Monitoring</p>
      </div>
    </div>
    
    <div id="req1" class="requirement-section">
      <h2>Requirement 1: Install and maintain network security controls</h2>
      
      <div class="requirement-item">
        <h3>1.i Firewall Rules - Unrestricted Access</h3>
        $(format_status "$REQ1_STATUS" "security groups with unrestricted access")
        
        <button class="toggle-btn" onclick="toggleCollapsible('req1-details')">
          Show Details
        </button>
        
        <div id="req1-details" class="collapsible">
          <div class="details-card">
            <h4>Security Groups with Open Access</h4>
            <div class="findings-content">
EOF

# Add the content from the detailed file for Requirement 1.i
if [[ -f "$REPORT_DIR/open_security_groups.txt" ]]; then
  echo "<pre>" >> "$HTML_REPORT"
  cat "$REPORT_DIR/open_security_groups.txt" >> "$HTML_REPORT"
  echo "</pre>" >> "$HTML_REPORT"
fi

cat >> "$HTML_REPORT" << EOF
            </div>
          </div>
        </div>
      </div>
      
      <div class="requirement-item">
        <h3>1.ii Publicly Exposed Protocols</h3>
        $(format_status "$REQ1_2_STATUS" "security groups with publicly exposed protocols")
        
        <button class="toggle-btn" onclick="toggleCollapsible('req1-2-details')">
          Show Details
        </button>
        
        <div id="req1-2-details" class="collapsible">
          <div class="details-card">
            <h4>Security Groups with Unrestricted Public Access to Sensitive Protocols</h4>
            <div class="findings-content">
EOF

# Add the content from the detailed file for Requirement 1.ii
if [[ -f "$REPORT_DIR/public_protocols.txt" ]]; then
  echo "<pre>" >> "$HTML_REPORT"
  cat "$REPORT_DIR/public_protocols.txt" >> "$HTML_REPORT"
  echo "</pre>" >> "$HTML_REPORT"
fi

cat >> "$HTML_REPORT" << EOF
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <div id="req3" class="requirement-section">
      <h2>Requirement 3: Protect stored account data</h2>
      
      <div class="requirement-item">
        <h3>3.i Key Rotation Settings</h3>
        $(format_status "$REQ3_STATUS" "keys without rotation enabled")
        
        <button class="toggle-btn" onclick="toggleCollapsible('req3-details')">
          Show Details
        </button>
        
        <div id="req3-details" class="collapsible">
          <div class="details-card">
            <h4>KMS Keys without Rotation Enabled</h4>
            <div class="findings-content">
EOF

# Add the content from the detailed file for Requirement 3.i
if [[ -f "$REPORT_DIR/keys_without_rotation.txt" ]]; then
  echo "<pre>" >> "$HTML_REPORT"
  cat "$REPORT_DIR/keys_without_rotation.txt" >> "$HTML_REPORT"
  echo "</pre>" >> "$HTML_REPORT"
fi

cat >> "$HTML_REPORT" << EOF
            </div>
          </div>
        </div>
      </div>
      
      <div class="requirement-item">
        <h3>3.ii Unprotected Secrets</h3>
        $(format_status "$REQ3_2_STATUS" "secrets not protected by custom KMS keys")
        
        <button class="toggle-btn" onclick="toggleCollapsible('req3-2-details')">
          Show Details
        </button>
        
        <div id="req3-2-details" class="collapsible">
          <div class="details-card">
            <h4>Secrets Not Protected by Custom KMS Keys</h4>
            <div class="findings-content">
EOF

# Add the content from the detailed file for Requirement 3.ii
if [[ -f "$REPORT_DIR/unprotected_secrets.txt" ]]; then
  echo "<pre>" >> "$HTML_REPORT"
  cat "$REPORT_DIR/unprotected_secrets.txt" >> "$HTML_REPORT"
  echo "</pre>" >> "$HTML_REPORT"
fi

cat >> "$HTML_REPORT" << EOF
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <div id="req4" class="requirement-section">
      <h2>Requirement 4: Protect cardholder data with strong cryptography</h2>
      
      <div class="requirement-item">
        <h3>4.i Outdated TLS Versions</h3>
        $(format_status "$REQ4_STATUS" "load balancers using TLS 1.0")
        
        <button class="toggle-btn" onclick="toggleCollapsible('req4-details')">
          Show Details
        </button>
        
        <div id="req4-details" class="collapsible">
          <div class="details-card">
            <h4>Load Balancers Using TLS 1.0</h4>
            <div class="findings-content">
EOF

# Add the content from the detailed file for Requirement 4.i
if [[ -f "$REPORT_DIR/outdated_tls.txt" ]]; then
  echo "<pre>" >> "$HTML_REPORT"
  cat "$REPORT_DIR/outdated_tls.txt" >> "$HTML_REPORT"
  echo "</pre>" >> "$HTML_REPORT"
fi

cat >> "$HTML_REPORT" << EOF
            </div>
          </div>
        </div>
      </div>
      
      <div class="requirement-item">
        <h3>4.ii Weak Ciphers</h3>
        $(format_status "$REQ4_2_STATUS" "load balancers using weak ciphers")
        
        <button class="toggle-btn" onclick="toggleCollapsible('req4-2-details')">
          Show Details
        </button>
        
        <div id="req4-2-details" class="collapsible">
          <div class="details-card">
            <h4>Load Balancers Using Weak Ciphers</h4>
            <div class="findings-content">
EOF

# Add the content from the detailed file for Requirement 4.ii
if [[ -f "$REPORT_DIR/weak_ciphers.txt" ]]; then
  echo "<pre>" >> "$HTML_REPORT"
  cat "$REPORT_DIR/weak_ciphers.txt" >> "$HTML_REPORT"
  echo "</pre>" >> "$HTML_REPORT"
fi

cat >> "$HTML_REPORT" << EOF
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <div id="req8" class="requirement-section">
      <h2>Requirement 8: Identify users and authenticate access</h2>
      
      <div class="requirement-item">
        <h3>8.i Password Policy</h3>
        $(format_status "$REQ8_STATUS" "IAM password policies")
        
        <button class="toggle-btn" onclick="toggleCollapsible('req8-details')">
          Show Details
        </button>
        
        <div id="req8-details" class="collapsible">
          <div class="details-card">
            <h4>IAM Password Policy Settings</h4>
            <div class="findings-content">
EOF

# Add the content from the detailed file for Requirement 8.i
if [[ -f "$REPORT_DIR/password_policy.txt" ]]; then
  echo "<pre>" >> "$HTML_REPORT"
  cat "$REPORT_DIR/password_policy.txt" >> "$HTML_REPORT"
  echo "</pre>" >> "$HTML_REPORT"
fi

cat >> "$HTML_REPORT" << EOF
            </div>
          </div>
        </div>
      </div>
      
      <div class="requirement-item">
        <h3>8.ii MFA Enforcement</h3>
        $(format_status "$REQ8_2_STATUS" "IAM users without MFA")
        
        <button class="toggle-btn" onclick="toggleCollapsible('req8-2-details')">
          Show Details
        </button>
        
        <div id="req8-2-details" class="collapsible">
          <div class="details-card">
            <h4>IAM Users without MFA Enabled</h4>
            <div class="findings-content">
EOF

# Add the content from the detailed file for Requirement 8.ii
if [[ -f "$REPORT_DIR/users_without_mfa.txt" ]]; then
  echo "<pre>" >> "$HTML_REPORT"
  cat "$REPORT_DIR/users_without_mfa.txt" >> "$HTML_REPORT"
  echo "</pre>" >> "$HTML_REPORT"
fi

cat >> "$HTML_REPORT" << EOF
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <div id="req10" class="requirement-section">
      <h2>Requirement 10: Log and monitor all access</h2>
      
      <div class="requirement-item">
        <h3>10.i Log Retention</h3>
        $(format_status "$REQ10_STATUS" "log buckets without 1-year retention")
        
        <button class="toggle-btn" onclick="toggleCollapsible('req10-details')">
          Show Details
        </button>
        
        <div id="req10-details" class="collapsible">
          <div class="details-card">
            <h4>Log Buckets without 1-Year Retention</h4>
            <div class="findings-content">
EOF

# Add the content from the detailed file for Requirement 10.i
if [[ -f "$REPORT_DIR/log_retention.txt" ]]; then
  echo "<pre>" >> "$HTML_REPORT"
  cat "$REPORT_DIR/log_retention.txt" >> "$HTML_REPORT"
  echo "</pre>" >> "$HTML_REPORT"
fi

cat >> "$HTML_REPORT" << EOF
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  
  <footer>
    <p>PCI DSS v4.0 Compliance Report Generated on $REPORT_DATE</p>
  </footer>
  
  <script>
    function toggleCollapsible(id) {
      const element = document.getElementById(id);
      const button = event.target;
      
      if (element.style.display === "block") {
        element.style.display = "none";
        button.textContent = "Show Details";
      } else {
        element.style.display = "block";
        button.textContent = "Hide Details";
      }
    }
    
    // Highlight the active navigation item when scrolling
    document.addEventListener('DOMContentLoaded', function() {
      const sections = document.querySelectorAll('.requirement-section, .summary-info');
      const navLinks = document.querySelectorAll('.nav-link');
      
      window.addEventListener('scroll', function() {
        let current = '';
        
        sections.forEach(section => {
          const sectionTop = section.offsetTop - 100;
          const sectionHeight = section.clientHeight;
          if (pageYOffset >= sectionTop && pageYOffset < sectionTop + sectionHeight) {
            current = section.getAttribute('id');
          }
        });
        
        navLinks.forEach(link => {
          link.classList.remove('active');
          if (link.getAttribute('href').substring(1) === current) {
            link.classList.add('active');
          }
          
          // If we're at the top, highlight summary
          if (pageYOffset < 100) {
            document.querySelector('a[href="#summary"]').classList.add('active');
          }
        });
      });
    });
  </script>
</body>
</html>
EOF

# Make the script executable
chmod +x "$HTML_REPORT"

echo "HTML report generated: $HTML_REPORT"
echo "You can open this file in a web browser to view the detailed compliance report."
