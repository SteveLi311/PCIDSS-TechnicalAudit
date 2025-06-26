# Implementing Requirement-Specific Checks for PCI DSS v4.0.1

This guide explains how to implement comprehensive, detailed checks for specific PCI DSS requirements in the AWS environment. We'll use Requirement 1.2.6 (Security features for insecure services/protocols) as an example to demonstrate best practices.

## Guiding Principles

1. **Cross-Reference the PCI DSS Requirements Document**: Always start by understanding exactly what the requirement states in `PCI_DSS_v4.0.1_Requirements.md`
2. **Focus on Detailed Evidence Collection**: Provide specific resource identifiers, configuration details, and context
3. **Create Dedicated Functions**: Build modular, reusable functions for each check
4. **Ensure Comprehensive Reporting**: Include all relevant details in a structured format

## Step 1: Understand the Requirement

First, consult the requirements document to understand what Requirement 1.2.6 specifies:

> **1.2.6 Security features are defined and implemented for all services, protocols, and ports that are in use and considered to be insecure, such that the risk is mitigated.**

This requires identifying any insecure services (Telnet, FTP, unencrypted databases, etc.) and checking if appropriate security features are implemented.

## Step 2: Create a Dedicated Assessment Function

Create a specialized function to check for insecure services in security groups. The function should:

- Accept a VPC ID as input
- Check every security group in the VPC
- Test for multiple common insecure services/protocols
- Extract detailed information, including sources (IP/CIDR/security groups)
- Return comprehensive HTML-formatted results

The implementation is found in `check_insecure_services.sh`.

## Step 3: Pay Special Attention to Detail

When checking security groups, be thorough:

1. **Check Multiple Insecure Services**:
   - Telnet (port 23)
   - FTP (port 21)
   - SQL Server (port 1433) without encryption
   - MySQL/MariaDB (port 3306) without encryption
   - MongoDB (port 27017) without authentication
   - Redis (port 6379) without authentication
   - Memcached (port 11211) without authentication
   - SMTP (port 25) without TLS
   - HTTP (port 80) without HTTPS redirect

2. **Identify All Sources**:
   - IPv4 CIDR ranges (using `CidrIp`)
   - IPv6 CIDR ranges (using `CidrIpv6`)
   - Security group references (using `GroupId`)
   - Display source names where possible

3. **Color-Code Severity**:
   - Red: Critical issues (Telnet, FTP)
   - Yellow: Warning issues (unencrypted database connections)
   - Green: Passed checks

## Step 4: Integration with the Main Assessment Script

In `implement_requirement_1_2_6.sh`, we demonstrate how to:

1. Source the modular check function
2. Create proper HTML report structure
3. Iterate through all target VPCs
4. Combine results for comprehensive reporting
5. Provide actionable recommendations

## Key Code Elements

### 1. The Core Check Function

```bash
check_insecure_services() {
    local vpc_id="$1"
    local details=""
    local found_insecure=false
    
    # Get all security groups in the VPC
    sg_list=$(aws ec2 describe-security-groups --region $REGION --filters "Name=vpc-id,Values=$vpc_id" --query 'SecurityGroups[*].GroupId' --output text)
    
    details+="<p>Analysis of security groups in VPC $vpc_id:</p><ul>"
    
    for sg_id in $sg_list; do
        # Get security group details
        sg_info=$(aws ec2 describe-security-groups --region $REGION --group-ids $sg_id)
        sg_name=$(echo "$sg_info" | grep "GroupName" | head -1 | awk -F '"' '{print $4}')
        
        # Initialize the HTML list item for this security group
        sg_has_issues=false
        sg_details="<li>Security Group: $sg_id ($sg_name)<ul>"
        
        # Check for Telnet (port 23)
        telnet_rules=$(echo "$sg_info" | grep -A 15 '"FromPort": 23' | grep -B 10 '"ToPort": 23')
        if [ -n "$telnet_rules" ]; then
            # [Detailed source extraction and reporting]
            found_insecure=true
            sg_has_issues=true
        }
        
        # [Additional protocol checks...]
        
        # Only add this security group to the details if it had issues
        if [ "$sg_has_issues" = true ]; then
            details+="$sg_details"
        }
    }
    
    echo "$details"
}
```

### 2. Proper Source IP Extraction

```bash
# Check for CidrIp (IPv4) sources
mysql_ipv4_sources=$(echo "$mysql_rules" | grep "CidrIp" | awk -F '"' '{print $4}')

# Check for IPv6 sources
mysql_ipv6_sources=$(echo "$mysql_rules" | grep "CidrIpv6" | awk -F '"' '{print $4}')

# Check for security group sources
mysql_sg_sources=$(echo "$mysql_rules" | grep "GroupId" | awk -F '"' '{print $4}')

# Add security group sources with names
if [ -n "$mysql_sg_sources" ]; then
    for source in $mysql_sg_sources; do
        # Get the source security group name
        source_sg_name=$(aws ec2 describe-security-groups --region $REGION --group-ids $source --query 'SecurityGroups[0].GroupName' --output text 2>/dev/null)
        sg_details+="<li>Security Group: $source ($source_sg_name)</li>"
    done
}
```

### 3. Integrating with the Reporting Framework

```bash
for vpc_id in $vpcs; do
    echo -e "\nChecking VPC: $vpc_id for insecure services/protocols..."
    
    # Call the check_insecure_services function
    vpc_details=$(check_insecure_services "$vpc_id")
    
    # Append the VPC details to the overall details
    all_details+="<h4>VPC: $vpc_id</h4>$vpc_details"
    
    # Check if insecure services were found in this VPC
    if [[ "$vpc_details" == *"class=\"red\""* || "$vpc_details" == *"class=\"yellow\""* ]]; then
        insecure_services_found=true
    fi
}
```

### 4. Detailed Recommendations for Failed Checks

```bash
add_check_item "$OUTPUT_FILE" "fail" "1.2.6 - Security features for insecure services/protocols" \
    "$all_details" \
    "Per PCI DSS requirement 1.2.6, security features must be defined and implemented for all services, protocols, and ports that are in use and considered to be insecure. Action items:
    <ol>
        <li>Replace insecure protocols with secure alternatives where possible (e.g., Telnet→SSH, FTP→SFTP/FTPS).</li>
        <li>For insecure services that must be used for business reasons, implement additional security features such as:
            <ul>
                <li>Restrict source IP addresses to specific trusted hosts or networks</li>
                <li>Implement encrypted tunnels (e.g., VPN or SSH tunneling)</li>
                <li>Use TLS/SSL for database connections</li>
                <li>Enable strong authentication mechanisms</li>
                <li>Implement network segmentation</li>
            </ul>
        </li>
        <li>Document business justification for any insecure services that must remain in use</li>
        <li>Document the security features implemented to mitigate risks of insecure services</li>
    </ol>"
```

## Applying This Approach to Other Requirements

This pattern can be applied to other PCI DSS requirements by:

1. **Reading the Specific Requirement**: Understand exactly what needs to be assessed
2. **Creating Dedicated Functions**: Build modular, reusable code for the specific check
3. **Ensuring Thorough Inspection**: Check all relevant AWS resources comprehensively
4. **Providing Clear, Actionable Results**: Display detailed findings and recommendations

## Example Requirements Using Similar Patterns

- **Requirement 1.2.5**: Create an inventory of all allowed ports, protocols, and services
- **Requirement 1.3.1**: Check if inbound traffic to the CDE is properly restricted
- **Requirement 1.4.4**: Verify that CHD storage components are not directly accessible from untrusted networks
- **Requirement 2.2.5**: Check for insecure services/protocols and verify business justification

## Conclusion

When implementing requirement-specific checks:

1. Always refer to the PCI DSS documentation for exact requirements
2. Design checks to be detailed, comprehensive and actionable
3. Focus on providing specific evidence and resource identifiers
4. Make recommendations that align directly with the requirement text
5. Structure the output for clear understanding by technical teams, management, and auditors

By following these guidelines, your PCI DSS assessment scripts will provide valuable, detailed information that helps organizations maintain compliance and improve security posture.
