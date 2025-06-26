#!/bin/bash

# Function to check for insecure services in security groups
# This function implements a detailed assessment for PCI DSS Requirement 1.2.6
# and provides comprehensive reporting of insecure services/protocols

check_insecure_services() {
    local vpc_id="$1"
    local details=""
    local found_insecure=false
    
    # Get all security groups in the VPC
    echo -ne "Checking security groups in VPC $vpc_id for insecure services... "
    sg_list=$(aws ec2 describe-security-groups --region $REGION --filters "Name=vpc-id,Values=$vpc_id" --query 'SecurityGroups[*].GroupId' --output text)
    
    if [ -z "$sg_list" ]; then
        echo -e "\033[0;33mNo security groups found\033[0m"
        return 0
    fi
    
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
            # Check for CidrIp (IPv4) sources
            telnet_ipv4_sources=$(echo "$telnet_rules" | grep "CidrIp" | awk -F '"' '{print $4}')
            
            # Check for IPv6 sources
            telnet_ipv6_sources=$(echo "$telnet_rules" | grep "CidrIpv6" | awk -F '"' '{print $4}')
            
            # Check for security group sources
            telnet_sg_sources=$(echo "$telnet_rules" | grep "GroupId" | awk -F '"' '{print $4}')
            
            sg_details+="<li class=\"red\">Allows Telnet (port 23) from:<ul>"
            
            # Add IPv4 sources
            if [ -n "$telnet_ipv4_sources" ]; then
                for source in $telnet_ipv4_sources; do
                    sg_details+="<li>$source (IPv4)</li>"
                done
            fi
            
            # Add IPv6 sources
            if [ -n "$telnet_ipv6_sources" ]; then
                for source in $telnet_ipv6_sources; do
                    sg_details+="<li>$source (IPv6)</li>"
                done
            fi
            
            # Add security group sources
            if [ -n "$telnet_sg_sources" ]; then
                for source in $telnet_sg_sources; do
                    # Get the source security group name
                    source_sg_name=$(aws ec2 describe-security-groups --region $REGION --group-ids $source --query 'SecurityGroups[0].GroupName' --output text 2>/dev/null)
                    sg_details+="<li>Security Group: $source ($source_sg_name)</li>"
                done
            fi
            
            # If no sources found, explicitly state this
            if [ -z "$telnet_ipv4_sources" ] && [ -z "$telnet_ipv6_sources" ] && [ -z "$telnet_sg_sources" ]; then
                sg_details+="<li><em>Error: Could not determine source - please check manually</em></li>"
            fi
            
            sg_details+="</ul></li>"
            found_insecure=true
            sg_has_issues=true
            echo -e "\033[0;31mTelnet (23) detected in $sg_id\033[0m"
        fi
        
        # Check for FTP (port 21)
        ftp_rules=$(echo "$sg_info" | grep -A 15 '"FromPort": 21' | grep -B 10 '"ToPort": 21')
        if [ -n "$ftp_rules" ]; then
            # Check for CidrIp (IPv4) sources
            ftp_ipv4_sources=$(echo "$ftp_rules" | grep "CidrIp" | awk -F '"' '{print $4}')
            
            # Check for IPv6 sources
            ftp_ipv6_sources=$(echo "$ftp_rules" | grep "CidrIpv6" | awk -F '"' '{print $4}')
            
            # Check for security group sources
            ftp_sg_sources=$(echo "$ftp_rules" | grep "GroupId" | awk -F '"' '{print $4}')
            
            sg_details+="<li class=\"red\">Allows FTP (port 21) from:<ul>"
            
            # Add IPv4 sources
            if [ -n "$ftp_ipv4_sources" ]; then
                for source in $ftp_ipv4_sources; do
                    sg_details+="<li>$source (IPv4)</li>"
                done
            fi
            
            # Add IPv6 sources
            if [ -n "$ftp_ipv6_sources" ]; then
                for source in $ftp_ipv6_sources; do
                    sg_details+="<li>$source (IPv6)</li>"
                done
            fi
            
            # Add security group sources
            if [ -n "$ftp_sg_sources" ]; then
                for source in $ftp_sg_sources; do
                    # Get the source security group name
                    source_sg_name=$(aws ec2 describe-security-groups --region $REGION --group-ids $source --query 'SecurityGroups[0].GroupName' --output text 2>/dev/null)
                    sg_details+="<li>Security Group: $source ($source_sg_name)</li>"
                done
            fi
            
            # If no sources found, explicitly state this
            if [ -z "$ftp_ipv4_sources" ] && [ -z "$ftp_ipv6_sources" ] && [ -z "$ftp_sg_sources" ]; then
                sg_details+="<li><em>Error: Could not determine source - please check manually</em></li>"
            fi
            
            sg_details+="</ul></li>"
            found_insecure=true
            sg_has_issues=true
            echo -e "\033[0;31mFTP (21) detected in $sg_id\033[0m"
        fi
        
        # Check for non-encrypted SQL Server (port 1433)
        mssql_rules=$(echo "$sg_info" | grep -A 15 '"FromPort": 1433' | grep -B 10 '"ToPort": 1433')
        if [ -n "$mssql_rules" ]; then
            # Check for CidrIp (IPv4) sources
            mssql_ipv4_sources=$(echo "$mssql_rules" | grep "CidrIp" | awk -F '"' '{print $4}')
            
            # Check for IPv6 sources
            mssql_ipv6_sources=$(echo "$mssql_rules" | grep "CidrIpv6" | awk -F '"' '{print $4}')
            
            # Check for security group sources
            mssql_sg_sources=$(echo "$mssql_rules" | grep "GroupId" | awk -F '"' '{print $4}')
            
            sg_details+="<li class=\"yellow\">Allows SQL Server (port 1433) - Ensure encryption is in use from:<ul>"
            
            # Add IPv4 sources
            if [ -n "$mssql_ipv4_sources" ]; then
                for source in $mssql_ipv4_sources; do
                    sg_details+="<li>$source (IPv4)</li>"
                done
            fi
            
            # Add IPv6 sources
            if [ -n "$mssql_ipv6_sources" ]; then
                for source in $mssql_ipv6_sources; do
                    sg_details+="<li>$source (IPv6)</li>"
                done
            fi
            
            # Add security group sources
            if [ -n "$mssql_sg_sources" ]; then
                for source in $mssql_sg_sources; do
                    # Get the source security group name
                    source_sg_name=$(aws ec2 describe-security-groups --region $REGION --group-ids $source --query 'SecurityGroups[0].GroupName' --output text 2>/dev/null)
                    sg_details+="<li>Security Group: $source ($source_sg_name)</li>"
                done
            fi
            
            # If no sources found, explicitly state this
            if [ -z "$mssql_ipv4_sources" ] && [ -z "$mssql_ipv6_sources" ] && [ -z "$mssql_sg_sources" ]; then
                sg_details+="<li><em>Error: Could not determine source - please check manually</em></li>"
            fi
            
            sg_details+="</ul></li>"
            found_insecure=true
            sg_has_issues=true
            echo -e "\033[0;33mSQL Server (1433) detected in $sg_id\033[0m"
        fi
        
        # Check for non-encrypted MySQL/MariaDB (port 3306)
        mysql_rules=$(echo "$sg_info" | grep -A 15 '"FromPort": 3306' | grep -B 10 '"ToPort": 3306')
        if [ -n "$mysql_rules" ]; then
            # Check for CidrIp (IPv4) sources
            mysql_ipv4_sources=$(echo "$mysql_rules" | grep "CidrIp" | awk -F '"' '{print $4}')
            
            # Check for IPv6 sources
            mysql_ipv6_sources=$(echo "$mysql_rules" | grep "CidrIpv6" | awk -F '"' '{print $4}')
            
            # Check for security group sources
            mysql_sg_sources=$(echo "$mysql_rules" | grep "GroupId" | awk -F '"' '{print $4}')
            
            sg_details+="<li class=\"yellow\">Allows MySQL/MariaDB (port 3306) - Ensure encryption is in use from:<ul>"
            
            # Add IPv4 sources
            if [ -n "$mysql_ipv4_sources" ]; then
                for source in $mysql_ipv4_sources; do
                    sg_details+="<li>$source (IPv4)</li>"
                done
            fi
            
            # Add IPv6 sources
            if [ -n "$mysql_ipv6_sources" ]; then
                for source in $mysql_ipv6_sources; do
                    sg_details+="<li>$source (IPv6)</li>"
                done
            fi
            
            # Add security group sources
            if [ -n "$mysql_sg_sources" ]; then
                for source in $mysql_sg_sources; do
                    # Get the source security group name
                    source_sg_name=$(aws ec2 describe-security-groups --region $REGION --group-ids $source --query 'SecurityGroups[0].GroupName' --output text 2>/dev/null)
                    sg_details+="<li>Security Group: $source ($source_sg_name)</li>"
                done
            fi
            
            # If no sources found, explicitly state this
            if [ -z "$mysql_ipv4_sources" ] && [ -z "$mysql_ipv6_sources" ] && [ -z "$mysql_sg_sources" ]; then
                sg_details+="<li><em>Error: Could not determine source - please check manually</em></li>"
            fi
            
            sg_details+="</ul></li>"
            found_insecure=true
            sg_has_issues=true
            echo -e "\033[0;33mMySQL (3306) detected in $sg_id\033[0m"
        fi
        
        # Check for MongoDB (port 27017) without authentication/encryption 
        mongo_rules=$(echo "$sg_info" | grep -A 10 '"FromPort": 27017' | grep -B 5 '"ToPort": 27017')
        if [ -n "$mongo_rules" ]; then
            mongo_sources=$(echo "$mongo_rules" | grep "CidrIp" | awk -F '"' '{print $4}')
            sg_details+="<li class=\"yellow\">Allows MongoDB (port 27017) - Ensure authentication and encryption are in use from:<ul>"
            for source in $mongo_sources; do
                sg_details+="<li>$source</li>"
            done
            sg_details+="</ul></li>"
            found_insecure=true
            sg_has_issues=true
            echo -e "\033[0;33mMongoDB (27017) detected in $sg_id\033[0m"
        fi
        
        # Check for Redis (port 6379) without authentication/encryption
        redis_rules=$(echo "$sg_info" | grep -A 10 '"FromPort": 6379' | grep -B 5 '"ToPort": 6379')
        if [ -n "$redis_rules" ]; then
            redis_sources=$(echo "$redis_rules" | grep "CidrIp" | awk -F '"' '{print $4}')
            sg_details+="<li class=\"yellow\">Allows Redis (port 6379) - Ensure authentication and encryption are in use from:<ul>"
            for source in $redis_sources; do
                sg_details+="<li>$source</li>"
            done
            sg_details+="</ul></li>"
            found_insecure=true
            sg_has_issues=true
            echo -e "\033[0;33mRedis (6379) detected in $sg_id\033[0m"
        fi
        
        # Check for Memcached (port 11211) without authentication/encryption
        memcached_rules=$(echo "$sg_info" | grep -A 10 '"FromPort": 11211' | grep -B 5 '"ToPort": 11211')
        if [ -n "$memcached_rules" ]; then
            memcached_sources=$(echo "$memcached_rules" | grep "CidrIp" | awk -F '"' '{print $4}')
            sg_details+="<li class=\"yellow\">Allows Memcached (port 11211) - Ensure proper security controls are in place from:<ul>"
            for source in $memcached_sources; do
                sg_details+="<li>$source</li>"
            done
            sg_details+="</ul></li>"
            found_insecure=true
            sg_has_issues=true
            echo -e "\033[0;33mMemcached (11211) detected in $sg_id\033[0m"
        fi
        
        # Check for SMTP (port 25) without TLS 
        smtp_rules=$(echo "$sg_info" | grep -A 10 '"FromPort": 25' | grep -B 5 '"ToPort": 25')
        if [ -n "$smtp_rules" ]; then
            smtp_sources=$(echo "$smtp_rules" | grep "CidrIp" | awk -F '"' '{print $4}')
            sg_details+="<li class=\"yellow\">Allows SMTP (port 25) - Ensure TLS is in use from:<ul>"
            for source in $smtp_sources; do
                sg_details+="<li>$source</li>"
            done
            sg_details+="</ul></li>"
            found_insecure=true
            sg_has_issues=true
            echo -e "\033[0;33mSMTP (25) detected in $sg_id\033[0m"
        fi
        
        # Check for HTTP (port 80) without a redirect to HTTPS
        http_rules=$(echo "$sg_info" | grep -A 10 '"FromPort": 80' | grep -B 5 '"ToPort": 80')
        if [ -n "$http_rules" ]; then
            # Check if HTTPS is also allowed (443) to see if a redirect is possible
            https_rules=$(echo "$sg_info" | grep -A 10 '"FromPort": 443' | grep -B 5 '"ToPort": 443')
            
            if [ -z "$https_rules" ]; then
                # HTTPS not found in this security group, which is concerning
                http_sources=$(echo "$http_rules" | grep "CidrIp" | awk -F '"' '{print $4}')
                sg_details+="<li class=\"yellow\">Allows HTTP (port 80) without HTTPS (port 443) also open - Ensure HTTP-to-HTTPS redirection is in place from:<ul>"
                for source in $http_sources; do
                    sg_details+="<li>$source</li>"
                done
                sg_details+="</ul></li>"
                found_insecure=true
                sg_has_issues=true
                echo -e "\033[0;33mHTTP (80) without HTTPS detected in $sg_id\033[0m"
            fi
        fi
        
        # Check for overly permissive rules (0.0.0.0/0) for critical services
        all_traffic_rules=$(echo "$sg_info" | grep -A 2 '"CidrIp": "0.0.0.0/0"')
        if [ -n "$all_traffic_rules" ]; then
            # Public sources for any protocol are a concern
            sg_details+="<li class=\"red\">Security group has rules allowing traffic from any IP (0.0.0.0/0):<ul>"
            
            # Get specific rules with 0.0.0.0/0
            public_rules=$(echo "$sg_info" | grep -A 5 '"CidrIp": "0.0.0.0/0"' | grep -B 5 -A 5 "IpProtocol" | grep -E "FromPort|ToPort|IpProtocol")
            sg_details+="<li><pre>$public_rules</pre></li>"
            
            sg_details+="</ul></li>"
            found_insecure=true
            sg_has_issues=true
            echo -e "\033[0;31mOverly permissive rules (0.0.0.0/0) detected in $sg_id\033[0m"
        fi
        
        sg_details+="</ul></li>"
        
        # Only add this security group to the details if it had issues
        if [ "$sg_has_issues" = true ]; then
            details+="$sg_details"
        fi
    done
    
    details+="</ul>"
    
    if [ "$found_insecure" = false ]; then
        echo -e "\033[0;32mNo insecure services detected\033[0m"
        details="<p class=\"green\">No insecure services or overly permissive rules detected in any security groups in VPC $vpc_id.</p>"
    else
        echo -e "\033[0;31mInsecure services or overly permissive rules detected\033[0m"
    fi
    
    echo "$details"
}

# Usage example (commented out):
# check_insecure_services "vpc-12345678"
