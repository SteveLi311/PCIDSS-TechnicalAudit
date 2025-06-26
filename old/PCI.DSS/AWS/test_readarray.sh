#!/usr/bin/env bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Test data - simulated JSON output for a security group with public rules
TEST_DATA='
{
  "SecurityGroups": [
    {
      "IpPermissions": [
        {
          "IpProtocol": "tcp",
          "FromPort": 80,
          "ToPort": 80,
          "IpRanges": [
            {
              "CidrIp": "0.0.0.0/0"
            }
          ]
        },
        {
          "IpProtocol": "tcp",
          "FromPort": 22,
          "ToPort": 22,
          "IpRanges": [
            {
              "CidrIp": "0.0.0.0/0"
            }
          ]
        },
        {
          "IpProtocol": "tcp",
          "FromPort": 443,
          "ToPort": 443,
          "IpRanges": [
            {
              "CidrIp": "0.0.0.0/0"
            }
          ]
        }
      ]
    }
  ]
}
'

echo "Testing readarray functionality for security group parsing:"
echo "============================================================"

# Create a temporary file for the test data
TMP_FILE=$(mktemp)
echo "$TEST_DATA" > "$TMP_FILE"

# Check if jq is available
if command -v jq &> /dev/null; then
    echo -e "${GREEN}jq is available, testing readarray with jq...${NC}"
    
    # Initialize port list variable
    port_list=""
    
    # Use readarray to extract permissions with public access
    echo "Using readarray to parse permissions:"
    readarray -t permissions < <(jq -c '.SecurityGroups[0].IpPermissions[] | select(.IpRanges[].CidrIp == "0.0.0.0/0")' < "$TMP_FILE")
    
    # Display the number of permissions found
    echo "Found ${#permissions[@]} permissions with public access"
    
    # Process each permission in the array
    for permission in "${permissions[@]}"; do
        echo "Processing permission: $permission"
        
        if [ -n "$permission" ]; then
            protocol=$(echo "$permission" | jq -r '.IpProtocol')
            fromPort=$(echo "$permission" | jq -r '.FromPort')
            toPort=$(echo "$permission" | jq -r '.ToPort')
            
            # Format console output
            if [ "$fromPort" == "$toPort" ]; then
                echo -e "${RED}  $protocol Port $fromPort open to the internet (0.0.0.0/0)${NC}"
                port_list+="<li class=\"red\">$protocol Port $fromPort open to the internet</li>"
            else
                echo -e "${RED}  $protocol Ports $fromPort-$toPort open to the internet (0.0.0.0/0)${NC}"
                port_list+="<li class=\"red\">$protocol Ports $fromPort-$toPort open to the internet</li>"
            fi
        fi
    done
    
    # Display the final HTML port list
    echo -e "\nFinal HTML port list:"
    echo "$port_list"
else
    echo -e "${RED}jq is not available, cannot test jq-based extraction${NC}"
fi

# Clean up
rm -f "$TMP_FILE"
echo -e "\nTest completed."