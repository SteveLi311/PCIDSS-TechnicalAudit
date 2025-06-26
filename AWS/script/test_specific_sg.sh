#!/bin/bash

# Set colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Check if security group ID is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <security-group-id>"
  echo "Example: $0 sg-91b712f5"
  exit 1
fi

SG_ID="$1"
REGION="ap-northeast-1"

echo "Analyzing Security Group: $SG_ID"

# Get security group details
sg_details=$(aws ec2 describe-security-groups --region $REGION --group-ids $SG_ID 2>/dev/null)

if [ -z "$sg_details" ]; then
  echo -e "${RED}Error: Could not retrieve security group details${NC}"
  exit 1
fi

# Check for public inbound rules
public_inbound=$(echo "$sg_details" | grep -c '"CidrIp": "0.0.0.0/0"')

if [ $public_inbound -gt 0 ]; then
  echo -e "${RED}WARNING: Security group $SG_ID has $public_inbound public inbound rules (0.0.0.0/0)${NC}"
  
  echo "CONSOLE OUTPUT:"
  echo "---------------"
  
  # Using jq if available for more reliable extraction
  if command -v jq &> /dev/null; then
    # Extract all permissions that have CidrIp 0.0.0.0/0
    permissions=$(echo "$sg_details" | jq -c '.SecurityGroups[0].IpPermissions[] | select(.IpRanges[].CidrIp == "0.0.0.0/0")' 2>/dev/null)
    
    # Process each permission
    echo "$permissions" | while read -r permission; do
      protocol=$(echo "$permission" | jq -r '.IpProtocol')
      
      # Handle "all protocols" case (-1)
      if [ "$protocol" == "-1" ]; then
        echo -e "${RED}  ALL PROTOCOLS AND PORTS open to the internet (0.0.0.0/0)${NC}"
      else
        # Handle specific protocols
        fromPort=$(echo "$permission" | jq -r 'if has("FromPort") then .FromPort | tostring else "N/A" end')
        toPort=$(echo "$permission" | jq -r 'if has("ToPort") then .ToPort | tostring else "N/A" end')
        
        # Handle port range
        if [ "$fromPort" == "$toPort" ]; then
          echo -e "${RED}  $protocol Port $fromPort open to the internet (0.0.0.0/0)${NC}"
        else
          echo -e "${RED}  $protocol Ports $fromPort-$toPort open to the internet (0.0.0.0/0)${NC}"
        fi
      fi
    done
  else
    echo "jq not found, using grep-based extraction"
    
    # Create temporary files to store raw JSON
    TMP_FILE=$(mktemp)
    echo "$sg_details" | grep -A 50 "IpPermissions" > "$TMP_FILE"
    
    # Read the file in a loop to extract protocol and port information
    protocol=""
    fromPort=""
    toPort=""
    cidr_found=false
    
    while IFS= read -r line; do
      if [[ $line == *"IpProtocol"* ]]; then
        # If we found a new IpProtocol, output any previous rule
        if [ "$cidr_found" = true ] && [ -n "$protocol" ]; then
          if [ "$protocol" == "-1" ]; then
            echo -e "${RED}  ALL PROTOCOLS AND PORTS open to the internet (0.0.0.0/0)${NC}"
          elif [ -n "$fromPort" ] && [ -n "$toPort" ]; then
            if [ "$fromPort" == "$toPort" ]; then
              echo -e "${RED}  $protocol Port $fromPort open to the internet (0.0.0.0/0)${NC}"
            else
              echo -e "${RED}  $protocol Ports $fromPort-$toPort open to the internet (0.0.0.0/0)${NC}"
            fi
          else
            echo -e "${RED}  $protocol (port unspecified) open to the internet (0.0.0.0/0)${NC}"
          fi
        fi
        
        # Reset for new protocol
        protocol=$(echo "$line" | sed -E 's/.*: "([^"]+)".*/\1/')
        fromPort=""
        toPort=""
        cidr_found=false
      elif [[ $line == *"FromPort"* ]]; then
        fromPort=$(echo "$line" | sed -E 's/.*: ([0-9-]+).*/\1/')
      elif [[ $line == *"ToPort"* ]]; then
        toPort=$(echo "$line" | sed -E 's/.*: ([0-9-]+).*/\1/')
      elif [[ $line == *'"CidrIp": "0.0.0.0/0"'* ]]; then
        cidr_found=true
      fi
    done < "$TMP_FILE"
    
    # Output last rule if we found one
    if [ "$cidr_found" = true ] && [ -n "$protocol" ]; then
      if [ "$protocol" == "-1" ]; then
        echo -e "${RED}  ALL PROTOCOLS AND PORTS open to the internet (0.0.0.0/0)${NC}"
      elif [ -n "$fromPort" ] && [ -n "$toPort" ]; then
        if [ "$fromPort" == "$toPort" ]; then
          echo -e "${RED}  $protocol Port $fromPort open to the internet (0.0.0.0/0)${NC}"
        else
          echo -e "${RED}  $protocol Ports $fromPort-$toPort open to the internet (0.0.0.0/0)${NC}"
        fi
      else
        echo -e "${RED}  $protocol (port unspecified) open to the internet (0.0.0.0/0)${NC}"
      fi
    fi
    
    # Clean up
    rm -f "$TMP_FILE"
  fi
else
  echo -e "${GREEN}No public inbound rules (0.0.0.0/0) found in Security Group $SG_ID${NC}"
fi