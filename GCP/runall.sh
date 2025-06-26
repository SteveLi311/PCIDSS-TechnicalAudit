#!/bin/bash

SCRIPT_DIR="."  # or specify path
NEED_ALL=("check_gcp_pci_requirement1.sh" "check_gcp_pci_requirement3.sh")  # Add script names that require 'all'

echo "🔧 Starting GCP PCI DSS requirement checks..."

for i in {1..8}; do
    SCRIPT_NAME="check_gcp_pci_requirement${i}.sh"
    SCRIPT_PATH="$SCRIPT_DIR/$SCRIPT_NAME"

    if [[ -x "$SCRIPT_PATH" ]]; then
        echo "➡️ Running $SCRIPT_NAME..."

        if [[ " ${NEED_ALL[@]} " =~ " ${SCRIPT_NAME} " ]]; then
            echo "⚙️  Feeding 'all' input to $SCRIPT_NAME"
            bash "$SCRIPT_PATH" <<< "all"
        else
            bash "$SCRIPT_PATH"
        fi

        echo "✅ Finished $SCRIPT_NAME"
        echo "--------------------------------"
    else
        echo "⚠️  Skipping $SCRIPT_NAME (not found or not executable)"
    fi
done

echo "🏁 All requirement checks completed."

