#!/bin/bash

# Check if fail2ban-client is installed
if ! command -v fail2ban-client &> /dev/null; then
    echo "Error: fail2ban-client is not installed. Please install Fail2Ban first."
    exit 1
fi

# Define the jail name (sshd)
JAIL_NAME="sshd"

# Function to get whitelisted IPs from a given jail
get_whitelisted_ips() {
    local jail="$1"
    echo "Checking whitelist for jail '$jail'..."

    # Get the list of whitelisted IPs using fail2ban-client
    whitelist=$(fail2ban-client status $jail | grep 'Whitelist' -A 50 | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)

    if [ -z "$whitelist" ]; then
        echo "No whitelisted IPs found for jail '$jail'."
    else
        echo "Whitelisted IP(s) for jail '$jail': $whitelist"
    fi
}

# Main function to check the sshd jail
main() {
    get_whitelisted_ips "$JAIL_NAME"
}

# Execute the main function
main

echo "Script execution completed."

