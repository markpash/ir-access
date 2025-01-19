#!/bin/bash

# Prepare
prepare(){
    echo
    echo "Preparing nftables setup..."
    echo
    sleep 0.5
    sudo apt update -qq
    echo 
    sleep 0.5
    sudo apt install -qqy nftables
}

# Define input files for prefixes
IPv4_FILE="ir_prefixes_v4.txt"
IPv6_FILE="ir_prefixes_v6.txt"

# Define output nftables configuration file
NFTABLES_CONF="/etc/nftables.conf"

## SSH Port
SSH_PORT=""
SSH_PATH="/etc/ssh/sshd_config"

## Get SSH Port
find_ssh_port() {
    echo 
    echo "Finding SSH port..."
    ## Check if the SSH configuration file exists
    if [ -e "$SSH_PATH" ]; then
        ## Use grep to search for the 'Port' directive in the SSH configuration file
        SSH_PORT=$(grep -oP '^Port\s+\K\d+' "$SSH_PATH" 2>/dev/null)

        if [ -n "$SSH_PORT" ]; then
            echo 
            echo "SSH port found: $SSH_PORT"
            sleep 0.5
        else
            echo 
            echo "SSH port is default 22."
            SSH_PORT=22
            sleep 0.5
        fi
    else
        echo
        echo "SSH configuration file not found at $SSH_PATH"
        echo
    fi
}

# Function to initialize the nftables configuration
initialize_nftables_conf() {
    cat <<EOF > "$NFTABLES_CONF"
#!/usr/sbin/nft -f

# Flush existing rules
flush ruleset

# Create the main table
table inet filter {
    set allowed_ipv4 {
        type ipv4_addr; flags interval; auto-merge;
        elements = {
EOF

    # Append IPv4 elements
    if [[ -f $IPv4_FILE ]]; then
        echo
        echo "Adding IPv4 prefixes..."
        awk '{printf "            %s,\n", $1}' "$IPv4_FILE" >> "$NFTABLES_CONF"
    else
        echo
        echo "Error: IPv4 file '$IPv4_FILE' not found!"
    fi

    # Remove trailing comma and close IPv4 set
    sed -i '$ s/,$//' "$NFTABLES_CONF"
    cat <<EOF >> "$NFTABLES_CONF"
        }
    }

    set allowed_ipv6 {
        type ipv6_addr; flags interval; auto-merge;
        elements = {
EOF

    # Append IPv6 elements
    if [[ -f $IPv6_FILE ]]; then
        echo
        echo "Adding IPv6 prefixes..."
        awk '{printf "            %s,\n", $1}' "$IPv6_FILE" >> "$NFTABLES_CONF"
    else
        echo
        echo "Error: IPv6 file '$IPv6_FILE' not found!"
    fi

    # Remove trailing comma and close IPv6 set
    sed -i '$ s/,$//' "$NFTABLES_CONF"
    cat <<EOF >> "$NFTABLES_CONF"
        }
    }

    chain input {
        type filter hook input priority filter; policy drop; # Drop everything by default

        # Allow established/related connections
        ct state established,related accept

        # Allow loopback interface
        iif lo accept

        # Allow SSH (port 22) from any source
        tcp dport $SSH_PORT accept

        # Allow traffic from allowed IPv4 addresses
        ip saddr @allowed_ipv4 accept

        # Allow traffic from allowed IPv6 addresses
        ip6 saddr @allowed_ipv6 accept
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF
    echo 
    echo "Initialized nftables configuration."
    echo 
}

# Function to apply the configuration and enable nftables
apply_nftables() {
    echo "Applying nftables configuration..."
    echo
    sleep 0.5
    sudo nft -f "$NFTABLES_CONF"
    if [[ $? -ne 0 ]]; then
        echo
        echo "Error: Failed to apply nftables configuration. Check the syntax and retry."
        exit 1
    fi

    echo "Enabling nftables service..."
    echo 
    sudo systemctl enable nftables
    sudo systemctl start nftables
    echo "Configuration applied and nftables service started."
    echo
}

# Function to verify the ruleset
verify_nftables() {
    echo "Verifying nftables ruleset..."
    echo
    sudo nft list ruleset
}

# Main script execution
prepare
sleep 1
find_ssh_port
sleep 1
initialize_nftables_conf
sleep 1
apply_nftables
sleep 1
verify_nftables
sleep 1

echo 
echo "Nftables setup is complete. Your server is now Iran-Access-Only except for SSH port."
echo "Configuration is saved in $NFTABLES_CONF."
echo
