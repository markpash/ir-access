#!/bin/bash

# Define input files for prefixes
IPv4_FILE="ir_prefixes_v4.txt"
IPv6_FILE="ir_prefixes_v6.txt"

# Define output nftables configuration file
NFTABLES_CONF="/etc/nftables.conf"

# Function to initialize the nftables configuration
initialize_nftables_conf() {
    cat <<EOF > "$NFTABLES_CONF"
#!/usr/sbin/nft -f

# Flush existing rules
flush ruleset

# Create the main table
table inet filter {
    set allowed_ipv4 {
        type ipv4_addr; flags interval;
        elements = {
EOF

    # Append IPv4 elements
    if [[ -f $IPv4_FILE ]]; then
        echo "Adding IPv4 prefixes..."
        awk '{printf "            %s,\n", $1}' "$IPv4_FILE" >> "$NFTABLES_CONF"
    else
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
        echo "Adding IPv6 prefixes..."
        awk '{printf "            %s,\n", $1}' "$IPv6_FILE" >> "$NFTABLES_CONF"
    else
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
        tcp dport 22 accept

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
    echo "Initialized nftables configuration."
}

# Function to apply the configuration and enable nftables
apply_nftables() {
    echo "Applying nftables configuration..."
    sudo nft -f "$NFTABLES_CONF"
    if [[ $? -ne 0 ]]; then
        echo "Error: Failed to apply nftables configuration. Check the syntax and retry."
        exit 1
    fi

    echo "Enabling nftables service..."
    sudo systemctl enable nftables
    sudo systemctl start nftables
    echo "Configuration applied and nftables service started."
}

# Function to verify the ruleset
verify_nftables() {
    echo "Verifying nftables ruleset..."
    sudo nft list ruleset
}

# Main script execution
initialize_nftables_conf
apply_nftables
verify_nftables

echo "Nftables setup is complete. Configuration is saved in $NFTABLES_CONF."
