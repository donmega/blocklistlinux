#!/bin/bash

# Function for downloading and processing IP lists
download_and_process_ip_list() {
  list_url="$1"
  ipset_name="$2"
  action="$3" # Use "DROP" or "REJECT" as needed 
  tmp_file="/tmp/ip-blocklist.txt.tmp"

  # Download list
  echo "Downloading IP list from $list_url..."
  if ! wget -qO- "$list_url" > $tmp_file; then
    echo "Error downloading IP list from $list_url. Check manually."
    return 1
  fi

  # Filter IPv4 addresses and remove duplicates
  echo "Filtering IPv4 addresses and removing duplicates..."
  grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" $tmp_file | sort -u > /tmp/ip-blocklist.txt
  rm $tmp_file

  # Create or flush ipset
  echo "Configuring ipset $ipset_name..."
  if ipset list "$ipset_name" &>/dev/null; then
    ipset flush "$ipset_name"
  else
    ipset create "$ipset_name" hash:ip maxelem 16777216
  fi

  # Add IPs to ipset
  echo "Adding IPs to ipset..."
  while read -r ip; do
    ipset add "$ipset_name" "$ip" -exist
  done < /tmp/ip-blocklist.txt

  # Clean up
  rm /tmp/ip-blocklist.txt
}

# Function for creating iptables chain and rule (if needed)
setup_iptables_chain() {
  chain_name="$1"
  action="$2"

  echo "Configuring iptables chain $chain_name..."
  if ! iptables -L -n | grep "Chain $chain_name" &>/dev/null; then
    iptables --new-chain "$chain_name"
  fi

  if ! iptables -L INPUT | grep "$chain_name" &>/dev/null; then
    iptables -I INPUT -j "$chain_name"
  fi

  if ! iptables -L "$chain_name" | grep "$action" &>/dev/null; then
    iptables -I "$chain_name" -m set --match-set "$chain_name" src -j "$action"
  fi
}

# --- Main script logic --- 

# Check for dependencies
for cmd in wget ipset iptables grep sort; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: Command '$cmd' not found. Please install."
    exit 1
  fi
done

# IP List Sources
blocklist_de_url="http://lists.blocklist.de/lists/all.txt"
firehol_url="https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset"
abuseipdb_url="https://abuseipdb.tmiland.com/abuseipdb.txt"

# IP Set and Chain Names
blocklist_de_set="blocklist-de"
firehol_set="blacklist3"
abuseipdb_set="abuseipdb"

# Download and process IP lists
download_and_process_ip_list "$blocklist_de_url" "$blocklist_de_set" "REJECT"
download_and_process_ip_list "$firehol_url" "$firehol_set" "DROP"   
download_and_process_ip_list "$abuseipdb_url" "$abuseipdb_set" "REJECT"

# Configure iptables chains (if needed)
setup_iptables_chain "$blocklist_de_set" "REJECT"
setup_iptables_chain "$firehol_set" "REJECT"
setup_iptables_chain "$abuseipdb_set" "REJECT"

echo "IP list updates and firewall configuration complete!"
