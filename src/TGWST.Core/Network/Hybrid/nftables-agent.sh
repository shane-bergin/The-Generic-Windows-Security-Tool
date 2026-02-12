#!/bin/bash
# TGWST WSL2 nftables + tcpdump agent
# Runs silently, JSON output to stdout for Windows pipe

set -euo pipefail

LOG="/var/log/tgwst-agent.log"
PIDFILE="/var/run/tgwst-agent.pid"

log() {
    echo "[$(date +'%H:%M:%S')] $*" >> "$LOG"
}

trap 'log "Agent stopped"; rm -f "$PIDFILE"' EXIT

echo $$ > "$PIDFILE"
log "Agent started PID $$"

# Create nftables table/chain
nft delete table ip tgwst 2>/dev/null || true
nft 'add table ip tgwst'
nft 'add chain ip tgwst input { type filter hook input priority 0 \; policy accept \; }'
nft 'add chain ip tgwst output { type filter hook output priority 0 \; policy accept \; }'

# Dynamic block list (JSON input from stdin)
BLOCKLIST=()

while true; do
    # Read JSON block command from stdin (Windows pipe)
    read -r line || continue
    if [[ "$line" == *"block"* ]]; then
        ip=$(echo "$line" | jq -r '.ip // empty')
        if [[ -n "$ip" ]]; then
            nft "add rule ip tgwst output ip daddr $ip drop"
            BLOCKLIST+=("$ip")
            echo "{\"action\":\"blocked\",\"ip\":\"$ip\",\"time\":\"$(date -Iseconds)\"}" 
        fi
    elif [[ "$line" == *"allow"* ]]; then
        ip=$(echo "$line" | jq -r '.ip // empty')
        if [[ -n "$ip" ]]; then
            nft delete rule ip tgwst output handle $(nft -a list chain ip tgwst output | grep "$ip" | awk '{print $NF}' | head -1) 2>/dev/null || true
            echo "{\"action\":\"allowed\",\"ip\":\"$ip\"}"
        fi
    elif [[ "$line" == *"flows"* ]]; then
        # Output current flows JSON
        conntrack=$(conntrack -L -o json | jq '.[] | select(.reply.pkts > 0) | {src: .orig.src, dst: .reply.src, sport: .orig.sport, dport: .reply.dport, bytes: .reply.bytes}')
        echo "{\"flows\": $conntrack}"
    fi
done