#!/bin/bash
# nfqueue-setup.sh — Set up iptables rules for NFQUEUE transport mode
#
# Usage: ./nfqueue-setup.sh <server_ip> <server_port> [out_queue] [in_queue]
# Example: ./nfqueue-setup.sh 45.140.43.136 11000 100 101

SERVER_IP="$1"
SERVER_PORT="$2"
OUT_QUEUE="${3:-100}"
IN_QUEUE="${4:-101}"

if [ -z "$SERVER_IP" ] || [ -z "$SERVER_PORT" ]; then
    echo "Usage: $0 <server_ip> <server_port> [out_queue] [in_queue]"
    echo ""
    echo "  server_ip    IP address of the remote paqet server"
    echo "  server_port  Port of the remote paqet server"
    echo "  out_queue    NFQUEUE number for outgoing packets (default: 100)"
    echo "  in_queue     NFQUEUE number for incoming packets (default: 101)"
    exit 1
fi

echo "Setting up NFQUEUE rules for $SERVER_IP:$SERVER_PORT"
echo "  Outgoing queue: $OUT_QUEUE"
echo "  Incoming queue: $IN_QUEUE"

# Clean existing rules (ignore errors if rules don't exist)
iptables -D OUTPUT -p tcp -d "$SERVER_IP" --dport "$SERVER_PORT" -j NFQUEUE --queue-num "$OUT_QUEUE" 2>/dev/null
iptables -D INPUT -p tcp -s "$SERVER_IP" --sport "$SERVER_PORT" -j NFQUEUE --queue-num "$IN_QUEUE" 2>/dev/null

# Add NFQUEUE rules
iptables -A OUTPUT -p tcp -d "$SERVER_IP" --dport "$SERVER_PORT" -j NFQUEUE --queue-num "$OUT_QUEUE"
iptables -A INPUT -p tcp -s "$SERVER_IP" --sport "$SERVER_PORT" -j NFQUEUE --queue-num "$IN_QUEUE"

echo "NFQUEUE rules applied successfully."
echo ""
echo "To remove rules:"
echo "  iptables -D OUTPUT -p tcp -d $SERVER_IP --dport $SERVER_PORT -j NFQUEUE --queue-num $OUT_QUEUE"
echo "  iptables -D INPUT -p tcp -s $SERVER_IP --sport $SERVER_PORT -j NFQUEUE --queue-num $IN_QUEUE"
