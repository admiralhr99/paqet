#!/bin/bash
# dpi-evasion-iptables.sh — iptables-based DPI evasion for kernel TCP mode
#
# Run on the CLIENT (Iran VPS) to fragment the TLS ClientHello and
# evade first-packet DPI inspection.
#
# Usage: ./dpi-evasion-iptables.sh <server_ip> <server_port>
# Example: ./dpi-evasion-iptables.sh 45.140.43.136 11000

SERVER_IP="$1"
SERVER_PORT="$2"

if [ -z "$SERVER_IP" ] || [ -z "$SERVER_PORT" ]; then
    echo "Usage: $0 <server_ip> <server_port>"
    echo ""
    echo "  server_ip    IP address of the remote paqet server"
    echo "  server_port  Port of the remote paqet server"
    echo ""
    echo "This script fragments outgoing TCP SYN packets to the server,"
    echo "splitting the TLS ClientHello across multiple segments to evade"
    echo "DPI systems that only inspect the first packet/segment."
    exit 1
fi

echo "Setting up DPI evasion iptables rules for $SERVER_IP:$SERVER_PORT"

# Clean existing rules
iptables -t mangle -D POSTROUTING -p tcp -d "$SERVER_IP" --dport "$SERVER_PORT" \
    --tcp-flags SYN,ACK SYN -j TCPMSS --set-mss 40 2>/dev/null
iptables -t mangle -D POSTROUTING -p tcp -d "$SERVER_IP" --dport "$SERVER_PORT" \
    -j TTL --ttl-set 64 2>/dev/null

# Fragment outgoing SYN+data packets to server
# Setting MSS to 40 forces the TLS ClientHello to be split across
# multiple TCP segments, defeating DPI that only checks the first segment.
iptables -t mangle -A POSTROUTING -p tcp -d "$SERVER_IP" --dport "$SERVER_PORT" \
    --tcp-flags SYN,ACK SYN -j TCPMSS --set-mss 40

# Normalize TTL to 64 (Linux default) to avoid TTL-based fingerprinting
iptables -t mangle -A POSTROUTING -p tcp -d "$SERVER_IP" --dport "$SERVER_PORT" \
    -j TTL --ttl-set 64

echo "DPI evasion rules applied."
echo ""
echo "To remove rules:"
echo "  iptables -t mangle -D POSTROUTING -p tcp -d $SERVER_IP --dport $SERVER_PORT --tcp-flags SYN,ACK SYN -j TCPMSS --set-mss 40"
echo "  iptables -t mangle -D POSTROUTING -p tcp -d $SERVER_IP --dport $SERVER_PORT -j TTL --ttl-set 64"
