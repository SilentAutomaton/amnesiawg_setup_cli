#!/bin/bash
# Runs inside the container. /etc/awg is the bind-mounted config directory.
set -eu

conf=/etc/awg/awg0.conf
iface=awg0
outbound=$(ip route show default | awk '{print $5; exit}')

# A restarted container may still have the interface from the previous run.
awg-quick down "$conf" 2>/dev/null || true
awg-quick up "$conf"

iptables -A INPUT -i "$iface" -j ACCEPT
iptables -A FORWARD -i "$iface" -j ACCEPT
iptables -A OUTPUT -o "$iface" -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s "$AWG_SUBNET" -o "$outbound" -j MASQUERADE

exec tail -f /dev/null
