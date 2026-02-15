#!/bin/bash
set -euo pipefail

# Undo everything setup-ap.sh did.
# Run as: sudo ./scripts/teardown-ap.sh

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo $0"
    exit 1
fi

AP_INTERFACE="wlp7s0"
UPLINK_INTERFACE="enxc8a362ba2d6d"

echo "=== OpenMix AP Teardown ==="

# Stop hostapd
killall hostapd 2>/dev/null || true
echo "hostapd stopped"

# Stop dnsmasq and remove our config
systemctl stop dnsmasq 2>/dev/null || true
rm -f /etc/dnsmasq.d/openmix.conf
echo "dnsmasq stopped, config removed"

# Remove iptables rules
iptables -t nat -D POSTROUTING -o "$UPLINK_INTERFACE" -j MASQUERADE 2>/dev/null || true
iptables -t nat -D PREROUTING -i "$AP_INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null || true
echo "iptables rules removed"

# Bring down AP interface
ip addr flush dev "$AP_INTERFACE" 2>/dev/null || true
ip link set "$AP_INTERFACE" down 2>/dev/null || true
echo "Interface $AP_INTERFACE down"

# Re-enable NetworkManager control if applicable
if command -v nmcli &>/dev/null; then
    nmcli device set "$AP_INTERFACE" managed yes 2>/dev/null || true
fi

echo ""
echo "AP teardown complete. WiFi is still unblocked."
echo "To re-block: sudo rfkill block wifi"
