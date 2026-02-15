#!/bin/bash
set -euo pipefail

# OpenMix WiFi AP Setup
# Run as: sudo ./scripts/setup-ap.sh
#
# Creates a WiFi access point on wlp7s0 that the TM6 connects to.
# DNS is overridden to redirect Vorwerk's bootstrap domains to the
# OpenMix server running in Docker on port 8080.
#
# Network topology:
#   Internet <--USB Ethernet--> enxc8a362ba2d6d <--NAT--> wlp7s0 (AP) <--WiFi--> TM6

if [ "$EUID" -ne 0 ]; then
    echo "Run as root: sudo $0"
    exit 1
fi

# --- Configuration ---
AP_INTERFACE="wlp7s0"
UPLINK_INTERFACE="enxc8a362ba2d6d"
AP_IP="192.168.50.1"
AP_SUBNET="255.255.255.0"
DHCP_RANGE_START="192.168.50.10"
DHCP_RANGE_END="192.168.50.100"
AP_SSID="TM6-OpenMix"
AP_PASSWORD="openmix2026"
AP_CHANNEL=6

# The OpenMix Docker server is on the host at port 8080.
# dnsmasq redirects Vorwerk domains to AP_IP, and the TM6
# connects on port 80. We use iptables to redirect port 80
# traffic arriving on the AP interface to Docker's port 8080.
OPENMIX_PORT=8080

echo "=== OpenMix AP Setup ==="
echo ""
echo "AP interface:     $AP_INTERFACE"
echo "Uplink interface: $UPLINK_INTERFACE"
echo "AP IP:            $AP_IP"
echo "SSID:             $AP_SSID"
echo ""

# --- Step 1: Install dependencies ---
echo "--- Step 1: Installing dependencies ---"
apt-get update -qq
apt-get install -y -qq hostapd dnsmasq iw > /dev/null
echo "Installed: hostapd, dnsmasq, iw"

# --- Step 2: Unblock WiFi ---
echo "--- Step 2: Unblocking WiFi ---"
rfkill unblock wifi
sleep 1
echo "WiFi unblocked"

# --- Step 3: Verify AP mode support ---
echo "--- Step 3: Checking AP mode support ---"
if iw list | grep -q "* AP"; then
    echo "AP mode: supported"
else
    echo "ERROR: $AP_INTERFACE does not support AP mode!"
    exit 1
fi

# --- Step 4: Stop conflicting services ---
echo "--- Step 4: Stopping conflicting services ---"
systemctl stop hostapd 2>/dev/null || true
systemctl stop dnsmasq 2>/dev/null || true
# Kill any existing wpa_supplicant on this interface
killall wpa_supplicant 2>/dev/null || true
# Remove NetworkManager control of this interface if applicable
if command -v nmcli &>/dev/null; then
    nmcli device set "$AP_INTERFACE" managed no 2>/dev/null || true
fi
echo "Conflicting services stopped"

# --- Step 5: Configure the AP interface ---
echo "--- Step 5: Configuring $AP_INTERFACE ---"
ip link set "$AP_INTERFACE" down
ip addr flush dev "$AP_INTERFACE"
ip addr add "$AP_IP/24" dev "$AP_INTERFACE"
ip link set "$AP_INTERFACE" up
sleep 1
echo "Interface up with IP $AP_IP"

# --- Step 6: Write hostapd config ---
echo "--- Step 6: Writing hostapd config ---"
cat > /etc/hostapd/openmix.conf << EOF
interface=$AP_INTERFACE
driver=nl80211
ssid=$AP_SSID
hw_mode=g
channel=$AP_CHANNEL
wpa=2
wpa_passphrase=$AP_PASSWORD
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
# Disable 802.11n/ac for max TM6 compatibility
wmm_enabled=0
EOF
echo "hostapd config written to /etc/hostapd/openmix.conf"

# --- Step 7: Write dnsmasq config ---
echo "--- Step 7: Writing dnsmasq config ---"

# Vorwerk domains to redirect (from PCAP analysis).
# These cover all locale variants — the TM6 resolves these
# during its cleartext HTTP bootstrap.
cat > /etc/dnsmasq.d/openmix.conf << EOF
# OpenMix: only listen on the AP interface
interface=$AP_INTERFACE
bind-interfaces

# DHCP for TM6
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,$AP_SUBNET,24h

# Point the TM6 at ourselves for DNS
dhcp-option=6,$AP_IP

# Log all DNS queries (useful for discovering new domains)
log-queries
log-facility=/var/log/openmix-dns.log

# --- Vorwerk bootstrap domains (cleartext HTTP, port 80) ---
# These are the domains the TM6 resolves during boot.
# Redirect them all to the OpenMix server.

# Bootstrap (the critical ones — cleartext HTTP)
address=/nwot-plain.vorwerk-digital.com/$AP_IP
address=/plain.production-eu.cookidoo.vorwerk-digital.com/$AP_IP

# OCSP (cleartext HTTP)
address=/server-ca.ocsp.tm-prod.vorwerk-digital.com/$AP_IP
address=/server-region-ca.ocsp.tm-prod.vorwerk-digital.com/$AP_IP

# EST Registration Authority (HTTPS — Stage 2)
address=/tm6-ra.production-eu.cookidoo.vorwerk-digital.com/$AP_IP

# Device API (HTTPS — Stage 2/3)
address=/device.production-eu.cookidoo.vorwerk-digital.com/$AP_IP
address=/nwot.vorwerk-digital.com/$AP_IP

# CDN (HTTPS — Stage 3, can skip initially)
#address=/recipepublic-device.prod.external.eu-tm-prod.vorwerk-digital.com/$AP_IP
#address=/patternlib-all.prod.external.eu-tm-prod.vorwerk-digital.com/$AP_IP
#address=/assets.tmecosys.com/$AP_IP
EOF
echo "dnsmasq config written to /etc/dnsmasq.d/openmix.conf"

# --- Step 8: Enable IP forwarding and NAT ---
echo "--- Step 8: Setting up NAT ---"
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# Flush existing rules for our interfaces (avoid duplicates on re-run)
iptables -t nat -D POSTROUTING -o "$UPLINK_INTERFACE" -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -o "$UPLINK_INTERFACE" -j MASQUERADE

# Redirect port 80 on the AP interface to Docker's port 8080 on localhost.
# This way the TM6 hits port 80 (as it expects) and we forward to Docker.
iptables -t nat -D PREROUTING -i "$AP_INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port "$OPENMIX_PORT" 2>/dev/null || true
iptables -t nat -A PREROUTING -i "$AP_INTERFACE" -p tcp --dport 80 -j REDIRECT --to-port "$OPENMIX_PORT"
echo "NAT enabled: $AP_INTERFACE -> $UPLINK_INTERFACE, port 80 -> $OPENMIX_PORT"

# --- Step 9: Start services ---
echo "--- Step 9: Starting services ---"
systemctl restart dnsmasq
hostapd -B /etc/hostapd/openmix.conf
sleep 2

# Verify
if hostapd_cli status 2>/dev/null | grep -q "state=ENABLED"; then
    echo "hostapd: RUNNING"
else
    echo "hostapd: checking..."
    hostapd_cli status 2>/dev/null || echo "(hostapd_cli not responsive yet — check 'journalctl -u hostapd')"
fi

if systemctl is-active --quiet dnsmasq; then
    echo "dnsmasq: RUNNING"
else
    echo "dnsmasq: FAILED — check 'journalctl -u dnsmasq'"
fi

echo ""
echo "=== AP Setup Complete ==="
echo ""
echo "SSID:     $AP_SSID"
echo "Password: $AP_PASSWORD"
echo "AP IP:    $AP_IP"
echo ""
echo "Next steps:"
echo "  1. Make sure the OpenMix server is running:"
echo "     cd $(dirname "$0")/.. && docker compose up -d openmix-server"
echo "  2. Connect TM6 to WiFi network '$AP_SSID'"
echo "  3. Watch the server logs:"
echo "     docker compose logs -f openmix-server"
echo "  4. Watch DNS queries:"
echo "     tail -f /var/log/openmix-dns.log"
echo ""
