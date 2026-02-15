#!/bin/bash
set -euo pipefail

# Analyze VARIOT TM6 PCAP captures
# Usage: ./analyze-pcap.sh <pcap_file> [output_dir]

PCAP="${1:?Usage: $0 <pcap_file> [output_dir]}"
OUTDIR="${2:-/openmix/data/analysis}"
mkdir -p "$OUTDIR"

echo "=== TM6 PCAP Analysis ==="
echo "Input:  $PCAP"
echo "Output: $OUTDIR"
echo ""

# 1. Basic stats
echo "--- Capture summary ---"
capinfos "$PCAP" 2>/dev/null | tee "$OUTDIR/capture-summary.txt"
echo ""

# 2. All unique DNS queries — what domains does the TM6 resolve?
echo "--- DNS queries ---"
tshark -r "$PCAP" -Y "dns.qry.name" -T fields -e dns.qry.name 2>/dev/null \
    | sort -u | tee "$OUTDIR/dns-queries.txt"
echo ""

# 3. DNS response IPs — what IPs do those domains resolve to?
echo "--- DNS responses (domain -> IP) ---"
tshark -r "$PCAP" -Y "dns.a" -T fields -e dns.qry.name -e dns.a 2>/dev/null \
    | sort -u | tee "$OUTDIR/dns-responses.txt"
echo ""

# 4. All destination IPs and ports
echo "--- Destination IP:port pairs ---"
tshark -r "$PCAP" -Y "tcp" -T fields -e ip.dst -e tcp.dstport 2>/dev/null \
    | sort -u | tee "$OUTDIR/dst-ip-ports.txt"
echo ""

# 5. TLS SNI (Server Name Indication) — hostnames the TM6 connects to over TLS
echo "--- TLS SNI (server names) ---"
tshark -r "$PCAP" -Y "tls.handshake.type == 1" -T fields \
    -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null \
    | sort -u | tee "$OUTDIR/tls-sni.txt"
echo ""

# 6. TLS versions used in ClientHello
echo "--- TLS versions in ClientHello ---"
tshark -r "$PCAP" -Y "tls.handshake.type == 1" -T fields \
    -e tls.handshake.extensions_server_name \
    -e tls.handshake.version \
    -e tls.handshake.extensions.supported_version 2>/dev/null \
    | sort -u | tee "$OUTDIR/tls-versions.txt"
echo ""

# 7. TLS cipher suites offered — fingerprints the TLS library
echo "--- TLS cipher suites (ClientHello) ---"
tshark -r "$PCAP" -Y "tls.handshake.type == 1" -T fields \
    -e tls.handshake.extensions_server_name \
    -e tls.handshake.ciphersuite 2>/dev/null \
    | sort -u | tee "$OUTDIR/tls-ciphersuites.txt"
echo ""

# 8. JA3 fingerprints — uniquely identifies the TLS client implementation
echo "--- JA3 TLS fingerprints ---"
tshark -r "$PCAP" -Y "tls.handshake.type == 1" -T fields \
    -e ip.src -e tls.handshake.ja3 2>/dev/null \
    | sort -u | tee "$OUTDIR/ja3-fingerprints.txt"
echo ""

# 9. Any cleartext HTTP traffic (not HTTPS)
echo "--- Cleartext HTTP requests ---"
tshark -r "$PCAP" -Y "http.request" -T fields \
    -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri 2>/dev/null \
    | tee "$OUTDIR/http-cleartext.txt"
echo ""

# 10. Non-TCP/UDP protocols (ICMP, mDNS, SSDP, etc.)
echo "--- Non-standard protocols ---"
tshark -r "$PCAP" -T fields -e frame.protocols 2>/dev/null \
    | tr ':' '\n' | sort -u | tee "$OUTDIR/protocols.txt"
echo ""

# 11. All unique source IPs — identify the TM6's IP
echo "--- Source IPs ---"
tshark -r "$PCAP" -T fields -e ip.src 2>/dev/null \
    | sort -u | tee "$OUTDIR/source-ips.txt"
echo ""

# 12. DHCP — TM6 hostname and MAC
echo "--- DHCP info ---"
tshark -r "$PCAP" -Y "dhcp" -T fields \
    -e dhcp.hw.mac_addr -e dhcp.option.hostname -e dhcp.option.vendor_class_id 2>/dev/null \
    | sort -u | tee "$OUTDIR/dhcp-info.txt"
echo ""

# 13. mDNS / SSDP / UPnP — local service discovery
echo "--- mDNS / SSDP ---"
tshark -r "$PCAP" -Y "mdns || ssdp" -T fields \
    -e ip.src -e dns.qry.name -e http.request.uri 2>/dev/null \
    | sort -u | tee "$OUTDIR/mdns-ssdp.txt"
echo ""

# 14. NTP — time sync servers
echo "--- NTP servers ---"
tshark -r "$PCAP" -Y "ntp" -T fields -e ip.dst 2>/dev/null \
    | sort -u | tee "$OUTDIR/ntp-servers.txt"
echo ""

# 15. TLS certificate info from ServerHello (issuer, subject, validity)
echo "--- TLS server certificates ---"
tshark -r "$PCAP" -Y "tls.handshake.type == 11" -T fields \
    -e tls.handshake.extensions_server_name \
    -e x509sat.uTF8String \
    -e x509ce.dNSName 2>/dev/null \
    | sort -u | tee "$OUTDIR/tls-server-certs.txt"
echo ""

echo "=== Analysis complete. Results in $OUTDIR ==="
ls -la "$OUTDIR"
