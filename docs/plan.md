# Thermomix TM6 Protocol Reverse Engineering

Right-to-repair project: build a self-hosted recipe server for TM6 before Vorwerk sunsets it.

**Target platform:** Ubuntu 22.04 (always-on network machine)

---

## Current State of Knowledge

### What the community has cracked

All existing work operates at the **Cookidoo cloud API level** — nobody has replaced Cookidoo with a self-hosted server or documented the TM6's on-device protocol.

| Project | What it does | URL |
|---------|-------------|-----|
| cookidoo-api | Async Python client for Cookidoo backend (reverse-engineered from Android app traffic). Integrated into Home Assistant since 2025.1 | https://github.com/miaucl/cookidoo-api |
| cookiput | Push custom recipes via Cookidoo's `created-recipes` endpoint | https://github.com/croeer/cookiput |
| cookidump | Bulk export recipes as JSON | https://github.com/auino/cookidump |
| cookidoo-scraper | REST API over Cookidoo website via Puppeteer | https://github.com/tobim-dev/cookidoo-scraper |
| mcp-cookidoo | MCP server wrapping cookidoo-api | https://github.com/alexandrepa/mcp-cookidoo |
| Monsieur-Cuisine-Connect-Hack | Full root of Lidl's Thermomix clone — serial protocol docs for motor/heat/scale | https://github.com/EliasKotlyar/Monsieur-Cuisine-Connect-Hack |

### What's known about TM6 networking

- WiFi: 802.11 b/g/n, 2.4 GHz + 5.2 GHz, WPA/WPA2
- IPv4 only, DHCP only — no manual IP, no manual DNS, no proxy config
- Connects to regional Cookidoo domains (cookidoo.thermomix.com, cookidoo.de, etc.)
- Syncs recipes on power-on; cached recipes work offline for 30 days
- Auth: OAuth2 JWT (`_oauth2_proxy` cookie)
- No real-time device status exposed to the cloud API

### Recipe creation API (from cookiput)

```
POST   /created-recipes/{locale}              {"recipeName": "..."}
PATCH  /created-recipes/{locale}/{recipeId}    {"ingredients": [...]}
PATCH  /created-recipes/{locale}/{recipeId}    {"instructions": [...]}
PATCH  /created-recipes/{locale}/{recipeId}    {"tools": ["TM6"], "totalTime": 4200, ...}
```

Times in seconds. Locale is `de-DE`, `en-US`, etc.

### Hardware

- FCC ID: 2AGELTM65 — internal photos at https://fccid.io/2AGELTM65/Internal-Photos/Internal-photographs-4403836
- Likely quad-core ARM SoC, Linux-based
- Synacktiv published TM5 exploit research (Jan 2026) but explicitly did NOT evaluate TM6/TM7: https://www.synacktiv.com/en/publications/let-me-cook-you-a-vulnerability-exploiting-the-thermomix-tm5

### Unknown / uncracked

- TM6 TLS certificate pinning behavior
- On-device protocol for guided cooking commands (temp, speed, time)
- Firmware extraction or modification on TM6
- Whether any unencrypted channels exist

---

## Attack Plan

### Phase 1: Passive Intelligence (no TM6 needed)

#### 1a. Analyze VARIOT PCAP datasets

A Spanish university (Universidad de Mondragon) published real TM6 network captures under CC BY 4.0:

- Normal traffic: https://datos.gob.es/en/catalogo/pudat0001-seguridad-iot-trafico-de-red-en-condiciones-de-normalidad-2-vorwerk-thermomix-tm6
  - Download: `https://iot.danz.eus/vorwerk-Thermomix-TM6-normal2`
- Compromised traffic: https://datos.gob.es/en/catalogo/pudat0001-seguridad-iot-trafico-de-red-en-condiciones-comprometidas-vorwerk-thermomix-tm6

**Goal:** Extract destination domains, ports, TLS versions, connection patterns, any cleartext channels.

```bash
# On Ubuntu 22.04
sudo apt install tshark wireshark
wget https://iot.danz.eus/vorwerk-Thermomix-TM6-normal2 -O tm6-normal.tar.gz
tar xzf tm6-normal.tar.gz

# Quick analysis
tshark -r <pcap_file> -Y "dns" -T fields -e dns.qry.name | sort -u
tshark -r <pcap_file> -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name | sort -u
tshark -r <pcap_file> -Y "tcp" -T fields -e ip.dst -e tcp.dstport | sort -u
```

#### 1b. Clone and map cookidoo-api

```bash
git clone https://github.com/miaucl/cookidoo-api.git
# Read docs/raw-api-requests/ for intercepted traffic
# Map every endpoint, auth flow, request/response schema
```

#### 1c. Examine FCC internal photos

Download from https://fccid.io/2AGELTM65/Internal-Photos/Internal-photographs-4403836 and identify the SoC, WiFi chipset, flash storage. This determines what firmware extraction techniques are possible.

---

### Phase 2: Active Traffic Capture (Ubuntu 22.04)

#### Prerequisites

```bash
# Install mitmproxy
sudo apt install python3-pip
pip3 install mitmproxy

# Install hostapd + dnsmasq for WiFi AP
sudo apt install hostapd dnsmasq

# Need a USB WiFi adapter that supports AP mode (e.g. Alfa AWUS036ACM)
# The machine's built-in NIC stays on the LAN for internet
```

#### Set up WiFi AP

```bash
# /etc/hostapd/hostapd.conf
interface=wlan1          # USB WiFi adapter
driver=nl80211
ssid=TM6-Research
hw_mode=g
channel=6
wpa=2
wpa_passphrase=<password>
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
```

```bash
# /etc/dnsmasq.conf (for the AP interface only)
interface=wlan1
dhcp-range=192.168.50.10,192.168.50.100,255.255.255.0,24h
```

#### Enable NAT + transparent proxy redirect

```bash
# Enable IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# NAT for internet access
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Redirect HTTPS through mitmproxy (transparent mode)
MITMPROXY_PORT=8080
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 443 -j REDIRECT --to-port $MITMPROXY_PORT
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 -j REDIRECT --to-port $MITMPROXY_PORT
```

#### Run mitmproxy in transparent mode

```bash
mitmproxy --mode transparent --showhost --set block_global=false
# or for logging:
mitmdump --mode transparent --showhost -w tm6_capture.flow
```

#### Connect TM6 to the AP

Point TM6 WiFi settings at `TM6-Research` network. If it connects and traffic flows — no cert pinning (unlikely but possible). If it refuses to sync — cert pinning is active.

#### If cert pinning is active (likely)

Options:
1. **DNS-level analysis only** — even with pinning, DNS queries may be cleartext (check PCAP first). Configure dnsmasq to log all queries.
2. **SSLstrip-style downgrade** — unlikely to work on modern TLS but worth trying.
3. **Intercept the Android app instead** — root an old phone, install custom CA, use Frida for cert pinning bypass. This is how cookidoo-api was built and remains the most proven approach.
4. **Firmware extraction** — if FCC photos reveal a standard SoC with accessible flash, dump firmware via JTAG/UART and replace pinned certs. This is the nuclear option.

---

### Phase 3: Build the Recipe Server

**Goal:** A local proxy that the TM6 thinks is Cookidoo.

Architecture (depends on Phase 2 findings):

```
TM6 --WiFi--> Ubuntu AP --DNS override--> Local Recipe Server
                                |
                                +--> Real Cookidoo (for auth, passthrough)
```

- DNS spoofing: resolve cookidoo.*.com to local IP
- Local server mimics Cookidoo's API surface
- Serves custom recipes in the format TM6 expects
- Proxies auth and subscription checks to real Cookidoo
- Caches/stores recipes locally for when Vorwerk pulls the plug

**Fallback architecture** (if on-device protocol is too locked down):

```
Custom Tool --cookidoo-api--> Cookidoo Cloud --sync--> TM6
```

Less interesting but functional: push recipes through Cookidoo as a relay using the existing API. This is what cookiput already does.

---

## Shopping List

### Hardware needed

- USB WiFi adapter with AP mode support (e.g. Alfa AWUS036ACM, ~$35)
  - Check the Ubuntu machine — if it has two NICs (eth + wlan) you might not need this
- Optional: old Android phone for app traffic interception + Frida

### Software (Ubuntu 22.04)

```bash
sudo apt install tshark wireshark hostapd dnsmasq iptables-persistent
pip3 install mitmproxy
# Frida (if doing Android interception)
pip3 install frida-tools
```

---

## Key Questions to Answer

1. Do the VARIOT PCAPs reveal any cleartext traffic or non-standard ports?
2. Does the TM6 use DNS-over-HTTPS or plain DNS? (if plain, we get domain intel even with TLS pinning)
3. What exact SoC is in the TM6? (FCC photos)
4. Does the TM6 verify server certificates (pinning) or just use standard CA validation?
5. What does the guided cooking recipe format look like at the device level vs the API level?
6. Is there a UART/JTAG header on the TM6 PCB? (FCC photos)

---

## References

- cookidoo-api: https://github.com/miaucl/cookidoo-api
- cookiput: https://github.com/croeer/cookiput
- cookidump: https://github.com/auino/cookidump
- cookidoo-scraper: https://github.com/tobim-dev/cookidoo-scraper
- mcp-cookidoo: https://github.com/alexandrepa/mcp-cookidoo
- Monsieur Cuisine hack: https://github.com/EliasKotlyar/Monsieur-Cuisine-Connect-Hack
- Synacktiv TM5 research: https://www.synacktiv.com/en/publications/let-me-cook-you-a-vulnerability-exploiting-the-thermomix-tm5
- FCC TM6 internal photos: https://fccid.io/2AGELTM65/Internal-Photos/Internal-photographs-4403836
- VARIOT TM6 traffic (normal): https://datos.gob.es/en/catalogo/pudat0001-seguridad-iot-trafico-de-red-en-condiciones-de-normalidad-2-vorwerk-thermomix-tm6
- VARIOT TM6 traffic (compromised): https://datos.gob.es/en/catalogo/pudat0001-seguridad-iot-trafico-de-red-en-condiciones-comprometidas-vorwerk-thermomix-tm6
- Home Assistant Cookidoo integration: https://www.home-assistant.io/integrations/cookidoo/
- HA community thread (1000+ posts): https://community.home-assistant.io/t/thermomix-tm6-possible-support/375539
- EEVblog TM6 thread: https://www.eevblog.com/forum/cooking/for-the-tech-geeks-thermomix-tm6/10/
- iFixit TM5 teardown: https://www.ifixit.com/Teardown/Thermomix+TM5+Teardown/117133
