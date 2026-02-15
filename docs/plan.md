# Thermomix TM6 Protocol Reverse Engineering

Right-to-repair project: build a self-hosted recipe server for TM6 before Vorwerk sunsets it.

**Target platform:** Ubuntu 22.04 (always-on network machine)

---

## This Machine

| Component | Detail |
|-----------|--------|
| CPU | Intel i9-13900F — 24 cores / 32 threads, up to 5.6 GHz |
| RAM | 64 GB DDR |
| Disk | 1.4 TB NVMe, ~207 GB free |
| OS | Ubuntu 22.04.5 LTS, kernel 6.8.0-94-generic |
| Primary internet | `enxc8a362ba2d6d` — ASIX AX88179 USB 3.0 Gigabit Ethernet (DHCP, 192.168.4.x) |
| Onboard Ethernet | `eno1` (Realtek RTL8125 2.5GbE) — DOWN, no cable connected |
| WiFi | `wlp7s0` — Intel AX210 (WiFi 6E, 2.4/5/6 GHz), driver: iwlwifi. Currently **soft-blocked** (`rfkill`) |
| Tailscale | Active on `tailscale0` |
| Docker | Running (docker_gwbridge UP) |

### Network interface mapping

The plan below references generic names. Here's what they map to on this machine:

| Plan reference | Actual interface | Notes |
|---------------|-----------------|-------|
| `eth0` (internet uplink) | `enxc8a362ba2d6d` | USB Ethernet — the active internet connection |
| `wlan1` (AP for TM6) | `wlp7s0` | Intel AX210 — must `rfkill unblock wifi` first |

### No USB WiFi adapter needed

The Intel AX210 supports AP mode and the machine already has a separate wired internet uplink via USB Ethernet. The two-NIC requirement (one for internet, one for AP) is already satisfied:

```
Internet <--USB Ethernet--> enxc8a362ba2d6d <--NAT--> wlp7s0 (AP) <--WiFi--> TM6
```

### Pre-installed vs. needed software

| Tool | Status |
|------|--------|
| dnsmasq | Installed (base package only — `dnsmasq-base`) |
| tshark / wireshark | **Not installed** |
| mitmproxy / mitmdump | **Not installed** |
| hostapd | **Not installed** |
| frida-tools | **Not installed** |

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
| Monsieur-Cuisine-Connect-Hack | Full root of Lidl's Thermomix clone — serial protocol docs for motor/heat/scale. **Full analysis: [docs/mcc-hack-analysis.md](mcc-hack-analysis.md)** | https://github.com/EliasKotlyar/Monsieur-Cuisine-Connect-Hack |

### Monsieur Cuisine Connect - key takeaways for TM6

Detailed analysis in `docs/mcc-hack-analysis.md`. The MCC is the closest architectural analog to the TM6 that has been fully reverse-engineered. Key facts:

- **SoC**: MediaTek MT6580 (quad-core Cortex-A7), Android 6.0, 1 GB RAM, 16 GB eMMC
- **Two-chip architecture**: Android tablet SoC talks to a dedicated MCU via serial UART (`/dev/ttyMT0`). The MCU controls motor, heater, scale, thermometer. **The TM6 almost certainly uses the same two-chip pattern.**
- **Serial protocol**: 15-byte fixed-length frames. Header `0x55 0x0F 0xA1`, footer `0xAA`, additive checksum. Commands: motor speed (0-10), temperature level (0-19), motor direction, scale tare/calibration, sleep mode.
- **Root method**: Physical USB debug port under maintenance cover + MediaTek SP Flash Tool. No software exploit needed.
- **Factory test app** (`EnduranceTest`): This was the Rosetta Stone for the serial protocol. The TM6 firmware will have an equivalent test mode.
- **Cloud server**: `mc20.monsieur-cuisine.com`, IP-restricted to Europe. Update manifest at `/666a60bc-0ce2-4878-9e3b-23ba3ceaba5a/versions.txt`.
- **Recipe storage**: SQLite database on device. Newer MC3 model encrypts with SQLCipher (key = MD5 of last 29 chars of SHA-1 APK signature).
- **No custom server built**: Despite full root + documented serial protocol, the community has NOT built a replacement recipe server or local control app. The gap is in software, not in knowledge.

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

### PCAP Analysis Findings (VARIOT normal2 dataset)

Full details in [docs/pcap-findings.md](pcap-findings.md). Key discoveries:

**The TM6 boot sequence is partially cleartext:**

| Step | Protocol | What happens |
|------|----------|-------------|
| 1 | DHCP (cleartext) | Standard DHCP, hostname `thermomix-{last6ofMAC}` |
| 2 | SSDP (cleartext) | UPnP M-SEARCH to `239.255.255.250:1900` every ~20s |
| 3 | DNS (plaintext UDP 53) | **No DNS-over-HTTPS** — DNS spoofing is viable |
| 4 | HTTP (cleartext port 80) | **Infrastructure bootstrap** — fetches `/.well-known/device-infra-home` → 307 → `/.well-known/infrastructure-home` (HAL+JSON with EST endpoints) |
| 5 | HTTP (cleartext port 80) | **Signed time sync** — GET `/time?challenge={base64}` → PKCS#7 signed response |
| 6 | HTTP (cleartext port 80) | **OCSP checks** — certificate revocation checks to Vorwerk's own OCSP responders |
| 7 | HTTP → HTTPS redirect | Device config fetch (content-addressable hash) |
| 8 | TLS 1.3 (port 443) | All remaining traffic: API, auth, recipes, telemetry |

**EST (RFC 7030) PKI bootstrap:**

The infrastructure-home JSON (served over cleartext HTTP!) points the device to its PKI:
- `est-cacerts` — download trusted CA certificates
- `est-simpleenroll` — get a device client certificate
- `est-simplereenroll` — renew the client certificate
- Registration Authority: `tm6-ra.production-eu.cookidoo.vorwerk-digital.com`

**Vorwerk private PKI:**
- Own CA with custom OCSP responders (`server-ca.ocsp.tm-prod.vorwerk-digital.com`, `server-region-ca.ocsp.tm-prod.vorwerk-digital.com`)
- OCSP checks are over cleartext HTTP

**The attack surface:**

Since the infrastructure-home URL is served over plaintext HTTP and resolved via plaintext DNS, we can:
1. Redirect DNS to our server
2. Serve a modified `infrastructure-home` pointing EST to our own CA
3. If the TM6 accepts our CA → we control all TLS trust → full API interception

**The open question:** Does the TM6 validate the EST server's TLS certificate against a firmware-embedded trust anchor, or does it follow whatever the cleartext infrastructure-home JSON tells it? This requires testing with actual hardware.

### Remaining unknowns

- Does the TM6 validate EST server certs against a firmware-embedded root? (requires hardware test)
- On-device protocol for guided cooking commands (temp, speed, time)
- Firmware extraction or modification on TM6
- Exact recipe payload format at the device level

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
# Unblock the WiFi adapter (currently rfkill soft-blocked)
sudo rfkill unblock wifi

# Install missing tools
sudo apt install tshark wireshark hostapd iptables-persistent
pip3 install mitmproxy

# dnsmasq-base is already installed; install the full service wrapper
sudo apt install dnsmasq
```

#### Set up WiFi AP

```bash
# /etc/hostapd/hostapd.conf
interface=wlp7s0         # Intel AX210 (onboard)
driver=nl80211
ssid=TM6-Research
hw_mode=g                # 2.4 GHz — best compatibility with TM6
channel=6
wpa=2
wpa_passphrase=<password>
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
```

```bash
# /etc/dnsmasq.d/tm6-ap.conf (drop-in, keeps system dnsmasq config intact)
interface=wlp7s0
bind-interfaces
dhcp-range=192.168.50.10,192.168.50.100,255.255.255.0,24h
```

```bash
# Assign static IP to AP interface
sudo ip addr add 192.168.50.1/24 dev wlp7s0
```

#### Enable NAT + transparent proxy redirect

```bash
# Enable IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# NAT — route AP traffic out through the USB Ethernet uplink
sudo iptables -t nat -A POSTROUTING -o enxc8a362ba2d6d -j MASQUERADE

# Redirect HTTPS through mitmproxy (transparent mode)
MITMPROXY_PORT=8080
sudo iptables -t nat -A PREROUTING -i wlp7s0 -p tcp --dport 443 -j REDIRECT --to-port $MITMPROXY_PORT
sudo iptables -t nat -A PREROUTING -i wlp7s0 -p tcp --dport 80 -j REDIRECT --to-port $MITMPROXY_PORT
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

### Phase 3: Build the OpenMix Server

**Goal:** A self-contained Docker service that impersonates Vorwerk's infrastructure, step by step.

```
TM6 --WiFi--> Ubuntu AP --DNS--> OpenMix Server (Docker)
                |                    |
                +--USB Ethernet------+---> Internet (for passthrough if needed)
```

#### Stage 1: Basic Connectivity (cleartext bootstrap)

Serve the cleartext HTTP endpoints that the TM6 hits first. No TLS required.

| Endpoint | What to serve |
|----------|--------------|
| `GET /.well-known/device-infra-home` | 307 redirect to our own infrastructure-home |
| `GET /.well-known/infrastructure-home` | HAL+JSON pointing EST to our CA, time to our server |
| `GET /time?challenge={base64}` | PKCS#7 signed time response using our CA key |
| OCSP responder | Valid OCSP responses for our CA's certificates |

#### Stage 2: PKI & Authentication

If Stage 1 proves the TM6 follows our redirected bootstrap:

- Run our own EST Registration Authority (cacerts, simpleenroll, simplereenroll)
- Issue device client certificates from our CA
- Stand up the TLS endpoints the device expects (mutual TLS)
- Implement device auth flow (`login.device.production-eu...`)

#### Stage 3: Recipe Content

Once the device trusts our server and authenticates:

- Reverse-engineer the recipe sync API via mitmproxy
- Build recipe storage (SQLite or filesystem)
- Serve recipes in the TM6's expected format
- Import recipes from Cookidoo exports (cookidump/cookidoo-api)

**Fallback architecture** (if EST redirection fails):

```
Custom Tool --cookidoo-api--> Cookidoo Cloud --sync--> TM6
```

Push recipes through Cookidoo as a relay using the existing API. This is what cookiput already does.

---

## Shopping List

### Hardware needed

- ~~USB WiFi adapter~~ — **not needed**, Intel AX210 onboard + USB Ethernet already provides two NICs
- Optional: old Android phone for app traffic interception + Frida

### Software to install

```bash
# All that's missing (dnsmasq-base already present)
sudo apt install tshark wireshark hostapd dnsmasq iptables-persistent
pip3 install mitmproxy
# Frida (if doing Android interception)
pip3 install frida-tools
```

---

## Key Questions to Answer

### Architecture A blockers (local Cookidoo impersonation)

These must be resolved before building the OpenMix server. If any answer is unfavorable, we fall back to Architecture B (cloud relay via cookidoo-api).

| # | Question | Status | How to answer | Blocks |
|---|----------|--------|---------------|--------|
| A1 | **Does the TM6 accept a redirected PKI bootstrap?** The infrastructure-home JSON is served over cleartext HTTP. If we redirect DNS and serve our own EST CA, does the TM6 trust it? | **PARTIALLY ANSWERED** — PCAP confirms cleartext bootstrap exists. The EST `cacerts` endpoint itself is HTTPS, so the device may validate the EST server's TLS cert against a firmware-embedded root. **Requires hardware test.** | Redirect bootstrap DNS to local server, serve modified infrastructure-home pointing EST to our CA. Observe whether TM6 enrolls. | Everything |
| A2 | **What API endpoints does the TM6 firmware call?** The cookidoo-api documents the Android app's API surface, but the TM6 may hit different or additional endpoints. | **PARTIALLY ANSWERED** — PCAP reveals domains: `es.device.production-eu.cookidoo.vorwerk-digital.com` (device API), `login.device.production-eu.cookidoo.vorwerk-digital.com` (auth), `es.device-usagebox.production-eu.cookidoo.vorwerk-digital.com` (telemetry), plus CDN domains for recipes/assets. Exact API paths are behind TLS. | If A1 passes → full mitmproxy capture. Cross-reference with cookidoo-api. | Server API surface |
| A3 | **What is the exact recipe payload format the TM6 expects?** | OPEN — behind TLS, requires A1. | Capture recipe sync response via mitmproxy. | Recipe storage & serving |
| A4 | **How does the TM6 handle auth tokens?** | **PARTIALLY ANSWERED** — TM6 uses EST client certificates (not just OAuth2). The device enrolls via `est-simpleenroll` to get a client cert. Auth likely uses mutual TLS + OAuth2. | Capture initial connection via mitmproxy (requires A1). | Auth proxy design |
| A5 | **Does the TM6 phone home for license/subscription checks?** | OPEN — requires hardware testing. | Observe traffic with expired subscription. | Subscription handling |

### General research questions

1. ~~Do the VARIOT PCAPs reveal any cleartext traffic or non-standard ports?~~ **ANSWERED: YES** — cleartext HTTP bootstrap, time sync, OCSP. See PCAP findings.
2. ~~Does the TM6 use DNS-over-HTTPS or plain DNS?~~ **ANSWERED: Plain DNS** (UDP port 53). DNS spoofing confirmed viable.
3. What exact SoC is in the TM6? (FCC photos) — OPEN
4. What does the guided cooking recipe format look like at the device level vs the API level? — OPEN
5. Is there a UART/JTAG header on the TM6 PCB? (FCC photos) — OPEN

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
