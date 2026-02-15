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

**Goal:** Full transparent MITM between TM6 and Vorwerk, then progressively replace Vorwerk's endpoints with our own.

```
TM6 --WiFi--> Our AP (wlp7s0) --iptables--> mitmproxy --USB Ethernet--> Vorwerk
                                                  ↓
                                           logs everything to disk
```

Each stage has a **feasibility gate** — a concrete yes/no test. If a gate fails, we find another way through. No point building Stage 3 until Stage 2 passes.

---

#### Stage 0: AP connectivity

Create our own WiFi network. Connect TM6. Verify it can reach the internet through us.

**What we build:** `setup-ap.sh` (hostapd + dnsmasq + NAT + iptables)

**Test:** TM6 connects to `TM6-OpenMix` WiFi, gets a DHCP lease, and can function normally (recipes load, sync works). We see DNS queries in `dnsmasq` logs.

> **GATE 0: Does the TM6 connect to our AP and work normally?**
>
> - **PASS →** We control the network. Proceed to Stage 1.
> - **FAIL →** TM6 refuses to connect, or connects but can't reach Vorwerk. Debug AP/NAT/DNS config. This is a setup issue, not a fundamental blocker.

---

#### Stage 1: HTTP passthrough + protocol capture

Spoof DNS for Vorwerk's cleartext HTTP domains only. Proxy all HTTP requests to real Vorwerk, log full request+response. HTTPS goes directly to Vorwerk via NAT (we don't touch it yet).

**What we build:** `openmix-server.py --mode passthrough`

**What we learn:** The complete cleartext HTTP protocol — bootstrap sequence, infrastructure-home JSON, time sync, OCSP, redirects. This runs as long as needed (days/weeks) to build confidence in the protocol.

> **GATE 1: Does the TM6 complete its cleartext HTTP bootstrap through our proxy?**
>
> - **PASS →** We have the full HTTP protocol captured. The TM6 doesn't care that HTTP went through a proxy. Proceed to Stage 2.
> - **FAIL →** TM6 detects the proxy (e.g. timing, missing headers, different response size). Fix the proxy to be more transparent. This is unlikely for cleartext HTTP but possible.

---

#### Stage 2: Bootstrap hijack — can we control the PKI?

This is the **make-or-break gate** for the entire MITM approach. Switch to hijack mode: serve our own `infrastructure-home` JSON pointing EST to our CA. Everything else still proxied to real Vorwerk.

**What we build:** `openmix-server.py --mode hijack`

**What we test:** Does the TM6 follow our modified infrastructure-home and attempt to connect to our EST server? Two sub-questions:

1. Does the TM6 accept our modified `infrastructure-home` JSON? (It might validate a signature on the bootstrap response itself.)
2. Does the TM6 connect to our EST endpoint? (It might validate the EST server's TLS cert against a firmware-embedded root.)

> **GATE 2: Does the TM6 accept our CA via the redirected EST bootstrap?**
>
> - **PASS →** We are the TM6's Certificate Authority. We can issue certs it trusts. Proceed to Stage 3. **This unlocks everything.**
> - **FAIL (2a): TM6 rejects our infrastructure-home** → The bootstrap response may be signed or integrity-checked. Investigate the PKCS#7 time response format — maybe the infrastructure-home is also signed and we need to replay or forge a valid signature. Find a way through.
> - **FAIL (2b): TM6 connects to our EST but rejects our TLS cert** → There is a firmware-embedded trust anchor for the EST RA. Next steps: firmware extraction (JTAG/UART from FCC photos), locate the embedded root cert, replace it or find another way to inject our CA.

---

#### Stage 3: Full MITM — transparent proxy for all traffic

We are the CA. Now run mitmproxy in transparent mode with our CA for **all** traffic — HTTP and HTTPS. The TM6 operates normally (connects to "Vorwerk" which is actually us proxying to real Vorwerk), and we log everything.

**What we build:** mitmproxy addon that hijacks bootstrap + transparently proxies all HTTPS

**What this gives us:**
- Every API endpoint, request, and response — including recipes, auth, config, telemetry
- Recipe payloads captured automatically as the family uses the TM6
- Full protocol documentation built up over weeks/months of normal use
- A complete local archive of every recipe accessed

> **GATE 3: Does the TM6 function normally through our full MITM proxy?**
>
> - **PASS →** Long-term operation begins. Leave it running for months. Proceed to Stage 4 when we have enough data.
> - **FAIL →** Some HTTPS endpoints use additional pinning or mutual TLS that mitmproxy can't handle. Identify which endpoints fail and proxy those directly (bypass MITM for those specific hosts). We may still capture most traffic.

---

#### Stage 4: Replace Vorwerk — standalone OpenMix server

With months of captured traffic, we know the full protocol. Build a standalone server that doesn't proxy to Vorwerk at all.

- Serve recipes from local storage (SQLite)
- Handle auth locally (issue our own tokens)
- Respond to all API endpoints the TM6 expects
- Import recipes from captures + cookidoo-api exports

> **GATE 4: Does the TM6 function with zero Vorwerk connectivity?**
>
> - **PASS →** OpenMix is complete. The TM6 works entirely offline against our server. Vorwerk can sunset Cookidoo and it doesn't matter.
> - **FAIL →** Some functionality requires real Vorwerk (e.g. firmware updates, subscription validation). Document what breaks and decide what to stub out.

---

#### Feasibility summary

```
Gate 0: AP connectivity          → setup issue, always fixable
Gate 1: HTTP passthrough         → very likely to pass (cleartext, no validation)
Gate 2: EST bootstrap hijack     → THE BIG UNKNOWN — determines entire approach
Gate 3: Full MITM works          → likely if Gate 2 passes
Gate 4: Standalone server        → engineering effort, no unknown blockers
```

**If Gate 2 fails**, we dig deeper — firmware extraction, embedded cert replacement, or other attack vectors. The goal is full device MITM, period.

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

### Architecture A blockers → now tracked as feasibility gates

All blocker questions are now embedded in the Phase 3 gate structure above. The critical unknown is **Gate 2** (EST bootstrap hijack). Everything else is either answered by PCAP analysis or becomes answerable once Gate 2 passes.

| Old blocker | Status | Where it's tracked |
|-------------|--------|-------------------|
| A1: Does TM6 accept redirected PKI? | **Gate 2** — the make-or-break test | Phase 3, Stage 2 |
| A2: What API endpoints? | Answered once Gate 3 passes (full MITM) | Phase 3, Stage 3 |
| A3: Recipe payload format? | Answered once Gate 3 passes (full MITM) | Phase 3, Stage 3 |
| A4: Auth tokens? | Partially answered (EST client certs). Full answer from Gate 3 | Phase 3, Stage 3 |
| A5: Subscription checks? | Answered once Gate 3 passes (full MITM) | Phase 3, Stage 4 |

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
