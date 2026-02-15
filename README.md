# OpenMix

Self-hosted recipe server for the Vorwerk Thermomix TM6. A right-to-repair project — Vorwerk is sunsetting Cookidoo, and without it the TM6 loses access to all cloud-hosted recipes.

## How it works

**We create our own WiFi network** that the TM6 connects to instead of your home router. This machine runs a WiFi access point (using `hostapd` on the onboard Intel AX210) with its own DHCP and DNS. Because we control the network, we control what the TM6 sees when it tries to reach Vorwerk's servers.

The TM6 boots with a **cleartext HTTP bootstrap** before any TLS connections. During this phase it fetches an infrastructure configuration that tells it where to find its PKI (Certificate Authority, enrollment endpoints) and time server. Because this bootstrap happens over plain HTTP resolved via plain DNS, we can intercept it by spoofing DNS responses on our network to point Vorwerk's domains at our own server.

```
                    Our network (192.168.50.0/24)
                    ┌─────────────────────────────────────────┐
                    │                                         │
TM6 ──WiFi──> wlp7s0 (AP: "TM6-OpenMix")                    │
                    │                                         │
                    ├── dnsmasq: DHCP + DNS (spoofs Vorwerk)  │
                    │                                         │
                    ├── iptables: port 80 → Docker :8080      │
                    │                                         │
                    ├── OpenMix Server (Docker)               │
                    │                                         │
                    └── NAT ──> enxc8a362ba2d6d ──> Internet  │
                                (USB Ethernet)                │
                    └─────────────────────────────────────────┘
```

The TM6 is manually connected to our `TM6-OpenMix` WiFi (via the touchscreen) just like you'd connect it to any home router. It has no idea it's not on a normal network.

## Current status: Stage 1 (cleartext bootstrap)

The OpenMix server currently serves the three cleartext HTTP endpoints the TM6 hits during boot:

| Endpoint | Response |
|----------|----------|
| `GET /.well-known/device-infra-home` | 307 redirect to infrastructure-home |
| `GET /.well-known/infrastructure-home` | HAL+JSON pointing EST/time to our server |
| `GET /time?challenge=<base64>` | PKCS#7 signed time response |

A self-signed CA is auto-generated on first run and stored in `data/ca/`.

## Quick start

```bash
# Build and start the server
docker compose up -d openmix-server

# Verify
curl -s http://localhost:8080/.well-known/infrastructure-home | python3 -m json.tool
```

## Hardware test with a real TM6

See [docs/test-v1.md](docs/test-v1.md) for full instructions. Summary:

```bash
# 1. Start the server
docker compose up -d openmix-server

# 2. Set up WiFi AP + DNS redirect (needs sudo)
sudo ./scripts/setup-ap.sh

# 3. Connect TM6 to "TM6-OpenMix" WiFi

# 4. Watch logs
docker compose logs -f openmix-server
sudo tail -f /var/log/openmix-dns.log

# 5. Teardown
sudo ./scripts/teardown-ap.sh
```

## Project structure

```
openmix/
├── Dockerfile                  # Python 3.11 + tshark + cryptography
├── docker-compose.yml          # openmix (analysis) + openmix-server (bootstrap)
├── scripts/
│   ├── openmix-server.py       # Stage 1 bootstrap server
│   ├── setup-ap.sh             # WiFi AP + DNS redirect setup
│   ├── teardown-ap.sh          # Undo AP setup
│   └── analyze-pcap.sh         # PCAP analysis helper
├── docs/
│   ├── plan.md                 # Master project plan
│   ├── pcap-findings.md        # VARIOT PCAP analysis results
│   ├── mcc-hack-analysis.md    # Monsieur Cuisine Connect reverse engineering notes
│   └── test-v1.md              # Stage 1 hardware test instructions
└── data/                       # (gitignored) PCAPs, CA keys, test logs
```

## Roadmap

1. **Stage 1** (current) — Serve cleartext bootstrap endpoints, test with real TM6
2. **Stage 2** — EST Registration Authority, device certificate enrollment, mutual TLS
3. **Stage 3** — Recipe API, storage, and sync

## Key findings from PCAP analysis

- TM6 uses **plain DNS** (UDP 53) — no DNS-over-HTTPS
- Infrastructure bootstrap is **cleartext HTTP** (port 80)
- TM6 uses **EST (RFC 7030)** for PKI enrollment
- Vorwerk runs a **private PKI** with custom OCSP responders
- All post-bootstrap traffic is **TLS 1.3**
- Full analysis: [docs/pcap-findings.md](docs/pcap-findings.md)

## Documentation

- [Project plan](docs/plan.md) — architecture, attack plan, blocker questions
- [PCAP findings](docs/pcap-findings.md) — TM6 network behavior from VARIOT dataset
- [Hardware test instructions](docs/test-v1.md) — how to run Stage 1 against a real TM6
- [MCC hack analysis](docs/mcc-hack-analysis.md) — Monsieur Cuisine Connect reverse engineering (closest TM6 analog)

## License

This is a right-to-repair research project. Use at your own risk.
