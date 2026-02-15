# OpenMix Stage 1 — Hardware Test Instructions

## What this does

This test creates **a separate WiFi network** on this machine that the TM6 connects to. We are not intercepting traffic on your home network — we are building our own network from scratch with its own DHCP, DNS, and HTTP server. The TM6 is manually pointed at this network via its touchscreen WiFi settings, just like connecting it to any router.

Because we control the entire network (DNS, routing, HTTP), when the TM6 tries to reach Vorwerk's servers during its boot sequence, our DNS responds with our own IP address and our server handles the requests instead of Vorwerk's.

```
                    Our network (192.168.50.0/24)
                    ┌─────────────────────────────────────────┐
TM6 ──WiFi──> wlp7s0 (AP: "TM6-OpenMix")                    │
                    ├── dnsmasq: DHCP + spoofed DNS           │
                    ├── iptables: port 80 → Docker :8080      │
                    ├── OpenMix Server (Docker)               │
                    └── NAT ──> USB Ethernet ──> Internet     │
                    └─────────────────────────────────────────┘
```

## Prerequisites

- OpenMix server Docker container built (`docker compose build openmix-server`)
- TM6 device powered on and ready to connect to WiFi
- **WiFi AP mode**: The Intel AX210 (`wlp7s0`) supports AP mode — this is a documented capability of the `iwlwifi` driver. The setup script verifies this at runtime via `iw list`.

## Step 1: Start the OpenMix server

```bash
cd ~/sambashare/expts/openmix
docker compose up -d openmix-server
```

Verify it's running:

```bash
curl -s http://localhost:8080/.well-known/infrastructure-home | python3 -m json.tool
```

You should see the HAL+JSON with EST endpoints pointing to `192.168.50.1`.

## Step 2: Create the WiFi network

This creates a completely separate WiFi network on this machine. Your home network is not affected.

```bash
sudo ./scripts/setup-ap.sh
```

This does everything in one go:

1. Installs `hostapd`, `dnsmasq`, `iw`
2. Unblocks WiFi (`rfkill unblock wifi`)
3. Verifies the AX210 supports AP mode
4. Creates a new WiFi network on `wlp7s0` with its own subnet (`192.168.50.0/24`)
5. Starts the access point: **SSID `TM6-OpenMix`**, password `openmix2026`
6. Runs DHCP (assigns IPs to devices that join) and DNS (spoofs Vorwerk domains to `192.168.50.1`)
7. Sets up NAT so the TM6 can still reach the internet via USB Ethernet for non-spoofed traffic
8. Redirects port 80 → 8080 via iptables (so the TM6's HTTP requests hit Docker)

## Step 3: Connect TM6 to our network

On the TM6 touchscreen, go to WiFi settings and connect to our network:

- **SSID:** `TM6-OpenMix`
- **Password:** `openmix2026`

## Step 4: Observe

Open two terminals:

```bash
# Terminal 1 — server logs (every HTTP request the TM6 makes)
docker compose logs -f openmix-server

# Terminal 2 — DNS logs (every domain the TM6 resolves)
sudo tail -f /var/log/openmix-dns.log
```

### What to look for

**Success indicators:**

- DNS log shows queries for `ES.nwot-plain.vorwerk-digital.com` and `es.plain.production-eu.cookidoo.vorwerk-digital.com`
- Server log shows `GET /.well-known/device-infra-home` → 307
- Server log shows `GET /.well-known/infrastructure-home` → 200
- Server log shows `GET /time?challenge=...` → 200
- Any unknown paths logged (404s) — these reveal additional endpoints the TM6 expects

**Failure indicators:**

- TM6 refuses to connect to WiFi → check hostapd logs (`journalctl -u hostapd`)
- DNS queries appear but no HTTP requests → TM6 may be checking connectivity before proceeding
- TM6 hits `/.well-known/infrastructure-home` but ignores our EST endpoints → device may validate the bootstrap response signature
- TM6 attempts HTTPS to `tm6-ra.production-eu.cookidoo.vorwerk-digital.com` and fails → EST server TLS cert is validated against a firmware-embedded root (this is the big open question)

## Step 5: Record results

Save the logs for analysis:

```bash
docker compose logs openmix-server > data/test-v1-server.log
sudo cp /var/log/openmix-dns.log data/test-v1-dns.log
```

## Teardown

To undo everything and restore the machine to its previous state:

```bash
sudo ./scripts/teardown-ap.sh
docker compose stop openmix-server
```

## Configuration

Edit `scripts/setup-ap.sh` to change:

| Setting | Line | Default |
|---------|------|---------|
| SSID | 28 | `TM6-OpenMix` |
| Password | 29 | `openmix2026` |
| AP IP | 25 | `192.168.50.1` |
| WiFi channel | 30 | `6` |

The OpenMix server is configured via environment variables in `docker-compose.yml`:

| Variable | Default | Purpose |
|----------|---------|---------|
| `OPENMIX_HOST` | `192.168.50.1` | IP the TM6 sees in infrastructure-home URLs |
| `OPENMIX_LOCALE` | `es` | Country prefix (es=Spain, de=Germany, gb=UK, etc.) |
| `OPENMIX_CA_DIR` | `/openmix/data/ca` | Where CA key/cert are stored |
