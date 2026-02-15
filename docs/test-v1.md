# OpenMix Stage 1 — Hardware Test Instructions

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

## Step 2: Set up the WiFi AP

```bash
sudo ./scripts/setup-ap.sh
```

This does everything in one go:

1. Installs `hostapd`, `dnsmasq`, `iw`
2. Unblocks WiFi (`rfkill unblock wifi`)
3. Verifies the AX210 supports AP mode
4. Assigns `192.168.50.1` to `wlp7s0`
5. Starts an AP named **TM6-OpenMix** (password: `openmix2026`)
6. Configures dnsmasq to hand out DHCP leases and redirect all Vorwerk bootstrap domains to `192.168.50.1`
7. Sets up NAT so the TM6 can still reach the internet via USB Ethernet
8. Redirects port 80 → 8080 via iptables (so the TM6's HTTP requests hit Docker)

## Step 3: Connect TM6

On the TM6, go to WiFi settings and connect to:

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
