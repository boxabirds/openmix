# TM6 PCAP Analysis Findings

Source: VARIOT `Vorwerk-Thermomix-TM6-normal2` dataset (captured 2022-06-10, Universidad de Mondragon)

## Device Identity

- **Hostname:** `thermomix-3fdd12`
- **MAC:** `64:05:e4:3f:dd:12`
- **IP (in capture):** `192.18.1.88`
- **Firmware User-Agent:** `nwot-device/3.3.74-202205041255`

---

## TM6 Boot Sequence (in order)

### Step 1: DHCP (cleartext)

Standard DHCP DISCOVER/OFFER/REQUEST/ACK. Reports hostname `thermomix-{last6ofMAC}`.

### Step 2: SSDP/UPnP discovery (cleartext)

Sends SSDP M-SEARCH to `239.255.255.250:1900` — probing for local services. Repeats every ~20 seconds throughout the session.

### Step 3: DNS (plaintext UDP port 53)

All DNS is standard plaintext to the DHCP-assigned DNS server. **No DNS-over-HTTPS.** DNS spoofing via the AP's dnsmasq is viable.

### Step 4: Infrastructure bootstrap (cleartext HTTP port 80)

**This is the critical finding.**

**Request 1:**
```
GET http://ES.nwot-plain.vorwerk-digital.com/.well-known/device-infra-home
User-Agent: nwot-device/3.3.74-202205041255
```
**Response:** `307` redirect to `http://es.plain.production-eu.cookidoo.vorwerk-digital.com/.well-known/infrastructure-home`
**Server:** `nginx/1.19.1`

**Request 2:**
```
GET http://es.plain.production-eu.cookidoo.vorwerk-digital.com/.well-known/infrastructure-home
User-Agent: nwot-device/3.3.74-202205041255
```
**Response:** `200 OK`, `application/hal+json`, 771 bytes:
```json
{
  "_links": {
    "curies": [{
      "name": "ca",
      "href": "http://es.plain.production-eu.cookidoo.vorwerk-digital.com/api#{rel}",
      "templated": true
    }],
    "self": {
      "href": "http://es.plain.production-eu.cookidoo.vorwerk-digital.com/.well-known/device-infrastructure-home"
    },
    "ca:est-cacerts": {
      "href": "https://tm6-ra.production-eu.cookidoo.vorwerk-digital.com/.well-known/est/cacerts",
      "templated": false
    },
    "ca:est-simpleenroll": {
      "href": "https://tm6-ra.production-eu.cookidoo.vorwerk-digital.com/.well-known/est/simpleenroll",
      "templated": false
    },
    "ca:est-simplereenroll": {
      "href": "https://tm6-ra.production-eu.cookidoo.vorwerk-digital.com/.well-known/est/simplereenroll",
      "templated": false
    },
    "ts:time": {
      "href": "http://es.plain.production-eu.cookidoo.vorwerk-digital.com/time{?challenge}",
      "templated": true
    }
  }
}
```

**This reveals the TM6 uses RFC 7030 (EST — Enrollment over Secure Transport):**

| Link | Purpose |
|------|---------|
| `est-cacerts` | Download the CA certificates the device should trust |
| `est-simpleenroll` | Enroll the device to get a client certificate |
| `est-simplereenroll` | Renew the device's client certificate |
| `ts:time` | Signed time synchronization |

The EST Registration Authority is at `tm6-ra.production-eu.cookidoo.vorwerk-digital.com`.

### Step 5: Signed time sync (cleartext HTTP port 80)

```
GET http://es.plain.production-eu.cookidoo.vorwerk-digital.com/time?challenge=LhT8EMIuadeXGRVrb-jZrw==
User-Agent: nwot-device/3.3.74-202205041255
```
**Response:** `200 OK`, `application/pkcs7-mime`, 9064 bytes

The time response is PKCS#7 signed (CMS SignedData). The device sends a random challenge; the server returns the current time signed with the CA's key. This prevents replay attacks and ensures the device has accurate time before validating certificates.

### Step 6: OCSP certificate validation (cleartext HTTP port 80)

The TM6 checks certificate revocation status against Vorwerk's own OCSP responders:
- `server-ca.ocsp.tm-prod.vorwerk-digital.com` — root CA OCSP
- `server-region-ca.ocsp.tm-prod.vorwerk-digital.com` — regional CA OCSP

Multiple OCSP requests (both GET and POST) for different certificate serials. All over plain HTTP.

### Step 7: Device config fetch (HTTP → HTTPS redirect)

```
GET http://es.device.production-eu.cookidoo.vorwerk-digital.com/tm6-snapshot/device-config/{sha256_hash}
```
**Response:** `308 Permanent Redirect` (to HTTPS)

The config hash `acc5fdfe71fca6626bca043b3fd27a211901a7e9ddd1d266c926cdd2912abd4b` is likely a content-addressable identifier for the device's configuration version.

### Step 8: TLS connections (HTTPS port 443)

After the cleartext bootstrap, all remaining traffic is TLS 1.3:
- `es.nwot.vorwerk-digital.com` → `eu.ingress.prod.cookidoo.vorwerk-digital.com` (API gateway)
- `login.device.production-eu.cookidoo.vorwerk-digital.com` (device auth)
- `es.device.production-eu.cookidoo.vorwerk-digital.com` (device API — heavy traffic)
- `es.device-usagebox.production-eu.cookidoo.vorwerk-digital.com` (telemetry)
- `recipepublic-device.prod.external.eu-tm-prod.vorwerk-digital.com` (recipe CDN, CloudFront)
- `patternlib-all.prod.external.eu-tm-prod.vorwerk-digital.com` (UI assets, CloudFront)
- `assets.tmecosys.com` (images, Fastly CDN)

TLS cipher: `TLS_AES_256_GCM_SHA384`, curve: `x25519`

---

## Implications for OpenMix

### The attack surface: cleartext infrastructure bootstrap

The TM6's infrastructure discovery happens over **unencrypted HTTP**. By controlling DNS on the WiFi AP, we can:

1. Redirect `ES.nwot-plain.vorwerk-digital.com` and `es.plain.production-eu.cookidoo.vorwerk-digital.com` to our local server
2. Serve a modified `/.well-known/infrastructure-home` that points EST endpoints to our own CA
3. Potentially get the TM6 to trust our CA certificates and enroll with our PKI

### The catch: EST bootstrap trust

The EST `cacerts` endpoint is HTTPS (`tm6-ra.production-eu.cookidoo.vorwerk-digital.com`). The TM6 must already trust *some* certificate to connect to it. There are two possibilities:

1. **The TM6 has a firmware-embedded trust anchor** specifically for the EST RA. If so, even if we redirect the domain, the TLS handshake to our server would fail because we can't present a cert signed by that trust anchor.

2. **The TM6 uses a standard CA bundle** (or no cert validation) for the initial EST `cacerts` fetch. If so, we can serve our own CA and the device will trust it.

The OCSP traffic suggests scenario 1 — Vorwerk runs their own CA and the device validates against it. But the fact that the infrastructure-home URL pointing to the EST server is served over plaintext HTTP means we can change where the device looks for its CA certificates.

### What we need to test with actual hardware

1. **Redirect the bootstrap domains** via DNS and serve a modified `infrastructure-home` pointing EST to our own server. Does the TM6 follow it?
2. **Serve our own `est/cacerts`** response. Does the TM6 accept arbitrary CA certs, or does it validate the EST server's TLS cert against a firmware-embedded root?
3. **If EST redirection works**, serve our own CA → the TM6 trusts our server for all subsequent TLS connections → full API interception is possible.
4. **If EST redirection fails**, the OCSP and time endpoints are still over cleartext HTTP. We can intercept/modify those, which may enable other attack vectors (e.g., time manipulation, OCSP response replay).

### DNS domains to redirect for OpenMix

At minimum, the AP's dnsmasq must resolve these to the local server:

```
# Bootstrap (HTTP)
ES.nwot-plain.vorwerk-digital.com
es.plain.production-eu.cookidoo.vorwerk-digital.com

# OCSP (HTTP)
server-ca.ocsp.tm-prod.vorwerk-digital.com
server-region-ca.ocsp.tm-prod.vorwerk-digital.com

# EST RA (HTTPS)
tm6-ra.production-eu.cookidoo.vorwerk-digital.com

# Device API (HTTPS)
es.device.production-eu.cookidoo.vorwerk-digital.com
login.device.production-eu.cookidoo.vorwerk-digital.com
es.nwot.vorwerk-digital.com

# CDN (HTTPS)
recipepublic-device.prod.external.eu-tm-prod.vorwerk-digital.com
patternlib-all.prod.external.eu-tm-prod.vorwerk-digital.com
assets.tmecosys.com

# Telemetry (can be blocked)
es.device-usagebox.production-eu.cookidoo.vorwerk-digital.com
```

Note: domain prefix changes by locale (`es` = Spain in this capture). Other locales will use `de`, `gb`, `fr`, etc.
