#!/usr/bin/env python3
"""
OpenMix Server — Stage 1: Cleartext Bootstrap

Impersonates Vorwerk's infrastructure bootstrap endpoints that the TM6
hits over plaintext HTTP during boot. This is the first step in getting
the TM6 to trust our server.

Endpoints served:
  GET /.well-known/device-infra-home       → 307 redirect
  GET /.well-known/infrastructure-home     → HAL+JSON with EST/time URLs
  GET /time?challenge=<base64>             → PKCS#7 signed time response

Usage:
  python3 openmix-server.py [--port 80] [--host 0.0.0.0]
"""

import argparse
import base64
import json
import logging
import os
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Optional: cryptography for PKCS#7 time signing
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import NameOID
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("openmix")

# --- Configuration ---

# The server's own address — used to build self-referencing URLs.
# In production this is the AP gateway IP (e.g. 192.168.50.1).
SERVER_HOST = os.environ.get("OPENMIX_HOST", "192.168.50.1")
SERVER_PORT = int(os.environ.get("OPENMIX_PORT", "80"))

# Locale prefix — the TM6 uses a 2-letter country code.
# The PCAP shows "es" (Spain). Adjust for your locale.
LOCALE = os.environ.get("OPENMIX_LOCALE", "es")

# EST RA — where we'll point the device for certificate enrollment.
# For now, point to ourselves. Stage 2 will implement actual EST.
EST_HOST = os.environ.get("OPENMIX_EST_HOST", SERVER_HOST)
EST_PORT = int(os.environ.get("OPENMIX_EST_PORT", "8443"))

# CA key/cert paths (generated on first run if missing)
CA_DIR = os.environ.get("OPENMIX_CA_DIR", "/openmix/data/ca")


def get_infrastructure_home():
    """
    Build the HAL+JSON infrastructure-home response.

    This is what Vorwerk's server returns at:
      http://es.plain.production-eu.cookidoo.vorwerk-digital.com/.well-known/infrastructure-home

    We modify it to point EST and time endpoints to our own server.
    """
    base_http = f"http://{SERVER_HOST}:{SERVER_PORT}" if SERVER_PORT != 80 else f"http://{SERVER_HOST}"
    est_base = f"https://{EST_HOST}:{EST_PORT}" if EST_PORT != 443 else f"https://{EST_HOST}"

    return {
        "_links": {
            "curies": [{
                "name": "ca",
                "href": f"{base_http}/api#{{rel}}",
                "templated": True
            }],
            "self": {
                "href": f"{base_http}/.well-known/device-infrastructure-home"
            },
            "ca:est-cacerts": {
                "href": f"{est_base}/.well-known/est/cacerts",
                "templated": False
            },
            "ca:est-simpleenroll": {
                "href": f"{est_base}/.well-known/est/simpleenroll",
                "templated": False
            },
            "ca:est-simplereenroll": {
                "href": f"{est_base}/.well-known/est/simplereenroll",
                "templated": False
            },
            "ts:time": {
                "href": f"{base_http}/time{{?challenge}}",
                "templated": True
            }
        }
    }


class OpenMixCA:
    """
    Minimal CA for signing time responses and (later) issuing device certs.
    Generates a self-signed root CA on first use.
    """

    def __init__(self, ca_dir):
        self.ca_dir = ca_dir
        self.ca_key_path = os.path.join(ca_dir, "ca-key.pem")
        self.ca_cert_path = os.path.join(ca_dir, "ca-cert.pem")
        self.ca_key = None
        self.ca_cert = None

        if HAS_CRYPTO:
            os.makedirs(ca_dir, exist_ok=True)
            self._load_or_generate()

    def _load_or_generate(self):
        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_cert_path):
            log.info("Loading existing CA from %s", self.ca_dir)
            with open(self.ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self.ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
        else:
            log.info("Generating new CA keypair in %s", self.ca_dir)
            self.ca_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
            )
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenMix"),
                x509.NameAttribute(NameOID.COMMON_NAME, "OpenMix Root CA"),
            ])
            self.ca_cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(self.ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
                .not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .sign(self.ca_key, hashes.SHA256())
            )

            with open(self.ca_key_path, "wb") as f:
                f.write(self.ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            with open(self.ca_cert_path, "wb") as f:
                f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
            log.info("CA generated: %s", self.ca_cert.subject)

    def sign_time_response(self, challenge_b64):
        """
        Create a PKCS#7 SignedData containing the current time,
        signed with our CA key. This mimics Vorwerk's /time endpoint.

        The actual format from Vorwerk is a CMS SignedData (application/pkcs7-mime).
        We replicate that structure so the TM6 can verify it.
        """
        if not HAS_CRYPTO:
            log.warning("cryptography not installed — returning unsigned time")
            return None

        # The time payload — we don't know the exact format Vorwerk uses
        # inside the PKCS#7 envelope, but it likely includes:
        # - The current UTC time
        # - The challenge nonce (to prevent replay)
        now = datetime.now(timezone.utc)
        time_payload = json.dumps({
            "utc": now.isoformat(),
            "unix": int(now.timestamp()),
            "challenge": challenge_b64,
        }).encode("utf-8")

        # Build PKCS#7 SignedData
        signed = (
            pkcs7.PKCS7SignatureBuilder()
            .set_data(time_payload)
            .add_signer(self.ca_cert, self.ca_key, hashes.SHA256())
            .sign(serialization.Encoding.DER, options=[])
        )
        return signed


class OpenMixHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the OpenMix bootstrap server."""

    server_version = "nginx/1.19.1"  # Mimic Vorwerk's server header

    def log_message(self, format, *args):
        log.info(
            "%s %s",
            self.address_string(),
            format % args,
        )

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # Log all requests with full detail for debugging
        log.info(
            "Request: %s %s | User-Agent: %s",
            self.command,
            self.path,
            self.headers.get("User-Agent", "unknown"),
        )

        if path == "/.well-known/device-infra-home":
            self._handle_device_infra_home()
        elif path in ("/.well-known/infrastructure-home",
                      "/.well-known/device-infrastructure-home"):
            self._handle_infrastructure_home()
        elif path == "/time":
            self._handle_time(parsed)
        else:
            self._handle_unknown()

    def _handle_device_infra_home(self):
        """
        Step 4, Request 1: The TM6 first hits this endpoint.
        Vorwerk returns a 307 redirect to the real infrastructure-home.
        We redirect to ourselves.
        """
        base = f"http://{SERVER_HOST}:{SERVER_PORT}" if SERVER_PORT != 80 else f"http://{SERVER_HOST}"
        location = f"{base}/.well-known/infrastructure-home"

        self.send_response(307)
        self.send_header("Location", location)
        self.send_header("Server", self.server_version)
        self.end_headers()
        log.info("→ 307 redirect to %s", location)

    def _handle_infrastructure_home(self):
        """
        Step 4, Request 2: Return the HAL+JSON infrastructure config.
        This is what tells the TM6 where to find its CA, EST, and time server.
        """
        body = json.dumps(get_infrastructure_home(), indent=2).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/hal+json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", self.server_version)
        self.end_headers()
        self.wfile.write(body)
        log.info("→ 200 infrastructure-home (%d bytes)", len(body))

    def _handle_time(self, parsed):
        """
        Step 5: Signed time sync.
        The TM6 sends GET /time?challenge=<base64> and expects a
        PKCS#7 SignedData response (application/pkcs7-mime).
        """
        params = parse_qs(parsed.query)
        challenge = params.get("challenge", [None])[0]

        if not challenge:
            self.send_error(400, "Missing challenge parameter")
            return

        log.info("Time challenge: %s", challenge)

        ca = self.server.ca
        signed_data = ca.sign_time_response(challenge)

        if signed_data:
            self.send_response(200)
            self.send_header("Content-Type", "application/pkcs7-mime")
            self.send_header("Content-Length", str(len(signed_data)))
            self.send_header("Server", self.server_version)
            self.end_headers()
            self.wfile.write(signed_data)
            log.info("→ 200 signed time (%d bytes)", len(signed_data))
        else:
            # Fallback: return unsigned JSON time (for testing without cryptography)
            now = datetime.now(timezone.utc)
            body = json.dumps({
                "utc": now.isoformat(),
                "unix": int(now.timestamp()),
                "challenge": challenge,
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", self.server_version)
            self.end_headers()
            self.wfile.write(body)
            log.info("→ 200 unsigned time fallback (%d bytes)", len(body))

    def _handle_unknown(self):
        """Log and 404 any unrecognized path — helps discover what the TM6 asks for."""
        log.warning(
            "UNKNOWN REQUEST: %s %s (headers: %s)",
            self.command,
            self.path,
            dict(self.headers),
        )
        body = b"Not Found"
        self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", self.server_version)
        self.end_headers()
        self.wfile.write(body)


class OpenMixServer(HTTPServer):
    """HTTP server with CA state attached."""

    def __init__(self, server_address, handler_class, ca):
        self.ca = ca
        super().__init__(server_address, handler_class)


def main():
    parser = argparse.ArgumentParser(description="OpenMix Stage 1 Bootstrap Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=SERVER_PORT, help="HTTP port (default: 80)")
    parser.add_argument("--ca-dir", default=CA_DIR, help="CA key/cert directory")
    args = parser.parse_args()

    ca = OpenMixCA(args.ca_dir)

    server = OpenMixServer((args.host, args.port), OpenMixHandler, ca)
    log.info("OpenMix Stage 1 server starting on %s:%d", args.host, args.port)
    log.info("CA directory: %s", args.ca_dir)
    if HAS_CRYPTO:
        log.info("PKCS#7 time signing: ENABLED")
    else:
        log.info("PKCS#7 time signing: DISABLED (install 'cryptography' package)")
    log.info("Infrastructure-home will point EST to: https://%s:%d", EST_HOST, EST_PORT)
    log.info("")
    log.info("DNS domains to redirect to this server:")
    log.info("  %s.nwot-plain.vorwerk-digital.com", LOCALE.upper())
    log.info("  %s.plain.production-eu.cookidoo.vorwerk-digital.com", LOCALE)
    log.info("")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
