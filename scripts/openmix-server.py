#!/usr/bin/env python3
"""
OpenMix Server — MITM passthrough with selective hijack.

Sits between the TM6 and Vorwerk's real servers. By default, every request
is proxied to the real Vorwerk server via the USB Ethernet internet connection
and the full request+response is logged. Specific endpoints can be hijacked
to serve our own responses instead.

The Docker container resolves DNS normally (via systemd-resolved on the host),
so it reaches real Vorwerk servers. The TM6 can't — its DNS is spoofed by
dnsmasq on the AP interface to point at us.

Modes:
  --mode passthrough   Proxy everything to Vorwerk, log all traffic (default)
  --mode hijack        Serve our own bootstrap responses, proxy the rest

Usage:
  python3 openmix-server.py [--mode passthrough] [--port 80]
"""

import argparse
import json
import logging
import os
import time as time_mod
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import http.client
import ssl

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

SERVER_HOST = os.environ.get("OPENMIX_HOST", "192.168.50.1")
SERVER_PORT = int(os.environ.get("OPENMIX_PORT", "80"))
LOCALE = os.environ.get("OPENMIX_LOCALE", "es")
EST_HOST = os.environ.get("OPENMIX_EST_HOST", SERVER_HOST)
EST_PORT = int(os.environ.get("OPENMIX_EST_PORT", "8443"))
CA_DIR = os.environ.get("OPENMIX_CA_DIR", "/openmix/data/ca")
LOG_DIR = os.environ.get("OPENMIX_LOG_DIR", "/openmix/data/captures")

# How long to wait for Vorwerk to respond (seconds)
PROXY_TIMEOUT = 30


def get_infrastructure_home():
    """Build the modified HAL+JSON that points EST/time to our server."""
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
    """Minimal CA for signing time responses and (later) issuing device certs."""

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
        """Create a PKCS#7 SignedData containing the current time."""
        if not HAS_CRYPTO:
            return None

        now = datetime.now(timezone.utc)
        time_payload = json.dumps({
            "utc": now.isoformat(),
            "unix": int(now.timestamp()),
            "challenge": challenge_b64,
        }).encode("utf-8")

        signed = (
            pkcs7.PKCS7SignatureBuilder()
            .set_data(time_payload)
            .add_signer(self.ca_cert, self.ca_key, hashes.SHA256())
            .sign(serialization.Encoding.DER, options=[])
        )
        return signed


class CaptureLogger:
    """
    Logs full HTTP request/response pairs to disk for later analysis.
    Each capture is a JSON file with request + response details.
    """

    def __init__(self, log_dir):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.seq = 0

    def log_exchange(self, request_data, response_data, source):
        """
        Log a complete HTTP exchange.
        source: 'proxied' (from real Vorwerk) or 'hijacked' (our response)
        """
        self.seq += 1
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{ts}_{self.seq:04d}_{source}.json"
        filepath = os.path.join(self.log_dir, filename)

        # Don't write binary body inline — save separately if large
        resp_body = response_data.get("body", b"")
        resp_content_type = response_data.get("content_type", "")

        if isinstance(resp_body, bytes):
            if len(resp_body) > 10000 or not resp_content_type.startswith(("text/", "application/json", "application/hal")):
                # Save binary body as separate file
                body_file = filepath.replace(".json", ".body")
                with open(body_file, "wb") as f:
                    f.write(resp_body)
                response_data = {**response_data, "body": f"<binary {len(resp_body)} bytes, see {os.path.basename(body_file)}>"}
            else:
                try:
                    response_data = {**response_data, "body": resp_body.decode("utf-8")}
                except UnicodeDecodeError:
                    body_file = filepath.replace(".json", ".body")
                    with open(body_file, "wb") as f:
                        f.write(resp_body)
                    response_data = {**response_data, "body": f"<binary {len(resp_body)} bytes, see {os.path.basename(body_file)}>"}

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "request": request_data,
            "response": response_data,
        }

        with open(filepath, "w") as f:
            json.dump(record, f, indent=2, default=str)

        log.info("Captured → %s", filename)


class OpenMixHandler(BaseHTTPRequestHandler):
    """HTTP request handler with proxy passthrough."""

    server_version = "nginx/1.19.1"

    def log_message(self, format, *args):
        # Suppress default logging — we do our own
        pass

    def _get_request_data(self):
        """Capture the incoming request details."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        return {
            "method": self.command,
            "path": self.path,
            "host": self.headers.get("Host", "unknown"),
            "headers": dict(self.headers),
            "body_length": len(body),
            "body": body,
        }

    def _should_hijack(self, path):
        """Return True if this path should be served by us instead of proxied."""
        if self.server.mode != "hijack":
            return False
        clean = path.rstrip("/")
        return clean in (
            "/.well-known/device-infra-home",
            "/.well-known/infrastructure-home",
            "/.well-known/device-infrastructure-home",
        ) or clean.startswith("/time")

    def _proxy_to_vorwerk(self, req_data):
        """
        Forward the request to the real Vorwerk server and return the response.
        The Docker container resolves DNS normally via systemd-resolved,
        which goes out through USB Ethernet to the real internet.
        """
        host = req_data["host"]
        path = req_data["path"]
        method = req_data["method"]
        body = req_data["body"]

        log.info("PROXY → %s %s (Host: %s)", method, path, host)

        try:
            conn = http.client.HTTPConnection(host, port=80, timeout=PROXY_TIMEOUT)

            # Forward all original headers except Host (already set by connection)
            forward_headers = {}
            for key, value in req_data["headers"].items():
                lower = key.lower()
                if lower not in ("host", "connection", "transfer-encoding"):
                    forward_headers[key] = value

            conn.request(method, path, body=body if body else None, headers=forward_headers)
            resp = conn.getresponse()

            resp_body = resp.read()
            resp_headers = dict(resp.getheaders())

            log.info("PROXY ← %d %s (%d bytes, Content-Type: %s)",
                     resp.status, resp.reason, len(resp_body),
                     resp_headers.get("Content-Type", resp_headers.get("content-type", "unknown")))

            conn.close()

            return {
                "status": resp.status,
                "reason": resp.reason,
                "headers": resp_headers,
                "body": resp_body,
                "content_type": resp_headers.get("Content-Type", resp_headers.get("content-type", "")),
            }

        except Exception as e:
            log.error("PROXY FAILED: %s %s → %s", method, host, e)
            return {
                "status": 502,
                "reason": "Bad Gateway",
                "headers": {},
                "body": f"OpenMix proxy error: {e}".encode(),
                "content_type": "text/plain",
            }

    def _send_response_data(self, resp_data):
        """Send a proxied or constructed response back to the TM6."""
        self.send_response(resp_data["status"])
        for key, value in resp_data.get("headers", {}).items():
            # Skip hop-by-hop headers
            if key.lower() in ("transfer-encoding", "connection", "keep-alive"):
                continue
            self.send_header(key, value)
        self.end_headers()
        body = resp_data.get("body", b"")
        if isinstance(body, str):
            body = body.encode()
        self.wfile.write(body)

    def _handle_any(self):
        """Handle any HTTP method (GET, POST, PUT, etc.)."""
        parsed = urlparse(self.path)
        path = parsed.path
        req_data = self._get_request_data()

        log.info("← %s %s | Host: %s | UA: %s",
                 self.command, self.path,
                 req_data["host"],
                 req_data["headers"].get("User-Agent", "unknown"))

        # Check if we should hijack this request
        if self._should_hijack(path):
            resp_data = self._handle_hijacked(parsed, req_data)
            source = "hijacked"
        else:
            # Proxy to real Vorwerk
            resp_data = self._proxy_to_vorwerk(req_data)
            source = "proxied"

        # Log the full exchange to disk
        log_req = {**req_data}
        if isinstance(log_req.get("body"), bytes):
            log_req["body"] = f"<{len(log_req['body'])} bytes>"
        self.server.capture.log_exchange(log_req, resp_data, source)

        # Send response to TM6
        self._send_response_data(resp_data)

    def _handle_hijacked(self, parsed, req_data):
        """Serve our own response for hijacked endpoints."""
        path = parsed.path.rstrip("/")

        if path == "/.well-known/device-infra-home":
            base = f"http://{SERVER_HOST}:{SERVER_PORT}" if SERVER_PORT != 80 else f"http://{SERVER_HOST}"
            location = f"{base}/.well-known/infrastructure-home"
            log.info("HIJACK → 307 redirect to %s", location)
            return {
                "status": 307,
                "reason": "Temporary Redirect",
                "headers": {"Location": location, "Server": self.server_version},
                "body": b"",
                "content_type": "",
            }

        elif path in ("/.well-known/infrastructure-home",
                       "/.well-known/device-infrastructure-home"):
            body = json.dumps(get_infrastructure_home(), indent=2).encode("utf-8")
            log.info("HIJACK → 200 infrastructure-home (%d bytes)", len(body))
            return {
                "status": 200,
                "reason": "OK",
                "headers": {
                    "Content-Type": "application/hal+json",
                    "Content-Length": str(len(body)),
                    "Server": self.server_version,
                },
                "body": body,
                "content_type": "application/hal+json",
            }

        elif path == "/time":
            params = parse_qs(parsed.query)
            challenge = params.get("challenge", [None])[0]
            if not challenge:
                return {
                    "status": 400,
                    "reason": "Bad Request",
                    "headers": {},
                    "body": b"Missing challenge parameter",
                    "content_type": "text/plain",
                }

            signed_data = self.server.ca.sign_time_response(challenge)
            if signed_data:
                log.info("HIJACK → 200 signed time (%d bytes)", len(signed_data))
                return {
                    "status": 200,
                    "reason": "OK",
                    "headers": {
                        "Content-Type": "application/pkcs7-mime",
                        "Content-Length": str(len(signed_data)),
                        "Server": self.server_version,
                    },
                    "body": signed_data,
                    "content_type": "application/pkcs7-mime",
                }
            else:
                now = datetime.now(timezone.utc)
                body = json.dumps({
                    "utc": now.isoformat(),
                    "unix": int(now.timestamp()),
                    "challenge": challenge,
                }).encode("utf-8")
                return {
                    "status": 200,
                    "reason": "OK",
                    "headers": {
                        "Content-Type": "application/json",
                        "Content-Length": str(len(body)),
                        "Server": self.server_version,
                    },
                    "body": body,
                    "content_type": "application/json",
                }

        # Shouldn't reach here
        return {"status": 500, "headers": {}, "body": b"", "content_type": ""}

    # Handle all HTTP methods
    do_GET = _handle_any
    do_POST = _handle_any
    do_PUT = _handle_any
    do_PATCH = _handle_any
    do_DELETE = _handle_any
    do_HEAD = _handle_any
    do_OPTIONS = _handle_any


class OpenMixServer(HTTPServer):
    """HTTP server with CA, capture logger, and mode."""

    def __init__(self, server_address, handler_class, ca, capture, mode):
        self.ca = ca
        self.capture = capture
        self.mode = mode
        super().__init__(server_address, handler_class)


def main():
    parser = argparse.ArgumentParser(description="OpenMix MITM Passthrough Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=SERVER_PORT, help="HTTP port")
    parser.add_argument("--ca-dir", default=CA_DIR, help="CA key/cert directory")
    parser.add_argument("--log-dir", default=LOG_DIR, help="Capture log directory")
    parser.add_argument("--mode", choices=["passthrough", "hijack"], default="passthrough",
                        help="passthrough: proxy everything to Vorwerk and log. "
                             "hijack: serve our bootstrap, proxy the rest.")
    args = parser.parse_args()

    ca = OpenMixCA(args.ca_dir)
    capture = CaptureLogger(args.log_dir)

    server = OpenMixServer((args.host, args.port), OpenMixHandler, ca, capture, args.mode)

    log.info("=" * 60)
    log.info("OpenMix server starting")
    log.info("  Mode: %s", args.mode)
    log.info("  Listen: %s:%d", args.host, args.port)
    log.info("  CA: %s", args.ca_dir)
    log.info("  Captures: %s", args.log_dir)
    log.info("")
    if args.mode == "passthrough":
        log.info("  PASSTHROUGH: all requests proxied to real Vorwerk")
        log.info("  Every request+response logged to %s", args.log_dir)
        log.info("  The TM6 talks to Vorwerk normally — we just record everything")
    else:
        log.info("  HIJACK: bootstrap endpoints served by us, rest proxied")
        log.info("  Hijacked: /.well-known/device-infra-home")
        log.info("            /.well-known/infrastructure-home")
        log.info("            /time?challenge=...")
        log.info("  EST target: https://%s:%d", EST_HOST, EST_PORT)
    log.info("=" * 60)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
