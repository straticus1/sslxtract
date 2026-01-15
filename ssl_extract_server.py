#!/usr/bin/env python3
"""
ssl_extract_server.py - HTTPS server for remote SSL certificate extraction

A simple API server that accepts requests to fetch SSL certificates from
remote endpoints and returns them or saves them to disk.

Configuration via JSON config file.
"""

import argparse
import json
import os
import ssl
import sys
import hashlib
import threading
import logging
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from typing import Optional, Dict, Any

# Import the extractor from sslxtract
from sslxtract import SSLExtractor, der_to_pem, get_cert_info, parse_target

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class Config:
    """Server configuration."""

    def __init__(self, config_path: Optional[str] = None):
        self.host: str = "0.0.0.0"
        self.port: int = 8443
        self.ssl_cert: Optional[str] = None
        self.ssl_key: Optional[str] = None
        self.storage_dir: str = "./certs"
        self.timeout: float = 10.0
        self.allowed_hosts: Optional[list] = None  # None = allow all
        self.blocked_hosts: list = []
        self.require_auth: bool = False
        self.api_keys: list = []
        self.max_concurrent: int = 10
        self.log_requests: bool = True

        if config_path:
            self.load(config_path)

    def load(self, config_path: str):
        """Load configuration from JSON file."""
        with open(config_path) as f:
            data = json.load(f)

        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def to_dict(self) -> dict:
        """Export config as dictionary."""
        return {
            'host': self.host,
            'port': self.port,
            'ssl_cert': self.ssl_cert,
            'ssl_key': self.ssl_key,
            'storage_dir': self.storage_dir,
            'timeout': self.timeout,
            'allowed_hosts': self.allowed_hosts,
            'blocked_hosts': self.blocked_hosts,
            'require_auth': self.require_auth,
            'api_keys': self.api_keys,
            'max_concurrent': self.max_concurrent,
            'log_requests': self.log_requests
        }

    def save(self, config_path: str):
        """Save configuration to JSON file."""
        with open(config_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)


class CertificateStore:
    """Manages certificate storage on disk."""

    def __init__(self, storage_dir: str):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.storage_dir / "index.json"
        self.index: Dict[str, Any] = self._load_index()
        self._lock = threading.Lock()

    def _load_index(self) -> dict:
        """Load certificate index from disk."""
        if self.index_file.exists():
            try:
                with open(self.index_file) as f:
                    return json.load(f)
            except Exception:
                pass
        return {'certificates': {}}

    def _save_index(self):
        """Save certificate index to disk."""
        with open(self.index_file, 'w') as f:
            json.dump(self.index, f, indent=2)

    def _cert_id(self, target: str, der_cert: bytes) -> str:
        """Generate unique ID for certificate."""
        fingerprint = hashlib.sha256(der_cert).hexdigest()[:16]
        safe_target = target.replace('://', '_').replace(':', '_').replace('/', '_')
        return f"{safe_target}_{fingerprint}"

    def save(self, target: str, der_cert: bytes, chain: list = None) -> dict:
        """Save certificate to storage."""
        with self._lock:
            cert_id = self._cert_id(target, der_cert)
            cert_dir = self.storage_dir / cert_id
            cert_dir.mkdir(exist_ok=True)

            # Save leaf certificate
            leaf_pem = der_to_pem(der_cert)
            (cert_dir / "leaf.pem").write_text(leaf_pem)
            (cert_dir / "leaf.der").write_bytes(der_cert)

            # Save chain if available
            if chain and len(chain) > 1:
                chain_pem = ''.join(der_to_pem(c) for c in chain)
                (cert_dir / "chain.pem").write_text(chain_pem)

            # Get cert info
            info = get_cert_info(der_cert)

            # Update index
            entry = {
                'id': cert_id,
                'target': target,
                'fetched_at': datetime.utcnow().isoformat(),
                'fingerprint': hashlib.sha256(der_cert).hexdigest(),
                'info': info,
                'path': str(cert_dir)
            }
            self.index['certificates'][cert_id] = entry
            self._save_index()

            return entry

    def get(self, cert_id: str) -> Optional[dict]:
        """Get certificate by ID."""
        return self.index['certificates'].get(cert_id)

    def list_all(self) -> list:
        """List all stored certificates."""
        return list(self.index['certificates'].values())

    def get_pem(self, cert_id: str) -> Optional[str]:
        """Get PEM content by cert ID."""
        entry = self.get(cert_id)
        if entry:
            pem_path = Path(entry['path']) / "leaf.pem"
            if pem_path.exists():
                return pem_path.read_text()
        return None

    def delete(self, cert_id: str) -> bool:
        """Delete certificate by ID."""
        with self._lock:
            if cert_id in self.index['certificates']:
                entry = self.index['certificates'][cert_id]
                cert_dir = Path(entry['path'])
                if cert_dir.exists():
                    import shutil
                    shutil.rmtree(cert_dir)
                del self.index['certificates'][cert_id]
                self._save_index()
                return True
        return False


class SSLExtractHandler(BaseHTTPRequestHandler):
    """HTTP request handler for SSL certificate extraction."""

    config: Config = None
    extractor: SSLExtractor = None
    store: CertificateStore = None
    semaphore: threading.Semaphore = None

    def log_message(self, format, *args):
        """Override to use our logger."""
        if self.config.log_requests:
            logger.info("%s - %s", self.address_string(), format % args)

    def _send_json(self, data: dict, status: int = 200):
        """Send JSON response."""
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, message: str, status: int = 400):
        """Send error response."""
        self._send_json({'error': message, 'success': False}, status)

    def _check_auth(self) -> bool:
        """Check API key authentication."""
        if not self.config.require_auth:
            return True

        auth = self.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            token = auth[7:]
            return token in self.config.api_keys

        # Also check query param
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        api_key = params.get('api_key', [None])[0]
        return api_key in self.config.api_keys

    def _check_host_allowed(self, host: str) -> bool:
        """Check if target host is allowed."""
        # Check blocked list
        for blocked in self.config.blocked_hosts:
            if blocked in host:
                return False

        # Check allowed list (if configured)
        if self.config.allowed_hosts:
            for allowed in self.config.allowed_hosts:
                if allowed in host:
                    return True
            return False

        return True

    def do_GET(self):
        """Handle GET requests."""
        if not self._check_auth():
            self._send_error("Unauthorized", 401)
            return

        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == '/health':
            self._send_json({'status': 'ok', 'service': 'ssl-extract-server'})

        elif path == '/extract':
            # Extract certificate from target
            target = params.get('target', [None])[0]
            if not target:
                self._send_error("Missing 'target' parameter")
                return

            save = params.get('save', ['false'])[0].lower() == 'true'
            verbose = params.get('verbose', ['false'])[0].lower() == 'true'

            self._extract_cert(target, save=save, verbose=verbose)

        elif path == '/certs':
            # List stored certificates
            certs = self.store.list_all()
            self._send_json({'certificates': certs, 'count': len(certs)})

        elif path.startswith('/certs/'):
            # Get specific certificate
            cert_id = path[7:]  # Remove '/certs/' prefix
            if cert_id.endswith('/pem'):
                cert_id = cert_id[:-4]
                pem = self.store.get_pem(cert_id)
                if pem:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/x-pem-file')
                    self.send_header('Content-Disposition', f'attachment; filename="{cert_id}.pem"')
                    self.end_headers()
                    self.wfile.write(pem.encode())
                else:
                    self._send_error("Certificate not found", 404)
            else:
                entry = self.store.get(cert_id)
                if entry:
                    self._send_json(entry)
                else:
                    self._send_error("Certificate not found", 404)

        else:
            self._send_error("Not found", 404)

    def do_POST(self):
        """Handle POST requests."""
        if not self._check_auth():
            self._send_error("Unauthorized", 401)
            return

        parsed = urlparse(self.path)
        path = parsed.path

        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b'{}'
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._send_error("Invalid JSON body")
            return

        if path == '/extract':
            # Extract certificate from target
            target = data.get('target')
            if not target:
                self._send_error("Missing 'target' in request body")
                return

            save = data.get('save', False)
            verbose = data.get('verbose', False)
            protocol = data.get('protocol')
            servername = data.get('servername')

            self._extract_cert(target, save=save, verbose=verbose,
                              protocol=protocol, servername=servername)

        elif path == '/extract/batch':
            # Batch extraction
            targets = data.get('targets', [])
            if not targets:
                self._send_error("Missing 'targets' array in request body")
                return

            save = data.get('save', False)
            results = []

            for target in targets:
                try:
                    result = self._do_extract(target, save=save)
                    results.append({'target': target, 'success': True, **result})
                except Exception as e:
                    results.append({'target': target, 'success': False, 'error': str(e)})

            self._send_json({
                'results': results,
                'total': len(targets),
                'succeeded': sum(1 for r in results if r['success']),
                'failed': sum(1 for r in results if not r['success'])
            })

        else:
            self._send_error("Not found", 404)

    def do_DELETE(self):
        """Handle DELETE requests."""
        if not self._check_auth():
            self._send_error("Unauthorized", 401)
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith('/certs/'):
            cert_id = path[7:]
            if self.store.delete(cert_id):
                self._send_json({'success': True, 'deleted': cert_id})
            else:
                self._send_error("Certificate not found", 404)
        else:
            self._send_error("Not found", 404)

    def _extract_cert(self, target: str, save: bool = False, verbose: bool = False,
                      protocol: str = None, servername: str = None):
        """Extract certificate and send response."""
        try:
            result = self._do_extract(target, save=save, verbose=verbose,
                                     protocol=protocol, servername=servername)
            self._send_json({'success': True, **result})
        except ValueError as e:
            self._send_error(str(e), 400)
        except Exception as e:
            logger.exception(f"Error extracting cert from {target}")
            self._send_error(f"Extraction failed: {e}", 500)

    def _do_extract(self, target: str, save: bool = False, verbose: bool = False,
                    protocol: str = None, servername: str = None) -> dict:
        """Perform certificate extraction."""
        # Parse target
        host, port, detected_protocol = parse_target(target)
        protocol = protocol or detected_protocol

        # Check if host is allowed
        if not self._check_host_allowed(host):
            raise ValueError(f"Host '{host}' is not allowed")

        # Acquire semaphore for rate limiting
        if not self.semaphore.acquire(timeout=30):
            raise ValueError("Server busy, try again later")

        try:
            # Extract certificate
            der_cert, chain = self.extractor.extract(host, port, protocol, servername)

            if not der_cert:
                raise ValueError("No certificate received")

            # Get certificate info
            info = get_cert_info(der_cert, verbose=verbose)
            pem = der_to_pem(der_cert)

            result = {
                'target': target,
                'host': host,
                'port': port,
                'protocol': protocol,
                'pem': pem,
                'info': info,
                'chain_length': len(chain) if chain else 1
            }

            # Save if requested
            if save:
                entry = self.store.save(target, der_cert, chain)
                result['stored'] = True
                result['cert_id'] = entry['id']
            else:
                result['stored'] = False

            return result

        finally:
            self.semaphore.release()


class ThreadedHTTPServer(HTTPServer):
    """HTTP server that handles requests in threads."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.daemon_threads = True

    def process_request(self, request, client_address):
        """Handle request in a new thread."""
        thread = threading.Thread(target=self.process_request_thread,
                                  args=(request, client_address))
        thread.daemon = True
        thread.start()

    def process_request_thread(self, request, client_address):
        """Process request in thread."""
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


def create_self_signed_cert(cert_path: str, key_path: str):
    """Create a self-signed certificate for the server."""
    from subprocess import run

    logger.info("Generating self-signed certificate...")

    run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
        '-keyout', key_path, '-out', cert_path,
        '-days', '365', '-nodes',
        '-subj', '/CN=ssl-extract-server/O=sslxtract'
    ], check=True)

    logger.info(f"Certificate saved to {cert_path}")
    logger.info(f"Key saved to {key_path}")


def main():
    parser = argparse.ArgumentParser(
        description='HTTPS server for remote SSL certificate extraction',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Start with default config
  %(prog)s -c config.json           # Start with config file
  %(prog)s --init-config config.json  # Generate default config
  %(prog)s --generate-cert          # Generate self-signed cert

API Endpoints:
  GET  /health                      # Health check
  GET  /extract?target=host:port    # Extract certificate
  POST /extract                     # Extract with JSON body
  POST /extract/batch               # Batch extraction
  GET  /certs                       # List stored certificates
  GET  /certs/<id>                  # Get certificate info
  GET  /certs/<id>/pem              # Download PEM file
  DELETE /certs/<id>                # Delete stored certificate
"""
    )

    parser.add_argument('-c', '--config', help='Path to JSON config file')
    parser.add_argument('--host', help='Bind address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, help='Port number (default: 8443)')
    parser.add_argument('--cert', help='SSL certificate file')
    parser.add_argument('--key', help='SSL key file')
    parser.add_argument('--no-ssl', action='store_true', help='Run without SSL (HTTP only)')
    parser.add_argument('--init-config', metavar='FILE', help='Generate default config file and exit')
    parser.add_argument('--generate-cert', action='store_true', help='Generate self-signed certificate')
    parser.add_argument('--storage', help='Certificate storage directory')

    args = parser.parse_args()

    # Generate config file
    if args.init_config:
        config = Config()
        config.save(args.init_config)
        print(f"Config file saved to {args.init_config}")
        return

    # Load config
    config = Config(args.config)

    # Override with CLI args
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port
    if args.cert:
        config.ssl_cert = args.cert
    if args.key:
        config.ssl_key = args.key
    if args.storage:
        config.storage_dir = args.storage

    # Generate self-signed cert if requested
    if args.generate_cert:
        cert_path = config.ssl_cert or 'server.crt'
        key_path = config.ssl_key or 'server.key'
        create_self_signed_cert(cert_path, key_path)
        config.ssl_cert = cert_path
        config.ssl_key = key_path
        return

    # Create components
    extractor = SSLExtractor(timeout=config.timeout)
    store = CertificateStore(config.storage_dir)
    semaphore = threading.Semaphore(config.max_concurrent)

    # Configure handler
    SSLExtractHandler.config = config
    SSLExtractHandler.extractor = extractor
    SSLExtractHandler.store = store
    SSLExtractHandler.semaphore = semaphore

    # Create server
    server = ThreadedHTTPServer((config.host, config.port), SSLExtractHandler)

    # Setup SSL
    if not args.no_ssl:
        if not config.ssl_cert or not config.ssl_key:
            logger.error("SSL certificate and key required. Use --generate-cert or --no-ssl")
            sys.exit(1)

        if not os.path.exists(config.ssl_cert) or not os.path.exists(config.ssl_key):
            logger.error(f"SSL files not found: {config.ssl_cert}, {config.ssl_key}")
            sys.exit(1)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(config.ssl_cert, config.ssl_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"

    logger.info(f"Starting server on {scheme}://{config.host}:{config.port}")
    logger.info(f"Certificate storage: {config.storage_dir}")

    if config.require_auth:
        logger.info("API key authentication enabled")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
