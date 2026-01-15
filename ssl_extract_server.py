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
import socket
import subprocess
import shutil
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

# Import the extractor from sslxtract
from sslxtract import SSLExtractor, der_to_pem, get_cert_info, parse_target

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
    from cryptography.hazmat.backends import default_backend
    import certifi
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

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
        self.ssl_combined: Optional[str] = None  # Combined cert+key PEM file
        self.storage_dir: str = "./certs"
        self.timeout: float = 10.0
        self.allowed_hosts: Optional[list] = None  # None = allow all
        self.blocked_hosts: list = []
        self.require_auth: bool = False
        self.api_keys: list = []
        self.max_concurrent: int = 10
        self.log_requests: bool = True

        # Self-signed certificate settings
        self.self_signed_cert: Optional[str] = None
        self.self_signed_key: Optional[str] = None

        # Let's Encrypt settings
        self.enable_letsencrypt: bool = False
        self.letsencrypt_domain: Optional[str] = None
        self.letsencrypt_email: Optional[str] = None
        self.letsencrypt_cert: Optional[str] = None
        self.letsencrypt_key: Optional[str] = None
        self.letsencrypt_webroot: Optional[str] = None
        self.letsencrypt_staging: bool = False  # Use staging server for testing

        # CA Chain Verification settings
        # enabled: verify and reject untrusted chains
        # disabled: skip verification
        # logonly: verify but only log warnings, don't reject
        self.verify_public_ca_chains: str = "disabled"  # enabled, disabled, logonly
        self.verify_public_ca_chains_depth: int = 8  # Max intermediate cert depth

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
            'ssl_combined': self.ssl_combined,
            'storage_dir': self.storage_dir,
            'timeout': self.timeout,
            'allowed_hosts': self.allowed_hosts,
            'blocked_hosts': self.blocked_hosts,
            'require_auth': self.require_auth,
            'api_keys': self.api_keys,
            'max_concurrent': self.max_concurrent,
            'log_requests': self.log_requests,
            'self_signed_cert': self.self_signed_cert,
            'self_signed_key': self.self_signed_key,
            'enable_letsencrypt': self.enable_letsencrypt,
            'letsencrypt_domain': self.letsencrypt_domain,
            'letsencrypt_email': self.letsencrypt_email,
            'letsencrypt_cert': self.letsencrypt_cert,
            'letsencrypt_key': self.letsencrypt_key,
            'letsencrypt_webroot': self.letsencrypt_webroot,
            'letsencrypt_staging': self.letsencrypt_staging,
            'verify_public_ca_chains': self.verify_public_ca_chains,
            'verify_public_ca_chains_depth': self.verify_public_ca_chains_depth
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


class CAChainVerifier:
    """
    Verifies certificate chains against public CA roots.

    Supports complex intermediate certificate relationships up to configurable depth.
    """

    def __init__(self, max_depth: int = 8, mode: str = "enabled"):
        """
        Initialize the CA chain verifier.

        Args:
            max_depth: Maximum depth of intermediate certificates to verify (default: 8)
            mode: Verification mode - 'enabled', 'disabled', or 'logonly'
        """
        self.max_depth = max_depth
        self.mode = mode
        self._ca_store = None
        self._load_ca_store()

    def _load_ca_store(self):
        """Load the system/bundled CA certificates."""
        if not CRYPTO_AVAILABLE:
            logger.warning("cryptography/certifi not available - CA verification disabled")
            return

        try:
            # Load CA certificates from certifi bundle
            ca_bundle_path = certifi.where()
            self._ca_certs = {}

            with open(ca_bundle_path, 'rb') as f:
                pem_data = f.read()

            # Parse all certificates from the bundle
            for cert_pem in pem_data.split(b'-----END CERTIFICATE-----'):
                if b'-----BEGIN CERTIFICATE-----' in cert_pem:
                    cert_pem = cert_pem + b'-----END CERTIFICATE-----'
                    try:
                        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
                        # Index by subject for quick lookup
                        subject_bytes = cert.subject.public_bytes()
                        self._ca_certs[subject_bytes] = cert
                    except Exception:
                        pass

            logger.info(f"Loaded {len(self._ca_certs)} CA certificates for chain verification")
        except Exception as e:
            logger.warning(f"Failed to load CA store: {e}")
            self._ca_certs = {}

    def _find_issuer(self, cert: 'x509.Certificate') -> Optional['x509.Certificate']:
        """Find the issuer certificate from the CA store."""
        if not self._ca_certs:
            return None

        issuer_bytes = cert.issuer.public_bytes()
        return self._ca_certs.get(issuer_bytes)

    def _is_self_signed(self, cert: 'x509.Certificate') -> bool:
        """Check if certificate is self-signed."""
        return cert.issuer == cert.subject

    def verify_chain(self, der_certs: list) -> Dict[str, Any]:
        """
        Verify a certificate chain against public CA roots.

        Args:
            der_certs: List of DER-encoded certificates (leaf first, then intermediates)

        Returns:
            Dictionary with verification results:
            {
                'verified': bool,
                'chain_depth': int,
                'errors': list[str],
                'warnings': list[str],
                'chain_info': list[dict]  # Info about each cert in chain
            }
        """
        result = {
            'verified': False,
            'chain_depth': 0,
            'errors': [],
            'warnings': [],
            'chain_info': []
        }

        if self.mode == "disabled":
            result['verified'] = True
            result['warnings'].append("CA chain verification disabled")
            return result

        if not CRYPTO_AVAILABLE:
            result['errors'].append("cryptography library not available")
            return result

        if not der_certs:
            result['errors'].append("No certificates provided")
            return result

        try:
            # Parse all provided certificates
            chain = []
            for i, der_cert in enumerate(der_certs):
                try:
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    chain.append(cert)
                    result['chain_info'].append({
                        'position': i,
                        'subject': cert.subject.rfc4514_string(),
                        'issuer': cert.issuer.rfc4514_string(),
                        'serial': str(cert.serial_number),
                        'not_before': cert.not_valid_before.isoformat(),
                        'not_after': cert.not_valid_after.isoformat(),
                        'is_ca': self._is_ca_cert(cert),
                        'self_signed': self._is_self_signed(cert)
                    })
                except Exception as e:
                    result['errors'].append(f"Failed to parse certificate {i}: {e}")
                    return result

            result['chain_depth'] = len(chain)

            if result['chain_depth'] > self.max_depth:
                result['warnings'].append(
                    f"Chain depth {result['chain_depth']} exceeds max depth {self.max_depth}"
                )

            # Verify the chain
            verified, error_msg = self._verify_chain_trust(chain)
            if verified:
                result['verified'] = True
            else:
                result['errors'].append(error_msg)

        except Exception as e:
            result['errors'].append(f"Verification error: {e}")

        return result

    def _is_ca_cert(self, cert: 'x509.Certificate') -> bool:
        """Check if certificate is a CA certificate."""
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            return basic_constraints.value.ca
        except x509.ExtensionNotFound:
            return False

    def _verify_chain_trust(self, chain: list) -> Tuple[bool, str]:
        """
        Verify trust chain from leaf to root.

        Returns:
            Tuple of (verified: bool, error_message: str)
        """
        if not chain:
            return False, "Empty certificate chain"

        current = chain[0]  # Start with leaf

        for depth in range(self.max_depth):
            # Check if current cert is in our trusted CA store
            subject_bytes = current.subject.public_bytes()
            if subject_bytes in self._ca_certs:
                # Found trusted root!
                return True, ""

            # Check if self-signed (potential root)
            if self._is_self_signed(current):
                # Self-signed but not in trusted store
                return False, f"Self-signed certificate not in trusted CA store: {current.subject.rfc4514_string()}"

            # Find issuer in provided chain or CA store
            issuer = None
            issuer_bytes = current.issuer.public_bytes()

            # First check provided chain
            for cert in chain:
                if cert.subject.public_bytes() == issuer_bytes:
                    issuer = cert
                    break

            # Then check CA store
            if not issuer:
                issuer = self._ca_certs.get(issuer_bytes)

            if not issuer:
                return False, f"Cannot find issuer for: {current.subject.rfc4514_string()}"

            # TODO: Actually verify the signature if cryptography supports it
            # For now, we just verify the chain links exist

            current = issuer

        return False, f"Chain depth exceeded maximum ({self.max_depth})"

    def should_reject(self, verification_result: dict) -> bool:
        """
        Determine if the request should be rejected based on verification result.

        Returns True if mode is 'enabled' and verification failed.
        """
        if self.mode == "disabled":
            return False
        if self.mode == "logonly":
            if not verification_result['verified']:
                logger.warning(f"CA chain verification failed (logonly mode): {verification_result['errors']}")
            return False
        # mode == "enabled"
        return not verification_result['verified']


class SSLExtractHandler(BaseHTTPRequestHandler):
    """HTTP request handler for SSL certificate extraction."""

    config: Config = None
    extractor: SSLExtractor = None
    store: CertificateStore = None
    semaphore: threading.Semaphore = None
    chain_verifier: CAChainVerifier = None

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
                    protocol: str = None, servername: str = None,
                    verify_chain: bool = None) -> dict:
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

            # Verify CA chain if enabled
            if self.chain_verifier and self.chain_verifier.mode != "disabled":
                # Use provided chain or just leaf cert
                certs_to_verify = chain if chain else [der_cert]
                verification = self.chain_verifier.verify_chain(certs_to_verify)
                result['chain_verification'] = verification

                # Check if we should reject based on verification result
                if self.chain_verifier.should_reject(verification):
                    raise ValueError(
                        f"CA chain verification failed: {', '.join(verification['errors'])}"
                    )

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


def create_self_signed_cert(cert_path: str, key_path: str,
                            hostname: Optional[str] = None,
                            combined_path: Optional[str] = None,
                            days: int = 365) -> Tuple[str, str, Optional[str]]:
    """
    Create a self-signed certificate for the server.

    Args:
        cert_path: Path to save the certificate
        key_path: Path to save the private key
        hostname: Hostname/CN for the certificate (auto-detected if not provided)
        combined_path: Optional path for combined cert+key file
        days: Certificate validity in days

    Returns:
        Tuple of (cert_path, key_path, combined_path)
    """
    # Auto-detect hostname if not provided
    if not hostname:
        hostname = socket.gethostname()
        try:
            # Try to get FQDN
            fqdn = socket.getfqdn()
            if fqdn and fqdn != 'localhost':
                hostname = fqdn
        except Exception:
            pass

    logger.info(f"Generating self-signed certificate for '{hostname}'...")

    # Ensure parent directories exist
    Path(cert_path).parent.mkdir(parents=True, exist_ok=True)
    Path(key_path).parent.mkdir(parents=True, exist_ok=True)

    # Build SAN extension for modern browsers
    san_ext = f"subjectAltName=DNS:{hostname},DNS:localhost,IP:127.0.0.1"

    # Generate certificate with openssl
    cmd = [
        'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
        '-keyout', key_path, '-out', cert_path,
        '-sha256', '-days', str(days), '-nodes',
        '-subj', f'/CN={hostname}/O=sslxtract/OU=SSL-Extract-Server',
        '-addext', san_ext
    ]

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        # Older openssl might not support -addext, try without SAN
        logger.warning("Falling back to basic cert generation (no SAN extension)")
        cmd = [
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-keyout', key_path, '-out', cert_path,
            '-sha256', '-days', str(days), '-nodes',
            '-subj', f'/CN={hostname}/O=sslxtract/OU=SSL-Extract-Server'
        ]
        subprocess.run(cmd, check=True, capture_output=True, text=True)

    # Set restrictive permissions on key
    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o644)

    logger.info(f"Certificate saved to: {cert_path}")
    logger.info(f"Private key saved to: {key_path}")

    # Create combined file if requested
    if combined_path:
        Path(combined_path).parent.mkdir(parents=True, exist_ok=True)
        with open(combined_path, 'w') as combined:
            with open(cert_path) as cert:
                combined.write(cert.read())
            with open(key_path) as key:
                combined.write(key.read())
        os.chmod(combined_path, 0o600)
        logger.info(f"Combined cert+key saved to: {combined_path}")

    return cert_path, key_path, combined_path


def split_combined_pem(combined_path: str, cert_path: str, key_path: str) -> Tuple[str, str]:
    """
    Split a combined PEM file into separate cert and key files.

    Args:
        combined_path: Path to combined PEM file
        cert_path: Path to save certificate
        key_path: Path to save private key

    Returns:
        Tuple of (cert_path, key_path)
    """
    with open(combined_path) as f:
        content = f.read()

    # Extract certificate(s)
    cert_markers = ('-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----')
    key_markers = [
        ('-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----'),
        ('-----BEGIN RSA PRIVATE KEY-----', '-----END RSA PRIVATE KEY-----'),
        ('-----BEGIN EC PRIVATE KEY-----', '-----END EC PRIVATE KEY-----'),
    ]

    certs = []
    remaining = content
    while cert_markers[0] in remaining:
        start = remaining.index(cert_markers[0])
        end = remaining.index(cert_markers[1]) + len(cert_markers[1])
        certs.append(remaining[start:end])
        remaining = remaining[end:]

    # Extract private key
    key_content = None
    for key_start, key_end in key_markers:
        if key_start in content:
            start = content.index(key_start)
            end = content.index(key_end) + len(key_end)
            key_content = content[start:end]
            break

    if not certs:
        raise ValueError("No certificate found in combined PEM file")
    if not key_content:
        raise ValueError("No private key found in combined PEM file")

    # Write separate files
    Path(cert_path).parent.mkdir(parents=True, exist_ok=True)
    Path(key_path).parent.mkdir(parents=True, exist_ok=True)

    with open(cert_path, 'w') as f:
        f.write('\n'.join(certs) + '\n')
    with open(key_path, 'w') as f:
        f.write(key_content + '\n')

    os.chmod(cert_path, 0o644)
    os.chmod(key_path, 0o600)

    logger.info(f"Split combined PEM: cert -> {cert_path}, key -> {key_path}")
    return cert_path, key_path


def check_certbot_available() -> Optional[str]:
    """Check if certbot is available and return its path."""
    certbot_path = shutil.which('certbot')
    if certbot_path:
        return certbot_path

    # Check common locations
    common_paths = [
        '/usr/bin/certbot',
        '/usr/local/bin/certbot',
        '/snap/bin/certbot',
        '/opt/certbot/bin/certbot'
    ]
    for path in common_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    return None


def acquire_letsencrypt_cert(
    domain: str,
    email: str,
    cert_dir: str = "./letsencrypt",
    webroot: Optional[str] = None,
    staging: bool = False,
    standalone_port: int = 80
) -> Tuple[str, str, Optional[str]]:
    """
    Acquire a Let's Encrypt certificate using certbot.

    Args:
        domain: Domain name to get certificate for
        email: Email address for Let's Encrypt account
        cert_dir: Directory to store certificates
        webroot: Webroot path for webroot authentication
        staging: Use Let's Encrypt staging server (for testing)
        standalone_port: Port for standalone verification (default 80)

    Returns:
        Tuple of (cert_path, key_path, combined_path)

    Raises:
        RuntimeError: If certbot is not available or fails
    """
    certbot = check_certbot_available()
    if not certbot:
        raise RuntimeError(
            "certbot not found! Install it with:\n"
            "  macOS: brew install certbot\n"
            "  Ubuntu/Debian: sudo apt install certbot\n"
            "  RHEL/CentOS: sudo yum install certbot\n"
            "  Or use snap: sudo snap install certbot --classic"
        )

    cert_dir = Path(cert_dir).resolve()
    cert_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Acquiring Let's Encrypt certificate for '{domain}'...")
    if staging:
        logger.warning("Using Let's Encrypt STAGING server (certificates not trusted)")

    # Build certbot command
    cmd = [
        certbot, 'certonly',
        '--non-interactive',
        '--agree-tos',
        '--email', email,
        '-d', domain,
        '--cert-name', domain,
        '--config-dir', str(cert_dir / 'config'),
        '--work-dir', str(cert_dir / 'work'),
        '--logs-dir', str(cert_dir / 'logs'),
    ]

    if staging:
        cmd.append('--staging')

    if webroot:
        cmd.extend(['--webroot', '-w', webroot])
    else:
        # Use standalone mode
        cmd.extend(['--standalone', '--preferred-challenges', 'http'])
        if standalone_port != 80:
            cmd.extend(['--http-01-port', str(standalone_port)])

    logger.info(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        logger.debug(result.stdout)
    except subprocess.CalledProcessError as e:
        logger.error(f"certbot failed: {e.stderr}")
        raise RuntimeError(f"Let's Encrypt certificate acquisition failed:\n{e.stderr}")

    # Find the certificate files
    live_dir = cert_dir / 'config' / 'live' / domain
    cert_path = live_dir / 'fullchain.pem'
    key_path = live_dir / 'privkey.pem'

    if not cert_path.exists() or not key_path.exists():
        raise RuntimeError(f"Certificate files not found in {live_dir}")

    # Create combined file
    combined_path = cert_dir / f'{domain}-combined.pem'
    with open(combined_path, 'w') as combined:
        with open(cert_path) as cert:
            combined.write(cert.read())
        with open(key_path) as key:
            combined.write(key.read())
    os.chmod(combined_path, 0o600)

    logger.info(f"Let's Encrypt certificate acquired successfully!")
    logger.info(f"  Certificate: {cert_path}")
    logger.info(f"  Private key: {key_path}")
    logger.info(f"  Combined:    {combined_path}")

    return str(cert_path), str(key_path), str(combined_path)


def create_session_ssl(
    mode: str,
    config: Config,
    config_path: Optional[str] = None,
    domain: Optional[str] = None,
    email: Optional[str] = None,
    cert_dir: str = "./ssl",
    staging: bool = False,
    combined: bool = False
) -> Tuple[str, str, Optional[str]]:
    """
    Create SSL certificates for the server session.

    Args:
        mode: 'self' for self-signed, 'letsencrypt' for Let's Encrypt
        config: Server configuration object
        config_path: Path to config file to update
        domain: Domain for Let's Encrypt (required for letsencrypt mode)
        email: Email for Let's Encrypt (required for letsencrypt mode)
        cert_dir: Directory to store certificates
        staging: Use Let's Encrypt staging server
        combined: Also create combined cert+key file

    Returns:
        Tuple of (cert_path, key_path, combined_path)
    """
    cert_dir = Path(cert_dir).resolve()
    cert_dir.mkdir(parents=True, exist_ok=True)

    if mode == 'self':
        # Generate self-signed certificate
        cert_path = str(cert_dir / 'server.crt')
        key_path = str(cert_dir / 'server.key')
        combined_path = str(cert_dir / 'server-combined.pem') if combined else None

        create_self_signed_cert(
            cert_path=cert_path,
            key_path=key_path,
            hostname=domain,
            combined_path=combined_path
        )

        # Update config
        config.ssl_cert = cert_path
        config.ssl_key = key_path
        config.self_signed_cert = cert_path
        config.self_signed_key = key_path
        if combined_path:
            config.ssl_combined = combined_path

    elif mode == 'letsencrypt':
        if not domain:
            raise ValueError("Domain required for Let's Encrypt certificates")
        if not email:
            raise ValueError("Email required for Let's Encrypt certificates")

        cert_path, key_path, combined_path = acquire_letsencrypt_cert(
            domain=domain,
            email=email,
            cert_dir=str(cert_dir),
            staging=staging
        )

        # Update config
        config.ssl_cert = cert_path
        config.ssl_key = key_path
        config.enable_letsencrypt = True
        config.letsencrypt_domain = domain
        config.letsencrypt_email = email
        config.letsencrypt_cert = cert_path
        config.letsencrypt_key = key_path
        config.letsencrypt_staging = staging
        if combined_path:
            config.ssl_combined = combined_path

    else:
        raise ValueError(f"Unknown SSL mode: {mode}. Use 'self' or 'letsencrypt'")

    # Save config if path provided
    if config_path:
        config.save(config_path)
        logger.info(f"Configuration updated: {config_path}")

    return cert_path, key_path, combined_path


def main():
    parser = argparse.ArgumentParser(
        description='HTTPS server for remote SSL certificate extraction',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Start with default config
  %(prog)s -c config.json           # Start with config file
  %(prog)s --init-config config.json  # Generate default config
  %(prog)s --generate-cert          # Generate self-signed cert (legacy)

  # BADASS SSL Session Creation:
  %(prog)s --create-session-ssl=self
      Generate self-signed cert, configure & start server automatically

  %(prog)s --create-session-ssl=letsencrypt --domain=example.com --email=you@example.com
      Acquire Let's Encrypt cert, configure & start server

  %(prog)s --create-session-ssl=self --combined --ssl-dir=./mycerts
      Create self-signed with combined cert+key file

  %(prog)s --create-session-ssl=letsencrypt --domain=api.example.com \\
           --email=admin@example.com --staging --save-config=config.json
      Test Let's Encrypt flow with staging server, save config

  %(prog)s --combined-pem=./combined.pem
      Use existing combined cert+key PEM file

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
    parser.add_argument('--combined-pem', metavar='FILE',
                        help='Combined cert+key PEM file (will split for use)')
    parser.add_argument('--no-ssl', action='store_true', help='Run without SSL (HTTP only)')
    parser.add_argument('--init-config', metavar='FILE', help='Generate default config file and exit')
    parser.add_argument('--generate-cert', action='store_true',
                        help='Generate self-signed certificate (legacy, use --create-session-ssl)')
    parser.add_argument('--storage', help='Certificate storage directory')

    # BADASS SSL Session Creation
    ssl_group = parser.add_argument_group('SSL Session Creation',
        'Automatically generate and configure SSL certificates')
    ssl_group.add_argument('--create-session-ssl', choices=['self', 'letsencrypt'],
                           metavar='MODE',
                           help='Create SSL cert: "self" for self-signed, "letsencrypt" for Let\'s Encrypt')
    ssl_group.add_argument('--domain',
                           help='Domain/hostname for certificate (auto-detected for self-signed)')
    ssl_group.add_argument('--email',
                           help='Email for Let\'s Encrypt registration (required for letsencrypt)')
    ssl_group.add_argument('--ssl-dir', default='./ssl',
                           help='Directory to store SSL certificates (default: ./ssl)')
    ssl_group.add_argument('--combined', action='store_true',
                           help='Also create combined cert+key PEM file')
    ssl_group.add_argument('--staging', action='store_true',
                           help="Use Let's Encrypt staging server (for testing)")
    ssl_group.add_argument('--save-config', metavar='FILE',
                           help='Save updated config to file after SSL setup')
    ssl_group.add_argument('--ssl-only', action='store_true',
                           help='Only create SSL certs, do not start server')

    # CA Chain Verification
    verify_group = parser.add_argument_group('CA Chain Verification',
        'Verify extracted certificates against public CA roots')
    verify_group.add_argument('--verify-ca-chains', choices=['enabled', 'disabled', 'logonly'],
                              metavar='MODE', dest='verify_ca_chains',
                              help='CA chain verification: enabled (reject untrusted), '
                                   'disabled (skip), logonly (warn only)')
    verify_group.add_argument('--verify-ca-depth', type=int, metavar='N',
                              dest='verify_ca_depth',
                              help='Max depth of intermediate CA chain to verify (default: 8)')

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
    if args.verify_ca_chains:
        config.verify_public_ca_chains = args.verify_ca_chains
    if args.verify_ca_depth:
        config.verify_public_ca_chains_depth = args.verify_ca_depth

    # Handle combined PEM file
    if args.combined_pem:
        if not os.path.exists(args.combined_pem):
            logger.error(f"Combined PEM file not found: {args.combined_pem}")
            sys.exit(1)
        ssl_dir = Path(args.ssl_dir).resolve()
        ssl_dir.mkdir(parents=True, exist_ok=True)
        cert_path, key_path = split_combined_pem(
            args.combined_pem,
            str(ssl_dir / 'server.crt'),
            str(ssl_dir / 'server.key')
        )
        config.ssl_cert = cert_path
        config.ssl_key = key_path
        config.ssl_combined = str(Path(args.combined_pem).resolve())

    # BADASS SSL Session Creation
    if args.create_session_ssl:
        mode = args.create_session_ssl

        # Validate letsencrypt requirements
        if mode == 'letsencrypt':
            if not args.domain:
                logger.error("--domain required for Let's Encrypt certificates")
                sys.exit(1)
            if not args.email:
                logger.error("--email required for Let's Encrypt registration")
                sys.exit(1)

        try:
            cert_path, key_path, combined_path = create_session_ssl(
                mode=mode,
                config=config,
                config_path=args.save_config,
                domain=args.domain,
                email=args.email,
                cert_dir=args.ssl_dir,
                staging=args.staging,
                combined=args.combined
            )

            logger.info("=" * 60)
            logger.info("SSL SESSION CREATED SUCCESSFULLY!")
            logger.info("=" * 60)
            logger.info(f"  Mode:        {mode}")
            logger.info(f"  Certificate: {cert_path}")
            logger.info(f"  Private Key: {key_path}")
            if combined_path:
                logger.info(f"  Combined:    {combined_path}")
            if args.save_config:
                logger.info(f"  Config:      {args.save_config}")
            logger.info("=" * 60)

            if args.ssl_only:
                logger.info("SSL-only mode: not starting server")
                return

        except Exception as e:
            logger.error(f"SSL session creation failed: {e}")
            sys.exit(1)

    # Generate self-signed cert if requested (legacy)
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

    # Create CA chain verifier if enabled
    chain_verifier = None
    if config.verify_public_ca_chains != "disabled":
        chain_verifier = CAChainVerifier(
            max_depth=config.verify_public_ca_chains_depth,
            mode=config.verify_public_ca_chains
        )
        logger.info(f"CA chain verification: {config.verify_public_ca_chains} "
                    f"(max depth: {config.verify_public_ca_chains_depth})")

    # Configure handler
    SSLExtractHandler.config = config
    SSLExtractHandler.extractor = extractor
    SSLExtractHandler.store = store
    SSLExtractHandler.semaphore = semaphore
    SSLExtractHandler.chain_verifier = chain_verifier

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
