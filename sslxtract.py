#!/usr/bin/env python3
"""
sslxtract - Blazing fast SSL certificate extraction utility

Extract SSL/TLS certificates from any TCP endpoint:
- Direct TLS connections (HTTPS, IMAPS, POP3S, etc.)
- STARTTLS protocols (SMTP, IMAP, POP3, FTP)

Usage:
    sslxtract <host>:<port> [options]
    sslxtract smtp://mail.example.com:587 [options]
    sslxtract https://example.com [options]
"""

import argparse
import socket
import ssl
import sys
import os
import subprocess
from datetime import datetime
from typing import Optional, Tuple, List
from urllib.parse import urlparse
import concurrent.futures

# ANSI colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def color(text: str, c: str) -> str:
    """Apply color if stdout is a tty."""
    if sys.stdout.isatty():
        return f"{c}{text}{Colors.RESET}"
    return text

# Default ports for protocols
PROTOCOL_PORTS = {
    'https': 443,
    'smtps': 465,
    'smtp': 587,      # STARTTLS
    'imaps': 993,
    'imap': 143,      # STARTTLS
    'pop3s': 995,
    'pop3': 110,      # STARTTLS
    'ftps': 990,
    'ftp': 21,        # STARTTLS
    'ldaps': 636,
    'ldap': 389,      # STARTTLS
    'xmpp': 5222,     # STARTTLS
    'postgres': 5432, # STARTTLS
    'mysql': 3306,    # STARTTLS
}

# Protocols requiring STARTTLS
STARTTLS_PROTOCOLS = {'smtp', 'imap', 'pop3', 'ftp', 'ldap', 'xmpp', 'postgres', 'mysql'}


class SSLExtractor:
    """Fast SSL certificate extractor with protocol support."""

    def __init__(self, timeout: float = 10.0, verify: bool = False):
        self.timeout = timeout
        self.verify = verify

    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for certificate extraction."""
        ctx = ssl.create_default_context()
        if not self.verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def extract_direct_tls(self, host: str, port: int, servername: Optional[str] = None) -> Tuple[bytes, List[bytes]]:
        """Extract certificate via direct TLS connection."""
        ctx = self.create_ssl_context()
        sni = servername or host

        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                # Get the peer certificate in DER format
                der_cert = ssock.getpeercert(binary_form=True)

                # Try to get full chain if available
                chain = []
                try:
                    # Python 3.10+ has get_unverified_chain
                    if hasattr(ssock, 'get_unverified_chain'):
                        for cert in ssock.get_unverified_chain():
                            chain.append(cert.public_bytes(ssl._ssl.ENCODING_DER))
                except Exception:
                    pass

                if not chain and der_cert:
                    chain = [der_cert]

                return der_cert, chain

    def smtp_starttls(self, host: str, port: int) -> Tuple[bytes, List[bytes]]:
        """Extract certificate via SMTP STARTTLS."""
        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)

            # Read banner
            banner = sock.recv(1024)
            if not banner.startswith(b'220'):
                raise ConnectionError(f"SMTP banner error: {banner.decode(errors='ignore')}")

            # Send EHLO
            sock.sendall(b'EHLO sslxtract\r\n')
            response = b''
            while True:
                chunk = sock.recv(1024)
                response += chunk
                if b'\r\n' in chunk and (b'250 ' in response or b'250-' not in response.split(b'\r\n')[-2]):
                    break

            if b'250' not in response:
                raise ConnectionError(f"EHLO failed: {response.decode(errors='ignore')}")

            # Send STARTTLS
            sock.sendall(b'STARTTLS\r\n')
            response = sock.recv(1024)
            if not response.startswith(b'220'):
                raise ConnectionError(f"STARTTLS failed: {response.decode(errors='ignore')}")

            # Upgrade to TLS
            ctx = self.create_ssl_context()
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                chain = [der_cert] if der_cert else []
                return der_cert, chain

    def imap_starttls(self, host: str, port: int) -> Tuple[bytes, List[bytes]]:
        """Extract certificate via IMAP STARTTLS."""
        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)

            # Read banner
            banner = sock.recv(1024)
            if b'OK' not in banner and b'*' not in banner:
                raise ConnectionError(f"IMAP banner error: {banner.decode(errors='ignore')}")

            # Send STARTTLS
            sock.sendall(b'a001 STARTTLS\r\n')
            response = sock.recv(1024)
            if b'OK' not in response:
                raise ConnectionError(f"STARTTLS failed: {response.decode(errors='ignore')}")

            # Upgrade to TLS
            ctx = self.create_ssl_context()
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                chain = [der_cert] if der_cert else []
                return der_cert, chain

    def pop3_starttls(self, host: str, port: int) -> Tuple[bytes, List[bytes]]:
        """Extract certificate via POP3 STARTTLS."""
        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)

            # Read banner
            banner = sock.recv(1024)
            if not banner.startswith(b'+OK'):
                raise ConnectionError(f"POP3 banner error: {banner.decode(errors='ignore')}")

            # Send STLS
            sock.sendall(b'STLS\r\n')
            response = sock.recv(1024)
            if not response.startswith(b'+OK'):
                raise ConnectionError(f"STLS failed: {response.decode(errors='ignore')}")

            # Upgrade to TLS
            ctx = self.create_ssl_context()
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                chain = [der_cert] if der_cert else []
                return der_cert, chain

    def ftp_starttls(self, host: str, port: int) -> Tuple[bytes, List[bytes]]:
        """Extract certificate via FTP AUTH TLS."""
        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)

            # Read banner
            banner = sock.recv(1024)
            if not banner.startswith(b'220'):
                raise ConnectionError(f"FTP banner error: {banner.decode(errors='ignore')}")

            # Send AUTH TLS
            sock.sendall(b'AUTH TLS\r\n')
            response = sock.recv(1024)
            if not response.startswith(b'234'):
                raise ConnectionError(f"AUTH TLS failed: {response.decode(errors='ignore')}")

            # Upgrade to TLS
            ctx = self.create_ssl_context()
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                chain = [der_cert] if der_cert else []
                return der_cert, chain

    def xmpp_starttls(self, host: str, port: int) -> Tuple[bytes, List[bytes]]:
        """Extract certificate via XMPP STARTTLS."""
        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)

            # Send stream header
            stream_header = f"<?xml version='1.0'?><stream:stream to='{host}' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
            sock.sendall(stream_header.encode())

            # Read response until we see features
            response = b''
            while b'</stream:features>' not in response:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk

            if b'starttls' not in response.lower():
                raise ConnectionError("XMPP server doesn't support STARTTLS")

            # Send STARTTLS
            sock.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            response = sock.recv(1024)
            if b'proceed' not in response.lower():
                raise ConnectionError(f"STARTTLS failed: {response.decode(errors='ignore')}")

            # Upgrade to TLS
            ctx = self.create_ssl_context()
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                chain = [der_cert] if der_cert else []
                return der_cert, chain

    def postgres_starttls(self, host: str, port: int) -> Tuple[bytes, List[bytes]]:
        """Extract certificate via PostgreSQL SSL request."""
        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)

            # Send SSL request packet
            # Length (8 bytes) + SSL request code (80877103)
            ssl_request = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
            sock.sendall(ssl_request)

            # Read response (single byte: 'S' for SSL, 'N' for no SSL)
            response = sock.recv(1)
            if response != b'S':
                raise ConnectionError("PostgreSQL server doesn't support SSL")

            # Upgrade to TLS
            ctx = self.create_ssl_context()
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                chain = [der_cert] if der_cert else []
                return der_cert, chain

    def extract(self, host: str, port: int, protocol: Optional[str] = None, servername: Optional[str] = None) -> Tuple[bytes, List[bytes]]:
        """Extract certificate using appropriate method."""
        # Auto-detect protocol based on port if not specified
        if protocol is None:
            protocol = self._detect_protocol(port)

        protocol = protocol.lower() if protocol else 'tls'

        # Use STARTTLS for applicable protocols
        if protocol == 'smtp' and port in (25, 587):
            return self.smtp_starttls(host, port)
        elif protocol == 'imap' and port == 143:
            return self.imap_starttls(host, port)
        elif protocol == 'pop3' and port == 110:
            return self.pop3_starttls(host, port)
        elif protocol == 'ftp' and port == 21:
            return self.ftp_starttls(host, port)
        elif protocol == 'xmpp' and port in (5222, 5269):
            return self.xmpp_starttls(host, port)
        elif protocol == 'postgres' and port == 5432:
            return self.postgres_starttls(host, port)
        else:
            # Direct TLS
            return self.extract_direct_tls(host, port, servername)

    def _detect_protocol(self, port: int) -> str:
        """Detect protocol based on port number."""
        port_to_proto = {v: k for k, v in PROTOCOL_PORTS.items()}
        return port_to_proto.get(port, 'tls')


def der_to_pem(der_cert: bytes) -> str:
    """Convert DER certificate to PEM format."""
    import base64
    b64 = base64.b64encode(der_cert).decode('ascii')
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def parse_target(target: str) -> Tuple[str, int, Optional[str]]:
    """Parse target specification into host, port, protocol."""
    # Handle URL-style input
    if '://' in target:
        parsed = urlparse(target)
        protocol = parsed.scheme.lower()
        host = parsed.hostname or parsed.path
        port = parsed.port or PROTOCOL_PORTS.get(protocol, 443)
        return host, port, protocol

    # Handle host:port format
    if ':' in target:
        host, port_str = target.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            # Might be IPv6 without port
            host = target
            port = 443
    else:
        host = target
        port = 443

    return host, port, None


def get_cert_info(der_cert: bytes, verbose: bool = False) -> dict:
    """Extract certificate information."""
    try:
        pem = der_to_pem(der_cert)

        if verbose:
            # Full certificate details
            result = subprocess.run(
                ['openssl', 'x509', '-noout', '-text'],
                input=pem.encode(),
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                return {'full_text': result.stdout.decode()}

        # Standard info extraction
        result = subprocess.run(
            ['openssl', 'x509', '-noout', '-subject', '-issuer', '-dates', '-serial',
             '-fingerprint', '-sha256'],
            input=pem.encode(),
            capture_output=True,
            timeout=5
        )
        if result.returncode == 0:
            info = {}
            for line in result.stdout.decode().strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                # Handle "key= value" or "key = value" formats
                if '=' in line:
                    key, _, value = line.partition('=')
                    key = key.strip()
                    value = value.strip()
                    # Normalize key names
                    if key == 'subject':
                        info['subject'] = value
                    elif key == 'issuer':
                        info['issuer'] = value
                    elif key == 'notBefore':
                        info['notBefore'] = value
                    elif key == 'notAfter':
                        info['notAfter'] = value
                    elif key == 'serial':
                        info['serial'] = value
                    elif 'Fingerprint' in key:
                        info['SHA256 Fingerprint'] = value
                    else:
                        info[key] = value
            return info
    except Exception:
        pass

    return {'error': 'Could not parse certificate'}


def print_cert_info(der_cert: bytes, verbose: bool = False, label: str = "Certificate"):
    """Print certificate information to stderr."""
    info = get_cert_info(der_cert, verbose)

    print(color(f"\n {label}:", Colors.BOLD + Colors.CYAN), file=sys.stderr)

    if 'full_text' in info:
        # Verbose mode - print full openssl x509 -text output
        print(info['full_text'], file=sys.stderr)
        return

    if 'subject' in info:
        print(f"  Subject: {color(info['subject'], Colors.GREEN)}", file=sys.stderr)
    if 'issuer' in info:
        print(f"  Issuer:  {info['issuer']}", file=sys.stderr)
    if 'notBefore' in info:
        print(f"  Valid:   {info['notBefore']} - {info.get('notAfter', 'N/A')}", file=sys.stderr)
    if 'SHA256 Fingerprint' in info:
        fp = info['SHA256 Fingerprint']
        print(f"  SHA256:  {color(fp, Colors.YELLOW)}", file=sys.stderr)
    if 'san' in info:
        print(f"  SANs:    {', '.join(info['san'][:5])}" +
              (f" (+{len(info['san'])-5} more)" if len(info['san']) > 5 else ""), file=sys.stderr)
    if 'serial' in info:
        print(f"  Serial:  {info['serial']}", file=sys.stderr)

    print(file=sys.stderr)


def print_chain_info(chain: List[bytes], verbose: bool = False, show_leaf: bool = True,
                     show_intermediate: bool = True, show_root: bool = True):
    """Print information about certificate chain."""
    if not chain:
        return

    for i, cert in enumerate(chain):
        is_leaf = (i == 0)
        is_root = (i == len(chain) - 1) and len(chain) > 1
        is_intermediate = not is_leaf and not is_root

        # Determine label
        if is_leaf:
            label = "Leaf Certificate"
            if not show_leaf:
                continue
        elif is_root and len(chain) > 2:
            label = "Root Certificate"
            if not show_root:
                continue
        else:
            label = f"Intermediate Certificate [{i}]"
            if not show_intermediate:
                continue

        print_cert_info(cert, verbose, label)


def pipe_to_openssl(pem_cert: str, openssl_args: List[str]):
    """Pipe certificate to openssl command."""
    cmd = ['openssl'] + openssl_args
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=sys.stdout,
        stderr=sys.stderr
    )
    proc.communicate(input=pem_cert.encode())
    return proc.returncode


def get_expiration_date(der_cert: bytes) -> dict:
    """Get certificate expiration information."""
    pem = der_to_pem(der_cert)
    result = subprocess.run(
        ['openssl', 'x509', '-noout', '-enddate', '-startdate', '-subject'],
        input=pem.encode(),
        capture_output=True,
        timeout=5
    )
    if result.returncode == 0:
        info = {}
        for line in result.stdout.decode().strip().split('\n'):
            if '=' in line:
                key, _, value = line.partition('=')
                info[key.strip()] = value.strip()

        # Parse dates and calculate days until expiry
        from datetime import datetime
        try:
            not_after = info.get('notAfter', '')
            # Parse the date format: "Dec  3 15:49:27 2025 GMT"
            expire_dt = datetime.strptime(not_after.replace('  ', ' '), '%b %d %H:%M:%S %Y %Z')
            days_left = (expire_dt - datetime.utcnow()).days
            info['days_until_expiry'] = days_left
            info['expired'] = days_left < 0
        except Exception:
            pass

        return info
    return {}


def print_expiration(der_cert: bytes, label: str = "Certificate"):
    """Print expiration information."""
    info = get_expiration_date(der_cert)

    subject = info.get('subject', 'Unknown')
    not_after = info.get('notAfter', 'Unknown')
    days_left = info.get('days_until_expiry', '?')
    expired = info.get('expired', False)

    if expired:
        status = color("EXPIRED", Colors.RED + Colors.BOLD)
    elif isinstance(days_left, int) and days_left < 30:
        status = color(f"{days_left} days", Colors.YELLOW + Colors.BOLD)
    elif isinstance(days_left, int):
        status = color(f"{days_left} days", Colors.GREEN)
    else:
        status = "unknown"

    print(f"  {color(label, Colors.CYAN)}: {subject}", file=sys.stderr)
    print(f"    Expires: {not_after} ({status})", file=sys.stderr)


def print_chain_expiration(chain: List[bytes]):
    """Print expiration dates for entire chain."""
    print(color("\n Certificate Chain Expiration:", Colors.BOLD + Colors.CYAN), file=sys.stderr)

    for i, cert in enumerate(chain):
        if i == 0:
            label = "Leaf"
        elif i == len(chain) - 1 and len(chain) > 1:
            label = "Root"
        else:
            label = f"Intermediate [{i}]"
        print_expiration(cert, label)

    print(file=sys.stderr)


def validate_chain(host: str, port: int, servername: str = None) -> dict:
    """Validate SSL certificate chain against system trust store."""
    sni = servername or host
    result = {
        'valid': False,
        'errors': [],
        'warnings': [],
        'chain_complete': False
    }

    try:
        # Try with verification enabled
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                # If we get here, chain is valid
                result['valid'] = True
                result['chain_complete'] = True

                # Get chain info
                cert = ssock.getpeercert()
                if cert:
                    result['subject'] = dict(x[0] for x in cert.get('subject', []))
                    result['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    result['notBefore'] = cert.get('notBefore')
                    result['notAfter'] = cert.get('notAfter')

    except ssl.SSLCertVerificationError as e:
        result['errors'].append(str(e))
        # Try to get more details
        if 'certificate has expired' in str(e).lower():
            result['errors'].append("Certificate has expired")
        elif 'self signed' in str(e).lower():
            result['errors'].append("Self-signed certificate (not trusted)")
        elif 'unable to get local issuer' in str(e).lower():
            result['errors'].append("Incomplete chain - missing intermediate certificate")

    except ssl.SSLError as e:
        result['errors'].append(f"SSL Error: {e}")

    except socket.timeout:
        result['errors'].append("Connection timed out")

    except ConnectionRefusedError:
        result['errors'].append("Connection refused")

    except Exception as e:
        result['errors'].append(f"Error: {e}")

    return result


def print_validation_result(result: dict, target: str):
    """Print certificate validation results."""
    print(color(f"\n Certificate Validation for {target}:", Colors.BOLD + Colors.CYAN), file=sys.stderr)

    if result['valid']:
        print(f"  Status: {color('VALID', Colors.GREEN + Colors.BOLD)}", file=sys.stderr)
        if result.get('subject'):
            cn = result['subject'].get('commonName', 'N/A')
            print(f"  Subject CN: {cn}", file=sys.stderr)
        if result.get('issuer'):
            issuer_cn = result['issuer'].get('commonName', 'N/A')
            print(f"  Issuer CN: {issuer_cn}", file=sys.stderr)
        if result.get('notAfter'):
            print(f"  Expires: {result['notAfter']}", file=sys.stderr)
    else:
        print(f"  Status: {color('INVALID', Colors.RED + Colors.BOLD)}", file=sys.stderr)
        for error in result['errors']:
            print(f"  {color('Error:', Colors.RED)} {error}", file=sys.stderr)

    for warning in result.get('warnings', []):
        print(f"  {color('Warning:', Colors.YELLOW)} {warning}", file=sys.stderr)

    print(file=sys.stderr)


def extract_multiple(targets: List[str], extractor: SSLExtractor, max_workers: int = 10) -> List[Tuple[str, Optional[bytes], Optional[str]]]:
    """Extract certificates from multiple targets in parallel."""
    results = []

    def extract_one(target: str) -> Tuple[str, Optional[bytes], Optional[str]]:
        try:
            host, port, protocol = parse_target(target)
            der_cert, _ = extractor.extract(host, port, protocol)
            return (target, der_cert, None)
        except Exception as e:
            return (target, None, str(e))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(extract_one, t): t for t in targets}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    return results


def main():
    parser = argparse.ArgumentParser(
        description='Extract SSL/TLS certificates from TCP endpoints',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com:443                    # Direct TLS on port 443
  %(prog)s https://example.com                # HTTPS (port 443)
  %(prog)s smtp://mail.example.com:587        # SMTP with STARTTLS
  %(prog)s mail.example.com:25 -p smtp        # SMTP STARTTLS on port 25
  %(prog)s example.com:443 --scan             # Just print cert info, no output
  %(prog)s example.com:443 --scan -v          # Verbose scan (full cert details)
  %(prog)s example.com:443 --save cert.pem    # Save certificate to file
  %(prog)s example.com:443 --chain --save chain.pem  # Save full chain
  %(prog)s example.com:443 | openssl x509 -text  # Pipe to openssl
  %(prog)s example.com:443 --openssl x509 -text  # Built-in openssl pipe
  %(prog)s example.com:443 --show-leaf        # Show only leaf cert info
  %(prog)s example.com:443 --show-intermediate  # Show only intermediates
  %(prog)s -f hosts.txt --scan                # Scan multiple hosts
  %(prog)s host1:443 host2:443 --save ./certs # Save all certs to directory
"""
    )

    parser.add_argument('targets', nargs='*', help='Target(s) in format host:port or protocol://host:port')
    parser.add_argument('-p', '--protocol', choices=['tls', 'smtp', 'imap', 'pop3', 'ftp', 'xmpp', 'postgres'],
                        help='Force protocol (auto-detected by default)')
    parser.add_argument('-s', '--servername', help='SNI server name (defaults to host)')
    parser.add_argument('-t', '--timeout', type=float, default=10.0, help='Connection timeout in seconds')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress all output except certificate')
    parser.add_argument('-f', '--file', help='Read targets from file (one per line)')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Max parallel workers for batch mode')
    parser.add_argument('--verify', action='store_true', help='Verify certificate chain')

    # Output modes
    output_group = parser.add_argument_group('Output modes')
    output_group.add_argument('--scan', action='store_true',
                              help='Scan mode: just print certificate info, no output')
    output_group.add_argument('--save', metavar='FILE',
                              help='Save certificate(s) to file or directory')
    output_group.add_argument('-d', '--der', action='store_true',
                              help='Output DER format instead of PEM')
    output_group.add_argument('-c', '--chain', action='store_true',
                              help='Output full certificate chain')
    output_group.add_argument('-j', '--json', action='store_true',
                              help='Output as JSON (for multiple targets)')
    output_group.add_argument('--openssl', nargs=argparse.REMAINDER,
                              help='Pipe to openssl with these arguments')

    # Display options
    display_group = parser.add_argument_group('Display options')
    display_group.add_argument('-v', '--verbose', action='store_true',
                               help='Show full certificate details (openssl x509 -text)')
    display_group.add_argument('--show-leaf', action='store_true',
                               help='Show only leaf certificate info')
    display_group.add_argument('--show-intermediate', action='store_true',
                               help='Show only intermediate certificate(s) info')
    display_group.add_argument('--show-root', action='store_true',
                               help='Show only root certificate info')

    # Validation options
    validation_group = parser.add_argument_group('Validation options')
    validation_group.add_argument('--validate', action='store_true',
                                  help='Verify SSL certificate chain validity')
    validation_group.add_argument('--expire-date', action='store_true',
                                  help='Show expiration date for leaf certificate')
    validation_group.add_argument('--expire-chain', action='store_true',
                                  help='Show expiration dates for entire certificate chain')

    args = parser.parse_args()

    # Collect targets
    targets = list(args.targets)
    if args.file:
        try:
            with open(args.file) as f:
                targets.extend(line.strip() for line in f if line.strip() and not line.startswith('#'))
        except IOError as e:
            print(f"{color('Error:', Colors.RED)} Cannot read file: {e}", file=sys.stderr)
            sys.exit(1)

    if not targets:
        parser.print_help()
        sys.exit(1)

    extractor = SSLExtractor(timeout=args.timeout, verify=args.verify)

    # Determine which parts of chain to show
    # If none specified, show all
    show_leaf = args.show_leaf or (not args.show_leaf and not args.show_intermediate and not args.show_root)
    show_intermediate = args.show_intermediate or (not args.show_leaf and not args.show_intermediate and not args.show_root)
    show_root = args.show_root or (not args.show_leaf and not args.show_intermediate and not args.show_root)

    # Single target mode
    if len(targets) == 1:
        target = targets[0]
        try:
            host, port, protocol = parse_target(target)
            protocol = args.protocol or protocol

            if not args.quiet:
                print(f"{color('Connecting to', Colors.CYAN)} {host}:{port}" +
                      (f" ({protocol})" if protocol else ""), file=sys.stderr)

            der_cert, chain = extractor.extract(host, port, protocol, args.servername)

            if not der_cert:
                print(f"{color('Error:', Colors.RED)} No certificate received", file=sys.stderr)
                sys.exit(1)

            # Always get chain for display
            if not chain:
                chain = [der_cert]

            # --validate mode: verify certificate chain
            if args.validate:
                validation_result = validate_chain(host, port, args.servername)
                print_validation_result(validation_result, target)
                sys.exit(0 if validation_result['valid'] else 1)

            # --expire-date mode: show expiration date
            if args.expire_date:
                print(color(f"\n Certificate Expiration for {target}:", Colors.BOLD + Colors.CYAN), file=sys.stderr)
                print_expiration(der_cert, "Leaf Certificate")
                print(file=sys.stderr)
                sys.exit(0)

            # --expire-chain mode: show chain expiration dates
            if args.expire_chain:
                print_chain_expiration(chain)
                sys.exit(0)

            # --scan mode: just print info and exit
            if args.scan:
                print_chain_info(chain, args.verbose, show_leaf, show_intermediate, show_root)
                sys.exit(0)

            # Show cert info if verbose or not quiet
            if args.verbose or not args.quiet:
                print_chain_info(chain, args.verbose, show_leaf, show_intermediate, show_root)

            # Determine which certs to output
            output_certs = []
            for i, cert in enumerate(chain):
                is_leaf = (i == 0)
                is_root = (i == len(chain) - 1) and len(chain) > 1
                is_intermediate = not is_leaf and not is_root

                if args.show_leaf and is_leaf:
                    output_certs.append(cert)
                elif args.show_intermediate and is_intermediate:
                    output_certs.append(cert)
                elif args.show_root and is_root:
                    output_certs.append(cert)
                elif args.chain or (not args.show_leaf and not args.show_intermediate and not args.show_root):
                    if args.chain:
                        output_certs.append(cert)

            # Default to leaf cert if no specific selection
            if not output_certs:
                if args.chain:
                    output_certs = chain
                else:
                    output_certs = [der_cert]

            # Format output
            if args.der:
                output = b''.join(output_certs)
            else:
                output = ''.join(der_to_pem(c) for c in output_certs)

            # Pipe to openssl if requested
            if args.openssl:
                if args.der:
                    print(f"{color('Error:', Colors.RED)} Cannot pipe DER to openssl, use PEM", file=sys.stderr)
                    sys.exit(1)
                sys.exit(pipe_to_openssl(output, args.openssl))

            # --save: Write to file
            if args.save:
                mode = 'wb' if args.der else 'w'
                with open(args.save, mode) as f:
                    f.write(output)
                if not args.quiet:
                    print(f"{color('Saved to', Colors.GREEN)} {args.save}", file=sys.stderr)
            elif not args.scan:
                # Output to stdout (unless in scan mode)
                if args.der:
                    sys.stdout.buffer.write(output)
                else:
                    print(output, end='')

            if not args.quiet:
                print(f"{color('Success!', Colors.GREEN)}", file=sys.stderr)

        except socket.timeout:
            print(f"{color('Error:', Colors.RED)} Connection timed out", file=sys.stderr)
            sys.exit(1)
        except ConnectionRefusedError:
            print(f"{color('Error:', Colors.RED)} Connection refused", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"{color('Error:', Colors.RED)} {e}", file=sys.stderr)
            sys.exit(1)

    # Multiple targets mode
    else:
        if not args.quiet:
            print(f"{color('Extracting from', Colors.CYAN)} {len(targets)} targets...", file=sys.stderr)

        results = extract_multiple(targets, extractor, args.workers)

        if args.json:
            import json
            output = []
            for target, der_cert, error in results:
                if der_cert:
                    info = get_cert_info(der_cert)
                    output.append({
                        'target': target,
                        'success': True,
                        'pem': der_to_pem(der_cert),
                        'info': info
                    })
                else:
                    output.append({
                        'target': target,
                        'success': False,
                        'error': error
                    })
            print(json.dumps(output, indent=2))
        else:
            success = 0
            failed = 0
            for target, der_cert, error in results:
                if der_cert:
                    success += 1
                    if not args.quiet:
                        print(f"{color('[OK]', Colors.GREEN)} {target}", file=sys.stderr)

                    # --scan mode: print info
                    if args.scan:
                        print_cert_info(der_cert, args.verbose, f"Certificate for {target}")

                    if args.save:
                        # Save each cert to target-based filename
                        safe_name = target.replace('://', '_').replace(':', '_').replace('/', '_')
                        ext = '.der' if args.der else '.pem'
                        filename = f"{args.save}/{safe_name}{ext}"
                        os.makedirs(args.save, exist_ok=True)
                        mode = 'wb' if args.der else 'w'
                        with open(filename, mode) as f:
                            f.write(der_cert if args.der else der_to_pem(der_cert))
                    elif not args.scan:
                        # Output to stdout
                        print(f"# {target}")
                        print(der_to_pem(der_cert))
                else:
                    failed += 1
                    if not args.quiet:
                        print(f"{color('[FAIL]', Colors.RED)} {target}: {error}", file=sys.stderr)

            if not args.quiet:
                print(f"\n{color('Done:', Colors.BOLD)} {success} succeeded, {failed} failed", file=sys.stderr)

        sys.exit(0 if all(r[1] for r in results) else 1)


if __name__ == '__main__':
    main()
