#!/usr/bin/env python3
"""
ssltool - SSL/TLS key and certificate format conversion utility

Convert between PEM, DER, PKCS#7, and PKCS#12 formats for:
- X.509 certificates
- RSA private keys
- ECDSA private keys
- EC parameters

Usage:
    ssltool x509 -inform pem -outform der -in cert.pem -out cert.der
    ssltool rsa -inform der -in key.der > key.pem
    ssltool ecdsa -inform pem -in key.pem -text
    ssltool ecparam -name secp256r1 -out params.pem
"""

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import urllib.request
import urllib.parse
from datetime import datetime
from typing import Optional, List, Dict, Any


# Format aliases
FORMAT_ALIASES = {
    'pem': 'PEM',
    'der': 'DER',
    'x509': 'PEM',  # X.509 text is PEM
    'p7b': 'PKCS7',
    'pkcs7': 'PKCS7',
    'pkcs12': 'PKCS12',
    'pfx': 'PKCS12',
    'auto': 'AUTO',
}


def detect_format(data: bytes) -> str:
    """Auto-detect input format from file content."""
    if data.startswith(b'-----BEGIN'):
        return 'PEM'
    # PKCS#12/PFX magic bytes
    if data[:2] == b'\x30\x82':
        # Could be DER or PKCS12, check for PKCS12 structure
        # PKCS12 typically has specific OIDs
        if b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07' in data[:50]:
            return 'PKCS12'
        return 'DER'
    if data[:2] == b'\x30\x80' or data[:1] == b'\x30':
        return 'DER'
    # PKCS#7 signature
    if b'-----BEGIN PKCS7-----' in data or b'-----BEGIN CERTIFICATE-----' in data:
        return 'PEM'
    return 'DER'  # Default to DER for binary


def read_input(infile: Optional[str]) -> bytes:
    """Read input from file or stdin."""
    if infile and infile != '-':
        with open(infile, 'rb') as f:
            return f.read()
    else:
        return sys.stdin.buffer.read()


def write_output(data: bytes, outfile: Optional[str], is_text: bool = False):
    """Write output to file or stdout."""
    if outfile and outfile != '-':
        mode = 'w' if is_text else 'wb'
        with open(outfile, mode) as f:
            f.write(data.decode() if is_text and isinstance(data, bytes) else data)
    else:
        if is_text:
            sys.stdout.write(data.decode() if isinstance(data, bytes) else data)
        else:
            sys.stdout.buffer.write(data)


def run_openssl(args: List[str], input_data: Optional[bytes] = None) -> tuple:
    """Run openssl command and return stdout, stderr, returncode."""
    try:
        proc = subprocess.run(
            ['openssl'] + args,
            input=input_data,
            capture_output=True,
            timeout=30
        )
        return proc.stdout, proc.stderr, proc.returncode
    except FileNotFoundError:
        print("Error: openssl not found in PATH", file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("Error: openssl command timed out", file=sys.stderr)
        sys.exit(1)


def cmd_x509(args):
    """Handle x509 certificate operations."""
    data = read_input(args.infile)

    # Auto-detect input format
    inform = FORMAT_ALIASES.get(args.inform.lower(), args.inform.upper())
    if inform == 'AUTO':
        inform = detect_format(data)

    outform = FORMAT_ALIASES.get(args.outform.lower(), args.outform.upper())

    # Build openssl command
    cmd = ['x509']
    cmd.extend(['-inform', inform])
    cmd.extend(['-outform', outform])

    if args.text:
        cmd.append('-text')
        cmd.append('-noout')

    if args.noout:
        cmd.append('-noout')

    if args.subject:
        cmd.append('-subject')

    if args.issuer:
        cmd.append('-issuer')

    if args.dates:
        cmd.append('-dates')

    if args.fingerprint:
        cmd.append('-fingerprint')
        if args.hash_alg:
            cmd.append(f'-{args.hash_alg}')

    if args.serial:
        cmd.append('-serial')

    if args.purpose:
        cmd.append('-purpose')

    if args.modulus:
        cmd.append('-modulus')

    if args.pubkey:
        cmd.append('-pubkey')

    stdout, stderr, rc = run_openssl(cmd, data)

    if stderr:
        sys.stderr.write(stderr.decode())

    if rc != 0:
        sys.exit(rc)

    is_text = args.text or args.noout or args.subject or args.issuer or args.dates
    write_output(stdout, args.outfile, is_text=is_text)


def cmd_rsa(args):
    """Handle RSA key operations."""
    data = read_input(args.infile)

    inform = FORMAT_ALIASES.get(args.inform.lower(), args.inform.upper())
    if inform == 'AUTO':
        inform = detect_format(data)

    outform = FORMAT_ALIASES.get(args.outform.lower(), args.outform.upper())

    cmd = ['rsa']
    cmd.extend(['-inform', inform])
    cmd.extend(['-outform', outform])

    if args.text:
        cmd.append('-text')
        cmd.append('-noout')

    if args.noout:
        cmd.append('-noout')

    if args.modulus:
        cmd.append('-modulus')

    if args.check:
        cmd.append('-check')

    if args.pubin:
        cmd.append('-pubin')

    if args.pubout:
        cmd.append('-pubout')

    if args.passin:
        cmd.extend(['-passin', args.passin])

    if args.passout:
        cmd.extend(['-passout', args.passout])

    stdout, stderr, rc = run_openssl(cmd, data)

    if stderr:
        sys.stderr.write(stderr.decode())

    if rc != 0:
        sys.exit(rc)

    is_text = args.text or args.noout or args.modulus or args.check
    write_output(stdout, args.outfile, is_text=is_text)


def cmd_ecdsa(args):
    """Handle ECDSA/EC key operations."""
    data = read_input(args.infile)

    inform = FORMAT_ALIASES.get(args.inform.lower(), args.inform.upper())
    if inform == 'AUTO':
        inform = detect_format(data)

    outform = FORMAT_ALIASES.get(args.outform.lower(), args.outform.upper())

    cmd = ['ec']
    cmd.extend(['-inform', inform])
    cmd.extend(['-outform', outform])

    if args.text:
        cmd.append('-text')
        cmd.append('-noout')

    if args.noout:
        cmd.append('-noout')

    if args.pubin:
        cmd.append('-pubin')

    if args.pubout:
        cmd.append('-pubout')

    if args.param_out:
        cmd.append('-param_out')

    if args.check:
        cmd.append('-check')

    if args.passin:
        cmd.extend(['-passin', args.passin])

    if args.passout:
        cmd.extend(['-passout', args.passout])

    stdout, stderr, rc = run_openssl(cmd, data)

    if stderr:
        sys.stderr.write(stderr.decode())

    if rc != 0:
        sys.exit(rc)

    is_text = args.text or args.noout or args.param_out or args.check
    write_output(stdout, args.outfile, is_text=is_text)


def get_cert_cn_and_sans(data: bytes, inform: str) -> tuple:
    """Extract CN and SANs from certificate."""
    # Get subject CN
    stdout, _, rc = run_openssl(['x509', '-inform', inform, '-noout', '-subject'], data)
    cn = None
    if rc == 0:
        subject = stdout.decode().strip()
        # Parse CN from subject line
        if 'CN=' in subject or 'CN =' in subject:
            for part in subject.split('/'):
                if part.startswith('CN=') or part.startswith('CN ='):
                    cn = part.split('=', 1)[1].strip()
                    break
            # Also try comma-separated format
            if not cn:
                for part in subject.split(','):
                    part = part.strip()
                    if part.startswith('CN=') or part.startswith('CN '):
                        cn = part.split('=', 1)[1].strip()
                        break

    # Get SANs
    stdout, _, rc = run_openssl(['x509', '-inform', inform, '-noout', '-ext', 'subjectAltName'], data)
    sans = []
    if rc == 0:
        for line in stdout.decode().split('\n'):
            line = line.strip()
            if line.startswith('DNS:'):
                sans.extend([s.strip()[4:] for s in line.split(',') if s.strip().startswith('DNS:')])

    return cn, sans


def get_cert_fingerprint(data: bytes, inform: str) -> str:
    """Get SHA256 fingerprint of certificate."""
    stdout, _, rc = run_openssl(['x509', '-inform', inform, '-outform', 'DER'], data)
    if rc == 0:
        return hashlib.sha256(stdout).hexdigest().upper()
    return ""


def query_crtsh(domain: str, include_expired: bool = False, limit: int = 100) -> List[Dict[str, Any]]:
    """Query crt.sh for certificates matching domain."""
    # URL encode the domain (handles wildcards)
    encoded = urllib.parse.quote(domain, safe='')
    url = f"https://crt.sh/?q={encoded}&output=json"
    if not include_expired:
        url += "&exclude=expired"

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'ssltool/1.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            return data[:limit] if isinstance(data, list) else []
    except urllib.error.HTTPError as e:
        print(f"Error: HTTP {e.code} from crt.sh", file=sys.stderr)
        return []
    except urllib.error.URLError as e:
        print(f"Error: Could not connect to crt.sh: {e.reason}", file=sys.stderr)
        return []
    except json.JSONDecodeError:
        print("Error: Invalid response from crt.sh", file=sys.stderr)
        return []
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return []


def search_ct_by_fingerprint(fingerprint: str) -> Optional[Dict[str, Any]]:
    """Search crt.sh by SHA256 fingerprint."""
    # crt.sh expects fingerprint without colons
    fp_clean = fingerprint.replace(':', '').upper()
    url = f"https://crt.sh/?q={fp_clean}&output=json"

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'ssltool/1.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            if isinstance(data, list) and len(data) > 0:
                return data[0]
            return None
    except Exception:
        return None


def format_ct_entry(entry: Dict[str, Any], verbose: bool = False) -> str:
    """Format a CT log entry for display."""
    lines = []
    cert_id = entry.get('id', 'N/A')
    name = entry.get('common_name') or entry.get('name_value', 'N/A')
    issuer = entry.get('issuer_name', 'N/A')
    not_before = entry.get('not_before', 'N/A')
    not_after = entry.get('not_after', 'N/A')
    serial = entry.get('serial_number', '')

    lines.append(f"  ID: {cert_id}")
    lines.append(f"  CN: {name}")
    lines.append(f"  Issuer: {issuer}")
    lines.append(f"  Valid: {not_before} - {not_after}")

    if verbose:
        if serial:
            lines.append(f"  Serial: {serial}")
        entry_ts = entry.get('entry_timestamp', '')
        if entry_ts:
            lines.append(f"  Logged: {entry_ts}")
        lines.append(f"  URL: https://crt.sh/?id={cert_id}")

    return '\n'.join(lines)


def cmd_ct(args):
    """Handle Certificate Transparency log search."""
    results = []

    if args.domain:
        # Search by domain
        print(f"Searching CT logs for: {args.domain}", file=sys.stderr)
        results = query_crtsh(args.domain, args.expired, args.limit)

    elif args.infile:
        # Search by certificate
        data = read_input(args.infile)
        inform = FORMAT_ALIASES.get(args.inform.lower(), args.inform.upper())
        if inform == 'AUTO':
            inform = detect_format(data)

        # Get fingerprint
        fingerprint = get_cert_fingerprint(data, inform)
        if fingerprint:
            print(f"Searching CT logs for fingerprint: {fingerprint[:16]}...", file=sys.stderr)
            entry = search_ct_by_fingerprint(fingerprint)
            if entry:
                results = [entry]
            else:
                # Fall back to CN/SAN search
                cn, sans = get_cert_cn_and_sans(data, inform)
                search_term = cn or (sans[0] if sans else None)
                if search_term:
                    print(f"Fingerprint not found, searching by CN: {search_term}", file=sys.stderr)
                    results = query_crtsh(search_term, args.expired, args.limit)
                else:
                    print("Error: Could not extract CN or SAN from certificate", file=sys.stderr)
                    sys.exit(1)
        else:
            print("Error: Could not compute certificate fingerprint", file=sys.stderr)
            sys.exit(1)
    else:
        print("Error: Must specify -domain or -in", file=sys.stderr)
        sys.exit(1)

    if not results:
        print("No certificates found in CT logs", file=sys.stderr)
        sys.exit(0)

    print(f"\nFound {len(results)} certificate(s):\n", file=sys.stderr)

    if args.json:
        # JSON output to stdout
        print(json.dumps(results, indent=2))
    else:
        # Human-readable output to stdout
        for i, entry in enumerate(results):
            if i > 0:
                print()
            print(f"[{i+1}]")
            print(format_ct_entry(entry, args.verbose))


def cmd_ecparam(args):
    """Handle EC parameter operations."""
    cmd = ['ecparam']

    if args.name:
        cmd.extend(['-name', args.name])

    if args.list_curves:
        cmd.append('-list_curves')

    if args.genkey:
        cmd.append('-genkey')

    if args.text:
        cmd.append('-text')

    if args.noout:
        cmd.append('-noout')

    if args.param_enc:
        cmd.extend(['-param_enc', args.param_enc])

    outform = FORMAT_ALIASES.get(args.outform.lower(), args.outform.upper())
    cmd.extend(['-outform', outform])

    # Read input if provided (for existing params)
    input_data = None
    if args.infile:
        input_data = read_input(args.infile)
        inform = FORMAT_ALIASES.get(args.inform.lower(), args.inform.upper())
        if inform == 'AUTO':
            inform = detect_format(input_data)
        cmd.extend(['-inform', inform])

    stdout, stderr, rc = run_openssl(cmd, input_data)

    if stderr:
        sys.stderr.write(stderr.decode())

    if rc != 0:
        sys.exit(rc)

    is_text = args.text or args.noout or args.list_curves
    write_output(stdout, args.outfile, is_text=is_text)


def main():
    parser = argparse.ArgumentParser(
        description='SSL/TLS key and certificate format conversion utility',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s x509 -inform pem -outform der -in cert.pem -out cert.der
  %(prog)s x509 -inform auto -in cert.pem -text
  %(prog)s rsa -inform der -in key.der -outform pem > key.pem
  %(prog)s ecdsa -in key.pem -text
  %(prog)s ecparam -name secp256r1 -genkey -out eckey.pem
  %(prog)s ecparam -list_curves
  %(prog)s ct -in cert.pem                    # Search CT logs for certificate
  %(prog)s ct -domain example.com             # Search CT logs by domain
  %(prog)s ct -domain "%.example.com"         # Search with wildcard

Supported formats:
  pem      - Base64 encoded with headers (default)
  der      - Binary DER encoding
  p7b      - PKCS#7/P7B format
  pkcs12   - PKCS#12/PFX format (certificates)
  auto     - Auto-detect input format
"""
    )

    subparsers = parser.add_subparsers(dest='command', help='Command')

    # x509 subcommand
    x509_parser = subparsers.add_parser('x509', help='X.509 certificate operations')
    x509_parser.add_argument('-inform', default='auto',
                             help='Input format (pem|der|p7b|pkcs12|auto)')
    x509_parser.add_argument('-outform', default='pem',
                             help='Output format (pem|der|p7b)')
    x509_parser.add_argument('-in', dest='infile', help='Input file (default: stdin)')
    x509_parser.add_argument('-out', dest='outfile', help='Output file (default: stdout)')
    x509_parser.add_argument('-text', action='store_true', help='Print certificate text')
    x509_parser.add_argument('-noout', action='store_true', help='No certificate output')
    x509_parser.add_argument('-subject', action='store_true', help='Print subject')
    x509_parser.add_argument('-issuer', action='store_true', help='Print issuer')
    x509_parser.add_argument('-dates', action='store_true', help='Print validity dates')
    x509_parser.add_argument('-fingerprint', action='store_true', help='Print fingerprint')
    x509_parser.add_argument('-hash', dest='hash_alg', choices=['sha1', 'sha256', 'sha384', 'sha512'],
                             help='Hash algorithm for fingerprint')
    x509_parser.add_argument('-serial', action='store_true', help='Print serial number')
    x509_parser.add_argument('-purpose', action='store_true', help='Print certificate purposes')
    x509_parser.add_argument('-modulus', action='store_true', help='Print modulus')
    x509_parser.add_argument('-pubkey', action='store_true', help='Output public key')
    x509_parser.set_defaults(func=cmd_x509)

    # rsa subcommand
    rsa_parser = subparsers.add_parser('rsa', help='RSA key operations')
    rsa_parser.add_argument('-inform', default='auto',
                            help='Input format (pem|der|auto)')
    rsa_parser.add_argument('-outform', default='pem',
                            help='Output format (pem|der)')
    rsa_parser.add_argument('-in', dest='infile', help='Input file (default: stdin)')
    rsa_parser.add_argument('-out', dest='outfile', help='Output file (default: stdout)')
    rsa_parser.add_argument('-text', action='store_true', help='Print key details')
    rsa_parser.add_argument('-noout', action='store_true', help='No key output')
    rsa_parser.add_argument('-modulus', action='store_true', help='Print modulus')
    rsa_parser.add_argument('-check', action='store_true', help='Check key consistency')
    rsa_parser.add_argument('-pubin', action='store_true', help='Input is public key')
    rsa_parser.add_argument('-pubout', action='store_true', help='Output public key')
    rsa_parser.add_argument('-passin', help='Input password source')
    rsa_parser.add_argument('-passout', help='Output password source')
    rsa_parser.set_defaults(func=cmd_rsa)

    # ecdsa subcommand
    ecdsa_parser = subparsers.add_parser('ecdsa', help='ECDSA/EC key operations')
    ecdsa_parser.add_argument('-inform', default='auto',
                              help='Input format (pem|der|auto)')
    ecdsa_parser.add_argument('-outform', default='pem',
                              help='Output format (pem|der)')
    ecdsa_parser.add_argument('-in', dest='infile', help='Input file (default: stdin)')
    ecdsa_parser.add_argument('-out', dest='outfile', help='Output file (default: stdout)')
    ecdsa_parser.add_argument('-text', action='store_true', help='Print key details')
    ecdsa_parser.add_argument('-noout', action='store_true', help='No key output')
    ecdsa_parser.add_argument('-pubin', action='store_true', help='Input is public key')
    ecdsa_parser.add_argument('-pubout', action='store_true', help='Output public key')
    ecdsa_parser.add_argument('-param_out', action='store_true', help='Print EC parameters')
    ecdsa_parser.add_argument('-check', action='store_true', help='Check key')
    ecdsa_parser.add_argument('-passin', help='Input password source')
    ecdsa_parser.add_argument('-passout', help='Output password source')
    ecdsa_parser.set_defaults(func=cmd_ecdsa)

    # ecparam subcommand
    ecparam_parser = subparsers.add_parser('ecparam', help='EC parameter operations')
    ecparam_parser.add_argument('-inform', default='auto',
                                help='Input format (pem|der|auto)')
    ecparam_parser.add_argument('-outform', default='pem',
                                help='Output format (pem|der)')
    ecparam_parser.add_argument('-in', dest='infile', help='Input file')
    ecparam_parser.add_argument('-out', dest='outfile', help='Output file (default: stdout)')
    ecparam_parser.add_argument('-name', help='EC curve name (e.g., secp256r1, prime256v1)')
    ecparam_parser.add_argument('-list_curves', action='store_true', help='List available curves')
    ecparam_parser.add_argument('-genkey', action='store_true', help='Generate EC private key')
    ecparam_parser.add_argument('-text', action='store_true', help='Print parameters')
    ecparam_parser.add_argument('-noout', action='store_true', help='No parameter output')
    ecparam_parser.add_argument('-param_enc', choices=['named_curve', 'explicit'],
                                help='Parameter encoding')
    ecparam_parser.set_defaults(func=cmd_ecparam)

    # ct subcommand (Certificate Transparency search)
    ct_parser = subparsers.add_parser('ct', help='Search Certificate Transparency logs')
    ct_parser.add_argument('-in', dest='infile', help='Certificate file to search for')
    ct_parser.add_argument('-inform', default='auto',
                           help='Input format (pem|der|auto)')
    ct_parser.add_argument('-domain', help='Domain to search for (use %% for wildcard)')
    ct_parser.add_argument('-expired', action='store_true',
                           help='Include expired certificates')
    ct_parser.add_argument('-limit', type=int, default=100,
                           help='Maximum results to return (default: 100)')
    ct_parser.add_argument('-json', action='store_true',
                           help='Output as JSON')
    ct_parser.add_argument('-v', '--verbose', action='store_true',
                           help='Show additional details')
    ct_parser.set_defaults(func=cmd_ct)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == '__main__':
    main()
