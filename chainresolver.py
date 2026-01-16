#!/usr/bin/env python3
"""
chainresolver.py - Build complete certificate chains from a leaf certificate

Given a certificate (PEM or DER), this utility will:
1. Parse the certificate and extract AIA (Authority Information Access) URLs
2. Fetch intermediate certificates from the CA's repository
3. Continue up the chain until reaching a root CA
4. Output the complete chain in various formats
5. Optionally check CAA and DANE/TLSA DNS records

Usage:
    chainresolver.py cert.pem                    # Output PEM chain to stdout
    chainresolver.py cert.pem --p12-out bundle.p12 --key key.pem
    chainresolver.py cert.pem --p7b-out chain.p7b
    chainresolver.py cert.pem -o fullchain.pem   # Save PEM chain to file
    chainresolver.py cert.pem --check-caa --domain example.com
    chainresolver.py cert.pem --check-dane --domain example.com --port 443
"""

import argparse
import base64
import hashlib
import os
import sys
import subprocess
import tempfile
import urllib.request
import urllib.error
from typing import Optional, List, Tuple, Dict, Any
from pathlib import Path

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
    if sys.stderr.isatty():
        return f"{c}{text}{Colors.RESET}"
    return text


def log_info(msg: str):
    """Log info message to stderr."""
    print(f"{color('INFO:', Colors.CYAN)} {msg}", file=sys.stderr)


def log_warn(msg: str):
    """Log warning message to stderr."""
    print(f"{color('WARN:', Colors.YELLOW)} {msg}", file=sys.stderr)


def log_error(msg: str):
    """Log error message to stderr."""
    print(f"{color('ERROR:', Colors.RED)} {msg}", file=sys.stderr)


def log_success(msg: str):
    """Log success message to stderr."""
    print(f"{color('OK:', Colors.GREEN)} {msg}", file=sys.stderr)


def der_to_pem(der_cert: bytes) -> str:
    """Convert DER certificate to PEM format."""
    b64 = base64.b64encode(der_cert).decode('ascii')
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def pem_to_der(pem_cert: str) -> bytes:
    """Convert PEM certificate to DER format."""
    # Remove PEM headers and decode
    lines = pem_cert.strip().split('\n')
    b64_data = ''.join(line for line in lines
                       if not line.startswith('-----'))
    return base64.b64decode(b64_data)


def load_certificate(path: str) -> Tuple[bytes, str]:
    """
    Load a certificate from file.

    Returns:
        Tuple of (der_bytes, pem_string)
    """
    with open(path, 'rb') as f:
        content = f.read()

    # Check if it's PEM or DER
    if b'-----BEGIN CERTIFICATE-----' in content:
        # PEM format
        pem = content.decode('utf-8')
        der = pem_to_der(pem)
        return der, pem
    else:
        # Assume DER format
        pem = der_to_pem(content)
        return content, pem


def get_cert_info(der_cert: bytes) -> Dict[str, Any]:
    """Get basic certificate info using openssl."""
    pem = der_to_pem(der_cert)
    result = subprocess.run(
        ['openssl', 'x509', '-noout', '-subject', '-issuer', '-serial', '-fingerprint', '-sha256'],
        input=pem.encode(),
        capture_output=True,
        timeout=10
    )

    info = {}
    if result.returncode == 0:
        for line in result.stdout.decode().strip().split('\n'):
            if '=' in line:
                key, _, value = line.partition('=')
                info[key.strip().lower()] = value.strip()

    return info


def get_aia_urls(der_cert: bytes) -> List[str]:
    """
    Extract AIA (Authority Information Access) CA Issuers URLs from certificate.

    These URLs point to the issuing CA certificate.
    """
    pem = der_to_pem(der_cert)

    # Use openssl to get the AIA extension
    result = subprocess.run(
        ['openssl', 'x509', '-noout', '-text'],
        input=pem.encode(),
        capture_output=True,
        timeout=10
    )

    if result.returncode != 0:
        return []

    text = result.stdout.decode()
    urls = []

    # Parse AIA section
    in_aia = False
    for line in text.split('\n'):
        line = line.strip()

        if 'Authority Information Access' in line:
            in_aia = True
            continue

        if in_aia:
            # Look for CA Issuers URI
            if 'CA Issuers - URI:' in line:
                url = line.split('URI:', 1)[1].strip()
                urls.append(url)
            # Exit AIA section when we hit another extension
            elif line and not line.startswith('CA Issuers') and not line.startswith('OCSP'):
                if ':' in line and 'URI' not in line:
                    in_aia = False

    return urls


def is_self_signed(der_cert: bytes) -> bool:
    """Check if certificate is self-signed (subject == issuer)."""
    pem = der_to_pem(der_cert)

    result = subprocess.run(
        ['openssl', 'x509', '-noout', '-subject', '-issuer'],
        input=pem.encode(),
        capture_output=True,
        timeout=10
    )

    if result.returncode != 0:
        return False

    lines = result.stdout.decode().strip().split('\n')
    if len(lines) >= 2:
        subject = lines[0].replace('subject=', '').strip()
        issuer = lines[1].replace('issuer=', '').strip()
        return subject == issuer

    return False


def fetch_certificate(url: str, timeout: int = 30) -> Optional[bytes]:
    """
    Fetch a certificate from a URL.

    Handles both DER and PEM formats.
    """
    log_info(f"Fetching: {url}")

    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'chainresolver/1.0'}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            content = response.read()

            # Check if it's PEM
            if b'-----BEGIN CERTIFICATE-----' in content:
                return pem_to_der(content.decode('utf-8'))

            # Assume DER
            return content

    except urllib.error.URLError as e:
        log_warn(f"Failed to fetch {url}: {e}")
        return None
    except Exception as e:
        log_warn(f"Error fetching {url}: {e}")
        return None


def get_cert_fingerprint(der_cert: bytes) -> str:
    """Get SHA256 fingerprint of certificate."""
    return hashlib.sha256(der_cert).hexdigest()


# =============================================================================
# CAA (Certification Authority Authorization) Functions
# =============================================================================

def query_dns(name: str, record_type: str, timeout: int = 10) -> List[str]:
    """
    Query DNS records using dig command.

    Args:
        name: DNS name to query
        record_type: Record type (CAA, TLSA, etc.)
        timeout: Query timeout

    Returns:
        List of record data strings
    """
    try:
        result = subprocess.run(
            ['dig', '+short', '+time=' + str(timeout), name, record_type],
            capture_output=True,
            timeout=timeout + 5
        )

        if result.returncode != 0:
            return []

        output = result.stdout.decode().strip()
        if not output:
            return []

        return [line.strip() for line in output.split('\n') if line.strip()]

    except FileNotFoundError:
        log_warn("'dig' command not found - install bind-tools/dnsutils for DNS queries")
        return []
    except Exception as e:
        log_warn(f"DNS query failed: {e}")
        return []


def parse_caa_record(record: str) -> Dict[str, str]:
    """
    Parse a CAA record.

    CAA record format: <flags> <tag> <value>
    Example: 0 issue "letsencrypt.org"

    Returns:
        Dict with 'flags', 'tag', 'value' keys
    """
    parts = record.split(None, 2)
    if len(parts) < 3:
        return {}

    flags, tag, value = parts
    # Remove quotes from value
    value = value.strip('"\'')

    return {
        'flags': flags,
        'tag': tag,
        'value': value
    }


def check_caa_records(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Check CAA (Certification Authority Authorization) records for a domain.

    CAA records specify which CAs are authorized to issue certificates for a domain.

    Args:
        domain: Domain to check
        timeout: DNS query timeout

    Returns:
        Dict with CAA check results:
        {
            'domain': str,
            'records': list of parsed CAA records,
            'authorized_cas': list of authorized CA domains,
            'issue': list of CAs authorized to issue regular certs,
            'issuewild': list of CAs authorized to issue wildcard certs,
            'iodef': list of incident reporting URLs,
            'has_caa': bool,
            'warnings': list of warning messages
        }
    """
    result = {
        'domain': domain,
        'records': [],
        'authorized_cas': [],
        'issue': [],
        'issuewild': [],
        'iodef': [],
        'has_caa': False,
        'warnings': []
    }

    # Check CAA at the domain and parent domains
    parts = domain.split('.')
    checked_domains = []

    for i in range(len(parts)):
        check_domain = '.'.join(parts[i:])
        if len(check_domain) < 2:
            continue

        checked_domains.append(check_domain)
        records = query_dns(check_domain, 'CAA', timeout)

        if records:
            result['has_caa'] = True
            result['caa_domain'] = check_domain

            for record in records:
                parsed = parse_caa_record(record)
                if parsed:
                    result['records'].append({
                        'domain': check_domain,
                        'raw': record,
                        **parsed
                    })

                    tag = parsed.get('tag', '').lower()
                    value = parsed.get('value', '')

                    if tag == 'issue':
                        result['issue'].append(value)
                        if value and value not in result['authorized_cas']:
                            result['authorized_cas'].append(value)
                    elif tag == 'issuewild':
                        result['issuewild'].append(value)
                        if value and value not in result['authorized_cas']:
                            result['authorized_cas'].append(value)
                    elif tag == 'iodef':
                        result['iodef'].append(value)

            # Found CAA records, stop climbing
            break

    if not result['has_caa']:
        result['warnings'].append(f"No CAA records found for {domain} (checked: {', '.join(checked_domains)})")

    return result


def print_caa_results(caa_result: Dict[str, Any]):
    """Print CAA check results."""
    print(file=sys.stderr)
    print(color("=" * 60, Colors.BOLD), file=sys.stderr)
    print(color(f" CAA Records for {caa_result['domain']}", Colors.BOLD + Colors.CYAN), file=sys.stderr)
    print(color("=" * 60, Colors.BOLD), file=sys.stderr)

    if not caa_result['has_caa']:
        print(f"  {color('No CAA records found', Colors.YELLOW)}", file=sys.stderr)
        print(f"  Any CA can issue certificates for this domain", file=sys.stderr)
    else:
        print(f"  CAA found at: {color(caa_result.get('caa_domain', ''), Colors.GREEN)}", file=sys.stderr)
        print(file=sys.stderr)

        if caa_result['issue']:
            print(f"  {color('Authorized CAs (issue):', Colors.BOLD)}", file=sys.stderr)
            for ca in caa_result['issue']:
                if ca:
                    print(f"    - {color(ca, Colors.GREEN)}", file=sys.stderr)
                else:
                    print(f"    - {color('(none - issuance prohibited)', Colors.RED)}", file=sys.stderr)

        if caa_result['issuewild']:
            print(f"  {color('Wildcard CAs (issuewild):', Colors.BOLD)}", file=sys.stderr)
            for ca in caa_result['issuewild']:
                if ca:
                    print(f"    - {color(ca, Colors.GREEN)}", file=sys.stderr)
                else:
                    print(f"    - {color('(none - wildcard issuance prohibited)', Colors.RED)}", file=sys.stderr)

        if caa_result['iodef']:
            print(f"  {color('Incident reporting (iodef):', Colors.BOLD)}", file=sys.stderr)
            for url in caa_result['iodef']:
                print(f"    - {url}", file=sys.stderr)

    for warning in caa_result['warnings']:
        print(f"  {color('Warning:', Colors.YELLOW)} {warning}", file=sys.stderr)

    print(color("=" * 60, Colors.BOLD), file=sys.stderr)


def verify_cert_against_caa(der_cert: bytes, caa_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify a certificate's issuer against CAA records.

    Args:
        der_cert: DER-encoded certificate
        caa_result: CAA check results from check_caa_records()

    Returns:
        Dict with verification result
    """
    result = {
        'verified': False,
        'issuer': None,
        'authorized': None,
        'message': ''
    }

    # Get certificate issuer
    info = get_cert_info(der_cert)
    issuer = info.get('issuer', '')
    result['issuer'] = issuer

    if not caa_result['has_caa']:
        result['verified'] = True
        result['message'] = "No CAA records - any CA is authorized"
        return result

    # Check if any authorized CA matches the issuer
    # This is a heuristic check - real validation requires knowing CA's CAA identifiers
    authorized_cas = caa_result['authorized_cas']

    for ca in authorized_cas:
        if not ca:
            continue
        # Check if CA domain appears in issuer
        ca_lower = ca.lower()
        issuer_lower = issuer.lower()

        # Common CA mappings
        ca_mappings = {
            'letsencrypt.org': ['let\'s encrypt', "let's encrypt", 'letsencrypt'],
            'digicert.com': ['digicert'],
            'sectigo.com': ['sectigo', 'comodo'],
            'globalsign.com': ['globalsign'],
            'godaddy.com': ['godaddy', 'starfield'],
            'amazon.com': ['amazon'],
            'google.com': ['google trust services', 'gts'],
            'pki.goog': ['google trust services', 'gts'],
            'comodoca.com': ['comodo', 'sectigo'],
        }

        # Direct match
        if ca_lower in issuer_lower:
            result['verified'] = True
            result['authorized'] = ca
            result['message'] = f"Issuer matches authorized CA: {ca}"
            return result

        # Check mappings
        for ca_domain, keywords in ca_mappings.items():
            if ca_lower == ca_domain or ca_domain in ca_lower:
                for keyword in keywords:
                    if keyword in issuer_lower:
                        result['verified'] = True
                        result['authorized'] = ca
                        result['message'] = f"Issuer matches authorized CA: {ca}"
                        return result

    result['verified'] = False
    result['message'] = f"Issuer '{issuer}' not in authorized CAs: {authorized_cas}"
    return result


# =============================================================================
# DANE (DNS-based Authentication of Named Entities) / TLSA Functions
# =============================================================================

def get_tlsa_name(domain: str, port: int, protocol: str = 'tcp') -> str:
    """
    Generate TLSA record name.

    Format: _<port>._<protocol>.<domain>
    Example: _443._tcp.example.com
    """
    return f"_{port}._{protocol}.{domain}"


def parse_tlsa_record(record: str) -> Dict[str, Any]:
    """
    Parse a TLSA record.

    TLSA record format: <usage> <selector> <matching-type> <certificate-data>
    Example: 3 1 1 <sha256-hash>

    Usage:
        0 = PKIX-TA (CA constraint)
        1 = PKIX-EE (Service certificate constraint)
        2 = DANE-TA (Trust anchor assertion)
        3 = DANE-EE (Domain-issued certificate)

    Selector:
        0 = Full certificate
        1 = SubjectPublicKeyInfo

    Matching Type:
        0 = Exact match (full data)
        1 = SHA-256 hash
        2 = SHA-512 hash
    """
    parts = record.split()
    if len(parts) < 4:
        return {}

    usage_names = {
        '0': 'PKIX-TA (CA constraint)',
        '1': 'PKIX-EE (Service cert constraint)',
        '2': 'DANE-TA (Trust anchor)',
        '3': 'DANE-EE (Domain-issued cert)'
    }

    selector_names = {
        '0': 'Full certificate',
        '1': 'SubjectPublicKeyInfo'
    }

    matching_names = {
        '0': 'Exact match',
        '1': 'SHA-256',
        '2': 'SHA-512'
    }

    return {
        'usage': parts[0],
        'usage_name': usage_names.get(parts[0], f'Unknown ({parts[0]})'),
        'selector': parts[1],
        'selector_name': selector_names.get(parts[1], f'Unknown ({parts[1]})'),
        'matching_type': parts[2],
        'matching_name': matching_names.get(parts[2], f'Unknown ({parts[2]})'),
        'data': ''.join(parts[3:]).lower()
    }


def check_dane_records(domain: str, port: int = 443, protocol: str = 'tcp',
                       timeout: int = 10) -> Dict[str, Any]:
    """
    Check DANE/TLSA records for a domain and port.

    DANE (DNS-based Authentication of Named Entities) uses TLSA records
    to bind TLS certificates to DNS names.

    Args:
        domain: Domain to check
        port: Port number (default: 443)
        protocol: Protocol (default: tcp)
        timeout: DNS query timeout

    Returns:
        Dict with DANE check results
    """
    tlsa_name = get_tlsa_name(domain, port, protocol)

    result = {
        'domain': domain,
        'port': port,
        'protocol': protocol,
        'tlsa_name': tlsa_name,
        'records': [],
        'has_dane': False,
        'warnings': []
    }

    records = query_dns(tlsa_name, 'TLSA', timeout)

    if records:
        result['has_dane'] = True
        for record in records:
            parsed = parse_tlsa_record(record)
            if parsed:
                result['records'].append({
                    'raw': record,
                    **parsed
                })
    else:
        result['warnings'].append(f"No TLSA records found at {tlsa_name}")

    return result


def print_dane_results(dane_result: Dict[str, Any]):
    """Print DANE/TLSA check results."""
    print(file=sys.stderr)
    print(color("=" * 60, Colors.BOLD), file=sys.stderr)
    print(color(f" DANE/TLSA Records for {dane_result['domain']}:{dane_result['port']}", Colors.BOLD + Colors.CYAN), file=sys.stderr)
    print(color("=" * 60, Colors.BOLD), file=sys.stderr)

    print(f"  TLSA name: {dane_result['tlsa_name']}", file=sys.stderr)
    print(file=sys.stderr)

    if not dane_result['has_dane']:
        print(f"  {color('No TLSA records found', Colors.YELLOW)}", file=sys.stderr)
        print(f"  DANE is not configured for this service", file=sys.stderr)
    else:
        print(f"  {color('TLSA Records:', Colors.BOLD)}", file=sys.stderr)
        for i, record in enumerate(dane_result['records'], 1):
            print(file=sys.stderr)
            print(f"    {color(f'Record {i}:', Colors.GREEN)}", file=sys.stderr)
            print(f"      Usage:    {record['usage']} - {record['usage_name']}", file=sys.stderr)
            print(f"      Selector: {record['selector']} - {record['selector_name']}", file=sys.stderr)
            print(f"      Matching: {record['matching_type']} - {record['matching_name']}", file=sys.stderr)
            data = record['data']
            if len(data) > 64:
                print(f"      Data:     {data[:32]}...{data[-16:]}", file=sys.stderr)
            else:
                print(f"      Data:     {data}", file=sys.stderr)

    for warning in dane_result['warnings']:
        print(f"  {color('Warning:', Colors.YELLOW)} {warning}", file=sys.stderr)

    print(color("=" * 60, Colors.BOLD), file=sys.stderr)


def get_cert_spki_hash(der_cert: bytes, hash_type: str = 'sha256') -> Optional[str]:
    """
    Get SubjectPublicKeyInfo hash from a certificate.

    Args:
        der_cert: DER-encoded certificate
        hash_type: Hash type ('sha256' or 'sha512')

    Returns:
        Hex-encoded hash string
    """
    pem = der_to_pem(der_cert)

    # Extract public key and hash it
    try:
        # Get the SubjectPublicKeyInfo in DER format
        result = subprocess.run(
            ['openssl', 'x509', '-pubkey', '-noout'],
            input=pem.encode(),
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            return None

        pubkey_pem = result.stdout.decode()

        # Convert to DER
        result = subprocess.run(
            ['openssl', 'pkey', '-pubin', '-outform', 'DER'],
            input=pubkey_pem.encode(),
            capture_output=True,
            timeout=10
        )

        if result.returncode != 0:
            return None

        pubkey_der = result.stdout

        # Hash it
        if hash_type == 'sha256':
            return hashlib.sha256(pubkey_der).hexdigest()
        elif hash_type == 'sha512':
            return hashlib.sha512(pubkey_der).hexdigest()

    except Exception as e:
        log_warn(f"Failed to get SPKI hash: {e}")
        return None


def get_cert_full_hash(der_cert: bytes, hash_type: str = 'sha256') -> str:
    """Get hash of full certificate."""
    if hash_type == 'sha256':
        return hashlib.sha256(der_cert).hexdigest()
    elif hash_type == 'sha512':
        return hashlib.sha512(der_cert).hexdigest()
    return ''


def verify_cert_against_dane(chain: List[bytes], dane_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify a certificate chain against DANE/TLSA records.

    Args:
        chain: List of DER-encoded certificates (leaf first)
        dane_result: DANE check results from check_dane_records()

    Returns:
        Dict with verification result
    """
    result = {
        'verified': False,
        'matched_record': None,
        'matched_cert': None,
        'message': ''
    }

    if not dane_result['has_dane']:
        result['message'] = "No DANE records to verify against"
        return result

    for record in dane_result['records']:
        usage = record['usage']
        selector = record['selector']
        matching_type = record['matching_type']
        expected_data = record['data'].lower()

        # Determine hash type
        if matching_type == '1':
            hash_type = 'sha256'
        elif matching_type == '2':
            hash_type = 'sha512'
        else:
            hash_type = None  # Exact match

        # Determine which certs to check based on usage
        if usage in ('1', '3'):  # EE types - check leaf only
            certs_to_check = [(0, chain[0])]
        else:  # TA types - check all certs
            certs_to_check = list(enumerate(chain))

        for cert_idx, cert in certs_to_check:
            # Get the data to compare
            if selector == '0':  # Full certificate
                if hash_type:
                    cert_data = get_cert_full_hash(cert, hash_type)
                else:
                    cert_data = cert.hex()
            else:  # SubjectPublicKeyInfo
                if hash_type:
                    cert_data = get_cert_spki_hash(cert, hash_type)
                else:
                    # Would need to extract raw SPKI - not commonly used
                    continue

            if cert_data and cert_data.lower() == expected_data:
                cert_label = "Leaf" if cert_idx == 0 else f"Certificate [{cert_idx}]"
                result['verified'] = True
                result['matched_record'] = record
                result['matched_cert'] = cert_idx
                result['message'] = f"DANE verified: {cert_label} matches TLSA record (usage={usage}, selector={selector}, matching={matching_type})"
                return result

    result['message'] = "No certificate matched any TLSA record"
    return result


def extract_domain_from_cert(der_cert: bytes) -> Optional[str]:
    """Extract the primary domain from a certificate's CN or SAN."""
    pem = der_to_pem(der_cert)

    # Try to get CN first
    result = subprocess.run(
        ['openssl', 'x509', '-noout', '-subject'],
        input=pem.encode(),
        capture_output=True,
        timeout=10
    )

    if result.returncode == 0:
        subject = result.stdout.decode()
        # Parse CN
        if 'CN=' in subject or 'CN =' in subject:
            cn = subject.split('CN')[-1].split('=', 1)[-1].strip()
            # Remove any trailing attributes
            cn = cn.split(',')[0].split('/')[0].strip()
            # Remove wildcard prefix
            if cn.startswith('*.'):
                cn = cn[2:]
            if cn and '.' in cn:
                return cn

    # Try SAN
    result = subprocess.run(
        ['openssl', 'x509', '-noout', '-text'],
        input=pem.encode(),
        capture_output=True,
        timeout=10
    )

    if result.returncode == 0:
        text = result.stdout.decode()
        for line in text.split('\n'):
            if 'DNS:' in line:
                # Extract first DNS name
                dns_name = line.split('DNS:')[1].split(',')[0].strip()
                if dns_name.startswith('*.'):
                    dns_name = dns_name[2:]
                if dns_name and '.' in dns_name:
                    return dns_name

    return None


def resolve_chain(
    leaf_der: bytes,
    max_depth: int = 10,
    timeout: int = 30,
    include_root: bool = True
) -> List[bytes]:
    """
    Resolve the complete certificate chain from a leaf certificate.

    Args:
        leaf_der: DER-encoded leaf certificate
        max_depth: Maximum chain depth to prevent infinite loops
        timeout: Timeout for HTTP requests
        include_root: Whether to include the root CA in the chain

    Returns:
        List of DER-encoded certificates (leaf first, root last)
    """
    chain = [leaf_der]
    seen_fingerprints = {get_cert_fingerprint(leaf_der)}
    current = leaf_der

    for depth in range(max_depth):
        # Check if current cert is self-signed (root)
        if is_self_signed(current):
            if not include_root and len(chain) > 1:
                # Remove root if not wanted
                chain = chain[:-1]
            log_success(f"Reached root CA at depth {depth}")
            break

        # Get AIA URLs
        aia_urls = get_aia_urls(current)

        if not aia_urls:
            log_warn(f"No AIA URLs found at depth {depth}, chain may be incomplete")
            break

        # Try to fetch the issuer certificate
        issuer_cert = None
        for url in aia_urls:
            issuer_cert = fetch_certificate(url, timeout)
            if issuer_cert:
                break

        if not issuer_cert:
            log_warn(f"Could not fetch issuer certificate at depth {depth}")
            break

        # Check for loops
        fp = get_cert_fingerprint(issuer_cert)
        if fp in seen_fingerprints:
            log_warn(f"Certificate loop detected at depth {depth}")
            break

        seen_fingerprints.add(fp)
        chain.append(issuer_cert)
        current = issuer_cert

        info = get_cert_info(issuer_cert)
        log_info(f"[{depth + 1}] Found: {info.get('subject', 'Unknown')}")

    return chain


def print_chain_info(chain: List[bytes]):
    """Print information about the resolved chain."""
    print(file=sys.stderr)
    print(color("=" * 60, Colors.BOLD), file=sys.stderr)
    print(color(f" Certificate Chain ({len(chain)} certificates)", Colors.BOLD + Colors.CYAN), file=sys.stderr)
    print(color("=" * 60, Colors.BOLD), file=sys.stderr)

    for i, cert in enumerate(chain):
        info = get_cert_info(cert)

        if i == 0:
            label = "Leaf"
            label_color = Colors.GREEN
        elif i == len(chain) - 1:
            label = "Root"
            label_color = Colors.YELLOW
        else:
            label = f"Intermediate [{i}]"
            label_color = Colors.BLUE

        print(file=sys.stderr)
        print(f"  {color(label, label_color + Colors.BOLD)}", file=sys.stderr)
        print(f"    Subject: {info.get('subject', 'Unknown')}", file=sys.stderr)
        print(f"    Issuer:  {info.get('issuer', 'Unknown')}", file=sys.stderr)

        fp = info.get('sha256 fingerprint', '')
        if fp:
            print(f"    SHA256:  {fp[:32]}...", file=sys.stderr)

    print(file=sys.stderr)
    print(color("=" * 60, Colors.BOLD), file=sys.stderr)


def chain_to_pem(chain: List[bytes]) -> str:
    """Convert chain to PEM format."""
    return ''.join(der_to_pem(cert) for cert in chain)


def export_p12(
    chain: List[bytes],
    output_path: str,
    key_path: Optional[str] = None,
    password: Optional[str] = None,
    friendly_name: Optional[str] = None
) -> bool:
    """
    Export certificate chain to PKCS#12 format.

    Args:
        chain: List of DER certificates (leaf first)
        output_path: Output .p12 file path
        key_path: Path to private key file (optional)
        password: Password for the P12 file (prompted if not provided)
        friendly_name: Friendly name for the certificate

    Returns:
        True if successful
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write chain to temp PEM file
        chain_pem_path = os.path.join(tmpdir, 'chain.pem')
        with open(chain_pem_path, 'w') as f:
            f.write(chain_to_pem(chain))

        # Write leaf cert separately
        leaf_pem_path = os.path.join(tmpdir, 'leaf.pem')
        with open(leaf_pem_path, 'w') as f:
            f.write(der_to_pem(chain[0]))

        # Write CA chain (intermediates + root)
        ca_pem_path = os.path.join(tmpdir, 'ca.pem')
        if len(chain) > 1:
            with open(ca_pem_path, 'w') as f:
                f.write(''.join(der_to_pem(cert) for cert in chain[1:]))

        # Build openssl command
        cmd = ['openssl', 'pkcs12', '-export', '-out', output_path]

        if key_path:
            cmd.extend(['-inkey', key_path])
        else:
            # Create a dummy key if none provided (for cert-only P12)
            cmd.append('-nokeys')

        cmd.extend(['-in', leaf_pem_path])

        if len(chain) > 1:
            cmd.extend(['-certfile', ca_pem_path])

        if friendly_name:
            cmd.extend(['-name', friendly_name])

        if password:
            cmd.extend(['-passout', f'pass:{password}'])
        else:
            # Empty password
            cmd.extend(['-passout', 'pass:'])

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            if result.returncode != 0:
                log_error(f"PKCS#12 export failed: {result.stderr.decode()}")
                return False
            return True
        except Exception as e:
            log_error(f"PKCS#12 export failed: {e}")
            return False


def export_p7b(chain: List[bytes], output_path: str) -> bool:
    """
    Export certificate chain to PKCS#7 (.p7b) format.

    Args:
        chain: List of DER certificates
        output_path: Output .p7b file path

    Returns:
        True if successful
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write chain to temp PEM file
        chain_pem_path = os.path.join(tmpdir, 'chain.pem')
        with open(chain_pem_path, 'w') as f:
            f.write(chain_to_pem(chain))

        # Convert to PKCS#7
        cmd = [
            'openssl', 'crl2pkcs7', '-nocrl',
            '-certfile', chain_pem_path,
            '-out', output_path
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            if result.returncode != 0:
                log_error(f"PKCS#7 export failed: {result.stderr.decode()}")
                return False
            return True
        except Exception as e:
            log_error(f"PKCS#7 export failed: {e}")
            return False


def export_der_chain(chain: List[bytes], output_dir: str) -> bool:
    """
    Export each certificate in the chain as separate DER files.

    Args:
        chain: List of DER certificates
        output_dir: Directory to save DER files

    Returns:
        True if successful
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    for i, cert in enumerate(chain):
        if i == 0:
            filename = 'leaf.der'
        elif i == len(chain) - 1:
            filename = 'root.der'
        else:
            filename = f'intermediate_{i}.der'

        path = os.path.join(output_dir, filename)
        with open(path, 'wb') as f:
            f.write(cert)
        log_info(f"Saved: {path}")

    return True


def verify_chain(chain: List[bytes]) -> bool:
    """
    Verify the certificate chain is valid.

    Returns:
        True if chain is valid
    """
    if len(chain) < 1:
        return False

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write leaf cert
        leaf_path = os.path.join(tmpdir, 'leaf.pem')
        with open(leaf_path, 'w') as f:
            f.write(der_to_pem(chain[0]))

        # Write CA chain (all except leaf)
        if len(chain) > 1:
            ca_path = os.path.join(tmpdir, 'ca.pem')
            with open(ca_path, 'w') as f:
                f.write(''.join(der_to_pem(cert) for cert in chain[1:]))

            cmd = ['openssl', 'verify', '-CAfile', ca_path, leaf_path]
        else:
            # Self-signed - verify against itself
            cmd = ['openssl', 'verify', '-CAfile', leaf_path, leaf_path]

        result = subprocess.run(cmd, capture_output=True, timeout=30)
        return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(
        description='Build complete certificate chains by fetching intermediate certificates',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s cert.pem                          # Output PEM chain to stdout
  %(prog)s cert.pem -o fullchain.pem         # Save PEM chain to file
  %(prog)s cert.pem --p12-out bundle.p12 --key server.key
                                             # Export as PKCS#12 with private key
  %(prog)s cert.pem --p12-out bundle.p12 --p12-password secret
                                             # Export as password-protected PKCS#12
  %(prog)s cert.pem --p7b-out chain.p7b      # Export as PKCS#7 (.p7b)
  %(prog)s cert.pem --der-out ./chain/       # Export each cert as DER
  %(prog)s cert.pem --no-root                # Exclude root CA from chain
  %(prog)s cert.pem --verify                 # Verify the resolved chain

DNS Validation:
  %(prog)s cert.pem --check-caa              # Check CAA records (domain from cert)
  %(prog)s cert.pem --check-caa --domain example.com
                                             # Check CAA for specific domain
  %(prog)s cert.pem --check-dane             # Check DANE/TLSA records
  %(prog)s cert.pem --check-dane --domain example.com --port 443
                                             # Check DANE for specific domain/port
  %(prog)s cert.pem --check-caa --check-dane # Check both CAA and DANE

Output formats:
  - PEM (default): Standard PEM-encoded chain, suitable for most servers
  - PKCS#12 (.p12/.pfx): Binary format with optional private key, used by Windows/Java
  - PKCS#7 (.p7b): Binary format without private key, used for certificate distribution
  - DER: Binary format, individual files per certificate

CAA Records:
  CAA (Certification Authority Authorization) records specify which CAs are
  authorized to issue certificates for a domain. When --check-caa is used,
  the tool verifies the certificate issuer against the domain's CAA policy.

DANE/TLSA Records:
  DANE (DNS-based Authentication of Named Entities) uses TLSA records to
  cryptographically bind certificates to DNS names. When --check-dane is
  used, the tool verifies the certificate matches the TLSA record data.
"""
    )

    parser.add_argument('certificate', help='Input certificate file (PEM or DER)')
    parser.add_argument('-o', '--output', help='Output PEM chain to file (default: stdout)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress progress output')

    # Output format options
    output_group = parser.add_argument_group('Output formats')
    output_group.add_argument('--p12-out', '--pkcs12-out', metavar='FILE',
                              help='Export as PKCS#12 (.p12/.pfx) file')
    output_group.add_argument('--p7b-out', '--pkcs7-out', metavar='FILE',
                              help='Export as PKCS#7 (.p7b) file')
    output_group.add_argument('--der-out', metavar='DIR',
                              help='Export each certificate as DER to directory')

    # PKCS#12 options
    p12_group = parser.add_argument_group('PKCS#12 options')
    p12_group.add_argument('--key', metavar='FILE',
                           help='Private key file to include in PKCS#12')
    p12_group.add_argument('--p12-password', metavar='PASS',
                           help='Password for PKCS#12 (default: empty)')
    p12_group.add_argument('--p12-name', metavar='NAME',
                           help='Friendly name for certificate in PKCS#12')

    # Chain options
    chain_group = parser.add_argument_group('Chain options')
    chain_group.add_argument('--no-root', action='store_true',
                             help='Exclude root CA from the chain')
    chain_group.add_argument('--max-depth', type=int, default=10,
                             help='Maximum chain depth (default: 10)')
    chain_group.add_argument('--timeout', type=int, default=30,
                             help='HTTP timeout for fetching certificates (default: 30s)')
    chain_group.add_argument('--verify', action='store_true',
                             help='Verify the resolved chain')

    # DNS validation options
    dns_group = parser.add_argument_group('DNS validation',
        'Check CAA and DANE/TLSA records for certificate validation')
    dns_group.add_argument('--check-caa', action='store_true',
                           help='Check CAA records and verify issuer authorization')
    dns_group.add_argument('--check-dane', action='store_true',
                           help='Check DANE/TLSA records and verify certificate binding')
    dns_group.add_argument('--domain', metavar='DOMAIN',
                           help='Domain for DNS checks (auto-extracted from cert if not specified)')
    dns_group.add_argument('--port', type=int, default=443,
                           help='Port for DANE/TLSA lookup (default: 443)')
    dns_group.add_argument('--dns-timeout', type=int, default=10,
                           help='DNS query timeout in seconds (default: 10)')
    dns_group.add_argument('--strict-dns', action='store_true',
                           help='Fail if DNS checks do not pass (default: warn only)')

    args = parser.parse_args()

    # Load input certificate
    if not os.path.exists(args.certificate):
        log_error(f"Certificate file not found: {args.certificate}")
        sys.exit(1)

    try:
        leaf_der, leaf_pem = load_certificate(args.certificate)
    except Exception as e:
        log_error(f"Failed to load certificate: {e}")
        sys.exit(1)

    if not args.quiet:
        info = get_cert_info(leaf_der)
        log_info(f"Loaded: {info.get('subject', args.certificate)}")

    # Resolve the chain
    if not args.quiet:
        log_info("Resolving certificate chain...")

    chain = resolve_chain(
        leaf_der,
        max_depth=args.max_depth,
        timeout=args.timeout,
        include_root=not args.no_root
    )

    if len(chain) == 1:
        log_warn("Could not resolve any additional certificates in the chain")

    # Print chain info
    if not args.quiet:
        print_chain_info(chain)

    # Verify if requested
    if args.verify:
        if verify_chain(chain):
            log_success("Chain verification: PASSED")
        else:
            log_error("Chain verification: FAILED")
            sys.exit(1)

    # DNS validation checks
    dns_failed = False

    if args.check_caa or args.check_dane:
        # Determine domain
        domain = args.domain
        if not domain:
            domain = extract_domain_from_cert(leaf_der)
            if domain:
                if not args.quiet:
                    log_info(f"Extracted domain from certificate: {domain}")
            else:
                log_error("Could not extract domain from certificate. Use --domain to specify.")
                sys.exit(1)

    # CAA check
    if args.check_caa:
        if not args.quiet:
            log_info(f"Checking CAA records for {domain}...")

        caa_result = check_caa_records(domain, timeout=args.dns_timeout)

        if not args.quiet:
            print_caa_results(caa_result)

        # Verify certificate against CAA
        caa_verify = verify_cert_against_caa(leaf_der, caa_result)

        if caa_verify['verified']:
            log_success(f"CAA verification: {caa_verify['message']}")
        else:
            if args.strict_dns:
                log_error(f"CAA verification FAILED: {caa_verify['message']}")
                dns_failed = True
            else:
                log_warn(f"CAA verification: {caa_verify['message']}")

    # DANE check
    if args.check_dane:
        if not args.quiet:
            log_info(f"Checking DANE/TLSA records for {domain}:{args.port}...")

        dane_result = check_dane_records(domain, port=args.port, timeout=args.dns_timeout)

        if not args.quiet:
            print_dane_results(dane_result)

        # Verify certificate against DANE
        if dane_result['has_dane']:
            dane_verify = verify_cert_against_dane(chain, dane_result)

            if dane_verify['verified']:
                log_success(f"DANE verification: {dane_verify['message']}")
            else:
                if args.strict_dns:
                    log_error(f"DANE verification FAILED: {dane_verify['message']}")
                    dns_failed = True
                else:
                    log_warn(f"DANE verification: {dane_verify['message']}")
        else:
            if not args.quiet:
                log_info("No DANE records found - skipping verification")

    if dns_failed:
        sys.exit(1)

    # Export in requested formats
    exported = False

    # PKCS#12 export
    if args.p12_out:
        if not args.quiet:
            log_info(f"Exporting PKCS#12 to: {args.p12_out}")

        if export_p12(
            chain,
            args.p12_out,
            key_path=args.key,
            password=args.p12_password,
            friendly_name=args.p12_name
        ):
            log_success(f"PKCS#12 saved: {args.p12_out}")
            exported = True
        else:
            sys.exit(1)

    # PKCS#7 export
    if args.p7b_out:
        if not args.quiet:
            log_info(f"Exporting PKCS#7 to: {args.p7b_out}")

        if export_p7b(chain, args.p7b_out):
            log_success(f"PKCS#7 saved: {args.p7b_out}")
            exported = True
        else:
            sys.exit(1)

    # DER export
    if args.der_out:
        if not args.quiet:
            log_info(f"Exporting DER files to: {args.der_out}")

        if export_der_chain(chain, args.der_out):
            log_success(f"DER files saved to: {args.der_out}")
            exported = True
        else:
            sys.exit(1)

    # PEM output (default or explicit)
    if args.output:
        pem_chain = chain_to_pem(chain)
        with open(args.output, 'w') as f:
            f.write(pem_chain)
        log_success(f"PEM chain saved: {args.output}")
        exported = True
    elif not exported:
        # Output PEM to stdout if no other format specified
        print(chain_to_pem(chain), end='')

    if not args.quiet and exported:
        print(file=sys.stderr)
        log_success("Chain resolution complete!")


if __name__ == '__main__':
    main()
