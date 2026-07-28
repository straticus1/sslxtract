#!/usr/bin/env python3
"""
dnsxtract.py - DNS enumeration and record extraction utility

Features:
- DNS Zone Transfer (AXFR) testing
- Record enumeration (A, AAAA, MX, NS, TXT, SOA, etc.)
- Reverse DNS lookup support
- DNSSEC validation check
- Multiple output formats (Text, JSON)
"""

import argparse
import sys
import socket
import json
import concurrent.futures
from typing import Dict, List, Any, Optional

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.exception
    import dns.flags
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# ANSI colors
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def color(text: str, c: str) -> str:
    if sys.stdout.isatty():
        return f"{c}{text}{Colors.RESET}"
    return text

class DNSExtractor:
    def __init__(self, nameservers: List[str] = None, timeout: float = 5.0):
        if not DNS_AVAILABLE:
            print(f"{color('Error:', Colors.RED)} dnspython module not found. Install with: pip install dnspython", file=sys.stderr)
            sys.exit(1)
            
        self.resolver = dns.resolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def get_nameservers(self, domain: str) -> List[str]:
        """Get authoritative nameservers for a domain."""
        try:
            answers = self.resolver.resolve(domain, 'NS')
            return [str(rdata.target).rstrip('.') for rdata in answers]
        except Exception:
            return []

    def check_axfr(self, domain: str, nameserver: str) -> Optional[dns.zone.Zone]:
        """Attempt DNS Zone Transfer (AXFR)."""
        try:
            ns_ip = socket.gethostbyname(nameserver)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain))
            return zone
        except Exception:
            return None

    def query_record(self, domain: str, rdtype: str) -> List[str]:
        """Query specific DNS record type."""
        try:
            answers = self.resolver.resolve(domain, rdtype)
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except Exception as e:
            # print(f"Debug: {e}", file=sys.stderr)
            return []

    def check_dnssec(self, domain: str) -> Dict[str, Any]:
        """Check DNSSEC records."""
        result = {'has_dnssec': False, 'records': []}
        try:
            # Check for DNSKEY
            keys = self.query_record(domain, 'DNSKEY')
            if keys:
                result['has_dnssec'] = True
                result['records'].append(f"Found {len(keys)} DNSKEY records")
            
            # Check for RRSIG on SOA
            try:
                # We need to make a raw query to see RRSIGs
                request = dns.message.make_query(domain, dns.rdatatype.SOA)
                request.flags |= dns.flags.AD  # Authenticated Data
                response = dns.query.udp(request, self.resolver.nameservers[0], timeout=5)
                
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                         result['records'].append("Found RRSIG on SOA")
                         break
            except Exception:
                pass
                
        except Exception:
            pass
        return result

    def scan_domain(self, domain: str, types: List[str] = None) -> Dict[str, Any]:
        """Scan a domain for standard records."""
        if not types:
            types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'CNAME']
            
        results = {}
        for rdtype in types:
            records = self.query_record(domain, rdtype)
            if records:
                results[rdtype] = records
        return results

def main():
    parser = argparse.ArgumentParser(description='DNS record extraction and zone transfer testing utility')
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('--server', help='Specific nameserver to use')
    parser.add_argument('--axfr', action='store_true', help='Attempt Zone Transfer (AXFR)')
    parser.add_argument('--dnssec', action='store_true', help='Check DNSSEC status')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--types', help='Comma-separated record types to query (default: common types)')
    
    args = parser.parse_args()
    
    nameservers = [args.server] if args.server else None
    extractor = DNSExtractor(nameservers)
    
    output = {
        'domain': args.domain,
        'records': {},
        'axfr': None,
        'dnssec': None
    }
    
    # 1. Standard Enumeration
    types = args.types.split(',') if args.types else None
    if not args.json:
        print(f"{color('Scanning', Colors.CYAN)} {args.domain}...")
        
    records = extractor.scan_domain(args.domain, types)
    output['records'] = records
    
    if not args.json:
        for rdtype, data in records.items():
            print(f"\n{color(rdtype, Colors.BOLD)} Records:")
            for r in data:
                print(f"  {r}")

    # 2. DNSSEC Check
    if args.dnssec:
        dnssec_info = extractor.check_dnssec(args.domain)
        output['dnssec'] = dnssec_info
        if not args.json:
            print(f"\n{color('DNSSEC', Colors.BOLD)}: {'Enabled' if dnssec_info['has_dnssec'] else 'Not found'}")
            for r in dnssec_info['records']:
                print(f"  {r}")

    # 3. Zone Transfer (AXFR)
    if args.axfr:
        if not args.json:
            print(f"\n{color('Testing Zone Transfer (AXFR)', Colors.BOLD)}...")
            
        # Get NS records first if not provided
        ns_list = [args.server] if args.server else extractor.get_nameservers(args.domain)
        
        axfr_results = []
        for ns in ns_list:
            if not args.json:
                print(f"  Checking nameserver: {ns}")
            zone = extractor.check_axfr(args.domain, ns)
            if zone:
                status = "SUCCESS"
                count = len(zone.nodes)
                if not args.json:
                    print(f"    {color('SUCCESS!', Colors.GREEN)} Retrieved {count} records")
                axfr_results.append({'nameserver': ns, 'success': True, 'count': count})
            else:
                if not args.json:
                    print(f"    {color('Failed', Colors.RED)} (Refused/Timeout)")
                axfr_results.append({'nameserver': ns, 'success': False})
                
        output['axfr'] = axfr_results

    # Output JSON if requested
    if args.json:
        print(json.dumps(output, indent=2))

if __name__ == '__main__':
    main()

