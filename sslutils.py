import socket
import ipaddress
import urllib.parse
from typing import Tuple, Optional, List, Union

# Private/Reserved IP ranges that should be blocked by default for SSRF protection
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def is_ip_allowed(ip_str: str, allowed_networks: List[str] = None) -> bool:
    """
    Check if an IP address is allowed.
    Blocks private/reserved networks by default unless explicitly allowed.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    # If specific allow list provided, check only that
    if allowed_networks:
        for net_str in allowed_networks:
            try:
                if ip in ipaddress.ip_network(net_str):
                    return True
            except ValueError:
                continue
        return False

    # Some older Python versions report multicast addresses as global, so
    # explicitly reject every special-purpose category as well.
    return (
        ip.is_global
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_unspecified
        and not ip.is_reserved
    )

def resolve_securely(hostname: str) -> str:
    """
    Resolve a hostname to an IP address, ensuring it's not a private IP.
    Raises ValueError if resolution fails or resolves to a blocked IP.
    """
    try:
        # Get address info - this handles both IPv4 and IPv6
        # We prefer IPv4 for compatibility, but support IPv6
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        
        for family, _, _, _, sockaddr in addr_info:
            ip_addr = sockaddr[0]
            if is_ip_allowed(ip_addr):
                return ip_addr
                
        # If we get here, all resolved IPs were blocked
        raise ValueError(f"Host '{hostname}' resolves to a blocked/private IP address.")
        
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve host '{hostname}': {e}")

def parse_target(target: str, default_port: int = 443) -> Tuple[str, int, str]:
    """
    Robust target parsing supporting IPv6 [bracket] notation and schemes.
    Returns: (host, port, protocol)
    """
    if not isinstance(target, str) or not target.strip() or target != target.strip():
        raise ValueError("Invalid target format")

    # Prepend dummy scheme if none exists to help urlparse
    if "://" not in target:
        target = f"tls://{target}"
        
    parsed = urllib.parse.urlparse(target)
    protocol = parsed.scheme.lower()
    if parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("Target must contain only a scheme, hostname, and optional port")
    
    # Handle IPv6 brackets in hostname
    host = parsed.hostname
    if host and host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
        
    try:
        port = parsed.port
    except ValueError as e:
        raise ValueError(f"Invalid port: {e}") from e
    if not port:
        # Infer port from protocol or default
        from sslxtract import PROTOCOL_PORTS
        port = PROTOCOL_PORTS.get(protocol, default_port)
        
    if not host:
        raise ValueError("Invalid target format: missing hostname")
    if any(char.isspace() for char in host):
        raise ValueError("Invalid target format: invalid hostname")
        
    return host, port, protocol

class BufferedSocket:
    """
    Wrapper around socket to provide safe readline/read capabilities
    for textual protocols (SMTP, IMAP, etc).
    """
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self._buffer = bytearray()
        
    def readline(self) -> bytes:
        # Reading one byte at a time intentionally avoids a buffered file
        # object consuming bytes from the TLS handshake before wrap_socket.
        while not self._buffer.endswith(b'\n'):
            chunk = self.sock.recv(1)
            if not chunk:
                break
            self._buffer.extend(chunk)
        line = bytes(self._buffer)
        self._buffer.clear()
        return line
    
    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b''
        if size < 0:
            data = bytes(self._buffer)
            self._buffer.clear()
            return data + self.sock.recv(4096)
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data + self.sock.recv(size - len(data))
    
    def sendall(self, data: bytes):
        self.sock.sendall(data)
        
    def close(self):
        self.sock.close()
