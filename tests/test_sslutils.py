import unittest
import socket
from unittest.mock import patch, MagicMock
import sys
import os

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sslutils import BufferedSocket, is_ip_allowed, parse_target, resolve_securely

class TestUtils(unittest.TestCase):
    
    def test_is_ip_allowed(self):
        # Public IPs should be allowed
        self.assertTrue(is_ip_allowed("8.8.8.8"))
        self.assertTrue(is_ip_allowed("1.1.1.1"))
        self.assertTrue(is_ip_allowed("93.184.216.34")) # example.com

        # Private IPs should be blocked
        self.assertFalse(is_ip_allowed("127.0.0.1"))
        self.assertFalse(is_ip_allowed("10.0.0.5"))
        self.assertFalse(is_ip_allowed("192.168.1.1"))
        self.assertFalse(is_ip_allowed("172.16.0.1"))
        self.assertFalse(is_ip_allowed("169.254.5.5"))
        self.assertFalse(is_ip_allowed("::1"))
        self.assertFalse(is_ip_allowed("0.0.0.0"))
        self.assertFalse(is_ip_allowed("224.0.0.1"))
        
        # Explicit allow list
        allowed = ["10.0.0.0/8"]
        self.assertTrue(is_ip_allowed("10.0.0.5", allowed))
        self.assertFalse(is_ip_allowed("192.168.1.1", allowed)) # Not in allow list
        
    def test_parse_target(self):
        # Standard cases
        self.assertEqual(parse_target("example.com"), ("example.com", 443, "tls"))
        self.assertEqual(parse_target("example.com:8443"), ("example.com", 8443, "tls"))
        self.assertEqual(parse_target("https://example.com"), ("example.com", 443, "https"))
        
        # IPv6 cases
        self.assertEqual(parse_target("[::1]"), ("::1", 443, "tls"))
        self.assertEqual(parse_target("[2001:db8::1]:8080"), ("2001:db8::1", 8080, "tls"))
        
        # Scheme inference
        self.assertEqual(parse_target("smtp://mail.server:25"), ("mail.server", 25, "smtp"))

    def test_parse_target_rejects_non_endpoint_parts(self):
        for target in (
            "https://user@example.com",
            "https://example.com/path",
            "https://example.com?query=value",
            "https://example.com:invalid",
            " ",
        ):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    parse_target(target)

    def test_buffered_socket_does_not_use_a_file_buffer(self):
        reader, writer = socket.socketpair()
        try:
            buffered = BufferedSocket(reader)
            writer.sendall(b"220 ready\r\nremaining")
            self.assertEqual(buffered.readline(), b"220 ready\r\n")
            self.assertEqual(reader.recv(9), b"remaining")
        finally:
            reader.close()
            writer.close()
        
    @patch('socket.getaddrinfo')
    def test_resolve_securely_success(self, mock_getaddrinfo):
        # Mock a safe public IP response
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))
        ]
        
        ip = resolve_securely("example.com")
        self.assertEqual(ip, "93.184.216.34")
        
    @patch('socket.getaddrinfo')
    def test_resolve_securely_block_private(self, mock_getaddrinfo):
        # Mock a private IP response (DNS Rebinding attempt)
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))
        ]
        
        with self.assertRaises(ValueError):
            resolve_securely("evil.local")

if __name__ == '__main__':
    unittest.main()
