import os
import sys
import unittest
from types import SimpleNamespace

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ssl_extract_server import SSLExtractHandler


class TestHostPolicy(unittest.TestCase):
    def setUp(self):
        self.handler = object.__new__(SSLExtractHandler)

    def test_blocked_domain_matches_only_domain_boundary(self):
        self.handler.config = SimpleNamespace(
            blocked_hosts=["internal.example"], allowed_hosts=None
        )
        self.assertFalse(self.handler._check_host_allowed("api.internal.example"))
        self.assertTrue(self.handler._check_host_allowed("internal.example.attacker.test"))

    def test_allowed_domain_and_network_rules(self):
        self.handler.config = SimpleNamespace(
            blocked_hosts=[], allowed_hosts=["example.com", "203.0.113.0/24"]
        )
        self.assertTrue(self.handler._check_host_allowed("api.example.com"))
        self.assertFalse(self.handler._check_host_allowed("example.com.attacker.test"))
        self.assertTrue(self.handler._check_host_allowed("203.0.113.7"))


if __name__ == "__main__":
    unittest.main()
