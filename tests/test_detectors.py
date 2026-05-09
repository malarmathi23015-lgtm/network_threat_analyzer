"""
============================================================
tests/test_detectors.py
AI-Powered Linux Network Threat Analyzer

PURPOSE:
    Unit tests for threat detection modules.
    Tests that detectors correctly identify threats
    and don't generate false positives for normal traffic.

HOW TO RUN:
    cd network_threat_analyzer
    pytest tests/ -v

BEGINNER NOTE:
    Unit tests are small programs that check if your code
    works correctly. Each test function:
    1. Sets up test data (the "arrange" phase)
    2. Runs the code being tested (the "act" phase)
    3. Checks the result is correct (the "assert" phase)

    pytest automatically finds and runs any function
    that starts with "test_"
============================================================
"""

import pytest
import sys
import os

# Add parent directory to path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detector.auth_log_analyzer import AuthLogParser


class TestAuthLogParser:
    """Tests for the auth log parser."""

    def setup_method(self):
        """Create a fresh parser before each test."""
        self.parser = AuthLogParser()

    def test_parse_failed_password(self):
        """Test that failed password lines are correctly parsed."""
        line = "Jan  1 12:00:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2"
        result = self.parser.parse_line(line)

        assert result is not None, "Should parse failed password line"
        assert result["event_type"] == "FAILED_LOGIN"
        assert result["username"] == "root"
        assert result["source_ip"] == "192.168.1.100"
        assert result["status"] == "failure"

    def test_parse_successful_login(self):
        """Test that successful login lines are correctly parsed."""
        line = "Jan  1 12:00:05 server sshd[1235]: Accepted password for alice from 10.0.0.5 port 22 ssh2"
        result = self.parser.parse_line(line)

        assert result is not None
        assert result["event_type"] == "SUCCESS_LOGIN"
        assert result["username"] == "alice"
        assert result["source_ip"] == "10.0.0.5"
        assert result["status"] == "success"

    def test_parse_invalid_user(self):
        """Test parsing of invalid user attempts."""
        line = "Jan  1 12:00:06 server sshd[1234]: Invalid user admin from 45.33.32.156"
        result = self.parser.parse_line(line)

        assert result is not None
        assert result["event_type"] == "INVALID_USER"
        assert result["username"] == "admin"
        assert result["source_ip"] == "45.33.32.156"

    def test_parse_sudo_event(self):
        """Test parsing of sudo privilege events."""
        line = "Jan  1 12:01:00 server sudo: alice : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"
        result = self.parser.parse_line(line)

        assert result is not None
        assert result["event_type"] == "SUDO"
        assert result["username"] == "alice"

    def test_parse_unknown_line(self):
        """Test that unrecognized lines return None."""
        line = "Jan  1 12:00:00 server kernel: Some random kernel message"
        result = self.parser.parse_line(line)

        assert result is None, "Unknown log lines should return None"

    def test_parse_empty_line(self):
        """Test that empty lines are handled gracefully."""
        result = self.parser.parse_line("")
        assert result is None

    def test_parse_publickey_login(self):
        """Test parsing of SSH public key authentication."""
        line = "Jan  1 12:00:10 server sshd[1236]: Accepted publickey for bob from 192.168.1.10 port 54000 ssh2"
        result = self.parser.parse_line(line)

        assert result is not None
        assert result["event_type"] == "SUCCESS_LOGIN"
        assert result["username"] == "bob"


class TestIPHelpers:
    """Tests for IP address utility functions."""

    def test_private_ip_detection(self):
        """Test that private IPs are correctly identified."""
        from detector.ip_reputation import is_private_ip

        # These should all be detected as private
        assert is_private_ip("192.168.1.1") == True
        assert is_private_ip("10.0.0.1") == True
        assert is_private_ip("172.16.0.1") == True
        assert is_private_ip("127.0.0.1") == True

    def test_public_ip_detection(self):
        """Test that public IPs are not flagged as private."""
        from detector.ip_reputation import is_private_ip

        assert is_private_ip("8.8.8.8") == False
        assert is_private_ip("1.1.1.1") == False
        assert is_private_ip("45.33.32.156") == False

    def test_invalid_ip_handling(self):
        """Test that invalid IP strings don't crash the code."""
        from detector.ip_reputation import is_private_ip

        # Invalid IPs should return True (treat as private/skip)
        assert is_private_ip("not-an-ip") == True
        assert is_private_ip("999.999.999.999") == True
        assert is_private_ip("") == True


class TestProtocolAnalyzer:
    """Tests for the protocol analysis module."""

    def setup_method(self):
        """Create mock database and analyzer."""
        # We use a mock database to avoid needing a real DB in tests
        class MockDB:
            def insert_packet(self, **kwargs): pass

        from analyzer.protocol_analyzer import ProtocolAnalyzer
        self.analyzer = ProtocolAnalyzer(MockDB())

    def test_analyze_tcp_syn_packet(self):
        """Test TCP SYN packet analysis."""
        packet = {
            "protocol": "TCP",
            "src_ip": "192.168.1.5",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 80,
            "flags": "S",
            "size": 60,
            "timestamp": "2024-01-01T12:00:00"
        }

        result = self.analyzer.analyze(packet)

        assert result["protocol"] == "TCP"
        assert "SYN" in result["flag_description"]
        assert result["service"] == "HTTP"  # Port 80 = HTTP

    def test_analyze_identifies_ssh_port(self):
        """Test that port 22 is identified as SSH."""
        packet = {
            "protocol": "TCP",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 54321,
            "dst_port": 22,
            "flags": "S",
            "size": 60,
            "timestamp": "2024-01-01T12:00:00"
        }

        result = self.analyzer.analyze(packet)
        assert result["service"] == "SSH"

    def test_detect_suspicious_port(self):
        """Test that known malware ports are flagged."""
        packet = {
            "protocol": "TCP",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "src_port": 12345,
            "dst_port": 4444,  # Metasploit port
            "flags": "S",
            "size": 60,
            "timestamp": "2024-01-01T12:00:00"
        }

        result = self.analyzer.analyze(packet)
        assert result.get("is_suspicious_port") == True

    def test_analyze_dns_packet(self):
        """Test DNS packet analysis."""
        packet = {
            "protocol": "DNS",
            "src_ip": "192.168.1.5",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 53,
            "dns_query": "www.google.com.",
            "size": 70,
            "timestamp": "2024-01-01T12:00:00"
        }

        result = self.analyzer.analyze(packet)
        assert result["dns_query_clean"] == "www.google.com"
        assert result["dns_tunneling_suspicious"] == False

    def test_detect_dns_tunneling(self):
        """Test that suspiciously long DNS queries are flagged."""
        # Simulate a DNS tunneling query (very long subdomain)
        long_subdomain = "a" * 60 + ".evil-attacker.com"
        packet = {
            "protocol": "DNS",
            "src_ip": "192.168.1.5",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 53,
            "dns_query": long_subdomain + ".",
            "size": 100,
            "timestamp": "2024-01-01T12:00:00"
        }

        result = self.analyzer.analyze(packet)
        assert result.get("dns_tunneling_suspicious") == True


# ============================================================
# Run tests if executed directly
# ============================================================
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
