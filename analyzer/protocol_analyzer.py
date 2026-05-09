"""
============================================================
analyzer/protocol_analyzer.py
AI-Powered Linux Network Threat Analyzer

PURPOSE:
    Analyzes packets by protocol type (TCP/UDP/HTTP/DNS/ICMP)
    and extracts meaningful information from each.

BEGINNER NOTE:
    Network protocols are like languages that computers use
    to talk to each other. Different types of communication
    use different protocols:

    - TCP:  Reliable connection (websites, file transfers)
    - UDP:  Fast, no guarantee (video streaming, games)
    - HTTP: Web traffic (loading websites)
    - DNS:  Translating names to IPs ("google.com" → 142.250.80.46)
    - ICMP: Diagnostic pings (checking if host is alive)
    - ARP:  Mapping IP to MAC address on local network
============================================================
"""

from collections import defaultdict
from datetime import datetime
from typing import Dict, Any, Optional

from core.logger import setup_logger
from database.db_manager import DatabaseManager

logger = setup_logger("ProtocolAnalyzer")


class ProtocolAnalyzer:
    """
    Examines each captured packet and extracts protocol-specific details.

    This class processes the packet dictionaries created by PacketCapture
    and enriches them with protocol-level insights.

    It also stores packet summaries in the database for later reporting.
    """

    def __init__(self, db: DatabaseManager):
        """
        Initialize with a database manager for storing packet data.

        Args:
            db (DatabaseManager): Database instance for storing records
        """
        self.db = db

        # Track protocol counts in memory for quick stats
        self.protocol_counts = defaultdict(int)

        # Track seen DNS queries (useful for detecting DNS tunneling)
        self.dns_queries = []

        # Track HTTP requests seen
        self.http_requests = []

        # Limit in-memory storage to avoid RAM exhaustion
        self.max_memory_items = 500

        logger.info("ProtocolAnalyzer initialized")

    def analyze(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point: analyze a packet and return enriched data.

        This method is registered as a callback in PacketCapture.
        It's called for every captured packet.

        Args:
            packet_info (dict): Packet dictionary from PacketCapture

        Returns:
            dict: Enriched packet information with protocol details
        """
        protocol = packet_info.get("protocol", "OTHER")
        self.protocol_counts[protocol] += 1

        # Route to the correct protocol-specific analyzer
        if protocol == "TCP":
            enriched = self._analyze_tcp(packet_info)
        elif protocol == "UDP":
            enriched = self._analyze_udp(packet_info)
        elif protocol == "HTTP":
            enriched = self._analyze_http(packet_info)
        elif protocol == "DNS":
            enriched = self._analyze_dns(packet_info)
        elif protocol == "ICMP":
            enriched = self._analyze_icmp(packet_info)
        elif protocol == "ARP":
            enriched = self._analyze_arp(packet_info)
        else:
            enriched = packet_info.copy()

        # Save a summary to the database (without the raw packet object)
        self._save_to_db(enriched)

        return enriched

    # ============================================================
    # PROTOCOL-SPECIFIC ANALYZERS
    # ============================================================

    def _analyze_tcp(self, packet_info: Dict) -> Dict:
        """
        Analyze TCP packet details.

        TCP flags tell us a lot about what's happening:
        - S (SYN):  Starting a connection
        - A (ACK):  Acknowledging data
        - F (FIN):  Closing connection
        - R (RST):  Resetting / aborting connection
        - P (PSH):  Pushing data immediately
        - U (URG):  Urgent data

        Port scan detection watches for many SYN packets to different ports.
        """
        enriched = packet_info.copy()
        flags = packet_info.get("flags", "")

        # Interpret TCP flags into human-readable form
        flag_meanings = []
        if "S" in flags and "A" not in flags:
            flag_meanings.append("SYN (connection request)")
        if "A" in flags and "S" not in flags:
            flag_meanings.append("ACK (acknowledgment)")
        if "S" in flags and "A" in flags:
            flag_meanings.append("SYN-ACK (connection accepted)")
        if "F" in flags:
            flag_meanings.append("FIN (closing connection)")
        if "R" in flags:
            flag_meanings.append("RST (connection reset)")
        if "P" in flags:
            flag_meanings.append("PSH (data push)")

        enriched["flag_description"] = ", ".join(flag_meanings) if flag_meanings else "Unknown"

        # Identify well-known services by destination port
        enriched["service"] = self._identify_service(
            packet_info.get("dst_port"), "TCP"
        )

        # Flag suspicious ports (non-standard high ports used by malware/RATs)
        dst_port = packet_info.get("dst_port", 0)
        enriched["is_suspicious_port"] = self._is_suspicious_port(dst_port)

        return enriched

    def _analyze_udp(self, packet_info: Dict) -> Dict:
        """
        Analyze UDP packet details.

        UDP is connectionless — data is sent without establishing
        a connection first. Used for speed-sensitive applications.
        """
        enriched = packet_info.copy()

        enriched["service"] = self._identify_service(
            packet_info.get("dst_port"), "UDP"
        )

        return enriched

    def _analyze_http(self, packet_info: Dict) -> Dict:
        """
        Analyze HTTP request details.

        BEGINNER NOTE:
            HTTP is the protocol used for web browsing.
            By inspecting HTTP traffic, we can see:
            - What websites are being visited
            - What data is being sent in forms
            - Suspicious requests (SQL injection, directory traversal)
        """
        enriched = packet_info.copy()

        method = packet_info.get("http_method", "")
        host = packet_info.get("http_host", "")
        path = packet_info.get("http_path", "")

        # Build the full URL for easier reading
        enriched["full_url"] = f"http://{host}{path}"

        # Check for common web attack patterns in the URL/path
        suspicious_patterns = [
            "../",           # Directory traversal attempt
            "etc/passwd",    # Trying to read Linux password file
            "cmd.exe",       # Windows command injection
            "SELECT ",       # SQL injection
            "UNION ",        # SQL injection
            "<script",       # Cross-site scripting (XSS)
            "eval(",         # JavaScript injection
            "/wp-admin",     # WordPress admin brute force
            ".php?",         # PHP parameter injection
        ]

        enriched["web_attack_indicators"] = []
        full_request = f"{host}{path}".lower()

        for pattern in suspicious_patterns:
            if pattern.lower() in full_request:
                enriched["web_attack_indicators"].append(pattern)

        enriched["has_web_attack"] = len(enriched["web_attack_indicators"]) > 0

        # Keep a history of HTTP requests (capped at max_memory_items)
        if len(self.http_requests) < self.max_memory_items:
            self.http_requests.append({
                "timestamp": packet_info.get("timestamp"),
                "src_ip": packet_info.get("src_ip"),
                "method": method,
                "url": enriched["full_url"],
                "attack_indicators": enriched["web_attack_indicators"]
            })

        return enriched

    def _analyze_dns(self, packet_info: Dict) -> Dict:
        """
        Analyze DNS query details.

        BEGINNER NOTE:
            DNS is the "phone book" of the internet.
            When you type "google.com", DNS translates it to an IP like 142.250.80.46.

        We watch DNS traffic for:
        - Unusually long domain names (DNS tunneling - hiding data in DNS queries)
        - Requests to known malicious domains
        - High frequency of NXDOMAIN (querying non-existent domains)
        """
        enriched = packet_info.copy()

        dns_query = packet_info.get("dns_query", "")

        if dns_query:
            # Clean up the DNS query (remove trailing dot)
            dns_query = dns_query.rstrip(".")
            enriched["dns_query_clean"] = dns_query

            # Check for DNS tunneling: unusually long subdomains
            # Legitimate domains rarely have subdomains longer than 30 chars
            labels = dns_query.split(".")
            max_label_length = max((len(label) for label in labels), default=0)
            enriched["dns_tunneling_suspicious"] = max_label_length > 50

            # Track DNS query history
            if len(self.dns_queries) < self.max_memory_items:
                self.dns_queries.append({
                    "timestamp": packet_info.get("timestamp"),
                    "src_ip": packet_info.get("src_ip"),
                    "query": dns_query,
                    "suspicious": enriched["dns_tunneling_suspicious"]
                })

        return enriched

    def _analyze_icmp(self, packet_info: Dict) -> Dict:
        """
        Analyze ICMP (ping) packet details.

        BEGINNER NOTE:
            ICMP is used for network diagnostics.
            The "ping" command sends ICMP Echo Requests.

        Attack uses of ICMP:
        - ICMP Flood: Sending thousands of pings to overwhelm a target (DoS)
        - ICMP Tunneling: Hiding data inside ping packets
        - Ping sweep: Discovering live hosts on a network
        """
        enriched = packet_info.copy()

        icmp_type = packet_info.get("icmp_type", -1)
        icmp_code = packet_info.get("icmp_code", -1)

        # Translate ICMP type numbers to human-readable names
        icmp_types = {
            0: "Echo Reply (ping response)",
            3: "Destination Unreachable",
            5: "Redirect",
            8: "Echo Request (ping)",
            11: "Time Exceeded",
            12: "Parameter Problem",
        }

        enriched["icmp_description"] = icmp_types.get(icmp_type, f"Type {icmp_type}")

        # Very large ICMP packets can indicate tunneling
        # Normal pings are 64-84 bytes; tunneled data can be 1000+ bytes
        enriched["possibly_tunneled"] = packet_info.get("size", 0) > 500

        return enriched

    def _analyze_arp(self, packet_info: Dict) -> Dict:
        """
        Analyze ARP packet details.

        BEGINNER NOTE:
            ARP links IP addresses to MAC (hardware) addresses.
            ARP spoofing is when an attacker sends fake ARP replies
            to redirect network traffic through their machine.

        We flag:
        - Unexpected ARP replies (nobody asked for them = "gratuitous ARP")
        - ARP replies with unusual MAC addresses
        """
        enriched = packet_info.copy()

        arp_op = packet_info.get("arp_op", 0)
        enriched["arp_operation"] = "Request" if arp_op == 1 else "Reply"

        # Gratuitous ARP: a reply with no request - often used in ARP spoofing
        # op=2 means it's a reply
        enriched["is_gratuitous"] = arp_op == 2

        return enriched

    # ============================================================
    # HELPER METHODS
    # ============================================================

    def _identify_service(self, port: Optional[int], protocol: str) -> str:
        """
        Map a port number to a well-known service name.

        Args:
            port (int): Port number
            protocol (str): 'TCP' or 'UDP'

        Returns:
            str: Service name or 'Unknown'
        """
        if port is None:
            return "Unknown"

        # Common well-known port assignments (IANA assigned)
        well_known_ports = {
            20: "FTP (Data)",
            21: "FTP (Control)",
            22: "SSH",
            23: "Telnet",
            25: "SMTP (Email)",
            53: "DNS",
            67: "DHCP (Server)",
            68: "DHCP (Client)",
            80: "HTTP",
            110: "POP3 (Email)",
            143: "IMAP (Email)",
            161: "SNMP",
            443: "HTTPS",
            445: "SMB (File Sharing)",
            465: "SMTPS (Email)",
            993: "IMAPS (Email)",
            995: "POP3S (Email)",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP (Remote Desktop)",
            5432: "PostgreSQL",
            5900: "VNC (Remote Desktop)",
            6379: "Redis",
            8080: "HTTP Alternate",
            8443: "HTTPS Alternate",
            27017: "MongoDB",
        }

        return well_known_ports.get(port, "Unknown")

    def _is_suspicious_port(self, port: Optional[int]) -> bool:
        """
        Check if a port is commonly used by malware or backdoors.

        Args:
            port (int): Port number to check

        Returns:
            bool: True if the port is suspicious
        """
        if port is None:
            return False

        # Ports known to be used by RATs, botnets, and malware
        suspicious_ports = {
            31337,  # Elite/Back Orifice backdoor
            12345,  # NetBus backdoor
            1234,   # Common test/backdoor port
            4444,   # Metasploit default handler
            5555,   # Android ADB / malware
            6666,   # IRC botnet C&C
            6667,   # IRC
            7777,   # Common backdoor
            9999,   # Common backdoor
        }

        return port in suspicious_ports

    def _save_to_db(self, packet_info: Dict):
        """
        Save a packet summary to the database (without raw packet data).

        Args:
            packet_info (dict): Enriched packet information
        """
        try:
            self.db.insert_packet(
                src_ip=packet_info.get("src_ip"),
                dst_ip=packet_info.get("dst_ip"),
                protocol=packet_info.get("protocol"),
                src_port=packet_info.get("src_port"),
                dst_port=packet_info.get("dst_port"),
                size=packet_info.get("size", 0),
                flags=packet_info.get("flags")
            )
        except Exception as e:
            logger.debug(f"Could not save packet to DB: {e}")

    def get_protocol_stats(self) -> Dict[str, int]:
        """
        Return current protocol traffic counts.

        Returns:
            Dict mapping protocol names to packet counts
        """
        return dict(self.protocol_counts)

    def get_recent_dns_queries(self, limit: int = 20) -> list:
        """
        Return the most recent DNS queries seen.

        Args:
            limit (int): Maximum number of queries to return

        Returns:
            List of DNS query dicts
        """
        return self.dns_queries[-limit:]

    def get_recent_http_requests(self, limit: int = 20) -> list:
        """
        Return the most recent HTTP requests seen.

        Args:
            limit (int): Maximum number of requests to return

        Returns:
            List of HTTP request dicts
        """
        return self.http_requests[-limit:]
