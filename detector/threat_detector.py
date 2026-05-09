"""
============================================================
detector/threat_detector.py
AI-Powered Linux Network Threat Analyzer

PURPOSE:
    Detects specific threat patterns in network traffic:
    - Port scanning
    - Brute force attacks
    - ICMP floods
    - ARP spoofing
    - Suspicious DNS activity
    - Web application attacks

BEGINNER NOTE:
    This is the "brain" of the threat detection system.
    It watches patterns over time (not just individual packets)
    to identify attacks.

    Example: One SYN packet to port 22 = normal SSH connection.
    But 50 SYN packets to 50 different ports in 2 seconds
    = port scan!

    We use sliding time windows to track these patterns.
============================================================
"""

import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Callable, Any

from core.logger import setup_logger
from core.config_manager import config
from database.db_manager import DatabaseManager

logger = setup_logger("ThreatDetector")


class ThreatDetector:
    """
    Monitors network traffic for known attack patterns.

    Uses time-windowed counters to detect:
    - Port scans (many ports probed from one IP)
    - Brute force (many failed login attempts)
    - ICMP floods (high volume of pings)
    - ARP spoofing (fake ARP replies)
    - DNS tunneling (unusually long DNS queries)

    Detected threats trigger registered alert callbacks.
    """

    def __init__(self, db: DatabaseManager):
        """
        Initialize the threat detector with tracking data structures.

        Args:
            db (DatabaseManager): Database for storing detected threats
        """
        self.db = db

        # Load thresholds from config
        self.port_scan_threshold = config.get_int(
            "THRESHOLDS", "port_scan_threshold", fallback=15
        )
        self.brute_force_threshold = config.get_int(
            "THRESHOLDS", "brute_force_threshold", fallback=5
        )
        self.brute_force_window = config.get_int(
            "THRESHOLDS", "brute_force_window", fallback=60
        )
        self.icmp_flood_threshold = config.get_int(
            "THRESHOLDS", "icmp_flood_threshold", fallback=100
        )

        # -----------------------------------------------
        # Port Scan Detection Data Structures
        # port_scan_tracker[src_ip] = set of destination ports
        # When this set gets large, it's a port scan
        # -----------------------------------------------
        self._port_scan_tracker: Dict[str, set] = defaultdict(set)
        self._port_scan_timestamps: Dict[str, float] = {}  # Track window start

        # -----------------------------------------------
        # Brute Force Detection Data Structures
        # brute_force_tracker[src_ip] = deque of timestamps
        # Count timestamps in the last N seconds
        # -----------------------------------------------
        self._brute_force_tracker: Dict[str, deque] = defaultdict(deque)

        # -----------------------------------------------
        # ICMP Flood Detection
        # Track ICMP packets per source IP per second
        # -----------------------------------------------
        self._icmp_tracker: Dict[str, deque] = defaultdict(deque)

        # -----------------------------------------------
        # ARP Spoofing Detection
        # Track IP→MAC mappings; alert if MAC changes
        # -----------------------------------------------
        self._arp_table: Dict[str, str] = {}  # ip -> mac address

        # -----------------------------------------------
        # Already alerted IPs (to avoid duplicate alerts)
        # Cooldown prevents spamming the same alert
        # -----------------------------------------------
        self._alerted: Dict[str, float] = {}
        self._alert_cooldown = 30  # seconds between same-type alerts for same IP

        # Alert callbacks - functions called when threat detected
        self._alert_callbacks: List[Callable] = []

        # Thread lock for thread-safe data access
        self._lock = threading.Lock()

        # Background cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="ThreatDetectorCleanup"
        )
        self._cleanup_thread.start()

        logger.info("ThreatDetector initialized")
        logger.info(f"  Port scan threshold:  {self.port_scan_threshold} ports")
        logger.info(f"  Brute force threshold: {self.brute_force_threshold} attempts/{self.brute_force_window}s")
        logger.info(f"  ICMP flood threshold:  {self.icmp_flood_threshold} pkts/s")

    def register_alert_callback(self, callback: Callable):
        """
        Register a function to call when a threat is detected.

        The callback receives:
        {
            'type': 'PORT_SCAN',
            'severity': 'HIGH',
            'source_ip': '192.168.1.5',
            'description': 'Port scan detected: 45 ports probed',
            'timestamp': '2024-01-01T12:00:00'
        }

        Args:
            callback (Callable): Alert handler function
        """
        self._alert_callbacks.append(callback)
        logger.debug(f"Alert callback registered: {callback.__name__}")

    def analyze_packet(self, packet_info: Dict[str, Any]):
        """
        Analyze a packet for threat indicators.

        This is called for every packet captured by PacketCapture.
        It routes the packet to protocol-specific detectors.

        Args:
            packet_info (dict): Packet information from ProtocolAnalyzer
        """
        protocol = packet_info.get("protocol", "")
        src_ip = packet_info.get("src_ip", "")

        # Skip packets without a source IP (can't track them)
        if not src_ip:
            return

        # Skip local loopback traffic (127.x.x.x)
        if src_ip.startswith("127."):
            return

        with self._lock:
            # Route to appropriate detector based on protocol
            if protocol == "TCP":
                self._detect_port_scan(packet_info)
                self._detect_web_attack(packet_info)

            elif protocol == "ICMP":
                self._detect_icmp_flood(packet_info)

            elif protocol == "ARP":
                self._detect_arp_spoofing(packet_info)

            elif protocol == "DNS":
                self._detect_dns_tunneling(packet_info)

            # Check for suspicious ports regardless of protocol
            if packet_info.get("is_suspicious_port"):
                self._alert_suspicious_port(packet_info)

    # ============================================================
    # SPECIFIC THREAT DETECTORS
    # ============================================================

    def _detect_port_scan(self, packet_info: Dict):
        """
        Detect port scanning activity.

        WHAT IS A PORT SCAN?
            An attacker probes many ports on your machine to find
            open services. Example: they try ports 22, 23, 25, 80,
            443, 3306, 3389... in rapid succession.

        HOW WE DETECT IT:
            Track how many DIFFERENT destination ports a single
            source IP tries to connect to within a time window.
            If it exceeds the threshold, it's likely a scan.

        TCP SYN scans are the most common:
            Attacker sends SYN but never completes the connection.
            We see SYN packets to many different ports.
        """
        src_ip = packet_info.get("src_ip")
        dst_port = packet_info.get("dst_port")
        flags = packet_info.get("flags", "")

        # Only track SYN packets (connection attempts)
        # SYN without ACK = new connection attempt
        if not dst_port or "S" not in flags or "A" in flags:
            return

        now = time.time()

        # Initialize or reset time window for this IP
        if src_ip not in self._port_scan_timestamps:
            self._port_scan_timestamps[src_ip] = now
            self._port_scan_tracker[src_ip] = set()

        # Reset window if it's been more than 10 seconds
        window_age = now - self._port_scan_timestamps[src_ip]
        if window_age > 10:
            self._port_scan_tracker[src_ip] = set()
            self._port_scan_timestamps[src_ip] = now

        # Add this port to the set of probed ports
        self._port_scan_tracker[src_ip].add(dst_port)

        # Check if threshold exceeded
        ports_probed = len(self._port_scan_tracker[src_ip])

        if ports_probed >= self.port_scan_threshold:
            self._fire_alert(
                alert_type="PORT_SCAN",
                source_ip=src_ip,
                severity="HIGH",
                description=(
                    f"Port scan detected from {src_ip}: "
                    f"{ports_probed} ports probed in {window_age:.1f} seconds. "
                    f"Sample ports: {list(self._port_scan_tracker[src_ip])[:10]}"
                ),
                dest_ip=packet_info.get("dst_ip"),
                protocol="TCP",
                raw_data=str(list(self._port_scan_tracker[src_ip])[:20])
            )

            # Reset tracker after alert to avoid duplicate flooding
            self._port_scan_tracker[src_ip] = set()
            self._port_scan_timestamps[src_ip] = now

    def _detect_icmp_flood(self, packet_info: Dict):
        """
        Detect ICMP (ping) flood attacks.

        WHAT IS AN ICMP FLOOD?
            An attacker sends thousands of ping packets per second
            to overwhelm the target's network or CPU.
            Also known as a "Ping Flood" DoS attack.

        HOW WE DETECT IT:
            Count ICMP packets from each source IP in the last second.
            If count exceeds threshold, it's a flood.
        """
        src_ip = packet_info.get("src_ip")
        if not src_ip:
            return

        now = time.time()

        # Add current timestamp to the deque
        self._icmp_tracker[src_ip].append(now)

        # Remove timestamps older than 1 second (sliding window)
        while (self._icmp_tracker[src_ip] and
               now - self._icmp_tracker[src_ip][0] > 1.0):
            self._icmp_tracker[src_ip].popleft()

        # Count packets in the last second
        icmp_rate = len(self._icmp_tracker[src_ip])

        if icmp_rate >= self.icmp_flood_threshold:
            self._fire_alert(
                alert_type="ICMP_FLOOD",
                source_ip=src_ip,
                severity="HIGH",
                description=(
                    f"ICMP flood detected from {src_ip}: "
                    f"{icmp_rate} ICMP packets per second "
                    f"(threshold: {self.icmp_flood_threshold})"
                ),
                dest_ip=packet_info.get("dst_ip"),
                protocol="ICMP"
            )

    def _detect_arp_spoofing(self, packet_info: Dict):
        """
        Detect ARP spoofing (ARP poisoning) attacks.

        WHAT IS ARP SPOOFING?
            An attacker sends fake ARP replies associating their MAC address
            with a legitimate IP (like the router's IP).
            This redirects all traffic through the attacker's machine
            (man-in-the-middle attack).

        HOW WE DETECT IT:
            We remember which IP maps to which MAC address.
            If an IP suddenly shows a DIFFERENT MAC address, alert!
        """
        src_ip = packet_info.get("src_ip")
        src_mac = packet_info.get("src_mac")

        if not src_ip or not src_mac:
            return

        # Skip broadcast addresses
        if src_ip in ("0.0.0.0", "255.255.255.255"):
            return

        if src_ip in self._arp_table:
            known_mac = self._arp_table[src_ip]
            if known_mac != src_mac:
                # MAC address changed! Possible ARP spoofing
                self._fire_alert(
                    alert_type="ARP_SPOOFING",
                    source_ip=src_ip,
                    severity="CRITICAL",
                    description=(
                        f"ARP spoofing detected! IP {src_ip} "
                        f"changed MAC from {known_mac} to {src_mac}. "
                        f"Possible man-in-the-middle attack!"
                    ),
                    protocol="ARP",
                    raw_data=f"old_mac={known_mac}, new_mac={src_mac}"
                )
        else:
            # First time seeing this IP, record it
            self._arp_table[src_ip] = src_mac

    def _detect_dns_tunneling(self, packet_info: Dict):
        """
        Detect DNS tunneling (data exfiltration via DNS).

        WHAT IS DNS TUNNELING?
            Attackers encode data in DNS query names to bypass firewalls.
            Example: sending data as "c29tZWRhdGE=.attacker.com"
            (base64 encoded data hidden in a subdomain)

        HOW WE DETECT IT:
            Legitimate domain labels (parts between dots) are short.
            Tunneled data creates very long subdomains.
        """
        dns_query = packet_info.get("dns_query_clean", "")

        if not dns_query:
            return

        # Split domain into labels: "www.google.com" -> ["www", "google", "com"]
        labels = dns_query.split(".")

        # Find the longest label
        max_label_len = max((len(label) for label in labels), default=0)

        # Also check total query length
        total_length = len(dns_query)

        # Thresholds: label > 50 chars or total > 100 chars = suspicious
        if max_label_len > 50 or total_length > 100:
            self._fire_alert(
                alert_type="DNS_TUNNELING",
                source_ip=packet_info.get("src_ip"),
                severity="MEDIUM",
                description=(
                    f"Possible DNS tunneling: query '{dns_query[:60]}...' "
                    f"has suspiciously long label ({max_label_len} chars). "
                    f"Total query length: {total_length}"
                ),
                protocol="DNS",
                raw_data=dns_query
            )

    def _detect_web_attack(self, packet_info: Dict):
        """
        Detect web application attack attempts.

        Checks for common attack patterns in HTTP traffic:
        - SQL Injection
        - Cross-Site Scripting (XSS)
        - Directory Traversal
        - Remote Code Execution attempts
        """
        # Only check HTTP packets with attack indicators
        if not packet_info.get("has_web_attack"):
            return

        indicators = packet_info.get("web_attack_indicators", [])

        self._fire_alert(
            alert_type="WEB_ATTACK",
            source_ip=packet_info.get("src_ip"),
            severity="HIGH",
            description=(
                f"Web attack attempt from {packet_info.get('src_ip')}: "
                f"Suspicious patterns detected: {', '.join(indicators)}. "
                f"Target URL: {packet_info.get('full_url', 'unknown')}"
            ),
            dest_ip=packet_info.get("dst_ip"),
            dest_port=packet_info.get("dst_port"),
            protocol="HTTP",
            raw_data=str(indicators)
        )

    def _alert_suspicious_port(self, packet_info: Dict):
        """
        Alert when traffic uses a port commonly associated with malware.

        Args:
            packet_info (dict): Packet information
        """
        dst_port = packet_info.get("dst_port")
        src_ip = packet_info.get("src_ip")

        self._fire_alert(
            alert_type="SUSPICIOUS_PORT",
            source_ip=src_ip,
            severity="MEDIUM",
            description=(
                f"Traffic to suspicious port {dst_port} from {src_ip}. "
                f"Port {dst_port} is commonly used by backdoors or malware."
            ),
            dest_ip=packet_info.get("dst_ip"),
            dest_port=dst_port,
            protocol=packet_info.get("protocol")
        )

    # ============================================================
    # ALERT SYSTEM
    # ============================================================

    def _fire_alert(self, alert_type: str, source_ip: str, severity: str,
                    description: str, dest_ip: str = None,
                    dest_port: int = None, source_port: int = None,
                    protocol: str = None, raw_data: str = None):
        """
        Create and dispatch a threat alert.

        Checks cooldown to avoid flooding with duplicate alerts.
        Saves alert to database and calls registered callbacks.

        Args:
            alert_type (str): Type of threat e.g. 'PORT_SCAN'
            source_ip (str):  Attacker's IP address
            severity (str):   'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'
            description (str): Human-readable threat explanation
            ... (other optional packet details)
        """
        # Cooldown check: don't repeat the same alert too frequently
        cooldown_key = f"{alert_type}:{source_ip}"
        now = time.time()

        if cooldown_key in self._alerted:
            last_alert_time = self._alerted[cooldown_key]
            if now - last_alert_time < self._alert_cooldown:
                return  # Skip - still in cooldown period

        # Record this alert time
        self._alerted[cooldown_key] = now

        # Build the alert dictionary
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": alert_type,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "source_port": source_port,
            "dest_port": dest_port,
            "protocol": protocol,
            "severity": severity,
            "description": description,
            "raw_data": raw_data
        }

        # Log the alert
        log_func = logger.warning if severity in ("LOW", "MEDIUM") else logger.error
        log_func(f"[{severity}] {alert_type}: {description[:100]}")

        # Save to database
        try:
            self.db.insert_alert(
                alert_type=alert_type,
                source_ip=source_ip,
                severity=severity,
                description=description,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol=protocol,
                raw_data=raw_data
            )
        except Exception as e:
            logger.error(f"Failed to save alert to database: {e}")

        # Notify all registered alert callbacks
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def notify_brute_force(self, source_ip: str, username: str,
                           attempt_count: int):
        """
        Called by AuthLogAnalyzer when brute force is detected in auth logs.

        Args:
            source_ip (str):    Attacking IP
            username (str):     Target username being brute-forced
            attempt_count (int): Number of failed attempts
        """
        self._fire_alert(
            alert_type="BRUTE_FORCE",
            source_ip=source_ip,
            severity="HIGH",
            description=(
                f"Brute force attack detected! {attempt_count} failed login "
                f"attempts for user '{username}' from {source_ip} "
                f"in {self.brute_force_window} seconds."
            ),
            protocol="SSH"
        )

    # ============================================================
    # MAINTENANCE
    # ============================================================

    def _cleanup_loop(self):
        """
        Background thread: periodically clean up old tracking data
        to prevent memory leaks from tracking too many IPs.
        """
        while True:
            time.sleep(60)  # Run cleanup every minute
            try:
                with self._lock:
                    now = time.time()

                    # Clear port scan data older than 30 seconds
                    expired_ips = [
                        ip for ip, ts in self._port_scan_timestamps.items()
                        if now - ts > 30
                    ]
                    for ip in expired_ips:
                        del self._port_scan_tracker[ip]
                        del self._port_scan_timestamps[ip]

                    # Clean up alert cooldown registry
                    expired_alerts = [
                        key for key, ts in self._alerted.items()
                        if now - ts > self._alert_cooldown * 2
                    ]
                    for key in expired_alerts:
                        del self._alerted[key]

                    if expired_ips:
                        logger.debug(f"Cleaned {len(expired_ips)} expired port scan trackers")

            except Exception as e:
                logger.error(f"Cleanup error: {e}")
