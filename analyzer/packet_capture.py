"""
============================================================
analyzer/packet_capture.py
AI-Powered Linux Network Threat Analyzer

PURPOSE:
    Captures live network packets using Scapy and feeds them
    to protocol analyzers for inspection.

BEGINNER NOTE:
    Think of this module as a "wiretap" for your network.
    Every time data travels across your network card
    (someone loads a webpage, pings a server, etc.),
    Scapy grabs a copy of that packet for us to inspect.

    Scapy can see:
    - Where the packet came from (IP address)
    - Where it's going (destination IP)
    - What protocol it uses (TCP/UDP/ICMP/DNS)
    - What data it contains (ports, flags, payload)

IMPORTANT:
    Packet capture requires ROOT privileges.
    Run with: sudo python3 main.py
============================================================
"""

import threading
import time
from typing import Callable, List
from datetime import datetime

from core.logger import setup_logger
from core.config_manager import config

logger = setup_logger("PacketCapture")

# We import scapy inside functions to handle cases where
# it's not installed yet (gives a better error message)
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.error("Scapy not installed! Run: pip install scapy")


class PacketCapture:
    """
    Captures network packets on a given interface using Scapy.

    This runs in a background thread so the rest of the program
    (dashboard, detectors) can keep running while packets are captured.

    Architecture:
        PacketCapture --> calls --> registered callback functions
        Each callback receives a parsed packet dict to process.

    Usage:
        capture = PacketCapture()
        capture.register_callback(my_function)
        capture.start()
        # ... later ...
        capture.stop()
    """

    def __init__(self):
        """Initialize the packet capture with settings from config."""
        self.interface = config.get("NETWORK", "interface", fallback="any")
        self.buffer_size = config.get_int("NETWORK", "packet_buffer_size", fallback=1000)

        # List of functions to call when a packet is captured
        # Any detector/analyzer registers here to receive packets
        self._callbacks: List[Callable] = []

        # Thread control
        self._running = False
        self._thread = None

        # Statistics
        self.stats = {
            "total_captured": 0,
            "tcp_count": 0,
            "udp_count": 0,
            "icmp_count": 0,
            "dns_count": 0,
            "arp_count": 0,
            "other_count": 0,
            "start_time": None
        }

        logger.info(f"PacketCapture initialized on interface: {self.interface}")

    def register_callback(self, callback: Callable):
        """
        Register a function to be called when a packet is captured.

        The callback receives a dictionary with parsed packet info:
        {
            'timestamp': '2024-01-01T12:00:00',
            'src_ip': '192.168.1.5',
            'dst_ip': '8.8.8.8',
            'protocol': 'TCP',
            'src_port': 54321,
            'dst_port': 80,
            'size': 64,
            'flags': 'S',      # TCP SYN flag
            'raw': <packet>    # The original Scapy packet
        }

        Args:
            callback (Callable): Function that accepts a packet dict
        """
        self._callbacks.append(callback)
        logger.debug(f"Registered callback: {callback.__name__}")

    def _process_packet(self, packet):
        """
        Called by Scapy for every captured packet.
        Parses the packet and calls all registered callbacks.

        Args:
            packet: Raw Scapy packet object
        """
        try:
            # Only process packets that have an IP layer
            # (ignores low-level ethernet frames, ARP, etc.)
            if not packet.haslayer(IP):
                # Handle ARP separately
                if packet.haslayer(ARP):
                    self._process_arp(packet)
                return

            # -----------------------------------------------
            # Build a clean dictionary from the packet data
            # -----------------------------------------------
            packet_info = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "size": len(packet),
                "protocol": "OTHER",
                "src_port": None,
                "dst_port": None,
                "flags": None,
                "raw": packet
            }

            # -----------------------------------------------
            # Identify and parse the transport layer protocol
            # -----------------------------------------------
            if packet.haslayer(TCP):
                packet_info["protocol"] = "TCP"
                packet_info["src_port"] = packet[TCP].sport
                packet_info["dst_port"] = packet[TCP].dport
                # TCP flags tell us if it's SYN (new connection), FIN (close), etc.
                packet_info["flags"] = str(packet[TCP].flags)
                self.stats["tcp_count"] += 1

                # Check if HTTP is inside TCP
                if packet.haslayer(HTTPRequest):
                    packet_info["protocol"] = "HTTP"
                    packet_info["http_method"] = packet[HTTPRequest].Method.decode(errors="replace")
                    packet_info["http_host"] = packet[HTTPRequest].Host.decode(errors="replace")
                    packet_info["http_path"] = packet[HTTPRequest].Path.decode(errors="replace")

            elif packet.haslayer(UDP):
                packet_info["protocol"] = "UDP"
                packet_info["src_port"] = packet[UDP].sport
                packet_info["dst_port"] = packet[UDP].dport
                self.stats["udp_count"] += 1

                # Check if DNS is inside UDP
                if packet.haslayer(DNS):
                    packet_info["protocol"] = "DNS"
                    try:
                        if packet[DNS].qd:  # DNS query
                            packet_info["dns_query"] = packet[DNS].qd.qname.decode(errors="replace")
                    except Exception:
                        pass
                    self.stats["dns_count"] += 1

            elif packet.haslayer(ICMP):
                packet_info["protocol"] = "ICMP"
                packet_info["icmp_type"] = packet[ICMP].type
                packet_info["icmp_code"] = packet[ICMP].code
                self.stats["icmp_count"] += 1

            else:
                self.stats["other_count"] += 1

            # Update total packet count
            self.stats["total_captured"] += 1

            # -----------------------------------------------
            # Send the packet to all registered callbacks
            # -----------------------------------------------
            for callback in self._callbacks:
                try:
                    callback(packet_info)
                except Exception as e:
                    logger.error(f"Error in callback {callback.__name__}: {e}")

        except Exception as e:
            logger.debug(f"Packet processing error (non-critical): {e}")

    def _process_arp(self, packet):
        """
        Process ARP packets separately to detect ARP spoofing.

        BEGINNER NOTE:
            ARP maps IP addresses to MAC addresses on a local network.
            Attackers can send fake ARP replies to redirect traffic
            through their machine (man-in-the-middle attack).
        """
        if not SCAPY_AVAILABLE:
            return

        packet_info = {
            "timestamp": datetime.now().isoformat(),
            "protocol": "ARP",
            "src_ip": packet[ARP].psrc,
            "dst_ip": packet[ARP].pdst,
            "src_mac": packet[ARP].hwsrc,
            "dst_mac": packet[ARP].hwdst,
            "arp_op": packet[ARP].op,  # 1 = request, 2 = reply
            "size": len(packet),
            "raw": packet
        }

        self.stats["arp_count"] += 1

        for callback in self._callbacks:
            try:
                callback(packet_info)
            except Exception as e:
                logger.error(f"ARP callback error: {e}")

    def _capture_loop(self):
        """
        The main capture loop that runs in a background thread.
        Calls Scapy's sniff() which blocks until stopped.
        """
        logger.info(f"Starting packet capture on interface: {self.interface}")
        self.stats["start_time"] = datetime.now()

        try:
            # sniff() captures packets continuously
            # prn= is the function called for each packet
            # store=False means don't keep all packets in RAM (saves memory)
            # stop_filter= lets us stop the loop cleanly
            sniff(
                iface=self.interface if self.interface != "any" else None,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda p: not self._running
            )
        except PermissionError:
            logger.error("Permission denied! Packet capture requires root/sudo.")
            logger.error("Run: sudo python3 main.py")
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
        finally:
            self._running = False
            logger.info("Packet capture stopped.")

    def start(self):
        """
        Start packet capture in a background thread.

        The thread runs independently so the main program
        (Flask dashboard, etc.) can continue running.
        """
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start capture - Scapy not installed")
            return

        if self._running:
            logger.warning("Packet capture is already running")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._capture_loop,
            name="PacketCaptureThread",
            daemon=True  # Thread stops automatically when main program exits
        )
        self._thread.start()
        logger.info("Packet capture thread started")

    def stop(self):
        """Stop the packet capture thread gracefully."""
        logger.info("Stopping packet capture...")
        self._running = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)  # Wait max 5 seconds

        logger.info("Packet capture stopped")

    def get_stats(self) -> dict:
        """
        Get current capture statistics.

        Returns:
            Dict with packet counts by protocol and runtime
        """
        stats = self.stats.copy()
        if stats["start_time"]:
            runtime = (datetime.now() - stats["start_time"]).total_seconds()
            stats["runtime_seconds"] = round(runtime, 2)
            if runtime > 0:
                stats["packets_per_second"] = round(
                    stats["total_captured"] / runtime, 2
                )
        return stats

    def is_running(self) -> bool:
        """Return True if packet capture is active."""
        return self._running
