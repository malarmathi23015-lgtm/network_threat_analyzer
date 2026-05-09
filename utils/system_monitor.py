"""
============================================================
utils/system_monitor.py
AI-Powered Linux Network Threat Analyzer

PURPOSE:
    Collects system performance metrics using psutil:
    - CPU usage
    - RAM usage
    - Network interface statistics
    - Disk usage

BEGINNER NOTE:
    psutil is a Python library that reads system stats from
    Linux's /proc filesystem (virtual files that expose kernel data).

    We collect these metrics to:
    1. Show them on the dashboard (health status)
    2. Detect anomalies (CPU spike during scan = suspicious)
    3. Ensure the analyzer itself isn't overloading the system
============================================================
"""

import threading
import time
from datetime import datetime
from typing import Dict, Any, Optional

from core.logger import setup_logger
from core.config_manager import config
from database.db_manager import DatabaseManager

logger = setup_logger("SystemMonitor")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.error("psutil not installed! Run: pip install psutil")


class SystemMonitor:
    """
    Periodically collects and stores system performance metrics.

    Runs as a background thread, sampling metrics every 30 seconds
    and storing snapshots in the database.
    """

    def __init__(self, db: DatabaseManager, interval: int = 30):
        """
        Initialize the system monitor.

        Args:
            db (DatabaseManager): Database for storing stats
            interval (int): Seconds between metric collections
        """
        self.db = db
        self.interval = interval

        # Track network stats for calculating rates (bytes per second)
        self._last_net_io = None
        self._last_net_time = None

        # Current stats (updated every interval)
        self._current_stats: Dict[str, Any] = {}

        # Thread control
        self._running = False
        self._thread = None

        if not PSUTIL_AVAILABLE:
            logger.warning("psutil unavailable, system monitoring disabled")

        logger.info(f"SystemMonitor initialized (interval={interval}s)")

    def start(self):
        """Start the background monitoring thread."""
        if not PSUTIL_AVAILABLE:
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="SystemMonitor"
        )
        self._thread.start()
        logger.info("System monitoring started")

    def stop(self):
        """Stop the monitoring thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("System monitoring stopped")

    def _monitor_loop(self):
        """Main monitoring loop: collect and store stats periodically."""
        while self._running:
            try:
                stats = self.collect_stats()
                self._current_stats = stats

                # Save to database
                self.db.insert_system_stats(
                    cpu_percent=stats.get("cpu_percent", 0),
                    memory_percent=stats.get("memory_percent", 0),
                    packets_captured=0,  # Filled by main controller
                    alerts_count=0,
                    bytes_sent=stats.get("net_bytes_sent", 0),
                    bytes_recv=stats.get("net_bytes_recv", 0)
                )

            except Exception as e:
                logger.error(f"System monitor error: {e}")

            time.sleep(self.interval)

    def collect_stats(self) -> Dict[str, Any]:
        """
        Collect all system metrics and return as a dictionary.

        Returns:
            Dict with CPU, memory, network, and disk stats
        """
        if not PSUTIL_AVAILABLE:
            return {"error": "psutil not available"}

        stats = {"timestamp": datetime.now().isoformat()}

        # -----------------------------------------------
        # CPU Statistics
        # -----------------------------------------------
        # cpu_percent: 0-100%, measured over 1 second interval
        stats["cpu_percent"] = psutil.cpu_percent(interval=1)
        stats["cpu_count"] = psutil.cpu_count()

        # Per-core usage (list of percentages)
        per_core = psutil.cpu_percent(percpu=True, interval=0)
        stats["cpu_per_core"] = per_core

        # -----------------------------------------------
        # Memory Statistics
        # -----------------------------------------------
        mem = psutil.virtual_memory()
        stats["memory_total_gb"] = round(mem.total / (1024**3), 2)
        stats["memory_used_gb"] = round(mem.used / (1024**3), 2)
        stats["memory_available_gb"] = round(mem.available / (1024**3), 2)
        stats["memory_percent"] = mem.percent

        # -----------------------------------------------
        # Network Statistics
        # -----------------------------------------------
        net_io = psutil.net_io_counters()
        now = time.time()

        stats["net_bytes_sent"] = net_io.bytes_sent
        stats["net_bytes_recv"] = net_io.bytes_recv
        stats["net_packets_sent"] = net_io.packets_sent
        stats["net_packets_recv"] = net_io.packets_recv
        stats["net_errors_in"] = net_io.errin
        stats["net_errors_out"] = net_io.errout

        # Calculate rates (bytes per second)
        if self._last_net_io and self._last_net_time:
            elapsed = now - self._last_net_time
            if elapsed > 0:
                stats["net_send_rate_bps"] = int(
                    (net_io.bytes_sent - self._last_net_io.bytes_sent) / elapsed
                )
                stats["net_recv_rate_bps"] = int(
                    (net_io.bytes_recv - self._last_net_io.bytes_recv) / elapsed
                )

        self._last_net_io = net_io
        self._last_net_time = now

        # -----------------------------------------------
        # Disk Statistics
        # -----------------------------------------------
        disk = psutil.disk_usage("/")
        stats["disk_total_gb"] = round(disk.total / (1024**3), 2)
        stats["disk_used_gb"] = round(disk.used / (1024**3), 2)
        stats["disk_free_gb"] = round(disk.free / (1024**3), 2)
        stats["disk_percent"] = disk.percent

        # -----------------------------------------------
        # System Uptime
        # -----------------------------------------------
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        stats["uptime_hours"] = round(uptime_seconds / 3600, 1)

        return stats

    def get_current_stats(self) -> Dict[str, Any]:
        """
        Return the most recently collected system stats.

        Returns:
            Dict with current system metrics
        """
        if not self._current_stats:
            return self.collect_stats()
        return self._current_stats.copy()

    def get_network_interfaces(self) -> Dict[str, Dict]:
        """
        Get statistics for each network interface.

        Returns:
            Dict mapping interface name to its stats
        """
        if not PSUTIL_AVAILABLE:
            return {}

        interfaces = {}
        net_stats = psutil.net_if_stats()
        net_io = psutil.net_io_counters(pernic=True)
        net_addrs = psutil.net_if_addrs()

        for iface_name, stats in net_stats.items():
            io = net_io.get(iface_name)
            addrs = net_addrs.get(iface_name, [])

            # Get IPv4 address
            ipv4 = None
            for addr in addrs:
                if addr.family.name == "AF_INET":
                    ipv4 = addr.address
                    break

            interfaces[iface_name] = {
                "is_up": stats.isup,
                "speed_mbps": stats.speed,
                "mtu": stats.mtu,
                "ipv4": ipv4,
                "bytes_sent": io.bytes_sent if io else 0,
                "bytes_recv": io.bytes_recv if io else 0,
                "packets_sent": io.packets_sent if io else 0,
                "packets_recv": io.packets_recv if io else 0,
            }

        return interfaces

    def is_healthy(self) -> bool:
        """
        Check if the system is operating within healthy limits.

        Returns:
            bool: True if CPU < 90% and Memory < 95%
        """
        stats = self.get_current_stats()
        cpu_ok = stats.get("cpu_percent", 0) < 90
        mem_ok = stats.get("memory_percent", 0) < 95
        return cpu_ok and mem_ok
