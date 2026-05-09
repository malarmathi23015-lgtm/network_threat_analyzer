"""
============================================================
core/alert_manager.py
AI-Powered Linux Network Threat Analyzer

PURPOSE:
    Central hub for all alerts. Receives alerts from multiple
    detectors and dispatches them to the dashboard, terminal,
    and any other registered outputs.

BEGINNER NOTE:
    This is like a newsroom dispatch system.
    Multiple reporters (detectors) send in stories (alerts).
    The desk editor (AlertManager) formats them and sends to:
    - The newspaper (dashboard)
    - The radio (terminal)
    - The archive (database)
    - Any wire services (future integrations like email/Slack)
============================================================
"""

import threading
from collections import deque
from datetime import datetime
from typing import Callable, Dict, List, Any

from core.logger import setup_logger

logger = setup_logger("AlertManager")

# Severity levels with priority (higher = more severe)
SEVERITY_PRIORITY = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

# Color codes for terminal display
SEVERITY_COLORS = {
    "LOW":      "\033[94m",    # Blue
    "MEDIUM":   "\033[93m",    # Yellow
    "HIGH":     "\033[91m",    # Red
    "CRITICAL": "\033[1;91m",  # Bold Red
}
RESET_COLOR = "\033[0m"


class AlertManager:
    """
    Centralized alert management system.

    Collects alerts from all detectors, stores them in a queue,
    and dispatches them to all registered consumers.

    Thread-safe: multiple detectors can submit alerts simultaneously.
    """

    def __init__(self, max_queue_size: int = 1000):
        """
        Initialize the alert manager.

        Args:
            max_queue_size (int): Maximum alerts to keep in memory
        """
        # Thread-safe deque for storing recent alerts
        self._alert_queue: deque = deque(maxlen=max_queue_size)

        # Registered consumers: functions called for each new alert
        self._consumers: List[Callable] = []

        # Statistics
        self.stats = {
            "total_alerts": 0,
            "by_severity": {s: 0 for s in SEVERITY_PRIORITY},
            "by_type": {}
        }

        # Thread lock for stats updates
        self._lock = threading.Lock()

        logger.info("AlertManager initialized")

    def register_consumer(self, consumer: Callable):
        """
        Register a function to receive all new alerts.

        The consumer is called with the alert dict:
        {
            'timestamp': '2024-01-01T12:00:00',
            'type': 'PORT_SCAN',
            'severity': 'HIGH',
            'source_ip': '192.168.1.5',
            'description': '...'
        }

        Args:
            consumer (Callable): Function that accepts an alert dict
        """
        self._consumers.append(consumer)
        logger.debug(f"Alert consumer registered: {consumer.__name__}")

    def receive_alert(self, alert: Dict[str, Any]):
        """
        Receive an alert from any detector and process it.

        This is the main entry point — detectors call this
        when they find a threat.

        Args:
            alert (dict): Alert information dictionary
        """
        # Ensure required fields have defaults
        alert.setdefault("timestamp", datetime.now().isoformat())
        alert.setdefault("severity", "LOW")
        alert.setdefault("type", "UNKNOWN")
        alert.setdefault("source_ip", "Unknown")
        alert.setdefault("description", "No description")

        severity = alert["severity"].upper()

        # Update statistics
        with self._lock:
            self.stats["total_alerts"] += 1
            self.stats["by_severity"][severity] = (
                self.stats["by_severity"].get(severity, 0) + 1
            )
            alert_type = alert["type"]
            self.stats["by_type"][alert_type] = (
                self.stats["by_type"].get(alert_type, 0) + 1
            )

        # Add to in-memory queue
        self._alert_queue.appendleft(alert)

        # Display in terminal with color
        self._print_alert(alert)

        # Dispatch to all registered consumers
        for consumer in self._consumers:
            try:
                consumer(alert)
            except Exception as e:
                logger.error(f"Consumer error ({consumer.__name__}): {e}")

    def _print_alert(self, alert: Dict):
        """
        Print a formatted, colored alert to the terminal.

        Args:
            alert (dict): Alert to display
        """
        severity = alert.get("severity", "LOW").upper()
        color = SEVERITY_COLORS.get(severity, "")
        reset = RESET_COLOR

        timestamp = alert.get("timestamp", "")[:19]  # Trim microseconds
        alert_type = alert.get("type", "UNKNOWN")
        source_ip = alert.get("source_ip", "N/A")
        description = alert.get("description", "")

        # Format: [12:00:00] ⚠ HIGH | PORT_SCAN | from 1.2.3.4 | Description...
        print(
            f"\n{color}"
            f"{'='*60}\n"
            f"[{timestamp}] ⚠ {severity} ALERT\n"
            f"Type: {alert_type}\n"
            f"Source IP: {source_ip}\n"
            f"Details: {description[:200]}\n"
            f"{'='*60}"
            f"{reset}\n"
        )

    def get_recent_alerts(self, limit: int = 50,
                          severity_filter: str = None) -> List[Dict]:
        """
        Get the most recent alerts from the in-memory queue.

        Args:
            limit (int): Maximum number of alerts to return
            severity_filter (str): Optional filter e.g. 'HIGH'

        Returns:
            List of alert dictionaries (newest first)
        """
        alerts = list(self._alert_queue)

        if severity_filter:
            alerts = [
                a for a in alerts
                if a.get("severity", "").upper() == severity_filter.upper()
            ]

        return alerts[:limit]

    def get_stats(self) -> Dict:
        """
        Return alert statistics.

        Returns:
            Dict with total counts and breakdowns
        """
        with self._lock:
            return {
                "total": self.stats["total_alerts"],
                "by_severity": dict(self.stats["by_severity"]),
                "by_type": dict(self.stats["by_type"]),
                "queue_size": len(self._alert_queue)
            }

    def clear_queue(self):
        """Clear all alerts from the in-memory queue."""
        self._alert_queue.clear()
        logger.info("Alert queue cleared")
