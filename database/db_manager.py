"""
============================================================
database/db_manager.py
AI-Powered Linux Network Threat Analyzer

PURPOSE:
    Manages all SQLite database operations — creating tables,
    inserting alerts, querying data, and cleanup.

BEGINNER NOTE:
    SQLite is a simple database stored in a single file.
    Think of it like an Excel spreadsheet that Python can read/write
    super fast. We use it to store all detected threats so we can
    look them up later, generate reports, and show them in the dashboard.

    SQL basics used here:
    - CREATE TABLE: Make a new table (like creating a new sheet)
    - INSERT INTO: Add a new row
    - SELECT: Read rows back out
    - DELETE: Remove old rows
============================================================
"""

import sqlite3
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from contextlib import contextmanager

from core.logger import setup_logger
from core.config_manager import config

logger = setup_logger("DatabaseManager")


class DatabaseManager:
    """
    Handles all database operations using SQLite.

    SQLite is file-based — no server needed!
    The database file is created automatically on first run.

    Usage:
        db = DatabaseManager()
        db.insert_alert("PORT_SCAN", "192.168.1.5", "HIGH", "Port scan detected")
        alerts = db.get_recent_alerts(limit=10)
    """

    def __init__(self):
        """Initialize database connection and create tables if they don't exist."""
        # Get database path from config, default to database/threats.db
        self.db_path = config.get("DATABASE", "db_path", fallback="database/threats.db")

        # Make sure the database directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        logger.info(f"Connecting to database: {self.db_path}")
        self._initialize_tables()

    @contextmanager
    def _get_connection(self):
        """
        Context manager that provides a database connection.

        BEGINNER NOTE:
            Using 'with' (context manager) ensures the connection
            is always closed properly, even if an error occurs.
            This prevents database corruption from unclosed connections.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Allows accessing columns by name
        try:
            yield conn
            conn.commit()  # Save any changes
        except Exception as e:
            conn.rollback()  # Undo changes if something went wrong
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()  # Always close the connection

    def _initialize_tables(self):
        """
        Create all required database tables if they don't already exist.

        Tables created:
        - alerts:       All detected threats and alerts
        - packets:      Summary stats for captured packets
        - auth_events:  Linux auth log events (login attempts)
        - ip_reputation: Cached results from IP reputation lookups
        - system_stats: CPU/memory/network usage snapshots
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # -----------------------------------------------
            # ALERTS TABLE: Stores every detected threat
            # -----------------------------------------------
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT    NOT NULL,
                    alert_type  TEXT    NOT NULL,
                    source_ip   TEXT,
                    dest_ip     TEXT,
                    source_port INTEGER,
                    dest_port   INTEGER,
                    protocol    TEXT,
                    severity    TEXT    NOT NULL DEFAULT 'LOW',
                    description TEXT    NOT NULL,
                    raw_data    TEXT,
                    is_reviewed INTEGER DEFAULT 0
                )
            """)

            # -----------------------------------------------
            # PACKETS TABLE: High-level packet statistics
            # -----------------------------------------------
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT    NOT NULL,
                    src_ip      TEXT,
                    dst_ip      TEXT,
                    protocol    TEXT,
                    src_port    INTEGER,
                    dst_port    INTEGER,
                    size        INTEGER,
                    flags       TEXT
                )
            """)

            # -----------------------------------------------
            # AUTH EVENTS TABLE: Linux login attempts
            # -----------------------------------------------
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auth_events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT    NOT NULL,
                    event_type  TEXT    NOT NULL,
                    username    TEXT,
                    source_ip   TEXT,
                    status      TEXT,
                    raw_line    TEXT
                )
            """)

            # -----------------------------------------------
            # IP REPUTATION TABLE: Cache for IP lookups
            # -----------------------------------------------
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address  TEXT    UNIQUE NOT NULL,
                    score       INTEGER DEFAULT 0,
                    country     TEXT,
                    is_malicious INTEGER DEFAULT 0,
                    last_checked TEXT,
                    source      TEXT
                )
            """)

            # -----------------------------------------------
            # SYSTEM STATS TABLE: Performance snapshots
            # -----------------------------------------------
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_stats (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT    NOT NULL,
                    cpu_percent REAL,
                    memory_percent REAL,
                    packets_captured INTEGER,
                    alerts_count INTEGER,
                    network_bytes_sent INTEGER,
                    network_bytes_recv INTEGER
                )
            """)

            logger.info("Database tables initialized successfully")

    # ============================================================
    # ALERT OPERATIONS
    # ============================================================

    def insert_alert(
        self,
        alert_type: str,
        source_ip: str = None,
        severity: str = "LOW",
        description: str = "",
        dest_ip: str = None,
        source_port: int = None,
        dest_port: int = None,
        protocol: str = None,
        raw_data: str = None
    ) -> int:
        """
        Save a new threat alert to the database.

        Args:
            alert_type (str): Type of threat e.g. 'PORT_SCAN', 'BRUTE_FORCE'
            source_ip (str):  IP address where threat originated
            severity (str):   Threat severity: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
            description (str): Human-readable explanation of the threat
            dest_ip (str):    Destination IP address
            source_port (int): Source port number
            dest_port (int):  Destination port number
            protocol (str):   Network protocol e.g. 'TCP', 'UDP', 'ICMP'
            raw_data (str):   Optional raw packet/log data for debugging

        Returns:
            int: ID of the newly inserted alert row
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts
                    (timestamp, alert_type, source_ip, dest_ip, source_port,
                     dest_port, protocol, severity, description, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                alert_type,
                source_ip,
                dest_ip,
                source_port,
                dest_port,
                protocol,
                severity.upper(),
                description,
                raw_data
            ))

            alert_id = cursor.lastrowid
            logger.info(f"Alert saved: [{severity}] {alert_type} from {source_ip}")
            return alert_id

    def get_recent_alerts(self, limit: int = 50, severity: str = None) -> List[Dict]:
        """
        Retrieve the most recent alerts from the database.

        Args:
            limit (int):    Maximum number of alerts to return
            severity (str): Filter by severity level (optional)

        Returns:
            List[Dict]: List of alert dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if severity:
                cursor.execute("""
                    SELECT * FROM alerts
                    WHERE severity = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (severity.upper(), limit))
            else:
                cursor.execute("""
                    SELECT * FROM alerts
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))

            # Convert Row objects to plain dictionaries
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_alert_stats(self) -> Dict[str, Any]:
        """
        Get summary statistics for alerts (used on dashboard).

        Returns:
            Dict with counts by severity and type
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Total alerts
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total = cursor.fetchone()[0]

            # Count by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM alerts
                GROUP BY severity
            """)
            by_severity = {row[0]: row[1] for row in cursor.fetchall()}

            # Count by type
            cursor.execute("""
                SELECT alert_type, COUNT(*) as count
                FROM alerts
                GROUP BY alert_type
                ORDER BY count DESC
                LIMIT 10
            """)
            by_type = {row[0]: row[1] for row in cursor.fetchall()}

            # Alerts in last 24 hours
            yesterday = (datetime.now() - timedelta(days=1)).isoformat()
            cursor.execute("""
                SELECT COUNT(*) FROM alerts
                WHERE timestamp > ?
            """, (yesterday,))
            last_24h = cursor.fetchone()[0]

            return {
                "total": total,
                "last_24h": last_24h,
                "by_severity": by_severity,
                "by_type": by_type
            }

    def get_top_threat_ips(self, limit: int = 10) -> List[Dict]:
        """
        Get IPs with the most alerts (top attackers).

        Args:
            limit (int): Number of IPs to return

        Returns:
            List of dicts with ip and count
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT source_ip, COUNT(*) as count
                FROM alerts
                WHERE source_ip IS NOT NULL
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT ?
            """, (limit,))
            return [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]

    # ============================================================
    # PACKET OPERATIONS
    # ============================================================

    def insert_packet(self, src_ip: str, dst_ip: str, protocol: str,
                      src_port: int = None, dst_port: int = None,
                      size: int = 0, flags: str = None):
        """
        Store a packet summary in the database.

        Args:
            src_ip (str):   Source IP address
            dst_ip (str):   Destination IP address
            protocol (str): Protocol name
            src_port (int): Source port
            dst_port (int): Destination port
            size (int):     Packet size in bytes
            flags (str):    TCP flags if applicable
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO packets
                    (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                src_ip, dst_ip, protocol,
                src_port, dst_port, size, flags
            ))

    def get_packet_stats(self) -> Dict[str, Any]:
        """
        Get packet statistics summary.

        Returns:
            Dict with total count and protocol breakdown
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM packets")
            total = cursor.fetchone()[0]

            cursor.execute("""
                SELECT protocol, COUNT(*) as count
                FROM packets
                GROUP BY protocol
                ORDER BY count DESC
            """)
            by_protocol = {row[0]: row[1] for row in cursor.fetchall()}

            return {"total": total, "by_protocol": by_protocol}

    # ============================================================
    # AUTH EVENT OPERATIONS
    # ============================================================

    def insert_auth_event(self, event_type: str, username: str = None,
                          source_ip: str = None, status: str = None,
                          raw_line: str = None):
        """
        Store a Linux auth log event.

        Args:
            event_type (str): 'FAILED_LOGIN', 'SUCCESS_LOGIN', 'SUDO', etc.
            username (str):   Account that was targeted
            source_ip (str):  Remote IP (for SSH attempts)
            status (str):     'success' or 'failure'
            raw_line (str):   Original log line
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO auth_events
                    (timestamp, event_type, username, source_ip, status, raw_line)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                event_type, username, source_ip, status, raw_line
            ))

    def get_recent_auth_events(self, limit: int = 50) -> List[Dict]:
        """
        Get the most recent auth log events.

        Args:
            limit (int): Maximum number of events to return

        Returns:
            List of auth event dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM auth_events
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # ============================================================
    # IP REPUTATION OPERATIONS
    # ============================================================

    def upsert_ip_reputation(self, ip_address: str, score: int,
                             country: str = None, is_malicious: bool = False,
                             source: str = "unknown"):
        """
        Insert or update IP reputation data (upsert = update if exists, insert if not).

        Args:
            ip_address (str):   The IP to store reputation for
            score (int):        Abuse score 0-100
            country (str):      Country code e.g. 'US', 'CN'
            is_malicious (bool): Whether IP is flagged as malicious
            source (str):       Data source e.g. 'abuseipdb'
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO ip_reputation
                    (ip_address, score, country, is_malicious, last_checked, source)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    score=excluded.score,
                    country=excluded.country,
                    is_malicious=excluded.is_malicious,
                    last_checked=excluded.last_checked,
                    source=excluded.source
            """, (
                ip_address, score, country,
                1 if is_malicious else 0,
                datetime.now().isoformat(),
                source
            ))

    def get_ip_reputation(self, ip_address: str) -> Optional[Dict]:
        """
        Look up cached reputation data for an IP.

        Args:
            ip_address (str): The IP to look up

        Returns:
            Dict with reputation data, or None if not cached
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM ip_reputation
                WHERE ip_address = ?
            """, (ip_address,))
            row = cursor.fetchone()
            return dict(row) if row else None

    # ============================================================
    # SYSTEM STATS OPERATIONS
    # ============================================================

    def insert_system_stats(self, cpu_percent: float, memory_percent: float,
                            packets_captured: int, alerts_count: int,
                            bytes_sent: int = 0, bytes_recv: int = 0):
        """
        Store a system performance snapshot.

        Args:
            cpu_percent (float):     CPU usage percentage
            memory_percent (float):  RAM usage percentage
            packets_captured (int):  Packets captured so far
            alerts_count (int):      Total alerts so far
            bytes_sent (int):        Network bytes sent
            bytes_recv (int):        Network bytes received
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO system_stats
                    (timestamp, cpu_percent, memory_percent, packets_captured,
                     alerts_count, network_bytes_sent, network_bytes_recv)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                cpu_percent, memory_percent,
                packets_captured, alerts_count,
                bytes_sent, bytes_recv
            ))

    def get_all_alerts_for_report(self) -> List[Dict]:
        """
        Get all alerts for report generation.

        Returns:
            All alert records as a list of dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
            return [dict(row) for row in cursor.fetchall()]

    # ============================================================
    # MAINTENANCE OPERATIONS
    # ============================================================

    def cleanup_old_records(self):
        """
        Delete database records older than the configured retention period.
        This keeps the database from growing too large over time.
        """
        retention_days = config.get_int("DATABASE", "data_retention_days", fallback=30)
        cutoff_date = (datetime.now() - timedelta(days=retention_days)).isoformat()

        with self._get_connection() as conn:
            cursor = conn.cursor()

            tables = ["alerts", "packets", "auth_events", "system_stats"]
            for table in tables:
                cursor.execute(f"DELETE FROM {table} WHERE timestamp < ?", (cutoff_date,))
                deleted = cursor.rowcount
                if deleted > 0:
                    logger.info(f"Cleaned up {deleted} old records from '{table}'")

        logger.info(f"Database cleanup complete (kept last {retention_days} days)")
