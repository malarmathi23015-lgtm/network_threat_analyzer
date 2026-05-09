"""
============================================================
detector/auth_log_analyzer.py
AI-Powered Linux Network Threat Analyzer

PURPOSE:
    Monitors /var/log/auth.log (or /var/log/secure) for:
    - Failed SSH login attempts (brute force)
    - Successful logins from unusual IPs
    - sudo privilege escalation events
    - New user account creation

BEGINNER NOTE:
    Linux keeps a detailed log of all login attempts in auth.log.
    Every time someone tries to SSH into your machine (or fails),
    it's written to this file.

    We use the 'watchdog' library to get notified the INSTANT
    a new line is written to auth.log, then parse it for threats.

    Example auth.log lines:
    Failed password for root from 192.168.1.100 port 54321 ssh2
    Accepted password for alice from 10.0.0.5 port 22 ssh2
    sudo: bob : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash
============================================================
"""

import re
import threading
import time
import os
from collections import defaultdict, deque
from datetime import datetime
from typing import Callable, Dict, List, Optional

from core.logger import setup_logger
from core.config_manager import config
from database.db_manager import DatabaseManager

logger = setup_logger("AuthLogAnalyzer")

# Try to import watchdog for real-time file monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logger.warning("watchdog not installed. Using polling fallback.")


class AuthLogParser:
    """
    Parses individual lines from auth.log using regex patterns.

    BEGINNER NOTE:
        Regex (Regular Expressions) are patterns for matching text.
        We use them to extract IP addresses, usernames, etc.
        from log lines like:
        "Failed password for root from 192.168.1.5 port 22 ssh2"

        The regex pattern r'(\d+\.\d+\.\d+\.\d+)' matches any IPv4 address.
    """

    # -----------------------------------------------
    # Regex patterns to match auth.log line formats
    # -----------------------------------------------

    # Matches: "Failed password for root from 192.168.1.5 port 54321 ssh2"
    FAILED_PASSWORD = re.compile(
        r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
    )

    # Matches: "Accepted password for alice from 10.0.0.5 port 22 ssh2"
    ACCEPTED_PASSWORD = re.compile(
        r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port (\d+)"
    )

    # Matches: "Invalid user admin from 45.33.32.156 port 12345"
    INVALID_USER = re.compile(
        r"Invalid user (\S+) from ([\d.]+)"
    )

    # Matches sudo events:
    # "sudo: alice : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"
    SUDO_EVENT = re.compile(
        r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)"
    )

    # Matches: "New user: alice" or "useradd[1234]: new user: name=alice"
    NEW_USER = re.compile(
        r"new user:\s*(?:name=)?(\S+)"
    )

    # Matches: "Disconnecting authenticating user root 192.168.1.5 port 22"
    DISCONNECT = re.compile(
        r"Disconnecting.*?([\d.]+) port (\d+)"
    )

    @classmethod
    def parse_line(cls, line: str) -> Optional[Dict]:
        """
        Parse a single auth.log line and extract structured data.

        Args:
            line (str): Raw log line from auth.log

        Returns:
            Dict with parsed fields, or None if line doesn't match any pattern
        """
        line = line.strip()
        if not line:
            return None

        # Try failed password pattern
        match = cls.FAILED_PASSWORD.search(line)
        if match:
            return {
                "event_type": "FAILED_LOGIN",
                "username": match.group(1),
                "source_ip": match.group(2),
                "port": int(match.group(3)),
                "status": "failure",
                "raw_line": line
            }

        # Try successful login pattern
        match = cls.ACCEPTED_PASSWORD.search(line)
        if match:
            return {
                "event_type": "SUCCESS_LOGIN",
                "username": match.group(1),
                "source_ip": match.group(2),
                "port": int(match.group(3)),
                "status": "success",
                "raw_line": line
            }

        # Try invalid user pattern
        match = cls.INVALID_USER.search(line)
        if match:
            return {
                "event_type": "INVALID_USER",
                "username": match.group(1),
                "source_ip": match.group(2),
                "status": "failure",
                "raw_line": line
            }

        # Try sudo event pattern
        match = cls.SUDO_EVENT.search(line)
        if match:
            return {
                "event_type": "SUDO",
                "username": match.group(1),
                "command": match.group(2).strip(),
                "source_ip": None,
                "status": "success",
                "raw_line": line
            }

        # Try new user creation pattern
        match = cls.NEW_USER.search(line)
        if match:
            return {
                "event_type": "NEW_USER_CREATED",
                "username": match.group(1),
                "source_ip": None,
                "status": "info",
                "raw_line": line
            }

        return None  # Line didn't match any known pattern


class AuthLogAnalyzer:
    """
    Monitors auth.log in real-time and detects authentication threats.

    Features:
    - Real-time log file monitoring using watchdog
    - Brute force detection using sliding time window
    - Alerts dispatched to ThreatDetector callbacks
    - All events saved to database
    """

    def __init__(self, db: DatabaseManager, threat_detector=None):
        """
        Initialize the auth log analyzer.

        Args:
            db (DatabaseManager): Database for storing auth events
            threat_detector: ThreatDetector instance for alerting
        """
        self.db = db
        self.threat_detector = threat_detector
        self.parser = AuthLogParser()

        # Path to auth log (from config)
        self.log_path = config.get(
            "AUTH_LOG", "log_path", fallback="/var/log/auth.log"
        )
        self.poll_interval = config.get_int(
            "AUTH_LOG", "poll_interval", fallback=2
        )

        # Brute force tracking: ip -> deque of timestamps
        self._brute_force_tracker: Dict[str, deque] = defaultdict(deque)
        self.brute_force_threshold = config.get_int(
            "THRESHOLDS", "brute_force_threshold", fallback=5
        )
        self.brute_force_window = config.get_int(
            "THRESHOLDS", "brute_force_window", fallback=60
        )

        # Track already-alerted IPs (with timestamp)
        self._alerted_ips: Dict[str, float] = {}

        # Background monitoring thread
        self._running = False
        self._monitor_thread = None
        self._observer = None

        # File position tracker (so we only read new lines)
        self._file_position = 0

        # Statistics
        self.stats = {
            "failed_logins": 0,
            "successful_logins": 0,
            "sudo_events": 0,
            "brute_force_alerts": 0,
            "new_users": 0
        }

        logger.info(f"AuthLogAnalyzer initialized, watching: {self.log_path}")

    def start(self):
        """
        Start monitoring auth.log in a background thread.

        Uses watchdog for instant notification of new log entries.
        Falls back to polling if watchdog is unavailable.
        """
        if self._running:
            logger.warning("Auth log analyzer already running")
            return

        # Check if log file exists and is readable
        if not os.path.exists(self.log_path):
            logger.warning(f"Auth log not found: {self.log_path}")
            logger.warning("Creating a simulated log for testing...")
            self._create_test_log()

        # Start monitoring from the end of the current file
        # (we don't want to reprocess old entries on startup)
        try:
            self._file_position = os.path.getsize(self.log_path)
        except Exception:
            self._file_position = 0

        self._running = True

        if WATCHDOG_AVAILABLE:
            self._start_watchdog()
        else:
            self._start_polling()

        logger.info("Auth log monitoring started")

    def _start_watchdog(self):
        """Use watchdog library for efficient, event-driven log monitoring."""
        log_dir = os.path.dirname(os.path.abspath(self.log_path))

        class LogChangeHandler(FileSystemEventHandler):
            def __init__(self, analyzer):
                self.analyzer = analyzer

            def on_modified(self, event):
                # Watchdog triggers on any file in the directory
                # We only care about our specific log file
                if event.src_path == os.path.abspath(self.analyzer.log_path):
                    self.analyzer._read_new_lines()

        self._observer = Observer()
        self._observer.schedule(LogChangeHandler(self), log_dir, recursive=False)
        self._observer.start()
        logger.info("Using watchdog for real-time log monitoring")

    def _start_polling(self):
        """Fallback: poll the log file every N seconds for changes."""
        self._monitor_thread = threading.Thread(
            target=self._polling_loop,
            daemon=True,
            name="AuthLogPoller"
        )
        self._monitor_thread.start()
        logger.info(f"Using polling for log monitoring (every {self.poll_interval}s)")

    def _polling_loop(self):
        """Poll the log file for new lines at regular intervals."""
        while self._running:
            try:
                self._read_new_lines()
            except Exception as e:
                logger.error(f"Log polling error: {e}")
            time.sleep(self.poll_interval)

    def _read_new_lines(self):
        """
        Read only the NEW lines added to the log file since last check.

        BEGINNER NOTE:
            We track the file position (like a cursor).
            Each time we check, we seek to where we left off
            and read only the new lines. This avoids re-processing
            old entries every time.
        """
        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                # Jump to where we last stopped reading
                f.seek(self._file_position)

                new_lines = f.readlines()

                # Update our position for next read
                self._file_position = f.tell()

            # Process each new line
            for line in new_lines:
                self._process_log_line(line)

        except FileNotFoundError:
            logger.error(f"Auth log file disappeared: {self.log_path}")
        except PermissionError:
            logger.error(f"No permission to read: {self.log_path}")
            logger.error("Try running with sudo for full auth log access")
        except Exception as e:
            logger.error(f"Error reading log: {e}")

    def _process_log_line(self, line: str):
        """
        Parse a log line and handle any detected events.

        Args:
            line (str): Raw log line to process
        """
        event = self.parser.parse_line(line)
        if not event:
            return  # Not a line we care about

        event_type = event.get("event_type")
        src_ip = event.get("source_ip")
        username = event.get("username")

        # Save to database
        try:
            self.db.insert_auth_event(
                event_type=event_type,
                username=username,
                source_ip=src_ip,
                status=event.get("status"),
                raw_line=event.get("raw_line")
            )
        except Exception as e:
            logger.debug(f"DB insert failed: {e}")

        # Update statistics
        if event_type == "FAILED_LOGIN":
            self.stats["failed_logins"] += 1
            logger.warning(f"Failed login: user={username}, ip={src_ip}")
            if src_ip:
                self._check_brute_force(src_ip, username)

        elif event_type == "SUCCESS_LOGIN":
            self.stats["successful_logins"] += 1
            logger.info(f"Successful login: user={username}, ip={src_ip}")

        elif event_type == "SUDO":
            self.stats["sudo_events"] += 1
            cmd = event.get("command", "")
            logger.warning(f"Sudo command: user={username}, cmd={cmd[:50]}")

        elif event_type == "NEW_USER_CREATED":
            self.stats["new_users"] += 1
            logger.warning(f"New user created: {username}")

        elif event_type == "INVALID_USER":
            logger.warning(f"Login attempt for invalid user: {username} from {src_ip}")
            if src_ip:
                self._check_brute_force(src_ip, username)

    def _check_brute_force(self, source_ip: str, username: str):
        """
        Check if this IP has made too many failed login attempts.

        Uses a sliding time window:
        - Add current timestamp to the IP's deque
        - Remove timestamps older than the window
        - If remaining timestamps >= threshold → brute force!

        Args:
            source_ip (str): IP making the login attempts
            username (str):  Username being targeted
        """
        now = time.time()

        # Add current attempt timestamp
        self._brute_force_tracker[source_ip].append(now)

        # Remove attempts outside the time window
        window_cutoff = now - self.brute_force_window
        while (self._brute_force_tracker[source_ip] and
               self._brute_force_tracker[source_ip][0] < window_cutoff):
            self._brute_force_tracker[source_ip].popleft()

        attempt_count = len(self._brute_force_tracker[source_ip])

        # Check if threshold exceeded
        if attempt_count >= self.brute_force_threshold:
            # Check cooldown (don't re-alert same IP too frequently)
            last_alert = self._alerted_ips.get(source_ip, 0)
            if now - last_alert < 120:  # 2 minute cooldown
                return

            self._alerted_ips[source_ip] = now
            self.stats["brute_force_alerts"] += 1

            logger.error(
                f"BRUTE FORCE DETECTED: {attempt_count} attempts "
                f"for '{username}' from {source_ip}"
            )

            # Notify the ThreatDetector if connected
            if self.threat_detector:
                self.threat_detector.notify_brute_force(
                    source_ip=source_ip,
                    username=username,
                    attempt_count=attempt_count
                )

    def _create_test_log(self):
        """
        Create a test auth.log file for systems where the real one
        is inaccessible (e.g., Docker containers, development systems).
        """
        test_log_path = "logs/test_auth.log"
        os.makedirs("logs", exist_ok=True)

        sample_entries = [
            "Jan  1 12:00:01 hostname sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2",
            "Jan  1 12:00:02 hostname sshd[1234]: Failed password for root from 192.168.1.100 port 54322 ssh2",
            "Jan  1 12:00:03 hostname sshd[1234]: Failed password for admin from 10.0.0.5 port 22 ssh2",
            "Jan  1 12:00:04 hostname sshd[1235]: Accepted password for alice from 192.168.1.50 port 52100 ssh2",
            "Jan  1 12:00:05 hostname sudo: alice : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/apt update",
        ]

        with open(test_log_path, "w") as f:
            f.write("\n".join(sample_entries) + "\n")

        self.log_path = test_log_path
        logger.info(f"Test log created at: {test_log_path}")

    def stop(self):
        """Stop monitoring auth.log."""
        self._running = False

        if self._observer:
            self._observer.stop()
            self._observer.join()

        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=3)

        logger.info("Auth log monitoring stopped")

    def get_stats(self) -> Dict:
        """
        Return current auth log analysis statistics.

        Returns:
            Dict with event counts
        """
        return self.stats.copy()

    def get_top_attacking_ips(self, limit: int = 10) -> List[Dict]:
        """
        Return the IPs with the most failed login attempts.

        Args:
            limit (int): Number of IPs to return

        Returns:
            List of dicts with ip and attempt count
        """
        return sorted(
            [
                {"ip": ip, "attempts": len(attempts)}
                for ip, attempts in self._brute_force_tracker.items()
            ],
            key=lambda x: x["attempts"],
            reverse=True
        )[:limit]
