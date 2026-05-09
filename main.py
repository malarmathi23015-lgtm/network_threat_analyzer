"""
============================================================
main.py
AI-Powered Linux Network Threat Analyzer

PURPOSE:
    The main entry point of the entire application.
    Initializes all modules, wires them together,
    and starts all background threads.

HOW IT WORKS:
    1. Load configuration
    2. Initialize database
    3. Create all analyzer/detector components
    4. Wire callbacks (connect outputs to inputs)
    5. Start all background threads
    6. Start the Flask dashboard (blocks until Ctrl+C)
    7. Graceful shutdown on Ctrl+C

ARCHITECTURE DIAGRAM:
    PacketCapture
        |
        v
    ProtocolAnalyzer  ─────────────────────┐
        |                                   |
        v                                   v
    ThreatDetector              AnomalyDetector (AI)
        |                                   |
        └──────────┬────────────────────────┘
                   v
            AlertManager
                   |
          ┌────────┴────────┐
          v                  v
    Flask Dashboard    Terminal Logs
          |
          v
      WebSocket → Browser

HOW TO RUN:
    sudo python3 main.py

    NOTE: sudo is required for packet capture.
    Without sudo, only the dashboard + auth log monitoring
    will work (no live packet capture).
============================================================
"""

import signal
import sys
import time
import threading
import os
from datetime import datetime

# ============================================================
# Import all our modules
# ============================================================
from core.logger import setup_logger
from core.config_manager import config
from core.alert_manager import AlertManager

from database.db_manager import DatabaseManager

from analyzer.packet_capture import PacketCapture
from analyzer.protocol_analyzer import ProtocolAnalyzer

from detector.threat_detector import ThreatDetector
from detector.auth_log_analyzer import AuthLogAnalyzer
from detector.ip_reputation import IPReputationChecker

from ai_engine.anomaly_detector import AnomalyDetector

from reporter.report_generator import ReportGenerator
from utils.system_monitor import SystemMonitor

from dashboard.app import create_app, run_dashboard

# ============================================================
# Setup the main application logger
# ============================================================
log_level = config.get("GENERAL", "log_level", fallback="INFO")
logger = setup_logger("Main", log_level)


def print_banner():
    """Print the startup banner to the terminal."""
    banner = r"""
    ╔═══════════════════════════════════════════════════════════╗
    ║       AI-Powered Linux Network Threat Analyzer            ║
    ║                  Version 1.0.0                            ║
    ║                                                           ║
    ║   [+] Live Packet Capture      [+] Protocol Analysis      ║
    ║   [+] Port Scan Detection      [+] Brute Force Detection   ║
    ║   [+] Auth Log Monitoring      [+] IP Reputation Check    ║
    ║   [+] AI Anomaly Detection     [+] Flask Dashboard        ║
    ║   [+] PDF/CSV Reports          [+] SQLite Database        ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print("\033[96m" + banner + "\033[0m")


class NetworkThreatAnalyzer:
    """
    The main application class that orchestrates all components.

    This class follows the "Composition" pattern — it holds
    references to all subsystems and coordinates them.

    Think of this as the "command center" that:
    - Creates all the workers (analyzers, detectors)
    - Tells them how to talk to each other (callbacks)
    - Starts/stops them all cleanly
    """

    def __init__(self):
        """Initialize all application components."""
        logger.info("Initializing Network Threat Analyzer...")

        # -----------------------------------------------
        # STEP 1: Database (everything saves here)
        # -----------------------------------------------
        self.db = DatabaseManager()
        logger.info("✓ Database initialized")

        # -----------------------------------------------
        # STEP 2: Alert Manager (central alert hub)
        # -----------------------------------------------
        self.alert_manager = AlertManager()
        logger.info("✓ Alert manager initialized")

        # -----------------------------------------------
        # STEP 3: Protocol Analyzer (enriches packets)
        # -----------------------------------------------
        self.protocol_analyzer = ProtocolAnalyzer(self.db)
        logger.info("✓ Protocol analyzer initialized")

        # -----------------------------------------------
        # STEP 4: Threat Detector (rule-based detection)
        # -----------------------------------------------
        self.threat_detector = ThreatDetector(self.db)
        logger.info("✓ Threat detector initialized")

        # -----------------------------------------------
        # STEP 5: AI Anomaly Detector (ML-based detection)
        # -----------------------------------------------
        self.anomaly_detector = AnomalyDetector(self.db)
        logger.info("✓ AI anomaly detector initialized")

        # -----------------------------------------------
        # STEP 6: Auth Log Analyzer (SSH brute force)
        # -----------------------------------------------
        self.auth_log_analyzer = AuthLogAnalyzer(
            db=self.db,
            threat_detector=self.threat_detector
        )
        logger.info("✓ Auth log analyzer initialized")

        # -----------------------------------------------
        # STEP 7: IP Reputation Checker
        # -----------------------------------------------
        self.ip_reputation = IPReputationChecker(self.db)
        logger.info("✓ IP reputation checker initialized")

        # -----------------------------------------------
        # STEP 8: Packet Capture (live network sniffing)
        # -----------------------------------------------
        self.packet_capture = PacketCapture()
        logger.info("✓ Packet capture initialized")

        # -----------------------------------------------
        # STEP 9: System Monitor (CPU/RAM/network stats)
        # -----------------------------------------------
        self.system_monitor = SystemMonitor(self.db, interval=30)
        logger.info("✓ System monitor initialized")

        # -----------------------------------------------
        # STEP 10: Report Generator
        # -----------------------------------------------
        self.report_generator = ReportGenerator(self.db)
        logger.info("✓ Report generator initialized")

        # -----------------------------------------------
        # STEP 11: Flask Dashboard
        # -----------------------------------------------
        self.flask_app, self.socketio = create_app(
            db=self.db,
            alert_manager=self.alert_manager,
            packet_capture=self.packet_capture,
            system_monitor=self.system_monitor,
            report_generator=self.report_generator,
            anomaly_detector=self.anomaly_detector
        )
        logger.info("✓ Flask dashboard initialized")

        # -----------------------------------------------
        # STEP 12: Wire everything together with callbacks
        # -----------------------------------------------
        self._wire_callbacks()
        logger.info("✓ Callbacks wired")

        logger.info("All components initialized successfully!")

    def _wire_callbacks(self):
        """
        Connect all the components together using callbacks.

        BEGINNER NOTE:
            A callback is a function you give to another module
            to call when something happens.

            Example:
            - PacketCapture captures a packet
            - It calls ProtocolAnalyzer.analyze (registered callback)
            - ProtocolAnalyzer enriches the packet
            - It calls ThreatDetector.analyze_packet (also registered)
            - ThreatDetector detects a threat
            - It calls AlertManager.receive_alert
            - AlertManager calls all its consumers (dashboard, etc.)

            This "chain of callbacks" is how data flows through
            the entire system.
        """

        # -----------------------------------------------
        # PacketCapture → ProtocolAnalyzer → ThreatDetector
        # -----------------------------------------------
        def on_packet(packet_info: dict):
            """Called for every captured packet."""
            # Enrich with protocol details
            enriched = self.protocol_analyzer.analyze(packet_info)

            # Check for rule-based threats
            self.threat_detector.analyze_packet(enriched)

            # Feed to AI model
            self.anomaly_detector.process_packet(enriched)

            # Optional: Check IP reputation for external IPs
            src_ip = enriched.get("src_ip", "")
            if src_ip and not src_ip.startswith(("192.", "10.", "172.", "127.")):
                # Run in background to avoid slowing down capture
                threading.Thread(
                    target=self.ip_reputation.check_ip,
                    args=(src_ip,),
                    daemon=True
                ).start()

        self.packet_capture.register_callback(on_packet)

        # -----------------------------------------------
        # ThreatDetector → AlertManager
        # -----------------------------------------------
        self.threat_detector.register_alert_callback(
            self.alert_manager.receive_alert
        )

        # -----------------------------------------------
        # AnomalyDetector → AlertManager
        # -----------------------------------------------
        self.anomaly_detector.register_alert_callback(
            self.alert_manager.receive_alert
        )

        # -----------------------------------------------
        # AlertManager → Flask Dashboard (WebSocket push)
        # -----------------------------------------------
        if hasattr(self.flask_app, 'push_alert_to_dashboard'):
            self.alert_manager.register_consumer(
                self.flask_app.push_alert_to_dashboard
            )

    def start(self):
        """
        Start all background threads and services.

        After calling this, all monitoring is running.
        The method then blocks on the Flask dashboard
        until the user presses Ctrl+C.
        """
        logger.info("=" * 60)
        logger.info("STARTING ALL SERVICES")
        logger.info("=" * 60)

        # -----------------------------------------------
        # Start packet capture (requires sudo/root)
        # -----------------------------------------------
        if os.geteuid() == 0:  # Check if running as root
            self.packet_capture.start()
            logger.info("✓ Packet capture STARTED (running as root)")
        else:
            logger.warning("⚠ Not running as root! Packet capture disabled.")
            logger.warning("  Restart with: sudo python3 main.py")
            logger.warning("  Dashboard and auth monitoring will still work.")

        # -----------------------------------------------
        # Start AI anomaly detection loop
        # -----------------------------------------------
        self.anomaly_detector.start()
        logger.info("✓ AI anomaly detection STARTED")

        # -----------------------------------------------
        # Start auth log monitoring
        # -----------------------------------------------
        self.auth_log_analyzer.start()
        logger.info("✓ Auth log monitoring STARTED")

        # -----------------------------------------------
        # Start system performance monitoring
        # -----------------------------------------------
        self.system_monitor.start()
        logger.info("✓ System monitoring STARTED")

        # -----------------------------------------------
        # Display access info
        # -----------------------------------------------
        host = config.get("DASHBOARD", "host", fallback="127.0.0.1")
        port = config.get_int("DASHBOARD", "port", fallback=5000)

        logger.info("=" * 60)
        logger.info(f"Dashboard: http://{host}:{port}")
        logger.info("Press Ctrl+C to stop all services")
        logger.info("=" * 60)

        # -----------------------------------------------
        # Auto-report scheduler (if configured)
        # -----------------------------------------------
        report_interval = config.get_int(
            "REPORTS", "auto_report_interval", fallback=0
        )
        if report_interval > 0:
            self._start_auto_reporter(report_interval)

        # -----------------------------------------------
        # Start Flask dashboard (THIS BLOCKS until Ctrl+C)
        # -----------------------------------------------
        run_dashboard(self.flask_app, self.socketio)

    def _start_auto_reporter(self, interval_minutes: int):
        """
        Start a background thread that generates reports automatically.

        Args:
            interval_minutes (int): How often to generate reports
        """
        def auto_report_loop():
            while True:
                time.sleep(interval_minutes * 60)
                try:
                    csv_path = self.report_generator.generate_csv_report()
                    logger.info(f"Auto-report generated: {csv_path}")
                except Exception as e:
                    logger.error(f"Auto-report error: {e}")

        t = threading.Thread(
            target=auto_report_loop,
            daemon=True,
            name="AutoReporter"
        )
        t.start()
        logger.info(f"✓ Auto-reporting every {interval_minutes} minutes")

    def stop(self):
        """
        Gracefully shut down all services.

        Called when the user presses Ctrl+C.
        Gives each component a chance to clean up.
        """
        logger.info("\nShutting down all services...")

        try:
            self.packet_capture.stop()
            logger.info("✓ Packet capture stopped")
        except Exception as e:
            logger.error(f"Error stopping capture: {e}")

        try:
            self.auth_log_analyzer.stop()
            logger.info("✓ Auth log monitoring stopped")
        except Exception as e:
            logger.error(f"Error stopping auth log: {e}")

        try:
            self.anomaly_detector.stop()
            logger.info("✓ AI engine stopped")
        except Exception as e:
            logger.error(f"Error stopping AI: {e}")

        try:
            self.system_monitor.stop()
            logger.info("✓ System monitor stopped")
        except Exception as e:
            logger.error(f"Error stopping monitor: {e}")

        try:
            self.db.cleanup_old_records()
            logger.info("✓ Database cleanup complete")
        except Exception as e:
            logger.error(f"Error during DB cleanup: {e}")

        logger.info("Shutdown complete. Goodbye!")


# ============================================================
# MAIN ENTRY POINT
# ============================================================

def main():
    """Application entry point."""
    print_banner()

    # Display version and startup time
    app_name = config.get("GENERAL", "app_name", fallback="Network Threat Analyzer")
    logger.info(f"Starting {app_name}")
    logger.info(f"Startup time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Create the main application
    analyzer = NetworkThreatAnalyzer()

    # -----------------------------------------------
    # Setup graceful shutdown on Ctrl+C (SIGINT)
    # -----------------------------------------------
    def signal_handler(sig, frame):
        """Handle Ctrl+C gracefully."""
        print("\n")  # Newline after ^C in terminal
        logger.info("Ctrl+C received — shutting down gracefully...")
        analyzer.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # -----------------------------------------------
    # START EVERYTHING
    # -----------------------------------------------
    try:
        analyzer.start()
    except KeyboardInterrupt:
        analyzer.stop()
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        analyzer.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
