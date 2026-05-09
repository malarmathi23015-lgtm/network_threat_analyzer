"""
============================================================
dashboard/app.py
AI-Powered Linux Network Threat Analyzer

PURPOSE:
    Flask web application providing the real-time dashboard.
    Shows live alerts, packet statistics, system health,
    and provides report download functionality.

BEGINNER NOTE:
    Flask is a lightweight Python web framework.
    It lets you create web pages with Python functions.

    @app.route("/") means: when someone visits http://localhost:5000/
    run this Python function and return the result as a web page.

    Flask-SocketIO adds WebSocket support:
    - Normal HTTP: browser asks → server responds → done
    - WebSocket: persistent connection, server PUSHES data to browser
    We use WebSockets to show new alerts instantly without refreshing.
============================================================
"""

import threading
from datetime import datetime
from typing import Optional

from flask import Flask, render_template, jsonify, send_file, abort
from flask_socketio import SocketIO, emit

from core.logger import setup_logger
from core.config_manager import config

logger = setup_logger("Dashboard")


def create_app(
    db=None,
    alert_manager=None,
    packet_capture=None,
    system_monitor=None,
    report_generator=None,
    anomaly_detector=None
):
    """
    Flask application factory function.

    BEGINNER NOTE:
        We use a factory pattern (create_app) instead of a global app.
        This makes the app easier to test and configure.
        All dependencies (db, alert_manager, etc.) are passed in.

    Args:
        db: DatabaseManager instance
        alert_manager: AlertManager instance
        packet_capture: PacketCapture instance
        system_monitor: SystemMonitor instance
        report_generator: ReportGenerator instance
        anomaly_detector: AnomalyDetector instance

    Returns:
        tuple: (Flask app, SocketIO instance)
    """
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static"
    )

    # Flask configuration
    app.config["SECRET_KEY"] = config.get_env(
        "SECRET_KEY",
        fallback=config.get("DASHBOARD", "secret_key", fallback="dev-secret-key")
    )
    app.config["JSON_SORT_KEYS"] = False

    # Initialize SocketIO for real-time communication
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        async_mode="threading"
    )

    # ============================================================
    # HTML PAGE ROUTES
    # ============================================================

    @app.route("/")
    def index():
        """Main dashboard page."""
        return render_template(
            "index.html",
            app_name=config.get("GENERAL", "app_name", fallback="Threat Analyzer"),
            version=config.get("GENERAL", "version", fallback="1.0.0")
        )

    @app.route("/alerts")
    def alerts_page():
        """Alerts detail page."""
        return render_template("alerts.html")

    @app.route("/reports")
    def reports_page():
        """Reports page."""
        return render_template("reports.html")

    @app.route("/settings")
    def settings_page():
        """Settings overview page."""
        return render_template("settings.html")

    # ============================================================
    # API ROUTES (Return JSON data for dashboard JavaScript)
    # ============================================================

    @app.route("/api/stats")
    def api_stats():
        """
        Return overall system statistics as JSON.

        Called by the dashboard every few seconds to update counters.
        """
        try:
            data = {}

            # Alert statistics
            if alert_manager:
                data["alerts"] = alert_manager.get_stats()

            # Alert breakdown from database
            if db:
                data["db_stats"] = db.get_alert_stats()
                data["packet_stats"] = db.get_packet_stats()
                data["top_ips"] = db.get_top_threat_ips(limit=10)

            # Packet capture statistics
            if packet_capture:
                data["capture"] = packet_capture.get_stats()

            # System performance
            if system_monitor:
                data["system"] = system_monitor.get_current_stats()

            # AI model status
            if anomaly_detector:
                data["ai"] = anomaly_detector.get_status()

            return jsonify({"status": "ok", "data": data})

        except Exception as e:
            logger.error(f"API stats error: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/alerts")
    def api_alerts():
        """Return recent alerts as JSON."""
        try:
            if not db:
                return jsonify({"alerts": []})

            alerts = db.get_recent_alerts(limit=100)
            return jsonify({"alerts": alerts, "count": len(alerts)})

        except Exception as e:
            logger.error(f"API alerts error: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/alerts/<severity>")
    def api_alerts_by_severity(severity):
        """Return alerts filtered by severity."""
        try:
            valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if severity.upper() not in valid_severities:
                abort(400)

            if not db:
                return jsonify({"alerts": []})

            alerts = db.get_recent_alerts(limit=50, severity=severity.upper())
            return jsonify({"alerts": alerts, "severity": severity.upper()})

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/system")
    def api_system():
        """Return system health metrics as JSON."""
        try:
            if not system_monitor:
                return jsonify({"error": "System monitor not available"})

            stats = system_monitor.get_current_stats()
            interfaces = system_monitor.get_network_interfaces()

            return jsonify({
                "stats": stats,
                "interfaces": interfaces,
                "is_healthy": system_monitor.is_healthy()
            })

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/auth-events")
    def api_auth_events():
        """Return recent auth log events."""
        try:
            if not db:
                return jsonify({"events": []})

            events = db.get_recent_auth_events(limit=50)
            return jsonify({"events": events, "count": len(events)})

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/reports/list")
    def api_reports_list():
        """List available reports for download."""
        try:
            if not report_generator:
                return jsonify({"csv": [], "pdf": []})

            reports = report_generator.list_reports()
            return jsonify(reports)

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/reports/generate/csv")
    def api_generate_csv():
        """Generate and download a CSV report."""
        try:
            if not report_generator:
                abort(503)

            filepath = report_generator.generate_csv_report()
            return send_file(
                filepath,
                as_attachment=True,
                download_name=filepath.split("/")[-1],
                mimetype="text/csv"
            )

        except Exception as e:
            logger.error(f"CSV generation error: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/reports/generate/pdf")
    def api_generate_pdf():
        """Generate and download a PDF report."""
        try:
            if not report_generator:
                abort(503)

            filepath = report_generator.generate_pdf_report()
            return send_file(
                filepath,
                as_attachment=True,
                download_name=filepath.split("/")[-1],
                mimetype="application/pdf"
            )

        except Exception as e:
            logger.error(f"PDF generation error: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/capture/status")
    def api_capture_status():
        """Return packet capture status."""
        if not packet_capture:
            return jsonify({"running": False})

        return jsonify({
            "running": packet_capture.is_running(),
            "stats": packet_capture.get_stats()
        })

    @app.route("/api/ai/status")
    def api_ai_status():
        """Return AI model training status."""
        if not anomaly_detector:
            return jsonify({"enabled": False})

        return jsonify(anomaly_detector.get_status())

    # ============================================================
    # WEBSOCKET EVENTS
    # ============================================================

    @socketio.on("connect")
    def on_connect():
        """Called when a browser connects via WebSocket."""
        logger.info(f"Dashboard client connected")
        emit("connected", {
            "message": "Connected to threat analyzer",
            "timestamp": datetime.now().isoformat()
        })

    @socketio.on("disconnect")
    def on_disconnect():
        """Called when a browser disconnects."""
        logger.info("Dashboard client disconnected")

    @socketio.on("request_stats")
    def on_request_stats():
        """Client requested an immediate stats update."""
        try:
            if db:
                stats = db.get_alert_stats()
                emit("stats_update", stats)
        except Exception as e:
            emit("error", {"message": str(e)})

    # ============================================================
    # HELPER: Push alerts to connected browsers via WebSocket
    # ============================================================

    def push_alert_to_dashboard(alert: dict):
        """
        Push a new alert to all connected browser clients instantly.

        This function is called by the AlertManager whenever
        a new threat is detected. No browser refresh needed!

        Args:
            alert (dict): Alert information to push
        """
        try:
            # Remove non-serializable items (like raw packet objects)
            safe_alert = {
                k: v for k, v in alert.items()
                if isinstance(v, (str, int, float, bool, list, dict, type(None)))
            }
            socketio.emit("new_alert", safe_alert)
        except Exception as e:
            logger.debug(f"WebSocket push error: {e}")

    # Attach the push function so main.py can register it as a callback
    app.push_alert_to_dashboard = push_alert_to_dashboard

    # ============================================================
    # ERROR HANDLERS
    # ============================================================

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Internal server error"}), 500

    return app, socketio


def run_dashboard(app, socketio):
    """
    Start the Flask dashboard server.

    This runs in a background thread so it doesn't block
    the packet capture or detection loops.

    Args:
        app: Flask app instance
        socketio: SocketIO instance
    """
    host = config.get("DASHBOARD", "host", fallback="127.0.0.1")
    port = config.get_int("DASHBOARD", "port", fallback=5000)
    debug = config.get_bool("DASHBOARD", "debug", fallback=False)

    logger.info(f"Starting dashboard at http://{host}:{port}")

    socketio.run(
        app,
        host=host,
        port=port,
        debug=debug,
        use_reloader=False,    # Must be False when running in a thread
        log_output=False       # Suppress Flask's default access logs
    )
