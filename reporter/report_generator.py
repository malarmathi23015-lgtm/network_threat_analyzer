"""
============================================================
reporter/report_generator.py
AI-Powered Linux Network Threat Analyzer

PURPOSE:
    Generates professional CSV and PDF reports from the
    threat database for documentation, auditing, or sharing.

BEGINNER NOTE:
    Reports are important in cybersecurity for:
    - Documenting incidents for management/clients
    - Compliance and auditing requirements
    - Tracking trends over time
    - Sharing findings with team members

    We generate two formats:
    - CSV: Simple spreadsheet format, easy to import into Excel
    - PDF: Formatted report with charts, suitable for sharing
============================================================
"""

import os
import csv
from datetime import datetime
from typing import List, Dict

from core.logger import setup_logger
from core.config_manager import config
from database.db_manager import DatabaseManager

logger = setup_logger("ReportGenerator")

# Try importing report libraries
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph,
        Spacer, HRFlowable
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("reportlab not installed. PDF generation unavailable.")


class ReportGenerator:
    """
    Generates CSV and PDF reports from threat intelligence data.

    Usage:
        reporter = ReportGenerator(db)
        csv_path = reporter.generate_csv_report()
        pdf_path = reporter.generate_pdf_report()
    """

    def __init__(self, db: DatabaseManager):
        """
        Initialize the report generator.

        Args:
            db (DatabaseManager): Database to pull report data from
        """
        self.db = db
        self.csv_dir = config.get("REPORTS", "csv_dir", fallback="reports/csv")
        self.pdf_dir = config.get("REPORTS", "pdf_dir", fallback="reports/pdf")
        self.app_name = config.get("GENERAL", "app_name", fallback="Network Threat Analyzer")

        # Create report directories
        os.makedirs(self.csv_dir, exist_ok=True)
        os.makedirs(self.pdf_dir, exist_ok=True)

        logger.info("ReportGenerator initialized")

    def generate_csv_report(self, filename: str = None) -> str:
        """
        Generate a CSV report of all alerts.

        CSV is a simple format compatible with Excel, Google Sheets,
        and any data analysis tool.

        Args:
            filename (str): Custom filename (auto-generated if None)

        Returns:
            str: Path to the generated CSV file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threat_report_{timestamp}.csv"

        filepath = os.path.join(self.csv_dir, filename)

        # Fetch all alerts from database
        alerts = self.db.get_all_alerts_for_report()

        if not alerts:
            logger.warning("No alerts found for CSV report")
            # Create empty report with headers
            alerts = []

        # CSV column headers
        fieldnames = [
            "id", "timestamp", "alert_type", "source_ip",
            "dest_ip", "source_port", "dest_port",
            "protocol", "severity", "description"
        ]

        try:
            with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(
                    csvfile,
                    fieldnames=fieldnames,
                    extrasaction="ignore"  # Ignore fields not in fieldnames
                )

                # Write header row
                writer.writeheader()

                # Write data rows
                for alert in alerts:
                    writer.writerow(alert)

            logger.info(f"CSV report saved: {filepath} ({len(alerts)} alerts)")
            return filepath

        except Exception as e:
            logger.error(f"CSV generation error: {e}")
            raise

    def generate_pdf_report(self, filename: str = None) -> str:
        """
        Generate a professional PDF threat report.

        Includes:
        - Executive summary with alert counts
        - Severity breakdown table
        - Top attacking IPs table
        - Full alerts listing

        Args:
            filename (str): Custom filename (auto-generated if None)

        Returns:
            str: Path to the generated PDF file
        """
        if not REPORTLAB_AVAILABLE:
            logger.error("reportlab not installed! Cannot generate PDF.")
            logger.error("Install with: pip install reportlab")
            raise ImportError("reportlab is required for PDF generation")

        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threat_report_{timestamp}.pdf"

        filepath = os.path.join(self.pdf_dir, filename)

        # Gather data for the report
        alerts = self.db.get_all_alerts_for_report()
        alert_stats = self.db.get_alert_stats()
        top_ips = self.db.get_top_threat_ips(limit=10)

        logger.info(f"Generating PDF report with {len(alerts)} alerts...")

        try:
            # Create PDF document
            doc = SimpleDocTemplate(
                filepath,
                pagesize=A4,
                rightMargin=0.75 * inch,
                leftMargin=0.75 * inch,
                topMargin=1 * inch,
                bottomMargin=1 * inch
            )

            # Get default styles and customize
            styles = getSampleStyleSheet()

            # Custom styles
            title_style = ParagraphStyle(
                "ReportTitle",
                parent=styles["Title"],
                fontSize=24,
                spaceAfter=12,
                textColor=colors.HexColor("#1a1a2e")
            )

            heading_style = ParagraphStyle(
                "SectionHeading",
                parent=styles["Heading2"],
                fontSize=14,
                textColor=colors.HexColor("#16213e"),
                spaceBefore=20,
                spaceAfter=10,
                borderPad=5,
            )

            body_style = styles["Normal"]

            # Build the PDF content as a list of flowables
            # (Flowables are elements that ReportLab arranges on pages)
            content = []

            # -----------------------------------------------
            # PAGE 1: HEADER
            # -----------------------------------------------
            content.append(Paragraph(self.app_name, title_style))
            content.append(Paragraph("Threat Intelligence Report", styles["Heading2"]))
            content.append(Paragraph(
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                body_style
            ))
            content.append(HRFlowable(width="100%", thickness=2,
                                       color=colors.HexColor("#e94560")))
            content.append(Spacer(1, 0.3 * inch))

            # -----------------------------------------------
            # EXECUTIVE SUMMARY
            # -----------------------------------------------
            content.append(Paragraph("Executive Summary", heading_style))
            content.append(Paragraph(
                f"This report summarizes network threat analysis results. "
                f"A total of <b>{alert_stats.get('total', 0)}</b> security alerts were detected, "
                f"with <b>{alert_stats.get('last_24h', 0)}</b> in the last 24 hours.",
                body_style
            ))
            content.append(Spacer(1, 0.2 * inch))

            # -----------------------------------------------
            # ALERT SEVERITY BREAKDOWN TABLE
            # -----------------------------------------------
            content.append(Paragraph("Alert Severity Breakdown", heading_style))

            severity_data = [
                ["Severity", "Count", "Status"],
            ]

            severity_colors_map = {
                "CRITICAL": colors.HexColor("#c0392b"),
                "HIGH":     colors.HexColor("#e74c3c"),
                "MEDIUM":   colors.HexColor("#f39c12"),
                "LOW":      colors.HexColor("#3498db"),
            }

            by_severity = alert_stats.get("by_severity", {})
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = by_severity.get(sev, 0)
                status = "⚠ CRITICAL" if sev == "CRITICAL" and count > 0 else (
                    "⚠ Alert" if count > 0 else "✓ Clear"
                )
                severity_data.append([sev, str(count), status])

            severity_table = Table(
                severity_data,
                colWidths=[2 * inch, 1.5 * inch, 2.5 * inch]
            )
            severity_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 11),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.HexColor("#f8f9fa"), colors.white]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("FONTSIZE", (0, 1), (-1, -1), 10),
            ]))
            content.append(severity_table)
            content.append(Spacer(1, 0.3 * inch))

            # -----------------------------------------------
            # TOP ATTACKING IPs TABLE
            # -----------------------------------------------
            if top_ips:
                content.append(Paragraph("Top Threat Source IPs", heading_style))

                ip_data = [["Rank", "IP Address", "Alert Count"]]
                for rank, item in enumerate(top_ips, 1):
                    ip_data.append([
                        str(rank),
                        item.get("ip", "Unknown"),
                        str(item.get("count", 0))
                    ])

                ip_table = Table(
                    ip_data,
                    colWidths=[0.8 * inch, 3 * inch, 2 * inch]
                )
                ip_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                     [colors.HexColor("#fff3cd"), colors.white]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                ]))
                content.append(ip_table)
                content.append(Spacer(1, 0.3 * inch))

            # -----------------------------------------------
            # RECENT ALERTS TABLE (last 50)
            # -----------------------------------------------
            content.append(Paragraph(
                f"Recent Alerts (showing last {min(50, len(alerts))})",
                heading_style
            ))

            if alerts:
                alert_data = [
                    ["Time", "Type", "Severity", "Source IP", "Description"]
                ]

                for alert in alerts[:50]:
                    # Truncate description to fit in table cell
                    desc = str(alert.get("description", ""))[:80]
                    if len(str(alert.get("description", ""))) > 80:
                        desc += "..."

                    alert_data.append([
                        str(alert.get("timestamp", ""))[:16],
                        str(alert.get("alert_type", ""))[:20],
                        str(alert.get("severity", "")),
                        str(alert.get("source_ip", "N/A")),
                        desc
                    ])

                alert_table = Table(
                    alert_data,
                    colWidths=[1.2*inch, 1.2*inch, 0.8*inch, 1.1*inch, 3.2*inch]
                )
                alert_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 9),
                    ("FONTSIZE", (0, 1), (-1, -1), 7),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                     [colors.HexColor("#f8f9fa"), colors.white]),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dee2e6")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("WORDWRAP", (0, 0), (-1, -1), True),
                ]))
                content.append(alert_table)
            else:
                content.append(Paragraph(
                    "No alerts recorded in the database yet.",
                    body_style
                ))

            # -----------------------------------------------
            # FOOTER NOTE
            # -----------------------------------------------
            content.append(Spacer(1, 0.5 * inch))
            content.append(HRFlowable(width="100%", thickness=1,
                                       color=colors.HexColor("#dee2e6")))
            content.append(Paragraph(
                f"Report generated by {self.app_name} | "
                f"Confidential - For internal use only",
                ParagraphStyle(
                    "Footer", parent=styles["Normal"],
                    fontSize=8, textColor=colors.grey,
                    alignment=TA_CENTER
                )
            ))

            # Build the PDF
            doc.build(content)
            logger.info(f"PDF report saved: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"PDF generation error: {e}")
            raise

    def list_reports(self) -> Dict[str, List[str]]:
        """
        List all generated reports.

        Returns:
            Dict with 'csv' and 'pdf' lists of filenames
        """
        csv_files = sorted(os.listdir(self.csv_dir), reverse=True)
        pdf_files = sorted(os.listdir(self.pdf_dir), reverse=True)

        return {
            "csv": [f for f in csv_files if f.endswith(".csv")],
            "pdf": [f for f in pdf_files if f.endswith(".pdf")]
        }
