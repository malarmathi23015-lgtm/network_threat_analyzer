"""
============================================================
ai_engine/anomaly_detector.py
AI-Powered Linux Network Threat Analyzer

PURPOSE:
    Uses Machine Learning (scikit-learn IsolationForest) to detect
    unusual patterns in network traffic that rule-based detectors
    might miss.

BEGINNER NOTE:
    What is Anomaly Detection?

    Imagine you track 100 days of your network traffic:
    - Usually you get 1000 packets/minute
    - Usually 80% is HTTPS, 10% DNS, 5% ICMP
    - Usually from 5-10 different source IPs

    The ML model LEARNS this "normal" pattern.

    Then one day: 10,000 packets/minute, all from 1 IP, all ICMP.
    The model says "ANOMALY! This is very different from normal!"

    IsolationForest Algorithm:
    - Builds random decision trees
    - Normal data points need MANY splits to isolate
    - Anomalies need FEW splits to isolate
    - Points that isolate easily → anomaly score high → flagged!

    We convert each time window of packets into a feature vector
    (a list of numbers) and let the model judge it.
============================================================
"""

import os
import threading
import time
import pickle
import numpy as np
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from core.logger import setup_logger
from core.config_manager import config
from database.db_manager import DatabaseManager

logger = setup_logger("AnomalyDetector")

# Try importing scikit-learn
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.error("scikit-learn not installed! Run: pip install scikit-learn")


class NetworkFeatureExtractor:
    """
    Converts raw packet statistics into ML feature vectors.

    BEGINNER NOTE:
        ML models don't understand packets — they understand numbers.
        We summarize each 30-second window of traffic as a vector of numbers:

        [total_packets, tcp_ratio, udp_ratio, icmp_ratio,
         unique_src_ips, unique_dst_ports, avg_packet_size,
         syn_ratio, rst_ratio, dns_query_count, ...]

        This vector goes into the ML model for scoring.
    """

    def __init__(self, window_seconds: int = 30):
        """
        Initialize the feature extractor.

        Args:
            window_seconds (int): Time window for computing features
        """
        self.window_seconds = window_seconds

        # Sliding window of packets: deque automatically drops old entries
        self._packet_buffer: deque = deque()

        # Thread lock for safe buffer access
        self._lock = threading.Lock()

    def add_packet(self, packet_info: Dict):
        """
        Add a new packet to the feature window.

        Args:
            packet_info (dict): Packet information dictionary
        """
        with self._lock:
            now = time.time()

            # Add packet with current timestamp
            self._packet_buffer.append({
                "time": now,
                "protocol": packet_info.get("protocol", "OTHER"),
                "src_ip": packet_info.get("src_ip", ""),
                "dst_port": packet_info.get("dst_port", 0),
                "size": packet_info.get("size", 0),
                "flags": packet_info.get("flags", ""),
            })

            # Remove packets older than our window
            cutoff = now - self.window_seconds
            while self._packet_buffer and self._packet_buffer[0]["time"] < cutoff:
                self._packet_buffer.popleft()

    def extract_features(self) -> Optional[List[float]]:
        """
        Extract a feature vector from the current packet window.

        Returns:
            List of floats representing network behavior,
            or None if not enough data
        """
        with self._lock:
            packets = list(self._packet_buffer)

        if len(packets) < 10:
            return None  # Not enough data to make meaningful features

        total = len(packets)

        # -----------------------------------------------
        # Protocol ratios
        # -----------------------------------------------
        protocols = [p["protocol"] for p in packets]
        tcp_count = protocols.count("TCP")
        udp_count = protocols.count("UDP")
        icmp_count = protocols.count("ICMP")
        dns_count = protocols.count("DNS")
        http_count = protocols.count("HTTP")

        # -----------------------------------------------
        # Source IP diversity
        # Many unique source IPs = normal web traffic
        # One source IP = potential DoS/scan
        # -----------------------------------------------
        src_ips = set(p["src_ip"] for p in packets if p["src_ip"])
        unique_src_ips = len(src_ips)

        # -----------------------------------------------
        # Destination port diversity
        # Many different ports probed = port scan
        # -----------------------------------------------
        dst_ports = set(p["dst_port"] for p in packets if p["dst_port"])
        unique_dst_ports = len(dst_ports)

        # -----------------------------------------------
        # Packet size statistics
        # Very small packets = SYN scan
        # Very large packets = data exfiltration or DDoS amplification
        # -----------------------------------------------
        sizes = [p["size"] for p in packets]
        avg_size = np.mean(sizes) if sizes else 0
        max_size = max(sizes) if sizes else 0
        std_size = np.std(sizes) if sizes else 0

        # -----------------------------------------------
        # TCP flag ratios
        # High SYN ratio = SYN flood or port scan
        # High RST ratio = scan with resets
        # -----------------------------------------------
        flags = [p["flags"] for p in packets if p["flags"]]
        syn_count = sum(1 for f in flags if "S" in f and "A" not in f)
        rst_count = sum(1 for f in flags if "R" in f)
        fin_count = sum(1 for f in flags if "F" in f)

        # -----------------------------------------------
        # Build the feature vector
        # ALL values must be numbers (floats)
        # -----------------------------------------------
        features = [
            total,                              # 1. Total packets in window
            tcp_count / total,                  # 2. TCP ratio
            udp_count / total,                  # 3. UDP ratio
            icmp_count / total,                 # 4. ICMP ratio
            dns_count / total,                  # 5. DNS ratio
            http_count / total,                 # 6. HTTP ratio
            float(unique_src_ips),              # 7. Unique source IPs
            float(unique_dst_ports),            # 8. Unique destination ports
            avg_size,                           # 9. Average packet size
            max_size,                           # 10. Max packet size
            std_size,                           # 11. Packet size variation
            syn_count / max(total, 1),          # 12. SYN packet ratio
            rst_count / max(total, 1),          # 13. RST packet ratio
            fin_count / max(total, 1),          # 14. FIN packet ratio
            total / self.window_seconds,        # 15. Packets per second
        ]

        return features

    def get_feature_names(self) -> List[str]:
        """Return human-readable names for each feature (for debugging)."""
        return [
            "total_packets",
            "tcp_ratio",
            "udp_ratio",
            "icmp_ratio",
            "dns_ratio",
            "http_ratio",
            "unique_src_ips",
            "unique_dst_ports",
            "avg_packet_size",
            "max_packet_size",
            "std_packet_size",
            "syn_ratio",
            "rst_ratio",
            "fin_ratio",
            "packets_per_second"
        ]


class AnomalyDetector:
    """
    Uses IsolationForest ML model to detect network anomalies.

    How it works:
    1. Collect training data: 100+ feature vectors from normal traffic
    2. Train IsolationForest: model learns what "normal" looks like
    3. Score new windows: model outputs -1 (anomaly) or 1 (normal)
    4. Alert on anomalies

    The model is retrained periodically to adapt to changing traffic patterns.
    """

    MODEL_PATH = "ai_engine/models/isolation_forest.pkl"

    def __init__(self, db: DatabaseManager):
        """
        Initialize the anomaly detector.

        Args:
            db (DatabaseManager): Database for logging anomalies
        """
        self.db = db
        self.enabled = config.get_bool("AI", "enabled", fallback=True)
        self.min_training_samples = config.get_int(
            "AI", "min_training_samples", fallback=100
        )
        self.contamination = config.get_float(
            "AI", "contamination", fallback=0.05
        )
        self.retrain_interval = config.get_int(
            "AI", "retrain_interval", fallback=30
        ) * 60  # Convert minutes to seconds

        # Feature extractor
        self.feature_extractor = NetworkFeatureExtractor(window_seconds=30)

        # ML pipeline: StandardScaler normalizes features, then IsolationForest
        # StandardScaler: transforms all features to have mean=0, std=1
        # This prevents large-valued features from dominating the model
        self.model = None
        self._is_trained = False

        # Training data accumulator
        self._training_data: List[List[float]] = []

        # Alert callbacks
        self._alert_callbacks: List = []

        # Thread control
        self._running = False
        self._last_retrain = 0
        self._detection_thread = None
        self._lock = threading.Lock()

        # Create model directory
        os.makedirs(os.path.dirname(self.MODEL_PATH), exist_ok=True)

        if not SKLEARN_AVAILABLE:
            logger.error("scikit-learn not available! AI detection disabled.")
            self.enabled = False

        if self.enabled:
            # Try to load a previously saved model
            self._load_model()
            logger.info(f"AnomalyDetector initialized (contamination={self.contamination})")
        else:
            logger.info("AI anomaly detection disabled")

    def register_alert_callback(self, callback):
        """Register a function to call when an anomaly is detected."""
        self._alert_callbacks.append(callback)

    def process_packet(self, packet_info: Dict):
        """
        Feed a packet to the feature extractor.

        Called for every captured packet.

        Args:
            packet_info (dict): Packet information dictionary
        """
        if not self.enabled:
            return

        self.feature_extractor.add_packet(packet_info)

    def start(self):
        """Start the background anomaly detection loop."""
        if not self.enabled:
            return

        self._running = True
        self._detection_thread = threading.Thread(
            target=self._detection_loop,
            daemon=True,
            name="AnomalyDetector"
        )
        self._detection_thread.start()
        logger.info("Anomaly detection loop started")

    def stop(self):
        """Stop the anomaly detection loop."""
        self._running = False
        if self._detection_thread:
            self._detection_thread.join(timeout=5)
        logger.info("Anomaly detection stopped")

    def _detection_loop(self):
        """
        Background loop: extract features, train model, detect anomalies.

        Runs every 30 seconds:
        1. Extract features from current packet window
        2. If not trained yet: accumulate training data
        3. If trained: score features and alert on anomalies
        4. Periodically retrain model with new data
        """
        while self._running:
            try:
                time.sleep(30)  # Analyze every 30 seconds

                # Extract features from recent traffic
                features = self.feature_extractor.extract_features()
                if features is None:
                    logger.debug("Not enough packets for feature extraction")
                    continue

                # Phase 1: Accumulate training data
                if len(self._training_data) < self.min_training_samples:
                    self._training_data.append(features)
                    remaining = self.min_training_samples - len(self._training_data)
                    logger.info(
                        f"AI training: {len(self._training_data)}/{self.min_training_samples} "
                        f"samples collected ({remaining} more needed)"
                    )

                # Phase 2: Train the model when we have enough data
                elif not self._is_trained:
                    self._train_model()

                # Phase 3: Detect anomalies using trained model
                else:
                    self._detect_anomaly(features)

                    # Also add to training data for future retraining
                    self._training_data.append(features)

                    # Retrain periodically
                    if time.time() - self._last_retrain > self.retrain_interval:
                        logger.info("Retraining anomaly detection model...")
                        self._train_model()

            except Exception as e:
                logger.error(f"Anomaly detection loop error: {e}")

    def _train_model(self):
        """
        Train the IsolationForest model on collected traffic data.

        BEGINNER NOTE:
            IsolationForest parameters:
            - n_estimators: How many decision trees to build (more = better but slower)
            - contamination: Expected fraction of anomalies (0.05 = 5% of training data)
            - random_state: Seed for reproducibility (same seed = same results each run)
        """
        if len(self._training_data) < self.min_training_samples:
            return

        logger.info(f"Training IsolationForest on {len(self._training_data)} samples...")

        try:
            X = np.array(self._training_data)

            # Create a pipeline: normalize features first, then train model
            self.model = Pipeline([
                ("scaler", StandardScaler()),       # Step 1: Normalize features
                ("isolation_forest", IsolationForest(
                    n_estimators=100,               # 100 trees
                    contamination=self.contamination,
                    random_state=42,
                    n_jobs=-1                       # Use all CPU cores
                ))
            ])

            self.model.fit(X)
            self._is_trained = True
            self._last_retrain = time.time()

            logger.info("✓ IsolationForest model trained successfully!")
            logger.info(f"  Training samples: {len(X)}")
            logger.info(f"  Features: {len(X[0])}")

            # Save model to disk for next run
            self._save_model()

        except Exception as e:
            logger.error(f"Model training failed: {e}")

    def _detect_anomaly(self, features: List[float]) -> bool:
        """
        Score a feature vector and alert if it's anomalous.

        Args:
            features (list): Feature vector to score

        Returns:
            bool: True if anomaly detected
        """
        if not self._is_trained or self.model is None:
            return False

        try:
            X = np.array([features])

            # Model returns: 1 = normal, -1 = anomaly
            prediction = self.model.predict(X)[0]

            # Get anomaly score: lower (more negative) = more anomalous
            score = self.model.score_samples(X)[0]

            if prediction == -1:
                # Build description using feature names
                feature_names = self.feature_extractor.get_feature_names()
                feature_desc = ", ".join(
                    f"{name}={val:.2f}"
                    for name, val in zip(feature_names, features)
                    if val != 0  # Only show non-zero features
                )

                description = (
                    f"AI detected anomalous network behavior! "
                    f"Anomaly score: {score:.4f}. "
                    f"Traffic stats: {feature_desc[:200]}"
                )

                logger.warning(f"ANOMALY DETECTED: score={score:.4f}")
                logger.debug(f"Features: {dict(zip(feature_names, features))}")

                # Save to database
                self.db.insert_alert(
                    alert_type="AI_ANOMALY",
                    severity="MEDIUM",
                    description=description,
                    raw_data=str(features)
                )

                # Notify callbacks
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "type": "AI_ANOMALY",
                    "severity": "MEDIUM",
                    "source_ip": None,
                    "description": description,
                    "anomaly_score": float(score),
                    "features": dict(zip(feature_names, features))
                }

                for callback in self._alert_callbacks:
                    try:
                        callback(alert)
                    except Exception as e:
                        logger.error(f"Alert callback error: {e}")

                return True

        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")

        return False

    def _save_model(self):
        """Save the trained model to disk for persistence across restarts."""
        try:
            with open(self.MODEL_PATH, "wb") as f:
                pickle.dump({
                    "model": self.model,
                    "training_samples": len(self._training_data),
                    "saved_at": datetime.now().isoformat()
                }, f)
            logger.info(f"Model saved to: {self.MODEL_PATH}")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")

    def _load_model(self):
        """Load a previously saved model from disk."""
        if not os.path.exists(self.MODEL_PATH):
            logger.info("No saved model found, will train from scratch")
            return

        try:
            with open(self.MODEL_PATH, "rb") as f:
                data = pickle.load(f)

            self.model = data["model"]
            self._is_trained = True
            logger.info(
                f"Loaded saved model (trained on {data.get('training_samples', '?')} samples, "
                f"saved at {data.get('saved_at', '?')})"
            )
        except Exception as e:
            logger.warning(f"Could not load saved model: {e}")

    def get_status(self) -> Dict:
        """
        Return current status of the anomaly detector.

        Returns:
            Dict with training status and model info
        """
        return {
            "enabled": self.enabled,
            "is_trained": self._is_trained,
            "training_samples": len(self._training_data),
            "min_required_samples": self.min_training_samples,
            "training_progress": (
                f"{len(self._training_data)}/{self.min_training_samples}"
            ),
            "model_type": "IsolationForest" if SKLEARN_AVAILABLE else "N/A",
            "contamination": self.contamination,
            "last_retrained": datetime.fromtimestamp(
                self._last_retrain
            ).isoformat() if self._last_retrain else "Never"
        }
