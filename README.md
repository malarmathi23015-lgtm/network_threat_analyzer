# 🛡 AI-Powered Linux Network Threat Analyzer

A professional, modular network security monitoring system built in Python. Captures live network traffic, detects threats in real-time, and displays everything in a sleek web dashboard.

---

## 📸 Features

| Feature | Description |
|---|---|
| 📡 Live Packet Capture | Real-time packet sniffing via Scapy |
| 🔍 Protocol Analysis | TCP, UDP, HTTP, DNS, ICMP, ARP |
| 🚨 Port Scan Detection | Sliding window SYN flood detection |
| 🔐 Brute Force Detection | SSH/auth log monitoring |
| 🌐 IP Reputation | AbuseIPDB integration with caching |
| 🤖 AI Anomaly Detection | IsolationForest ML model |
| 📊 Flask Dashboard | Real-time WebSocket alerts |
| 🗄 SQLite Database | Persistent threat storage |
| 📄 Reports | CSV and PDF export |
| 💻 System Monitor | CPU, RAM, network stats |

---

## 📁 Project Structure

```
network_threat_analyzer/
│
├── main.py                    ← Entry point (run this!)
├── requirements.txt           ← Python dependencies
├── .env.example               ← Environment variables template
│
├── config/
│   └── config.ini             ← All settings (edit this to customize)
│
├── core/                      ← Shared utilities
│   ├── logger.py              ← Centralized logging system
│   ├── config_manager.py      ← Configuration loader
│   └── alert_manager.py       ← Central alert dispatcher
│
├── analyzer/                  ← Packet capture & protocol analysis
│   ├── packet_capture.py      ← Scapy-based live capture
│   └── protocol_analyzer.py   ← TCP/UDP/HTTP/DNS/ICMP/ARP parsing
│
├── detector/                  ← Threat detection engines
│   ├── threat_detector.py     ← Port scan, ICMP flood, ARP spoof, web attacks
│   ├── auth_log_analyzer.py   ← Linux auth.log brute force detection
│   └── ip_reputation.py       ← AbuseIPDB IP reputation lookup
│
├── ai_engine/                 ← Machine learning anomaly detection
│   ├── anomaly_detector.py    ← IsolationForest model
│   └── models/                ← Saved ML models (auto-created)
│
├── database/
│   └── db_manager.py          ← SQLite database operations
│
├── reporter/
│   └── report_generator.py    ← CSV and PDF report generation
│
├── dashboard/                 ← Flask web dashboard
│   ├── app.py                 ← Flask routes + WebSocket events
│   └── templates/
│       ├── index.html         ← Main dashboard
│       ├── alerts.html        ← Alerts detail page
│       ├── reports.html       ← Report downloads
│       └── settings.html      ← Settings overview
│
├── utils/
│   └── system_monitor.py      ← CPU/RAM/network metrics (psutil)
│
├── tests/
│   └── test_detectors.py      ← Unit tests
│
├── logs/                      ← Log files (auto-created)
├── reports/
│   ├── csv/                   ← Generated CSV reports
│   └── pdf/                   ← Generated PDF reports
└── database/
    └── threats.db             ← SQLite database file (auto-created)
```

---

## ⚡ Quick Start

### 1. Clone and Setup

```bash
# Clone the project
git clone https://github.com/YOUR_USERNAME/network-threat-analyzer.git
cd network-threat-analyzer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure

```bash
# Copy the environment template
cp .env.example .env

# Edit .env and add your API keys (optional)
nano .env

# Review and customize settings
nano config/config.ini
```

Key settings in `config.ini`:
- `interface` — Network interface (`any`, `eth0`, `wlan0`)
- `port_scan_threshold` — Ports before scan alert
- `brute_force_threshold` — Failed logins before alert
- `abuseipdb_api_key` — For IP reputation (optional)

### 3. Run

```bash
# Requires sudo for packet capture
sudo python3 main.py
```

Then open your browser: **http://127.0.0.1:5000**

---

## 🔧 Linux Setup

### Install System Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-venv tcpdump libpcap-dev -y

# CentOS/RHEL
sudo dnf install python3 python3-pip libpcap-devel -y

# Arch Linux
sudo pacman -S python python-pip libpcap
```

### Python Version

Requires Python 3.8 or higher:
```bash
python3 --version
```

### Network Interface

Find your network interface:
```bash
ip link show
# or
ifconfig
```

Common names: `eth0`, `ens33`, `wlan0`, `enp0s3`

Update `config/config.ini`:
```ini
[NETWORK]
interface = eth0
```

### Auth Log Access

The auth log requires root or adm group membership:
```bash
# Option 1: Run with sudo (recommended)
sudo python3 main.py

# Option 2: Add yourself to adm group
sudo usermod -aG adm $USER
# Then log out and back in
```

---

## 🤖 AI Engine Explanation

The AI engine uses **Isolation Forest** — an unsupervised ML algorithm for anomaly detection.

**Training Phase** (first ~5 minutes):
- Collects 100 traffic feature vectors (30-second windows)
- Each vector captures: packet rates, protocol ratios, IP diversity, TCP flags

**Detection Phase**:
- Every 30 seconds, extracts features from current traffic
- Model scores the features: normal (1) or anomalous (-1)
- Anomalies trigger `AI_ANOMALY` alerts

**Features extracted**:
```
total_packets, tcp_ratio, udp_ratio, icmp_ratio, dns_ratio,
unique_src_ips, unique_dst_ports, avg_packet_size,
syn_ratio, rst_ratio, fin_ratio, packets_per_second
```

---

## 📊 Dashboard Pages

| Page | URL | Description |
|---|---|---|
| Dashboard | `/` | Live overview with stats, alert feed, AI status |
| Alerts | `/alerts` | Full alert table with severity filtering |
| Reports | `/reports` | Generate and download reports |
| Settings | `/settings` | View current configuration |

### API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/stats` | Overall statistics JSON |
| `GET /api/alerts` | Recent alerts JSON |
| `GET /api/system` | System health metrics |
| `GET /api/auth-events` | Auth log events |
| `GET /api/reports/generate/csv` | Download CSV report |
| `GET /api/reports/generate/pdf` | Download PDF report |

---

## 🧪 Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_detectors.py -v

# Run with coverage report
pip install pytest-cov
pytest tests/ --cov=. --cov-report=html
```

---

## 🔐 IP Reputation Setup (Optional)

1. Register at [https://www.abuseipdb.com/register](https://www.abuseipdb.com/register)
2. Get your free API key (1000 checks/day free)
3. Add to `.env`:
   ```
   ABUSEIPDB_API_KEY=your_key_here
   ```
4. Enable in `config.ini`:
   ```ini
   [IP_REPUTATION]
   enabled = true
   ```

---

## 📤 GitHub Upload Guide

```bash
# Initialize git repository
git init
git add .

# Create .gitignore first!
echo ".env" >> .gitignore
echo "*.db" >> .gitignore
echo "logs/" >> .gitignore
echo "reports/" >> .gitignore
echo "__pycache__/" >> .gitignore
echo "*.pyc" >> .gitignore
echo "ai_engine/models/*.pkl" >> .gitignore
echo "venv/" >> .gitignore

git add .gitignore
git commit -m "Initial commit: AI Network Threat Analyzer v1.0.0"

# Create repo on GitHub, then:
git remote add origin https://github.com/YOUR_USERNAME/network-threat-analyzer.git
git branch -M main
git push -u origin main
```

---

## 🖼 Screenshot Ideas

1. **Dashboard Overview** — Stat cards + live alert feed + protocol bars
2. **Port Scan Alert** — Terminal showing port scan detection
3. **Brute Force Alert** — Multiple failed SSH attempts detected
4. **AI Training Progress** — Progress bar showing model training
5. **PDF Report** — Generated professional report
6. **Alert Detail Page** — Full table with severity filters

---

## ⚠ Troubleshooting

| Problem | Solution |
|---|---|
| `Permission denied` for capture | Run with `sudo python3 main.py` |
| `scapy not found` | `pip install scapy` |
| No auth.log | Check path in config.ini, or it's created as test log |
| Dashboard not loading | Check port 5000 is free: `lsof -i :5000` |
| AI not training | Need 100+ packets (wait ~5 min of traffic) |

---

## 🎓 Learning Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [scikit-learn IsolationForest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- [AbuseIPDB API](https://docs.abuseipdb.com/)
- [Linux Auth Log Format](https://www.loggly.com/ultimate-guide/linux-logging-basics/)
