# Network Honeypot - System Architecture

## High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                    ATTACKER / INTERNET                       │
└─────────────┬──────────────────────┬────────────────────────┘
              │                      │
              ▼                      ▼
     ┌─────────────────┐    ┌─────────────────┐
     │  HTTP DECOY     │    │  SSH DECOY      │
     │  Port 8080      │    │  Port 2222      │
     │  Flask Login    │    │  Paramiko Shell │
     └────────┬────────┘    └────────┬────────┘
              │                      │
              └──────────┬───────────┘
                         ▼
              ┌─────────────────────┐
              │  SESSION MANAGER    │
              │  Event Coordination │
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │  IP ENRICHMENT      │
              │  GeoIP2 + Fallback  │
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │  SQLite DATABASE    │
              │  (WAL mode)         │
              └──────────┬──────────┘
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
┌──────────────────┐          ┌─────────────────────┐
│  DASHBOARD       │          │  LOG EXPORTERS      │
│  Flask Web UI    │          │  JSONL/CSV/MISP     │
│  Port 5000       │          └─────────────────────┘
└──────────────────┘
```

## Database Schema

### sessions
Core connection metadata for each attacker interaction.

| Column              | Type    | Description                          |
|---------------------|---------|--------------------------------------|
| session_id          | TEXT PK | UUID v4                              |
| source_ip           | TEXT    | Attacker IP address                  |
| source_port         | INTEGER | Ephemeral port from attacker         |
| dest_port           | INTEGER | Honeypot listener port (8080/2222)   |
| protocol            | TEXT    | 'http' or 'ssh'                      |
| started_at          | TEXT    | ISO 8601 UTC timestamp               |
| ended_at            | TEXT    | NULL until session closes            |
| duration_seconds    | REAL    | Calculated on close                  |
| user_agent          | TEXT    | HTTP User-Agent header (NULL for SSH)|
| ssh_client_version  | TEXT    | SSH client banner (NULL for HTTP)    |
| total_interactions  | INTEGER | Count of commands/HTTP requests      |

**Indexes:** source_ip, started_at, protocol

### auth_attempts
Captured credentials from login attempts.

| Column         | Type    | Description                              |
|----------------|---------|------------------------------------------|
| attempt_id     | INTEGER | Autoincrement PK                         |
| session_id     | TEXT FK | References sessions(session_id)          |
| timestamp      | TEXT    | ISO 8601 UTC                             |
| username       | TEXT    | Captured username                        |
| password_hash  | TEXT    | bcrypt hash (never plaintext)            |
| auth_method    | TEXT    | 'password', 'publickey', 'form'          |
| success        | BOOLEAN | Always 0 (honeypot rejects all auth)     |

**Indexes:** session_id, username

### interactions
Commands (SSH) and HTTP request payloads.

| Column                  | Type    | Description                          |
|-------------------------|---------|--------------------------------------|
| interaction_id          | INTEGER | Autoincrement PK                     |
| session_id              | TEXT FK | References sessions(session_id)      |
| timestamp               | TEXT    | ISO 8601 UTC                         |
| interaction_type        | TEXT    | 'ssh_command' or 'http_request'      |
| command                 | TEXT    | SSH command line (NULL for HTTP)     |
| command_classification  | TEXT    | 'recon', 'download', 'exploit', etc. |
| fake_output             | TEXT    | Simulated command response           |
| http_method             | TEXT    | GET/POST/PUT/DELETE (NULL for SSH)   |
| http_path               | TEXT    | Request path                         |
| http_query_params       | TEXT    | JSON blob                            |
| http_body               | TEXT    | POST body content                    |
| http_headers            | TEXT    | JSON blob                            |
| attack_signature        | TEXT    | 'sqli', 'xss', 'lfi', 'rce', etc.    |

**Indexes:** session_id, interaction_type, command_classification

### ip_intel
Enriched IP intelligence (cached per unique IP).

| Column                  | Type    | Description                          |
|-------------------------|---------|--------------------------------------|
| ip_address              | TEXT PK | Source IP                            |
| last_updated            | TEXT    | ISO 8601 UTC                         |
| country_code            | TEXT    | ISO 3166-1 alpha-2                   |
| country_name            | TEXT    | Full country name                    |
| city                    | TEXT    | City name (if available)             |
| latitude                | REAL    | Decimal degrees                      |
| longitude               | REAL    | Decimal degrees                      |
| asn                     | INTEGER | Autonomous System Number             |
| asn_org                 | TEXT    | ASN organization name                |
| is_tor                  | BOOLEAN | Tor exit node flag                   |
| is_vpn                  | BOOLEAN | VPN/proxy flag                       |
| abuse_confidence_score  | INTEGER | 0-100 from AbuseIPDB (optional)      |
| total_sessions          | INTEGER | Session count from this IP           |
| first_seen              | TEXT    | ISO 8601 UTC                         |
| last_seen               | TEXT    | ISO 8601 UTC                         |

**Indexes:** country_code

## Directory Structure

```
honeypot/
├── app/
│   ├── __init__.py
│   ├── main.py                    # Orchestrator entry point
│   ├── core/
│   │   ├── config.py              # Environment config loader
│   │   ├── session.py             # Session state manager
│   │   └── classifiers.py         # Command/HTTP classification
│   ├── decoy_http/
│   │   ├── server.py              # Flask app
│   │   ├── routes.py              # Login/admin endpoints
│   │   └── templates/
│   │       └── login.html
│   ├── decoy_ssh/
│   │   ├── server.py              # Paramiko wrapper
│   │   ├── shell.py               # Interactive shell simulator
│   │   └── banners.py             # Fake SSH version strings
│   ├── storage/
│   │   ├── database.py            # SQLite operations
│   │   └── models.py              # Dataclasses
│   ├── enrichment/
│   │   └── ip_lookup.py           # GeoIP2 integration
│   └── dashboard/
│       ├── app.py                 # Analytics web UI
│       └── templates/
│           └── index.html
├── scripts/
│   ├── setup_geoip.sh             # Download MaxMind DB
│   ├── simulate_attacks.py        # Test traffic generator
│   └── export_logs.py             # JSONL/CSV export
├── tests/
│   ├── test_http_decoy.py
│   ├── test_ssh_decoy.py
│   └── test_classifiers.py
├── data/                          # Git-ignored runtime data
│   ├── honeypot.db
│   └── GeoLite2-City.mmdb
├── requirements.txt
├── .env.example
├── README.md
├── PLAN.md
└── ARCHITECTURE.md
```

## Concurrency Model

**Threading Strategy:**
- HTTP decoy: Flask built-in threaded server (development) or Gunicorn (production)
- SSH decoy: Paramiko `ServerInterface` with one thread per connection
- Database writes: Thread-safe with mutex lock + WAL mode for concurrent reads

**Alternative (Phase 2+):** Async I/O with `asyncio` for better scalability:
- `asyncssh` for SSH server
- `FastAPI` + `uvicorn` for HTTP
- Single event loop handling all connections

## Security Boundaries

1. **Input Validation:** All attacker input treated as untrusted strings
2. **No Execution:** Zero use of `subprocess`, `eval()`, `exec()`, `os.system()`
3. **Resource Limits:**
   - Max 100 concurrent sessions
   - 5 minute idle timeout per session
   - 30 minute absolute session timeout
   - 4KB max command output size
4. **Credential Storage:** Passwords hashed with bcrypt before DB insert
5. **Network Isolation:** Firewall rules block outbound connections from honeypot process

## Threat Intelligence Flow

1. **Connection arrives** → Create session record with UUID
2. **Extract metadata** → IP, port, User-Agent/SSH banner
3. **Enrich IP** → Query GeoIP2 (offline) or API (online), cache in ip_intel table
4. **Capture auth** → Log username/password to auth_attempts (hashed)
5. **Record interactions** → SSH commands or HTTP requests to interactions table
6. **Classify behavior** → Regex patterns tag with MITRE ATT&CK techniques
7. **Dashboard updates** → Real-time query aggregates for web UI
8. **Export** → Periodic JSONL/CSV generation for SIEM ingestion

## Deception Techniques

- **Realistic banners:** Match real OpenSSH/Apache versions
- **Believable prompts:** `ubuntu@prod-db-01:~$` style hostnames
- **Fake data:** Simulated `/etc/passwd`, process lists, file trees
- **Slow responses:** Add 200-500ms delays to mimic real systems
- **Error messages:** Return authentic "command not found" errors for invalid commands
