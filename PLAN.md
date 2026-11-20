# Network Honeypot - Implementation Plan

## Project Goal
Build a production-grade SSH/HTTP honeypot in Python that captures attacker credentials, commands, and payloads with zero false positives, storing telemetry in SQLite and presenting analytics via a web dashboard.

## 4-Phase Roadmap

### Phase 1: Network Listeners & Storage Foundation (Days 1-3)
**Deliverables:**
- Project structure (app/, tests/, scripts/, data/)
- Configuration management (.env support)
- SQLite schema (sessions, auth_attempts, interactions, ip_intel)
- HTTP decoy (Flask) - fake login portal on port 8080
- Basic session tracking and credential logging
- Integration test harness

**Success Criteria:**
- HTTP server accepts connections, logs IP/User-Agent/credentials to SQLite
- Database schema created with proper indexes
- Can run `curl POST /login` and see stored auth_attempts

### Phase 2: SSH Decoy & Interactive Shell (Days 4-6)
**Deliverables:**
- Paramiko-based SSH server on port 2222
- Fake SSH banners (Ubuntu/Debian/CentOS variants)
- Interactive shell simulator with fake command responses
- Command classification engine (recon/download/exploit/persistence)
- MITRE ATT&CK technique tagging

**Success Criteria:**
- SSH client can connect, attempt auth (always fails), see fake shell
- Commands like `whoami`, `uname -a` return realistic fake output
- All commands logged to interactions table with classification

### Phase 3: IP Enrichment & Attack Classification (Days 7-9)
**Deliverables:**
- GeoIP2 integration (MaxMind GeoLite2)
- IP enrichment module with RFC1918/reserved IP handling
- HTTP payload classifier (SQLi/XSS/LFI/RCE/XXE detection)
- Enhanced command classifier with regex patterns
- ip_intel table population on first connection per IP

**Success Criteria:**
- New connections trigger GeoIP lookup (with offline fallback)
- HTTP requests classified by attack signature
- Dashboard can show country distribution map data

### Phase 4: Analytics Dashboard & Export (Days 10-12)
**Deliverables:**
- Flask dashboard app (separate port 5000)
- Overview page (stats, charts, top IPs/credentials)
- Session log table (paginated)
- GeoIP heatmap (Leaflet.js)
- JSON API endpoints for charts
- Export scripts (JSONL, CSV, MISP format)

**Success Criteria:**
- Dashboard displays real-time session count
- Can click session to see full command/payload history
- Export script generates valid JSONL for SIEM ingestion

## Safety Boundaries
- **No command execution**: All attacker input is logged as strings, never passed to `subprocess` or `eval()`
- **Resource limits**: 100 max concurrent sessions, 5min idle timeout, 4KB output limit
- **Input sanitization**: All paths/commands validated before classification
- **Non-privileged operation**: Runs as normal user on ports >1024 (or with capabilities)
- **Isolated deployment**: Documented firewall rules, DMZ placement, no outbound connections

## Testing Strategy
- Unit tests: Command/HTTP classifiers, GeoIP enrichment edge cases
- Integration tests: Full HTTP/SSH connection → DB write → Dashboard query
- Simulation script: Generate 100 fake attacks (random credentials, SQLi/XSS payloads)
- Manual verification: Real SSH client + curl tests against running honeypot

## Success Metrics
- Clean modular architecture (each decoy/module independently testable)
- Comprehensive SQLite schema with normalized relationships
- Zero command execution vulnerabilities
- Professional README with screenshots and deployment warnings
- 80%+ test coverage on core modules
