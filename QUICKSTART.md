# Quick Start Guide - Phase 1

## Immediate Testing (5 minutes)

### Step 1: Setup Environment
```bash
# Create virtual environment
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Create .env file
```bash
# Copy example config
copy .env.example .env
# (On Linux/Mac: cp .env.example .env)

# .env is already configured for localhost testing
# Default: HTTP on port 8080
```

### Step 3: Start Honeypot
```bash
# Run the honeypot server
python -m app.main
```

You should see:
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

Press Ctrl+C to stop
============================================================

[*] Starting HTTP Decoy on 0.0.0.0:8080
[*] Database: data/honeypot.db
[*] Fake login portal ready - waiting for attackers...
```

### Step 4: Test in Browser
Open: http://localhost:8080

You should see a professional-looking "Acme Corp Employee Portal" login page.

Try logging in with:
- Username: admin
- Password: test123

Result: You'll see "Invalid username or password" (expected - honeypot rejects all auth)

### Step 5: Run Automated Tests
```bash
# Open NEW terminal, activate venv, then:
python scripts/test_honeypot.py
```

Expected output:
```
🧪 Honeypot Test Script - Phase 1 Verification
[✓] Honeypot is responding at http://localhost:8080
[*] Testing GET requests on different paths...
  GET /                              -> 200
  GET /admin                         -> 403
  GET /wp-admin                      -> 404
[*] Testing credential capture (login attempts)...
  POST /login - admin      / admin           -> 200
  POST /login - root       / password        -> 200
[✓] Phase 1 verification complete!
```

### Step 6: Inspect Captured Data
```bash
# View all captured sessions
sqlite3 data/honeypot.db "SELECT session_id, source_ip, protocol, started_at FROM sessions;"

# View captured credentials (usernames only - passwords are hashed)
sqlite3 data/honeypot.db "SELECT username, timestamp FROM auth_attempts ORDER BY timestamp DESC;"

# View HTTP requests with attack signatures
sqlite3 data/honeypot.db "SELECT http_method, http_path, attack_signature FROM interactions WHERE interaction_type='http_request';"

# Get statistics
sqlite3 data/honeypot.db "SELECT 
    (SELECT COUNT(*) FROM sessions) as total_sessions,
    (SELECT COUNT(*) FROM auth_attempts) as credentials_captured,
    (SELECT COUNT(*) FROM interactions) as total_interactions;"
```

## What's Working (Phase 1)

✅ HTTP fake login portal on port 8080  
✅ Session tracking with UUID  
✅ Credential capture (bcrypt hashed passwords)  
✅ HTTP request logging (method, path, headers, body)  
✅ Attack signature classification (sqli, lfi, wordpress_scan, etc.)  
✅ SQLite storage with normalized schema  
✅ Thread-safe database operations  

## What's Next (Phase 2)

🔄 SSH decoy server (Paramiko)  
🔄 Interactive shell simulator  
🔄 Command classification engine  
🔄 Fake command responses (whoami, uname, ls, etc.)  

## Troubleshooting

### Port 8080 already in use?
Edit `.env`:
```
HTTP_PORT=9000
```

### Database locked?
Stop the honeypot (Ctrl+C) before running sqlite3 commands

### Can't see data?
Make sure test script ran successfully and check:
```bash
ls -la data/
# You should see: honeypot.db, honeypot.db-shm, honeypot.db-wal
```

## Security Reminder

⚠️ This honeypot is running on localhost for testing.

Before deploying to a network:
1. Review ARCHITECTURE.md security boundaries
2. Deploy in isolated VLAN/DMZ
3. Configure firewall rules
4. Have written authorization
5. Review legal compliance requirements

---

**Ready for Phase 2?** Check PLAN.md for the SSH decoy implementation roadmap.
