# What changed - review fixes (23 Nov 2026)

A full review of the code against the assignment brief (Project 08, *SOC Projects*) and the
team documents. Every fix below is covered by the test suite: `python -m pytest tests -v`
(172 tests). A full run of `scripts/simulate_attacks.py` captures 100 sessions, 92 SSH
commands and 50 HTTP requests.

## The big one: the SSH shell could not be reached

`check_auth_password()` rejected **every** password, so no attacker ever reached the fake
shell and **zero commands were ever captured**, although the brief (Phase 3) requires
logging every command an attacker types. Now, as in real honeypots (e.g. Cowrie):

* weak passwords listed in `SSH_ACCEPTED_CREDENTIALS` (`root/root`, `admin/admin`,
  `root/123456`, ...) let the attacker in to the fake shell;
* every other password is rejected like a real `sshd`;
* every attempt is still logged (bcrypt hash only), with `success = 1` for the weak ones.

---

## Member 1 - core (`main.py`, `config.py`, `session.py`, new `webserver.py`)
* **One shared `SessionManager`** for HTTP and SSH (before: each decoy had its own).
* **100-session limit** enforced, plus a **per-IP rate limit**.
* **Idle timeout (5 min) and max duration (30 min)** implemented. A "reaper" thread checks
  every 5 s; SSH attackers see `timed out waiting for input: auto-logout`.
* **Thread-safe** (lock around every access).
* **Clean shutdown**: Ctrl+C / SIGTERM stops every server and closes every open session in the
  database (before: sessions stayed "Active" forever). Sessions left open by a crash are
  closed at the next start.
* **Config validation**: bad numbers (`HTTP_PORT=abc`) give a clear message instead of a
  crash. Port clashes (including the dashboard port), negative limits and idle > max are
  checked. All problems are listed at once.
* **Busy ports** are detected before start-up, with a clear message.
* SSH is imported only when enabled (before: HTTP failed if `paramiko` was missing).
* Relative paths (database, log, key) are now inside the project folder, so the honeypot and
  the dashboard always use the same database.
* Real logging (console + rotating file `LOG_FILE`) and a warning when running as root.
* `DASHBOARD_ENABLED=true` now really starts the dashboard.

## Member 2 - HTTP decoy (`decoy_http/server.py`)
* Uses Member 5's classifier for every request (before: SQL injection on `/` was "benign").
* Request bodies are logged with **passwords redacted**; size capped (1 MB request, 4 KB stored).
* Sessions are closed after each request.
* Looks like Apache everywhere: one `Server: Apache/2.4.41 (Ubuntu)` header, Apache-style
  403/404/405/413/500 pages (before: `Werkzeug/3.0.1 Python` gave the honeypot away).
* Forged `X-Forwarded-For` is ignored unless `TRUST_PROXY_HEADERS=true`.
* HTTP Basic-auth logins are captured; `robots.txt` bait; every HTTP method handled.

## Member 3 - SSH decoy (`decoy_ssh/server.py`, `shell.py`)
* Weak-password login (see above).
* **One-line commands** (`ssh host 'uname -a'`), the most common bot behaviour, are captured.
* **No more 100 % CPU** per attacker (the loop waited without pausing).
* Idle / max-duration timeouts enforced; session always closed in the database, even when the
  login fails or the handshake breaks.
* Attacker's SSH client version is recorded.
* Host key created once at start-up (before: during the first attack, with a race).
* Arrow keys, Ctrl+U/L/C/D, backspace handled; command length capped.
* **Fake shell rewritten**: 40+ commands, working `cd` / `pwd` / prompt, pipes
  (`| grep`, `| head`, `| wc -l`) and chains (`;`, `&&`); `wget`/`curl` fail with DNS errors
  (realistic for a firewalled server) instead of "command not found"; root logins get a real
  root shell (`uid=0`, `#` prompt, `/root`); hostname consistent everywhere.
  Still **never executes anything** (checked by a test).

## Member 4 - storage (`storage/database.py`, new `models.py`)
* One lock per database file shared by every part; connections always closed.
* New: `upsert_ip_intel`, `close_open_sessions`, `update_session_client`, and proper queries
  for the dashboard (`get_attack_types`, `get_timeline`, `get_origins`, `get_geo_points`,
  sorting / filtering in `get_sessions`, SQL-injection-safe sort column).
* 10th index (`interactions.timestamp`), as documented.
* `models.py` with dataclasses for the four tables, as documented.

## Member 5 - classification and enrichment (`core/classifiers.py`, `enrichment/ip_lookup.py`)
* **IP enrichment is now actually used**: every new session's IP is looked up and stored in
  `ip_intel` (cached for 24 h). Before, nothing called it, so the origin map was always empty.
  Optional ASN database support.
* **Classifier accuracy**: categories are now checked from most specific to least. The old SQLi
  rule matched any `'` or `;`, so the documents' own XSS example `<script>alert('xss')</script>`
  was labelled SQLi, `O'Brien` was SQLi and `/;whoami` was SQLi instead of RCE.
  The phpMyAdmin rule no longer matches `/compmanager`. The documents' crontab example is now
  `persistence` (was `unknown`). Unknown commands no longer get a wrong MITRE ID.
* New categories: `privilege_escalation` (T1548), `benign` (SSH) and `sensitive_file_probe`
  (`/.env`, `/.git/config`, HTTP). Every category has a MITRE ATT&CK ID.

## Member 6 - dashboard and exports (`dashboard/`, new `storage/exporters.py`, `scripts/export_logs.py`)
* Charts: 24-hour timeline, SSH/HTTP attack types with MITRE IDs, top IPs, usernames, commands,
  **attack origins by country**. Headline numbers refresh every 10 s.
* Sessions page: 50 per page, sortable columns, HTTP/SSH filter, country column.
* Session page: shell replay with classification badges; login results; HTTP details.
* API input is validated (`?limit=abc` used to crash with a 500, `limit=-1` dumped everything).
* `/api/timeline?hours=N` now really returns the last N hours.
* **Exports** (missing before): JSONL (Splunk/ELK), CSV per table (Excel), MISP event, as
  download links and as `scripts/export_logs.py`.

## Member 7 - tests and tooling (`tests/`, `scripts/`)
* **pytest suite, 172 tests**, one file per member. It includes a real SSH client attacking a
  real server, a test that no code in `app/` can run commands, and start/stop of the whole
  program.
* `simulate_attacks.py` rewritten: exactly **100 attacks** (50 HTTP + 50 SSH including
  weak-password shells and one-line commands). Before, its SSH part silently failed.
* `scripts/setup_geoip.sh` (was documented but missing).
* `setup.py` renamed to `install.py` (Python packaging tools treat any `setup.py` as a
  package build script).
* `requirements.txt` uses version ranges that work on Python 3.9-3.13.
