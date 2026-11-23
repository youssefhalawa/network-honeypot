"""
Attack pattern classification engine (Member 5)

Identifies attacker tactics, techniques and procedures (TTPs) and maps them
to MITRE ATT&CK. Categories are checked from most specific / most severe to
least, and the FIRST match wins - so "uname -a; wget http://x" counts as a
download, and "<script>alert('x')</script>" counts as XSS, not SQL injection.
"""
import re
from typing import Tuple

# ---------------------------------------------------------------------------
# SSH commands  (checked in this order)
# ---------------------------------------------------------------------------
COMMAND_PATTERNS = {
    'cryptominer': {
        'patterns': [
            r'\b(xmrig|minerd|cgminer|bfgminer|minergate|nbminer|t-rex|cpuminer)\b',
            r'stratum\+(tcp|ssl)://',
            r'\b(monero|xmr|btc|eth)[\w.-]*pool',
            r'coinhive',
        ],
        'mitre': 'T1496',  # Resource Hijacking
        'description': 'Cryptocurrency mining activity',
    },
    'persistence': {
        'patterns': [
            r'\bcrontab\s+(-e|-r|-\s*$|[^-\s]\S*)',
            r'/var/spool/cron', r'/etc/cron', r'/etc/rc\.local', r'/etc/init\.d/',
            r'>>?\s*\S*authorized_keys',
            r'\b(systemctl|service)\s+(enable|daemon-reload)',
            r'\b(useradd|adduser|usermod|chpasswd)\b',
            r'\bpasswd\s+\w+',
            r'>>\s*\S*\.(bashrc|profile|bash_profile)',
            r'\bchmod\s+[ugo]*\+s\b', r'\bchattr\s+\+i\b',
        ],
        'mitre': 'T1053',  # Scheduled Task/Job (also covers account & key persistence here)
        'description': 'Establishing persistence mechanisms',
    },
    'credential_access': {
        'patterns': [
            r'\.ssh/(id_rsa|id_dsa|id_ecdsa|id_ed25519)\b',
            r'\b(cat|less|more|head|tail)\s+\S*/etc/shadow',
            r'\bhistory\b', r'\.(bash|zsh|mysql|psql)_history',
            r'\bgrep\b.*\b(pass|passwd|password|secret|token)\b',
            r'\bfind\b.*-name\s+\S*(pass|cred|secret|\.pem|\.key)',
            r'\.aws/credentials', r'\b(cat|less|more)\s+\S*\.env\b', r'wp-config\.php',
        ],
        'mitre': 'T1552',  # Unsecured Credentials
        'description': 'Searching for credentials or keys',
    },
    'download': {
        'patterns': [
            r'\b(wget|curl|fetch|aria2c|ftpget|lwp-download)\s+\S',
            r'\btftp\b', r'\bftp\b.*\bget\b',
            r'\bscp\s+\S+', r'\bgit\s+clone\b', r'\brsync\s+\S+',
        ],
        'mitre': 'T1105',  # Ingress Tool Transfer
        'description': 'Downloading malware or tools',
    },
    'privilege_escalation': {
        'patterns': [
            r'^\s*sudo\s+(su|-i|-s|bash|sh)\b', r'^\s*su(\s+-|\s+root)?\s*$', r'\bpkexec\b',
            r'\bfind\b.*-perm\s+-?[u4]',
        ],
        'mitre': 'T1548',  # Abuse Elevation Control Mechanism
        'description': 'Trying to become root',
    },
    'exploit': {
        'patterns': [
            r'\bchmod\s+(\+x|[0-7]*7[0-7]{2})\b',
            r'\b(bash|sh)\s+-i\b', r'/dev/(tcp|udp)/',
            r'\b(nc|ncat|netcat)\b.*\s-(e|c)\b',
            r'\|\s*(ba|z|da)?sh\b',
            r'\b(python[23]?|perl|ruby|php)\s+-(c|e|r)\b',
            r'\bbase64\s+(-d|--decode)\b',
            r'(^|[;&|]\s*)\./[\w.-]+',
            r'/tmp/[\w.-]+\.(sh|elf|py|bin)\b',
            r'\brm\s+-rf\s+/(\s|$|\*)',
            r'\b(kill|pkill|killall)\s+-9\b',
        ],
        'mitre': 'T1059',  # Command and Scripting Interpreter
        'description': 'Command execution or reverse shell attempts',
    },
    'lateral_movement': {
        'patterns': [
            r'\bssh\s+(\S+\s+)*\S+@\S+', r'\bsshpass\b',
            r'\b(nmap|masscan|zmap|hydra)\b',
            r'\bping\s+(-\S+\s+(\S+\s+)?)*\d{1,3}(\.\d{1,3}){3}',
            r'\barp\s+-a\b', r'\d{1,3}(\.\d{1,3}){3}/\d{1,2}\b',
        ],
        'mitre': 'T1021',  # Remote Services
        'description': 'Attempting lateral movement',
    },
    'recon': {
        'patterns': [
            r'^\s*(whoami|id|hostname|pwd|w|who|last|uptime|nproc|lscpu|free|df|lsblk|mount|env|printenv)\b',
            r'\buname\b', r'\b(ifconfig|iwconfig)\b', r'\bip\s+(a|addr|address|r|route|link)\b',
            r'\bps\b', r'\b(top|htop)\b', r'\b(netstat|ss|lsof)\b',
            r'\b(cat|less|more|head)\s+\S*/etc/(passwd|group|hosts|issue|os-release|resolv\.conf)',
            r'/proc/(cpuinfo|meminfo|version)', r'^\s*ls\b', r'\bcrontab\s+-l\b', r'\bsudo\s+-l\b',
            r'\b(dmidecode|lspci|lsusb)\b',
            r'^\s*(cat|head|tail|less|more|file|find|which|lsb_release|date)\b',
        ],
        'mitre': 'T1082',  # System Information Discovery
        'description': 'Reconnaissance - system enumeration',
    },
    'benign': {
        'patterns': [r'^\s*(cd|clear|exit|logout|echo|true|help)\b'],
        'mitre': '',
        'description': 'Harmless shell command',
    },
}

# ---------------------------------------------------------------------------
# HTTP requests  (checked in this order)
# ---------------------------------------------------------------------------
HTTP_ATTACK_SIGNATURES = {
    'xxe': {
        'patterns': [r'<!ENTITY\s+\S+\s+SYSTEM', r'<!DOCTYPE[^>]*\[\s*<!ENTITY'],
        'severity': 'high', 'mitre': 'T1190',
        'description': 'XML External Entity (XXE) injection',
    },
    'xss': {
        'patterns': [
            r'<script\b', r'\bon(error|load|click|mouseover|focus)\s*=', r'javascript\s*:',
            r'<(iframe|embed|object)\b', r'<(svg|img)\b[^>]*\bon\w+\s*=', r'\bdocument\.cookie\b',
        ],
        'severity': 'high', 'mitre': 'T1189',
        'description': 'Cross-Site Scripting (XSS) attempt',
    },
    'rce': {
        'patterns': [
            r'(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python\d?|perl|ping)\b',
            r'\$\{jndi:', r'__import__\s*\(', r'\b(system|exec|shell_exec|passthru|popen)\s*\(',
            r'<\?php', r'\$\{[^}]*(runtime|exec|getRuntime)',
        ],
        'severity': 'critical', 'mitre': 'T1190',
        'description': 'Remote Code Execution (RCE) attempt',
    },
    'lfi': {
        'patterns': [
            r'\.\./.*etc/(passwd|shadow|hosts|group)', r'\b(file|php|expect|zip|phar)://',
            r'/proc/self/', r'(\.\./){3,}', r'windows/(system32|win\.ini)', r'boot\.ini',
        ],
        'severity': 'high', 'mitre': 'T1083',
        'description': 'Local File Inclusion (LFI) attempt',
    },
    'sqli': {
        'patterns': [
            r"'\s*(or|and)\s+['\"\d\w]+\s*(=|like|>|<)",
            r'\bor\s+\d+\s*=\s*\d+', r'\bunion\b[\s(]+(all\s+)?select\b',
            r'\b(sleep|benchmark|pg_sleep)\s*\(', r'\bwaitfor\s+delay\b',
            r';\s*(drop|insert|update|delete|truncate|alter)\s', r"'\s*(--|#|/\*)",
            r'\binformation_schema\b', r'\b(extractvalue|updatexml|load_file)\s*\(',
            r"'\s*\)\s*(or|and)\b",
        ],
        'severity': 'critical', 'mitre': 'T1190',
        'description': 'SQL Injection attempt',
    },
    'path_traversal': {
        'patterns': [r'\.\./', r'\.\.\\', r'%2e%2e', r'%252e'],
        'severity': 'medium', 'mitre': 'T1083',
        'description': 'Path traversal attempt',
    },
    'sensitive_file_probe': {
        'patterns': [
            r'/\.(env|git|svn|hg|aws|docker|htaccess|htpasswd|ds_store)\b',
            r'/(config|configuration|settings)\.(php|ini|yml|yaml|json)\b',
            r'/[\w-]*backup[\w-]*\.(zip|tar|gz|sql|bak)\b', r'\.(sql|bak|old)(\s|$)',
            r'/server-status\b', r'/actuator\b',
        ],
        'severity': 'medium', 'mitre': 'T1083',
        'description': 'Probe for secret or configuration files',
    },
    'wordpress_scan': {
        'patterns': [r'wp-(admin|login|content|includes|config|json)', r'/wordpress\b', r'xmlrpc\.php'],
        'severity': 'low', 'mitre': 'T1595',
        'description': 'WordPress installation probe',
    },
    'phpmyadmin_scan': {
        'patterns': [r'phpmyadmin', r'/(pma|myadmin|mysqladmin|dbadmin|sqladmin)(/|\s|$)'],
        'severity': 'low', 'mitre': 'T1595',
        'description': 'phpMyAdmin probe',
    },
}

_COMPILED_SSH = {k: [re.compile(p, re.IGNORECASE) for p in v['patterns']] for k, v in COMMAND_PATTERNS.items()}
_COMPILED_HTTP = {k: [re.compile(p, re.IGNORECASE) for p in v['patterns']] for k, v in HTTP_ATTACK_SIGNATURES.items()}


def classify_ssh_command(command: str) -> Tuple[str, str, str]:
    """Return (classification, mitre_technique, description) for one shell command."""
    command = (command or '').strip()
    if not command:
        return 'benign', '', 'Empty command'
    for category, patterns in _COMPILED_SSH.items():
        if any(p.search(command) for p in patterns):
            data = COMMAND_PATTERNS[category]
            return category, data['mitre'], data['description']
    return 'unknown', '', 'Unclassified command'


def classify_http_request(method: str, path: str, query_params: str = '',
                          body: str = '', headers: str = '') -> Tuple[str, str, str]:
    """Return (attack_signature, severity, description) for one HTTP request.
    `query_params` and `body` should already be URL-decoded."""
    payload = f"{path or ''} {query_params or ''} {body or ''}"
    for signature, patterns in _COMPILED_HTTP.items():
        if any(p.search(payload) for p in patterns):
            data = HTTP_ATTACK_SIGNATURES[signature]
            return signature, data['severity'], data['description']
    return 'benign', 'info', 'Normal HTTP request'


def get_http_mitre(signature: str) -> str:
    return HTTP_ATTACK_SIGNATURES.get(signature, {}).get('mitre', '')


def get_ssh_mitre(classification: str) -> str:
    return COMMAND_PATTERNS.get(classification, {}).get('mitre', '')


def get_risk_score(classification: str) -> int:
    """Risk score (0-100) for an SSH classification or HTTP signature."""
    risk_scores = {
        'cryptominer': 95, 'rce': 95, 'exploit': 90, 'sqli': 90, 'download': 85,
        'privilege_escalation': 85, 'persistence': 80, 'xxe': 80, 'credential_access': 75,
        'lfi': 75, 'xss': 70, 'lateral_movement': 70, 'path_traversal': 60,
        'sensitive_file_probe': 55, 'recon': 50, 'credential_capture': 40, 'admin_probe': 35,
        'wordpress_scan': 30, 'phpmyadmin_scan': 30, 'unknown': 30, 'scan': 20, 'benign': 0,
    }
    return risk_scores.get(classification, 30)
