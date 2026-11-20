"""
Attack pattern classification engine
Identifies attacker tactics, techniques, and procedures (TTPs)
Maps to MITRE ATT&CK framework
"""
import re
from typing import Tuple, Optional

# Command classification patterns with MITRE ATT&CK mapping
COMMAND_PATTERNS = {
    'recon': {
        'patterns': [
            r'\b(whoami|id|uname|hostname|pwd)\b',
            r'\b(ifconfig|ip addr|ip a)\b',
            r'\b(ps aux|ps -ef|top|htop)\b',
            r'\b(netstat|ss -tulpn|lsof)\b',
            r'\bcat\s+/etc/(passwd|shadow|group|hosts)\b',
            r'\bls\s+(-la|--all)',
            r'\b(env|printenv|set)\b',
            r'\b(df -h|mount|lsblk)\b',
            r'\b(dmidecode|lspci|lsusb)\b',
        ],
        'mitre': 'T1082',  # System Information Discovery
        'description': 'Reconnaissance - system enumeration'
    },
    'download': {
        'patterns': [
            r'\b(wget|curl)\s+.*https?://',
            r'\b(tftp|ftp).*get\b',
            r'\bscp\s+.*@',
            r'\bgit\s+clone\b',
            r'\brsync\s+',
        ],
        'mitre': 'T1105',  # Ingress Tool Transfer
        'description': 'Downloading malware or tools'
    },
    'persistence': {
        'patterns': [
            r'\bcrontab\s+-e',
            r'\becho.*>>\s*/etc/crontab',
            r'\b(systemctl|service)\s+enable',
            r'\becho.*>>\s*\.ssh/authorized_keys',
            r'\b(useradd|adduser)\b',
            r'\bchmod\s+\+s\b',
            r'\bcp\s+.*\.ssh/',
        ],
        'mitre': 'T1053',  # Scheduled Task/Job
        'description': 'Establishing persistence mechanisms'
    },
    'exploit': {
        'patterns': [
            r'\bchmod\s+\+x\b',
            r'\b(bash|sh)\s+-i\b',
            r'\bnc\s+-e\b',
            r'\b/bin/(bash|sh)\b.*-c',
            r'\bpython.*socket\b',
            r'\bperl.*socket\b',
            r'/tmp/[a-z0-9]+\.(sh|elf|py)',
            r'\brm\s+-rf\s+/',
        ],
        'mitre': 'T1059',  # Command and Scripting Interpreter
        'description': 'Command execution or reverse shell attempts'
    },
    'cryptominer': {
        'patterns': [
            r'\b(xmrig|minerd|cgminer|minergate)\b',
            r'stratum\+tcp://',
            r'\b(monero|xmr|btc).*pool\b',
            r'coinhive',
        ],
        'mitre': 'T1496',  # Resource Hijacking
        'description': 'Cryptocurrency mining activity'
    },
    'credential_access': {
        'patterns': [
            r'\bcat\s+.*\.ssh/(id_rsa|id_dsa)',
            r'\bgrep.*password.*/',
            r'\bfind.*-name.*password',
            r'\bhistory\s*$',
            r'\bcat\s+\.bash_history',
            r'\bcat\s+\.mysql_history',
        ],
        'mitre': 'T1552',  # Unsecured Credentials
        'description': 'Searching for credentials or keys'
    },
    'lateral_movement': {
        'patterns': [
            r'\bssh\s+.*@',
            r'\bping\s+\d+\.\d+',
            r'\bnmap\b',
            r'\barp\s+-a',
            r'/24',  # CIDR notation scanning
        ],
        'mitre': 'T1021',  # Remote Services
        'description': 'Attempting lateral movement'
    },
}

# HTTP attack signature patterns
HTTP_ATTACK_SIGNATURES = {
    'sqli': {
        'patterns': [
            r"(union.*select|or\s+1\s*=\s*1|'\s*or\s*')",
            r"(;.*drop|;.*insert|;.*update|;.*delete)",
            r"(sleep\(|benchmark\(|waitfor\s+delay)",
            r"('|\"|;|--|\*|/\*|\*/)",
        ],
        'severity': 'critical',
        'description': 'SQL Injection attempt'
    },
    'xss': {
        'patterns': [
            r'<script[^>]*>.*</script>',
            r'(onerror|onload|onclick)\s*=',
            r'javascript:',
            r'<iframe',
            r'<embed',
        ],
        'severity': 'high',
        'description': 'Cross-Site Scripting (XSS) attempt'
    },
    'lfi': {
        'patterns': [
            r'\.\./.*etc/(passwd|shadow|hosts)',
            r'(file://|php://)',
            r'\.\./\.\./\.\.',
            r'/proc/self/',
        ],
        'severity': 'high',
        'description': 'Local File Inclusion (LFI) attempt'
    },
    'rce': {
        'patterns': [
            r'(;|\||`|\$\().*\b(cat|ls|whoami|wget|curl)',
            r'<%.*%>',  # JSP/ASP code injection
            r'\$\{.*\}',  # Template injection
            r'__import__',  # Python code injection
        ],
        'severity': 'critical',
        'description': 'Remote Code Execution (RCE) attempt'
    },
    'xxe': {
        'patterns': [
            r'<!ENTITY.*SYSTEM',
            r'<!DOCTYPE.*\[.*<!ELEMENT',
        ],
        'severity': 'high',
        'description': 'XML External Entity (XXE) injection'
    },
    'path_traversal': {
        'patterns': [
            r'\.\.',
            r'%2e%2e',
            r'\.\./',
            r'\.\.\\',
        ],
        'severity': 'medium',
        'description': 'Path traversal attempt'
    },
    'wordpress_scan': {
        'patterns': [
            r'wp-(admin|login|content|includes)',
            r'wordpress',
            r'xmlrpc\.php',
        ],
        'severity': 'low',
        'description': 'WordPress installation probe'
    },
    'phpmyadmin_scan': {
        'patterns': [
            r'phpmyadmin',
            r'pma\d*',
            r'mysql',
        ],
        'severity': 'low',
        'description': 'phpMyAdmin probe'
    },
}


def classify_ssh_command(command: str) -> Tuple[str, str, str]:
    """
    Classify SSH command and map to MITRE ATT&CK

    Args:
        command: The command string entered by attacker

    Returns:
        Tuple of (classification, mitre_technique, description)
    """
    command_lower = command.lower().strip()

    # Empty command
    if not command_lower:
        return 'benign', '', 'Empty command'

    # Check each classification pattern
    for category, data in COMMAND_PATTERNS.items():
        for pattern in data['patterns']:
            if re.search(pattern, command_lower, re.IGNORECASE):
                return category, data['mitre'], data['description']

    # No match - benign or unknown
    return 'unknown', 'T1059', 'Unclassified command'


def classify_http_request(method: str, path: str, query_params: str = '',
                          body: str = '', headers: str = '') -> Tuple[str, str, str]:
    """
    Classify HTTP request for attack signatures

    Args:
        method: HTTP method (GET, POST, etc.)
        path: URL path
        query_params: Query string
        body: Request body
        headers: Request headers

    Returns:
        Tuple of (attack_signature, severity, description)
    """
    # Combine all parts for analysis
    full_payload = f"{path} {query_params} {body}".lower()

    # Check each attack signature
    for signature, data in HTTP_ATTACK_SIGNATURES.items():
        for pattern in data['patterns']:
            if re.search(pattern, full_payload, re.IGNORECASE):
                return signature, data['severity'], data['description']

    # No attack detected
    return 'benign', 'info', 'Normal HTTP request'


def get_risk_score(classification: str) -> int:
    """
    Return risk score (0-100) for a command classification

    Args:
        classification: Command classification category

    Returns:
        Risk score integer
    """
    risk_scores = {
        'cryptominer': 95,
        'exploit': 90,
        'download': 85,
        'persistence': 80,
        'credential_access': 75,
        'lateral_movement': 70,
        'recon': 50,
        'unknown': 30,
        'benign': 0,
    }
    return risk_scores.get(classification, 30)
