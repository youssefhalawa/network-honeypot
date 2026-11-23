"""
Interactive SSH shell simulator (Member 3)

SECURITY: nothing here ever runs a real command, opens a real file or touches
the network. Every answer is a hard-coded string built in Python.

Realism features:
  * 40+ commands with believable Ubuntu 22.04 output
  * a working current directory (cd / pwd / prompt follow each other)
  * chains (;  &&  ||) and simple pipes (| grep, | head, | tail, | wc -l)
  * downloads "fail" with DNS errors, which matches a firewalled server
  * per-session history
"""
import re
import shlex
from datetime import datetime, timezone, timedelta
from typing import List, Tuple

from app.core.classifiers import classify_ssh_command

HOME = '/home/{user}'

FAKE_FILES = {
    '/etc/passwd': '''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
{user}:x:1000:1000:Ubuntu:/home/{user}:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
postgres:x:112:115:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash''',
    '/etc/group': '''root:x:0:
adm:x:4:syslog,{user}
sudo:x:27:
www-data:x:33:
docker:x:999:{user}
{user}:x:1000:''',
    '/etc/hosts': '''127.0.0.1       localhost
127.0.1.1       {host}
10.0.1.10       db-master
10.0.1.11       db-replica
10.0.1.20       web-01

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback''',
    '/etc/hostname': '{host}',
    '/etc/issue': 'Ubuntu 22.04.2 LTS \\n \\l',
    '/etc/os-release': '''PRETTY_NAME="Ubuntu 22.04.2 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.2 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"''',
    '/etc/resolv.conf': '''nameserver 127.0.0.53
options edns0 trust-ad
search ec2.internal''',
    '/proc/version': 'Linux version 5.15.0-67-generic (buildd@lcy02-amd64-029) (gcc (Ubuntu 11.3.0-1ubuntu1~22.04) '
                     '11.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #74-Ubuntu SMP Wed Feb 22 14:14:39 UTC 2023',
    '/proc/cpuinfo': '''processor\t: 0
vendor_id\t: GenuineIntel
model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
cpu MHz\t\t: 2499.998
cache size\t: 36608 KB
cpu cores\t: 2

processor\t: 1
vendor_id\t: GenuineIntel
model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
cpu MHz\t\t: 2499.998
cache size\t: 36608 KB
cpu cores\t: 2''',
    '/proc/meminfo': '''MemTotal:        4015232 kB
MemFree:          512344 kB
MemAvailable:    2671836 kB
Buffers:          102384 kB
Cached:          1923112 kB
SwapTotal:             0 kB
SwapFree:              0 kB''',
    '{home}/.bashrc': '''# ~/.bashrc: executed by bash(1) for non-login shells.
case $- in
    *i*) ;;
      *) return;;
esac
HISTCONTROL=ignoreboth
HISTSIZE=1000
alias ll='ls -alF'
alias la='ls -A' ''',
    '{home}/backup.sql': '''-- MySQL dump 10.13  Distrib 8.0.32, for Linux (x86_64)
-- Host: localhost    Database: acme_prod
-- ------------------------------------------------------
-- Server version\t8.0.32-0ubuntu0.22.04.2
/*!40101 SET NAMES utf8mb4 */;
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (`id` int NOT NULL AUTO_INCREMENT, `email` varchar(255), PRIMARY KEY (`id`));''',
    '{home}/documents/notes.txt': '''TODO
- rotate db backup to s3 bucket (ask ops for new keys)
- migrate web-01 to new load balancer
- renew TLS cert before Dec''',
    '{home}/scripts/backup.sh': '''#!/bin/bash
# nightly backup - runs from cron at 02:00
mysqldump -u backup acme_prod > /home/{user}/backup.sql''',
}

PERMISSION_DENIED = {'/etc/shadow', '/etc/sudoers', '/root', '/var/log/auth.log', '/etc/gshadow'}

FAKE_DIRS = {
    '/': ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'lib64', 'media', 'mnt', 'opt', 'proc', 'root',
          'run', 'sbin', 'srv', 'sys', 'tmp', 'usr', 'var'],
    '/home': ['{user}'],
    '{home}': ['backup.sql', 'documents', 'scripts'],
    '{home}/documents': ['notes.txt'],
    '{home}/scripts': ['backup.sh'],
    '{home}/.ssh': ['authorized_keys', 'known_hosts'],
    '/tmp': ['systemd-private-6f2c1d-systemd-logind.service-Xb3Hq1', 'tmux-1000'],
    '/var': ['backups', 'cache', 'lib', 'local', 'lock', 'log', 'mail', 'opt', 'run', 'spool', 'tmp', 'www'],
    '/var/www': ['html'],
    '/var/www/html': ['index.html'],
    '/etc': ['cron.d', 'crontab', 'group', 'hostname', 'hosts', 'issue', 'mysql', 'nginx', 'os-release',
             'passwd', 'resolv.conf', 'shadow', 'ssh', 'sudoers'],
    '/opt': [],
    '/usr': ['bin', 'include', 'lib', 'local', 'sbin', 'share', 'src'],
}

LS_LA_HOME = '''total 48
drwxr-x--- 6 {user} {user} 4096 Nov 15 10:23 .
drwxr-xr-x 3 root   root   4096 Sep 12 08:15 ..
-rw------- 1 {user} {user}  234 Nov 15 10:23 .bash_history
-rw-r--r-- 1 {user} {user}  220 Sep 12 08:15 .bash_logout
-rw-r--r-- 1 {user} {user} 3771 Sep 12 08:15 .bashrc
drwx------ 2 {user} {user} 4096 Sep 12 08:20 .cache
-rw-r--r-- 1 {user} {user}  807 Sep 12 08:15 .profile
drwx------ 2 {user} {user} 4096 Oct 01 12:30 .ssh
-rw-rw-r-- 1 {user} {user} 8192 Nov 14 16:55 backup.sql
drwxrwxr-x 2 {user} {user} 4096 Nov 10 09:45 documents
drwxrwxr-x 2 {user} {user} 4096 Nov 12 14:22 scripts'''

PS_AUX = '''USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.3 167744 12988 ?        Ss   Nov15   0:12 /sbin/init
root         412  0.0  0.4  47992 16584 ?        S<s  Nov15   0:03 /lib/systemd/systemd-journald
root         623  0.0  0.1  15428  7184 ?        Ss   Nov15   0:00 sshd: /usr/sbin/sshd -D [listener]
root         640  0.0  0.0   6896  2924 ?        Ss   Nov15   0:01 /usr/sbin/cron -f
mysql        789  0.3  9.8 2427356 395344 ?      Ssl  Nov15  42:11 /usr/sbin/mysqld
root         891  0.0  0.0  55228  1592 ?        Ss   Nov15   0:00 nginx: master process /usr/sbin/nginx
www-data     892  0.0  0.1  55856  5568 ?        S    Nov15   1:02 nginx: worker process
{user}      1234  0.0  0.1   8976  5520 pts/0    Ss   {t}   0:00 -bash
{user}      1456  0.0  0.0  10072  3312 pts/0    R+   {t}   0:00 ps aux'''

NETSTAT = '''Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp6       0      0 :::22                   :::*                    LISTEN'''

IP_ADDR = '''1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP group default qlen 1000
    link/ether 0a:3c:5e:91:2b:7d brd ff:ff:ff:ff:ff:ff
    inet 10.0.1.50/24 metric 100 brd 10.0.1.255 scope global dynamic eth0
       valid_lft 2714sec preferred_lft 2714sec'''

IFCONFIG = '''eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.0.1.50  netmask 255.255.255.0  broadcast 10.0.1.255
        ether 0a:3c:5e:91:2b:7d  txqueuelen 1000  (Ethernet)
        RX packets 18234511  bytes 9823412345 (9.8 GB)
        TX packets 14523344  bytes 4412348761 (4.4 GB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)'''

SILENT_COMMANDS = {
    'true', 'clear', 'export', 'unset', 'alias', 'set', 'touch', 'mkdir', 'rm', 'rmdir', 'cp', 'mv', 'chmod',
    'chown', 'kill', 'pkill', 'killall', 'sleep', 'cd', 'umask', 'history -c', 'unalias', 'nohup', 'disown',
    'ulimit', 'source', '.', 'sync', 'stty', 'tput', 'reset',
}

NOT_INSTALLED = {'nmap', 'masscan', 'zmap', 'hydra', 'nc', 'ncat', 'netcat', 'telnet', 'ftp', 'tftp', 'gcc', 'cc',
                 'make', 'perl', 'ruby', 'php', 'go', 'docker', 'sshpass', 'xmrig', 'screen', 'aria2c'}


class ShellSimulator:
    """Fake bash shell. Never executes anything."""

    def __init__(self, hostname: str = 'prod-db-01', username: str = 'ubuntu', max_output: int = 4096):
        self.hostname = hostname
        self.username = username
        self.is_root = username == 'root'
        # the normal account that "owns" the server's files
        self.account = 'ubuntu' if self.is_root else username
        self.home = '/root' if self.is_root else HOME.format(user=username)
        self.current_dir = self.home
        self.command_count = 0
        self.history: List[str] = []
        self.max_output = max_output
        self.login_time = datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    def process_command(self, command: str) -> Tuple[str, str, str]:
        """Return (fake_output, classification, mitre_technique)."""
        command = (command or '').strip()
        self.command_count += 1
        if command:
            self.history.append(command)
        classification, mitre, _ = classify_ssh_command(command)
        output = self._run_line(command)
        if len(output) > self.max_output:
            output = output[:self.max_output]
        return output, classification, mitre

    def get_prompt(self) -> str:
        path = self.current_dir
        if path == self.home:
            path = '~'
        elif path.startswith(self.home + '/'):
            path = '~' + path[len(self.home):]
        return f'{self.username}@{self.hostname}:{path}{"#" if self.is_root else "$"} '

    # ------------------------------------------------------------------
    def _fmt(self, text: str) -> str:
        return (text.replace('{home}', HOME.format(user=self.account)).replace('{user}', self.account)
                .replace('{host}', self.hostname))

    def _denied(self, path: str) -> bool:
        return not self.is_root and (path in PERMISSION_DENIED or path.startswith('/root/'))

    def _run_line(self, line: str) -> str:
        """Handle ; && || chains, then pipes inside each part."""
        if not line:
            return ''
        outputs = []
        for part in re.split(r'\s*(?:;|&&|\|\|)\s*', line):
            if part.strip():
                result = self._run_pipeline(part.strip())
                if result:
                    outputs.append(result)
        return '\n'.join(outputs)

    def _run_pipeline(self, segment: str) -> str:
        stages = [s.strip() for s in segment.split('|')]
        output = self._run_simple(stages[0])
        for stage in stages[1:]:
            output = self._filter(stage, output)
        return output

    def _filter(self, stage: str, text: str) -> str:
        words = self._split(stage)
        if not words:
            return text
        name, args = words[0], words[1:]
        lines = text.split('\n') if text else []
        if name == 'grep':
            flags = [a for a in args if a.startswith('-')]
            terms = [a for a in args if not a.startswith('-')]
            if not terms:
                return 'Usage: grep [OPTION]... PATTERNS [FILE]...'
            term = terms[0]
            ignore = any('i' in f for f in flags)
            invert = any('v' in f for f in flags)
            match = (lambda l: (term.lower() in l.lower()) if ignore else (term in l))
            return '\n'.join(l for l in lines if match(l) != invert)
        if name in ('head', 'tail'):
            n = 10
            for i, a in enumerate(args):
                if a == '-n' and i + 1 < len(args) and args[i + 1].isdigit():
                    n = int(args[i + 1])
                elif re.fullmatch(r'-\d+', a):
                    n = int(a[1:])
            return '\n'.join(lines[:n] if name == 'head' else lines[-n:])
        if name == 'wc':
            return str(len(lines)) if '-l' in args else f'{len(lines):>7} {len(text.split()):>7} {len(text):>7}'
        if name in ('sort', 'uniq', 'cat', 'less', 'more'):
            return '\n'.join(sorted(lines)) if name == 'sort' else text
        if name in ('sh', 'bash'):
            return ''          # "curl x | sh": download already failed, nothing to run
        return text

    @staticmethod
    def _split(text: str) -> List[str]:
        try:
            return shlex.split(text)
        except ValueError:
            return text.split()

    def _path(self, arg: str) -> str:
        if not arg or arg == '~':
            return self.home
        if arg.startswith('~/'):
            arg = self.home + arg[1:]
        if not arg.startswith('/'):
            arg = self.current_dir.rstrip('/') + '/' + arg
        parts = []
        for piece in arg.split('/'):
            if piece in ('', '.'):
                continue
            if piece == '..':
                if parts:
                    parts.pop()
            else:
                parts.append(piece)
        return '/' + '/'.join(parts)

    def _dirs(self):
        return {self._fmt(k): [self._fmt(x) for x in v] for k, v in FAKE_DIRS.items()}

    def _files(self):
        return {self._fmt(k): self._fmt(v) for k, v in FAKE_FILES.items()}

    # ------------------------------------------------------------------
    def _run_simple(self, command: str) -> str:
        # Output redirection: "echo x > file" prints nothing
        redirected = bool(re.search(r'(^|[^2])>{1,2}\s*\S', command))
        command_wo_redirect = re.split(r'\s+\d?>{1,2}\s*', command)[0].strip()
        words = self._split(command_wo_redirect)
        if not words:
            return ''
        name, args = words[0], words[1:]
        if name == 'sudo':
            return self._sudo(args)
        output = self._dispatch(name, args, command_wo_redirect)
        if redirected and not re.search(r'not found|Permission denied|No such file|Could not resolve|failed', output):
            return ''
        return output

    def _sudo(self, args: List[str]) -> str:
        if self.is_root:
            rest = [a for a in args if not a.startswith('-')]
            return self._dispatch(rest[0], rest[1:], ' '.join(rest)) if rest else ''
        if args[:1] == ['-l']:
            return f'Sorry, user {self.username} may not run sudo on {self.hostname}.'
        return f'{self.username} is not in the sudoers file.  This incident will be reported.'

    def _dispatch(self, name: str, args: List[str], full: str) -> str:
        now = datetime.now(timezone.utc)
        dirs, files = self._dirs(), self._files()
        arg_str = ' '.join(args)

        if name in ('whoami',):
            return self.username
        if name == 'id':
            if self.is_root:
                return 'uid=0(root) gid=0(root) groups=0(root)'
            return (f'uid=1000({self.username}) gid=1000({self.username}) '
                    f'groups=1000({self.username}),4(adm),999(docker)')
        if name == 'hostname':
            return '10.0.1.50' if '-I' in args or '-i' in args else self.hostname
        if name == 'pwd':
            return self.current_dir
        if name == 'uname':
            if not args or args == ['-s']:
                return 'Linux'
            if args == ['-r']:
                return '5.15.0-67-generic'
            if args == ['-m'] or args == ['-p']:
                return 'x86_64'
            if args == ['-n']:
                return self.hostname
            return (f'Linux {self.hostname} 5.15.0-67-generic #74-Ubuntu SMP Wed Feb 22 14:14:39 UTC 2023 '
                    'x86_64 x86_64 x86_64 GNU/Linux')
        if name == 'date':
            return now.strftime('%a %b %d %H:%M:%S UTC %Y')
        if name == 'uptime':
            return f" {now.strftime('%H:%M:%S')} up 23 days,  4:12,  1 user,  load average: 0.08, 0.12, 0.09"
        if name in ('w', 'who'):
            since = self.login_time.strftime('%H:%M')
            if name == 'who':
                return f'{self.username} pts/0        {self.login_time.strftime("%Y-%m-%d")} {since} (10.0.1.100)'
            return (f" {now.strftime('%H:%M:%S')} up 23 days,  4:12,  1 user,  load average: 0.08, 0.12, 0.09\n"
                    'USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n'
                    f'{self.username:<8} pts/0    10.0.1.100       {since}    0.00s  0.02s  0.00s w')
        if name == 'last':
            earlier = now - timedelta(hours=12, minutes=34)
            return (f'{self.username:<8} pts/0        10.0.1.100       {self.login_time.strftime("%a %b %d %H:%M")}'
                    '   still logged in\n'
                    f'{self.username:<8} pts/0        10.0.1.100       {earlier.strftime("%a %b %d %H:%M")} - '
                    f'{(earlier + timedelta(minutes=41)).strftime("%H:%M")}  (00:41)\n\nwtmp begins Tue Sep 12 08:15:02 2023')
        if name == 'cd':
            target = self._path(args[0]) if args else self.home
            if self._denied(target):
                return f'-bash: cd: {args[0]}: Permission denied'
            if target in dirs or target in ('/root', '/proc', '/dev', '/sys', '/bin', '/sbin', '/lib', '/boot', '/run',
                                            '/srv', '/mnt', '/media', '/var/log', '/var/tmp', '/etc/ssh',
                                            '/usr/bin', '/usr/local', '/var/lib'):
                self.current_dir = target
                return ''
            return f'-bash: cd: {args[0]}: No such file or directory'
        if name in ('ls', 'll', 'dir'):
            flags = ''.join(a[1:] for a in args if a.startswith('-'))
            if name == 'll':
                flags += 'la'
            targets = [a for a in args if not a.startswith('-')] or [self.current_dir]
            target = self._path(targets[0])
            if self._denied(target):
                return f"ls: cannot open directory '{targets[0]}': Permission denied"
            if target == '/root':
                return 'total 28\ndrwx------  5 root root 4096 Nov 15 10:20 .\ndrwxr-xr-x 19 root root 4096 Sep 12 08:14 ..\n' \
                       '-rw-------  1 root root 1203 Nov 15 10:20 .bash_history\n-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc\n' \
                       'drwx------  2 root root 4096 Sep 12 08:20 .ssh\ndrwxr-xr-x  3 root root 4096 Sep 12 08:31 snap' \
                    if 'l' in flags else 'snap'
            if target == HOME.format(user=self.account) and 'l' in flags:
                return self._fmt(LS_LA_HOME)
            if target in files:
                return targets[0]
            if target not in dirs:
                return f"ls: cannot access '{targets[0]}': No such file or directory"
            entries = dirs[target]
            if 'a' in flags and target == self.home:
                entries = ['.', '..', '.bash_history', '.bash_logout', '.bashrc', '.cache', '.profile', '.ssh'] + entries
            if 'l' in flags:
                rows = [f'total {4 * len(entries)}']
                for e in entries:
                    is_file = (target.rstrip('/') + '/' + e) in files or '.' in e.strip('.')
                    perm = '-rw-r--r-- 1' if is_file else 'drwxr-xr-x 2'
                    rows.append(f'{perm} root root {"1024" if is_file else "4096"} Nov 12 09:14 {e}')
                return '\n'.join(rows)
            return '  '.join(entries)
        if name in ('cat', 'less', 'more', 'head', 'tail', 'nano', 'vi', 'vim'):
            if name in ('nano', 'vi', 'vim'):
                return f'Error opening terminal: unknown.' if name == 'nano' else \
                    'Vim: Warning: Output is not to a terminal'
            paths = [a for a in args if not a.startswith('-')]
            if not paths:
                return ''
            out = []
            for p in paths:
                full_path = self._path(p)
                if self._denied(full_path):
                    out.append(f'{name}: {p}: Permission denied')
                elif full_path == '/etc/shadow':
                    out.append('root:$6$Gq8sT1x2$K9vY3mXbQe7aLr0pZ8wN2dF4hJ6kU1sV5cB3nM7qR9tY0iO2pA4sD6fG8hJ0kL2zX4cV6bN8mQ1wE3rT5yU7:19612:0:99999:7:::\n'
                               'daemon:*:19235:0:99999:7:::\nubuntu:$6$Xr4pL9q2$T2bN5mQ8wE1rT4yU7iO0pA3sD6fG9hJ2kL5zX8cV1bN4mQ7wE0rT3yU6iO9pA2sD5fG8hJ1kL4zX7cV0bN3:19612:0:99999:7:::\n'
                               'mysql:!:19235:0:99999:7:::')
                elif full_path == '/root/.bash_history':
                    out.append('apt update\napt upgrade -y\nsystemctl restart mysql\nvim /etc/mysql/my.cnf\nexit')
                elif full_path in files:
                    out.append(files[full_path])
                elif full_path == HOME.format(user=self.account) + '/.bash_history':
                    out.append('\n'.join(['ls -la', 'cd scripts', './backup.sh', 'mysql -u root -p', 'exit']))
                elif full_path in dirs:
                    out.append(f'{name}: {p}: Is a directory')
                elif full_path.endswith('authorized_keys'):
                    out.append('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK3m9p8yqfEw2v6x1Wl0d0pQ0ZJ7n3o4ZQm9r2yN1Ugx ops@bastion')
                else:
                    out.append(f'{name}: {p}: No such file or directory')
            return '\n'.join(out)
        if name == 'echo':
            text = arg_str
            return re.sub(r'\$(USER|LOGNAME)', self.username, re.sub(r'\$HOME', self.home,
                          re.sub(r'\$SHELL', '/bin/bash', text)))
        if name in ('ps',):
            return self._fmt(PS_AUX).replace('{t}', self.login_time.strftime('%H:%M'))
        if name == 'top':
            return ('top - %s up 23 days,  4:12,  1 user,  load average: 0.08, 0.12, 0.09\n'
                    'Tasks: 112 total,   1 running, 111 sleeping,   0 stopped,   0 zombie\n'
                    '%%Cpu(s):  1.3 us,  0.7 sy,  0.0 ni, 97.8 id,  0.2 wa\n'
                    'MiB Mem :   3921.1 total,    500.3 free,   1309.6 used,   2111.2 buff/cache\n\n'
                    '    PID USER      PR  NI    VIRT    RES    SHR S  %%CPU  %%MEM     TIME+ COMMAND\n'
                    '    789 mysql     20   0 2427356 395344  36464 S   1.0   9.8  42:11.07 mysqld') % now.strftime('%H:%M:%S')
        if name in ('ifconfig',):
            return IFCONFIG
        if name == 'ip':
            if args[:1] in (['r'], ['route']):
                return 'default via 10.0.1.1 dev eth0 proto dhcp src 10.0.1.50 metric 100\n' \
                       '10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.50 metric 100'
            return IP_ADDR
        if name in ('netstat', 'ss'):
            return NETSTAT
        if name in ('env', 'printenv'):
            return (f'SHELL=/bin/bash\nPWD={self.current_dir}\nLOGNAME={self.username}\nHOME={self.home}\n'
                    f'LANG=C.UTF-8\nUSER={self.username}\nSHLVL=1\nSSH_CONNECTION=10.0.1.100 52114 10.0.1.50 22\n'
                    'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games\n'
                    '_=/usr/bin/env')
        if name == 'df':
            return ('Filesystem      Size  Used Avail Use% Mounted on\n/dev/root        20G  8.5G   11G  43% /\n'
                    'tmpfs           2.0G     0  2.0G   0% /dev/shm\n/dev/nvme1n1    100G   45G   55G  45% /data')
        if name == 'free':
            return ('               total        used        free      shared  buff/cache   available\n'
                    'Mem:         3921112     1309600      500344        1012     2111168     2671836\n'
                    'Swap:              0           0           0')
        if name == 'nproc':
            return '2'
        if name == 'lscpu':
            return ('Architecture:            x86_64\nCPU(s):                  2\n'
                    'Model name:              Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\n'
                    'Hypervisor vendor:       KVM\nVirtualization type:     full')
        if name == 'lsb_release':
            return ('Distributor ID:\tUbuntu\nDescription:\tUbuntu 22.04.2 LTS\nRelease:\t22.04\nCodename:\tjammy')
        if name == 'history':
            if args[:1] == ['-c']:
                self.history.clear()
                return ''
            return '\n'.join(f'{i:>5}  {c}' for i, c in enumerate(self.history, 1))
        if name == 'crontab':
            if '-l' in args:
                return f'no crontab for {self.username}'
            if '-e' in args:
                return f'no crontab for {self.username} - using an empty one\ncrontab: installing new crontab'
            return ''
        if name == 'which':
            known = {'python3', 'bash', 'sh', 'curl', 'wget', 'ls', 'cat', 'mysql', 'git', 'nginx', 'ssh'}
            return '\n'.join(f'/usr/bin/{a}' for a in args if a in known)
        if name == 'wget':
            url = next((a for a in args if not a.startswith('-')), '')
            host = re.sub(r'^\w+://', '', url).split('/')[0].split(':')[0] or url
            return (f"--{now.strftime('%Y-%m-%d %H:%M:%S')}--  {url}\nResolving {host} ({host})... "
                    f"failed: Temporary failure in name resolution.\nwget: unable to resolve host address '{host}'")
        if name == 'curl':
            url = next((a for a in args if not a.startswith('-')), '')
            if not url:
                return "curl: try 'curl --help' or 'curl --manual' for more information"
            host = re.sub(r'^\w+://', '', url).split('/')[0].split(':')[0]
            return f'curl: (6) Could not resolve host: {host}'
        if name == 'git':
            if args[:1] == ['clone'] and len(args) > 1:
                return (f"Cloning into '{args[-1].rstrip('/').split('/')[-1].replace('.git', '')}'...\n"
                        f"fatal: unable to access '{args[-1]}': Could not resolve host: "
                        f"{re.sub(r'^\w+://', '', args[-1]).split('/')[0]}")
            return 'usage: git [--version] [--help] [-C <path>] [-c <name>=<value>] <command> [<args>]'
        if name in ('scp', 'ssh', 'rsync'):
            target = next((a for a in args if '@' in a or ':' in a), args[-1] if args else '')
            host = target.split('@')[-1].split(':')[0] or 'host'
            return f'ssh: connect to host {host} port 22: Connection timed out'
        if name in ('ping',):
            host = next((a for a in args if not a.startswith('-') and not a.isdigit()), '')
            return f'PING {host} ({host}) 56(84) bytes of data.\n\n--- {host} ping statistics ---\n' \
                   '4 packets transmitted, 0 received, 100% packet loss, time 3062ms'
        if name in ('python', 'python3'):
            if args[:1] in (['-V'], ['--version']):
                return 'Python 3.10.12'
            if name == 'python':
                return "Command 'python' not found, did you mean:\n  command 'python3' from deb python3"
            return ''
        if name in ('apt', 'apt-get', 'yum', 'dnf'):
            if name in ('yum', 'dnf'):
                return f'-bash: {name}: command not found'
            if self.is_root:
                return ('Reading package lists... Done\nBuilding dependency tree... Done\n'
                        'E: Unable to locate package ' + (args[-1] if args else ''))
            return ('E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n'
                    'E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?')
        if name in ('systemctl', 'service'):
            if args[:1] in (['status'],) or (name == 'service' and args[-1:] == ['status']):
                return '● ' + (args[-1] if name == 'systemctl' else args[0]) + '.service - loaded active (running)'
            return 'Failed to %s unit: Access denied' % (args[0] if args else 'run')
        if name in ('su',):
            return 'Password: \nsu: Authentication failure'
        if name == 'passwd':
            return f'Changing password for {self.username}.\nCurrent password: \npasswd: Authentication token manipulation error\npasswd: password unchanged'
        if name in ('useradd', 'adduser', 'usermod', 'userdel', 'groupadd'):
            return f'{name}: Permission denied.\n{name}: cannot lock /etc/passwd; try again later.'
        if name == 'find':
            if any('pass' in a or 'secret' in a or '.pem' in a or 'key' in a for a in args):
                return f'find: ‘/root’: Permission denied\n{self.home}/scripts/backup.sh'
            return "find: ‘/root’: Permission denied\nfind: ‘/var/lib/mysql’: Permission denied"
        if name == 'grep':
            return ''
        if name == 'mysql':
            return "ERROR 1045 (28000): Access denied for user '%s'@'localhost' (using password: NO)" % self.username
        if name in ('base64',):
            return ''
        if name == 'file':
            return '\n'.join(f'{a}: cannot open `{a}\' (No such file or directory)' for a in args)
        if name in ('bash', 'sh') and args:
            script = next((a for a in args if not a.startswith('-')), '')
            if script and self._path(script) in files:
                return ''
            return f'{name}: {script}: No such file or directory' if script else ''
        if name.startswith('./') or name.startswith('/tmp/') or name.startswith('/dev/shm/'):
            full_path = self._path(name)
            if full_path in files and not self.is_root:
                return f'-bash: {name}: Permission denied'
            return f'-bash: {name}: No such file or directory'
        if name in SILENT_COMMANDS or full in SILENT_COMMANDS:
            return ''
        if name in NOT_INSTALLED:
            return f"Command '{name}' not found, but can be installed with:\nsudo apt install {name}"
        if name in ('exit', 'logout'):
            return ''
        return f'-bash: {name}: command not found'
