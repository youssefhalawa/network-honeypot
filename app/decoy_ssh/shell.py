"""
Interactive SSH shell simulator
Provides realistic fake command responses without executing anything
"""
import random
from typing import Optional
from app.core.classifiers import classify_ssh_command


class ShellSimulator:
    """
    Simulates a Linux bash shell with fake but realistic responses
    SECURITY: Never executes real commands - all responses are pre-generated
    """

    def __init__(self, hostname: str = 'prod-db-01', username: str = 'ubuntu'):
        self.hostname = hostname
        self.username = username
        self.current_dir = f'/home/{username}'
        self.command_count = 0

    def process_command(self, command: str) -> tuple[str, str, str]:
        """
        Process command and return fake output

        Args:
            command: Command string from attacker

        Returns:
            Tuple of (output, classification, mitre_technique)
        """
        self.command_count += 1
        command = command.strip()

        # Classify the command for telemetry
        classification, mitre, description = classify_ssh_command(command)

        # Generate fake output based on command
        output = self._generate_output(command)

        return output, classification, mitre

    def _generate_output(self, command: str) -> str:
        """Generate realistic fake output for common commands"""
        cmd_lower = command.lower().strip()

        # Empty command
        if not cmd_lower:
            return ''

        # System info commands
        if cmd_lower == 'whoami':
            return self.username

        if cmd_lower == 'id':
            return f'uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),4(adm),27(sudo),44(docker)'

        if cmd_lower in ['hostname', 'hostname -f']:
            return self.hostname

        if cmd_lower == 'pwd':
            return self.current_dir

        if cmd_lower in ['uname', 'uname -s']:
            return 'Linux'

        if cmd_lower == 'uname -r':
            return '5.15.0-67-generic'

        if cmd_lower in ['uname -a', 'uname --all']:
            return f'Linux {self.hostname} 5.15.0-67-generic #74-Ubuntu SMP Wed Feb 22 14:14:39 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux'

        if cmd_lower == 'date':
            from datetime import datetime, timezone
            return datetime.now(timezone.utc).strftime('%a %b %d %H:%M:%S UTC %Y')

        if cmd_lower == 'uptime':
            return f' 14:32:11 up 23 days,  4:12,  2 users,  load average: 0.08, 0.12, 0.09'

        # File system commands
        if cmd_lower in ['ls', 'ls -l', 'ls -la', 'ls -al']:
            return '''total 48
drwxr-xr-x 6 ubuntu ubuntu 4096 Nov 15 10:23 .
drwxr-xr-x 3 root   root   4096 Sep 12 08:15 ..
-rw------- 1 ubuntu ubuntu  234 Nov 15 10:23 .bash_history
-rw-r--r-- 1 ubuntu ubuntu  220 Sep 12 08:15 .bash_logout
-rw-r--r-- 1 ubuntu ubuntu 3526 Sep 12 08:15 .bashrc
drwx------ 2 ubuntu ubuntu 4096 Oct 01 12:30 .ssh
drwxrwxr-x 2 ubuntu ubuntu 4096 Nov 10 09:45 documents
drwxrwxr-x 2 ubuntu ubuntu 4096 Nov 12 14:22 scripts
-rw-rw-r-- 1 ubuntu ubuntu 8192 Nov 14 16:55 backup.sql'''

        if cmd_lower.startswith('ls ') and '/tmp' in cmd_lower:
            return '''cache.txt
ssh-agent.sock
systemd-private-12345'''

        if cmd_lower == 'cat /etc/passwd':
            return '''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
postgres:x:112:115:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash'''

        if cmd_lower == 'cat /etc/shadow':
            return 'cat: /etc/shadow: Permission denied'

        if cmd_lower == 'cat /etc/hosts':
            return '''127.0.0.1       localhost
127.0.1.1       prod-db-01
10.0.1.10       db-master
10.0.1.11       db-replica
10.0.1.20       web-01'''

        # Process commands
        if cmd_lower in ['ps', 'ps aux', 'ps -ef']:
            return '''USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.4 169564 13944 ?        Ss   Nov15   0:12 /sbin/init
root       456  0.0  0.2  70612  9128 ?        Ss   Nov15   0:00 /usr/sbin/sshd -D
mysql      789  0.1  5.2 1821432 168944 ?      Ssl  Nov15   2:34 /usr/sbin/mysqld
ubuntu    1234  0.0  0.1  21420  5016 pts/0    Ss   14:15   0:00 -bash
ubuntu    1456  0.0  0.1  37364  3312 pts/0    R+   14:32   0:00 ps aux'''

        # Network commands
        if 'ifconfig' in cmd_lower or 'ip addr' in cmd_lower or 'ip a' in cmd_lower:
            return '''1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    inet 10.0.1.50/24 brd 10.0.1.255 scope global eth0'''

        if 'netstat' in cmd_lower or 'ss -tulpn' in cmd_lower:
            return '''Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      456/sshd
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      789/mysqld
tcp6       0      0 :::80                   :::*                    LISTEN      891/nginx'''

        # Environment
        if cmd_lower in ['env', 'printenv']:
            return f'''USER={self.username}
HOME={self.current_dir}
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LANG=en_US.UTF-8
PWD={self.current_dir}'''

        # Disk usage
        if 'df' in cmd_lower:
            return '''Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        20G  8.5G   11G  43% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
/dev/sda2       100G   45G   55G  45% /data'''

        # Command not found
        cmd_name = command.split()[0] if command.split() else command
        return f'bash: {cmd_name}: command not found'

    def get_prompt(self) -> str:
        """Return bash prompt string"""
        return f'{self.username}@{self.hostname}:~$ '
