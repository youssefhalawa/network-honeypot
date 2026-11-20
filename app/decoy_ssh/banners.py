"""
SSH banner templates and fake system prompts
Simulates various Linux distributions to appear realistic
"""

SSH_BANNERS = {
    'ubuntu_22': 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1',
    'ubuntu_20': 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5',
    'debian_11': 'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1',
    'centos_7': 'SSH-2.0-OpenSSH_7.4',
    'rhel_8': 'SSH-2.0-OpenSSH_8.0',
    'windows': 'SSH-2.0-OpenSSH_for_Windows_8.1',
}

# Default banner (most common target)
DEFAULT_BANNER = SSH_BANNERS['ubuntu_22']

# Fake MOTD (Message of the Day) shown after "successful" login
FAKE_MOTD = """
Ubuntu 22.04.2 LTS

Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-67-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of {timestamp}

  System load:  0.08              Processes:             234
  Usage of /:   42.3% of 19.56GB  Users logged in:       2
  Memory usage: 34%               IPv4 address for eth0: 10.0.1.50
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

Last login: {last_login} from 10.0.1.100
"""

# Fake hostname patterns
FAKE_HOSTNAMES = [
    'prod-db-01',
    'web-server-02',
    'app-node-03',
    'backup-srv-01',
    'mail-gateway',
    'file-server',
    'jenkins-ci',
    'docker-host-01',
]

# Fake username for prompt
FAKE_USERNAME = 'ubuntu'

def get_fake_prompt(hostname: str = 'prod-db-01', username: str = 'ubuntu') -> str:
    """Generate realistic bash prompt"""
    return f"{username}@{hostname}:~$ "

def get_fake_motd(hostname: str = 'prod-db-01') -> str:
    """Generate MOTD with current timestamp"""
    from datetime import datetime, timezone, timedelta

    now = datetime.now(timezone.utc)
    # Fake "last login" time (2-24 hours ago)
    last_login = now - timedelta(hours=12, minutes=34)

    return FAKE_MOTD.format(
        timestamp=now.strftime('%a %b %d %H:%M:%S UTC %Y'),
        last_login=last_login.strftime('%a %b %d %H:%M:%S %Y')
    )
