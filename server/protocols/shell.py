"""
Shell Protocol Bridge

This module acts as the bridge between the terminal protocols (SSH, Telnet)
and the LLM client (Ollama).

The flow is:
1. User types a command (captured by Term or TelnetHandler)
2. User presses Enter (triggers command termination)
3. Command is passed to this bridge
4. Bridge calls LLM for analysis
5. Response is processed and sent back to user
"""

from __future__ import annotations

import re
import time
import json
import os
import posixpath  # always POSIX paths for the simulated Linux filesystem
from datetime import datetime
from typing import Optional, Dict, Any
from twisted.python import log

from LLM.client import OllamaClient

# ---------------------------------------------------------------------------
# Static file contents and command outputs — instant, no LLM needed
# ---------------------------------------------------------------------------

_STATIC_FILES: dict = {
    "/etc/hostname": "ubuntu-srv",
    "/etc/os-release": (
        'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
        'VERSION="22.04.3 LTS (Jammy Jellyfish)"\nID=ubuntu\nID_LIKE=debian'
    ),
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "sshd:x:128:65534::/run/sshd:/usr/sbin/nologin\n"
        "devops:x:1000:1000:DevOps Admin,,,:/home/devops:/bin/bash"
    ),
    "/etc/shadow": (
        "root:$6$rounds=5000$rNdFAKESALT$FAKEHASHabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl:19000:0:99999:7:::\n"
        "devops:$6$rounds=5000$xYzFAKESALT$FAKEHASHzyxwvutsrqponmlkjihgfedcba9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqpo:19100:0:99999:7:::"
    ),
    "/etc/sudoers": (
        "# This file MUST be edited with the 'visudo' command.\nroot    ALL=(ALL:ALL) ALL\n%sudo   ALL=(ALL:ALL) ALL"
    ),
    "/proc/version": (
        "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-006) "
        "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld 2.38) "
        "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023"
    ),
    "/proc/uptime": "548234.12 1034291.54",
    "/proc/cpuinfo": (
        "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 85\n"
        "model name\t: Intel(R) Xeon(R) Gold 6154 CPU @ 3.00GHz\ncpu MHz\t\t: 3000.000\n"
        "cache size\t: 25344 KB\ncpu cores\t: 1\nbogomips\t: 6000.00"
    ),
    "/proc/meminfo": (
        "MemTotal:        4096000 kB\nMemFree:          823456 kB\n"
        "MemAvailable:    1954321 kB\nBuffers:          123456 kB\n"
        "Cached:           987654 kB\nSwapTotal:       2097148 kB\nSwapFree:        2097148 kB"
    ),
    "/root/.env": (
        "DB_HOST=127.0.0.1\n"
        "DB_USER=app_user\n"
        "DB_PASSWORD=Pr0d@ppP@ss2023!\n"
        "DB_NAME=webapp_prod\n"
        "JWT_SECRET=f8a4d3b2e1c96057fa31\n"
        "AWS_ACCESS_KEY_ID=AKIA4HFAKE7EXP1REKEY\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY1\n"
        "REDIS_URL=redis://10.0.0.6:6379/0"
    ),
    "/root/todo_migration.txt": (
        "# DB Migration TODO\n"
        "- [ ] Move prod DB to new RDS instance\n"
        "- [ ] Update app .env with new DB_HOST after cutover\n"
        "- [ ] Test connection from app server before DNS switch\n"
        "- [ ] Snapshot old instance before deleting\n\n"
        "AWS creds → .aws/credentials (use rds-admin profile)\n"
        "Old passwd backup → /var/backups/passwd.bak"
    ),
    "/root/.aws/credentials": (
        "[default]\naws_access_key_id = AKIA4HFAKE7EXP1REKEY\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY1\n\n"
        "[rds-admin]\naws_access_key_id = AKIAIOSFODNN7FAKE002\n"
        "aws_secret_access_key = je7MtGbClwBF/2Tk/h3FAKE/7drTFAKEKEY002\nregion = us-east-1"
    ),
    "/var/backups/passwd.bak": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "devops:x:1000:1000:DevOps Admin,,,:/home/devops:/bin/bash"
    ),
    "/var/backups/shadow.bak": (
        "root:$6$rounds=5000$rNdFAKESALT$FAKEHASHabcdefghijklmnopqrstuvwxyz0123456:19000:0:99999:7:::\n"
        "devops:$6$rounds=5000$xYzFAKESALT$FAKEHASHzyxwvutsrqponmlkjihgfedcba98765:19100:0:99999:7:::"
    ),
    "/var/www/html/config.php": (
        "<?php\n"
        "// Application configuration\n"
        "define('DB_HOST', '127.0.0.1');\n"
        "define('DB_USER', 'app_user');\n"
        "define('DB_PASSWORD', 'Pr0d@ppP@ss2023!');\n"
        "define('DB_NAME', 'webapp_prod');\n"
        "define('APP_SECRET', 'c3f8a9d2e7b14056f31a');\n"
        "define('S3_BUCKET', 'prod-backups-2023');\n"
        "?>"
    ),
    # /dev/urandom: return garbled-looking noise instead of "No such file"
    "/dev/urandom": (
        "Q3)7!z$Xo1v;K#E8&mR{T5Hf2?kc.bN9>As0^jG6@Lp|d*Yw<"
        "4WnI_F7!xMZq%rU~B8+eV2s{C1=h3OtP6,gJ)l9yD0-uaS5#kN"
        ">7R@Xf!3Q$m*T8Lv1bKzW4pIoH2c%Ej^9y0dG6~nA|Bs;Ft<2R"
    ),
    "/dev/random": (
        "Q3)7!z$Xo1v;K#E8&mR{T5Hf2?kc.bN9>As0^jG6@Lp|d*Yw<"
        "4WnI_F7!xMZq%rU~B8+eV2s{C1=h3OtP6,gJ)l9yD0-uaS5#kN"
    ),
}

_IFCONFIG = """\
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255
        inet6 fe80::250:56ff:fe81:a3c2  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:81:a3:c2  txqueuelen 1000  (Ethernet)
        RX packets 128456  bytes 12345678 (12.3 MB)
        TX packets 98765  bytes 9876543 (9.8 MB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)"""

_IP_ADDR = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP
    link/ether 00:50:56:81:a3:c2 brd ff:ff:ff:ff:ff:ff
    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0"""

_NETSTAT = """\
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address  State     PID/Program
tcp        0      0 0.0.0.0:22              0.0.0.0:*        LISTEN    701/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*        LISTEN    821/nginx
tcp        0      0 0.0.0.0:443             0.0.0.0:*        LISTEN    821/nginx
tcp        0      0 127.0.0.1:3306          0.0.0.0:*        LISTEN    1023/mysqld"""

_SS = """\
Netid  State   Recv-Q  Send-Q  Local Address:Port   Peer Address:Port
tcp    LISTEN  0       128     0.0.0.0:22            0.0.0.0:*         users:(("sshd",pid=701))
tcp    LISTEN  0       511     0.0.0.0:80            0.0.0.0:*         users:(("nginx",pid=821))
tcp    LISTEN  0       511     0.0.0.0:443           0.0.0.0:*         users:(("nginx",pid=821))
tcp    LISTEN  0       70      127.0.0.1:3306        0.0.0.0:*         users:(("mysqld",pid=1023))"""

_DF = """\
Filesystem      Size  Used Avail Use% Mounted on
udev            2.0G     0  2.0G   0% /dev
tmpfs           400M  1.5M  399M   1% /run
/dev/sda1        40G  7.9G   32G  21% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
/dev/sda15      105M  6.1M   99M   6% /boot/efi"""

_FREE = """\
               total        used        free      shared  buff/cache   available
Mem:         4096000     1234567      823456        1024     2037977     2345678
Swap:        2097148           0     2097148"""

_LAST = """\
root     pts/0   10.0.0.15   Mon Apr 28 12:35   still logged in
devops   pts/1   10.0.0.12   Sun Apr 27 09:12 - 17:45  (08:33)
root     pts/0   10.0.0.15   Sat Apr 26 22:10 - 22:58  (00:48)
devops   pts/0   10.0.0.10   Fri Apr 25 14:20 - 16:05  (01:45)

wtmp begins Fri Apr 11 00:00:01 2025"""

_CRONTAB = """\
# m h  dom mon dow   command
*/5 * * * * /usr/local/bin/backup.sh >> /var/log/backup.log 2>&1
0 2 * * * /usr/bin/find /tmp -mtime +7 -delete
@reboot /usr/local/bin/startup.sh"""

# ---------------------------------------------------------------------------
# Destructive command simulation
# ---------------------------------------------------------------------------

_RM_RF_WARNING = (
    "rm: it is dangerous to operate recursively on '/'\r\n"
    "rm: use --no-preserve-root to override this safeguard\r\n"
)

_RM_SAFE    = re.compile(r'\brm\b.{0,20}-[a-z]*r[a-z]*f[a-z]*.{0,10}/')
_FORKBOMB   = re.compile(r':\s*\(\s*\)\s*\{|:\(\)\{')


def _nuclear_output() -> str:
    ts = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    deleted = [
        "/bin/bash", "/bin/ls", "/bin/cat", "/bin/cp", "/bin/mv", "/bin/rm",
        "/usr/bin/python3", "/usr/bin/perl", "/usr/bin/curl", "/usr/bin/wget",
        "/usr/sbin/nginx", "/usr/sbin/sshd", "/usr/sbin/mysqld",
        "/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libm.so.6",
        "/etc/passwd", "/etc/shadow", "/etc/nginx/nginx.conf",
        "/etc/ssh/sshd_config", "/etc/cron.d/backup",
        "/var/log/auth.log", "/var/log/syslog", "/var/www/html/index.html",
        "/home/devops/.ssh/authorized_keys", "/root/.aws/credentials",
        "/root/.bash_history", "/root/todo_migration.txt",
    ]
    out = "rm: removing root directory '/'...\r\n"
    for f in deleted:
        out += f"rm: removing '{f}'\r\n"
    out += (
        "\r\nrm: cannot remove '/proc/sysrq-trigger': Operation not permitted\r\n"
        "\r\n"
        f"Broadcast message from root@ubuntu-srv (pts/0) ({ts}):\r\n"
        "The system will go down for reboot NOW!\r\n"
        "\r\n"
        "INIT: Switching to runlevel: 6\r\n"
        "INIT: Sending processes configured via /etc/inittab the TERM signal\r\n"
        "Stopping nginx: nginx.\r\n"
        "Stopping MySQL database server: mysqld.\r\n"
        "Stopping OpenBSD Secure Shell server: sshd.\r\n"
        "Unmounting local filesystems...\r\n"
    )
    return out


def _forkbomb_output() -> str:
    ts = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    return (
        "-bash: fork: Cannot allocate memory\r\n" * 6
        + "\r\n"
        + f"Broadcast message from root@ubuntu-srv (pts/0) ({ts}):\r\n"
        + "The system is going down for reboot NOW!\r\n"
        + "\r\n"
        + "INIT: Switching to runlevel: 6\r\n"
        + "Stopping OpenBSD Secure Shell server: sshd.\r\n"
    )


def _classify_destructive(command: str) -> str:
    """Return 'nuclear', 'warn', 'forkbomb', or '' for normal commands."""
    stripped = command.replace(" ", "")
    if _FORKBOMB.search(command) or ":(){" in stripped:
        return "forkbomb"
    if "--no-preserve-root" in command and _RM_SAFE.search(command):
        return "nuclear"
    if _RM_SAFE.search(command):
        return "warn"
    return ""
from utils.terminal import sanitize_for_llm, process_backspaces
from utils.session import SessionInfo, get_session_manager


class SessionStateTracker:
    """
    Tracks the execution state of a shell session.
    
    The LLM needs to know:
    - Where the attacker is (cwd)
    - What environment they have (env vars)
    - What they're typing (buffer)
    
    This class maintains that state and updates it as commands execute.
    """
    
    def __init__(self):
        """Initialize the state tracker."""
        # Map of session_id -> state dict
        self.session_states: Dict[str, Dict[str, Any]] = {}
    
    def initialize_state(
        self,
        session_id: str,
        env_vars: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """
        Initialize state for a new session.
        
        Args:
            session_id: Unique session identifier
            env_vars: Environment variables from authentication handshake
        
        Returns:
            Initial state dictionary
        """
        state = {
            'cwd': '/home/ubuntu',  # Default — overridden per-session by initialize_llm_session
            'env': env_vars or {},
            'buffer': '',
            'previous_cwd': None,  # For 'cd -' support
            'history': [],  # Command history
        }
        
        self.session_states[session_id] = state
        log.msg(f"Initialized state for session {session_id}: cwd={state['cwd']}")
        
        return state
    
    def get_state(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the current state for a session.
        
        Args:
            session_id: Session identifier
        
        Returns:
            State dict or None if not found
        """
        return self.session_states.get(session_id)

    def ensure_state(
        self,
        session_id: str,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Get an existing state or create a new one on demand."""
        state = self.get_state(session_id)
        if state is None:
            state = self.initialize_state(session_id, env_vars)
        elif env_vars:
            state['env'].update(env_vars)
        return state

    def update_environment(
        self,
        session_id: str,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Merge newly observed environment variables into session state."""
        state = self.ensure_state(session_id)
        if env_vars:
            state['env'].update(env_vars)
        return state

    def update_buffer(self, session_id: str, buffer: bytes | str) -> str:
        """
        Store the current line buffer after applying terminal cleanup.

        The shell buffer is what the attacker is typing right now, not yet
        executed. It is updated incrementally by the terminal protocol.
        """
        state = self.ensure_state(session_id)
        if isinstance(buffer, bytes):
            cleaned_buffer = sanitize_for_llm(process_backspaces(buffer)).strip("\r\n")
        else:
            cleaned_buffer = buffer.strip("\r\n")
        state['buffer'] = cleaned_buffer
        return cleaned_buffer

    def freeze_buffer(self, session_id: str, fallback: bytes | str = b"") -> str:
        """
        Freeze the current line on Enter, then clear the live typing buffer.
        """
        state = self.ensure_state(session_id)
        frozen_buffer = state.get('buffer', '')
        if not frozen_buffer:
            frozen_buffer = self.update_buffer(session_id, fallback)
        state['buffer'] = ''
        return frozen_buffer
    
    def _resolve_path(self, cwd: str, path: str) -> str:
        """
        Resolve a path relative to the current working directory.
        
        This is a HONEYPOT PATH RESOLVER - we don't actually access the filesystem,
        we just simulate it for the LLM.
        
        Args:
            cwd: Current working directory
            path: Path to resolve (can be relative or absolute)
        
        Returns:
            Resolved absolute path
        """
        # If path is absolute, use it directly
        if path.startswith('/'):
            return posixpath.normpath(path)

        # If path is relative, resolve from cwd
        resolved = posixpath.join(cwd, path)
        normalized = posixpath.normpath(resolved)
        
        return normalized
    
    def update_cwd_from_command(self, session_id: str, command: str) -> bool:
        """
        Parse a command and update cwd if it's a 'cd' command.
        
        Args:
            session_id: Session identifier
            command: The command that was executed
        
        Returns:
            True if cwd was updated, False otherwise
        """
        state = self.get_state(session_id)
        if not state:
            return False
        
        # Tokenize command (simple split on whitespace)
        tokens = command.split()
        if not tokens:
            return False
        
        cmd = tokens[0].lower()
        
        # Handle 'cd' command
        if cmd == 'cd':
            old_cwd = state['cwd']
            home = state.get('home_dir', '/home/ubuntu')

            if len(tokens) == 1:
                state['previous_cwd'] = old_cwd
                state['cwd'] = home
            elif tokens[1] == '-':
                if state['previous_cwd']:
                    target = state['previous_cwd']
                    state['previous_cwd'] = old_cwd
                    state['cwd'] = target
            elif tokens[1] in ('~', f'~{state.get("home_dir", "")}'.rstrip('/')):
                state['previous_cwd'] = old_cwd
                state['cwd'] = home
            else:
                target_path = tokens[1]
                new_cwd = self._resolve_path(old_cwd, target_path)
                state['previous_cwd'] = old_cwd
                state['cwd'] = new_cwd
            
            log.msg(
                f"Session {session_id} changed directory",
                from_cwd=old_cwd,
                to_cwd=state['cwd'],
            )
            
            return True
        
        # Handle 'pwd' command (just logs current directory)
        elif cmd == 'pwd':
            log.msg(f"Session {session_id} queried cwd: {state['cwd']}")
            return False
        
        return False
    
    def build_execution_payload(
        self,
        session_id: str,
        command: str,
        username: str = "unknown",
        source_ip: str = "0.0.0.0",
    ) -> Dict[str, Any]:
        """
        Build JSON payload for LLM execution context.
        
        This wraps the command with all relevant state (cwd, env, session info)
        that the LLM needs to properly analyze and respond.
        
        Args:
            session_id: Session identifier
            command: The command being executed
            username: SSH username
            source_ip: Source IP address
        
        Returns:
            Payload dictionary ready for JSON serialization
        """
        state = self.get_state(session_id)
        if not state:
            return {'error': 'Session state not found'}
        
        # Create execution context
        payload = {
            'session_id': session_id,
            'timestamp': time.time(),
            'user': {
                'username': username,
                'source_ip': source_ip,
            },
            'execution': {
                'cwd': state['cwd'],
                'command': command,
                'environment': state['env'],
            },
            'state': {
                'buffer': state.get('buffer', ''),
                'previous_cwd': state.get('previous_cwd'),
                'history_count': len(state.get('history', [])),
            },
        }
        
        return payload
    
    def record_command(
        self,
        session_id: str,
        command: str,
    ) -> None:
        """
        Record a command in session history.
        
        Args:
            session_id: Session identifier
            command: The command to record
        """
        state = self.get_state(session_id)
        if state:
            state['history'].append({
                'command': command,
                'cwd': state['cwd'],
                'timestamp': time.time(),
            })
            
            # Keep history limit to prevent memory exhaustion
            if len(state['history']) > 1000:
                state['history'] = state['history'][-500:]
    
    def get_state_for_llm(self, session_id: str) -> Dict[str, str]:
        """
        Get a formatted state dictionary suitable for LLM context.
        
        Args:
            session_id: Session identifier
        
        Returns:
            Dict with 'cwd' and 'env' keys
        """
        state = self.get_state(session_id)
        if not state:
            return {'cwd': '/home/user', 'env': {}}
        
        return {
            'cwd': state['cwd'],
            'env': state['env'],
            'buffer': state.get('buffer', ''),
        }
    
    def cleanup_state(self, session_id: str) -> None:
        """
        Cleanup state when session ends.
        
        Args:
            session_id: Session identifier
        """
        if session_id in self.session_states:
            state = self.session_states.pop(session_id)
            log.msg(
                f"Cleaned up state for session {session_id}",
                final_cwd=state['cwd'],
                commands_executed=len(state.get('history', [])),
            )


class ShellCommandBridge:
    """
    Bridge between terminal protocols and LLM.
    
    This class processes commands from SSH/Telnet sessions and routes them
    to the Ollama LLM for analysis.
    """
    
    def __init__(self):
        """Initialize the shell bridge."""
        self.ollama_client = OllamaClient()
        self.session_manager = get_session_manager()
        self.state_tracker = SessionStateTracker()
        
        self.last_command_hash: Dict[str, int] = {}
        self.duplicate_threshold: int = 5
        self._session_created: Dict[str, set] = {}
        self._session_destroyed: Dict[str, bool] = {}

    # ------------------------------------------------------------------
    # Local command interceptor — instant responses, no LLM call.
    # Appends to LLM history so follow-up commands have context.
    # ------------------------------------------------------------------

    def _intercept_one(self, session_id: str, cmd: str, cwd: str) -> Optional[str]:
        """
        Handle one simple command locally without the LLM.
        Returns the response string (may be empty) or None if LLM is needed.
        """
        from LLM.client import _FS_CONTENTS

        parts = cmd.strip().split(None, 1)
        if not parts:
            return ""
        verb = parts[0].lower()
        args = parts[1].strip() if len(parts) > 1 else ""

        if verb == "whoami":
            return "root"
        if verb == "hostname":
            meta = self.ollama_client._session_meta.get(session_id, {})
            return meta.get("hostname", "ubuntu-srv")
        if verb == "pwd":
            return cwd
        if verb == "id":
            return "uid=0(root) gid=0(root) groups=0(root)"
        if verb in ("export", "unset", "unalias", "source", "."):
            return ""
        if verb == "alias":
            if args:
                return ""  # alias definition — silent
            return (
                "alias alert='notify-send --urgency=low -i "
                "\"$([ $? = 0 ] && echo terminal || echo error)\" "
                "\"$(history|tail -n1|sed -e 's/^\\s*[0-9]\\+\\s*//;s/[;&|]\\s*alert$//')\"'\n"
                "alias egrep='egrep --color=auto'\n"
                "alias fgrep='fgrep --color=auto'\n"
                "alias grep='grep --color=auto'\n"
                "alias l='ls -CF'\n"
                "alias la='ls -A'\n"
                "alias ll='ls -alF'\n"
                "alias ls='ls --color=auto'"
            )
        if verb in ("chmod", "chown", "chgrp", "kill", "killall", "rm"):
            return ""
        if verb == "echo":
            # Handle output redirection silently and track the created file
            for redir in (">>", ">"):
                if redir in args:
                    file_part = args.split(redir, 1)[1].strip()
                    full_path = posixpath.normpath(posixpath.join(cwd, file_part))
                    self._session_created.setdefault(session_id, set()).add(full_path)
                    return ""
            return args
        if verb == "clear":
            return "\033[2J\033[H"

        if verb == "cd":
            target_arg = args.split()[0] if args.split() else ""
            if not target_arg or target_arg == "~":
                new_path = "/root"
            elif target_arg == "-":
                return None  # state tracker handles cd -
            elif target_arg.startswith("/"):
                new_path = target_arg.rstrip("/") or "/"
            else:
                new_path = posixpath.normpath(posixpath.join(cwd, target_arg))
            norm = new_path.rstrip("/") or "/"

            if norm in _FS_CONTENTS:
                return ""  # silent success

            session_paths = self._session_created.get(session_id, set())
            if norm in session_paths:
                return ""  # attacker-created dir

            # Check if it's a FILE in the parent dir (Not a directory)
            parent = posixpath.dirname(norm)
            basename = posixpath.basename(norm)
            if parent in _FS_CONTENTS:
                all_items = set(_FS_CONTENTS[parent].split()) | {
                    posixpath.basename(p) for p in session_paths if posixpath.dirname(p) == parent
                }
                if basename in all_items:
                    return f"bash: cd: {target_arg}: Not a directory"

            return f"bash: cd: {target_arg}: No such file or directory"

        if verb == "history":
            cmds = [
                "cat /etc/shadow", "mysql -u admin -p'P@ssw0rd123!'",
                "cd /var/www/html", "git pull origin main", "git push origin main",
                "vi /etc/nginx/nginx.conf", "systemctl restart nginx",
                "tail -f /var/log/nginx/error.log", "cat .aws/credentials",
                "aws s3 ls s3://prod-backups-2023", "df -h",
                "netstat -tulnp", "cat /etc/hosts",
            ]
            return "\n".join(f"  {i+1}  {c}" for i, c in enumerate(cmds))

        if verb == "date":
            from datetime import datetime
            return datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")

        if verb == "uptime":
            from datetime import datetime
            t = datetime.now().strftime("%H:%M:%S")
            return f" {t} up 6 days, 14:23,  1 user,  load average: 0.08, 0.12, 0.09"

        if verb == "uname":
            if not args:
                return "Linux"
            if "-a" in args:
                return "Linux ubuntu-srv 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
            out = []
            if "-s" in args: out.append("Linux")
            if "-n" in args: out.append("ubuntu-srv")
            if "-r" in args: out.append("5.15.0-91-generic")
            if "-m" in args or "-p" in args or "-i" in args: out.append("x86_64")
            if "-o" in args: out.append("GNU/Linux")
            return " ".join(out) if out else "Linux"

        if verb == "which":
            _which = {
                "python3": "/usr/bin/python3", "python": "/usr/bin/python3",
                "bash": "/bin/bash", "sh": "/bin/sh",
                "curl": "/usr/bin/curl", "wget": "/usr/bin/wget",
                "nc": "/usr/bin/nc", "netcat": "/usr/bin/netcat",
                "vim": "/usr/bin/vim", "vi": "/usr/bin/vi", "nano": "/usr/bin/nano",
                "cat": "/bin/cat", "ls": "/bin/ls", "grep": "/bin/grep",
                "awk": "/usr/bin/awk", "find": "/usr/bin/find",
                "ssh": "/usr/bin/ssh", "scp": "/usr/bin/scp",
                "git": "/usr/bin/git", "mysql": "/usr/bin/mysql",
                "nginx": "/usr/sbin/nginx", "perl": "/usr/bin/perl",
                "ruby": "", "nmap": "", "gcc": "/usr/bin/gcc",
            }
            tool = args.strip()
            if tool in _which:
                return _which[tool] if _which[tool] else f"which: no {tool} in ($PATH)"
            return None  # unknown tool — let LLM decide

        if verb == "cat":
            paths = [a for a in args.split() if not a.startswith("-")]
            if not paths:
                return None
            outputs = []
            for p in paths:
                full = p if p.startswith("/") else posixpath.normpath(posixpath.join(cwd, p))
                if full in _STATIC_FILES:
                    outputs.append(_STATIC_FILES[full])
                    continue
                # Check seed fast-lookup (covers .bash_history, /etc/hosts, .aws/credentials, etc.)
                fast = self.ollama_client._fast_lookup.get(session_id, {})
                cat_key = f"cat {p}"
                if cat_key in fast:
                    outputs.append(fast[cat_key])
                    continue
                # File listed in FS but no static content → LLM
                parent_dir = posixpath.dirname(full)
                basename = posixpath.basename(full)
                if parent_dir in _FS_CONTENTS and basename in _FS_CONTENTS[parent_dir].split():
                    return None
                outputs.append(f"cat: {p}: No such file or directory")
            return "\n".join(outputs)

        if verb in ("ifconfig",):
            return _IFCONFIG

        if verb == "ip":
            sub = args.strip().split()[0].lower() if args.strip() else ""
            if sub in ("addr", "a", "address", "link"):
                return _IP_ADDR
            return None

        if verb == "netstat":
            return _NETSTAT

        if verb == "ss":
            return _SS

        if verb in ("df",):
            return _DF

        if verb == "free":
            return _FREE

        if verb in ("last", "lastlog"):
            return _LAST

        if verb == "crontab":
            if "-l" in args:
                return _CRONTAB
            return None

        if verb == "lsof":
            return _NETSTAT  # close enough for -i usage

        if verb in ("w", "who"):
            from datetime import datetime
            t = datetime.now().strftime("%H:%M")
            return f" {t} up 6 days, 14:23,  1 user,  load average: 0.08, 0.12, 0.09\nUSER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\nroot     pts/0    10.0.0.15        12:35    0.00s  0.04s  0.00s w"

        if verb == "ps":
            fast = self.ollama_client._fast_lookup.get(session_id, {})
            key = ("ps " + args).strip()
            if key in fast:
                return fast[key]
            return None  # exotic ps options → LLM

        if verb in ("env", "printenv"):
            return (
                "SHELL=/bin/bash\nTERM=xterm-256color\nUSER=root\nLOGNAME=root\n"
                "HOME=/root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                "LANG=en_US.UTF-8\nHISTFILE=/root/.bash_history\nHISTSIZE=1000\n"
                "SSH_TTY=/dev/pts/0\nSSH_CLIENT=10.0.0.15 54321 22"
            )

        if verb == "file":
            path_arg = args.strip().split()[0] if args.strip() else ""
            full = path_arg if path_arg.startswith("/") else posixpath.normpath(posixpath.join(cwd, path_arg))
            parent_dir = posixpath.dirname(full)
            basename = posixpath.basename(full)
            if full in _FS_CONTENTS:
                return f"{path_arg}: directory"
            if parent_dir in _FS_CONTENTS and basename in _FS_CONTENTS[parent_dir].split():
                return f"{path_arg}: ASCII text"
            return f"{path_arg}: cannot open (No such file or directory)"

        if verb == "mkdir":
            if not args:
                return "mkdir: missing operand"
            for name in args.split():
                if name.startswith("-"):
                    continue
                full = posixpath.normpath(posixpath.join(cwd, name))
                self._session_created.setdefault(session_id, set()).add(full)
            return ""

        if verb == "touch":
            for name in args.split():
                if name.startswith("-"):
                    continue
                full = posixpath.normpath(posixpath.join(cwd, name))
                self._session_created.setdefault(session_id, set()).add(full)
            return ""

        if verb in ("wget", "curl"):
            url_match = re.search(r'https?://\S+', args)
            url_str = url_match.group() if url_match else args.strip()
            host = url_str.split("//")[-1].split("/")[0]
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if verb == "wget":
                return (
                    f"--{now}--  {url_str}\n"
                    f"Resolving {host} ({host})... 203.0.113.42\n"
                    f"Connecting to {host} ({host})|203.0.113.42|:80... "
                    f"failed: Connection timed out.\n\n"
                    f"FINISHED --{now}--\n"
                    f"Total wall clock time: 30s\n"
                    f"Downloaded: 0 files, 0 in 0s (0 B/s)"
                )
            else:
                return f"curl: (6) Could not resolve host: {host}"

        if verb in ("python3", "python"):
            m = re.match(r"""-c\s+["']print\(["']([^"']*)["']\)["']""", args)
            if m:
                return m.group(1)
            return None

        if verb == "grep":
            recursive = "-r" in args or "-R" in args
            if not recursive:
                return None
            case_i_flag = "-i" in args
            re_flags_g = re.IGNORECASE if case_i_flag else 0
            toks = args.split()
            non_flags = [t for t in toks if not t.startswith("-")]
            if not non_flags:
                return None
            pattern = non_flags[0].strip("\"'")
            sp = non_flags[1] if len(non_flags) > 1 else "."
            if sp in (".", "~"):
                search_root = cwd
            elif sp.startswith("/"):
                search_root = sp.rstrip("/") or "/"
            else:
                search_root = posixpath.normpath(posixpath.join(cwd, sp))
            results = []
            for fpath, content in _STATIC_FILES.items():
                norm_fp = fpath.rstrip("/")
                if not (norm_fp == search_root or norm_fp.startswith(search_root + "/")):
                    continue
                for line in content.split("\n"):
                    if re.search(pattern, line, re_flags_g):
                        cwd_clean = cwd.rstrip("/")
                        rel = ("." + norm_fp[len(cwd_clean):]) if norm_fp.startswith(cwd_clean + "/") else norm_fp
                        results.append(f"{rel}:{line}")
            fast = self.ollama_client._fast_lookup.get(session_id, {})
            bash_hist = fast.get("cat .bash_history", "")
            if bash_hist:
                hist_abs = posixpath.join(cwd, ".bash_history")
                if hist_abs.startswith(search_root) or search_root == cwd:
                    for line in bash_hist.split("\n"):
                        if re.search(pattern, line, re_flags_g):
                            results.append(f"./.bash_history:{line}")
            return "\n".join(results)

        if verb == "ls":
            # Check seed fast-lookup first (handles "ls -la /home" etc.)
            full_cmd = ("ls " + args).strip()
            seed_fast = self.ollama_client._fast_lookup.get(session_id, {})
            if full_cmd != "ls" and full_cmd in seed_fast:
                return seed_fast[full_cmd]

            flags = ""
            path_arg = None
            for tok in args.split():
                if tok.startswith("-"):
                    flags += tok[1:]
                else:
                    path_arg = tok
                    break

            if path_arg is not None:
                target = path_arg if path_arg.startswith("/") else posixpath.normpath(posixpath.join(cwd, path_arg))
                target = target.rstrip("/") or "/"
                display = path_arg
            else:
                target = cwd.rstrip("/") or "/"
                display = "."

            session_paths = self._session_created.get(session_id, set())

            # Merge static FS with any session-created children
            if target in _FS_CONTENTS:
                static = [x for x in _FS_CONTENTS[target].split() if x]
                created = [posixpath.basename(p) for p in session_paths if posixpath.dirname(p) == target]
                items = static + [c for c in created if c not in static]
                combined = "  ".join(items)
                if "R" in flags:
                    return f"{display}:\n{combined}".rstrip()
                return combined

            # Session-created directory
            if target in session_paths:
                children = [posixpath.basename(p) for p in session_paths if posixpath.dirname(p) == target]
                if "R" in flags:
                    return f"{display}:\n" + "\n".join(children)
                return "  ".join(children) if children else ""

            if path_arg is not None:
                return f"ls: cannot access '{path_arg}': No such file or directory"
            return None

        return None  # needs LLM

    def _apply_filter(self, text: str, filter_cmd: str) -> Optional[str]:
        """Apply a single pipe filter (grep, head, tail, wc, cut, awk, sort) to text."""
        parts = filter_cmd.strip().split(None, 1)
        if not parts:
            return text
        verb = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        if verb == "grep":
            invert = "-v" in args
            case_i = "-i" in args
            toks = [t for t in args.split() if not t.startswith("-")]
            pattern = toks[0] if toks else ""
            if not pattern:
                return text
            flags = re.IGNORECASE if case_i else 0
            lines = text.split("\n")
            filtered = [l for l in lines if bool(re.search(pattern, l, flags)) != invert]
            return "\n".join(filtered)

        if verb == "wc":
            if "-l" in args:
                return str(len([l for l in text.split("\n") if l]))
            if "-w" in args:
                return str(len(text.split()))
            return str(len(text))

        if verb == "head":
            n = 10
            for t in args.split():
                if t.startswith("-") and t[1:].isdigit():
                    n = int(t[1:])
            return "\n".join(text.split("\n")[:n])

        if verb == "tail":
            n = 10
            for t in args.split():
                if t.startswith("-") and t[1:].isdigit():
                    n = int(t[1:])
            return "\n".join(text.split("\n")[-n:])

        if verb == "cut":
            delim, fields = "\t", []
            toks = args.split()
            i = 0
            while i < len(toks):
                if toks[i] in ("-d",) and i + 1 < len(toks):
                    delim = toks[i + 1]; i += 2
                elif toks[i].startswith("-d"):
                    delim = toks[i][2:]; i += 1
                elif toks[i] in ("-f",) and i + 1 < len(toks):
                    fields = [int(x) - 1 for x in toks[i + 1].split(",") if x.isdigit()]; i += 2
                elif toks[i].startswith("-f"):
                    fields = [int(x) - 1 for x in toks[i][2:].split(",") if x.isdigit()]; i += 1
                else:
                    i += 1
            if not fields:
                return text
            out = []
            for line in text.split("\n"):
                p = line.split(delim)
                out.append(delim.join(p[f] for f in fields if f < len(p)))
            return "\n".join(out)

        if verb == "awk":
            m = re.search(r'\{print \$(\d+)\}', args)
            if m:
                idx = int(m.group(1)) - 1
                return "\n".join((l.split()[idx] if idx < len(l.split()) else "") for l in text.split("\n") if l.split())
            m2 = re.search(r"-F([^' ]+).*\{print \$(\d+)\}", args)
            if m2:
                delim, idx = m2.group(1), int(m2.group(2)) - 1
                return "\n".join((l.split(delim)[idx] if idx < len(l.split(delim)) else "") for l in text.split("\n") if l)
            return None

        if verb == "sort":
            lines = text.split("\n")
            return "\n".join(sorted(lines, reverse="-r" in args))

        if verb == "uniq":
            seen: set = set()
            out = []
            for l in text.split("\n"):
                if l not in seen:
                    seen.add(l); out.append(l)
            return "\n".join(out)

        if verb == "tr":
            toks = args.split()
            if len(toks) >= 2:
                if "-d" in args:
                    chars = toks[-1]
                    return text.translate(str.maketrans("", "", chars))
                if len(toks) == 2:
                    table = str.maketrans(toks[0], toks[1])
                    return text.translate(table)
            return text

        return None  # unsupported filter — needs LLM

    def _intercept_piped(self, session_id: str, command: str, cwd: str) -> Optional[str]:
        """Handle pipe chains locally if every stage is interceptable."""
        stages = [s.strip() for s in command.split("|")]
        # First stage must be a local command
        result = self._intercept_one(session_id, stages[0], cwd)
        if result is None:
            return None
        # Apply each filter stage
        for stage in stages[1:]:
            result = self._apply_filter(result, stage)
            if result is None:
                return None
        return result

    def _intercept_compound(
        self, session_id: str, command: str, cwd: str
    ) -> Optional[str]:
        """
        Try to handle a compound (&&-separated or pipe) command locally.
        Returns combined output or None if any part needs the LLM.
        Also appends every handled sub-command to LLM history.
        """
        # Pipes take priority over &&
        if "|" in command:
            result = self._intercept_piped(session_id, command, cwd)
            if result is not None:
                self.ollama_client._append(session_id, "user", f"[{cwd}]# {command}")
                self.ollama_client._append(session_id, "assistant", result)
            return result

        parts = re.split(r'\s*(?:&&|;)\s*', command)
        responses: list = []
        for part in parts:
            r = self._intercept_one(session_id, part.strip(), cwd)
            if r is None:
                return None
            responses.append(r)
            self.ollama_client._append(session_id, "user", f"[{cwd}]# {part.strip()}")
            self.ollama_client._append(session_id, "assistant", r)
        return "\n".join(r for r in responses if r)

    # ------------------------------------------------------------------

    def update_session_environment(
        self,
        session_id: str,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Public wrapper for environment updates from protocol handlers."""
        return self.state_tracker.update_environment(session_id, env_vars)

    def update_session_buffer(self, session_id: str, buffer: bytes | str) -> str:
        """Public wrapper for live line-buffer updates from protocol handlers."""
        return self.state_tracker.update_buffer(session_id, buffer)

    def _get_or_create_session(self, session_id: str, protocol: str) -> SessionInfo:
        """
        Ensure command processing still works even if session registration
        has not been wired in yet by the transport layer.
        """
        session = self.session_manager.get_session(session_id)
        if session is None:
            session = SessionInfo("0.0.0.0", 0, "0.0.0.0", 0)
            session.session_id = session_id
            session.protocol = protocol
            self.session_manager.sessions[session_id] = session
        return session
    
    def initialize_session_state(
        self,
        session_id: str,
        environment_vars: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """
        Initialize state tracking for a new session.
        
        This should be called when a session is first created.
        
        Args:
            session_id: Unique session identifier
            environment_vars: Environment variables from authentication
        
        Returns:
            Initial state dictionary
        """
        return self.state_tracker.ensure_state(session_id, environment_vars)

    def initialize_llm_session(
        self,
        session_id: str,
        username: str = "ubuntu",
        hostname: str = "ubuntu-srv",
    ) -> None:
        """
        Seed the LLM with the attacker's identity and set the session cwd
        to the correct home directory for that user.
        """
        self.ollama_client.initialize_session(session_id, username, hostname)
        home = "/root" if username == "root" else f"/home/{username}"
        state = self.state_tracker.ensure_state(session_id)
        state["cwd"] = home
        state["home_dir"] = home

    def process_shell_command(
        self,
        session_id: str,
        command: bytes,
        protocol: str = "ssh",
    ) -> Dict[str, Any]:
        """
        Main entry point for processing shell commands.
        
        This should be called by Term.py and TelnetHandler when a complete
        command is ready (i.e., when Enter is pressed).
        
        Args:
            session_id: Unique session identifier
            command: Raw command bytes (may contain backspaces, control chars)
            protocol: Protocol type ('ssh', 'telnet')
        
        Returns:
            Dictionary with LLM analysis results and execution context
        
        EXECUTION TRIGGER: This is called when \r (Enter key) is detected.
        The buffer is frozen here and sent to the LLM.
        """
        
        # Get session info
        session = self._get_or_create_session(session_id, protocol)
        
        # Freeze the live line buffer at the moment Enter was pressed.
        frozen_buffer = self.state_tracker.freeze_buffer(session_id, command)

        # Clean up command
        try:
            cleaned_command = frozen_buffer or self._sanitize_command(command)
        except Exception as e:
            log.err(f"Error sanitizing command: {e}")
            return {"error": f"Command sanitization failed: {e}"}
        
        if not cleaned_command or cleaned_command.isspace():
            return {"empty": True}

        # Broken shell: system was destroyed this session
        if self._session_destroyed.get(session_id):
            cmd = cleaned_command.strip().split()[0] if cleaned_command.strip() else cleaned_command
            return {
                "terminal_response": f"sh: 1: {cmd}: not found\r\n".encode(),
                "command": cleaned_command,
            }

        # pwd: answer from state tracker instantly, no LLM call
        if cleaned_command.strip() in ("pwd",):
            state = self.state_tracker.get_state(session_id)
            cwd = state.get("cwd", "/root") if state else "/root"
            return {"terminal_response": (cwd + "\r\n").encode(), "command": cleaned_command}

        # Destructive command simulation
        destructive = _classify_destructive(cleaned_command)
        if destructive == "warn":
            return {"terminal_response": _RM_RF_WARNING.encode(), "command": cleaned_command}
        if destructive == "nuclear":
            self._session_destroyed[session_id] = True
            return {
                "terminal_response": _nuclear_output().encode(),
                "command": cleaned_command,
                "system_destroyed": True,
            }
        if destructive == "forkbomb":
            return {"terminal_response": _forkbomb_output().encode(), "command": cleaned_command, "disconnect": True}

        # Local interceptor — instant for simple & compound commands
        _state = self.state_tracker.get_state(session_id)
        _cwd = _state.get("cwd", "/root") if _state else "/root"
        local_out = self._intercept_compound(session_id, cleaned_command, _cwd)
        if local_out is not None:
            if local_out:
                # Normalise line endings: bare \n becomes \r\n for SSH terminals
                normalised = local_out.replace("\r\n", "\n").replace("\n", "\r\n")
                resp = (normalised + "\r\n").encode("utf-8", errors="replace")
            else:
                resp = b""
            # Sync cwd when cd succeeded locally (empty output = bash success)
            first_tok = cleaned_command.strip().split()[0].lower() if cleaned_command.strip() else ""
            if first_tok == "cd" and not local_out:
                self.state_tracker.update_cwd_from_command(session_id, cleaned_command)
            return {"terminal_response": resp, "command": cleaned_command}

        # Check for duplicate commands (rate limiting)
        if self._is_duplicate_command(session_id, cleaned_command):
            log.msg(f"Duplicate command detected for session {session_id}")
            return {"duplicate": True}
        
        # Record command in state history
        self.state_tracker.record_command(session_id, cleaned_command)
        
        # Record this command in the session
        session.record_command(cleaned_command)
        
        # Build execution payload with current state (cwd, env)
        execution_payload = self.state_tracker.build_execution_payload(
            session_id=session_id,
            command=cleaned_command,
            username=session.username or "unknown",
            source_ip=session.source_ip or "0.0.0.0",
        )
        execution_payload.setdefault('state', {})['buffer'] = cleaned_command
        llm_payload_json = json.dumps(execution_payload, ensure_ascii=True)
        
        # Build context for LLM
        context = self._build_llm_context(session, cleaned_command, protocol)
        
        # Get state for LLM (cwd, env)
        state = self.state_tracker.get_state_for_llm(session_id)
        
        # Log command for debugging
        log.msg(
            f"Session {session_id} ({protocol}): Processing command",
            command=cleaned_command[:100],  # Truncate for logging
            cwd=state.get('cwd', '/home/user'),
            username=session.username,
        )
        
        llm_response_text = self._call_llm_string(
            session=session,
            protocol=protocol,
            command=cleaned_command,
            execution_payload=execution_payload,
        )

        # Only update cwd after the LLM confirms cd succeeded (no output = success in bash)
        first_token = cleaned_command.split()[0].lower() if cleaned_command.split() else ""
        if first_token == "cd" and not llm_response_text.strip():
            self.state_tracker.update_cwd_from_command(session_id, cleaned_command)

        terminal_response = self.format_response_for_terminal(
            {
                'error': execution_payload.get('error'),
                'llm_response': llm_response_text,
            },
            session,
        )

        # Build the result with full context
        result = {
            'session_id': session_id,
            'command': cleaned_command,
            'context': context,
            'llm_payload_json': llm_payload_json,
            'execution_payload': execution_payload,  # Send cwd, env to LLM
            'state': state,  # Current cwd and env
            'llm_response': llm_response_text,
            'terminal_response': terminal_response,
            'status': 'analysis_complete',
        }

        return result

    def _call_llm_string(
        self,
        session: SessionInfo,
        protocol: str,
        command: str,
        execution_payload: Dict[str, Any],
    ) -> str:
        """
        Call the LLM module synchronously and coerce the result into a string.
        """
        try:
            llm_result = self.ollama_client.process_command_execution(
                session_id=session.session_id,
                command=command.encode("utf-8", errors="replace"),
                channel_type=protocol,
                username=session.username,
                source_ip=session.source_ip,
                environment=execution_payload['execution']['environment'],
                cwd=execution_payload['execution']['cwd'],
            )
        except Exception as e:
            log.err(f"LLM command execution failed for session {session.session_id}: {e}")
            return ""

        if isinstance(llm_result, str):
            return llm_result

        if isinstance(llm_result, dict):
            for key in ("response", "output", "text", "message"):
                value = llm_result.get(key)
                if isinstance(value, str):
                    return value

            meaningful_result = {
                key: value
                for key, value in llm_result.items()
                if value not in (None, "", [], {})
            }
            if meaningful_result:
                return json.dumps(meaningful_result, ensure_ascii=True)

        return ""
    
    def _sanitize_command(self, command: bytes) -> str:
        """
        Sanitize command for LLM processing.
        
        Args:
            command: Raw command bytes
        
        Returns:
            Clean command string
        """
        # Process backspaces first
        cleaned = process_backspaces(command)
        
        # Use the comprehensive sanitization utility
        sanitized = sanitize_for_llm(cleaned)
        
        # Remove any remaining whitespace
        sanitized = sanitized.strip()
        
        return sanitized
    
    def _is_duplicate_command(self, session_id: str, command: str) -> bool:
        """
        Check if this is a duplicate command sent recently.
        
        Args:
            session_id: Session identifier
            command: Command to check
        
        Returns:
            True if duplicate, False otherwise
        """
        import hashlib
        
        cmd_hash = hashlib.md5(command.encode()).hexdigest()
        key = f"{session_id}:{cmd_hash}"
        
        current_time = time.time()
        
        if key in self.last_command_hash:
            elapsed = current_time - self.last_command_hash[key]
            if elapsed < self.duplicate_threshold:
                return True
        
        # Update timestamp
        self.last_command_hash[key] = current_time
        
        # Cleanup old entries (older than 1 hour)
        for k in list(self.last_command_hash.keys()):
            if current_time - self.last_command_hash[k] > 3600:
                del self.last_command_hash[k]
        
        return False
    
    def _build_llm_context(
        self,
        session: SessionInfo,
        command: str,
        protocol: str,
    ) -> Dict[str, Any]:
        """
        Build context information to send to the LLM.
        
        Args:
            session: SessionInfo object with context
            command: The command being executed
            protocol: Protocol type
        
        Returns:
            Dictionary with contextual information for the LLM
        """
        return {
            'session_id': session.session_id,
            'username': session.username,
            'source_ip': session.source_ip,
            'protocol': protocol,
            'command': command,
            'terminal': {
                'type': session.terminal_type,
                'width': session.terminal_width,
                'height': session.terminal_height,
            },
            'environment': session.environment_vars,
            'telnet_options': session.telnet_options if protocol == 'telnet' else {},
            'authenticated': session.authenticated,
            'command_count': session.command_count,
            'session_duration': session.get_session_duration(),
        }
    
    def format_response_for_terminal(
        self,
        response: Dict[str, Any],
        session: SessionInfo,
    ) -> bytes:
        """
        Format LLM response for display in the terminal.
        
        This handles ANSI color codes based on terminal capabilities,
        and respects terminal dimensions for line wrapping.
        
        Args:
            response: LLM analysis results
            session: Session info (for terminal capabilities)
        
        Returns:
            Bytes ready to send back to the terminal
        
        TODO: Implement response formatting with ANSI codes if terminal supports it
        """
        
        # Check if terminal supports colors
        supports_color = session.terminal_type not in ['dumb', 'unknown', 'vt100']
        
        output = ""
        
        # TODO: Format response based on:
        # - Terminal type (TERM variable)
        # - Terminal width (for wrapping)
        # - Whether colors are supported
        
        # For now, just return a basic response
        if response.get('error'):
            output = f"[ERROR] {response['error']}\r\n"
        elif response.get('empty'):
            pass  # Don't output anything for empty commands
        elif response.get('duplicate'):
            pass  # Don't output anything for duplicate commands
        else:
            llm_response = response.get('llm_response', '')
            if llm_response:
                if not llm_response.endswith("\n"):
                    llm_response += "\n"
                output = llm_response.replace("\n", "\r\n")

        return output.encode()
    
    def cleanup_session(self, session_id: str) -> None:
        self.state_tracker.cleanup_state(session_id)
        self._session_created.pop(session_id, None)
        self._session_destroyed.pop(session_id, None)
        
        # Clean up session info
        session = self.session_manager.get_session(session_id)
        if session:
            session.close()
        
        # TODO: Clean up any cached data for this session
        # TODO: Send final metrics to logging system


# Global instance
_shell_bridge: Optional[ShellCommandBridge] = None


def get_shell_bridge() -> ShellCommandBridge:
    """Get or create the global shell command bridge."""
    global _shell_bridge
    if _shell_bridge is None:
        _shell_bridge = ShellCommandBridge()
    return _shell_bridge


def initialize_session_state(
    session_id: str,
    environment_vars: Dict[str, str] = None,
) -> Dict[str, Any]:
    """
    Initialize state tracking for a new session.
    
    Call this when a new SSH/Telnet session is created,
    passing in the captured environment variables.
    
    Usage in server/protocols/term.py or server/telnet/handler.py:
        from server.protocols.shell import initialize_session_state
        
        # When session starts:
        env_vars = {'TERM': 'xterm-256color', 'SHELL': '/bin/bash', ...}
        state = initialize_session_state(session_id, env_vars)
    
    Args:
        session_id: Unique session identifier
        environment_vars: Environment variables captured from authentication
    
    Returns:
        Initial state dictionary
    """
    bridge = get_shell_bridge()
    return bridge.initialize_session_state(session_id, environment_vars)


def initialize_llm_session(
    session_id: str,
    username: str = "root",
    hostname: str = "ubuntu-srv",
) -> None:
    """
    Seed the LLM with the attacker's identity for this session.

    Call this once after SSH authentication succeeds so the LLM's
    system prompt names the correct user, home directory, and hostname.

    Usage in server/protocols/term.py:
        from server.protocols.shell import initialize_llm_session
        initialize_llm_session(self.session_id, username=self.username or "root")
    """
    bridge = get_shell_bridge()
    bridge.initialize_llm_session(session_id, username, hostname)


def update_session_environment(
    session_id: str,
    environment_vars: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Merge newly captured handshake environment variables into session state."""
    bridge = get_shell_bridge()
    return bridge.update_session_environment(session_id, environment_vars)


def update_session_buffer(
    session_id: str,
    buffer: bytes | str,
) -> str:
    """Persist the attacker's current in-progress command line."""
    bridge = get_shell_bridge()
    return bridge.update_session_buffer(session_id, buffer)


def process_command(
    session_id: str,
    command: bytes,
    protocol: str = "ssh",
) -> Dict[str, Any]:
    """
    Convenient function to process a command through the bridge.
    
    This is called when a complete command is detected (Enter key / \r).
    
    Usage in your protocol handlers:
        from server.protocols.shell import process_command
        
        # When Enter is pressed in terminal:
        result = process_command(
            session_id=session_id,
            command=raw_command_bytes,
            protocol='ssh'  # or 'telnet'
        )
        # Result includes 'execution_payload' with cwd, env, command
        # Send to LLM which returns analysis
    
    Args:
        session_id: Unique session identifier
        command: Raw command bytes (may have backspaces, etc)
        protocol: Protocol type ('ssh' or 'telnet')
    
    Returns:
        Dictionary with analysis results and execution payload
    """
    bridge = get_shell_bridge()
    return bridge.process_shell_command(session_id, command, protocol)


def cleanup_session_state(session_id: str) -> None:
    """
    Cleanup state when a session ends.
    
    Call this when a session terminates.
    
    Usage:
        from server.protocols.shell import cleanup_session_state
        
        # When connection closes:
        cleanup_session_state(session_id)
    
    Args:
        session_id: Session identifier to cleanup
    """
    bridge = get_shell_bridge()
    bridge.cleanup_session(session_id)
