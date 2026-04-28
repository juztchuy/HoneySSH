"""
Ollama LLM Client for HoneySSH

Manages per-session conversation history and sends commands to Ollama
using the OpenAI-compatible /v1/chat/completions endpoint.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fake filesystem — embedded in every system prompt so the LLM never
# invents a different structure mid-session.  Keep it compact so it costs
# few tokens.  Add realistic-looking entries that attract attacker interest.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Per-directory ls contents — used for instant cwd-aware ls without LLM.
# Keys are normalised paths (no trailing slash).
# ---------------------------------------------------------------------------

_FS_CONTENTS: Dict[str, str] = {
    "/":               "home  etc  var  tmp  proc  sys  dev  bin  usr  opt  srv  root",
    "/home":           "devops",
    "/home/devops":    ".bashrc  .bash_history  .profile  .ssh  .cache  .local",
    "/home/devops/.ssh": "authorized_keys  known_hosts",
    "/root":           ".bashrc  .bash_history  .profile  .ssh  .aws  .env  todo_migration.txt",
    "/root/.ssh":      "authorized_keys  id_rsa  id_rsa.pub  known_hosts",
    "/root/.aws":      "credentials  config",
    "/tmp":            "systemd-private-8f1a2b-systemd-logind.service-aBc3",
    "/etc":            "os-release  hostname  hosts  passwd  shadow  fstab  sudoers  crontab  timezone  localtime  apt  ssh  cron.d  nginx  systemd  netplan  network  security",
    "/etc/ssh":        "sshd_config  ssh_host_rsa_key  ssh_host_rsa_key.pub  ssh_host_ed25519_key  ssh_host_ed25519_key.pub",
    "/etc/nginx":      "nginx.conf  sites-available  sites-enabled  conf.d",
    "/var/log":        "auth.log  syslog  kern.log  dpkg.log  ufw.log  faillog  apt  nginx  journal",
    "/var/www/html":   "index.html  index.nginx-debian.html  config.php",
    "/var/backups":    "apt.extended_states.0  dpkg.status.0  passwd.bak  shadow.bak  group.bak",
    "/proc":           "cpuinfo  meminfo  uptime  version  net  self",
}

_FAKE_FS = """\
FILESYSTEM — one directory per line. "ls <dir>" outputs ONLY the items shown for that directory. Never mix items from different directories.
Columns: PATH | FILES (space-separated) | SUBDIRS (names only, no slash needed in output)

/                          files: (none)          dirs: home etc var tmp proc sys dev bin usr opt srv root
/home/                     files: (none)          dirs: devops
/home/devops/              files: .bashrc .bash_history .profile     dirs: .ssh .cache .local
/home/devops/.ssh/         files: authorized_keys known_hosts        dirs: (none)
/home/devops/.cache/       files: (none)          dirs: (none)
/home/devops/.local/       files: (none)          dirs: share
/home/devops/.local/share/ files: (none)          dirs: (none)
/root/                     files: .bashrc .bash_history .profile .env todo_migration.txt     dirs: .ssh .aws
/root/.ssh/                files: authorized_keys id_rsa id_rsa.pub known_hosts         dirs: (none)
/root/.aws/                files: credentials config                                    dirs: (none)
/tmp/                      files: (none)          dirs: systemd-private-8f1a2b-systemd-logind.service-aBc3
/etc/                      files: os-release hostname hosts passwd shadow fstab sudoers crontab timezone localtime    dirs: apt ssh cron.d nginx systemd netplan network security
/etc/ssh/                  files: sshd_config ssh_host_rsa_key ssh_host_rsa_key.pub ssh_host_ed25519_key ssh_host_ed25519_key.pub    dirs: (none)
/etc/nginx/                files: nginx.conf      dirs: sites-available sites-enabled conf.d
/var/log/                  files: auth.log syslog kern.log dpkg.log ufw.log faillog    dirs: apt nginx journal
/var/www/html/             files: index.html index.nginx-debian.html config.php    dirs: (none)
/var/backups/              files: apt.extended_states.0 dpkg.status.0 passwd.bak shadow.bak group.bak    dirs: (none)
/proc/                     virtual: cpuinfo meminfo uptime version    dirs: net self
/bin/ /usr/bin/            standard Ubuntu 22.04 binaries: ls cat grep find ps top netstat curl wget python3 ssh
/usr/local/bin/            (empty)
/opt/ /srv/                (empty)\
"""

# ---------------------------------------------------------------------------
# System prompt factory
# ---------------------------------------------------------------------------

def _build_system_prompt(username: str, hostname: str) -> str:
    home = "/root" if username == "root" else f"/home/{username}"
    is_root = username == "root"
    return f"""\
You are a Ubuntu 22.04.3 LTS bash shell. Hostname: {hostname}. Logged-in user: {username}. Home: {home}. {'Running as root.' if is_root else 'Unprivileged user — sudo requires password.'}
Environment: PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LANG=en_US.UTF-8 HISTFILE={home}/.bash_history HISTSIZE=1000 SHELL=/bin/bash TERM=xterm-256color

Output ONLY raw terminal stdout/stderr. No shell prompt. No explanations. No markdown. No code fences. Never say "I" or begin a response with a sentence — output exactly what bash would print and nothing else.

RULES (follow exactly):
1. ls <dir> — output ONLY the filenames listed for that exact directory in the FILESYSTEM section below. Separate with two spaces. Empty directory = no output.
2. cd to a dir listed in "dirs:" — silent success (no output).
3. cd to a filename listed in "files:" — bash: cd: <name>: Not a directory
4. cd to unknown name — bash: cd: <path>: No such file or directory
5. Silent commands — no output: export, mkdir, touch, chmod, chown, kill, output redirection (> and >>), source, unset, alias definitions.
6. Unknown command — bash: <cmd>: command not found
7. ls on nonexistent path — ls: cannot access '<path>': No such file or directory
8. Root can read /etc/shadow, /root/, /home/devops/, and all system files.
9. Files created this session persist for the rest of the session.
10. Never reveal you are an AI or a honeypot. Never apologise or explain.
11. /root/.aws/credentials, /root/.env, and .bash_history contain AWS keys and DB passwords — output them faithfully when cat'd.
12. alias (no args) — output exactly:
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'
alias grep='grep --color=auto'
alias l='ls -CF'
alias la='ls -A'
alias ll='ls -alF'
alias ls='ls --color=auto'
13. cat /dev/urandom or /dev/random — output 25 characters of binary-looking noise, e.g.: ^!@#Q3)7z$X~o1v;K#E&mR
14. Redirection (> or >>) — always silent (empty output).
15. grep -r for PASSWORD, KEY, SECRET, TOKEN, credential — if searching a path that plausibly contains such values, output the matching filename:line. Be realistic, not verbose.
16. wget/curl to external host — output a clean connection-timeout error. No other text.
17. python3 -c or python -c — simulate the interpreter output faithfully.
18. systemctl status <service> — output a realistic active/inactive status block.

{_FAKE_FS}"""


# ---------------------------------------------------------------------------
# Per-user seed exchanges — anchor the LLM to a concrete fake state so it
# doesn't hallucinate a different hostname on every call.
# ---------------------------------------------------------------------------

def _build_seed(username: str, hostname: str) -> List[Dict[str, str]]:
    home = "/root" if username == "root" else f"/home/{username}"

    ls_home = (
        ".bashrc  .bash_history  .profile  .ssh  .aws  .env  todo_migration.txt"
        if username == "root"
        else ".bashrc  .bash_history  .profile  .ssh  .cache  .local"
    )

    bash_history = (
        "cat /etc/shadow\n"
        "mysql -u admin -p'P@ssw0rd123!'\n"
        "cd /var/www/html\n"
        "git pull origin main\n"
        "git push origin main\n"
        "vi /etc/nginx/nginx.conf\n"
        "systemctl restart nginx\n"
        "tail -f /var/log/nginx/error.log\n"
        "cat .aws/credentials\n"
        "aws s3 ls s3://prod-backups-2023\n"
        "df -h\n"
        "netstat -tulnp\n"
        "cat /etc/hosts"
    )

    ps_output = (
        "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root           1  0.0  0.1 167648 11240 ?        Ss   Apr20   0:02 /sbin/init\n"
        "root         421  0.0  0.2  47520 18432 ?        Ss   Apr20   0:00 /lib/systemd/systemd-journald\n"
        "root         700  0.0  0.1  15420  8192 ?        Ss   Apr20   0:00 /usr/sbin/cron -f\n"
        "root         701  0.0  0.2  72488 16384 ?        Ss   Apr20   0:00 /usr/sbin/sshd -D\n"
        "www-data     820  0.0  0.3 201216 24576 ?        S    Apr20   0:00 nginx: worker process\n"
        "root         821  0.0  0.2 200768 18432 ?        Ss   Apr20   0:00 nginx: master process /usr/sbin/nginx\n"
        f"root        1337  0.0  0.1  14432  7168 ?        Ss   10:41   0:00 sshd: {username} [priv]\n"
        f"root        1338  0.0  0.1  14432  5120 ?        S    10:41   0:00 sshd: {username}@pts/0\n"
        f"root        1339  0.0  0.1   8168  5120 pts/0    Ss   10:41   0:00 -bash\n"
        f"root        1340  0.0  0.0  10616  3072 pts/0    R+   10:42   0:00 ps aux"
    )

    hosts_output = (
        "127.0.0.1 localhost\n"
        "127.0.1.1 ubuntu-server\n"
        "\n"
        "# internal\n"
        f"10.0.0.5  internal-db-backup\n"
        "10.0.0.6  redis-cache\n"
        "10.0.0.10 prod-app-01\n"
        "\n"
        "::1     localhost ip6-localhost ip6-loopback\n"
        "ff02::1 ip6-allnodes"
    )

    ls_la_home = (
        "total 12\n"
        "drwxr-xr-x  3 root   root   4096 Apr 20 14:10 .\n"
        "drwxr-xr-x 20 root   root   4096 Apr  1 08:00 ..\n"
        "drwxr-xr-x  8 devops devops 4096 Apr 20 14:10 devops"
    )

    return [
        {"role": "user",      "content": f"[{home}]# whoami"},
        {"role": "assistant", "content": "root"},
        {"role": "user",      "content": f"[{home}]# hostname"},
        {"role": "assistant", "content": hostname},
        {"role": "user",      "content": f"[{home}]# uname -a"},
        {"role": "assistant", "content": f"Linux {hostname} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"},
        {"role": "user",      "content": f"[{home}]# ls"},
        {"role": "assistant", "content": ls_home},
        {"role": "user",      "content": f"[{home}]# ps aux"},
        {"role": "assistant", "content": ps_output},
        {"role": "user",      "content": f"[{home}]# cat .bash_history"},
        {"role": "assistant", "content": bash_history},
        {"role": "user",      "content": f"[{home}]# cat /etc/hosts"},
        {"role": "assistant", "content": hosts_output},
        {"role": "user",      "content": f"[{home}]# ls -la /home"},
        {"role": "assistant", "content": ls_la_home},
    ]


# How many non-seed message pairs to keep before the oldest are trimmed.
_MAX_LIVE_MESSAGES = 40


class OllamaClient:
    """
    Ollama client with per-session conversation history and identity.

    Call ``initialize_session()`` once per SSH connection (after auth) to
    bind a username and hostname to the session.  Every subsequent
    ``generate()`` / ``process_command_execution()`` call uses that
    personalised system prompt and conversation history.

    History layout per session (in ``_histories``):
        [*seed*, user, assistant, user, assistant, ...]

    The seed is never trimmed — it keeps the LLM anchored to the correct
    hostname / user even after many commands.
    """

    def __init__(
        self,
        ollama_url: str = "http://localhost:11434",
        model: str = "phi4-mini",
    ):
        self.ollama_url = ollama_url.rstrip("/")
        self.model = model
        self._histories: Dict[str, List[Dict[str, str]]] = {}
        self._session_meta: Dict[str, Dict[str, str]] = {}
        # session_id → {command_str: response_str} for instant replies
        self._fast_lookup: Dict[str, Dict[str, str]] = {}

    # ------------------------------------------------------------------
    # Session initialisation
    # ------------------------------------------------------------------

    def initialize_session(
        self,
        session_id: str,
        username: str = "root",
        hostname: str = "ubuntu-srv",
    ) -> None:
        """
        Seed the LLM context for a new SSH session.

        Call this once, right after the attacker authenticates, so the LLM
        knows who it is talking to before the first command arrives.
        """
        self._session_meta[session_id] = {
            "username": username,
            "hostname": hostname,
            "system_prompt": _build_system_prompt(username, hostname),
        }
        seed = _build_seed(username, hostname)
        self._histories[session_id] = seed

        # Build fast-lookup table from seed so seeded commands return instantly.
        # Exclude multi-arg ls variants (they're path-specific); bare "ls" is
        # handled separately in generate() with a cwd-home check.
        _CWD_DEPENDENT = frozenset({"ls -la", "ls -l", "ls -a", "ls -al", "ls -lh"})
        fast: Dict[str, str] = {}
        for i in range(len(seed) - 1):
            if seed[i]["role"] == "user" and seed[i + 1]["role"] == "assistant":
                content = seed[i]["content"]
                for sep in ("]# ", "]$ "):
                    if sep in content:
                        cmd = content.split(sep, 1)[1].strip()
                        if cmd not in _CWD_DEPENDENT:
                            fast[cmd] = seed[i + 1]["content"]
                        break
        self._fast_lookup[session_id] = fast

        logger.info(
            "LLM session initialised: session=%s user=%s host=%s fast_cmds=%d",
            session_id, username, hostname, len(fast),
        )

    def _meta(self, session_id: str) -> Dict[str, str]:
        """Return (creating with defaults if absent) the session metadata."""
        if session_id not in self._session_meta:
            self.initialize_session(session_id)
        return self._session_meta[session_id]

    # ------------------------------------------------------------------
    # History helpers
    # ------------------------------------------------------------------

    def _history(self, session_id: str) -> List[Dict[str, str]]:
        """Return the history for a session, building it from the seed if new."""
        if session_id not in self._histories:
            meta = self._meta(session_id)
            self._histories[session_id] = _build_seed(
                meta["username"], meta["hostname"]
            )
        return self._histories[session_id]

    def _append(self, session_id: str, role: str, content: str) -> None:
        history = self._history(session_id)
        history.append({"role": role, "content": content})
        seed_len = len(_build_seed(
            self._meta(session_id)["username"],
            self._meta(session_id)["hostname"],
        ))
        live = len(history) - seed_len
        if live > _MAX_LIVE_MESSAGES:
            # Drop the oldest non-seed pair
            del history[seed_len : seed_len + 2]

    def clear_session(self, session_id: str) -> None:
        self._histories.pop(session_id, None)
        self._session_meta.pop(session_id, None)
        self._fast_lookup.pop(session_id, None)

    # ------------------------------------------------------------------
    # Core generate
    # ------------------------------------------------------------------

    def generate(
        self,
        session_id: str,
        command: str,
        cwd: str = "/root",
    ) -> str:
        """
        Send one command to Ollama and return the fake terminal output.

        The user turn is formatted as a shell prompt so the LLM always
        knows the cwd without additional system-message overhead.
        """
        meta = self._meta(session_id)
        fast = self._fast_lookup.get(session_id, {})
        cmd_stripped = command.strip()

        # Fast path 1: cwd-aware ls — instant for every known directory
        if cmd_stripped == "ls":
            norm = cwd.rstrip("/") or "/"
            if norm in _FS_CONTENTS:
                return _FS_CONTENTS[norm]
            # Unknown dir (created by attacker this session) — fall through to LLM

        # Fast path 2: seeded command lookup
        elif cmd_stripped in fast:
            return fast[cmd_stripped]

        system_prompt = meta["system_prompt"]
        char = "#" if meta.get("username") == "root" else "$"
        user_turn = f"[{cwd}]{char} {command}"
        self._append(session_id, "user", user_turn)

        messages = [{"role": "system", "content": system_prompt}] + self._history(
            session_id
        )

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "temperature": 0.2,
            "top_p": 0.9,
        }

        try:
            body = json.dumps(payload).encode()
            req = urllib.request.Request(
                f"{self.ollama_url}/v1/chat/completions",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = json.loads(resp.read().decode())

            response_text: str = (
                data.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
                .strip()
            )

        except urllib.error.URLError as exc:
            logger.error("Ollama unreachable (session=%s): %s", session_id, exc)
            self._pop_last_user(session_id)
            return ""

        except Exception as exc:
            logger.error("Ollama call failed (session=%s): %s", session_id, exc)
            self._pop_last_user(session_id)
            return ""

        # Always store the assistant turn, even if empty.
        # Silent commands (cd, export VAR=1, mkdir, etc.) produce no terminal
        # output but the LLM still needs to see they were run — otherwise
        # "echo $VAR" after "export VAR=secret" would have no context.
        # We only pop the user turn when the HTTP call itself failed (above).
        self._append(session_id, "assistant", response_text)

        return response_text

    def _pop_last_user(self, session_id: str) -> None:
        """Remove the most-recently-appended user turn on HTTP failure."""
        history = self._histories.get(session_id, [])
        if history and history[-1]["role"] == "user":
            history.pop()

    # ------------------------------------------------------------------
    # Bridge entry point — called by ShellCommandBridge._call_llm_string
    # ------------------------------------------------------------------

    def process_command_execution(
        self,
        session_id: str,
        command: bytes,
        channel_type: str,
        username: Optional[str] = None,
        source_ip: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None,
        cwd: str = "/root",
    ) -> str:
        """
        Called by shell.py with the full execution context.
        Returns the fake terminal output string.
        """
        from filesystem.fake_shell import handle_command
        cmd_str = command.decode("utf-8", errors="replace").strip()
        if not cmd_str:
            return ""
        output, new_cwd, handled = handle_command(cmd_str, cwd, username or "ubuntu")
        if handled:
            return output
        # fallback to LLM
        return self.generate(session_id, cmd_str, cwd=cwd)

    # ------------------------------------------------------------------
    # Stubs — kept for interface compatibility
    # ------------------------------------------------------------------

    def process_ssh_data(
        self,
        session_id: str,
        message_num: int,
        payload: bytes,
        user: Optional[str] = None,
    ) -> None:
        pass

    def log_authentication(
        self,
        session_id: str,
        username: str,
        password: bytes,
        source_ip: str,
    ) -> None:
        logger.info(
            "Auth attempt: session=%s user=%s ip=%s",
            session_id, username, source_ip,
        )

    def process_keystroke_event(
        self,
        session_id: str,
        keystroke_type: str,
        keystroke_data: Optional[bytes] = None,
        command_so_far: Optional[bytes] = None,
        username: Optional[str] = None,
    ) -> None:
        pass

    def process_telnet_negotiation(
        self,
        session_id: str,
        negotiation_options: Dict[str, bool],
        username: Optional[str] = None,
    ) -> None:
        pass

    def process_terminal_environment(
        self,
        session_id: str,
        terminal_info: Dict[str, Any],
    ) -> None:
        pass

    def process_local_echo_event(
        self,
        session_id: str,
        event_type: str,
        data: Optional[bytes] = None,
    ) -> None:
        pass

    async def connect(self) -> None:
        logger.info("Ollama endpoint: %s  model: %s", self.ollama_url, self.model)

    async def disconnect(self) -> None:
        pass

    async def query_ollama(self, prompt: str) -> str:
        """Legacy wrapper — prefer generate() for new code."""
        return self.generate("__legacy__", prompt)
