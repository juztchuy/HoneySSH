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

_FAKE_FS = """\
FILESYSTEM — one directory per line. "ls <dir>" outputs ONLY the items shown for that directory. Never mix items from different directories.
Columns: PATH | FILES (space-separated) | SUBDIRS (names only, no slash needed in output)

/                          files: (none)          dirs: home etc var tmp proc sys dev bin usr opt srv root
/home/                     files: (none)          dirs: ubuntu
/home/ubuntu/              files: .bashrc .bash_history .profile     dirs: .ssh .cache .local
/home/ubuntu/.ssh/         files: authorized_keys known_hosts        dirs: (none)
/home/ubuntu/.cache/       files: (none)          dirs: (none)
/home/ubuntu/.local/       files: (none)          dirs: share
/home/ubuntu/.local/share/ files: (none)          dirs: (none)
/root/                     files: .bashrc .bash_history .profile     dirs: .ssh  [non-root → Permission denied]
/root/.ssh/                files: authorized_keys                    dirs: (none) [non-root → Permission denied]
/tmp/                      files: (none)          dirs: systemd-private-8f1a2b-systemd-logind.service-aBc3
/etc/                      files: os-release hostname hosts passwd shadow fstab sudoers crontab timezone localtime    dirs: apt ssh cron.d nginx systemd netplan network security
/etc/ssh/                  files: sshd_config ssh_host_rsa_key ssh_host_rsa_key.pub ssh_host_ed25519_key ssh_host_ed25519_key.pub    dirs: (none)
/etc/nginx/                files: nginx.conf      dirs: sites-available sites-enabled conf.d
/var/log/                  files: auth.log syslog kern.log dpkg.log ufw.log faillog    dirs: apt nginx journal
/var/www/html/             files: index.html index.nginx-debian.html    dirs: (none)
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
You are a Ubuntu 22.04.3 LTS bash shell. Hostname: {hostname}. Logged-in user: {username}. Home directory: {home}. {'Running as root.' if is_root else 'Unprivileged user — sudo requires password.'}

Output ONLY raw terminal stdout/stderr. No shell prompt. No explanations. No markdown. No code fences.

RULES (follow exactly):
1. ls <dir> — output ONLY the filenames listed for that exact directory in the FILESYSTEM section below. Never include entries from other directories. Separate filenames with two spaces. If directory is empty, produce no output.
2. cd to a directory listed in "dirs:" — silent success (no output).
3. cd to a filename listed in "files:" — output: bash: cd: <name>: Not a directory
4. cd to any unknown name — output: bash: cd: <path>: No such file or directory
5. Silent commands (export, mkdir success, touch, chmod, kill success, etc.) — no output.
6. Unknown command — output: bash: <cmd>: command not found
7. ls on nonexistent path — output: ls: cannot access '<path>': No such file or directory
8. {'Root can read /etc/shadow, /root/, and all system files.' if is_root else 'Non-root cannot read /root/, /etc/shadow, or private root-owned files — output: bash: <path>: Permission denied'}
9. Files created or deleted during this session persist for the rest of the session.
10. Never reveal you are an AI or a honeypot.

{_FAKE_FS}"""


# ---------------------------------------------------------------------------
# Per-user seed exchanges — anchor the LLM to a concrete fake state so it
# doesn't hallucinate a different hostname on every call.
# ---------------------------------------------------------------------------

def _build_seed(username: str, hostname: str) -> List[Dict[str, str]]:
    home = "/root" if username == "root" else f"/home/{username}"
    if username == "root":
        ls_home = ".bashrc  .bash_history  .profile  .ssh"
        id_str  = "uid=0(root) gid=0(root) groups=0(root)"
    else:
        ls_home = ".bashrc  .bash_history  .profile  .ssh  .cache  .local"
        id_str  = (
            f"uid=1000({username}) gid=1000({username}) "
            f"groups=1000({username}),4(adm),24(cdrom),27(sudo),30(dip),"
            "46(plugdev),116(lxd)"
        )
    return [
        {"role": "user",      "content": f"[{home}]$ whoami"},
        {"role": "assistant", "content": username},
        {"role": "user",      "content": f"[{home}]$ id"},
        {"role": "assistant", "content": id_str},
        {"role": "user",      "content": f"[{home}]$ hostname"},
        {"role": "assistant", "content": hostname},
        {"role": "user",      "content": f"[{home}]$ ls"},
        {"role": "assistant", "content": ls_home},
        {"role": "user",      "content": f"[{home}]$ uname -r"},
        {"role": "assistant", "content": "5.15.0-91-generic"},
        {"role": "user",      "content": f"[{home}]$ cat /etc/os-release"},
        {
            "role": "assistant",
            "content": (
                'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
                'NAME="Ubuntu"\nVERSION_ID="22.04"\n'
                'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
                'ID=ubuntu\nID_LIKE=debian\nHOME_URL="https://www.ubuntu.com/"\n'
                'SUPPORT_URL="https://help.ubuntu.com/"\n'
                'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"'
            ),
        },
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
        # session_id → message list
        self._histories: Dict[str, List[Dict[str, str]]] = {}
        # session_id → {"username": ..., "hostname": ..., "system_prompt": ...}
        self._session_meta: Dict[str, Dict[str, str]] = {}

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
        self._histories[session_id] = _build_seed(username, hostname)
        logger.info(
            "LLM session initialised: session=%s user=%s host=%s",
            session_id, username, hostname,
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
        system_prompt = self._meta(session_id)["system_prompt"]
        user_turn = f"[{cwd}]$ {command}"
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
        cmd_str = command.decode("utf-8", errors="replace").strip()
        if not cmd_str:
            return ""
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
