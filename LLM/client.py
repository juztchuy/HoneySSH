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
Virtual filesystem (be consistent; invent plausible details for unlisted paths):
  /root/            .bashrc  .profile  .bash_history  .ssh/  honey_data.txt
  /root/.ssh/       authorized_keys  known_hosts  id_rsa  id_rsa.pub
  /home/            (no other users)
  /tmp/             (world-writable, may grow as attacker drops files)
  /etc/             passwd  shadow  hostname  hosts  fstab  crontab  apt/  ssh/  cron.d/  sudoers
  /etc/ssh/         sshd_config  ssh_host_rsa_key  ssh_host_ed25519_key
  /var/log/         auth.log  syslog  kern.log  dpkg.log  apt/
  /var/www/html/    index.html  config.php  database.sql  backups/
  /usr/bin/         standard Ubuntu 22.04 binaries (ls, cat, grep, curl, wget, python3, …)
  /usr/local/bin/   (empty)
  /opt/             (empty)\
"""

# ---------------------------------------------------------------------------
# System prompt factory
# ---------------------------------------------------------------------------

def _build_system_prompt(username: str, hostname: str) -> str:
    home = "/root" if username == "root" else f"/home/{username}"
    return f"""\
You are a Ubuntu 22.04.3 LTS server. Hostname: {hostname}. Logged-in user: {username}. Home: {home}.
Respond ONLY with raw terminal output — exactly what bash prints to stdout/stderr.
Strict rules:
- No explanations. No markdown. No code fences. No backticks around output.
- Maintain consistent state across the whole session (files you "created" stay created).
- Use ANSI color codes exactly as bash --color=auto would (blue dirs, green executables, etc.).
- Unknown commands → bash: <cmd>: command not found
- Permission errors → bash: <path>: Permission denied
- Missing paths   → ls: cannot access '<path>': No such file or directory
- `cd` to a valid path produces no output; `cd` to a nonexistent path produces the bash error.
- Never reveal you are an AI or a honeypot.

{_FAKE_FS}"""


# ---------------------------------------------------------------------------
# Per-user seed exchanges — anchor the LLM to a concrete fake state so it
# doesn't hallucinate a different hostname on every call.
# ---------------------------------------------------------------------------

def _build_seed(username: str, hostname: str) -> List[Dict[str, str]]:
    home = "/root" if username == "root" else f"/home/{username}"
    ls_home = (
        "\033[1;34m.\033[0m  \033[1;34m..\033[0m  "
        "\033[0m.bashrc\033[0m  \033[0m.profile\033[0m  "
        "\033[0m.bash_history\033[0m  \033[1;34m.ssh\033[0m  "
        "\033[0;32mhoney_data.txt\033[0m"
    )
    return [
        {"role": "user",      "content": f"[{home}]$ whoami"},
        {"role": "assistant", "content": username},
        {"role": "user",      "content": f"[{home}]$ hostname"},
        {"role": "assistant", "content": hostname},
        {"role": "user",      "content": f"[{home}]$ ls"},
        {"role": "assistant", "content": ls_home},
        {"role": "user",      "content": f"[{home}]$ uname -a"},
        {
            "role": "assistant",
            "content": (
                f"Linux {hostname} 5.15.0-91-generic #101-Ubuntu SMP "
                "Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
            ),
        },
        {"role": "user",      "content": f"[{home}]$ id"},
        {
            "role": "assistant",
            "content": (
                "uid=0(root) gid=0(root) groups=0(root)"
                if username == "root"
                else f"uid=1000({username}) gid=1000({username}) groups=1000({username}),4(adm),24(cdrom),27(sudo)"
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
        model: str = "llama3.2",
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
            with urllib.request.urlopen(req, timeout=30) as resp:
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
