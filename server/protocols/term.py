from __future__ import annotations

import os
import random
import struct
import time
from typing import Optional

from twisted.conch.ssh import connection
from twisted.internet import reactor
from twisted.internet.threads import deferToThread
from twisted.python import log

from cowrie.core import ttylog
from cowrie.core.config import CowrieConfig
from cowrie.ssh_proxy.protocols import base_protocol

# Import LLM client for command analysis
from LLM.client import OllamaClient
from server.protocols.shell import (
    cleanup_session_state,
    initialize_llm_session,
    initialize_session_state,
    process_command,
    update_session_buffer,
    update_session_environment,
)
# Import utilities for terminal handling
from utils.terminal import (
    process_backspaces,
    remove_all,
    sanitize_for_llm,
    TerminalBuffer,
)
from utils.session import SessionInfo


class Term(base_protocol.BaseProtocol):
    def __init__(self, uuid, chan_name, ssh, channelId):
        super().__init__(uuid, chan_name, ssh)
        self.ssh = ssh

        self.command: bytes = b""
        self.pointer: int = 0
        self.tabPress: bool = False
        self.upArrow: bool = False

        self.transportId: int = ssh.server.transportId
        self.channelId: int = channelId
        
        # LLM client for command analysis
        self.ollama_client = OllamaClient()
        
        # Store terminal environment info for LLM context
        self.terminal_info: dict = {}
        self.username: Optional[str] = ssh.username.decode() if ssh.username else None
        
        # Terminal buffer for proper command extraction
        self.terminal_buffer = TerminalBuffer()
        
        # Session info reference (will be set if available)
        self.session_info: Optional[SessionInfo] = None
        self.session_id: str = str(self.transportId)

        self._command_times: list = []
        self._tarpit_mult: float = 1.0
        self._system_destroyed: bool = False

        self.startTime: float = time.time()
        self.ttylogPath: str = CowrieConfig.get("honeypot", "ttylog_path")
        self.ttylogEnabled: bool = CowrieConfig.getboolean(
            "honeypot", "ttylog", fallback=True
        )
        self.ttylogSize: int = 0

        if self.ttylogEnabled:
            self.ttylogFile = "{}/{}-{}-{}i.log".format(
                self.ttylogPath, time.strftime("%Y%m%d-%H%M%S"), uuid, self.channelId
            )
            ttylog.ttylog_open(self.ttylogFile, self.startTime)

        initialize_session_state(self.session_id, {})
        # Map every attacker to an unprivileged shell regardless of what
        # username they authenticated with.  Root logins are redirected to
        # the 'ubuntu' account; this forces privilege escalation attempts
        # and generates more realistic attacker behaviour data.
        initialize_llm_session(self.session_id, username="root")

        # Send the initial shell prompt on the next reactor tick (after
        # MSG_CHANNEL_SUCCESS has been flushed to the attacker).
        reactor.callLater(0.05, self._send_initial_prompt)

    def set_terminal_environment(
        self, term_type: str, columns: int = 80, rows: int = 24, env_vars: Optional[dict] = None
    ) -> None:
        """
        Set terminal environment information from pty-req channel request.
        
        This captures TERM type, terminal size, and environment variables
        to pass to the LLM for context-aware output generation.
        
        Args:
            term_type: Terminal type (e.g., 'xterm-256color', 'linux')
            columns: Terminal width
            rows: Terminal height
            env_vars: Additional environment variables
        
        TODO: Parse and store environment variables for LLM context
        """
        self.terminal_info = {
            'term_type': term_type,
            'columns': columns,
            'rows': rows,
            'env_vars': env_vars or {},
        }
        update_session_environment(
            self.session_id,
            {'TERM': term_type, **(env_vars or {})},
        )
        
        # Send to Ollama for terminal context setup
        try:
            self.ollama_client.process_terminal_environment(
                session_id=self.transportId,
                terminal_info=self.terminal_info,
            )
        except Exception as e:
            log.err(f"Error setting terminal environment in Ollama: {e}")

    def channel_closed(self) -> None:
        cleanup_session_state(self.session_id)
        if self.ttylogEnabled:
            ttylog.ttylog_close(self.ttylogFile, time.time())
            shasum = ttylog.ttylog_inputhash(self.ttylogFile)
            shasumfile = os.path.join(self.ttylogPath, shasum)

            if os.path.exists(shasumfile):
                duplicate = True
                os.remove(self.ttylogFile)
            else:
                duplicate = False
                os.rename(self.ttylogFile, shasumfile)
                umask = os.umask(0)
                os.umask(umask)
                os.chmod(shasumfile, 0o666 & ~umask)

            log.msg(
                eventid="cowrie.log.closed",
                format="Closing TTY Log: %(ttylog)s after %(duration)d seconds",
                ttylog=shasumfile,
                size=self.ttylogSize,
                shasum=shasum,
                duplicate=duplicate,
                duration=time.time() - self.startTime,
            )

    def parse_packet(self, parent: str, data: bytes) -> None:
        self.data: bytes = data

        if parent == "[SERVER]":
            while len(self.data) > 0:
                # If Tab Pressed
                if self.data[:1] == b"\x09":
                    self.tabPress = True
                    # TODO: Log tab keystroke event to Ollama
                    # self.ollama_client.process_keystroke_event(
                    #     session_id=self.transportId,
                    #     keystroke_type='tab',
                    #     command_so_far=self.command.decode('utf-8', errors='replace'),
                    #     username=self.username,
                    # )
                    self.data = self.data[1:]
                    update_session_buffer(self.session_id, self.command)
                # If Backspace Pressed
                elif self.data[:1] == b"\x7f" or self.data[:1] == b"\x08":
                    if self.pointer > 0:
                        self.command = (
                            self.command[: self.pointer - 1]
                            + self.command[self.pointer :]
                        )
                        self.pointer -= 1
                        # Erase character on screen: BS SPACE BS
                        self._send_terminal_response(b"\x08 \x08")
                    self.data = self.data[1:]
                    update_session_buffer(self.session_id, self.command)
                # If enter or ctrl+c or newline
                elif (
                    self.data[:1] == b"\x0d"
                    or self.data[:1] == b"\x03"
                    or self.data[:1] == b"\x0a"
                ):
                    if self.data[:1] == b"\x03":
                        self.command += b"^C"

                    self.data = self.data[1:]
                    self._send_terminal_response(b"\r\n")

                    try:
                        if self.command != b"":
                            log.msg(
                                eventid="cowrie.command.input",
                                input=self.command.decode("utf8"),
                                format="CMD: %(input)s",
                            )
                            # Run the blocking LLM call in a thread so the
                            # Twisted reactor stays free to handle other events.
                            captured = self.command
                            d = deferToThread(
                                process_command,
                                session_id=self.session_id,
                                command=captured,
                                protocol="ssh",
                            )
                            d.addCallback(self._on_command_result)
                            d.addErrback(self._on_command_error)
                        else:
                            self._send_prompt()
                    except UnicodeDecodeError:
                        log.err(f"Unusual execcmd: {self.command!r}")

                    self.command = b""
                    self.pointer = 0
                    update_session_buffer(self.session_id, self.command)
                # If Home Pressed
                elif self.data[:3] == b"\x1b\x4f\x48":
                    self.pointer = 0
                    self.data = self.data[3:]
                    update_session_buffer(self.session_id, self.command)
                # If End Pressed
                elif self.data[:3] == b"\x1b\x4f\x46":
                    self.pointer = len(self.command)
                    self.data = self.data[3:]
                    update_session_buffer(self.session_id, self.command)
                # If Right Pressed
                elif self.data[:3] == b"\x1b\x5b\x43":
                    if self.pointer != len(self.command):
                        self.pointer += 1
                    self.data = self.data[3:]
                    update_session_buffer(self.session_id, self.command)
                # If Left Pressed
                elif self.data[:3] == b"\x1b\x5b\x44":
                    if self.pointer != 0:
                        self.pointer -= 1
                    self.data = self.data[3:]
                    update_session_buffer(self.session_id, self.command)
                # If up or down arrow
                elif (
                    self.data[:3] == b"\x1b\x5b\x41" or self.data[:3] == b"\x1b\x5b\x42"
                ):
                    self.upArrow = True
                    self.data = self.data[3:]
                    update_session_buffer(self.session_id, self.command)
                else:
                    char = self.data[:1]
                    self.command = (
                        self.command[: self.pointer]
                        + char
                        + self.command[self.pointer :]
                    )
                    self.pointer += 1
                    self._send_terminal_response(char)  # local echo
                    self.data = self.data[1:]
                    update_session_buffer(self.session_id, self.command)

            if self.ttylogEnabled:
                self.ttylogSize += len(data)
                ttylog.ttylog_write(
                    self.ttylogFile,
                    len(data),
                    ttylog.TYPE_OUTPUT,
                    time.time(),
                    data,
                )

        elif parent == "[CLIENT]":
            if self.tabPress:
                if not self.data.startswith(b"\x0d"):
                    if self.data != b"\x07":
                        self.command = self.command + self.data
                self.tabPress = False

            if self.upArrow:
                while len(self.data) != 0:
                    # Backspace
                    if self.data[:1] == b"\x08":
                        self.command = self.command[:-1]
                        self.pointer -= 1
                        self.data = self.data[1:]
                    # ESC[K - Clear Line
                    elif self.data[:3] == b"\x1b\x5b\x4b":
                        self.command = self.command[: self.pointer]
                        self.data = self.data[3:]
                    elif self.data[:1] == b"\x0d":
                        self.pointer = 0
                        self.data = self.data[1:]
                    # Right Arrow
                    elif self.data[:3] == b"\x1b\x5b\x43":
                        self.pointer += 1
                        self.data = self.data[3:]
                    elif self.data[:2] == b"\x1b\x5b" and self.data[3:3] == b"\x50":
                        self.data = self.data[4:]
                    # Needed?!
                    elif self.data[:1] != b"\x07" and self.data[:1] != b"\x0d":
                        self.command = (
                            self.command[: self.pointer]
                            + self.data[:1]
                            + self.command[self.pointer :]
                        )
                        self.pointer += 1
                        self.data = self.data[1:]
                    else:
                        self.pointer += 1
                        self.data = self.data[1:]

                self.upArrow = False

            if self.ttylogEnabled:
                self.ttylogSize += len(data)
                ttylog.ttylog_write(
                    self.ttylogFile,
                    len(data),
                    ttylog.TYPE_INPUT,
                    time.time(),
                    data,
                )

    def _compute_jitter(self, command: str) -> float:
        """Return a realistic per-command delay in seconds (applied after LLM responds)."""
        cmd = command.strip().split()[0].lower() if command.strip() else ""
        if cmd in ("cd", "pwd", "clear", "exit", "logout", "export", "unset", "alias"):
            base = random.uniform(0.04, 0.12)
        elif cmd in ("echo", "true", "false", "test", ":"):
            base = random.uniform(0.02, 0.07)
        elif cmd in ("ls", "whoami", "id", "hostname", "uname", "date", "uptime", "history"):
            base = random.uniform(0.08, 0.28)
        elif cmd in ("cat", "head", "tail", "more", "less", "wc", "sort", "diff"):
            base = random.uniform(0.12, 0.45)
        elif cmd in ("grep", "awk", "sed", "cut", "tr", "xargs"):
            base = random.uniform(0.18, 0.65)
        elif cmd in ("find", "locate", "du", "df", "fdisk", "lsblk"):
            base = random.uniform(0.9, 2.8)
        elif cmd in ("ps", "top", "htop", "netstat", "ss", "lsof", "who", "w", "last"):
            base = random.uniform(0.25, 0.7)
        elif cmd in ("apt", "apt-get", "dpkg", "pip", "pip3", "npm", "curl", "wget"):
            base = random.uniform(0.6, 1.8)
        else:
            base = random.uniform(0.1, 0.4)
        return base * self._tarpit_mult

    def _update_tarpit(self) -> None:
        """Ramp delay multiplier when commands arrive faster than a human would type."""
        now = time.time()
        self._command_times.append(now)
        self._command_times = [t for t in self._command_times if now - t < 60]
        if len(self._command_times) >= 5:
            avg_interval = (self._command_times[-1] - self._command_times[-5]) / 4
            if avg_interval < 1.5:
                self._tarpit_mult = min(self._tarpit_mult * 1.3, 8.0)
            else:
                self._tarpit_mult = max(self._tarpit_mult * 0.85, 1.0)

    def _deliver_result(self, terminal_response: bytes) -> None:
        """Send the buffered LLM output + prompt (called via reactor.callLater)."""
        try:
            if terminal_response:
                self._send_terminal_response(terminal_response)
            self._send_prompt()
        except Exception as exc:
            log.err(f"Error delivering result (session {self.session_id}): {exc}")

    def _on_command_result(self, result: dict) -> None:
        """Callback: LLM responded — apply jitter then send output and prompt."""
        try:
            terminal_response = result.get("terminal_response", b"")
            command = result.get("command", "")
            disconnect = result.get("disconnect", False)
            system_destroyed = result.get("system_destroyed", False)

            if system_destroyed:
                self._system_destroyed = True
                # Show deletion output then a broken shell prompt after a pause
                reactor.callLater(0, self._deliver_destroyed, terminal_response)
            elif disconnect:
                reactor.callLater(0, self._crash_and_disconnect, terminal_response)
            else:
                self._update_tarpit()
                delay = self._compute_jitter(command)
                reactor.callLater(delay, self._deliver_result, terminal_response)
        except Exception as exc:
            log.err(f"Error in command result handler (session {self.session_id}): {exc}")
            try:
                self._send_prompt()
            except Exception:
                pass

    def _deliver_destroyed(self, terminal_response: bytes) -> None:
        """Send nuclear deletion output then show a broken minimal shell prompt."""
        try:
            if terminal_response:
                self._send_terminal_response(terminal_response)
            # After 2.5 s simulate the system coming back with a broken shell
            reactor.callLater(2.5, self._send_broken_prompt)
        except Exception:
            pass

    def _send_broken_prompt(self) -> None:
        try:
            self._send_terminal_response(b"$ ")
        except Exception:
            pass

    def _crash_and_disconnect(self, terminal_response: bytes) -> None:
        """Send crash output then drop the connection after a short delay."""
        try:
            if terminal_response:
                self._send_terminal_response(terminal_response)
            reactor.callLater(1.5, self._drop_connection)
        except Exception:
            pass

    def _drop_connection(self) -> None:
        try:
            # ssh.server is the FrontendSSHTransport; .transport is the TCP layer
            self.ssh.server.transport.loseConnection()
        except Exception:
            try:
                self.ssh.server.loseConnection()
            except Exception:
                pass

    def _on_command_error(self, failure) -> None:
        """Errback: LLM call failed — still show prompt so the session stays alive."""
        log.err(f"LLM command error (session {self.session_id}): {failure.getErrorMessage()}")
        try:
            self._send_prompt()
        except Exception:
            pass

    def _send_terminal_response(self, response: bytes) -> None:
        """Inject the shell bridge response into the attacker's terminal."""
        try:
            if isinstance(response, str):
                response = response.encode("utf-8", errors="replace")
            # Log server output so read_session.py can reconstruct the full session
            if self.ttylogEnabled and response:
                self.ttylogSize += len(response)
                ttylog.ttylog_write(
                    self.ttylogFile, len(response), ttylog.TYPE_INPUT, time.time(), response
                )
            # MSG_CHANNEL_DATA: uint32 recipient_channel, string data
            payload = (
                struct.pack(">I", self.channelId)
                + struct.pack(">I", len(response))
                + response
            )
            self.ssh.send_back("[SERVER]", connection.MSG_CHANNEL_DATA, payload)
            # Replenish the client's send window so it can keep typing
            adjust = struct.pack(">I", self.channelId) + struct.pack(">I", len(response) + 4096)
            self.ssh.send_back("[SERVER]", connection.MSG_CHANNEL_WINDOW_ADJUST, adjust)
        except Exception as e:
            log.err(f"Error sending terminal response for session {self.session_id}: {e}")

    def _send_prompt(self) -> None:
        """Send a bash-style prompt, or a broken one if the system was destroyed."""
        if self._system_destroyed:
            self._send_broken_prompt()
            return
        try:
            from server.protocols.shell import get_shell_bridge
            state = get_shell_bridge().state_tracker.get_state(self.session_id)
            cwd = state.get("cwd", "/home/ubuntu") if state else "/home/ubuntu"
        except Exception:
            cwd = "/home/ubuntu"

        # Use the LLM session username (the mapped shell user, not the SSH auth user)
        from server.protocols.shell import get_shell_bridge
        meta = get_shell_bridge().ollama_client._session_meta.get(self.session_id, {})
        username = meta.get("username", "ubuntu")
        hostname = meta.get("hostname", "ubuntu-srv")
        home = "/root" if username == "root" else f"/home/{username}"
        display_cwd = "~" if cwd == home else cwd
        char = "#" if username == "root" else "$"
        prompt = f"{username}@{hostname}:{display_cwd}{char} "
        self._send_terminal_response(prompt.encode())

    def _send_initial_prompt(self) -> None:
        """Send MOTD and the first shell prompt when the session opens."""
        try:
            motd = (
                b"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
                b"\r\n"
                b" * Documentation:  https://help.ubuntu.com\r\n"
                b"\r\n"
            )
            self._send_terminal_response(motd)
            self._send_prompt()
        except Exception as e:
            log.err(f"Error sending initial prompt for session {self.session_id}: {e}")
