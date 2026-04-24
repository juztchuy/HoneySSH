from __future__ import annotations

import os
import time
from typing import Optional

from twisted.conch.ssh import connection
from twisted.python import log

from cowrie.core import ttylog
from cowrie.core.config import CowrieConfig
from cowrie.ssh_proxy.protocols import base_protocol
from cowrie.ssh_proxy.util import int_to_hex, string_to_hex

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
        initialize_llm_session(
            self.session_id,
            username=self.username or "root",
        )

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
                    # TODO: Log backspace keystroke event to Ollama
                    # self.ollama_client.process_keystroke_event(
                    #     session_id=self.transportId,
                    #     keystroke_type='backspace',
                    #     command_so_far=self.command.decode('utf-8', errors='replace'),
                    #     username=self.username,
                    # )
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

                    try:
                        if self.command != b"":
                            log.msg(
                                eventid="cowrie.command.input",
                                input=self.command.decode("utf8"),
                                format="CMD: %(input)s",
                            )

                            result = process_command(
                                session_id=self.session_id,
                                command=self.command,
                                protocol="ssh",
                            )
                            terminal_response = result.get("terminal_response", b"")
                            if terminal_response:
                                self._send_terminal_response(terminal_response)
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
                    self.command = (
                        self.command[: self.pointer]
                        + self.data[:1]
                        + self.command[self.pointer :]
                    )
                    self.pointer += 1
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

    def _send_terminal_response(self, response: bytes) -> None:
        """Inject the shell bridge response into the attacker's terminal."""
        try:
            payload = int_to_hex(self.channelId) + string_to_hex(response)
            self.ssh.send_back("[SERVER]", connection.MSG_CHANNEL_DATA, payload)
        except Exception as e:
            log.err(f"Error sending terminal response for session {self.session_id}: {e}")
