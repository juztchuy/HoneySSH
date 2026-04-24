from __future__ import annotations

import os
import re
import time
from typing import Optional, Dict

from twisted.python import log

from cowrie.core import ttylog
from cowrie.core.checkers import HoneypotPasswordChecker
from cowrie.core.config import CowrieConfig

# Import LLM client for Ollama integration
from LLM.client import OllamaClient
# Import utilities
from utils.terminal import (
    process_backspaces,
    remove_all,
    sanitize_for_llm,
    TerminalBuffer,
)
from utils.echo import AuthenticationEchoHandler, LocalEchoHandler
from utils.session import SessionInfo


class TelnetHandler:
    def __init__(self, server):
        # holds packet data; useful to manipulate it across functions as needed
        self.currentData: bytes = b""
        self.sendData = True

        # front and backend references
        self.server = server
        self.client = None
        
        # LLM client for Ollama integration
        self.ollama_client = OllamaClient()
        
        # Telnet option negotiation tracking for client fingerprinting
        self.negotiation_options: Dict[str, bool] = {}
        self.session_id = str(time.time())  # Simple session ID
        
        # Session info reference
        self.session_info: Optional[SessionInfo] = None
        
        # Authentication echo handlers
        self.auth_echo_handler = AuthenticationEchoHandler()
        self.local_echo_handler = LocalEchoHandler()
        
        # Terminal buffer for proper command extraction
        self.terminal_buffer = TerminalBuffer()

        # definitions from config
        self.spoofAuthenticationData = CowrieConfig.getboolean(
            "proxy", "telnet_spoof_authentication", fallback=True
        )

        self.backendLogin = CowrieConfig.get("proxy", "backend_user").encode()
        self.backendPassword = CowrieConfig.get("proxy", "backend_pass").encode()

        self.usernameInNegotiationRegex = CowrieConfig.get(
            "proxy", "telnet_username_in_negotiation_regex", raw=True
        ).encode()
        self.usernamePromptRegex = CowrieConfig.get(
            "proxy", "telnet_username_prompt_regex", raw=True
        ).encode()
        self.passwordPromptRegex = CowrieConfig.get(
            "proxy", "telnet_password_prompt_regex", raw=True
        ).encode()

        # telnet state
        self.currentCommand = b""

        # auth state
        self.authStarted = False
        self.authDone = False

        self.usernameState = b""  # TODO clear on end
        self.inputingLogin = False

        self.passwordState = b""  # TODO clear on end
        self.inputingPassword = False

        self.waitingLoginEcho = False

        # some data is sent by the backend right before the password prompt, we want to capture that
        # and the respective frontend response and send it before starting to intercept auth data
        self.prePasswordData = False

        # buffer
        self.backend_buffer = []

        # tty logging
        self.startTime = time.time()
        self.ttylogPath = CowrieConfig.get("honeypot", "ttylog_path", fallback=".")
        self.ttylogEnabled = CowrieConfig.getboolean(
            "honeypot", "ttylog", fallback=True
        )
        self.ttylogSize = 0

        if self.ttylogEnabled:
            self.ttylogFile = "{}/telnet-{}.log".format(
                self.ttylogPath, time.strftime("%Y%m%d-%H%M%S")
            )
            ttylog.ttylog_open(self.ttylogFile, self.startTime)

    def setClient(self, client):
        self.client = client

    def start_authentication_with_echo(self) -> None:
        """
        Start authentication phase with proper local echo handling.
        
        This should be called when the backend sends a login prompt.
        The echo handler will ensure that:
        - Username input is echoed back to the client
        - Password input is NOT echoed back
        """
        self.auth_echo_handler.start_authentication()
        self.local_echo_handler.enable_echo()
        self.authStarted = True
        
        log.msg(f"Session {self.session_id}: Authentication started with local echo")

    def end_authentication_with_echo(self, username: str) -> None:
        """
        End authentication phase when login is successful.
        
        Args:
            username: Authenticated username
        """
        self.auth_echo_handler.end_authentication(username)
        self.local_echo_handler.disable_echo()
        self.authDone = True
        self.usernameState = username.encode()
        
        log.msg(f"Session {self.session_id}: Authentication successful for user {username}")

    def log_telnet_option_negotiation(self, options: Dict[str, bool], username: Optional[str] = None) -> None:
        """
        Log Telnet option negotiation for client fingerprinting.
        
        Telnet clients can be identified by their specific option negotiation patterns
        (DO/DONT/WILL/WONT). This helps identify specific botnet clients or tools.
        
        Args:
            options: Dictionary of negotiated Telnet options
                e.g., {'ECHO': True, 'SUPPRESS_GO_AHEAD': True, 'LINEMODE': False}
            username: Username if authentication has started
        
        TODO: Implement botnet fingerprinting based on negotiation patterns
        """
        self.negotiation_options = options
        
        log.msg(
            f"Telnet negotiation options: {options}"
        )
        
        # Send to Ollama for client fingerprinting
        try:
            self.ollama_client.process_telnet_negotiation(
                session_id=self.session_id,
                negotiation_options=options,
                username=username,
            )
        except Exception as e:
            log.err(f"Error logging telnet negotiation to Ollama: {e}")

    def log_local_echo_event(self, event_type: str, original_data: Optional[bytes] = None) -> None:
        """
        Log local echo events (backspace sequences, character echoes).
        
        This is used when the honeypot performs local echo for authentication.
        It can help detect honeypot awareness if an attacker is bypassing
        the local echo with knowledge of the backend server.
        
        Args:
            event_type: Type of echo event ('backspace_sequence', 'character_echo')
            original_data: Original data that was echoed
        
        TODO: Implement detection of honeypot-aware clients
        """
        log.debug(
            f"Local echo event: type={event_type}"
        )
        
        # Send to Ollama for analysis
        try:
            self.ollama_client.process_local_echo_event(
                session_id=self.session_id,
                event_type=event_type,
                data=original_data,
            )
        except Exception as e:
            log.err(f"Error logging local echo event to Ollama: {e}")

    def close(self):
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

            self.ttylogEnabled = (
                False  # do not close again if function called after closing
            )

            log.msg(
                eventid="cowrie.log.closed",
                format="Closing TTY Log: %(ttylog)s after %(duration)d seconds",
                ttylog=shasumfile,
                size=self.ttylogSize,
                shasum=shasum,
                duplicate=duplicate,
                duration=time.time() - self.startTime,
            )

    def sendBackend(self, data: bytes) -> None:
        self.backend_buffer.append(data)

        if not self.client:
            return

        for packet in self.backend_buffer:
            self.client.transport.write(packet)
            # log raw packets if user sets so
            if CowrieConfig.getboolean("proxy", "log_raw", fallback=False):
                log.msg("to_backend - " + data.decode("unicode-escape"))

            if self.ttylogEnabled and self.authStarted:
                cleanData = data.replace(
                    b"\x00", b"\n"
                )  # some frontends send 0xFF instead of newline
                ttylog.ttylog_write(
                    self.ttylogFile,
                    len(cleanData),
                    ttylog.TYPE_INPUT,
                    time.time(),
                    cleanData,
                )
                self.ttylogSize += len(cleanData)

            self.backend_buffer = self.backend_buffer[1:]

    def sendFrontend(self, data: bytes) -> None:
        self.server.transport.write(data)

        # log raw packets if user sets so
        if CowrieConfig.getboolean("proxy", "log_raw", fallback=False):
            log.msg("to_frontend - " + data.decode("unicode-escape"))

        if self.ttylogEnabled and self.authStarted:
            ttylog.ttylog_write(
                self.ttylogFile, len(data), ttylog.TYPE_OUTPUT, time.time(), data
            )
            # self.ttylogSize += len(data)

    def addPacket(self, parent: str, data: bytes) -> None:
        self.currentData = data
        self.sendData = True

        if self.spoofAuthenticationData and not self.authDone:
            # detect prompts from backend
            if parent == "backend":
                self.setProcessingStateBackend()

            # detect patterns from frontend
            if parent == "frontend":
                self.setProcessingStateFrontend()

            # save user inputs from frontend
            if parent == "frontend":
                if self.inputingPassword:
                    self.processPasswordInput()

                if self.inputingLogin:
                    self.processUsernameInput()

            # capture username echo from backend
            if self.waitingLoginEcho and parent == "backend":
                self.currentData = self.currentData.replace(
                    self.backendLogin + b"\r\n", b""
                )
                self.waitingLoginEcho = False

        # log user commands
        if parent == "frontend" and self.authDone:
            self.currentCommand += data.replace(b"\r\x00", b"").replace(b"\r\n", b"")

            # check if a command has terminated
            if b"\r" in data:
                if len(self.currentCommand) > 0:
                    log.msg(
                        eventid="cowrie.command.input",
                        input=self.currentCommand,
                        format="CMD: %(input)s",
                    )
                    
                    # Send command to Ollama for analysis
                    try:
                        self.ollama_client.process_command_execution(
                            session_id=self.session_id,
                            command=self.currentCommand,
                            channel_type='telnet',
                            username=self.usernameState.decode('utf-8', errors='replace') if self.usernameState else None,
                            # TODO: Get source IP from server
                            # source_ip=self.server.peer_ip,
                            environment={'TELNET_OPTIONS': str(self.negotiation_options)},
                        )
                    except Exception as e:
                        log.err(f"Error sending telnet command to Ollama: {e}")
                
                self.currentCommand = b""

        # send data after processing (also check if processing did not reduce it to an empty string)
        if self.sendData and len(self.currentData):
            if parent == "frontend":
                self.sendBackend(self.currentData)
            else:
                self.sendFrontend(self.currentData)

    def processUsernameInput(self) -> None:
        self.sendData = False  # withold data until input is complete

        # remove control characters
        control_chars = [b"\r", b"\x00", b"\n"]
        self.usernameState += remove_all(self.currentData, control_chars)

        # backend echoes data back to user to show on terminal prompt
        #     - NULL char is replaced by NEWLINE by backend
        #     - 0x7F (backspace) is replaced by two 0x08 separated by a blankspace
        
        # Check for backspace sequences and log them to Ollama
        if b"\x7f" in self.currentData:
            self.log_local_echo_event("backspace_sequence", self.currentData)
        
        echoed_data = self.currentData.replace(b"\x7f", b"\x08 \x08").replace(b"\x00", b"\n")
        self.sendFrontend(echoed_data)

        # check if done inputing
        if b"\r" in self.currentData:
            terminatingChar = chr(
                self.currentData[self.currentData.index(b"\r") + 1]
            ).encode()  # usually \n or \x00

            # cleanup
            self.usernameState = process_backspaces(self.usernameState)

            log.msg(f"User input login: {self.usernameState.decode('unicode-escape')}")
            self.inputingLogin = False

            # actually send to backend
            self.currentData = self.backendLogin + b"\r" + terminatingChar
            self.sendData = True

            # we now have to ignore the username echo from the backend in the next packet
            self.waitingLoginEcho = True

    def processPasswordInput(self) -> None:
        self.sendData = False  # withold data until input is complete

        if self.prePasswordData:
            self.sendBackend(self.currentData[:3])
            self.prePasswordData = False

        # remove control characters
        control_chars = [b"\xff", b"\xfd", b"\x01", b"\r", b"\x00", b"\n"]
        self.passwordState += remove_all(self.currentData, control_chars)

        # check if done inputing
        if b"\r" in self.currentData:
            terminatingChar = chr(
                self.currentData[self.currentData.index(b"\r") + 1]
            ).encode()  # usually \n or \x00

            # cleanup
            self.passwordState = process_backspaces(self.passwordState)

            log.msg(
                f"User input password: {self.passwordState.decode('unicode-escape')}"
            )
            self.inputingPassword = False

            # having the password (and the username, either empy or set before), we can check the login
            # on the database, and if valid authenticate or else, if invalid send a fake password to get
            # the login failed prompt
            src_ip = self.server.transport.getPeer().host
            if HoneypotPasswordChecker().checkUserPass(
                self.usernameState, self.passwordState, src_ip
            ):
                passwordToSend = self.backendPassword
                self.authDone = True
                self.server.setTimeout(
                    CowrieConfig.getint("honeypot", "idle_timeout", fallback=300)
                )
            else:
                log.msg("Sending invalid auth to backend")
                passwordToSend = self.backendPassword + b"fake"

            # actually send to backend
            self.currentData = passwordToSend + b"\r" + terminatingChar
            self.sendData = True

    def setProcessingStateBackend(self) -> None:
        """
        This function analyses a data packet and sets the processing state of the handler accordingly.
        It looks for authentication phases (password input and username input), as well as data that
        may need to be processed specially.
        """
        hasPassword = re.search(self.passwordPromptRegex, self.currentData)
        if hasPassword:
            log.msg("Password prompt from backend")
            self.authStarted = True
            self.inputingPassword = True
            self.passwordState = b""

        hasLogin = re.search(self.usernamePromptRegex, self.currentData)
        if hasLogin:
            log.msg("Login prompt from backend")
            self.authStarted = True
            self.inputingLogin = True
            self.usernameState = b""

        self.prePasswordData = b"\xff\xfb\x01" in self.currentData

    def setProcessingStateFrontend(self) -> None:
        """
        Same for the frontend.
        """
        # login username is sent in channel negotiation to match the client's username
        negotiationLoginPattern = re.compile(self.usernameInNegotiationRegex)
        hasNegotiationLogin = negotiationLoginPattern.search(self.currentData)
        if hasNegotiationLogin:
            self.usernameState = hasNegotiationLogin.group(2)
            username_str = self.usernameState.decode("unicode-escape")
            log.msg(
                f"Detected username {username_str} in negotiation, spoofing for backend..."
            )

            # Log the environment variable for consistency with shell mode
            log.msg(
                eventid="cowrie.client.var",
                format="Telnet NEW-ENVIRON: %(name)s=%(value)s",
                name="USER",
                value=username_str,
            )

            # CVE-2026-24061 detection: USER environment variable with -f flag
            # This exploit bypasses authentication in GNU inetutils telnetd <= 2.7
            if username_str.startswith("-f"):
                log.msg(
                    eventid="cowrie.telnet.exploit_attempt",
                    format="CVE-2026-24061 exploit attempt detected: USER=%(value)s",
                    cve="CVE-2026-24061",
                    name="USER",
                    value=username_str,
                )

            # spoof username in data sent
            # username is always sent correct, password is the one sent wrong if we don't want to authenticate
            self.currentData = negotiationLoginPattern.sub(
                rb"\1" + self.backendLogin + rb"\3", self.currentData
            )