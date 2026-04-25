from __future__ import annotations

import uuid
from typing import Any

from twisted.conch.ssh import connection, transport, userauth
from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.ssh_proxy.protocols import (
    base_protocol,
    exec_term,
    port_forward,
    sftp,
)
# Use our LLM-integrated Term, not Cowrie's proxy term
from server.protocols import term
from cowrie.ssh_proxy.util import int_to_hex, string_to_hex
from server.protocols.shell import initialize_session_state, update_session_environment

PACKETLAYOUT = (
    transport.messages
    | connection.messages
    | userauth.SSHUserAuthServer.protocolMessages
)

# PACKETLAYOUT = {
#     1: "SSH_MSG_DISCONNECT",  # ['uint32', 'reason_code'], ['string', 'reason'], ['string', 'language_tag']
#     2: "SSH_MSG_IGNORE",  # ['string', 'data']
#     3: "SSH_MSG_UNIMPLEMENTED",  # ['uint32', 'seq_no']
#     4: "SSH_MSG_DEBUG",  # ['boolean', 'always_display']
#     5: "SSH_MSG_SERVICE_REQUEST",  # ['string', 'service_name']
#     6: "SSH_MSG_SERVICE_ACCEPT",  # ['string', 'service_name']
#     7: "SSH_MSG_EXT_INFO",  # ['TODO', 'TODO']
#     20: "SSH_MSG_KEXINIT",  # ['string', 'service_name']
#     21: "SSH_MSG_NEWKEYS",
#     50: "SSH_MSG_USERAUTH_REQUEST",  # ['string', 'username'], ['string', 'service_name'], ['string', 'method_name']
#     51: "SSH_MSG_USERAUTH_FAILURE",  # ['name-list', 'authentications'], ['boolean', 'partial_success']
#     52: "SSH_MSG_USERAUTH_SUCCESS",  #
#     53: "SSH_MSG_USERAUTH_BANNER",  # ['string', 'message'], ['string', 'language_tag']
#     60: "SSH_MSG_USERAUTH_INFO_REQUEST",  # ['string', 'name'], ['string', 'instruction'],
#     # ['string', 'language_tag'], ['uint32', 'num-prompts'],
#     # ['string', 'prompt[x]'], ['boolean', 'echo[x]']
#     61: "SSH_MSG_USERAUTH_INFO_RESPONSE",  # ['uint32', 'num-responses'], ['string', 'response[x]']
#     80: "SSH_MSG_GLOBAL_REQUEST",  # ['string', 'request_name'], ['boolean', 'want_reply']  #tcpip-forward
#     81: "SSH_MSG_REQUEST_SUCCESS",
#     82: "SSH_MSG_REQUEST_FAILURE",
#     90: "SSH_MSG_CHANNEL_OPEN",  # ['string', 'channel_type'], ['uint32', 'sender_channel'],
#     # ['uint32', 'initial_window_size'], ['uint32', 'maximum_packet_size'],
#     91: "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",  # ['uint32', 'recipient_channel'], ['uint32', 'sender_channel'],
#     # ['uint32', 'initial_window_size'], ['uint32', 'maximum_packet_size']
#     92: "SSH_MSG_CHANNEL_OPEN_FAILURE",  # ['uint32', 'recipient_channel'], ['uint32', 'reason_code'],
#     # ['string', 'reason'], ['string', 'language_tag']
#     93: "SSH_MSG_CHANNEL_WINDOW_ADJUST",  # ['uint32', 'recipient_channel'], ['uint32', 'additional_bytes']
#     94: "SSH_MSG_CHANNEL_DATA",  # ['uint32', 'recipient_channel'], ['string', 'data']
#     95: "SSH_MSG_CHANNEL_EXTENDED_DATA",  # ['uint32', 'recipient_channel'],
#     # ['uint32', 'data_type_code'], ['string', 'data']
#     96: "SSH_MSG_CHANNEL_EOF",  # ['uint32', 'recipient_channel']
#     97: "SSH_MSG_CHANNEL_CLOSE",  # ['uint32', 'recipient_channel']
#     98: "SSH_MSG_CHANNEL_REQUEST",  # ['uint32', 'recipient_channel'], ['string', 'request_type'],
#     # ['boolean', 'want_reply']
#     99: "SSH_MSG_CHANNEL_SUCCESS",
#     100: "SSH_MSG_CHANNEL_FAILURE",
# }


class SSH(base_protocol.BaseProtocol):
    def __init__(self, server):
        super().__init__()

        self.channels: list[dict[str, Any]] = []
        self.username: bytes = b""
        self.password: bytes = b""
        self.auth_type: bytes = b""
        self.service: bytes = b""

        self.sendOn: bool = False
        self.expect_password = 0
        self.server = server
        self.client = None
        self.log_raw = CowrieConfig.getboolean("proxy", "log_raw", fallback=False)

    def set_client(self, client):
        self.client = client

    def parse_num_packet(self, parent: str, message_num: int, payload: bytes) -> None:
        self.data = payload
        self.packetSize = len(payload)
        self.sendOn = True

        if parent == "[SERVER]":
            direction = "PROXY -> BACKEND"
        else:
            direction = "BACKEND -> PROXY"

        if self.log_raw:
            log.msg(
                eventid="cowrie.proxy.ssh",
                format="%(direction)s - %(packet)s - %(payload)s",
                direction=direction,
                packet=PACKETLAYOUT[message_num].ljust(37),
                payload=repr(payload),
                protocol="ssh",
            )

        if message_num == transport.MSG_SERVICE_REQUEST:
            service = self.extract_string()
            if service == b"ssh-userauth":
                self.sendOn = False

        elif message_num == userauth.MSG_USERAUTH_BANNER:
            self.sendOn = False

        elif message_num == transport.MSG_EXT_INFO:
            extensioncount: int = self.extract_int(4)
            for _ in range(extensioncount):
                log.msg(
                    f"SSH_MSG_EXT_INFO: {self.extract_string()!r}={self.extract_string()!r}"
                )
            self.sendOn = False

        # - UserAuth
        elif message_num == userauth.MSG_USERAUTH_REQUEST:
            self.sendOn = False
            self.username = self.extract_string()
            self.extract_string()  # service
            self.auth_type = self.extract_string()

            if self.auth_type == b"password":
                self.extract_bool()
                self.password = self.extract_string()
                # self.server.sendPacket(52, b'')

            elif self.auth_type == b"publickey":
                self.sendOn = False
                self.server.sendPacket(51, string_to_hex("password") + chr(0).encode())

        elif message_num == userauth.MSG_USERAUTH_FAILURE:
            self.sendOn = False
            auth_list = self.extract_string()

            if b"publickey" in auth_list:
                log.msg("[SSH] Detected Public Key Auth - Disabling!")
                payload = string_to_hex("password") + chr(0).encode()
                # self.server.sendPacket(51, payload)

        elif message_num == userauth.MSG_USERAUTH_SUCCESS:
            self.sendOn = False

        elif message_num == userauth.MSG_USERAUTH_INFO_REQUEST:
            self.sendOn = False
            self.auth_type = b"keyboard-interactive"
            self.extract_string()
            self.extract_string()
            self.extract_string()
            num_prompts = self.extract_int(4)
            for i in range(0, num_prompts):
                request = self.extract_string()
                self.extract_bool()

                if b"password" in request.lower():
                    self.expect_password = i

        elif message_num == userauth.MSG_USERAUTH_INFO_RESPONSE:
            self.sendOn = False
            num_responses = self.extract_int(4)
            for i in range(0, num_responses):
                response = self.extract_string()
                if i == self.expect_password:
                    self.password = response

        # - End UserAuth
        # - Channels
        elif message_num == connection.MSG_CHANNEL_OPEN:
            channel_type = self.extract_string()
            channel_id = self.extract_int(4)

            log.msg(f"got channel {channel_type!r} request")

            if channel_type == b"session":
                # if using an interactive session reset frontend timeout
                self.server.setTimeout(
                    CowrieConfig.getint("honeypot", "interactive_timeout", fallback=300)
                )

                self.create_channel(parent, channel_id, channel_type)

                if self.client is None:
                    # Standalone: no backend — confirm channel open directly to attacker
                    self.sendOn = False
                    # create_channel stored {"serverID": channel_id}, so
                    # find it via "[CLIENT]" which searches by "serverID".
                    channel = self.get_channel(channel_id, "[CLIENT]")
                    channel["clientID"] = channel_id  # we are our own backend
                    self.server.sendPacket(
                        connection.MSG_CHANNEL_OPEN_CONFIRMATION,
                        int_to_hex(channel_id)    # recipient (attacker's ID)
                        + int_to_hex(channel_id)  # sender   (our ID)
                        + int_to_hex(2097152)     # window   2 MB
                        + int_to_hex(32768),      # max pkt  32 KB
                    )

            elif channel_type == b"direct-tcpip" or channel_type == b"forwarded-tcpip":
                self.extract_int(4)
                self.extract_int(4)

                dst_ip = self.extract_string()
                dst_port = self.extract_int(4)

                src_ip = self.extract_string()
                src_port = self.extract_int(4)

                if CowrieConfig.getboolean("ssh", "forwarding"):
                    log.msg(
                        eventid="cowrie.direct-tcpip.request",
                        format="direct-tcp connection request to %(dst_ip)s:%(dst_port)s "
                        "from %(src_ip)s:%(src_port)s",
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        src_ip=src_ip,
                        src_port=src_port,
                    )

                    the_uuid = uuid.uuid4().hex
                    self.create_channel(parent, channel_id, channel_type)

                    if parent == "[SERVER]":
                        other_parent = "[CLIENT]"
                        the_name = "[LPRTF" + str(channel_id) + "]"
                    else:
                        other_parent = "[SERVER]"
                        the_name = "[RPRTF" + str(channel_id) + "]"

                    channel = self.get_channel(channel_id, other_parent)
                    channel["name"] = the_name
                    channel["session"] = port_forward.PortForward(
                        the_uuid, channel["name"], self
                    )

                else:
                    log.msg("[SSH] Detected Port Forwarding Channel - Disabling!")
                    log.msg(
                        eventid="cowrie.direct-tcpip.data",
                        format="discarded direct-tcp forward request %(id)s to %(dst_ip)s:%(dst_port)s ",
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                    )

                    self.sendOn = False
                    self.send_back(
                        parent,
                        92,
                        int_to_hex(channel_id)
                        + int_to_hex(1)
                        + string_to_hex("open failed")
                        + int_to_hex(0),
                    )
            else:
                # UNKNOWN CHANNEL TYPE
                if channel_type not in [b"exit-status"]:
                    log.msg(f"[SSH Unknown Channel Type Detected - {channel_type!r}")

        elif message_num == connection.MSG_CHANNEL_OPEN_CONFIRMATION:
            channel = self.get_channel(self.extract_int(4), parent)
            # SENDER
            sender_id = self.extract_int(4)

            if parent == "[SERVER]":
                channel["serverID"] = sender_id
            elif parent == "[CLIENT]":
                channel["clientID"] = sender_id
                # CHANNEL OPENED

        elif message_num == connection.MSG_CHANNEL_OPEN_FAILURE:
            channel = self.get_channel(self.extract_int(4), parent)
            self.channels.remove(channel)
            # CHANNEL FAILED TO OPEN

        elif message_num == connection.MSG_CHANNEL_REQUEST:
            channel = self.get_channel(self.extract_int(4), parent)
            channel_type = self.extract_string()
            the_uuid = uuid.uuid4().hex

            if channel_type == b"shell":
                want_reply = self.extract_bool()
                channel["name"] = "[TERM" + str(channel["serverID"]) + "]"
                channel["session"] = term.Term(
                    the_uuid, channel["name"], self, channel["clientID"]
                )
                env_vars = channel.get("env_vars", {})
                initialize_session_state(str(self.server.transportId), env_vars)
                if env_vars:
                    channel["session"].set_terminal_environment(
                        term_type=env_vars.get("TERM", "linux"),
                        env_vars=env_vars,
                    )
                log.msg(f"MSG_CHANNEL_REQUEST: {channel_type!r}")

                if self.client is None:
                    self.sendOn = False
                    if want_reply:
                        self.server.sendPacket(
                            connection.MSG_CHANNEL_SUCCESS,
                            int_to_hex(channel["serverID"]),
                        )

            elif channel_type == b"exec":
                channel["name"] = "[EXEC" + str(channel["serverID"]) + "]"
                self.extract_bool()
                command = self.extract_string()
                channel["session"] = exec_term.ExecTerm(
                    the_uuid, channel["name"], self, channel["serverID"], command
                )
                log.msg(f"MSG_CHANNEL_REQUEST: {channel_type!r}: {command!r}")

            elif channel_type == b"subsystem":
                self.extract_bool()
                subsystem = self.extract_string()
                log.msg(f"MSG_CHANNEL_REQUEST: {channel_type!r}: {subsystem!r}")

                if subsystem == b"sftp":
                    if CowrieConfig.getboolean("ssh", "sftp_enabled"):
                        channel["name"] = "[SFTP" + str(channel["serverID"]) + "]"
                        # self.out.channel_opened(the_uuid, channel['name'])
                        channel["session"] = sftp.SFTP(the_uuid, channel["name"], self)
                    else:
                        # log.msg(log.LPURPLE, '[SSH]', 'Detected SFTP Channel Request - Disabling!')
                        self.sendOn = False
                        self.send_back(parent, 100, int_to_hex(channel["serverID"]))
                else:
                    # UNKNOWN SUBSYSTEM
                    log.msg(f"MSG_CHANNEL_REQUEST: {channel_type!r}: {subsystem!r}")
                    log.msg(
                        "[SSH] Unknown Subsystem Type Detected - " + subsystem.decode()
                    )
            elif channel_type == b"env":
                _ = self.extract_bool()
                var = self.extract_string()
                value = self.extract_string()
                log.msg(f"MSG_CHANNEL_REQUEST: env: {var.decode()}={value.decode()}")

                decoded_var = var.decode(errors="replace")
                decoded_value = value.decode(errors="replace")
                channel.setdefault("env_vars", {})[decoded_var] = decoded_value
                update_session_environment(
                    str(self.server.transportId),
                    {decoded_var: decoded_value},
                )

            elif channel_type == b"pty-req":
                """
                Parse pty-req (pseudo-terminal request) to extract terminal type,
                dimensions, and other terminal-related options.
                Format: string(term_type), uint32(width), uint32(height), uint32(pwidth), uint32(pheight)
                """
                want_reply = self.extract_bool()
                term_type = self.extract_string()
                columns = self.extract_int(4)
                rows = self.extract_int(4)
                # pwidth and pheight are pixel dimensions, usually 0
                _ = self.extract_int(4)  # pwidth
                _ = self.extract_int(4)  # pheight
                
                # TODO: Extract terminal modes (if present)
                # modes = self.extract_string()
                
                log.msg(
                    f"MSG_CHANNEL_REQUEST: pty-req: {term_type.decode()}, "
                    f"cols={columns}, rows={rows}"
                )
                
                # If we have an open terminal session, pass the terminal info to it
                if channel.get("session") and hasattr(channel["session"], "set_terminal_environment"):
                    try:
                        env_vars = {}
                        if "env_vars" in channel:
                            env_vars.update(channel["env_vars"])
                        channel["session"].set_terminal_environment(
                            term_type=term_type.decode() if isinstance(term_type, bytes) else term_type,
                            columns=columns,
                            rows=rows,
                            env_vars=env_vars,
                        )
                        update_session_environment(
                            str(self.server.transportId),
                            {
                                "TERM": term_type.decode() if isinstance(term_type, bytes) else term_type,
                            } | env_vars,
                        )
                    except Exception as e:
                        log.err(f"Error setting terminal environment: {e}")

                if self.client is None:
                    self.sendOn = False
                    if want_reply:
                        self.server.sendPacket(
                            connection.MSG_CHANNEL_SUCCESS,
                            int_to_hex(channel["serverID"]),
                        )

            else:
                # UNKNOWN CHANNEL REQUEST TYPE
                if channel_type not in [
                    b"window-change",
                    b"pty-req",
                    b"exit-status",
                    b"exit-signal",
                ]:
                    log.msg(
                        f"[SSH] Unknown Channel Request Type Detected - {channel_type.decode()}"
                    )

        elif message_num == connection.MSG_CHANNEL_FAILURE:
            pass

        elif message_num == connection.MSG_CHANNEL_WINDOW_ADJUST:
            # Standalone: attacker is expanding our send window — nothing to forward
            if self.client is None:
                self.sendOn = False

        elif message_num == connection.MSG_CHANNEL_CLOSE:
            channel = self.get_channel(self.extract_int(4), parent)
            channel[parent] = True

            if self.client is None:
                # Echo close back so the attacker's SSH client knows we closed too
                self.sendOn = False
                channel["[CLIENT]"] = True
                try:
                    self.server.sendPacket(
                        connection.MSG_CHANNEL_CLOSE,
                        int_to_hex(channel["serverID"]),
                    )
                except Exception:
                    pass

            if "[SERVER]" in channel and "[CLIENT]" in channel:
                if channel["session"] is not None:
                    log.msg("remote close")
                    channel["session"].channel_closed()
                self.channels.remove(channel)

        # - END Channels
        # - ChannelData
        elif message_num == connection.MSG_CHANNEL_DATA:
            channel = self.get_channel(self.extract_int(4), parent)
            channel["session"].parse_packet(parent, self.extract_string())
            self.sendOn = False  # Term sends LLM response via _send_terminal_response

        elif message_num == connection.MSG_CHANNEL_EXTENDED_DATA:
            channel = self.get_channel(self.extract_int(4), parent)
            self.extract_int(4)
            channel["session"].parse_packet(parent, self.extract_string())
            self.sendOn = False
        # - END ChannelData

        elif message_num == connection.MSG_GLOBAL_REQUEST:
            channel_type = self.extract_string()
            if channel_type == b"tcpip-forward":
                if not CowrieConfig.getboolean("ssh", "forwarding"):
                    self.sendOn = False
                    self.send_back(parent, 82, b"")

        else:
            log.msg(f"Unhandled SSH packet: {message_num}")

        if self.sendOn:
            if parent == "[SERVER]":
                if self.client is not None:
                    self.client.sendPacket(message_num, payload)
                # else: standalone — response already sent inline above
            else:
                self.server.sendPacket(message_num, payload)

    def send_back(self, parent: str, message_num: int, payload: bytes) -> None:
        if parent == "[SERVER]":
            direction = "PROXY -> FRONTEND"
        else:
            direction = "PROXY -> BACKEND"

            log.msg(
                eventid="cowrie.proxy.ssh",
                format="%(direction)s - %(packet)s - %(payload)s",
                direction=direction,
                packet=PACKETLAYOUT[message_num].ljust(37),
                payload=repr(payload),
                protocol="ssh",
            )

        if parent == "[SERVER]":
            self.server.sendPacket(message_num, payload)
        elif parent == "[CLIENT]":
            self.client.sendPacket(message_num, payload)

    def create_channel(self, parent, channel_id, channel_type, session=None):
        if parent == "[SERVER]":
            self.channels.append(
                {"serverID": channel_id, "type": channel_type, "session": session}
            )
        elif parent == "[CLIENT]":
            self.channels.append(
                {"clientID": channel_id, "type": channel_type, "session": session}
            )

    def get_channel(self, channel_num: int, parent: str) -> dict[str, Any]:
        the_channel = None
        for channel in self.channels:
            if parent == "[CLIENT]":
                search = "serverID"
            else:
                search = "clientID"

            if channel[search] == channel_num:
                the_channel = channel
                break
        if the_channel is None:
            raise KeyError
        else:
            return the_channel
