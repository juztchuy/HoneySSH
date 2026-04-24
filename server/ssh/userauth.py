from __future__ import annotations

from twisted.conch.ssh.common import getNS
from twisted.python import log

from cowrie.ssh import userauth

# Import the LLM client for Ollama queries
from LLM.client import OllamaClient


# object is added for Python 2.7 compatibility (#1198) - as is super with args
class ProxySSHAuthServer(userauth.HoneyPotSSHUserAuthServer):
    def __init__(self):
        super().__init__()
        self.triedPassword = None

    def auth_password(self, packet):
        """
        Overridden to get password
        """
        self.triedPassword = getNS(packet[1:])[0]

        return super().auth_password(packet)

    def _cbFinishedAuth(self, result):
        """
        We only want to return a success to the user, no service needs to be set.
        Those will be proxied back to the backend.
        """
        self.transport.sendPacket(52, b"")
        self.transport.frontendAuthenticated = True

        # Log authentication event to Ollama client
        try:
            ollama_client = OllamaClient()
            ollama_client.log_authentication(
                session_id=self.transport.transportId,
                username=self.user,
                password=self.triedPassword,
                source_ip=self.transport.peer_ip,
            )
        except Exception as e:
            log.err(f"Error logging authentication to Ollama client: {e}")

        # TODO store this somewhere else, and do not call from here
        if self.transport.sshParse.client:
            self.transport.sshParse.client.authenticateBackend(
                self.user, self.triedPassword
            )