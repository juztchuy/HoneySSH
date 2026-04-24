"""
Authentication Echo Handler

Handles local echo for authentication phase.

When a user logs in over Telnet or SSH, they expect:
1. Username prompt: echo their input (so they see what they type)
2. Password prompt: NO echo (so bystanders don't see passwords)

This module implements that logic.
"""

from __future__ import annotations

from typing import Optional
from twisted.python import log


class AuthenticationEchoHandler:
    """
    Manages local echo during authentication phase.
    
    The key caveat: In Telnet, when the server receives user input,
    it should echo it back so the user sees it on their terminal.
    But during password entry, it should NOT echo (for security).
    
    The flow:
    1. Server asks for username (no data yet)
    2. User types "admin" (4 keystrokes)
    3. Server receives "admin" and echoes it back
    4. User sees "admin" on screen
    5. User presses Enter
    6. Server asks for password
    7. User types "secret" (6 keystrokes)
    8. Server receives "secret" but does NOT echo it
    9. User sees nothing (password is hidden)
    """
    
    def __init__(self):
        """Initialize the echo handler."""
        self.in_authentication: bool = False
        self.awaiting_username: bool = False
        self.awaiting_password: bool = False
        self.current_username: bytes = b""
        self.username_echo_buffer: bytes = b""
    
    def start_authentication(self) -> None:
        """Signal that authentication phase has started."""
        self.in_authentication = True
        self.awaiting_username = True
        self.awaiting_password = False
        self.current_username = b""
        self.username_echo_buffer = b""
        
        log.msg("Authentication phase started - enabled local echo")
    
    def end_authentication(self, username: str) -> None:
        """
        Signal that authentication phase has ended (successful login).
        
        Args:
            username: The authenticated username
        """
        self.in_authentication = False
        self.awaiting_username = False
        self.awaiting_password = False
        self.current_username = username.encode()
        
        log.msg(f"Authentication phase ended - user {username} authenticated")
    
    def process_input(self, data: bytes) -> tuple[bytes, bytes]:
        """
        Process user input and determine what to echo back.
        
        Args:
            data: Raw bytes from the user
        
        Returns:
            Tuple of (data_to_send_to_backend, data_to_echo_to_frontend)
        
        The function handles special cases:
        - 0x7F (DEL/Backspace): Convert to 0x08 0x20 0x08 (proper Telnet sequence)
        - 0x03 (Ctrl+C): Echo as ^C
        - 0x04 (Ctrl+D): EOF character
        - 0x0D (Enter/CR): Terminator for current field
        """
        if not self.in_authentication:
            # Not in auth phase - no echo
            return data, b""
        
        echo_back = b""
        
        if self.awaiting_password:
            # During password entry: NO echo back to frontend
            echo_back = b""
        
        elif self.awaiting_username:
            # During username entry: echo everything back
            for byte in data:
                char = bytes([byte])
                
                if char == b"\x7f":  # Backspace/DEL
                    # Telnet backspace: 0x08 (BS) + 0x20 (space) + 0x08 (BS)
                    # This erases the character on screen
                    if len(self.current_username) > 0:
                        self.current_username = self.current_username[:-1]
                        echo_back += b"\x08 \x08"
                
                elif char == b"\x03":  # Ctrl+C
                    echo_back += b"^C"
                    self.current_username = b""
                
                elif char == b"\x0d" or char == b"\x0a":  # CR or LF
                    # End of username entry
                    echo_back += char
                    self.awaiting_username = False
                    self.awaiting_password = True
                
                elif char == b"\x00":  # Null byte - skip
                    pass
                
                else:  # Regular character
                    echo_back += char
                    self.current_username += char
        
        return data, echo_back
    
    def handle_ctrl_c(self) -> bytes:
        """Handle Ctrl+C during authentication."""
        self.current_username = b""
        if self.awaiting_password:
            self.awaiting_password = False
            self.awaiting_username = True
        return b"^C\r\n"
    
    def get_username_so_far(self) -> str:
        """Get the username currently being entered (for real-time display)."""
        return self.current_username.decode("utf-8", errors="replace")


class LocalEchoHandler:
    """
    Implements proper Telnet local echo behavior.
    
    Reference: RFC 858 (Telnet ECHO Option)
    
    In Telnet, when the server sets the ECHO option, the server echoes
    the user's input back so they can see what they're typing.
    """
    
    def __init__(self):
        """Initialize the local echo handler."""
        self.echo_enabled: bool = False
        self.suppress_go_ahead: bool = False
    
    def enable_echo(self) -> None:
        """Enable local echo."""
        self.echo_enabled = True
        log.msg("Local echo enabled")
    
    def disable_echo(self) -> None:
        """Disable local echo (e.g., for password entry)."""
        self.echo_enabled = False
        log.msg("Local echo disabled")
    
    def echo_if_enabled(self, data: bytes) -> bytes:
        """
        Echo data back if echo is enabled, handling special cases.
        
        Args:
            data: Data to potentially echo
        
        Returns:
            Data to send back to client (may be empty if echo disabled)
        """
        if not self.echo_enabled:
            return b""
        
        return self._process_echo(data)
    
    def _process_echo(self, data: bytes) -> bytes:
        """
        Process echo with special handling for control characters.
        
        Args:
            data: Data to echo
        
        Returns:
            Processed echo output
        """
        output = b""
        
        for byte in data:
            char = bytes([byte])
            
            if char == b"\x7f":  # DEL/Backspace
                # Telnet backspace sequence: BS SPACE BS
                output += b"\x08 \x08"
            
            elif char == b"\x03":  # Ctrl+C
                # Echo as ^C
                output += b"\x03"  # Send the Ctrl+C as-is
            
            elif char == b"\x04":  # Ctrl+D (EOF)
                # Don't echo EOF character
                pass
            
            elif char == b"\x0d" or char == b"\x0a":  # CR or LF
                # Echo the line terminator
                output += b"\r\n"
            
            elif ord(char) < 32:  # Control character
                # Echo as ^X where X is the character
                output += b"^" + bytes([ord(char) + 64])
            
            else:  # Printable character
                output += char
        
        return output


def create_telnet_echo_sequences(action: str) -> bytes:
    """
    Create standard Telnet echo sequences.
    
    Args:
        action: One of:
            - 'backspace': Delete one character
            - 'clear_line': Clear entire line
            - 'newline': Start new line
    
    Returns:
        Bytes to send to client
    
    TODO: Extend with more Telnet sequences as needed
    """
    sequences = {
        'backspace': b"\x08 \x08",  # BS SPACE BS
        'clear_line': b"\x1b[2K",    # ANSI clear line
        'newline': b"\r\n",
        'bell': b"\x07",             # BEL - alert/bell
    }
    
    return sequences.get(action, b"")
