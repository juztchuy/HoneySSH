"""
Terminal and Protocol Utilities

This module provides essential utilities for cleaning up terminal input,
managing line endings, and other protocol-specific operations.
"""

from __future__ import annotations

import re
from typing import Optional


def process_backspaces(s: bytes) -> bytes:
    """
    Takes a user-input string that might have backspaces in it (represented as 0x7F),
    and actually performs the 'backspace operation' to return a clean string.
    
    Example:
        Input:  b"lss\x7fls" (typed "lss" then backspace then "ls")
        Output: b"lsls"
    
    Args:
        s: Input bytes that may contain 0x7F (backspace) characters
    
    Returns:
        Cleaned bytes with backspace operations applied
    """
    n = b""
    for i in range(len(s)):
        char = chr(s[i]).encode()
        if char == b"\x7f":
            if len(n) > 0:
                n = n[:-1]
        else:
            n += char
    return n


def remove_all(original_string: bytes, remove_list: list[bytes]) -> bytes:
    """
    Removes all substrings in the list remove_list from string original_string.
    
    This is useful for removing protocol-specific characters that shouldn't be
    sent to the LLM, such as:
    - Null bytes (\x00) from certain telnet clients
    - Carriage returns (\r) followed by null (\r\x00)
    - Extra newlines
    
    Example:
        Input:  b"hello\r\x00world", [b"\r\x00", b"\x00"]
        Output: b"helloworld"
    
    Args:
        original_string: The string to clean
        remove_list: List of byte sequences to remove
    
    Returns:
        Cleaned string with all substrings removed
    """
    n = original_string
    for substring in remove_list:
        n = n.replace(substring, b"")
    return n


def normalize_line_endings(data: bytes, target: bytes = b"\n") -> bytes:
    """
    Normalize different line ending styles to a single format.
    
    Handles common line ending variations from different clients:
    - \r\n (Windows/Telnet)
    - \r (Mac/Old terminal)
    - \n (Unix - already normalized)
    
    Args:
        data: Input bytes
        target: Target line ending (default: UNIX \n)
    
    Returns:
        Data with normalized line endings
    """
    # First, handle \r\n (most common)
    data = data.replace(b"\r\n", target)
    # Then handle standalone \r
    data = data.replace(b"\r", target)
    return data


def extract_command_until_terminator(
    buffer: bytes, 
    terminators: Optional[list[bytes]] = None
) -> tuple[Optional[bytes], bytes]:
    """
    Extract a complete command from a buffer until a terminator is found.
    
    This is crucial for detecting when the user has pressed Enter and a command
    is ready to send to the LLM.
    
    Args:
        buffer: Input buffer containing partial or complete commands
        terminators: List of byte sequences that mark command end (default: [\r, \n])
    
    Returns:
        Tuple of (complete_command, remaining_buffer)
        If no terminator found: (None, buffer)
    
    Example:
        >>> buf = b"ls -la\r\necho hello\r\n"
        >>> cmd, remaining = extract_command_until_terminator(buf)
        >>> cmd
        b'ls -la'
        >>> remaining
        b'echo hello\r\n'
    """
    if terminators is None:
        terminators = [b"\r\n", b"\r", b"\n"]
    
    for terminator in terminators:
        idx = buffer.find(terminator)
        if idx != -1:
            command = buffer[:idx]
            remaining = buffer[idx + len(terminator):]
            return command, remaining
    
    return None, buffer


def sanitize_for_llm(data: bytes, decode_errors: str = "replace") -> str:
    """
    Sanitize input bytes for safe processing by the LLM.
    
    This function:
    1. Processes backspaces to flatten input
    2. Removes protocol-specific bytes
    3. Normalizes line endings
    4. Decodes to UTF-8
    
    Args:
        data: Raw bytes from terminal
        decode_errors: How to handle decode errors ('replace', 'ignore', 'strict')
    
    Returns:
        Clean string safe for LLM processing
    """
    # Clean up backspaces
    cleaned = process_backspaces(data)
    
    # Remove null bytes and common protocol artifacts
    cleaned = remove_all(cleaned, [b"\x00", b"\xff", b"\x01", b"\x02"])
    
    # Normalize line endings
    cleaned = normalize_line_endings(cleaned)
    
    # Decode to string
    try:
        return cleaned.decode("utf-8", errors=decode_errors)
    except Exception as e:
        # Fallback to latin-1 which accepts all byte values
        return cleaned.decode("latin-1", errors="replace")


def extract_ansi_codes(data: bytes) -> tuple[str, list[str]]:
    """
    Extract ANSI escape codes from data for terminal configuration detection.
    
    This helps identify what kind of terminal the user is using.
    Common codes:
    - \x1b[1m - Bold
    - \x1b[22m - Normal intensity
    - \x1b[91m - Bright red
    - \x1b[?1049h - Alternate screen buffer (vi, less, etc.)
    
    Args:
        data: Raw bytes that may contain ANSI codes
    
    Returns:
        Tuple of (text_without_codes, list_of_codes_found)
    
    TODO: Use this for terminal capability detection
    """
    ansi_pattern = rb'\x1b\[[^a-zA-Z]*[a-zA-Z]'
    
    codes = re.findall(ansi_pattern, data)
    text = re.sub(ansi_pattern, b'', data)
    
    code_list = [c.decode('utf-8', errors='replace') for c in codes]
    
    return text.decode('utf-8', errors='replace'), code_list


class TerminalBuffer:
    """
    Manages terminal input buffering with support for:
    - Incremental command building
    - Backspace handling
    - Multi-line command detection
    """
    
    def __init__(self, max_buffer_size: int = 4096):
        """
        Initialize the terminal buffer.
        
        Args:
            max_buffer_size: Maximum bytes to buffer before forcing flush
        """
        self.buffer = b""
        self.max_buffer_size = max_buffer_size
        self.commands_history: list[str] = []
    
    def add_data(self, data: bytes) -> Optional[bytes]:
        """
        Add new data to the buffer and check for complete commands.
        
        Args:
            data: New bytes received from terminal
        
        Returns:
            Complete command (bytes) if found, None otherwise
        """
        self.buffer += data
        
        # Check for command terminators
        command, self.buffer = extract_command_until_terminator(self.buffer)
        
        # Check for buffer overflow
        if len(self.buffer) > self.max_buffer_size:
            # Force flush - something is wrong
            command = self.buffer[:self.max_buffer_size]
            self.buffer = b""
        
        return command
    
    def get_partial_command(self) -> str:
        """Get the current partial command being typed (for real-time analysis)."""
        return sanitize_for_llm(self.buffer)
    
    def clear(self) -> None:
        """Clear the buffer."""
        self.buffer = b""
    
    def flush(self) -> Optional[bytes]:
        """Force flush remaining buffer as a command."""
        if self.buffer:
            cmd = self.buffer
            self.buffer = b""
            return cmd
        return None
