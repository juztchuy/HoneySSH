"""
HoneySSH Utilities

Essential utilities for terminal handling, session management,
and authentication echo logic.
"""

from utils.terminal import (
    process_backspaces,
    remove_all,
    normalize_line_endings,
    extract_command_until_terminator,
    sanitize_for_llm,
    extract_ansi_codes,
    TerminalBuffer,
)

from utils.session import (
    SessionInfo,
    SessionManager,
    get_session_manager,
    create_session,
)

from utils.echo import (
    AuthenticationEchoHandler,
    LocalEchoHandler,
    create_telnet_echo_sequences,
)

__all__ = [
    # Terminal utilities
    'process_backspaces',
    'remove_all',
    'normalize_line_endings',
    'extract_command_until_terminator',
    'sanitize_for_llm',
    'extract_ansi_codes',
    'TerminalBuffer',
    
    # Session management
    'SessionInfo',
    'SessionManager',
    'get_session_manager',
    'create_session',
    
    # Authentication echo
    'AuthenticationEchoHandler',
    'LocalEchoHandler',
    'create_telnet_echo_sequences',
]
