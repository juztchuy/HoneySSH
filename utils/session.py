"""
Session Management

Manages session lifecycle, including UUIDs, environment tracking,
timeouts, and connection state.
"""

from __future__ import annotations

import time
import uuid as uuid_lib
from typing import Optional, Dict, Any
from twisted.python import log


class SessionInfo:
    """
    Tracks session metadata and environment.
    
    This is used to keep track of:
    - Unique session ID for LLM conversation history
    - Terminal type and environment variables
    - Authentication state
    - Idle timeouts
    - Source/destination IPs
    """
    
    def __init__(self, source_ip: str, source_port: int, dest_ip: str, dest_port: int):
        """
        Initialize a new session.
        
        Args:
            source_ip: Attacker's IP address
            source_port: Attacker's port
            dest_ip: Honeypot's bind IP
            dest_port: Honeypot's listening port
        """
        self.session_id: str = uuid_lib.uuid4().hex[:12]
        self.session_start: float = time.time()
        
        # Network info
        self.source_ip = source_ip
        self.source_port = source_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        
        # Authentication
        self.authenticated: bool = False
        self.username: Optional[str] = None
        self.auth_method: Optional[str] = None  # 'password', 'public-key', 'keyboard-interactive'
        self.auth_time: Optional[float] = None
        
        # Terminal environment
        self.terminal_type: str = "linux"  # Default fallback
        self.terminal_width: int = 80
        self.terminal_height: int = 24
        self.environment_vars: Dict[str, str] = {}
        
        # Protocol-specific
        self.protocol: str = "unknown"  # 'ssh', 'telnet'
        self.telnet_options: Dict[str, bool] = {}
        
        # Activity tracking
        self.last_activity: float = self.session_start
        self.command_count: int = 0
        
        log.msg(
            f"Session {self.session_id} created from {source_ip}:{source_port}"
        )
    
    def mark_authenticated(self, username: str, auth_method: str = "password") -> None:
        """Mark session as authenticated."""
        self.authenticated = True
        self.username = username
        self.auth_method = auth_method
        self.auth_time = time.time()
        
        log.msg(
            f"Session {self.session_id} authenticated as {username} "
            f"(method: {auth_method})"
        )
    
    def update_terminal_info(
        self,
        term_type: str,
        width: int = 80,
        height: int = 24,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> None:
        """Update terminal environment information."""
        self.terminal_type = term_type
        self.terminal_width = width
        self.terminal_height = height
        if env_vars:
            self.environment_vars.update(env_vars)
        
        log.msg(
            f"Session {self.session_id} terminal: {term_type} "
            f"{width}x{height}"
        )
    
    def record_command(self, command: str) -> None:
        """Record that a command was executed."""
        self.command_count += 1
        self.last_activity = time.time()
    
    def touch(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = time.time()
    
    def is_idle(self, timeout_seconds: int = 300) -> bool:
        """
        Check if session has been idle for longer than timeout.
        
        Args:
            timeout_seconds: Idle timeout in seconds (default: 5 minutes)
        
        Returns:
            True if idle, False otherwise
        """
        elapsed = time.time() - self.last_activity
        return elapsed > timeout_seconds
    
    def get_idle_time(self) -> float:
        """Get seconds since last activity."""
        return time.time() - self.last_activity
    
    def get_session_duration(self) -> float:
        """Get total session duration in seconds."""
        return time.time() - self.session_start
    
    def get_context_dict(self) -> Dict[str, Any]:
        """
        Get session context as a dictionary for passing to LLM.
        
        Returns:
            Dictionary with all relevant session context
        """
        return {
            'session_id': self.session_id,
            'username': self.username,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'protocol': self.protocol,
            'terminal': {
                'type': self.terminal_type,
                'width': self.terminal_width,
                'height': self.terminal_height,
            },
            'environment': self.environment_vars,
            'telnet_options': self.telnet_options,
            'authenticated': self.authenticated,
            'command_count': self.command_count,
            'duration_seconds': self.get_session_duration(),
        }
    
    def close(self) -> None:
        """Log session closure."""
        duration = self.get_session_duration()
        log.msg(
            f"Session {self.session_id} closed after {duration:.1f}s "
            f"({self.command_count} commands)"
        )


class SessionManager:
    """
    Manages all active sessions.
    
    This provides centralized tracking and cleanup of sessions.
    """
    
    def __init__(self, idle_timeout: int = 300):
        """
        Initialize the session manager.
        
        Args:
            idle_timeout: Idle timeout for sessions in seconds
        """
        self.sessions: Dict[str, SessionInfo] = {}
        self.idle_timeout = idle_timeout
    
    def create_session(
        self,
        source_ip: str,
        source_port: int,
        dest_ip: str,
        dest_port: int,
    ) -> SessionInfo:
        """Create and register a new session."""
        session = SessionInfo(source_ip, source_port, dest_ip, dest_port)
        self.sessions[session.session_id] = session
        return session
    
    def get_session(self, session_id: str) -> Optional[SessionInfo]:
        """Retrieve a session by ID."""
        return self.sessions.get(session_id)
    
    def cleanup_idle_sessions(self) -> int:
        """
        Remove idle sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        cleaned = 0
        sessions_to_remove = []
        
        for session_id, session in self.sessions.items():
            if session.is_idle(self.idle_timeout):
                sessions_to_remove.append(session_id)
                cleaned += 1
        
        for session_id in sessions_to_remove:
            session = self.sessions.pop(session_id)
            session.close()
            log.msg(f"Cleaned up idle session {session_id}")
        
        return cleaned
    
    def get_active_session_count(self) -> int:
        """Get number of active sessions."""
        return len(self.sessions)


# Global session manager instance
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """
    Get or create the global session manager.
    
    Returns:
        SessionManager instance
    """
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


def create_session(
    source_ip: str,
    source_port: int,
    dest_ip: str,
    dest_port: int,
) -> SessionInfo:
    """Create a new session via the global manager."""
    manager = get_session_manager()
    return manager.create_session(source_ip, source_port, dest_ip, dest_port)
