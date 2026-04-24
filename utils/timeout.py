"""
Timeout Management

Handles connection timeouts using Twisted's reactor to prevent
botnets from sitting idle on Ollama resources.
"""

from __future__ import annotations

from typing import Optional, Callable, Dict
from twisted.internet import reactor
from twisted.python import log


class SessionTimeout:
    """
    Manages timeout for a single session.
    
    When a session is idle for too long, it will either:
    1. Send a warning/keepalive packet
    2. Drop the connection entirely
    """
    
    def __init__(self, session_id: str, timeout_seconds: int = 300):
        """
        Initialize session timeout.
        
        Args:
            session_id: Unique session identifier
            timeout_seconds: Timeout in seconds (default: 5 minutes)
        """
        self.session_id = session_id
        self.timeout_seconds = timeout_seconds
        self.timeout_call = None
        self.warning_sent = False
    
    def reset(self) -> None:
        """Reset the timeout (called on activity)."""
        if self.timeout_call is not None:
            self.timeout_call.cancel()
            self.timeout_call = None
        
        self.warning_sent = False
        self._schedule_timeout()
    
    def _schedule_timeout(self) -> None:
        """Schedule the timeout callback."""
        if self.timeout_call is not None:
            self.timeout_call.cancel()
        
        self.timeout_call = reactor.callLater(
            self.timeout_seconds,
            self._on_timeout,
        )
    
    def _on_timeout(self) -> None:
        """Called when timeout expires."""
        log.msg(
            f"Session {self.session_id} idle timeout expired "
            f"({self.timeout_seconds}s)"
        )
        
        # TODO: Send notification to registered callback
        # This should trigger connection closure
    
    def cancel(self) -> None:
        """Cancel the timeout (e.g., when session ends)."""
        if self.timeout_call is not None:
            self.timeout_call.cancel()
            self.timeout_call = None
    
    def set_timeout_callback(self, callback: Callable) -> None:
        """
        Set callback to be called when timeout expires.
        
        Args:
            callback: Function to call, receives session_id as argument
        """
        self.timeout_callback = callback


class TimeoutManager:
    """
    Centralized manager for all session timeouts.
    
    This manages idle detection and connection cleanup across
    all active sessions.
    """
    
    def __init__(self, default_timeout: int = 300):
        """
        Initialize timeout manager.
        
        Args:
            default_timeout: Default timeout for new sessions in seconds
        """
        self.default_timeout = default_timeout
        self.timeouts: Dict[str, SessionTimeout] = {}
    
    def create_timeout(self, session_id: str, timeout_seconds: Optional[int] = None) -> SessionTimeout:
        """
        Create a new timeout for a session.
        
        Args:
            session_id: Session identifier
            timeout_seconds: Custom timeout (uses default if None)
        
        Returns:
            SessionTimeout object
        """
        if session_id in self.timeouts:
            self.timeouts[session_id].cancel()
        
        timeout = SessionTimeout(
            session_id,
            timeout_seconds or self.default_timeout,
        )
        timeout.reset()
        self.timeouts[session_id] = timeout
        
        log.msg(f"Timeout created for session {session_id}: {timeout.timeout_seconds}s")
        
        return timeout
    
    def reset_timeout(self, session_id: str) -> None:
        """
        Reset timeout for a session (call on every activity).
        
        Args:
            session_id: Session identifier
        """
        if session_id in self.timeouts:
            self.timeouts[session_id].reset()
    
    def cancel_timeout(self, session_id: str) -> None:
        """
        Cancel and remove timeout for a session.
        
        Args:
            session_id: Session identifier
        """
        if session_id in self.timeouts:
            self.timeouts[session_id].cancel()
            del self.timeouts[session_id]
            log.msg(f"Timeout cancelled for session {session_id}")
    
    def set_timeout_callback(self, session_id: str, callback: Callable) -> None:
        """
        Set callback for when timeout expires.
        
        Args:
            session_id: Session identifier
            callback: Function to call
        """
        if session_id in self.timeouts:
            self.timeouts[session_id].set_timeout_callback(callback)
    
    def cleanup_all(self) -> None:
        """Cancel all timeouts (usually called on shutdown)."""
        for session_id in list(self.timeouts.keys()):
            self.cancel_timeout(session_id)


# Global timeout manager instance
_timeout_manager: Optional[TimeoutManager] = None


def get_timeout_manager(default_timeout: int = 300) -> TimeoutManager:
    """Get or create the global timeout manager."""
    global _timeout_manager
    if _timeout_manager is None:
        _timeout_manager = TimeoutManager(default_timeout)
    return _timeout_manager


def create_session_timeout(session_id: str, timeout_seconds: int = 300) -> SessionTimeout:
    """Create a timeout for a session via the global manager."""
    manager = get_timeout_manager(timeout_seconds)
    return manager.create_timeout(session_id, timeout_seconds)
