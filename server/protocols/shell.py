"""
Shell Protocol Bridge

This module acts as the bridge between the terminal protocols (SSH, Telnet)
and the LLM client (Ollama).

The flow is:
1. User types a command (captured by Term or TelnetHandler)
2. User presses Enter (triggers command termination)
3. Command is passed to this bridge
4. Bridge calls LLM for analysis
5. Response is processed and sent back to user
"""

from __future__ import annotations

import time
import json
import os
import posixpath  # always POSIX paths for the simulated Linux filesystem
from typing import Optional, Dict, Any
from twisted.python import log

from LLM.client import OllamaClient
from utils.terminal import sanitize_for_llm, process_backspaces
from utils.session import SessionInfo, get_session_manager


class SessionStateTracker:
    """
    Tracks the execution state of a shell session.
    
    The LLM needs to know:
    - Where the attacker is (cwd)
    - What environment they have (env vars)
    - What they're typing (buffer)
    
    This class maintains that state and updates it as commands execute.
    """
    
    def __init__(self):
        """Initialize the state tracker."""
        # Map of session_id -> state dict
        self.session_states: Dict[str, Dict[str, Any]] = {}
    
    def initialize_state(
        self,
        session_id: str,
        env_vars: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """
        Initialize state for a new session.
        
        Args:
            session_id: Unique session identifier
            env_vars: Environment variables from authentication handshake
        
        Returns:
            Initial state dictionary
        """
        state = {
            'cwd': '/home/ubuntu',  # Default — overridden per-session by initialize_llm_session
            'env': env_vars or {},
            'buffer': '',
            'previous_cwd': None,  # For 'cd -' support
            'history': [],  # Command history
        }
        
        self.session_states[session_id] = state
        log.msg(f"Initialized state for session {session_id}: cwd={state['cwd']}")
        
        return state
    
    def get_state(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the current state for a session.
        
        Args:
            session_id: Session identifier
        
        Returns:
            State dict or None if not found
        """
        return self.session_states.get(session_id)

    def ensure_state(
        self,
        session_id: str,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Get an existing state or create a new one on demand."""
        state = self.get_state(session_id)
        if state is None:
            state = self.initialize_state(session_id, env_vars)
        elif env_vars:
            state['env'].update(env_vars)
        return state

    def update_environment(
        self,
        session_id: str,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Merge newly observed environment variables into session state."""
        state = self.ensure_state(session_id)
        if env_vars:
            state['env'].update(env_vars)
        return state

    def update_buffer(self, session_id: str, buffer: bytes | str) -> str:
        """
        Store the current line buffer after applying terminal cleanup.

        The shell buffer is what the attacker is typing right now, not yet
        executed. It is updated incrementally by the terminal protocol.
        """
        state = self.ensure_state(session_id)
        if isinstance(buffer, bytes):
            cleaned_buffer = sanitize_for_llm(process_backspaces(buffer)).strip("\r\n")
        else:
            cleaned_buffer = buffer.strip("\r\n")
        state['buffer'] = cleaned_buffer
        return cleaned_buffer

    def freeze_buffer(self, session_id: str, fallback: bytes | str = b"") -> str:
        """
        Freeze the current line on Enter, then clear the live typing buffer.
        """
        state = self.ensure_state(session_id)
        frozen_buffer = state.get('buffer', '')
        if not frozen_buffer:
            frozen_buffer = self.update_buffer(session_id, fallback)
        state['buffer'] = ''
        return frozen_buffer
    
    def _resolve_path(self, cwd: str, path: str) -> str:
        """
        Resolve a path relative to the current working directory.
        
        This is a HONEYPOT PATH RESOLVER - we don't actually access the filesystem,
        we just simulate it for the LLM.
        
        Args:
            cwd: Current working directory
            path: Path to resolve (can be relative or absolute)
        
        Returns:
            Resolved absolute path
        """
        # If path is absolute, use it directly
        if path.startswith('/'):
            return posixpath.normpath(path)

        # If path is relative, resolve from cwd
        resolved = posixpath.join(cwd, path)
        normalized = posixpath.normpath(resolved)
        
        return normalized
    
    def update_cwd_from_command(self, session_id: str, command: str) -> bool:
        """
        Parse a command and update cwd if it's a 'cd' command.
        
        Args:
            session_id: Session identifier
            command: The command that was executed
        
        Returns:
            True if cwd was updated, False otherwise
        """
        state = self.get_state(session_id)
        if not state:
            return False
        
        # Tokenize command (simple split on whitespace)
        tokens = command.split()
        if not tokens:
            return False
        
        cmd = tokens[0].lower()
        
        # Handle 'cd' command
        if cmd == 'cd':
            old_cwd = state['cwd']
            home = state.get('home_dir', '/home/ubuntu')

            if len(tokens) == 1:
                state['previous_cwd'] = old_cwd
                state['cwd'] = home
            elif tokens[1] == '-':
                if state['previous_cwd']:
                    target = state['previous_cwd']
                    state['previous_cwd'] = old_cwd
                    state['cwd'] = target
            elif tokens[1] in ('~', f'~{state.get("home_dir", "")}'.rstrip('/')):
                state['previous_cwd'] = old_cwd
                state['cwd'] = home
            else:
                target_path = tokens[1]
                new_cwd = self._resolve_path(old_cwd, target_path)
                state['previous_cwd'] = old_cwd
                state['cwd'] = new_cwd
            
            log.msg(
                f"Session {session_id} changed directory",
                from_cwd=old_cwd,
                to_cwd=state['cwd'],
            )
            
            return True
        
        # Handle 'pwd' command (just logs current directory)
        elif cmd == 'pwd':
            log.msg(f"Session {session_id} queried cwd: {state['cwd']}")
            return False
        
        return False
    
    def build_execution_payload(
        self,
        session_id: str,
        command: str,
        username: str = "unknown",
        source_ip: str = "0.0.0.0",
    ) -> Dict[str, Any]:
        """
        Build JSON payload for LLM execution context.
        
        This wraps the command with all relevant state (cwd, env, session info)
        that the LLM needs to properly analyze and respond.
        
        Args:
            session_id: Session identifier
            command: The command being executed
            username: SSH username
            source_ip: Source IP address
        
        Returns:
            Payload dictionary ready for JSON serialization
        """
        state = self.get_state(session_id)
        if not state:
            return {'error': 'Session state not found'}
        
        # Create execution context
        payload = {
            'session_id': session_id,
            'timestamp': time.time(),
            'user': {
                'username': username,
                'source_ip': source_ip,
            },
            'execution': {
                'cwd': state['cwd'],
                'command': command,
                'environment': state['env'],
            },
            'state': {
                'buffer': state.get('buffer', ''),
                'previous_cwd': state.get('previous_cwd'),
                'history_count': len(state.get('history', [])),
            },
        }
        
        return payload
    
    def record_command(
        self,
        session_id: str,
        command: str,
    ) -> None:
        """
        Record a command in session history.
        
        Args:
            session_id: Session identifier
            command: The command to record
        """
        state = self.get_state(session_id)
        if state:
            state['history'].append({
                'command': command,
                'cwd': state['cwd'],
                'timestamp': time.time(),
            })
            
            # Keep history limit to prevent memory exhaustion
            if len(state['history']) > 1000:
                state['history'] = state['history'][-500:]
    
    def get_state_for_llm(self, session_id: str) -> Dict[str, str]:
        """
        Get a formatted state dictionary suitable for LLM context.
        
        Args:
            session_id: Session identifier
        
        Returns:
            Dict with 'cwd' and 'env' keys
        """
        state = self.get_state(session_id)
        if not state:
            return {'cwd': '/home/user', 'env': {}}
        
        return {
            'cwd': state['cwd'],
            'env': state['env'],
            'buffer': state.get('buffer', ''),
        }
    
    def cleanup_state(self, session_id: str) -> None:
        """
        Cleanup state when session ends.
        
        Args:
            session_id: Session identifier
        """
        if session_id in self.session_states:
            state = self.session_states.pop(session_id)
            log.msg(
                f"Cleaned up state for session {session_id}",
                final_cwd=state['cwd'],
                commands_executed=len(state.get('history', [])),
            )


class ShellCommandBridge:
    """
    Bridge between terminal protocols and LLM.
    
    This class processes commands from SSH/Telnet sessions and routes them
    to the Ollama LLM for analysis.
    """
    
    def __init__(self):
        """Initialize the shell bridge."""
        self.ollama_client = OllamaClient()
        self.session_manager = get_session_manager()
        self.state_tracker = SessionStateTracker()
        
        # Command cache for rate limiting and deduplication
        self.last_command_hash: Dict[str, int] = {}
        self.duplicate_threshold: int = 5  # Seconds

    def update_session_environment(
        self,
        session_id: str,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Public wrapper for environment updates from protocol handlers."""
        return self.state_tracker.update_environment(session_id, env_vars)

    def update_session_buffer(self, session_id: str, buffer: bytes | str) -> str:
        """Public wrapper for live line-buffer updates from protocol handlers."""
        return self.state_tracker.update_buffer(session_id, buffer)

    def _get_or_create_session(self, session_id: str, protocol: str) -> SessionInfo:
        """
        Ensure command processing still works even if session registration
        has not been wired in yet by the transport layer.
        """
        session = self.session_manager.get_session(session_id)
        if session is None:
            session = SessionInfo("0.0.0.0", 0, "0.0.0.0", 0)
            session.session_id = session_id
            session.protocol = protocol
            self.session_manager.sessions[session_id] = session
        return session
    
    def initialize_session_state(
        self,
        session_id: str,
        environment_vars: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """
        Initialize state tracking for a new session.
        
        This should be called when a session is first created.
        
        Args:
            session_id: Unique session identifier
            environment_vars: Environment variables from authentication
        
        Returns:
            Initial state dictionary
        """
        return self.state_tracker.ensure_state(session_id, environment_vars)

    def initialize_llm_session(
        self,
        session_id: str,
        username: str = "ubuntu",
        hostname: str = "ubuntu-srv",
    ) -> None:
        """
        Seed the LLM with the attacker's identity and set the session cwd
        to the correct home directory for that user.
        """
        self.ollama_client.initialize_session(session_id, username, hostname)
        home = "/root" if username == "root" else f"/home/{username}"
        state = self.state_tracker.ensure_state(session_id)
        state["cwd"] = home
        state["home_dir"] = home

    def process_shell_command(
        self,
        session_id: str,
        command: bytes,
        protocol: str = "ssh",
    ) -> Dict[str, Any]:
        """
        Main entry point for processing shell commands.
        
        This should be called by Term.py and TelnetHandler when a complete
        command is ready (i.e., when Enter is pressed).
        
        Args:
            session_id: Unique session identifier
            command: Raw command bytes (may contain backspaces, control chars)
            protocol: Protocol type ('ssh', 'telnet')
        
        Returns:
            Dictionary with LLM analysis results and execution context
        
        EXECUTION TRIGGER: This is called when \r (Enter key) is detected.
        The buffer is frozen here and sent to the LLM.
        """
        
        # Get session info
        session = self._get_or_create_session(session_id, protocol)
        
        # Freeze the live line buffer at the moment Enter was pressed.
        frozen_buffer = self.state_tracker.freeze_buffer(session_id, command)

        # Clean up command
        try:
            cleaned_command = frozen_buffer or self._sanitize_command(command)
        except Exception as e:
            log.err(f"Error sanitizing command: {e}")
            return {"error": f"Command sanitization failed: {e}"}
        
        if not cleaned_command or cleaned_command.isspace():
            # Empty command, don't send to LLM
            return {"empty": True}
        
        # Check for duplicate commands (rate limiting)
        if self._is_duplicate_command(session_id, cleaned_command):
            log.msg(f"Duplicate command detected for session {session_id}")
            return {"duplicate": True}
        
        # Record command in state history
        self.state_tracker.record_command(session_id, cleaned_command)
        
        # Record this command in the session
        session.record_command(cleaned_command)
        
        # Build execution payload with current state (cwd, env)
        execution_payload = self.state_tracker.build_execution_payload(
            session_id=session_id,
            command=cleaned_command,
            username=session.username or "unknown",
            source_ip=session.source_ip or "0.0.0.0",
        )
        execution_payload.setdefault('state', {})['buffer'] = cleaned_command
        llm_payload_json = json.dumps(execution_payload, ensure_ascii=True)
        
        # Build context for LLM
        context = self._build_llm_context(session, cleaned_command, protocol)
        
        # Get state for LLM (cwd, env)
        state = self.state_tracker.get_state_for_llm(session_id)
        
        # Log command for debugging
        log.msg(
            f"Session {session_id} ({protocol}): Processing command",
            command=cleaned_command[:100],  # Truncate for logging
            cwd=state.get('cwd', '/home/user'),
            username=session.username,
        )
        
        llm_response_text = self._call_llm_string(
            session=session,
            protocol=protocol,
            command=cleaned_command,
            execution_payload=execution_payload,
        )

        # Only update cwd after the LLM confirms cd succeeded (no output = success in bash)
        first_token = cleaned_command.split()[0].lower() if cleaned_command.split() else ""
        if first_token == "cd" and not llm_response_text.strip():
            self.state_tracker.update_cwd_from_command(session_id, cleaned_command)

        terminal_response = self.format_response_for_terminal(
            {
                'error': execution_payload.get('error'),
                'llm_response': llm_response_text,
            },
            session,
        )

        # Build the result with full context
        result = {
            'session_id': session_id,
            'command': cleaned_command,
            'context': context,
            'llm_payload_json': llm_payload_json,
            'execution_payload': execution_payload,  # Send cwd, env to LLM
            'state': state,  # Current cwd and env
            'llm_response': llm_response_text,
            'terminal_response': terminal_response,
            'status': 'analysis_complete',
        }

        return result

    def _call_llm_string(
        self,
        session: SessionInfo,
        protocol: str,
        command: str,
        execution_payload: Dict[str, Any],
    ) -> str:
        """
        Call the LLM module synchronously and coerce the result into a string.
        """
        try:
            llm_result = self.ollama_client.process_command_execution(
                session_id=session.session_id,
                command=command.encode("utf-8", errors="replace"),
                channel_type=protocol,
                username=session.username,
                source_ip=session.source_ip,
                environment=execution_payload['execution']['environment'],
                cwd=execution_payload['execution']['cwd'],
            )
        except Exception as e:
            log.err(f"LLM command execution failed for session {session.session_id}: {e}")
            return ""

        if isinstance(llm_result, str):
            return llm_result

        if isinstance(llm_result, dict):
            for key in ("response", "output", "text", "message"):
                value = llm_result.get(key)
                if isinstance(value, str):
                    return value

            meaningful_result = {
                key: value
                for key, value in llm_result.items()
                if value not in (None, "", [], {})
            }
            if meaningful_result:
                return json.dumps(meaningful_result, ensure_ascii=True)

        return ""
    
    def _sanitize_command(self, command: bytes) -> str:
        """
        Sanitize command for LLM processing.
        
        Args:
            command: Raw command bytes
        
        Returns:
            Clean command string
        """
        # Process backspaces first
        cleaned = process_backspaces(command)
        
        # Use the comprehensive sanitization utility
        sanitized = sanitize_for_llm(cleaned)
        
        # Remove any remaining whitespace
        sanitized = sanitized.strip()
        
        return sanitized
    
    def _is_duplicate_command(self, session_id: str, command: str) -> bool:
        """
        Check if this is a duplicate command sent recently.
        
        Args:
            session_id: Session identifier
            command: Command to check
        
        Returns:
            True if duplicate, False otherwise
        """
        import hashlib
        
        cmd_hash = hashlib.md5(command.encode()).hexdigest()
        key = f"{session_id}:{cmd_hash}"
        
        current_time = time.time()
        
        if key in self.last_command_hash:
            elapsed = current_time - self.last_command_hash[key]
            if elapsed < self.duplicate_threshold:
                return True
        
        # Update timestamp
        self.last_command_hash[key] = current_time
        
        # Cleanup old entries (older than 1 hour)
        for k in list(self.last_command_hash.keys()):
            if current_time - self.last_command_hash[k] > 3600:
                del self.last_command_hash[k]
        
        return False
    
    def _build_llm_context(
        self,
        session: SessionInfo,
        command: str,
        protocol: str,
    ) -> Dict[str, Any]:
        """
        Build context information to send to the LLM.
        
        Args:
            session: SessionInfo object with context
            command: The command being executed
            protocol: Protocol type
        
        Returns:
            Dictionary with contextual information for the LLM
        """
        return {
            'session_id': session.session_id,
            'username': session.username,
            'source_ip': session.source_ip,
            'protocol': protocol,
            'command': command,
            'terminal': {
                'type': session.terminal_type,
                'width': session.terminal_width,
                'height': session.terminal_height,
            },
            'environment': session.environment_vars,
            'telnet_options': session.telnet_options if protocol == 'telnet' else {},
            'authenticated': session.authenticated,
            'command_count': session.command_count,
            'session_duration': session.get_session_duration(),
        }
    
    def format_response_for_terminal(
        self,
        response: Dict[str, Any],
        session: SessionInfo,
    ) -> bytes:
        """
        Format LLM response for display in the terminal.
        
        This handles ANSI color codes based on terminal capabilities,
        and respects terminal dimensions for line wrapping.
        
        Args:
            response: LLM analysis results
            session: Session info (for terminal capabilities)
        
        Returns:
            Bytes ready to send back to the terminal
        
        TODO: Implement response formatting with ANSI codes if terminal supports it
        """
        
        # Check if terminal supports colors
        supports_color = session.terminal_type not in ['dumb', 'unknown', 'vt100']
        
        output = ""
        
        # TODO: Format response based on:
        # - Terminal type (TERM variable)
        # - Terminal width (for wrapping)
        # - Whether colors are supported
        
        # For now, just return a basic response
        if response.get('error'):
            output = f"[ERROR] {response['error']}\r\n"
        elif response.get('empty'):
            pass  # Don't output anything for empty commands
        elif response.get('duplicate'):
            pass  # Don't output anything for duplicate commands
        else:
            llm_response = response.get('llm_response', '')
            if llm_response:
                if not llm_response.endswith("\n"):
                    llm_response += "\n"
                output = llm_response.replace("\n", "\r\n")

        return output.encode()
    
    def cleanup_session(self, session_id: str) -> None:
        """
        Cleanup when a session ends.
        
        Args:
            session_id: Session to cleanup
        """
        # Clean up session state
        self.state_tracker.cleanup_state(session_id)
        
        # Clean up session info
        session = self.session_manager.get_session(session_id)
        if session:
            session.close()
        
        # TODO: Clean up any cached data for this session
        # TODO: Send final metrics to logging system


# Global instance
_shell_bridge: Optional[ShellCommandBridge] = None


def get_shell_bridge() -> ShellCommandBridge:
    """Get or create the global shell command bridge."""
    global _shell_bridge
    if _shell_bridge is None:
        _shell_bridge = ShellCommandBridge()
    return _shell_bridge


def initialize_session_state(
    session_id: str,
    environment_vars: Dict[str, str] = None,
) -> Dict[str, Any]:
    """
    Initialize state tracking for a new session.
    
    Call this when a new SSH/Telnet session is created,
    passing in the captured environment variables.
    
    Usage in server/protocols/term.py or server/telnet/handler.py:
        from server.protocols.shell import initialize_session_state
        
        # When session starts:
        env_vars = {'TERM': 'xterm-256color', 'SHELL': '/bin/bash', ...}
        state = initialize_session_state(session_id, env_vars)
    
    Args:
        session_id: Unique session identifier
        environment_vars: Environment variables captured from authentication
    
    Returns:
        Initial state dictionary
    """
    bridge = get_shell_bridge()
    return bridge.initialize_session_state(session_id, environment_vars)


def initialize_llm_session(
    session_id: str,
    username: str = "root",
    hostname: str = "ubuntu-srv",
) -> None:
    """
    Seed the LLM with the attacker's identity for this session.

    Call this once after SSH authentication succeeds so the LLM's
    system prompt names the correct user, home directory, and hostname.

    Usage in server/protocols/term.py:
        from server.protocols.shell import initialize_llm_session
        initialize_llm_session(self.session_id, username=self.username or "root")
    """
    bridge = get_shell_bridge()
    bridge.initialize_llm_session(session_id, username, hostname)


def update_session_environment(
    session_id: str,
    environment_vars: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Merge newly captured handshake environment variables into session state."""
    bridge = get_shell_bridge()
    return bridge.update_session_environment(session_id, environment_vars)


def update_session_buffer(
    session_id: str,
    buffer: bytes | str,
) -> str:
    """Persist the attacker's current in-progress command line."""
    bridge = get_shell_bridge()
    return bridge.update_session_buffer(session_id, buffer)


def process_command(
    session_id: str,
    command: bytes,
    protocol: str = "ssh",
) -> Dict[str, Any]:
    """
    Convenient function to process a command through the bridge.
    
    This is called when a complete command is detected (Enter key / \r).
    
    Usage in your protocol handlers:
        from server.protocols.shell import process_command
        
        # When Enter is pressed in terminal:
        result = process_command(
            session_id=session_id,
            command=raw_command_bytes,
            protocol='ssh'  # or 'telnet'
        )
        # Result includes 'execution_payload' with cwd, env, command
        # Send to LLM which returns analysis
    
    Args:
        session_id: Unique session identifier
        command: Raw command bytes (may have backspaces, etc)
        protocol: Protocol type ('ssh' or 'telnet')
    
    Returns:
        Dictionary with analysis results and execution payload
    """
    bridge = get_shell_bridge()
    return bridge.process_shell_command(session_id, command, protocol)


def cleanup_session_state(session_id: str) -> None:
    """
    Cleanup state when a session ends.
    
    Call this when a session terminates.
    
    Usage:
        from server.protocols.shell import cleanup_session_state
        
        # When connection closes:
        cleanup_session_state(session_id)
    
    Args:
        session_id: Session identifier to cleanup
    """
    bridge = get_shell_bridge()
    bridge.cleanup_session(session_id)
