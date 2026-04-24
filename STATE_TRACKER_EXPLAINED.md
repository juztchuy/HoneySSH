# State Tracker: Solving the Stateless LLM Problem

## The Problem

LLMs are **stateless** by nature. They process one request at a time with no memory of previous interactions.

Without state tracking, imagine this scenario:

```
Time 1: Attacker runs: cd /tmp
        Honeypot sends to LLM: "cd /tmp"
        LLM responds: "Changed to /tmp"
        ✓ Works correctly

Time 2: Attacker runs: uname -a
        Without state tracking, honeypot sends to LLM: "uname -a"
        ❌ PROBLEM: LLM doesn't know they're in /tmp
        LLM might respond: "Running uname in /home/user"
        WRONG! They're in /tmp
```

**The Solution:** Before sending ANY command to the LLM, include the full execution context:
- Current working directory (cwd)
- Environment variables (env)
- Username and source IP
- Command history (optional)

---

## Implementation: State Tracker

Located in: `server/protocols/shell.py`

### Core Components

#### 1. SessionStateTracker Class
Maintains per-session state:

```python
class SessionStateTracker:
    def __init__(self):
        self.session_states: Dict[str, Dict[str, Any]] = {}
        # Maps session_id -> {cwd, env, previous_cwd, history}
    
    # Key methods:
    - initialize_state(session_id, env_vars)
    - update_cwd_from_command(session_id, command)
    - build_execution_payload(session_id, command)
    - get_state_for_llm(session_id)
```

#### 2. ShellCommandBridge Enhancement
Uses the StateTracker to process commands:

```python
class ShellCommandBridge:
    def __init__(self):
        self.state_tracker = SessionStateTracker()  # ← NEW
    
    def process_shell_command(self, session_id, command, protocol):
        # 1. Update cwd if "cd" command
        self.state_tracker.update_cwd_from_command(session_id, command)
        
        # 2. Build payload with current cwd and env
        execution_payload = self.state_tracker.build_execution_payload(
            session_id, command, username, source_ip
        )
        
        # 3. Return payload for LLM
        return result  # Includes execution_payload
```

---

## JSON Payload: What the LLM Receives

When a user presses Enter (\r) and a command is processed:

```json
{
  "session_id": "abc123",
  "timestamp": 1703001234.5,
  "user": {
    "username": "attacker",
    "source_ip": "192.168.1.100"
  },
  "execution": {
    "cwd": "/tmp",              ← CURRENT DIRECTORY (key!)
    "command": "uname -a",      ← COMMAND
    "environment": {            ← ENVIRONMENT (key!)
      "TERM": "xterm-256color",
      "SHELL": "/bin/bash",
      "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
      "LANG": "en_US.UTF-8"
    }
  },
  "state": {
    "previous_cwd": "/home/attacker",
    "history_count": 2
  }
}
```

Now the LLM knows:
- ✓ Current directory is /tmp
- ✓ Available tools (from PATH)
- ✓ Terminal type (from TERM)
- ✓ Language encoding (from LANG)

---

## End-to-End Example

### Scenario: Multi-command Attack Sequence

```
1. Attacker connects (SSH)
   ├─ HONEYPOT: initialize_session_state(session_id, env_vars)
   └─ STATE: cwd="/home/user", env={TERM:..., SHELL:...}

2. Attacker types: "cd /var/log" + presses Enter (\r)
   ├─ HONEYPOT: process_command(session_id, b"cd /var/log\r")
   ├─ FLOW:
   │  ├─ Sanitize command → "cd /var/log"
   │  ├─ Update cwd: /home/user → /var/log
   │  ├─ Build payload: {cwd: "/var/log", command: "cd /var/log", env: {...}}
   │  └─ Send to LLM
   └─ LLM RESPONSE: "User changed to /var/log"

3. Attacker types: "ls -la error.log" + presses Enter
   ├─ HONEYPOT: process_command(session_id, b"ls -la error.log\r")
   ├─ FLOW:
   │  ├─ Sanitize command → "ls -la error.log"
   │  ├─ NOT a cd command, cwd stays: /var/log
   │  ├─ Build payload: {cwd: "/var/log", command: "ls -la error.log", env: {...}}
   │  └─ Send to LLM
   └─ LLM RESPONSE: "Attacker viewing error log in /var/log"

4. Attacker disconnects
   ├─ HONEYPOT: cleanup_session_state(session_id)
   └─ STATE: Removed from tracker (cwd history, env vars cleaned up)
```

---

## Code Integration Points

### Integration Point 1: Session Initialization

**File:** `server/protocols/term.py` (SSH) or `server/telnet/handler.py` (Telnet)

**When:** When a new channel/session is created

```python
from server.protocols.shell import initialize_session_state

class Term(base_channel.BaseChannel):
    def channelOpen(self, data):
        """Channel opened - initialize state."""
        
        # Environment variables captured from pty-req or NEW-ENVIRON
        env_vars = {
            'TERM': self.terminal_type,      # e.g., 'xterm-256color'
            'SHELL': self.shell_path,        # e.g., '/bin/bash'
            'LANG': getenv('LANG'),          # e.g., 'en_US.UTF-8'
            'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',  # Default
        }
        
        # Initialize state tracking
        state = initialize_session_state(
            session_id=self.session_id,
            environment_vars=env_vars
        )
        
        log.msg(f"Session {self.session_id} initialized: cwd={state['cwd']}")
```

### Integration Point 2: Command Execution

**File:** Located in `Term.dataReceived()` or similar

**When:** When user presses Enter (\r) and complete command exists

```python
from server.protocols.shell import process_command

def dataReceived(self, data: bytes):
    """Data received from user."""
    
    # TerminalBuffer already handles buffering and \r detection
    complete_command = self.terminal_buffer.add_data(data)
    
    if complete_command:
        # EXECUTION TRIGGER ← HERE
        # User pressed Enter, command is ready
        
        result = process_command(
            session_id=self.session_id,
            command=complete_command,
            protocol='ssh'
        )
        
        # Access the execution payload
        exec_payload = result['execution_payload']
        
        # PAYLOAD STRUCTURE:
        # {
        #   'session_id': '...',
        #   'execution': {
        #     'cwd': '/tmp',           ← Updated by state tracker
        #     'command': 'ls -la',
        #     'environment': {...}     ← From handshake
        #   },
        #   'user': {
        #     'username': 'attacker',
        #     'source_ip': '...'
        #   }
        # }
        
        # Convert to JSON for LLM
        import json
        payload_json = json.dumps(exec_payload)
        
        # Send to LLM (TODO: implement async Ollama call)
        # llm_response = await ollama_client.query_ollama(payload_json)
```

### Integration Point 3: Session Cleanup

**File:** `server/protocols/term.py` or `server/telnet/handler.py`

**When:** When connection closes

```python
from server.protocols.shell import cleanup_session_state

def channelClosed(self):
    """Channel closed - cleanup state."""
    cleanup_session_state(self.session_id)
    log.msg(f"Session {self.session_id} cleaned up")
```

---

## State Tracker: Method Reference

### initialize_state(session_id, env_vars)

```python
state = tracker.initialize_state('abc123', {
    'TERM': 'xterm-256color',
    'SHELL': '/bin/bash'
})

# Returns:
# {
#   'cwd': '/home/user',          ← Default starting dir
#   'env': {TERM, SHELL, ...},    ← Captured from handshake
#   'previous_cwd': None,         ← For 'cd -' support
#   'history': []                 ← Command history
# }
```

### update_cwd_from_command(session_id, command)

```python
# Command: "cd /var/log"
tracker.update_cwd_from_command('abc123', 'cd /var/log')
# Result: cwd = '/var/log'

# Command: "cd .."
tracker.update_cwd_from_command('abc123', 'cd ..')
# Result: cwd = previous_dir (goes up)

# Command: "cd -"
tracker.update_cwd_from_command('abc123', 'cd -')
# Result: cwd = previous_cwd (toggles)

# Command: "cd" (alone)
tracker.update_cwd_from_command('abc123', 'cd')
# Result: cwd = '/home/user' (home)

# Command: "ls" (not cd)
tracker.update_cwd_from_command('abc123', 'ls -la')
# Result: cwd unchanged, returns False
```

### build_execution_payload(session_id, command, username, source_ip)

```python
payload = tracker.build_execution_payload(
    session_id='abc123',
    command='ls -la',
    username='attacker',
    source_ip='192.168.1.100'
)

# Returns: Full JSON-serializable dict with:
# - timestamp
# - user info
# - execution context (cwd, command, env)
# - state info (history count)
```

### get_state_for_llm(session_id)

```python
state = tracker.get_state_for_llm('abc123')

# Returns: {cwd, env} only (lightweight for LLM)
```

### record_command(session_id, command)

```python
tracker.record_command('abc123', 'ls -la')

# Records in state['history']:
# [
#   {command: 'cd /tmp', cwd: '/tmp', timestamp: 1703001234},
#   {command: 'ls -la', cwd: '/tmp', timestamp: 1703001235}
# ]
```

### cleanup_state(session_id)

```python
tracker.cleanup_state('abc123')

# Removes session from session_states dict
# Logs: session_id, final_cwd, commands_executed
```

---

## Path Resolution Examples

The StateTracker handles path resolution for relative paths:

| Command | Current cwd | Result |
|---------|------------|--------|
| cd /var/log | /home/user | → /var/log |
| cd .. | /var/log | → /var |
| cd ~ | /var/log | → /home/user |
| cd - | /var/log (prev=/home) | → /home |
| cd ../tmp | /var/log | → /tmp |
| cd . | /var/log | → /var/log |

---

## Memory Management

The StateTracker is memory-efficient:

- **Per-session state:** ~1KB minimum
- **Command history:** Capped at 500 commands (oldest removed)
- **Session states dict:** One entry per active session
- **Duplicate cache:** Full cleanup of >1 hour old entries

---

## Testing Your Integration

### Unit Test 1: State Initialization

```python
from server.protocols.shell import initialize_session_state

state = initialize_session_state('test123', {'TERM': 'xterm'})
assert state['cwd'] == '/home/user'
assert state['env']['TERM'] == 'xterm'
```

### Unit Test 2: CD Command Updates

```python
from server.protocols.shell import initialize_session_state, process_command

initialize_session_state('test123', {})
result = process_command('test123', b'cd /tmp', 'ssh')
# Check that execution_payload has cwd='/tmp'
assert result['execution_payload']['execution']['cwd'] == '/tmp'
```

### Unit Test 3: Multiple Commands

```python
# Command 1: cd /var
result1 = process_command('test123', b'cd /var', 'ssh')
cwd1 = result1['execution_payload']['execution']['cwd']
assert cwd1 == '/var'

# Command 2: cd log (relative)
result2 = process_command('test123', b'cd log', 'ssh')
cwd2 = result2['execution_payload']['execution']['cwd']
assert cwd2 == '/var/log'
```

---

## Debugging Tips

### Check Current State
```python
from server.protocols.shell import get_shell_bridge

bridge = get_shell_bridge()
state = bridge.state_tracker.get_state(session_id)
print(f"CWD: {state['cwd']}")
print(f"ENV: {state['env']}")
```

### Enable Verbose Logging
```python
# Twisted logging already captures state changes
# Look for messages like:
# "Initialized state for session abc123: cwd=/home/user"
# "Session abc123 changed directory: from_cwd=/home/user, to_cwd=/tmp"
```

### Track Execution Payloads
```python
import json

result = process_command(session_id, command, 'ssh')
payload = result['execution_payload']
print(json.dumps(payload, indent=2))
```

---

## Key Takeaways

1. **State Tracker solves the stateless LLM problem** by maintaining cwd and env per session
2. **Execution Trigger** is when \r (Enter) is detected - that's when to call process_command()
3. **Three integration points:**
   - Initialize state on connection
   - Process command on Enter
   - Cleanup on disconnect
4. **JSON Payload** includes cwd, env, command, username, source_ip for LLM
5. **Automatic cwd updates** when cd commands are detected
6. **Memory efficient** with history capping and duplicate cleanup

The LLM now has full context for every command.

