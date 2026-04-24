# State Tracker Integration Guide

## What Was Built

The `StateTracker` in `server/protocols/shell.py` maintains persistent state for each session:

```
Session State
├── cwd (Current Working Directory)
├── env (Environment Variables)
├── previous_cwd (For 'cd -' support)
└── history (Command history)
```

**Why this matters:** The LLM is stateless. Without tracking `cwd`, it won't know that the attacker ran `cd /tmp` and is now in `/tmp`. The executor would try to run `ls` in the wrong directory.

---

## Architecture Overview

```
Terminal Input (SSH/Telnet)
    ↓
TerminalBuffer (utils/terminal.py) - Buffers keystrokes
    ↓
Detect \r (Enter Key)
    ↓
Extract Complete Command
    ↓
process_command() [server/protocols/shell.py]
    ↓
StateTracker.update_cwd_from_command()  ← Updates cwd if "cd /tmp"
StateTracker.build_execution_payload()  ← Wraps with current cwd
    ↓
LLM Query with Full Context
    ↓
Response Sent Back to Terminal
```

---

## Integration Checklist

### Step 1: Initialize State on Session Start

When a new SSH/Telnet session is created, call `initialize_session_state()`:

**Location: `server/protocols/ssh.py` or `server/telnet/handler.py`**

```python
from server.protocols.shell import initialize_session_state

# When session first connects:
def connectionMade(self):
    """Called when client connects."""
    session_id = generate_session_id()  # Already done in SessionInfo
    
    # Get environment vars from authentication
    env_vars = {
        'TERM': terminal_type,      # e.g., 'xterm-256color'
        'SHELL': '/bin/bash',        # From backend
        'LANG': 'en_US.UTF-8',      # From NEW-ENVIRON or default
    }
    
    # Initialize state tracking
    state = initialize_session_state(session_id, env_vars)
    # state will contain:
    # {
    #     'cwd': '/home/user',
    #     'env': env_vars,
    #     'previous_cwd': None
    # }
```

### Step 2: Process Commands When Enter is Pressed

When the user presses Enter (\r), the buffer is complete and ready for processing:

**Location: `server/protocols/term.py` or `server/telnet/handler.py`**

```python
from server.protocols.shell import process_command

# In your terminal data handler (when \r is detected):
def process_user_input(self, data: bytes):
    """Process user input from terminal."""
    
    # Buffer management already handles \r detection
    # When buffer is complete:
    complete_command = self.terminal_buffer.extract_command()
    
    if complete_command:
        # THIS IS THE EXECUTION TRIGGER
        # When Enter (\r) is pressed, process_command is called
        result = process_command(
            session_id=self.session_id,
            command=complete_command,
            protocol='ssh'  # or 'telnet'
        )
        
        # result will contain:
        # {
        #     'execution_payload': {
        #         'execution': {
        #             'cwd': '/home/user',      ← CURRENT DIRECTORY
        #             'command': 'ls -la',
        #             'environment': {...},     ← ENVIRONMENT VARIABLES
        #         },
        #         'user': {
        #             'username': 'attacker',
        #             'source_ip': '192.168.1.100',
        #         }
        #     }
        # }
        
        # Now send this to LLM:
        llm_response = await ollama_client.query_ollama(result['execution_payload'])
        
        # Send response back to terminal
        self.transport.write(llm_response.encode() + b'\r\n')
```

### Step 3: Update Directory When "cd" Command Executes

The StateTracker automatically updates `cwd` when it detects a `cd` command:

```python
# This happens INSIDE process_command() automatically:

# Command: "cd /tmp"
state_tracker.update_cwd_from_command(session_id, "cd /tmp")
# Result: cwd = '/tmp'

# Command: "cd .."
state_tracker.update_cwd_from_command(session_id, "cd ..")
# Result: cwd = '/home' (goes up one level)

# Command: "cd -"
state_tracker.update_cwd_from_command(session_id, "cd -")
# Result: cwd = previous_cwd (toggles between two dirs)

# Command: "cd"
state_tracker.update_cwd_from_command(session_id, "cd")
# Result: cwd = '/home/user' (goes home)
```

### Step 4: Send Execution Payload to LLM

The execution payload is automatically built and includes all state:

```python
# Returned from process_command():
result = {
    'execution_payload': {
        'session_id': 'abc123def456',
        'timestamp': 1703001234.567,
        'user': {
            'username': 'attacker',
            'source_ip': '192.168.1.100',
        },
        'execution': {
            'cwd': '/tmp/malware',           ← CWD IS HERE
            'command': 'gcc exploit.c',
            'environment': {                 ← ENV IS HERE
                'TERM': 'xterm-256color',
                'SHELL': '/bin/bash',
                'PATH': '/usr/bin:/bin',
            },
        },
        'state': {
            'previous_cwd': '/home/attacker',
            'history_count': 3,
        },
    }
}

# Send to LLM with full context:
import json
payload_json = json.dumps(result['execution_payload'])

# LLM now knows:
# - What command is being run
# - WHERE it's being run (cwd)
# - WHAT ENVIRONMENT it has (env vars)
```

### Step 5: Cleanup on Session End

When a session terminates, clean up state:

**Location: `server/protocols/ssh.py` or `server/telnet/handler.py`**

```python
from server.protocols.shell import cleanup_session_state

def connectionLost(self, reason):
    """Called when client disconnects."""
    # Cleanup state tracking
    cleanup_session_state(self.session_id)
    
    # Rest of cleanup...
```

---

## Example: Complete SSH Handler Integration

```python
# server/protocols/term.py

from server.protocols.shell import (
    initialize_session_state,
    process_command,
    cleanup_session_state,
)

class Term(base_channel.BaseChannel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session_id = None  # Will be set to SessionInfo.session_id
        
    def channelOpen(self, data):
        """Channel is opened."""
        # Initialize state with environment from pty-req
        env_vars = {
            'TERM': self.terminal_type,
            'SHELL': self.shell_path,
            'LANG': 'en_US.UTF-8',
        }
        
        state = initialize_session_state(self.session_id, env_vars)
        log.msg(f"Initialized session {self.session_id}, cwd={state['cwd']}")
    
    def dataReceived(self, data: bytes):
        """Data received from client."""
        # Buffer management handles \r detection
        complete_command = self.terminal_buffer.add_data(data)
        
        if complete_command:
            # EXECUTION TRIGGER: Enter key pressed
            log.msg(f"Executing: {complete_command} in cwd={self.current_cwd}")
            
            result = process_command(
                session_id=self.session_id,
                command=complete_command,
                protocol='ssh'
            )
            
            # Access current state:
            exec_payload = result['execution_payload']
            cwd = exec_payload['execution']['cwd']
            command = exec_payload['execution']['command']
            env = exec_payload['execution']['environment']
            
            # Now call LLM with full context
            log.msg(f"Sending to LLM: {command} in {cwd}")
            # TODO: Call ollama_client here
    
    def channelClosed(self):
        """Channel closed."""
        cleanup_session_state(self.session_id)
```

---

## State Examples

### Example 1: Directory Navigation

```
User runs: cd /var/log
StateTracker updates:
  Previous: cwd = /home/attacker
  Current:  cwd = /var/log

Next command "tail error.log" executes in /var/log
LLM sees: cwd=/var/log, command="tail error.log"
```

### Example 2: Relative Path Resolution

```
Current: cwd = /home/attacker/documents
User runs: cd ../projects
StateTracker resolves:
  ../projects = /home/attacker/projects
  Previous: cwd = /home/attacker/documents
  Current:  cwd = /home/attacker/projects

Next command executes in /home/attacker/projects
```

### Example 3: Environment Variables

```
SSH handshake captures:
  env = {
    'TERM': 'xterm-256color',
    'SHELL': '/bin/bash',
    'PATH': '/usr/bin:/bin:/usr/sbin',
    'LANG': 'en_US.UTF-8'
  }

Every command includes this env
LLM can analyze:
  - Can they use apt-get? (depends on PATH)
  - What locale encodings available? (from LANG)
  - Full terminal capability? (from TERM)
```

---

## JSON Payload Structure (For LLM)

When `process_command()` is called and \r is detected, this payload is created:

```json
{
  "session_id": "abc123def456",
  "timestamp": 1703001234.567,
  "user": {
    "username": "attacker",
    "source_ip": "192.168.1.100"
  },
  "execution": {
    "cwd": "/tmp/malware",
    "command": "gcc exploit.c -o exploit",
    "environment": {
      "TERM": "xterm-256color",
      "SHELL": "/bin/bash",
      "PATH": "/usr/bin:/bin",
      "LANG": "en_US.UTF-8"
    }
  },
  "state": {
    "previous_cwd": "/home/attacker",
    "history_count": 5
  }
}
```

This is what the LLM receives. It can now:
1. Analyze the command in the context of the current directory
2. Understand what tools are available (from PATH in env)
3. Track the attacker's navigation through the filesystem

---

## Key Methods

### initialization_session_state()
**What:** Initialize state when session starts
**When:** Call from SSH/Telnet handler `connectionMade()` or equivalent
**What it returns:** Initial state dict with cwd='/home/user'

### process_command()
**What:** Process a command when user presses Enter
**When:** Call when \r is detected in terminal buffer
**What it returns:** Result dict with 'execution_payload' containing cwd, env, command
**Side effects:** Updates cwd if command is "cd", records command in history

### cleanup_session_state()
**What:** Clean up state when session ends
**When:** Call from SSH/Telnet handler `connectionLost()` or equivalent
**What it returns:** None

---

## Testing Checklist

- [ ] Session state initialized with cwd='/home/user'
- [ ] "cd /tmp" updates cwd to '/tmp'
- [ ] "cd .." goes up one directory correctly
- [ ] "cd -" toggles between two directories
- [ ] Environment variables persisted across commands
- [ ] execution_payload contains cwd and env every command
- [ ] LLM receives full context (cwd, env, username, source_ip)
- [ ] Session state cleaned up on disconnect (no memory leak)
- [ ] Multiple concurrent sessions don't interfere with each other

---

## Performance Notes

- **Memory:** Each session stores ~1KB of state + command history (limited to 500 commands)
- **CPU:** Path resolution is O(1) string operations
- **Latency:** State updates are immediate (no I/O)
- **Cleanup:** Automatic on session end, plus cleanup of > 1-hour-old duplicate detection cache

