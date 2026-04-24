# Complete HoneySSH Architecture with State Tracker

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     ATTACKER TERMINAL                            │
│                   (SSH or Telnet Client)                         │
└────────────────────────────┬────────────────────────────────────┘
                             │
                      [Network Data]
                             │
┌────────────────────────────▼────────────────────────────────────┐
│               HONEYPOT PROTOCOL HANDLER                          │
│  (server/protocols/term.py or server/telnet/handler.py)        │
│                                                                  │
│  • Receives: Raw user input (SSH/Telnet)                        │
│  • Uses: TerminalBuffer for keystroke buffering                │
│  • Tracks: Session state, timeouts, authentication             │
│  • Detects: Enter key (\r) = command complete                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    [Complete Command]
                             │
┌────────────────────────────▼────────────────────────────────────┐
│              SHELL COMMAND BRIDGE & STATE TRACKER               │
│           (server/protocols/shell.py - NEW!)                    │
│                                                                  │
│  ShellCommandBridge:                                            │
│  • Routes commands to LLM                                       │
│  • Builds execution payloads                                    │
│  • Manages rate limiting                                        │
│                                                                  │
│  SessionStateTracker:  ← STATE TRACKER (SOLVES STATELESS LLM)  │
│  • Tracks: cwd, env, history per session                       │
│  • Updates: cwd when "cd" command detected                     │
│  • Builds: JSON payload with cwd + env + command               │
│                                                                  │
│  Flow:                                                          │
│  1. Initialize state on connection                             │
│  2. Sanitize command (backspaces, null bytes)                 │
│  3. Detect cd commands and update cwd                          │
│  4. Build execution payload                                     │
│  5. Record in command history                                   │
│                                                                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                     [JSON Payload]
                {cwd, env, command, user}
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                    LLM CLIENT (Ollama)                          │
│              (LLM/client.py - TODO: HTTP calls)                 │
│                                                                  │
│  • Sends: POST http://localhost:11434/api/generate             │
│  • Payload: Full execution context                              │
│  • Receives: LLM analysis (TODO: implement)                    │
│                                                                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                  [LLM Response/Analysis]
                             │
┌────────────────────────────▼────────────────────────────────────┐
│            RESPONSE FORMATTER                                    │
│         (server/protocols/shell.py)                              │
│                                                                  │
│  • Formats: Response for terminal display                       │
│  • Applies: ANSI codes based on terminal type                  │
│  • Respects: Terminal dimensions for wrapping                  │
│                                                                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                      [Terminal Output]
                             │
┌────────────────────────────▼────────────────────────────────────┐
│               Attacker's Terminal Display                        │
└────────────────────────────────────────────────────────────────┘
```

---

## Data Flow: Complete Example

### Scenario: Attacker connects and runs commands

```
TIME 0: SSH Connection Established
─────────────────────────────────
User connects from 192.168.1.100:54321

→ Term.connectionMade() called
  ├─ Create SessionInfo (UUID=abc123, IP, port)
  ├─ Capture terminal info (TERM=xterm-256color, width=120, height=30)
  ├─ Capture environment vars: {TERM, SHELL, LANG, PATH, ...}
  └─ StateTracker.initialize_state(abc123, env_vars)
     └─ Returns: {cwd: '/home/attacker', env: {...}, history: []}

STATE AT t=0:
  Session: abc123
  Directory: /home/attacker
  Environment: {TERM: xterm-256color, SHELL: /bin/bash, ...}
  History: []


TIME 1: User Types "cd /var/log" and Presses Enter
────────────────────────────────────────────────────
Keystrokes received: c, d, space, /, v, a, r, /, l, o, g, \r

→ TerminalBuffer buffers characters
→ Detects \r (Enter key) - command complete!
→ Extracts: "cd /var/log"

→ process_command(abc123, b"cd /var/log\r", 'ssh') called

  ├─ Sanitize: b"cd /var/log\r" → "cd /var/log"
  ├─ NOT duplicate (first command)
  ├─ StateTracker.update_cwd_from_command(abc123, "cd /var/log")
  │  └─ Detects "cd" command
  │  └─ Updates: cwd = '/var/log' (previous = '/home/attacker')
  │
  ├─ StateTracker.record_command(abc123, "cd /var/log")
  │  └─ Adds to history: {cmd: "cd /var/log", cwd: '/var/log', ts: 1703001001}
  │
  ├─ StateTracker.build_execution_payload(...)
  │  └─ Returns:
  │     {
  │       session_id: abc123,
  │       execution: {
  │         cwd: '/var/log',              ← UPDATED!
  │         command: 'cd /var/log',
  │         environment: {TERM, SHELL, ...}
  │       },
  │       user: {username: attacker, source_ip: 192.168.1.100}
  │     }
  │
  └─ Return result with execution_payload

→ Send to LLM:
  POST http://localhost:11434/api/generate
  {execution_payload with cwd='/var/log'}

STATE AT t=1:
  Session: abc123
  Directory: /var/log              ← CHANGED!
  Previous: /home/attacker
  Commands: ["cd /var/log"]
  LLM knows: cd command was executed


TIME 2: User Types "ls -la error.log" and Presses Enter
────────────────────────────────────────────────────────
Keystrokes: l, s, space, -, l, a, space, e, r, r, o, r, ., l, o, g, \r

→ process_command(abc123, b"ls -la error.log\r", 'ssh') called

  ├─ Sanitize: "ls -la error.log"
  ├─ NOT duplicate
  ├─ StateTracker.update_cwd_from_command(abc123, "ls -la error.log")
  │  └─ NOT a cd command
  │  └─ cwd stays: '/var/log'
  │
  ├─ StateTracker.build_execution_payload(...)
  │  └─ Returns:
  │     {
  │       session_id: abc123,
  │       execution: {
  │         cwd: '/var/log',              ← SAME
  │         command: 'ls -la error.log',
  │         environment: {TERM, ...}       ← SAME
  │       },
  │       user: {...}
  │     }
  │
  └─ Return result

→ Send to LLM:
  POST http://localhost:11434/api/generate
  {execution_payload with cwd='/var/log'}

STATE AT t=2:
  Session: abc123
  Directory: /var/log              ← SAME
  Commands: ["cd /var/log", "ls -la error.log"]
  LLM knows: ls command runs in /var/log (the directory changed by previous cd!)


TIME 3: Connection Closes
──────────────────────────
→ Term.connectionLost() called

  └─ cleanup_session_state(abc123)
     ├─ StateTracker.cleanup_state(abc123)
     │  └─ Removes: session_states[abc123]
     │  └─ Logs: final_cwd=/var/log, commands_executed=2
     │
     └─ SessionInfo.close()

FINAL STATE:
  Session: DELETED
  No memory leaks (all state cleaned up)
```

---

## Key Components

### 1. Authorization and Handshake

**File:** `server/userauth.py`, `server/protocols/ssh.py`

```
✓ Username captured
✓ Authentication validated
✓ Terminal type determined (TERM env var)
✓ Environment variables collected
  → Passed to StateTracker.initialize_state()
```

### 2. Terminal Buffer Management

**File:** `utils/terminal.py`, protocol handlers

```
✓ TerminalBuffer class manages keystroke buffering
✓ Handles backspace (0x7F) → 0x08 0x20 0x08
✓ Detects command terminator (\r, \n, \r\n)
✓ Feeds complete commands to StateTracker
```

### 3. State Tracking

**File:** `server/protocols/shell.py` - SessionStateTracker

```
✓ Per-session state: cwd, env, history
✓ Automatic cwd updates from cd commands
✓ Path resolution for relative paths
✓ Command history tracking
✓ Memory-efficient (auto-cleanup)
```

### 4. Execution Payload

**File:** `server/protocols/shell.py` - build_execution_payload()

```
json = {
  session_id,
  timestamp,
  user: {username, source_ip},
  execution: {
    cwd,              ← FOR LLM
    command,          ← FOR LLM
    environment       ← FOR LLM
  },
  state: {
    previous_cwd,
    history_count
  }
}
```

### 5. LLM Integration (TODO Phase 5)

**File:** `LLM/client.py`, `server/protocols/shell.py`

```
TODO: Implement OllamaClient.query_ollama()
- Send execution_payload as JSON to Ollama API
- Receive LLM analysis
- Parse response
- Format for terminal display
```

---

## Session State Structure

```python
session_states = {
    'abc123': {
        'cwd': '/var/log',
        'env': {
            'TERM': 'xterm-256color',
            'SHELL': '/bin/bash',
            'LANG': 'en_US.UTF-8',
            'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'
        },
        'previous_cwd': '/home/attacker',
        'history': [
            {
                'command': 'cd /var/log',
                'cwd': '/var/log',
                'timestamp': 1703001001.234
            },
            {
                'command': 'ls -la error.log',
                'cwd': '/var/log',
                'timestamp': 1703001005.567
            }
        ]
    },
    'def456': {
        'cwd': '/home/user',
        'env': {...},
        ...
    }
}
```

---

## Integration Checklist

### Protocol Handler Changes Required

#### Term.py (SSH)
- [ ] Import: `from server.protocols.shell import initialize_session_state, process_command, cleanup_session_state`
- [ ] In `channelOpen()`: Call `initialize_session_state(session_id, env_vars)`
- [ ] In `dataReceived()`: Call `process_command()` when complete command detected
- [ ] In `channelClosed()`: Call `cleanup_session_state(session_id)`

#### Handler.py (Telnet)
- [ ] Import: `from server.protocols.shell import initialize_session_state, process_command, cleanup_session_state`
- [ ] In `connectionMade()`: Call `initialize_session_state(session_id, env_vars)`
- [ ] In command processing: Call `process_command()` when Enter detected
- [ ] In `connectionLost()`: Call `cleanup_session_state(session_id)`

### Test Cases

```python
# Test 1: State initialization
state = initialize_session_state('test1', {'TERM': 'xterm'})
assert state['cwd'] == '/home/user'
assert state['env']['TERM'] == 'xterm'

# Test 2: CD command updates cwd
process_command('test1', b'cd /tmp', 'ssh')
state = bridge.state_tracker.get_state('test1')
assert state['cwd'] == '/tmp'

# Test 3: Non-cd command preserves cwd
process_command('test1', b'ls -la', 'ssh')
state = bridge.state_tracker.get_state('test1')
assert state['cwd'] == '/tmp'  # Still /tmp

# Test 4: Execution payload includes cwd
result = process_command('test1', b'pwd', 'ssh')
assert result['execution_payload']['execution']['cwd'] == '/tmp'

# Test 5: Multiple sessions independent
state1 = initialize_session_state('session1', {})
state2 = initialize_session_state('session2', {})
process_command('session1', b'cd /var', 'ssh')
s1 = bridge.state_tracker.get_state('session1')
s2 = bridge.state_tracker.get_state('session2')
assert s1['cwd'] == '/var'
assert s2['cwd'] == '/home/user'  # Independent
```

---

## Performance Characteristics

| Aspect | Value | Notes |
|--------|-------|-------|
| Memory per session | ~1 KB | + history |
| Max history entries | 500 | Auto-capped |
| Path resolution | O(1) | String operations |
| State lookup | O(1) | Dict lookup |
| CD detection | O(1) | Tokenization only |
| Cleanup delay | Immediate | No async delay |
| Duplicate cache retention | 1 hour | Auto-cleanup |

---

## Security Considerations

1. **No filesystem access:** All cwd tracking is simulated (honeypot only)
2. **No command execution:** Commands go to LLM, not executed
3. **State isolation:** Each session has separate state
4. **Memory limits:** Command history capped to prevent DoS
5. **Timeout support:** Integration with TimeoutManager for idle connections
6. **Rate limiting:** Duplicate command detection (5-second threshold)

---

## Decision Tree: When to Call Each Function

```
Connection Started?
├─ YES → Call initialize_session_state(session_id, env_vars)
└─ NO → Skip

Data Received?
├─ Terminal input buffer
│  ├─ \r detected? (Enter key)
│  │  ├─ YES → Call process_command(session_id, buffer, protocol)
│  │  └─ NO → Continue buffering
│  └─ Other keys
│     ├─ Backspace? → TerminalBuffer handles it
│     └─ Regular char → TerminalBuffer buffers it

Connection Closed?
├─ YES → Call cleanup_session_state(session_id)
└─ NO → Continue
```

---

## Files and Their Roles

| File | Purpose | StateTracker Integration |
|------|---------|--------------------------|
| `server/protocols/shell.py` | Command bridge + state tracking | Core implementation |
| `server/protocols/term.py` | SSH terminal handler | Calls initialize/process/cleanup |
| `server/telnet/handler.py` | Telnet handler | Calls initialize/process/cleanup |
| `utils/terminal.py` | Terminal utilities | Provides command sanitization |
| `utils/session.py` | Session management | Tracks auth, terminal info |
| `utils/echo.py` | Echo handling | Pre-session echo support |
| `utils/timeout.py` | Timeout management | Idle connection handling |
| `LLM/client.py` | Ollama LLM client | TODO: Receives execution_payload |

---

## Next Steps

1. **Phase 5:** Implement Ollama HTTP integration
   - Implement `OllamaClient.query_ollama()`
   - Send execution_payload to Ollama
   - Parse LLM response
   - Format response for terminal

2. **Phase 6:** Integration testing
   - Test multiple concurrent sessions
   - Test cd command tracking
   - Test response formatting
   - Test memory cleanup

3. **Phase 7:** Deployment
   - Load testing
   - Stability testing
   - Logging and monitoring
   - Production deployment

---

## Quick Reference: Integration Code

### For SSH (term.py):

```python
from server.protocols.shell import (
    initialize_session_state,
    process_command,
    cleanup_session_state
)

class Term:
    def channelOpen(self, data):
        env = {'TERM': self.terminal_type, 'SHELL': '/bin/bash'}
        init_state = initialize_session_state(self.session_id, env)
    
    def dataReceived(self, data):
        complete_cmd = self.terminal_buffer.extract_command()
        if complete_cmd:
            result = process_command(self.session_id, complete_cmd, 'ssh')
            payload = result['execution_payload']
            # TODO: Send payload to Ollama
    
    def channelClosed(self):
        cleanup_session_state(self.session_id)
```

### For Telnet (handler.py):

```python
from server.protocols.shell import (
    initialize_session_state,
    process_command,
    cleanup_session_state
)

class TelnetHandler:
    def connectionMade(self):
        env = {'TERM': 'dumb', 'SHELL': '/bin/bash'}
        init_state = initialize_session_state(self.session_id, env)
    
    def addPacket(self, data):
        complete_cmd = self.terminal_buffer.extract_command()
        if complete_cmd:
            result = process_command(self.session_id, complete_cmd, 'telnet')
            payload = result['execution_payload']
            # TODO: Send payload to Ollama
    
    def connectionLost(self, reason):
        cleanup_session_state(self.session_id)
```

