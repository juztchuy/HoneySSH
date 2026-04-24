# Pre-LLM Implementation Checklist

## Final Verification Before LLM Phase

This document serves as a checklist to verify your HoneySSH server is ready for LLM integration.

---

## ✅ 1. Session Management

### UUID Generation
- [x] Each new connection gets a unique session_id
  - Location: `utils/session.py` - `SessionInfo.__init__()` line 24
  - Uses: `uuid.uuid4().hex[:12]` for 12-character hex ID
  - Access: `session.session_id` or passed as `session_id` parameter

### Usage Examples

**SSH Protocol (server/protocols/ssh.py):**
```python
from utils.session import create_session

# When connection is made:
session = create_session(
    source_ip="192.168.1.1",
    source_port=54321,
    dest_ip="0.0.0.0",
    dest_port=22,
)
session.protocol = 'ssh'
# Store reference to session in SSH transport object
```

**Telnet Protocol (server/telnet/handler.py):**
```python
from utils.session import create_session

# When connection is made:
session = create_session(
    source_ip="192.168.1.1",
    source_port=54321,
    dest_ip="0.0.0.0",
    dest_port=23,
)
session.protocol = 'telnet'
self.session_info = session
```

---

## ✅ 2. Command Terminator Detection

### Problem Solved
- Commands are properly detected when Enter is pressed (\r or \n)
- Backspaces and control characters are handled
- Empty lines and duplicate commands are filtered

### Implementation Details

**Function:** `utils.terminal.extract_command_until_terminator()`
- Detects: \r\n, \r, \n
- Returns: (command_bytes, remaining_buffer)
- Example:
  ```python
  from utils.terminal import extract_command_until_terminator
  
  buffer = b"ls -la\r\necho hello\r\n"
  cmd, remaining = extract_command_until_terminator(buffer)
  # cmd = b'ls -la'
  # remaining = b'echo hello\r\n'
  ```

**Usage in Terminal Handlers:**
```python
from utils.terminal import TerminalBuffer

# In __init__:
self.terminal_buffer = TerminalBuffer()

# When data arrives:
complete_command = self.terminal_buffer.add_data(data)
if complete_command:
    # Send to LLM via shell bridge
    from server.protocols.shell import process_command
    result = process_command(
        session_id=self.session_id,
        command=complete_command,
        protocol='ssh'  # or 'telnet'
    )
```

---

## ✅ 3. Timeout Handling

### Idle Connection Prevention
- Connections idle for >5 minutes are flagged for cleanup
- Prevents botnets from exhausting Ollama resources
- Can be customized per session

### Implementation

**Function:** `utils.timeout.SessionTimeout`
- Default: 300 seconds (5 minutes)
- Customizable per session
- Integrated with Twisted reactor

**Usage:**
```python
from utils.timeout import create_session_timeout

# Create timeout for a session:
timeout = create_session_timeout(session_id, timeout_seconds=300)

# On user activity:
timeout.reset()  # Reset the timer

# When session ends:
timeout.cancel()  # Stop the timer
```

**Integration Points:**
- Reset timeout on every keystroke (via `session.touch()`)
- Cancel timeout on session close
- TODO: Implement callback to close connection on timeout

---

## ✅ 4. Terminal Environment Capture

### What We Capture
- **TERM type:** xterm-256color, linux, vt100, dumb, etc.
- **Terminal size:** width (columns) and height (rows)
- **Environment variables:** SHELL, LANG, PATH, etc.

### Using Terminal Context

**SSH PTY-REQ Parsing (server/protocols/ssh.py):**
```python
# Extracted in MSG_CHANNEL_REQUEST handler
elif channel_type == b"pty-req":
    term_type = extract_string()      # e.g., b"xterm-256color"
    columns = extract_int(4)          # e.g., 80
    rows = extract_int(4)             # e.g., 24
    
    # Pass to Term channel:
    channel["session"].set_terminal_environment(
        term_type=term_type.decode(),
        columns=columns,
        rows=rows,
        env_vars={}
    )
```

**Telnet Environment Variable Handling:**
```python
# TODO: Parse NEW-ENVIRON option negotiations
# Store terminal info in handler.negotiation_options
# Display via TelnetHandler.terminal_info
```

**Passing to LLM:**
```python
from server.protocols.shell import process_command

result = process_command(session_id, command, protocol='ssh')
# Context is automatically built with:
# - session.terminal_type
# - session.terminal_width/height
# - session.environment_vars
```

---

## ✅ 5. Backspace and Control Character Handling

### Utilities Provided

**1. `process_backspaces(s: bytes) -> bytes`**
- Flattens backspace operations
- Example: `lss\x7fls` → `lsls`

**2. `remove_all(s: bytes, remove_list: list) -> bytes`**
- Strips unwanted bytes
- Example: `hello\r\x00world` → `helloworld`

**3. `sanitize_for_llm(data: bytes) -> str`**
- All-in-one sanitization
- Processes backspaces → removes nulls → normalizes line endings → decodes to UTF-8

### Usage

```python
from utils.terminal import sanitize_for_llm

# In your command handler:
raw_command = b"lss\x7fls\x00\r"
clean_command = sanitize_for_llm(raw_command)
# Result: "lsls"
```

---

## ✅ 6. Local Echo for Authentication

### Pre-Session Handshake Logic

**Problem:** Users expect to see their username as they type, but NOT their password.

**Solution:** Use `utils.echo.AuthenticationEchoHandler`

**Flow:**
1. Server receives username prompt from backend
2. Handler enters "awaiting_username" state
3. User types "admin" → Handler echoes back "admin" to client
4. User presses Enter → Handler enters "awaiting_password" state
5. User types "secret" → Handler does NOT echo (password hidden)
6. User authenticates successfully → Handler exits authentication mode

**Implementation:**

```python
# In TelnetHandler.__init__:
from utils.echo import AuthenticationEchoHandler
self.auth_echo_handler = AuthenticationEchoHandler()

# When login begins:
self.start_authentication_with_echo()

# When user types during login:
data_to_send, data_to_echo = self.auth_echo_handler.process_input(data)

# When login succeeds:
self.end_authentication_with_echo(username="admin")
```

**Backspace Handling:**
- Standard: 0x7F (DEL character)
- Telnet echo: 0x08 (BS) 0x20 (SPACE) 0x08 (BS) = erases character on screen
- Handled automatically by `AuthenticationEchoHandler`

---

## ✅ 7. Environment Variable Extraction

### What Variables to Capture

**From Telnet NEW-ENVIRON:**
- USER (username)
- TERM (terminal type)
- LANG (language/encoding)
- TZ (timezone)

**From SSH Environment Variables:**
- TERM
- SHELL
- LANG
- PATH
- COLUMNS/ROWS (from pty-req)

### Applying to LLM

The LLM needs these for correct output formatting:
- **TERM=dumb:** Plain text only, no colors/formatting
- **TERM=xterm-256color:** Full ANSI colors and capabilities
- **LANG=utf-8:** Can use Unicode characters
- **Dimensions:** For line wrapping and formatting

**Auto-applied via `shell.py`:**
```python
context = {
    'terminal': {
        'type': session.terminal_type,  # From pty-req or telnet
        'width': session.terminal_width,
        'height': session.terminal_height,
    },
    'environment': session.environment_vars,  # All captured vars
}
# Automatically passed to LLM when processing commands
```

---

## ✅ 8. Command Rate Limiting

### Duplicate Detection

Built into `server/protocols/shell.py` - `ShellCommandBridge._is_duplicate_command()`

**Prevents:**
- Spending Ollama resources on identical commands
- Spam of the same command repeated every millisecond
- DoS attacks via resource exhaustion

**Configuration:**
```python
# In ShellCommandBridge.__init__:
self.duplicate_threshold: int = 5  # Seconds
# Same command within 5s is considered duplicate
```

---

## ✅ 9. Session Context Dictionary

### Available Information

Built into `utils/session.SessionInfo.get_context_dict()`

```python
{
    'session_id': '1a2b3c4d5e6f',
    'username': 'attacker',
    'source_ip': '192.168.1.100',
    'dest_ip': '192.168.1.1',
    'protocol': 'ssh',
    'terminal': {
        'type': 'xterm-256color',
        'width': 120,
        'height': 30,
    },
    'environment': {
        'TERM': 'xterm-256color',
        'SHELL': '/bin/bash',
        'LANG': 'en_US.UTF-8',
    },
    'telnet_options': {},  # If telnet: negotiation options
    'authenticated': True,
    'command_count': 5,
    'duration_seconds': 42.3,
}
```

### Using This Context

```python
from utils.session import get_session_manager

manager = get_session_manager()
session = manager.get_session(session_id)

# Use context for LLM prompt:
context = session.get_context_dict()
prompt = f"""
User: {context['username']}
Terminal: {context['terminal']['type']}
Command: {command}

Please analyze this command...
"""
```

---

## 🚀 Integration Workflow

### Complete Example: SSH Command Processing

```python
# 1. Session starts (in server/ssh/server_transport.py):
from utils.session import create_session

session = create_session(
    source_ip=self.peer_ip,
    source_port=self.peer_port,
    dest_ip=self.local_ip,
    dest_port=self.local_port,
)
session.protocol = 'ssh'

# 2. Terminal type received (in server/protocols/ssh.py):
session.update_terminal_info(
    term_type='xterm-256color',
    width=80,
    height=24,
    env_vars={'SHELL': '/bin/bash'},
)

# 3. User authenticates (in server/userauth.py):
session.mark_authenticated('attacker', 'password')

# 4. User types command (in server/protocols/term.py):
from server.protocols.shell import process_command

command = b"ls -la\x0a"
result = process_command(
    session_id=session.session_id,
    command=command,
    protocol='ssh',
)
# Result includes LLM analysis (when implemented)

# 5. Session ends (in server/server_transport.py):
session.close()
```

---

## 📋 Remaining TODOs Before Golive

- [ ] Implement Ollama HTTP POST in `LLM/client.py`
- [ ] Implement response parsing from Ollama JSON
- [ ] Implement terminal output formatting with ANSI codes
- [ ] Connect timeout callbacks to actual connection closure
- [ ] Extract TERM variable from Telnet NEW-ENVIRON option
- [ ] Extract environment variables from SSH pty-req modes field
- [ ] Implement rate limiting enforcement (currently just detected)
- [ ] Add command history storage for logging/forensics
- [ ] Integrate with honeypot logging system for metrics

---

## 📚 Reference Files

### Utilities Module
- **terminal.py:** Terminal I/O utilities
- **session.py:** Session management
- **echo.py:** Authentication echo
- **timeout.py:** Connection timeouts

### Server Protocol Handlers
- **server/ssh/server_transport.py:** SSH main transport
- **server/protocols/term.py:** SSH terminal/shell
- **server/protocols/ssh.py:** SSH protocol parser
- **server/protocols/shell.py:** Bridge to LLM (NEW)
- **server/telnet/handler.py:** Telnet handler with echo support

### LLM Integration
- **LLM/client.py:** Ollama client
- **utils/session.py:** Session context for LLM

---

## ✨ Key Architecture Principles

1. **Separation of Concerns:** Terminal handling, session mgmt, and LLM are separate
2. **Data Flow:** Terminal → Bridge (shell.py) → LLM → Response Formatter → Terminal
3. **Extensibility:** Easy to add new protocols or LLM backends
4. **Resilience:** Timeouts, duplicate detection, and error handling built-in
5. **Context-Aware:** Full terminal environment passed to LLM for accurate responses

