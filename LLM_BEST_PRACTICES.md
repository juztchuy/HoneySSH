# LLM Integration Best Practices Guide

## For Implementing Ollama Query Methods

---

## 1. HTTP API Basics

### Ollama API Endpoint
- **URL:** `http://localhost:11434/api/generate`
- **Method:** POST
- **Content-Type:** application/json

### Basic Request Structure

```json
{
  "model": "llama2",
  "prompt": "What is a reverse shell?",
  "temperature": 0.7,
  "stream": false
}
```

### Basic Response Structure

```json
{
  "model": "llama2",
  "created_at": "2024-01-15T10:30:00Z",
  "response": "A reverse shell is...",
  "done": true,
  "context": [1, 2, 3, ...],
  "total_duration": 5000000000,
  "load_duration": 1000000000,
  "prompt_eval_count": 10,
  "eval_count": 50,
  "eval_duration": 4000000000
}
```

---

## 2. Query Patterns for Honeypot Analysis

### Pattern 1: Command Risk Assessment

**Prompt Template:**
```python
prompt = f"""You are a cybersecurity expert analyzing a honeypot.

User: {username}
Terminal: {terminal_type}
Command: {command}

Analyze this command for:
1. Is it malicious or suspicious? (yes/no/maybe)
2. What is the intent? (reconnaissance/exploitation/persistence/etc)
3. Risk level: 0-10 (0=harmless, 10=critical threat)
4. Specific concerns or observations

Keep response brief and structured."""
```

**Response Parsing:**
```python
# Expected format (structure your prompt to get this):
response = {
    'is_malicious': True,
    'intent': 'reconnaissance',
    'risk_level': 7,
    'concerns': 'Scanning for open ports, typical botnet behavior',
}
```

### Pattern 2: Keystroke Pattern Analysis

**Prompt Template:**
```python
prompt = f"""Analyze this user input pattern.

User: {username}
Keystrokes: {keystroke_sequence}
Terminal: {terminal_type}

What does this reveal about the attacker's skill level or intent?
1. Skill level: novice/intermediate/advanced
2. Likely automated tool: yes/no
3. Behavioral notes: (brief observations)"""
```

### Pattern 3: Telnet Client Fingerprinting

**Prompt Template:**
```python
prompt = f"""Identify this Telnet client from its option negotiation.

Telnet Options Sent: {telnet_options_dict}

This client is likely:
1. Client name: (Mirai, Hajime, etc.) or generic
2. Confidence: low/medium/high
3. Known vulnerabilities: (if any)
4. Typical targets: (what they usually target)"""
```

---

## 3. Implementation Template

### Using aiohttp (Async/Await)

```python
import aiohttp
import json
from typing import Dict, Any

async def query_ollama_async(
    prompt: str,
    model: str = "llama2",
    temperature: float = 0.7,
) -> Dict[str, Any]:
    """
    Query Ollama LLM asynchronously.
    
    Args:
        prompt: The prompt to send
        model: Model name (default: llama2)
        temperature: Response randomness 0.0-1.0
        
    Returns:
        Dict with 'response' key containing text, or {'error': message}
    """
    payload = {
        "model": model,
        "prompt": prompt,
        "temperature": temperature,
        "stream": False,
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "http://localhost:11434/api/generate",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'status': 'success',
                        'response': data.get('response', ''),
                        'model': data.get('model'),
                        'duration_ms': data.get('total_duration', 0) // 1_000_000,
                    }
                else:
                    return {
                        'status': 'error',
                        'error': f"HTTP {response.status}",
                    }
    except asyncio.TimeoutError:
        return {
            'status': 'error',
            'error': 'Ollama timeout (30s)',
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
        }
```

### Using requests (Blocking/Synchronous)

```python
import requests
import json
from typing import Dict, Any

def query_ollama_sync(
    prompt: str,
    model: str = "llama2",
    temperature: float = 0.7,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Query Ollama LLM synchronously.
    
    Args:
        prompt: The prompt to send
        model: Model name (default: llama2)
        temperature: Response randomness 0.0-1.0
        timeout: Request timeout in seconds
        
    Returns:
        Dict with 'response' key containing text
    """
    payload = {
        "model": model,
        "prompt": prompt,
        "temperature": temperature,
        "stream": False,
    }
    
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        
        data = response.json()
        return {
            'status': 'success',
            'response': data.get('response', ''),
            'model': data.get('model'),
            'duration_ms': data.get('total_duration', 0) // 1_000_000,
        }
    except requests.Timeout:
        return {
            'status': 'error',
            'error': f'Ollama timeout ({timeout}s)',
        }
    except requests.ConnectionError:
        return {
            'status': 'error',
            'error': 'Cannot reach Ollama at localhost:11434',
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
        }
```

---

## 4. Integration with Twisted Framework

### Async Pattern with Twisted Deferred

```python
from twisted.internet import reactor, defer
from twisted.web.client import readBody
from twisted.web.iweb import IBodyProducer
from twisted.web import client
from zope.interface import implementer
from typing import Dict, Any
import json

@implementer(IBodyProducer)
class JSONProducer:
    def __init__(self, data: Dict):
        self.body = json.dumps(data).encode('utf-8')
        self.length = len(self.body)

    def stopProducing(self):
        pass

    def startProducing(self, consumer):
        consumer.write(self.body)
        return defer.succeed(None)

def query_ollama_twisted(
    prompt: str,
    model: str = "llama2",
    temperature: float = 0.7,
) -> defer.Deferred:
    """
    Query Ollama using Twisted Deferred pattern.
    
    Usage:
        d = query_ollama_twisted(prompt)
        d.addCallback(handle_response)
        d.addErrback(handle_error)
    """
    payload = {
        "model": model,
        "prompt": prompt,
        "temperature": temperature,
        "stream": False,
    }
    
    agent = client.Agent(reactor)
    producer = JSONProducer(payload)
    
    d = agent.request(
        b'POST',
        b'http://localhost:11434/api/generate',
        headers=client.Headers({'Content-Type': ['application/json']}),
        bodyProducer=producer,
    )
    
    def handle_response(response):
        if response.code != 200:
            return defer.fail(
                Exception(f"Ollama returned {response.code}")
            )
        return readBody(response)
    
    def parse_response(body):
        data = json.loads(body)
        return {
            'status': 'success',
            'response': data.get('response', ''),
        }
    
    d.addCallback(handle_response)
    d.addCallback(parse_response)
    d.addErrback(lambda failure: {
        'status': 'error',
        'error': str(failure.value),
    })
    
    return d
```

---

## 5. Response Parsing Strategies

### Strategy 1: Extract Structured Data from Text

```python
def parse_risk_analysis(response_text: str) -> Dict[str, Any]:
    """
    Extract structured data from LLM response.
    
    Example response:
    "Is it malicious? YES
     Risk level: 8/10
     Intent: network reconnaissance
     Concerns are present."
    """
    lines = response_text.split('\n')
    result = {
        'is_malicious': 'unknown',
        'risk_level': 5,
        'intent': 'unknown',
        'concerns': [],
    }
    
    for line in lines:
        if 'malicious' in line.lower():
            result['is_malicious'] = 'YES' in line or 'Yes' in line
        elif 'risk' in line.lower():
            import re
            match = re.search(r'(\d+)', line)
            if match:
                result['risk_level'] = int(match.group(1))
        elif 'intent' in line.lower():
            result['intent'] = line.split(':')[1].strip() if ':' in line else 'unknown'
        elif 'concern' in line.lower():
            result['concerns'].append(line.strip())
    
    return result
```

### Strategy 2: Ask for JSON Response

**Improved Prompt Template:**
```python
prompt = f"""You are a cybersecurity expert analyzing a honeypot.

User: {username}
Command: {command}

Respond ONLY with valid JSON (no other text):
{{
  "is_malicious": true/false,
  "risk_level": 0-10,
  "intent": "reconnaissance|exploitation|persistence|scanning|unknown",
  "concerns": ["concern1", "concern2"]
}}"""
```

**Parsing:**
```python
def parse_json_response(response_text: str) -> Dict[str, Any]:
    """
    Extract JSON from response, handling partial/malformed responses.
    """
    import json
    import re
    
    # Try to find JSON block
    match = re.search(r'\{.*\}', response_text, re.DOTALL)
    if not match:
        return {'error': 'No JSON found in response'}
    
    try:
        return json.loads(match.group())
    except json.JSONDecodeError:
        return {'error': 'Invalid JSON in response'}
```

---

## 6. Prompt Optimization for Ollama

### Token Efficiency

**DON'T DO THIS (Verbose):**
```python
prompt = """Imagine you are a highly skilled cybersecurity professional 
with over 20 years of experience in network security and intrusion detection 
systems. You have been asked to analyze the following command that was 
executed on a honeypot designed to capture malicious activity..."""
```

**DO THIS (Concise):**
```python
prompt = """Cybersecurity expert. Analyze this honeypot command:
Command: {}
Malicious? Risk 0-10? Intent?"""
```

### Temperature Settings

- **Temperature 0.0-0.3:** Deterministic (good for structured analysis)
- **Temperature 0.5-0.7:** Balanced (good for general analysis)
- **Temperature 0.9-1.0:** Creative (good for brainstorming)

**Recommendation for honeypot:** Use 0.3-0.5 for consistent risk assessment

### Model Selection

| Model | Speed | Accuracy | Use Case |
|-------|-------|----------|----------|
| phi | Fast | Medium | Real-time keystroke analysis |
| neural-chat | Medium | High | General command analysis |
| llama2 | Slower | Very High | Detailed threat analysis (default) |

---

## 7. Caching Strategy

### Avoid Redundant Queries

```python
import hashlib
from collections import OrderedDict
from typing import Dict

class OllamaCache:
    """Simple LRU cache for Ollama queries."""
    
    def __init__(self, max_size: int = 1000):
        self.cache: OrderedDict = OrderedDict()
        self.max_size = max_size
    
    def get_key(self, prompt: str) -> str:
        """Generate cache key from prompt."""
        return hashlib.md5(prompt.encode()).hexdigest()
    
    def get(self, prompt: str) -> Optional[Dict[str, Any]]:
        """Get cached response if available."""
        key = self.get_key(prompt)
        if key in self.cache:
            # Move to end (LRU)
            self.cache.move_to_end(key)
            return self.cache[key]
        return None
    
    def set(self, prompt: str, response: Dict[str, Any]):
        """Cache a response."""
        if len(self.cache) >= self.max_size:
            self.cache.popitem(last=False)  # Remove oldest
        
        key = self.get_key(prompt)
        self.cache[key] = response
        self.cache.move_to_end(key)
```

### Usage

```python
cache = OllamaCache()

def query_with_cache(prompt: str) -> Dict[str, Any]:
    cached = cache.get(prompt)
    if cached:
        return {**cached, 'source': 'cache'}
    
    result = query_ollama_sync(prompt)
    if result['status'] == 'success':
        cache.set(prompt, result)
    
    return result
```

---

## 8. Error Handling Best Practices

### Graceful Degradation

```python
async def process_command_with_fallback(
    session_id: str,
    command: str,
) -> Dict[str, Any]:
    """
    Process command, falling back to heuristics if LLM fails.
    """
    try:
        # Try LLM analysis
        result = await ollama_client.process_command_execution(
            session_id=session_id,
            command=command,
            channel_type='shell',
            username='unknown',
            source_ip='0.0.0.0',
            environment={},
        )
        
        if result['status'] == 'success':
            return result
    except Exception as e:
        logging.warning(f"LLM analysis failed: {e}")
    
    # Fallback: Simple heuristic analysis
    return {
        'status': 'fallback',
        'is_malicious': detect_suspicious_command(command),
        'risk_level': simple_risk_scoring(command),
        'intent': guess_intent(command),
        'note': 'LLM unavailable, using heuristics',
    }
```

### Timeout Prevention

```python
# Always set timeouts
timeout_seconds = 30  # Don't wait forever for Ollama

# In requests:
response = requests.post(..., timeout=timeout_seconds)

# In aiohttp:
timeout = aiohttp.ClientTimeout(total=timeout_seconds)
async with session.post(..., timeout=timeout) as response:
    ...

# In Twisted:
reactor.callLater(timeout_seconds, d.cancel)
```

---

## 9. Logging and Monitoring

### Query Logging

```python
import logging
from datetime import datetime

class OllamaQueryLogger:
    def __init__(self, log_file: str = "ollama_queries.log"):
        self.logger = logging.getLogger('ollama')
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(handler)
    
    def log_query(self, session_id: str, prompt: str, tokens: int):
        self.logger.info(
            f"Query [{session_id}] - {tokens} tokens - "
            f"Prompt: {prompt[:100]}..."
        )
    
    def log_response(self, session_id: str, response: str, duration_ms: int):
        self.logger.info(
            f"Response [{session_id}] - {duration_ms}ms - "
            f"Output: {response[:100]}..."
        )
    
    def log_error(self, session_id: str, error: str):
        self.logger.error(f"Error [{session_id}]: {error}")
```

---

## 10. Performance Optimization

### Batch Processing

```python
async def batch_analyze_commands(commands: List[str]) -> Dict[str, Any]:
    """
    Analyze multiple commands efficiently.
    """
    # Group similar commands
    grouped = {}
    for cmd in commands:
        category = categorize_command(cmd)
        if category not in grouped:
            grouped[category] = []
        grouped[category].append(cmd)
    
    # Single LLM call per category
    results = {}
    for category, cmds in grouped.items():
        prompt = f"Analyze these {category} commands: {cmds}"
        response = await query_ollama_async(prompt)
        for cmd in cmds:
            results[cmd] = response
    
    return results
```

### Parallel Queries

```python
import asyncio

async def parallel_analysis(
    commands: List[str],
    max_concurrent: int = 3,
) -> Dict[str, Any]:
    """
    Process multiple commands concurrently (with limit).
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def limited_query(cmd):
        async with semaphore:
            return await query_ollama_async(f"Analyze: {cmd}")
    
    tasks = [limited_query(cmd) for cmd in commands]
    results = await asyncio.gather(*tasks)
    
    return {cmd: result for cmd, result in zip(commands, results)}
```

---

## 11. Testing Your Implementation

### Unit Test Template

```python
import unittest
from unittest.mock import patch, MagicMock

class TestOllamaIntegration(unittest.TestCase):
    
    @patch('requests.post')
    def test_query_ollama_success(self, mock_post):
        """Test successful Ollama query."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'response': 'This command is suspicious',
            'model': 'llama2',
            'total_duration': 5000000000,
        }
        mock_post.return_value = mock_response
        
        result = query_ollama_sync("ls")
        
        self.assertEqual(result['status'], 'success')
        self.assertIn('This command', result['response'])
    
    @patch('requests.post')
    def test_query_ollama_timeout(self, mock_post):
        """Test Ollama timeout handling."""
        mock_post.side_effect = requests.Timeout()
        
        result = query_ollama_sync("ls")
        
        self.assertEqual(result['status'], 'error')
        self.assertIn('timeout', result['error'].lower())
```

---

## 12. Deployment Checklist

- [ ] Ollama container is running and healthy
- [ ] `curl http://localhost:11434/api/generate` returns response
- [ ] Model is downloaded (llama2 by default)
- [ ] Request timeout set to 30+ seconds
- [ ] Logging configured for all queries
- [ ] Cache layer implemented (optional but recommended)
- [ ] Error handling covers network failures
- [ ] Rate limiting in place to prevent Ollama overload
- [ ] Monitoring dashboards set up for query metrics
- [ ] Fallback heuristics ready for LLM downtime

---

## Quick Reference: Common Issues

| Issue | Solution |
|-------|----------|
| `Connection refused` | Start Ollama: `ollama serve` |
| `Request timeout` | Increase timeout or use faster model (phi) |
| `Invalid JSON response` | Adjust prompt to request plain text |
| `Garbled response` | Set `stream: false` in API call |
| `Memory exhausted` | Reduce batch size or use smaller model |
| `Repeated errors` | Check `http://localhost:11434/api/tags` for available models |

