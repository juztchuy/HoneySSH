"""
HoneySSH — Ollama connectivity and pipeline smoke test.

Run this once Ollama is installed and a model is pulled:

    ollama pull llama3.2
    python main.py

What it checks:
  1. Ollama is reachable at http://localhost:11434
  2. The model responds to a plain prompt
  3. Per-session history works  (cd /tmp → ls shows /tmp context)
  4. Silent commands are remembered  (export VAR=secret → echo $VAR returns secret)
  5. Terminal formatting  (no markdown, no code fences in output)
"""

import json
import sys
import textwrap
import urllib.request
import urllib.error

# Make sure project root is on the path when run directly
import os
sys.path.insert(0, os.path.dirname(__file__))

from LLM.client import OllamaClient

OLLAMA_URL = "http://localhost:11434"
MODEL      = "llama3.2"          # change if you pulled a different model
SESSION    = "smoke-test-001"

SEPARATOR = "─" * 60


def check_ollama_reachable(url: str) -> bool:
    """Step 1 — verify the Ollama process is up."""
    print(f"\n[1] Checking Ollama at {url} …")
    try:
        with urllib.request.urlopen(f"{url}/v1/models", timeout=5) as resp:
            data = json.loads(resp.read().decode())
        models = [m.get("id", "") for m in data.get("data", [])]
        if models:
            print(f"    OK  — models available: {', '.join(models)}")
        else:
            print("    OK  — Ollama is up (no models listed yet; still pulling?)")
        return True
    except urllib.error.URLError as exc:
        print(f"    FAIL — cannot reach Ollama: {exc}")
        print("    Make sure 'ollama serve' is running.")
        return False


def run_command(client: OllamaClient, label: str, command: str, cwd: str) -> str:
    """Send one command and pretty-print the result."""
    print(f"\n  [{label}]")
    print(f"  prompt : [{cwd}]$ {command}")
    response = client.generate(SESSION, command, cwd=cwd)
    if response:
        indented = textwrap.indent(response, "  │ ")
        print(f"  output :\n{indented}")
    else:
        print("  output : (empty — silent command)")
    return response


def main() -> None:
    print(SEPARATOR)
    print("  HoneySSH — Ollama pipeline smoke test")
    print(SEPARATOR)

    # ------------------------------------------------------------------ #
    # 1. Connectivity                                                       #
    # ------------------------------------------------------------------ #
    if not check_ollama_reachable(OLLAMA_URL):
        sys.exit(1)

    client = OllamaClient(ollama_url=OLLAMA_URL, model=MODEL)

    # ------------------------------------------------------------------ #
    # 2. Session initialisation (username seeded into system prompt)       #
    # ------------------------------------------------------------------ #
    print(f"\n[2] Initialising session as root@ubuntu-srv …")
    client.initialize_session(SESSION, username="root", hostname="ubuntu-srv")
    seed_len = len(client._histories[SESSION])
    print(f"    OK  — seed history has {seed_len} messages")

    # ------------------------------------------------------------------ #
    # 3. Basic command                                                      #
    # ------------------------------------------------------------------ #
    print(f"\n[3] Basic command")
    run_command(client, "whoami", "whoami", cwd="/root")

    # ------------------------------------------------------------------ #
    # 4. History / CWD tracking                                            #
    # Navigate to /tmp, then ls — the LLM should reflect /tmp context.     #
    # ------------------------------------------------------------------ #
    print(f"\n[4] CWD history tracking  (cd /tmp → ls)")
    run_command(client, "cd /tmp",  "cd /tmp",  cwd="/root")   # silent
    out = run_command(client, "ls",     "ls",       cwd="/tmp")    # cwd updated by shell.py
    if "/tmp" not in out.lower() and out:
        print("  NOTE: ls output may not mention /tmp explicitly — check it looks realistic")

    # ------------------------------------------------------------------ #
    # 5. Silent-command memory  (export VAR → echo $VAR)                  #
    # ------------------------------------------------------------------ #
    print(f"\n[5] Silent-command memory  (export → echo)")
    run_command(client, "export VAR=s3cr3t",  "export VAR=s3cr3t", cwd="/tmp")
    out = run_command(client, "echo $VAR",    "echo $VAR",          cwd="/tmp")
    if "s3cr3t" in out:
        print("  PASS — LLM remembered the exported variable")
    else:
        print("  WARN — LLM did not echo the variable (model may need a stronger system prompt)")

    # ------------------------------------------------------------------ #
    # 6. Terminal formatting check  (no markdown code fences)             #
    # ------------------------------------------------------------------ #
    print(f"\n[6] Terminal formatting check")
    out = run_command(client, "cat /etc/passwd", "cat /etc/passwd", cwd="/tmp")
    fences = out.count("```")
    if fences == 0:
        print("  PASS — no markdown code fences in output")
    else:
        print(f"  WARN — found {fences} backtick fence(s); consider strengthening the system prompt")

    # ------------------------------------------------------------------ #
    # 7. History depth                                                     #
    # ------------------------------------------------------------------ #
    history = client._histories.get(SESSION, [])
    print(f"\n[7] Session history depth: {len(history)} messages  (seed={seed_len})")

    # ------------------------------------------------------------------ #
    # Done                                                                 #
    # ------------------------------------------------------------------ #
    print(f"\n{SEPARATOR}")
    print("  Smoke test complete.  If all checks passed, your LLM pipeline is ready.")
    print(SEPARATOR)


if __name__ == "__main__":
    main()
