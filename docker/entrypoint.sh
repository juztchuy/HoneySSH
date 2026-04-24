#!/bin/sh
# HoneySSH container entrypoint
# 1. Wait for Ollama to be reachable
# 2. Pull the model if it isn't cached yet
# 3. Start the honeypot

set -e

OLLAMA_URL="${OLLAMA_URL:-http://ollama:11434}"
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.2}"
MAX_WAIT=120   # seconds before giving up on Ollama

# ── 1. Wait for Ollama ────────────────────────────────────────────────────
echo "[entrypoint] Waiting for Ollama at ${OLLAMA_URL} ..."
elapsed=0
until curl -sf "${OLLAMA_URL}/v1/models" > /dev/null 2>&1; do
    if [ "$elapsed" -ge "$MAX_WAIT" ]; then
        echo "[entrypoint] ERROR: Ollama not reachable after ${MAX_WAIT}s. Starting anyway."
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
done
echo "[entrypoint] Ollama is up."

# ── 2. Pull model if not already downloaded ───────────────────────────────
echo "[entrypoint] Checking model '${OLLAMA_MODEL}' ..."
MODEL_PRESENT=$(curl -sf "${OLLAMA_URL}/v1/models" | grep -c "\"${OLLAMA_MODEL}\"" || true)
if [ "$MODEL_PRESENT" -eq 0 ]; then
    echo "[entrypoint] Pulling model '${OLLAMA_MODEL}' — this may take a few minutes ..."
    curl -sf -X POST "${OLLAMA_URL}/api/pull" \
         -H "Content-Type: application/json" \
         -d "{\"name\":\"${OLLAMA_MODEL}\"}" \
         --no-buffer | grep -E '"status"' || true
    echo "[entrypoint] Model pull complete."
else
    echo "[entrypoint] Model '${OLLAMA_MODEL}' already present."
fi

# ── 3. Start HoneySSH ─────────────────────────────────────────────────────
echo "[entrypoint] Starting HoneySSH ..."
exec python start.py
