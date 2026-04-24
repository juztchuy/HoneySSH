# ── Stage 1: dependency install ───────────────────────────────────────────
FROM python:3.11-slim AS deps

WORKDIR /app

# Build-time deps (gcc needed for some crypto wheels)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libssl-dev \
        libffi-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


# ── Stage 2: runtime image ────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

# Runtime-only system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        openssh-client \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from build stage
COPY --from=deps /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=deps /usr/local/bin /usr/local/bin

# Copy application source
COPY . .

# ── Generate SSH host keys (Cowrie needs these to present to attackers) ────
RUN mkdir -p etc var/log/cowrie var/lib/cowrie/tty var/lib/cowrie/downloads && \
    ssh-keygen -t rsa  -b 2048 -f etc/ssh_host_rsa_key   -N "" -q && \
    ssh-keygen -t dsa         -f etc/ssh_host_dsa_key    -N "" -q && \
    ssh-keygen -t ecdsa       -f etc/ssh_host_ecdsa_key  -N "" -q && \
    ssh-keygen -t ed25519     -f etc/ssh_host_ed25519_key -N "" -q

# ── Entrypoint ────────────────────────────────────────────────────────────
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# SSH honeypot port (not 22 — host maps 22→2222 if desired)
EXPOSE 2222
# Telnet honeypot port
EXPOSE 2223

ENTRYPOINT ["/entrypoint.sh"]
