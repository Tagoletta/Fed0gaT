# ─────────────────────────────────────────────────────────────────
# Fed0gaT – Stateless CTI Scraper Container
#
# Usage (single run, ephemeral):
#   docker run --rm \
#     -e GH_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx \
#     -e GH_REPO=your-org/your-feed-repo \
#     -e GIT_NAME="Fed0gaT Bot" \
#     -e GIT_EMAIL="bot@example.com" \
#     -e DATA_DIR=feeds \
#     fed0gat
#
# Schedule on the host with cron (no data persists in the container):
#   0 * * * * docker run --rm -e GH_TOKEN=... -e GH_REPO=... fed0gat
# ─────────────────────────────────────────────────────────────────

# ── Stage 1: dependency builder (keeps final image clean) ─────────
FROM python:3.10-alpine AS builder

WORKDIR /build

# Install build deps only in this stage
RUN apk add --no-cache \
        gcc \
        musl-dev \
        libffi-dev \
        openssl-dev

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: minimal runtime image ───────────────────────────────
FROM python:3.10-alpine

# git is required for clone / commit / push operations
RUN apk add --no-cache git openssh-client ca-certificates && \
    # Trust GitHub's SSH host key (needed if ever switched to SSH remote)
    mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts 2>/dev/null && \
    chmod 600 /root/.ssh/known_hosts

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Only copy the two files the script needs at runtime.
# Everything else (README, Dockerfile, workflow) is not needed inside the container.
COPY fed0gat.py  .
COPY sources.json .

# Run as a non-root user for defence-in-depth
RUN addgroup -S fed0gat && adduser -S fed0gat -G fed0gat && \
    chown -R fed0gat:fed0gat /app

# git needs a home directory it can write to for global config
ENV HOME=/home/fed0gat
RUN mkdir -p /home/fed0gat && chown fed0gat:fed0gat /home/fed0gat

USER fed0gat

# ── Environment variables (override at runtime) ───────────────────
# GH_TOKEN  – REQUIRED: GitHub personal access token
# GH_REPO   – REQUIRED: "owner/repo-name"
# GIT_NAME  – committer display name
# GIT_EMAIL – committer email
# DATA_DIR  – subdirectory in the repo to store feed files (default: feeds)
# DRY_RUN   – set to "1" to test without pushing

ENV GIT_NAME="Fed0gaT Bot" \
    GIT_EMAIL="bot@fed0gat.local" \
    DATA_DIR="feeds" \
    DRY_RUN="0"

# The container runs once and exits – scheduling is external (host cron / K8s CronJob)
ENTRYPOINT ["python", "/app/fed0gat.py"]
