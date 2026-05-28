# Fed0gaT Web Dashboard container
#
# Usage:
#   docker build -t fed0gat-web -f webapp/Dockerfile webapp/
#   docker run -p 5000:5000 \
#     -e GH_TOKEN=ghp_xxxx \
#     -e GH_REPO=owner/feed-repo \
#     -e WEB_SECRET=$(openssl rand -hex 32) \
#     fed0gat-web

FROM python:3.11-slim

# Non-root user for security
RUN useradd -m -u 1000 appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py           ./app.py
COPY github_client.py ./github_client.py
COPY templates/       ./templates/

RUN chown -R appuser:appuser /app
USER appuser

# ── Environment defaults (override at runtime) ────────────────────────────────
ENV GH_TOKEN=""
ENV GH_REPO=""
ENV DATA_DIR="feeds"
ENV WEB_SECRET="change-me"
ENV PORT="5000"

EXPOSE 5000

# Gunicorn: 2 worker processes, 60s timeout (GitHub API can be slow)
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "2", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "app:app"]
