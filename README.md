<div align="center">

```
███████╗███████╗██████╗  ██████╗  ██████╗  █████╗ ████████╗
██╔════╝██╔════╝██╔══██╗██╔═████╗██╔════╝ ██╔══██╗╚══██╔══╝
█████╗  █████╗  ██║  ██║██║██╔██║██║  ███╗███████║   ██║
██╔══╝  ██╔══╝  ██║  ██║████╔╝██║██║   ██║██╔══██║   ██║
██║     ███████╗██████╔╝╚██████╔╝╚██████╔╝██║  ██║   ██║
╚═╝     ╚══════╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝
```

### Automated Cyber Threat Intelligence Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-6366f1.svg?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-Hourly-2088FF?style=flat-square&logo=github-actions&logoColor=white)](https://github.com/features/actions)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![Feeds](https://img.shields.io/badge/Threat_Feeds-27_Active-10b981?style=flat-square)](#-data-sources)

**Fed0gaT** is a fully automated, stateless Cyber Threat Intelligence (CTI) aggregator.  
It scrapes **27 public & authenticated threat feeds** every hour, producing clean IP, Hash, and URL blocklists — ready for direct firewall and EDR ingestion.

[Features](#-features) · [Architecture](#-architecture) · [Data Sources](#-data-sources) · [Quick Start](#-quick-start) · [Dashboard](#-web-dashboard) · [Configuration](#-configuration)

</div>

---

## ✦ Overview

Modern threat intelligence requires continuous, up-to-date data from multiple sources. Fed0gaT solves this by:

- **Aggregating** indicators from 27 feeds across 9 authoritative CTI providers
- **Validating** every IOC with strict regex-based type enforcement — IPs never enter the hash list, hashes never enter the URL list
- **Publishing** clean, header-free plain-text blocklists to GitHub — consumable directly by firewalls, SIEMs, and EDR platforms
- **Operating statelessly** — no database, no server disk writes; GitHub is the sole persistent storage
- **Archiving** a daily snapshot of each list (one file per day per type) while `latest-*.txt` always reflects the most recent hourly scrape

---

## ✦ Features

| Category | Detail |
|---|---|
| **Automation** | GitHub Actions cron job — runs every hour at `XX:00`, zero manual intervention |
| **IOC Types** | IPv4/IPv6 addresses · MD5 / SHA1 / SHA256 hashes · HTTP/HTTPS URLs |
| **Feed Sources** | 27 active sources: abuse.ch suite, AlienVault OTX, Spamhaus, EmergingThreats, Tor, Blocklist.de, CINS Score |
| **API Auth** | Native support for header-auth (OTX) and body-auth (MalwareBazaar, ThreatFox, URLhaus) |
| **Deduplication** | Per-type sorted unique sets before every write |
| **Type Safety** | Two-layer contamination guard — `_coerce()` at parse time + `_enforce_type()` before write |
| **Archiving** | Daily snapshot: `YYYY-MM-DD-{type}.txt` created once per calendar day |
| **Firewall Ready** | Plain-text output, no comment headers, no defanging — direct feed-in compatible |
| **Web Dashboard** | Flask app with KPI cards, 24h trend chart, 7-day bar chart, IOC type distribution |
| **IOC Editor** | Browser-based add / delete / bulk-import with direct GitHub commit |
| **Timezone** | All timestamps in UTC+3 (Istanbul) |
| **Stateless** | Docker container leaves zero persistent data on host after exit |

---

## ✦ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        GitHub Actions (cron 0 * * * *)              │
│                                                                     │
│  ┌──────────────┐     ┌──────────────────────────────────────────┐  │
│  │  fed0gat.py  │     │           Threat Feed Sources            │  │
│  │              │────▶│  abuse.ch  │  OTX  │  Spamhaus  │  ...  │  │
│  │  Orchestrator│     └──────────────────────────────────────────┘  │
│  └──────┬───────┘                                                   │
│         │  validate · deduplicate · type-enforce                    │
│         ▼                                                           │
│  ┌──────────────────────────────┐                                   │
│  │     feeds/ (GitHub Repo)     │                                   │
│  │                              │                                   │
│  │  latest-ip.txt    ◀── hourly overwrite                          │
│  │  latest-hash.txt  ◀── hourly overwrite                          │
│  │  latest-url.txt   ◀── hourly overwrite                          │
│  │                              │                                   │
│  │  2026-05-28-ip.txt  ◀── daily snapshot (once per day)           │
│  │  2026-05-28-hash.txt                                             │
│  │  2026-05-28-url.txt                                              │
│  │                              │                                   │
│  │  stats.json         ◀── appended each run (dashboard data)      │
│  └──────────────┬───────────────┘                                   │
└─────────────────┼───────────────────────────────────────────────────┘
                  │ GitHub API (read)
        ┌─────────▼────────┐          ┌─────────────────────┐
        │  Web Dashboard   │          │  Firewall / EDR     │
        │  Flask + Chart.js│          │                     │
        │                  │          │  Reads latest-*.txt │
        │  KPI  Charts     │          │  directly from repo │
        │  IOC Editor      │          │  (raw GitHub URL)   │
        └──────────────────┘          └─────────────────────┘
```

### Two-Layer Type Enforcement

```
Raw feed data
     │
     ▼
① _coerce()          — Per-entry validation at parse time
     │  IP   source → IPv4/v6 regex only
     │  Hash source → MD5/SHA1/SHA256 hex only
     │  URL  source → http/https scheme + host required
     │
     ▼  (after all sources collected)
② _enforce_type()    — Final gate before any disk write
     │  Re-validates every IOC against its declared type
     │  Logs and drops anything that slipped through
     ▼
latest-ip.txt    → IPs only
latest-hash.txt  → Hashes only (MD5 / SHA1 / SHA256)
latest-url.txt   → URLs only  (live http/https, firewall-ready)
```

---

## ✦ Data Sources

### IP Feeds (12 sources, 10 active)

| Source | Provider | Content |
|---|---|---|
| Feodo Tracker IP Blocklist | abuse.ch | Botnet C2 server IPs (Emotet, TrickBot, QakBot…) |
| Feodo Tracker CIDR | abuse.ch | Same data in subnet notation |
| SSLBL IP Blacklist | abuse.ch | IPs hosting malicious SSL certificates |
| ThreatFox C2 IPs *(API)* | abuse.ch | Recent botnet C2 IP:port IOCs |
| Blocklist.de | blocklist.de | SSH, mail, Apache brute-force attacker IPs |
| Spamhaus DROP | Spamhaus | Networks that should never be routed |
| Spamhaus EDROP | Spamhaus | Extended DROP — hijacked netblocks |
| EmergingThreats | Proofpoint | Compromised / active attacker IPs |
| CINS Score | CriticalStack | Actively malicious IP list |
| Tor Exit Nodes | Tor Project | All Tor exit node addresses |
| AlienVault OTX IPv4 *(API)* | AT&T Cybersecurity | Community pulse IPv4 indicators |

### Hash Feeds (9 sources, all active)

| Source | Provider | Content |
|---|---|---|
| MalwareBazaar SHA256 | abuse.ch | Recent malware sample SHA256 |
| MalwareBazaar MD5 | abuse.ch | Recent malware sample MD5 |
| MalwareBazaar SHA1 | abuse.ch | Recent malware sample SHA1 |
| MalwareBazaar API *(API)* | abuse.ch | Extended recent samples — all hash types |
| ThreatFox SHA256 (CSV) | abuse.ch | ThreatFox malware SHA256 IOCs |
| ThreatFox MD5 (CSV) | abuse.ch | ThreatFox malware MD5 IOCs |
| ThreatFox API SHA256 *(API)* | abuse.ch | Authenticated — higher rate limits |
| AlienVault OTX SHA256 *(API)* | AT&T Cybersecurity | Community pulse SHA256 indicators |
| AlienVault OTX MD5 *(API)* | AT&T Cybersecurity | Community pulse MD5 indicators |

### URL Feeds (6 sources, all active)

| Source | Provider | Content |
|---|---|---|
| URLhaus | abuse.ch | Active malware distribution URLs |
| URLhaus API *(API)* | abuse.ch | Authenticated — online-only subset |
| ThreatFox URLs (CSV) | abuse.ch | Malware URL IOCs |
| ThreatFox API URLs *(API)* | abuse.ch | Authenticated — recent 24h |
| OpenPhish | OpenPhish | Verified phishing site URLs |
| AlienVault OTX URLs *(API)* | AT&T Cybersecurity | Community pulse URL indicators |

> *(API)* = requires an API key configured as a GitHub Secret or environment variable

---

## ✦ Quick Start

### Option 1 — GitHub Actions (Recommended, fully automated)

```bash
# 1. Fork or clone this repository to your GitHub account
git clone https://github.com/Tagoletta/Fed0gaT.git
cd Fed0gaT

# 2. Add the following repository secrets:
#    Settings → Secrets and variables → Actions → New repository secret

#    Secret name              Value
#    ─────────────────────    ──────────────────────────────
#    OTX_API_KEY              (your AlienVault OTX API key)
#    MALWAREBAZAAR_API_KEY    (your abuse.ch API key)
#    THREATFOX_API_KEY        (your abuse.ch API key)
#    URLHAUS_API_KEY          (your abuse.ch API key)
#
#    Note: GITHUB_TOKEN is provided automatically — do NOT add it manually.

# 3. Trigger the first run:
#    Actions → "Fed0gaT – Hourly CTI Update" → Run workflow
#    (After this, it runs automatically every hour)
```

### Option 2 — Docker (one-shot, stateless)

```bash
# Build the scraper image
docker build -t fed0gat-scraper .

# Run once (fetches all feeds, pushes to GitHub, container exits cleanly)
docker run --rm \
  -e GH_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx \
  -e GH_REPO=Tagoletta/Fed0gaT \
  -e OTX_API_KEY=your_otx_key \
  -e MALWAREBAZAAR_API_KEY=your_abuse_ch_key \
  -e THREATFOX_API_KEY=your_abuse_ch_key \
  -e URLHAUS_API_KEY=your_abuse_ch_key \
  fed0gat-scraper
```

### Option 3 — Docker Compose (scraper + dashboard)

```bash
# Copy and configure environment
cp .env.example .env
# → Edit .env: set GH_TOKEN, GH_REPO, WEB_SECRET, API keys

# Start the web dashboard
docker compose up -d webapp

# Run the scraper manually (or via host cron)
docker compose run --rm scraper

# Schedule via host cron (every hour):
# 0 * * * * docker compose -f /path/to/Fed0gaT/docker-compose.yml run --rm scraper
```

### Option 4 — Local Python

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

export GH_TOKEN=ghp_xxxx
export GH_REPO=Tagoletta/Fed0gaT
export OTX_API_KEY=your_key
# ... other API keys

python fed0gat.py          # live run
python fed0gat.py --dry-run  # test without pushing
```

---

## ✦ Web Dashboard

Start the dashboard and navigate to `http://localhost:5000`

```bash
cd webapp
pip install -r requirements.txt
GH_TOKEN=ghp_xxxx GH_REPO=Tagoletta/Fed0gaT python app.py
```

### Dashboard Features

```
┌──────────────────────────────────────────────────────────┐
│  ⬡ Fed0gaT          Dashboard                           │
│  ────────────────                                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │  12,456  │ │   8,234  │ │   3,421  │ │  24,111  │   │
│  │ Zararlı  │ │ Zararlı  │ │ Zararlı  │ │  Toplam  │   │
│  │    IP    │ │   Hash   │ │   URL    │ │   IOC    │   │
│  │ +342 ↑   │ │  +89 ↑   │ │  -12 ↓   │ │          │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
│                                                          │
│  Son 24 Saat – IOC Trendi          Tür Dağılımı         │
│  ┌──────────────────────────┐  ┌────────────────────┐   │
│  │  ∿∿∿ IP  ∿∿∿ Hash       │  │      ◉             │   │
│  │    ∿∿∿ URL              │  │   IP  51%          │   │
│  └──────────────────────────┘  │   Hash 34%         │   │
│                                │   URL  15%         │   │
│  7 Günlük Tarihsel Maksimum    └────────────────────┘   │
│  ┌──────────────────────────────────────────────────┐   │
│  │ ██ ██ ██ ██ ██ ██ ██  IP / Hash / URL            │   │
│  └──────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
```

### IOC Editor Features

- **3 tabs**: IP Adresleri / Hash'ler / URL'ler — live entry counts on each tab
- **Search & filter**: instant filtering with match highlighting
- **Add entry**: single-line input with real-time validation
- **Bulk import**: paste hundreds of entries at once via modal
- **Delete**: per-row delete button or checkbox multi-select
- **Save**: commits directly to GitHub with a custom message

---

## ✦ Configuration

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `GH_TOKEN` | ✅ | — | GitHub PAT or Actions `GITHUB_TOKEN` |
| `GH_REPO` | ✅* | auto | Target repo `owner/name` (*auto-detected in Actions) |
| `GIT_NAME` | — | `Fed0gaT Bot` | Git committer name |
| `GIT_EMAIL` | — | `bot@fed0gat.local` | Git committer email |
| `DATA_DIR` | — | `feeds` | Subdirectory in repo for feed files |
| `DRY_RUN` | — | `0` | Set to `1` to skip GitHub push (testing) |
| `OTX_API_KEY` | — | — | AlienVault OTX API key |
| `MALWAREBAZAAR_API_KEY` | — | — | abuse.ch API key |
| `THREATFOX_API_KEY` | — | — | abuse.ch API key |
| `URLHAUS_API_KEY` | — | — | abuse.ch API key |
| `WEB_SECRET` | (web) | — | Flask session secret for the dashboard |

> All abuse.ch services (MalwareBazaar, ThreatFox, URLhaus, Feodo) share the same API key.

### Adding a New Feed Source

Edit `sources.json` and add an entry under the appropriate type key (`ip`, `hash`, or `url`):

```json
{
  "name": "My Custom Feed",
  "url": "https://example.com/ioc-feed.txt",
  "format": "plain",
  "comment_char": "#",
  "enabled": true
}
```

For authenticated feeds:

```json
{
  "name": "My Authenticated Feed",
  "url": "https://api.example.com/iocs",
  "format": "json",
  "method": "POST",
  "post_body": { "query": "get_recent" },
  "json_root": "data",
  "json_field": "indicator",
  "api_key_env": "MY_API_KEY",
  "api_key_body": "api_key",
  "enabled": true
}
```

| Field | Values | Description |
|---|---|---|
| `format` | `plain` / `csv` / `json` | Feed response format |
| `method` | `GET` / `POST` | HTTP method |
| `json_root` | string | Dot-path to the list in JSON (e.g. `"results"`) |
| `json_field` | string | Field name within each item |
| `json_filter` | `{"field": "type", "value": "ip"}` | Item-level filter |
| `json_multi_fields` | `["sha256", "md5"]` | Extract multiple fields per item |
| `api_key_env` | string | Env var name holding the key |
| `api_key_header` | string | HTTP header name (GET header auth) |
| `api_key_body` | string | Body field name (POST body auth) |
| `strip_port` | `true`/`false` | Strip `:port` suffix from IP:port values |

---

## ✦ Project Structure

```
Fed0gaT/
│
├── fed0gat.py                    # Core scraper — OOP, modular, stateless
├── sources.json                  # Feed configuration (27 sources)
├── requirements.txt              # Python dependencies
│
├── Dockerfile                    # Scraper container (python:3.10-alpine)
├── docker-compose.yml            # Scraper + dashboard stack
├── .env.example                  # Environment variable template
│
├── .github/
│   └── workflows/
│       └── fed0gat.yml           # GitHub Actions — cron every hour
│
└── webapp/
    ├── app.py                    # Flask application (7 API routes)
    ├── github_client.py          # GitHub REST API v3 client
    ├── requirements.txt          # Web app dependencies
    ├── Dockerfile                # Dashboard container (python:3.11-slim)
    └── templates/
        ├── layout.html           # Glassmorphic sidebar layout
        ├── dashboard.html        # KPI cards + Chart.js charts
        └── editor.html           # Paginated IOC editor
```

---

## ✦ Output Files

All files live in the `feeds/` subdirectory of the repository.

| File | Updated | Content |
|---|---|---|
| `latest-ip.txt` | Every hour | Current IP blocklist — plain text, one entry per line |
| `latest-hash.txt` | Every hour | Current hash list — MD5 / SHA1 / SHA256 |
| `latest-url.txt` | Every hour | Current URL blocklist — live `http/https` format |
| `YYYY-MM-DD-ip.txt` | Once per day | Daily snapshot of IP list |
| `YYYY-MM-DD-hash.txt` | Once per day | Daily snapshot of hash list |
| `YYYY-MM-DD-url.txt` | Once per day | Daily snapshot of URL list |
| `stats.json` | Every hour | Run history for dashboard charts (last 168 runs) |

### Direct Feed URLs (for firewall / EDR integration)

```
https://raw.githubusercontent.com/Tagoletta/Fed0gaT/main/feeds/latest-ip.txt
https://raw.githubusercontent.com/Tagoletta/Fed0gaT/main/feeds/latest-hash.txt
https://raw.githubusercontent.com/Tagoletta/Fed0gaT/main/feeds/latest-url.txt
```

These URLs return plain-text, comment-free IOC lists — usable directly as external threat feed sources in Palo Alto, Fortinet, Cisco, CrowdStrike, Sentinel, and similar platforms.

---

## ✦ How It Works — Hourly Cycle

```
:00  GitHub Actions runner starts
 │
 ├─ Checkout repository
 ├─ Install Python dependencies
 │
 ├─ Load sources.json (27 feeds)
 │
 ├─ For each feed source:
 │   ├─ HTTP GET / POST (with API key if configured)
 │   ├─ Parse: plain text / CSV / JSON
 │   ├─ Validate type (Layer 1: _coerce)
 │   └─ Collect to ip[] / hash[] / url[]
 │
 ├─ Cross-type contamination check (Layer 2: _enforce_type)
 │   └─ Log and drop any wrong-type entries
 │
 ├─ Daily archive check:
 │   └─ If yesterday's archive missing → copy latest-*.txt → YYYY-MM-DD-*.txt
 │
 ├─ Write latest-ip.txt / latest-hash.txt / latest-url.txt
 │   └─ Sorted · Deduplicated · Plain text · No headers
 │
 ├─ Append to stats.json (for dashboard charts)
 │
 ├─ git add -A
 ├─ git commit -m "Fed0gaT Hourly Update: YYYY-MM-DD HH:MM +03:00"
 └─ git push → GitHub
```

---

## ✦ Security Considerations

- **No secrets on disk** — API keys live exclusively in GitHub Secrets or runtime environment variables; `.env` is git-ignored
- **No persistent host storage** — Docker container writes nothing to host filesystem; ephemeral temp dirs are deleted on exit
- **Private IP filtering** — RFC 1918, loopback, link-local, and broadcast ranges are explicitly excluded from IP feeds
- **Strict type enforcement** — a SHA256 hash cannot appear in `latest-ip.txt` by design; validated at two independent layers
- **Token sanitisation** — GitHub token is redacted from all log output before printing

---

## ✦ Tech Stack

| Layer | Technology |
|---|---|
| Scraper | Python 3.10+, `requests`, `urllib3` |
| Scheduling | GitHub Actions (cron) |
| Storage | GitHub repository (stateless) |
| Web Backend | Flask 3, Gunicorn |
| Web Frontend | Tailwind CSS v3 (CDN), Chart.js v4, JetBrains Mono |
| GitHub API | REST API v3 (contents read/write) |
| Containerisation | Docker (Alpine for scraper, Slim for webapp) |

---

## ✦ License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built with Python · Powered by GitHub Actions · Threat data from the open security community

**[github.com/Tagoletta/Fed0gaT](https://github.com/Tagoletta/Fed0gaT)**

</div>
