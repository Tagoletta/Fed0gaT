#!/usr/bin/env python3
"""
Fed0gaT – Stateless Hourly Cyber Threat Intelligence Scraper

Fetches IPs, hashes, and URLs from public threat feeds every hour.
Rotates latest-*.txt to timestamped archives, then commits and pushes
everything to GitHub. No data ever touches the host disk permanently.

Environment variables required:
  GH_TOKEN  – GitHub personal access token (or GITHUB_TOKEN in Actions)
  GH_REPO   – target repository, e.g. "owner/fed0gat-data"
              (auto-detected via GITHUB_REPOSITORY in Actions mode)

Optional:
  GIT_NAME  – committer name  (default: "Fed0gaT Bot")
  GIT_EMAIL – committer email (default: "bot@fed0gat.local")
  DATA_DIR  – subdirectory inside the repo for feed files (default: "feeds")
  DRY_RUN   – set to "1" to skip git operations (testing)
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("fed0gat")


# ── Environment ───────────────────────────────────────────────────────────────

# Running inside a GitHub Actions runner (repo already checked-out)
IN_GITHUB_ACTIONS: bool = os.environ.get("GITHUB_ACTIONS") == "true"
GITHUB_WORKSPACE: str = os.environ.get("GITHUB_WORKSPACE", "")
GITHUB_REPOSITORY: str = os.environ.get("GITHUB_REPOSITORY", "")

GH_TOKEN: str = os.environ.get("GH_TOKEN", "")
GH_REPO: str = os.environ.get("GH_REPO") or GITHUB_REPOSITORY
GIT_NAME: str = os.environ.get("GIT_NAME", "Fed0gaT Bot")
GIT_EMAIL: str = os.environ.get("GIT_EMAIL", "bot@fed0gat.local")
DATA_SUBDIR: str = os.environ.get("DATA_DIR", "feeds")
DRY_RUN: bool = os.environ.get("DRY_RUN", "0") == "1"

SOURCES_FILE: Path = Path(__file__).parent / "sources.json"

FEED_TYPES = ("ip", "hash", "url")

# Turkey has been permanently on UTC+3 since 2016 (no DST).
# Using a fixed offset avoids any tzdata dependency inside containers.
TZ = timezone(timedelta(hours=3))


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class FeedSource:
    name: str
    url: str
    kind: str                       # "ip" | "hash" | "url"
    fmt: str                        # "plain" | "csv" | "json"
    comment_char: str = "#"
    csv_column: int = 0
    json_field: Optional[str] = None
    enabled: bool = True
    strip_port: bool = False        # strip ":port" suffix from IP feeds
    # ── API authentication ───────────────────────────────────────────
    api_key_env: str = ""           # env var name holding the API key
    api_key_header: str = ""        # HTTP header for key (GET/POST header auth)
    api_key_body: str = ""          # POST body field name (body-level auth)
    method: str = "GET"             # "GET" | "POST"
    post_body: Optional[Dict] = None  # template body for POST requests
    # ── JSON response navigation ─────────────────────────────────────
    json_root: str = ""             # dot-separated path to the list in JSON (e.g. "data" or "results")
    json_filter: Optional[Dict] = None  # {"field": "ioc_type", "value": "ip:port"} – item-level filter
    json_multi_fields: Optional[List[str]] = None  # extract multiple fields per item as separate IOCs


@dataclass
class FeedResult:
    source: FeedSource
    entries: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class RunStats:
    counts: Dict[str, int] = field(default_factory=lambda: {k: 0 for k in FEED_TYPES})
    sources_ok: int = 0
    sources_fail: int = 0
    archived: int = 0


# ── Validators ────────────────────────────────────────────────────────────────

class DataValidator:
    """Regex-based validators and extractors for IPs, hashes, and URLs."""

    # Private / reserved address ranges that should never appear in threat feeds
    _PRIVATE = re.compile(
        r"^(?:"
        r"10\."                             # RFC 1918
        r"|172\.(?:1[6-9]|2\d|3[01])\."   # RFC 1918
        r"|192\.168\."                      # RFC 1918
        r"|127\."                           # Loopback
        r"|169\.254\."                      # Link-local
        r"|0\.0\.0\.0"                      # Unspecified
        r"|255\.255\.255\.255"              # Broadcast
        r")"
    )

    _RE_IPV4 = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )
    # Simplified but practical IPv6 pattern
    _RE_IPV6 = re.compile(
        r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
        r"|^(?:[0-9a-fA-F]{1,4}:){1,7}:$"
        r"|^:(?::[0-9a-fA-F]{1,4}){1,7}$"
        r"|^::$"
        r"|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$"
        r"|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$"
        r"|^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$"
        r"|^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$"
        r"|^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$"
        r"|^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$"
    )
    _RE_MD5    = re.compile(r"^[a-fA-F0-9]{32}$")
    _RE_SHA1   = re.compile(r"^[a-fA-F0-9]{40}$")
    _RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")

    @classmethod
    def validate_ip(cls, raw: str) -> Optional[str]:
        ip = raw.strip()
        if cls._PRIVATE.match(ip):
            return None
        if cls._RE_IPV4.match(ip) or cls._RE_IPV6.match(ip):
            return ip
        return None

    @classmethod
    def validate_hash(cls, raw: str) -> Optional[str]:
        h = raw.strip().lower()
        if cls._RE_MD5.match(h) or cls._RE_SHA1.match(h) or cls._RE_SHA256.match(h):
            return h
        return None

    @classmethod
    def validate_url(cls, raw: str) -> Optional[str]:
        url = raw.strip()
        # Refang before validation so urlparse works correctly
        test = URLDefanger.refang(url)
        try:
            p = urlparse(test)
            if p.scheme in ("http", "https") and p.netloc:
                return url  # Return original (already defanged or not)
        except Exception:
            pass
        return None


# ── URL Defanger ──────────────────────────────────────────────────────────────

class URLDefanger:
    """Converts live URLs to defanged representation and back."""

    @staticmethod
    def defang(url: str) -> str:
        url = re.sub(r"^https://", "hxxps://", url)
        url = re.sub(r"^http://",  "hxxp://",  url)
        # Defang only the first dot in the host portion to keep readability
        try:
            p = urlparse(url.replace("hxxp", "http", 1))
            host_defanged = p.netloc.replace(".", "[.]", 1)
            url = url.replace(p.netloc, host_defanged, 1)
        except Exception:
            pass
        return url

    @staticmethod
    def refang(url: str) -> str:
        url = re.sub(r"^hxxps://", "https://", url, flags=re.IGNORECASE)
        url = re.sub(r"^hxxp://",  "http://",  url, flags=re.IGNORECASE)
        url = url.replace("[.]", ".")
        return url


# ── HTTP Client ────────────────────────────────────────────────────────────────

class HttpClient:
    """Resilient HTTP client with retry logic and size guard."""

    TIMEOUT_SECS  = 45
    MAX_BYTES      = 100 * 1024 * 1024  # 100 MB – generous for large IP lists

    def __init__(self) -> None:
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://",  adapter)
        session.headers["User-Agent"] = (
            "Fed0gaT/1.0 CTI-Scraper (+https://github.com/fed0gat)"
        )
        self._session = session

    def get(self, url: str, extra_headers: Optional[Dict] = None) -> str:
        resp = self._session.get(
            url, timeout=self.TIMEOUT_SECS, stream=True,
            headers=extra_headers or {},
        )
        resp.raise_for_status()
        return self._read_stream(resp, url)

    def post(self, url: str, body: dict, extra_headers: Optional[Dict] = None) -> str:
        resp = self._session.post(
            url, json=body, timeout=self.TIMEOUT_SECS,
            headers=extra_headers or {},
        )
        resp.raise_for_status()
        return resp.text

    def _read_stream(self, resp: requests.Response, url: str) -> str:
        chunks: List[bytes] = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65_536):
            total += len(chunk)
            if total > self.MAX_BYTES:
                logger.warning("Feed %s exceeded size cap (%d MB) – truncating.", url, self.MAX_BYTES // 1_048_576)
                break
            chunks.append(chunk)
        encoding = resp.encoding or "utf-8"
        return b"".join(chunks).decode(encoding, errors="replace")


# ── Feed Fetcher & Parser ─────────────────────────────────────────────────────

class FeedFetcher:
    """Downloads and parses a single threat feed into a clean list of IOCs."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def fetch(self, source: FeedSource) -> FeedResult:
        result = FeedResult(source=source)
        try:
            logger.info("  ↓  [%s] %s", source.kind.upper(), source.name)

            # Resolve API key from environment
            api_key = ""
            if source.api_key_env:
                api_key = os.environ.get(source.api_key_env, "")
                if not api_key:
                    logger.warning("     └─ SKIP: env var %s not set", source.api_key_env)
                    result.error = f"{source.api_key_env} not set"
                    return result

            # Build auth headers (header-level authentication, e.g. OTX)
            extra_headers: Dict[str, str] = {}
            if api_key and source.api_key_header:
                extra_headers[source.api_key_header] = api_key

            # Build POST body (inject API key into body if needed, e.g. abuse.ch APIs)
            if source.method == "POST" and source.post_body is not None:
                body = dict(source.post_body)
                if api_key and source.api_key_body:
                    body[source.api_key_body] = api_key
                raw = self._http.post(source.url, body, extra_headers)
            else:
                raw = self._http.get(source.url, extra_headers)

            entries = self._parse(raw, source)
            result.entries = entries
            logger.info("     └─ %d valid entries", len(entries))
        except Exception as exc:
            result.error = str(exc)
            logger.error("     └─ FAILED: %s", exc)
        return result

    # ── Parsers ─────────────────────────────────────────────────

    def _parse(self, raw: str, source: FeedSource) -> List[str]:
        if source.fmt == "csv":
            return self._parse_csv(raw, source)
        if source.fmt == "json":
            return self._parse_json(raw, source)
        return self._parse_plain(raw, source)

    def _parse_plain(self, raw: str, source: FeedSource) -> List[str]:
        entries: List[str] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith(source.comment_char):
                continue
            entry = self._coerce(line, source)
            if entry:
                entries.append(entry)
        return entries

    def _parse_csv(self, raw: str, source: FeedSource) -> List[str]:
        entries: List[str] = []
        reader = csv.reader(raw.splitlines())
        for row in reader:
            if not row:
                continue
            first_cell = row[0].strip()
            if first_cell.startswith(source.comment_char) or first_cell.startswith('"#'):
                continue
            col = source.csv_column
            if col >= len(row):
                continue
            entry = self._coerce(row[col].strip().strip('"'), source)
            if entry:
                entries.append(entry)
        return entries

    def _parse_json(self, raw: str, source: FeedSource) -> List[str]:
        entries: List[str] = []
        try:
            data = json.loads(raw)

            # Navigate to the list using json_root (dot-separated path, e.g. "results" or "data")
            if source.json_root:
                for key in source.json_root.split("."):
                    if isinstance(data, dict):
                        data = data.get(key, [])
            # Fall back to common root keys when json_root is not set
            if isinstance(data, dict):
                data = data.get("data", data.get("results", data.get("items", [])))

            if not isinstance(data, list):
                logger.warning("JSON feed did not contain a list: %s", source.url)
                return entries

            for item in data:
                # Item-level filter (e.g. {"field": "ioc_type", "value": "ip:port"})
                if source.json_filter and isinstance(item, dict):
                    fld = source.json_filter.get("field", "")
                    val = source.json_filter.get("value", "")
                    if str(item.get(fld, "")) != val:
                        continue

                if isinstance(item, str):
                    entry = self._coerce(item.strip(), source)
                    if entry:
                        entries.append(entry)
                elif isinstance(item, dict):
                    # Extract multiple fields per item (e.g. sha256_hash + md5_hash)
                    fields = source.json_multi_fields or ([source.json_field] if source.json_field else [])
                    for fld in fields:
                        value = str(item.get(fld, "")).strip()
                        if value:
                            entry = self._coerce(value, source)
                            if entry:
                                entries.append(entry)

        except json.JSONDecodeError as exc:
            logger.warning("JSON parse error for %s: %s", source.name, exc)
        return entries

    # ── Validation & transformation ──────────────────────────────

    def _coerce(self, raw: str, source: FeedSource) -> Optional[str]:
        """Validate, normalise, and transform a single raw string into a clean IOC."""
        if not raw:
            return None

        if source.kind == "ip":
            candidate = raw
            # Strip CIDR prefix
            if "/" in candidate:
                candidate = candidate.split("/")[0]
            # Strip optional :port (e.g. ThreatFox sends "1.2.3.4:443")
            if source.strip_port and ":" in candidate and not self._looks_ipv6(candidate):
                candidate = candidate.split(":")[0]
            return DataValidator.validate_ip(candidate)

        if source.kind == "hash":
            return DataValidator.validate_hash(raw)

        if source.kind == "url":
            # Refang first (some feeds deliver hxxp:// or [.] notation),
            # then validate, then store as plain live URL for firewall/EDR compatibility.
            refanged = URLDefanger.refang(raw)
            if DataValidator.validate_url(refanged) is None:
                return None
            return refanged

        return None

    @staticmethod
    def _looks_ipv6(value: str) -> bool:
        return value.count(":") >= 2


# ── Git Manager ───────────────────────────────────────────────────────────────

class GitManager:
    """Handles all git operations for the stateless push-to-GitHub workflow."""

    def __init__(self) -> None:
        self._work_dir: Optional[Path] = None
        self._temp_dir: Optional[str]  = None

    @property
    def work_dir(self) -> Path:
        assert self._work_dir is not None, "Call setup() first"
        return self._work_dir

    # ── Lifecycle ────────────────────────────────────────────────

    def setup(self) -> Path:
        if IN_GITHUB_ACTIONS and GITHUB_WORKSPACE:
            # Repo is already checked out by actions/checkout
            self._work_dir = Path(GITHUB_WORKSPACE)
            logger.info("[git] Actions mode – workspace: %s", self._work_dir)
            self._configure_git(self._work_dir)
        else:
            # Docker / local: clone into a fresh temp directory
            self._temp_dir = tempfile.mkdtemp(prefix="fed0gat_")
            self._work_dir = Path(self._temp_dir)
            remote_url = self._authenticated_url()
            logger.info("[git] Cloning %s …", GH_REPO)
            self._run(["git", "clone", "--depth=1", remote_url, str(self._work_dir)])
            self._configure_git(self._work_dir)
        return self._work_dir

    def commit_and_push(self, message: str) -> None:
        wd = str(self.work_dir)
        self._run(["git", "-C", wd, "add", "-A"])

        # Check if there's anything to commit
        status = subprocess.run(
            ["git", "-C", wd, "status", "--porcelain"],
            capture_output=True, text=True, check=False,
        )
        if not status.stdout.strip():
            logger.info("[git] Nothing changed – skipping commit.")
            return

        self._run(["git", "-C", wd, "commit", "-m", message])
        logger.info("[git] Pushing to GitHub …")

        if IN_GITHUB_ACTIONS:
            self._run(["git", "-C", wd, "push"])
        else:
            self._run(["git", "-C", wd, "push", self._authenticated_url(), "HEAD:main"])

        logger.info("[git] Push complete ✓")

    def cleanup(self) -> None:
        if self._temp_dir:
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            logger.debug("[git] Removed ephemeral temp dir %s", self._temp_dir)
            self._temp_dir = None

    # ── Internals ────────────────────────────────────────────────

    def _configure_git(self, path: Path) -> None:
        wd = str(path)
        self._run(["git", "-C", wd, "config", "user.name",  GIT_NAME])
        self._run(["git", "-C", wd, "config", "user.email", GIT_EMAIL])
        if not IN_GITHUB_ACTIONS and GH_TOKEN:
            # Use a credential helper that returns the token without touching ~/.gitconfig
            self._run([
                "git", "-C", wd, "config", "credential.helper",
                f"!f() {{ echo username=x-access-token; echo password={GH_TOKEN}; }}; f",
            ])

    @staticmethod
    def _authenticated_url() -> str:
        return f"https://x-access-token:{GH_TOKEN}@github.com/{GH_REPO}.git"

    @staticmethod
    def _run(cmd: List[str]) -> None:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            # Sanitise token from error output before logging
            stderr = result.stderr.replace(GH_TOKEN, "***") if GH_TOKEN else result.stderr
            stdout = result.stdout.replace(GH_TOKEN, "***") if GH_TOKEN else result.stdout
            raise RuntimeError(
                f"Git command failed (exit {result.returncode}): {' '.join(cmd[:3])} …\n"
                f"stdout: {stdout.strip()}\nstderr: {stderr.strip()}"
            )


# ── File Rotator ──────────────────────────────────────────────────────────────

class FileRotator:
    """
    Daily archive strategy:
      - latest-{kind}.txt  → overwritten every hour with fresh IOCs
      - YYYY-MM-DD-{kind}.txt → created ONCE per day (snapshot of previous day's
        latest file), only if yesterday's archive does not already exist in the
        data directory.

    This way the repo accumulates one file per day per IOC type, and
    latest-*.txt always reflects the most recent hourly scrape.
    """

    def __init__(self, data_dir: Path, ts: datetime) -> None:
        self._dir  = data_dir
        self._ts   = ts
        # Archive gets yesterday's date: the data in latest-*.txt was
        # collected on the previous calendar day.
        yesterday         = ts - timedelta(days=1)
        self._archive_date = yesterday.strftime("%Y-%m-%d")

    def archive_if_new_day(self, kind: str) -> Optional[Path]:
        """
        Copy latest-{kind}.txt → YYYY-MM-DD-{kind}.txt using yesterday's date,
        but only if that archive file does not already exist.
        Returns the archive Path on success, None if skipped.
        """
        latest  = self._dir / f"latest-{kind}.txt"
        archive = self._dir / f"{self._archive_date}-{kind}.txt"

        if not latest.exists():
            logger.debug("[archive] latest-%s.txt yok, atlanıyor.", kind)
            return None
        if archive.exists():
            logger.debug("[archive] %s zaten var, atlanıyor.", archive.name)
            return None

        shutil.copy2(str(latest), str(archive))
        logger.info("[archive] Günlük arşiv oluşturuldu: %s", archive.name)
        return archive

    def write_latest(self, kind: str, entries: List[str]) -> Path:
        dest   = self._dir / f"latest-{kind}.txt"
        unique = sorted(set(entries))
        # Plain IOC list — no headers — firewall/EDR ready
        dest.write_text("\n".join(unique) + "\n", encoding="utf-8")
        logger.info("[write] latest-%s.txt ← %d unique entries", kind, len(unique))
        return dest


# ── Source Loader ─────────────────────────────────────────────────────────────

def load_sources(path: Path) -> List[FeedSource]:
    with open(path, encoding="utf-8") as fh:
        raw: dict = json.load(fh)
    sources: List[FeedSource] = []
    for kind, items in raw.items():
        if not isinstance(items, list):
            continue
        for item in items:
            sources.append(FeedSource(
                name              = item["name"],
                url               = item["url"],
                kind              = kind,
                fmt               = item.get("format", "plain"),
                comment_char      = item.get("comment_char", "#"),
                csv_column        = item.get("csv_column", 0),
                json_field        = item.get("json_field"),
                enabled           = item.get("enabled", True),
                strip_port        = item.get("strip_port", False),
                # API auth
                api_key_env       = item.get("api_key_env", ""),
                api_key_header    = item.get("api_key_header", ""),
                api_key_body      = item.get("api_key_body", ""),
                method            = item.get("method", "GET"),
                post_body         = item.get("post_body"),
                # JSON navigation
                json_root         = item.get("json_root", ""),
                json_filter       = item.get("json_filter"),
                json_multi_fields = item.get("json_multi_fields"),
            ))
    logger.info("[sources] Loaded %d feed sources.", len(sources))
    return sources


# ── Main Orchestrator ─────────────────────────────────────────────────────────

class Fed0gaT:
    def __init__(self, dry_run: bool = False) -> None:
        self._dry_run = dry_run or DRY_RUN
        self._http    = HttpClient()
        self._fetcher = FeedFetcher(self._http)
        self._git     = GitManager()

    def run(self) -> int:
        now = datetime.now(TZ)
        logger.info("═" * 62)
        logger.info("  Fed0gaT  │  %s +03:00  │  dry_run=%s",
                    now.strftime("%Y-%m-%d %H:%M:%S"), self._dry_run)
        logger.info("═" * 62)

        self._check_env()
        sources = load_sources(SOURCES_FILE)

        # Initialise git workspace (clone or use Actions workspace)
        if not self._dry_run:
            work_dir = self._git.setup()
        else:
            work_dir = Path(tempfile.mkdtemp(prefix="fed0gat_dryrun_"))

        data_dir = work_dir / DATA_SUBDIR
        data_dir.mkdir(parents=True, exist_ok=True)

        # Fetch all feeds
        stats = RunStats()
        all_iocs: Dict[str, List[str]] = {k: [] for k in FEED_TYPES}

        for source in sources:
            if not source.enabled:
                continue
            logger.info("")
            result = self._fetcher.fetch(source)
            if result.ok:
                all_iocs[source.kind].extend(result.entries)
                stats.sources_ok += 1
            else:
                stats.sources_fail += 1

        logger.info("")

        # ── Cross-type contamination guard ──────────────────────────────────
        # Final strict pass: every collected IOC must match its declared type.
        # This catches edge-cases where a feed returns mixed-type content
        # (e.g. OTX returning domain-only strings in a URL feed, or ThreatFox
        # POST responses slipping wrong ioc_type items past the json_filter).
        logger.info("[guard] Running cross-type contamination check …")
        for kind in FEED_TYPES:
            before = len(all_iocs[kind])
            all_iocs[kind] = self._enforce_type(kind, all_iocs[kind])
            dropped = before - len(all_iocs[kind])
            if dropped:
                logger.warning("[guard] %s feed: dropped %d wrong-type / invalid entries", kind.upper(), dropped)
            else:
                logger.info("[guard] %s feed: clean (%d entries)", kind.upper(), before)

        # Archive (once per day) + write latest
        rotator = FileRotator(data_dir, now)
        for kind in FEED_TYPES:
            if rotator.archive_if_new_day(kind):
                stats.archived += 1
            rotator.write_latest(kind, all_iocs[kind])
            stats.counts[kind] = len(set(all_iocs[kind]))

        # Persist run statistics so the web dashboard can build charts
        self._update_stats(data_dir, stats.counts, now)

        # Commit & push
        commit_msg = f"Fed0gaT Hourly Update: {now.strftime('%Y-%m-%d %H:%M')} +03:00"
        if not self._dry_run:
            try:
                self._git.commit_and_push(commit_msg)
            finally:
                self._git.cleanup()
        else:
            logger.info("[dry-run] Would commit: %s", commit_msg)
            shutil.rmtree(str(work_dir), ignore_errors=True)

        self._print_summary(stats, commit_msg)
        return 0

    # ── Helpers ──────────────────────────────────────────────────

    @staticmethod
    def _enforce_type(kind: str, iocs: List[str]) -> List[str]:
        """
        Hard type gate — the last line of defence before writing to disk.

        Guarantees:
          ip   file → only valid public IPv4/IPv6 addresses
          hash file → only valid MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
          url  file → only valid http/https URLs (including defanged hxxp form)

        Anything that doesn't match is silently dropped here, regardless of
        which feed it came from.
        """
        if kind == "ip":
            return [v for v in iocs if DataValidator.validate_ip(v) is not None]
        if kind == "hash":
            return [v for v in iocs if DataValidator.validate_hash(v) is not None]
        if kind == "url":
            # validate_url handles both defanged (hxxp) and live (http) forms
            return [v for v in iocs if DataValidator.validate_url(v) is not None]
        return iocs

    @staticmethod
    def _update_stats(data_dir: Path, counts: Dict[str, int], now: datetime) -> None:
        """Append this run's IOC counts to stats.json (keeps last 168 entries = 7 days)."""
        stats_file = data_dir / "stats.json"
        history: dict = {"runs": []}
        if stats_file.exists():
            try:
                history = json.loads(stats_file.read_text(encoding="utf-8"))
            except Exception:
                history = {"runs": []}

        history.setdefault("runs", []).append({
            "ts":   now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ip":   counts.get("ip",   0),
            "hash": counts.get("hash", 0),
            "url":  counts.get("url",  0),
        })
        # Cap history at 7 days of hourly runs
        history["runs"] = history["runs"][-168:]
        history["last_updated"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        stats_file.write_text(json.dumps(history, indent=2), encoding="utf-8")
        logger.info("[stats] stats.json updated (%d runs recorded)", len(history["runs"]))

    @staticmethod
    def _check_env() -> None:
        errors: List[str] = []
        if not GH_TOKEN:
            errors.append("GH_TOKEN is not set")
        if not GH_REPO and not IN_GITHUB_ACTIONS:
            errors.append("GH_REPO is not set (e.g. owner/my-feed-repo)")
        if errors:
            for e in errors:
                logger.critical("Config error: %s", e)
            raise SystemExit(1)

    @staticmethod
    def _print_summary(stats: RunStats, commit_msg: str) -> None:
        logger.info("")
        logger.info("╔══════════════════════════════════════════════════════════╗")
        logger.info("║  Fed0gaT Run Summary                                     ║")
        logger.info("╠══════════════════════════════════════════════════════════╣")
        logger.info("║  IPs    : %8d unique IOCs                           ║", stats.counts["ip"])
        logger.info("║  Hashes : %8d unique IOCs                           ║", stats.counts["hash"])
        logger.info("║  URLs   : %8d unique IOCs                           ║", stats.counts["url"])
        logger.info("╠══════════════════════════════════════════════════════════╣")
        logger.info("║  Sources OK / FAIL : %3d / %-3d                          ║",
                    stats.sources_ok, stats.sources_fail)
        logger.info("║  Günlük arşiv      : %3d                                 ║", stats.archived)
        logger.info("╠══════════════════════════════════════════════════════════╣")
        logger.info("║  Commit : %-48s  ║", commit_msg[:48])
        logger.info("╚══════════════════════════════════════════════════════════╝")


# ── Entry Point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="fed0gat",
        description="Stateless hourly CTI scraper – pushes IOC feeds to GitHub.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and parse feeds but do NOT push anything to GitHub.",
    )
    args = parser.parse_args()
    sys.exit(Fed0gaT(dry_run=args.dry_run).run())


if __name__ == "__main__":
    main()
