"""
GitHub REST API client for Fed0gaT web dashboard.

All feed data lives in a GitHub repository. This client provides:
  - reading file content + SHA (required for updates)
  - updating (PUT) file content with a commit message
  - listing a directory to discover archive files
  - reading stats.json for chart data
"""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class GitHubError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class GitHubClient:
    API_BASE = "https://api.github.com"

    def __init__(self, token: str, repo: str, data_dir: str = "feeds") -> None:
        self._repo     = repo        # "owner/repo-name"
        self._data_dir = data_dir.strip("/")
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503])
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.headers.update({
            "Authorization":        f"Bearer {token}",
            "Accept":               "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        self._s = session

    # ── File operations ───────────────────────────────────────────────────────

    def get_file(self, rel_path: str) -> Dict[str, Any]:
        """Return {"content": str, "sha": str, "size": int, "lines": list[str]}."""
        url  = f"{self.API_BASE}/repos/{self._repo}/contents/{self._data_dir}/{rel_path}"
        resp = self._s.get(url)
        self._raise_for_status(resp)
        data = resp.json()
        raw  = base64.b64decode(data["content"].replace("\n", "")).decode("utf-8", errors="replace")
        # Strip header comment block, keep real IOC lines
        lines = [
            ln for ln in raw.splitlines()
            if ln.strip() and not ln.startswith("#")
        ]
        return {
            "content": raw,
            "sha":     data["sha"],
            "size":    data["size"],
            "lines":   lines,
        }

    def update_file(
        self,
        rel_path: str,
        new_content: str,
        sha: str,
        commit_message: Optional[str] = None,
    ) -> None:
        """Overwrite a file in the repo with new_content and commit."""
        url     = f"{self.API_BASE}/repos/{self._repo}/contents/{self._data_dir}/{rel_path}"
        encoded = base64.b64encode(new_content.encode("utf-8")).decode("ascii")
        payload = {
            "message": commit_message or f"Fed0gaT Web: update {rel_path}",
            "content": encoded,
            "sha":     sha,
        }
        resp = self._s.put(url, json=payload)
        self._raise_for_status(resp)

    # ── Directory listing ─────────────────────────────────────────────────────

    def list_directory(self) -> List[Dict[str, Any]]:
        """List all files in the data directory."""
        url  = f"{self.API_BASE}/repos/{self._repo}/contents/{self._data_dir}"
        resp = self._s.get(url)
        self._raise_for_status(resp)
        return resp.json()  # list of {name, size, sha, type, ...}

    # ── Stats / history ───────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """
        Read stats.json written by the scraper.
        Returns {"runs": [...], "last_updated": "..."} or empty structure on miss.
        """
        try:
            file_data = self.get_file("stats.json")
            return json.loads(file_data["content"])
        except GitHubError as exc:
            if exc.status == 404:
                return {"runs": [], "last_updated": None}
            raise

    def get_dashboard_data(self) -> Dict[str, Any]:
        """
        Aggregate everything the dashboard needs in as few API calls as possible.
        Returns:
          latest_counts  – {"ip": N, "hash": N, "url": N}
          prev_counts    – counts from the previous run (for delta badges)
          chart_24h      – last 24 run entries  [{ts, ip, hash, url}, ...]
          chart_7d       – daily aggregated totals for last 7 days
          archives       – recent archive file list [{name, kind, ts, size}, ...]
          last_updated   – ISO timestamp string or None
        """
        stats  = self.get_stats()
        runs   = stats.get("runs", [])

        latest_counts = {"ip": 0, "hash": 0, "url": 0}
        prev_counts   = {"ip": 0, "hash": 0, "url": 0}
        if runs:
            r = runs[-1]
            latest_counts = {"ip": r.get("ip", 0), "hash": r.get("hash", 0), "url": r.get("url", 0)}
        if len(runs) >= 2:
            r = runs[-2]
            prev_counts = {"ip": r.get("ip", 0), "hash": r.get("hash", 0), "url": r.get("url", 0)}

        chart_24h = runs[-24:] if len(runs) >= 24 else runs

        # Daily aggregation: average per day (last 7 calendar days)
        daily: Dict[str, Dict[str, int]] = {}
        for run in runs:
            day = run["ts"][:10]  # "YYYY-MM-DD"
            if day not in daily:
                daily[day] = {"ip": 0, "hash": 0, "url": 0, "n": 0}
            daily[day]["ip"]   = max(daily[day]["ip"],   run.get("ip",   0))
            daily[day]["hash"] = max(daily[day]["hash"], run.get("hash", 0))
            daily[day]["url"]  = max(daily[day]["url"],  run.get("url",  0))
            daily[day]["n"] += 1
        chart_7d = [
            {"day": day, **vals}
            for day, vals in sorted(daily.items())
        ][-7:]

        # Recent archives from directory listing
        archives = self._parse_archives()

        return {
            "latest_counts": latest_counts,
            "prev_counts":   prev_counts,
            "chart_24h":     chart_24h,
            "chart_7d":      chart_7d,
            "archives":      archives[:20],  # last 20 archive files
            "last_updated":  stats.get("last_updated"),
            "total_runs":    len(runs),
        }

    # ── Internals ─────────────────────────────────────────────────────────────

    _ARCHIVE_RE = re.compile(
        r"^(?P<date>\d{4}-\d{2}-\d{2})_(?P<hm>\d{2}-\d{2})-(?P<kind>ip|hash|url)\.txt$"
    )

    def _parse_archives(self) -> List[Dict[str, Any]]:
        """List and parse archive filenames from the data directory."""
        try:
            files = self.list_directory()
        except GitHubError:
            return []
        archives = []
        for f in files:
            m = self._ARCHIVE_RE.match(f["name"])
            if m:
                ts_str = f"{m.group('date')}T{m.group('hm').replace('-', ':')}:00Z"
                archives.append({
                    "name": f["name"],
                    "kind": m.group("kind"),
                    "ts":   ts_str,
                    "size": f.get("size", 0),
                })
        archives.sort(key=lambda x: x["ts"], reverse=True)
        return archives

    @staticmethod
    def _raise_for_status(resp: requests.Response) -> None:
        if not resp.ok:
            try:
                msg = resp.json().get("message", resp.text)
            except Exception:
                msg = resp.text
            raise GitHubError(resp.status_code, f"GitHub API {resp.status_code}: {msg}")
