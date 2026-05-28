"""
Fed0gaT Web Dashboard – Flask application

Routes:
  GET  /                     Dashboard (KPIs + charts)
  GET  /editor               IOC file editor (tabs: ip / hash / url)
  GET  /api/dashboard        JSON data for dashboard charts
  GET  /api/file/<kind>      Raw file content + SHA + parsed lines
  POST /api/file/<kind>      Save edited file back to GitHub
  POST /api/file/<kind>/add  Add a single IOC entry
  POST /api/file/<kind>/del  Remove one or more IOC entries

Environment variables:
  GH_TOKEN   – GitHub personal access token   (required)
  GH_REPO    – "owner/repo-name"              (required)
  DATA_DIR   – subdirectory in repo           (default: feeds)
  WEB_SECRET – Flask session secret           (required in production)
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Dict, List, Tuple

from flask import (
    Flask,
    abort,
    jsonify,
    render_template,
    request,
)

from github_client import GitHubClient, GitHubError

app = Flask(__name__)
app.secret_key = os.environ.get("WEB_SECRET", "change-me-in-production")

GH_TOKEN = os.environ.get("GH_TOKEN", "")
GH_REPO  = os.environ.get("GH_REPO",  "")
DATA_DIR = os.environ.get("DATA_DIR", "feeds")

VALID_KINDS = {"ip", "hash", "url"}

TZ = timezone(timedelta(hours=3))  # UTC+3 Istanbul (permanent since 2016)

# ── Validators (mirrors fed0gat.py – kept local to avoid import coupling) ─────

_RE_IPV4   = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")
_RE_MD5    = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_SHA1   = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_PRIVATE   = re.compile(r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.)")

def _validate(value: str, kind: str) -> Tuple[bool, str]:
    """Returns (is_valid, normalised_value_or_error_message)."""
    v = value.strip()
    if not v:
        return False, "Boş değer"
    if kind == "ip":
        ip = v.split("/")[0].split(":")[0]
        if _PRIVATE.match(ip):
            return False, "Özel/iç ağ adresi"
        if _RE_IPV4.match(ip):
            return True, ip
        return False, "Geçersiz IPv4 formatı"
    if kind == "hash":
        h = v.lower()
        if _RE_MD5.match(h) or _RE_SHA1.match(h) or _RE_SHA256.match(h):
            return True, h
        return False, "Geçersiz hash (MD5/SHA1/SHA256 olmalı)"
    if kind == "url":
        if not v.startswith(("http://", "https://", "hxxp://", "hxxps://")):
            return False, "URL http:// veya https:// ile başlamalı"
        return True, v
    return False, "Bilinmeyen tür"


def _make_client() -> GitHubClient:
    return GitHubClient(GH_TOKEN, GH_REPO, DATA_DIR)


def _require_config(f):
    """Decorator: return 503 if env vars are missing."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not GH_TOKEN or not GH_REPO:
            return jsonify({"error": "GH_TOKEN veya GH_REPO ayarlanmamış"}), 503
        return f(*args, **kwargs)
    return wrapper


# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
@_require_config
def dashboard():
    return render_template("dashboard.html", repo=GH_REPO, data_dir=DATA_DIR)


@app.route("/editor")
@_require_config
def editor():
    kind = request.args.get("kind", "ip")
    if kind not in VALID_KINDS:
        kind = "ip"
    return render_template("editor.html", repo=GH_REPO, active_kind=kind)


# ── JSON API ──────────────────────────────────────────────────────────────────

@app.route("/api/dashboard")
@_require_config
def api_dashboard():
    try:
        data = _make_client().get_dashboard_data()
        return jsonify(data)
    except GitHubError as exc:
        return jsonify({"error": str(exc)}), exc.status
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/file/<kind>", methods=["GET"])
@_require_config
def api_get_file(kind: str):
    if kind not in VALID_KINDS:
        abort(400)
    try:
        data = _make_client().get_file(f"latest-{kind}.txt")
        return jsonify({
            "kind":  kind,
            "sha":   data["sha"],
            "size":  data["size"],
            "lines": data["lines"],
            "count": len(data["lines"]),
        })
    except GitHubError as exc:
        return jsonify({"error": str(exc)}), exc.status
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/file/<kind>", methods=["POST"])
@_require_config
def api_save_file(kind: str):
    """Replace entire file content (lines array) and push to GitHub."""
    if kind not in VALID_KINDS:
        abort(400)
    body = request.get_json(silent=True) or {}
    sha   = body.get("sha")
    lines = body.get("lines")
    note  = body.get("note", "")

    if not sha or lines is None:
        return jsonify({"error": "sha ve lines zorunlu"}), 400

    # Validate every line
    validated, rejected = [], []
    for raw in lines:
        ok, val = _validate(str(raw), kind)
        if ok:
            validated.append(val)
        else:
            rejected.append({"entry": raw, "reason": val})

    unique  = sorted(set(validated))
    content = "\n".join(unique) + "\n"
    msg_note = f" – {note}" if note else ""
    commit   = f"Fed0gaT Web: {kind.upper()} listesi güncellendi{msg_note} ({len(unique)} kayıt)"

    try:
        _make_client().update_file(f"latest-{kind}.txt", content, sha, commit)
        return jsonify({
            "ok":       True,
            "count":    len(unique),
            "rejected": rejected,
            "commit":   commit,
        })
    except GitHubError as exc:
        return jsonify({"error": str(exc)}), exc.status
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/file/<kind>/add", methods=["POST"])
@_require_config
def api_add_entry(kind: str):
    """Add a single IOC without replacing the whole file."""
    if kind not in VALID_KINDS:
        abort(400)
    body  = request.get_json(silent=True) or {}
    entry = str(body.get("entry", "")).strip()
    sha   = body.get("sha")

    if not sha or not entry:
        return jsonify({"error": "sha ve entry zorunlu"}), 400

    ok, val = _validate(entry, kind)
    if not ok:
        return jsonify({"error": val}), 422

    try:
        gh   = _make_client()
        data = gh.get_file(f"latest-{kind}.txt")
        current_lines: List[str] = data["lines"]
        if val in current_lines:
            return jsonify({"error": "Bu kayıt zaten listede mevcut"}), 409

        current_lines.append(val)
        unique  = sorted(set(current_lines))
        content = "\n".join(unique) + "\n"
        commit  = f"Fed0gaT Web: {kind.upper()} – eklendi: {val}"
        gh.update_file(f"latest-{kind}.txt", content, data["sha"], commit)
        return jsonify({"ok": True, "entry": val, "count": len(unique)})
    except GitHubError as exc:
        return jsonify({"error": str(exc)}), exc.status
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/file/<kind>/del", methods=["POST"])
@_require_config
def api_delete_entries(kind: str):
    """Remove one or more IOC entries by value."""
    if kind not in VALID_KINDS:
        abort(400)
    body    = request.get_json(silent=True) or {}
    to_del  = set(str(e).strip() for e in body.get("entries", []))
    sha     = body.get("sha")

    if not sha or not to_del:
        return jsonify({"error": "sha ve entries zorunlu"}), 400

    try:
        gh      = _make_client()
        data    = gh.get_file(f"latest-{kind}.txt")
        before  = len(data["lines"])
        kept    = sorted(set(ln for ln in data["lines"] if ln not in to_del))
        removed = before - len(kept)
        content = "\n".join(kept) + "\n"
        commit  = f"Fed0gaT Web: {kind.upper()} – {removed} kayıt silindi"
        gh.update_file(f"latest-{kind}.txt", content, data["sha"], commit)
        return jsonify({"ok": True, "removed": removed, "count": len(kept)})
    except GitHubError as exc:
        return jsonify({"error": str(exc)}), exc.status
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Dev server entry ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
