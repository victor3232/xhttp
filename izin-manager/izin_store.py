#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Core pengelola file izin (license) HITS SSH.

Format file:
    ### nama 2026-12-31 1.2.3.4

Mendukung:
- baca/tulis file lokal (untuk tes)
- baca/tulis GitHub Contents API (untuk Railway)
- add / update / delete / check IP
"""

from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

JAKARTA = dt.timezone(dt.timedelta(hours=7))
LIFETIME = "2099-12-31"
GITHUB_API = "https://api.github.com"

NAME_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,40}$")


class StoreError(Exception):
    pass


class StoreConflict(StoreError):
    pass


@dataclass
class Entry:
    line_no: int
    raw: str
    name: str
    expiry: str
    ip: str
    valid: bool
    error: str = ""
    days_left: int | None = None
    status: str = "invalid"


def today_jkt() -> dt.date:
    return dt.datetime.now(JAKARTA).date()


def normalize_expiry(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("expiry wajib diisi")
    if value.lower() in ("lifetime", "life", "forever", "selamanya"):
        return LIFETIME
    try:
        parsed = dt.date.fromisoformat(value)
    except ValueError:
        raise ValueError("expiry harus YYYY-MM-DD atau lifetime")
    return parsed.isoformat()


def normalize_ip(value: str) -> str:
    value = (value or "").strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError("IP tidak valid")


def normalize_name(value: str) -> str:
    value = re.sub(r"\s+", " ", (value or "").strip())
    if not value:
        raise ValueError("nama wajib diisi")
    if not NAME_RE.fullmatch(value):
        raise ValueError("nama hanya huruf, angka, spasi, titik, garis bawah, strip (maks 40)")
    return value


def parse_entries(text: str) -> list[Entry]:
    entries: list[Entry] = []
    today = today_jkt()
    for idx, raw in enumerate((text or "").splitlines(), 1):
        stripped = raw.strip()
        if not stripped.startswith("###"):
            continue
        body = stripped[3:].strip()
        parts = body.split()
        if len(parts) < 2:
            entries.append(Entry(idx, raw, "", "", "", False, "format tidak lengkap"))
            continue
        ip = parts[-1]
        try:
            ip = normalize_ip(ip)
            valid_ip = True
        except ValueError:
            valid_ip = False
        if len(parts) >= 3:
            expiry = parts[-2]
            name = " ".join(parts[:-2])
        else:
            expiry = LIFETIME
            name = " ".join(parts[:-1])

        valid_expiry = True
        try:
            expiry_norm = normalize_expiry(expiry)
        except ValueError:
            expiry_norm = expiry
            valid_expiry = False

        status = "invalid"
        days_left = None
        if valid_ip and valid_expiry:
            if expiry_norm == LIFETIME:
                status = "lifetime"
            else:
                try:
                    exp_date = dt.date.fromisoformat(expiry_norm)
                    days_left = (exp_date - today).days
                    status = "active" if days_left >= 0 else "expired"
                except ValueError:
                    status = "invalid"

        entries.append(Entry(
            line_no=idx,
            raw=raw,
            name=name,
            expiry=expiry_norm,
            ip=ip if valid_ip else parts[-1],
            valid=valid_ip and valid_expiry,
            error="" if valid_ip and valid_expiry else "IP/expiry tidak valid",
            days_left=days_left,
            status=status,
        ))
    return entries


def format_line(name: str, expiry: str, ip: str) -> str:
    return "### %s %s %s" % (normalize_name(name), normalize_expiry(expiry), normalize_ip(ip))


def _ensure_newline(text: str) -> str:
    return text if not text or text.endswith("\n") else text + "\n"


def add_or_update(text: str, name: str, expiry: str, ip: str) -> tuple[str, dict]:
    name = normalize_name(name)
    expiry = normalize_expiry(expiry)
    ip = normalize_ip(ip)
    lines = (text or "").splitlines(True)
    entries = parse_entries(text)
    for entry in entries:
        if entry.valid and entry.ip == ip:
            lines[entry.line_no - 1] = format_line(name, expiry, ip) + "\n"
            return "".join(lines), {"action": "updated", "line": entry.line_no, "ip": ip}
    new_text = _ensure_newline(text)
    new_text += format_line(name, expiry, ip) + "\n"
    return new_text, {"action": "added", "ip": ip}


def delete_ip(text: str, ip: str) -> tuple[str, dict]:
    ip = normalize_ip(ip)
    lines = (text or "").splitlines(True)
    entries = parse_entries(text)
    remove = {entry.line_no for entry in entries if entry.valid and entry.ip == ip}
    if not remove:
        raise ValueError("IP tidak ditemukan di file izin")
    kept = [line for idx, line in enumerate(lines, 1) if idx not in remove]
    return "".join(kept), {"action": "deleted", "count": len(remove), "ip": ip}


def check_ip(text: str, ip: str) -> dict:
    ip = normalize_ip(ip)
    entries = [entry for entry in parse_entries(text) if entry.valid and entry.ip == ip]
    if not entries:
        return {
            "ok": True,
            "found": False,
            "ip": ip,
            "name": "",
            "expiry": "",
            "status": "not_found",
            "days_left": None,
        }
    entry = entries[0]
    return {
        "ok": True,
        "found": True,
        "ip": entry.ip,
        "name": entry.name,
        "expiry": entry.expiry,
        "status": entry.status,
        "days_left": entry.days_left,
        "duplicates": len(entries),
    }


def summary(entries: list[Entry]) -> dict:
    out = {"total": 0, "active": 0, "expired": 0, "lifetime": 0, "invalid": 0}
    for entry in entries:
        out["total"] += 1
        if entry.status in out:
            out[entry.status] += 1
    return out


class LocalStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.lock = threading.Lock()

    def read(self) -> tuple[str, str]:
        try:
            return self.path.read_text(encoding="utf-8", errors="replace"), ""
        except FileNotFoundError:
            return "", ""

    def update(self, mutator, message: str) -> tuple[str, dict]:
        with self.lock:
            text, _sha = self.read()
            new_text, info = mutator(text)
            if new_text != text:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.path.write_text(new_text, encoding="utf-8")
            return new_text, info


class GitHubStore:
    def __init__(self, repo: str, path: str, branch: str, token: str, api: str = GITHUB_API):
        self.repo = repo.strip().strip("/")
        self.path = path.strip().lstrip("/")
        self.branch = branch.strip() or "main"
        self.token = token.strip()
        self.api = api.rstrip("/")
        if not self.token:
            raise StoreError("GITHUB_TOKEN kosong")

    def _request(self, method: str, url: str, payload: dict | None = None) -> tuple[int, dict]:
        body = b""
        headers = {
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "kyt-izin-manager/1.0",
        }
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body if body else None, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                raw = resp.read().decode("utf-8", "replace")
                return resp.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            try:
                data = json.loads(raw) if raw else {}
            except Exception:
                data = {"message": raw[:500]}
            if exc.code in (409, 422):
                raise StoreConflict(data.get("message") or "konflik GitHub")
            if exc.code in (401, 403):
                raise StoreError("GitHub menolak token: %s" % (data.get("message") or exc.code))
            raise StoreError("GitHub error %s: %s" % (exc.code, data.get("message") or "unknown"))
        except Exception as exc:
            raise StoreError("Gagal menghubungi GitHub: %s" % exc)

    def _url(self) -> str:
        path = urllib.parse.quote(self.path, safe="/")
        return "%s/repos/%s/contents/%s" % (self.api, self.repo, path)

    def read(self) -> tuple[str, str]:
        url = self._url() + "?" + urllib.parse.urlencode({"ref": self.branch})
        _status, data = self._request("GET", url)
        if data.get("type") != "file":
            raise StoreError("path %s bukan file di repo" % self.path)
        try:
            content = base64.b64decode(data.get("content") or "").decode("utf-8", "replace")
        except Exception as exc:
            raise StoreError("gagal decode isi file: %s" % exc)
        return content, data.get("sha") or ""

    def write(self, text: str, sha: str, message: str) -> None:
        payload = {
            "message": message,
            "content": base64.b64encode(text.encode("utf-8")).decode("ascii"),
            "branch": self.branch,
        }
        if sha:
            payload["sha"] = sha
        self._request("PUT", self._url(), payload)

    def update(self, mutator, message: str) -> tuple[str, dict]:
        last: Exception | None = None
        for attempt in range(3):
            text, sha = self.read()
            new_text, info = mutator(text)
            if new_text == text:
                return text, info
            try:
                self.write(new_text, sha, message)
                return new_text, info
            except StoreConflict as exc:
                last = exc
                time.sleep(0.6 * (attempt + 1))
        raise last or StoreError("gagal update file izin")


def make_store():
    token = (os.environ.get("GITHUB_TOKEN") or "").strip()
    if token:
        return GitHubStore(
            repo=os.environ.get("GITHUB_REPO", "victor3232/xhttp"),
            path=os.environ.get("GITHUB_PATH", "izin"),
            branch=os.environ.get("GITHUB_BRANCH", "main"),
            token=token,
            api=os.environ.get("GITHUB_API", GITHUB_API),
        )
    return LocalStore(os.environ.get("IZIN_FILE", "izin"))
