#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPNFree - website pembuatan akun SSH & Xray untuk VPS KYT.

Prinsip:
- Tidak menyentuh akun yang sudah ada. Hanya membuat akun baru berprefix acak,
  lalu opsional menghapus akun yang dibuat lewat website.
- Output akun diambil langsung dari file hasil script panel VPS, sehingga
  formatnya identik dengan menu bawaan.
"""

from __future__ import annotations

import argparse
import base64
import collections
import datetime as dt
import fcntl
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import mimetypes
import os
import pwd
import re
import secrets
import shutil
import signal
import socketserver
import sqlite3
import string
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
STATIC_DIR = APP_DIR / "static"
DB_PATH = DATA_DIR / "web.db"
LOG_PATH = DATA_DIR / "web.log"
SECRET_PATH = APP_DIR / "secret.key"
ADMIN_CRED_PATH = Path("/root/kyt-web-admin.txt")
CONFIG_PATH = Path("/etc/kyt-web.conf")

JAKARTA = dt.timezone(dt.timedelta(hours=7))


def read_web_conf() -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        with open("/etc/kyt-web.conf", "r", errors="ignore") as fh:
            for raw in fh:
                line = raw.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    data[key.strip().upper()] = value.strip().strip("'\"")
    except FileNotFoundError:
        pass
    return data


_WEB_CONF = read_web_conf()
PUBLIC_HOST = _WEB_CONF.get("DOMAIN", "vpnfree.stunnelv4.biz.id") or "vpnfree.stunnelv4.biz.id"
BRAND = "VPNFree"
FORM_COOKIE = "kyt_form"
ADMIN_COOKIE = "kyt_admin"
SESSION_TTL = 8 * 3600
FORM_TTL = 24 * 3600
MAX_BODY = 64 * 1024

SERVICES = {
    "ssh": {
        "label": "SSH",
        "sub": "SSH / Dropbear / WS / SSL",
        "icon": "terminal",
    },
    "xray": {
        "label": "Xray",
        "sub": "VMess, VLESS, atau Trojan",
        "icon": "bolt",
    },
}
PROTOCOLS = {
    "vmess": {
        "label": "VMess",
        "script": "/usr/local/sbin/addws",
        "marker": "###",
        "db": "/etc/vmess/.vmess.db",
        "dir": "/etc/vmess",
        "ipdir": "/etc/kyt/limit/vmess/ip",
        "prefix": "wm",
    },
    "vless": {
        "label": "VLESS",
        "script": "/usr/local/sbin/addvless",
        "marker": "#&",
        "db": "/etc/vless/.vless.db",
        "dir": "/etc/vless",
        "ipdir": "/etc/kyt/limit/vless/ip",
        "prefix": "wl",
    },
    "trojan": {
        "label": "Trojan",
        "script": "/usr/local/sbin/addtr",
        "marker": "#!",
        "db": "/etc/trojan/.trojan.db",
        "dir": "/etc/trojan",
        "ipdir": "/etc/kyt/limit/trojan/ip",
        "prefix": "wt",
    },
}
SSH_SCRIPT = "/usr/local/sbin/addssh"
XRAY_CONFIG = Path("/etc/xray/config.json")
HTML_DIR = Path("/var/www/html")
MIHOMO_STATE = Path("/etc/kyt/jeda-mullog")

DEFAULTS = {
    "site_name": BRAND,
    "maintenance": "0",
    "ssh_enabled": "1",
    "xray_enabled": "1",
    "vmess_enabled": "1",
    "vless_enabled": "1",
    "trojan_enabled": "1",
    "ssh_ip_limit": "2",
    "ssh_quota_gb": "0",
    "xray_ip_limit": "2",
    "xray_quota_gb": "0",
    "ssh_daily_3": "10",
    "ssh_daily_7": "5",
    "xray_daily_3": "10",
    "xray_daily_7": "5",
    "per_ip_daily": "2",
}

INT_SETTINGS = {
    "ssh_ip_limit": (0, 100),
    "ssh_quota_gb": (0, 10000),
    "xray_ip_limit": (0, 100),
    "xray_quota_gb": (0, 10000),
    "ssh_daily_3": (0, 1000),
    "ssh_daily_7": (0, 1000),
    "xray_daily_3": (0, 1000),
    "xray_daily_7": (0, 1000),
    "per_ip_daily": (0, 1000),
}

USER_RE = re.compile(r"^[a-z][a-z0-9]{7,14}$")
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ANSI_OSC_RE = re.compile(r"\x1b\][^\x07]*(?:\x07|\x1b\\)")

CREATE_LOCK = threading.Lock()
RATE_LOCK = threading.Lock()
RATE_BUCKETS: dict[str, collections.deque] = {}
PUBLIC_RATE: dict[str, collections.deque] = {}

DATA_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("vpnfree")
logger.setLevel(logging.INFO)
_handler = RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(_handler)
logger.addHandler(logging.StreamHandler(sys.stderr))


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def now_jkt() -> dt.datetime:
    return dt.datetime.now(JAKARTA)


def today_key() -> str:
    return now_jkt().strftime("%Y-%m-%d")


def next_reset_epoch() -> int:
    now = now_jkt()
    tomorrow = (now + dt.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(tomorrow.timestamp())


def fmt_ts(epoch: int | float | None, pattern: str = "%d %b %Y, %H:%M WIB") -> str:
    if not epoch:
        return "-"
    return dt.datetime.fromtimestamp(float(epoch), JAKARTA).strftime(pattern)


def clean_output(text: str) -> str:
    text = ANSI_OSC_RE.sub("", text or "")
    text = ANSI_RE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    return text.strip("\n")


def e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def mask_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            parts = ip.split(".")
            return ".".join(parts[:3] + ["x"])
        return str(addr.exploded[:4]) + "…"
    except Exception:
        return ip or "-"


def parse_ip(raw: str) -> str:
    raw = (raw or "").strip()
    if raw.startswith("["):
        raw = raw[1:].split("]", 1)[0]
    elif raw.count(":") == 1 and "." in raw:
        raw = raw.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(raw))
    except Exception:
        return raw[:64] or "unknown"


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = db_connect()
    try:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                service TEXT NOT NULL,
                protocol TEXT NOT NULL DEFAULT '',
                days INTEGER NOT NULL,
                ip TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                created_day TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                output TEXT NOT NULL DEFAULT '',
                error TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_accounts_day ON accounts(created_day, service, days, status);
            CREATE INDEX IF NOT EXISTS idx_accounts_ip ON accounts(created_day, service, ip, status);
            CREATE TABLE IF NOT EXISTS admin (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                csrf TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                ip TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at INTEGER NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT ''
            );
            """
        )
        for k, v in DEFAULTS.items():
            conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))
        row = conn.execute("SELECT username FROM admin LIMIT 1").fetchone()
        if not row:
            password = secrets.token_urlsafe(14)
            username = "admin"
            conn.execute(
                "INSERT INTO admin(username,password_hash,updated_at) VALUES(?,?,?)",
                (username, hash_password(password), int(time.time())),
            )
            ADMIN_CRED_PATH.write_text(
                "VPNFree admin\n"
                f"URL      : https://{PUBLIC_HOST}/admin\n"
                f"Username : {username}\n"
                f"Password : {password}\n"
                "\nGanti password setelah login pertama.\n",
                encoding="utf-8",
            )
            os.chmod(ADMIN_CRED_PATH, 0o600)
            logger.info("admin awal dibuat; kredensial di %s", ADMIN_CRED_PATH)
        conn.commit()
    finally:
        conn.close()


def get_settings() -> dict[str, str]:
    conn = db_connect()
    try:
        data = dict(DEFAULTS)
        for row in conn.execute("SELECT key,value FROM settings"):
            data[row["key"]] = row["value"]
        return data
    finally:
        conn.close()


def set_settings(values: dict[str, str]) -> None:
    conn = db_connect()
    try:
        for key, value in values.items():
            conn.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, str(value)),
            )
        conn.commit()
    finally:
        conn.close()


def quota_state(settings: dict[str, str] | None = None) -> dict:
    """Kuota global per layanan per durasi + pemakaian per IP hari ini."""
    settings = settings or get_settings()
    day = today_key()
    conn = db_connect()
    try:
        data = {}
        for service in SERVICES:
            data[service] = {}
            for days in (3, 7):
                limit = int(settings.get(f"{service}_daily_{days}", "0") or 0)
                used = conn.execute(
                    "SELECT COUNT(*) AS n FROM accounts "
                    "WHERE created_day=? AND service=? AND days=? AND status='active'",
                    (day, service, days),
                ).fetchone()["n"]
                data[service][str(days)] = {
                    "limit": limit,
                    "used": int(used),
                    "remaining": max(0, limit - int(used)),
                }
        return {"day": day, "services": data, "reset_at": next_reset_epoch()}
    finally:
        conn.close()


def per_ip_used(ip: str, service: str) -> int:
    conn = db_connect()
    try:
        return int(
            conn.execute(
                "SELECT COUNT(*) AS n FROM accounts "
                "WHERE created_day=? AND service=? AND ip=? AND status='active'",
                (today_key(), service, ip),
            ).fetchone()["n"]
        )
    finally:
        conn.close()


def audit(action: str, detail: str, ip: str = "") -> None:
    conn = db_connect()
    try:
        conn.execute(
            "INSERT INTO audit(at,action,detail,ip) VALUES(?,?,?,?)",
            (int(time.time()), action, detail[:1000], ip[:64]),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Password & session
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    iterations = 310_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.urlsafe_b64encode(salt).decode().rstrip("="),
        base64.urlsafe_b64encode(digest).decode().rstrip("="),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_b64 + "=" * (-len(salt_b64) % 4))
        expected = base64.urlsafe_b64decode(hash_b64 + "=" * (-len(hash_b64) % 4))
        got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
        return hmac.compare_digest(got, expected)
    except Exception:
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(username: str, ip: str) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    conn = db_connect()
    try:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (int(time.time()),))
        conn.execute(
            "INSERT INTO sessions(token_hash,username,csrf,created_at,expires_at,ip) "
            "VALUES(?,?,?,?,?,?)",
            (token_hash(token), username, csrf, int(time.time()), int(time.time()) + SESSION_TTL, ip),
        )
        conn.commit()
    finally:
        conn.close()
    return token, csrf


def get_session(token: str | None) -> sqlite3.Row | None:
    if not token:
        return None
    conn = db_connect()
    try:
        row = conn.execute(
            "SELECT * FROM sessions WHERE token_hash=? AND expires_at>=?",
            (token_hash(token), int(time.time())),
        ).fetchone()
        return row
    finally:
        conn.close()


def drop_session(token: str | None) -> None:
    if not token:
        return
    conn = db_connect()
    try:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(token),))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# VPS account operations
# ---------------------------------------------------------------------------

def run_panel_script(args: list[str], answers: list[str], timeout: int = 120) -> tuple[int, str]:
    env = os.environ.copy()
    env.update({"TERM": "dumb", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    payload = "\n".join(str(a) for a in answers) + "\n"
    proc = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        cwd="/root",
        start_new_session=True,
    )
    try:
        out, _ = proc.communicate(payload, timeout=timeout)
        return proc.returncode, clean_output(out or "")
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except Exception:
            pass
        try:
            out, _ = proc.communicate(timeout=5)
        except Exception:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                pass
            out = ""
        logger.error("timeout script %s", " ".join(args))
        return 124, clean_output(out or "timeout")


def username_free(user: str) -> bool:
    if not USER_RE.match(user):
        return False
    try:
        pwd.getpwnam(user)
        return False
    except KeyError:
        pass
    try:
        config_text = XRAY_CONFIG.read_text(errors="ignore")
        for marker in ("###", "#&", "#!"):
            if re.search(r"(?m)^" + re.escape(marker) + r"\s+" + re.escape(user) + r"(?:\s|$)", config_text):
                return False
    except FileNotFoundError:
        pass
    for proto in PROTOCOLS.values():
        if Path(proto["db"]).exists():
            try:
                if re.search(
                    r"(?m)^###\s+" + re.escape(user) + r"(?:\s|$)",
                    Path(proto["db"]).read_text(errors="ignore"),
                ):
                    return False
            except Exception:
                pass
    if list(HTML_DIR.glob(f"*-{user}.txt")):
        return False
    return True


def make_username(service: str, protocol: str = "") -> str:
    prefix = "ws" if service == "ssh" else PROTOCOLS[protocol]["prefix"]
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    for _ in range(100):
        user = prefix + "".join(secrets.choice(alphabet) for _ in range(7))
        if username_free(user):
            return user
    raise RuntimeError("tidak bisa membuat username unik")


def make_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(12))


def verify_ssh(user: str, password: str) -> tuple[bool, str]:
    try:
        pwd.getpwnam(user)
    except KeyError:
        return False, "user tidak terbentuk"
    if not (HTML_DIR / f"ssh-{user}.txt").exists():
        return False, "file output SSH tidak terbentuk"
    try:
        db = Path("/etc/ssh/.ssh.db").read_text(errors="ignore")
        if not re.search(r"(?m)^#ssh#\s+" + re.escape(user) + r"(?:\s|$)", db):
            return False, "baris database SSH tidak terbentuk"
    except FileNotFoundError:
        return False, "database SSH tidak ditemukan"
    return True, ""


def verify_xray(protocol: str, user: str) -> tuple[bool, str]:
    cfg = PROTOCOLS[protocol]
    try:
        config_text = XRAY_CONFIG.read_text(errors="ignore")
    except FileNotFoundError:
        return False, "config xray tidak ditemukan"
    pattern = r"(?m)^" + re.escape(cfg["marker"]) + r"\s+" + re.escape(user) + r"(?:\s|$)"
    if not re.search(pattern, config_text):
        return False, "blok config tidak terbentuk"
    try:
        db = Path(cfg["db"]).read_text(errors="ignore")
        if not re.search(r"(?m)^###\s+" + re.escape(user) + r"(?:\s|$)", db):
            return False, "baris database tidak terbentuk"
    except FileNotFoundError:
        return False, "database protokol tidak ditemukan"
    if not (HTML_DIR / f"{protocol}-{user}.txt").exists():
        return False, "file output tidak terbentuk"
    return True, ""


def read_account_output(service: str, user: str, protocol: str = "") -> str:
    name = f"ssh-{user}.txt" if service == "ssh" else f"{protocol}-{user}.txt"
    path = HTML_DIR / name
    try:
        return clean_output(path.read_text(encoding="utf-8", errors="replace"))
    except FileNotFoundError:
        return ""


def remove_ssh_account(user: str) -> None:
    subprocess.run(["pkill", "-9", "-u", user], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["userdel", user], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for path in (
        f"/etc/ssh/{user}",
        f"/etc/limit/ssh/{user}",
        f"/etc/limit/ssh/{user}.lock",
        f"/etc/limit/ssh/{user}.tmp",
        f"/etc/kyt/limit/ssh/ip/{user}",
        str(HTML_DIR / f"ssh-{user}.txt"),
        str(MIHOMO_STATE / "state" / f"ssh-{user}.json"),
        str(MIHOMO_STATE / "restored" / f"ssh-{user}"),
    ):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    db_path = Path("/etc/ssh/.ssh.db")
    if db_path.exists():
        lines = [
            line
            for line in db_path.read_text(errors="ignore").splitlines(True)
            if not re.match(r"^#ssh#\s+" + re.escape(user) + r"(?:\s|$)", line)
        ]
        db_path.write_text("".join(lines), errors="ignore")


def remove_xray_blocks(protocol: str, user: str) -> bool:
    cfg = PROTOCOLS[protocol]
    try:
        lines = XRAY_CONFIG.read_text(errors="ignore").splitlines(True)
    except FileNotFoundError:
        return False
    pattern = re.compile(
        r"^\s*" + re.escape(cfg["marker"]) + r"\s+" + re.escape(user) + r"(?:\s|$)"
    )
    out: list[str] = []
    changed = False
    i = 0
    while i < len(lines):
        if pattern.match(lines[i]):
            changed = True
            i += 1
            if i < len(lines) and lines[i].lstrip().startswith("},{"):
                i += 1
            continue
        out.append(lines[i])
        i += 1
    if changed:
        tmp = XRAY_CONFIG.with_suffix(".json.tmp")
        tmp.write_text("".join(out), encoding="utf-8")
        os.replace(tmp, XRAY_CONFIG)
    db_path = Path(cfg["db"])
    if db_path.exists():
        keep = [
            line
            for line in db_path.read_text(errors="ignore").splitlines(True)
            if not re.match(r"^###\s+" + re.escape(user) + r"(?:\s|$)", line)
        ]
        db_path.write_text("".join(keep), encoding="utf-8")
    for path in (
        Path(cfg["dir"]) / user,
        Path(cfg["ipdir"]) / user,
        HTML_DIR / f"{protocol}-{user}.txt",
        MIHOMO_STATE / "state" / f"xray-{protocol}-{user}.json",
        MIHOMO_STATE / "restored" / f"xray-{protocol}-{user}",
    ):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    return changed


def remove_xray_account(protocol: str, user: str) -> None:
    changed = remove_xray_blocks(protocol, user)
    if changed:
        subprocess.run(["systemctl", "restart", "xray"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def create_ssh_account(user: str, password: str, days: int, ip_limit: int, quota_gb: int) -> tuple[bool, str, str]:
    rc, log = run_panel_script(
        [SSH_SCRIPT],
        [user, password, str(ip_limit), str(quota_gb), str(days)],
        timeout=120,
    )
    ok, reason = verify_ssh(user, password)
    if ok:
        return True, read_account_output("ssh", user), log
    logger.error("gagal membuat SSH %s rc=%s reason=%s\n%s", user, rc, reason, log[-4000:])
    remove_ssh_account(user)
    return False, reason, log


def create_xray_account(protocol: str, user: str, days: int, ip_limit: int, quota_gb: int) -> tuple[bool, str, str]:
    cfg = PROTOCOLS[protocol]
    rc, log = run_panel_script(
        [cfg["script"]],
        [user, str(days), str(quota_gb), str(ip_limit)],
        timeout=120,
    )
    ok, reason = verify_xray(protocol, user)
    if ok:
        return True, read_account_output("ssh" if False else "xray", user, protocol), log
    logger.error(
        "gagal membuat XRAY %s/%s rc=%s reason=%s\n%s", protocol, user, rc, reason, log[-4000:]
    )
    remove_xray_account(protocol, user)
    return False, reason, log


def create_account(service: str, protocol: str, days: int, ip: str, user_agent: str) -> dict:
    settings = get_settings()
    quota = quota_state(settings)
    if settings.get("maintenance") == "1":
        raise ValueError("Website sedang dalam perawatan. Silakan coba lagi nanti.")
    if not settings.get(f"{service}_enabled") == "1":
        raise ValueError(f"Layanan {SERVICES[service]['label']} sedang dinonaktifkan admin.")
    if service == "xray" and settings.get(f"{protocol}_enabled", "1") != "1":
        raise ValueError(f"Protokol {PROTOCOLS[protocol]['label']} sedang ditutup admin.")
    q = quota["services"][service][str(days)]
    if q["limit"] <= 0 or q["remaining"] <= 0:
        raise ValueError(
            f"Kuota {SERVICES[service]['label']} {days} hari hari ini sudah habis. "
            "Kuota di-reset otomatis pukul 00.00 WIB."
        )
    per_ip_limit = int(settings.get("per_ip_daily", "0") or 0)
    if per_ip_limit > 0 and per_ip_used(ip, service) >= per_ip_limit:
        raise ValueError(
            "Batas pembuatan akun dari IP Anda hari ini sudah tercapai. "
            "Coba lagi setelah pukul 00.00 WIB."
        )

    ip_limit = int(settings.get(f"{service}_ip_limit", "0") or 0)
    quota_gb = int(settings.get(f"{service}_quota_gb", "0") or 0)
    username = make_username(service, protocol)
    password = make_password() if service == "ssh" else ""

    with CREATE_LOCK:
        # Recheck setelah lock untuk mencegah dua request menembus kuota terakhir.
        quota = quota_state(settings)
        q = quota["services"][service][str(days)]
        if q["limit"] <= 0 or q["remaining"] <= 0:
            raise ValueError("Kuota hari ini baru saja habis. Silakan coba lagi besok.")
        if per_ip_limit > 0 and per_ip_used(ip, service) >= per_ip_limit:
            raise ValueError("Batas pembuatan akun dari IP Anda hari ini sudah tercapai.")

        if service == "ssh":
            ok, output, log = create_ssh_account(username, password, days, ip_limit, quota_gb)
        else:
            ok, output, log = create_xray_account(protocol, username, days, ip_limit, quota_gb)

        now = int(time.time())
        token = secrets.token_urlsafe(32)
        conn = db_connect()
        try:
            conn.execute(
                "INSERT INTO accounts(token,username,service,protocol,days,ip,created_at,"
                "created_day,expires_at,status,output,error,user_agent) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    token,
                    username,
                    service,
                    protocol,
                    days,
                    ip,
                    now,
                    today_key(),
                    now + days * 86400,
                    "active" if ok else "failed",
                    output if ok else "",
                    "" if ok else output or "gagal",
                    user_agent[:300],
                ),
            )
            conn.commit()
        except Exception:
            logger.error("gagal menyimpan akun %s ke database: %s", username, traceback.format_exc())
            if ok:
                # Jangan tinggalkan akun yatim kalau database gagal ditulis.
                try:
                    if service == "ssh":
                        remove_ssh_account(username)
                    elif protocol in PROTOCOLS:
                        remove_xray_account(protocol, username)
                except Exception:
                    logger.error("gagal rollback akun %s: %s", username, traceback.format_exc())
            raise
        finally:
            conn.close()

        if not ok:
            logger.error("pembuatan akun gagal %s/%s: %s", service, username, output)
            raise ValueError("Pembuatan akun gagal di server. Silakan coba lagi atau hubungi admin.")
        audit(
            "create",
            f"{service}/{protocol or '-'} {username} {days}d ip={ip}",
            ip,
        )
        return {
            "token": token,
            "username": username,
            "service": service,
            "protocol": protocol,
            "days": days,
            "expires_at": now + days * 86400,
            "output": output,
        }


def delete_account_record(row: sqlite3.Row) -> None:
    user = row["username"]
    if not USER_RE.match(user):
        raise ValueError("Username tidak aman untuk dihapus")
    if row["service"] == "ssh":
        remove_ssh_account(user)
    elif row["service"] == "xray" and row["protocol"] in PROTOCOLS:
        remove_xray_account(row["protocol"], user)
    else:
        raise ValueError("Data akun tidak valid")
    conn = db_connect()
    try:
        conn.execute(
            "UPDATE accounts SET status='deleted', output='' WHERE id=?",
            (row["id"],),
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "vpnfree"
    sys_version = ""

    def log_message(self, fmt, *args):
        logger.info("%s - %s", self.client_ip(), fmt % args)

    def client_ip(self) -> str:
        for header in ("CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"):
            value = self.headers.get(header, "")
            if value:
                return parse_ip(value.split(",")[0].strip())
        return parse_ip(self.client_address[0])

    def is_https(self) -> bool:
        return (
            self.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower() == "https"
            or self.headers.get("X-Forwarded-Ssl", "").lower() == "on"
        )

    def cookie(self, name: str) -> str:
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == name:
                    return urllib.parse.unquote(v)
        return ""

    def set_cookie(self, name: str, value: str, max_age: int, http_only: bool = True) -> str:
        bits = [
            f"{name}={urllib.parse.quote(value)}",
            f"Max-Age={max_age}",
            "Path=/",
            "SameSite=Lax",
        ]
        if http_only:
            bits.append("HttpOnly")
        if self.is_https():
            bits.append("Secure")
        return "; ".join(bits)

    def clear_cookie(self, name: str) -> str:
        return f"{name}=; Max-Age=0; Path=/; SameSite=Lax; HttpOnly"

    def _send(
        self,
        status: int,
        body: bytes | str,
        content_type: str = "text/html; charset=utf-8",
        cookies: list[str] | None = None,
        extra_headers: dict[str, str] | None = None,
        head_only: bool = False,
    ) -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "
            "form-action 'self'; img-src 'self' data:; font-src 'self'; "
            "style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'",
        )
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def html(
        self,
        status: int,
        body: str,
        cookies: list[str] | None = None,
        extra_headers: dict[str, str] | None = None,
        head_only: bool = False,
    ) -> None:
        self._send(status, body, cookies=cookies, extra_headers=extra_headers, head_only=head_only)

    def redirect(self, location: str, cookies: list[str] | None = None, status: int = 303) -> None:
        self._send(status, b"", cookies=cookies, extra_headers={"Location": location})

    def json(self, status: int, data) -> None:
        self._send(
            status,
            json.dumps(data, ensure_ascii=False),
            content_type="application/json; charset=utf-8",
            extra_headers={"Cache-Control": "no-store"},
        )

    def parse_body(self) -> dict[str, str]:
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            return {}
        raw = self.rfile.read(length)
        ctype = self.headers.get("Content-Type", "")
        if "application/json" in ctype:
            try:
                data = json.loads(raw.decode("utf-8", "replace"))
                return {str(k): str(v) for k, v in data.items() if isinstance(v, (str, int, float))}
            except Exception:
                return {}
        parsed = urllib.parse.parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        return {k: v[0] if v else "" for k, v in parsed.items()}

    def public_form_token(self) -> tuple[str, str | None]:
        token = self.cookie(FORM_COOKIE)
        cookie = None
        if not re.fullmatch(r"[A-Za-z0-9_-]{24,80}", token or ""):
            token = secrets.token_urlsafe(24)
            cookie = self.set_cookie(FORM_COOKIE, token, FORM_TTL)
        return token, cookie

    def admin_session(self) -> sqlite3.Row | None:
        return get_session(self.cookie(ADMIN_COOKIE))

    def require_admin(self, csrf: str | None = None) -> sqlite3.Row | None:
        session = self.admin_session()
        if not session:
            self.redirect("/admin/login")
            return None
        if csrf is not None and not hmac.compare_digest(csrf, session["csrf"]):
            self.html(403, page_shell("Akses ditolak", "<main class='wrap narrow'><div class='panel'><h1>403</h1><p>Token keamanan tidak valid. Muat ulang halaman.</p></div></main>"))
            return None
        return session

    # ------------------------------------------------------------------
    # GET
    # ------------------------------------------------------------------

    def do_HEAD(self):
        self.do_GET(head_only=True)

    def do_GET(self, head_only: bool = False):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        try:
            if path == "/healthz":
                self.json(200, {"ok": True, "time": int(time.time())})
                return
            if path.startswith("/static/"):
                self.serve_static(path, head_only)
                return
            if path == "/":
                token, cookie = self.public_form_token()
                self.html(200, render_home(token, get_settings()), cookies=[cookie] if cookie else None, head_only=head_only)
                return
            if path == "/hasil" or path == "/hasil/":
                self.html(404, render_not_found(), head_only=head_only)
                return
            if path.startswith("/hasil/"):
                self.result_page(path.split("/", 2)[2], head_only)
                return
            if path == "/api/quota":
                self.json(200, quota_state())
                return
            if path == "/admin" or path == "/admin/":
                session = self.admin_session()
                if not session:
                    self.redirect("/admin/login")
                    return
                msg = (query.get("msg", [""])[0] or "")[:50]
                self.html(
                    200,
                    render_admin_dashboard(session, get_settings(), msg),
                    extra_headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"},
                    head_only=head_only,
                )
                return
            if path == "/admin/login":
                if self.admin_session():
                    self.redirect("/admin")
                    return
                token, cookie = self.public_form_token()
                self.html(
                    200,
                    render_admin_login(token, ""),
                    cookies=[cookie] if cookie else None,
                    extra_headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"},
                    head_only=head_only,
                )
                return
            if path == "/admin/logout":
                self.redirect("/admin/login")
                return
            if path == "/favicon.ico":
                self._send(204, b"")
                return
            self.html(404, render_not_found(), head_only=head_only)
        except Exception:
            logger.error("GET error: %s", traceback.format_exc())
            self.html(500, render_error("Terjadi kesalahan di server."), head_only=head_only)

    def serve_static(self, path: str, head_only: bool = False) -> None:
        rel = path[len("/static/") :]
        target = (STATIC_DIR / rel).resolve()
        try:
            target.relative_to(STATIC_DIR.resolve())
        except ValueError:
            self._send(404, b"Not found", content_type="text/plain")
            return
        if not target.is_file():
            self._send(404, b"Not found", content_type="text/plain")
            return
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if target.suffix == ".woff2":
            ctype = "font/woff2"
        data = target.read_bytes()
        self._send(
            200,
            data,
            content_type=ctype,
            extra_headers={"Cache-Control": "public, max-age=604800, immutable"},
            head_only=head_only,
        )

    def result_page(self, token: str, head_only: bool = False) -> None:
        download = bool((token or "").endswith(".txt"))
        if download:
            token = token[:-4]
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,80}", token or ""):
            self.html(404, render_not_found(), head_only=head_only)
            return
        conn = db_connect()
        try:
            row = conn.execute(
                "SELECT * FROM accounts WHERE token=? AND status='active'", (token,)
            ).fetchone()
        finally:
            conn.close()
        if not row:
            self.html(404, render_not_found(), head_only=head_only)
            return
        if download:
            body = (row["output"] or "").encode("utf-8")
            self._send(
                200,
                body,
                content_type="text/plain; charset=utf-8",
                extra_headers={
                    "Content-Disposition": f'attachment; filename="{row["username"]}.txt"',
                    "Cache-Control": "no-store",
                },
                head_only=head_only,
            )
            return
        self.html(
            200,
            render_result(row),
            extra_headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"},
            head_only=head_only,
        )

    # ------------------------------------------------------------------
    # POST
    # ------------------------------------------------------------------

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        try:
            if path == "/buat":
                self.public_create()
                return
            if path == "/admin/login":
                self.admin_login()
                return
            if path == "/admin/logout":
                session = self.admin_session()
                drop_session(self.cookie(ADMIN_COOKIE))
                audit("logout", session["username"] if session else "", self.client_ip())
                self.redirect("/admin/login", cookies=[self.clear_cookie(ADMIN_COOKIE)])
                return
            if path == "/admin/settings":
                self.admin_settings()
                return
            if path == "/admin/delete":
                self.admin_delete()
                return
            if path == "/admin/password":
                self.admin_password()
                return
            if path == "/admin/reset-quota":
                self.admin_reset_quota()
                return
            self.html(404, render_not_found())
        except ValueError as exc:
            self.html(400, render_error(str(exc)))
        except Exception:
            logger.error("POST error: %s", traceback.format_exc())
            self.html(500, render_error("Terjadi kesalahan di server."))

    def public_create(self) -> None:
        body = self.parse_body()
        token_cookie = self.cookie(FORM_COOKIE)
        if not token_cookie or not hmac.compare_digest(body.get("_form", ""), token_cookie):
            self.html(400, render_error("Sesi formulir kedaluwarsa. Muat ulang halaman lalu coba lagi."))
            return
        service = body.get("service", "")
        protocol = body.get("protocol", "")
        days_raw = body.get("days", "")
        if service not in SERVICES:
            self.html(400, render_error("Layanan tidak valid."))
            return
        if service == "xray" and protocol not in PROTOCOLS:
            self.html(400, render_error("Pilih protokol Xray terlebih dahulu."))
            return
        if service == "ssh":
            protocol = ""
        if days_raw not in ("3", "7"):
            self.html(400, render_error("Masa aktif tidak valid."))
            return
        days = int(days_raw)
        if not rate_ok("create:" + self.client_ip(), 8, 600):
            self.html(
                429,
                render_error("Terlalu banyak percobaan. Tunggu beberapa menit lalu coba lagi."),
            )
            return
        try:
            account = create_account(
                service,
                protocol,
                days,
                self.client_ip(),
                self.headers.get("User-Agent", ""),
            )
        except ValueError as exc:
            self.html(409, render_error(str(exc), retry=True))
            return
        except Exception:
            logger.error("create fatal: %s", traceback.format_exc())
            self.html(500, render_error("Pembuatan akun gagal. Silakan coba lagi atau hubungi admin.", retry=True))
            return
        self.redirect(f"/hasil/{account['token']}")

    def admin_login(self) -> None:
        body = self.parse_body()
        ip = self.client_ip()
        if not rate_ok("login:" + ip, 6, 900):
            time.sleep(0.8)
            self.html(429, render_admin_login(body.get("_form", ""), "Terlalu banyak percobaan. Tunggu 15 menit."))
            return
        token_cookie = self.cookie(FORM_COOKIE)
        if not token_cookie or not hmac.compare_digest(body.get("_form", ""), token_cookie):
            self.html(400, render_admin_login("", "Sesi formulir kedaluwarsa. Muat ulang halaman."))
            return
        username = body.get("username", "").strip()[:64]
        password = body.get("password", "")[:200]
        conn = db_connect()
        try:
            row = conn.execute("SELECT * FROM admin WHERE username=?", (username,)).fetchone()
        finally:
            conn.close()
        if not row or not verify_password(password, row["password_hash"]):
            time.sleep(0.6)
            audit("login_failed", username, ip)
            self.html(401, render_admin_login(token_cookie, "Username atau password salah."))
            return
        session_token, _csrf = create_session(username, ip)
        audit("login", username, ip)
        self.redirect(
            "/admin",
            cookies=[self.set_cookie(ADMIN_COOKIE, session_token, SESSION_TTL, http_only=True)],
        )

    def admin_settings(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        values = {}
        for key, (low, high) in INT_SETTINGS.items():
            raw = body.get(key, "0").strip()
            try:
                num = int(raw)
            except ValueError:
                num = 0
            values[key] = str(max(low, min(high, num)))
        values["ssh_enabled"] = "1" if body.get("ssh_enabled") == "1" else "0"
        values["xray_enabled"] = "1" if body.get("xray_enabled") == "1" else "0"
        for proto in PROTOCOLS:
            values[f"{proto}_enabled"] = "1" if body.get(f"{proto}_enabled") == "1" else "0"
        values["maintenance"] = "1" if body.get("maintenance") == "1" else "0"
        set_settings(values)
        audit("settings", json.dumps(values, sort_keys=True), self.client_ip())
        self.redirect("/admin?msg=settings")

    def admin_delete(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        account_id = body.get("id", "")
        conn = db_connect()
        try:
            row = conn.execute("SELECT * FROM accounts WHERE id=? AND status='active'", (account_id,)).fetchone()
        finally:
            conn.close()
        if not row:
            self.redirect("/admin?msg=notfound")
            return
        try:
            delete_account_record(row)
            audit("delete", f"{row['service']}/{row['protocol'] or '-'} {row['username']}", self.client_ip())
            self.redirect("/admin?msg=deleted")
        except ValueError as exc:
            self.redirect("/admin?msg=deletefail")

    def admin_password(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        current = body.get("current", "")
        new = body.get("new", "")
        confirm = body.get("confirm", "")
        if len(new) < 10:
            self.redirect("/admin?msg=passwordshort")
            return
        if new != confirm:
            self.redirect("/admin?msg=passwordmismatch")
            return
        conn = db_connect()
        try:
            row = conn.execute("SELECT * FROM admin WHERE username=?", (session["username"],)).fetchone()
            if not row or not verify_password(current, row["password_hash"]):
                self.redirect("/admin?msg=passwordwrong")
                return
            conn.execute(
                "UPDATE admin SET password_hash=?, updated_at=? WHERE username=?",
                (hash_password(new), int(time.time()), session["username"]),
            )
            conn.execute("DELETE FROM sessions WHERE username=?", (session["username"],))
            conn.commit()
        finally:
            conn.close()
        try:
            ADMIN_CRED_PATH.write_text(
                "VPNFree admin\n"
                f"URL      : https://{PUBLIC_HOST}/admin\n"
                f"Username : {session['username']}\n"
                "Password : (sudah diganti lewat dashboard)\n",
                encoding="utf-8",
            )
            os.chmod(ADMIN_CRED_PATH, 0o600)
        except Exception:
            pass
        audit("password_change", session["username"], self.client_ip())
        self.redirect("/admin/login", cookies=[self.clear_cookie(ADMIN_COOKIE)])

    def admin_reset_quota(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        # Reset hitungan hari ini tanpa menghapus akun: tandai record hari ini
        # sebagai diarsipkan dari hitungan kuota.
        conn = db_connect()
        try:
            conn.execute(
                "UPDATE accounts SET created_day=? WHERE created_day=? AND status='active'",
                (today_key() + "-reset-" + str(int(time.time()))[:6], today_key()),
            )
            conn.commit()
        finally:
            conn.close()
        audit("reset_quota", today_key(), self.client_ip())
        self.redirect("/admin?msg=quota")


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def rate_ok(key: str, limit: int, window: int) -> bool:
    now = time.time()
    with RATE_LOCK:
        bucket = RATE_BUCKETS.setdefault(key, collections.deque())
        while bucket and now - bucket[0] > window:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def favicon_svg() -> str:
    return ""


def page_shell(title: str, body: str, admin: bool = False, noindex: bool = False) -> str:
    nav_extra = ""
    if not admin:
        nav_extra = (
            '<a href="/#buat">Buat akun</a>'
            '<a href="/#cara">Cara pakai</a>'
            '<a href="/#faq">FAQ</a>'
        )
    else:
        nav_extra = '<a href="/admin">Dashboard</a><a href="/" target="_blank" rel="noopener">Lihat situs</a>'
    robots = '<meta name="robots" content="noindex,nofollow">' if noindex else ""
    return f"""<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)} — VPNFree</title>
<meta name="description" content="Buat akun VPN gratis SSH dan Xray dalam hitungan detik. Tanpa email, tanpa login.">
<meta name="theme-color" content="#fffaf2">
{robots}
<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<div class="grain" aria-hidden="true"></div>
<header class="nav">
  <div class="wrap nav-inner">
    <a class="brand" href="/" aria-label="VPNFree">
      <span class="brand-mark">{logomark()}</span>
      <span class="brand-word">vpn<span>free</span></span>
    </a>
    <nav class="nav-links">{nav_extra}</nav>
    <a class="nav-cta" href="/#buat">Buat akun <span aria-hidden="true">↗</span></a>
  </div>
</header>
{body}
<footer class="footer">
  <div class="wrap footer-inner">
    <div>
      <div class="brand footer-brand"><span class="brand-mark">{logomark()}</span><span class="brand-word">vpn<span>free</span></span></div>
      <p>Akun gratis untuk belajar, bekerja, dan menjelajah dengan aman.</p>
    </div>
    <div class="footer-links">
      <a href="/#buat">Buat akun</a>
      <a href="/#cara">Cara pakai</a>
      <a href="/#faq">FAQ</a>
      <a href="/admin">Admin</a>
    </div>
    <div class="footer-note">Dibuat untuk komunitas. Gunakan dengan bijak.</div>
  </div>
</footer>
<script src="/static/app.js" defer></script>
</body>
</html>"""


def logomark() -> str:
    return """<svg viewBox="0 0 40 40" role="img" aria-hidden="true"><path d="M20 3.5 34 9v9.4c0 8.9-5.7 15.1-14 18.1C11.7 33.5 6 27.3 6 18.4V9l14-5.5Z" fill="currentColor"/><path d="M20 9.5v18.8c5-2.5 8-6.8 8-12.2v-4.7L20 9.5Z" fill="#fffaf2" opacity=".92"/><path d="m14 19.2 4.1 4.2 8-8.2" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/></svg>"""


def icon(name: str) -> str:
    icons = {
        "terminal": '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m5 7 4 4-4 4M12 16h7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        "bolt": '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M13 2 4.5 13.5H11l-1 8.5 8.5-11.5H12l1-8.5Z" fill="currentColor"/></svg>',
        "globe": '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M3.5 12h17M12 3c2.7 2.6 4.1 5.6 4.1 9S14.7 18.4 12 21c-2.7-2.6-4.1-5.6-4.1-9S9.3 5.6 12 3Z" fill="none" stroke="currentColor" stroke-width="1.7"/></svg>',
        "clock": '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 7v5l3.5 2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
        "shield": '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2.5 20 6v6.2c0 5.1-3.3 8.7-8 10.3-4.7-1.6-8-5.2-8-10.3V6l8-3.5Z" fill="none" stroke="currentColor" stroke-width="2"/><path d="m8.5 12 2.3 2.3 4.7-4.8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        "download": '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12m0 0 4-4m-4 4-4-4M5 20h14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        "copy": '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="8" y="8" width="11" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h2" fill="none" stroke="currentColor" stroke-width="2"/></svg>',
    }
    return icons.get(name, "")


def render_home(form_token: str, settings: dict[str, str]) -> str:
    quota = quota_state(settings)
    quota_json = json.dumps(quota, ensure_ascii=False).replace("</", "<\\/")
    ssh3 = quota["services"]["ssh"]["3"]
    xr3 = quota["services"]["xray"]["3"]
    maintenance = settings.get("maintenance") == "1"
    ssh_on = settings.get("ssh_enabled", "1") == "1"
    proto_on = {p: settings.get(f"{p}_enabled", "1") == "1" for p in PROTOCOLS}
    xray_on = settings.get("xray_enabled", "1") == "1" and any(proto_on.values())
    available = ssh_on or xray_on
    default_service = "ssh" if ssh_on else ("xray" if xray_on else "")
    first_proto = next((p for p in ("vmess", "vless", "trojan") if proto_on[p]), "")
    maintenance_html = (
        '<div class="notice notice-warn"><strong>Mode perawatan.</strong> Pembuatan akun sementara ditutup.</div>'
        if maintenance
        else ""
    )
    closed_html = ""
    if not available:
        closed_html = '<div class="notice notice-error"><strong>Semua layanan ditutup.</strong> Admin sedang menutup pembuatan akun.</div>'
    proto_html = ""
    for proto, meta in PROTOCOLS.items():
        off = not proto_on[proto]
        checked = "checked" if (default_service == "xray" and first_proto == proto and not off) else ""
        disabled = "disabled" if off else ""
        proto_html += (
            f'<label class="protocol-pill{" is-off" if off else ""}" data-protocol-card="{proto}">'
            f'<input type="radio" name="protocol" value="{proto}" {checked} {disabled}>'
            f'<span>{e(meta["label"])}{" <small>OFF</small>" if off else ""}</span></label>'
        )
    web_config = {
        "ssh": ssh_on,
        "xray": xray_on,
        "protocols": proto_on,
        "maintenance": maintenance,
    }
    web_config_json = json.dumps(web_config, ensure_ascii=False).replace("</", "<\\/")
    body = f"""
<main>
  <section class="hero wrap">
    <div class="hero-copy">
      <div class="eyebrow"><span class="dot"></span> GRATIS · TANPA EMAIL · LANGSUNG JADI</div>
      <h1>Internet bebas,<br><em>akun langsung jadi.</em></h1>
      <p class="hero-lead">Pilih layanan, tentukan masa aktif, lalu salin konfigurasi. Semua diproses langsung di server VPN — tanpa antre, tanpa akun tambahan.</p>
      <div class="hero-actions">
        <a class="btn btn-primary" href="#buat">Buat akun sekarang <span aria-hidden="true">↘</span></a>
        <a class="btn btn-ghost" href="#cara">Lihat cara pakai</a>
      </div>
      <div class="hero-stats">
        <div><strong>{ssh3['limit'] + quota['services']['ssh']['7']['limit'] + xr3['limit'] + quota['services']['xray']['7']['limit']}</strong><span>slot kuota / hari</span></div>
        <div><strong>3–7</strong><span>hari masa aktif</span></div>
        <div><strong>00.00</strong><span>reset otomatis WIB</span></div>
      </div>
    </div>
    <div class="hero-art" aria-hidden="true">
      <div class="orbit orbit-a"></div>
      <div class="orbit orbit-b"></div>
      <div class="ticket">
        <div class="ticket-top">
          <div class="ticket-logo">{logomark()}</div>
          <div class="ticket-brand">VPN<span>FREE</span></div>
          <div class="ticket-chip">GRATIS</div>
        </div>
        <div class="ticket-tunnel">
          <span class="tunnel t1"></span><span class="tunnel t2"></span><span class="tunnel t3"></span>
          <span class="tunnel-core">{icon('bolt')}</span>
        </div>
        <div class="ticket-rows">
          <div><span>LAYANAN</span><b>SSH / XRAY</b></div>
          <div><span>MASA AKTIF</span><b>3 — 7 HARI</b></div>
          <div><span>KUOTA</span><b>TERBATAS / HARI</b></div>
        </div>
        <div class="ticket-barcode"></div>
      </div>
      <div class="float-pill pill-a"><span class="pill-dot"></span> server online</div>
      <div class="float-pill pill-b">{icon('shield')} tanpa log</div>
    </div>
  </section>

  <section class="marquee" aria-hidden="true">
    <div class="marquee-track">
      <span>SSH WS</span><i>✦</i><span>VMESS</span><i>✦</i><span>VLESS</span><i>✦</i><span>TROJAN</span><i>✦</i><span>SSL / TLS</span><i>✦</i><span>DROPBEAR</span><i>✦</i>
      <span>SSH WS</span><i>✦</i><span>VMESS</span><i>✦</i><span>VLESS</span><i>✦</i><span>TROJAN</span><i>✦</i><span>SSL / TLS</span><i>✦</i><span>DROPBEAR</span><i>✦</i>
    </div>
  </section>

  <section class="section wrap" id="buat">
    <div class="section-head">
      <div>
        <div class="eyebrow"><span class="dot"></span> BUAT AKUN</div>
        <h2>Dua langkah, akun siap.</h2>
      </div>
      <p>Kuota dihitung per layanan dan di-reset otomatis setiap tengah malam WIB.</p>
    </div>
    {maintenance_html}
    {closed_html}
    <form class="creator panel" method="post" action="/buat" id="create-form" novalidate>
      <input type="hidden" name="_form" value="{e(form_token)}">
      <div class="creator-grid">
        <fieldset class="field-group">
          <legend><span>01</span> Pilih layanan</legend>
          <div class="service-grid">
            <label class="service-card {'selected' if default_service == 'ssh' else ''}{' is-off' if not ssh_on else ''}" data-service-card="ssh" data-enabled="{1 if ssh_on else 0}">
              <input type="radio" name="service" value="ssh" {'checked' if default_service == 'ssh' else ''} {'disabled' if not ssh_on else ''}>
              <span class="service-icon">{icon('terminal')}</span>
              <span class="service-copy"><b>SSH</b><small>{'OpenSSH · Dropbear · WS · SSL' if ssh_on else 'Dinonaktifkan admin'}</small></span>
              <span class="checkmark" aria-hidden="true">✓</span>
            </label>
            <label class="service-card {'selected' if default_service == 'xray' else ''}{' is-off' if not xray_on else ''}" data-service-card="xray" data-enabled="{1 if xray_on else 0}">
              <input type="radio" name="service" value="xray" {'checked' if default_service == 'xray' else ''} {'disabled' if not xray_on else ''}>
              <span class="service-icon">{icon('bolt')}</span>
              <span class="service-copy"><b>Xray</b><small>{'Pilih VMess, VLESS, atau Trojan' if xray_on else 'Dinonaktifkan admin'}</small></span>
              <span class="checkmark" aria-hidden="true">✓</span>
            </label>
          </div>
          <div class="protocol-wrap" id="protocol-wrap" {'' if default_service == 'xray' else 'hidden'}>
            <span class="mini-label">Protokol Xray</span>
            <div class="protocol-grid">
              {proto_html}
            </div>
          </div>
        </fieldset>

        <fieldset class="field-group">
          <legend><span>02</span> Pilih masa aktif</legend>
          <div class="duration-grid">
            <label class="duration-card selected" data-duration-card="3">
              <input type="radio" name="days" value="3" checked>
              <span class="duration-badge">PALING POPULER</span>
              <b>3 hari</b>
              <small>Pas untuk uji coba dan perjalanan singkat.</small>
              <span class="duration-quota" data-quota-label="3">—</span>
            </label>
            <label class="duration-card" data-duration-card="7">
              <input type="radio" name="days" value="7">
              <span class="duration-badge subtle">LEBIH LAMA</span>
              <b>7 hari</b>
              <small>Masa aktif lebih panjang, kuota lebih terbatas.</small>
              <span class="duration-quota" data-quota-label="7">—</span>
            </label>
          </div>
        </fieldset>
      </div>

      <div class="creator-bottom">
        <div class="quota-readout" id="quota-readout" aria-live="polite">
          <div class="quota-ring" id="quota-ring"><span id="quota-remaining">—</span></div>
          <div>
            <strong id="quota-title">Memuat kuota…</strong>
            <p id="quota-sub">Kuota global per layanan.</p>
          </div>
        </div>
        <div class="reset-box"><span class="reset-label">RESET DALAM</span><b id="reset-countdown">--:--:--</b><small>WIB</small></div>
        <button class="btn btn-primary btn-create" type="submit" id="create-button" {'disabled' if maintenance or not available else ''}>Buat akun <span aria-hidden="true">↗</span></button>
      </div>
      <p class="form-note">Dengan membuat akun, Anda setuju menggunakan layanan secara wajar. Satu IP dibatasi <b>{e(settings.get('per_ip_daily', '2'))} akun</b> per layanan per hari.</p>
    </form>
    <div class="quota-strip">
      <div class="quota-item"><span>SSH · 3 hari</span><b data-quota-chip="ssh-3">—</b><i><u data-quota-fill="ssh-3"></u></i></div>
      <div class="quota-item"><span>SSH · 7 hari</span><b data-quota-chip="ssh-7">—</b><i><u data-quota-fill="ssh-7"></u></i></div>
      <div class="quota-item"><span>Xray · 3 hari</span><b data-quota-chip="xray-3">—</b><i><u data-quota-fill="xray-3"></u></i></div>
      <div class="quota-item"><span>Xray · 7 hari</span><b data-quota-chip="xray-7">—</b><i><u data-quota-fill="xray-7"></u></i></div>
    </div>
  </section>

  <section class="section wrap features">
    <div class="feature-big panel">
      <div class="eyebrow"><span class="dot"></span> KENAPA VPNFREE</div>
      <h2>Dibuat simpel.<br>Dijalankan serius.</h2>
      <p>Kami tidak menyimpan email, tidak meminta nomor telepon, dan tidak memasang iklan. Akun dibuat langsung di server untuk Anda.</p>
      <div class="feature-list">
        <div>{icon('clock')}<span><b>Otomatis & cepat</b><small>Akun selesai dalam hitungan detik.</small></span></div>
        <div>{icon('shield')}<span><b>Kuota adil</b><small>Batas harian menjaga layanan tetap ringan.</small></span></div>
        <div>{icon('globe')}<span><b>Format asli panel</b><small>Payload, port, dan tautan sama seperti menu VPS.</small></span></div>
      </div>
    </div>
    <div class="feature-side">
      <div class="mini-card"><span class="mini-icon">{icon('bolt')}</span><h3>SSH & Xray</h3><p>Dua keluarga protokol populer dalam satu tempat.</p></div>
      <div class="mini-card accent"><span class="mini-icon">{icon('clock')}</span><h3>Reset 00.00</h3><p>Kuota baru tersedia otomatis setiap tengah malam WIB.</p></div>
    </div>
  </section>

  <section class="section wrap steps" id="cara">
    <div class="section-head"><div><div class="eyebrow"><span class="dot"></span> CARA PAKAI</div><h2>Tiga menit, langsung terhubung.</h2></div></div>
    <div class="step-grid">
      <article><span class="step-num">01</span><h3>Pilih layanan</h3><p>Tentukan SSH atau Xray, lalu pilih protokol dan masa aktif.</p></article>
      <article><span class="step-num">02</span><h3>Buat & simpan</h3><p>Salin output akun atau unduh sebagai file teks. Simpan baik-baik.</p></article>
      <article><span class="step-num">03</span><h3>Impor ke aplikasi</h3><p>Masukkan host, port, dan kredensial ke aplikasi tunnel pilihan Anda.</p></article>
    </div>
    <div class="format-note panel"><div class="format-icon">{icon('terminal')}</div><div><b>Output persis seperti menu VPS</b><p>Semua baris, port, payload, dan tautan akun diambil langsung dari file hasil script panel — bukan template buatan website.</p></div></div>
  </section>

  <section class="section wrap faq" id="faq">
    <div class="section-head"><div><div class="eyebrow"><span class="dot"></span> FAQ</div><h2>Pertanyaan yang sering muncul.</h2></div></div>
    <div class="faq-list">
      <details><summary>Apakah akun ini benar-benar gratis?</summary><p>Ya. Tidak ada pembayaran, email, atau pendaftaran. Kuota harian dibatasi agar layanan tetap tersedia untuk semua orang.</p></details>
      <details><summary>Kenapa kuota saya habis padahal baru tengah hari?</summary><p>Kuota bersifat global per layanan. Jika slot hari ini habis, kuota akan di-reset otomatis pukul 00.00 WIB.</p></details>
      <details><summary>Apakah akun bisa dipakai di beberapa perangkat?</summary><p>Bisa, selama jumlah IP yang login tidak melebihi batas yang ditetapkan admin. Pelanggaran limit IP dapat menyebabkan akun dibekukan sementara oleh Timer Mullog.</p></details>
      <details><summary>Bagaimana kalau saya kehilangan output akun?</summary><p>Simpan tautan hasil atau unduh file teks sebelum menutup halaman. Halaman hasil memakai tautan privat yang tidak dapat ditebak.</p></details>
      <details><summary>Apakah akun lama di VPS akan terganggu?</summary><p>Tidak. Website hanya membuat akun baru dan tidak mengubah akun yang sudah ada.</p></details>
    </div>
  </section>
</main>
<script type="application/json" id="quota-data">{quota_json}</script>
<script type="application/json" id="web-config">{web_config_json}</script>
"""
    return page_shell("Akun VPN Gratis SSH & Xray", body)


def render_result(row: sqlite3.Row) -> str:
    service = SERVICES.get(row["service"], {"label": row["service"]})
    protocol = PROTOCOLS.get(row["protocol"], {}).get("label", "")
    label = service["label"] + (f" · {protocol}" if protocol else "")
    output = e(row["output"])
    expires = fmt_ts(row["expires_at"], "%d %b %Y · %H:%M WIB")
    body = f"""
<main class="result-main wrap">
  <div class="result-head">
    <div class="success-mark" aria-hidden="true">✓</div>
    <div class="eyebrow"><span class="dot"></span> AKUN BERHASIL DIBUAT</div>
    <h1>Sudah jadi. <em>Simpan sekarang.</em></h1>
    <p>Akun <b>{e(row['username'])}</b> aktif untuk <b>{label}</b> selama <b>{row['days']} hari</b>, sampai {e(expires)}.</p>
  </div>
  <div class="result-grid">
    <section class="output-card panel">
      <div class="output-head">
        <div><span class="mini-label">OUTPUT AKUN</span><b>{e(row['username'])}</b></div>
        <div class="output-actions">
          <button class="btn btn-small btn-ghost" type="button" id="copy-output">{icon('copy')} Salin</button>
          <a class="btn btn-small btn-dark" href="/hasil/{e(row['token'])}.txt" download>{icon('download')} Unduh .txt</a>
        </div>
      </div>
      <pre class="account-output" id="account-output">{output}</pre>
      <div class="copy-status" id="copy-status" role="status"></div>
    </section>
    <aside class="result-side">
      <div class="panel save-card">
        <div class="save-icon">{icon('shield')}</div>
        <h3>Jangan tutup dulu.</h3>
        <p>Simpan tautan halaman ini atau unduh file teks. Demi keamanan, halaman hasil memakai tautan privat.</p>
        <div class="save-link"><span>TAUTAN HASIL</span><code id="result-url">/hasil/{e(row['token'])}</code></div>
        <button class="btn btn-primary btn-block" type="button" id="copy-link">Salin tautan hasil</button>
      </div>
      <div class="panel tips-card">
        <span class="mini-label">CATATAN</span>
        <ul>
          <li>Gunakan host dan port yang tertulis di output.</li>
          <li>Jangan bagikan akun ke lebih banyak IP dari batas.</li>
          <li>Akun berakhir otomatis pada {e(expires)}.</li>
        </ul>
      </div>
      <a class="btn btn-ghost btn-block" href="/">Buat akun lain</a>
    </aside>
  </div>
</main>
"""
    return page_shell("Akun berhasil dibuat", body, noindex=True)


def render_admin_login(form_token: str, error: str) -> str:
    err = f'<div class="notice notice-error">{e(error)}</div>' if error else ""
    body = f"""
<main class="admin-login wrap">
  <div class="login-card panel">
    <div class="login-brand"><span class="brand-mark">{logomark()}</span><span class="brand-word">vpn<span>free</span></span></div>
    <div class="eyebrow"><span class="dot"></span> ADMIN PANEL</div>
    <h1>Masuk untuk mengatur.</h1>
    <p>Kelola limit IP, kuota bandwidth, dan jatah akun harian.</p>
    {err}
    <form method="post" action="/admin/login" class="stack-form">
      <input type="hidden" name="_form" value="{e(form_token)}">
      <label>Username<input type="text" name="username" autocomplete="username" required autofocus></label>
      <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
      <button class="btn btn-primary btn-block" type="submit">Masuk</button>
    </form>
    <a class="back-link" href="/">← Kembali ke situs</a>
  </div>
</main>
"""
    return page_shell("Admin", body, admin=True, noindex=True)


def render_admin_dashboard(session: sqlite3.Row, settings: dict[str, str], msg: str) -> str:
    quota = quota_state(settings)
    conn = db_connect()
    try:
        total = conn.execute("SELECT COUNT(*) n FROM accounts WHERE status='active'").fetchone()["n"]
        today = conn.execute(
            "SELECT COUNT(*) n FROM accounts WHERE status='active' AND created_day=?",
            (today_key(),),
        ).fetchone()["n"]
        accounts = conn.execute(
            "SELECT * FROM accounts WHERE status='active' ORDER BY id DESC LIMIT 80"
        ).fetchall()
        recent_audit = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 10").fetchall()
    finally:
        conn.close()

    messages = {
        "settings": ("ok", "Pengaturan disimpan."),
        "deleted": ("ok", "Akun website berhasil dihapus."),
        "notfound": ("error", "Akun tidak ditemukan atau sudah dihapus."),
        "deletefail": ("error", "Akun gagal dihapus. Cek log server."),
        "passwordshort": ("error", "Password baru minimal 10 karakter."),
        "passwordmismatch": ("error", "Konfirmasi password tidak sama."),
        "passwordwrong": ("error", "Password saat ini salah."),
        "quota": ("ok", "Hitungan kuota hari ini di-reset (akun tidak dihapus)."),
    }
    notice = ""
    if msg in messages:
        kind, text = messages[msg]
        notice = f'<div class="notice notice-{kind}">{e(text)}</div>'

    quota_rows = ""
    for service in ("ssh", "xray"):
        for days in (3, 7):
            q = quota["services"][service][str(days)]
            pct = (q["used"] / q["limit"] * 100) if q["limit"] else 0
            quota_rows += (
                f'<div class="quota-item"><span>{e(SERVICES[service]["label"])} · {days} hari</span>'
                f'<b>{q["used"]} / {q["limit"]}</b><i><u style="width:{min(100, pct):.1f}%"></u></i></div>'
            )

    account_rows = ""
    for row in accounts:
        proto = PROTOCOLS.get(row["protocol"], {}).get("label", row["protocol"])
        label = SERVICES.get(row["service"], {}).get("label", row["service"]) + (f" · {proto}" if proto else "")
        status = "Aktif" if row["expires_at"] > time.time() else "Kedaluwarsa"
        account_rows += f"""
        <tr>
          <td><b>{e(row['username'])}</b><small>{e(label)} · {row['days']} hari</small></td>
          <td>{e(mask_ip(row['ip']))}</td>
          <td>{e(fmt_ts(row['created_at'], '%d %b %H:%M'))}</td>
          <td>{e(fmt_ts(row['expires_at'], '%d %b %Y'))}</td>
          <td><span class="badge {'badge-ok' if status == 'Aktif' else 'badge-muted'}">{status}</span></td>
          <td>
            <form method="post" action="/admin/delete" class="inline-form" data-confirm="Hapus akun {e(row['username'])}? Akun akan dihapus dari VPS. Tindakan ini tidak bisa dibatalkan.">
              <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
              <input type="hidden" name="id" value="{row['id']}">
              <button class="btn btn-tiny btn-danger" type="submit">Hapus</button>
            </form>
          </td>
        </tr>"""
    if not account_rows:
        account_rows = '<tr><td colspan="6" class="empty">Belum ada akun yang dibuat lewat website.</td></tr>'

    audit_rows = "".join(
        f"<li><span>{e(fmt_ts(a['at'], '%d %b %H:%M'))}</span><b>{e(a['action'])}</b><small>{e(a['detail'])}</small></li>"
        for a in recent_audit
    ) or "<li class='empty'>Belum ada aktivitas.</li>"

    body = f"""
<main class="admin-main wrap">
  <div class="admin-head">
    <div><div class="eyebrow"><span class="dot"></span> ADMIN DASHBOARD</div><h1>Kendali penuh.</h1><p>Semua perubahan langsung dipakai untuk pembuatan akun berikutnya.</p></div>
    <div class="admin-head-actions">
      <form method="post" action="/admin/logout"><button class="btn btn-ghost" type="submit">Keluar</button></form>
    </div>
  </div>
  {notice}
  <div class="admin-stats">
    <div class="stat-card"><span>Total akun website</span><strong>{total}</strong><small>akun aktif</small></div>
    <div class="stat-card accent"><span>Dibuat hari ini</span><strong>{today}</strong><small>{e(today_key())}</small></div>
    <div class="stat-card"><span>Reset kuota</span><strong>00.00</strong><small>otomatis WIB</small></div>
  </div>

  <div class="admin-grid">
    <section class="panel admin-panel">
      <div class="panel-head"><div><span class="mini-label">PENGATURAN</span><h2>Limit & kuota akun</h2></div></div>
      <form method="post" action="/admin/settings" class="settings-form">
        <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
        <div class="settings-grid">
          <fieldset>
            <legend>{icon('terminal')} SSH</legend>
            <label>Limit IP per akun<input type="number" name="ssh_ip_limit" min="0" max="100" value="{e(settings['ssh_ip_limit'])}"><small>0 = tanpa batas</small></label>
            <label>Kuota bandwidth (GB)<input type="number" name="ssh_quota_gb" min="0" max="10000" value="{e(settings['ssh_quota_gb'])}"><small>0 = tanpa batas</small></label>
            <label>Kuota 3 hari / hari<input type="number" name="ssh_daily_3" min="0" max="1000" value="{e(settings['ssh_daily_3'])}"></label>
            <label>Kuota 7 hari / hari<input type="number" name="ssh_daily_7" min="0" max="1000" value="{e(settings['ssh_daily_7'])}"></label>
            <label class="switch"><input type="checkbox" name="ssh_enabled" value="1" {'checked' if settings['ssh_enabled'] == '1' else ''}><span>Aktifkan layanan SSH</span></label>
          </fieldset>
          <fieldset>
            <legend>{icon('bolt')} Xray</legend>
            <label>Limit IP per akun<input type="number" name="xray_ip_limit" min="0" max="100" value="{e(settings['xray_ip_limit'])}"><small>0 = tanpa batas</small></label>
            <label>Kuota bandwidth (GB)<input type="number" name="xray_quota_gb" min="0" max="10000" value="{e(settings['xray_quota_gb'])}"><small>0 = tanpa batas</small></label>
            <label>Kuota 3 hari / hari<input type="number" name="xray_daily_3" min="0" max="1000" value="{e(settings['xray_daily_3'])}"></label>
            <label>Kuota 7 hari / hari<input type="number" name="xray_daily_7" min="0" max="1000" value="{e(settings['xray_daily_7'])}"></label>
            <label class="switch"><input type="checkbox" name="xray_enabled" value="1" {'checked' if settings['xray_enabled'] == '1' else ''}><span>Aktifkan layanan Xray</span></label>
            <div class="protocol-switches">
              <span class="mini-label">Protokol yang dibuka</span>
              <label class="switch"><input type="checkbox" name="vmess_enabled" value="1" {'checked' if settings['vmess_enabled'] == '1' else ''}><span>VMess</span></label>
              <label class="switch"><input type="checkbox" name="vless_enabled" value="1" {'checked' if settings['vless_enabled'] == '1' else ''}><span>VLESS</span></label>
              <label class="switch"><input type="checkbox" name="trojan_enabled" value="1" {'checked' if settings['trojan_enabled'] == '1' else ''}><span>Trojan</span></label>
            </div>
          </fieldset>
        </div>
        <div class="settings-grid two">
          <label>Batas akun per IP / layanan / hari<input type="number" name="per_ip_daily" min="0" max="1000" value="{e(settings['per_ip_daily'])}"><small>0 = tanpa batas per IP</small></label>
        </div>
        <label class="switch maintenance"><input type="checkbox" name="maintenance" value="1" {'checked' if settings['maintenance'] == '1' else ''}><span>Mode perawatan (tutup pembuatan akun)</span></label>
        <div class="form-actions"><button class="btn btn-primary" type="submit">Simpan pengaturan</button></div>
      </form>
    </section>

    <aside class="admin-side">
      <section class="panel admin-panel">
        <div class="panel-head"><div><span class="mini-label">HARI INI</span><h2>Pemakaian kuota</h2></div></div>
        <div class="quota-strip vertical">{quota_rows}</div>
        <form method="post" action="/admin/reset-quota" class="inline-form" data-confirm="Reset hitungan kuota hari ini? Akun tidak dihapus, hanya hitungannya dikosongkan.">
          <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
          <button class="btn btn-small btn-ghost" type="submit">Reset hitungan hari ini</button>
        </form>
      </section>
      <section class="panel admin-panel">
        <div class="panel-head"><div><span class="mini-label">KEAMANAN</span><h2>Ganti password</h2></div></div>
        <form method="post" action="/admin/password" class="stack-form compact">
          <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
          <label>Password saat ini<input type="password" name="current" autocomplete="current-password" required></label>
          <label>Password baru<input type="password" name="new" autocomplete="new-password" minlength="10" required></label>
          <label>Ulangi password baru<input type="password" name="confirm" autocomplete="new-password" minlength="10" required></label>
          <button class="btn btn-dark btn-block" type="submit">Perbarui password</button>
        </form>
      </section>
    </aside>
  </div>

  <section class="panel admin-panel accounts-panel">
    <div class="panel-head"><div><span class="mini-label">AKUN WEBSITE</span><h2>80 akun terbaru</h2></div><span class="panel-hint">Hanya akun buatan website yang bisa dihapus di sini.</span></div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Akun</th><th>IP</th><th>Dibuat</th><th>Berakhir</th><th>Status</th><th></th></tr></thead>
        <tbody>{account_rows}</tbody>
      </table>
    </div>
  </section>

  <section class="panel admin-panel">
    <div class="panel-head"><div><span class="mini-label">AUDIT</span><h2>Aktivitas terakhir</h2></div></div>
    <ul class="audit-list">{audit_rows}</ul>
  </section>
</main>
"""
    return page_shell("Admin Dashboard", body, admin=True, noindex=True)


def render_error(message: str, retry: bool = False) -> str:
    button = '<a class="btn btn-primary" href="/">Coba lagi</a>' if retry else '<a class="btn btn-primary" href="/">Kembali</a>'
    body = f"""
<main class="error-main wrap">
  <div class="error-card panel">
    <div class="error-code">!</div>
    <div class="eyebrow"><span class="dot"></span> TIDAK BISA DIPROSES</div>
    <h1>{e(message)}</h1>
    <p>Jika masalah berlanjut, hubungi admin dan sertakan waktu kejadian.</p>
    {button}
  </div>
</main>
"""
    return page_shell("Terjadi kesalahan", body, noindex=True)


def render_not_found() -> str:
    body = """
<main class="error-main wrap">
  <div class="error-card panel">
    <div class="error-code">404</div>
    <div class="eyebrow"><span class="dot"></span> HALAMAN TIDAK DITEMUKAN</div>
    <h1>Tautan ini tidak ada.</h1>
    <p>Mungkin sudah kedaluwarsa atau salah ketik. Silakan kembali ke halaman utama.</p>
    <a class="btn btn-primary" href="/">Kembali</a>
  </div>
</main>"""
    return page_shell("Tidak ditemukan", body, noindex=True)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--init-only", action="store_true")
    args = parser.parse_args()

    # File database/log hanya boleh dibaca root.
    os.umask(0o077)
    init_db()
    if args.init_only:
        print(f"database siap: {DB_PATH}")
        if ADMIN_CRED_PATH.exists():
            print(ADMIN_CRED_PATH.read_text(encoding="utf-8"))
        return 0

    if not Path(SSH_SCRIPT).exists():
        logger.warning("script %s tidak ditemukan", SSH_SCRIPT)
    for cfg in PROTOCOLS.values():
        if not Path(cfg["script"]).exists():
            logger.warning("script %s tidak ditemukan", cfg["script"])

    httpd = Server((args.host, args.port), Handler)
    logger.info("VPNFree listening on %s:%s", args.host, args.port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
