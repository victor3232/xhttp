#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HITS SSH - website pembuatan akun SSH & Xray untuk VPS KYT.

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
import io
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
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
BRANDING_DIR = DATA_DIR / "branding"
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
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def turnstile_config() -> tuple[str, str, bool]:
    conf = read_web_conf()
    site = (conf.get("TURNSTILE_SITE_KEY") or "").strip()
    secret = (conf.get("TURNSTILE_SECRET_KEY") or "").strip()
    enabled = (conf.get("TURNSTILE_ENABLED") or "0").strip() == "1" and bool(site) and bool(secret)
    return site, secret, enabled


def verify_turnstile(token: str, ip: str) -> tuple[bool, str]:
    _site, secret, enabled = turnstile_config()
    if not enabled:
        return True, ""
    token = (token or "").strip()
    if not token:
        return False, "Selesaikan verifikasi keamanan Turnstile terlebih dahulu."
    payload = urllib.parse.urlencode(
        {"secret": secret, "response": token, "remoteip": ip}
    ).encode("utf-8")
    try:
        req = urllib.request.Request(TURNSTILE_VERIFY_URL, data=payload, method="POST")
        with urllib.request.urlopen(req, timeout=12) as resp:
            result = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as exc:
        logger.warning("turnstile verify error: %s", exc)
        return False, "Verifikasi keamanan sedang tidak tersedia. Coba lagi beberapa saat."
    if result.get("success") is True:
        return True, ""
    logger.warning("turnstile rejected: %s", result.get("error-codes") or [])
    return False, "Verifikasi keamanan tidak valid. Muat ulang halaman lalu coba lagi."
BRAND = "HITS SSH"
FORM_COOKIE = "kyt_form"
ADMIN_COOKIE = "kyt_admin"
SESSION_TTL = 8 * 3600
FORM_TTL = 24 * 3600
MAX_BODY = 512 * 1024

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

COUNTRY_NAMES = {
    "AD": "Andorra", "AE": "Uni Emirat Arab", "AF": "Afganistan", "AL": "Albania",
    "AM": "Armenia", "AO": "Angola", "AR": "Argentina", "AT": "Austria",
    "AU": "Australia", "AZ": "Azerbaijan", "BA": "Bosnia dan Herzegovina",
    "BD": "Bangladesh", "BE": "Belgia", "BG": "Bulgaria", "BH": "Bahrain",
    "BN": "Brunei", "BO": "Bolivia", "BR": "Brasil", "BY": "Belarus",
    "CA": "Kanada", "CH": "Swiss", "CL": "Cile", "CN": "Tiongkok",
    "CO": "Kolombia", "CR": "Kosta Rika", "CY": "Siprus", "CZ": "Ceko",
    "DE": "Jerman", "DK": "Denmark", "DO": "Republik Dominika", "DZ": "Aljazair",
    "EC": "Ekuador", "EE": "Estonia", "EG": "Mesir", "ES": "Spanyol",
    "ET": "Etiopia", "FI": "Finlandia", "FJ": "Fiji", "FR": "Prancis",
    "GB": "Inggris", "GE": "Georgia", "GH": "Ghana", "GR": "Yunani",
    "GT": "Guatemala", "HK": "Hong Kong", "HR": "Kroasia", "HU": "Hongaria",
    "ID": "Indonesia", "IE": "Irlandia", "IL": "Israel", "IN": "India",
    "IQ": "Irak", "IR": "Iran", "IS": "Islandia", "IT": "Italia",
    "JM": "Jamaika", "JO": "Yordania", "JP": "Jepang", "KE": "Kenya",
    "KH": "Kamboja", "KR": "Korea Selatan", "KW": "Kuwait", "KZ": "Kazakhstan",
    "LA": "Laos", "LB": "Lebanon", "LK": "Sri Lanka", "LT": "Lituania",
    "LU": "Luksemburg", "LV": "Latvia", "LY": "Libya", "MA": "Maroko",
    "MD": "Moldova", "ME": "Montenegro", "MK": "Makedonia Utara", "MM": "Myanmar",
    "MN": "Mongolia", "MO": "Makau", "MT": "Malta", "MU": "Mauritius",
    "MV": "Maladewa", "MX": "Meksiko", "MY": "Malaysia", "NG": "Nigeria",
    "NL": "Belanda", "NO": "Norwegia", "NP": "Nepal", "NZ": "Selandia Baru",
    "OM": "Oman", "PA": "Panama", "PE": "Peru", "PG": "Papua Nugini",
    "PH": "Filipina", "PK": "Pakistan", "PL": "Polandia", "PT": "Portugal",
    "PY": "Paraguay", "QA": "Qatar", "RO": "Rumania", "RS": "Serbia",
    "RU": "Rusia", "RW": "Rwanda", "SA": "Arab Saudi", "SE": "Swedia",
    "SG": "Singapura", "SI": "Slovenia", "SK": "Slowakia", "SN": "Senegal",
    "TH": "Thailand", "TJ": "Tajikistan", "TL": "Timor Leste", "TN": "Tunisia",
    "TR": "Turki", "TW": "Taiwan", "TZ": "Tanzania", "UA": "Ukraina",
    "UG": "Uganda", "US": "Amerika Serikat", "UY": "Uruguay", "UZ": "Uzbekistan",
    "VE": "Venezuela", "VN": "Vietnam", "ZA": "Afrika Selatan", "ZM": "Zambia",
    "ZW": "Zimbabwe",
}

UI_THEME_COLORS = {
    "cream": "#fffaf2",
    "midnight": "#070b14",
    "ocean": "#06121f",
    "forest": "#07120d",
    "royal": "#12071f",
}
UI_THEMES = {
    "cream": ("Cream", "Hangat, bersih, nyaman untuk penggunaan lama."),
    "midnight": ("Midnight", "Navy gelap dengan aksen cyan neon."),
    "ocean": ("Ocean", "Biru laut dalam dengan aksen sky blue."),
    "forest": ("Forest", "Hijau gelap dengan aksen lime segar."),
    "royal": ("Royal", "Ungu gelap dengan aksen pink neon."),
}
DEFAULT_META = "HITS SSH — akun VPN gratis dan premium SSH, VMess, VLESS, Trojan. Premium tanpa login, bayar QRIS GoPay."
DEFAULT_HERO_TITLE = "Internet bebas,"
DEFAULT_HERO_TITLE_ACCENT = "akun langsung jadi."
DEFAULT_HERO_LEAD = "Buat akun gratis dalam hitungan detik, atau beli akun premium lewat QRIS GoPay. Tanpa registrasi, tanpa email, dan invoice bisa dicek kembali kapan saja."

DEFAULTS = {
    "site_name": BRAND,
    "brand_name": BRAND,
    "brand_accent": "SSH",
    "meta_description": DEFAULT_META,
    "hero_title": DEFAULT_HERO_TITLE,
    "hero_title_accent": DEFAULT_HERO_TITLE_ACCENT,
    "hero_lead": DEFAULT_HERO_LEAD,
    "brand_logo": "",
    "brand_logo_version": "",
    "ui_theme": "cream",
    "server_show": "1",
    "server_auto": "1",
    "server_country_code": "",
    "server_country_name": "",
    "server_city": "",
    "server_note": "",
    "server_source": "",
    "server_last_check": "",
    "maintenance": "0",
    "free_enabled": "1",
    "premium_enabled": "1",
    "premium_expiry_min": "15",
    "gopay_base_url": "https://pgku.stunnelv4.biz.id",
    "contact_telegram": "",
    "contact_group": "",
    "contact_note": "",
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
    "premium_expiry_min": (5, 120),
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
            CREATE TABLE IF NOT EXISTS premium_products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                protocol TEXT NOT NULL,
                label TEXT NOT NULL,
                days INTEGER NOT NULL,
                price INTEGER NOT NULL,
                ip_limit INTEGER NOT NULL DEFAULT 2,
                quota_gb INTEGER NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 1,
                sort INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice TEXT UNIQUE NOT NULL,
                product_code TEXT NOT NULL,
                protocol TEXT NOT NULL,
                days INTEGER NOT NULL,
                price INTEGER NOT NULL,
                unique_code INTEGER NOT NULL,
                total INTEGER NOT NULL,
                ip_limit INTEGER NOT NULL DEFAULT 2,
                quota_gb INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'PENDING',
                qr_string TEXT NOT NULL DEFAULT '',
                buyer_ip TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                paid_at INTEGER,
                reference TEXT NOT NULL DEFAULT '',
                account_username TEXT NOT NULL DEFAULT '',
                account_output TEXT NOT NULL DEFAULT '',
                provision_error TEXT NOT NULL DEFAULT '',
                notified INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status, created_at);
            CREATE INDEX IF NOT EXISTS idx_orders_total ON orders(total, created_at);
            CREATE INDEX IF NOT EXISTS idx_orders_reference ON orders(reference);
            CREATE TABLE IF NOT EXISTS pay_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT ''
            );
            """
        )
        for k, v in DEFAULTS.items():
            conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))
        if not conn.execute("SELECT 1 FROM premium_products LIMIT 1").fetchone():
            labels = {"ssh": "SSH", "vmess": "VMess", "vless": "VLESS", "trojan": "Trojan"}
            durations = [(3, 1000), (7, 2500), (30, 10000)]
            order = 0
            for proto in ("ssh", "vmess", "vless", "trojan"):
                for days, price in durations:
                    order += 10
                    conn.execute(
                        "INSERT OR IGNORE INTO premium_products"
                        "(code,protocol,label,days,price,ip_limit,quota_gb,active,sort,updated_at)"
                        " VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (
                            f"{proto}-{days}",
                            proto,
                            f"{labels[proto]} {days} Hari",
                            days,
                            price,
                            2,
                            0,
                            1,
                            order,
                            int(time.time()),
                        ),
                    )
        row = conn.execute("SELECT username FROM admin LIMIT 1").fetchone()
        if not row:
            conn.execute(
                "INSERT INTO admin(username,password_hash,updated_at) VALUES(?,?,?)",
                ("admin", hash_password(secrets.token_urlsafe(32)), int(time.time())),
            )
            ADMIN_CRED_PATH.write_text(
                "HITS SSH admin\n"
                f"URL    : https://{PUBLIC_HOST}/admin\n"
                "Login  : token bot Telegram\n"
                "Token  : awk '/^#bot# /{print $2}' /etc/bot/.bot.db\n",
                encoding="utf-8",
            )
            os.chmod(ADMIN_CRED_PATH, 0o600)
            logger.info("admin awal dibuat; login memakai token bot")
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


def branding() -> dict[str, str]:
    try:
        settings = get_settings()
    except Exception:
        settings = {}
    name = (settings.get("brand_name") or BRAND).strip()[:40] or BRAND
    accent = (settings.get("brand_accent") or "").strip()[:20]
    theme = (settings.get("ui_theme") or "cream").strip()
    if theme not in UI_THEMES:
        theme = "cream"
    return {
        "name": name,
        "accent": accent,
        "theme": theme,
        "meta": (settings.get("meta_description") or DEFAULT_META).strip()[:300],
        "hero_title": (settings.get("hero_title") or DEFAULT_HERO_TITLE).strip()[:100],
        "hero_title_accent": (settings.get("hero_title_accent") or DEFAULT_HERO_TITLE_ACCENT).strip()[:100],
        "hero_lead": (settings.get("hero_lead") or DEFAULT_HERO_LEAD).strip()[:400],
        "logo": (settings.get("brand_logo") or "").strip(),
        "logo_version": (settings.get("brand_logo_version") or "").strip(),
    }


def flag_emoji(code: str) -> str:
    code = (code or "").strip().upper()
    if len(code) == 2 and code.isalpha():
        return "".join(chr(ord(ch) + 127397) for ch in code)
    return "🌐"


def _fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "HITS-SSH/1.0"})
    with urllib.request.urlopen(req, timeout=6) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def detect_server_info() -> dict | None:
    sources = [
        ("https://ipinfo.io/json", lambda d: (d.get("country"), d.get("city"), None)),
        ("https://ipapi.co/json/", lambda d: (d.get("country_code"), d.get("city"), d.get("country_name"))),
        ("https://ifconfig.co/json", lambda d: (d.get("country_iso"), d.get("city"), d.get("country"))),
    ]
    for url, parser in sources:
        try:
            data = _fetch_json(url)
            code, city, fallback_name = parser(data)
        except Exception as exc:
            logger.warning("deteksi server gagal via %s: %s", url, exc)
            continue
        code = (code or "").strip().upper()
        if len(code) != 2 or not code.isalpha():
            continue
        name = COUNTRY_NAMES.get(code) or (fallback_name or "").strip() or code
        city = (city or "").strip()
        return {"code": code, "name": name, "city": city, "source": url}
    return None


def refresh_server_info(force: bool = False) -> dict | None:
    settings = get_settings()
    if not force:
        if settings.get("server_auto", "1") != "1":
            return None
        if (settings.get("server_country_code") or "").strip():
            return None
    info = detect_server_info()
    if not info:
        return None
    set_settings(
        {
            "server_auto": "1",
            "server_country_code": info["code"],
            "server_country_name": info["name"],
            "server_city": info["city"],
            "server_note": "",
            "server_source": info["source"],
            "server_last_check": str(int(time.time())),
        }
    )
    logger.info("lokasi server: %s %s (%s)", info["code"], info["name"], info["source"])
    return info


def server_info() -> dict:
    settings = get_settings()
    code = (settings.get("server_country_code") or "").strip().upper()
    name = (settings.get("server_country_name") or "").strip() or COUNTRY_NAMES.get(code, code)
    city = (settings.get("server_city") or "").strip()
    note = (settings.get("server_note") or "").strip()[:160]
    show = settings.get("server_show", "1") == "1" and bool(code or name)
    return {
        "show": show,
        "code": code,
        "name": name,
        "city": city,
        "note": note,
        "flag": flag_emoji(code),
        "source": (settings.get("server_source") or "").strip(),
        "last_check": (settings.get("server_last_check") or "").strip(),
    }


def server_strip_html() -> str:
    info = server_info()
    if not info["show"] or not info["name"]:
        return ""
    details = []
    if info["city"] and info["city"].lower() != info["name"].lower():
        details.append(info["city"])
    if info["note"]:
        details.append(info["note"])
    detail = " · ".join(details) or "Lokasi VPS"
    return f"""
      <div class="server-strip">
        <span class="server-flag" aria-hidden="true">{info['flag']}</span>
        <div class="server-copy">
          <span class="mini-label">LOKASI SERVER</span>
          <b>{e(info['name'])}</b>
          <small>{e(detail)}</small>
        </div>
        <span class="server-status">Online</span>
      </div>"""


def brand_word_html(name: str, accent: str) -> str:
    name = (name or BRAND).strip()
    accent = (accent or "").strip()
    if accent and accent in name:
        before, _sep, after = name.partition(accent)
        return f"{e(before)}<span>{e(accent)}</span>{e(after)}"
    return e(name)


def brand_logo_path(kind: str = "logo") -> Path | None:
    try:
        settings = get_settings()
    except Exception:
        return None
    if kind == "favicon":
        path = BRANDING_DIR / "favicon.png"
        return path if path.exists() else None
    name = (settings.get("brand_logo") or "").strip()
    if name not in ("logo.webp", "logo.png"):
        return None
    path = BRANDING_DIR / name
    return path if path.exists() else None


def save_brand_logo(data_url: str) -> tuple[bool, str]:
    if not data_url.startswith("data:image/"):
        return False, "Format logo tidak valid."
    try:
        _header, encoded = data_url.split(",", 1)
        raw = base64.b64decode(encoded, validate=True)
    except Exception:
        return False, "File logo tidak bisa dibaca."
    if len(raw) > 2 * 1024 * 1024:
        return False, "Ukuran logo maksimal 2 MB."
    try:
        from PIL import Image
        image = Image.open(io.BytesIO(raw))
        image.load()
    except Exception:
        return False, "File logo bukan gambar yang didukung."
    if image.width < 128 or image.height < 128:
        return False, "Logo minimal 128×128 piksel."
    image = image.convert("RGBA")
    side = min(image.width, image.height)
    left = (image.width - side) // 2
    top = (image.height - side) // 2
    image = image.crop((left, top, left + side, top + side))
    image = image.resize((256, 256), Image.LANCZOS)
    BRANDING_DIR.mkdir(parents=True, exist_ok=True)
    logo_name = "logo.webp"
    try:
        image.save(BRANDING_DIR / "logo.webp", "WEBP", quality=88, method=6)
    except Exception:
        logo_name = "logo.png"
        image.save(BRANDING_DIR / "logo.png", "PNG", optimize=True)
    image.resize((64, 64), Image.LANCZOS).save(BRANDING_DIR / "favicon.png", "PNG", optimize=True)
    for name in ("logo.webp", "logo.png"):
        if name != logo_name:
            try:
                (BRANDING_DIR / name).unlink()
            except FileNotFoundError:
                pass
    return True, logo_name


def remove_brand_logo() -> None:
    for name in ("logo.webp", "logo.png", "favicon.png"):
        try:
            (BRANDING_DIR / name).unlink()
        except FileNotFoundError:
            pass


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


SSH_BOX_SEP = "━" * 19


def _ssh_field(raw: str, key: str) -> str:
    match = re.search(
        r"^[ \t]*" + re.escape(key) + r"[ \t]*:[ \t]*(.*?)[ \t]*$",
        raw,
        re.MULTILINE,
    )
    return match.group(1).strip() if match else ""


def format_ssh_output(raw: str) -> str:
    """Rapikan output akun SSH ke format kartu klasik HITS SSH."""
    raw = clean_output(raw or "")
    if not raw:
        return raw
    head = raw.lstrip()
    if head.startswith(SSH_BOX_SEP) and "SSH OVPN Account" in head[:120]:
        return raw

    username = _ssh_field(raw, "Username")
    password = _ssh_field(raw, "Password")
    if not username or not password:
        return raw

    settings = get_settings()
    host = _ssh_field(raw, "Host") or (settings.get("domain") or "").strip()
    slowdns = _ssh_field(raw, "Host Slowdns")
    pubkey = _ssh_field(raw, "Pub Key")
    expiry = _ssh_field(raw, "Berakhir Pada") or _ssh_field(raw, "Expired until")
    if not expiry and _ssh_field(raw, "Aktif Selama"):
        expiry = _ssh_field(raw, "Aktif Selama")

    ports = [
        ("Port OpenSSH", "443, 80, 22"),
        ("Port SSH UDP", "1-65535"),
        ("Port Dropbear", "443, 109"),
        ("Port SSH WS", "80, 8080, 8081-9999"),
        ("Port SSH SSL WS", "443"),
        ("HCR", "8811 (TLS + Plain; akun SSH)"),
        ("Port SlowDNS", "53, 80, 443"),
        ("Port SSL/TLS", "400-900"),
        ("Port OVPN WS SSL", "443"),
        ("Port OVPN SSL", "443"),
        ("Port OVPN TCP", "443, 1194"),
        ("Port OVPN UDP", "2200"),
        ("BadVPN UDP", "7100, 7200, 7300"),
    ]

    payload_ssh = _ssh_field(raw, "Payload SSH WS") or (
        f"GET / HTTP/1.1[crlf]Host: {host}[crlf]Upgrade: websocket"
        "[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf][crlf]"
    )
    payload_enh = _ssh_field(raw, "Payload WS ENHANCED") or (
        "PATCH / HTTP/1.1[crlf]Host: [host][crlf]Host: INPUT_YOUR_BUGCDN"
        "[crlf]Connection: Upgrade[crlf]User-Agent: [ua]"
        "[crlf]Upgrade: websocket[crlf][crlf]"
    )
    payload_cfray = _ssh_field(raw, "CF-RAY without proxy & port") or (
        "GET / HTTP/1.1[crlf]Host: INPUT_YOUR_BUGCDN[crlf][crlf]"
        "CF-RAY / HTTP/1.1[crlf]Host: "
        f"{host}[crlf]Upgrade: websocket[crlf]Connection: Keep-Alive"
        "[crlf]User-Agent: [ua][crlf][crlf]"
    )
    payload_https = (
        f"GET / HTTP/1.1[crlf]Host: {host}[crlf]Upgrade: websocket[crlf][crlf]"
    )

    out: list[str] = [SSH_BOX_SEP, " SSH OVPN Account", SSH_BOX_SEP]
    out.append(f" {'Username':<17}: {username}")
    out.append(f" {'Password':<17}: {password}")
    if host:
        out.append(f" {'Host':<17}: {host}")
    if slowdns:
        out.append(f" {'Host Slowdns':<17}: {slowdns}")
    if pubkey:
        out.append(f" {'Pub Key':<17}: {pubkey}")
    for label, default in ports:
        value = _ssh_field(raw, label) or default
        if label == "Port OVPN TCP" and value and "443" not in value:
            value = f"443, {value}"
        out.append(f" {label:<17}: {value}")
    out += [SSH_BOX_SEP, " Payload SSH WS", SSH_BOX_SEP, payload_ssh]
    out += [SSH_BOX_SEP, " Payload WS ENHANCED", SSH_BOX_SEP, payload_enh]
    out += [SSH_BOX_SEP, " CF-RAY without proxy & port", SSH_BOX_SEP, payload_cfray]
    out += [SSH_BOX_SEP, " Payload WS HTTPS", SSH_BOX_SEP, payload_https]
    out += [SSH_BOX_SEP, SSH_BOX_SEP]
    if host:
        out.append(f" {'OVPN Download':<17}: https://{host}:81/")
        out.append(SSH_BOX_SEP)
        out.append(f" Save Link Account: https://{host}:81/ssh-{username}.txt")
        out.append(SSH_BOX_SEP)
    if expiry:
        out.append(f" Expired until  : {expiry}")
        out.append(SSH_BOX_SEP)
    return "\n".join(out)


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
        output = format_ssh_output(read_account_output("ssh", user))
        try:
            output_path = HTML_DIR / f"ssh-{user}.txt"
            output_path.write_text(output + "\n", encoding="utf-8")
            os.chmod(output_path, 0o644)
        except OSError:
            logger.warning("gagal menulis ulang output SSH %s", user)
        return True, output, log
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
    if settings.get("free_enabled", "1") != "1":
        raise ValueError("Kategori akun gratis sedang ditutup admin.")
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


# ===========================================================================
# HITS SSH Premium — GoPay/QRIS, invoice, dan provisioning
# ===========================================================================

BOT_DB_LINE = Path("/etc/bot/.bot.db")
BOT_KYT_DB = Path("/usr/bin/kyt/database.db")
GOPAY_TOKEN_FILE = Path("/usr/bin/kyt/gomerch_token.json")
GOPAY_DEFAULT_BASE = "https://pgku.stunnelv4.biz.id"
GOPAY_LOCK = threading.Lock()
_GOPAY_CACHE = {"ts": 0.0, "rows": []}
_GOPAY_RATE_UNTIL = 0.0
_GOPAY_REFRESH_AT = 0.0


def bot_credentials() -> tuple[str, str]:
    try:
        with open(BOT_DB_LINE, "r", errors="ignore") as fh:
            for line in fh:
                if line.startswith("#bot# "):
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[1].strip(), parts[2].strip()
    except FileNotFoundError:
        pass
    return "", ""


def admin_login_token() -> str:
    token, _chat = bot_credentials()
    if token:
        return token
    conf = read_web_conf()
    return (conf.get("ADMIN_TOKEN") or "").strip()


def pay_state_set(key: str, value: str) -> None:
    conn = db_connect()
    try:
        conn.execute(
            "INSERT INTO pay_state(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        conn.commit()
    finally:
        conn.close()


def pay_state_get(key: str, default: str = "") -> str:
    conn = db_connect()
    try:
        row = conn.execute("SELECT value FROM pay_state WHERE key=?", (key,)).fetchone()
        return str(row["value"]) if row else default
    finally:
        conn.close()


def bot_setting(key: str, default: str = "") -> str:
    if not BOT_KYT_DB.exists():
        return default
    try:
        conn = sqlite3.connect(f"file:{BOT_KYT_DB}?mode=ro", uri=True, timeout=5)
        try:
            row = conn.execute("SELECT v FROM settings WHERE k=?", (key,)).fetchone()
            return str(row[0]) if row and row[0] is not None else default
        finally:
            conn.close()
    except Exception:
        return default


def telegram_send(text: str) -> bool:
    token, chat = bot_credentials()
    if not token or not chat:
        return False
    data = urllib.parse.urlencode(
        {
            "chat_id": chat,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": "1",
        }
    ).encode("utf-8")
    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=data,
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10).read(1)
        return True
    except Exception as exc:
        logger.warning("telegram premium gagal: %s", exc)
        return False


def gopay_config() -> dict:
    token = refresh = ""
    try:
        with open(GOPAY_TOKEN_FILE, "r", errors="ignore") as fh:
            data = json.load(fh) or {}
            token = str(data.get("token") or "").strip()
            refresh = str(data.get("refresh_token") or "").strip()
    except Exception:
        pass
    if not token:
        token = bot_setting("gomerch_token", "").strip()
    if not refresh:
        refresh = bot_setting("gomerch_refresh_token", "").strip()
    base = (bot_setting("gomerch_base_url", "") or get_settings().get("gopay_base_url", "") or GOPAY_DEFAULT_BASE).rstrip("/")
    static_qr = bot_setting("gomerch_static_qr", "").strip()
    return {
        "base": base,
        "token": token,
        "refresh_token": refresh,
        "static_qr": static_qr,
        "phone": bot_setting("gomerch_phone", "").strip(),
    }


def gopay_ready() -> tuple[bool, str]:
    cfg = gopay_config()
    if not cfg["static_qr"]:
        return False, "QRIS GoPay belum diatur di bot."
    if not cfg["token"]:
        return False, "Token GoPay belum ada. Login GoPay lewat bot."
    return True, ""


def _crc16(data: str) -> str:
    crc = 0xFFFF
    for ch in data:
        crc ^= ord(ch) << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return "%04X" % (crc & 0xFFFF)


def gopay_build_qris(amount: int) -> str:
    static_qr = gopay_config()["static_qr"]
    if not static_qr:
        return ""
    body = static_qr[:-4].replace("010211", "010212", 1)
    parts = body.split("5802ID")
    amount_str = str(int(amount))
    amount_field = "54" + "%02d" % len(amount_str) + amount_str
    payload = parts[0] + amount_field + "5802ID" + parts[1]
    return payload + _crc16(payload)


def gopay_history(force: bool = False) -> list:
    global _GOPAY_CACHE, _GOPAY_RATE_UNTIL
    if time.time() < _GOPAY_RATE_UNTIL:
        return []
    with GOPAY_LOCK:
        now = time.time()
        if not force and _GOPAY_CACHE["rows"] and now - _GOPAY_CACHE["ts"] < 8:
            return _GOPAY_CACHE["rows"]
        cfg = gopay_config()
        if not cfg["token"]:
            pay_state_set("gopay_error", "Token GoPay kosong")
            return []
        url = cfg["base"] + "/api/history?" + urllib.parse.urlencode({"token": cfg["token"]})
        try:
            with urllib.request.urlopen(url, timeout=20) as resp:
                raw = resp.read().decode("utf-8", "replace")
                data = json.loads(raw)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                _GOPAY_RATE_UNTIL = time.time() + 16 * 60
                pay_state_set("gopay_error", "Rate limit GoPay (429), tunggu 16 menit")
            elif exc.code in (400, 401):
                pay_state_set("gopay_error", "Token GoPay expired; refresh lewat bot")
                pay_state_set("gopay_token_invalid", str(int(time.time())))
            else:
                pay_state_set("gopay_error", f"HTTP {exc.code} dari gateway")
            logger.warning("gopay history HTTP %s", exc.code)
            return []
        except Exception as exc:
            pay_state_set("gopay_error", f"Gagal koneksi gateway: {exc}")
            logger.warning("gopay history error: %s", exc)
            return []
        if not data.get("success"):
            pay_state_set("gopay_error", "Gateway menolak history GoPay")
            return []
        rows = data.get("data") or []
        _GOPAY_CACHE = {"ts": time.time(), "rows": rows}
        pay_state_set("gopay_last_check", str(int(time.time())))
        pay_state_set("gopay_error", "")
        pay_state_set("gopay_token_invalid", "")
        pay_state_set("gopay_last_ok", str(int(time.time())))
        return rows


def _parse_tx_time(value) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value) / (1000.0 if value > 1e11 else 1.0)
    s = str(value).strip()
    if not s:
        return 0.0
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return dt.datetime.strptime(s[:19], fmt).replace(tzinfo=JAKARTA).timestamp()
        except Exception:
            pass
    return 0.0


def gopay_match(total: int, created_at: int, used: set[str]) -> str:
    for tx in gopay_history():
        if not isinstance(tx, dict):
            continue
        status = str(tx.get("status") or "").lower()
        if not re.search(r"success|settled|completed", status):
            continue
        try:
            nominal = int(tx.get("amount") or 0)
        except Exception:
            nominal = 0
        if nominal != int(total):
            continue
        txid = str(tx.get("id") or tx.get("reference_id") or "").strip()
        if not txid or txid in used:
            continue
        tx_ts = _parse_tx_time(tx.get("time") or tx.get("created_at"))
        if tx_ts and tx_ts < (created_at - 120):
            continue
        return txid
    return ""


def gopay_qr_svg(qr_string: str) -> bytes:
    if not qr_string:
        return b""
    try:
        import qrcode
        import qrcode.image.svg

        img = qrcode.make(
            qr_string,
            image_factory=qrcode.image.svg.SvgPathImage,
            box_size=10,
            border=2,
        )
        buf = io.BytesIO()
        img.save(buf)
        return buf.getvalue()
    except Exception as exc:
        logger.warning("qrcode gagal: %s", exc)
        return b""


def premium_products(active_only: bool = False) -> list[sqlite3.Row]:
    conn = db_connect()
    try:
        sql = "SELECT * FROM premium_products"
        if active_only:
            sql += " WHERE active=1"
        sql += " ORDER BY sort, id"
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


def premium_product(code: str, active_only: bool = True) -> sqlite3.Row | None:
    conn = db_connect()
    try:
        sql = "SELECT * FROM premium_products WHERE code=?"
        if active_only:
            sql += " AND active=1"
        return conn.execute(sql, (code,)).fetchone()
    finally:
        conn.close()


def premium_public_data() -> dict:
    products = []
    for row in premium_products(active_only=True):
        products.append(
            {
                "code": row["code"],
                "protocol": row["protocol"],
                "label": row["label"],
                "days": row["days"],
                "price": row["price"],
                "ip_limit": row["ip_limit"],
                "quota_gb": row["quota_gb"],
            }
        )
    return {"products": products}


def _invoice_code() -> str:
    alphabet = string.ascii_uppercase + string.digits
    for _ in range(30):
        code = "HITS-" + now_jkt().strftime("%y%m%d") + "-" + "".join(secrets.choice(alphabet) for _ in range(8))
        conn = db_connect()
        try:
            if not conn.execute("SELECT 1 FROM orders WHERE invoice=?", (code,)).fetchone():
                return code
        finally:
            conn.close()
    raise RuntimeError("gagal membuat kode invoice")


def _allocate_total(price: int) -> tuple[int, int]:
    since = int(time.time()) - 7 * 86400
    conn = db_connect()
    try:
        used = {
            int(r["total"])
            for r in conn.execute("SELECT total FROM orders WHERE created_at>=?", (since,))
        }
    finally:
        conn.close()
    bot_amounts: set[int] = set()
    if BOT_KYT_DB.exists():
        try:
            bconn = sqlite3.connect(f"file:{BOT_KYT_DB}?mode=ro", uri=True, timeout=5)
            try:
                for r in bconn.execute(
                    "SELECT amount FROM deposit WHERE status IN ('PENDING','PAID') AND created>=datetime('now','-2 days')"
                ):
                    try:
                        bot_amounts.add(int(r[0]))
                    except Exception:
                        pass
            finally:
                bconn.close()
        except Exception:
            pass
    for code in range(1, 1000):
        total = int(price) + code
        if total not in used and total not in bot_amounts:
            return code, total
    raise ValueError("Nomor unik invoice habis sementara. Coba lagi beberapa saat.")


def order_by_invoice(invoice: str) -> sqlite3.Row | None:
    conn = db_connect()
    try:
        return conn.execute("SELECT * FROM orders WHERE invoice=?", (invoice,)).fetchone()
    finally:
        conn.close()


def create_premium_order(product_code: str, ip: str, user_agent: str) -> sqlite3.Row:
    settings = get_settings()
    if settings.get("maintenance") == "1":
        raise ValueError("Website sedang dalam perawatan. Silakan coba lagi nanti.")
    if settings.get("premium_enabled", "1") != "1":
        raise ValueError("Kategori Premium sedang ditutup admin.")
    product = premium_product(product_code, active_only=True)
    if not product:
        raise ValueError("Paket premium tidak tersedia.")
    if product["protocol"] == "ssh" and settings.get("ssh_enabled", "1") != "1":
        raise ValueError("Protokol SSH sedang ditutup admin.")
    if product["protocol"] in PROTOCOLS and (
        settings.get("xray_enabled", "1") != "1"
        or settings.get(f"{product['protocol']}_enabled", "1") != "1"
    ):
        raise ValueError(f"Protokol {PROTOCOLS[product['protocol']]['label']} sedang ditutup admin.")
    ready, reason = gopay_ready()
    if not ready:
        raise ValueError(reason)
    conn = db_connect()
    try:
        active = conn.execute(
            "SELECT COUNT(*) n FROM orders WHERE buyer_ip=? AND status IN ('PENDING','PAID','PROVISIONING') AND created_at>=?",
            (ip, int(time.time()) - 3600),
        ).fetchone()["n"]
    finally:
        conn.close()
    if int(active) >= 3:
        raise ValueError("Terlalu banyak invoice aktif dari IP Anda. Selesaikan atau tunggu invoice lama kedaluwarsa.")

    unique_code, total = _allocate_total(int(product["price"]))
    qr = gopay_build_qris(total)
    if not qr:
        raise ValueError("Gagal membuat QRIS GoPay. Hubungi admin.")
    invoice = _invoice_code()
    now = int(time.time())
    expires = now + int(settings.get("premium_expiry_min", "15")) * 60
    conn = db_connect()
    try:
        conn.execute(
            "INSERT INTO orders(invoice,product_code,protocol,days,price,unique_code,total,"
            "ip_limit,quota_gb,status,qr_string,buyer_ip,user_agent,created_at,expires_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,'PENDING',?,?,?,?,?)",
            (
                invoice,
                product["code"],
                product["protocol"],
                product["days"],
                product["price"],
                unique_code,
                total,
                product["ip_limit"],
                product["quota_gb"],
                qr,
                ip,
                user_agent[:300],
                now,
                expires,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    audit("premium_invoice", f"{invoice} {product['code']} total={total} ip={ip}", ip)
    return order_by_invoice(invoice)


def premium_order_notify(row: sqlite3.Row, ok: bool, error: str = "") -> None:
    label = f"{row['protocol'].upper()} · {row['days']} hari"
    if ok:
        b = branding()
        text = (
            f"<b>✅ {e(b['name'])} PREMIUM TERJUAL</b>\n"
            f"Invoice : <code>{e(row['invoice'])}</code>\n"
            f"Paket   : <code>{e(label)}</code>\n"
            f"Total   : <code>Rp {int(row['total']):,}</code>\n"
            f"Akun    : <code>{e(row['account_username'])}</code>\n"
            "Status  : <code>AKTIF</code>"
        ).replace(",", ".")
    else:
        text = (
            "<b>⚠️ PEMBAYARAN MASUK, AKUN GAGAL</b>\n"
            f"Invoice : <code>{e(row['invoice'])}</code>\n"
            f"Paket   : <code>{e(label)}</code>\n"
            f"Total   : <code>Rp {int(row['total']):,}</code>\n"
            f"Error   : <code>{e((error or 'tidak diketahui')[:300])}</code>\n"
            "Silakan retry dari Admin Dashboard."
        ).replace(",", ".")
    telegram_send(text)


def provision_premium_order(invoice: str) -> bool:
    global CREATE_LOCK
    with CREATE_LOCK:
        row = order_by_invoice(invoice)
        if not row:
            return False
        if row["status"] == "COMPLETED" and row["account_output"]:
            return True
        if not row["reference"] and not row["paid_at"]:
            logger.warning("provision %s ditolak: belum ada pembayaran", invoice)
            return False
        if row["protocol"] in PROTOCOLS:
            username = make_username("xray", row["protocol"])
            password = ""
            ok, output, log = create_xray_account(
                row["protocol"],
                username,
                int(row["days"]),
                int(row["ip_limit"]),
                int(row["quota_gb"]),
            )
        else:
            username = make_username("ssh", "")
            password = make_password()
            ok, output, log = create_ssh_account(
                username,
                password,
                int(row["days"]),
                int(row["ip_limit"]),
                int(row["quota_gb"]),
            )
        conn = db_connect()
        try:
            if ok:
                conn.execute(
                    "UPDATE orders SET status='COMPLETED', account_username=?, account_output=?,"
                    " provision_error='', notified=1 WHERE invoice=?",
                    (username, output, invoice),
                )
            else:
                conn.execute(
                    "UPDATE orders SET status='FAILED', provision_error=?, notified=1 WHERE invoice=?",
                    ((output or "gagal membuat akun")[:1000], invoice),
                )
            conn.commit()
        finally:
            conn.close()
        fresh = order_by_invoice(invoice)
        if fresh:
            premium_order_notify(fresh, bool(ok), "" if ok else (output or ""))
            audit("premium_provision", f"{invoice} {username} {'ok' if ok else 'gagal'}", row["buyer_ip"])
        return bool(ok)


def retry_premium_order(invoice: str) -> bool:
    row = order_by_invoice(invoice)
    if not row or not (row["reference"] or row["paid_at"]):
        return False
    if row["status"] == "COMPLETED":
        return True
    conn = db_connect()
    try:
        conn.execute("UPDATE orders SET status='PAID', provision_error='' WHERE invoice=?", (invoice,))
        conn.commit()
    finally:
        conn.close()
    return provision_premium_order(invoice)


def _bot_paid_references() -> set[str]:
    if not BOT_KYT_DB.exists():
        return set()
    try:
        conn = sqlite3.connect(f"file:{BOT_KYT_DB}?mode=ro", uri=True, timeout=5)
        try:
            return {str(r[0]) for r in conn.execute("SELECT reference FROM deposit WHERE status='PAID' AND reference IS NOT NULL AND reference!=''")}
        finally:
            conn.close()
    except Exception:
        return set()


def expire_premium_orders() -> int:
    conn = db_connect()
    try:
        cur = conn.execute(
            "UPDATE orders SET status='EXPIRED' WHERE status='PENDING' AND expires_at<?",
            (int(time.time()),),
        )
        conn.commit()
        return int(cur.rowcount or 0)
    finally:
        conn.close()


def poll_premium_orders() -> None:
    expire_premium_orders()
    conn = db_connect()
    try:
        rows = conn.execute(
            "SELECT * FROM orders WHERE status IN ('PENDING','EXPIRED','PAID','FAILED')"
            " AND created_at>=? ORDER BY created_at ASC",
            (int(time.time()) - 48 * 86400,),
        ).fetchall()
        refs = {
            str(r["reference"])
            for r in conn.execute(
                "SELECT reference FROM orders WHERE reference IS NOT NULL AND reference!=''"
            )
        }
    finally:
        conn.close()
    pending = [r for r in rows if r["status"] in ("PENDING", "EXPIRED") and not r["reference"]]
    if not pending:
        pay_state_set("gopay_pending", "0")
        return
    ready, reason = gopay_ready()
    if not ready:
        pay_state_set("gopay_error", reason)
        return
    history = gopay_history()
    if not history:
        pay_state_set("gopay_pending", str(len(pending)))
        return
    used = set(refs) | _bot_paid_references()
    matched = 0
    for row in pending:
        txid = gopay_match(int(row["total"]), int(row["created_at"]), used)
        if not txid:
            continue
        used.add(txid)
        conn = db_connect()
        try:
            conn.execute(
                "UPDATE orders SET status='PAID', reference=?, paid_at=? WHERE invoice=? AND reference=''",
                (txid, int(time.time()), row["invoice"]),
            )
            conn.commit()
        finally:
            conn.close()
        audit("premium_paid", f"{row['invoice']} ref={txid} total={row['total']}", row["buyer_ip"])
        matched += 1
        logger.info("premium paid %s ref=%s", row["invoice"], txid)
        provision_premium_order(row["invoice"])
    pay_state_set("gopay_pending", str(max(0, len(pending) - matched)))
    pay_state_set("gopay_last_match", str(int(time.time())) if matched else pay_state_get("gopay_last_match"))


def payment_daemon() -> None:
    time.sleep(5)
    while True:
        try:
            poll_premium_orders()
        except Exception:
            logger.error("payment daemon: %s", traceback.format_exc())
        time.sleep(10)


def premium_stats() -> dict:
    conn = db_connect()
    try:
        today = int(time.time()) - 86400
        total_paid = conn.execute("SELECT COUNT(*) n FROM orders WHERE status='COMPLETED'").fetchone()["n"]
        revenue = conn.execute("SELECT COALESCE(SUM(total),0) s FROM orders WHERE status='COMPLETED'").fetchone()["s"]
        today_orders = conn.execute("SELECT COUNT(*) n FROM orders WHERE created_at>=?", (today,)).fetchone()["n"]
        pending = conn.execute("SELECT COUNT(*) n FROM orders WHERE status IN ('PENDING','EXPIRED')").fetchone()["n"]
        failed = conn.execute("SELECT COUNT(*) n FROM orders WHERE status='FAILED'").fetchone()["n"]
        return {
            "total_paid": int(total_paid),
            "revenue": int(revenue),
            "today_orders": int(today_orders),
            "pending": int(pending),
            "failed": int(failed),
        }
    finally:
        conn.close()


def gopay_admin_status() -> dict:
    cfg = gopay_config()
    return {
        "base": cfg["base"],
        "token": bool(cfg["token"]),
        "static_qr": bool(cfg["static_qr"]),
        "pending": pay_state_get("gopay_pending", "0"),
        "last_check": pay_state_get("gopay_last_check", ""),
        "last_ok": pay_state_get("gopay_last_ok", ""),
        "last_match": pay_state_get("gopay_last_match", ""),
        "error": pay_state_get("gopay_error", ""),
        "token_invalid": pay_state_get("gopay_token_invalid", ""),
    }


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "hits-ssh"
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
        if content_type.startswith("text/html"):
            self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "
            "form-action 'self'; "
            "img-src 'self' data: blob: https://challenges.cloudflare.com; "
            "font-src 'self' https://challenges.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; "
            "script-src 'self' https://challenges.cloudflare.com; "
            "connect-src 'self' https://challenges.cloudflare.com; "
            "frame-src https://challenges.cloudflare.com; "
            "worker-src 'self' blob:",
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
            if path == "/branding/logo":
                self.serve_brand_file(False, head_only)
                return
            if path == "/branding/favicon":
                self.serve_brand_file(True, head_only)
                return
            if path.startswith("/static/"):
                self.serve_static(path, head_only)
                return
            if path == "/":
                token, cookie = self.public_form_token()
                self.html(200, render_home(token, get_settings()), cookies=[cookie] if cookie else None, head_only=head_only)
                return
            if path == "/gratis" or path == "/gratis/":
                token, cookie = self.public_form_token()
                self.html(200, render_free_page(token, get_settings()), cookies=[cookie] if cookie else None, head_only=head_only)
                return
            if path == "/premium" or path == "/premium/":
                token, cookie = self.public_form_token()
                self.html(200, render_premium_page(token, get_settings()), cookies=[cookie] if cookie else None, head_only=head_only)
                return
            if path == "/kontak" or path == "/kontak/":
                self.html(200, render_contact_page(get_settings()), head_only=head_only)
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
            if path == "/cek-invoice":
                self.check_invoice_page(query, head_only)
                return
            if path.startswith("/api/invoice/"):
                self.api_invoice(path.split("/", 3)[3])
                return
            if path.startswith("/invoice/"):
                self.invoice_page(path.split("/", 2)[2], head_only)
                return
            if path == "/admin" or path == "/admin/":
                session = self.admin_session()
                if not session:
                    self.redirect("/admin/login")
                    return
                msg = (query.get("msg", [""])[0] or "")[:50]
                q = (query.get("q", [""])[0] or "")[:80]
                self.html(
                    200,
                    render_admin_dashboard(session, get_settings(), msg, q),
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

    def serve_brand_file(self, favicon: bool = False, head_only: bool = False) -> None:
        target = brand_logo_path("favicon" if favicon else "logo")
        if not target:
            self._send(404, b"Not found", content_type="text/plain", head_only=head_only)
            return
        ctype = "image/png" if target.suffix.lower() == ".png" else "image/webp"
        self._send(
            200,
            target.read_bytes(),
            content_type=ctype,
            extra_headers={"Cache-Control": "public, max-age=86400"},
            head_only=head_only,
        )

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
            download_output = row["output"] or ""
            if row["service"] == "ssh":
                download_output = format_ssh_output(download_output)
            body = download_output.encode("utf-8")
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
            if path == "/premium/buy":
                self.premium_buy()
                return
            if path == "/cek-invoice":
                self.check_invoice_post()
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
            if path == "/admin/reset-quota":
                self.admin_reset_quota()
                return
            if path == "/admin/premium":
                self.admin_premium()
                return
            if path == "/admin/premium/add":
                self.admin_premium_add()
                return
            if path == "/admin/order/retry":
                self.admin_order_retry()
                return
            if path == "/admin/gopay/test":
                self.admin_gopay_test()
                return
            if path == "/admin/branding":
                self.admin_branding()
                return
            if path == "/admin/theme":
                self.admin_theme()
                return
            if path == "/admin/server":
                self.admin_server()
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
        ts_ok, ts_msg = verify_turnstile(body.get("cf-turnstile-response", ""), self.client_ip())
        if not ts_ok:
            self.html(400, render_error(ts_msg, retry=True))
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

    def premium_buy(self) -> None:
        body = self.parse_body()
        token_cookie = self.cookie(FORM_COOKIE)
        if not token_cookie or not hmac.compare_digest(body.get("_form", ""), token_cookie):
            self.html(400, render_error("Sesi formulir kedaluwarsa. Muat ulang halaman lalu coba lagi."))
            return
        if not rate_ok("premium:" + self.client_ip(), 6, 600):
            self.html(429, render_error("Terlalu banyak percobaan. Tunggu beberapa menit lalu coba lagi."))
            return
        ts_ok, ts_msg = verify_turnstile(body.get("cf-turnstile-response", ""), self.client_ip())
        if not ts_ok:
            self.html(400, render_error(ts_msg, retry=True))
            return
        product_code = body.get("product_code", "").strip()[:40]
        if not re.fullmatch(r"[a-z0-9-]{3,40}", product_code):
            self.html(400, render_error("Paket premium tidak valid."))
            return
        try:
            order = create_premium_order(product_code, self.client_ip(), self.headers.get("User-Agent", ""))
        except ValueError as exc:
            self.html(409, render_error(str(exc), retry=True))
            return
        except Exception:
            logger.error("premium buy: %s", traceback.format_exc())
            self.html(500, render_error("Gagal membuat invoice. Silakan coba lagi atau hubungi admin.", retry=True))
            return
        self.redirect(f"/invoice/{order['invoice']}?new=1")

    def check_invoice_page(self, query: dict, head_only: bool = False) -> None:
        code = (query.get("code", [""])[0] or "").strip().upper()[:80]
        if code:
            if order_by_invoice(code):
                self.redirect(f"/invoice/{code}")
                return
            token, cookie = self.public_form_token()
            self.html(
                404,
                render_check_invoice(token, "Invoice tidak ditemukan.", code),
                cookies=[cookie] if cookie else None,
                head_only=head_only,
            )
            return
        token, cookie = self.public_form_token()
        self.html(
            200,
            render_check_invoice(token, "", ""),
            cookies=[cookie] if cookie else None,
            head_only=head_only,
        )

    def check_invoice_post(self) -> None:
        body = self.parse_body()
        token_cookie = self.cookie(FORM_COOKIE)
        if not token_cookie or not hmac.compare_digest(body.get("_form", ""), token_cookie):
            self.html(400, render_error("Sesi formulir kedaluwarsa. Muat ulang halaman."))
            return
        code = body.get("invoice", "").strip().upper()[:80]
        if not rate_ok("invoice:" + self.client_ip(), 20, 300):
            self.html(429, render_error("Terlalu banyak percobaan. Tunggu beberapa menit."))
            return
        if not re.fullmatch(r"HITS-\d{6}-[A-Z0-9]{8}", code or ""):
            token, cookie = self.public_form_token()
            self.html(400, render_check_invoice(token, "Format invoice tidak valid.", code), cookies=[cookie] if cookie else None)
            return
        if not order_by_invoice(code):
            token, cookie = self.public_form_token()
            self.html(404, render_check_invoice(token, "Invoice tidak ditemukan.", code), cookies=[cookie] if cookie else None)
            return
        self.redirect(f"/invoice/{code}")

    def invoice_page(self, suffix: str, head_only: bool = False) -> None:
        download = suffix.endswith(".txt")
        qr = suffix.endswith("/qr.svg")
        if qr:
            code = suffix[:-7]
        elif download:
            code = suffix[:-4]
        else:
            code = suffix
        code = code.strip().upper()
        if not re.fullmatch(r"HITS-\d{6}-[A-Z0-9]{8}", code or ""):
            self.html(404, render_not_found(), head_only=head_only)
            return
        row = order_by_invoice(code)
        if not row:
            self.html(404, render_not_found(), head_only=head_only)
            return
        if qr:
            svg = gopay_qr_svg(row["qr_string"])
            if not svg:
                self._send(404, b"QR unavailable", content_type="text/plain")
                return
            self._send(200, svg, content_type="image/svg+xml", extra_headers={"Cache-Control": "no-store"}, head_only=head_only)
            return
        if download:
            if row["status"] != "COMPLETED" or not row["account_output"]:
                self.html(409, render_error("Akun belum siap. Selesaikan pembayaran terlebih dahulu."))
                return
            b = branding()
            header = (
                f"{b['name']} PREMIUM\n"
                f"Invoice : {row['invoice']}\n"
                f"Paket   : {row['protocol'].upper()} {row['days']} hari\n"
                f"Total   : Rp {int(row['total']):,}\n"
                f"Dibayar : {fmt_ts(row['paid_at'], '%d %b %Y %H:%M WIB')}\n"
                "----------------------------------------\n\n"
            ).replace(",", ".")
            download_output = row["account_output"] or ""
            if row["protocol"] == "ssh":
                download_output = format_ssh_output(download_output)
            body = (header + download_output).encode("utf-8")
            self._send(
                200,
                body,
                content_type="text/plain; charset=utf-8",
                extra_headers={
                    "Content-Disposition": f'attachment; filename="{row["invoice"]}.txt"',
                    "Cache-Control": "no-store",
                },
                head_only=head_only,
            )
            return
        self.html(
            200,
            render_invoice(row, new=("new=1" in self.path)),
            extra_headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"},
            head_only=head_only,
        )

    def api_invoice(self, code: str) -> None:
        code = (code or "").strip().upper()
        if not re.fullmatch(r"HITS-\d{6}-[A-Z0-9]{8}", code):
            self.json(404, {"ok": False, "error": "not found"})
            return
        row = order_by_invoice(code)
        if not row:
            self.json(404, {"ok": False, "error": "not found"})
            return
        status = row["status"]
        payload = {
            "ok": True,
            "invoice": row["invoice"],
            "status": status,
            "total": row["total"],
            "expires_at": row["expires_at"],
            "username": row["account_username"] if status == "COMPLETED" else "",
            "account": (
                format_ssh_output(row["account_output"])
                if status == "COMPLETED" and row["protocol"] == "ssh"
                else (row["account_output"] if status == "COMPLETED" else "")
            ),
            "error": row["provision_error"] if status == "FAILED" else "",
        }
        self.json(200, payload)

    def admin_premium(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        conn = db_connect()
        try:
            rows = conn.execute("SELECT * FROM premium_products").fetchall()
            for row in rows:
                pid = int(row["id"])
                try:
                    days = max(1, min(365, int(body.get(f"days_{pid}", row["days"]))))
                    price = max(1000, min(10000000, int(body.get(f"price_{pid}", row["price"]))))
                    ip_limit = max(0, min(100, int(body.get(f"ip_{pid}", row["ip_limit"]))))
                    quota = max(0, min(10000, int(body.get(f"quota_{pid}", row["quota_gb"]))))
                except ValueError:
                    continue
                active = 1 if body.get(f"active_{pid}") == "1" else 0
                conn.execute(
                    "UPDATE premium_products SET days=?,price=?,ip_limit=?,quota_gb=?,active=?,updated_at=? WHERE id=?",
                    (days, price, ip_limit, quota, active, int(time.time()), pid),
                )
            conn.commit()
        finally:
            conn.close()
        audit("premium_products", "update", self.client_ip())
        self.redirect("/admin?msg=premium")

    def admin_premium_add(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        protocol = body.get("protocol", "")
        if protocol not in PROTOCOLS and protocol != "ssh":
            self.redirect("/admin?msg=premiumfail")
            return
        try:
            days = max(1, min(365, int(body.get("days", "30"))))
            price = max(1000, min(10000000, int(body.get("price", "10000"))))
            ip_limit = max(0, min(100, int(body.get("ip_limit", "2"))))
            quota = max(0, min(10000, int(body.get("quota_gb", "0"))))
        except ValueError:
            self.redirect("/admin?msg=premiumfail")
            return
        code = f"{protocol}-{days}"
        conn = db_connect()
        try:
            if conn.execute("SELECT 1 FROM premium_products WHERE code=?", (code,)).fetchone():
                self.redirect("/admin?msg=premiumexists")
                return
            label = (body.get("label", "").strip()[:40] or f"{protocol.upper()} {days} Hari")
            sort = int(time.time())
            conn.execute(
                "INSERT INTO premium_products(code,protocol,label,days,price,ip_limit,quota_gb,active,sort,updated_at)"
                " VALUES(?,?,?,?,?,?,?,1,?,?)",
                (code, protocol, label, days, price, ip_limit, quota, sort, int(time.time())),
            )
            conn.commit()
        finally:
            conn.close()
        audit("premium_products", f"add {code}", self.client_ip())
        self.redirect("/admin?msg=premium")

    def admin_order_retry(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        invoice = body.get("invoice", "").strip().upper()
        row = order_by_invoice(invoice)
        if not row:
            self.redirect("/admin?msg=ordernotfound")
            return
        if retry_premium_order(invoice):
            self.redirect("/admin?msg=retryok")
        else:
            self.redirect("/admin?msg=retryfail")

    def admin_gopay_test(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        rows = gopay_history(force=True)
        if rows:
            pay_state_set("gopay_error", "")
            self.redirect("/admin?msg=gopayok")
        else:
            self.redirect("/admin?msg=gopayfail")

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
        supplied = body.get("token", "").strip()
        expected = admin_login_token()
        if not expected:
            time.sleep(0.6)
            self.html(503, render_admin_login(token_cookie, "Token bot Telegram belum tersedia di VPS ini."))
            return
        if not supplied or not hmac.compare_digest(supplied, expected):
            time.sleep(0.6)
            audit("login_failed", "token", ip)
            self.html(401, render_admin_login(token_cookie, "Token admin salah."))
            return
        session_token, _csrf = create_session("admin", ip)
        audit("login", "token", ip)
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
        values["free_enabled"] = "1" if body.get("free_enabled") == "1" else "0"
        values["premium_enabled"] = "1" if body.get("premium_enabled") == "1" else "0"
        for proto in PROTOCOLS:
            values[f"{proto}_enabled"] = "1" if body.get(f"{proto}_enabled") == "1" else "0"
        values["maintenance"] = "1" if body.get("maintenance") == "1" else "0"
        values["contact_telegram"] = normalize_contact_url(body.get("contact_telegram", ""))
        values["contact_group"] = normalize_contact_url(body.get("contact_group", ""))
        values["contact_note"] = body.get("contact_note", "").strip()[:300]
        set_settings(values)
        audit("settings", json.dumps(values, sort_keys=True), self.client_ip())
        self.redirect("/admin?msg=settings")

    def admin_branding(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        values = {
            "brand_name": (body.get("brand_name", "").strip() or BRAND)[:40],
            "brand_accent": body.get("brand_accent", "").strip()[:20],
            "hero_title": (body.get("hero_title", "").strip() or DEFAULT_HERO_TITLE)[:100],
            "hero_title_accent": (body.get("hero_title_accent", "").strip() or DEFAULT_HERO_TITLE_ACCENT)[:100],
            "hero_lead": (body.get("hero_lead", "").strip() or DEFAULT_HERO_LEAD)[:400],
            "meta_description": (body.get("meta_description", "").strip() or DEFAULT_META)[:300],
        }
        logo_error = ""
        if body.get("remove_logo") == "1":
            remove_brand_logo()
            values["brand_logo"] = ""
            values["brand_logo_version"] = ""
        elif body.get("logo_data"):
            ok, result = save_brand_logo(body.get("logo_data", ""))
            if ok:
                values["brand_logo"] = result
                values["brand_logo_version"] = str(int(time.time()))
            else:
                logo_error = result
        set_settings(values)
        audit("branding", f"{values['brand_name']} logo={logo_error or values.get('brand_logo', 'keep')}", self.client_ip())
        self.redirect("/admin?msg=brandingfail" if logo_error else "/admin?msg=branding")

    def admin_theme(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        theme = body.get("ui_theme", "cream").strip()
        if theme not in UI_THEMES:
            self.redirect("/admin?msg=themefail")
            return
        set_settings({"ui_theme": theme})
        audit("theme", theme, self.client_ip())
        self.redirect("/admin?msg=theme")

    def admin_server(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        action = body.get("action", "save")
        if action == "detect":
            info = refresh_server_info(force=True)
            if info:
                audit("server", f"detect {info['code']} {info['city']}", self.client_ip())
                self.redirect("/admin?msg=serverdetect")
            else:
                self.redirect("/admin?msg=serverfail")
            return
        code = body.get("server_country_code", "").strip().upper()
        if code and (len(code) != 2 or not code.isalpha()):
            self.redirect("/admin?msg=serverfail")
            return
        name = body.get("server_country_name", "").strip()[:60]
        if not name and code:
            name = COUNTRY_NAMES.get(code, code)
        values = {
            "server_show": "1" if body.get("server_show") == "1" else "0",
            "server_auto": "0",
            "server_country_code": code,
            "server_country_name": name,
            "server_city": body.get("server_city", "").strip()[:80],
            "server_note": body.get("server_note", "").strip()[:160],
            "server_source": "manual",
            "server_last_check": str(int(time.time())),
        }
        set_settings(values)
        audit("server", f"manual {code} {name}", self.client_ip())
        self.redirect("/admin?msg=server")

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
                "HITS SSH admin\n"
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


def page_shell(title: str, body: str, admin: bool = False, noindex: bool = False, active: str = "", turnstile: bool = False) -> str:
    b = branding()
    brand_name = b["name"]
    brand_html = brand_word_html(brand_name, b["accent"])
    robots = '<meta name="robots" content="noindex,nofollow">' if noindex else ""
    turnstile_script = (
        '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
        if turnstile
        else ""
    )
    if brand_logo_path("favicon"):
        favicon = f'<link rel="icon" href="/branding/favicon?v={e(b["logo_version"])}" type="image/png">'
    else:
        favicon = '<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">'
    if admin:
        header = f"""
<header class="nav nav-admin">
  <div class="wrap nav-inner">
    <a class="brand" href="/" aria-label="{e(brand_name)}">
      <span class="brand-mark">{logomark()}</span>
      <span class="brand-word">{brand_html}</span>
    </a>
    <nav class="nav-links nav-links-inline" aria-label="Menu admin">
      <a href="/admin" class="active">Dashboard</a>
      <a href="/" target="_blank" rel="noopener">Lihat situs</a>
    </nav>
    <a class="nav-cta" href="/" target="_blank" rel="noopener">Lihat situs <span aria-hidden="true">↗</span></a>
  </div>
</header>"""
    else:
        items = [
            ("home", "/", "Beranda"),
            ("premium", "/premium", "Beli Akun"),
            ("free", "/gratis", "Buat Akun Gratis"),
            ("invoice", "/cek-invoice", "Cek Invoice"),
            ("contact", "/kontak", "Kontak / Bantuan"),
        ]
        menu_parts = []
        for key, href, label in items:
            cls = "nav-link" + (" active" if active == key else "")
            aria = ' aria-current="page"' if active == key else ""
            menu_parts.append(f'<a href="{href}" class="{cls}"{aria}>{label}</a>')
        menu = "".join(menu_parts)
        header = f"""
<header class="nav nav-public">
  <div class="wrap nav-inner">
    <a class="brand" href="/" aria-label="{e(brand_name)}">
      <span class="brand-mark">{logomark()}</span>
      <span class="brand-word">{brand_html}</span>
    </a>
    <button class="nav-toggle" id="nav-toggle" type="button" aria-label="Buka menu" aria-expanded="false" aria-controls="site-menu">
      <span></span><span></span><span></span>
    </button>
    <nav class="nav-links" id="site-menu" aria-label="Menu utama">
      <div class="nav-drawer-head"><span class="mini-label">MENU {e(brand_name.upper())}</span></div>
      {menu}
      <a class="nav-drawer-cta" href="/premium">Beli akun premium <span aria-hidden="true">↗</span></a>
      <div class="nav-drawer-foot"><a href="/admin">Admin</a><span>Free &amp; Premium</span></div>
    </nav>
  </div>
</header>
<div class="nav-scrim" id="nav-scrim" hidden></div>"""
    footer = f"""
<footer class="footer">
  <div class="wrap footer-inner">
    <div>
      <div class="brand footer-brand"><span class="brand-mark">{logomark()}</span><span class="brand-word">{brand_html}</span></div>
      <p>Akun VPN gratis dan premium untuk belajar, bekerja, dan menjelajah dengan aman.</p>
    </div>
    <div class="footer-links">
      <a href="/">Beranda</a>
      <a href="/gratis">Akun gratis</a>
      <a href="/premium">Premium</a>
      <a href="/cek-invoice">Cek Invoice</a>
      <a href="/kontak">Kontak</a>
      <a href="/admin">Admin</a>
    </div>
    <div class="footer-note">{e(brand_name)} · Free &amp; Premium · Gunakan dengan bijak.</div>
  </div>
</footer>"""
    return f"""<!doctype html>
<html lang="id" class="theme-{e(b["theme"])}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)} — {e(brand_name)}</title>
<meta name="description" content="{e(b['meta'])}">
<meta name="theme-color" content="{UI_THEME_COLORS.get(b['theme'], '#fffaf2')}">
{robots}
{favicon}
<link rel="stylesheet" href="/static/style.css?v=20261105hits9">
{turnstile_script}
</head>
<body>
{header}
{body}
{footer}
<script src="/static/app.js?v=20261105hits9" defer></script>
</body>
</html>"""


def logomark() -> str:
    if brand_logo_path("logo"):
        b = branding()
        return f'<img class="brand-logo" src="/branding/logo?v={e(b["logo_version"])}" alt="">'
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


def _free_context(settings: dict[str, str]) -> dict:
    quota = quota_state(settings)
    maintenance = settings.get("maintenance") == "1"
    free_on = settings.get("free_enabled", "1") == "1"
    ssh_global = settings.get("ssh_enabled", "1") == "1"
    proto_on = {p: settings.get(f"{p}_enabled", "1") == "1" for p in PROTOCOLS}
    xray_global = settings.get("xray_enabled", "1") == "1" and any(proto_on.values())
    ssh_on = free_on and ssh_global
    xray_on = free_on and xray_global
    available = ssh_on or xray_on
    default_service = "ssh" if ssh_on else ("xray" if xray_on else "")
    first_proto = next((p for p in ("vmess", "vless", "trojan") if proto_on[p]), "")

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

    maintenance_html = (
        '<div class="notice notice-warn"><strong>Mode perawatan.</strong> Pembuatan akun sementara ditutup.</div>'
        if maintenance
        else ""
    )
    closed_html = ""
    if not free_on:
        closed_html = '<div class="notice notice-error"><strong>Kategori gratis ditutup.</strong> Admin sedang menutup pembuatan akun gratis.</div>'
    elif not available:
        closed_html = '<div class="notice notice-error"><strong>Semua layanan gratis ditutup.</strong> Admin sedang menutup pembuatan akun.</div>'

    return {
        "quota": quota,
        "maintenance": maintenance,
        "free_on": free_on,
        "ssh_on": ssh_on,
        "xray_on": xray_on,
        "available": available,
        "default_service": default_service,
        "proto_html": proto_html,
        "maintenance_html": maintenance_html,
        "closed_html": closed_html,
        "proto_on": proto_on,
        "web_config": {
            "free": free_on,
            "ssh": ssh_on,
            "xray": xray_on,
            "protocols": proto_on,
            "maintenance": maintenance,
        },
    }


def _premium_context(settings: dict[str, str]) -> dict:
    maintenance = settings.get("maintenance") == "1"
    free_on = settings.get("free_enabled", "1") == "1"
    ssh_global = settings.get("ssh_enabled", "1") == "1"
    proto_on = {p: settings.get(f"{p}_enabled", "1") == "1" for p in PROTOCOLS}
    xray_global = settings.get("xray_enabled", "1") == "1" and any(proto_on.values())
    premium_on = settings.get("premium_enabled", "1") == "1" and not maintenance
    rows = []
    if premium_on:
        for row in premium_products(active_only=True):
            if row["protocol"] == "ssh" and not ssh_global:
                continue
            if row["protocol"] in PROTOCOLS and (
                not xray_global or not proto_on.get(row["protocol"], False)
            ):
                continue
            rows.append(row)
    premium_on = premium_on and bool(rows)

    data = {
        "products": [
            {
                "code": row["code"],
                "protocol": row["protocol"],
                "label": row["label"],
                "days": row["days"],
                "price": row["price"],
                "ip_limit": row["ip_limit"],
                "quota_gb": row["quota_gb"],
            }
            for row in rows
        ],
        "expiry_min": int(settings.get("premium_expiry_min", "15")),
    }

    cards = ""
    labels = {"ssh": "SSH", "vmess": "VMess", "vless": "VLESS", "trojan": "Trojan"}
    for proto in ("ssh", "vmess", "vless", "trojan"):
        group = [row for row in rows if row["protocol"] == proto]
        if not group:
            continue
        cheapest = min(int(row["price"]) for row in group)
        cards += (
            f'<button class="premium-service" type="button" data-protocol="{proto}">'
            f'<span class="premium-service-icon">{icon("terminal" if proto == "ssh" else "bolt")}</span>'
            f'<b>{labels[proto]}</b>'
            f'<small>mulai {rupiah(cheapest)}</small></button>'
        )

    notice = ""
    if maintenance:
        notice = '<div class="notice notice-warn"><strong>Mode perawatan.</strong> Pembelian premium ditutup sementara.</div>'
    elif not premium_on or not rows:
        notice = '<div class="notice notice-warn"><strong>Premium sedang ditutup.</strong> Admin belum membuka paket jualan.</div>'

    cheapest_all = min((int(row["price"]) for row in rows), default=0)
    return {
        "premium_on": premium_on,
        "rows": rows,
        "data": data,
        "cards": cards,
        "notice": notice,
        "maintenance": maintenance,
        "free_on": free_on,
        "ssh_global": ssh_global,
        "xray_global": xray_global,
        "proto_on": proto_on,
        "cheapest": cheapest_all,
    }


def _page_hero(eyebrow: str, title_html: str, lead: str, chips: str = "") -> str:
    chip_html = f'<div class="page-hero-chips">{chips}</div>' if chips else ""
    return f"""
  <section class="page-hero wrap">
    <div class="page-hero-copy">
      <div class="eyebrow"><span class="dot"></span> {eyebrow}</div>
      <h1>{title_html}</h1>
      <p class="page-hero-lead">{lead}</p>
      {chip_html}
    </div>
    <a class="page-hero-back" href="/">← Beranda</a>
  </section>"""


def render_home(form_token: str, settings: dict[str, str]) -> str:
    fc = _free_context(settings)
    pc = _premium_context(settings)
    b = branding()
    hero_title = b["hero_title"]
    hero_title_accent = b["hero_title_accent"]
    hero_lead = b["hero_lead"]
    quota = fc["quota"]
    total_slots = (
        quota["services"]["ssh"]["3"]["limit"]
        + quota["services"]["ssh"]["7"]["limit"]
        + quota["services"]["xray"]["3"]["limit"]
        + quota["services"]["xray"]["7"]["limit"]
    )
    premium_price = rupiah(pc["cheapest"]) if pc["cheapest"] else "—"
    free_note = "" if fc["free_on"] else '<div class="notice notice-error"><strong>Kategori gratis sedang ditutup.</strong></div>'
    premium_note = "" if pc["premium_on"] else '<div class="notice notice-warn"><strong>Premium sedang ditutup.</strong></div>'
    body = f"""
<main>
  <section class="hero wrap">
    <div class="hero-copy">
      <div class="eyebrow"><span class="dot"></span> FREE &amp; PREMIUM · TANPA LOGIN</div>
      <h1>{e(hero_title)}<br><em>{e(hero_title_accent)}</em></h1>
      <p class="hero-lead">{e(hero_lead)}</p>
      <div class="hero-actions">
        <a class="btn btn-primary" href="/gratis">Buat akun gratis <span aria-hidden="true">↘</span></a>
        <a class="btn btn-ghost" href="/premium">Beli akun premium</a>
      </div>
      <div class="hero-stats">
        <div><strong>{total_slots}</strong><span>slot gratis / hari</span></div>
        <div><strong>{premium_price}</strong><span>mulai premium</span></div>
        <div><strong>00.00</strong><span>reset otomatis WIB</span></div>
      </div>
    </div>
    <div class="hero-art" aria-hidden="true">
      <div class="orbit orbit-a"></div>
      <div class="orbit orbit-b"></div>
      <div class="ticket">
        <div class="ticket-top">
          <div class="ticket-logo">{logomark()}</div>
          <div class="ticket-brand">{brand_word_html(b["name"], b["accent"])}</div>
          <div class="ticket-chip">FREE + PREMIUM</div>
        </div>
        <div class="ticket-tunnel">
          <span class="tunnel t1"></span><span class="tunnel t2"></span><span class="tunnel t3"></span>
          <span class="tunnel-core">{icon('bolt')}</span>
        </div>
        <div class="ticket-rows">
          <div><span>LAYANAN</span><b>SSH / XRAY</b></div>
          <div><span>MASA AKTIF</span><b>3 — 30 HARI</b></div>
          <div><span>PEMBAYARAN</span><b>QRIS GOPAY</b></div>
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

  <section class="section wrap category-section" id="layanan">
    <div class="section-head">
      <div>
        <div class="eyebrow"><span class="dot"></span> PILIH KEBUTUHAN</div>
        <h2>Dua kategori.<br>Satu tempat.</h2>
      </div>
      <p>Gratis untuk coba-coba, premium untuk masa aktif lebih panjang. Keduanya tanpa akun website dan tanpa email.</p>
    </div>
    {free_note}
    {premium_note}
    <div class="category-grid">
      <article class="category-card free-card">
        <div class="category-top"><span class="category-tag">GRATIS</span><span class="category-price">Rp 0</span></div>
        <h3>Akun gratis</h3>
        <p>Cocok untuk uji coba, tugas, dan pemakaian singkat. Kuota dibuat adil per layanan.</p>
        <ul>
          <li>SSH, VMess, VLESS, Trojan</li>
          <li>Masa aktif 3 atau 7 hari</li>
          <li>Kuota harian, reset 00.00 WIB</li>
          <li>Limit IP diatur admin</li>
        </ul>
        <a class="btn btn-primary btn-block" href="/gratis">Buat akun gratis <span aria-hidden="true">↗</span></a>
      </article>
      <article class="category-card premium-card">
        <div class="category-top"><span class="category-tag">PREMIUM</span><span class="category-price">{premium_price}</span></div>
        <h3>Akun premium</h3>
        <p>Masa aktif lebih panjang, limit IP dan kuota per paket, tanpa kuota pembelian harian.</p>
        <ul>
          <li>Multi-durasi 3 / 7 / 30 hari</li>
          <li>SSH, VMess, VLESS, Trojan</li>
          <li>Bayar QRIS GoPay</li>
          <li>Invoice bisa dicek ulang</li>
        </ul>
        <a class="btn btn-dark btn-block" href="/premium">Beli akun premium <span aria-hidden="true">↗</span></a>
      </article>
    </div>
  </section>

  <section class="section wrap steps" id="cara">
    <div class="section-head"><div><div class="eyebrow"><span class="dot"></span> CARA PAKAI</div><h2>Tiga langkah, langsung terhubung.</h2></div></div>
    <div class="step-grid">
      <article><span class="step-num">01</span><h3>Pilih layanan</h3><p>Buat akun gratis, atau pilih paket premium sesuai masa aktif.</p></article>
      <article><span class="step-num">02</span><h3>Simpan data</h3><p>Gratis: salin output. Premium: simpan invoice lalu unduh file .txt.</p></article>
      <article><span class="step-num">03</span><h3>Impor ke aplikasi</h3><p>Masukkan host, port, dan kredensial ke aplikasi tunnel pilihan Anda.</p></article>
    </div>
  </section>

  <section class="section wrap faq" id="faq">
    <div class="section-head"><div><div class="eyebrow"><span class="dot"></span> FAQ</div><h2>Pertanyaan yang sering muncul.</h2></div></div>
    <div class="faq-list">
      <details><summary>Apakah akun gratis benar-benar gratis?</summary><p>Ya. Tidak ada pembayaran, email, atau pendaftaran. Kuota harian dibatasi agar layanan tetap tersedia untuk semua orang.</p></details>
      <details><summary>Apa bedanya akun gratis dan premium?</summary><p>Akun gratis memakai kuota harian dan masa aktif 3–7 hari. Premium berbayar, tanpa kuota pembelian harian, dengan masa aktif dan limit yang diatur per paket.</p></details>
      <details><summary>Bagaimana kalau saya lupa invoice premium?</summary><p>Buka halaman Cek Invoice, lalu masukkan kode invoice yang tampil setelah pembelian. Tidak perlu login.</p></details>
      <details><summary>Apakah akun bisa dipakai di beberapa perangkat?</summary><p>Bisa, selama jumlah IP yang login tidak melebihi batas paket. Pelanggaran limit IP dapat menyebabkan akun dibekukan sementara.</p></details>
      <details><summary>Butuh bantuan lain?</summary><p>Buka halaman <a href="/kontak">Kontak / Bantuan</a>. Admin dapat mengatur link Telegram atau grup komunitas dari dashboard.</p></details>
    </div>
  </section>
</main>
"""
    return page_shell("Beranda", body, active="home")


def render_free_page(form_token: str, settings: dict[str, str]) -> str:
    fc = _free_context(settings)
    quota = fc["quota"]
    ts_site, _ts_secret, ts_on = turnstile_config()
    server_strip = server_strip_html()
    ts_widget = (
        '<div class="turnstile-box">'
        f'<div class="cf-turnstile" data-sitekey="{e(ts_site)}" data-theme="light" data-language="id" data-size="flexible"></div>'
        '<small class="turnstile-status" data-turnstile-status>Memuat verifikasi keamanan…</small>'
        '</div>'
        if ts_on
        else ""
    )
    quota_json = json.dumps(quota, ensure_ascii=False).replace("</", "<\\/")
    web_config_json = json.dumps(fc["web_config"], ensure_ascii=False).replace("</", "<\\/")
    chips = (
        f'<span class="page-chip">{quota["services"]["ssh"]["3"]["limit"] + quota["services"]["ssh"]["7"]["limit"] + quota["services"]["xray"]["3"]["limit"] + quota["services"]["xray"]["7"]["limit"]} slot / hari</span>'
        '<span class="page-chip">Reset 00.00 WIB</span>'
        f'<span class="page-chip">Batas {e(settings.get("per_ip_daily", "2"))} akun / IP</span>'
    )
    hero = _page_hero(
        "KATEGORI GRATIS",
        "Akun gratis,<br><em>langsung jadi.</em>",
        "Pilih layanan dan masa aktif. Akun dibuat langsung di server, tanpa email dan tanpa login website.",
        chips,
    )
    body = f"""
<main>
{hero}
  <section class="section wrap free-section page-section" id="gratis">
    {fc['maintenance_html']}
    {fc['closed_html']}
    <form class="creator panel" method="post" action="/buat" id="create-form" novalidate>
      <input type="hidden" name="_form" value="{e(form_token)}">
      <div class="creator-grid">
        <fieldset class="field-group">
          <legend><span>01</span> Pilih layanan</legend>
          <div class="service-grid">
            <label class="service-card {'selected' if fc['default_service'] == 'ssh' else ''}{' is-off' if not fc['ssh_on'] else ''}" data-service-card="ssh" data-enabled="{1 if fc['ssh_on'] else 0}">
              <input type="radio" name="service" value="ssh" {'checked' if fc['default_service'] == 'ssh' else ''} {'disabled' if not fc['ssh_on'] else ''}>
              <span class="service-icon">{icon('terminal')}</span>
              <span class="service-copy"><b>SSH</b><small>{'OpenSSH · Dropbear · WS · SSL' if fc['ssh_on'] else 'Dinonaktifkan admin'}</small></span>
              <span class="checkmark" aria-hidden="true">✓</span>
            </label>
            <label class="service-card {'selected' if fc['default_service'] == 'xray' else ''}{' is-off' if not fc['xray_on'] else ''}" data-service-card="xray" data-enabled="{1 if fc['xray_on'] else 0}">
              <input type="radio" name="service" value="xray" {'checked' if fc['default_service'] == 'xray' else ''} {'disabled' if not fc['xray_on'] else ''}>
              <span class="service-icon">{icon('bolt')}</span>
              <span class="service-copy"><b>Xray</b><small>{'Pilih VMess, VLESS, atau Trojan' if fc['xray_on'] else 'Dinonaktifkan admin'}</small></span>
              <span class="checkmark" aria-hidden="true">✓</span>
            </label>
          </div>
          <div class="protocol-wrap" id="protocol-wrap" {'' if fc['default_service'] == 'xray' else 'hidden'}>
            <span class="mini-label">Protokol Xray</span>
            <div class="protocol-grid">
              {fc['proto_html']}
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

      {server_strip}
      {ts_widget}
      <div class="creator-bottom">
        <div class="quota-readout" id="quota-readout" aria-live="polite">
          <div class="quota-ring" id="quota-ring"><span id="quota-remaining">—</span></div>
          <div>
            <strong id="quota-title">Memuat kuota…</strong>
            <p id="quota-sub">Kuota global per layanan.</p>
          </div>
        </div>
        <div class="reset-box"><span class="reset-label">RESET DALAM</span><b id="reset-countdown">--:--:--</b><small>WIB</small></div>
        <button class="btn btn-primary btn-create" type="submit" id="create-button" {'disabled' if fc['maintenance'] or not fc['available'] else ''}>Buat akun <span aria-hidden="true">↗</span></button>
      </div>
      <p class="form-note">Dengan membuat akun, Anda setuju menggunakan layanan secara wajar. Satu IP dibatasi <b>{e(settings.get('per_ip_daily', '2'))} akun</b> per layanan per hari.</p>
    </form>
    <div class="quota-strip">
      <div class="quota-item"><span>SSH · 3 hari</span><b data-quota-chip="ssh-3">—</b><i><u data-quota-fill="ssh-3"></u></i></div>
      <div class="quota-item"><span>SSH · 7 hari</span><b data-quota-chip="ssh-7">—</b><i><u data-quota-fill="ssh-7"></u></i></div>
      <div class="quota-item"><span>Xray · 3 hari</span><b data-quota-chip="xray-3">—</b><i><u data-quota-fill="xray-3"></u></i></div>
      <div class="quota-item"><span>Xray · 7 hari</span><b data-quota-chip="xray-7">—</b><i><u data-quota-fill="xray-7"></u></i></div>
    </div>
    <div class="page-crosslink panel">
      <div><b>Butuh masa aktif lebih panjang?</b><p>Paket premium tersedia tanpa kuota pembelian harian.</p></div>
      <a class="btn btn-ghost btn-small" href="/premium">Lihat premium</a>
    </div>
  </section>
</main>
<script type="application/json" id="quota-data">{quota_json}</script>
<script type="application/json" id="web-config">{web_config_json}</script>
"""
    return page_shell("Buat Akun Gratis", body, active="free", turnstile=ts_on)


def render_premium_page(form_token: str, settings: dict[str, str]) -> str:
    pc = _premium_context(settings)
    b = branding()
    premium_json = json.dumps(pc["data"], ensure_ascii=False).replace("</", "<\\/")
    ts_site, _ts_secret, ts_on = turnstile_config()
    server_strip = server_strip_html()
    ts_widget = (
        '<div class="turnstile-box premium-turnstile">'
        f'<div class="cf-turnstile" data-sitekey="{e(ts_site)}" data-theme="light" data-language="id" data-size="flexible"></div>'
        '<small class="turnstile-status" data-turnstile-status>Memuat verifikasi keamanan…</small>'
        '</div>'
        if ts_on
        else ""
    )
    chips = (
        f'<span class="page-chip">Mulai {rupiah(pc["cheapest"])}</span>'
        f'<span class="page-chip">Invoice {e(settings.get("premium_expiry_min", "15"))} menit</span>'
        '<span class="page-chip">QRIS GoPay</span>'
    )
    hero = _page_hero(
        e(b["name"].upper()) + " PREMIUM",
        "Beli sekali.<br><em>Tanpa login.</em>",
        "Pilih layanan dan masa aktif, bayar QRIS GoPay, lalu simpan invoice. Akun dibuat otomatis setelah pembayaran terdeteksi.",
        chips,
    )
    body = f"""
<main>
{hero}
  <section class="section wrap premium-section page-section" id="premium">
    {pc['notice']}
    <div class="premium-layout">
      <div class="premium-picker panel">
        <div class="premium-step">
          <span class="mini-label">01 · PILIH LAYANAN</span>
          <div class="premium-services" id="premium-services">{pc['cards']}</div>
        </div>
        <div class="premium-step">
          <span class="mini-label">02 · PILIH MASA AKTIF</span>
          <div class="premium-durations" id="premium-durations">
            <p class="premium-hint">Pilih layanan terlebih dahulu.</p>
          </div>
        </div>
        {server_strip}
        <div class="premium-summary" id="premium-summary" hidden>
          <div><span>Paket</span><b id="premium-summary-name">—</b></div>
          <div><span>Harga</span><b id="premium-summary-price">—</b></div>
          <div><span>Masa aktif</span><b id="premium-summary-days">—</b></div>
        </div>
        <form id="premium-form" method="post" action="/premium/buy">
          <input type="hidden" name="_form" value="{e(form_token)}">
          <input type="hidden" name="product_code" id="premium-product" value="">
          {ts_widget}
          <button class="btn btn-primary btn-block btn-premium" type="submit" id="premium-button" disabled>
            Beli via QRIS <span aria-hidden="true">↗</span>
          </button>
        </form>
        <p class="form-note">Total pembayaran ditambah <b>kode unik Rp1–999</b> agar tidak tertukar dengan pembeli lain. Nominal persis tertera di invoice.</p>
      </div>
      <aside class="premium-side">
        <div class="panel premium-info">
          <div class="premium-badge">QRIS GOPAY</div>
          <h3>Bayar dari mana saja.</h3>
          <p>Scan QRIS dengan GoPay, OVO, DANA, ShopeePay, atau m-banking. Akun dibuat otomatis setelah transaksi terdeteksi.</p>
          <ul>
            <li>Tanpa daftar dan tanpa login.</li>
            <li>Invoice {e(settings.get("premium_expiry_min", "15"))} menit dan bisa dicek ulang.</li>
            <li>Download detail akun <b>.txt</b> setelah lunas.</li>
          </ul>
        </div>
        <div class="panel check-card">
          <span class="mini-label">SUDAH BELI?</span>
          <h3>Cek Invoice</h3>
          <p>Masukkan kode invoice untuk membuka kembali QR, status pembayaran, dan data akun.</p>
          <a class="btn btn-dark btn-block" href="/cek-invoice">Buka Cek Invoice</a>
        </div>
        <div class="panel premium-info compact-info">
          <span class="mini-label">ALUR SINGKAT</span>
          <ol class="mini-steps">
            <li>Pilih paket dan masa aktif.</li>
            <li>Scan QRIS sesuai nominal.</li>
            <li>Salin invoice, tunggu akun aktif.</li>
            <li>Unduh detail akun <b>.txt</b>.</li>
          </ol>
        </div>
      </aside>
    </div>
    <script type="application/json" id="premium-data">{premium_json}</script>
  </section>
  <section class="section wrap page-section">
    <div class="page-crosslink panel">
      <div><b>Belum siap membeli?</b><p>Gunakan akun gratis dulu untuk mencoba layanan.</p></div>
      <a class="btn btn-ghost btn-small" href="/gratis">Buat akun gratis</a>
    </div>
  </section>
</main>
"""
    return page_shell("Beli Akun Premium", body, active="premium", turnstile=ts_on)


def normalize_contact_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if re.match(r"^https?://", value, re.I):
        return value[:300]
    if value.startswith("@"):
        return ("https://t.me/" + value[1:])[:300]
    if re.match(r"^t\.me/", value, re.I):
        return ("https://" + value)[:300]
    return ""


def render_contact_page(settings: dict[str, str]) -> str:
    telegram = normalize_contact_url(settings.get("contact_telegram", ""))
    group = normalize_contact_url(settings.get("contact_group", ""))
    note = (settings.get("contact_note", "") or "").strip()[:300]
    links = ""
    if telegram:
        links += f"""
        <a class="contact-card panel" href="{e(telegram)}" target="_blank" rel="noopener">
          <span class="contact-icon">{icon('terminal')}</span>
          <span><b>Telegram Admin</b><small>Chat langsung untuk bantuan akun dan pembayaran.</small></span>
          <span class="contact-arrow" aria-hidden="true">↗</span>
        </a>"""
    if group:
        links += f"""
        <a class="contact-card panel" href="{e(group)}" target="_blank" rel="noopener">
          <span class="contact-icon">{icon('globe')}</span>
          <span><b>Grup Komunitas</b><small>Info server, tips, dan diskusi sesama pengguna.</small></span>
          <span class="contact-arrow" aria-hidden="true">↗</span>
        </a>"""
    if not links:
        links = """
        <div class="notice notice-warn contact-empty"><strong>Link kontak belum diatur.</strong> Admin dapat mengisi link Telegram atau grup dari Dashboard → Pengaturan → Kontak &amp; Bantuan.</div>"""
    note_html = f'<div class="contact-note panel"><span class="mini-label">CATATAN ADMIN</span><p>{e(note)}</p></div>' if note else ""
    chips = '<span class="page-chip">Tanpa login</span><span class="page-chip">Bantuan akun</span><span class="page-chip">Invoice premium</span>'
    hero = _page_hero(
        "KONTAK / BANTUAN",
        "Butuh bantuan?<br><em>Hubungi kami.</em>",
        "Untuk kendala akun, pembayaran, atau invoice, gunakan kanal resmi di bawah ini. Sertakan kode invoice jika menyangkut pembelian premium.",
        chips,
    )
    body = f"""
<main>
{hero}
  <section class="section wrap page-section">
    <div class="contact-grid">
      <div class="contact-links">{links}</div>
      <aside class="contact-side">
        {note_html}
        <div class="panel contact-help">
          <span class="mini-label">BANTUAN CEPAT</span>
          <h3>Sebelum menghubungi admin</h3>
          <ul>
            <li><b>Lupa akun premium?</b> Buka <a href="/cek-invoice">Cek Invoice</a> dengan kode invoice.</li>
            <li><b>Pembayaran sudah masuk?</b> Tunggu ±45 detik, lalu muat ulang invoice.</li>
            <li><b>Akun gagal dibuat?</b> Simpan invoice dan hubungi admin untuk retry.</li>
            <li><b>Kuota gratis habis?</b> Kuota di-reset otomatis pukul 00.00 WIB.</li>
          </ul>
          <div class="contact-actions">
            <a class="btn btn-ghost btn-small" href="/cek-invoice">Cek Invoice</a>
            <a class="btn btn-dark btn-small" href="/gratis">Buat akun gratis</a>
          </div>
        </div>
      </aside>
    </div>
  </section>
</main>
"""
    return page_shell("Kontak & Bantuan", body, active="contact")


def render_result(row: sqlite3.Row) -> str:
    service = SERVICES.get(row["service"], {"label": row["service"]})
    protocol = PROTOCOLS.get(row["protocol"], {}).get("label", "")
    label = service["label"] + (f" · {protocol}" if protocol else "")
    raw_output = row["output"] or ""
    if row["service"] == "ssh":
        raw_output = format_ssh_output(raw_output)
    output = e(raw_output)
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
    b = branding()
    body = f"""
<main class="admin-login wrap">
  <div class="login-card panel">
    <div class="login-brand"><span class="brand-mark">{logomark()}</span><span class="brand-word">{brand_word_html(b["name"], b["accent"])}</span></div>
    <div class="eyebrow"><span class="dot"></span> ADMIN PANEL</div>
    <h1>Masuk dengan token.</h1>
    <p>Tempel Token Bot Telegram. Tidak perlu username atau password.</p>
    {err}
    <form method="post" action="/admin/login" class="stack-form">
      <input type="hidden" name="_form" value="{e(form_token)}">
      <label>Token Bot Telegram
        <input type="password" name="token" autocomplete="off" spellcheck="false" required autofocus placeholder="123456789:AA...">
      </label>
      <button class="btn btn-primary btn-block" type="submit">Masuk</button>
    </form>
    <p class="form-note login-help">Ambil token di VPS:<br><code>awk '/^#bot# /{{print $2}}' /etc/bot/.bot.db</code></p>
    <a class="back-link" href="/">← Kembali ke situs</a>
  </div>
</main>
"""
    return page_shell("Admin", body, admin=True, noindex=True)


def render_admin_dashboard(session: sqlite3.Row, settings: dict[str, str], msg: str, q: str = "") -> str:
    quota = quota_state(settings)
    products = premium_products(active_only=False)
    pstats = premium_stats()
    gstat = gopay_admin_status()
    like = f"%{q}%"
    conn = db_connect()
    try:
        total = conn.execute("SELECT COUNT(*) n FROM accounts WHERE status='active'").fetchone()["n"]
        today = conn.execute(
            "SELECT COUNT(*) n FROM accounts WHERE status='active' AND created_day=?",
            (today_key(),),
        ).fetchone()["n"]
        accounts = conn.execute(
            "SELECT * FROM accounts WHERE status='active' ORDER BY id DESC LIMIT 60"
        ).fetchall()
        orders = conn.execute(
            "SELECT * FROM orders WHERE (?='' OR invoice LIKE ? OR account_username LIKE ? OR buyer_ip LIKE ?)"
            " ORDER BY id DESC LIMIT 100",
            (q, like, like, like),
        ).fetchall()
        recent_audit = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 10").fetchall()
    finally:
        conn.close()

    messages = {
        "settings": ("ok", "Pengaturan disimpan."),
        "deleted": ("ok", "Akun website berhasil dihapus."),
        "notfound": ("error", "Akun tidak ditemukan atau sudah dihapus."),
        "deletefail": ("error", "Akun gagal dihapus. Cek log server."),
        "quota": ("ok", "Hitungan kuota hari ini di-reset (akun tidak dihapus)."),
        "premium": ("ok", "Pengaturan paket premium disimpan."),
        "premiumfail": ("error", "Data paket premium tidak valid."),
        "premiumexists": ("error", "Paket dengan kode itu sudah ada."),
        "retryok": ("ok", "Akun premium berhasil dibuat ulang."),
        "retryfail": ("error", "Retry gagal. Cek error provisioning."),
        "ordernotfound": ("error", "Invoice tidak ditemukan."),
        "gopayok": ("ok", "Gateway GoPay merespons dan history berhasil dibaca."),
        "gopayfail": ("error", "Gagal membaca history GoPay. Cek status gateway/token."),
        "branding": ("ok", "Branding disimpan. Perubahan langsung dipakai di semua halaman."),
        "brandingfail": ("error", "Logo gagal diproses. Periksa format, ukuran minimal 128×128, dan ukuran file."),
        "theme": ("ok", "Tema UI diterapkan ke website dan dashboard."),
        "themefail": ("error", "Tema tidak dikenal. Pilih salah satu tema yang tersedia."),
        "server": ("ok", "Info server disimpan dan tampil di halaman free & premium."),
        "serverdetect": ("ok", "Lokasi server berhasil dideteksi otomatis dari IP VPS."),
        "serverfail": ("error", "Gagal mendeteksi lokasi server. Isi kode negara manual atau coba lagi."),
    }
    notice = ""
    if msg in messages:
        kind, text = messages[msg]
        notice = f'<div class="notice notice-{kind}">{e(text)}</div>'

    quota_rows = ""
    for service in ("ssh", "xray"):
        for days in (3, 7):
            qq = quota["services"][service][str(days)]
            pct = (qq["used"] / qq["limit"] * 100) if qq["limit"] else 0
            quota_rows += (
                f'<div class="quota-item"><span>{e(SERVICES[service]["label"])} · {days} hari</span>'
                f'<b>{qq["used"]} / {qq["limit"]}</b><i><u style="width:{min(100, pct):.1f}%"></u></i></div>'
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
        account_rows = '<tr><td colspan="6" class="empty">Belum ada akun free yang dibuat lewat website.</td></tr>'

    product_rows = ""
    for row in products:
        pid = int(row["id"])
        proto = "SSH" if row["protocol"] == "ssh" else PROTOCOLS.get(row["protocol"], {}).get("label", row["protocol"])
        product_rows += f"""
        <tr>
          <td><b>{e(proto)}</b><small>{e(row['code'])}</small></td>
          <td><input class="mini-input" type="number" name="days_{pid}" min="1" max="365" value="{int(row['days'])}"></td>
          <td><input class="mini-input" type="number" name="price_{pid}" min="1000" max="10000000" value="{int(row['price'])}"></td>
          <td><input class="mini-input" type="number" name="ip_{pid}" min="0" max="100" value="{int(row['ip_limit'])}"></td>
          <td><input class="mini-input" type="number" name="quota_{pid}" min="0" max="10000" value="{int(row['quota_gb'])}"></td>
          <td class="center"><input type="checkbox" name="active_{pid}" value="1" {'checked' if row['active'] else ''}></td>
        </tr>"""
    if not product_rows:
        product_rows = '<tr><td colspan="6" class="empty">Belum ada paket premium.</td></tr>'

    order_rows = ""
    for row in orders:
        status_map = {
            "PENDING": ("badge-warn", "Pending"),
            "PAID": ("badge-warn", "Paid"),
            "PROVISIONING": ("badge-warn", "Proses"),
            "COMPLETED": ("badge-ok", "Sukses"),
            "FAILED": ("badge-bad", "Gagal akun"),
            "EXPIRED": ("badge-muted", "Expired"),
        }
        cls, txt = status_map.get(row["status"], ("badge-muted", row["status"]))
        action = ""
        if row["status"] in ("PAID", "FAILED"):
            action = f"""
            <form method="post" action="/admin/order/retry" class="inline-form" data-confirm="Coba buat akun untuk invoice {e(row['invoice'])}?">
              <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
              <input type="hidden" name="invoice" value="{e(row['invoice'])}">
              <button class="btn btn-tiny btn-dark" type="submit">Retry</button>
            </form>"""
        if row["status"] == "COMPLETED":
            action = f'<a class="btn btn-tiny btn-ghost" href="/invoice/{e(row["invoice"])}.txt" download>TXT</a>'
        order_rows += f"""
        <tr>
          <td><a class="invoice-link" href="/invoice/{e(row['invoice'])}" target="_blank" rel="noopener"><b>{e(row['invoice'])}</b></a><small>{e(row['buyer_ip'])}</small></td>
          <td>{e(row['protocol'].upper())}<small>{row['days']} hari</small></td>
          <td><b>{rupiah(row['total'])}</b><small>+{rupiah(row['unique_code'])}</small></td>
          <td>{e(fmt_ts(row['created_at'], '%d %b %H:%M'))}</td>
          <td><span class="badge {cls}">{e(txt)}</span></td>
          <td>{e(row['account_username'] or '-')}<small>{e((row['provision_error'] or '')[:42])}</small></td>
          <td>{action}</td>
        </tr>"""
    if not order_rows:
        order_rows = '<tr><td colspan="7" class="empty">Belum ada transaksi premium.</td></tr>'

    audit_rows = "".join(
        f"<li><span>{e(fmt_ts(a['at'], '%d %b %H:%M'))}</span><b>{e(a['action'])}</b><small>{e(a['detail'])}</small></li>"
        for a in recent_audit
    ) or "<li class='empty'>Belum ada aktivitas.</li>"

    gopay_ok = gstat["token"] and gstat["static_qr"]
    gopay_badge = '<span class="badge badge-ok">Siap</span>' if gopay_ok else '<span class="badge badge-bad">Belum siap</span>'
    gopay_error = gstat["error"]
    gopay_error_html = f'<div class="notice notice-error compact-notice">{e(gopay_error)}</div>' if gopay_error else ""
    last_check = fmt_ts(int(gstat["last_check"]), "%d %b %H:%M:%S") if str(gstat["last_check"]).isdigit() else "-"
    last_match = fmt_ts(int(gstat["last_match"]), "%d %b %H:%M:%S") if str(gstat["last_match"]).isdigit() else "-"
    token_warn = ""
    if gstat["token_invalid"]:
        token_warn = '<div class="notice notice-warn compact-notice">Token GoPay expired. Buka bot Telegram → Store Admin → GoPay → Login OTP, lalu klik Test GoPay.</div>'
    b = branding()
    logo_path = brand_logo_path("logo")
    logo_preview_src = f"/branding/logo?v={e(b['logo_version'])}" if logo_path else "/static/favicon.svg"
    logo_label = "Logo kustom aktif" if logo_path else "Belum ada logo kustom"
    current_theme = b["theme"]
    sv = server_info()
    sv_last = fmt_ts(int(sv["last_check"]), "%d %b %Y %H:%M WIB") if str(sv["last_check"]).isdigit() else "Belum pernah"
    sv_source = sv["source"] or "-"
    theme_cards = ""
    for theme_key, (theme_label, theme_desc) in UI_THEMES.items():
        theme_cards += (
            f'<label class="theme-option{" selected" if current_theme == theme_key else ""}">'
            f'<input type="radio" name="ui_theme" value="{theme_key}"'
            f'{" checked" if current_theme == theme_key else ""}>'
            f'<span class="theme-swatch theme-{theme_key}"><i></i><i></i><i></i></span>'
            f'<b>{e(theme_label)}</b><small>{e(theme_desc)}</small></label>'
        )

    body = f"""
<main class="admin-main wrap">
  <div class="admin-head">
    <div><div class="eyebrow"><span class="dot"></span> {e(b["name"].upper())} ADMIN</div><h1>Kendali penuh.</h1><p>Free, premium, invoice, dan pembayaran GoPay dalam satu dashboard.</p></div>
    <div class="admin-head-actions">
      <a class="btn btn-ghost" href="/" target="_blank" rel="noopener">Lihat situs</a>
      <form method="post" action="/admin/logout"><button class="btn btn-ghost" type="submit">Keluar</button></form>
    </div>
  </div>
  {notice}
  <div class="admin-stats four">
    <div class="stat-card"><span>Akun free aktif</span><strong>{total}</strong><small>{today} dibuat hari ini</small></div>
    <div class="stat-card"><span>Invoice premium</span><strong>{pstats['total_paid']}</strong><small>{pstats['pending']} pending · {pstats['failed']} gagal akun</small></div>
    <div class="stat-card accent"><span>Pendapatan premium</span><strong>{rupiah(pstats['revenue'])}</strong><small>transaksi sukses</small></div>
    <div class="stat-card"><span>GoPay gateway</span><strong>{'ON' if gopay_ok else 'OFF'}</strong><small>{e(gstat['base'])}</small></div>
  </div>

  <section class="panel admin-panel branding-panel">
    <div class="panel-head"><div><span class="mini-label">BRANDING</span><h2>Logo, nama &amp; slogan</h2></div><span class="panel-hint">Berlaku di semua halaman dan notifikasi.</span></div>
    <form method="post" action="/admin/branding" class="branding-form">
      <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
      <input type="hidden" name="logo_data" id="brand-logo-data" value="">
      <div class="branding-grid">
        <fieldset>
          <legend>Identitas website</legend>
          <label>Nama brand
            <input type="text" name="brand_name" value="{e(settings.get('brand_name', BRAND))}" maxlength="40" required>
          </label>
          <label>Bagian yang diwarnai
            <input type="text" name="brand_accent" value="{e(settings.get('brand_accent', ''))}" maxlength="20" placeholder="SSH">
            <small>Harus bagian dari nama brand. Kosongkan jika tidak ingin aksen warna.</small>
          </label>
          <label>Meta description
            <textarea name="meta_description" rows="2" maxlength="300">{e(settings.get('meta_description', DEFAULT_META))}</textarea>
          </label>
        </fieldset>
        <fieldset>
          <legend>Logo mark</legend>
          <div class="brand-logo-row">
            <div class="brand-logo-preview"><img id="brand-logo-preview" src="{logo_preview_src}" alt="Logo saat ini"></div>
            <div class="brand-logo-copy">
              <input type="file" id="brand-logo-input" accept="image/png,image/jpeg,image/webp">
              <small id="brand-logo-name">{logo_label}</small>
              <small>Persegi, minimal 128×128, maksimal 2 MB. Otomatis crop tengah dan resize 256×256.</small>
              <button type="submit" name="remove_logo" value="1" class="btn btn-tiny btn-danger" data-confirm="Hapus logo kustom dan kembali ke ikon default?">Hapus logo</button>
            </div>
          </div>
        </fieldset>
      </div>
      <fieldset class="branding-slogan">
        <legend>Slogan hero</legend>
        <div class="settings-grid two">
          <label>Baris pertama<input type="text" name="hero_title" value="{e(settings.get('hero_title', DEFAULT_HERO_TITLE))}" maxlength="100"></label>
          <label>Baris kedua (aksen)<input type="text" name="hero_title_accent" value="{e(settings.get('hero_title_accent', DEFAULT_HERO_TITLE_ACCENT))}" maxlength="100"></label>
        </div>
        <label>Paragraf pembuka<textarea name="hero_lead" rows="3" maxlength="400">{e(settings.get('hero_lead', DEFAULT_HERO_LEAD))}</textarea></label>
      </fieldset>
      <div class="branding-preview">
        <span class="mini-label">PRATINJAU BRAND</span>
        <div class="brand"><span class="brand-mark">{logomark()}</span><span class="brand-word">{brand_word_html(b['name'], b['accent'])}</span></div>
        <p>{e(settings.get('hero_title', DEFAULT_HERO_TITLE))} <em>{e(settings.get('hero_title_accent', DEFAULT_HERO_TITLE_ACCENT))}</em></p>
      </div>
      <div class="form-actions"><button class="btn btn-primary btn-small" type="submit">Simpan branding</button></div>
    </form>
  </section>

  <section class="panel admin-panel theme-panel">
    <div class="panel-head"><div><span class="mini-label">TEMA UI</span><h2>Warna website &amp; dashboard</h2></div><span class="badge badge-ok">{e(UI_THEMES[current_theme][0])} aktif</span></div>
    <form method="post" action="/admin/theme" class="theme-form">
      <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
      <div class="theme-grid">{theme_cards}</div>
      <p class="panel-hint">Warna font otomatis menyesuaikan: tema terang memakai teks gelap, tema gelap memakai teks terang.</p>
      <div class="form-actions"><button class="btn btn-primary btn-small" type="submit">Terapkan tema</button></div>
    </form>
  </section>

  <section class="panel admin-panel server-panel">
    <div class="panel-head"><div><span class="mini-label">KETERANGAN SERVER</span><h2>Lokasi server</h2></div><span class="badge badge-ok">{sv['flag']} {e(sv['name'] or 'Belum diatur')}</span></div>
    <form method="post" action="/admin/server" class="server-form">
      <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
      <div class="settings-grid">
        <fieldset>
          <legend>Info yang tampil</legend>
          <label>Kode negara (2 huruf)<input type="text" name="server_country_code" value="{e(sv['code'])}" maxlength="2" placeholder="SG" style="text-transform:uppercase"></label>
          <label>Nama negara<input type="text" name="server_country_name" value="{e(sv['name'])}" maxlength="60" placeholder="Singapura"></label>
          <label>Kota (opsional)<input type="text" name="server_city" value="{e(sv['city'])}" maxlength="80" placeholder="Singapore"></label>
          <label>Catatan (opsional)<input type="text" name="server_note" value="{e(sv['note'])}" maxlength="160" placeholder="Lokasi VPS · Asia Tenggara"></label>
          <label class="switch"><input type="checkbox" name="server_show" value="1" {'checked' if sv['show'] else ''}><span>Tampilkan info server di halaman free &amp; premium</span></label>
        </fieldset>
        <fieldset>
          <legend>Deteksi otomatis</legend>
          <div class="server-preview">
            <span>{sv['flag']}</span>
            <div><b>{e(sv['name'] or 'Belum terdeteksi')}</b><small>{e(sv['city'] or 'Kota belum diketahui')}</small></div>
          </div>
          <p class="panel-hint">Sumber: <b>{e(sv_source)}</b><br>Terakhir dicek: <b>{e(sv_last)}</b></p>
          <p class="panel-hint">Deteksi memakai IP publik VPS. Jika pindah VPS, klik tombol ini atau install ulang website.</p>
          <button class="btn btn-ghost btn-small" type="submit" name="action" value="detect">Deteksi otomatis dari IP VPS</button>
        </fieldset>
      </div>
      <div class="form-actions"><button class="btn btn-primary btn-small" type="submit" name="action" value="save">Simpan info server</button></div>
    </form>
  </section>

  <div class="admin-grid">
    <section class="panel admin-panel">
      <div class="panel-head"><div><span class="mini-label">KATEGORI FREE</span><h2>Limit & kuota gratis</h2></div></div>
      <form method="post" action="/admin/settings" class="settings-form">
        <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
        <div class="settings-grid">
          <fieldset>
            <legend>{icon('terminal')} SSH Free</legend>
            <label>Limit IP per akun<input type="number" name="ssh_ip_limit" min="0" max="100" value="{e(settings['ssh_ip_limit'])}"><small>0 = tanpa batas</small></label>
            <label>Kuota bandwidth (GB)<input type="number" name="ssh_quota_gb" min="0" max="10000" value="{e(settings['ssh_quota_gb'])}"><small>0 = tanpa batas</small></label>
            <label>Kuota 3 hari / hari<input type="number" name="ssh_daily_3" min="0" max="1000" value="{e(settings['ssh_daily_3'])}"></label>
            <label>Kuota 7 hari / hari<input type="number" name="ssh_daily_7" min="0" max="1000" value="{e(settings['ssh_daily_7'])}"></label>
            <label class="switch"><input type="checkbox" name="ssh_enabled" value="1" {'checked' if settings['ssh_enabled'] == '1' else ''}><span>Aktifkan SSH free</span></label>
          </fieldset>
          <fieldset>
            <legend>{icon('bolt')} Xray Free</legend>
            <label>Limit IP per akun<input type="number" name="xray_ip_limit" min="0" max="100" value="{e(settings['xray_ip_limit'])}"><small>0 = tanpa batas</small></label>
            <label>Kuota bandwidth (GB)<input type="number" name="xray_quota_gb" min="0" max="10000" value="{e(settings['xray_quota_gb'])}"><small>0 = tanpa batas</small></label>
            <label>Kuota 3 hari / hari<input type="number" name="xray_daily_3" min="0" max="1000" value="{e(settings['xray_daily_3'])}"></label>
            <label>Kuota 7 hari / hari<input type="number" name="xray_daily_7" min="0" max="1000" value="{e(settings['xray_daily_7'])}"></label>
            <label class="switch"><input type="checkbox" name="xray_enabled" value="1" {'checked' if settings['xray_enabled'] == '1' else ''}><span>Aktifkan Xray free</span></label>
            <div class="protocol-switches">
              <span class="mini-label">Protokol yang dibuka (free &amp; premium)</span>
              <label class="switch"><input type="checkbox" name="vmess_enabled" value="1" {'checked' if settings['vmess_enabled'] == '1' else ''}><span>VMess</span></label>
              <label class="switch"><input type="checkbox" name="vless_enabled" value="1" {'checked' if settings['vless_enabled'] == '1' else ''}><span>VLESS</span></label>
              <label class="switch"><input type="checkbox" name="trojan_enabled" value="1" {'checked' if settings['trojan_enabled'] == '1' else ''}><span>Trojan</span></label>
            </div>
          </fieldset>
        </div>
        <div class="settings-grid two">
          <label>Batas free per IP / layanan / hari<input type="number" name="per_ip_daily" min="0" max="1000" value="{e(settings['per_ip_daily'])}"><small>0 = tanpa batas per IP</small></label>
        </div>
        <label class="switch"><input type="checkbox" name="free_enabled" value="1" {'checked' if settings['free_enabled'] == '1' else ''}><span>Buka kategori akun gratis</span></label>
        <label class="switch"><input type="checkbox" name="premium_enabled" value="1" {'checked' if settings['premium_enabled'] == '1' else ''}><span>Buka kategori premium</span></label>
        <div class="settings-grid two">
          <label>Invoice premium berlaku (menit)<input type="number" name="premium_expiry_min" min="5" max="120" value="{e(settings['premium_expiry_min'])}"></label>
        </div>
        <fieldset class="contact-settings">
          <legend>Kontak &amp; Bantuan</legend>
          <label>Link Telegram admin / bantuan
            <input type="text" name="contact_telegram" value="{e(settings.get('contact_telegram', ''))}" placeholder="https://t.me/username atau @username" maxlength="300">
            <small>Dipakai untuk tombol Telegram di halaman Kontak.</small>
          </label>
          <label>Link grup komunitas (opsional)
            <input type="text" name="contact_group" value="{e(settings.get('contact_group', ''))}" placeholder="https://t.me/grupkamu" maxlength="300">
          </label>
          <label>Catatan bantuan
            <textarea name="contact_note" rows="3" maxlength="300" placeholder="Contoh: Admin online 08.00–22.00 WIB.">{e(settings.get('contact_note', ''))}</textarea>
          </label>
        </fieldset>
        <label class="switch maintenance"><input type="checkbox" name="maintenance" value="1" {'checked' if settings['maintenance'] == '1' else ''}><span>Mode perawatan (tutup seluruh pembuatan akun &amp; pembelian)</span></label>
        <div class="form-actions"><button class="btn btn-primary" type="submit">Simpan pengaturan</button></div>
      </form>
    </section>

    <aside class="admin-side">
      <section class="panel admin-panel">
        <div class="panel-head"><div><span class="mini-label">HARI INI</span><h2>Kuota free</h2></div></div>
        <div class="quota-strip vertical">{quota_rows}</div>
        <form method="post" action="/admin/reset-quota" class="inline-form" data-confirm="Reset hitungan kuota hari ini? Akun tidak dihapus, hanya hitungannya dikosongkan.">
          <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
          <button class="btn btn-small btn-ghost" type="submit">Reset hitungan hari ini</button>
        </form>
      </section>
      <section class="panel admin-panel">
        <div class="panel-head"><div><span class="mini-label">GOPAY</span><h2>Status gateway</h2></div>{gopay_badge}</div>
        {token_warn}
        {gopay_error_html}
        <div class="kv-list">
          <div><span>Base URL</span><b>{e(gstat['base'])}</b></div>
          <div><span>Token GoPay</span><b>{'Ada' if gstat['token'] else 'Tidak ada'}</b></div>
          <div><span>QRIS statis</span><b>{'Ada' if gstat['static_qr'] else 'Tidak ada'}</b></div>
          <div><span>Cek terakhir</span><b>{e(last_check)}</b></div>
          <div><span>Match terakhir</span><b>{e(last_match)}</b></div>
          <div><span>Invoice pending</span><b>{e(gstat['pending'])}</b></div>
        </div>
        <form method="post" action="/admin/gopay/test" class="inline-form" data-confirm="Tes koneksi ke gateway GoPay sekarang?">
          <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
          <button class="btn btn-small btn-ghost" type="submit">Test GoPay</button>
        </form>
        <p class="panel-hint">Token diambil dari bot. Jika expired, refresh lewat bot Store Admin → GoPay.</p>
      </section>
    </aside>
  </div>

  <section class="panel admin-panel">
    <div class="panel-head"><div><span class="mini-label">PREMIUM</span><h2>Paket jualan</h2></div><span class="panel-hint">Harga tidak termasuk kode unik Rp1–999.</span></div>
    <form method="post" action="/admin/premium" class="premium-table-form">
      <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
      <div class="table-wrap">
        <table class="premium-table">
          <thead><tr><th>Layanan</th><th>Hari</th><th>Harga</th><th>Limit IP</th><th>Kuota GB</th><th>Aktif</th></tr></thead>
          <tbody>{product_rows}</tbody>
        </table>
      </div>
      <div class="form-actions"><button class="btn btn-primary btn-small" type="submit">Simpan paket premium</button></div>
    </form>
    <details class="add-product">
      <summary>+ Tambah paket premium</summary>
      <form method="post" action="/admin/premium/add" class="settings-grid add-product-form">
        <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
        <label>Layanan<select name="protocol"><option value="ssh">SSH</option><option value="vmess">VMess</option><option value="vless">VLESS</option><option value="trojan">Trojan</option></select></label>
        <label>Label<input type="text" name="label" placeholder="SSH 30 Hari" maxlength="40"></label>
        <label>Hari<input type="number" name="days" min="1" max="365" value="30"></label>
        <label>Harga (Rp)<input type="number" name="price" min="1000" max="10000000" value="10000"></label>
        <label>Limit IP<input type="number" name="ip_limit" min="0" max="100" value="2"></label>
        <label>Kuota GB<input type="number" name="quota_gb" min="0" max="10000" value="0"></label>
        <div class="form-actions"><button class="btn btn-dark btn-small" type="submit">Tambah paket</button></div>
      </form>
    </details>
  </section>

  <section class="panel admin-panel accounts-panel">
    <div class="panel-head"><div><span class="mini-label">RIWAYAT PREMIUM</span><h2>Transaksi &amp; invoice</h2></div></div>
    <form method="get" action="/admin" class="admin-search">
      <input type="text" name="q" value="{e(q)}" placeholder="Cari invoice, username, atau IP...">
      <button class="btn btn-small btn-ghost" type="submit">Cari</button>
      {'' if not q else '<a class="btn btn-small btn-ghost" href="/admin">Reset</a>'}
    </form>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Invoice</th><th>Paket</th><th>Total</th><th>Dibuat</th><th>Status</th><th>Akun</th><th></th></tr></thead>
        <tbody>{order_rows}</tbody>
      </table>
    </div>
  </section>

  <section class="panel admin-panel accounts-panel">
    <div class="panel-head"><div><span class="mini-label">AKUN FREE</span><h2>Akun website terbaru</h2></div><span class="panel-hint">Hanya akun free buatan website.</span></div>
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


def render_check_invoice(form_token: str, error: str = "", code: str = "") -> str:
    err = f'<div class="notice notice-error">{e(error)}</div>' if error else ""
    body = f"""
<main class="invoice-page wrap">
  <div class="invoice-head check-head">
    <div class="eyebrow"><span class="dot"></span> CEK INVOICE / RIWAYAT</div>
    <h1>Buka lagi<br>pesanan Anda.</h1>
    <p class="page-hero-lead">Masukkan kode invoice yang tampil setelah pembelian. Tidak perlu login, tidak perlu email.</p>
  </div>
  <div class="check-layout">
    <div class="panel check-page-card">
      {err}
      <form method="post" action="/cek-invoice" class="stack-form">
        <input type="hidden" name="_form" value="{e(form_token)}">
        <label>Kode Invoice
          <input type="text" name="invoice" value="{e(code)}" placeholder="HITS-YYMMDD-XXXXXXXX" autocomplete="off" spellcheck="false" required autofocus>
        </label>
        <button class="btn btn-primary" type="submit">Buka invoice</button>
      </form>
      <p class="form-note">Kode invoice bersifat privat. Jangan bagikan ke orang lain.</p>
      <div class="check-tips">
        <div><b>Format kode</b><span>HITS-YYMMDD-XXXXXXXX</span></div>
        <div><b>Invoice berlaku</b><span>15 menit sejak dibuat</span></div>
        <div><b>Data akun</b><span>Muncul setelah pembayaran lunas</span></div>
      </div>
    </div>
    <aside class="panel invoice-history-card">
      <span class="mini-label">RIWAYAT DI PERANGKAT INI</span>
      <h3>Invoice terakhir</h3>
      <p>Daftar ini disimpan di browser Anda, bukan di server. Berguna jika lupa mencatat kode invoice.</p>
      <div id="invoice-history" class="invoice-history" data-empty="Belum ada invoice tersimpan di perangkat ini."></div>
      <a class="btn btn-dark btn-block btn-small" href="/premium">Beli paket premium</a>
      <a class="check-back-link" href="/kontak">Butuh bantuan? Hubungi admin &rarr;</a>
    </aside>
  </div>
  <p class="check-back"><a href="/">&larr; Kembali ke Beranda</a></p>
</main>
"""
    return page_shell("Cek Invoice", body, noindex=True, active="invoice")

def rupiah(value) -> str:
    return "Rp " + format(int(value), ",d").replace(",", ".")


def render_invoice(row: sqlite3.Row, new: bool = False) -> str:
    status = row["status"]
    label = f"{row['protocol'].upper()} · {row['days']} hari"
    status_text = {
        "PENDING": "Menunggu pembayaran",
        "PAID": "Pembayaran diterima",
        "PROVISIONING": "Menyiapkan akun",
        "COMPLETED": "Selesai",
        "FAILED": "Pembayaran diterima, akun gagal dibuat",
        "EXPIRED": "Invoice kedaluwarsa",
    }.get(status, status)
    status_class = "ok" if status == "COMPLETED" else ("warn" if status in ("PENDING", "PAID", "PROVISIONING") else "bad")
    total = int(row["total"])
    unique = int(row["unique_code"])
    price = int(row["price"])
    expires = fmt_ts(row["expires_at"], "%d %b %Y · %H:%M WIB")
    paid = fmt_ts(row["paid_at"], "%d %b %Y · %H:%M WIB") if row["paid_at"] else "-"
    qr_img = f'<img class="qr-img" src="/invoice/{e(row["invoice"])}/qr.svg" alt="QRIS GoPay" width="260" height="260">'
    pending_block = f"""
    <div class="invoice-pay">
      <div class="qr-box">{qr_img}<span>Scan dengan aplikasi bank / e-wallet</span></div>
      <div class="pay-detail">
        <span class="mini-label">TOTAL PEMBAYARAN</span>
        <div class="pay-total">{rupiah(total)}</div>
        <div class="pay-breakdown">{rupiah(price)} + kode unik {rupiah(unique)}</div>
        <div class="pay-expiry">Bayar sebelum <b>{e(expires)}</b></div>
        <div class="pay-countdown" id="invoice-countdown" data-expires="{int(row['expires_at'])}">--:--</div>
        <div class="notice notice-warn invoice-warning"><b>WAJIB SALIN KODE INVOICE.</b> Simpan kode ini untuk mengecek ulang pesanan.</div>
        <div class="invoice-code-line"><code>{e(row['invoice'])}</code><button type="button" class="btn btn-small btn-ghost" data-copy="{e(row['invoice'])}">Salin invoice</button></div>
        <div class="pay-status" id="invoice-live-status">Status: <b>{e(status_text)}</b></div>
      </div>
    </div>"""
    invoice_output = row["account_output"] or ""
    if row["protocol"] == "ssh":
        invoice_output = format_ssh_output(invoice_output)
    completed_block = f"""
    <div class="invoice-done">
      <div class="success-mark">✓</div>
      <div><div class="eyebrow"><span class="dot"></span> PEMBAYARAN BERHASIL</div><h2>Akun sudah aktif.</h2><p>Invoice <b>{e(row['invoice'])}</b> · {e(label)} · dibayar {e(paid)}.</p></div>
      <div class="invoice-actions">
        <button type="button" class="btn btn-small btn-ghost" id="copy-invoice-account">Salin akun</button>
        <a class="btn btn-small btn-dark" href="/invoice/{e(row['invoice'])}.txt" download>Unduh .txt</a>
      </div>
    </div>
    <pre class="account-output invoice-output" id="invoice-account">{e(invoice_output)}</pre>"""
    failed_block = f"""
    <div class="invoice-failed">
      <div class="error-code">!</div>
      <div><div class="eyebrow"><span class="dot"></span> PEMBAYARAN DITERIMA</div><h2>Akun belum berhasil dibuat.</h2><p>Simpan invoice ini dan hubungi admin. Pembayaran Anda sudah tercatat.</p><div class="invoice-code-line"><code>{e(row['invoice'])}</code><button type="button" class="btn btn-small btn-ghost" data-copy="{e(row['invoice'])}">Salin invoice</button></div></div>
    </div>"""
    expired_block = f"""
    <div class="invoice-expired">
      <div class="error-code">⌛</div>
      <div><div class="eyebrow"><span class="dot"></span> INVOICE KEDALUWARSA</div><h2>Waktu pembayaran habis.</h2><p>Invoice ini sudah lewat batas. Silakan buat pesanan baru, atau cek kembali beberapa saat jika Anda sudah terlanjur membayar.</p></div>
    </div>"""
    content = pending_block if status in ("PENDING", "PAID", "PROVISIONING") else (completed_block if status == "COMPLETED" else (failed_block if status == "FAILED" else expired_block))
    modal = ""
    if new and status in ("PENDING", "PAID", "PROVISIONING"):
        modal = f"""
<dialog class="invoice-dialog" id="invoice-dialog">
  <div class="dialog-icon">{icon('shield')}</div>
  <h2>Salin kode invoice sekarang.</h2>
  <p>Kode ini satu-satunya cara membuka kembali pesanan tanpa login. Jangan tutup halaman sebelum menyimpannya.</p>
  <div class="dialog-code"><code>{e(row['invoice'])}</code><button type="button" class="btn btn-small btn-dark" data-copy="{e(row['invoice'])}">Salin</button></div>
  <div class="dialog-warning">Saya sudah menyalin kode invoice</div>
  <button type="button" class="btn btn-primary btn-block" id="invoice-dialog-close">Saya sudah menyimpan</button>
</dialog>"""
    data = json.dumps(
        {
            "invoice": row["invoice"],
            "status": status,
            "expires_at": int(row["expires_at"]),
            "total": total,
            "label": label,
            "created_at": int(row["created_at"]),
        },
        ensure_ascii=False,
    ).replace("</", "<\\/")
    body = f"""
<main class="invoice-page wrap">
  <div class="invoice-head">
    <div class="eyebrow"><span class="dot"></span> INVOICE PREMIUM</div>
    <h1>{e(row['invoice'])}</h1>
    <div class="invoice-meta">
      <span class="badge badge-{status_class}">{e(status_text)}</span>
      <span>{e(label)}</span>
      <span>Dibuat {e(fmt_ts(row['created_at'], '%d %b %Y · %H:%M WIB'))}</span>
    </div>
  </div>
  <div class="invoice-shell panel">
    {content}
    <div class="invoice-foot">
      <span>Invoice <b>{e(row['invoice'])}</b></span>
      <span>Total <b>{rupiah(total)}</b></span>
      <a href="/cek-invoice">Cek invoice lain</a>
      <a href="/premium">Beli paket lain</a>
    </div>
  </div>
</main>
{modal}
<script type="application/json" id="invoice-data">{data}</script>
"""
    return page_shell("Invoice " + row["invoice"], body, noindex=True)


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
    parser.add_argument("--detect-server", action="store_true")
    args = parser.parse_args()

    # File database/log hanya boleh dibaca root.
    os.umask(0o077)
    init_db()
    if args.detect_server:
        info = refresh_server_info(force=True)
        print(json.dumps(info or {}, ensure_ascii=False))
        return 0 if info else 1
    try:
        refresh_server_info()
    except Exception:
        logger.warning("deteksi lokasi server saat start gagal: %s", traceback.format_exc())
    if args.init_only:
        print(f"database siap: {DB_PATH}")
        if ADMIN_CRED_PATH.exists():
            print(ADMIN_CRED_PATH.read_text(encoding="utf-8"))
        return 0

    threading.Thread(target=payment_daemon, name="gopay-poller", daemon=True).start()

    if not Path(SSH_SCRIPT).exists():
        logger.warning("script %s tidak ditemukan", SSH_SCRIPT)
    for cfg in PROTOCOLS.values():
        if not Path(cfg["script"]).exists():
            logger.warning("script %s tidak ditemukan", cfg["script"])

    httpd = Server((args.host, args.port), Handler)
    logger.info("HITS SSH listening on %s:%s", args.host, args.port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
