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
import decimal
import fcntl
import hashlib
import hmac
import html
import http.client
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
import smtplib
import socket
import socketserver
import sqlite3
import ssl
import string
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from email.utils import formataddr
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
USER_COOKIE = "kyt_user"
SESSION_TTL = 8 * 3600
USER_SESSION_TTL = 7 * 24 * 3600
EMAIL_TOKEN_TTL = 24 * 3600
RESET_TOKEN_TTL = 60 * 60
FORM_TTL = 24 * 3600
MAX_BODY = 512 * 1024
MAIL_KEY_PATH = Path("/etc/kyt-web-mail.key")
BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"

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
MIHOMO_BIN = Path("/usr/local/sbin/jeda-mullog")
MIHOMO_STATE_DIR = MIHOMO_STATE / "state"
XRAY_BIN = "/usr/local/bin/xray"
XRAY_API = "127.0.0.1:10000"
XRAY_TAGS = {
    "vmess": ["vmess-ws", "vmess-grpc", "vmess-hu", "vmess-xh", "vmess-tls"],
    "vless": ["vless-ws", "vless-grpc", "vless-hu", "vless-xh", "vless-tls"],
    "trojan": ["trojan-ws", "trojan-grpc", "trojan-hu", "trojan-xh", "trojan-tls"],
    "shadowsocks": ["ss-ws", "ss-grpc"],
}

# Pay As You Go: tarif dihitung dari harga patokan 30 hari.
PAYG_SECONDS_30D = 30 * 86400
PAYG_RUNNING = "RUNNING"
PAYG_PAUSED = "PAUSED"
PAYG_SUSPENDED = "SUSPENDED"
PAYG_LOCK = threading.Lock()
WALLET_LOCK = threading.Lock()

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
    "obsidian": "#05070a",
    "aurora": "#070a16",
    "ember": "#0b0806",
    "glacier": "#0b1015",
    "rosecream": "#fff8f6",
    "aquacream": "#f4fbfa",
    "bluecream": "#f5f8ff",
    "lavendercream": "#faf7ff",
    "mintcream": "#f5fcf7",
    "lemoncream": "#fffdf2",
    "peachcream": "#fff9f5",
    "slatecream": "#f7f8fa",
    "black": "#101214",
    "red": "#170607",
    "gray": "#15171a",
    "navy": "#07101f",
    "pink": "#fff0f6",
}
UI_THEMES = {
    "cream": ("Cream", "Hangat, bersih, nyaman untuk penggunaan lama."),
    "midnight": ("Midnight", "Navy gelap dengan aksen cyan neon."),
    "ocean": ("Ocean", "Biru laut dalam dengan aksen sky blue."),
    "forest": ("Forest", "Hijau gelap dengan aksen lime segar."),
    "royal": ("Royal", "Ungu gelap dengan aksen pink neon."),
    "obsidian": ("Obsidian", "Hitam glossy dengan aksen lime elektrik."),
    "aurora": ("Aurora", "Indigo malam dengan glow violet dan teal."),
    "ember": ("Ember", "Charcoal hangat dengan aksen copper."),
    "glacier": ("Glacier", "Slate dingin dengan aksen biru es."),
    "rosecream": ("Rose Cream", "Krem hangat dengan aksen merah rose, tanpa gradasi."),
    "aquacream": ("Aqua Cream", "Krem sejuk dengan aksen cyan, tanpa gradasi."),
    "bluecream": ("Blue Cream", "Krem bersih dengan aksen biru, tanpa gradasi."),
    "lavendercream": ("Lavender Cream", "Krem lembut dengan aksen lavender, tanpa gradasi."),
    "mintcream": ("Mint Cream", "Krem segar dengan aksen hijau mint, tanpa gradasi."),
    "lemoncream": ("Lemon Cream", "Krem hangat dengan aksen kuning lemon, tanpa gradasi."),
    "peachcream": ("Peach Cream", "Krem lembut dengan aksen peach, tanpa gradasi."),
    "slatecream": ("Slate Cream", "Krem netral dengan aksen slate, tanpa gradasi."),
    "black": ("Black", "Hitam charcoal solid dengan aksen putih, tidak pekat."),
    "red": ("Red", "Merah marun solid dengan aksen rose."),
    "gray": ("Gray", "Abu-abu graphite solid dengan aksen silver."),
    "navy": ("Navy", "Biru dongker solid dengan aksen gold."),
    "pink": ("Pink", "Pink lembut solid dengan aksen magenta, tanpa gradasi."),
}
DEFAULT_META = "HITS SSH — akun VPN gratis dan premium SSH, VMess, VLESS, Trojan. Daftar sekali, pantau akun dan invoice dari dashboard."
DEFAULT_HERO_TITLE = "Internet bebas,"
DEFAULT_HERO_TITLE_ACCENT = "akun langsung jadi."
DEFAULT_HERO_LEAD = "Daftar sekali, lalu buat akun gratis atau beli premium lewat QRIS GoPay. Semua akun, kuota, IP, dan invoice bisa dipantau dari satu dashboard."

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
    "premium_unique_last": "0",
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
    "mail_from_email": "oceantestdigital@gmail.com",
    "mail_from_name": BRAND,
    "mail_api_key": "",
    "mail_smtp_user": "",
    "mail_smtp_key": "",
    "mail_smtp_host": "smtp-relay.brevo.com",
    "mail_smtp_port": "2525",
    "mail_verify_subject": "Kode Verifikasi Anda",
    "mail_reset_subject": "Reset Password — HITS SSH",
    "payg_enabled": "1",
    "payg_base_ssh_30d": "10000",
    "payg_base_xray_30d": "10000",
    "payg_min_balance": "1000",
    "payg_min_topup": "5000",
    "payg_max_topup": "1000000",
    "payg_ssh_ip_limit": "2",
    "payg_ssh_quota_gb": "0",
    "payg_xray_ip_limit": "2",
    "payg_xray_quota_gb": "0",
    "payg_idle_minutes": "15",
    "popup_enabled": "0",
    "popup_title": "Informasi Penting",
    "popup_message": "",
    "popup_button_text": "",
    "popup_button_url": "",
    "popup_mode": "once",
    "popup_version": "1",
    "signup_email_mode": "block",
    "signup_email_allow": "gmail.com, googlemail.com",
    "signup_email_block_extra": "",
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
    "payg_base_ssh_30d": (1000, 10000000),
    "payg_base_xray_30d": (1000, 10000000),
    "payg_min_balance": (100, 1000000),
    "payg_min_topup": (1000, 10000000),
    "payg_max_topup": (1000, 100000000),
    "payg_ssh_ip_limit": (0, 100),
    "payg_ssh_quota_gb": (0, 10000),
    "payg_xray_ip_limit": (0, 100),
    "payg_xray_quota_gb": (0, 10000),
    "payg_idle_minutes": (1, 1440),
}

USER_RE = re.compile(r"^[a-z][a-z0-9]{7,14}$")
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ANSI_OSC_RE = re.compile(r"\x1b\][^\x07]*(?:\x07|\x1b\\)")

CREATE_LOCK = threading.Lock()
REGISTER_LOCK = threading.Lock()
RATE_LOCK = threading.Lock()
UNIQUE_CODE_LOCK = threading.Lock()
RATE_BUCKETS: dict[str, collections.deque] = {}
PUBLIC_RATE: dict[str, collections.deque] = {}
_CURRENT = threading.local()

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


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


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
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                verified_at INTEGER,
                last_login_at INTEGER,
                last_ip TEXT NOT NULL DEFAULT ''
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE TABLE IF NOT EXISTS user_sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                csrf TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                ip TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id, expires_at);
            CREATE TABLE IF NOT EXISTS user_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                code_hash TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_user_tokens_user ON user_tokens(user_id, kind, expires_at);
            CREATE TABLE IF NOT EXISTS usage_daily (
                username TEXT NOT NULL,
                day TEXT NOT NULL,
                start_bytes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(username, day)
            );
            CREATE TABLE IF NOT EXISTS deposits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                unique_code INTEGER NOT NULL,
                total INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                qr_string TEXT NOT NULL DEFAULT '',
                buyer_ip TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                paid_at INTEGER,
                reference TEXT NOT NULL DEFAULT '',
                credited_milli INTEGER NOT NULL DEFAULT 0,
                notified INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_deposits_user ON deposits(user_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_deposits_status ON deposits(status, created_at);
            CREATE INDEX IF NOT EXISTS idx_deposits_reference ON deposits(reference);
            CREATE TABLE IF NOT EXISTS wallet_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                at INTEGER NOT NULL,
                kind TEXT NOT NULL,
                amount_milli INTEGER NOT NULL,
                balance_after_milli INTEGER NOT NULL,
                ref TEXT NOT NULL DEFAULT '',
                note TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_wallet_ledger_user ON wallet_ledger(user_id, id);
            CREATE TABLE IF NOT EXISTS payg_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                account_id INTEGER NOT NULL UNIQUE,
                service TEXT NOT NULL,
                protocol TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'PAUSED',
                created_at INTEGER NOT NULL,
                started_at INTEGER,
                stopped_at INTEGER,
                last_billed_at INTEGER,
                last_seen_at INTEGER NOT NULL DEFAULT 0,
                bill_remainder_num INTEGER NOT NULL DEFAULT 0,
                spent_milli INTEGER NOT NULL DEFAULT 0,
                total_seconds INTEGER NOT NULL DEFAULT 0,
                last_error TEXT NOT NULL DEFAULT '',
                UNIQUE(user_id, service, protocol)
            );
            CREATE INDEX IF NOT EXISTS idx_payg_user ON payg_accounts(user_id);
            CREATE INDEX IF NOT EXISTS idx_payg_state ON payg_accounts(state);
            """
        )
        _ensure_column(conn, "accounts", "user_id", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "accounts", "kind", "TEXT NOT NULL DEFAULT 'free'")
        _ensure_column(conn, "orders", "user_id", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "user_tokens", "code_hash", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "users", "balance_milli", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "payg_accounts", "last_seen_at", "INTEGER NOT NULL DEFAULT 0")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id, created_at)")
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


def popup_config(settings: dict[str, str] | None = None) -> dict[str, str] | None:
    """Ambil isi popup informasi. None berarti popup tidak ditampilkan."""
    try:
        settings = settings or get_settings()
    except Exception:
        return None
    if settings.get("popup_enabled", "0") != "1":
        return None
    title = (settings.get("popup_title") or "Informasi Penting").strip()[:80]
    message = (settings.get("popup_message") or "").strip()
    if not message:
        return None
    button_text = (settings.get("popup_button_text") or "").strip()[:40]
    button_url = (settings.get("popup_button_url") or "").strip()[:500]
    if button_url and not (
        (button_url.startswith("/") and not button_url.startswith("//"))
        or button_url.startswith("https://")
        or button_url.startswith("http://")
    ):
        button_url = ""
    mode = (settings.get("popup_mode") or "once").strip()
    if mode not in ("once", "always"):
        mode = "once"
    version = (settings.get("popup_version") or "1").strip()[:24] or "1"
    return {
        "title": title,
        "message": message[:2000],
        "button_text": button_text,
        "button_url": button_url,
        "mode": mode,
        "version": version,
    }


def render_popup(settings: dict[str, str] | None = None) -> str:
    cfg = popup_config(settings)
    if not cfg:
        return ""
    button = ""
    if cfg["button_text"] and cfg["button_url"]:
        target = ' target="_blank" rel="noopener"' if cfg["button_url"].startswith("http") else ""
        button = (
            f'<a class="info-popup-cta" href="{e(cfg["button_url"])}"{target}>'
            f'{e(cfg["button_text"])}</a>'
        )
    return f"""
<div class="info-popup" id="info-popup" hidden data-popup-version="{e(cfg['version'])}" data-popup-mode="{e(cfg['mode'])}" role="dialog" aria-labelledby="info-popup-title">
  <div class="info-popup-card">
    <button class="info-popup-close" type="button" data-popup-close aria-label="Tutup informasi">×</button>
    <span class="info-popup-kicker">INFORMASI</span>
    <h2 id="info-popup-title">{e(cfg['title'])}</h2>
    <p class="info-popup-message">{e(cfg['message'])}</p>
    <div class="info-popup-actions">
      {button}
      <button class="info-popup-dismiss" type="button" data-popup-close>Mengerti</button>
    </div>
  </div>
</div>"""


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
                    "WHERE created_day=? AND service=? AND days=? AND status='active' AND kind='free'",
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
                "WHERE created_day=? AND service=? AND ip=? AND status='active' AND kind='free'",
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
# User accounts, email verification, and user sessions
# ---------------------------------------------------------------------------

def current_user() -> sqlite3.Row | None:
    return getattr(_CURRENT, "user", None)


def normalize_email(value: str) -> str:
    return (value or "").strip().lower()[:190]


def valid_email(value: str) -> bool:
    if len(value) < 5 or len(value) > 190:
        return False
    return bool(re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", value))


# Domain email sekali pakai yang umum. Admin bisa menambah daftar sendiri.
DISPOSABLE_EMAIL_DOMAINS = {
    "0-mail.com", "10minutemail.com", "10minutemail.net", "20minutemail.com",
    "anonbox.net", "binkmail.com", "bobmail.info", "burnermail.io",
    "chammy.info", "cool.fr.nf", "courriel.fr.nf", "discard.email",
    "dispostable.com", "dropmail.me", "emailnator.com", "emailondeck.com",
    "fakeinbox.com", "getnada.com", "grr.la", "guerrillamail.com",
    "guerrillamail.net", "guerrillamail.org", "guerrillamailblock.com",
    "inboxkitten.com", "jetable.fr.nf", "letthemeatspam.com", "luxusmail.org",
    "mail.gw", "mail.tm", "mail7.io", "mailcatch.com", "maildrop.cc",
    "mailinater.com", "mailinator.com", "mailmetrash.com", "mailnesia.com",
    "mailscrap.com", "mintemail.com", "moakt.com", "mohmal.com",
    "moncourrier.fr.nf", "monemail.fr.nf", "monmail.fr.nf", "mt2009.com",
    "nomail.xl.cx", "nospam.ze.tc", "pokemail.net", "sharklasers.com",
    "smailpro.com", "spam.la", "spam4.me", "spamgourmet.com", "speed.1s.fr",
    "temp-mail.org", "tempail.com", "tempinbox.com", "tempmail.com",
    "tempmail.plus", "tempmailo.com", "thankyou2010.com", "throwawaymail.com",
    "trash2009.com", "trashmail.com", "trashymail.com", "tyldd.com",
    "uggsrock.com", "vortexmail.net", "wegwerfmail.de", "wegwerfmail.net",
    "wegwerfmail.org", "wh4f.org", "willselfdestruct.com", "wronghead.com",
    "xagloo.com", "yopmail.com", "yopmail.fr", "yopmail.net",
}


def email_domain(value: str) -> str:
    email = normalize_email(value)
    return email.rsplit("@", 1)[-1] if "@" in email else ""


def email_compare_key(value: str) -> str:
    """Gmail/Googlemail tidak membedakan titik dan +tag."""
    email = normalize_email(value)
    local, sep, domain = email.partition("@")
    if sep and domain in ("gmail.com", "googlemail.com"):
        local = local.split("+", 1)[0].replace(".", "")
        return f"{local}@gmail.com"
    return email


def parse_domain_list(raw: str) -> list[str]:
    result: list[str] = []
    for part in re.split(r"[\s,;]+", raw or ""):
        domain = part.strip().lower().lstrip("@").rstrip(".")
        if domain and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}", domain):
            if domain not in result:
                result.append(domain)
    return result


def domain_in_list(domain: str, entries) -> bool:
    domain = (domain or "").lower().strip(".")
    return any(domain == item or domain.endswith("." + item) for item in entries)


def signup_email_allowed(email: str, settings: dict[str, str] | None = None) -> tuple[bool, str]:
    try:
        settings = settings or get_settings()
    except Exception:
        return True, ""
    mode = (settings.get("signup_email_mode") or "block").strip()
    if mode == "all":
        return True, ""
    domain = email_domain(email)
    if not domain:
        return False, "Format email tidak valid."
    if mode == "google":
        if domain in ("gmail.com", "googlemail.com"):
            return True, ""
        return False, "Pendaftaran hanya menerima email Google (Gmail)."
    if mode == "allow":
        allowed = parse_domain_list(settings.get("signup_email_allow", "")) or ["gmail.com", "googlemail.com"]
        if domain_in_list(domain, allowed):
            return True, ""
        return False, "Domain email belum diizinkan untuk pendaftaran."
    blocked = set(DISPOSABLE_EMAIL_DOMAINS)
    blocked.update(parse_domain_list(settings.get("signup_email_block_extra", "")))
    if domain_in_list(domain, blocked):
        return False, "Email sementara/temp mail tidak diizinkan. Gunakan email utama Anda."
    return True, ""


def email_already_registered(email: str) -> bool:
    key = email_compare_key(email)
    conn = db_connect()
    try:
        for row in conn.execute("SELECT email FROM users"):
            if email_compare_key(row["email"]) == key:
                return True
        return False
    finally:
        conn.close()


def safe_next(value: str) -> str:
    value = (value or "").strip()
    if not value.startswith("/") or value.startswith("//") or "\n" in value or "\r" in value:
        return "/dashboard"
    if value.startswith("/admin"):
        return "/dashboard"
    return value[:300]


def user_by_email(email: str) -> sqlite3.Row | None:
    normalized = normalize_email(email)
    conn = db_connect()
    try:
        row = conn.execute("SELECT * FROM users WHERE email=?", (normalized,)).fetchone()
        if row:
            return row
        key = email_compare_key(normalized)
        if key != normalized:
            for candidate in conn.execute("SELECT * FROM users"):
                if email_compare_key(candidate["email"]) == key:
                    return candidate
        return None
    finally:
        conn.close()


def user_by_id(user_id: int) -> sqlite3.Row | None:
    conn = db_connect()
    try:
        return conn.execute("SELECT * FROM users WHERE id=?", (int(user_id),)).fetchone()
    finally:
        conn.close()


def create_user(email: str, password: str, ip: str) -> tuple[sqlite3.Row | None, str]:
    email = normalize_email(email)
    now = int(time.time())
    with REGISTER_LOCK:
        if email_already_registered(email):
            return None, "Email sudah terdaftar. Silakan masuk atau gunakan email lain."
        conn = db_connect()
        try:
            cur = conn.execute(
                "INSERT INTO users(email,password_hash,status,created_at,updated_at,last_ip) "
                "VALUES(?,?,'pending',?,?,?)",
                (email, hash_password(password), now, now, ip[:64]),
            )
            conn.commit()
            return user_by_id(int(cur.lastrowid)), ""
        except sqlite3.IntegrityError:
            return None, "Email sudah terdaftar. Silakan masuk atau gunakan email lain."
        except Exception:
            logger.error("create_user: %s", traceback.format_exc())
            return None, "Pendaftaran gagal. Coba lagi beberapa saat."
        finally:
            conn.close()


def create_email_token(user_id: int, kind: str, ttl: int) -> tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    code = f"{secrets.randbelow(1_000_000):06d}"
    code_hash = hashlib.sha256(f"{code}:{int(user_id)}".encode("utf-8")).hexdigest()
    now = int(time.time())
    conn = db_connect()
    try:
        conn.execute("DELETE FROM user_tokens WHERE expires_at<? OR used_at IS NOT NULL", (now,))
        conn.execute(
            "INSERT INTO user_tokens(user_id,kind,token_hash,code_hash,created_at,expires_at) VALUES(?,?,?,?,?,?)",
            (int(user_id), kind, token_hash(raw), code_hash, now, now + ttl),
        )
        conn.commit()
    finally:
        conn.close()
    return raw, code


def peek_email_token(raw: str, kind: str) -> sqlite3.Row | None:
    if not raw or len(raw) > 200:
        return None
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT * FROM user_tokens WHERE token_hash=? AND kind=? AND used_at IS NULL AND expires_at>=?",
            (token_hash(raw), kind, int(time.time())),
        ).fetchone()
    finally:
        conn.close()


def consume_email_token(raw: str, kind: str) -> sqlite3.Row | None:
    row = peek_email_token(raw, kind)
    if not row:
        return None
    conn = db_connect()
    try:
        cur = conn.execute(
            "UPDATE user_tokens SET used_at=? WHERE id=? AND used_at IS NULL",
            (int(time.time()), row["id"]),
        )
        conn.commit()
        return row if cur.rowcount else None
    finally:
        conn.close()


def verify_email_code(email: str, code: str) -> sqlite3.Row | None:
    user = user_by_email(email)
    if not user:
        return None
    code = (code or "").strip()
    if not re.fullmatch(r"\d{6}", code):
        return None
    target = hashlib.sha256(f"{code}:{int(user['id'])}".encode("utf-8")).hexdigest()
    now = int(time.time())
    conn = db_connect()
    try:
        rows = conn.execute(
            "SELECT * FROM user_tokens WHERE user_id=? AND kind='verify' "
            "AND used_at IS NULL AND expires_at>=? ORDER BY id DESC LIMIT 10",
            (int(user["id"]), now),
        ).fetchall()
        for row in rows:
            if hmac.compare_digest(str(row["code_hash"] or ""), target):
                conn.execute("UPDATE user_tokens SET used_at=? WHERE id=?", (now, row["id"]))
                conn.commit()
                return user
        return None
    finally:
        conn.close()


def create_user_session(user_id: int, ip: str) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    now = int(time.time())
    conn = db_connect()
    try:
        conn.execute("DELETE FROM user_sessions WHERE expires_at<?", (now,))
        conn.execute(
            "INSERT INTO user_sessions(token_hash,user_id,csrf,created_at,expires_at,ip) VALUES(?,?,?,?,?,?)",
            (token_hash(token), int(user_id), csrf, now, now + USER_SESSION_TTL, ip[:64]),
        )
        conn.commit()
    finally:
        conn.close()
    return token, csrf


def get_user_session(token: str | None) -> sqlite3.Row | None:
    if not token:
        return None
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT s.*, u.email, u.status AS user_status, u.created_at AS user_created_at, "
            "u.verified_at, u.last_login_at, u.balance_milli FROM user_sessions s "
            "JOIN users u ON u.id=s.user_id "
            "WHERE s.token_hash=? AND s.expires_at>=? AND u.status='active'",
            (token_hash(token), int(time.time())),
        ).fetchone()
    finally:
        conn.close()


def drop_user_session(token: str | None) -> None:
    if not token:
        return
    conn = db_connect()
    try:
        conn.execute("DELETE FROM user_sessions WHERE token_hash=?", (token_hash(token),))
        conn.commit()
    finally:
        conn.close()


def drop_user_sessions(user_id: int, keep_token: str | None = None) -> None:
    conn = db_connect()
    try:
        if keep_token:
            conn.execute(
                "DELETE FROM user_sessions WHERE user_id=? AND token_hash<>?",
                (int(user_id), token_hash(keep_token)),
            )
        else:
            conn.execute("DELETE FROM user_sessions WHERE user_id=?", (int(user_id),))
        conn.commit()
    finally:
        conn.close()


def set_user_verified(user_id: int) -> None:
    now = int(time.time())
    conn = db_connect()
    try:
        conn.execute(
            "UPDATE users SET status='active', verified_at=COALESCE(verified_at,?), updated_at=? WHERE id=?",
            (now, now, int(user_id)),
        )
        conn.commit()
    finally:
        conn.close()


def update_user_password(user_id: int, password: str) -> None:
    conn = db_connect()
    try:
        conn.execute(
            "UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
            (hash_password(password), int(time.time()), int(user_id)),
        )
        conn.commit()
    finally:
        conn.close()


def audit_user(user_id: int, action: str, detail: str = "", ip: str = "") -> None:
    user = user_by_id(user_id)
    email = user["email"] if user else str(user_id)
    audit(action, f"user={email} {detail}".strip(), ip)

# ---------------------------------------------------------------------------
# Wallet, deposit, and Pay As You Go
# ---------------------------------------------------------------------------

def _setting_int(settings: dict[str, str], key: str, default: int = 0) -> int:
    try:
        return int(str(settings.get(key, default)).strip())
    except (TypeError, ValueError):
        return int(default)

def payg_base_price(service: str, settings: dict[str, str] | None = None) -> int:
    settings = settings or get_settings()
    key = "payg_base_ssh_30d" if service == "ssh" else "payg_base_xray_30d"
    return max(1000, _setting_int(settings, key, 10000))

def payg_rates(service: str, settings: dict[str, str] | None = None) -> dict:
    base = payg_base_price(service, settings)
    return {
        "base": base,
        "day_milli": decimal.Decimal(base) * 1000 / decimal.Decimal(30),
        "hour_milli": decimal.Decimal(base) * 1000 / decimal.Decimal(720),
        "minute_milli": decimal.Decimal(base) * 1000 / decimal.Decimal(43200),
    }

def rupiah_milli(value, decimals: int = 2, strip: bool = False) -> str:
    try:
        amount = decimal.Decimal(str(value)) / decimal.Decimal(1000)
        quant = decimal.Decimal(1).scaleb(-max(0, int(decimals)))
        amount = amount.quantize(quant, rounding=decimal.ROUND_HALF_UP)
    except Exception:
        amount = decimal.Decimal(0)
    text = f"{amount:,.{max(0, int(decimals))}f}"
    text = text.replace(",", "X").replace(".", ",").replace("X", ".")
    if strip and decimals > 0:
        text = text.rstrip("0").rstrip(",")
    return "Rp " + (text or "0")

def wallet_balance_milli(user_id: int) -> int:
    conn = db_connect()
    try:
        row = conn.execute("SELECT balance_milli FROM users WHERE id=?", (int(user_id),)).fetchone()
        return int(row["balance_milli"] or 0) if row else 0
    finally:
        conn.close()

def _wallet_write(user_id: int, amount_milli: int, kind: str, ref: str = "", note: str = "") -> tuple[int, int]:
    """Tambah/kurangi saldo secara atomik. Return (perubahan aktual, saldo akhir)."""
    amount_milli = int(amount_milli)
    with WALLET_LOCK:
        conn = db_connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT balance_milli FROM users WHERE id=?", (int(user_id),)).fetchone()
            if not row:
                conn.rollback()
                return 0, 0
            old = int(row["balance_milli"] or 0)
            new = old + amount_milli
            if new < 0:
                new = 0
            actual = new - old
            conn.execute(
                "UPDATE users SET balance_milli=?, updated_at=? WHERE id=?",
                (new, int(time.time()), int(user_id)),
            )
            conn.execute(
                "INSERT INTO wallet_ledger(user_id,at,kind,amount_milli,balance_after_milli,ref,note)"
                " VALUES(?,?,?,?,?,?,?)",
                (int(user_id), int(time.time()), kind[:30], actual, new, ref[:120], note[:240]),
            )
            conn.commit()
            return actual, new
        except Exception:
            conn.rollback()
            logger.error("wallet write: %s", traceback.format_exc())
            return 0, 0
        finally:
            conn.close()

def wallet_add(user_id: int, amount_milli: int, kind: str, ref: str = "", note: str = "") -> int:
    _actual, new = _wallet_write(user_id, abs(int(amount_milli)), kind, ref, note)
    return new

def wallet_deduct(user_id: int, amount_milli: int, kind: str, ref: str = "", note: str = "") -> tuple[int, int]:
    return _wallet_write(user_id, -abs(int(amount_milli)), kind, ref, note)

def wallet_ledger(user_id: int, limit: int = 50) -> list[sqlite3.Row]:
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT * FROM wallet_ledger WHERE user_id=? ORDER BY id DESC LIMIT ?",
            (int(user_id), max(1, int(limit))),
        ).fetchall()
    finally:
        conn.close()

def _jeda_call(*args: str, timeout: int = 40) -> tuple[int, str]:
    if not MIHOMO_BIN.exists():
        return 127, "jeda-mullog tidak ditemukan"
    try:
        proc = subprocess.run(
            [str(MIHOMO_BIN), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        return int(proc.returncode), (proc.stdout or "")[-2000:]
    except Exception as exc:
        logger.warning("jeda-mullog %s: %s", " ".join(args), exc)
        return 1, str(exc)

def _jeda_args(action: str, service: str, protocol: str, username: str) -> list[str]:
    if service == "ssh":
        return [action, "ssh", username]
    return [action, "xray", protocol, username]

def payg_jeda_state(service: str, protocol: str, username: str) -> dict | None:
    safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", str(username))
    if service == "ssh":
        name = f"ssh-{safe_user}.json"
    else:
        safe_proto = re.sub(r"[^A-Za-z0-9_.-]", "_", str(protocol))
        name = f"xray-{safe_proto}-{safe_user}.json"
    path = MIHOMO_STATE_DIR / name
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def xray_live_has_user(protocol: str, username: str) -> bool | None:
    """Cek user di Xray yang sedang berjalan lewat API. None = API tidak bisa dipakai."""
    tags = XRAY_TAGS.get(protocol, [])
    if not tags:
        return None
    for _attempt in range(12):
        found = False
        haystack = []
        retry = False
        for tag in tags:
            try:
                proc = subprocess.run(
                    [XRAY_BIN, "api", "inbounduser", "-s", XRAY_API, f"-tag={tag}", f"-email={username}"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=8,
                )
            except Exception:
                retry = True
                break
            if proc.returncode != 0:
                err = (proc.stderr or "").lower()
                if "handler not found" in err:
                    continue
                retry = True
                break
            haystack.append(proc.stdout or "")
        if not retry:
            combined = "\n".join(haystack)
            return '"email"' in combined or f'"{username}"' in combined
        time.sleep(0.6)
    return None

def xray_online_count(username: str) -> int | None:
    """Jumlah sesi online user di Xray. None = API tidak bisa dipakai."""
    try:
        proc = subprocess.run(
            [XRAY_BIN, "api", "statsonline", "-s", XRAY_API, f"-email={username}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8,
        )
    except Exception:
        return None
    if proc.returncode == 0:
        try:
            data = json.loads(proc.stdout or "{}")
            stat = data.get("stat") or {}
            return max(0, int(stat.get("value") or 0))
        except Exception:
            return None
    if "not found" in (proc.stderr or "").lower():
        return 0
    return None

def ssh_active_session_count(username: str) -> int | None:
    """Jumlah koneksi SSH aktif user saat ini (bukan histori auth.log)."""
    try:
        proc = subprocess.run(
            ["ss", "-tnpH"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=8,
        )
    except Exception:
        return None
    ports = _ssh_listener_ports()
    count = 0
    for line in proc.stdout.splitlines():
        if "ESTAB" not in line:
            continue
        if "sshd" not in line and "dropbear" not in line:
            continue
        fields = line.split()
        if len(fields) < 5:
            continue
        local_port = fields[3].rsplit(":", 1)[-1]
        if ports and local_port not in ports:
            continue
        pid_match = re.search(r"pid=(\d+)", line)
        if not pid_match:
            continue
        if _pid_user(int(pid_match.group(1))) == username:
            count += 1
    if count == 0:
        try:
            who = subprocess.run(
                ["who"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, timeout=5,
            ).stdout
            count = sum(1 for line in who.splitlines() if line.split()[:1] == [username])
        except Exception:
            pass
    return count

def payg_account_is_blocked(service: str, protocol: str, username: str) -> tuple[bool, str]:
    """Cek nyata: akun benar-benar tidak ada di config + Xray live / terkunci di sistem."""
    if service == "ssh":
        try:
            pw = pwd.getpwnam(username)
        except KeyError:
            return True, "user tidak ada"
        try:
            out = subprocess.run(
                ["passwd", "-S", username],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=10,
            ).stdout.split()
            status = out[1] if len(out) > 1 else ""
        except Exception:
            status = ""
        shell = pw.pw_shell or ""
        if status in ("L", "LK") or shell in ("/usr/sbin/nologin", "/sbin/nologin"):
            return True, ""
        return False, "password SSH masih aktif"
    live = xray_live_has_user(protocol, username)
    if live is None:
        return False, "API Xray tidak tersedia untuk verifikasi live"
    if live:
        return False, "masih aktif di Xray live"
    cfg = PROTOCOLS.get(protocol) or {}
    try:
        text = XRAY_CONFIG.read_text(errors="ignore")
    except FileNotFoundError:
        return True, "config xray tidak ada"
    marker = rf"(?m)^(?:###|#&|#!)\s+{re.escape(username)}(?:\s|$)"
    email = rf'"email"\s*:\s*"{re.escape(username)}"'
    if re.search(marker, text) or re.search(email, text):
        return False, "masih ada di config xray"
    db_path = cfg.get("db")
    if db_path and Path(db_path).exists():
        try:
            db_text = Path(db_path).read_text(errors="ignore")
            if re.search(rf"(?m)^###\s+{re.escape(username)}(?:\s|$)", db_text):
                return False, "masih ada di database xray"
        except Exception:
            pass
    return True, ""

def payg_hold_account(service: str, protocol: str, username: str) -> tuple[bool, str]:
    """Kunci akun tanpa timer otomatis + verifikasi config benar-benar tercabut."""
    state = payg_jeda_state(service, protocol, username)
    if state and not state.get("hold"):
        _jeda_call(*_jeda_args("release", service, protocol, username))
    elif state and state.get("hold"):
        blocked, _reason = payg_account_is_blocked(service, protocol, username)
        if not blocked:
            # State hold ada tapi config aktif lagi (mis. dipulihkan manual). Ulang.
            _jeda_call(*_jeda_args("release", service, protocol, username))
    rc, out = _jeda_call(*_jeda_args("hold", service, protocol, username))
    if rc not in (0, 3):
        return False, out or f"exit {rc}"
    blocked, reason = payg_account_is_blocked(service, protocol, username)
    if not blocked:
        logger.error("PAYG hold gagal diverifikasi %s/%s %s: %s", service, protocol, username, reason)
        return False, reason
    return True, ""

def payg_release_account(service: str, protocol: str, username: str) -> tuple[bool, str]:
    rc, out = _jeda_call(*_jeda_args("release", service, protocol, username))
    if rc not in (0, 3):
        return False, out or f"exit {rc}"
    blocked, reason = payg_account_is_blocked(service, protocol, username)
    if blocked:
        logger.error("PAYG release gagal diverifikasi %s/%s %s: %s", service, protocol, username, reason)
        return False, reason
    return True, ""

def payg_rows_for_user(user_id: int) -> list[sqlite3.Row]:
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT p.*, a.token, a.status AS account_status FROM payg_accounts p "
            "JOIN accounts a ON a.id=p.account_id WHERE p.user_id=? ORDER BY p.id DESC",
            (int(user_id),),
        ).fetchall()
    finally:
        conn.close()

def payg_row_by_id(payg_id: int, user_id: int | None = None) -> sqlite3.Row | None:
    conn = db_connect()
    try:
        if user_id is None:
            return conn.execute(
                "SELECT p.*, a.token, a.status AS account_status FROM payg_accounts p "
                "JOIN accounts a ON a.id=p.account_id WHERE p.id=?",
                (int(payg_id),),
            ).fetchone()
        return conn.execute(
            "SELECT p.*, a.token, a.status AS account_status FROM payg_accounts p "
            "JOIN accounts a ON a.id=p.account_id WHERE p.id=? AND p.user_id=?",
            (int(payg_id), int(user_id)),
        ).fetchone()
    finally:
        conn.close()

def payg_existing(user_id: int, service: str, protocol: str) -> sqlite3.Row | None:
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT * FROM payg_accounts WHERE user_id=? AND service=? AND protocol=?",
            (int(user_id), service, protocol),
        ).fetchone()
    finally:
        conn.close()

def payg_create_account(user_id: int, service: str, protocol: str, ip: str, user_agent: str) -> sqlite3.Row:
    settings = get_settings()
    if settings.get("maintenance") == "1":
        raise ValueError("Website sedang dalam perawatan. Silakan coba lagi nanti.")
    if settings.get("payg_enabled", "1") != "1":
        raise ValueError("Pay As You Go sedang ditutup admin.")
    if service not in SERVICES:
        raise ValueError("Layanan tidak valid.")
    if service == "xray" and protocol not in PROTOCOLS:
        raise ValueError("Pilih protokol Xray terlebih dahulu.")
    if service == "ssh":
        protocol = ""
    if settings.get(f"{service}_enabled", "1") != "1":
        raise ValueError(f"Layanan {SERVICES[service]['label']} sedang dinonaktifkan admin.")
    if service == "xray" and settings.get(f"{protocol}_enabled", "1") != "1":
        raise ValueError(f"Protokol {PROTOCOLS[protocol]['label']} sedang ditutup admin.")
    if payg_existing(int(user_id), service, protocol):
        raise ValueError("Anda sudah punya akun Pay As You Go untuk layanan ini. Kelola dari dashboard.")
    min_balance = _setting_int(settings, "payg_min_balance", 1000) * 1000
    balance_milli = wallet_balance_milli(int(user_id))
    if balance_milli < min_balance:
        raise ValueError(f"Saldo minimal {rupiah_milli(min_balance)} untuk membuat akun Pay As You Go.")

    ip_limit = _setting_int(settings, f"payg_{service}_ip_limit", 2)
    quota_gb = _setting_int(settings, f"payg_{service}_quota_gb", 0)
    username = make_username(service, protocol)
    password = make_password() if service == "ssh" else ""
    # Tampilkan estimasi masa pakai saldo di notifikasi, bukan 3650 hari
    # (angka internal 3650 hanya supaya akun PAYG tidak ikut expiry otomatis).
    try:
        estimate_days = max(1, int(round(float(balance_milli) / float(payg_rates(service, settings)["day_milli"]))))
    except Exception:
        estimate_days = 30
    payg_env = {
        "KYT_MASA_LABEL": f"Pay As You Go · estimasi ±{estimate_days} hari",
        "KYT_EXPIRES_LABEL": "Mengikuti saldo (tanpa masa aktif tetap)",
    }
    account_id = 0
    payg_id = 0
    with CREATE_LOCK:
        if service == "ssh":
            ok, output, log = create_ssh_account(
                username, password, 3650, ip_limit, quota_gb, extra_env=payg_env
            )
        else:
            ok, output, log = create_xray_account(
                protocol, username, 3650, ip_limit, quota_gb, extra_env=payg_env
            )
        if not ok:
            raise ValueError(output or "Gagal membuat akun VPN. Coba lagi.")
        now = int(time.time())
        token = secrets.token_urlsafe(24)
        conn = db_connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "INSERT INTO accounts(token,username,service,protocol,days,ip,created_at,created_day,"
                "expires_at,status,output,error,user_agent,user_id,kind) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'payg')",
                (
                    token, username, service, protocol, 0, ip, now, today_key(),
                    now + 3650 * 86400, "active", output, "", (user_agent or "")[:300], int(user_id),
                ),
            )
            account_id = int(cur.lastrowid)
            cur_payg = conn.execute(
                "INSERT INTO payg_accounts(user_id,account_id,service,protocol,username,state,created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (int(user_id), account_id, service, protocol, username, PAYG_PAUSED, now),
            )
            payg_id = int(cur_payg.lastrowid)
            conn.commit()
        except Exception as exc:
            conn.rollback()
            try:
                remove_ssh_account(username) if service == "ssh" else remove_xray_account(protocol, username)
            except Exception:
                logger.warning("gagal hapus akun PAYG setelah insert gagal: %s", traceback.format_exc())
            if isinstance(exc, sqlite3.IntegrityError):
                raise ValueError("Anda sudah punya akun Pay As You Go untuk layanan ini. Kelola dari dashboard.")
            raise
        finally:
            conn.close()
    held, err = payg_hold_account(service, protocol, username)
    if not held:
        try:
            remove_ssh_account(username) if service == "ssh" else remove_xray_account(protocol, username)
        except Exception:
            logger.warning("gagal hapus akun PAYG setelah hold gagal: %s", traceback.format_exc())
        conn = db_connect()
        try:
            conn.execute("DELETE FROM payg_accounts WHERE account_id=?", (account_id,))
            conn.execute("DELETE FROM accounts WHERE id=?", (account_id,))
            conn.commit()
        finally:
            conn.close()
        raise ValueError("Gagal mengunci akun Pay As You Go. Hubungi admin.")
    audit_user(int(user_id), "payg_create", f"{service}/{protocol or '-'} {username}", ip)
    return payg_row_by_id(payg_id, int(user_id))

def payg_start(payg_id: int, user_id: int) -> sqlite3.Row:
    row = payg_row_by_id(payg_id, user_id)
    if not row:
        raise ValueError("Akun Pay As You Go tidak ditemukan.")
    if row["state"] == PAYG_RUNNING:
        return row
    settings = get_settings()
    min_balance = _setting_int(settings, "payg_min_balance", 1000) * 1000
    if wallet_balance_milli(int(user_id)) < min_balance:
        raise ValueError(f"Saldo minimal {rupiah_milli(min_balance)} untuk menyalakan akun.")
    state = payg_jeda_state(row["service"], row["protocol"], row["username"])
    if state and not state.get("hold"):
        raise ValueError("Akun sedang dibekukan mullog. Tunggu sampai pulih lalu coba lagi.")
    ok, err = payg_release_account(row["service"], row["protocol"], row["username"])
    if not ok:
        raise ValueError("Gagal menyalakan akun. Coba lagi atau hubungi admin.")
    now = int(time.time())
    conn = db_connect()
    try:
        conn.execute(
            "UPDATE payg_accounts SET state=?, started_at=?, stopped_at=NULL, last_billed_at=?,"
            " last_seen_at=?, bill_remainder_num=0, last_error='' WHERE id=? AND user_id=?",
            (PAYG_RUNNING, now, now, now, int(payg_id), int(user_id)),
        )
        conn.commit()
    finally:
        conn.close()
    audit_user(int(user_id), "payg_start", f"{row['service']}/{row['protocol'] or '-'} {row['username']}")
    return payg_row_by_id(payg_id, user_id)

def payg_stop(payg_id: int, user_id: int) -> sqlite3.Row:
    row = payg_row_by_id(payg_id, user_id)
    if not row:
        raise ValueError("Akun Pay As You Go tidak ditemukan.")
    if row["state"] == PAYG_RUNNING:
        payg_bill_one(int(payg_id), int(time.time()))
        row = payg_row_by_id(payg_id, user_id)
    ok, err = payg_hold_account(row["service"], row["protocol"], row["username"])
    if not ok:
        raise ValueError("Gagal menghentikan akun. Coba lagi atau hubungi admin.")
    new_state = PAYG_SUSPENDED if wallet_balance_milli(int(user_id)) <= 0 else PAYG_PAUSED
    conn = db_connect()
    try:
        conn.execute(
            "UPDATE payg_accounts SET state=?, stopped_at=?, last_billed_at=?, last_seen_at=0 WHERE id=? AND user_id=?",
            (new_state, int(time.time()), int(time.time()), int(payg_id), int(user_id)),
        )
        conn.commit()
    finally:
        conn.close()
    audit_user(int(user_id), "payg_stop", f"{row['service']}/{row['protocol'] or '-'} {row['username']} {new_state}")
    return payg_row_by_id(payg_id, user_id)

def payg_bill_one(payg_id: int, now: int | None = None) -> None:
    now = int(now or time.time())
    with PAYG_LOCK:
        row = payg_row_by_id(payg_id)
        if not row or row["state"] != PAYG_RUNNING:
            return
        if payg_jeda_state(row["service"], row["protocol"], row["username"]):
            conn = db_connect()
            try:
                conn.execute("UPDATE payg_accounts SET last_billed_at=? WHERE id=?", (now, int(payg_id)))
                conn.commit()
            finally:
                conn.close()
            return
        last = int(row["last_billed_at"] or now)
        elapsed = max(0, now - last)
        if elapsed <= 0:
            return
        settings = get_settings()
        base = payg_base_price(row["service"], settings)
        numerator = elapsed * base * 1000 + int(row["bill_remainder_num"] or 0)
        cost_milli = numerator // PAYG_SECONDS_30D
        remainder = numerator % PAYG_SECONDS_30D
        if cost_milli > 0:
            actual, new_balance = wallet_deduct(
                int(row["user_id"]),
                cost_milli,
                "payg",
                ref=f"payg:{payg_id}",
                note=f"{row['username']} {elapsed}s @ {rupiah(base)}/30h",
            )
        else:
            actual = 0
            new_balance = wallet_balance_milli(int(row["user_id"]))
        state = row["state"]
        stopped = row["stopped_at"]
        last_error = row["last_error"] or ""
        if new_balance <= 0:
            state = PAYG_SUSPENDED
            stopped = now
            remainder = 0
            last_error = "Saldo habis"
        conn = db_connect()
        try:
            conn.execute(
                "UPDATE payg_accounts SET state=?, stopped_at=?, last_billed_at=?, bill_remainder_num=?,"
                " spent_milli=spent_milli+?, total_seconds=total_seconds+?, last_error=? WHERE id=?",
                (state, stopped, now, remainder, abs(int(actual)), elapsed, last_error[:240], int(payg_id)),
            )
            conn.commit()
        finally:
            conn.close()
        if state == PAYG_SUSPENDED:
            ok, err = payg_hold_account(row["service"], row["protocol"], row["username"])
            if not ok:
                conn = db_connect()
                try:
                    conn.execute("UPDATE payg_accounts SET last_error=? WHERE id=?", (err[:240], int(payg_id)))
                    conn.commit()
                finally:
                    conn.close()
            telegram_send(
                f"<b>⛔ PAY AS YOU GO BERHENTI</b>\n"
                f"Akun   : <code>{e(row['username'])}</code>\n"
                f"Layanan: <code>{e(row['service'])}/{e(row['protocol'] or '-')}</code>\n"
                f"Alasan : <code>saldo habis</code>\n"
                f"Sisa   : <code>{rupiah_milli(new_balance)}</code>"
            )
            audit("payg_suspend", f"{row['username']} saldo=0", "")

def payg_enforce_holds() -> None:
    conn = db_connect()
    try:
        rows = conn.execute(
            "SELECT id, service, protocol, username, state FROM payg_accounts WHERE state IN (?,?)",
            (PAYG_PAUSED, PAYG_SUSPENDED),
        ).fetchall()
    finally:
        conn.close()
    for row in rows:
        blocked, _reason = payg_account_is_blocked(row["service"], row["protocol"], row["username"])
        if blocked:
            continue
        ok, err = payg_hold_account(row["service"], row["protocol"], row["username"])
        conn = db_connect()
        try:
            if ok:
                conn.execute("UPDATE payg_accounts SET last_error='' WHERE id=?", (int(row["id"]),))
            else:
                conn.execute("UPDATE payg_accounts SET last_error=? WHERE id=?", (err[:240], int(row["id"])))
                logger.error("PAYG enforce hold gagal %s: %s", row["username"], err)
            conn.commit()
        finally:
            conn.close()

def payg_idle_check(now: int | None = None) -> None:
    """Matikan PAYG yang tidak punya sesi/login aktif selama batas idle."""
    now = int(now or time.time())
    settings = get_settings()
    try:
        idle_minutes = max(1, min(1440, int(settings.get("payg_idle_minutes", "15"))))
    except (TypeError, ValueError):
        idle_minutes = 15
    threshold = idle_minutes * 60
    conn = db_connect()
    try:
        rows = conn.execute(
            "SELECT id,user_id,service,protocol,username,last_seen_at FROM payg_accounts WHERE state=?",
            (PAYG_RUNNING,),
        ).fetchall()
    finally:
        conn.close()
    for row in rows:
        try:
            if row["service"] == "ssh":
                active = ssh_active_session_count(row["username"])
            else:
                active = xray_online_count(row["username"])
            if active is None:
                conn = db_connect()
                try:
                    conn.execute(
                        "UPDATE payg_accounts SET last_error=? WHERE id=?",
                        ("deteksi sesi online gagal", int(row["id"])),
                    )
                    conn.commit()
                finally:
                    conn.close()
                continue
            if active > 0:
                conn = db_connect()
                try:
                    conn.execute(
                        "UPDATE payg_accounts SET last_seen_at=?, last_error='' WHERE id=?",
                        (now, int(row["id"])),
                    )
                    conn.commit()
                finally:
                    conn.close()
                continue
            last_seen = int(row["last_seen_at"] or 0)
            if last_seen <= 0:
                conn = db_connect()
                try:
                    conn.execute(
                        "UPDATE payg_accounts SET last_seen_at=? WHERE id=?",
                        (now, int(row["id"])),
                    )
                    conn.commit()
                finally:
                    conn.close()
                continue
            if now - last_seen < threshold:
                continue
            payg_stop(int(row["id"]), int(row["user_id"]))
            conn = db_connect()
            try:
                conn.execute(
                    "UPDATE payg_accounts SET last_seen_at=0, last_error='' WHERE id=?",
                    (int(row["id"]),),
                )
                conn.commit()
            finally:
                conn.close()
            audit(
                "payg_idle_stop",
                f"{row['service']}/{row['protocol'] or '-'} {row['username']} idle={idle_minutes}m",
                "",
            )
            logger.info("payg idle stop %s (%s menit tanpa sesi)", row["username"], idle_minutes)
        except Exception:
            logger.warning("payg idle check %s: %s", row["id"], traceback.format_exc())

def payg_tick_all() -> None:
    settings = get_settings()
    if settings.get("payg_enabled", "1") != "1":
        return
    conn = db_connect()
    try:
        rows = conn.execute("SELECT id FROM payg_accounts WHERE state=?", (PAYG_RUNNING,)).fetchall()
    finally:
        conn.close()
    for row in rows:
        try:
            payg_bill_one(int(row["id"]))
        except Exception:
            logger.warning("payg billing %s: %s", row["id"], traceback.format_exc())
    try:
        payg_idle_check()
    except Exception:
        logger.warning("payg idle check: %s", traceback.format_exc())
    try:
        payg_enforce_holds()
    except Exception:
        logger.warning("payg enforce holds: %s", traceback.format_exc())

def payg_settle_all() -> None:
    conn = db_connect()
    try:
        rows = conn.execute("SELECT id FROM payg_accounts WHERE state=?", (PAYG_RUNNING,)).fetchall()
    finally:
        conn.close()
    for row in rows:
        try:
            payg_bill_one(int(row["id"]))
        except Exception:
            logger.warning("payg settle %s: %s", row["id"], traceback.format_exc())

def payg_stop_all() -> None:
    conn = db_connect()
    try:
        rows = conn.execute("SELECT id, user_id FROM payg_accounts WHERE state=?", (PAYG_RUNNING,)).fetchall()
    finally:
        conn.close()
    for row in rows:
        try:
            payg_stop(int(row["id"]), int(row["user_id"]))
        except Exception:
            logger.warning("payg stop all %s: %s", row["id"], traceback.format_exc())

def payg_daemon() -> None:
    time.sleep(10)
    while True:
        try:
            payg_tick_all()
        except Exception:
            logger.error("payg daemon: %s", traceback.format_exc())
        time.sleep(30)

def _deposit_code() -> str:
    alphabet = string.ascii_uppercase + string.digits
    for _ in range(30):
        code = "TOP-" + now_jkt().strftime("%y%m%d") + "-" + "".join(secrets.choice(alphabet) for _ in range(8))
        conn = db_connect()
        try:
            if not conn.execute("SELECT 1 FROM deposits WHERE invoice=?", (code,)).fetchone():
                return code
        finally:
            conn.close()
    raise RuntimeError("gagal membuat kode deposit")

def deposit_by_invoice(invoice: str) -> sqlite3.Row | None:
    conn = db_connect()
    try:
        return conn.execute("SELECT * FROM deposits WHERE invoice=?", ((invoice or "").strip().upper(),)).fetchone()
    finally:
        conn.close()

def create_deposit(user_id: int, amount: int, ip: str, user_agent: str) -> sqlite3.Row:
    settings = get_settings()
    if settings.get("maintenance") == "1":
        raise ValueError("Website sedang dalam perawatan. Silakan coba lagi nanti.")
    min_topup = _setting_int(settings, "payg_min_topup", 5000)
    max_topup = _setting_int(settings, "payg_max_topup", 1000000)
    amount = int(amount)
    if amount < min_topup:
        raise ValueError(f"Minimal deposit {rupiah(min_topup)}.")
    if amount > max_topup:
        raise ValueError(f"Maksimal deposit {rupiah(max_topup)} per transaksi.")
    conn = db_connect()
    try:
        active = conn.execute(
            "SELECT COUNT(*) n FROM deposits WHERE user_id=? AND status IN ('PENDING','PAID') AND created_at>=?",
            (int(user_id), int(time.time()) - 3600),
        ).fetchone()["n"]
    finally:
        conn.close()
    if int(active) >= 3:
        raise ValueError("Terlalu banyak invoice deposit aktif. Selesaikan atau tunggu invoice lama kedaluwarsa.")
    unique_code, total = _allocate_total(amount)
    try:
        qr = gopay_build_qris(total)
        if not qr:
            raise ValueError("Gagal membuat QRIS GoPay. Hubungi admin.")
        invoice = _deposit_code()
        now = int(time.time())
        expires = now + int(settings.get("premium_expiry_min", "15")) * 60
        conn = db_connect()
        try:
            conn.execute(
                "INSERT INTO deposits(invoice,user_id,amount,unique_code,total,status,qr_string,"
                "buyer_ip,user_agent,created_at,expires_at) VALUES(?,?,?,?,?,'PENDING',?,?,?,?,?)",
                (invoice, int(user_id), amount, unique_code, total, qr, ip, (user_agent or "")[:300], now, expires),
            )
            conn.commit()
        finally:
            conn.close()
    finally:
        _release_total(total)
    audit_user(int(user_id), "deposit_invoice", f"{invoice} amount={amount} total={total}", ip)
    return deposit_by_invoice(invoice)

def expire_deposits() -> int:
    conn = db_connect()
    try:
        cur = conn.execute(
            "UPDATE deposits SET status='EXPIRED' WHERE status='PENDING' AND expires_at<?",
            (int(time.time()),),
        )
        conn.commit()
        return int(cur.rowcount or 0)
    finally:
        conn.close()

def _deposit_references() -> set[str]:
    conn = db_connect()
    try:
        return {
            str(r[0])
            for r in conn.execute(
                "SELECT reference FROM deposits WHERE reference IS NOT NULL AND reference!=''"
            )
        }
    finally:
        conn.close()

def _credit_deposit(invoice: str, reference: str) -> bool:
    now = int(time.time())
    conn = db_connect()
    user = None
    row = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM deposits WHERE invoice=?", (invoice,)).fetchone()
        if not row or row["status"] == "PAID":
            conn.rollback()
            return False
        amount_milli = int(row["amount"]) * 1000
        user = conn.execute("SELECT balance_milli,email FROM users WHERE id=?", (int(row["user_id"]),)).fetchone()
        if not user:
            conn.rollback()
            return False
        new_balance = int(user["balance_milli"] or 0) + amount_milli
        conn.execute(
            "UPDATE deposits SET status='PAID', reference=?, paid_at=?, credited_milli=?, notified=1 WHERE invoice=?",
            (reference[:120], now, amount_milli, invoice),
        )
        conn.execute(
            "UPDATE users SET balance_milli=?, updated_at=? WHERE id=?",
            (new_balance, now, int(row["user_id"])),
        )
        conn.execute(
            "INSERT INTO wallet_ledger(user_id,at,kind,amount_milli,balance_after_milli,ref,note)"
            " VALUES(?,?,?,?,?,?,?)",
            (int(row["user_id"]), now, "deposit", amount_milli, new_balance, invoice, "Top up saldo"),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        logger.error("credit deposit %s: %s", invoice, traceback.format_exc())
        return False
    finally:
        conn.close()
    audit("deposit_paid", f"{invoice} user={row['user_id']} amount={row['amount']} ref={reference}", row["buyer_ip"])
    telegram_send(
        f"<b>💰 DEPOSIT SALDO MASUK</b>\n"
        f"Invoice : <code>{e(invoice)}</code>\n"
        f"User    : <code>{e(user['email'])}</code>\n"
        f"Nominal : <code>{rupiah(int(row['amount']))}</code>\n"
        f"Saldo   : <code>{rupiah_milli(new_balance)}</code>"
    )
    return True

def poll_deposits() -> None:
    expire_deposits()
    conn = db_connect()
    try:
        rows = conn.execute(
            "SELECT * FROM deposits WHERE status IN ('PENDING','EXPIRED') AND created_at>=? ORDER BY created_at ASC",
            (int(time.time()) - 48 * 86400,),
        ).fetchall()
        refs = {
            str(r["reference"])
            for r in conn.execute("SELECT reference FROM orders WHERE reference IS NOT NULL AND reference!=''")
        }
    finally:
        conn.close()
    pending = _pending_matchable(rows)
    if not pending:
        return
    ready, reason = gopay_ready()
    if not ready:
        pay_state_set("gopay_error", reason)
        return
    used = refs | _bot_paid_references() | _deposit_references()
    matched = 0
    for row in pending:
        txid = gopay_match(int(row["total"]), int(row["created_at"]), used)
        if not txid:
            continue
        used.add(txid)
        if _credit_deposit(row["invoice"], txid):
            matched += 1
            logger.info("deposit paid %s ref=%s", row["invoice"], txid)
    if matched:
        pay_state_set("gopay_last_match", str(int(time.time())))

def deposit_history(user_id: int, limit: int = 50) -> list[sqlite3.Row]:
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT * FROM deposits WHERE user_id=? ORDER BY id DESC LIMIT ?",
            (int(user_id), max(1, int(limit))),
        ).fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Email delivery (Brevo HTTPS API)
# ---------------------------------------------------------------------------

def base_url() -> str:
    host = (PUBLIC_HOST or "").strip().rstrip("/")
    if host.startswith("http://") or host.startswith("https://"):
        return host
    return "https://" + host


def mail_config() -> dict[str, str]:
    cfg = {
        "api_key": "",
        "smtp_user": "",
        "smtp_key": "",
        "smtp_host": "smtp-relay.brevo.com",
        "smtp_port": "2525",
        "from_email": "oceantestdigital@gmail.com",
        "from_name": BRAND,
        "verify_subject": "Kode Verifikasi Anda",
        "reset_subject": "Reset Password — HITS SSH",
    }
    try:
        raw = MAIL_KEY_PATH.read_text(errors="ignore")
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip().upper()
            value = value.strip().strip("'\"")
            if key in ("BREVO_API_KEY", "API_KEY", "MAIL_API_KEY"):
                cfg["api_key"] = value
            elif key in ("SMTP_USER", "MAIL_SMTP_USER", "BREVO_SMTP_USER"):
                cfg["smtp_user"] = value
            elif key in ("SMTP_KEY", "SMTP_PASSWORD", "MAIL_SMTP_KEY", "BREVO_SMTP_KEY"):
                cfg["smtp_key"] = value
            elif key in ("SMTP_HOST", "MAIL_SMTP_HOST"):
                cfg["smtp_host"] = value
            elif key in ("SMTP_PORT", "MAIL_SMTP_PORT"):
                cfg["smtp_port"] = value
            elif key in ("MAIL_FROM_EMAIL", "FROM_EMAIL", "MAIL_FROM"):
                cfg["from_email"] = value
            elif key in ("MAIL_FROM_NAME", "FROM_NAME"):
                cfg["from_name"] = value
            elif key in ("MAIL_VERIFY_SUBJECT", "VERIFY_SUBJECT"):
                cfg["verify_subject"] = value
            elif key in ("MAIL_RESET_SUBJECT", "RESET_SUBJECT"):
                cfg["reset_subject"] = value
    except FileNotFoundError:
        pass
    try:
        settings = get_settings()
        cfg["api_key"] = cfg["api_key"] or (settings.get("mail_api_key") or "").strip()
        cfg["smtp_key"] = cfg["smtp_key"] or (settings.get("mail_smtp_key") or "").strip()
        cfg["smtp_user"] = (settings.get("mail_smtp_user") or cfg["smtp_user"]).strip()
        cfg["smtp_host"] = (settings.get("mail_smtp_host") or cfg["smtp_host"]).strip()
        cfg["smtp_port"] = (settings.get("mail_smtp_port") or cfg["smtp_port"]).strip()
        cfg["from_email"] = (settings.get("mail_from_email") or cfg["from_email"]).strip()
        cfg["from_name"] = (settings.get("mail_from_name") or cfg["from_name"]).strip()
        cfg["verify_subject"] = (settings.get("mail_verify_subject") or cfg["verify_subject"]).strip()
        cfg["reset_subject"] = (settings.get("mail_reset_subject") or cfg["reset_subject"]).strip()
    except Exception:
        pass
    return cfg


def mail_ready() -> tuple[bool, str]:
    cfg = mail_config()
    if cfg["api_key"]:
        if not cfg["api_key"].startswith("xkeysib-"):
            return False, "API key Brevo harus diawali xkeysib-."
        return (True, "") if cfg["from_email"] else (False, "Alamat pengirim email belum diatur.")
    if cfg["smtp_key"]:
        if not cfg["smtp_key"].startswith("xsmtpsib-"):
            return False, "SMTP key Brevo harus diawali xsmtpsib-."
        if not cfg["smtp_user"]:
            return False, "SMTP Login Brevo belum diisi (bukan email pengirim)."
        return (True, "") if cfg["from_email"] else (False, "Alamat pengirim email belum diatur.")
    return False, "Isi API key xkeysib- atau SMTP Login + SMTP key xsmtpsib-."


class _IPv4HTTPSConnection(http.client.HTTPSConnection):
    """Koneksi HTTPS yang dipaksa lewat IPv4 agar whitelist IP Brevo stabil."""

    def connect(self):
        infos = socket.getaddrinfo(self.host, self.port, socket.AF_INET, socket.SOCK_STREAM)
        if not infos:
            raise OSError("no IPv4 address for " + str(self.host))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(infos[0][4])
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _send_email_api(cfg: dict[str, str], to_email: str, subject: str, html_body: str, text_body: str) -> tuple[bool, str]:
    payload = {
        "sender": {"name": cfg["from_name"] or BRAND, "email": cfg["from_email"]},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_body,
        "textContent": text_body,
        "replyTo": {"name": cfg["from_name"] or BRAND, "email": cfg["from_email"]},
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": cfg["api_key"],
        "content-length": str(len(body)),
    }
    conn = None
    try:
        conn = _IPv4HTTPSConnection("api.brevo.com", timeout=20, context=ssl.create_default_context())
        conn.request("POST", "/v3/smtp/email", body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", "replace")[:600]
        if 200 <= resp.status < 300:
            return True, ""
        logger.warning("brevo api status %s: %s", resp.status, data)
        if resp.status in (401, 403) and "authorised_ips" in data:
            return False, "IP VPS belum diizinkan di Brevo (Security → Authorised IPs)."
        return False, "Email gagal dikirim. Coba lagi beberapa saat."
    except Exception as exc:
        logger.warning("brevo api error: %s", exc)
        return False, "Email gagal dikirim. Coba lagi beberapa saat."
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _send_email_smtp(cfg: dict[str, str], to_email: str, subject: str, html_body: str, text_body: str) -> tuple[bool, str]:
    host = cfg["smtp_host"] or "smtp-relay.brevo.com"
    try:
        port = int(cfg["smtp_port"] or "2525")
    except ValueError:
        port = 2525
    safe_subject = (subject or "").replace("\n", " ").replace("\r", " ")[:200]
    msg = EmailMessage()
    msg["From"] = formataddr((cfg["from_name"] or BRAND, cfg["from_email"]))
    msg["To"] = to_email
    msg["Subject"] = safe_subject
    msg["Reply-To"] = formataddr((cfg["from_name"] or BRAND, cfg["from_email"]))
    msg["X-Mailer"] = BRAND
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=25, context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(host, port, timeout=25)
        try:
            server.ehlo()
            if port != 465 and server.has_extn("starttls"):
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
            server.login(cfg["smtp_user"], cfg["smtp_key"])
            server.send_message(msg)
            return True, ""
        finally:
            try:
                server.quit()
            except Exception:
                pass
    except smtplib.SMTPAuthenticationError:
        logger.warning("brevo smtp auth gagal untuk user %s", cfg["smtp_user"])
        return False, "SMTP Login atau SMTP key Brevo salah."
    except Exception as exc:
        logger.warning("brevo smtp error: %s", exc)
        return False, "Email gagal dikirim via SMTP. Coba lagi beberapa saat."


def send_email(to_email: str, subject: str, html_body: str, text_body: str) -> tuple[bool, str]:
    cfg = mail_config()
    api_ok = bool(cfg["api_key"]) and cfg["api_key"].startswith("xkeysib-")
    smtp_ok = bool(cfg["smtp_key"]) and cfg["smtp_key"].startswith("xsmtpsib-") and bool(cfg["smtp_user"])
    if api_ok:
        ok, message = _send_email_api(cfg, to_email, subject, html_body, text_body)
        if ok:
            return True, ""
        if not smtp_ok:
            return False, message
        logger.warning("Brevo API gagal, mencoba SMTP fallback")
    if smtp_ok:
        return _send_email_smtp(cfg, to_email, subject, html_body, text_body)
    logger.warning("email ke %s dilewati: Brevo API/SMTP belum lengkap", to_email)
    return False, "Pengiriman email belum dikonfigurasi. Hubungi admin."


def email_layout(title: str, intro: str, button: str, url: str, note: str, code: str = "") -> tuple[str, str]:
    b = branding()
    name = e(b["name"])
    code_html = ""
    code_text = ""
    if code:
        code_html = f"""
<tr><td style="padding:6px 30px 0">
<div style="border:1px dashed #d9bf9f;border-radius:14px;background:#fff8ed;padding:16px 18px;text-align:center">
<div style="color:#8b7562;font-size:11px;letter-spacing:1.5px;font-weight:700">KODE VERIFIKASI</div>
<div style="margin-top:6px;color:#30241d;font-size:34px;line-height:1.1;font-weight:800;letter-spacing:9px">{e(code)}</div>
<div style="margin-top:6px;color:#8b7562;font-size:11px">Masukkan kode ini di halaman verifikasi.</div>
</div>
</td></tr>"""
        code_text = f"\nKode verifikasi: {code}\n"
    html_body = f"""<!doctype html>
<html lang="id"><body style="margin:0;padding:0;background:#f6f1e8;font-family:Arial,Helvetica,sans-serif;color:#30241d">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">Klik tombol verifikasi atau masukkan kode 6 digit dari email ini.</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f6f1e8;padding:28px 12px">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#fffdf8;border:1px solid #e6d3bd;border-radius:18px;overflow:hidden">
<tr><td style="padding:26px 30px 8px">
<div style="font-size:12px;letter-spacing:2px;color:#a63f23;font-weight:700">{name}</div>
<h1 style="margin:12px 0 8px;font-size:26px;line-height:1.2;color:#30241d">{e(title)}</h1>
<p style="margin:0;color:#6b5544;font-size:14px;line-height:1.65">{e(intro)}</p>
<p style="margin:10px 0 0;color:#30241d;font-size:13px;line-height:1.6"><b>Klik tombol biru di bawah ini.</b> Kalau tombol tidak terlihat, salin tautan panjang di bagian bawah email ke browser.</p>
</td></tr>
{code_html}
<tr><td style="padding:22px 30px 10px">
<a href="{e(url)}" style="display:inline-block;background:#a63f23;color:#fffdf8;text-decoration:none;font-weight:700;font-size:15px;padding:15px 28px;border-radius:999px">✅ {e(button)}</a>
</td></tr>
<tr><td style="padding:8px 30px 26px">
<p style="margin:0 0 8px;color:#6b5544;font-size:12px;line-height:1.6">{e(note)}</p>
<p style="margin:0 0 5px;color:#8b7562;font-size:11px">Jika tombol tidak bisa diklik, salin <b>link verifikasi</b> ini:</p>
<p style="margin:0;color:#8b7562;font-size:11px;line-height:1.6;word-break:break-all">{e(url)}</p>
</td></tr>
<tr><td style="padding:16px 30px;background:#fbf1e3;color:#8b7562;font-size:11px;line-height:1.6">
Email otomatis dari {name}. Jangan bagikan tautan/kode ini ke siapa pun.
</td></tr>
</table>
</td></tr></table>
</body></html>"""
    text_body = (
        f"{title}\n\n{intro}\n{code_text}\n{button}: {url}\n\n{note}\n\n{name}"
    )
    return html_body, text_body


def send_verification_email(user: sqlite3.Row, raw_token: str, code: str = "") -> tuple[bool, str]:
    cfg = mail_config()
    url = f"{base_url()}/verify?token={urllib.parse.quote(raw_token)}"
    html_body, text_body = email_layout(
        "Kode verifikasi Anda",
        f"Halo, terima kasih sudah mendaftar di {branding()['name']}. Verifikasi email untuk mengaktifkan akun Anda.",
        "Buka Link Verifikasi",
        url,
        "Link dan kode verifikasi berlaku 24 jam. Jika Anda tidak mendaftar, abaikan email ini.",
        code=code,
    )
    return send_email(user["email"], cfg["verify_subject"] or "Kode Verifikasi Anda", html_body, text_body)


def send_reset_email(user: sqlite3.Row, raw_token: str) -> tuple[bool, str]:
    cfg = mail_config()
    url = f"{base_url()}/reset-password?token={urllib.parse.quote(raw_token)}"
    html_body, text_body = email_layout(
        "Atur ulang password",
        "Kami menerima permintaan untuk mengatur ulang password akun Anda. Klik tombol di bawah untuk membuat password baru.",
        "Buat password baru",
        url,
        "Tautan berlaku 1 jam dan hanya bisa dipakai sekali. Jika bukan Anda, abaikan email ini.",
    )
    return send_email(user["email"], cfg["reset_subject"] or "Reset Password", html_body, text_body)


# ---------------------------------------------------------------------------
# VPS account operations
# ---------------------------------------------------------------------------

def run_panel_script(
    args: list[str],
    answers: list[str],
    timeout: int = 120,
    extra_env: dict[str, str] | None = None,
) -> tuple[int, str]:
    env = os.environ.copy()
    env.update({"TERM": "dumb", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    if extra_env:
        env.update({str(k): str(v) for k, v in extra_env.items()})
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


DNS_MODE_FILE = Path("/etc/kyt-dns-mode")
SLOWDNS_DOMAIN_FILES = (Path("/etc/xray/dns"), Path("/root/slowdns/dns_domain"))
SLOWDNS_PUB_FILES = (Path("/root/slowdns/server.pub"), Path("/etc/slowdns/server.pub"))
XRAY_DNS_LABELS = {
    "xray-tls": "Xray TLS (443)",
    "xray-auto": "Xray AUTO (80+443)",
    "xray-ntls": "Xray NTLS (80)",
}
SLOWDNS_FIELD_RE = re.compile(
    r"(?m)^[ \t]*(?:Host Slowdns|Pub(?:lic)? Key|Mode SlowDNS)[ \t]*:[^\n]*\n?"
)

def _read_first(paths: tuple[Path, ...]) -> str:
    for path in paths:
        try:
            value = path.read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            continue
        if value:
            return value
    return ""

def dns_mode() -> str:
    """Mode SlowDNS aktif, mengikuti /etc/kyt-dns-mode dari menu VPS."""
    try:
        return DNS_MODE_FILE.read_text(errors="ignore").strip() or "off"
    except OSError:
        return "off"

def slowdns_info(kind: str) -> list[tuple[str, str]]:
    """Info Host Slowdns/Pub Key yang sama dengan `slowdns-info` di VPS.

    kind="ssh"  -> hanya tampil saat mode DNS = ssh.
    kind="xray" -> hanya tampil saat mode DNS = xray-*.
    """
    mode = dns_mode()
    label = ""
    if kind == "ssh":
        if mode != "ssh":
            return []
    else:
        label = XRAY_DNS_LABELS.get(mode, "")
        if not label:
            return []
    host = _read_first(SLOWDNS_DOMAIN_FILES)
    pubkey = _read_first(SLOWDNS_PUB_FILES)
    info: list[tuple[str, str]] = []
    if host:
        info.append(("Host Slowdns", host))
    if pubkey:
        info.append(("Pub Key", pubkey))
    if label and (host or pubkey):
        info.append(("Mode SlowDNS", label))
    return info

def format_ssh_output(raw: str, expiry_label: str | None = None) -> str:
    """Rapikan output akun SSH ke format kartu klasik HITS SSH.

    Host Slowdns, Pub Key, dan Port SlowDNS diambil otomatis dari mode DNS
    yang sedang aktif di VPS, jadi output lama ikut menyesuaikan saat mode
    diganti lewat menu.
    """
    raw = clean_output(raw or "")
    if not raw:
        return raw

    username = _ssh_field(raw, "Username")
    password = _ssh_field(raw, "Password")
    if not username or not password:
        return raw

    settings = get_settings()
    host = _ssh_field(raw, "Host") or (settings.get("domain") or "").strip()
    expiry = _ssh_field(raw, "Berakhir Pada") or _ssh_field(raw, "Expired until")
    if not expiry and _ssh_field(raw, "Aktif Selama"):
        expiry = _ssh_field(raw, "Aktif Selama")
    if expiry_label is not None:
        expiry = expiry_label
    dns_info = slowdns_info("ssh")

    ports = [
        ("Port OpenSSH", "443, 80, 22"),
        ("Port SSH UDP", "1-65535"),
        ("Port Dropbear", "443, 109"),
        ("Port SSH WS", "80, 8080, 8081-9999"),
        ("Port SSH SSL WS", "443"),
        ("HCR", "8811 (TLS + Plain; akun SSH)"),
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
    for label, value in dns_info:
        out.append(f" {label:<17}: {value}")
    for label, default in ports:
        value = _ssh_field(raw, label) or default
        if label == "Port OVPN TCP" and value and "443" not in value:
            value = f"443, {value}"
        out.append(f" {label:<17}: {value}")
        if label == "HCR" and dns_info:
            out.append(f" {'Port SlowDNS':<17}: 53, 80, 443")
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


def _xray_output_host(raw: str) -> str:
    match = re.search(
        r"(?m)^[ \t]*(?:server|sni|host)[ \t]*:[ \t]*([^\s#]+)",
        raw,
        re.IGNORECASE,
    )
    return match.group(1).strip() if match else ""

def format_xray_output(raw: str, protocol: str = "") -> str:
    """Tambahkan info SlowDNS ke output Xray sesuai mode DNS yang aktif.

    Mode xray-*  -> tampil Host, Host Slowdns, Pub Key, dan Mode SlowDNS.
    Mode ssh/off -> baris SlowDNS lama dibuang supaya tidak menyesatkan.
    """
    raw = clean_output(raw or "")
    raw = SLOWDNS_FIELD_RE.sub("", raw)
    raw = re.sub(r"\n{3,}", "\n\n", raw).strip("\n")
    if not raw:
        return raw
    info = slowdns_info("xray")
    if not info:
        return raw
    settings = get_settings()
    host = (settings.get("domain") or "").strip() or _xray_output_host(raw)
    block: list[str] = [SSH_BOX_SEP, " Xray DNS Account", SSH_BOX_SEP]
    if host:
        block.append(f" {'Host':<17}: {host}")
    for label, value in info:
        block.append(f" {label:<17}: {value}")
    block.append(SSH_BOX_SEP)
    return "\n".join(block) + "\n" + raw

def format_account_output(service: str, protocol: str, raw: str, kind: str = "") -> str:
    if service == "ssh":
        expiry_label = "Pay As You Go · tanpa masa aktif tetap" if kind == "payg" else None
        return format_ssh_output(raw, expiry_label=expiry_label)
    if service == "xray":
        return format_xray_output(raw, protocol)
    return clean_output(raw or "")

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


def create_ssh_account(
    user: str,
    password: str,
    days: int,
    ip_limit: int,
    quota_gb: int,
    extra_env: dict[str, str] | None = None,
) -> tuple[bool, str, str]:
    rc, log = run_panel_script(
        [SSH_SCRIPT],
        [user, password, str(ip_limit), str(quota_gb), str(days)],
        timeout=120,
        extra_env=extra_env,
    )
    ok, reason = verify_ssh(user, password)
    if ok:
        output = format_ssh_output(
            read_account_output("ssh", user),
            expiry_label=(extra_env or {}).get("KYT_EXPIRES_LABEL"),
        )
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


def create_xray_account(
    protocol: str,
    user: str,
    days: int,
    ip_limit: int,
    quota_gb: int,
    extra_env: dict[str, str] | None = None,
) -> tuple[bool, str, str]:
    cfg = PROTOCOLS[protocol]
    rc, log = run_panel_script(
        [cfg["script"]],
        [user, str(days), str(quota_gb), str(ip_limit)],
        timeout=120,
        extra_env=extra_env,
    )
    ok, reason = verify_xray(protocol, user)
    if ok:
        return True, read_account_output("ssh" if False else "xray", user, protocol), log
    logger.error(
        "gagal membuat XRAY %s/%s rc=%s reason=%s\n%s", protocol, user, rc, reason, log[-4000:]
    )
    remove_xray_account(protocol, user)
    return False, reason, log


def create_account(service: str, protocol: str, days: int, ip: str, user_agent: str, user_id: int = 0) -> dict:
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
                "created_day,expires_at,status,output,error,user_agent,user_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                    int(user_id or 0),
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

GOPAY_REFRESH_LOCK = threading.Lock()
_GOPAY_LAST_REFRESH = 0.0
GOPAY_REFRESH_COOLDOWN = 5 * 60

def _save_gopay_token(token: str, refresh: str = "") -> None:
    token = (token or "").strip()
    if not token:
        return
    data: dict[str, str] = {}
    try:
        with open(GOPAY_TOKEN_FILE, "r", errors="ignore") as fh:
            existing = json.load(fh) or {}
            if isinstance(existing, dict):
                data.update({str(k): str(v) for k, v in existing.items() if v})
    except Exception:
        pass
    data["token"] = token
    if refresh:
        data["refresh_token"] = str(refresh).strip()
    try:
        tmp = str(GOPAY_TOKEN_FILE) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, str(GOPAY_TOKEN_FILE))
    except Exception:
        logger.warning("gagal menyimpan token GoPay: %s", traceback.format_exc())
    try:
        conn = sqlite3.connect(BOT_KYT_DB, timeout=10)
        try:
            conn.execute(
                "INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                ("gomerch_token", token),
            )
            if refresh:
                conn.execute(
                    "INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    ("gomerch_refresh_token", str(refresh).strip()),
                )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        logger.warning("gagal menyimpan token GoPay ke database bot: %s", traceback.format_exc())

def gopay_refresh_token(force: bool = False) -> str:
    """Refresh access token GoPay memakai refresh_token yang tersimpan."""
    global _GOPAY_LAST_REFRESH
    with GOPAY_REFRESH_LOCK:
        if not force and time.time() - _GOPAY_LAST_REFRESH < GOPAY_REFRESH_COOLDOWN:
            return ""
        cfg = gopay_config()
        refresh = (cfg.get("refresh_token") or "").strip()
        if not refresh:
            return ""
        url = cfg["base"] + "/auth/refresh/token?" + urllib.parse.urlencode({"refresh_token": refresh})
        try:
            with urllib.request.urlopen(url, timeout=20) as resp:
                raw = resp.read().decode("utf-8", "replace")
            data = json.loads(raw)
        except Exception as exc:
            logger.warning("gopay refresh error: %s", exc)
            return ""
        if not data.get("success"):
            logger.warning("gopay refresh ditolak: %s", str(data)[:500])
            return ""
        item = data.get("data") or {}
        new_token = item.get("access_token") or item.get("token") or ""
        new_refresh = item.get("refresh_token") or item.get("refreshToken") or ""
        if not new_token:
            logger.warning("gopay refresh tanpa access_token: %s", str(data)[:500])
            return ""
        _save_gopay_token(str(new_token), str(new_refresh))
        _GOPAY_LAST_REFRESH = time.time()
        pay_state_set("gopay_error", "")
        pay_state_set("gopay_token_invalid", "")
        pay_state_set("gopay_last_ok", str(int(time.time())))
        logger.info("token GoPay berhasil di-refresh")
        return str(new_token)


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
        def _fetch_history(token: str) -> dict:
            url = cfg["base"] + "/api/history?" + urllib.parse.urlencode({"token": token})
            with urllib.request.urlopen(url, timeout=20) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))

        try:
            data = _fetch_history(cfg["token"])
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 401):
                new_token = gopay_refresh_token()
                if new_token:
                    try:
                        data = _fetch_history(new_token)
                    except urllib.error.HTTPError as retry_exc:
                        if retry_exc.code == 429:
                            _GOPAY_RATE_UNTIL = time.time() + 16 * 60
                            pay_state_set("gopay_error", "Rate limit GoPay (429), tunggu 16 menit")
                        elif retry_exc.code in (400, 401):
                            pay_state_set("gopay_error", "Refresh token GoPay gagal; login OTP lewat bot")
                            pay_state_set("gopay_token_invalid", str(int(time.time())))
                        else:
                            pay_state_set("gopay_error", f"HTTP {retry_exc.code} dari gateway")
                        logger.warning("gopay history retry HTTP %s", retry_exc.code)
                        return []
                    except Exception as retry_exc:
                        pay_state_set("gopay_error", f"Gagal koneksi gateway: {retry_exc}")
                        logger.warning("gopay history retry error: %s", retry_exc)
                        return []
                else:
                    pay_state_set("gopay_error", "Token GoPay expired; login OTP lewat bot")
                    pay_state_set("gopay_token_invalid", str(int(time.time())))
                    logger.warning("gopay history HTTP %s; refresh token gagal", exc.code)
                    return []
            elif exc.code == 429:
                _GOPAY_RATE_UNTIL = time.time() + 16 * 60
                pay_state_set("gopay_error", "Rate limit GoPay (429), tunggu 16 menit")
                logger.warning("gopay history HTTP %s", exc.code)
                return []
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


PREMIUM_UNIQUE_MAX = 50
PREMIUM_EXPIRED_GRACE = 3600  # kode EXPIRED diamankan 1 jam dari pembayaran telat
RESERVED_TOTALS: set[int] = set()


def _release_total(total: int) -> None:
    with UNIQUE_CODE_LOCK:
        RESERVED_TOTALS.discard(int(total))


def _allocate_total(price: int) -> tuple[int, int]:
    """Kode unik 1..50 diacak. Kode bebas lagi setelah invoice selesai/expired."""
    with UNIQUE_CODE_LOCK:
        settings = get_settings()
        try:
            last = int(settings.get("premium_unique_last", "0") or 0)
        except (TypeError, ValueError):
            last = 0
        now = int(time.time())
        conn = db_connect()
        try:
            used = {
                int(r["total"])
                for r in conn.execute(
                    "SELECT total FROM orders "
                    "WHERE status IN ('PENDING','PAID','PROVISIONING') "
                    "OR (status='EXPIRED' AND expires_at>=?)",
                    (now - PREMIUM_EXPIRED_GRACE,),
                )
            }
            used |= {
                int(r["total"])
                for r in conn.execute(
                    "SELECT total FROM deposits "
                    "WHERE status IN ('PENDING','PAID') "
                    "OR (status='EXPIRED' AND expires_at>=?)",
                    (now - PREMIUM_EXPIRED_GRACE,),
                )
            }
        finally:
            conn.close()
        used |= RESERVED_TOTALS
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
        candidates = [
            code
            for code in range(1, PREMIUM_UNIQUE_MAX + 1)
            if int(price) + code not in used and int(price) + code not in bot_amounts
        ]
        if not candidates:
            raise ValueError("Nomor unik invoice habis sementara. Coba lagi beberapa saat.")
        if last in candidates and len(candidates) > 1:
            candidates.remove(last)
        code = secrets.choice(candidates)
        total = int(price) + code
        RESERVED_TOTALS.add(total)
        set_settings({"premium_unique_last": str(code)})
        return code, total


def order_by_invoice(invoice: str) -> sqlite3.Row | None:
    conn = db_connect()
    try:
        return conn.execute("SELECT * FROM orders WHERE invoice=?", (invoice,)).fetchone()
    finally:
        conn.close()


def create_premium_order(product_code: str, ip: str, user_agent: str, user_id: int = 0) -> sqlite3.Row:
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
    try:
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
                "ip_limit,quota_gb,status,qr_string,buyer_ip,user_agent,created_at,expires_at,user_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,'PENDING',?,?,?,?,?,?)",
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
                    int(user_id or 0),
                ),
            )
            conn.commit()
        finally:
            conn.close()
    finally:
        _release_total(total)
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


def _pending_matchable(rows, now: int | None = None) -> list:
    """Invoice yang masih boleh dicocokkan dengan pembayaran GoPay."""
    now = int(time.time()) if now is None else int(now)
    result = []
    for row in rows:
        if row["status"] not in ("PENDING", "EXPIRED") or row["reference"]:
            continue
        if row["status"] == "EXPIRED" and int(row["expires_at"] or 0) < now - PREMIUM_EXPIRED_GRACE:
            continue
        result.append(row)
    return result


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
    pending = _pending_matchable(rows)
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
    used = set(refs) | _bot_paid_references() | _deposit_references()
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
            poll_deposits()
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
# Dashboard data: usage, IP login, and mullog status
# ---------------------------------------------------------------------------

MULLOG_STATE_DIR = MIHOMO_STATE / "state"
MULLOG_HISTORY = MIHOMO_STATE / "history.jsonl"


def _int_file(path: Path | str) -> int:
    try:
        value = Path(path).read_text(errors="ignore").strip()
        return max(0, int(value)) if value else 0
    except Exception:
        return 0


def _read_state_file(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(errors="ignore"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def mullog_states() -> list[dict]:
    result = []
    try:
        names = sorted(MULLOG_STATE_DIR.glob("*.json"))
    except Exception:
        return result
    for path in names:
        state = _read_state_file(path)
        if state:
            state["_file"] = path.name
            result.append(state)
    return result


def mullog_state_for(states: list[dict], user: str, proto: str = "") -> dict | None:
    for state in states:
        if str(state.get("user", "")) != user:
            continue
        if proto and str(state.get("proto", "")) != proto:
            continue
        return state
    return None


def mullog_history(user: str, limit: int = 100) -> list[dict]:
    events: list[dict] = []
    try:
        with open(MULLOG_HISTORY, "r", errors="ignore") as fh:
            lines = fh.readlines()[-3000:]
    except FileNotFoundError:
        return events
    for raw in lines:
        try:
            item = json.loads(raw)
        except Exception:
            continue
        if not isinstance(item, dict) or str(item.get("user", "")) != user:
            continue
        events.append(item)
    events.sort(key=lambda x: int(x.get("ts", 0)), reverse=True)
    suspend_by_key: dict[tuple, dict] = {}
    for item in events:
        if item.get("event") == "suspend":
            key = (item.get("kind"), item.get("proto") or "", int(item.get("created", 0) or 0))
            suspend_by_key.setdefault(key, item)
    for item in events:
        if item.get("event") == "restore":
            key = (item.get("kind"), item.get("proto") or "", int(item.get("created", 0) or 0))
            target = suspend_by_key.get(key)
            if target is not None:
                target["restored_at"] = item.get("ts")
    return events[:limit]


def account_paths(service: str, protocol: str, username: str) -> dict[str, Path]:
    if service == "ssh":
        return {
            "quota": Path("/etc/ssh") / username,
            "usage": Path("/etc/limit/ssh") / username,
            "ip": Path("/etc/kyt/limit/ssh/ip") / username,
        }
    return {
        "quota": Path("/etc") / protocol / username,
        "usage": Path("/etc/limit") / protocol / username,
        "ip": Path("/etc/kyt/limit") / protocol / "ip" / username,
    }


def _strip_hostport(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    # Xray kadang menulis sumber sebagai "tcp:1.2.3.4:0" atau "udp://...".
    value = re.sub(r"^(?:tcp|udp):(?://)?", "", value, flags=re.I)
    if value.startswith("["):
        return value[1:].split("]", 1)[0]
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            return host
    return value


def _local_ip(value: str) -> bool:
    return value in ("127.0.0.1", "::1", "::", "0.0.0.0") or value.startswith("127.")


def _tail_lines(path: Path, count: int = 5000) -> list[str]:
    try:
        if not path.exists():
            return []
        proc = subprocess.run(
            ["tail", "-n", str(count), str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=8,
        )
        return proc.stdout.splitlines()
    except Exception:
        return []


def collect_xray_ips(usernames: set[str], minutes: int = 20) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {name: set() for name in usernames}
    if not usernames:
        return result
    now = dt.datetime.now()
    cutoff = now - dt.timedelta(minutes=max(1, minutes))
    pattern = re.compile(
        r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\.\d+\s+from\s+(\S+)\s+accepted\b.*?\bemail:\s*(\S+)"
    )
    for line in _tail_lines(Path("/var/log/xray/access.log"), 6000):
        match = pattern.search(line)
        if not match:
            continue
        try:
            stamp = dt.datetime.strptime(match.group(1), "%Y/%m/%d %H:%M:%S")
        except ValueError:
            continue
        if stamp < cutoff:
            continue
        user = match.group(3)
        if user not in result:
            continue
        ip = _strip_hostport(match.group(2))
        if ip and not _local_ip(ip):
            result[user].add(ip)
    return result


def _ssh_listener_ports() -> set[str]:
    ports: set[str] = set()
    try:
        proc = subprocess.run(
            ["ss", "-tlnpH"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=8,
        )
    except Exception:
        return ports
    for line in proc.stdout.splitlines():
        if "sshd" not in line and "dropbear" not in line:
            continue
        fields = line.split()
        if len(fields) >= 4:
            ports.add(fields[3].rsplit(":", 1)[-1])
    return ports or {"22", "2222", "2223", "109", "143"}


def _pid_user(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/status", "r", errors="ignore") as fh:
            for line in fh:
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    return pwd.getpwuid(uid).pw_name
    except Exception:
        pass
    return ""


def _ws_peer_map() -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for line in Path("/run/ws-ssh.map").read_text(errors="ignore").splitlines()[-400:]:
            parts = line.split()
            if len(parts) >= 3:
                result[parts[1]] = parts[2]
    except Exception:
        pass
    return result


def collect_ssh_ips(usernames: set[str], minutes: int = 30) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {name: set() for name in usernames}
    if not usernames:
        return result
    ports = _ssh_listener_ports()
    ws_map = _ws_peer_map()
    try:
        proc = subprocess.run(
            ["ss", "-tnpH"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
        for line in proc.stdout.splitlines():
            if "ESTAB" not in line and "SYN-RECV" not in line:
                continue
            if "sshd" not in line and "dropbear" not in line:
                continue
            fields = line.split()
            if len(fields) < 5:
                continue
            local_port = fields[3].rsplit(":", 1)[-1]
            if local_port not in ports:
                continue
            peer_ip = _strip_hostport(fields[4])
            peer_port = fields[4].rsplit(":", 1)[-1]
            pid_match = re.search(r"pid=(\d+)", line)
            if not pid_match:
                continue
            user = _pid_user(int(pid_match.group(1)))
            if user not in result:
                continue
            if _local_ip(peer_ip):
                peer_ip = ws_map.get(peer_port, "")
            if peer_ip and not _local_ip(peer_ip):
                result[user].add(peer_ip)
    except Exception:
        pass

    missing = {name for name in usernames if not result[name]}
    if missing:
        now = dt.datetime.now(dt.timezone.utc)
        cutoff = now - dt.timedelta(minutes=max(1, minutes))
        regex = re.compile(
            r"^(\S+)\s+\S+\s+sshd(?:-session)?\[\d+\]:\s+Accepted\s+(?:password|publickey|keyboard-interactive)\s+for\s+(\S+)\s+from\s+(\S+)\s+port"
        )
        for line in _tail_lines(Path("/var/log/auth.log"), 6000):
            match = regex.search(line)
            if not match or match.group(2) not in missing:
                continue
            try:
                stamp = dt.datetime.fromisoformat(match.group(1))
                if stamp.tzinfo is None:
                    stamp = stamp.replace(tzinfo=dt.timezone.utc)
            except ValueError:
                continue
            if stamp < cutoff:
                continue
            ip = _strip_hostport(match.group(3))
            if ip and not _local_ip(ip):
                result[match.group(2)].add(ip)
    return result


def collect_online_ips(accounts: list[dict]) -> dict[str, list[str]]:
    xray_users = {a["username"] for a in accounts if a["service"] == "xray"}
    ssh_users = {a["username"] for a in accounts if a["service"] == "ssh"}
    merged: dict[str, set[str]] = {}
    for name, ips in collect_xray_ips(xray_users).items():
        merged.setdefault(name, set()).update(ips)
    for name, ips in collect_ssh_ips(ssh_users).items():
        merged.setdefault(name, set()).update(ips)
    return {name: sorted(ips) for name, ips in merged.items()}


def usage_snapshot_once() -> None:
    conn = db_connect()
    try:
        rows = conn.execute(
            "SELECT username, service, protocol, created_at FROM accounts WHERE status='active' "
            "UNION ALL "
            "SELECT account_username AS username, "
            "CASE WHEN protocol='ssh' THEN 'ssh' ELSE 'xray' END AS service, "
            "protocol, COALESCE(paid_at, created_at) AS created_at FROM orders "
            "WHERE status='COMPLETED' AND account_username<>''"
        ).fetchall()
    finally:
        conn.close()
    day = today_key()
    day_start = int(now_jkt().replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    seen: set[str] = set()
    conn = db_connect()
    try:
        for row in rows:
            username = row["username"]
            if not username or username in seen:
                continue
            seen.add(username)
            current = _int_file(account_paths(row["service"], row["protocol"], username)["usage"])
            baseline = 0 if int(row["created_at"] or 0) >= day_start else current
            conn.execute(
                "INSERT OR IGNORE INTO usage_daily(username,day,start_bytes) VALUES(?,?,?)",
                (username, day, baseline),
            )
        conn.commit()
    finally:
        conn.close()


def usage_snapshot_loop() -> None:
    while True:
        try:
            usage_snapshot_once()
        except Exception:
            logger.warning("usage snapshot gagal: %s", traceback.format_exc())
        time.sleep(60)


def usage_today(username: str, current: int, created_at: int) -> int:
    day = today_key()
    conn = db_connect()
    try:
        row = conn.execute(
            "SELECT start_bytes FROM usage_daily WHERE username=? AND day=?",
            (username, day),
        ).fetchone()
        if row is None:
            day_start = int(now_jkt().replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
            baseline = 0 if int(created_at or 0) >= day_start else int(current)
            conn.execute(
                "INSERT OR IGNORE INTO usage_daily(username,day,start_bytes) VALUES(?,?,?)",
                (username, day, baseline),
            )
            conn.commit()
            return max(0, int(current) - baseline)
        return max(0, int(current) - int(row["start_bytes"]))
    finally:
        conn.close()


def user_orders(user_id: int) -> list[sqlite3.Row]:
    conn = db_connect()
    try:
        return conn.execute(
            "SELECT * FROM orders WHERE user_id=? ORDER BY id DESC",
            (int(user_id),),
        ).fetchall()
    finally:
        conn.close()


def user_accounts(user_id: int) -> list[dict]:
    now = int(time.time())
    states = mullog_states()
    conn = db_connect()
    try:
        free_rows = conn.execute(
            "SELECT * FROM accounts WHERE user_id=? AND status IN ('active','failed') AND kind='free' ORDER BY id DESC",
            (int(user_id),),
        ).fetchall()
        order_rows = conn.execute(
            "SELECT * FROM orders WHERE user_id=? AND status='COMPLETED' ORDER BY id DESC",
            (int(user_id),),
        ).fetchall()
        payg_rows = conn.execute(
            "SELECT a.*, p.id AS payg_id, p.state AS payg_state, p.started_at AS payg_started_at,"
            " p.stopped_at AS payg_stopped_at, p.last_billed_at AS payg_last_billed_at,"
            " p.spent_milli AS payg_spent_milli, p.total_seconds AS payg_total_seconds,"
            " p.last_error AS payg_last_error"
            " FROM accounts a JOIN payg_accounts p ON p.account_id=a.id"
            " WHERE a.user_id=? ORDER BY a.id DESC",
            (int(user_id),),
        ).fetchall()
    finally:
        conn.close()

    accounts: list[dict] = []
    for row in free_rows:
        username = row["username"]
        paths = account_paths(row["service"], row["protocol"], username)
        quota = _int_file(paths["quota"])
        usage = _int_file(paths["usage"])
        ip_limit = _int_file(paths["ip"])
        state = mullog_state_for(states, username, row["protocol"] if row["service"] == "xray" else "")
        hold = bool(state.get("hold")) if state else False
        expires = int(row["expires_at"] or 0)
        accounts.append({
            "source": "free",
            "username": username,
            "service": row["service"],
            "protocol": row["protocol"] or "",
            "days": int(row["days"] or 0),
            "created_at": int(row["created_at"] or 0),
            "expires_at": expires,
            "output": row["output"] or "",
            "error": row["error"] or "",
            "row_status": row["status"],
            "token": row["token"],
            "invoice": "",
            "quota_bytes": quota,
            "usage_bytes": usage,
            "today_bytes": usage_today(username, usage, int(row["created_at"] or 0)),
            "ip_limit": ip_limit,
            "suspended": None if hold else state,
            "hold": hold,
            "expired": expires < now,
        })

    for row in order_rows:
        username = row["account_username"]
        if not username:
            continue
        service = "ssh" if row["protocol"] == "ssh" else "xray"
        paths = account_paths(service, row["protocol"], username)
        quota = _int_file(paths["quota"])
        if quota <= 0 and int(row["quota_gb"] or 0) > 0:
            quota = int(row["quota_gb"]) * 1024 ** 3
        usage = _int_file(paths["usage"])
        ip_limit = _int_file(paths["ip"])
        if ip_limit <= 0 and int(row["ip_limit"] or 0) > 0:
            ip_limit = int(row["ip_limit"])
        base_time = int(row["paid_at"] or row["created_at"] or 0)
        expires = base_time + int(row["days"] or 0) * 86400
        state = mullog_state_for(states, username, row["protocol"] if service == "xray" else "")
        hold = bool(state.get("hold")) if state else False
        accounts.append({
            "source": "premium",
            "username": username,
            "service": service,
            "protocol": row["protocol"] or "",
            "days": int(row["days"] or 0),
            "created_at": base_time,
            "expires_at": expires,
            "output": row["account_output"] or "",
            "error": row["provision_error"] or "",
            "row_status": "active" if row["status"] == "COMPLETED" else row["status"],
            "token": "",
            "invoice": row["invoice"],
            "quota_bytes": quota,
            "usage_bytes": usage,
            "today_bytes": usage_today(username, usage, base_time),
            "ip_limit": ip_limit,
            "suspended": None if hold else state,
            "hold": hold,
            "expired": expires < now,
        })

    for row in payg_rows:
        username = row["username"]
        paths = account_paths(row["service"], row["protocol"], username)
        quota = _int_file(paths["quota"])
        usage = _int_file(paths["usage"])
        ip_limit = _int_file(paths["ip"])
        state = mullog_state_for(states, username, row["protocol"] if row["service"] == "xray" else "")
        hold = bool(state.get("hold")) if state else False
        expires = int(row["expires_at"] or 0)
        payg_state = str(row["payg_state"] or PAYG_PAUSED)
        accounts.append({
            "source": "payg",
            "username": username,
            "service": row["service"],
            "protocol": row["protocol"] or "",
            "days": 0,
            "created_at": int(row["created_at"] or 0),
            "expires_at": expires,
            "output": row["output"] or "",
            "error": row["error"] or "",
            "row_status": row["status"],
            "token": row["token"],
            "invoice": "",
            "quota_bytes": quota,
            "usage_bytes": usage,
            "today_bytes": usage_today(username, usage, int(row["created_at"] or 0)),
            "ip_limit": ip_limit,
            "suspended": None if hold else state,
            "hold": hold,
            "expired": expires < now,
            "payg_id": int(row["payg_id"]),
            "payg_state": payg_state,
            "payg_started_at": int(row["payg_started_at"] or 0),
            "payg_spent_milli": int(row["payg_spent_milli"] or 0),
            "payg_total_seconds": int(row["payg_total_seconds"] or 0),
            "payg_last_error": row["payg_last_error"] or "",
            "payg_rate": payg_rates(row["service"]),
        })

    balance_milli = wallet_balance_milli(user_id)
    payg_settings = get_settings()
    min_balance_milli = _setting_int(payg_settings, "payg_min_balance", 1000) * 1000
    for item in accounts:
        if item.get("source") == "payg":
            item["balance_milli"] = balance_milli
            item["payg_min_balance_milli"] = min_balance_milli
            item["payg_idle_minutes"] = _setting_int(payg_settings, "payg_idle_minutes", 15)
    accounts.sort(key=lambda item: item["created_at"], reverse=True)
    online = collect_online_ips(accounts)
    for item in accounts:
        item["online_ips"] = online.get(item["username"], [])
    return accounts


def dashboard_data(user_id: int) -> dict:
    accounts = user_accounts(user_id)
    active = [a for a in accounts if not a["expired"] and a["row_status"] == "active" and not a["suspended"]]
    suspended = [a for a in accounts if a["suspended"]]
    expired = [a for a in accounts if a["expired"]]
    today_total = sum(int(a["today_bytes"]) for a in accounts)
    usage_total = sum(int(a["usage_bytes"]) for a in accounts)
    payg = [a for a in accounts if a["source"] == "payg"]
    settings = get_settings()
    return {
        "accounts": accounts,
        "active": active,
        "suspended": suspended,
        "expired": expired,
        "today_total": today_total,
        "usage_total": usage_total,
        "orders": user_orders(user_id),
        "security_ok": not suspended,
        "balance_milli": wallet_balance_milli(user_id),
        "payg": payg,
        "payg_running": [a for a in payg if a.get("payg_state") == PAYG_RUNNING],
        "payg_settings": {
            "enabled": settings.get("payg_enabled", "1") == "1",
            "min_balance_milli": _setting_int(settings, "payg_min_balance", 1000) * 1000,
            "min_topup": _setting_int(settings, "payg_min_topup", 5000),
            "idle_minutes": _setting_int(settings, "payg_idle_minutes", 15),
            "rates_ssh": payg_rates("ssh", settings),
            "rates_xray": payg_rates("xray", settings),
        },
        "deposits": deposit_history(user_id, 20),
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

    def user_session(self) -> sqlite3.Row | None:
        return get_user_session(self.cookie(USER_COOKIE))

    def require_user(self, csrf: str | None = None) -> sqlite3.Row | None:
        session = self.user_session()
        if not session:
            target = urllib.parse.quote(self.path[:300], safe="/")
            self.redirect("/login?next=" + target)
            return None
        if csrf is not None and not hmac.compare_digest(csrf, session["csrf"]):
            self.html(
                403,
                page_shell(
                    "Akses ditolak",
                    "<main class='wrap narrow'><div class='panel'><h1>403</h1>"
                    "<p>Token keamanan tidak valid. Muat ulang halaman.</p></div></main>",
                ),
            )
            return None
        return session

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
        if not (path.startswith("/static/") or path.startswith("/branding/") or path in ("/healthz", "/favicon.ico")):
            _CURRENT.user = self.user_session()
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
            if path in ("/login", "/login/"):
                self.auth_page("login", query, head_only)
                return
            if path in ("/register", "/register/"):
                self.auth_page("register", query, head_only)
                return
            if path in ("/forgot-password", "/forgot-password/"):
                self.auth_page("forgot", query, head_only)
                return
            if path in ("/reset-password", "/reset-password/"):
                self.reset_password_page(query, head_only)
                return
            if path in ("/verify", "/verify/"):
                self.verify_email_page(query, head_only)
                return
            if path in ("/verify-pending", "/verify-pending/"):
                self.auth_page("verify", query, head_only)
                return
            if path.startswith("/dashboard"):
                self.dashboard_page(path, query, head_only)
                return
            if path == "/":
                token, cookie = self.public_form_token()
                self.html(200, render_home(token, get_settings()), cookies=[cookie] if cookie else None, head_only=head_only)
                return
            if path == "/gratis" or path == "/gratis/":
                if not self.user_session():
                    self.redirect("/login?next=/gratis")
                    return
                token, cookie = self.public_form_token()
                self.html(200, render_free_page(token, get_settings()), cookies=[cookie] if cookie else None, head_only=head_only)
                return
            if path == "/premium" or path == "/premium/":
                if not self.user_session():
                    self.redirect("/login?next=/premium")
                    return
                token, cookie = self.public_form_token()
                scheme = (query.get("scheme", ["duration"])[0] or "duration").strip().lower()
                self.html(200, render_premium_page(token, get_settings(), scheme), cookies=[cookie] if cookie else None, head_only=head_only)
                return
            if path == "/deposit" or path == "/deposit/":
                if not self.user_session():
                    self.redirect("/login?next=/deposit")
                    return
                token, cookie = self.public_form_token()
                msg = (query.get("msg", [""])[0] or "")[:30]
                self.html(
                    200,
                    render_deposit_page(token, get_settings(), int(self.user_session()["user_id"]), msg),
                    cookies=[cookie] if cookie else None,
                    extra_headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"},
                    head_only=head_only,
                )
                return
            if path.startswith("/deposit/"):
                self.deposit_invoice_page(path[len("/deposit/"):], head_only)
                return
            if path.startswith("/api/deposit/"):
                self.api_deposit(path.split("/", 3)[3])
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
        if int(row["user_id"] or 0):
            session = self.user_session()
            if not session:
                self.redirect("/login?next=" + urllib.parse.quote(self.path[:300], safe="/"))
                return
            if int(session["user_id"]) != int(row["user_id"]):
                self.html(404, render_not_found(), head_only=head_only)
                return
        if download:
            download_output = format_account_output(
                row["service"], row["protocol"], row["output"] or "", row["kind"]
            )
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
        _CURRENT.user = self.user_session()
        try:
            if path == "/register":
                self.register_post()
                return
            if path == "/login":
                self.login_post()
                return
            if path == "/logout":
                self.logout_post()
                return
            if path == "/verify/resend":
                self.verify_resend_post()
                return
            if path == "/verify/code":
                self.verify_code_post()
                return
            if path == "/forgot-password":
                self.forgot_password_post()
                return
            if path == "/reset-password":
                self.reset_password_post()
                return
            if path == "/dashboard/password":
                self.dashboard_password_post()
                return
            if path == "/dashboard/logout-all":
                self.dashboard_logout_all()
                return
            if path == "/buat":
                self.public_create()
                return
            if path == "/premium/buy":
                self.premium_buy()
                return
            if path == "/deposit":
                self.deposit_post()
                return
            if path == "/payg/create":
                self.payg_create_post()
                return
            if path == "/dashboard/payg/start":
                self.payg_start_post()
                return
            if path == "/dashboard/payg/stop":
                self.payg_stop_post()
                return
            if path == "/cek-invoice":
                self.check_invoice_post()
                return
            if path == "/admin/login":
                self.admin_login()
                return
            if path == "/admin/user/verify":
                self.admin_user_verify()
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
            if path == "/admin/popup":
                self.admin_popup()
                return
            if path == "/admin/signup":
                self.admin_signup()
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
            if path == "/admin/mail":
                self.admin_mail()
                return
            if path == "/admin/payg":
                self.admin_payg()
                return
            if path == "/admin/wallet":
                self.admin_wallet()
                return
            if path == "/admin/deposit":
                self.admin_deposit()
                return
            self.html(404, render_not_found())
        except ValueError as exc:
            self.html(400, render_error(str(exc)))
        except Exception:
            logger.error("POST error: %s", traceback.format_exc())
            self.html(500, render_error("Terjadi kesalahan di server."))

    def public_create(self) -> None:
        session = self.user_session()
        if not session:
            self.redirect("/login?next=/gratis")
            return
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
                int(session["user_id"]),
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
        session = self.user_session()
        if not session:
            self.redirect("/login?next=/premium")
            return
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
            order = create_premium_order(
                product_code,
                self.client_ip(),
                self.headers.get("User-Agent", ""),
                int(session["user_id"]),
            )
        except ValueError as exc:
            self.html(409, render_error(str(exc), retry=True))
            return
        except Exception:
            logger.error("premium buy: %s", traceback.format_exc())
            self.html(500, render_error("Gagal membuat invoice. Silakan coba lagi atau hubungi admin.", retry=True))
            return
        self.redirect(f"/invoice/{order['invoice']}?new=1")

    def deposit_post(self) -> None:
        session = self.user_session()
        if not session:
            self.redirect("/login?next=/deposit")
            return
        body = self.parse_body()
        token_cookie = self.cookie(FORM_COOKIE)
        if not token_cookie or not hmac.compare_digest(body.get("_form", ""), token_cookie):
            self.html(400, render_error("Sesi formulir kedaluwarsa. Muat ulang halaman lalu coba lagi."))
            return
        if not rate_ok("deposit:" + self.client_ip(), 6, 600):
            self.html(429, render_error("Terlalu banyak percobaan. Tunggu beberapa menit lalu coba lagi."))
            return
        ts_ok, ts_msg = verify_turnstile(body.get("cf-turnstile-response", ""), self.client_ip())
        if not ts_ok:
            self.html(400, render_error(ts_msg, retry=True))
            return
        try:
            amount = int(body.get("amount", "0"))
        except ValueError:
            amount = 0
        try:
            row = create_deposit(int(session["user_id"]), amount, self.client_ip(), self.headers.get("User-Agent", ""))
        except ValueError as exc:
            text = str(exc)
            if "Minimal deposit" in text or "Maksimal deposit" in text:
                self.redirect("/deposit?msg=amount")
            elif "Terlalu banyak" in text:
                self.redirect("/deposit?msg=limit")
            else:
                self.redirect("/deposit?msg=fail")
            return
        except Exception:
            logger.error("deposit post: %s", traceback.format_exc())
            self.redirect("/deposit?msg=fail")
            return
        self.redirect(f"/deposit/{row['invoice']}?new=1")

    def payg_create_post(self) -> None:
        session = self.user_session()
        if not session:
            self.redirect("/login?next=%2Fpremium%3Fscheme%3Dpayg")
            return
        body = self.parse_body()
        token_cookie = self.cookie(FORM_COOKIE)
        if not token_cookie or not hmac.compare_digest(body.get("_form", ""), token_cookie):
            self.html(400, render_error("Sesi formulir kedaluwarsa. Muat ulang halaman lalu coba lagi."))
            return
        if not rate_ok("payg:" + self.client_ip(), 6, 600):
            self.html(429, render_error("Terlalu banyak percobaan. Tunggu beberapa menit lalu coba lagi."))
            return
        ts_ok, ts_msg = verify_turnstile(body.get("cf-turnstile-response", ""), self.client_ip())
        if not ts_ok:
            self.html(400, render_error(ts_msg, retry=True))
            return
        service = body.get("service", "")
        protocol = body.get("protocol", "")
        try:
            row = payg_create_account(
                int(session["user_id"]),
                service,
                protocol,
                self.client_ip(),
                self.headers.get("User-Agent", ""),
            )
        except ValueError as exc:
            text = str(exc)
            if "Saldo minimal" in text:
                self.redirect("/dashboard?msg=payg-nobalance")
            else:
                self.redirect("/dashboard?msg=payg-fail")
            return
        except Exception:
            logger.error("payg create: %s", traceback.format_exc())
            self.redirect("/dashboard?msg=payg-fail")
            return
        self.redirect("/dashboard/akun?msg=payg-created")

    def payg_start_post(self) -> None:
        body = self.parse_body()
        session = self.require_user(body.get("_csrf", ""))
        if not session:
            return
        try:
            payg_id = int(body.get("payg_id", "0"))
        except ValueError:
            payg_id = 0
        try:
            payg_start(payg_id, int(session["user_id"]))
        except ValueError as exc:
            text = str(exc)
            if "Saldo minimal" in text:
                self.redirect("/dashboard/akun?msg=payg-nobalance")
            elif "mullog" in text.lower():
                self.redirect("/dashboard/akun?msg=payg-mullog")
            else:
                self.redirect("/dashboard/akun?msg=payg-fail")
            return
        except Exception:
            logger.error("payg start: %s", traceback.format_exc())
            self.redirect("/dashboard/akun?msg=payg-fail")
            return
        self.redirect("/dashboard/akun?msg=payg-started")

    def payg_stop_post(self) -> None:
        body = self.parse_body()
        session = self.require_user(body.get("_csrf", ""))
        if not session:
            return
        try:
            payg_id = int(body.get("payg_id", "0"))
        except ValueError:
            payg_id = 0
        try:
            payg_stop(payg_id, int(session["user_id"]))
        except Exception:
            logger.error("payg stop: %s", traceback.format_exc())
            self.redirect("/dashboard/akun?msg=payg-fail")
            return
        self.redirect("/dashboard/akun?msg=payg-stopped")

    def deposit_invoice_page(self, suffix: str, head_only: bool = False) -> None:
        qr = suffix.endswith("/qr.svg")
        code = suffix[:-7] if qr else suffix
        code = (code or "").strip().upper()
        if not re.fullmatch(r"TOP-\d{6}-[A-Z0-9]{8}", code):
            self.html(404, render_not_found(), head_only=head_only)
            return
        row = deposit_by_invoice(code)
        if not row:
            self.html(404, render_not_found(), head_only=head_only)
            return
        session = self.user_session()
        if not session:
            self.redirect("/login?next=" + urllib.parse.quote(self.path[:300], safe="/"))
            return
        if int(session["user_id"]) != int(row["user_id"]):
            self.html(404, render_not_found(), head_only=head_only)
            return
        if qr:
            svg = gopay_qr_svg(row["qr_string"])
            if not svg:
                self._send(404, b"QR unavailable", content_type="text/plain")
                return
            self._send(200, svg, content_type="image/svg+xml", extra_headers={"Cache-Control": "no-store"}, head_only=head_only)
            return
        self.html(
            200,
            render_deposit_invoice(row, new=("new=1" in self.path)),
            extra_headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"},
            head_only=head_only,
        )

    def api_deposit(self, code: str) -> None:
        code = (code or "").strip().upper()
        if not re.fullmatch(r"TOP-\d{6}-[A-Z0-9]{8}", code):
            self.json(404, {"ok": False, "error": "not found"})
            return
        row = deposit_by_invoice(code)
        if not row:
            self.json(404, {"ok": False, "error": "not found"})
            return
        session = self.user_session()
        if not session or int(session["user_id"]) != int(row["user_id"]):
            self.json(403, {"ok": False, "error": "forbidden"})
            return
        self.json(200, {
            "ok": True,
            "invoice": row["invoice"],
            "status": row["status"],
            "amount": int(row["amount"]),
            "total": int(row["total"]),
            "paid_at": row["paid_at"],
            "balance_milli": wallet_balance_milli(int(row["user_id"])),
        })

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
        if int(row["user_id"] or 0):
            session = self.user_session()
            if not session:
                self.redirect("/login?next=" + urllib.parse.quote(self.path[:300], safe="/"))
                return
            if int(session["user_id"]) != int(row["user_id"]):
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
            download_output = format_account_output(
                "ssh" if row["protocol"] == "ssh" else "xray",
                row["protocol"],
                row["account_output"] or "",
            )
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
        if int(row["user_id"] or 0):
            session = self.user_session()
            if not session or int(session["user_id"]) != int(row["user_id"]):
                self.json(403, {"ok": False, "error": "forbidden"})
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
                format_account_output(
                    "ssh" if row["protocol"] == "ssh" else "xray",
                    row["protocol"],
                    row["account_output"] or "",
                )
                if status == "COMPLETED" and row["account_output"]
                else ""
            ),
            "error": row["provision_error"] if status == "FAILED" else "",
        }
        self.json(200, payload)

    # ------------------------------------------------------------------
    # User authentication & dashboard
    # ------------------------------------------------------------------

    def auth_page(self, mode: str, query: dict, head_only: bool = False) -> None:
        if mode in ("login", "register") and self.user_session():
            self.redirect("/dashboard")
            return
        token, cookie = self.public_form_token()
        msg = (query.get("msg", [""])[0] or "").strip()[:40]
        info = {
            "verified": "Email berhasil diverifikasi. Silakan masuk.",
            "logout": "Anda sudah keluar dari akun.",
            "reset": "Password berhasil diubah. Silakan masuk dengan password baru.",
            "reset-sent": "Jika email terdaftar, tautan reset password sudah dikirim.",
            "registered": "Pendaftaran berhasil. Cek email untuk verifikasi.",
            "pending": "Email belum diverifikasi. Masukkan kode 6 digit dari email, atau klik link verifikasi.",
        }.get(msg, "")
        error = ""
        if msg == "mailfail":
            error = "Email verifikasi gagal dikirim. Hubungi admin agar akun diverifikasi manual."
        email = (query.get("email", [""])[0] or "").strip()[:190]
        next_path = safe_next(query.get("next", ["/dashboard"])[0])
        self.html(
            200,
            render_auth_page(mode, token, error=error, info=info, email=email, next_path=next_path),
            cookies=[cookie] if cookie else None,
            extra_headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"},
            head_only=head_only,
        )

    def verify_email_page(self, query: dict, head_only: bool = False) -> None:
        token = (query.get("token", [""])[0] or "").strip()
        row = consume_email_token(token, "verify")
        if not row:
            token_cookie, cookie = self.public_form_token()
            self.html(
                400,
                render_auth_page(
                    "verify",
                    token_cookie,
                    error="Tautan verifikasi tidak valid atau sudah kedaluwarsa. Minta tautan baru di bawah.",
                ),
                cookies=[cookie] if cookie else None,
                extra_headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"},
                head_only=head_only,
            )
            return
        set_user_verified(int(row["user_id"]))
        audit_user(int(row["user_id"]), "verify_email", "", self.client_ip())
        self.redirect("/login?msg=verified")

    def reset_password_page(self, query: dict, head_only: bool = False) -> None:
        token = (query.get("token", [""])[0] or "").strip()
        row = peek_email_token(token, "reset")
        token_cookie, cookie = self.public_form_token()
        if not row:
            self.html(
                400,
                render_auth_page(
                    "reset",
                    token_cookie,
                    error="Tautan reset tidak valid atau sudah kedaluwarsa. Minta tautan baru dari halaman login.",
                ),
                cookies=[cookie] if cookie else None,
                extra_headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"},
                head_only=head_only,
            )
            return
        self.html(
            200,
            render_auth_page("reset", token_cookie, reset_token=token),
            cookies=[cookie] if cookie else None,
            extra_headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"},
            head_only=head_only,
        )

    def dashboard_page(self, path: str, query: dict, head_only: bool = False) -> None:
        session = self.require_user()
        if not session:
            return
        section = path[len("/dashboard"):].strip("/").split("/")[0] or "overview"
        if section not in ("overview", "akun", "saldo", "mullog", "invoice", "profil"):
            self.html(404, render_not_found(), head_only=head_only)
            return
        msg = (query.get("msg", [""])[0] or "").strip()[:40]
        data = dashboard_data(int(session["user_id"]))
        body = render_dashboard_page(session, data, section, msg)
        self.html(
            200,
            body,
            extra_headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"},
            head_only=head_only,
        )

    def register_post(self) -> None:
        body = self.parse_body()
        token_cookie = self.cookie(FORM_COOKIE)
        if not token_cookie or not hmac.compare_digest(body.get("_form", ""), token_cookie):
            self.html(400, render_auth_page("register", "", error="Sesi formulir kedaluwarsa. Muat ulang halaman."))
            return
        ip = self.client_ip()
        if not rate_ok("register:" + ip, 6, 900):
            self.html(429, render_auth_page("register", token_cookie, error="Terlalu banyak percobaan. Tunggu 15 menit."))
            return
        ts_ok, ts_msg = verify_turnstile(body.get("cf-turnstile-response", ""), ip)
        if not ts_ok:
            self.html(400, render_auth_page("register", token_cookie, error=ts_msg, email=body.get("email", "")))
            return
        email = normalize_email(body.get("email", ""))
        password = body.get("password", "")
        confirm = body.get("confirm", "")
        next_path = safe_next(body.get("next", "/dashboard"))
        if not valid_email(email):
            self.html(400, render_auth_page("register", token_cookie, error="Format email tidak valid.", email=email, next_path=next_path))
            return
        domain_ok, domain_error = signup_email_allowed(email)
        if not domain_ok:
            audit("register_blocked", f"{email} domain={email_domain(email)}", ip)
            self.html(400, render_auth_page("register", token_cookie, error=domain_error, email=email, next_path=next_path))
            return
        if len(password) < 8:
            self.html(400, render_auth_page("register", token_cookie, error="Password minimal 8 karakter.", email=email, next_path=next_path))
            return
        if len(password) > 200:
            self.html(400, render_auth_page("register", token_cookie, error="Password terlalu panjang.", email=email, next_path=next_path))
            return
        if password != confirm:
            self.html(400, render_auth_page("register", token_cookie, error="Konfirmasi password tidak sama.", email=email, next_path=next_path))
            return
        user, error = create_user(email, password, ip)
        if not user:
            self.html(409, render_auth_page("register", token_cookie, error=error, email=email, next_path=next_path))
            return
        raw_token, code = create_email_token(int(user["id"]), "verify", EMAIL_TOKEN_TTL)
        sent, _mail_msg = send_verification_email(user, raw_token, code)
        audit_user(int(user["id"]), "register", "pending" if not sent else "verification_sent", ip)
        target = "/verify-pending?email=" + urllib.parse.quote(email)
        self.redirect(target + ("" if sent else "&mailfail=1"))

    def login_post(self) -> None:
        body = self.parse_body()
        token_cookie = self.cookie(FORM_COOKIE)
        if not token_cookie or not hmac.compare_digest(body.get("_form", ""), token_cookie):
            self.html(400, render_auth_page("login", "", error="Sesi formulir kedaluwarsa. Muat ulang halaman."))
            return
        ip = self.client_ip()
        email = normalize_email(body.get("email", ""))
        next_path = safe_next(body.get("next", "/dashboard"))
        if not rate_ok("login:" + ip, 12, 900) or not rate_ok("login-email:" + email, 8, 900):
            self.html(429, render_auth_page("login", token_cookie, error="Terlalu banyak percobaan. Tunggu 15 menit.", email=email, next_path=next_path))
            return
        ts_ok, ts_msg = verify_turnstile(body.get("cf-turnstile-response", ""), ip)
        if not ts_ok:
            self.html(400, render_auth_page("login", token_cookie, error=ts_msg, email=email, next_path=next_path))
            return
        user = user_by_email(email)
        password = body.get("password", "")
        if not user or not verify_password(password, user["password_hash"]):
            time.sleep(0.4)
            audit("user_login_failed", email, ip)
            self.html(401, render_auth_page("login", token_cookie, error="Email atau password salah.", email=email, next_path=next_path))
            return
        if user["status"] != "active":
            self.redirect("/verify-pending?email=" + urllib.parse.quote(email) + "&pending=1")
            return
        drop_user_session(self.cookie(USER_COOKIE))
        token, _csrf = create_user_session(int(user["id"]), ip)
        conn = db_connect()
        try:
            conn.execute(
                "UPDATE users SET last_login_at=?, last_ip=?, updated_at=? WHERE id=?",
                (int(time.time()), ip[:64], int(time.time()), int(user["id"])),
            )
            conn.commit()
        finally:
            conn.close()
        audit_user(int(user["id"]), "login", "", ip)
        self.redirect(
            next_path,
            cookies=[self.set_cookie(USER_COOKIE, token, USER_SESSION_TTL, http_only=True)],
        )

    def logout_post(self) -> None:
        session = self.user_session()
        if session:
            body = self.parse_body()
            if not hmac.compare_digest(body.get("_csrf", ""), session["csrf"]):
                self.html(403, render_error("Token keamanan tidak valid. Muat ulang halaman."))
                return
            drop_user_session(self.cookie(USER_COOKIE))
            audit_user(int(session["user_id"]), "logout", "", self.client_ip())
        self.redirect("/login?msg=logout", cookies=[self.clear_cookie(USER_COOKIE)])

    def verify_resend_post(self) -> None:
        body = self.parse_body()
        token_cookie = self.cookie(FORM_COOKIE)
        if not token_cookie or not hmac.compare_digest(body.get("_form", ""), token_cookie):
            self.html(400, render_auth_page("verify", "", error="Sesi formulir kedaluwarsa. Muat ulang halaman."))
            return
        ip = self.client_ip()
        email = normalize_email(body.get("email", ""))
        if not rate_ok("resend:" + ip, 5, 900) or not rate_ok("resend-email:" + email, 3, 900):
            self.html(429, render_auth_page("verify", token_cookie, error="Terlalu banyak permintaan. Tunggu 15 menit.", email=email))
            return
        ts_ok, ts_msg = verify_turnstile(body.get("cf-turnstile-response", ""), ip)
        if not ts_ok:
            self.html(400, render_auth_page("verify", token_cookie, error=ts_msg, email=email))
            return
        user = user_by_email(email)
        sent = True
        if user and user["status"] != "active":
            raw_token, code = create_email_token(int(user["id"]), "verify", EMAIL_TOKEN_TTL)
            sent, _ = send_verification_email(user, raw_token, code)
            audit_user(int(user["id"]), "verify_resend", "" if sent else "mail_failed", ip)
        target = "/verify-pending?email=" + urllib.parse.quote(email)
        self.redirect(target + ("" if sent else "&mailfail=1"))

    def verify_code_post(self) -> None:
        body = self.parse_body()
        token_cookie = self.cookie(FORM_COOKIE)
        if not token_cookie or not hmac.compare_digest(body.get("_form", ""), token_cookie):
            self.html(400, render_auth_page("verify", "", error="Sesi formulir kedaluwarsa. Muat ulang halaman."))
            return
        ip = self.client_ip()
        email = normalize_email(body.get("email", ""))
        code = (body.get("code", "") or "").strip()
        if not rate_ok("verifycode:" + ip, 12, 900) or not rate_ok("verifycode-email:" + email, 8, 900):
            self.html(429, render_auth_page("verify", token_cookie, error="Terlalu banyak percobaan. Tunggu 15 menit.", email=email))
            return
        if not valid_email(email) or not re.fullmatch(r"\d{6}", code):
            self.html(400, render_auth_page("verify", token_cookie, error="Email atau kode 6 digit tidak valid.", email=email))
            return
        user = verify_email_code(email, code)
        if not user:
            time.sleep(0.4)
            audit("user_verify_code_failed", email, ip)
            self.html(400, render_auth_page("verify", token_cookie, error="Kode salah atau sudah kedaluwarsa. Kirim ulang email verifikasi.", email=email))
            return
        set_user_verified(int(user["id"]))
        audit_user(int(user["id"]), "verify_code", "", ip)
        self.redirect("/login?msg=verified")

    def forgot_password_post(self) -> None:
        body = self.parse_body()
        token_cookie = self.cookie(FORM_COOKIE)
        if not token_cookie or not hmac.compare_digest(body.get("_form", ""), token_cookie):
            self.html(400, render_auth_page("forgot", "", error="Sesi formulir kedaluwarsa. Muat ulang halaman."))
            return
        ip = self.client_ip()
        email = normalize_email(body.get("email", ""))
        if not rate_ok("forgot:" + ip, 5, 900) or not rate_ok("forgot-email:" + email, 3, 900):
            self.html(429, render_auth_page("forgot", token_cookie, error="Terlalu banyak permintaan. Tunggu 15 menit.", email=email))
            return
        ts_ok, ts_msg = verify_turnstile(body.get("cf-turnstile-response", ""), ip)
        if not ts_ok:
            self.html(400, render_auth_page("forgot", token_cookie, error=ts_msg, email=email))
            return
        user = user_by_email(email)
        if user and user["status"] == "active":
            raw_token, _code = create_email_token(int(user["id"]), "reset", RESET_TOKEN_TTL)
            sent, _ = send_reset_email(user, raw_token)
            audit_user(int(user["id"]), "forgot_password", "" if sent else "mail_failed", ip)
        self.redirect("/login?msg=reset-sent")

    def reset_password_post(self) -> None:
        body = self.parse_body()
        token_cookie = self.cookie(FORM_COOKIE)
        if not token_cookie or not hmac.compare_digest(body.get("_form", ""), token_cookie):
            self.html(400, render_auth_page("reset", "", error="Sesi formulir kedaluwarsa. Muat ulang halaman."))
            return
        ip = self.client_ip()
        token = (body.get("token", "") or "").strip()
        password = body.get("password", "")
        confirm = body.get("confirm", "")
        if len(password) < 8:
            self.html(400, render_auth_page("reset", token_cookie, error="Password minimal 8 karakter.", reset_token=token))
            return
        if password != confirm:
            self.html(400, render_auth_page("reset", token_cookie, error="Konfirmasi password tidak sama.", reset_token=token))
            return
        row = consume_email_token(token, "reset")
        if not row:
            self.html(400, render_auth_page("reset", token_cookie, error="Tautan reset tidak valid atau sudah kedaluwarsa."))
            return
        update_user_password(int(row["user_id"]), password)
        drop_user_sessions(int(row["user_id"]))
        audit_user(int(row["user_id"]), "reset_password", "", ip)
        self.redirect("/login?msg=reset", cookies=[self.clear_cookie(USER_COOKIE)])

    def dashboard_password_post(self) -> None:
        body = self.parse_body()
        session = self.require_user(body.get("_csrf", ""))
        if not session:
            return
        current = body.get("current", "")
        new = body.get("new", "")
        confirm = body.get("confirm", "")
        if len(new) < 8:
            self.redirect("/dashboard/profil?msg=password-short")
            return
        if new != confirm:
            self.redirect("/dashboard/profil?msg=password-mismatch")
            return
        user = user_by_id(int(session["user_id"]))
        if not user or not verify_password(current, user["password_hash"]):
            self.redirect("/dashboard/profil?msg=password-wrong")
            return
        update_user_password(int(user["id"]), new)
        drop_user_sessions(int(user["id"]), keep_token=self.cookie(USER_COOKIE))
        audit_user(int(user["id"]), "password_change", "", self.client_ip())
        self.redirect("/dashboard/profil?msg=password-ok")

    def dashboard_logout_all(self) -> None:
        body = self.parse_body()
        session = self.require_user(body.get("_csrf", ""))
        if not session:
            return
        drop_user_sessions(int(session["user_id"]))
        audit_user(int(session["user_id"]), "logout_all", "", self.client_ip())
        self.redirect("/login?msg=logout", cookies=[self.clear_cookie(USER_COOKIE)])

    def admin_user_verify(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        try:
            user_id = int(body.get("user_id", "0"))
        except ValueError:
            user_id = 0
        user = user_by_id(user_id)
        if user:
            set_user_verified(user_id)
            audit("admin_verify_user", user["email"], self.client_ip())
            self.redirect("/admin?msg=userverified")
        else:
            self.redirect("/admin?msg=userverifyfail")

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
            if key.startswith("payg_"):
                continue
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

    def admin_popup(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        title = body.get("popup_title", "").strip()[:80] or "Informasi Penting"
        message = body.get("popup_message", "").strip()[:2000]
        button_text = body.get("popup_button_text", "").strip()[:40]
        button_url = body.get("popup_button_url", "").strip()[:500]
        if button_url and not (
            (button_url.startswith("/") and not button_url.startswith("//"))
            or button_url.startswith("https://")
            or button_url.startswith("http://")
        ):
            button_url = ""
        mode = body.get("popup_mode", "once").strip()
        if mode not in ("once", "always"):
            mode = "once"
        enabled = body.get("popup_enabled") == "1"
        if enabled and not message:
            self.redirect("/admin?msg=popupfail")
            return
        values = {
            "popup_enabled": "1" if enabled else "0",
            "popup_title": title,
            "popup_message": message,
            "popup_button_text": button_text,
            "popup_button_url": button_url,
            "popup_mode": mode,
            # Versi baru membuat popup tampil lagi di browser yang sudah menutupnya.
            "popup_version": str(int(time.time() * 1000)),
        }
        set_settings(values)
        audit("popup", f"enabled={values['popup_enabled']} mode={mode}", self.client_ip())
        self.redirect("/admin?msg=popup")

    def admin_signup(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        mode = body.get("signup_email_mode", "block").strip()
        if mode not in ("all", "block", "google", "allow"):
            mode = "block"
        values = {
            "signup_email_mode": mode,
            "signup_email_allow": body.get("signup_email_allow", "").strip()[:4000],
            "signup_email_block_extra": body.get("signup_email_block_extra", "").strip()[:4000],
        }
        set_settings(values)
        audit("signup_filter", f"mode={mode}", self.client_ip())
        self.redirect("/admin?msg=signup")

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

    def admin_mail(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        from_name = (body.get("mail_from_name", "") or "").strip()[:60] or BRAND
        from_email = (body.get("mail_from_email", "") or "").strip().lower()[:190]
        verify_subject = (body.get("mail_verify_subject", "") or "").strip()[:120] or "Kode Verifikasi Anda"
        reset_subject = (body.get("mail_reset_subject", "") or "").strip()[:120] or "Reset Password — HITS SSH"
        api_key = (body.get("mail_api_key", "") or "").strip()
        smtp_user = (body.get("mail_smtp_user", "") or "").strip()[:190]
        smtp_key = (body.get("mail_smtp_key", "") or "").strip()
        smtp_host = (body.get("mail_smtp_host", "") or "").strip()[:190] or "smtp-relay.brevo.com"
        try:
            smtp_port = int(body.get("mail_smtp_port", "2525") or "2525")
        except ValueError:
            smtp_port = 2525
        smtp_port = max(1, min(65535, smtp_port))
        if not valid_email(from_email):
            self.redirect("/admin?msg=mailfail")
            return
        if api_key and not api_key.startswith("xkeysib-"):
            self.redirect("/admin?msg=mailkeybad")
            return
        if smtp_key and not smtp_key.startswith("xsmtpsib-"):
            self.redirect("/admin?msg=mailkeybad")
            return
        values = {
            "mail_from_name": from_name,
            "mail_from_email": from_email,
            "mail_verify_subject": verify_subject,
            "mail_reset_subject": reset_subject,
            "mail_smtp_user": smtp_user,
            "mail_smtp_host": smtp_host,
            "mail_smtp_port": str(smtp_port),
        }
        if api_key:
            values["mail_api_key"] = api_key[:200]
        if smtp_key:
            values["mail_smtp_key"] = smtp_key[:200]
        set_settings(values)
        audit("mail", f"from={from_email} verify={verify_subject} api={'changed' if api_key else 'keep'} smtp={'changed' if smtp_key else 'keep'}", self.client_ip())
        if body.get("action") == "test":
            html_body, text_body = email_layout(
                "Tes pengiriman email",
                "Ini email percobaan dari dashboard admin. Jika Anda menerima email ini, konfigurasi Brevo sudah benar.",
                "Buka situs",
                base_url(),
                "Tidak ada tindakan yang diperlukan.",
            )
            ok, _ = send_email(from_email, f"Tes Email — {branding()['name']}", html_body, text_body)
            self.redirect("/admin?msg=mailtestok" if ok else "mailtestfail")
            return
        self.redirect("/admin?msg=mail")

    def admin_payg(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        enabled = "1" if body.get("payg_enabled") == "1" else "0"
        values = {"payg_enabled": enabled}
        for key in (
            "payg_base_ssh_30d", "payg_base_xray_30d",
            "payg_min_balance", "payg_min_topup", "payg_max_topup",
            "payg_ssh_ip_limit", "payg_ssh_quota_gb",
            "payg_xray_ip_limit", "payg_xray_quota_gb",
            "payg_idle_minutes",
        ):
            low, high = INT_SETTINGS[key]
            try:
                num = int(body.get(key, "0"))
            except ValueError:
                num = 0
            values[key] = str(max(low, min(high, num)))
        if int(values["payg_max_topup"]) < int(values["payg_min_topup"]):
            values["payg_max_topup"] = values["payg_min_topup"]
        if enabled != "1":
            payg_stop_all()
        else:
            payg_settle_all()
        set_settings(values)
        audit("payg_settings", json.dumps(values, sort_keys=True), self.client_ip())
        self.redirect("/admin?msg=payg")

    def admin_wallet(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        email = normalize_email(body.get("email", ""))
        user = user_by_email(email)
        if not user:
            self.redirect("/admin?msg=walletfail")
            return
        try:
            amount = abs(int(body.get("amount", "0")))
        except ValueError:
            amount = 0
        if amount <= 0:
            self.redirect("/admin?msg=walletfail")
            return
        action = body.get("action", "add")
        note = body.get("note", "").strip()[:200]
        if action == "subtract":
            wallet_deduct(int(user["id"]), amount * 1000, "admin", ref="admin", note=note or "Penyesuaian admin")
        else:
            wallet_add(int(user["id"]), amount * 1000, "admin", ref="admin", note=note or "Penyesuaian admin")
        audit("wallet_adjust", f"user={email} {action} {amount}", self.client_ip())
        self.redirect("/admin?msg=wallet")

    def admin_deposit(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        invoice = body.get("invoice", "").strip().upper()
        row = deposit_by_invoice(invoice)
        if not row:
            self.redirect("/admin?msg=depositfail")
            return
        if row["status"] == "PAID":
            self.redirect("/admin?msg=depositpaid")
            return
        ok = _credit_deposit(invoice, "MANUAL-ADMIN")
        self.redirect("/admin?msg=depositok" if ok else "/admin?msg=depositfail")

    def admin_delete(self) -> None:
        body = self.parse_body()
        session = self.require_admin(body.get("_csrf", ""))
        if not session:
            return
        account_id = body.get("id", "")
        conn = db_connect()
        try:
            row = conn.execute("SELECT * FROM accounts WHERE id=? AND status='active' AND kind='free'", (account_id,)).fetchone()
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
    popup_html = "" if admin else render_popup()
    cu = current_user()
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
            ("premium", "/premium", "Premium Akun"),
            ("free", "/gratis", "Free Akun"),
            ("deposit", "/deposit", "Deposit"),
            ("invoice", "/cek-invoice", "Cek Invoice"),
            ("contact", "/kontak", "Kontak"),
        ]
        if cu:
            items.insert(3, ("dashboard", "/dashboard", "Dashboard"))
        menu_parts = []
        for key, href, label in items:
            cls = "nav-link" + (" active" if active == key else "")
            aria = ' aria-current="page"' if active == key else ""
            menu_parts.append(f'<a href="{href}" class="{cls}"{aria}>{label}</a>')
        menu = "".join(menu_parts)
        if cu:
            try:
                cu_balance = int(cu["balance_milli"] or 0)
            except Exception:
                cu_balance = 0
            auth_menu = f"""
      <a class="nav-link nav-balance-chip" href="/deposit">{icon('wallet')}<span>Saldo <b>{rupiah_milli(cu_balance, strip=True)}</b></span></a>
      <a class="nav-link nav-user-chip" href="/dashboard/profil"><span class="nav-avatar">{e((cu['email'][:1] or 'M').upper())}</span><span class="nav-email">{e(cu['email'])}</span></a>
      <form method="post" action="/logout" class="nav-logout"><input type="hidden" name="_csrf" value="{e(cu['csrf'])}"><button class="nav-link nav-logout-btn" type="submit">Keluar</button></form>"""
            drawer_cta = (
                '<a class="nav-drawer-cta" href="/dashboard">Buka dashboard <span aria-hidden="true">↗</span></a>'
                '<a class="nav-drawer-cta" href="/deposit">Deposit / top up saldo <span aria-hidden="true">↗</span></a>'
            )
        else:
            auth_menu = ""
            drawer_cta = (
                '<a class="nav-drawer-cta" href="/login">Login <span aria-hidden="true">↗</span></a>'
                '<a class="nav-drawer-cta" href="/register">Daftar gratis <span aria-hidden="true">↗</span></a>'
                '<a class="nav-drawer-cta" href="/deposit">Deposit / top up saldo <span aria-hidden="true">↗</span></a>'
            )
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
      {auth_menu}
      {drawer_cta}
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
      <a href="/deposit">Deposit Saldo</a>
      <a href="/dashboard">Dashboard</a>
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
<meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<title>{e(title)} — {e(brand_name)}</title>
<meta name="description" content="{e(b['meta'])}">
<meta name="theme-color" content="{UI_THEME_COLORS.get(b['theme'], '#fffaf2')}">
{robots}
{favicon}
<link rel="stylesheet" href="/static/style.css?v=20261107signup1">
{turnstile_script}
</head>
<body>
{header}
{body}
{footer}
{popup_html}
<script src="/static/app.js?v=20261107signup1" defer></script>
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
        "wallet": '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7.5A2.5 2.5 0 0 1 6.5 5H18a2 2 0 0 1 2 2v1.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><rect x="3" y="7.5" width="18" height="12" rx="2.5" fill="none" stroke="currentColor" stroke-width="2"/><path d="M16 13.5h2.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
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
    cu = current_user()
    payg_rows = []
    payg_on = settings.get("payg_enabled", "1") == "1" and not maintenance
    if payg_on:
        for proto in ("ssh", "vmess", "vless", "trojan"):
            service = "ssh" if proto == "ssh" else "xray"
            if service == "ssh" and not ssh_global:
                continue
            if service == "xray" and (not xray_global or not proto_on.get(proto, False)):
                continue
            existing = payg_existing(int(cu["user_id"]), service, "") if cu and service == "ssh" else (
                payg_existing(int(cu["user_id"]), service, proto) if cu else None
            )
            payg_rows.append({
                "protocol": proto,
                "service": service,
                "label": "SSH" if proto == "ssh" else PROTOCOLS[proto]["label"],
                "sub": SERVICES[service]["sub"],
                "rates": payg_rates(service, settings),
                "existing": existing,
            })
    balance_milli = wallet_balance_milli(int(cu["user_id"])) if cu else 0
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
        "payg_on": payg_on,
        "payg_rows": payg_rows,
        "payg_balance_milli": balance_milli,
        "payg_min_balance_milli": _setting_int(settings, "payg_min_balance", 1000) * 1000,
        "payg_min_topup": _setting_int(settings, "payg_min_topup", 5000),
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
    cu = current_user()
    balance_milli = wallet_balance_milli(int(cu["user_id"])) if cu else 0
    payg_on = settings.get("payg_enabled", "1") == "1" and settings.get("maintenance") != "1"
    rates_ssh = payg_rates("ssh", settings)
    rates_xray = payg_rates("xray", settings)
    payg_hour_min = min(rates_ssh["hour_milli"], rates_xray["hour_milli"])
    wallet_balance_text = rupiah_milli(balance_milli, strip=True) if cu else "Rp 0"
    deposit_cta = "/deposit" if cu else "/login?next=/deposit"
    payg_off_note = "" if payg_on else '<div class="notice notice-warn compact-notice"><b>Pay As You Go sedang ditutup.</b> Deposit tetap bisa dilakukan.</div>'
    body = f"""
<main>
  <section class="hero wrap">
    <div class="hero-copy">
      <div class="eyebrow"><span class="dot"></span> FREE &amp; PREMIUM · MEMBER AREA</div>
      <h1>{e(hero_title)}<br><em>{e(hero_title_accent)}</em></h1>
      <p class="hero-lead">{e(hero_lead)}</p>
      <a class="hero-scroll" href="#layanan">
        <span class="hero-scroll-line" aria-hidden="true"></span>
        <span>Lihat layanan</span>
        <span class="hero-scroll-arrow" aria-hidden="true">↓</span>
      </a>
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

  <section class="section wrap wallet-band" id="saldo">
    <div class="wallet-promo panel">
      <div class="wallet-promo-copy">
        <div class="eyebrow"><span class="dot"></span> SALDO &amp; PAY AS YOU GO</div>
        <h2>Isi saldo.<br><em>Nyalakan saat butuh.</em></h2>
        <p>Beli paket durasi seperti biasa, atau pakai Pay As You Go: saldo hanya terpotong saat akun Anda ON. Tarif otomatis mengikuti harga patokan admin.</p>
        {payg_off_note}
        <div class="wallet-promo-actions">
          <a class="btn btn-primary" href="{deposit_cta}">{icon('wallet')} Deposit saldo</a>
          <a class="btn btn-ghost" href="/premium?scheme=payg">Lihat tarif PAYG</a>
        </div>
        <small class="wallet-promo-note">Minimal top up {rupiah(_setting_int(settings, "payg_min_topup", 5000))} · saldo aktif di semua akun PAYG.</small>
      </div>
      <div class="wallet-promo-card">
        <span class="mini-label">{'SALDO ANDA' if cu else 'MULAI DARI'}</span>
        <b class="wallet-promo-amount">{wallet_balance_text if cu else rupiah_milli(payg_hour_min)}</b>
        <small>{'Siap dipakai untuk akun Pay As You Go.' if cu else 'per jam, tarif PAYG termurah'}</small>
        <div class="wallet-promo-rates">
          <div><span>SSH</span><b>{rupiah_milli(rates_ssh['hour_milli'])} / jam</b></div>
          <div><span>Xray</span><b>{rupiah_milli(rates_xray['hour_milli'])} / jam</b></div>
        </div>
        <a class="btn btn-dark btn-block" href="{deposit_cta}">Top up sekarang <span aria-hidden="true">↗</span></a>
      </div>
    </div>
  </section>

  <section class="section wrap category-section" id="layanan">
    <div class="section-head">
      <div>
        <div class="eyebrow"><span class="dot"></span> PILIH KEBUTUHAN</div>
        <h2>Dua kategori.<br>Satu tempat.</h2>
      </div>
      <p>Gratis untuk coba-coba, premium untuk masa aktif lebih panjang. Daftar sekali, lalu semua akun dan invoice tersimpan di dashboard.</p>
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
          <li>Paket durasi 3 / 7 / 30 hari</li>
          <li>Atau Pay As You Go dari saldo</li>
          <li>SSH, VMess, VLESS, Trojan</li>
          <li>Bayar QRIS GoPay</li>
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
      <details><summary>Bagaimana kalau saya lupa invoice premium?</summary><p>Buka <a href="/dashboard/invoice">Riwayat Invoice</a> di dashboard. Invoice lama sebelum fitur akun tetap bisa dicek lewat <a href="/cek-invoice">Cek Invoice</a> dengan kodenya.</p></details>
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
        "Pilih layanan dan masa aktif. Login diperlukan agar akun dan monitoring tersimpan di dashboard Anda.",
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


def render_premium_page(form_token: str, settings: dict[str, str], scheme: str = "duration") -> str:
    pc = _premium_context(settings)
    b = branding()
    scheme = "payg" if scheme == "payg" else "duration"
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
    tabs = f"""
    <div class="scheme-tabs" role="tablist" aria-label="Skema pembelian">
      <a class="scheme-tab{' active' if scheme == 'duration' else ''}" href="/premium" role="tab" aria-selected="{'true' if scheme == 'duration' else 'false'}">
        <span class="scheme-tab-icon">{icon('clock')}</span>
        <span class="scheme-tab-copy"><b>Paket Durasi</b><small>Bayar di awal · 3 / 7 / 30 hari</small></span>
        <span class="scheme-tab-side">{'Aktif' if scheme == 'duration' else 'Pilih'}</span>
      </a>
      <a class="scheme-tab{' active' if scheme == 'payg' else ''}" href="/premium?scheme=payg" role="tab" aria-selected="{'true' if scheme == 'payg' else 'false'}">
        <span class="scheme-tab-icon">{icon('bolt')}</span>
        <span class="scheme-tab-copy"><b>Pay As You Go</b><small>Bayar per menit · hanya saat ON</small></span>
        <span class="scheme-tab-side">{'Aktif' if scheme == 'payg' else 'Pilih'}</span>
      </a>
    </div>"""
    chips = (
        f'<span class="page-chip">Mulai {rupiah(pc["cheapest"])}</span>'
        f'<span class="page-chip">Invoice {e(settings.get("premium_expiry_min", "15"))} menit</span>'
        '<span class="page-chip">QRIS GoPay</span>'
        f'<span class="page-chip">Saldo {rupiah_milli(pc["payg_balance_milli"], strip=True)}</span>'
    )
    if scheme == "payg":
        hero = _page_hero(
            e(b["name"].upper()) + " PAY AS YOU GO",
            "Bayar per menit.<br><em>Saat dipakai saja.</em>",
            "Isi saldo sekali, lalu nyalakan akun saat butuh. Argo berjalan hanya ketika akun ON dan berhenti otomatis saat saldo habis.",
            chips,
        )
    else:
        hero = _page_hero(
            e(b["name"].upper()) + " PREMIUM",
            "Beli sekali.<br><em>Khusus member.</em>",
            "Pilih layanan dan masa aktif, bayar QRIS GoPay, lalu simpan invoice. Akun dibuat otomatis setelah pembayaran terdeteksi.",
            chips,
        )

    payg_cards = []
    first_payg = None
    for item in pc["payg_rows"]:
        rates = item["rates"]
        existing = item["existing"]
        if existing is None and first_payg is None:
            first_payg = item
        existing_tag = '<span class="payg-existing-tag">Sudah punya</span>' if existing else ""
        payg_cards.append(
            f'<button class="payg-service-card{" is-existing" if existing else ""}" type="button"'
            f' data-payg-service="{e(item["service"])}" data-payg-protocol="{e(item["protocol"])}"'
            f' data-payg-label="{e(item["label"])}" data-payg-existing="{1 if existing else 0}"'
            f' data-payg-minute="{e(rupiah_milli(rates["minute_milli"]))}"'
            f' data-payg-hour="{e(rupiah_milli(rates["hour_milli"]))}"'
            f' data-payg-day="{e(rupiah_milli(rates["day_milli"]))}">'
            f'<span class="payg-service-icon">{icon("terminal" if item["service"] == "ssh" else "bolt")}</span>'
            f'<b>{e(item["label"])}</b>'
            f'<small>{rupiah_milli(rates["hour_milli"])} / jam</small>'
            f'<em>{rupiah_milli(rates["minute_milli"])} / menit</em>'
            f'{existing_tag}'
            f'</button>'
        )
    payg_cards_html = "".join(payg_cards) or '<p class="premium-hint">Pay As You Go belum dibuka admin.</p>'
    default_service = first_payg["service"] if first_payg else ""
    default_protocol = first_payg["protocol"] if first_payg else ""
    payg_can_create = bool(first_payg) and pc["payg_balance_milli"] >= pc["payg_min_balance_milli"]
    payg_notice = ""
    if not pc["payg_on"]:
        payg_notice = '<div class="notice notice-warn"><strong>Pay As You Go sedang ditutup.</strong> Admin belum membuka skema ini.</div>'
    elif pc["payg_balance_milli"] < pc["payg_min_balance_milli"]:
        payg_notice = (
            '<div class="notice notice-warn"><strong>Saldo belum cukup.</strong> '
            f'Minimal {rupiah_milli(pc["payg_min_balance_milli"])} untuk membuat akun PAYG. '
            '<a href="/deposit">Top up dulu →</a></div>'
        )
    payg_picker = f"""
        <div class="premium-step">
          <span class="mini-label">01 · PILIH LAYANAN PAYG</span>
          <div class="payg-service-grid" id="payg-services">{payg_cards_html}</div>
        </div>
        <div class="premium-step">
          <span class="mini-label">02 · TARIF OTOMATIS</span>
          <div class="payg-rate-box" id="payg-rate-box">
            <div><span>Per menit</span><b id="payg-rate-minute">—</b></div>
            <div><span>Per jam</span><b id="payg-rate-hour">—</b></div>
            <div><span>Per hari</span><b id="payg-rate-day">—</b></div>
          </div>
        </div>
        {server_strip}
        <div class="premium-summary payg-summary">
          <div><span>Saldo Anda</span><b>{rupiah_milli(pc["payg_balance_milli"], strip=True)}</b></div>
          <div><span>Minimal saldo</span><b>{rupiah_milli(pc["payg_min_balance_milli"])}</b></div>
          <div><span>Layanan</span><b id="payg-selected-label">—</b></div>
        </div>
        <form id="payg-form" method="post" action="/payg/create" data-can-create="{1 if payg_can_create else 0}">
          <input type="hidden" name="_form" value="{e(form_token)}">
          <input type="hidden" name="service" id="payg-service" value="{e(default_service)}">
          <input type="hidden" name="protocol" id="payg-protocol" value="{e(default_protocol)}">
          {ts_widget}
          <button class="btn btn-primary btn-block btn-premium" type="submit" id="payg-button" {'disabled' if not payg_can_create else ''}>
            Buat akun Pay As You Go <span aria-hidden="true">↗</span>
          </button>
        </form>
        <p class="form-note">Saldo <b>tidak dipotong</b> saat akun dibuat. Argo mulai saat Anda menekan <b>Start</b> di dashboard.</p>
    """
    duration_picker = f"""
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
    """
    side = f"""
      <aside class="premium-side">
        <div class="panel premium-info">
          <div class="premium-badge">{'SALDO PAYG' if scheme == 'payg' else 'QRIS GOPAY'}</div>
          <h3>{'Argo per menit.' if scheme == 'payg' else 'Bayar dari mana saja.'}</h3>
          <p>{'Saldo hanya berkurang saat akun berstatus ON. Berhenti otomatis jika saldo habis, dan bisa dinyalakan lagi setelah top up.' if scheme == 'payg' else 'Scan QRIS dengan GoPay, OVO, DANA, ShopeePay, atau m-banking. Akun dibuat otomatis setelah transaksi terdeteksi.'}</p>
          <ul>
            <li>Wajib login, riwayat tersimpan.</li>
            <li>{'Minimal saldo ' + rupiah_milli(pc['payg_min_balance_milli']) + ' untuk Start.' if scheme == 'payg' else 'Invoice ' + e(settings.get('premium_expiry_min', '15')) + ' menit dan bisa dicek ulang.'}</li>
            <li>{'Tombol Start / Stop ada di dashboard.' if scheme == 'payg' else 'Download detail akun .txt setelah lunas.'}</li>
          </ul>
          <a class="btn btn-dark btn-block" href="/deposit">{icon('wallet')} Deposit saldo</a>
        </div>
        <div class="panel check-card">
          <span class="mini-label">{'SALDO & RIWAYAT' if scheme == 'payg' else 'SUDAH BELI?'}</span>
          <h3>{'Cek saldo' if scheme == 'payg' else 'Cek Invoice'}</h3>
          <p>{'Lihat saldo, riwayat top up, dan pemakaian argo di dashboard.' if scheme == 'payg' else 'Masukkan kode invoice untuk membuka kembali QR, status pembayaran, dan data akun.'}</p>
          <a class="btn btn-dark btn-block" href="{'/dashboard/saldo' if scheme == 'payg' else '/cek-invoice'}">{'Buka saldo' if scheme == 'payg' else 'Buka Cek Invoice'}</a>
        </div>
        <div class="panel premium-info compact-info">
          <span class="mini-label">ALUR SINGKAT</span>
          <ol class="mini-steps">
            {'<li>Isi saldo lewat QRIS.</li><li>Buat akun PAYG.</li><li>Tekan Start saat ingin dipakai.</li><li>Tekan Stop agar saldo berhenti berkurang.</li>' if scheme == 'payg' else '<li>Pilih paket dan masa aktif.</li><li>Scan QRIS sesuai nominal.</li><li>Salin invoice, tunggu akun aktif.</li><li>Unduh detail akun .txt.</li>'}
          </ol>
        </div>
      </aside>"""
    body = f"""
<main>
{hero}
  <section class="section wrap premium-section page-section" id="premium">
    {tabs}
    {pc['notice']}
    {payg_notice if scheme == 'payg' else ''}
    <div class="premium-layout">
      <div class="premium-picker panel">
        {payg_picker if scheme == 'payg' else duration_picker}
      </div>
      {side}
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
    chips = '<span class="page-chip">Member area</span><span class="page-chip">Bantuan akun</span><span class="page-chip">Invoice premium</span>'
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


def fmt_bytes(value) -> str:
    try:
        number = max(0, int(value or 0))
    except (TypeError, ValueError):
        number = 0
    mb = number / (1024 * 1024)
    if mb >= 1024:
        return f"{mb / 1024:.2f}".replace(".", ",") + " GB"
    if mb >= 1:
        return f"{mb:.2f}".replace(".", ",") + " MB"
    kb = number / 1024
    return f"{kb:.1f}".replace(".", ",") + " KB"


def _service_label(service: str, protocol: str) -> str:
    base = SERVICES.get(service, {"label": service})["label"]
    if protocol:
        base += " · " + PROTOCOLS.get(protocol, {}).get("label", protocol.upper())
    return base

def _copy_label(service: str, protocol: str) -> str:
    if service == "ssh" or not protocol:
        return "Salin SSH"
    label = PROTOCOLS.get(protocol, {}).get("label", "Xray")
    return "Salin " + label


def _account_badge(account: dict) -> tuple[str, str]:
    if account.get("row_status") == "failed":
        return "badge-bad", "Gagal"
    if account.get("source") == "payg":
        if account.get("payg_state") == PAYG_SUSPENDED:
            if int(account.get("balance_milli") or 0) >= int(account.get("payg_min_balance_milli") or 0):
                return "badge-warn", "Siap dinyalakan"
            return "badge-bad", "Saldo habis"
        if account.get("suspended"):
            return "badge-bad", "Suspended"
        if account.get("payg_state") == PAYG_RUNNING:
            return "badge-ok", "Argo jalan"
        return "badge-muted", "Paused"
    if account.get("suspended"):
        return "badge-bad", "Suspended"
    if account.get("expired"):
        return "badge-bad", "Expired"
    quota = int(account.get("quota_bytes") or 0)
    usage = int(account.get("usage_bytes") or 0)
    remaining = int(account.get("expires_at") or 0) - int(time.time())
    if (quota > 0 and usage >= quota * 0.9) or remaining <= 86400:
        return "badge-warn", "Hampir habis"
    return "badge-ok", "Aktif"


def _usage_html(account: dict) -> str:
    quota = int(account.get("quota_bytes") or 0)
    usage = int(account.get("usage_bytes") or 0)
    today = int(account.get("today_bytes") or 0)
    if quota > 0:
        pct = max(0.0, min(100.0, usage * 100.0 / quota))
        bar_class = "usage-bar-fill" + (" is-warn" if pct >= 80 else "") + (" is-bad" if pct >= 100 else "")
        remaining = max(0, quota - usage)
        label = f"{fmt_bytes(usage)} / {fmt_bytes(quota)}"
        foot = f"Sisa {fmt_bytes(remaining)} · hari ini {fmt_bytes(today)}"
    else:
        pct = 0.0
        bar_class = "usage-bar-fill is-muted"
        label = f"{fmt_bytes(usage)} terpakai"
        foot = f"Tanpa batas kuota · hari ini {fmt_bytes(today)}"
    return f"""
      <div class="usage-block">
        <div class="usage-head"><span>Pemakaian kuota</span><b>{e(label)}</b></div>
        <div class="usage-bar"><i class="{bar_class}" style="width:{pct:.1f}%"></i></div>
        <small class="usage-foot">{e(foot)}</small>
      </div>"""


def _online_html(account: dict) -> str:
    ips = account.get("online_ips") or []
    ip_limit = int(account.get("ip_limit") or 0)
    limit_text = f"limit {ip_limit} IP" if ip_limit > 0 else "tanpa batas IP"
    over = ip_limit > 0 and len(ips) > ip_limit
    chip_class = "ip-count is-over" if over else "ip-count"
    ip_list = ""
    if ips:
        ip_list = '<div class="ip-list">' + "".join(f'<code>{e(ip)}</code>' for ip in ips) + "</div>"
    else:
        ip_list = '<p class="dash-empty-inline">Tidak ada koneksi aktif saat ini.</p>'
    return f"""
      <div class="ip-block">
        <div class="ip-head"><span>IP login aktif</span><b class="{chip_class}">{len(ips)} / {ip_limit if ip_limit > 0 else '∞'}</b></div>
        <small class="usage-foot">{e(limit_text)}</small>
        {ip_list}
      </div>"""


def _payg_html(account: dict) -> str:
    if account.get("source") != "payg":
        return ""
    state = account.get("payg_state") or PAYG_PAUSED
    rates = account.get("payg_rate") or payg_rates(account.get("service", "ssh"))
    balance = int(account.get("balance_milli") or 0)
    min_balance = int(account.get("payg_min_balance_milli") or 0)
    spent = int(account.get("payg_spent_milli") or 0)
    csrf = current_user()["csrf"] if current_user() else ""
    payg_id = int(account.get("payg_id") or 0)
    if state == PAYG_RUNNING:
        label = "Argo berjalan"
        idle_min = int(account.get("payg_idle_minutes") or 15)
        note = f"Saldo dipotong per menit selama ON. Auto-off jika tidak ada login {idle_min} menit. Tekan Stop untuk berhenti."
        action = (
            f'<form method="post" action="/dashboard/payg/stop" class="inline-form">'
            f'<input type="hidden" name="_csrf" value="{e(csrf)}">'
            f'<input type="hidden" name="payg_id" value="{payg_id}">'
            f'<button class="btn btn-small btn-danger" type="submit">Stop argo</button></form>'
        )
        argo = (
            f'<div class="payg-live" data-argo-start="{int(account.get("payg_started_at") or 0)}"'
            f' data-argo-rate-milli="{int(rates["minute_milli"])}">'
            f'<span class="payg-dot"></span><b data-argo-clock>00:00:00</b>'
            f'<small>± <span data-argo-cost>{rupiah_milli(0)}</span> sesi ini</small></div>'
        )
    elif state == PAYG_SUSPENDED:
        if balance >= min_balance:
            label = "Siap dinyalakan"
            note = "Saldo sudah cukup. Tekan Start untuk menyalakan akun dan memulai argo."
            action = (
                f'<form method="post" action="/dashboard/payg/start" class="inline-form">'
                f'<input type="hidden" name="_csrf" value="{e(csrf)}">'
                f'<input type="hidden" name="payg_id" value="{payg_id}">'
                f'<button class="btn btn-small btn-primary" type="submit">Start argo</button></form>'
                '<a class="btn btn-small btn-ghost" href="/deposit">Top up lagi</a>'
            )
        else:
            label = "Saldo habis"
            note = "Akun otomatis dimatikan. Isi saldo lalu tekan Start untuk menyalakan lagi."
            action = '<a class="btn btn-small btn-primary" href="/deposit">Top up saldo</a>'
        argo = ""
    else:
        label = "Argo berhenti"
        note = "Saldo tidak berkurang saat Stop. Tekan Start saat akun ingin dipakai."
        disabled = " disabled" if balance < min_balance else ""
        action = (
            f'<form method="post" action="/dashboard/payg/start" class="inline-form">'
            f'<input type="hidden" name="_csrf" value="{e(csrf)}">'
            f'<input type="hidden" name="payg_id" value="{payg_id}">'
            f'<button class="btn btn-small btn-primary" type="submit"{disabled}>Start argo</button></form>'
        )
        if balance < min_balance:
            action += '<a class="btn btn-small btn-ghost" href="/deposit">Top up saldo</a>'
        argo = ""
    return f"""
      <div class="payg-panel">
        <div class="payg-panel-head">
          <div><span class="mini-label">PAY AS YOU GO</span><b>{e(label)}</b><small>{e(note)}</small></div>
          <span class="badge {'badge-ok' if state == PAYG_RUNNING else ('badge-warn' if state == PAYG_SUSPENDED and balance >= min_balance else ('badge-bad' if state == PAYG_SUSPENDED else 'badge-muted'))}">{e(label)}</span>
        </div>
        <div class="payg-metrics">
          <div><span>Per menit</span><b>{rupiah_milli(rates['minute_milli'])}</b></div>
          <div><span>Per jam</span><b>{rupiah_milli(rates['hour_milli'])}</b></div>
          <div><span>Saldo</span><b>{rupiah_milli(balance)}</b></div>
          <div><span>Sudah terpakai</span><b>{rupiah_milli(spent)}</b></div>
        </div>
        {argo}
        <div class="payg-actions">{action}<a class="btn btn-small btn-ghost" href="/dashboard/saldo">Riwayat saldo</a></div>
        <small class="payg-foot">Minimal saldo untuk Start: <b>{rupiah_milli(min_balance)}</b> · tarif mengikuti harga patokan admin.</small>
      </div>"""

def _suspended_html(account: dict) -> str:
    state = account.get("suspended")
    if not state:
        return ""
    until = int(state.get("until", 0) or 0)
    count = state.get("count")
    limit = state.get("limit")
    return f"""
      <div class="acct-alert">
        <b>Terkena suspend mullog</b>
        <span>{e(str(count if count not in (None, '') else '-'))} IP terdeteksi, batas {e(str(limit if limit not in (None, '') else '-'))}.</span>
        <span>Pulih <b data-countdown-until="{until}">{e(fmt_ts(until, '%d %b %Y · %H:%M WIB'))}</b></span>
      </div>"""


def render_account_card(account: dict) -> str:
    username = account["username"]
    badge_class, badge_text = _account_badge(account)
    output = account.get("output") or ""
    if output:
        output = format_account_output(
            account["service"],
            account["protocol"],
            output,
            "payg" if account.get("source") == "payg" else "",
        )
    output_id = "acct-" + re.sub(r"[^A-Za-z0-9_-]", "-", f"{account['source']}-{username}")
    expires = int(account.get("expires_at") or 0)
    remaining = max(0, int((expires - time.time()) // 86400) + (1 if expires > time.time() else 0))
    expiry_text = fmt_ts(expires, "%d %b %Y · %H:%M WIB")
    if account.get("source") == "payg":
        expiry_text = "Pay As You Go · tanpa masa aktif tetap"
    elif account.get("expired"):
        expiry_text = "Berakhir " + expiry_text
    else:
        expiry_text = f"{remaining} hari lagi · {expiry_text}"
    download_url = ""
    link_url = ""
    if account["source"] in ("free", "payg") and account.get("token"):
        download_url = f"/hasil/{account['token']}.txt"
        link_url = f"/hasil/{account['token']}"
    elif account.get("invoice"):
        download_url = f"/invoice/{account['invoice']}.txt"
        link_url = f"/invoice/{account['invoice']}"
    actions = []
    if output:
        copy_label = _copy_label(account["service"], account["protocol"])
        actions.append(f'<button class="btn btn-small btn-ghost" type="button" data-copy-target="{output_id}">{icon("copy")} {e(copy_label)}</button>')
    if download_url:
        actions.append(f'<a class="btn btn-small btn-dark" href="{e(download_url)}" download>{icon("download")} Unduh .txt</a>')
    if link_url:
        actions.append(f'<button class="btn btn-small btn-ghost" type="button" data-copy-text="{e(base_url() + link_url)}">Salin link</button>')
    if output:
        actions.append(f'<button class="btn btn-small btn-ghost" type="button" data-output-toggle="{output_id}">Lihat config</button>')
    error_html = ""
    if account.get("error"):
        error_html = f'<div class="notice notice-error compact-notice">{e(account["error"])}</div>'
    output_html = ""
    if output:
        output_html = f'<pre class="account-output acct-output" id="{output_id}" hidden>{e(output)}</pre>'
    return f"""
      <article class="acct-card">
        <div class="acct-top">
          <div class="acct-id">
            <span class="mini-label">{e(_service_label(account['service'], account['protocol']))}</span>
            <b>{e(username)}</b>
            <small>{e('Pay As You Go · saldo' if account['source'] == 'payg' else (str(account['days']) + ' hari · ' + ('Premium' if account['source'] == 'premium' else 'Gratis')))}</small>
          </div>
          <span class="badge {badge_class}">{badge_text}</span>
        </div>
        {_suspended_html(account)}
        {_payg_html(account)}
        {error_html}
        <div class="acct-meta">
          <span>{icon('clock')} {e(expiry_text)}</span>
          <span>{icon('shield')} {e('Mullog aktif' if account.get('suspended') else 'Tidak ada pelanggaran')}</span>
        </div>
        {_usage_html(account)}
        {_online_html(account)}
        <div class="acct-actions">{''.join(actions)}</div>
        {output_html}
      </article>"""


def render_auth_page(
    mode: str,
    form_token: str,
    error: str = "",
    info: str = "",
    email: str = "",
    next_path: str = "/dashboard",
    reset_token: str = "",
    show_resend: bool = False,
) -> str:
    b = branding()
    ts_site, _ts_secret, ts_on = turnstile_config()
    copy = {
        "login": ("MEMBER AREA", "Selamat datang kembali.", "Masuk untuk membuat akun, memantau kuota, IP, dan invoice.", "Masuk"),
        "register": ("DAFTAR GRATIS", "Satu akun, semua terkendali.", "Cukup email dan password. Setelah verifikasi, dashboard langsung aktif.", "Daftar sekarang"),
        "forgot": ("LUPA PASSWORD", "Atur ulang dengan aman.", "Masukkan email akun. Kami kirim tautan untuk membuat password baru.", "Kirim tautan reset"),
        "reset": ("PASSWORD BARU", "Buat password baru.", "Minimal 8 karakter. Bebas kombinasi huruf, angka, atau simbol.", "Simpan password"),
        "verify": ("VERIFIKASI EMAIL", "MASUKKAN KODE VERIFIKASI", "Silakan cek Inbox atau folder SPAM, lalu masukkan kode 6 digit dari email. Anda juga bisa klik tombol verifikasi di email. Belum menerima email? Kirim ulang di bawah.", "Verifikasi dengan kode"),
    }
    eyebrow, title, lead, submit = copy.get(mode, copy["login"])
    err_html = f'<div class="notice notice-error">{e(error)}</div>' if error else ""
    info_html = f'<div class="notice notice-ok">{e(info)}</div>' if info else ""
    ts_widget = (
        '<div class="turnstile-box">'
        f'<div class="cf-turnstile" data-sitekey="{e(ts_site)}" data-theme="light" data-language="id" data-size="flexible"></div>'
        '<small class="turnstile-status" data-turnstile-status>Memuat verifikasi keamanan…</small>'
        "</div>"
        if ts_on and mode != "reset"
        else ""
    )
    signup_note = ""
    if mode == "register":
        try:
            signup_settings = get_settings()
        except Exception:
            signup_settings = {}
        signup_mode = (signup_settings.get("signup_email_mode") or "block").strip()
        if signup_mode == "google":
            signup_note = '<p class="form-note auth-note">Pendaftaran hanya menerima email Google (Gmail).</p>'
        elif signup_mode == "allow":
            signup_note = '<p class="form-note auth-note">Gunakan email dari domain yang diizinkan admin.</p>'
        elif signup_mode == "block":
            signup_note = '<p class="form-note auth-note">Email sementara/temp mail tidak diterima. Gunakan email utama Anda.</p>'
    if mode == "login":
        fields = f"""
        <label>Email
          <input type="email" name="email" value="{e(email)}" autocomplete="email" required autofocus placeholder="nama@email.com">
        </label>
        <label>Password
          <span class="pass-wrap"><input type="password" name="password" autocomplete="current-password" required placeholder="Password Anda"><button type="button" class="pass-toggle" data-toggle-pass aria-label="Tampilkan password">Lihat</button></span>
        </label>
        <input type="hidden" name="next" value="{e(next_path)}">
        {ts_widget}
        <button class="btn btn-primary btn-block" type="submit">{e(submit)}</button>"""
        links = f"""
        <div class="auth-links">
          <span>Belum punya akun? <a href="/register?next={urllib.parse.quote(next_path, safe='/')}">Daftar gratis</a></span>
          <a href="/forgot-password">Lupa password?</a>
        </div>"""
    elif mode == "register":
        fields = f"""
        <label>Email
          <input type="email" name="email" value="{e(email)}" autocomplete="email" required autofocus placeholder="nama@email.com">
        </label>
        <label>Password
          <span class="pass-wrap"><input type="password" name="password" minlength="8" autocomplete="new-password" required placeholder="Minimal 8 karakter"><button type="button" class="pass-toggle" data-toggle-pass aria-label="Tampilkan password">Lihat</button></span>
        </label>
        <label>Ulangi password
          <input type="password" name="confirm" minlength="8" autocomplete="new-password" required placeholder="Ketik ulang password">
        </label>
        <input type="hidden" name="next" value="{e(next_path)}">
        {ts_widget}
        {signup_note}
        <p class="form-note auth-note">Minimal 8 karakter. Tidak perlu simbol rumit.</p>
        <button class="btn btn-primary btn-block" type="submit">{e(submit)}</button>"""
        links = '<div class="auth-links"><span>Sudah punya akun? <a href="/login">Masuk</a></span></div>'
    elif mode == "forgot":
        fields = f"""
        <label>Email
          <input type="email" name="email" value="{e(email)}" autocomplete="email" required autofocus placeholder="nama@email.com">
        </label>
        {ts_widget}
        <button class="btn btn-primary btn-block" type="submit">{e(submit)}</button>"""
        links = '<div class="auth-links"><span>Ingat password? <a href="/login">Kembali masuk</a></span></div>'
    elif mode == "reset":
        fields = f"""
        <input type="hidden" name="token" value="{e(reset_token)}">
        <label>Password baru
          <span class="pass-wrap"><input type="password" name="password" minlength="8" autocomplete="new-password" required autofocus placeholder="Minimal 8 karakter"><button type="button" class="pass-toggle" data-toggle-pass aria-label="Tampilkan password">Lihat</button></span>
        </label>
        <label>Ulangi password baru
          <input type="password" name="confirm" minlength="8" autocomplete="new-password" required placeholder="Ketik ulang password">
        </label>
        <button class="btn btn-primary btn-block" type="submit">{e(submit)}</button>"""
        links = '<div class="auth-links"><span>Sudah diubah? <a href="/login">Masuk</a></span></div>'
    else:  # verify
        fields = f"""
        <label>Email
          <input type="email" name="email" value="{e(email)}" autocomplete="email" required placeholder="nama@email.com">
        </label>
        <label>Kode verifikasi 6 digit
          <input type="text" name="code" inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6" autocomplete="one-time-code" required placeholder="123456" style="letter-spacing:6px;font-family:var(--font-mono);font-size:20px;text-align:center">
        </label>
        <button class="btn btn-primary btn-block" type="submit">{e(submit)}</button>
        <p class="form-note auth-note">Kode dan link verifikasi berlaku 24 jam. Cek email Anda, lalu masukkan kode di atas atau klik link verifikasi.</p>"""
        links = '<div class="auth-links"><span>Sudah verifikasi? <a href="/login">Masuk</a></span></div>'
    resend_block = ""
    if (show_resend and mode == "login") or mode == "verify":
        resend_block = f"""
        <div class="auth-divider"><span>atau</span></div>
        <form method="post" action="/verify/resend" class="resend-form">
          <input type="hidden" name="_form" value="{e(form_token)}">
          <input type="hidden" name="email" value="{e(email)}">
          {ts_widget}
          <button class="btn btn-ghost btn-block btn-small" type="submit">Kirim ulang email verifikasi</button>
        </form>"""
    body = f"""
<main class="auth-main wrap">
  <section class="auth-shell">
    <aside class="auth-visual panel">
      <a class="auth-brand" href="/"><span class="brand-mark">{logomark()}</span><span class="brand-word">{brand_word_html(b['name'], b['accent'])}</span></a>
      <div class="eyebrow"><span class="dot"></span> MEMBER AREA</div>
      <h2>Satu dashboard.<br><em>Semua akun.</em></h2>
      <p>Pantau akun SSH &amp; Xray, pemakaian kuota, IP login, status mullog, dan riwayat invoice dalam satu tempat.</p>
      <ul class="auth-benefits">
        <li><b>Monitoring real-time</b><span>Kuota, IP online, dan status suspend.</span></li>
        <li><b>Riwayat aman</b><span>Invoice dan config bisa dibuka kembali.</span></li>
        <li><b>Lebih rapi</b><span>Tidak perlu mencatat link satu per satu.</span></li>
      </ul>
      {server_strip_html()}
    </aside>
    <div class="auth-card panel">
      <div class="eyebrow"><span class="dot"></span> {e(eyebrow)}</div>
      <h1>{e(title)}</h1>
      <p class="auth-lead">{e(lead)}</p>
      {err_html}
      {info_html}
      <form method="post" action="{'/verify/code' if mode == 'verify' else '/reset-password' if mode == 'reset' else '/forgot-password' if mode == 'forgot' else '/register' if mode == 'register' else '/login'}" class="stack-form auth-form">
        <input type="hidden" name="_form" value="{e(form_token)}">
        {fields}
      </form>
      {resend_block}
      {links}
      <p class="form-note auth-foot">Dengan masuk, Anda setuju memakai layanan secara wajar.</p>
    </div>
  </section>
</main>"""
    return page_shell("Masuk" if mode == "login" else "Daftar" if mode == "register" else "Akun", body, noindex=True, turnstile=ts_on and mode != "reset")


def _dash_nav(active: str) -> str:
    items = [
        ("overview", "/dashboard", "Ringkasan", "globe"),
        ("akun", "/dashboard/akun", "Akun & Monitoring", "terminal"),
        ("saldo", "/dashboard/saldo", "Saldo & Deposit", "wallet"),
        ("mullog", "/dashboard/mullog", "Cek Mullog", "shield"),
        ("invoice", "/dashboard/invoice", "Riwayat Invoice", "download"),
        ("profil", "/dashboard/profil", "Profil & Password", "clock"),
    ]
    out = []
    for key, href, label, ic in items:
        cls = "dash-nav-link" + (" active" if key == active else "")
        out.append(f'<a class="{cls}" href="{href}"><span>{icon(ic)}</span>{e(label)}</a>')
    return "".join(out)


def _dash_bottom(active: str) -> str:
    items = [
        ("overview", "/dashboard", "Ringkasan", "globe"),
        ("buat", "/gratis", "Buat", "bolt"),
        ("akun", "/dashboard/akun", "Akun", "terminal"),
        ("saldo", "/dashboard/saldo", "Saldo", "wallet"),
        ("mullog", "/dashboard/mullog", "Mullog", "shield"),
        ("invoice", "/dashboard/invoice", "Invoice", "download"),
        ("profil", "/dashboard/profil", "Profil", "clock"),
    ]
    out = []
    for key, href, label, ic in items:
        cls = "dash-bottom-link" + (" active" if key == active else "")
        out.append(f'<a class="{cls}" href="{href}"><span>{icon(ic)}</span><small>{e(label)}</small></a>')
    return "".join(out)


def _dash_alerts(msg: str) -> str:
    mapping = {
        "password-ok": ("ok", "Password berhasil diperbarui. Sesi lain sudah dikeluarkan."),
        "password-wrong": ("error", "Password saat ini salah."),
        "password-short": ("error", "Password baru minimal 8 karakter."),
        "password-mismatch": ("error", "Konfirmasi password baru tidak sama."),
        "payg-created": ("ok", "Akun Pay As You Go berhasil dibuat. Tekan Start saat ingin dipakai."),
        "payg-started": ("ok", "Argo Pay As You Go berjalan. Saldo akan dipotong per menit."),
        "payg-stopped": ("ok", "Argo berhenti. Saldo tidak berkurang sampai Anda menekan Start lagi."),
        "payg-nobalance": ("error", "Saldo belum cukup. Lakukan deposit lalu tekan Start."),
        "payg-mullog": ("error", "Akun sedang dibekukan mullog. Tunggu sampai pulih lalu coba lagi."),
        "payg-fail": ("error", "Aksi Pay As You Go gagal. Coba lagi atau hubungi admin."),
        "deposit-created": ("ok", "Invoice deposit dibuat. Scan QRIS untuk membayar."),
    }
    if msg in mapping:
        kind, text = mapping[msg]
        return f'<div class="notice notice-{kind}">{e(text)}</div>'
    return ""


def render_dashboard_page(session: sqlite3.Row, data: dict, section: str, msg: str = "") -> str:
    email = session["email"]
    initial = (email[:1] or "M").upper()
    accounts = data["accounts"]
    orders = data["orders"]
    alerts = _dash_alerts(msg)
    nav = _dash_nav(section)
    bottom = _dash_bottom(section)
    current_user_row = session

    if section == "overview":
        security_class = "is-ok" if data["security_ok"] else "is-bad"
        security_text = "Aman" if data["security_ok"] else "Ada akun ter-suspend"
        security_sub = "Tidak ada pelanggaran mullog aktif." if data["security_ok"] else f"{len(data['suspended'])} akun perlu perhatian."
        recent = accounts[:4]
        recent_html = "".join(render_account_card(a) for a in recent) if recent else """
          <div class="dash-empty">
            <b>Belum ada akun.</b>
            <p>Buat akun gratis atau beli paket premium untuk mulai memantau di sini.</p>
            <div class="dash-empty-actions"><a class="btn btn-primary btn-small" href="/gratis">Buat akun gratis</a><a class="btn btn-ghost btn-small" href="/premium">Beli premium</a></div>
          </div>"""
        suspend_html = ""
        if data["suspended"]:
            rows = "".join(
                f"<li><b>{e(a['username'])}</b> — {e(str(a['suspended'].get('count', '-')))} IP, pulih {e(fmt_ts(int(a['suspended'].get('until', 0)), '%d %b %Y · %H:%M WIB'))}</li>"
                for a in data["suspended"]
            )
            suspend_html = f'<div class="notice notice-error"><b>Mullog aktif.</b> Akun berikut sedang dibekukan sementara:<ul class="dash-alert-list">{rows}</ul><a href="/dashboard/mullog">Lihat detail mullog →</a></div>'
        payg_cards = "".join(render_account_card(a) for a in data["payg"])
        payg_section = f"""
        <section class="dash-section">
          <div class="dash-section-head"><div><span class="mini-label">PAY AS YOU GO</span><h2>Argo &amp; saldo</h2></div><a class="btn btn-ghost btn-small" href="/deposit">Deposit saldo</a></div>
          <div class="acct-list">{payg_cards}</div>
        </section>""" if data["payg"] else f"""
        <section class="dash-section">
          <div class="dash-section-head"><div><span class="mini-label">PAY AS YOU GO</span><h2>Argo &amp; saldo</h2></div><a class="btn btn-ghost btn-small" href="/premium?scheme=payg">Lihat tarif</a></div>
          <div class="dash-empty"><b>Belum ada akun Pay As You Go.</b><p>Isi saldo, lalu buat akun yang hanya terpotong saat ON.</p><div class="dash-empty-actions"><a class="btn btn-primary btn-small" href="/deposit">Deposit saldo</a><a class="btn btn-ghost btn-small" href="/premium?scheme=payg">Buat akun PAYG</a></div></div>
        </section>"""
        content = f"""
        {alerts}
        <div class="dash-summary four">
          <article class="dash-stat">
            <span>Total akun aktif</span>
            <b>{len(data['active'])}</b>
            <small>{len(data['expired'])} expired · {len(accounts)} total</small>
          </article>
          <article class="dash-stat wallet-stat">
            <span>Saldo</span>
            <b>{rupiah_milli(data['balance_milli'], strip=True)}</b>
            <small><a href="/deposit">Deposit saldo</a> · min {rupiah_milli(data['payg_settings']['min_balance_milli'])}</small>
          </article>
          <article class="dash-stat">
            <span>Pemakaian hari ini</span>
            <b>{fmt_bytes(data['today_total'])}</b>
            <small>Total kumulatif {fmt_bytes(data['usage_total'])}</small>
          </article>
          <article class="dash-stat {security_class}">
            <span>Status keamanan</span>
            <b>{e(security_text)}</b>
            <small>{e(security_sub)}</small>
          </article>
        </div>
        {suspend_html}
        {payg_section}
        <section class="dash-section">
          <div class="dash-section-head"><div><span class="mini-label">AKUN TERBARU</span><h2>Akun &amp; monitoring</h2></div><a class="btn btn-ghost btn-small" href="/dashboard/akun">Lihat semua</a></div>
          <div class="acct-list">{recent_html}</div>
        </section>
        <section class="dash-section">
          <div class="dash-section-head"><div><span class="mini-label">AKSES CEPAT</span><h2>Butuh akun baru?</h2></div></div>
          <div class="dash-quick four">
            <a class="dash-quick-card" href="/gratis"><span>{icon('terminal')}</span><b>Buat akun gratis</b><small>SSH atau Xray, 3–7 hari.</small></a>
            <a class="dash-quick-card" href="/premium"><span>{icon('bolt')}</span><b>Beli paket durasi</b><small>QRIS GoPay, masa aktif lebih panjang.</small></a>
            <a class="dash-quick-card" href="/premium?scheme=payg"><span>{icon('wallet')}</span><b>Pay As You Go</b><small>Saldo terpotong hanya saat ON.</small></a>
            <a class="dash-quick-card" href="/dashboard/invoice"><span>{icon('download')}</span><b>Riwayat invoice</b><small>{len(orders)} transaksi tersimpan.</small></a>
          </div>
        </section>"""
        title, subtitle = "Ringkasan akun", "Pantau semua akun dan status keamanan Anda."
    elif section == "akun":
        active = [a for a in accounts if not a["expired"] and a["row_status"] == "active"]
        expired = [a for a in accounts if a["expired"] or a["row_status"] == "failed"]
        active_html = "".join(render_account_card(a) for a in active) or """
          <div class="dash-empty"><b>Belum ada akun aktif.</b><p>Buat akun baru untuk mulai memantau kuota dan IP.</p><div class="dash-empty-actions"><a class="btn btn-primary btn-small" href="/gratis">Buat akun gratis</a><a class="btn btn-ghost btn-small" href="/premium">Beli premium</a></div></div>"""
        expired_html = "".join(render_account_card(a) for a in expired) or '<div class="dash-empty"><b>Tidak ada akun expired.</b><p>Semua akun Anda masih aktif.</p></div>'
        content = f"""
        {alerts}
        <section class="dash-section">
          <div class="dash-section-head"><div><span class="mini-label">AKTIF</span><h2>Akun berjalan</h2></div><span class="dash-count">{len(active)} akun</span></div>
          <div class="acct-list">{active_html}</div>
        </section>
        <section class="dash-section">
          <div class="dash-section-head"><div><span class="mini-label">ARSIP</span><h2>Expired &amp; gagal</h2></div><span class="dash-count">{len(expired)} akun</span></div>
          <div class="acct-list">{expired_html}</div>
        </section>"""
        title, subtitle = "Akun & monitoring", "Kuota, IP login, dan status mullog per akun."
    elif section == "mullog":
        active_states = data["suspended"]
        active_html = ""
        if active_states:
            cards = []
            for a in active_states:
                st = a["suspended"]
                cards.append(f"""
                <article class="mullog-active">
                  <div class="mullog-active-head"><div><span class="mini-label">SEDANG DIBEKUKAN</span><b>{e(a['username'])}</b><small>{e(_service_label(a['service'], a['protocol']))}</small></div><span class="badge badge-bad">Suspended</span></div>
                  <div class="mullog-grid">
                    <div><span>Jam pelanggaran</span><b>{e(fmt_ts(int(st.get('created', 0)), '%d %b %Y · %H:%M WIB'))}</b></div>
                    <div><span>IP terdeteksi</span><b>{e(str(st.get('count', '-')))} IP</b></div>
                    <div><span>Batas IP</span><b>{e(str(st.get('limit', '-')))} IP</b></div>
                    <div><span>Pulih dalam</span><b data-countdown-until="{int(st.get('until', 0))}">{e(fmt_ts(int(st.get('until', 0)), '%d %b %Y · %H:%M WIB'))}</b></div>
                  </div>
                  <p class="mullog-note">Akun tidak bisa dipakai sampai timer selesai. Kuota dan config tidak dihapus.</p>
                </article>""")
            active_html = "".join(cards)
        else:
            active_html = '<div class="dash-empty is-ok"><b>Tidak ada suspend aktif.</b><p>Semua akun Anda dalam status normal. Pelanggaran limit IP akan muncul di sini secara otomatis.</p></div>'
        history = []
        for a in accounts:
            for ev in mullog_history(a["username"], 50):
                if ev.get("event") == "suspend":
                    ev["_username"] = a["username"]
                    ev["_service"] = _service_label(a["service"], a["protocol"])
                    history.append(ev)
        history.sort(key=lambda x: int(x.get("ts", 0)), reverse=True)
        if history:
            rows = []
            for ev in history[:80]:
                restored = ev.get("restored_at")
                status = '<span class="badge badge-ok">Dipulihkan</span>' if restored else '<span class="badge badge-bad">Aktif / belum pulih</span>'
                duration = max(1, int((int(ev.get("until", 0)) - int(ev.get("created", ev.get("ts", 0)))) / 60))
                rows.append(
                    "<tr>"
                    f"<td>{e(fmt_ts(int(ev.get('ts', 0)), '%d %b %Y · %H:%M WIB'))}</td>"
                    f"<td><b>{e(ev.get('_username', '-'))}</b><small>{e(ev.get('_service', '-'))}</small></td>"
                    f"<td>{e(str(ev.get('count', '-')))} / {e(str(ev.get('limit', '-')))} IP</td>"
                    f"<td>{duration} menit</td>"
                    f"<td>{status}</td>"
                    "</tr>"
                )
            history_html = f'<div class="dash-table-wrap"><table class="dash-table"><thead><tr><th>Waktu</th><th>Akun</th><th>IP</th><th>Durasi</th><th>Status</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
        else:
            history_html = '<div class="dash-empty"><b>Belum ada riwayat mullog.</b><p>Riwayat dicatat otomatis saat akun terkena suspend limit IP.</p></div>'
        content = f"""
        {alerts}
        <section class="dash-section">
          <div class="dash-section-head"><div><span class="mini-label">STATUS SAAT INI</span><h2>Mullog aktif</h2></div><span class="dash-count">{len(active_states)} akun</span></div>
          <div class="mullog-list">{active_html}</div>
        </section>
        <section class="dash-section">
          <div class="dash-section-head"><div><span class="mini-label">RIWAYAT</span><h2>Histori pelanggaran</h2></div></div>
          {history_html}
        </section>"""
        title, subtitle = "Cek mullog", "Status suspend sementara dan riwayat pelanggaran limit IP."
    elif section == "invoice":
        status_map = {
            "PENDING": ("badge-warn", "Pending"),
            "PAID": ("badge-warn", "Paid"),
            "PROVISIONING": ("badge-warn", "Diproses"),
            "COMPLETED": ("badge-ok", "Selesai"),
            "FAILED": ("badge-bad", "Gagal"),
            "EXPIRED": ("badge-muted", "Expired"),
        }
        cards = []
        for row in orders:
            cls, text = status_map.get(row["status"], ("badge-muted", row["status"]))
            label = _service_label("ssh" if row["protocol"] == "ssh" else "xray", "" if row["protocol"] == "ssh" else row["protocol"])
            actions = f'<a class="btn btn-small btn-ghost" href="/invoice/{e(row["invoice"])}">Buka invoice</a>'
            if row["status"] == "COMPLETED":
                actions += f'<a class="btn btn-small btn-dark" href="/invoice/{e(row["invoice"])}.txt" download>{icon("download")} Unduh .txt</a>'
            cards.append(f"""
            <article class="invoice-card">
              <div class="invoice-card-top"><div><span class="mini-label">{e(row['invoice'])}</span><b>{e(label)} · {int(row['days'])} hari</b></div><span class="badge {cls}">{text}</span></div>
              <div class="invoice-card-meta"><span>Total <b>{rupiah(row['total'])}</b></span><span>Dibuat {e(fmt_ts(row['created_at'], '%d %b %Y · %H:%M WIB'))}</span></div>
              <div class="invoice-card-actions">{actions}</div>
            </article>""")
        invoice_html = "".join(cards) or """
          <div class="dash-empty"><b>Belum ada invoice.</b><p>Pembelian premium akan muncul di sini beserta status dan file akunnya.</p><div class="dash-empty-actions"><a class="btn btn-primary btn-small" href="/premium">Beli premium</a></div></div>"""
        content = f"""
        {alerts}
        <section class="dash-section">
          <div class="dash-section-head"><div><span class="mini-label">TRANSAKSI</span><h2>Riwayat pembelian</h2></div><span class="dash-count">{len(orders)} invoice</span></div>
          <div class="invoice-list">{invoice_html}</div>
        </section>
        <div class="dash-note">Invoice lama yang dibuat sebelum fitur akun tetap bisa dibuka lewat <a href="/cek-invoice">Cek Invoice</a> dengan kodenya.</div>"""
        title, subtitle = "Riwayat invoice", "Semua transaksi premium dan file akun tersimpan di sini."
    elif section == "saldo":
        balance = int(data["balance_milli"])
        min_balance = int(data["payg_settings"]["min_balance_milli"])
        min_topup = int(data["payg_settings"]["min_topup"])
        rates_ssh = data["payg_settings"]["rates_ssh"]
        rates_xray = data["payg_settings"]["rates_xray"]
        dep_rows = ""
        status_map = {
            "PENDING": ("badge-warn", "Menunggu"),
            "PAID": ("badge-ok", "Masuk"),
            "EXPIRED": ("badge-muted", "Kedaluwarsa"),
        }
        for row in data["deposits"]:
            cls, txt = status_map.get(row["status"], ("badge-muted", row["status"]))
            dep_rows += (
                "<tr>"
                f"<td><a class=\"invoice-link\" href=\"/deposit/{e(row['invoice'])}\"><b>{e(row['invoice'])}</b></a>"
                f"<small>{e(fmt_ts(row['created_at'], '%d %b %Y · %H:%M'))}</small></td>"
                f"<td><b>{rupiah(row['amount'])}</b><small>+ kode {rupiah(row['unique_code'])}</small></td>"
                f"<td><span class=\"badge {cls}\">{txt}</span></td>"
                "</tr>"
            )
        if not dep_rows:
            dep_rows = '<tr><td colspan="3" class="empty">Belum ada deposit.</td></tr>'
        ledger_rows = ""
        kind_labels = {"deposit": "Deposit", "payg": "Pemakaian PAYG", "admin": "Penyesuaian admin", "refund": "Refund"}
        for row in wallet_ledger(int(session["user_id"]), 40):
            amount = int(row["amount_milli"])
            sign = "+" if amount >= 0 else "−"
            cls = "ledger-plus" if amount >= 0 else "ledger-minus"
            ledger_rows += (
                "<tr>"
                f"<td>{e(fmt_ts(row['at'], '%d %b %Y · %H:%M'))}</td>"
                f"<td>{e(kind_labels.get(row['kind'], row['kind']))}<small>{e(row['note'] or '')}</small></td>"
                f"<td class=\"{cls}\">{sign}{rupiah_milli(abs(amount))}</td>"
                f"<td>{rupiah_milli(row['balance_after_milli'], strip=True)}</td>"
                "</tr>"
            )
        if not ledger_rows:
            ledger_rows = '<tr><td colspan="4" class="empty">Belum ada mutasi saldo.</td></tr>'
        content = f"""
        {alerts}
        <div class="wallet-hero panel">
          <div class="wallet-hero-copy">
            <span class="mini-label">SALDO AKTIF</span>
            <b>{rupiah_milli(balance, strip=True)}</b>
            <small>Minimal saldo untuk Start PAYG: {rupiah_milli(min_balance)} · minimal top up {rupiah(min_topup)}.</small>
          </div>
          <div class="wallet-hero-actions">
            <a class="btn btn-primary" href="/deposit">{icon('wallet')} Deposit saldo</a>
            <a class="btn btn-ghost" href="/premium?scheme=payg">Buat akun PAYG</a>
          </div>
        </div>
        <section class="dash-section">
          <div class="dash-section-head"><div><span class="mini-label">TARIF OTOMATIS</span><h2>Pay As You Go</h2></div><span class="dash-count">per 30 hari</span></div>
          <div class="payg-rate-grid">
            <div class="payg-rate-card"><span class="mini-label">SSH</span><b>{rupiah(rates_ssh['base'])} / 30 hari</b><div><span>Per hari</span><b>{rupiah_milli(rates_ssh['day_milli'])}</b></div><div><span>Per jam</span><b>{rupiah_milli(rates_ssh['hour_milli'])}</b></div><div><span>Per menit</span><b>{rupiah_milli(rates_ssh['minute_milli'])}</b></div></div>
            <div class="payg-rate-card"><span class="mini-label">XRAY</span><b>{rupiah(rates_xray['base'])} / 30 hari</b><div><span>Per hari</span><b>{rupiah_milli(rates_xray['day_milli'])}</b></div><div><span>Per jam</span><b>{rupiah_milli(rates_xray['hour_milli'])}</b></div><div><span>Per menit</span><b>{rupiah_milli(rates_xray['minute_milli'])}</b></div></div>
          </div>
        </section>
        <section class="dash-section">
          <div class="dash-section-head"><div><span class="mini-label">TOP UP</span><h2>Riwayat deposit</h2></div><a class="btn btn-ghost btn-small" href="/deposit">Deposit baru</a></div>
          <div class="dash-table-wrap"><table class="dash-table"><thead><tr><th>Invoice</th><th>Nominal</th><th>Status</th></tr></thead><tbody>{dep_rows}</tbody></table></div>
        </section>
        <section class="dash-section">
          <div class="dash-section-head"><div><span class="mini-label">MUTASI</span><h2>Riwayat saldo</h2></div></div>
          <div class="dash-table-wrap"><table class="dash-table"><thead><tr><th>Waktu</th><th>Jenis</th><th>Nominal</th><th>Saldo</th></tr></thead><tbody>{ledger_rows}</tbody></table></div>
        </section>
        <div class="dash-note">Saldo hanya dipotong saat akun Pay As You Go berstatus <b>ON</b>. Saat saldo habis, akun otomatis dimatikan dan bisa dinyalakan lagi setelah top up.</div>"""
        title, subtitle = "Saldo & deposit", "Top up, pantau argo, dan lihat semua mutasi saldo."
    else:
        user_created = fmt_ts(session["user_created_at"], "%d %b %Y")
        last_login = fmt_ts(session["last_login_at"], "%d %b %Y · %H:%M WIB") if session["last_login_at"] else "Baru pertama masuk"
        verified = fmt_ts(session["verified_at"], "%d %b %Y · %H:%M WIB") if session["verified_at"] else "-"
        content = f"""
        {alerts}
        <section class="dash-section">
          <div class="dash-section-head"><div><span class="mini-label">PROFIL</span><h2>Data akun</h2></div><span class="badge badge-ok">Terverifikasi</span></div>
          <div class="dash-profile-grid">
            <div class="dash-profile-card"><span>Email</span><b>{e(email)}</b><small>Dipakai untuk login dan verifikasi.</small></div>
            <div class="dash-profile-card"><span>Bergabung</span><b>{e(user_created)}</b><small>Verifikasi: {e(verified)}</small></div>
            <div class="dash-profile-card"><span>Login terakhir</span><b>{e(last_login)}</b><small>Dari IP {e(session['ip'] or '-')}</small></div>
          </div>
        </section>
        <section class="dash-section">
          <div class="dash-section-head"><div><span class="mini-label">KEAMANAN</span><h2>Ganti password</h2></div></div>
          <div class="dash-panel panel">
            <form method="post" action="/dashboard/password" class="stack-form">
              <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
              <label>Password saat ini
                <input type="password" name="current" autocomplete="current-password" required>
              </label>
              <label>Password baru
                <input type="password" name="new" minlength="8" autocomplete="new-password" required placeholder="Minimal 8 karakter">
              </label>
              <label>Ulangi password baru
                <input type="password" name="confirm" minlength="8" autocomplete="new-password" required>
              </label>
              <button class="btn btn-primary" type="submit">Simpan password</button>
            </form>
          </div>
        </section>
        <section class="dash-section">
          <div class="dash-section-head"><div><span class="mini-label">SESI</span><h2>Keluar dari perangkat lain</h2></div></div>
          <div class="dash-panel panel dash-danger">
            <p>Jika Anda merasa ada perangkat lain yang masih login, keluarkan semua sesi. Anda akan diminta login ulang.</p>
            <form method="post" action="/dashboard/logout-all" data-confirm="Keluar dari semua perangkat?">
              <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
              <button class="btn btn-danger" type="submit">Keluar dari semua perangkat</button>
            </form>
          </div>
        </section>"""
        title, subtitle = "Profil & password", "Kelola data akun dan keamanan login Anda."

    body = f"""
<main class="dash-main wrap">
  <div class="dash-layout">
    <aside class="dash-side panel">
      <div class="dash-user">
        <span class="dash-avatar">{e(initial)}</span>
        <div><b>{e(email)}</b><small>Member {e(branding()['name'])}</small></div>
      </div>
      <nav class="dash-nav" aria-label="Menu dashboard">{nav}</nav>
      <div class="dash-side-cta">
        <a class="btn btn-primary btn-small btn-block" href="/deposit">{icon('wallet')} Deposit saldo</a>
        <a class="btn btn-ghost btn-small btn-block" href="/gratis">Buat akun</a>
        <a class="btn btn-ghost btn-small btn-block" href="/premium">Beli premium</a>
      </div>
      <form method="post" action="/logout" class="dash-logout">
        <input type="hidden" name="_csrf" value="{e(current_user_row['csrf'])}">
        <button class="dash-logout-btn" type="submit">Keluar</button>
      </form>
    </aside>
    <div class="dash-content">
      <header class="dash-head">
        <div>
          <div class="eyebrow"><span class="dot"></span> DASHBOARD MEMBER</div>
          <h1>{e(title)}</h1>
          <p>{e(subtitle)}</p>
        </div>
        <div class="dash-head-actions">
          <a class="btn btn-ghost btn-small" href="/dashboard/saldo">Saldo {rupiah_milli(data['balance_milli'], strip=True)}</a>
          <a class="btn btn-primary btn-small" href="/deposit">Deposit</a>
        </div>
      </header>
      {content}
    </div>
  </div>
  <nav class="dash-bottom" aria-label="Menu dashboard mobile">{bottom}</nav>
</main>"""
    return page_shell(title, body, noindex=True)


def render_result(row: sqlite3.Row) -> str:
    service = SERVICES.get(row["service"], {"label": row["service"]})
    protocol = PROTOCOLS.get(row["protocol"], {}).get("label", "")
    label = service["label"] + (f" · {protocol}" if protocol else "")
    raw_output = row["output"] or ""
    raw_output = format_account_output(row["service"], row["protocol"], raw_output, row["kind"])
    output = e(raw_output)
    expires = fmt_ts(row["expires_at"], "%d %b %Y · %H:%M WIB")
    try:
        is_payg = row["kind"] == "payg"
    except Exception:
        is_payg = False
    if is_payg:
        detail_line = f"Akun <b>{e(row['username'])}</b> dibuat untuk <b>{label}</b> dengan skema <b>Pay As You Go</b>. Tekan Start di dashboard saat ingin dipakai."
        tip_last = "Saldo dipotong hanya saat akun berstatus ON. Tekan Stop untuk menghentikan argo."
    else:
        detail_line = f"Akun <b>{e(row['username'])}</b> aktif untuk <b>{label}</b> selama <b>{row['days']} hari</b>, sampai {e(expires)}."
        tip_last = f"Akun berakhir otomatis pada {e(expires)}."
    body = f"""
<main class="result-main wrap">
  <div class="result-head">
    <div class="success-mark" aria-hidden="true">✓</div>
    <div class="eyebrow"><span class="dot"></span> AKUN BERHASIL DIBUAT</div>
    <h1>Sudah jadi. <em>Simpan sekarang.</em></h1>
    <p>{detail_line}</p>
  </div>
  <div class="result-grid">
    <section class="output-card panel">
      <div class="output-head">
        <div><span class="mini-label">OUTPUT AKUN</span><b>{e(row['username'])}</b></div>
        <div class="output-actions">
          <button class="btn btn-small btn-ghost" type="button" id="copy-output">{icon('copy')} {e(_copy_label(row['service'], row['protocol']))}</button>
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
          <li>{tip_last}</li>
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
    signup_mode = (settings.get("signup_email_mode") or "block").strip()
    signup_badge = {
        "all": ("badge-muted", "Semua domain"),
        "block": ("badge-ok", "Blokir temp mail"),
        "google": ("badge-ok", "Hanya Google"),
        "allow": ("badge-ok", "Allowlist custom"),
    }.get(signup_mode, ("badge-ok", "Blokir temp mail"))
    like = f"%{q}%"
    conn = db_connect()
    try:
        total = conn.execute("SELECT COUNT(*) n FROM accounts WHERE status='active' AND kind='free'").fetchone()["n"]
        today = conn.execute(
            "SELECT COUNT(*) n FROM accounts WHERE status='active' AND kind='free' AND created_day=?",
            (today_key(),),
        ).fetchone()["n"]
        accounts = conn.execute(
            "SELECT * FROM accounts WHERE status='active' AND kind='free' ORDER BY id DESC LIMIT 60"
        ).fetchall()
        orders = conn.execute(
            "SELECT * FROM orders WHERE (?='' OR invoice LIKE ? OR account_username LIKE ? OR buyer_ip LIKE ?)"
            " ORDER BY id DESC LIMIT 100",
            (q, like, like, like),
        ).fetchall()
        recent_audit = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 10").fetchall()
        users = conn.execute("SELECT * FROM users ORDER BY id DESC LIMIT 50").fetchall()
        deposits = conn.execute(
            "SELECT d.*, u.email FROM deposits d LEFT JOIN users u ON u.id=d.user_id ORDER BY d.id DESC LIMIT 80"
        ).fetchall()
        payg_list = conn.execute(
            "SELECT p.*, u.email, u.balance_milli FROM payg_accounts p LEFT JOIN users u ON u.id=p.user_id"
            " ORDER BY p.id DESC LIMIT 80"
        ).fetchall()
        wallet_total = conn.execute("SELECT COALESCE(SUM(balance_milli),0) s FROM users").fetchone()["s"]
        payg_running = conn.execute("SELECT COUNT(*) n FROM payg_accounts WHERE state='RUNNING'").fetchone()["n"]
        deposit_paid = conn.execute("SELECT COALESCE(SUM(amount),0) s FROM deposits WHERE status='PAID'").fetchone()["s"]
    finally:
        conn.close()

    messages = {
        "settings": ("ok", "Pengaturan disimpan."),
        "popup": ("ok", "Popup informasi disimpan dan langsung aktif sesuai pengaturan."),
        "popupfail": ("error", "Popup belum bisa diaktifkan karena isi pesan masih kosong."),
        "signup": ("ok", "Filter domain pendaftaran disimpan."),
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
        "userverified": ("ok", "User berhasil diverifikasi manual dan sekarang bisa login."),
        "userverifyfail": ("error", "User tidak ditemukan."),
        "mail": ("ok", "Pengaturan email disimpan."),
        "mailfail": ("error", "Email pengirim tidak valid."),
        "mailkeybad": ("error", "API key Brevo harus diawali xkeysib- (bukan xsmtpsib- / SMTP key)."),
        "mailtestok": ("ok", "Email percobaan berhasil dikirim. Cek inbox/spam."),
        "mailtestfail": ("error", "Email percobaan gagal. Periksa API key, sender terverifikasi, dan log server."),
        "payg": ("ok", "Pengaturan Pay As You Go disimpan."),
        "wallet": ("ok", "Saldo user berhasil disesuaikan."),
        "walletfail": ("error", "User atau nominal tidak valid."),
        "depositok": ("ok", "Deposit ditandai lunas dan saldo sudah ditambahkan."),
        "depositpaid": ("ok", "Deposit ini sudah lunas."),
        "depositfail": ("error", "Deposit tidak ditemukan atau gagal diproses."),
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

    user_rows = ""
    for u in users:
        is_active = u["status"] == "active"
        badge = '<span class="badge badge-ok">Terverifikasi</span>' if is_active else '<span class="badge badge-warn">Pending</span>'
        last = fmt_ts(u["last_login_at"], "%d %b %H:%M") if u["last_login_at"] else "-"
        action = "-"
        if not is_active:
            action = (
                f'<form method="post" action="/admin/user/verify" class="inline-form">'
                f'<input type="hidden" name="_csrf" value="{e(session["csrf"])}">'
                f'<input type="hidden" name="user_id" value="{int(u["id"])}">'
                f'<button class="btn btn-tiny btn-ghost" type="submit">Verifikasi</button></form>'
            )
        balance_milli = 0
        try:
            balance_milli = int(u["balance_milli"] or 0)
        except Exception:
            pass
        user_rows += (
            f"<tr><td><b>{e(u['email'])}</b><small>{e(fmt_ts(u['created_at'], '%d %b %Y'))}</small></td>"
            f"<td>{badge}</td><td><b>{rupiah_milli(balance_milli, strip=True)}</b></td><td>{e(last)}</td><td>{action}</td></tr>"
        )
    if not user_rows:
        user_rows = '<tr><td colspan="5" class="empty">Belum ada user terdaftar.</td></tr>'

    deposit_rows = ""
    dep_status = {
        "PENDING": ("badge-warn", "Pending"),
        "PAID": ("badge-ok", "Lunas"),
        "EXPIRED": ("badge-muted", "Expired"),
    }
    for row in deposits:
        cls, txt = dep_status.get(row["status"], ("badge-muted", row["status"]))
        action = ""
        if row["status"] != "PAID":
            action = (
                f'<form method="post" action="/admin/deposit" class="inline-form" data-confirm="Tandai deposit {e(row["invoice"])} lunas dan tambahkan saldo?">'
                f'<input type="hidden" name="_csrf" value="{e(session["csrf"])}">'
                f'<input type="hidden" name="invoice" value="{e(row["invoice"])}">'
                f'<button class="btn btn-tiny btn-dark" type="submit">Mark paid</button></form>'
            )
        deposit_rows += (
            f"<tr><td><b>{e(row['invoice'])}</b><small>{e(row['email'] or '-')} · {e(fmt_ts(row['created_at'], '%d %b %H:%M'))}</small></td>"
            f"<td><b>{rupiah(row['amount'])}</b><small>+ kode {rupiah(row['unique_code'])}</small></td>"
            f"<td><span class=\"badge {cls}\">{txt}</span></td><td>{action}</td></tr>"
        )
    if not deposit_rows:
        deposit_rows = '<tr><td colspan="4" class="empty">Belum ada deposit.</td></tr>'

    payg_admin_rows = ""
    for row in payg_list:
        state = row["state"]
        cls = "badge-ok" if state == PAYG_RUNNING else ("badge-bad" if state == PAYG_SUSPENDED else "badge-muted")
        payg_admin_rows += (
            f"<tr><td><b>{e(row['username'])}</b><small>{e(row['email'] or '-')} · {e(row['service'])}/{e(row['protocol'] or '-')}</small></td>"
            f"<td><span class=\"badge {cls}\">{e(state)}</span></td>"
            f"<td><b>{rupiah_milli(row['spent_milli'], strip=True)}</b><small>terpakai</small></td>"
            f"<td>{rupiah_milli(row['balance_milli'], strip=True)}</td></tr>"
        )
    if not payg_admin_rows:
        payg_admin_rows = '<tr><td colspan="4" class="empty">Belum ada akun PAYG.</td></tr>'

    mail_ok, mail_msg = mail_ready()
    mail_cfg = mail_config()
    api_active = str(mail_cfg.get("api_key", "")).startswith("xkeysib-")
    smtp_active = str(mail_cfg.get("smtp_key", "")).startswith("xsmtpsib-") and bool(mail_cfg.get("smtp_user"))
    mail_method = "Brevo API (xkeysib-)" if api_active else ("SMTP Brevo (xsmtpsib-)" if smtp_active else "Belum aktif")
    mail_backup = "SMTP siap (port 2525)" if smtp_active else "SMTP belum siap"
    mail_status = f"""
    <div class="mail-status-grid">
      <div><span>METODE AKTIF</span><b>{e(mail_method)}</b><small>Dipakai lebih dulu untuk kirim email.</small></div>
      <div><span>CADANGAN</span><b>{e(mail_backup)}</b><small>Otomatis dipakai kalau API gagal.</small></div>
      <div><span>PENGIRIM</span><b>{e(mail_cfg.get('from_name', BRAND))}</b><small>{e(mail_cfg.get('from_email', '-'))}</small></div>
    </div>"""
    mail_notice = ""
    if not mail_ok:
        mail_notice = (
            '<div class="notice notice-warn compact-notice">'
            f'<b>Email verifikasi belum aktif.</b> {e(mail_msg)} '
            "Isi konfigurasi di panel <b>Email Verifikasi</b> di atas (API key xkeysib- atau SMTP Login + SMTP key xsmtpsib-), "
            "lalu klik <b>Test kirim</b>. Sementara itu, verifikasi user manual lewat tombol di bawah."
            "</div>"
        )

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
    rates_ssh = payg_rates("ssh", settings)
    rates_xray = payg_rates("xray", settings)
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
  <div class="admin-stats">
    <div class="stat-card"><span>Total saldo user</span><strong>{rupiah_milli(wallet_total, strip=True)}</strong><small>saldo aktif di semua wallet</small></div>
    <div class="stat-card"><span>Deposit lunas</span><strong>{rupiah(deposit_paid)}</strong><small>{len(deposits)} invoice terbaru</small></div>
    <div class="stat-card"><span>PAYG berjalan</span><strong>{payg_running}</strong><small>{len(payg_list)} akun PAYG</small></div>
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

  <section class="panel admin-panel popup-admin-panel">
    <div class="panel-head"><div><span class="mini-label">POPUP INFORMASI</span><h2>Pesan penting untuk pengunjung</h2></div><span class="badge {'badge-ok' if settings.get('popup_enabled', '0') == '1' and settings.get('popup_message', '').strip() else 'badge-muted'}">{'Aktif' if settings.get('popup_enabled', '0') == '1' and settings.get('popup_message', '').strip() else 'Nonaktif'}</span></div>
    <form method="post" action="/admin/popup" class="server-form">
      <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
      <div class="settings-grid">
        <fieldset>
          <legend>Isi popup</legend>
          <label>Judul<input type="text" name="popup_title" value="{e(settings.get('popup_title', 'Informasi Penting'))}" maxlength="80" placeholder="Informasi Penting"></label>
          <label>Pesan<textarea name="popup_message" rows="5" maxlength="2000" placeholder="Contoh: Server Singapura sedang maintenance. Akun yang sudah ada tetap aman.">{e(settings.get('popup_message', ''))}</textarea><small>Baris baru tetap tampil. Maksimal 2.000 karakter.</small></label>
          <label>Teks tombol (opsional)<input type="text" name="popup_button_text" value="{e(settings.get('popup_button_text', ''))}" maxlength="40" placeholder="Lihat info"></label>
          <label>Link tombol (opsional)<input type="text" name="popup_button_url" value="{e(settings.get('popup_button_url', ''))}" maxlength="500" placeholder="/kontak atau https://t.me/..."></label>
        </fieldset>
        <fieldset>
          <legend>Perilaku</legend>
          <label class="switch"><input type="checkbox" name="popup_enabled" value="1" {'checked' if settings.get('popup_enabled', '0') == '1' else ''}><span>Aktifkan popup informasi</span></label>
          <label>Tampilkan<select name="popup_mode">
            <option value="once" {'selected' if settings.get('popup_mode', 'once') == 'once' else ''}>Sekali per browser (sampai isi diubah)</option>
            <option value="always" {'selected' if settings.get('popup_mode', 'once') == 'always' else ''}>Setiap halaman dibuka</option>
          </select></label>
          <p class="panel-hint">Popup muncul kecil di kanan bawah dan bisa ditutup. Menyimpan perubahan menaikkan versi agar browser yang sudah menutup popup melihatnya lagi.</p>
          <div class="info-popup-preview" aria-hidden="true">
            <span class="info-popup-kicker">INFORMASI</span>
            <b>{e(settings.get('popup_title', 'Informasi Penting'))}</b>
            <p>{e(settings.get('popup_message', '') or 'Belum ada isi popup.')}</p>
          </div>
        </fieldset>
      </div>
      <div class="form-actions"><button class="btn btn-primary btn-small" type="submit">Simpan popup</button></div>
    </form>
  </section>

  <section class="panel admin-panel signup-admin-panel">
    <div class="panel-head"><div><span class="mini-label">PENDAFTARAN</span><h2>Filter domain email</h2></div><span class="badge {signup_badge[0]}">{signup_badge[1]}</span></div>
    <form method="post" action="/admin/signup" class="server-form">
      <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
      <div class="settings-grid">
        <fieldset>
          <legend>Kebijakan</legend>
          <label>Mode filter<select name="signup_email_mode">
            <option value="block" {'selected' if signup_mode == 'block' else ''}>Blokir temp mail (rekomendasi)</option>
            <option value="google" {'selected' if signup_mode == 'google' else ''}>Hanya Google (Gmail)</option>
            <option value="allow" {'selected' if signup_mode == 'allow' else ''}>Hanya domain diizinkan (custom)</option>
            <option value="all" {'selected' if signup_mode == 'all' else ''}>Semua domain</option>
          </select></label>
          <p class="panel-hint">Hanya Google = gmail.com dan googlemail.com. Titik dan +tag di Gmail dianggap alamat yang sama, jadi tidak bisa dipakai mendaftar berkali-kali.</p>
          <label>Domain yang diizinkan<textarea name="signup_email_allow" rows="4" maxlength="4000" placeholder="gmail.com&#10;googlemail.com">{e(settings.get('signup_email_allow', 'gmail.com, googlemail.com'))}</textarea><small>Dipakai saat mode "Hanya domain diizinkan". Satu domain per baris atau pisahkan koma.</small></label>
        </fieldset>
        <fieldset>
          <legend>Blokir tambahan</legend>
          <label>Domain yang diblokir<textarea name="signup_email_block_extra" rows="7" maxlength="4000" placeholder="proton.me&#10;protonmail.com">{e(settings.get('signup_email_block_extra', ''))}</textarea><small>Satu domain per baris. Subdomain otomatis ikut diblokir. Berlaku pada mode "Blokir temp mail".</small></label>
          <p class="panel-hint">Daftar bawaan sudah memuat mailinator.com, yopmail.com, 10minutemail.com, temp-mail.org, dan domain sejenis. Untuk memblokir provider tertentu, tambahkan domainnya di sini.</p>
        </fieldset>
      </div>
      <div class="form-actions"><button class="btn btn-primary btn-small" type="submit">Simpan filter pendaftaran</button></div>
    </form>
  </section>

  <section class="panel admin-panel server-panel">
    <div class="panel-head"><div><span class="mini-label">EMAIL VERIFIKASI</span><h2>Pengirim &amp; subjek</h2></div><span class="badge {'badge-ok' if mail_ok else 'badge-warn'}">{'Siap' if mail_ok else 'Belum siap'}</span></div>
    {mail_status}
    <form method="post" action="/admin/mail" class="server-form">
      <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
      <div class="settings-grid">
        <fieldset>
          <legend>Nama &amp; pengirim</legend>
          <label>Nama pengirim<input type="text" name="mail_from_name" value="{e(settings.get('mail_from_name', BRAND))}" maxlength="60" placeholder="HITS SSH"></label>
          <label>Email pengirim<input type="email" name="mail_from_email" value="{e(settings.get('mail_from_email', 'oceantestdigital@gmail.com'))}" maxlength="190"></label>
          <label>API key Brevo (xkeysib-)<input type="password" name="mail_api_key" autocomplete="off" placeholder="xkeysib-... (kosongkan = key lama tetap dipakai)"><small><b>Ini key utama yang aktif.</b> Kosongkan jika tidak ingin mengganti.</small></label>
          <label>SMTP Login Brevo<input type="text" name="mail_smtp_user" value="{e(settings.get('mail_smtp_user', ''))}" maxlength="190" placeholder="Login yang tampil di halaman SMTP Brevo"><small>Opsional / cadangan. Bukan email pengirim.</small></label>
          <label>SMTP key Brevo (xsmtpsib-)<input type="password" name="mail_smtp_key" autocomplete="off" placeholder="xsmtpsib-... (kosongkan = key lama tetap dipakai)"><small>Cadangan otomatis jika API gagal. Port 2525.</small></label>
          <div class="settings-grid two">
            <label>SMTP host<input type="text" name="mail_smtp_host" value="{e(settings.get('mail_smtp_host', 'smtp-relay.brevo.com'))}" maxlength="190"></label>
            <label>SMTP port<input type="number" name="mail_smtp_port" min="1" max="65535" value="{e(settings.get('mail_smtp_port', '2525'))}"></label>
          </div>
          <p class="panel-hint">{e(mail_msg) if not mail_ok else 'Email API siap dipakai.'}</p>
        </fieldset>
        <fieldset>
          <legend>Subjek email</legend>
          <label>Subjek verifikasi<input type="text" name="mail_verify_subject" value="{e(settings.get('mail_verify_subject', 'Kode Verifikasi Anda'))}" maxlength="120" placeholder="Kode Verifikasi Anda"></label>
          <label>Subjek reset password<input type="text" name="mail_reset_subject" value="{e(settings.get('mail_reset_subject', 'Reset Password — HITS SSH'))}" maxlength="120"></label>
          <p class="panel-hint">Contoh format yang tampil di inbox:<br><b>{e(settings.get('mail_from_name', BRAND))}</b> · <b>{e(settings.get('mail_verify_subject', 'Kode Verifikasi Anda'))}</b></p>
          <p class="panel-hint">Email pengirim harus terverifikasi di Brevo (menu Senders).</p>
        </fieldset>
      </div>
      <div class="form-actions">
        <button class="btn btn-primary btn-small" type="submit" name="action" value="save">Simpan pengaturan email</button>
        <button class="btn btn-ghost btn-small" type="submit" name="action" value="test">Test kirim ke email pengirim</button>
      </div>
    </form>
  </section>

  <section class="panel admin-panel payg-admin-panel">
    <div class="panel-head"><div><span class="mini-label">PAY AS YOU GO</span><h2>Harga patokan & saldo</h2></div><span class="badge {'badge-ok' if settings.get('payg_enabled', '1') == '1' else 'badge-bad'}">{'Aktif' if settings.get('payg_enabled', '1') == '1' else 'Nonaktif'}</span></div>
    <form method="post" action="/admin/payg" class="server-form">
      <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
      <div class="settings-grid">
        <fieldset>
          <legend>Harga patokan 30 hari</legend>
          <label>SSH (Rp / 30 hari)<input type="number" name="payg_base_ssh_30d" min="1000" max="10000000" value="{e(settings.get('payg_base_ssh_30d', '10000'))}"></label>
          <label>Xray (Rp / 30 hari)<input type="number" name="payg_base_xray_30d" min="1000" max="10000000" value="{e(settings.get('payg_base_xray_30d', '10000'))}"></label>
          <p class="panel-hint">Tarif otomatis: per hari = harga / 30 · per jam = harga / 720 · per menit = harga / 43.200. Perubahan langsung dipakai semua akun PAYG.</p>
        </fieldset>
        <fieldset>
          <legend>Batas saldo & top up</legend>
          <label>Minimal saldo untuk Start (Rp)<input type="number" name="payg_min_balance" min="100" max="1000000" value="{e(settings.get('payg_min_balance', '1000'))}"></label>
          <label>Minimal top up (Rp)<input type="number" name="payg_min_topup" min="1000" max="10000000" value="{e(settings.get('payg_min_topup', '5000'))}"></label>
          <label>Maksimal top up (Rp)<input type="number" name="payg_max_topup" min="1000" max="100000000" value="{e(settings.get('payg_max_topup', '1000000'))}"></label>
          <label>Auto-off jika tidak ada login (menit)<input type="number" name="payg_idle_minutes" min="1" max="1440" value="{e(settings.get('payg_idle_minutes', '15'))}"><small>Akun OFF otomatis jika tidak ada sesi aktif selama ini.</small></label>
          <label class="switch"><input type="checkbox" name="payg_enabled" value="1" {'checked' if settings.get('payg_enabled', '1') == '1' else ''}><span>Buka Pay As You Go</span></label>
        </fieldset>
      </div>
      <div class="settings-grid two">
        <fieldset>
          <legend>Limit akun PAYG · SSH</legend>
          <label>Limit IP per akun<input type="number" name="payg_ssh_ip_limit" min="0" max="100" value="{e(settings.get('payg_ssh_ip_limit', '2'))}"><small>0 = tanpa batas</small></label>
          <label>Kuota bandwidth (GB)<input type="number" name="payg_ssh_quota_gb" min="0" max="10000" value="{e(settings.get('payg_ssh_quota_gb', '0'))}"><small>0 = tanpa batas</small></label>
        </fieldset>
        <fieldset>
          <legend>Limit akun PAYG · Xray</legend>
          <label>Limit IP per akun<input type="number" name="payg_xray_ip_limit" min="0" max="100" value="{e(settings.get('payg_xray_ip_limit', '2'))}"><small>0 = tanpa batas</small></label>
          <label>Kuota bandwidth (GB)<input type="number" name="payg_xray_quota_gb" min="0" max="10000" value="{e(settings.get('payg_xray_quota_gb', '0'))}"><small>0 = tanpa batas</small></label>
        </fieldset>
      </div>
      <p class="panel-hint">Limit IP &amp; kuota ini dipakai saat akun PAYG dibuat. Akun PAYG yang sudah ada tetap memakai limit saat pembuatannya.</p>
      <div class="payg-rate-grid admin-rate-grid">
        <div class="payg-rate-card"><span class="mini-label">SSH</span><b>{rupiah(rates_ssh['base'])} / 30 hari</b><div><span>Per hari</span><b>{rupiah_milli(rates_ssh['day_milli'])}</b></div><div><span>Per jam</span><b>{rupiah_milli(rates_ssh['hour_milli'])}</b></div><div><span>Per menit</span><b>{rupiah_milli(rates_ssh['minute_milli'])}</b></div><div><span>Limit IP</span><b>{e(settings.get('payg_ssh_ip_limit', '2'))}</b></div><div><span>Kuota</span><b>{e(settings.get('payg_ssh_quota_gb', '0'))} GB</b></div></div>
        <div class="payg-rate-card"><span class="mini-label">XRAY</span><b>{rupiah(rates_xray['base'])} / 30 hari</b><div><span>Per hari</span><b>{rupiah_milli(rates_xray['day_milli'])}</b></div><div><span>Per jam</span><b>{rupiah_milli(rates_xray['hour_milli'])}</b></div><div><span>Per menit</span><b>{rupiah_milli(rates_xray['minute_milli'])}</b></div><div><span>Limit IP</span><b>{e(settings.get('payg_xray_ip_limit', '2'))}</b></div><div><span>Kuota</span><b>{e(settings.get('payg_xray_quota_gb', '0'))} GB</b></div></div>
      </div>
      <div class="form-actions"><button class="btn btn-primary btn-small" type="submit">Simpan pengaturan PAYG</button></div>
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

  <section class="panel admin-panel">
    <div class="panel-head"><div><span class="mini-label">DEPOSIT SALDO</span><h2>Invoice top up</h2></div><span class="panel-hint">Mark paid untuk kredit manual jika gateway terlambat.</span></div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Invoice</th><th>Nominal</th><th>Status</th><th></th></tr></thead>
        <tbody>{deposit_rows}</tbody>
      </table>
    </div>
    <details class="add-product">
      <summary>+ Sesuaikan saldo user</summary>
      <form method="post" action="/admin/wallet" class="settings-grid add-product-form">
        <input type="hidden" name="_csrf" value="{e(session['csrf'])}">
        <label>Email user<input type="email" name="email" placeholder="user@email.com" required></label>
        <label>Nominal (Rp)<input type="number" name="amount" min="1" max="100000000" value="10000" required></label>
        <label>Aksi<select name="action"><option value="add">Tambah saldo</option><option value="subtract">Kurangi saldo</option></select></label>
        <label>Catatan<input type="text" name="note" maxlength="200" placeholder="Contoh: bonus / refund"></label>
        <div class="form-actions"><button class="btn btn-dark btn-small" type="submit">Simpan saldo</button></div>
      </form>
    </details>
  </section>

  <section class="panel admin-panel">
    <div class="panel-head"><div><span class="mini-label">PAY AS YOU GO</span><h2>Akun & argo</h2></div><span class="panel-hint">Saldo dan pemakaian per akun.</span></div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Akun</th><th>State</th><th>Terpakai</th><th>Saldo user</th></tr></thead>
        <tbody>{payg_admin_rows}</tbody>
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

  <section class="panel admin-panel accounts-panel">
    <div class="panel-head"><div><span class="mini-label">USER TERDAFTAR</span><h2>Akun member</h2></div><span class="panel-hint">Verifikasi manual jika email tidak terkirim.</span></div>
    {mail_notice}
    <div class="table-wrap">
      <table>
        <thead><tr><th>Email</th><th>Status</th><th>Saldo</th><th>Login terakhir</th><th></th></tr></thead>
        <tbody>{user_rows}</tbody>
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


def render_deposit_page(form_token: str, settings: dict[str, str], user_id: int, msg: str = "") -> str:
    balance = wallet_balance_milli(user_id)
    min_topup = _setting_int(settings, "payg_min_topup", 5000)
    max_topup = _setting_int(settings, "payg_max_topup", 1000000)
    ts_site, _ts_secret, ts_on = turnstile_config()
    ts_widget = (
        '<div class="turnstile-box premium-turnstile">'
        f'<div class="cf-turnstile" data-sitekey="{e(ts_site)}" data-theme="light" data-language="id" data-size="flexible"></div>'
        '<small class="turnstile-status" data-turnstile-status>Memuat verifikasi keamanan…</small>'
        '</div>'
        if ts_on
        else ""
    )
    notice = ""
    msgs = {
        "created": ("ok", "Invoice deposit dibuat. Scan QRIS dan bayar sesuai nominal."),
        "amount": ("error", f"Nominal deposit minimal {rupiah(min_topup)} dan maksimal {rupiah(max_topup)}."),
        "limit": ("error", "Terlalu banyak invoice deposit aktif. Selesaikan atau tunggu invoice lama kedaluwarsa."),
        "fail": ("error", "Gagal membuat invoice deposit. Coba lagi beberapa saat."),
    }
    if msg in msgs:
        kind, text = msgs[msg]
        notice = f'<div class="notice notice-{kind}">{e(text)}</div>'
    quick = "".join(
        f'<button type="button" class="amount-pill" data-amount="{amount}">{rupiah(amount)}</button>'
        for amount in (5000, 10000, 20000, 50000, 100000)
    )
    history = deposit_history(user_id, 30)
    rows = ""
    status_map = {
        "PENDING": ("badge-warn", "Menunggu"),
        "PAID": ("badge-ok", "Masuk"),
        "EXPIRED": ("badge-muted", "Kedaluwarsa"),
    }
    for row in history:
        cls, txt = status_map.get(row["status"], ("badge-muted", row["status"]))
        rows += (
            "<tr>"
            f"<td><a class=\"invoice-link\" href=\"/deposit/{e(row['invoice'])}\"><b>{e(row['invoice'])}</b></a>"
            f"<small>{e(fmt_ts(row['created_at'], '%d %b %Y · %H:%M WIB'))}</small></td>"
            f"<td><b>{rupiah(row['amount'])}</b><small>+ kode {rupiah(row['unique_code'])}</small></td>"
            f"<td><span class=\"badge {cls}\">{txt}</span></td>"
            f"<td>{e(fmt_ts(row['paid_at'], '%d %b %H:%M')) if row['paid_at'] else '-'}</td>"
            "</tr>"
        )
    if not rows:
        rows = '<tr><td colspan="4" class="empty">Belum ada riwayat deposit.</td></tr>'
    body = f"""
<main class="deposit-main wrap">
  <div class="deposit-head">
    <div class="eyebrow"><span class="dot"></span> SALDO &amp; DEPOSIT</div>
    <h1>Isi saldo.<br><em>Pakai saat butuh.</em></h1>
    <p>Saldo dipakai untuk akun Pay As You Go. Top up lewat QRIS GoPay, saldo masuk otomatis setelah pembayaran terdeteksi.</p>
  </div>
  {notice}
  <div class="deposit-layout">
    <section class="panel deposit-form-card">
      <div class="wallet-balance-box">
        <span class="mini-label">SALDO SAAT INI</span>
        <b>{rupiah_milli(balance, strip=True)}</b>
        <small>Minimal saldo untuk Start PAYG: {rupiah_milli(_setting_int(settings, 'payg_min_balance', 1000) * 1000)}</small>
      </div>
      <form method="post" action="/deposit" class="stack-form deposit-form" id="deposit-form">
        <input type="hidden" name="_form" value="{e(form_token)}">
        <label>Nominal deposit
          <input type="number" name="amount" id="deposit-amount" min="{min_topup}" max="{max_topup}" step="1000" value="{min_topup}" required>
          <small>Minimal {rupiah(min_topup)} · maksimal {rupiah(max_topup)}.</small>
        </label>
        <div class="amount-pills">{quick}</div>
        {ts_widget}
        <button class="btn btn-primary btn-block" type="submit">Buat invoice QRIS <span aria-hidden="true">↗</span></button>
      </form>
      <p class="form-note">Nominal invoice = deposit + <b>kode unik Rp1–999</b> untuk mencocokkan pembayaran. Saldo yang masuk adalah nominal deposit.</p>
    </section>
    <aside class="deposit-side">
      <div class="panel premium-info">
        <div class="premium-badge">PAY AS YOU GO</div>
        <h3>Tarif otomatis.</h3>
        <p>Tarif mengikuti harga patokan admin. Saldo hanya terpotong saat akun berstatus ON.</p>
        <div class="payg-rate-box compact">
          <div><span>SSH / jam</span><b>{rupiah_milli(payg_rates('ssh', settings)['hour_milli'])}</b></div>
          <div><span>Xray / jam</span><b>{rupiah_milli(payg_rates('xray', settings)['hour_milli'])}</b></div>
        </div>
        <a class="btn btn-dark btn-block" href="/dashboard/saldo">Riwayat saldo</a>
      </div>
      <div class="panel check-card">
        <span class="mini-label">BUTUH BANTUAN?</span>
        <h3>Deposit tidak masuk?</h3>
        <p>Buka invoice deposit, lalu hubungi admin dengan kode invoice dan bukti pembayaran.</p>
        <a class="btn btn-ghost btn-block" href="/kontak">Hubungi admin</a>
      </div>
    </aside>
  </div>
  <section class="dash-section deposit-history">
    <div class="dash-section-head"><div><span class="mini-label">RIWAYAT</span><h2>Invoice deposit</h2></div><span class="dash-count">{len(history)} transaksi</span></div>
    <div class="dash-table-wrap"><table class="dash-table"><thead><tr><th>Invoice</th><th>Nominal</th><th>Status</th><th>Dibayar</th></tr></thead><tbody>{rows}</tbody></table></div>
  </section>
</main>
"""
    return page_shell("Deposit Saldo", body, active="deposit", noindex=True, turnstile=ts_on)

def render_deposit_invoice(row: sqlite3.Row, new: bool = False) -> str:
    status = row["status"]
    status_text = {
        "PENDING": "Menunggu pembayaran",
        "PAID": "Saldo sudah masuk",
        "EXPIRED": "Invoice kedaluwarsa",
    }.get(status, status)
    status_class = "ok" if status == "PAID" else ("warn" if status == "PENDING" else "bad")
    total = int(row["total"])
    amount = int(row["amount"])
    unique = int(row["unique_code"])
    expires = fmt_ts(row["expires_at"], "%d %b %Y · %H:%M WIB")
    paid = fmt_ts(row["paid_at"], "%d %b %Y · %H:%M WIB") if row["paid_at"] else "-"
    balance = wallet_balance_milli(int(row["user_id"]))
    if status == "PAID":
        content = f"""
    <div class="invoice-done">
      <div class="success-mark">✓</div>
      <div><div class="eyebrow"><span class="dot"></span> SALDO MASUK</div><h2>Top up berhasil.</h2><p>Invoice <b>{e(row['invoice'])}</b> · {rupiah(amount)} masuk ke saldo Anda pada {e(paid)}.</p></div>
      <div class="invoice-actions"><a class="btn btn-small btn-dark" href="/dashboard/saldo">Buka saldo</a><a class="btn btn-small btn-ghost" href="/premium?scheme=payg">Buat akun PAYG</a></div>
    </div>
    <div class="wallet-invoice-balance"><span>Saldo sekarang</span><b>{rupiah_milli(balance, strip=True)}</b></div>"""
    elif status == "PENDING":
        content = f"""
    <div class="invoice-pay">
      <div class="qr-box"><img class="qr-img" src="/deposit/{e(row['invoice'])}/qr.svg" alt="QRIS GoPay" width="260" height="260"><span>Scan dengan aplikasi bank / e-wallet</span></div>
      <div class="pay-detail">
        <span class="mini-label">TOTAL PEMBAYARAN</span>
        <div class="pay-total">{rupiah(total)}</div>
        <div class="pay-breakdown">{rupiah(amount)} deposit + kode unik {rupiah(unique)}</div>
        <div class="pay-expiry">Bayar sebelum <b>{e(expires)}</b></div>
        <div class="pay-countdown" id="deposit-countdown" data-expires="{int(row['expires_at'])}">--:--</div>
        <div class="notice notice-warn invoice-warning"><b>Saldo masuk: {rupiah(amount)}.</b> Kode unik dipakai untuk mencocokkan pembayaran.</div>
        <div class="invoice-code-line"><code>{e(row['invoice'])}</code><button type="button" class="btn btn-small btn-ghost" data-copy="{e(row['invoice'])}">Salin invoice</button></div>
        <div class="pay-status" id="deposit-live-status">Status: <b>{e(status_text)}</b></div>
      </div>
    </div>"""
    else:
        content = f"""
    <div class="invoice-expired">
      <div class="error-code">⌛</div>
      <div><div class="eyebrow"><span class="dot"></span> INVOICE KEDALUWARSA</div><h2>Waktu pembayaran habis.</h2><p>Invoice ini sudah lewat batas. Silakan buat invoice deposit baru.</p><a class="btn btn-small btn-primary" href="/deposit">Deposit lagi</a></div>
    </div>"""
    data = json.dumps({
        "invoice": row["invoice"],
        "status": status,
        "expires_at": int(row["expires_at"]),
        "total": total,
        "amount": amount,
    }, ensure_ascii=False).replace("</", "<\\/")
    body = f"""
<main class="invoice-page wrap">
  <div class="invoice-head">
    <div class="eyebrow"><span class="dot"></span> INVOICE DEPOSIT</div>
    <h1>{e(row['invoice'])}</h1>
    <div class="invoice-meta">
      <span class="badge badge-{status_class}">{e(status_text)}</span>
      <span>Deposit {rupiah(amount)}</span>
      <span>Dibuat {e(fmt_ts(row['created_at'], '%d %b %Y · %H:%M WIB'))}</span>
    </div>
  </div>
  <div class="invoice-shell panel">
    {content}
    <div class="invoice-foot">
      <span>Invoice <b>{e(row['invoice'])}</b></span>
      <span>Total <b>{rupiah(total)}</b></span>
      <a href="/deposit">Deposit lagi</a>
      <a href="/dashboard/saldo">Riwayat saldo</a>
    </div>
  </div>
</main>
<script type="application/json" id="deposit-data">{data}</script>
"""
    return page_shell("Invoice Deposit", body, noindex=True)

def render_check_invoice(form_token: str, error: str = "", code: str = "") -> str:
    err = f'<div class="notice notice-error">{e(error)}</div>' if error else ""
    body = f"""
<main class="invoice-page wrap">
  <div class="invoice-head check-head">
    <div class="eyebrow"><span class="dot"></span> CEK INVOICE / RIWAYAT</div>
    <h1>Buka lagi<br>pesanan Anda.</h1>
    <p class="page-hero-lead">Masukkan kode invoice. Invoice baru tersimpan di dashboard member; invoice lama tetap bisa dibuka dengan kodenya.</p>
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
    invoice_output = format_account_output(
        "ssh" if row["protocol"] == "ssh" else "xray",
        row["protocol"],
        invoice_output,
    )
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
  <p>Kode ini juga tersimpan di dashboard member. Jangan tutup halaman sebelum menyimpannya.</p>
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
    threading.Thread(target=payg_daemon, name="payg-billing", daemon=True).start()
    try:
        usage_snapshot_once()
    except Exception:
        logger.warning("snapshot awal usage gagal: %s", traceback.format_exc())
    threading.Thread(target=usage_snapshot_loop, name="usage-snapshot", daemon=True).start()

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
