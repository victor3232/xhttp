#!/usr/bin/env python3
# ============================================================
#  kyt-node-agent v2 — agent ringan untuk VPS cabang (node)
#  - API Key + Secret per node (HMAC-SHA256)
#  - idempotency key untuk semua aksi mutasi
#  - renew, suspend/resume (mullog), sessions/IP, capability
#  - tidak ada endpoint shell/exec bebas
#  Kompatibel dengan kredensial lama (X-Kyt-Node + token).
# ============================================================
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import pwd
import re
import secrets
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CONF_PATH = "/etc/kyt-node/agent.json"
VERSION = "2.0.0"
USER_RE = re.compile(r"^[a-z][a-z0-9]{7,14}$")
SSH_SCRIPT = "/usr/local/sbin/addssh"
SSH_RENEW = "/usr/local/sbin/renewssh"
XRAY_SCRIPTS = {
    "vmess": "/usr/local/sbin/addws",
    "vless": "/usr/local/sbin/addvless",
    "trojan": "/usr/local/sbin/addtr",
}
XRAY_RENEW = {
    "vmess": "/usr/local/sbin/renewws",
    "vless": "/usr/local/sbin/renewvless",
    "trojan": "/usr/local/sbin/renewtr",
}
MULLOG_BIN = "/usr/local/sbin/jeda-mullog"
MULLOG_STATE = Path("/etc/kyt/jeda-mullog/state")
MULLOG_HISTORY = Path("/etc/kyt/jeda-mullog/history.jsonl")
HTML_DIR = Path("/var/www/html")
XRAY_CONFIG = Path("/etc/xray/config.json")
IDEM_DB = "/var/lib/kyt-node/idempotency.db"
LOCATION_CACHE = Path("/var/lib/kyt-node/location.json")
LOCATION_TTL = 3600
MAX_BODY = 64 * 1024
CLOCK_SKEW = 60
NONCE_TTL = 300

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def load_conf() -> dict:
    with open(CONF_PATH, encoding="utf-8") as fh:
        return json.load(fh)


CONF = load_conf()
NODE = str(CONF.get("node") or "node")
API_KEY = str(CONF.get("api_key") or "")
SECRET = str(CONF.get("secret") or CONF.get("token") or "")
LEGACY_TOKEN = str(CONF.get("token") or "")
OLD_API_KEY = ""
OLD_SECRET = ""
OLD_UNTIL = 0.0
REVOKED = bool(CONF.get("revoked"))
ALLOW_IPS = {str(x) for x in (CONF.get("allow_ips") or []) if x}
CERT = CONF.get("cert") or "/etc/xray/xray.crt"
KEY = CONF.get("key") or "/etc/xray/xray.key"
MAX_SLOTS = int(CONF.get("max_slots") or 0)

_nonce_lock = threading.Lock()
_nonces: dict[str, float] = {}
_rate_lock = threading.Lock()
_rates: dict[str, list] = {}
_idem_lock = threading.Lock()


def save_conf(data: dict) -> None:
    tmp = CONF_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONF_PATH)


def init_idem() -> None:
    os.makedirs(os.path.dirname(IDEM_DB), exist_ok=True)
    con = sqlite3.connect(IDEM_DB, timeout=20)
    try:
        con.execute("CREATE TABLE IF NOT EXISTS keys (k TEXT PRIMARY KEY, result TEXT NOT NULL, created INTEGER NOT NULL)")
        con.commit()
    finally:
        con.close()


def idem_get(key: str) -> dict | None:
    if not key:
        return None
    con = sqlite3.connect(IDEM_DB, timeout=20)
    try:
        row = con.execute("SELECT result FROM keys WHERE k=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None
    except Exception:
        return None
    finally:
        con.close()


def idem_put(key: str, result: dict) -> None:
    if not key:
        return
    with _idem_lock:
        con = sqlite3.connect(IDEM_DB, timeout=20)
        try:
            con.execute("INSERT OR REPLACE INTO keys(k,result,created) VALUES(?,?,?)",
                        (key, json.dumps(result, ensure_ascii=False), int(time.time())))
            con.execute("DELETE FROM keys WHERE created<?", (int(time.time()) - 7 * 86400,))
            con.commit()
        finally:
            con.close()


def _clean_nonces() -> None:
    now = time.time()
    with _nonce_lock:
        for k, ts in list(_nonces.items()):
            if now - ts > NONCE_TTL:
                _nonces.pop(k, None)


def _rate_ok(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        bucket = [t for t in _rates.get(ip, []) if now - t < 60]
        if len(bucket) >= 180:
            _rates[ip] = bucket
            return False
        bucket.append(now)
        _rates[ip] = bucket
    return True


def _run_script(path: str, answers: list[str], timeout: int = 120) -> tuple[int, str]:
    env = os.environ.copy()
    env.update({"TERM": "dumb", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    payload = "\n".join(str(a) for a in answers) + "\n"
    proc = subprocess.Popen(
        [path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, env=env, cwd="/root", start_new_session=True,
    )
    try:
        out, _ = proc.communicate(payload, timeout=timeout)
        return proc.returncode, (out or "").strip()
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, 9)
        except Exception:
            pass
        try:
            out, _ = proc.communicate(timeout=5)
        except Exception:
            out = ""
        return 124, (out or "timeout").strip()


def _read_int(path) -> int:
    try:
        raw = open(path, encoding="utf-8", errors="ignore").read().strip()
        m = re.search(r"\d+", raw)
        return int(m.group(0)) if m else 0
    except Exception:
        return 0


def _read_text(path) -> str:
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except Exception:
        return ""


def _ssh_db_line(user: str) -> str:
    for line in _read_text("/etc/ssh/.ssh.db").splitlines():
        if re.match(r"^#ssh#\s+" + re.escape(user) + r"(?:\s|$)", line):
            return line
    return ""


def _xray_db_line(protocol: str, user: str) -> str:
    path = {"vmess": "/etc/vmess/.vmess.db", "vless": "/etc/vless/.vless.db",
            "trojan": "/etc/trojan/.trojan.db"}[protocol]
    for line in _read_text(path).splitlines():
        if re.match(r"^###\s+" + re.escape(user) + r"(?:\s|$)", line):
            return line
    return ""


def _parse_expiry(service: str, protocol: str, user: str) -> int:
    try:
        if service == "ssh":
            line = _ssh_db_line(user)
            m = re.search(r"(\d{1,2} [A-Za-z]{3},? \d{4})", line)
            if m:
                return int(time.mktime(time.strptime(m.group(1).replace(",", ""), "%d %b %Y")))
        else:
            line = _xray_db_line(protocol, user)
            m = re.search(r"(\d{4}-\d{2}-\d{2})", line)
            if m:
                return int(time.mktime(time.strptime(m.group(1), "%Y-%m-%d")))
    except Exception:
        pass
    return 0


def _paths(service: str, protocol: str, user: str) -> dict:
    if service == "ssh":
        return {"quota": f"/etc/ssh/{user}", "usage": f"/etc/limit/ssh/{user}",
                "ip": f"/etc/kyt/limit/ssh/ip/{user}", "profile": f"{HTML_DIR}/ssh-{user}.txt"}
    return {"quota": f"/etc/{protocol}/{user}", "usage": f"/etc/limit/{protocol}/{user}",
            "ip": f"/etc/kyt/limit/{protocol}/ip/{user}", "profile": f"{HTML_DIR}/{protocol}-{user}.txt"}


def _exists(service: str, protocol: str, user: str) -> bool:
    if service == "ssh":
        return bool(_ssh_db_line(user)) or os.path.exists(f"/etc/ssh/{user}")
    return bool(_xray_db_line(protocol, user))


def _count_accounts() -> dict:
    def count(path: str, pattern: str) -> int:
        return sum(1 for line in _read_text(path).splitlines() if re.match(pattern, line))
    return {"ssh": count("/etc/ssh/.ssh.db", r"^#ssh#\s+"),
            "vmess": count("/etc/vmess/.vmess.db", r"^###\s+"),
            "vless": count("/etc/vless/.vless.db", r"^###\s+"),
            "trojan": count("/etc/trojan/.trojan.db", r"^###\s+")}


def _services() -> dict:
    out = {}
    for name in ("xray", "ssh", "dropbear", "haproxy"):
        try:
            r = subprocess.run(["systemctl", "is-active", name], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True, timeout=5)
            out[name] = (r.stdout or "").strip() or "unknown"
        except Exception:
            out[name] = "unknown"
    return out


def _clean_isp(value: str) -> str:
    """Hilangkan prefix AS number dari ipinfo, contoh 'AS14061 DigitalOcean, LLC'."""
    value = re.sub(r"^AS\d+\s+", "", (value or "").strip(), flags=re.I)
    return value.strip()


def _location(force: bool = False) -> dict:
    """Deteksi ISP/region node. Sumber sama dengan VPS utama, plus fallback file autoscript."""
    if not force:
        try:
            cached = json.loads(LOCATION_CACHE.read_text(encoding="utf-8"))
            if cached and time.time() - int(cached.get("_ts") or 0) < LOCATION_TTL:
                cached.pop("_ts", None)
                return cached
        except Exception:
            pass
    data = {}
    sources = [
        ("https://ipinfo.io/json", "country", "city", "org"),
        ("https://ipapi.co/json/", "country_code", "city", "org"),
        ("https://ifconfig.co/json", "country_iso", "city", "organization"),
    ]
    for url, ckey, citykey, orgkey in sources:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "kyt-node/2.1"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                raw = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:
            continue
        code = str(raw.get(ckey) or "").strip().upper()
        if len(code) != 2 or not code.isalpha():
            continue
        data = {
            "country_code": code,
            "city": str(raw.get(citykey) or "").strip(),
            "isp": _clean_isp(str(raw.get(orgkey) or "")),
            "source": url,
        }
        break
    if not data.get("isp"):
        data["isp"] = _read_text("/etc/xray/isp").strip()
    if not data.get("city"):
        data["city"] = _read_text("/etc/xray/city").strip()
    if not data.get("country_code"):
        data["country_code"] = _read_text("/etc/xray/country").strip().upper()
    if data.get("country_code") or data.get("isp"):
        try:
            os.makedirs(LOCATION_CACHE.parent, exist_ok=True)
            tmp = str(LOCATION_CACHE) + ".tmp"
            payload = dict(data)
            payload["_ts"] = int(time.time())
            open(tmp, "w", encoding="utf-8").write(json.dumps(payload))
            os.chmod(tmp, 0o600)
            os.replace(tmp, LOCATION_CACHE)
        except Exception:
            pass
    return data


def _validate(payload: dict) -> tuple:
    service = str(payload.get("service") or "")
    protocol = str(payload.get("protocol") or "")
    user = str(payload.get("username") or "")
    if service not in ("ssh", "xray"):
        raise ValueError("service tidak valid")
    if service == "xray" and protocol not in XRAY_SCRIPTS:
        raise ValueError("protocol tidak valid")
    if service == "ssh":
        protocol = ""
    if not USER_RE.match(user):
        raise ValueError("username tidak valid (8-15 huruf/angka, diawali huruf)")
    days = int(payload.get("days") or 0)
    ip_limit = int(payload.get("ip_limit") or 0)
    quota_gb = int(payload.get("quota_gb") or 0)
    if not (1 <= days <= 3650):
        raise ValueError("days harus 1-3650")
    if not (0 <= ip_limit <= 100):
        raise ValueError("ip_limit harus 0-100")
    if not (0 <= quota_gb <= 10000):
        raise ValueError("quota_gb harus 0-10000")
    password = str(payload.get("password") or "")
    if service == "ssh" and not password:
        alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        password = "".join(secrets.choice(alphabet) for _ in range(12))
    return service, protocol, user, days, ip_limit, quota_gb, password


def _status(service: str, protocol: str, user: str) -> dict:
    if service not in ("ssh", "xray") or not USER_RE.match(user):
        raise ValueError("parameter tidak valid")
    if service == "xray" and protocol not in XRAY_SCRIPTS:
        raise ValueError("protocol tidak valid")
    if service == "ssh":
        protocol = ""
    if not _exists(service, protocol, user):
        return {"ok": False, "error": "Akun tidak ditemukan.", "code": "not_found"}
    paths = _paths(service, protocol, user)
    online = 0
    if service == "ssh":
        try:
            r = subprocess.run(["pgrep", "-u", user], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True, timeout=5)
            online = len([x for x in (r.stdout or "").splitlines() if x.strip()])
        except Exception:
            online = 0
    sessions = []
    try:
        if service == "ssh":
            sessions = sorted(collect_ssh_ips({user}, 30).get(user, set()))
        else:
            sessions = sorted(collect_xray_ips({user}, 30).get(user, set()))
    except Exception:
        sessions = []
    if sessions:
        online = max(online, len(sessions))
    state = mullog_state(service, protocol, user)
    return {
        "ok": True, "node": NODE, "username": user, "service": service, "protocol": protocol,
        "usage_bytes": _read_int(paths["usage"]), "quota_bytes": _read_int(paths["quota"]),
        "ip_limit": _read_int(paths["ip"]), "expires_at": _parse_expiry(service, protocol, user),
        "online": online, "sessions": sessions, "mullog": state,
    }


def _create(payload: dict) -> dict:
    service, protocol, user, days, ip_limit, quota_gb, password = _validate(payload)
    if _exists(service, protocol, user):
        return {"ok": False, "error": "Akun sudah ada di node ini.", "code": "exists"}
    if service == "ssh":
        rc, log = _run_script(SSH_SCRIPT, [user, password, str(ip_limit), str(quota_gb), str(days)])
    else:
        rc, log = _run_script(XRAY_SCRIPTS[protocol], [user, str(days), str(quota_gb), str(ip_limit)])
    if not _exists(service, protocol, user):
        return {"ok": False, "error": "Pembuatan akun gagal.", "code": "failed",
                "rc": rc, "log": log[-3000:]}
    paths = _paths(service, protocol, user)
    return {
        "ok": True, "node": NODE, "username": user,
        "password": password if service == "ssh" else "", "service": service, "protocol": protocol,
        "expires_at": _parse_expiry(service, protocol, user),
        "profile": _read_text(paths["profile"]).strip(), "rc": rc,
    }


def _remove_ssh(user: str) -> None:
    subprocess.run(["pkill", "-9", "-u", user], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["userdel", user], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for path in (f"/etc/ssh/{user}", f"/etc/limit/ssh/{user}", f"/etc/limit/ssh/{user}.lock",
                 f"/etc/limit/ssh/{user}.tmp", f"/etc/kyt/limit/ssh/ip/{user}",
                 f"{HTML_DIR}/ssh-{user}.txt"):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    path = "/etc/ssh/.ssh.db"
    if os.path.exists(path):
        lines = [l for l in _read_text(path).splitlines(True)
                 if not re.match(r"^#ssh#\s+" + re.escape(user) + r"(?:\s|$)", l)]
        open(path, "w", encoding="utf-8", errors="ignore").write("".join(lines))


def _remove_xray(protocol: str, user: str) -> bool:
    marker = {"vmess": "###", "vless": "#&", "trojan": "#!"}[protocol]
    try:
        lines = open(XRAY_CONFIG, encoding="utf-8", errors="ignore").read().splitlines(True)
    except FileNotFoundError:
        return False
    pattern = re.compile(r"^\s*" + re.escape(marker) + r"\s+" + re.escape(user) + r"(?:\s|$)")
    out, changed, i = [], False, 0
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
        tmp = str(XRAY_CONFIG) + ".tmp"
        open(tmp, "w", encoding="utf-8").write("".join(out))
        os.replace(tmp, XRAY_CONFIG)
    db = {"vmess": "/etc/vmess/.vmess.db", "vless": "/etc/vless/.vless.db",
          "trojan": "/etc/trojan/.trojan.db"}[protocol]
    if os.path.exists(db):
        keep = [l for l in _read_text(db).splitlines(True)
                if not re.match(r"^###\s+" + re.escape(user) + r"(?:\s|$)", l)]
        open(db, "w", encoding="utf-8").write("".join(keep))
    for path in (f"/etc/{protocol}/{user}", f"/etc/limit/{protocol}/{user}",
                 f"/etc/kyt/limit/{protocol}/ip/{user}", f"{HTML_DIR}/{protocol}-{user}.txt"):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    return changed


def _delete(service: str, protocol: str, user: str) -> dict:
    if service not in ("ssh", "xray") or not USER_RE.match(user):
        raise ValueError("parameter tidak valid")
    if service == "xray" and protocol not in XRAY_SCRIPTS:
        raise ValueError("protocol tidak valid")
    if service == "ssh":
        _remove_ssh(user)
    else:
        if _remove_xray(protocol, user):
            subprocess.run(["systemctl", "restart", "xray"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=60)
    return {"ok": True, "node": NODE, "username": user, "deleted": True}


def _renew(service: str, protocol: str, user: str, payload: dict) -> dict:
    if service not in ("ssh", "xray") or not USER_RE.match(user):
        raise ValueError("parameter tidak valid")
    if service == "xray" and protocol not in XRAY_SCRIPTS:
        raise ValueError("protocol tidak valid")
    if service == "ssh":
        protocol = ""
    if not _exists(service, protocol, user):
        return {"ok": False, "error": "Akun tidak ditemukan.", "code": "not_found"}
    days = int(payload.get("days") or 0)
    if not (1 <= days <= 3650):
        raise ValueError("days harus 1-3650")
    paths = _paths(service, protocol, user)
    quota_gb = payload.get("quota_gb")
    ip_limit = payload.get("ip_limit")
    if service == "ssh":
        # renewssh menulis ulang password dari variabel kosong -> jangan dipakai.
        line = _ssh_db_line(user)
        m = re.search(r"(\d{1,2} [A-Za-z]{3},? \d{4})", line)
        now = int(time.time())
        current = 0
        if m:
            try:
                current = int(time.mktime(time.strptime(m.group(1).replace(",", ""), "%d %b %Y")))
            except Exception:
                current = 0
        base = max(now, current)
        new_ts = base + days * 86400
        new_display = time.strftime("%d %b, %Y", time.localtime(new_ts))
        new_iso = time.strftime("%Y-%m-%d", time.localtime(new_ts))
        new_line = re.sub(r"\d{1,2} [A-Za-z]{3},? \d{4}", new_display, line, count=1)
        db = "/etc/ssh/.ssh.db"
        lines = _read_text(db).splitlines(True)
        lines = [new_line + "\n" if re.match(r"^#ssh#\s+" + re.escape(user) + r"(?:\s|$)", l) else l for l in lines]
        open(db, "w", encoding="utf-8", errors="ignore").write("".join(lines))
        subprocess.run(["usermod", "-e", new_iso, user], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20)
        subprocess.run(["chage", "-E", new_iso, user], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20)
        if quota_gb is not None:
            q = max(0, min(10000, int(quota_gb)))
            if q > 0:
                open(paths["quota"], "w").write(str(q * 1024 * 1024 * 1024))
        if ip_limit is not None:
            open(paths["ip"], "w").write(str(max(0, min(100, int(ip_limit)))))
    else:
        q = quota_gb
        if q is None:
            q = round(_read_int(paths["quota"]) / (1024 ** 3))
        ip = ip_limit
        if ip is None:
            ip = _read_int(paths["ip"])
        rc, log = _run_script(XRAY_RENEW[protocol], [user, str(days), str(int(q)), str(int(ip))])
        if not _exists(service, protocol, user):
            return {"ok": False, "error": "Renew gagal.", "code": "failed", "rc": rc, "log": log[-2000:]}
        # Script panel memperbarui config.json, tetapi tidak selalu .vmess/.vless/.trojan.db.
        # Sinkronkan tanggal di db agar status & monitoring membaca expiry yang benar.
        marker = {"vmess": "###", "vless": "#&", "trojan": "#!"}[protocol]
        new_date = ""
        for line in _read_text(XRAY_CONFIG).splitlines():
            if re.match(r"^\s*" + re.escape(marker) + r"\s+" + re.escape(user) + r"(?:\s|$)", line):
                mdate = re.search(r"(\d{4}-\d{2}-\d{2})", line)
                if mdate:
                    new_date = mdate.group(1)
                    break
        if new_date:
            db = {"vmess": "/etc/vmess/.vmess.db", "vless": "/etc/vless/.vless.db",
                  "trojan": "/etc/trojan/.trojan.db"}[protocol]
            lines = _read_text(db).splitlines(True)
            out = []
            for line in lines:
                if re.match(r"^###\s+" + re.escape(user) + r"(?:\s|$)", line):
                    line = re.sub(r"(\d{4}-\d{2}-\d{2})", new_date, line, count=1)
                out.append(line)
            open(db, "w", encoding="utf-8").write("".join(out))
    return _status(service, protocol, user)


def _mullog_args(action: str, service: str, protocol: str, user: str) -> list:
    if service == "ssh":
        return [MULLOG_BIN, action, "ssh", user]
    return [MULLOG_BIN, action, "xray", protocol, user]


def mullog_state(service: str, protocol: str, user: str) -> dict | None:
    safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", str(user))
    if service == "ssh":
        name = f"ssh-{safe_user}.json"
    else:
        safe_proto = re.sub(r"[^A-Za-z0-9_.-]", "_", str(protocol))
        name = f"xray-{safe_proto}-{safe_user}.json"
    path = MULLOG_STATE / name
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _mullog(action: str, service: str, protocol: str, user: str) -> dict:
    if not os.path.exists(MULLOG_BIN):
        return {"ok": False, "error": "jeda-mullog tidak terpasang di node.", "code": "no_mullog"}
    try:
        r = subprocess.run(_mullog_args(action, service, protocol, user),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=60)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "code": "failed"}
    if r.returncode not in (0, 3):
        return {"ok": False, "error": (r.stdout or "gagal").strip()[-1000:], "code": "failed"}
    return {"ok": True, "node": NODE, "username": user, "action": action,
            "mullog": mullog_state(service, protocol, user)}


# ---------------- sessions / IP ----------------
def _strip_hostport(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
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


def _tail_lines(path: Path, count: int = 5000) -> list:
    try:
        if not path.exists():
            return []
        p = subprocess.run(["tail", "-n", str(count), str(path)], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, text=True, timeout=8)
        return p.stdout.splitlines()
    except Exception:
        return []


def collect_xray_ips(usernames: set, minutes: int = 20) -> dict:
    result = {name: set() for name in usernames}
    if not usernames:
        return result
    cutoff = dt.datetime.now() - dt.timedelta(minutes=max(1, minutes))
    pattern = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\.\d+\s+from\s+(\S+)\s+accepted\b.*?\bemail:\s*(\S+)")
    for line in _tail_lines(Path("/var/log/xray/access.log"), 6000):
        m = pattern.search(line)
        if not m:
            continue
        try:
            stamp = dt.datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S")
        except ValueError:
            continue
        if stamp < cutoff:
            continue
        user = m.group(3)
        if user not in result:
            continue
        ip = _strip_hostport(m.group(2))
        if ip and not _local_ip(ip):
            result[user].add(ip)
    return result


def _ssh_listener_ports() -> set:
    ports = set()
    try:
        p = subprocess.run(["ss", "-tlnpH"], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, text=True, timeout=8)
    except Exception:
        return ports
    for line in p.stdout.splitlines():
        if "sshd" not in line and "dropbear" not in line:
            continue
        f = line.split()
        if len(f) >= 4:
            ports.add(f[3].rsplit(":", 1)[-1])
    return ports or {"22", "2222", "2223", "109", "143"}


def _pid_user(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/status", "r", errors="ignore") as fh:
            for line in fh:
                if line.startswith("Uid:"):
                    return pwd.getpwuid(int(line.split()[1])).pw_name
    except Exception:
        pass
    return ""


def _ws_peer_map() -> dict:
    result = {}
    try:
        for line in Path("/run/ws-ssh.map").read_text(errors="ignore").splitlines()[-400:]:
            parts = line.split()
            if len(parts) >= 3:
                result[parts[1]] = parts[2]
    except Exception:
        pass
    return result


def collect_ssh_ips(usernames: set, minutes: int = 30) -> dict:
    result = {name: set() for name in usernames}
    if not usernames:
        return result
    ports = _ssh_listener_ports()
    ws_map = _ws_peer_map()
    try:
        p = subprocess.run(["ss", "-tnpH"], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, text=True, timeout=10)
        for line in p.stdout.splitlines():
            if "ESTAB" not in line and "SYN-RECV" not in line:
                continue
            if "sshd" not in line and "dropbear" not in line:
                continue
            f = line.split()
            if len(f) < 5:
                continue
            if f[3].rsplit(":", 1)[-1] not in ports:
                continue
            peer = _strip_hostport(f[4])
            peer_port = f[4].rsplit(":", 1)[-1]
            pm = re.search(r"pid=(\d+)", line)
            if not pm:
                continue
            user = _pid_user(int(pm.group(1)))
            if user not in result:
                continue
            if _local_ip(peer):
                peer = ws_map.get(peer_port, "")
            if peer:
                result[user].add(peer)
    except Exception:
        pass
    return result


def _credentials_rotate(data: dict) -> dict:
    global API_KEY, SECRET, LEGACY_TOKEN, OLD_API_KEY, OLD_SECRET, OLD_UNTIL
    new_key = str(data.get("api_key") or "").strip()
    new_secret = str(data.get("secret") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{8,80}", new_key) or len(new_secret) < 32:
        raise ValueError("api_key/secret tidak valid")
    conf = load_conf()
    OLD_API_KEY = API_KEY
    OLD_SECRET = SECRET
    OLD_UNTIL = time.time() + 60
    conf["api_key"] = new_key
    conf["secret"] = new_secret
    conf["token"] = new_secret
    save_conf(conf)
    API_KEY = new_key
    SECRET = new_secret
    LEGACY_TOKEN = new_secret
    logging.info("credentials rotated api_key=%s", new_key)
    return {"ok": True, "node": NODE, "api_key": new_key}


def _credentials_revoke() -> dict:
    global REVOKED
    conf = load_conf()
    conf["revoked"] = True
    save_conf(conf)
    REVOKED = True
    logging.warning("credentials revoked")
    return {"ok": True, "node": NODE, "revoked": True}


class Handler(BaseHTTPRequestHandler):
    server_version = "kyt-node/" + VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        logging.info("%s %s", self.client_address[0], fmt % args)

    def _send(self, code: int, data: dict) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Kyt-Node", NODE)
        self.end_headers()
        self.wfile.write(body)

    def _auth(self, body: bytes) -> bool:
        ip = self.client_address[0]
        if ALLOW_IPS and ip not in ALLOW_IPS:
            self._send(403, {"ok": False, "error": "IP tidak diizinkan", "code": "ip_denied"})
            return False
        if not _rate_ok(ip):
            self._send(429, {"ok": False, "error": "Terlalu banyak request", "code": "rate_limit"})
            return False
        if REVOKED:
            self._send(403, {"ok": False, "error": "Credential node dicabut.", "code": "revoked"})
            return False
        key = self.headers.get("X-Kyt-Api-Key", "")
        node = self.headers.get("X-Kyt-Node", "")
        if key:
            if key == API_KEY:
                secret = SECRET
            elif OLD_API_KEY and key == OLD_API_KEY and time.time() < OLD_UNTIL:
                secret = OLD_SECRET
            else:
                self._send(401, {"ok": False, "error": "API Key tidak valid", "code": "auth"})
                return False
        else:
            if node != NODE or not LEGACY_TOKEN:
                self._send(401, {"ok": False, "error": "Node tidak valid", "code": "auth"})
                return False
            secret = LEGACY_TOKEN
        ts = self.headers.get("X-Kyt-Timestamp", "")
        nonce = self.headers.get("X-Kyt-Nonce", "")
        sig = self.headers.get("X-Kyt-Signature", "")
        try:
            ts_i = int(ts)
        except Exception:
            ts_i = 0
        if abs(time.time() - ts_i) > CLOCK_SKEW or not (8 <= len(nonce) <= 64) or not sig:
            self._send(401, {"ok": False, "error": "Signature tidak valid", "code": "auth"})
            return False
        _clean_nonces()
        with _nonce_lock:
            if nonce in _nonces:
                self._send(401, {"ok": False, "error": "Nonce dipakai ulang", "code": "replay"})
                return False
        digest = hashlib.sha256(body).hexdigest()
        canonical = "\n".join([self.command, self.path, ts, nonce, digest])
        expect = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, sig):
            self._send(401, {"ok": False, "error": "Signature tidak valid", "code": "auth"})
            return False
        with _nonce_lock:
            _nonces[nonce] = time.time()
        return True

    def _body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            length = 0
        if length > MAX_BODY:
            raise ValueError("body terlalu besar")
        return self.rfile.read(length) if length > 0 else b""

    def _idem(self) -> str:
        key = self.headers.get("Idempotency-Key", "")[:128]
        return key if 8 <= len(key) <= 128 else ""

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/v1/ping":
            self._send(200, {"ok": True, "node": NODE, "version": VERSION, "revoked": REVOKED})
            return
        if not self._auth(b""):
            return
        try:
            if path == "/v1/health":
                self._send(200, {"ok": True, "node": NODE, "version": VERSION,
                                 "hostname": os.uname().nodename, "time": int(time.time()),
                                 "services": _services(), "accounts": _count_accounts(),
                                 "max_slots": MAX_SLOTS, "revoked": REVOKED,
                                 "location": _location()})
            elif path == "/v1/capacity":
                acc = _count_accounts()
                self._send(200, {"ok": True, "node": NODE, "accounts": acc,
                                 "total": sum(acc.values()), "max_slots": MAX_SLOTS})
            elif path == "/v1/capabilities":
                self._send(200, {"ok": True, "node": NODE, "version": VERSION,
                                 "features": ["create", "status", "delete", "renew", "suspend",
                                              "resume", "sessions", "mullog", "idempotency",
                                              "rotate", "revoke"],
                                 "scripts": {"ssh": os.path.exists(SSH_SCRIPT),
                                             **{k: os.path.exists(v) for k, v in XRAY_SCRIPTS.items()}},
                                 "mullog": os.path.exists(MULLOG_BIN),
                                 "services": _services(),
                                 "location": _location()})
            elif path == "/v1/location":
                query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                self._send(200, {"ok": True, "node": NODE,
                                 "location": _location(force=bool(query.get("force")))})
            elif path == "/v1/accounts":
                acc = _count_accounts()
                self._send(200, {"ok": True, "node": NODE, "accounts": acc,
                                 "total": sum(acc.values()), "max_slots": MAX_SLOTS})
            else:
                m = re.match(r"^/v1/accounts/(ssh|xray)/([a-z]*)/([a-z0-9]+)$", path)
                if not m:
                    self._send(404, {"ok": False, "error": "Endpoint tidak ada"})
                    return
                self._send(200, _status(m.group(1), m.group(2), m.group(3)))
        except ValueError as exc:
            self._send(400, {"ok": False, "error": str(exc)})
        except Exception:
            logging.exception("GET %s", path)
            self._send(500, {"ok": False, "error": "Internal error"})

    def do_POST(self):
        global REVOKED
        path = urllib.parse.urlparse(self.path).path
        try:
            body = self._body()
        except ValueError as exc:
            self._send(400, {"ok": False, "error": str(exc)})
            return
        if not self._auth(body):
            return
        idem = self._idem()
        try:
            data = json.loads(body.decode("utf-8") or "{}")
            if path == "/v1/accounts":
                cached = idem_get(idem)
                if cached is not None:
                    self._send(200, cached)
                    return
                result = _create(data)
                if result.get("ok"):
                    idem_put(idem, result)
                self._send(200 if result.get("ok") else 409, result)
            elif path == "/v1/credentials/rotate":
                self._send(200, _credentials_rotate(data))
            elif path == "/v1/credentials/revoke":
                self._send(200, _credentials_revoke())
            else:
                m = re.match(r"^/v1/accounts/(ssh|xray)/([a-z]*)/([a-z0-9]+)/(renew|suspend|resume)$", path)
                if not m:
                    self._send(404, {"ok": False, "error": "Endpoint tidak ada"})
                    return
                service, protocol, user, action = m.group(1), m.group(2), m.group(3), m.group(4)
                cached = idem_get(idem)
                if cached is not None:
                    self._send(200, cached)
                    return
                if action == "renew":
                    result = _renew(service, protocol, user, data)
                elif action == "suspend":
                    result = _mullog("hold", service, protocol, user)
                else:
                    result = _mullog("release", service, protocol, user)
                if result.get("ok"):
                    idem_put(idem, result)
                self._send(200 if result.get("ok") else 409, result)
        except ValueError as exc:
            self._send(400, {"ok": False, "error": str(exc)})
        except Exception:
            logging.exception("POST %s", path)
            self._send(500, {"ok": False, "error": "Internal error"})

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path
        if not self._auth(b""):
            return
        idem = self._idem()
        try:
            m = re.match(r"^/v1/accounts/(ssh|xray)/([a-z]*)/([a-z0-9]+)$", path)
            if not m:
                self._send(404, {"ok": False, "error": "Endpoint tidak ada"})
                return
            cached = idem_get(idem)
            if cached is not None:
                self._send(200, cached)
                return
            result = _delete(m.group(1), m.group(2), m.group(3))
            idem_put(idem, result)
            self._send(200, result)
        except ValueError as exc:
            self._send(400, {"ok": False, "error": str(exc)})
        except Exception:
            logging.exception("DELETE %s", path)
            self._send(500, {"ok": False, "error": "Internal error"})


def main() -> None:
    if not SECRET or len(SECRET) < 32:
        print("secret agent minimal 32 karakter", file=sys.stderr)
        sys.exit(1)
    init_idem()
    bind = str(CONF.get("bind") or "0.0.0.0")
    port = int(CONF.get("port") or 8787)
    httpd = ThreadingHTTPServer((bind, port), Handler)
    httpd.daemon_threads = True
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT, KEY)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    logging.info("kyt-node-agent %s node=%s bind=%s:%s api_key=%s",
                 VERSION, NODE, bind, port, API_KEY or "legacy")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
