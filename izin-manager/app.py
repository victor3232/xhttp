#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IZIN MANAGER - add/del/check IP lisensi HITS SSH.

Bisa jalan lokal (file izin) atau di Railway (GitHub Contents API).
"""

from __future__ import annotations

import hmac
import os
import secrets
import sys
import time
from collections import defaultdict
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from izin_store import (
    StoreError,
    add_or_update,
    check_ip,
    delete_ip,
    make_store,
    parse_entries,
    summary,
    today_jkt,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

ADMIN_PASSWORD = (os.environ.get("ADMIN_PASSWORD") or "").strip()
API_KEY = (os.environ.get("API_KEY") or "").strip()
try:
    CACHE_TTL = int(os.environ.get("CACHE_TTL", "15") or "15")
except ValueError:
    CACHE_TTL = 15

if not ADMIN_PASSWORD:
    ADMIN_PASSWORD = "admin"
    print("PERINGATAN: ADMIN_PASSWORD belum diset. Memakai 'admin'.", file=sys.stderr)

_CACHE = {"ts": 0.0, "text": "", "error": ""}
_LOGIN_FAILS: dict[str, list[float]] = defaultdict(list)


def get_store():
    return make_store()


def load_text(force: bool = False) -> str:
    now = time.time()
    if not force and _CACHE["ts"] and now - _CACHE["ts"] < CACHE_TTL:
        if _CACHE["error"]:
            raise StoreError(_CACHE["error"])
        return _CACHE["text"]
    try:
        text, _sha = get_store().read()
        _CACHE.update({"ts": now, "text": text, "error": ""})
        return text
    except Exception as exc:
        _CACHE.update({"ts": now, "text": "", "error": str(exc)})
        raise


def invalidate_cache() -> None:
    _CACHE["ts"] = 0.0


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)

    return wrapper


def csrf_token() -> str:
    token = session.get("csrf")
    if not token:
        token = secrets.token_hex(24)
        session["csrf"] = token
    return token


def check_csrf() -> None:
    sent = (request.form.get("csrf") or "").strip()
    expected = session.get("csrf") or ""
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, "CSRF token tidak valid. Muat ulang halaman.")


def api_ok() -> bool:
    if session.get("admin"):
        return True
    if API_KEY:
        supplied = (request.headers.get("X-API-Key") or request.args.get("key") or "").strip()
        return bool(supplied) and hmac.compare_digest(supplied, API_KEY)
    return False


def rate_ok(ip: str) -> bool:
    now = time.time()
    bucket = _LOGIN_FAILS[ip]
    _LOGIN_FAILS[ip] = [ts for ts in bucket if now - ts < 900]
    return len(_LOGIN_FAILS[ip]) < 8


def rate_fail(ip: str) -> None:
    _LOGIN_FAILS[ip].append(time.time())


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True, "time": int(time.time())})


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        ip = request.headers.get("CF-Connecting-IP") or request.remote_addr or "-"
        if not rate_ok(ip):
            error = "Terlalu banyak percobaan. Tunggu 15 menit."
        else:
            supplied = (request.form.get("password") or "").strip()
            if hmac.compare_digest(supplied, ADMIN_PASSWORD):
                session.clear()
                session["admin"] = True
                session["csrf"] = secrets.token_hex(24)
                target = request.args.get("next") or url_for("index")
                if not target.startswith("/"):
                    target = url_for("index")
                return redirect(target)
            rate_fail(ip)
            error = "Password salah."
    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    q = (request.args.get("q") or "").strip().lower()
    error = ""
    entries = []
    try:
        text = load_text()
        entries = parse_entries(text)
    except Exception as exc:
        error = str(exc)
    if q:
        entries = [
            e for e in entries
            if q in e.name.lower() or q in e.ip.lower() or q in e.expiry.lower()
        ]
    stats = summary(parse_entries(load_text())) if not error else summary([])
    return render_template(
        "index.html",
        entries=entries,
        stats=stats,
        q=request.args.get("q", ""),
        error=error,
        csrf=csrf_token(),
        repo=os.environ.get("GITHUB_REPO", "victor3232/xhttp"),
        branch=os.environ.get("GITHUB_BRANCH", "main"),
        path=os.environ.get("GITHUB_PATH", "izin"),
        local_mode=not bool(os.environ.get("GITHUB_TOKEN")),
        today=today_jkt().isoformat(),
    )


@app.route("/add", methods=["POST"])
@login_required
def add():
    check_csrf()
    name = request.form.get("name", "")
    expiry = request.form.get("expiry", "")
    ip = request.form.get("ip", "")
    try:
        text, info = get_store().update(
            lambda current: add_or_update(current, name, expiry, ip),
            "izin: set %s (%s)" % (ip, name),
        )
        invalidate_cache()
        _CACHE.update({"ts": time.time(), "text": text, "error": ""})
        flash("%s: %s" % ("Diperbarui" if info["action"] == "updated" else "Ditambahkan", ip), "ok")
    except Exception as exc:
        flash(str(exc), "error")
    return redirect(url_for("index"))


@app.route("/delete", methods=["POST"])
@login_required
def delete():
    check_csrf()
    ip = request.form.get("ip", "")
    try:
        text, info = get_store().update(
            lambda current: delete_ip(current, ip),
            "izin: delete %s" % ip,
        )
        invalidate_cache()
        _CACHE.update({"ts": time.time(), "text": text, "error": ""})
        flash("Dihapus: %s (%s baris)" % (ip, info.get("count", 1)), "ok")
    except Exception as exc:
        flash(str(exc), "error")
    return redirect(url_for("index"))


@app.route("/api/check")
def api_check():
    if not api_ok():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    ip = (request.args.get("ip") or "").strip()
    try:
        data = check_ip(load_text(), ip)
        return jsonify(data)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.route("/api/entries")
def api_entries():
    if not api_ok():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    try:
        entries = parse_entries(load_text())
        return jsonify({
            "ok": True,
            "summary": summary(entries),
            "entries": [entry.__dict__ for entry in entries],
        })
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/add", methods=["POST"])
def api_add():
    if not api_ok():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or "")
    expiry = str(data.get("expiry") or "")
    ip = str(data.get("ip") or "")
    try:
        text, info = get_store().update(
            lambda current: add_or_update(current, name, expiry, ip),
            "izin: add %s (%s)" % (ip, name),
        )
        invalidate_cache()
        _CACHE.update({"ts": time.time(), "text": text, "error": ""})
        return jsonify({"ok": True, **info})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.route("/api/delete", methods=["POST"])
def api_delete():
    if not api_ok():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip") or "")
    try:
        text, info = get_store().update(
            lambda current: delete_ip(current, ip),
            "izin: delete %s" % ip,
        )
        invalidate_cache()
        _CACHE.update({"ts": time.time(), "text": text, "error": ""})
        return jsonify({"ok": True, **info})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


if __name__ == "__main__":
    port = int(os.environ.get("PORT") or "8080")
    app.run(host="0.0.0.0", port=port, debug=False)
