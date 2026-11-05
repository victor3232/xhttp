#!/usr/bin/env python3
"""Pasang edge nginx + HAProxy untuk website VPNFree. Idempotent."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

if len(sys.argv) < 2:
    raise SystemExit("usage: configure_edge.py DOMAIN")
DOMAIN = sys.argv[1].strip().lower().rstrip(".")
if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,250}[a-z0-9])?", DOMAIN) or "." not in DOMAIN:
    raise SystemExit(f"domain tidak valid: {DOMAIN}")

ROOT = Path(__file__).resolve().parent
CERT_DIR = Path("/etc/ssl/kyt-web")
CERT = CERT_DIR / "vpnfree.crt"
KEY = CERT_DIR / "vpnfree.key"
HAPROXY_PEM = Path("/etc/haproxy/vpnfree.pem")
NGINX_CONF = Path("/etc/nginx/conf.d/vpnfree.conf")
NGINX_MAIN = Path("/etc/nginx/nginx.conf")
HAPROXY_CFG = Path("/etc/haproxy/haproxy.cfg")

stamp = time.strftime("%Y%m%d-%H%M%S")

# ---------- sertifikat awal (self-signed) ----------
CERT_DIR.mkdir(parents=True, exist_ok=True)
if not CERT.exists() or not KEY.exists():
    subprocess.run(
        [
            "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "3650",
            "-subj", f"/CN={DOMAIN}",
            "-addext", f"subjectAltName=DNS:{DOMAIN}",
            "-keyout", str(KEY), "-out", str(CERT),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    os.chmod(KEY, 0o600)
    os.chmod(CERT, 0o644)
HAPROXY_PEM.write_bytes(CERT.read_bytes() + b"\n" + KEY.read_bytes())
os.chmod(HAPROXY_PEM, 0o600)

# ---------- nginx server ----------
template_path = ROOT / "vpnfree.conf.tpl"
if not template_path.exists():
    template_path = Path("/usr/local/sbin/vpnfree.conf.tpl")
if template_path.exists():
    template = template_path.read_text()
else:
    if not NGINX_CONF.exists():
        raise SystemExit("template vpnfree.conf.tpl tidak ditemukan")
    template = NGINX_CONF.read_text()
    template = re.sub(r"(?m)^(\s*server_name\s+).*$", r"\1__DOMAIN__;", template)
NGINX_CONF.write_text(template.replace("__DOMAIN__", DOMAIN))
if NGINX_MAIN.exists():
    shutil.copy2(NGINX_MAIN, f"/root/nginx.conf.backup-kytweb-{stamp}")
    text = NGINX_MAIN.read_text()
    if "conf.d/vpnfree.conf" not in text and "conf.d/*.conf" not in text:
        include = "    include /etc/nginx/conf.d/xray.conf;\n"
        if include in text:
            text = text.replace(include, include + "    include /etc/nginx/conf.d/vpnfree.conf;\n", 1)
        else:
            # fallback: sisipkan sebelum penutup blok http
            text = text.replace("\n}\n", "\n    include /etc/nginx/conf.d/vpnfree.conf;\n}\n", 1)
        NGINX_MAIN.write_text(text)

# ---------- HAProxy ----------
if not HAPROXY_CFG.exists():
    raise SystemExit("haproxy.cfg tidak ditemukan")
shutil.copy2(HAPROXY_CFG, f"/root/haproxy-backup-kytweb-{stamp}.cfg")
text = HAPROXY_CFG.read_text()

# Tambahkan cert domain ke bind TLS.
if "crt /etc/haproxy/vpnfree.pem" not in text:
    m = re.search(r"(^.*bind abns@haproxy-https[^\n]*crt /etc/haproxy/hap\.pem)([^\n]*)$", text, re.M)
    if not m:
        raise SystemExit("bind TLS HAProxy tidak ditemukan")
    text = text[: m.start()] + m.group(1) + " crt /etc/haproxy/vpnfree.pem" + m.group(2) + text[m.end():]

# ACL: update domain kalau sudah ada, atau sisipkan baru.
if "acl is_vpnfree_http" in text:
    text = re.sub(r"(?m)^\s*acl is_vpnfree_http .*$\n?", f"    acl is_vpnfree_http req.hdr(host) -i {DOMAIN}\n", text)
    text = re.sub(r"(?m)^\s*acl is_vpnfree_ssl .*$\n?", "", text)
    text = re.sub(r"(?m)^\s*acl is_tls ssl_fc\s*$\n?", "", text)
    anchor = f"    acl is_vpnfree_http req.hdr(host) -i {DOMAIN}\n"
    block = (
        anchor
        + f"    acl is_vpnfree_ssl ssl_fc_sni -i {DOMAIN}\n"
        + f"    acl is_vpnfree_ssl req.ssl_sni -i {DOMAIN}\n"
        + "    acl is_tls ssl_fc\n"
    )
    text = text.replace(anchor, block, 1)
else:
    anchor = "    acl up-to ssl_fc_alpn -i h2\n"
    if anchor not in text:
        raise SystemExit("ACL up-to HAProxy tidak ditemukan")
    block = (
        anchor
        + f"    acl is_vpnfree_http req.hdr(host) -i {DOMAIN}\n"
        + f"    acl is_vpnfree_ssl ssl_fc_sni -i {DOMAIN}\n"
        + f"    acl is_vpnfree_ssl req.ssl_sni -i {DOMAIN}\n"
        + "    acl is_tls ssl_fc\n"
    )
    text = text.replace(anchor, block, 1)

# use_backend
if "use_backend VPNFREE_HTTP" not in text:
    anchor = "    use_backend GRUP_FTVPN if up-to\n"
    if anchor not in text:
        raise SystemExit("use_backend HAProxy tidak ditemukan")
    text = text.replace(
        anchor,
        "    use_backend VPNFREE_HTTP if is_vpnfree_http !is_tls\n"
        "    use_backend VPNFREE_SSL if is_vpnfree_ssl\n\n"
        + anchor,
        1,
    )
else:
    text = re.sub(r"(?m)^    use_backend VPNFREE_HTTP .*$", "    use_backend VPNFREE_HTTP if is_vpnfree_http !is_tls", text)
    text = re.sub(r"(?m)^    use_backend VPNFREE_SSL .*$", "    use_backend VPNFREE_SSL if is_vpnfree_ssl", text)

# backend
if "backend VPNFREE_HTTP" not in text:
    anchor = "\nbackend recir_https_www\n"
    if anchor not in text:
        raise SystemExit("backend recir_https_www tidak ditemukan")
    block = (
        "# VPNFree website (nginx lokal)\n"
        "backend VPNFREE_HTTP\n"
        "    mode tcp\n"
        "    server vpnfree-http 127.0.0.1:8088 send-proxy-v2\n\n"
        "backend VPNFREE_SSL\n"
        "    mode tcp\n"
        "    server vpnfree-ssl 127.0.0.1:8444 send-proxy-v2\n"
        + anchor
    )
    text = text.replace(anchor, block, 1)
else:
    text = re.sub(r"(?m)^    server vpnfree-http .*$", "    server vpnfree-http 127.0.0.1:8088 send-proxy-v2", text)
    text = re.sub(r"(?m)^    server vpnfree-ssl .*$", "    server vpnfree-ssl 127.0.0.1:8444 send-proxy-v2", text)

HAPROXY_CFG.write_text(text)

# ---------- validasi & reload ----------
if subprocess.run(["nginx", "-t"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
    raise SystemExit("nginx -t gagal; konfigurasi tidak di-reload")
if subprocess.run(["/usr/sbin/haproxy", "-c", "-f", str(HAPROXY_CFG)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
    raise SystemExit("haproxy -c gagal; konfigurasi tidak di-reload")

subprocess.run(["systemctl", "reload", "nginx"], check=False)
subprocess.run(["systemctl", "reload", "haproxy"], check=False)
print(f"edge siap untuk {DOMAIN}")
