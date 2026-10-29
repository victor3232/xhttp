#!/bin/bash
# ============================================================
#  fix-realip.sh  -  IP ASLI untuk SSH WS + Xray
#  - Proxy WS Python baru di 127.0.0.1:10019 (Go ws-epro :10015 tetap)
#  - nginx mengirim X-Real-IP / X-Forwarded-For = IP asli client
#  - Xray trust header X-Real-IP (XFF index 0)
#  - Log tidak lagi dihapus tiap 1/20 menit (history cek login)
#  Aman: backup + rollback otomatis kalau config gagal
# ============================================================
RED=$'\033[38;2;251;113;133m'
GRN=$'\033[38;2;52;211;153m'
YEL=$'\033[38;2;251;191;36m'
CYN=$'\033[38;2;34;211;238m'
VIO=$'\033[38;2;139;92;246m'
NC=$'\033[0m'
BLD=$'\033[1m'

ok()   { echo -e " ${GRN}✔${NC} $*"; }
warn() { echo -e " ${YEL}!${NC} $*"; }
bad()  { echo -e " ${RED}✘${NC} $*"; }
line() { printf ' %s' "$VIO"; printf '━%.0s' $(seq 1 58); printf '%s\n' "$NC"; }

[ "$(id -u)" = "0" ] || { bad "Jalankan sebagai root!"; exit 1; }

REPO="${REPO:-https://raw.githubusercontent.com/victor3232/xhttp/main/}"
case "$REPO" in */) ;; *) REPO="$REPO/" ;; esac
DIR="$(cd "$(dirname "$0")" && pwd)"
TS="$(date +%Y%m%d%H%M%S)"
BK="/root/realip-backup-$TS"
NGINX_CONF="/etc/nginx/conf.d/xray.conf"
XRAY_CONF="/etc/xray/config.json"
SERVICE="/etc/systemd/system/ws-ssh.service"
WSPY="/usr/bin/ws-ssh.py"

mkdir -p "$BK" || exit 1

fetch() {
    local url="$1" out="$2"
    case "$url" in
        *\?*) ;;
        *) url="${url}?v=${TS}" ;;
    esac
    curl -fsSL --connect-timeout 8 --max-time 60 --retry 2 \
        -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' \
        "$url" -o "$out"
}

clear
echo ""
line
echo -e " ${BLD}${CYN}     FIX REAL IP - SSH WS + XRAY (VMESS/VLESS/TR/SS)${NC}"
line
echo ""

# ------------------------------------------------------------
# 0. PREFLIGHT + BACKUP
# ------------------------------------------------------------
echo -e " ${BLD}${VIO}[0/5]${NC} ${BLD}Cek sistem + backup${NC}"
[ -f "$NGINX_CONF" ] || { bad "$NGINX_CONF tidak ditemukan."; bad "Script ini untuk VPS yang sudah terpasang xhttp/premi.sh."; exit 1; }
command -v nginx >/dev/null 2>&1 || { bad "nginx tidak terpasang."; exit 1; }
command -v python3 >/dev/null 2>&1 || { bad "python3 tidak terpasang."; exit 1; }
PYBIN="$(command -v python3)"

for f in "$NGINX_CONF" "$XRAY_CONF" "$WSPY" "$SERVICE" \
         /etc/cron.d/log.xray /etc/cron.d/log.nginx /etc/cron.d/logclean; do
    [ -f "$f" ] && cp -a "$f" "$BK/" 2>/dev/null
done
ok "Backup → $BK"

# ------------------------------------------------------------
# 1. INSTALL PROXY WS PYTHON (port 10019)
# ------------------------------------------------------------
echo ""
echo -e " ${BLD}${VIO}[1/5]${NC} ${BLD}Install WS proxy real-IP (port 10019)${NC}"
WS_SRC=""
for cand in "$DIR/limit/ws.py" "$DIR/ws.py" "$WSPY"; do
    [ -s "$cand" ] && { WS_SRC="$cand"; break; }
done
if [ -z "$WS_SRC" ]; then
    TMPWS="$(mktemp)"
    if fetch "${REPO}limit/ws.py" "$TMPWS"; then
        WS_SRC="$TMPWS"
    else
        bad "Gagal download limit/ws.py dari repo."
        exit 1
    fi
fi

"$PYBIN" - "$WS_SRC" <<'PY' || { bad "ws.py tidak valid"; exit 1; }
import sys
compile(open(sys.argv[1], encoding='utf-8').read(), sys.argv[1], 'exec')
PY

install -m 755 "$WS_SRC" "$WSPY" || { bad "Gagal install $WSPY"; exit 1; }
ok "ws.py → $WSPY"

# Port SSH yang dipakai di VPS (biasanya 2222 dari premi.sh)
SSH_TARGET_PORT=2222
if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE '[:.]2222$'; then
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE '[:.]22$'; then
        SSH_TARGET_PORT=22
    fi
fi

cat > "$SERVICE" <<EOF
[Unit]
Description=WS SSH Proxy (real client IP, port 10019)
After=network.target

[Service]
Type=simple
Environment=WS_TARGET=127.0.0.1:${SSH_TARGET_PORT}
Environment=WS_SSH_MAP=/run/ws-ssh.map
Environment=WS_PORT=10019
Environment=PYTHONUNBUFFERED=1
ExecStart=${PYBIN} -O ${WSPY}
Restart=always
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl stop ws-ssh 2>/dev/null || true
sleep 0.3
if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE '[:.]10019$'; then
    bad "Port 10019 masih dipakai proses lain:"
    ss -ltnp 2>/dev/null | grep ':10019' || true
    exit 1
fi

systemctl enable ws-ssh >/dev/null 2>&1
systemctl restart ws-ssh || { bad "ws-ssh gagal start"; journalctl -u ws-ssh -n 20 --no-pager 2>/dev/null; exit 1; }
sleep 1
if ! systemctl is-active --quiet ws-ssh; then
    bad "ws-ssh tidak aktif"; journalctl -u ws-ssh -n 30 --no-pager 2>/dev/null; exit 1
fi
if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE '[:.]10019$'; then
    bad "ws-ssh aktif tapi tidak listen di 10019"; exit 1
fi
ok "ws-ssh aktif di 127.0.0.1:10019 → SSH 127.0.0.1:${SSH_TARGET_PORT}"

# ------------------------------------------------------------
# 2. PATCH NGINX
# ------------------------------------------------------------
echo ""
echo -e " ${BLD}${VIO}[2/5]${NC} ${BLD}Patch nginx (IP asli + SSH → 10019)${NC}"
TMP_NG="$(mktemp)"
"$PYBIN" - "$NGINX_CONF" "$TMP_NG" <<'PY' || { bad "Patch nginx gagal"; rm -f "$TMP_NG"; exit 1; }
import re
import sys

src, dst = sys.argv[1], sys.argv[2]
lines = open(src, encoding='utf-8').read().splitlines(True)
out = []
added = 0
for i, line in enumerate(lines):
    out.append(line)
    if re.match(r'^\s*listen\s+.*\bproxy_protocol\b', line):
        window = ''.join(lines[i + 1:i + 6])
        indent = re.match(r'^[ \t]*', line).group(0)
        if 'set_real_ip_from' not in window:
            out.append('%sset_real_ip_from 127.0.0.1;\n' % indent)
            added += 1
        if 'real_ip_header' not in window:
            out.append('%sreal_ip_header proxy_protocol;\n' % indent)
            added += 1

text = ''.join(out)

# Support Cloudflare: prefer CF-Connecting-IP, fallback $remote_addr
cf_map = ('map $http_cf_connecting_ip $real_client_ip {\n'
          '    ""      $remote_addr;\n'
          '    default $http_cf_connecting_ip;\n'
          '}\n')
if 'real_client_ip' not in text:
    text = cf_map + text

repl = [
    ('proxy_set_header X-Real-IP $http_x_forwarded_for;',
     'proxy_set_header X-Real-IP $real_client_ip;'),
    ('proxy_set_header X-Forwarded-For $http_x_forwarded_for;',
     'proxy_set_header X-Forwarded-For $real_client_ip;'),
    ('grpc_set_header X-Real-IP $http_x_forwarded_for;',
     'grpc_set_header X-Real-IP $real_client_ip;'),
    ('grpc_set_header X-Forwarded-For $http_x_forwarded_for;',
     'grpc_set_header X-Forwarded-For $real_client_ip;'),
    ('proxy_set_header X-Real-IP $remote_addr;',
     'proxy_set_header X-Real-IP $real_client_ip;'),
    ('proxy_set_header X-Forwarded-For $remote_addr;',
     'proxy_set_header X-Forwarded-For $real_client_ip;'),
    ('grpc_set_header X-Real-IP $remote_addr;',
     'grpc_set_header X-Real-IP $real_client_ip;'),
    ('grpc_set_header X-Forwarded-For $remote_addr;',
     'grpc_set_header X-Forwarded-For $real_client_ip;'),
    ('proxy_pass http://127.0.0.1:10015;',
     'proxy_pass http://127.0.0.1:10019;'),
]
for old, new in repl:
    text = text.replace(old, new)

open(dst, 'w', encoding='utf-8').write(text)
print('cf_map=%d real_headers=%d ssh_10019=%d' % (
    1 if 'real_client_ip' in text else 0,
    text.count('$real_client_ip;'),
    text.count('proxy_pass http://127.0.0.1:10019;')))
PY

if ! grep -q 'real_client_ip' "$TMP_NG" || \
   ! grep -q 'proxy_pass http://127.0.0.1:10019;' "$TMP_NG"; then
    bad "Hasil patch nginx tidak sesuai harapan"; rm -f "$TMP_NG"; exit 1
fi

cat "$TMP_NG" > "$NGINX_CONF"
rm -f "$TMP_NG"
if ! _ngtest="$(nginx -t 2>&1)"; then
    echo "$_ngtest" | sed 's/^/    /'
    cp -a "$BK/xray.conf" "$NGINX_CONF"
    bad "nginx -t gagal → config dikembalikan"
    exit 1
fi
systemctl reload nginx 2>/dev/null || systemctl restart nginx
sleep 1
systemctl is-active --quiet nginx || { cp -a "$BK/xray.conf" "$NGINX_CONF"; systemctl restart nginx; bad "nginx gagal reload → rollback"; exit 1; }
ok "nginx: X-Real-IP/X-Forwarded-For = IP asli, SSH WS → 10019"

# ------------------------------------------------------------
# 3. PATCH XRAY (trustedXForwardedFor)
# ------------------------------------------------------------
echo ""
echo -e " ${BLD}${VIO}[3/5]${NC} ${BLD}Patch Xray (trustedXForwardedFor)${NC}"
if [ -f "$XRAY_CONF" ]; then
    TMP_XR="$(mktemp)"
    _patch_out="$("$PYBIN" - "$XRAY_CONF" "$TMP_XR" <<'PY'
import json
import re
import sys


def matching(text, start):
    depth = 0
    i = start
    in_str = False
    esc = False
    while i < len(text):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == '\\':
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    raise ValueError('unbalanced braces')


src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding='utf-8').read()
m = re.search(r'"inbounds"\s*:\s*\[', text)
if not m:
    raise SystemExit('config: "inbounds" not found')
arr = text.index('[', m.start())

objects = []
i = arr + 1
while i < len(text):
    c = text[i]
    if c == '{':
        j = matching(text, i)
        objects.append((i, j))
        i = j + 1
    elif c == ']':
        break
    else:
        i += 1

inserts = []
patched = skipped = 0
for start, end in objects:
    obj = text[start:end + 1]
    if not re.search(r'"listen"\s*:\s*"127\.0\.0\.1"', obj):
        continue
    sm = re.search(r'"streamSettings"\s*:\s*\{', obj)
    if not sm:
        continue
    sm_end = matching(obj, sm.end() - 1)
    network = re.search(r'"network"\s*:\s*"([^"]+)"', obj[sm.start():sm_end + 1])
    net = network.group(1).lower() if network else ''
    if net not in ('ws', 'grpc', 'httpupgrade', 'xhttp'):
        continue
    if 'trustedXForwardedFor' in obj or re.search(r'"sockopt"\s*:', obj):
        skipped += 1
        continue

    brace = start + sm.end() - 1
    line_start = text.rfind('\n', 0, start + sm.start()) + 1
    indent = re.match(r'[ \t]*', text[line_start:]).group(0) + '  '
    inserts.append((brace + 1,
                    '\n%s"sockopt": { "trustedXForwardedFor": ["X-Real-IP"] },'
                    % indent))
    patched += 1

for pos, chunk in sorted(inserts, reverse=True):
    text = text[:pos] + chunk + text[pos:]

# Marker akun (### user, #& user, dst) bukan JSON; buang baris komentar.
stripped = '\n'.join(
    line for line in text.splitlines()
    if not line.lstrip().startswith('#')
)
json.loads(stripped)

# loglevel harus "info" supaya email muncul di access.log
text = text.replace('"loglevel": "warning"', '"loglevel": "info"')

open(dst, 'w', encoding='utf-8').write(text)
print('patched=%d skipped=%d' % (patched, skipped))
PY
)" || { bad "Patch config Xray gagal"; rm -f "$TMP_XR"; exit 1; }
    echo "    $_patch_out"
    cp "$TMP_XR" "$XRAY_CONF"
    rm -f "$TMP_XR"

    XRAY_BIN="$(command -v xray 2>/dev/null || true)"
    [ -z "$XRAY_BIN" ] && [ -x /usr/local/bin/xray ] && XRAY_BIN=/usr/local/bin/xray
    _xray_ok=1
    if [ -n "$XRAY_BIN" ]; then
        _xtest="$("$XRAY_BIN" -test -config "$XRAY_CONF" 2>&1)"
        if [ $? -ne 0 ]; then
            if echo "$_xtest" | grep -qiE 'geoip|geosite|\.dat'; then
                warn "xray -test gagal karena file geo (bukan config) — lanjut"
            else
                echo "$_xtest" | tail -8 | sed 's/^/    /'
                _xray_ok=0
            fi
        fi
    else
        warn "binary xray tidak ditemukan, lewati xray -test"
    fi

    if [ "$_xray_ok" = "1" ]; then
        systemctl restart xray 2>/dev/null || true
        sleep 2
        if systemctl is-active --quiet xray; then
            _n=$(grep -c 'trustedXForwardedFor' "$XRAY_CONF" 2>/dev/null || echo 0)
            ok "Xray aktif, $_n inbound trust X-Real-IP (XFF)"
        else
            cp -a "$BK/config.json" "$XRAY_CONF"
            systemctl restart xray 2>/dev/null || true
            bad "Xray gagal start → config dikembalikan"
            journalctl -u xray -n 20 --no-pager 2>/dev/null | sed 's/^/    /'
            exit 1
        fi
    else
        cp -a "$BK/config.json" "$XRAY_CONF"
        bad "Config Xray tidak valid → dikembalikan (Xray tidak di-restart)"
        exit 1
    fi
else
    warn "$XRAY_CONF tidak ada — lewati patch Xray"
fi

# ------------------------------------------------------------
# 4. LOG RETENTION (biar cek login punya history)
# ------------------------------------------------------------
echo ""
echo -e " ${BLD}${VIO}[4/5]${NC} ${BLD}Log retention${NC}"
for f in /etc/cron.d/log.xray /etc/cron.d/log.nginx /etc/cron.d/logclean; do
    [ -f "$f" ] || continue
    sed -i -E 's/^([[:space:]]*[^#[:space:]])/# \1/' "$f"
done
cat > /etc/logrotate.d/xray-access <<'EOF'
/var/log/xray/access.log /var/log/xray/error.log {
    daily
    rotate 7
    missingok
    notifempty
    copytruncate
    compress
    delaycompress
}
EOF
ok "Cron truncate 1/20 menit dimatikan (backup di $BK)"
ok "Rotate harian 7x untuk log Xray"

# ------------------------------------------------------------
# 5. VERIFIKASI
# ------------------------------------------------------------
echo ""
echo -e " ${BLD}${VIO}[5/5]${NC} ${BLD}Verifikasi${NC}"
_ws="$(systemctl is-active ws-ssh 2>/dev/null)"
[ "$_ws" = "active" ] && ok "ws-ssh: active" || warn "ws-ssh: $_ws"
ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE '[:.]10019$' && ok "Listen 10019: OK" || warn "Port 10019 tidak listen"
_n=$(grep -c 'X-Real-IP $real_client_ip;' "$NGINX_CONF" 2>/dev/null || echo 0)
[ "$_n" -gt 0 ] && ok "nginx X-Real-IP header: $_n lokasi" || warn "nginx header belum terpasang"
_n=$(grep -c 'proxy_pass http://127.0.0.1:10019;' "$NGINX_CONF" 2>/dev/null || echo 0)
[ "$_n" -eq 1 ] && ok "nginx SSH WS upstream: 10019" || warn "SSH WS upstream: $_n"
_n=$(grep -c 'trustedXForwardedFor' "$XRAY_CONF" 2>/dev/null || echo 0)
[ "$_n" -gt 0 ] && ok "Xray trust header: $_n inbound" || warn "Xray trust header: 0"

# Rollback helper
cat > "$BK/ROLLBACK.sh" <<EOF
#!/bin/bash
set -e
[ -f "$BK/xray.conf" ] && cp -a "$BK/xray.conf" "$NGINX_CONF"
[ -f "$BK/config.json" ] && cp -a "$BK/config.json" "$XRAY_CONF"
systemctl restart ws-ssh 2>/dev/null || true
systemctl restart nginx 2>/dev/null || true
systemctl restart xray 2>/dev/null || true
echo "Rollback selesai. Log cron dikembalikan manual dari $BK bila perlu."
EOF
chmod +x "$BK/ROLLBACK.sh"

echo ""
line
echo -e " ${BLD}${GRN}     FIX REAL IP SELESAI${NC}"
line
echo ""
echo -e " ${CYN}Langkah test:${NC}"
echo -e "   ${GRN}1.${NC} Reconnect SSH WS (APK) — IP asli akan tercatat"
echo -e "   ${GRN}2.${NC} Reconnect VMESS/VLESS/Trojan/SS"
echo -e "   ${GRN}3.${NC} Jalankan: ${BLD}cekssh${NC} lalu ${BLD}cekws${NC}"
echo ""
echo -e " ${YEL}Catatan:${NC} log lama yang sudah terhapus cron tidak bisa kembali."
echo -e " History baru mulai terkumpul setelah fix ini."
echo ""
echo -e " ${CYN}Rollback kalau ada masalah:${NC}"
echo -e "   ${BLD}bash $BK/ROLLBACK.sh${NC}"
echo ""
