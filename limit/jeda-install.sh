#!/bin/bash
# Install / update Timer Mullog (suspend sementara akun SSH & Xray).
# Aman dijalankan berulang. Repo utama bisa dioverride lewat argumen pertama.
set -u

REPO="${1:-https://raw.githubusercontent.com/victor3232/xhttp/main/}"
REPO="${REPO%/}/"
GH="https://raw.githubusercontent.com/victor3232/xhttp/main/"
STATE_DIR="/etc/kyt/jeda-mullog"
CONF="/etc/kyt/jeda-mullog.conf"

fetch() {
    local name="$1" out="$2" tmp
    tmp="${out}.tmp.$$"
    mkdir -p "$(dirname "$out")" 2>/dev/null
    rm -f "$tmp"
    if [ -d "$REPO" ] && [ -f "${REPO}limit/${name}" ]; then
        cp -f "${REPO}limit/${name}" "$tmp" 2>/dev/null || true
    fi
    if [ ! -s "$tmp" ]; then
        wget -q --timeout=30 -O "$tmp" "${REPO}limit/${name}" 2>/dev/null || true
    fi
    if [ ! -s "$tmp" ]; then
        wget -q --timeout=30 -O "$tmp" "${GH}limit/${name}" 2>/dev/null || true
    fi
    if [ -s "$tmp" ]; then
        mv -f "$tmp" "$out"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

mkdir -p "$STATE_DIR/state" "$STATE_DIR/restored"
chmod 700 "$STATE_DIR" "$STATE_DIR/state" "$STATE_DIR/restored" 2>/dev/null

fetch jeda-mullog /usr/local/sbin/jeda-mullog || {
    echo "Gagal mengunduh engine Timer Mullog" >&2
    exit 1
}
chmod 755 /usr/local/sbin/jeda-mullog

# setting-jeda biasanya sudah dari menu.zip; fallback unduh langsung.
if [ ! -s /usr/local/sbin/setting-jeda ]; then
    fetch setting-jeda /usr/local/sbin/setting-jeda || true
fi
[ -s /usr/local/sbin/setting-jeda ] && chmod 755 /usr/local/sbin/setting-jeda

fetch jeda-mullog.service /etc/systemd/system/jeda-mullog.service || {
    echo "Gagal mengunduh service Timer Mullog" >&2
    exit 1
}
chmod 644 /etc/systemd/system/jeda-mullog.service

# Pastikan limiter yang dipakai adalah versi suspend, bukan versi lama.
fetch ssh /etc/xray/limit.ssh || true
[ -s /etc/xray/limit.ssh ] && chmod 755 /etc/xray/limit.ssh
fetch limit-ip /usr/bin/limit-ip || true
[ -s /usr/bin/limit-ip ] && chmod 755 /usr/bin/limit-ip

if [ ! -s "$CONF" ]; then
    printf 'ENABLED=1\nMINUTES=20\nNOTIFY=1\n' > "$CONF"
else
    grep -qE '^ENABLED=' "$CONF" || echo 'ENABLED=1' >> "$CONF"
    grep -qE '^MINUTES=' "$CONF" || echo 'MINUTES=20' >> "$CONF"
    grep -qE '^NOTIFY=' "$CONF" || echo 'NOTIFY=1' >> "$CONF"
fi
chmod 644 "$CONF" 2>/dev/null

# Validasi sebelum service dijalankan.
python3 -m py_compile /usr/local/sbin/jeda-mullog || exit 1
bash -n /etc/xray/limit.ssh 2>/dev/null || true
bash -n /usr/bin/limit-ip 2>/dev/null || true

systemctl daemon-reload
systemctl enable jeda-mullog >/dev/null 2>&1
systemctl restart jeda-mullog >/dev/null 2>&1
# Muat ulang limiter agar patch suspend aktif.
systemctl restart limitssh >/dev/null 2>&1 || true
for svc in vmip vlip trip; do
    systemctl restart "$svc" >/dev/null 2>&1 || true
done

exit 0
