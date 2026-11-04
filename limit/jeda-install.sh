#!/bin/bash
# Install / update Timer Mullog (suspend sementara akun SSH & Xray).
# Aman dijalankan berulang. Repo utama bisa dioverride lewat argumen pertama.
set -u

REPO="${1:-https://raw.githubusercontent.com/victor3232/xhttp/main/}"
REPO="${REPO%/}/"
GH="https://raw.githubusercontent.com/victor3232/xhttp/main/"
VER="20261104"
STATE_DIR="/etc/kyt/jeda-mullog"
CONF="/etc/kyt/jeda-mullog.conf"

fetch() {
    local name="$1" out="$2" verify="${3:-}" tmp attempt q
    tmp="${out}.tmp.$$"
    mkdir -p "$(dirname "$out")" 2>/dev/null
    for attempt in 1 2 3; do
        rm -f "$tmp"
        q="?v=${VER}"
        [ "$attempt" -gt 1 ] && q="?v=${VER}-${attempt}-$(date +%s)"
        if [ -d "$REPO" ] && [ -f "${REPO}limit/${name}" ]; then
            cp -f "${REPO}limit/${name}" "$tmp" 2>/dev/null || true
        fi
        if [ ! -s "$tmp" ]; then
            wget -q --timeout=30 -O "$tmp" "${REPO}limit/${name}${q}" 2>/dev/null || true
        fi
        if [ ! -s "$tmp" ]; then
            wget -q --timeout=30 -O "$tmp" "${GH}limit/${name}${q}" 2>/dev/null || true
        fi
        if [ -s "$tmp" ] && { [ -z "$verify" ] || grep -q -- "$verify" "$tmp"; }; then
            mv -f "$tmp" "$out"
            return 0
        fi
        sleep 2
    done
    rm -f "$tmp"
    return 1
}

mkdir -p "$STATE_DIR/state" "$STATE_DIR/restored"
chmod 700 "$STATE_DIR" "$STATE_DIR/state" "$STATE_DIR/restored" 2>/dev/null

fetch jeda-mullog /usr/local/sbin/jeda-mullog "def suspend_ssh" || {
    echo "Gagal mengunduh engine Timer Mullog" >&2
    exit 1
}
chmod 755 /usr/local/sbin/jeda-mullog

# Menu dan script pendukung; verify mencegah cache lama dari Worker.
fetch setting-jeda /usr/local/sbin/setting-jeda "TIMER MULLOG" || true
[ -s /usr/local/sbin/setting-jeda ] && chmod 755 /usr/local/sbin/setting-jeda
fetch utility /usr/local/sbin/utility "TIMER MULLOG" || echo "Peringatan: menu utility lama masih dipakai" >&2
[ -s /usr/local/sbin/utility ] && chmod 755 /usr/local/sbin/utility
fetch backup /usr/local/sbin/backup "jeda-mullog" || echo "Peringatan: backup lama masih dipakai" >&2
[ -s /usr/local/sbin/backup ] && chmod 755 /usr/local/sbin/backup
fetch restore /usr/local/sbin/restore "jeda-mullog" || echo "Peringatan: restore lama masih dipakai" >&2
[ -s /usr/local/sbin/restore ] && chmod 755 /usr/local/sbin/restore

fetch jeda-mullog.service /etc/systemd/system/jeda-mullog.service "ExecStart=/usr/local/sbin/jeda-mullog" || {
    echo "Gagal mengunduh service Timer Mullog" >&2
    exit 1
}
chmod 644 /etc/systemd/system/jeda-mullog.service

# Pastikan limiter yang dipakai adalah versi suspend, bukan versi lama.
fetch ssh /etc/xray/limit.ssh "jeda-mullog suspend ssh" || {
    echo "Gagal mengunduh limiter SSH versi suspend" >&2
    exit 1
}
chmod 755 /etc/xray/limit.ssh
fetch limit-ip /usr/bin/limit-ip "jeda-mullog suspend xray" || {
    echo "Gagal mengunduh limiter Xray versi suspend" >&2
    exit 1
}
chmod 755 /usr/bin/limit-ip

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
for f in /etc/xray/limit.ssh /usr/bin/limit-ip /usr/local/sbin/setting-jeda /usr/local/sbin/utility /usr/local/sbin/backup /usr/local/sbin/restore; do
    [ -s "$f" ] && { bash -n "$f" || exit 1; }
done

systemctl daemon-reload
systemctl enable jeda-mullog >/dev/null 2>&1
systemctl restart jeda-mullog >/dev/null 2>&1
# Muat ulang limiter agar patch suspend aktif.
systemctl restart limitssh >/dev/null 2>&1 || true
for svc in vmip vlip trip; do
    systemctl restart "$svc" >/dev/null 2>&1 || true
done

exit 0
