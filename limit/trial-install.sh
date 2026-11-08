#!/bin/bash
# Install / update Trial Account engine.
# Aman dijalankan berulang: setting /etc/kyt/trial.conf tidak ditimpa.
set -u

SRC="${1:-/usr/local/sbin}"
if [ -d "$SRC/menu" ]; then
    SRC="$SRC/menu"
fi

ok()  { echo -e " \033[92m✔\033[0m $*"; }
warn(){ echo -e " \033[93m!\033[0m $*"; }
bad() { echo -e " \033[91m✘\033[0m $*"; }

[ "$(id -u)" = "0" ] || { bad "Jalankan sebagai root."; exit 1; }

mkdir -p /etc/kyt/trial/state /etc/kyt/limit/shadowsocks/ip
chmod 700 /etc/kyt/trial/state 2>/dev/null || true

for f in kyt-trial kyt-trial-expire trial; do
    if [ -f "$SRC/$f" ]; then
        if [ "$(readlink -f "$SRC/$f")" = "$(readlink -f "/usr/local/sbin/$f" 2>/dev/null)" ]; then
            chmod 755 "/usr/local/sbin/$f"
        else
            install -m 755 "$SRC/$f" "/usr/local/sbin/$f"
        fi
        ok "$f"
    else
        warn "$f tidak ditemukan di $SRC"
    fi
done

if [ -f "$SRC/trial.conf" ]; then
    if [ ! -f /etc/kyt/trial.conf ]; then
        install -m 600 "$SRC/trial.conf" /etc/kyt/trial.conf
        ok "trial.conf dibuat"
    else
        chmod 600 /etc/kyt/trial.conf
        ok "trial.conf dipertahankan"
    fi
fi

for u in kyt-trial-expire ssip; do
    if [ -f "$SRC/$u.service" ]; then
        if [ "$(readlink -f "$SRC/$u.service")" = "$(readlink -f "/etc/systemd/system/$u.service" 2>/dev/null)" ]; then
            chmod 644 "/etc/systemd/system/$u.service"
        else
            install -m 644 "$SRC/$u.service" "/etc/systemd/system/$u.service"
        fi
        ok "$u.service"
    else
        warn "$u.service tidak ditemukan"
    fi
done

systemctl daemon-reload >/dev/null 2>&1
for u in kyt-trial-expire ssip; do
    if [ -f "/etc/systemd/system/$u.service" ]; then
        systemctl enable --now "$u" >/dev/null 2>&1 && ok "$u aktif" || warn "$u gagal aktif"
    fi
done

echo ""
echo "Trial engine siap."
echo "  Menu VPS : Utility -> 27. TRIAL MANAGER"
echo "  Bot      : Menu -> TRIAL SETTINGS"
