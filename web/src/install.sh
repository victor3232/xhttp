#!/bin/bash
# Installer mandiri VPNFree. Dipanggil oleh setting-web saat pertama ON.
set -e
DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
    echo "Usage: install.sh DOMAIN" >&2
    exit 64
fi
DOMAIN=$(printf '%s' "$DOMAIN" | tr 'A-Z' 'a-z' | tr -d '[:space:]')
case "$DOMAIN" in
    *.*) ;;
    *) echo "Domain tidak valid: $DOMAIN" >&2; exit 64 ;;
esac

ROOT="$(cd "$(dirname "$0")" && pwd)"
CONF="/etc/kyt-web.conf"
APP_DIR="/opt/kyt-web"
WEBROOT="/var/www/letsencrypt"

if [ "$(id -u)" != "0" ]; then
    echo "Installer harus dijalankan sebagai root." >&2
    exit 1
fi

for c in python3 unzip curl wget openssl nginx; do
    if ! command -v "$c" >/dev/null 2>&1; then
        echo "Memasang dependency: $c"
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$c" >/dev/null
    fi
done
if ! command -v certbot >/dev/null 2>&1; then
    echo "Memasang certbot..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot >/dev/null
fi
if ! python3 -c 'import qrcode' >/dev/null 2>&1; then
    echo "Memasang generator QRIS..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-qrcode >/dev/null
fi
if ! python3 -c 'from PIL import Image' >/dev/null 2>&1; then
    echo "Memasang pengolah logo..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-pil >/dev/null
fi
if [ ! -x /usr/sbin/haproxy ]; then
    echo "HAProxy tidak ditemukan. Pastikan script VPN utama sudah terpasang." >&2
    exit 1
fi

install -d -m 755 "$APP_DIR" "$APP_DIR/data"
chmod 700 "$APP_DIR/data"
install -m 644 "$ROOT/app.py" "$APP_DIR/app.py"
rm -rf "$APP_DIR/static" "$APP_DIR/__pycache__"
install -d -m 755 "$APP_DIR/static"
cp -a "$ROOT/static/." "$APP_DIR/static/"
chmod 644 "$APP_DIR/static/style.css" "$APP_DIR/static/app.js" "$APP_DIR/static/favicon.svg"
find "$APP_DIR/static" -type f -exec chmod 644 {} +
install -m 644 "$ROOT/kyt-web.service" /etc/systemd/system/kyt-web.service

install -m 755 "$ROOT/edge/configure_edge.py" /usr/local/sbin/kyt-web-configure-edge
install -m 644 "$ROOT/edge/vpnfree.conf.tpl" /usr/local/sbin/vpnfree.conf.tpl
install -m 755 "$ROOT/edge/kyt-web-cert-sync" /usr/local/sbin/kyt-web-cert-sync
install -m 755 "$ROOT/edge/issue-cert.sh" /usr/local/sbin/issue-cert.sh
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
ln -sf /usr/local/sbin/kyt-web-cert-sync /etc/letsencrypt/renewal-hooks/deploy/kyt-web-cert-sync

touch "$CONF"
chmod 644 "$CONF"
if grep -qE '^DOMAIN=' "$CONF"; then
    sed -i "s|^DOMAIN=.*|DOMAIN=$DOMAIN|" "$CONF"
else
    echo "DOMAIN=$DOMAIN" >> "$CONF"
fi
if grep -qE '^ENABLED=' "$CONF"; then
    sed -i 's|^ENABLED=.*|ENABLED=1|' "$CONF"
else
    echo 'ENABLED=1' >> "$CONF"
fi

# Fallback admin login jika bot Telegram belum terpasang.
if [ ! -s /etc/bot/.bot.db ] && ! grep -qE '^ADMIN_TOKEN=' "$CONF"; then
    ADMIN_WEB_TOKEN=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 48)
    echo "ADMIN_TOKEN=$ADMIN_WEB_TOKEN" >> "$CONF"
    printf 'HITS SSH admin\nURL: https://%s/admin\nToken: %s\n' "$DOMAIN" "$ADMIN_WEB_TOKEN" > /root/hits-admin-token.txt
    chmod 600 /root/hits-admin-token.txt
fi

mkdir -p "$WEBROOT/.well-known/acme-challenge" /etc/ssl/kyt-web
echo "Mendeteksi lokasi server dari IP publik..."
python3 "$APP_DIR/app.py" --detect-server || echo "Peringatan: lokasi server belum terdeteksi; atur manual di Admin Dashboard."
python3 /usr/local/sbin/kyt-web-configure-edge "$DOMAIN"

# Coba terbitkan sertifikat jika HTTP-01 sudah bisa diakses dari publik.
printf 'kyt-install-check' > "$WEBROOT/.well-known/acme-challenge/kyt-install-check"
CHALLENGE=$(curl -4 -fsSL --max-time 15 "http://$DOMAIN/.well-known/acme-challenge/kyt-install-check" 2>/dev/null || true)
rm -f "$WEBROOT/.well-known/acme-challenge/kyt-install-check"
if [ "$CHALLENGE" = "kyt-install-check" ]; then
    echo "DNS siap; menerbitkan sertifikat Let's Encrypt..."
    /usr/local/sbin/issue-cert.sh "$DOMAIN" || echo "Peringatan: sertifikat belum berhasil; website tetap memakai self-signed."
else
    echo "Peringatan: DNS $DOMAIN belum mengarah ke VPS ini."
    echo "Website tetap dipasang dengan sertifikat sementara (self-signed)."
    echo "Setelah DNS diarahkan, jalankan: issue-cert.sh $DOMAIN"
fi

systemctl daemon-reload
systemctl enable kyt-web >/dev/null 2>&1
systemctl restart kyt-web
sleep 2
if systemctl is-active --quiet kyt-web; then
    echo "Website aktif: https://$DOMAIN"
else
    echo "Website gagal start. Cek: journalctl -u kyt-web -n 50" >&2
    exit 1
fi
