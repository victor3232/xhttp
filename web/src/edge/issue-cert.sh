#!/bin/bash
# Terbitkan/perbarui sertifikat Let's Encrypt untuk domain website.
set -e
DOMAIN="${1:-$(awk -F= '$1=="DOMAIN"{sub(/^[^=]*=/,"");print;exit}' /etc/kyt-web.conf 2>/dev/null)}"
WEBROOT="/var/www/letsencrypt"
EMAIL="${2:-admin@stunnelv4.biz.id}"
[ -n "$DOMAIN" ] || { echo "DOMAIN kosong" >&2; exit 1; }

mkdir -p "$WEBROOT/.well-known/acme-challenge"
if [ -s "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    certbot renew --cert-name "$DOMAIN" --quiet || true
else
    certbot certonly --webroot -w "$WEBROOT" -d "$DOMAIN" \
        --email "$EMAIL" --agree-tos --non-interactive \
        --keep-until-expiring
fi
/usr/local/sbin/kyt-web-cert-sync "$DOMAIN"
