#!/bin/bash
# ============================================================
#  install-node.sh — pasang KYT Node Agent di VPS cabang
#  Tidak memasang website panel dan tidak mengubah akun VPN.
#  Pemakaian:
#    bash install-node.sh --domain node.domain.com --code id-1 --port 8787
#  IP master bersifat opsional. Tanpa --master-ip, agent tetap aman
#  karena memakai API Key + HMAC dan tidak bergantung pada IP web utama.
# ============================================================
set -euo pipefail

MASTER_IP="${KYT_MASTER_IP:-}"
DOMAIN="${KYT_NODE_DOMAIN:-}"
CODE="${KYT_NODE_CODE:-}"
PORT="${KYT_NODE_PORT:-8787}"
MAX_SLOTS="${KYT_NODE_MAX_SLOTS:-50}"
REPO="victor3232/xhttp"

while [ $# -gt 0 ]; do
    case "$1" in
        --master-ip) MASTER_IP="${2:-}"; shift 2 ;;
        --domain) DOMAIN="${2:-}"; shift 2 ;;
        --code) CODE="${2:-}"; shift 2 ;;
        --port) PORT="${2:-}"; shift 2 ;;
        --max-slots) MAX_SLOTS="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "Argumen tidak dikenal: $1" >&2; exit 64 ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "Jalankan sebagai root." >&2; exit 1; }
[ -r /etc/os-release ] || { echo "OS tidak dikenali." >&2; exit 1; }
. /etc/os-release
case "${ID:-}" in debian|ubuntu) ;; *) echo "Hanya Debian/Ubuntu." >&2; exit 1 ;; esac
[ "$(uname -m)" = "x86_64" ] || { echo "Hanya x86_64." >&2; exit 1; }

if [ -z "$DOMAIN" ]; then read -r -p "Domain node (harus mengarah ke VPS ini): " DOMAIN; fi
if [ -z "$CODE" ]; then read -r -p "Kode node (contoh id-1): " CODE; fi
[ -n "$DOMAIN" ] && [ -n "$CODE" ] || { echo "Data belum lengkap." >&2; exit 64; }
[[ "$CODE" =~ ^[a-z0-9-]{2,16}$ ]] || { echo "Kode node tidak valid." >&2; exit 64; }
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || { echo "Port tidak valid." >&2; exit 64; }

echo "[1/6] Memasang dependensi..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold python3 curl ca-certificates openssl netfilter-persistent iptables </dev/null >/dev/null

if [ ! -s /etc/xray/xray.crt ] || [ ! -s /etc/xray/xray.key ]; then
    echo "Sertifikat /etc/xray/xray.crt & xray.key tidak ditemukan." >&2
    echo "Pastikan autoscript VPN + domain/SSL sudah terpasang di node ini." >&2
    exit 1
fi

for s in addssh addws addvless addtr; do
    [ -x "/usr/local/sbin/$s" ] || { echo "Script $s tidak ditemukan. Autoscript VPN belum lengkap." >&2; exit 1; }
done

echo "[2/6] Mengunduh agent..."
SHA=$(curl -fsSL --max-time 15 "https://api.github.com/repos/${REPO}/commits/main" 2>/dev/null \
      | grep -o '"sha"[[:space:]]*:[[:space:]]*"[0-9a-f]\{40\}"' | head -n1 | grep -o '[0-9a-f]\{40\}') || true
URL="https://raw.githubusercontent.com/${REPO}/main/node/kyt-node-agent.py"
[ -n "$SHA" ] && URL="https://raw.githubusercontent.com/${REPO}/${SHA}/node/kyt-node-agent.py"
curl -fsSL --max-time 60 -o /usr/local/sbin/kyt-node-agent "$URL" || {
    echo "Gagal mengunduh agent dari repo." >&2; exit 1; }
chmod 755 /usr/local/sbin/kyt-node-agent
python3 -m py_compile /usr/local/sbin/kyt-node-agent || { echo "Agent tidak valid." >&2; exit 1; }

echo "[3/6] Membuat credential unik..."
API_KEY="${CODE}-$(openssl rand -hex 8)"
SECRET="$(openssl rand -hex 32)"
mkdir -p /etc/kyt-node
umask 077
if [ -n "$MASTER_IP" ]; then
    ALLOW_JSON="[\"${MASTER_IP}\"]"
else
    ALLOW_JSON="[]"
fi
cat > /etc/kyt-node/agent.json <<EOF
{"node":"${CODE}","bind":"0.0.0.0","port":${PORT},"api_key":"${API_KEY}","secret":"${SECRET}","token":"${SECRET}","domain":"${DOMAIN}","allow_ips":${ALLOW_JSON},"cert":"/etc/xray/xray.crt","key":"/etc/xray/xray.key","max_slots":${MAX_SLOTS},"revoked":false}
EOF
chmod 600 /etc/kyt-node/agent.json

echo "[4/6] Memasang service..."
cat > /etc/systemd/system/kyt-node-agent.service <<'EOF'
[Unit]
Description=KYT Node Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/sbin/kyt-node-agent
Restart=always
RestartSec=3
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable kyt-node-agent >/dev/null 2>&1

if [ -n "$MASTER_IP" ]; then
    echo "[5/6] Mengatur firewall (hanya IP master $MASTER_IP)..."
    iptables -C INPUT -p tcp -s "$MASTER_IP" --dport "$PORT" -j ACCEPT 2>/dev/null || \
        iptables -I INPUT 1 -p tcp -s "$MASTER_IP" --dport "$PORT" -j ACCEPT
    iptables -C INPUT -p tcp --dport "$PORT" -j DROP 2>/dev/null || \
        iptables -I INPUT 2 -p tcp --dport "$PORT" -j DROP
else
    echo "[5/6] Membuka port agent (autentikasi API Key + HMAC)..."
    while iptables -C INPUT -p tcp --dport "$PORT" -j DROP 2>/dev/null; do
        iptables -D INPUT -p tcp --dport "$PORT" -j DROP 2>/dev/null || break
    done
    iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || \
        iptables -I INPUT 1 -p tcp --dport "$PORT" -j ACCEPT
fi
netfilter-persistent save >/dev/null 2>&1 || true

echo "[6/6] Menjalankan agent..."
systemctl restart kyt-node-agent
sleep 2
if ! systemctl is-active --quiet kyt-node-agent; then
    echo "Agent gagal start. Cek: journalctl -u kyt-node-agent -n 50 --no-pager" >&2
    exit 1
fi
curl -sk --max-time 8 "https://127.0.0.1:${PORT}/v1/ping" >/dev/null || {
    echo "Agent tidak merespons di port ${PORT}." >&2; exit 1; }

cat > /usr/local/sbin/kyt-node <<'CLI'
#!/bin/bash
set -euo pipefail
CONF=/etc/kyt-node/agent.json
case "${1:-show}" in
  show)
    python3 - "$CONF" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print("node      :",d.get("node"))
dom=d.get("domain") or ""
if not dom:
    try: dom=open("/etc/xray/domain").read().strip()
    except Exception: dom="<domain>"
print("url       : https://%s:%s" % (dom, d.get("port")))
print("api_key   :",d.get("api_key"))
print("secret    :", "tersimpan (tidak ditampilkan)")
print("allow_ips :", ",".join(d.get("allow_ips") or []))
print("revoked   :", bool(d.get("revoked")))
PY
    ;;
  rotate)
    NEW="$(openssl rand -hex 32)"
    python3 - "$CONF" "$NEW" <<'PY'
import json,sys
p,n=sys.argv[1],sys.argv[2]
d=json.load(open(p)); d["secret"]=n; d["token"]=n
json.dump(d,open(p,"w"))
PY
    chmod 600 "$CONF"; systemctl restart kyt-node-agent
    echo "Secret baru: $NEW"; echo "Perbarui Secret di Admin > Multi-Server."
    ;;
  revoke)
    python3 - "$CONF" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d["revoked"]=True
json.dump(d,open(p,"w"))
PY
    chmod 600 "$CONF"; systemctl restart kyt-node-agent
    echo "Credential dicabut. Aktifkan lagi dengan: kyt-node enable"
    ;;
  enable)
    python3 - "$CONF" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d["revoked"]=False
json.dump(d,open(p,"w"))
PY
    chmod 600 "$CONF"; systemctl restart kyt-node-agent
    echo "Credential aktif kembali."
    ;;
  *) echo "usage: kyt-node {show|rotate|revoke|enable}" >&2; exit 64 ;;
esac
CLI
chmod 755 /usr/local/sbin/kyt-node

cat <<EOF

============================================================
 NODE BERHASIL DIPASANG
============================================================
 URL agent : https://${DOMAIN}:${PORT}
 Node code : ${CODE}
 API Key   : ${API_KEY}
 Secret    : ${SECRET}
 Master IP : ${MASTER_IP:-otomatis / terbuka (HMAC)}

 Simpan Secret ini, hanya ditampilkan sekali.
 Di VPS utama: Admin -> Multi-Server -> Add Server.
 Perintah node: kyt-node show|rotate|revoke|enable
============================================================
EOF
