#!/bin/bash
# ============================================================
#  fix-bot-ubuntu24.sh
#  Perbaiki Bot Telegram yang gagal install di Ubuntu 24 / Debian 12
#  (PEP 668 "externally-managed-environment") TANPA input ulang token.
#
#  Pakai:  bash fix-bot-ubuntu24.sh
# ============================================================
grenbo="\e[92;1m"; NC='\e[0m'
RED='\033[1;31m'; GRN='\033[1;32m'; YEL='\033[1;33m'
say(){ echo -e "${grenbo}$*${NC}"; }
ok(){  echo -e "${GRN}  ✔${NC} $*"; }
warn(){ echo -e "${YEL}  !${NC} $*"; }
bad(){ echo -e "${RED}  ✘${NC} $*"; }

[ "$(id -u)" = "0" ] || { bad "Jalankan sebagai root."; exit 1; }

KYT_DIR="/usr/bin/kyt"
SERVICE="/etc/systemd/system/kyt.service"

if [ ! -d "$KYT_DIR" ]; then
  bad "Folder $KYT_DIR tidak ada. Jalankan dulu installer bot (kyt.sh)."
  exit 1
fi

say "Diagnosa..."
echo "     python3 : $(python3 --version 2>&1)"
echo "     pip     : $(python3 -m pip --version 2>&1 | head -1)"
echo "     bot dir : $KYT_DIR"
echo "     var.txt : $([ -s $KYT_DIR/var.txt ] && echo 'ada ✅' || echo 'TIDAK ADA ⚠️')"

say "Install python3-venv & pip..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null 2>&1
apt-get install -y python3 python3-pip python3-venv >/dev/null 2>&1

REQ="$KYT_DIR/requirements.txt"
[ -s "$REQ" ] || REQ="/dev/stdin"
if [ "$REQ" = "/dev/stdin" ]; then
  printf 'telethon>=1.36.0,<2\nrequests>=2.31.0\n' > /tmp/kyt-req.txt
  REQ="/tmp/kyt-req.txt"
fi

say "Pasang dependency (3 lapis)..."
PYBIN="/usr/bin/python3"
MODE=""
if python3 -m pip install --break-system-packages --no-cache-dir -r "$REQ" >/dev/null 2>&1; then
  MODE="pip --break-system-packages"
elif python3 -m venv "$KYT_DIR/venv" >/dev/null 2>&1 && \
     "$KYT_DIR/venv/bin/pip" install --no-cache-dir -r "$REQ" >/dev/null 2>&1; then
  PYBIN="$KYT_DIR/venv/bin/python3"
  MODE="venv (terisolasi)"
elif apt-get install -y python3-telethon python3-requests >/dev/null 2>&1; then
  MODE="apt (python3-telethon)"
fi

if $PYBIN -c "import telethon, requests" >/dev/null 2>&1; then
  ok "telethon siap  [$MODE]  -> $PYBIN"
else
  bad "telethon masih gagal. Coba manual:"
  echo "     python3 -m pip install --break-system-packages telethon requests"
  exit 1
fi

say "Perbaiki service kyt..."
# ambil WorkingDirectory lama kalau ada
WD="/usr/bin"
[ -f "$SERVICE" ] && WD=$(grep -E '^WorkingDirectory=' "$SERVICE" | cut -d= -f2)
[ -z "$WD" ] && WD="/usr/bin"

cat > "$SERVICE" << END
[Unit]
Description=Simple kyt - @kyt
After=network.target

[Service]
Type=simple
WorkingDirectory=$WD
ExecStart=$PYBIN -m kyt
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
END

systemctl daemon-reload
systemctl enable kyt >/dev/null 2>&1
systemctl restart kyt
sleep 4

if systemctl is-active --quiet kyt; then
  ok "BOT AKTIF ✅ — coba kirim /menu ke bot kamu."
else
  bad "Bot belum aktif. Log terakhir:"
  journalctl -u kyt -n 20 --no-pager 2>/dev/null | sed 's/^/     /'
  echo
  warn "Kalau log bilang 'var.txt not found', jalankan installer: bash kyt.sh"
fi
