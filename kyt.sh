#!/bin/bash
# ============================================================
#  kyt.sh - Installer Bot Telegram
#  Kompatibel: Ubuntu 22 / 24, Debian 11 / 12  (fix PEP 668)
# ============================================================
grenbo="\e[92;1m"; NC='\e[0m'
RED='\033[1;31m'; GRN='\033[1;32m'; YEL='\033[1;33m'
say(){ echo -e "${grenbo}$*${NC}"; }
ok(){  echo -e "${GRN}  ✔${NC} $*"; }
warn(){ echo -e "${YEL}  !${NC} $*"; }
bad(){ echo -e "${RED}  ✘${NC} $*"; }

[ "$(id -u)" = "0" ] || { bad "Jalankan sebagai root."; exit 1; }

# data panel (aman kalau file belum ada)
NS=$(cat /etc/xray/dns 2>/dev/null)
PUB=$(cat /etc/slowdns/server.pub 2>/dev/null)
domain=$(cat /etc/xray/domain 2>/dev/null)

# simpan var.txt lama (biar tidak perlu input token lagi saat re-install)
OLDVAR=""
[ -f /usr/bin/kyt/var.txt ] && OLDVAR="$(cat /usr/bin/kyt/var.txt)"

rm -f /etc/systemd/system/kyt.service

# ---------- paket dasar ----------
say "Install paket dasar..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null 2>&1
apt-get install -y python3 python3-pip python3-venv git unzip wget curl >/dev/null 2>&1
ok "python3: $(python3 --version 2>&1)"

# ---------- script pendukung (bot.zip) ----------
cd /usr/bin || exit 1
rm -rf kyt bot bot.zip kyt.zip
wget -q --timeout=30 -O bot.zip https://raw.githubusercontent.com/serigala16/wiz4rd/MASTER/limit/bot.zip
if [ -s bot.zip ]; then
  unzip -oq bot.zip && mv -f bot/* /usr/bin/ 2>/dev/null
  ok "script pendukung (bot.zip) terpasang"
else
  warn "bot.zip gagal diunduh (dilewati)"
fi
rm -rf bot.zip bot

# ---------- source bot (kyt.zip) ----------
wget -q --timeout=60 -O kyt.zip https://raw.githubusercontent.com/victor3232/xhttp/main/limit/kyt.zip
if [ ! -s kyt.zip ]; then bad "kyt.zip gagal diunduh. Cek koneksi."; exit 1; fi
unzip -oq kyt.zip
rm -f kyt.zip
# rapikan kalau struktur zip masih nested (kyt/kyt/...) -> kyt/...
if [ -f /usr/bin/kyt/kyt/__main__.py ] && [ ! -f /usr/bin/kyt/__main__.py ]; then
  rm -rf /tmp/kyt-flat
  mv /usr/bin/kyt/kyt /tmp/kyt-flat
  rm -rf /usr/bin/kyt
  mv /tmp/kyt-flat /usr/bin/kyt
  ok "struktur paket bot dirapikan (kyt/kyt -> kyt)"
fi
[ -n "$OLDVAR" ] && printf '%s\n' "$OLDVAR" > /usr/bin/kyt/var.txt

# ---------- dependency (3 lapis, anti PEP 668) ----------
say "Install dependency bot (telethon)..."
PYBIN=/usr/bin/python3
MODE=""
if python3 -m pip install --break-system-packages --no-cache-dir -r kyt/requirements.txt >/dev/null 2>&1; then
  MODE="pip --break-system-packages"
elif python3 -m venv kyt/venv >/dev/null 2>&1 && \
     kyt/venv/bin/pip install --no-cache-dir -r kyt/requirements.txt >/dev/null 2>&1; then
  PYBIN=/usr/bin/kyt/venv/bin/python3
  MODE="venv (terisolasi)"
elif apt-get install -y python3-telethon python3-requests >/dev/null 2>&1; then
  MODE="apt (python3-telethon)"
fi

if $PYBIN -c "import telethon, requests" >/dev/null 2>&1; then
  ok "telethon siap  [$MODE]"
else
  bad "telethon GAGAL dipasang. Diagnosa:"
  echo "     python3 --version : $(python3 --version 2>&1)"
  echo "     pip               : $(python3 -m pip --version 2>&1 | head -1)"
  echo "     coba manual       : python3 -m pip install --break-system-packages telethon requests"
fi

# ---------- konfigurasi (var.txt) ----------
if [ ! -s /usr/bin/kyt/var.txt ]; then
  echo ""
  echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e " \e[1;97;101m          ADD BOT PANEL          \e[0m"
  echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e "${grenbo}[*] Creat Bot and Token Bot : @BotFather${NC}"
  echo -e "${grenbo}[*] Info Id Telegram : @MissRose_bot , perintah /info${NC}"
  echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  read -e -p "[*] Input your Bot Token : " bottoken
  read -e -p "[*] Input Your Id Telegram : " admin
  {
    echo "BOT_TOKEN='\"$bottoken\"'"
    echo "ADMIN='\"$admin\"'"
    echo "DOMAIN='\"$domain\"'"
    echo "PUB='\"$PUB\"'"
    echo "HOST='\"$NS\"'"
  } > /usr/bin/kyt/var.txt
  clear
else
  ok "var.txt lama dipakai (token tidak perlu diinput ulang)"
fi

# ---------- service ----------
cat > /etc/systemd/system/kyt.service << END
[Unit]
Description=Simple kyt - @kyt
After=network.target

[Service]
Type=simple
WorkingDirectory=/usr/bin
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

# ---------- verifikasi ----------
if systemctl is-active --quiet kyt; then
  ok "Service BOT AKTIF ✅"
else
  bad "Service bot GAGAL start. Log terakhir:"
  journalctl -u kyt -n 15 --no-pager 2>/dev/null | sed 's/^/     /'
fi

cd /root
rm -f /root/kyt.sh
echo ""
echo -e "${GRN}============================================${NC}"
echo -e "${GRN}  INSTALL BOT SELESAI${NC}"
echo -e "${GRN}============================================${NC}"
echo -e "  Cek status : systemctl status kyt"
echo -e "  Lihat log  : journalctl -u kyt -f"
echo -e "  Buka bot   : kirim /menu ke bot Telegram kamu"
echo ""
