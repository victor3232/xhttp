#!/bin/bash
# ============================================================
#  kyt.sh - Installer Bot Telegram (+ STORE & Duitku)
#  Kompatibel: Ubuntu 22 / 24, Debian 11 / 12
#  Fix: PEP 668 (externally-managed) + struktur paket kyt/kyt
# ============================================================
grenbo="\e[92;1m"; NC='\e[0m'
RED='\033[1;31m'; GRN='\033[1;32m'; YEL='\033[1;33m'
say(){ echo -e "${grenbo}$*${NC}"; }
ok(){  echo -e "${GRN}  ✔${NC} $*"; }
warn(){ echo -e "${YEL}  !${NC} $*"; }
bad(){ echo -e "${RED}  ✘${NC} $*"; }

[ "$(id -u)" = "0" ] || { bad "Jalankan sebagai root."; exit 1; }

NS=$(cat /etc/xray/dns 2>/dev/null)
PUB=$(cat /etc/slowdns/server.pub 2>/dev/null)
domain=$(cat /etc/xray/domain 2>/dev/null)

# simpan var.txt lama (biar token tidak perlu input ulang)
OLDVAR=""
[ -f /usr/bin/kyt/var.txt ] && OLDVAR="$(cat /usr/bin/kyt/var.txt)"

# simpan DATABASE STORE lama (saldo, pesanan, deposit, pengaturan)
# -> tanpa ini, reinstall = semua data pelanggan HILANG
OLDDB=""
if [ -f /usr/bin/kyt/database.db ]; then
  mkdir -p /root/backup
  cp -f /usr/bin/kyt/database.db /root/backup/kyt-db-sebelum-install-$(date +%Y%m%d-%H%M%S).db 2>/dev/null
  cp -f /usr/bin/kyt/database.db /root/.kyt-database-lama.db 2>/dev/null
  [ -f /root/.kyt-database-lama.db ] && OLDDB="/root/.kyt-database-lama.db"
fi

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

# ---- NORMALISASI struktur paket (anti kyt/kyt) ----
if [ ! -f /usr/bin/kyt/__init__.py ] && [ -f /usr/bin/kyt/kyt/__init__.py ]; then
  rm -rf /tmp/kyt-flat
  mv /usr/bin/kyt/kyt /tmp/kyt-flat
  rm -rf /usr/bin/kyt
  mv /tmp/kyt-flat /usr/bin/kyt
  ok "struktur paket dirapikan (kyt/kyt -> kyt)"
fi

# ---- pastikan __main__.py ada (kalau zip lama tidak punya) ----
if [ -f /usr/bin/kyt/__init__.py ] && [ ! -f /usr/bin/kyt/__main__.py ]; then
  cat > /usr/bin/kyt/__main__.py <<'KYTMAIN'
from kyt import *
from importlib import import_module
from kyt.modules import ALL_MODULES
for module_name in ALL_MODULES:
        imported_module = import_module("kyt.modules." + module_name)

import asyncio
async def _store_poll_loop():
    from kyt.modules.deposit import cek_semua_pending
    while True:
        await asyncio.sleep(20)
        try:
            await cek_semua_pending()
        except Exception as e:
            logging.error("store poller: %s", e)
async def _notif_expired_loop():
    from kyt.modules.notif import cek_expired
    await asyncio.sleep(60)
    while True:
        try:
            await cek_expired()
        except Exception as e:
            logging.error("notif expired: %s", e)
        await asyncio.sleep(600)
async def _backup_db_loop():
    from kyt.modules.backup import backup_db_harian
    await asyncio.sleep(120)
    while True:
        try:
            await asyncio.to_thread(backup_db_harian)
        except Exception as e:
            logging.error("backup db: %s", e)
        await asyncio.sleep(6 * 3600)
try:
    bot.loop.create_task(_store_poll_loop())
except Exception as e:
    logging.error("gagal start store poller: %s", e)
try:
    bot.loop.create_task(_notif_expired_loop())
except Exception as e:
    logging.error("gagal start notif expired: %s", e)
try:
    bot.loop.create_task(_backup_db_loop())
except Exception as e:
    logging.error("gagal start backup db: %s", e)
bot.run_until_disconnected()
KYTMAIN
  warn "__main__.py dibuat otomatis"
fi

# ---- verifikasi isi paket ----
[ -f /usr/bin/kyt/__init__.py ] || { bad "Paket bot tidak ditemukan di /usr/bin/kyt"; exit 1; }
if [ -f /usr/bin/kyt/store_lib.py ]; then
  ok "modul STORE + Duitku terdeteksi"
else
  bad "MODUL STORE BELUM ADA!"
  echo "     -> limit/kyt.zip di repo masih VERSI LAMA."
  echo "     -> Upload limit/kyt.zip yang baru, lalu jalankan ulang kyt.sh"
fi
[ -f /usr/bin/kyt/modules/notif.py ] && ok "modul NOTIF EXPIRED terdeteksi" \
  || warn "modules/notif.py belum ada (notif expired tidak jalan)"
[ -f /usr/bin/kyt/modules/backup.py ] && ok "modul BACKUP & RESTORE terdeteksi" \
  || warn "modules/backup.py belum ada (backup/restore tidak jalan)"

# ---- script pendukung bot (bot-vps-info, bot-member-ssh, bot-backup, ...) ----
if [ -d /usr/bin/kyt/shell/bot ]; then
  chmod +x /usr/bin/kyt/shell/bot/* 2>/dev/null
  for f in /usr/bin/kyt/shell/bot/*; do
    [ -f "$f" ] && ln -sf "$f" "/usr/local/bin/$(basename "$f")"
  done
  ok "script pendukung bot dipasang ke /usr/local/bin"
fi

[ -n "$OLDVAR" ] && printf '%s\n' "$OLDVAR" > /usr/bin/kyt/var.txt

# ---- kembalikan database store lama (kalau ada) ----
if [ -n "$OLDDB" ] && [ -s "$OLDDB" ]; then
  cp -f "$OLDDB" /usr/bin/kyt/database.db
  ok "database store lama dipakai (saldo/pesanan/deposit AMAN)"
  warn "salinan backup db: /root/backup/kyt-db-sebelum-install-*.db"
else
  warn "database store belum ada -> mulai dari kosong"
fi

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
    echo "BOT_TOKEN='$bottoken'"
    echo "ADMIN='$admin'"
    echo "DOMAIN='$domain'"
    echo "PUB='$PUB'"
    echo "HOST='$NS'"
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
echo -e "  Buka bot   : kirim /start ke bot Telegram kamu"
echo ""
