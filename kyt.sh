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

# ---------- deteksi OS ----------
OS_ID=""; OS_VER=""; OS_NAMA=""
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_ID="$ID"; OS_VER="$VERSION_ID"; OS_NAMA="$PRETTY_NAME"
fi
say "OS terdeteksi: ${OS_NAMA:-tidak diketahui}"

case "$OS_ID" in
  ubuntu)
    case "$OS_VER" in
      20.04|22.04|24.04|24.10|25.04|25.10|26.04) ok "Ubuntu $OS_VER didukung" ;;
      *) warn "Ubuntu $OS_VER belum diuji, dicoba tetap jalan" ;;
    esac
    ;;
  debian)
    case "$OS_VER" in
      11|12|13|14) ok "Debian $OS_VER didukung" ;;
      *) warn "Debian $OS_VER belum diuji, dicoba tetap jalan" ;;
    esac
    ;;
  *)
    warn "Distro '$OS_ID' belum diuji (Ubuntu/Debian disarankan)"
    ;;
esac

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
apt-get update -y >/dev/null 2>&1 || warn "apt-get update gagal (lanjut)"

pasang_paket() {
  apt-get install -y "$@" >/dev/null 2>&1 && return 0
  local _g=""
  for _p in "$@"; do
    apt-get install -y "$_p" >/dev/null 2>&1 || _g="$_g $_p"
  done
  [ -n "$_g" ] && warn "dilewati (tidak ada di repo):$_g"
  return 0
}

pasang_paket python3 python3-pip python3-venv git unzip wget curl
ok "python3: $(python3 --version 2>&1)"
command -v pip3 >/dev/null 2>&1 || pasang_paket python3-pip
command -v unzip >/dev/null 2>&1 || bad "unzip tidak terpasang (penting!)"

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

# ---------- dependency (anti PEP 668, tahan pip versi lama/baru) ----------
say "Install dependency bot (telethon)..."
PYBIN=/usr/bin/python3
MODE=""
REQ="kyt/requirements.txt"

# Versi telethon MINIMUM yang aman.
# Di bawah ini, conversation(exclusive=False) / penanganan error bisa
# berbeda -> bot bisa "diam" setelah beberapa pertanyaan (bug lama).
# CATATAN: Debian 12 apt memberi 1.25.1, Debian 13 apt memberi 1.40.0.
# Versi apt itu TIDAK CUKUP, jadi JANGAN dipakai sebagai pilihan utama.
TELE_MIN="1.36.0"
TELE_PILIH="1.45.0"

pip_pasang() {
  # $1 = python binary, $2.. = paket
  local PY="$1"; shift
  "$PY" -m pip install --break-system-packages --no-cache-dir "$@" >/dev/null 2>&1 && return 0
  # pip lama belum kenal --break-system-packages
  "$PY" -m pip install --no-cache-dir "$@" >/dev/null 2>&1 && return 0
  return 1
}

# cek apakah versi telethon di python ini >= TELE_MIN
tele_ok() {
  "$1" - "$TELE_MIN" <<'PYX' >/dev/null 2>&1
import sys
try:
    import telethon
except Exception:
    sys.exit(1)
def v(x):
    out = []
    for p in str(x).split("."):
        n = ""
        for c in p:
            if c.isdigit():
                n += c
            else:
                break
        out.append(int(n or 0))
    return tuple(out)
sys.exit(0 if v(telethon.__version__) >= v(sys.argv[1]) else 1)
PYX
}

pip_siap() {
  python3 -m pip --version >/dev/null 2>&1 ||
    (pasang_paket python3-pip && python3 -m pip --version >/dev/null 2>&1)
}

# ---------- LANGKAH 1: coba pip sistem (versi PIN, paling stabil) ----------
pip_siap
if pip_pasang python3 "telethon==$TELE_PILIH" "requests>=2.31.0" && tele_ok python3; then
  MODE="pip (sistem, telethon $TELE_PILIH)"
fi

# ---------- LANGKAH 2: venv (WAJIB berhasil kalau pip sistem gagal) ----------
if [ -z "$MODE" ]; then
  # pastikan modul venv ada (Debian sering belum)
  python3 -c "import venv" >/dev/null 2>&1 || pasang_paket python3-venv
  python3 -c "import ensurepip" >/dev/null 2>&1 || pasang_paket python3-venv
  rm -rf kyt/venv
  if python3 -m venv kyt/venv >/dev/null 2>&1; then
    VPY=/usr/bin/kyt/venv/bin/python3
    pip_pasang "$VPY" --upgrade pip
    if pip_pasang "$VPY" "telethon==$TELE_PILIH" "requests>=2.31.0" && tele_ok "$VPY"; then
      PYBIN="$VPY"
      MODE="venv (terisolasi, telethon $TELE_PILIH)"
    fi
  fi
fi

# ---------- LANGKAH 3: apt = CADANGAN TERAKHIR ----------
# JANGAN dipakai kalau versinya < TELE_MIN (Debian 12 apt = 1.25.1 -> tidak aman)
if [ -z "$MODE" ]; then
  if (pasang_paket python3-telethon python3-requests) && tele_ok python3; then
    MODE="apt (versi $(python3 -c 'import telethon;print(telethon.__version__)' 2>/dev/null))"
  else
    warn "python3-telethon dari apt terlalu tua (< $TELE_MIN) - DITOLAK"
  fi
fi

# ---------- LANGKAH 4: paksa versi minimum apa pun caranya ----------
if [ -z "$MODE" ]; then
  warn "mencoba paksa telethon==$TELE_MIN ..."
  if pip_pasang python3 "telethon==$TELE_MIN" "requests" && tele_ok python3; then
    MODE="pip (pin $TELE_MIN)"
  fi
fi

# ---------- PILIH PYTHON YANG BENAR-BENAR PUNYA TELEGRAM YANG CUKUP ----------
# (kalau MODE kosong, service TIDAK boleh dipasang dengan python yang salah)
if [ -n "$MODE" ]; then
  PYBIN=/usr/bin/python3
  tele_ok "$PYBIN" || {
    if [ -x /usr/bin/kyt/venv/bin/python3 ] && tele_ok /usr/bin/kyt/venv/bin/python3; then
      PYBIN=/usr/bin/kyt/venv/bin/python3
    fi
  }
fi

# Pillow = OPSIONAL: dipakai merapikan rasio gambar /start ke 16:9.
# Kalau gagal dipasang, bot TETAP jalan (gambar dikirim apa adanya).
say "Install Pillow (opsional, untuk gambar /start)..."
if $PYBIN -c "import PIL" >/dev/null 2>&1; then
  ok "Pillow sudah ada"
elif pip_pasang "$PYBIN" "pillow>=10.0.0"; then
  ok "Pillow terpasang (gambar /start otomatis 16:9)"
else
  warn "Pillow gagal dipasang - gambar /start dikirim apa adanya (tetap jalan)"
fi

if [ -n "$MODE" ] && tele_ok "$PYBIN"; then
  ok "telethon siap  [$MODE]"
  $PYBIN -c "import sys,telethon,requests;print('     python   : %s'%sys.version.split()[0]);print('     telethon : %s'%telethon.__version__);print('     requests : %s'%requests.__version__);print('     jalur    : %s'%sys.executable)" 2>/dev/null
  # tes asyncio + conversation (inti bot)
  if $PYBIN -c "import asyncio,telethon;from telethon import TelegramClient,events,Button;print('')" >/dev/null 2>&1; then
    ok "API telethon (events/Button) OK"
  else
    bad "API telethon tidak lengkap - cek log di bawah"
  fi
  # tes conversation(exclusive=False) -- ini inti alur tanya() bot
  if $PYBIN -c "
from telethon.tl.custom import conversation as C
import inspect
p = inspect.signature(C.Conversation.__init__).parameters
assert 'exclusive' in p and 'total_timeout' in p
" >/dev/null 2>&1; then
    ok "conversation(exclusive=False) didukung (alur tanya aman)"
  else
    bad "telethon tidak mendukung conversation(exclusive=False)!"
    bad "Ini PENYEBAB bot 'diam' setelah beberapa pertanyaan."
    bad "Perbaiki: python3 -m pip install --break-system-packages telethon==$TELE_PILIH"
  fi
else
  bad "telethon GAGAL dipasang / versinya terlalu tua (< $TELE_MIN)."
  echo "     Versi apt yang tersedia: $(apt-cache policy python3-telethon 2>/dev/null | grep Candidate | awk '{print $2}')"
  echo "     python3 --version : $(python3 --version 2>&1)"
  echo "     pip               : $(python3 -m pip --version 2>&1 | head -1)"
  echo ""
  echo "     COBA MANUAL (pilih salah satu):"
  echo "       python3 -m pip install --break-system-packages telethon==$TELE_PILIH requests"
  echo "       apt install python3-venv && python3 -m venv kyt/venv && kyt/venv/bin/pip install telethon==$TELE_PILIH requests"
  echo ""
  echo "     JANGAN lanjut sebelum telethon >= $TELE_MIN, karena bot akan sering 'diam'."
  echo ""
  echo -e "\033[1;31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e " \033[1;31m INSTALASI DIHENTIKAN \033[0m"
  echo -e "\033[1;31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo " Service bot TIDAK dipasang, karena kalau dipasang akan"
  echo " sering 'diam' setelah beberapa pertanyaan (bug telethon lama)."
  echo ""
  echo " Jalankan perintah manual di atas, lalu ulangi:"
  echo "   bash kyt.sh"
  exit 1
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
