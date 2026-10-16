#!/bin/bash
# ============================================================
#  INSTALL UDP CUSTOM  ->  biar menu "Service SSH UDP" jadi ON
#  Sumber resmi : https://github.com/http-custom/udp-custom
#  Binary       : udp-custom v1.4 (statically linked x86-64)
#
#  Cara kerja : udp-custom listen di UDP :36712, lalu menambah
#  iptables DNAT untuk SEMUA port UDP 1-65535 -> :36712,
#  KECUALI port pada daftar EXCLUDE (biar tidak bentrok).
#
#  - Tanpa "apt upgrade", tanpa reboot.
#  - Idempotent: aman dijalankan berulang.
# ============================================================
set -u

# -------- bisa diubah bila perlu --------
UDP_DIR="${UDP_DIR:-/root/udp}"
UDP_SVC="${UDP_SVC:-/etc/systemd/system/udp-custom.service}"
UDP_PORT="${UDP_PORT:-36712}"
# Port UDP yang TIDAK boleh direbut udp-custom (dipakai service lain):
#   53,5300        = DNS / SlowDNS
#   2200           = OpenVPN UDP
#   2100           = misc (iptables paket)
#   7100,7200,7300 = BadVPN (SSH UDP)
#   500,4500,1701  = L2TP / IPSec / IKEv2
UDP_EXCLUDE="${UDP_EXCLUDE:-53,5300,2200,2100,7100,7200,7300,500,4500,1701}"
# ----------------------------------------

UDP_URL_1="https://raw.githubusercontent.com/http-custom/udp-custom/main/bin/udp-custom-linux-amd64"
UDP_URL_2="https://github.com/http-custom/udp-custom/raw/main/bin/udp-custom-linux-amd64"

BIN="$UDP_DIR/udp-custom"
CFG="$UDP_DIR/config.json"

echo "== Install UDP Custom (SSH UDP) =="

if [ "$(id -u)" != "0" ]; then
  echo "GAGAL: harus dijalankan sebagai root."
  exit 1
fi

if ! command -v wget >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1; then
  echo "GAGAL: butuh wget atau curl."
  exit 1
fi

mkdir -p "$UDP_DIR"

# ---------- 1) Binary ----------
if [ -s "$BIN" ]; then
  echo "Binary  : sudah ada ($BIN)"
else
  echo "Unduh   : udp-custom (binary) ..."
  if command -v wget >/dev/null 2>&1; then
    wget -q --timeout=45 -O "$BIN" "$UDP_URL_1" || wget -q --timeout=45 -O "$BIN" "$UDP_URL_2"
  else
    curl -fsSL --max-time 45 -o "$BIN" "$UDP_URL_1" || curl -fsSL --max-time 45 -o "$BIN" "$UDP_URL_2"
  fi
  if [ ! -s "$BIN" ]; then
    echo "GAGAL: tidak bisa mengunduh binary udp-custom."
    rm -f "$BIN"
    exit 1
  fi
  echo "Binary  : OK"
fi
chmod +x "$BIN"

# ---------- 2) Config ----------
if [ ! -s "$CFG" ]; then
  cat > "$CFG" <<EOF
{
  "listen": ":${UDP_PORT}",
  "stream_buffer": 33554432,
  "receive_buffer": 83886080,
  "auth": {
    "mode": "passwords"
  }
}
EOF
  echo "Config  : dibuat ($CFG)"
else
  echo "Config  : sudah ada (dibiarkan)"
fi
chmod 644 "$CFG"

# ---------- 3) Service systemd ----------
cat > "$UDP_SVC" <<EOF
[Unit]
Description=UDP Custom (SSH UDP) by ePro Dev. Team
After=network.target

[Service]
User=root
Type=simple
WorkingDirectory=$UDP_DIR
ExecStart=$BIN server --config $CFG --exclude $UDP_EXCLUDE
Restart=always
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOF
echo "Service : $UDP_SVC"

# ---------- 4) Aktifkan ----------
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable udp-custom >/dev/null 2>&1
  systemctl restart udp-custom
  sleep 2
  if systemctl is-active --quiet udp-custom; then
    echo "Status  : AKTIF ✅"
  else
    echo "Status  : GAGAL start. Log terakhir:"
    journalctl -u udp-custom -n 15 --no-pager 2>/dev/null
    exit 1
  fi
else
  echo "Status  : systemctl tidak tersedia (lewati start)."
fi

echo
echo "Selesai."
echo "  Port UDP Custom   : $UDP_PORT (klien boleh konek di port UDP lain)"
echo "  Port dikecualikan : $UDP_EXCLUDE"
echo "  Cek status        : systemctl status udp-custom"
