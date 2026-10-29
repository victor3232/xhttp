#!/bin/bash
# ============================================================
#  update-all.sh - Update UI Menu + Fix SSH Hybrid
#  Jalankan di VPS yang sudah terpasang script VPN
#  Perintah: bash update-all.sh
# ============================================================
RED='\033[38;2;251;113;133m'
GRN='\033[38;2;52;211;153m'
YEL='\033[38;2;251;191;36m'
CYN='\033[38;2;34;211;238m'
VIO='\033[38;2;139;92;246m'
NC='\033[0m'
BLD='\033[1m'

ok()  { echo -e " ${GRN}✔${NC} $*"; }
warn(){ echo -e " ${YEL}!${NC} $*"; }
bad() { echo -e " ${RED}✘${NC} $*"; }
line(){ printf ' %s' "$VIO"; printf '━%.0s' $(seq 1 55); printf '%s\n' "$NC"; }

[ "$(id -u)" = "0" ] || { bad "Jalankan sebagai root!"; exit 1; }

DIR="$(cd "$(dirname "$0")" && pwd)"
if [ ! -f "$DIR/limit/menu.zip" ]; then
    bad "File limit/menu.zip tidak ditemukan!"
    bad "Pastikan struktur folder: update-all.sh + limit/"
    exit 1
fi

clear
echo ""
line
echo -e " ${BLD}${CYN}     UPDATE ALL - UI MENU + FIX SSH HYBRID${NC}"
line
echo ""

# =============================================
# PART 1: UPDATE MENU UI
# =============================================
echo -e " ${BLD}${VIO}[PART 1]${NC} ${BLD}Update Menu UI${NC}"
echo ""

echo -e " ${YEL}[1/3]${NC} Backup menu lama..."
if [ -d /usr/local/sbin ]; then
    tar czf /root/backup-menu-$(date +%Y%m%d%H%M%S).tar.gz \
        /usr/local/sbin/menu /usr/local/sbin/m-* \
        /usr/local/sbin/cekws /usr/local/sbin/cekvless \
        /usr/local/sbin/cektr /usr/local/sbin/cekss \
        /usr/local/sbin/utility /usr/local/sbin/menu-backup \
        2>/dev/null
    ok "Backup → /root/backup-menu-*.tar.gz"
else
    warn "/usr/local/sbin tidak ada, skip backup"
fi

echo -e " ${YEL}[2/3]${NC} Extract menu baru..."
cd /tmp && rm -rf menu_update_tmp && mkdir menu_update_tmp && cd menu_update_tmp
unzip -oq "$DIR/limit/menu.zip"
chmod +x menu/* 2>/dev/null
ok "$(ls menu/ | wc -l) file di-extract"

echo -e " ${YEL}[3/3]${NC} Install menu baru..."
mv -f menu/* /usr/local/sbin/ 2>/dev/null
rm -rf /tmp/menu_update_tmp
ok "Menu UI updated!"
echo ""

# =============================================
# PART 2: FIX SSH HYBRID CIPHER
# =============================================
echo -e " ${BLD}${VIO}[PART 2]${NC} ${BLD}Fix SSH Hybrid (APK Lama + Baru)${NC}"
echo ""

echo -e " ${YEL}[1/5]${NC} Backup config lama..."
cp -f /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null
cp -f /usr/bin/tun.conf /usr/bin/tun.conf.bak 2>/dev/null
ok "Backup selesai"

echo -e " ${YEL}[2/5]${NC} Tambah cipher hybrid di sshd_config..."
sed -i '/^Ciphers /d' /etc/ssh/sshd_config
sed -i '/^KexAlgorithms /d' /etc/ssh/sshd_config
sed -i '/^MACs /d' /etc/ssh/sshd_config
sed -i '/^HostKeyAlgorithms /d' /etc/ssh/sshd_config
sed -i '/^PubkeyAcceptedAlgorithms /d' /etc/ssh/sshd_config
sed -i '/HYBRID CIPHER/d' /etc/ssh/sshd_config

cat >> /etc/ssh/sshd_config <<'SSHEOF'

# ===== HYBRID CIPHER (Support APK Lama + Baru) =====
Ciphers chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256
MACs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,rsa-sha2-256,ssh-rsa
PubkeyAcceptedAlgorithms +ssh-rsa
SSHEOF

if [ -d /etc/ssh/sshd_config.d ]; then
    cat > /etc/ssh/sshd_config.d/99-hybrid-cipher.conf <<'SSHEOF2'
Ciphers chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256
MACs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,rsa-sha2-256,ssh-rsa
PubkeyAcceptedAlgorithms +ssh-rsa
SSHEOF2
    ok "sshd_config.d/99-hybrid-cipher.conf dibuat"
fi
ok "Cipher hybrid ditambahkan"

echo -e " ${YEL}[3/5]${NC} Ubah WS target ke OpenSSH..."
if [ -f /usr/bin/tun.conf ]; then
    sed -i 's/target_port: 143/target_port: 2222/' /usr/bin/tun.conf
    ok "tun.conf → target_port: 2222"
fi
if [ -f /usr/bin/ws.py ]; then
    sed -i "s/127.0.0.1:143/127.0.0.1:2222/" /usr/bin/ws.py
    ok "ws.py → 127.0.0.1:2222"
fi

echo -e " ${YEL}[4/5]${NC} Restart services..."
_sshd_ok=0
sshd -t 2>/dev/null && _sshd_ok=1

if [ $_sshd_ok -eq 1 ]; then
    ok "sshd_config valid"
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
    ok "SSH restarted"
else
    warn "sshd_config error — kemungkinan cipher tidak compiled-in"
    warn "Menghapus cipher yang tidak didukung..."
    # Fallback: hapus cbc dan 3des, pakai yang pasti ada
    sed -i 's/,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc//g' /etc/ssh/sshd_config
    [ -f /etc/ssh/sshd_config.d/99-hybrid-cipher.conf ] && \
        sed -i 's/,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc//g' /etc/ssh/sshd_config.d/99-hybrid-cipher.conf
    if sshd -t 2>/dev/null; then
        ok "Config diperbaiki (tanpa CBC)"
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
        ok "SSH restarted"
    else
        bad "sshd_config masih error! Restore backup:"
        bad "  cp /etc/ssh/sshd_config.bak.* /etc/ssh/sshd_config"
        bad "  systemctl restart ssh"
    fi
fi

systemctl restart ws 2>/dev/null && ok "WS restarted"

echo -e " ${YEL}[5/5]${NC} Verifikasi..."
echo ""
_ciphers=$(sshd -T 2>/dev/null | grep "^ciphers " | head -1)
for c in aes128-cbc chacha20-poly1305 aes128-ctr aes128-gcm; do
    if echo "$_ciphers" | grep -q "$c"; then
        ok "$c → AKTIF"
    else
        warn "$c → tidak aktif"
    fi
done

_ws_target=$(grep "target_port" /usr/bin/tun.conf 2>/dev/null | head -1 | awk '{print $2}')
[ "$_ws_target" = "2222" ] && ok "WS → OpenSSH (2222)" || warn "WS target: $_ws_target"

echo ""
line
echo -e " ${BLD}${GRN}     UPDATE SELESAI!${NC}"
line
echo ""
echo -e " ${CYN}Yang diupdate:${NC}"
echo -e "   ${GRN}✔${NC} Menu UI (banner, info, status, 2 kolom, submenu)"
echo -e "   ${GRN}✔${NC} Cek Login (IP asli + ISP + Count)"
echo -e "   ${GRN}✔${NC} SSH Hybrid (APK lama + baru)"
echo ""
echo -e " ${CYN}Test koneksi:${NC}"
echo -e "   ${GRN}•${NC} APK Baru → konek seperti biasa"
echo -e "   ${GRN}•${NC} APK Lama → konek seperti biasa"
echo ""
echo -e " ${YEL}Ketik ${BLD}menu${NC}${YEL} untuk lihat tampilan baru${NC}"
echo ""
