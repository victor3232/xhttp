#!/bin/bash
# ============================================================
#  fix-ssh-hybrid.sh
#  Fix SSH agar support APK lama (aes128-cbc) + APK baru
#  Jalankan di VPS sebagai root
# ============================================================
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[0;33m'; NC='\033[0m'
ok()  { echo -e " ${GRN}✔${NC} $*"; }
warn(){ echo -e " ${YEL}!${NC} $*"; }
bad() { echo -e " ${RED}✘${NC} $*"; }

[ "$(id -u)" = "0" ] || { bad "Jalankan sebagai root"; exit 1; }

echo ""
echo -e "${GRN}═══ FIX SSH HYBRID (Support APK Lama + Baru) ═══${NC}"
echo ""

# 1. Backup
echo -e "${YEL}[1/5] Backup file lama...${NC}"
cp -f /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null
cp -f /usr/bin/tun.conf /usr/bin/tun.conf.bak 2>/dev/null
ok "Backup selesai"

# 2. Tambah cipher hybrid di sshd_config
echo -e "${YEL}[2/5] Tambah cipher hybrid di sshd_config...${NC}"
# Hapus baris Ciphers/KexAlgorithms/MACs/HostKeyAlgorithms/PubkeyAccepted lama
sed -i '/^Ciphers /d' /etc/ssh/sshd_config
sed -i '/^KexAlgorithms /d' /etc/ssh/sshd_config
sed -i '/^MACs /d' /etc/ssh/sshd_config
sed -i '/^HostKeyAlgorithms /d' /etc/ssh/sshd_config
sed -i '/^PubkeyAcceptedAlgorithms /d' /etc/ssh/sshd_config

# Tambah di akhir file
cat >> /etc/ssh/sshd_config <<'SSHEOF'

# ===== HYBRID CIPHER (Support APK Lama + Baru) =====
Ciphers chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256
MACs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,rsa-sha2-256,ssh-rsa
PubkeyAcceptedAlgorithms +ssh-rsa
SSHEOF

# Juga di sshd_config.d jika ada
if [ -d /etc/ssh/sshd_config.d ]; then
    cat > /etc/ssh/sshd_config.d/99-hybrid-cipher.conf <<'SSHEOF2'
# HYBRID CIPHER (Support APK Lama + Baru)
Ciphers chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256
MACs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,rsa-sha2-256,ssh-rsa
PubkeyAcceptedAlgorithms +ssh-rsa
SSHEOF2
    ok "sshd_config.d/99-hybrid-cipher.conf dibuat"
fi
ok "Cipher hybrid ditambahkan"

# 3. Ubah tun.conf target ke OpenSSH (2222) bukan Dropbear (143)
echo -e "${YEL}[3/5] Ubah WS target ke OpenSSH...${NC}"
if [ -f /usr/bin/tun.conf ]; then
    sed -i 's/target_port: 143/target_port: 2222/' /usr/bin/tun.conf
    ok "tun.conf → target_port: 2222 (OpenSSH)"
fi

# ws.py juga (kalau ada yang pakai)
if [ -f /usr/bin/ws.py ]; then
    sed -i "s/127.0.0.1:143/127.0.0.1:2222/" /usr/bin/ws.py
    ok "ws.py → 127.0.0.1:2222 (OpenSSH)"
fi

# 4. Restart services
echo -e "${YEL}[4/5] Restart SSH & WS services...${NC}"
# Test config dulu
sshd -t 2>/dev/null
if [ $? -ne 0 ]; then
    warn "sshd_config ada error, cek manual: sshd -t"
    warn "Kemungkinan cipher tidak di-compile. Hapus cipher yang error."
else
    ok "sshd_config valid"
fi

systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
ok "SSH restarted"

systemctl restart ws 2>/dev/null
ok "WS restarted"

# 5. Verifikasi
echo -e "${YEL}[5/5] Verifikasi...${NC}"
echo ""

# Cek cipher yang aktif
_ciphers=$(sshd -T 2>/dev/null | grep "^ciphers " | head -1)
if echo "$_ciphers" | grep -q "aes128-cbc"; then
    ok "aes128-cbc AKTIF (APK lama support)"
else
    bad "aes128-cbc TIDAK aktif — cek apakah compiled-in: ssh -Q cipher"
fi

if echo "$_ciphers" | grep -q "chacha20-poly1305"; then
    ok "chacha20-poly1305 AKTIF (APK baru support)"
else
    bad "chacha20-poly1305 TIDAK aktif"
fi

if echo "$_ciphers" | grep -q "aes128-ctr"; then
    ok "aes128-ctr AKTIF (universal)"
else
    bad "aes128-ctr TIDAK aktif"
fi

# Cek WS target
_ws_target=$(grep "target_port" /usr/bin/tun.conf 2>/dev/null | head -1 | awk '{print $2}')
if [ "$_ws_target" = "2222" ]; then
    ok "WS target → OpenSSH port 2222"
else
    warn "WS target: $_ws_target (harusnya 2222)"
fi

echo ""
echo -e "${GRN}═══ SELESAI ═══${NC}"
echo ""
echo -e "Test dari client:"
echo -e "  ${GRN}APK Baru:${NC} connect seperti biasa"
echo -e "  ${GRN}APK Lama:${NC} connect seperti biasa (aes128-cbc sekarang didukung)"
echo ""
