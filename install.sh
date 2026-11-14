#!/bin/bash
# ============================================================
#  WRAPPER INSTALLER HITS SSH PANEL
#  Jalankan:
#    wget --no-check-certificate https://raw.githubusercontent.com/victor3232/xhttp/main/install.sh && chmod +x install.sh && ./install.sh
#
#  Fitur:
#    - Install tmux otomatis jika belum ada
#    - Jalankan premi.sh di dalam sesi tmux "install"
#    - apt update + fix Debian/Ubuntu sebelum install
#    - Kalau koneksi putus, tinggal: tmux attach -t install
#    - Kalau tmux tidak bisa (OpenVZ/minimal), fallback ke screen
#    - Kalau keduanya tidak ada, jalankan langsung
# ============================================================
export DEBIAN_FRONTEND=noninteractive
wget() { command wget -4 --no-check-certificate "$@"; }
curl() { command curl -4 -k "$@"; }
export -f wget curl 2>/dev/null || true

RAW="https://raw.githubusercontent.com/victor3232/xhttp/main"
SESI="install"
SCRIPT="/root/premi.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

clear
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e " ${BOLD}  HITS SSH — INSTALLER OTOMATIS${NC}"
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ---- pastikan root ----
if [ "$(id -u)" -ne 0 ]; then
    echo -e " ${RED}[!] Script harus dijalankan sebagai root.${NC}"
    echo -e "     Ketik: ${CYAN}sudo -i${NC} lalu jalankan lagi."
    exit 1
fi

# ---- cek OS ----
OS_ID=$(grep -w "^ID" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
OS_VER=$(grep -w "^VERSION_ID" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
echo -e " ${GREEN}[✓]${NC} OS    : ${BOLD}${OS_ID} ${OS_VER}${NC}"
echo -e " ${GREEN}[✓]${NC} Arch  : $(uname -m)"
echo -e " ${GREEN}[✓]${NC} Kernel: $(uname -r)"
echo ""

# ---- step 1: apt update & fix ----
echo -e " ${CYAN}[1/4]${NC} Update sistem & pasang dependensi dasar..."

# Nonaktifkan interaksi needrestart
if [ -f /etc/needrestart/needrestart.conf ]; then
    sed -i "s/#\?\$nrconf{restart}.*$/\$nrconf{restart} = 'a';/" \
        /etc/needrestart/needrestart.conf 2>/dev/null
    grep -q "nrconf{restart}" /etc/needrestart/needrestart.conf || \
        echo "\$nrconf{restart} = 'a';" >> /etc/needrestart/needrestart.conf
fi

# Fix dpkg jika terganggu
dpkg --configure -a 2>/dev/null
apt-get install -f -y -qq 2>/dev/null

# apt update dengan retry
for i in 1 2 3; do
    DEBIAN_FRONTEND=noninteractive apt-get update -y -qq 2>/dev/null && break
    echo -e "   ${YELLOW}apt update gagal, coba ulang ($i/3)...${NC}"
    sleep 3
done

# upgrade non-interaktif
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" 2>/dev/null

echo -e "   ${GREEN}→ sistem sudah diperbarui${NC}"

# ---- step 2: pasang tmux / screen ----
echo -e " ${CYAN}[2/4]${NC} Memasang tmux & wget..."

DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tmux wget curl screen 2>/dev/null
command -v tmux   >/dev/null 2>&1 && HAS_TMUX=1   || HAS_TMUX=0
command -v screen >/dev/null 2>&1 && HAS_SCREEN=1 || HAS_SCREEN=0

if [ "$HAS_TMUX" = "1" ]; then
    echo -e "   ${GREEN}→ tmux tersedia${NC}"
elif [ "$HAS_SCREEN" = "1" ]; then
    echo -e "   ${YELLOW}→ tmux tidak ada, pakai screen${NC}"
else
    echo -e "   ${YELLOW}→ tmux & screen tidak ada, jalankan langsung${NC}"
fi

# ---- step 3: download premi.sh ----
echo -e " ${CYAN}[3/4]${NC} Mengunduh premi.sh..."
rm -f "$SCRIPT"
for i in 1 2 3; do
    wget -q --timeout=30 -O "$SCRIPT" "${RAW}/premi.sh" 2>/dev/null && \
        [ -s "$SCRIPT" ] && break
    curl -fsSL --max-time 30 -o "$SCRIPT" "${RAW}/premi.sh" 2>/dev/null && \
        [ -s "$SCRIPT" ] && break
    echo -e "   ${YELLOW}Unduhan gagal, coba ulang ($i/3)...${NC}"
    sleep 3
done

if [ ! -s "$SCRIPT" ]; then
    echo -e " ${RED}[!] Gagal mengunduh premi.sh. Periksa koneksi internet.${NC}"
    exit 1
fi

chmod +x "$SCRIPT"
LINES=$(wc -l < "$SCRIPT")
echo -e "   ${GREEN}→ premi.sh siap ($LINES baris)${NC}"

# ---- step 4: jalankan di tmux/screen ----
echo -e " ${CYAN}[4/4]${NC} Menjalankan installer..."
echo ""
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Buat tmux config minimal agar status bar informatif
cat > /root/.tmux-install.conf << 'TMUXCFG'
set -g status-style bg=colour235,fg=colour255
set -g status-left "#[fg=colour46,bold] ● INSTALLER HITS SSH  "
set -g status-right "#[fg=colour220] Jangan tutup window ini! | %H:%M "
set -g status-left-length 40
set -g status-right-length 50
set -g mouse on
set -g history-limit 50000
TMUXCFG

if [ "$HAS_TMUX" = "1" ]; then
    # Kalau sesi sudah ada (jalankan ulang), hapus dulu
    tmux kill-session -t "$SESI" 2>/dev/null || true

    echo -e " ${GREEN}[✓]${NC} Installer berjalan di tmux sesi ${BOLD}'${SESI}'${NC}"
    echo ""
    echo -e " ${YELLOW}  ⚠  Jangan tutup terminal ini selama instalasi!${NC}"
    echo -e " ${YELLOW}     Kalau koneksi SSH putus, sambung kembali lalu ketik:${NC}"
    echo -e "     ${CYAN}${BOLD}tmux attach -t ${SESI}${NC}"
    echo ""
    echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    sleep 2

    # Jalankan premi.sh di dalam tmux, tampilkan sesi di terminal ini
    tmux new-session -s "$SESI" -f /root/.tmux-install.conf \
        "bash $SCRIPT; echo ''; echo '=== INSTALLER SELESAI ==='; read -n1 -s -rp 'Tekan tombol apa saja...'"

elif [ "$HAS_SCREEN" = "1" ]; then
    echo -e " ${GREEN}[✓]${NC} Installer berjalan di screen sesi ${BOLD}'${SESI}'${NC}"
    echo -e " ${YELLOW}     Kalau koneksi SSH putus, sambung kembali lalu ketik:${NC}"
    echo -e "     ${CYAN}${BOLD}screen -r ${SESI}${NC}"
    echo ""
    sleep 2
    screen -S "$SESI" bash "$SCRIPT"
else
    echo -e " ${YELLOW}[!]${NC} Langsung tanpa tmux/screen."
    echo -e " ${YELLOW}    Jangan tutup SSH selama instalasi berlangsung!${NC}"
    echo ""
    sleep 2
    bash "$SCRIPT"
fi

rm -f /root/.tmux-install.conf
