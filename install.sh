#!/bin/bash
# Bootstrap installer HITS SSH; gunakan hanya pada VPS khusus yang baru.
set -u
KBASE=https://raw.githubusercontent.com/victor3232/xhttp
KAPI=https://api.github.com/repos/victor3232/xhttp/commits/main
KSHA=$(wget -qO- --timeout=20 --tries=2 "$KAPI" 2>/dev/null | grep -o '"sha"[[:space:]]*:[[:space:]]*"[0-9a-f]\{40\}"' | head -n1 | grep -o '[0-9a-f]\{40\}')
if [ -n "$KSHA" ]; then RAW="$KBASE/$KSHA/premi.sh"; else RAW="$KBASE/main/premi.sh"; fi
SESSION=kyt-install
if [ "$(id -u)" -ne 0 ]; then echo 'Jalankan sebagai root (sudo -i).' >&2; exit 1; fi
if [ ! -t 0 ] || [ ! -t 1 ]; then echo 'Installer memerlukan terminal interaktif.' >&2; exit 1; fi
if [ ! -r /etc/os-release ]; then echo 'Tidak dapat mendeteksi OS.' >&2; exit 1; fi
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  debian:11|debian:12|debian:13|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) ;;
  *) echo "OS belum didukung: ${ID:-?} ${VERSION_ID:-?}" >&2; exit 1 ;;
esac
if [ "$(uname -m)" != x86_64 ]; then echo 'Installer utama hanya mendukung x86_64.' >&2; exit 1; fi
if command -v tmux >/dev/null 2>&1 && tmux has-session -t "=$SESSION" 2>/dev/null; then
  echo "Sesi $SESSION sudah ada. Sambungkan dengan: tmux attach -t $SESSION"; exit 0
fi
echo 'PERINGATAN: premi.sh dapat menghapus Apache/Nginx, menimpa konfigurasi dan data akun, serta me-reboot VPS.'
echo 'Gunakan hanya pada VPS khusus yang baru. Tinjau dan cadangkan data terlebih dahulu.'
read -r -p 'Ketik LANJUT untuk melanjutkan: ' answer
[ "$answer" = LANJUT ] || { echo 'Dibatalkan.'; exit 1; }
export DEBIAN_FRONTEND=noninteractive
echo 'Memperbarui indeks paket dan memasang tmux, wget, dan sertifikat CA...'
apt-get update || { echo 'apt-get update gagal.' >&2; exit 1; }
apt-get install -y tmux wget ca-certificates || { echo 'Instalasi dependensi gagal.' >&2; exit 1; }
stage=$(mktemp -d /root/.kyt-installer.XXXXXXXX) || exit 1
chmod 700 "$stage"
script="$stage/premi.sh"
if ! wget --https-only --timeout=30 --tries=3 -O "$script" "${RAW}?v=$(date +%s)"; then echo "Unduhan gagal. Direktori kerja: $stage" >&2; exit 1; fi
if [ ! -s "$script" ] || ! bash -n "$script"; then echo "Installer kosong atau sintaks tidak valid: $script" >&2; exit 1; fi
chmod 700 "$script"
echo "Installer: $script"
echo "Jika SSH putus, sambungkan kembali sebagai root: tmux attach -t $SESSION"
echo 'Installer akan lanjut otomatis; reboot otomatis setelah selesai (KYT_NO_REBOOT=1 untuk skip).'
tmux new-session -s "$SESSION" "bash '$script'; status=\$?; printf '\nInstaller keluar dengan status %s. Menutup otomatis dalam 30 detik.\n' \"\$status\"; read -t 30 -r || true"
