#!/bin/bash
# Bootstrap installer HITS SSH; gunakan hanya pada VPS khusus yang baru.
set -u
RAW=https://raw.githubusercontent.com/victor3232/xhttp/main/premi.sh
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
if ! wget --https-only --timeout=30 --tries=3 -O "$script" "$RAW"; then echo "Unduhan gagal. Direktori kerja: $stage" >&2; exit 1; fi
if [ ! -s "$script" ] || ! bash -n "$script"; then echo "Installer kosong atau sintaks tidak valid: $script" >&2; exit 1; fi
chmod 700 "$script"
echo "Installer: $script"
echo "Jika SSH putus, sambungkan kembali sebagai root: tmux attach -t $SESSION"
echo 'Installer bersifat interaktif dan mungkin meminta reboot.'
tmux new-session -s "$SESSION" "bash '$script'; status=$?; printf '\nInstaller keluar dengan status %s. Tekan Enter untuk menutup.\n' "$status"; read -r"
