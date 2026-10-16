#!/bin/bash
# ============================================================
#  ganti-repo.sh
#  Mengganti semua URL repo "victor3232/xhttp" menjadi repo kamu
#  di SELURUH paket (termasuk rebuild menu.zip otomatis).
#
#  Pemakaian:
#     ./ganti-repo.sh <user-github> <nama-repo>
#  Contoh:
#     ./ganti-repo.sh budi tunnel-test
#     -> semua URL jadi https://raw.githubusercontent.com/budi/tunnel-test/main/
#
#  Jalankan dari dalam folder paket (yang ada premi.sh & limit/).
# ============================================================
set -e

NEW_USER="$1"
NEW_REPO="$2"
if [ -z "$NEW_USER" ] || [ -z "$NEW_REPO" ]; then
    echo "Pemakaian: $0 <user-github> <nama-repo>"
    echo "Contoh   : $0 budi tunnel-test"
    exit 1
fi

OLD="victor3232/xhttp"
NEW="${NEW_USER}/${NEW_REPO}"
BASE="$(cd "$(dirname "$0")" && pwd)"

echo "Mengganti  $OLD  ->  $NEW"
echo "Folder     : $BASE"
echo ""

# Backup singkat
if [ ! -d "$BASE/.bak-ganti-repo" ]; then
    mkdir -p "$BASE/.bak-ganti-repo"
    cp "$BASE/premi.sh" "$BASE/.bak-ganti-repo/premi.sh.bak" 2>/dev/null || true
fi

COUNT=0
while IFS= read -r -d '' f; do
    # lewati file biner & zip
    if ! grep -Iq . "$f" 2>/dev/null; then continue; fi
    case "$f" in *.zip) continue;; esac
    if grep -q "$OLD" "$f" 2>/dev/null; then
        sed -i "s#${OLD}#${NEW}#g" "$f"
        COUNT=$((COUNT+1))
        echo "  diubah: ${f#$BASE/}"
    fi
done < <(find "$BASE" -type f -print0)

# Rebuild menu.zip dari sumber (agar URL di dalam menu juga ikut berubah)
if [ -d "$BASE/limit/menu/menu" ]; then
    ( cd "$BASE/limit/menu" && rm -f ../menu.zip && zip -rq ../menu.zip menu )
    echo ""
    echo "  menu.zip dibuat ulang dari limit/menu/menu"
fi

echo ""
echo "Selesai. $COUNT file diubah."
echo "URL baru: https://raw.githubusercontent.com/${NEW}/main/"
echo ""
echo "LANGKAH SELANJUTNYA:"
echo "  1) Upload SELURUH isi folder ini ke repo ${NEW} (branch main)."
echo "  2) Tambahkan IP VPS tes kamu ke file 'izin', contoh:"
echo "       ### test 2099-12-31 <IP_VPS_BARU>"
echo "  3) Install di VPS BARU (jangan di VPS lama)."
