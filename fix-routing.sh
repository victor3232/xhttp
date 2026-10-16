#!/bin/bash
# ============================================================
#  fix-routing.sh
#  Memperbaiki config Xray yang koneksinya DI-DROP oleh Xray v26
#  karena routing merujuk outbound tag yang tidak didefinisikan
#  (direct/proxy/block/reject/dnsOut/api).
#
#  Jalankan DI VPS yang sudah terinstall:
#     bash fix-routing.sh
# ============================================================
CFG=/etc/xray/config.json
if [ ! -f "$CFG" ]; then
    echo "Config tidak ditemukan: $CFG"
    exit 1
fi

cp "$CFG" "$CFG.bak.$(date +%Y%m%d%H%M%S)"

python3 - "$CFG" <<'PY'
import sys, re
p = sys.argv[1]
s = open(p).read()

if re.search(r'"tag"\s*:\s*"direct"', s):
    print("Sudah diperbaiki (outbound tag 'direct' ada). Tidak diubah.")
    sys.exit(0)

new = '''"outbounds": [
    { "protocol": "freedom", "settings": {}, "tag": "direct" },
    { "protocol": "freedom", "settings": {}, "tag": "proxy" },
    { "protocol": "freedom", "settings": {}, "tag": "dnsOut" },
    { "protocol": "freedom", "settings": {}, "tag": "api" },
    { "protocol": "blackhole", "settings": {}, "tag": "block" },
    { "protocol": "blackhole", "settings": {}, "tag": "blocked" },
    { "protocol": "blackhole", "settings": {}, "tag": "reject" }
  ]'''

m = re.search(r'"outbounds"\s*:\s*\[.*?\]', s, re.S)
if not m:
    print("Blok \"outbounds\" tidak ditemukan!")
    sys.exit(2)

s = s[:m.start()] + new + s[m.end():]
open(p, 'w').write(s)
print("Outbounds berhasil diperbaiki.")
PY
rc=$?
if [ $rc -ne 0 ]; then
    echo "Perbaikan gagal (kode $rc)."
    exit $rc
fi

if command -v xray >/dev/null 2>&1; then
    if xray -test -config "$CFG" >/tmp/xraytest.log 2>&1; then
        echo "Config OK."
    else
        echo "PERINGATAN: config gagal diuji:"
        tail -n 3 /tmp/xraytest.log
    fi
fi

systemctl restart xray && echo "Xray di-restart." || echo "Gagal restart xray."
