#!/bin/bash
# ============================================================
#  FIX HTTPUpgrade / XHTTP  (jalur 443 lewat HAProxy)
#  Masalah : backend FTVPN di /etc/haproxy/haproxy.cfg pakai "mode http"
#            -> WS jalan, tapi HTTPUpgrade RUSAK ("unrecognized reply")
#  Solusi  : ubah backend FTVPN menjadi "mode tcp"
#  Aman    : WS/TLS/nginx tetap jalan (sudah diuji), idempotent.
# ============================================================
set -u

CFG="/etc/haproxy/haproxy.cfg"

echo "== Fix HTTPUpgrade (haproxy backend FTVPN -> mode tcp) =="

if [ ! -f "$CFG" ]; then
  echo "GAGAL: $CFG tidak ditemukan."
  exit 1
fi

# --- cek apakah sudah mode tcp ---
if awk '/^backend[ \t]+FTVPN[ \t]*$/{f=1;next} f&&/^backend/{f=0} f&&/^[ \t]*mode[ \t]+tcp/{print "ok";exit}' "$CFG" | grep -q ok; then
  echo "INFO    : backend FTVPN sudah mode tcp (tidak ada perubahan)."
  CHANGED=0
else
  # --- backup ---
  BAK="${CFG}.bak.$(date +%Y%m%d-%H%M%S)"
  cp -a "$CFG" "$BAK" && echo "Backup  : $BAK"

  # --- ubah mode http -> mode tcp HANYA pada blok 'backend FTVPN' ---
  sed -i '/^backend[ \t]\+FTVPN[ \t]*$/,/^backend /{s/^\([ \t]*\)mode[ \t]\+http/\1mode tcp/}' "$CFG"

  if awk '/^backend[ \t]+FTVPN[ \t]*$/{f=1;next} f&&/^backend/{f=0} f&&/^[ \t]*mode[ \t]+tcp/{print "ok";exit}' "$CFG" | grep -q ok; then
    echo "OK      : backend FTVPN diubah ke mode tcp."
    CHANGED=1
  else
    echo "PERINGATAN: pola 'backend FTVPN' + 'mode http' tidak ditemukan."
    [ -n "${BAK:-}" ] && cp -a "$BAK" "$CFG"
    exit 2
  fi
fi

# --- validasi & restart ---
echo "Validasi:"
if haproxy -c -f "$CFG" >/tmp/hapcheck.log 2>&1; then
  echo "  Config OK"
else
  echo "  Config TIDAK valid -> restore backup"
  cat /tmp/hapcheck.log
  [ "${CHANGED:-0}" = 1 ] && [ -n "${BAK:-}" ] && cp -a "$BAK" "$CFG"
  exit 1
fi

if [ "${CHANGED:-0}" = 1 ]; then
  systemctl restart haproxy 2>/dev/null || service haproxy restart 2>/dev/null
  sleep 1
  if systemctl is-active --quiet haproxy 2>/dev/null; then
    echo "HAProxy : aktif ✅"
  else
    echo "HAProxy : cek manual (systemctl status haproxy)"
  fi
fi

echo
echo "SELESAI. Silakan tes akun HTTPUpgrade / XHTTP di port 443."
[ -n "${BAK:-}" ] && echo "Balik ke semula bila perlu:  cp -a $BAK $CFG && systemctl restart haproxy"
