# -*- coding: utf-8 -*-
# ============================================================
#  modules/backup.py - BACKUP & RESTORE
#   1) Backup VPS  : config + akun + database bot -> 1 file .zip
#   2) Backup DB   : database bot saja (saldo/pesanan/deposit)
#   3) Restore     : upload kembali file-nya ke bot
#  Tidak butuh rclone / Google Drive / email.
# ============================================================
import os
import glob
import shutil
import sqlite3
import subprocess
import zipfile
import tempfile
import datetime as DT

import requests

from kyt import *
from kyt import store_lib as S

BACKUP_DIR = "/root/backup"


def _db_bot():
    """Lokasi database bot (ikut WorkingDirectory service /usr/bin)."""
    p = os.path.abspath(S.DB_PATH)
    if os.path.isfile(p):
        return p
    for kandidat in ("/usr/bin/kyt/database.db", "/usr/bin/database.db",
                     "/usr/local/kyt/database.db", "/root/kyt/database.db"):
        if os.path.isfile(kandidat):
            return kandidat
    return p


def _var_bot():
    return os.path.join(os.path.dirname(_db_bot()), "var.txt")

def _db_web():
    """Database website VPNFree, kalau website terpasang."""
    p = "/opt/kyt-web/data/web.db"
    return p if os.path.isfile(p) else ""

def _snapshot_db(src, dst):
    """Salin database SQLite dengan backup API (WAL-safe, tidak korup)."""
    if not os.path.isfile(src):
        return False
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            os.remove(dst + suffix)
        except Exception:
            pass
    s = sqlite3.connect("file:%s?mode=ro" % src, uri=True, timeout=30)
    d = sqlite3.connect(dst, timeout=30)
    try:
        with d:
            s.backup(d)
        d.execute("PRAGMA journal_mode=DELETE")
        integ = d.execute("PRAGMA integrity_check").fetchone()
        if not integ or str(integ[0]).lower() != "ok":
            raise RuntimeError("integrity_check: %s" % (integ,))
    finally:
        d.close()
        s.close()
    for suffix in ("-wal", "-shm", "-journal"):
        try:
            os.remove(dst + suffix)
        except Exception:
            pass
    return True

def _cek_sqlite(path):
    """True kalau file SQLite sehat."""
    try:
        with sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=20) as c:
            integ = c.execute("PRAGMA integrity_check").fetchone()
            return bool(integ) and str(integ[0]).lower() == "ok"
    except Exception:
        return False

def _pulihkan_db(src, dst=None):
    """Tulis database dari src ke target (default: database bot). WAL-safe."""
    dst = dst or _db_bot()
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.isfile(dst):
        try:
            _snapshot_db(dst, dst + ".sebelum-restore")
        except Exception:
            pass
    for suffix in ("-wal", "-shm", "-journal"):
        try:
            os.remove(dst + suffix)
        except Exception:
            pass
    s = sqlite3.connect("file:%s?mode=ro" % src, uri=True, timeout=30)
    d = sqlite3.connect(dst, timeout=30)
    try:
        with d:
            s.backup(d)
        d.execute("PRAGMA journal_mode=DELETE")
        integ = d.execute("PRAGMA integrity_check").fetchone()
        if not integ or str(integ[0]).lower() != "ok":
            raise RuntimeError("integrity_check: %s" % (integ,))
    finally:
        d.close()
        s.close()
    for suffix in ("-wal", "-shm", "-journal"):
        try:
            os.remove(dst + suffix)
        except Exception:
            pass
    return True

# berkas penting yang ikut di-backup
BERKAS = [
    # ---- akun VPN (data buyer) ----
    "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
    "/etc/ssh/.ssh.db", "/etc/ssh/sshd_config",
    "/etc/vmess/.vmess.db",
    "/etc/vless/.vless.db",
    "/etc/trojan/.trojan.db",
    "/etc/shadowsocks/.shadowsocks.db",
    "/etc/l2tp/.l2tp.db", "/etc/l2tp/psk",
    "/etc/ppp/chap-secrets",        # akun L2TP (CHAP)
    "/etc/ipsec.secrets",           # akun IKEv2 (EAP)
    "/etc/ipsec.conf",
    "/etc/kyt-theme.conf",
    "/etc/kyt-dns-mode",
    "/etc/kyt-license.conf",
    "/usr/local/sbin/slowdns-router",
    "/etc/systemd/system/slowdns-router.service",
    # ---- konfigurasi service ----
    "/etc/xray/config.json",
    "/etc/xray/domain", "/etc/xray/city", "/etc/xray/isp", "/etc/xray/dns",
    "/etc/xray/xray.crt", "/etc/xray/xray.key",   # sertifikat TLS Xray
    "/etc/haproxy/haproxy.cfg", "/etc/haproxy/hap.pem",
    "/etc/nginx/nginx.conf", "/etc/nginx/conf.d/xray.conf",
    "/etc/default/dropbear",
    "/etc/kyt.txt",
    "/etc/kyt/trial.conf",
    "/etc/kyt/jeda-mullog.conf",
    "/etc/kyt-web.conf",
    "/etc/kyt-web-mail.key",
    "/root/kyt-web-admin.txt",
    "/etc/nginx/conf.d/vpnfree.conf",
    "/etc/haproxy/vpnfree.pem",
    "/etc/systemd/system/kyt-web.service",
    "/etc/ssl/kyt-web/vpnfree.crt",
    "/etc/ssl/kyt-web/vpnfree.key",
    # ---- payment gateway bot ----
    "/usr/bin/kyt/gomerch_token.json",
    # ---- profil akun (file .txt yang dibagikan ke buyer) ----
    "/var/www/html/ssh-80.txt",
]

# folder yang ikut di-backup (rekursif)
# File di dalam FOLDER yang lebih besar dari ini akan DILEWATI.
# (data akun & profil hampir selalu < 100 KB)
BATAS_FILE = 8 * 1024 * 1024   # 8 MB

# CATATAN PENTING: /usr/local/share/xray SENGAJA TIDAK di-backup.
# Isinya geoip.dat (~16 MB) + geosite.dat (~11 MB) = ~27 MB data
# routing yang diunduh otomatis oleh installer premi.sh.
# Bukan data buyer -> kalau ikut, file backup jadi besar tanpa guna.
FOLDER = [
    "/root/akun",          # config akun xray
    "/root/slowdns",       # domain/key/upstream SlowDNS
    "/var/www/html",       # profil akun buyer (.txt)
    "/etc/openvpn",        # sertifikat & config OVPN
    "/etc/letsencrypt",    # sertifikat SSL
    "/opt/kyt-web",        # aplikasi + data + tema website
    "/etc/ssl/kyt-web",    # sertifikat website
    "/etc/nginx",          # konfigurasi nginx website
    "/etc/haproxy",        # konfigurasi haproxy website
    "/etc/kyt",            # trial, jeda-mullog, limit IP
    "/etc/limit",          # pemakaian kuota akun
    "/etc/bot",            # token/admin bot
]

# hanya path dengan awalan ini yang boleh ditulis saat restore (anti zip-slip)
IZIN = ("etc/xray/", "etc/ssh/", "etc/vmess/", "etc/vless/", "etc/trojan/",
        "etc/shadowsocks/", "etc/l2tp/", "etc/ppp/", "etc/haproxy/",
        "etc/nginx/", "etc/openvpn/", "etc/letsencrypt/",
        "etc/default/", "etc/kyt/", "etc/limit/", "etc/bot/",
        "etc/systemd/system/", "root/akun/", "root/slowdns/",
        "usr/bin/kyt/", "usr/local/sbin/slowdns-router",
        "opt/kyt-web/", "etc/ssl/kyt-web/",
        "var/www/html/", "usr/local/share/xray/")
IZIN_TEPAT = ("etc/passwd", "etc/group", "etc/shadow", "etc/gshadow",
              "etc/ipsec.secrets", "etc/ipsec.conf", "etc/kyt.txt",
              "etc/kyt-theme.conf", "etc/kyt-dns-mode", "etc/kyt-license.conf",
              "etc/kyt-web.conf", "etc/kyt-web-mail.key",
              "root/kyt-web-admin.txt")


def _izin(arc):
    return arc in IZIN_TEPAT or arc.startswith(IZIN)


# ---------------- backup ----------------
def buat_backup_vps():
    """Bikin 1 file zip berisi semua data penting. Return (path, jumlah_file)."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    nama = "kyt-backup-%s.zip" % DT.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(BACKUP_DIR, nama)
    n = 0
    dilewati_besar = []
    pasangan = [(f, f.lstrip("/")) for f in BERKAS]
    # database & var bot selalu disimpan dengan nama tetap
    pasangan.append((_db_bot(), "usr/bin/kyt/database.db"))
    pasangan.append((_var_bot(), "usr/bin/kyt/var.txt"))
    if _db_web():
        pasangan.append((_db_web(), "opt/kyt-web/data/web.db"))
    tmpdb = tempfile.mkdtemp(prefix="kytbkdb-")
    sudah = set()
    try:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, strict_timestamps=False) as z:
            for f, arc in pasangan:
                if not os.path.isfile(f) or arc in sudah:
                    continue
                if f in (_db_bot(), _db_web()):
                    # Snapshot konsisten, bukan menyalin file DB yang sedang dipakai.
                    snap = os.path.join(tmpdb, "database-%d.db" % (n + 1))
                    if _snapshot_db(f, snap):
                        z.write(snap, arc)
                        n += 1
                        sudah.add(arc)
                    else:
                        raise RuntimeError("gagal snapshot database: %s" % f)
                else:
                    z.write(f, arc)
                    n += 1
                    sudah.add(arc)
            for d in FOLDER:
                if not os.path.isdir(d):
                    continue
                for root, _dirs, files in os.walk(d):
                    for fn in files:
                        p = os.path.join(root, fn)
                        # DB bot/web sudah ditulis sebagai snapshot di atas.
                        if os.path.abspath(p) in (
                                os.path.abspath(_db_bot()),
                                os.path.abspath(_db_web() or "/nonexistent")):
                            continue
                        # Jangan ikutkan WAL/journal lama: bisa merusak DB saat restore.
                        if p.endswith(("-wal", "-shm", "-journal")):
                            continue
                        try:
                            if os.path.getsize(p) > BATAS_FILE:
                                dilewati_besar.append("%s (%.1f MB)"
                                                      % (p, os.path.getsize(p) / 1048576.0))
                                continue
                        except Exception:
                            pass
                        arc = p.lstrip("/")
                        if arc in sudah:
                            continue
                        z.write(p, arc)
                        sudah.add(arc)
                        n += 1
    finally:
        shutil.rmtree(tmpdb, ignore_errors=True)
    if dilewati_besar:
        logging.info("backup: %d file besar dilewati", len(dilewati_besar))
    return path, n


def buat_backup_db():
    """Copy database bot -> /root/backup. Return path."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    if not os.path.isfile(_db_bot()):
        return None
    nama = "kyt-db-%s.db" % DT.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(BACKUP_DIR, nama)
    # WAL-safe: jangan copy file DB mentah saat bot sedang menulis.
    _snapshot_db(_db_bot(), path)
    return path


def backup_db_harian(simpan=10):
    """Backup otomatis 1x per hari (dipanggil dari loop background)."""
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        if not os.path.isfile(_db_bot()):
            return None
        dst = os.path.join(BACKUP_DIR, "kyt-db-%s.db" % DT.date.today().strftime("%Y%m%d"))
        if not os.path.exists(dst):
            _snapshot_db(_db_bot(), dst)
        for f in sorted(glob.glob(os.path.join(BACKUP_DIR, "kyt-db-*.db")))[:-simpan]:
            try:
                os.remove(f)
            except Exception:
                pass
        return dst
    except Exception as e:
        logging.error("backup db harian: %s", e)
        return None


def ringkasan():
    """Info jumlah data di database bot."""
    try:
        x = S.db()
        u = x.execute("SELECT COUNT(*) c FROM store_user").fetchone()["c"]
        p = x.execute("SELECT COUNT(*) c FROM pesanan").fetchone()["c"]
        d = x.execute("SELECT COUNT(*) c FROM deposit").fetchone()["c"]
        s = x.execute("SELECT COALESCE(SUM(saldo),0) s FROM store_user").fetchone()["s"]
        x.close()
        ukuran = os.path.getsize(_db_bot()) if os.path.isfile(_db_bot()) else 0
        return ("user: %d | akun terjual: %d | deposit: %d | total saldo: %s | ukuran db: %.1f KB"
                % (u, p, d, S.rupiah(s), ukuran / 1024.0))
    except Exception as e:
        return "tidak bisa dibaca: %s" % e


# ---------------- restore ----------------
# berkas yang WAJIB ada di dalam zip backup (kalau tidak, restore ditolak)
WAJIB_BACKUP = [
    "usr/bin/kyt/database.db",
    "etc/xray/config.json",
    "etc/passwd",
]


def cek_backup(path_zip):
    """Periksa isi zip backup sebelum dipulihkan.
    Return (ok, pesan, daftar_file_penting)."""
    if not os.path.isfile(path_zip):
        return False, "File tidak ditemukan.", []
    try:
        with zipfile.ZipFile(path_zip) as z:
            nama = z.namelist()
            rusak = z.testzip()
            if rusak:
                return False, "File di dalam zip rusak: %s" % rusak, []
            # database bot & website wajib bisa dibuka & sehat
            for dbarc, label in (("usr/bin/kyt/database.db", "bot"),
                                 ("opt/kyt-web/data/web.db", "website")):
                if dbarc in nama:
                    tmpdb = tempfile.mkdtemp(prefix="kytcek-")
                    try:
                        z.extract(dbarc, tmpdb)
                        dbf = os.path.join(tmpdb, dbarc)
                        if not _cek_sqlite(dbf):
                            return False, ("Database %s di dalam zip rusak / bukan SQLite."
                                           % label), []
                    finally:
                        shutil.rmtree(tmpdb, ignore_errors=True)
    except Exception as e:
        return False, "Zip rusak / tidak bisa dibuka: %s" % e, []
    if not nama:
        return False, "Zip kosong.", []

    ada = set(nama)
    hilang = [w for w in WAJIB_BACKUP if w not in ada]
    penting = [n for n in nama if n in (
        "usr/bin/kyt/database.db", "opt/kyt-web/data/web.db",
        "etc/xray/config.json", "etc/passwd",
        "etc/shadow", "etc/vmess/.vmess.db", "etc/vless/.vless.db",
        "etc/trojan/.trojan.db", "etc/shadowsocks/.shadowsocks.db",
        "etc/l2tp/.l2tp.db", "etc/ppp/chap-secrets", "etc/ipsec.secrets",
        "etc/xray/xray.crt", "etc/haproxy/hap.pem",
        "usr/bin/kyt/gomerch_token.json", "etc/bot/.bot.db",
        "etc/kyt-web.conf", "etc/kyt-web-mail.key",
    )]
    if hilang:
        return False, ("Backup tidak lengkap. Tidak ada: %s"
                       % ", ".join(hilang)), penting
    return True, "Backup lengkap (%d file)." % len(nama), penting


# geoip/geosite TIDAK di-backup (besar), tapi DIBUTUHKAN Xray.
# Kalau hilang (VPS baru), unduh ulang otomatis.
GEO = [
    ("/usr/local/share/xray/geoip.dat",
     "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"),
    ("/usr/local/share/xray/geosite.dat",
     "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"),
]


def pastikan_geo():
    """Pastikan geoip.dat & geosite.dat ada. Return (ok, pesan)."""
    kurang = [(p, u) for p, u in GEO if not os.path.isfile(p)]
    if not kurang:
        return True, ""
    gagal = []
    for path, url in kurang:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            r = requests.get(url, timeout=180, stream=True,
                             headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200 and r.content and len(r.content) > 100000:
                with open(path, "wb") as f:
                    f.write(r.content)
                logging.info("geo diunduh: %s (%.1f MB)",
                             path, len(r.content) / 1048576.0)
            else:
                gagal.append(os.path.basename(path))
        except Exception as e:
            logging.error("unduh %s gagal: %s", path, e)
            gagal.append(os.path.basename(path))
    if gagal:
        return False, ("geoip/geosite belum ada: %s.\n"
                       "Jalankan installer panel (premi.sh) atau unduh manual:\n"
                       "`wget -O /usr/local/share/xray/geoip.dat %s`"
                       % (", ".join(gagal), GEO[0][1]))
    return True, "geoip/geosite diunduh ulang."


def _svc_bot():
    """Nama service systemd untuk bot ini, atau None kalau tidak jalan
       sebagai service."""
    for nama in ("kyt", "kyt-bot"):
        try:
            r = subprocess.run(["systemctl", "list-unit-files", nama + ".service"],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=10)
            if (nama + ".service") in (r.stdout or b"").decode(errors="ignore"):
                return nama
        except Exception:
            pass
    return None


def _jadwalkan_restart_bot(detik=12):
    """Restart service BOT nanti (± detik), dari proses TERPISAH.

    Kenapa tidak langsung? Karena kalau 'systemctl restart kyt' dijalankan
    dari dalam bot, proses bot MATI sebelum pesan hasil restore terkirim
    -> user hanya melihat 'Memulihkan...' selamanya.
    systemd-run membuat timer mandiri yang TIDAK ikut mati saat bot
    restart, jadi pesan tetap terkirim lebih dulu.
    Return nama cara yang dipakai, atau None kalau gagal.
    """
    svc = _svc_bot()
    if not svc:
        return None
    uniq = DT.datetime.now().strftime("%H%M%S")
    # 1) systemd-run -> paling andal (timer mandiri)
    try:
        r = subprocess.run(
            ["systemd-run", "--on-active=%d" % max(3, int(detik)),
             "--unit=kyt-restore-%s" % uniq, "--collect",
             "systemctl", "restart", svc],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        if r.returncode == 0:
            return "systemd-run"
    except Exception:
        pass
    # 2) at
    try:
        if shutil.which("at"):
            r = subprocess.run(
                "echo 'sleep %d; systemctl restart %s' | at now" % (max(3, int(detik)), svc),
                shell=True, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=15)
            if r.returncode == 0:
                return "at"
    except Exception:
        pass
    # Cara lain tidak aman: proses lain masih satu cgroup dengan bot,
    # jadi ikut mati saat bot restart. Mendingan minta restart manual.
    return None


def _service_ada(nama):
    """True kalau service benar-benar ada (systemd unit ATAU init.d script)."""
    for d in ("/lib/systemd/system", "/usr/lib/systemd/system"):
        if os.path.isfile(os.path.join(d, nama + ".service")):
            return True
    try:
        r = subprocess.run(["systemctl", "list-unit-files", nama + ".service"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        if (nama + ".service") in (r.stdout or b"").decode(errors="ignore"):
            return True
    except Exception:
        pass
    # SysV init script (mis. xl2tpd di Debian 13 tidak punya unit systemd)
    p = "/etc/init.d/" + nama
    try:
        return os.path.isfile(p) and os.access(p, os.X_OK)
    except Exception:
        return False


def _service_aksi(nama, aksi="restart"):
    """Jalankan aksi pada service. Coba systemctl dulu, lalu init.d/service."""
    kandidat = [["systemctl", aksi, nama]]
    if aksi in ("reload", "reload-or-restart"):
        kandidat.append(["systemctl", "restart", nama])
    kandidat.append(["/etc/init.d/%s" % nama, aksi])
    kandidat.append(["service", nama, aksi])
    for c in kandidat:
        try:
            r = subprocess.run(c, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=90)
            if r.returncode == 0:
                return True
        except Exception:
            pass
    return False


def _unit_openvpn():
    """Nama instance openvpn@... yang ada (kalau pakai template)."""
    try:
        r = subprocess.run(["systemctl", "list-unit-files", "--no-legend",
                            "openvpn@*.service"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        return [l.split()[0] for l in (r.stdout or b"").decode(errors="ignore").splitlines()
                if l.split()]
    except Exception:
        return []


def _muat_ulang_service():
    """Restart semua service VPN yang ADA (kecuali bot 'kyt').

    Return (berhasil, gagal). Service yang tidak ada DILEWATI, jadi tidak
    muncul sebagai 'gagal' palsu. SysV (mis. xl2tpd) ikut ditangani.
    """
    daftar = [("xray", "restart"),
              ("haproxy", "restart"),
              ("nginx", "restart"),
              ("xl2tpd", "restart"),
              ("strongswan-starter", "restart"),
              ("ipsec", "restart"),
              ("openvpn", "restart")]
    for u in _unit_openvpn():
        daftar.append((u, "restart"))
    daftar += [("ws", "restart"),
               ("udp-mini-1", "restart"),
               ("udp-mini-2", "restart"),
               ("udp-mini-3", "restart"),
               ("dropbear", "restart"),
               ("slowdns", "restart")]
    # sshd: pakai reload supaya sesi SSH yang sedang terbuka tidak terputus
    for nama_ssh in ("ssh", "sshd"):
        if _service_ada(nama_ssh):
            daftar.append((nama_ssh, "reload-or-restart"))
            break

    berhasil, gagal = [], []
    for nama, aksi in daftar:
        if not _service_ada(nama):
            continue
        if _service_aksi(nama, aksi):
            berhasil.append(nama)
        else:
            gagal.append(nama)
    return berhasil, gagal


def restore_vps(path_zip):
    """Terapkan isi file zip ke sistem. Return (ok, pesan)."""
    ok_cek, pesan_cek, _p = cek_backup(path_zip)
    if not ok_cek:
        return False, pesan_cek

    tmp = tempfile.mkdtemp(prefix="kytrestore-")
    try:
        with zipfile.ZipFile(path_zip) as z:
            for n in z.namelist():
                if n.startswith("/") or ".." in n.replace("\\", "/").split("/"):
                    shutil.rmtree(tmp, ignore_errors=True)
                    return False, "Zip berisi path tidak aman: %s" % n
            z.extractall(tmp)
        for dbarc, label in (("usr/bin/kyt/database.db", "bot"),
                             ("opt/kyt-web/data/web.db", "website")):
            dbf = os.path.join(tmp, dbarc)
            if os.path.isfile(dbf) and not _cek_sqlite(dbf):
                shutil.rmtree(tmp, ignore_errors=True)
                return False, ("Database %s di dalam zip rusak / bukan SQLite." % label)
    except Exception as e:
        shutil.rmtree(tmp, ignore_errors=True)
        return False, "Zip rusak / tidak bisa dibuka: %s" % e

    # ---- cadangkan berkas sistem yang sekarang (jaring pengaman) ----
    cadangan = "/root/backup/sebelum-restore-%s" % DT.datetime.now().strftime("%Y%m%d-%H%M%S")
    for f in ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
              "/etc/xray/config.json", "/etc/l2tp/.l2tp.db",
              "/etc/ppp/chap-secrets", "/etc/ipsec.secrets"):
        try:
            if os.path.isfile(f):
                os.makedirs(cadangan + os.path.dirname(f), exist_ok=True)
                shutil.copy2(f, cadangan + f)
        except Exception:
            pass
    for _dir in ("/opt/kyt-web", "/etc/nginx", "/etc/haproxy",
                 "/etc/ssl/kyt-web", "/etc/kyt", "/etc/letsencrypt"):
        try:
            if os.path.isdir(_dir):
                os.makedirs(os.path.dirname(cadangan + _dir), exist_ok=True)
                shutil.copytree(_dir, cadangan + _dir, symlinks=True,
                                dirs_exist_ok=True)
        except Exception:
            pass
    try:
        if os.path.isfile(_db_bot()):
            _snapshot_db(_db_bot(), _db_bot() + ".sebelum-restore")
    except Exception:
        pass
    try:
        if os.path.isfile(_db_web()):
            d = os.path.join(cadangan, "opt/kyt-web/data/web.db")
            os.makedirs(os.path.dirname(d), exist_ok=True)
            _snapshot_db(_db_web(), d)
    except Exception:
        pass

    # Hentikan service yang file-nya akan ditimpa agar tidak terjadi "Text file busy".
    # slowdns berjalan dari binary /root/slowdns/slowdns, harus dihentikan dulu.
    # kyt-web dihentikan hanya jika zip berisi database website.
    web_zip = os.path.join(tmp, "opt/kyt-web/data/web.db")
    web_ada = os.path.isfile(web_zip)
    slowdns_zip = os.path.isdir(os.path.join(tmp, "root", "slowdns"))

    if slowdns_zip:
        _service_aksi("slowdns", "stop")
        _service_aksi("slowdns-router", "stop")
    if web_ada:
        _service_aksi("kyt-web", "stop")
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                os.remove("/opt/kyt-web/data/web.db" + suffix)
            except Exception:
                pass

    dipulihkan, dilewati = 0, 0
    for root, _dirs, files in os.walk(tmp):
        for fn in files:
            src = os.path.join(root, fn)
            arc = os.path.relpath(src, tmp).replace("\\", "/")
            if not _izin(arc):
                dilewati += 1
                continue
            dst = "/" + arc
            try:
                if arc == "usr/bin/kyt/database.db":
                    # Jangan timpa file DB mentah: pakai SQLite backup API
                    # supaya WAL/transaksi lama tidak merusak data.
                    _pulihkan_db(src)
                elif arc == "opt/kyt-web/data/web.db":
                    _pulihkan_db(src, "/opt/kyt-web/data/web.db")
                else:
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copy2(src, dst)
                    if arc in ("etc/shadow", "etc/gshadow"):
                        os.chmod(dst, 0o640)
                dipulihkan += 1
            except Exception as e:
                logging.error("restore %s: %s", dst, e)
                dilewati += 1
    shutil.rmtree(tmp, ignore_errors=True)
    for _dbp in (_db_bot(), "/opt/kyt-web/data/web.db"):
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                os.remove(_dbp + suffix)
            except Exception:
                pass
    if web_ada:
        _service_aksi("kyt-web", "restart")
    # slowdns akan di-restart bersama service VPN lainnya di bawah

    # ---- jangan sampai root terkunci ----
    try:
        with open("/etc/shadow") as f:
            isi = f.read()
        if not any(l.startswith("root:") for l in isi.splitlines()):
            logging.error("shadow hasil restore tidak punya root -> dibatalkan")
            for f in ("/etc/shadow", "/etc/gshadow"):
                b = cadangan + f
                if os.path.isfile(b):
                    shutil.copy2(b, f)
            return False, ("Restore dibatalkan: file shadow tidak berisi user "
                           "root (bisa mengunci akses VPS).")
    except Exception as e:
        logging.error("cek shadow: %s", e)

    # hak akses penting
    for f, mode in (("/etc/shadow", 0o640), ("/etc/gshadow", 0o640),
                    ("/etc/ipsec.secrets", 0o600),
                    ("/etc/ppp/chap-secrets", 0o600),
                    ("/etc/xray/xray.key", 0o600),
                    ("/etc/haproxy/hap.pem", 0o600),
                    ("/etc/kyt-web-mail.key", 0o600),
                    ("/etc/kyt-web.conf", 0o600),
                    ("/usr/bin/kyt/gomerch_token.json", 0o600),
                    ("/opt/kyt-web/data/web.db", 0o600),
                    ("/usr/bin/kyt/database.db", 0o600)):
        try:
            os.chmod(f, mode)
        except Exception:
            pass

    # pastikan database bot punya tabel lengkap
    try:
        S.init_store()
    except Exception:
        pass

    # Pulihkan permission execute pada binary/script di /root/slowdns
    # (zip/shutil.copy2 bisa kehilangan execute bit dari file epoch-0)
    for _exe in ("/root/slowdns/slowdns", "/root/slowdns/install.sh"):
        try:
            if os.path.isfile(_exe):
                os.chmod(_exe, 0o755)
        except Exception:
            pass

    # muat ulang unit systemd yang ikut dipulihkan (mis. SlowDNS router)
    try:
        subprocess.run(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30)
    except Exception:
        pass

    # geoip/geosite wajib ada untuk Xray (tidak ikut di-backup)
    geo_ok, geo_pesan = pastikan_geo()

    # Muat ulang semua service VPN yang ADA. 'kyt' (service bot ini
    # sendiri) TIDAK diikutkan di sini - lihat catatan di bawah.
    # Kalau 'kyt' di-restart sekarang, proses bot mati sebelum pesan
    # hasil terkirim -> user cuma melihat "Memulihkan..." selamanya.
    # Restart bot dijadwalkan dari handler SETELAH pesan terkirim.
    berhasil_svc, gagal_svc = _muat_ulang_service()

    # SlowDNS mengikuti mode yang tersimpan. Router hanya hidup di AUTO.
    try:
        with open("/etc/kyt-dns-mode") as f:
            mode_dns = f.read().strip()
    except Exception:
        mode_dns = "off"
    try:
        if mode_dns == "xray-auto":
            _service_aksi("slowdns-router", "restart")
        else:
            subprocess.run(["systemctl", "disable", "--now", "slowdns-router"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=30)
        if mode_dns == "off":
            subprocess.run(["systemctl", "disable", "--now", "slowdns"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=30)
    except Exception:
        pass

    pesan = "%d file dipulihkan, %d dilewati.\nCadangan lama: `%s`" % (
        dipulihkan, dilewati, cadangan)
    if geo_pesan:
        pesan += "\n\n" + ("✅ " if geo_ok else "⚠️ ") + geo_pesan
    if gagal_svc:
        pesan += ("\n\n⚠️ Service gagal dimuat ulang: %s\n"
                  "Cek: `systemctl status %s`"
                  % (", ".join(gagal_svc), gagal_svc[0]))
    else:
        pesan += ("\n✅ Service VPN sudah dimuat ulang%s. "
                  "Akun bisa langsung dipakai (tidak perlu reboot)."
                  % ((": " + ", ".join(berhasil_svc)) if berhasil_svc else ""))

    # ringkasan akun hasil restore
    try:
        a = S.hitung_akun_sistem()
        pesan += ("\n\n**Akun terbaca di VPS:**\n"
                  "SSH `%d` | VMess `%d` | VLESS `%d` | Trojan `%d` | SS `%d` | L2TP `%d`"
                  % (a["ssh"], a["vmess"], a["vless"], a["trojan"], a["ss"], a["l2tp"]))
    except Exception:
        pass

    return (dipulihkan > 0, pesan)


def restore_db(path_file):
    """Pulihkan database bot dari file .db atau .zip. Return (ok, pesan)."""
    if not os.path.isfile(path_file):
        return False, "File tidak ditemukan."
    sumber = path_file
    tmp = None

    if zipfile.is_zipfile(path_file):
        tmp = tempfile.mkdtemp(prefix="kytdb-")
        try:
            with zipfile.ZipFile(path_file) as z:
                kandidat = [n for n in z.namelist()
                            if n.endswith("database.db") or n.endswith(".db")]
                if not kandidat:
                    shutil.rmtree(tmp, ignore_errors=True)
                    return False, "Di dalam zip tidak ada file database.db"
                z.extractall(tmp)
            sumber = os.path.join(tmp, kandidat[0])
        except Exception as e:
            shutil.rmtree(tmp, ignore_errors=True)
            return False, "Zip rusak: %s" % e

    # pastikan ini sqlite yang benar
    try:
        with open(sumber, "rb") as f:
            if f.read(16) != b"SQLite format 3\x00":
                if tmp:
                    shutil.rmtree(tmp, ignore_errors=True)
                return False, "Bukan file database SQLite yang sah."
    except Exception as e:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
        return False, "Gagal membaca file: %s" % e

    if not _cek_sqlite(sumber):
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
        return False, "Database SQLite rusak (integrity_check gagal)."

    try:
        _pulihkan_db(sumber)
    except Exception as e:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
        return False, "Gagal menulis database: %s" % e
    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)

    try:
        S.init_store()      # pastikan tabel & produk lengkap
    except Exception:
        pass
    for suffix in ("-wal", "-shm", "-journal"):
        try:
            os.remove(_db_bot() + suffix)
        except Exception:
            pass
    return True, "Database bot berhasil dipulihkan."


# ---------------- helper kirim/terima file ----------------
async def _kirim_file(chat, path, caption=""):
    try:
        await bot.send_file(chat, path, caption=caption, force_document=True)
        return True
    except Exception as e:
        logging.error("kirim file gagal: %s", e)
        return False


async def _minta_file(event, judul):
    """Tunggu user mengirim file (untuk restore).

    PENTING: pertanyaan dikirim DARI DALAM conversation.
    Kalau dikirim di luar, conv.get_response() error
    "No message was sent previously".
    """
    # pakai antrean tunggu yang sama dengan tanya() (tanpa conversation)
    try:
        m = await tunggu_pesan(event, judul, timeout=300)
    except Exception as e:
        logging.error("minta file gagal: %s", repr(e))
        await balas(event, "❌ Gagal menerima file: %s" % e)
        return None
    if m is None:
        return None
    if not getattr(m, "file", None):
        await balas(event, "❌ Itu bukan file. Kirim sebagai **dokumen** (.zip/.db).")
        return None
    nama = getattr(m.file, "name", None) or "upload.bin"
    path = os.path.join("/tmp", "kytupload-%s-%s" % (DT.datetime.now().strftime("%H%M%S"), nama))
    try:
        await m.download_media(path)
    except Exception as e:
        logging.error("download upload gagal: %s", e)
        await balas(event, "❌ Gagal mengunduh file: %s" % e)
        return None
    return path


def _adm_ok(event):
    return valid(str(event.sender_id)) == "true"


# ---------------- menu ----------------
@bot.on(events.CallbackQuery(data=b'backer'))
async def backer(event):
    if not _adm_ok(event):
        await event.answer("Akses Ditolak", alert=True)
        return
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        ada = len(glob.glob(os.path.join(BACKUP_DIR, "kyt-db-*.db")))
    except Exception:
        ada = 0
    teks = f"""
━━━━━━━━━━━━━━━━━━━━━━━
**BACKUP & RESTORE**
━━━━━━━━━━━━━━━━━━━━━━━
Database bot : `{_db_bot()}`
Isi database : {ringkasan()}
Backup db di server : `{ada}` file ({BACKUP_DIR})

**💾 Backup VPS** (1 file .zip) berisi:
  • Akun buyer: SSH, VMess, VLESS, Trojan, Shadowsocks, L2TP/IKEv2
    (passwd, shadow, .vmess.db, .vless.db, .trojan.db,
     .shadowsocks.db, .l2tp.db, chap-secrets, ipsec.secrets)
  • Config: xray, haproxy, nginx, openvpn, dropbear
  • Sertifikat TLS: xray.crt/key, hap.pem, letsencrypt
  • Profil akun (/var/www/html) & /root/akun
  • **Database bot** (saldo, pesanan, deposit, pengaturan)
  • **Website VPNFree** (database user/order/deposit, tema,
    branding, konfigurasi nginx/haproxy, sertifikat SSL)

**💾 Backup Database** = database bot saja (kecil & cepat)

File dikirim ke chat ini, simpan baik-baik.
Kalau pindah VPS: install ulang panel + bot, lalu pakai **Restore**.
━━━━━━━━━━━━━━━━━━━━━━━
"""
    rows = [
        [Button.inline("💾 Backup VPS (lengkap)", "bk-vps")],
        [Button.inline("💾 Backup Database Bot", "bk-db"),
         Button.inline("♻️ Restore", "rs-menu")],
        [Button.inline("‹ Store ›", "storeadmin"),
         Button.inline("‹ Main Menu ›", "menu")],
    ]
    await safe_send(event, teks, buttons=rows)


@bot.on(events.CallbackQuery(data=b'bk-vps'))
async def bk_vps(event):
    if not _adm_ok(event):
        await event.answer("Akses Ditolak", alert=True)
        return
    await safe_send(event, "⏳ **Membuat backup VPS...**\nMohon tunggu.")
    try:
        path, n = await __import__('asyncio').to_thread(buat_backup_vps)
    except Exception as e:
        await safe_send(event, "❌ Gagal: %s" % e,
                        buttons=[[Button.inline("‹ Backup ›", "backer")]])
        return
    ukuran = os.path.getsize(path) / 1024.0 / 1024.0
    if ukuran < 1:
        besar = "%.0f KB" % (ukuran * 1024)
    else:
        besar = "%.2f MB" % ukuran
    catatan = ""
    if ukuran > 20:
        catatan = ("\n\n⚠️ Ukuran cukup besar. Kalau tidak wajar, cek isi "
                   "/var/www/html atau /etc/openvpn (mungkin ada file besar).")
    elif ukuran < 0.05:
        catatan = "\n\n⚠️ Ukuran sangat kecil — pastikan akun memang belum banyak."
    okk = await _kirim_file(event.chat_id, path,
                            "💾 **BACKUP VPS**\n%d file • %s\n%s\n\n"
                            "Isi: akun buyer (SSH/VMess/VLESS/Trojan/SS/L2TP) + "
                            "config + sertifikat + database bot + website.\n"
                            "geoip/geosite TIDAK ikut (bisa diunduh ulang installer).\n\n"
                            "Simpan file ini. Untuk pindah VPS -> menu Restore.%s"
                            % (n, besar, DT.datetime.now().strftime("%d-%m-%Y %H:%M"),
                               catatan))
    try:
        os.remove(path)
    except Exception:
        pass
    if not okk:
        await safe_send(event, "❌ File backup gagal dikirim ke Telegram.",
                        buttons=[[Button.inline("‹ Backup ›", "backer")]])


@bot.on(events.CallbackQuery(data=b'bk-db'))
async def bk_db(event):
    if not _adm_ok(event):
        await event.answer("Akses Ditolak", alert=True)
        return
    try:
        path = await __import__('asyncio').to_thread(buat_backup_db)
    except Exception as e:
        await safe_send(event, "❌ Gagal: %s" % e,
                        buttons=[[Button.inline("‹ Backup ›", "backer")]])
        return
    if not path:
        await safe_send(event, "❌ Database bot belum ada.",
                        buttons=[[Button.inline("‹ Backup ›", "backer")]])
        return
    okk = await _kirim_file(event.chat_id, path,
                            "💾 **BACKUP DATABASE BOT**\n%s\n\n"
                            "Berisi: saldo user, riwayat pesanan, deposit, pengaturan."
                            % DT.datetime.now().strftime("%d-%m-%Y %H:%M"))
    if not okk:
        await safe_send(event, "❌ File gagal dikirim.",
                        buttons=[[Button.inline("‹ Backup ›", "backer")]])


@bot.on(events.CallbackQuery(data=b'rs-menu'))
async def rs_menu(event):
    if not _adm_ok(event):
        await event.answer("Akses Ditolak", alert=True)
        return
    teks = """
━━━━━━━━━━━━━━━━━━━━━━━
**RESTORE**
━━━━━━━━━━━━━━━━━━━━━━━
Kirim **file** hasil backup ke bot ini (dokumen .zip / .db),
bot akan memulihkannya otomatis.

⚠️ Data yang sekarang akan DITIMPA.
   (database bot yang sekarang tetap disimpan sebagai
    `database.db.sebelum-restore`)
━━━━━━━━━━━━━━━━━━━━━━━
"""
    rows = [
        [Button.inline("♻️ Restore VPS (zip)", "rs-vps")],
        [Button.inline("♻️ Restore Database Bot", "rs-db")],
        [Button.inline("‹ Backup ›", "backer")],
    ]
    await safe_send(event, teks, buttons=rows)


@bot.on(events.CallbackQuery(data=b'rs-vps'))
async def rs_vps(event):
    if not _adm_ok(event):
        await event.answer("Akses Ditolak", alert=True)
        return
    path = await _minta_file(event,
                             "📤 **Kirim file backup VPS (.zip)** ke chat ini.\n"
                             "Kirim `-` untuk batal.")
    if not path:
        await balas(event, "❌ Tidak ada file yang diterima.",
                    buttons=[[Button.inline("‹ Backup ›", "backer")]])
        return

    # ---- periksa dulu isi backup ----
    ok_cek, pesan_cek, penting = await __import__('asyncio').to_thread(cek_backup, path)
    if not ok_cek:
        try:
            os.remove(path)
        except Exception:
            pass
        await balas(event, "❌ **Backup ditolak.**\n\n%s" % pesan_cek,
                    buttons=[[Button.inline("‹ Backup ›", "backer")]])
        return

    rinci = "\n".join("  • `%s`" % x for x in penting[:12])
    await balas(event,
                "✅ **Backup valid**\n%s\n\n**Isi penting:**\n%s\n\n"
                "⚠️ Data yang sekarang akan DITIMPA.\n"
                "Cadangan otomatis dibuat di `/root/backup/sebelum-restore-*`.\n\n"
                "Lanjutkan restore?" % (pesan_cek, rinci),
                buttons=[[Button.inline("✅ Ya, Restore Sekarang", "rs-vps-go-%s" % os.path.basename(path))],
                         [Button.inline("‹ Batal ›", "backer")]])


@bot.on(events.CallbackQuery(pattern=r'^rs-vps-go-'))
async def rs_vps_go(event):
    if not _adm_ok(event):
        await event.answer("Akses Ditolak", alert=True)
        return
    nama = event.data.decode().replace("rs-vps-go-", "")
    path = os.path.join("/tmp", nama)
    if not os.path.isfile(path):
        await event.answer("File sudah tidak ada. Ulangi dari menu.", alert=True)
        return
    await balas(event, "⏳ **Memulihkan...** mohon tunggu (bisa 1-2 menit).")
    okk, pesan = await __import__('asyncio').to_thread(restore_vps, path)
    try:
        os.remove(path)
    except Exception:
        pass

    # Jadwalkan restart bot SETELAH pesan ini terkirim. Kalau di-restart
    # dari dalam (sinkron), bot mati dulu -> pesan tidak pernah terkirim.
    cara = None
    if okk:
        try:
            cara = _jadwalkan_restart_bot(12)
            logging.info("restore: restart bot dijadwalkan via %s", cara)
        except Exception as e:
            logging.error("jadwalkan restart bot: %s", e)
    if cara:
        pesan += ("\n\n🔄 Bot restart otomatis ±12 detik lagi untuk memuat data "
                  "baru. Tunggu sebentar, lalu buka menu lagi.")
    else:
        pesan += ("\n\nℹ️ Kalau menu belum berubah, restart bot manual:\n"
                  "`systemctl restart kyt`")

    await balas(event,
                ("✅ **RESTORE SELESAI**\n\n%s" % pesan) if okk
                else ("❌ **GAGAL:** %s" % pesan),
                buttons=[[Button.inline("🔄 Hitung Ulang Akun", "sa-stat"),
                          Button.inline("‹ Backup ›", "backer")]])


@bot.on(events.CallbackQuery(data=b'rs-db'))
async def rs_db(event):
    if not _adm_ok(event):
        await event.answer("Akses Ditolak", alert=True)
        return
    path = await _minta_file(event,
                             "📤 **Kirim file database bot** (.db atau .zip) ke chat ini.\n"
                             "Kirim `-` untuk batal.")
    if not path:
        await event.reply("❌ Tidak ada file yang diterima.",
                          buttons=[[Button.inline("‹ Backup ›", "backer")]])
        return
    okk, pesan = await __import__('asyncio').to_thread(restore_db, path)
    try:
        os.remove(path)
    except Exception:
        pass
    if okk:
        try:
            cara = _jadwalkan_restart_bot(10)
            if cara:
                pesan += ("\n\n🔄 Bot restart otomatis ±10 detik lagi untuk "
                          "memuat database baru.")
        except Exception as e:
            logging.error("jadwalkan restart setelah restore db: %s", e)
    await safe_send(event,
                    ("✅ **RESTORE DATABASE SELESAI**\n%s\n\nIsi sekarang:\n%s"
                     % (pesan, ringkasan())) if okk else ("❌ **GAGAL:** %s" % pesan),
                    buttons=[[Button.inline("‹ Backup ›", "backer")]])
