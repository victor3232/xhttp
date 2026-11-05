# VPNFree — paket website modular

Folder ini berdiri sendiri. Semua yang dibutuhkan website ada di `src/` dan
dibungkus menjadi `web.zip`. Script utama VPN (`premi.sh`, `menu.zip`, Timer
Mullog, SlowDNS, dll.) tidak diubah.

## Struktur

```text
web/
  build.sh        # membuat web.zip dari src/
  web.zip         # paket siap dipasang (hasil build)
  src/
    install.sh
    app.py
    kyt-web.service
    static/
    edge/
      configure_edge.py
      vpnfree.conf.tpl
      kyt-web-cert-sync
      issue-cert.sh
```

## Integrasi Utility

`menu.zip` hanya membawa script kecil `setting-web`. Script itu:

- **ON**: kalau `/opt/kyt-web` belum ada, mengunduh `web/web.zip` dari Worker,
  menjalankan `install.sh`, lalu enable + start `kyt-web`.
- **ON berikutnya**: cukup enable + start.
- **OFF**: `systemctl disable --now kyt-web`. Database, config, dan file di
  `/opt/kyt-web` tidak dihapus.

## Maintenance UI

Edit `src/app.py`, `src/static/style.css`, atau `src/static/app.js`, lalu:

```bash
./build.sh
```

Upload `web.zip` ke repo. Worker akan menyajikannya di:

```text
https://scvpn.jolang323.workers.dev/web/web.zip
```

Tidak perlu menyentuh `premi.sh` atau `menu.zip` setiap kali UI berubah. Cukup
ON-kan ulang dari Utility; installer mempertahankan database yang sudah ada.

## Domain

Saat ON pertama, `setting-web` meminta domain dengan default
`web.<domain-vpn>`. Domain disimpan di `/etc/kyt-web.conf`.

## Fitur HITS SSH

- Kategori gratis: SSH, VMess, VLESS, Trojan; kuota harian.
- Kategori premium multi-durasi: harga, masa aktif, limit IP, dan kuota per paket.
- Checkout tanpa login, QRIS GoPay, kode unik nominal, invoice privat.
- Cek invoice, download detail akun `.txt`, dan riwayat transaksi admin.
- Login admin memakai token bot Telegram.

## Halaman publik

- `/` — Beranda dan ringkasan kategori.
- `/gratis` — pembuatan akun SSH/Xray gratis.
- `/premium` — pembelian akun premium QRIS GoPay.
- `/cek-invoice` — cek invoice dan riwayat lokal perangkat.
- `/kontak` — kontak/bantuan, link diatur dari Admin Dashboard.

## Ganti subdomain

Buka Utility → `26 SETTING WEBSITE` → `4 Ganti domain / subdomain`.
Wajib membuat DNS A record ke IP VPS dan mengetik `POINTING` sebelum proses.
Script akan memverifikasi HTTP, menerbitkan SSL, dan rollback otomatis jika gagal.
