# IZIN MANAGER

Panel kecil untuk **add / delete / check IP** di file lisensi:

```text
https://github.com/victor3232/xhttp/blob/main/izin
```

Bisa jalan di:

```text
✅ Railway (disarankan)
✅ VPS / lokal (mode file)
```

Tidak menyentuh script VPN, akun, Xray, web.db, atau bot.

## Fitur

```text
✅ Login admin
✅ Tambah IP + nama + tanggal expired
✅ Update otomatis kalau IP sudah ada
✅ Hapus IP
✅ Cek status IP (aktif / expired / lifetime)
✅ Cari nama / IP / tanggal
✅ API untuk script
✅ Commit langsung ke GitHub
✅ Mode lokal untuk tes
```

## Format file izin

```text
### nama 2026-12-31 1.2.3.4
### premiumv1 2026-12-31 139.59.225.55
### dragon 2099-12-31 139.59.245.191
```

- `### nama expiry IP`
- `expiry` = `YYYY-MM-DD`
- `lifetime` otomatis ditulis `2099-12-31`

## Jalan lokal

```bash
cd izin-manager
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

export ADMIN_PASSWORD=rahasia
export IZIN_FILE=../izin
python app.py
```

Buka:

```text
http://127.0.0.1:8080
```

## Deploy Railway

### 1. Buat GitHub token

Gunakan **fine-grained token**, bukan classic token:

```text
GitHub → Settings → Developer settings → Fine-grained tokens
```

Akses:

```text
Repository access : only select repositories → victor3232/xhttp
Permissions       : Contents → Read and write
```

Copy token `github_pat_...`.

### 2. Buat project Railway

```text
Railway → New Project → Deploy from GitHub repo
Pilih repo victor3232/xhttp
Root Directory : izin-manager
```

Kalau Railway minta build/start:

```text
Build  : NIXPACKS (otomatis dari requirements.txt)
Start  : gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 60
```

### 3. Isi variables

| Variable | Wajib | Contoh | Fungsi |
|---|---|---|---|
| `ADMIN_PASSWORD` | ✅ | password kuat | login panel |
| `SECRET_KEY` | ✅ | random 64 char | session cookie |
| `GITHUB_TOKEN` | ✅ | `github_pat_...` | akses repo |
| `GITHUB_REPO` | ✅ | `victor3232/xhttp` | repo |
| `GITHUB_BRANCH` | ✅ | `main` | branch |
| `GITHUB_PATH` | ✅ | `izin` | file lisensi |
| `API_KEY` | opsional | random | API script |
| `CACHE_TTL` | opsional | `15` | cache detik |

Generate `SECRET_KEY`:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Generate `API_KEY`:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 4. Generate domain

```text
Railway → Settings → Networking → Generate Domain
```

Buka domain, login, tambah IP.

## CLI

Bisa dipakai tanpa web:

```bash
export GITHUB_TOKEN=github_pat_...
export GITHUB_REPO=victor3232/xhttp
export GITHUB_BRANCH=main
export GITHUB_PATH=izin

python cli.py list
python cli.py check 1.2.3.4
python cli.py add "admin" 2026-12-31 1.2.3.4
python cli.py del 1.2.3.4
```

Mode lokal:

```bash
export IZIN_FILE=../izin
python cli.py add "tes" 2026-12-31 1.2.3.4
```

## API

Auth lewat header:

```text
X-API-Key: API_KEY
```

Atau query:

```text
?key=API_KEY
```

### Cek IP

```bash
curl -s "https://domain-railway/api/check?ip=1.2.3.4" \
  -H "X-API-Key: $API_KEY"
```

Hasil:

```json
{
  "ok": true,
  "found": true,
  "ip": "1.2.3.4",
  "name": "admin",
  "expiry": "2026-12-31",
  "status": "active",
  "days_left": 52
}
```

### Tambah IP

```bash
curl -s -X POST "https://domain-railway/api/add" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"admin","expiry":"2026-12-31","ip":"1.2.3.4"}'
```

### Hapus IP

```bash
curl -s -X POST "https://domain-railway/api/delete" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4"}'
```

### List

```bash
curl -s "https://domain-railway/api/entries" \
  -H "X-API-Key: $API_KEY"
```

## Script cek izin dari VPS

```bash
curl -4 -fsSL "https://domain-railway/api/check?ip=$(curl -4 -s ipv4.icanhazip.com)" \
  -H "X-API-Key: $API_KEY"
```

## Catatan worker

Installer memakai:

```text
https://raw.githubusercontent.com/victor3232/xhttp/main/izin
```

Kalau worker melakukan cache, perubahan file GitHub mungkin belum langsung terlihat.
Tes dari VPS:

```bash
curl -4 -s "https://raw.githubusercontent.com/victor3232/xhttp/main/izin?v=$(date +%s)" | grep IP_ANDA
```

Kalau belum muncul:

```text
1. Tunggu cache worker
2. Purge cache worker
3. Atau update file di sumber yang worker baca
```

## Keamanan

```text
✅ Jangan commit GITHUB_TOKEN ke repo
✅ ADMIN_PASSWORD minimal 16 karakter
✅ API_KEY hanya untuk script tepercaya
✅ Token GitHub hanya repo ini, Contents read/write
✅ Jangan share URL panel ke publik
✅ Panel ini bisa menambah/menghapus lisensi
```

## Struktur

```text
izin-manager/
├── app.py              # Flask UI + API
├── cli.py              # CLI
├── izin_store.py       # parser + GitHub/local store
├── templates/
│   ├── base.html
│   ├── login.html
│   └── index.html
├── static/style.css
├── requirements.txt
├── Procfile
├── railway.json
└── README.md
```
