
### TESTED ON OS
```
- UBUNTU 22 / 24 / 26
- DEBIAN 11 / 12 / 13
```
### SIMPLE FEATURE
```
- LIMIT IP
- LIMIT QUOATA XRAY
- BOT NOTIF MULLOG & QUOTA HABIS
- SIMPLE CREATE WITH TELEGRAM BOT
- SUPPORT SEMUA METHOD INJECT
- L2TP / IPSec (PSK) & IKEv2 (EAP-MSCHAPv2)
```
### PROTOCOL SUPPORT
```
XRAY / VMESS
- ws, grpc, httpupgrade (upgrade), xhttp, tcp + TLS

XRAY / VLESS
- ws, grpc, httpupgrade (upgrade), xhttp, tcp + XTLS-Vision

XRAY / TROJAN
- ws, grpc, httpupgrade (upgrade), xhttp, tcp + TLS

XRAY / SHADOWSOCKS
- ws

SSH
- OpenSSH, Dropbear, SSH WS (WebSocket), SSH UDP, SNI/HCR payload, TCP, SSL/TLS

VPN
- OpenVPN (TCP/UDP/WS)
- L2TP / IPSec (PSK)
- IKEv2 (EAP-MSCHAPv2)
```

### PORT INFO
```
- MULTI PORT 443 / 80
- XRAY (WS/GRPC/HTTPUPGRADE/XHTTP) : 443
- VLESS XTLS-VISION (TCP TLS)      : 8443
- VMESS TCP TLS                    : 8543
- TROJAN TCP TLS                   : 8643
- L2TP / IPSec                     : 500, 4500 (UDP), 1701 (UDP)
- IKEv2                            : 500, 4500 (UDP)
- OpenVPN TCP 1194 / UDP 2200
- SSH UDP (BadVPN)                 : 7100, 7200, 7300
```

### CATATAN HAPROXY
```
- HAProxy dipastikan AKTIF (enable + restart + verifikasi) di akhir instalasi.
- Bila sertifikat /etc/haproxy/hap.pem kosong/rusak, otomatis dibangun ulang
  dari /etc/xray/xray.crt + xray.key (fallback self-signed bila perlu).
- systemd diberi drop-in Restart=always supaya HAProxy otomatis hidup lagi jika mati.
- Menu Tambahan [20] "FIX / RESTART HAPROXY" untuk perbaikan manual.
```

### ADD ON
```
function install_xray() {
    clear
    print_install "Core Xray v26.3.27 (Fix Root Permission | Support XHTTP/HTTPUpgrade/XTLS-Vision)"

    # 1. Buat Direktori
    mkdir -p /etc/xray
    mkdir -p /var/log/xray
    mkdir -p /usr/local/share/xray
    chown www-data.www-data /var/log/xray
    chmod +x /var/log/xray
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log

    # 2. Download Xray Core v26.3.27 (Stable)
    ARCH=$(uname -m)
    if [[ $ARCH == "x86_64" ]]; then
        LINK="https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip"
    elif [[ $ARCH == "aarch64" ]]; then
        LINK="https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-arm64-v8a.zip"
    else
        print_error "Arsitektur tidak didukung!"
        exit 1
    fi

    echo "Downloading Xray Core v26.3.27..."
    wget -q -O /tmp/xray.zip "$LINK"

    # 3. Cek apakah download sukses
    if [ ! -s /tmp/xray.zip ]; then
        echo "Download Gagal! Mencoba Link Backup..."
        wget -q -O /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip"
    fi

    # 4. Unzip dan Pasang
    unzip -o /tmp/xray.zip -d /tmp/xray_bin > /dev/null 2>&1
    mv /tmp/xray_bin/xray /usr/local/bin/xray
    chmod +x /usr/local/bin/xray
    rm -rf /tmp/xray.zip
    rm -rf /tmp/xray_bin

    # 5. Ambil Config & Service
    wget -O /etc/xray/config.json "${REPO}limit/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}limit/runn.service" >/dev/null 2>&1

    # 6. Download GeoData
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"

    domain=$(cat /etc/xray/domain)

    # Settings UP Nginx Server & HAProxy
    clear
    curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
    print_install "Memasang Konfigurasi Packet"
    wget -O /etc/haproxy/haproxy.cfg "${REPO}limit/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}limit/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf

    curl ${REPO}limit/nginx.conf > /etc/nginx/nginx.conf
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

    chmod +x /etc/systemd/system/runn.service
    ...
    print_success "Xray Core v26.3.27 Installed"
}
```

### TAMPILAN SCRIPT
![IMG_20231217_190421](https://github.com/victor3232/xhttp/assets/44395332/2651a342-67a3-4d01-b52b-4995abc7afac)
