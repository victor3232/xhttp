# VPNFree edge — digenerate oleh installer.
# HTTP: ACME + redirect. HTTPS: diteruskan HAProxy sebagai HTTP/PROXY ke nginx.
geo $kyt_from_cloudflare {
    default 0;
    173.245.48.0/20 1;
    103.21.244.0/22 1;
    103.22.200.0/22 1;
    103.31.4.0/22 1;
    141.101.64.0/18 1;
    108.162.192.0/18 1;
    190.93.240.0/20 1;
    188.114.96.0/20 1;
    197.234.240.0/22 1;
    198.41.128.0/17 1;
    162.158.0.0/15 1;
    104.16.0.0/13 1;
    104.24.0.0/14 1;
    172.64.0.0/13 1;
    131.0.72.0/22 1;
    2400:cb00::/32 1;
    2606:4700::/32 1;
    2803:f800::/32 1;
    2405:b500::/32 1;
    2405:8100::/32 1;
    2a06:98c0::/29 1;
    2c0f:f248::/32 1;
}
map $http_cf_connecting_ip $kyt_cf_ip {
    default $http_cf_connecting_ip;
    ""      $remote_addr;
}
map $kyt_from_cloudflare $kyt_client_ip {
    default $remote_addr;
    1       $kyt_cf_ip;
}

server {
    listen 127.0.0.1:8088 proxy_protocol;
    server_name __DOMAIN__;
    server_tokens off;
    root /var/www/letsencrypt;
    client_max_body_size 128k;
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    location ^~ /.well-known/acme-challenge/ {
        default_type text/plain;
        try_files $uri =404;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    # TLS diterminasi HAProxy; nginx menerima HTTP + PROXY protocol.
    # Catatan: JANGAN pakai "http2 on;" — direktif itu baru ada di nginx >= 1.25.
    # Debian 12 (nginx 1.22) dan Ubuntu 22/24 (nginx 1.18/1.24) akan gagal nginx -t.
    # HAProxy sudah menangani HTTP/2 di sisi klien dan meneruskan HTTP/1.1 ke sini.
    listen 127.0.0.1:8444 proxy_protocol;
    server_name __DOMAIN__;
    server_tokens off;
    client_max_body_size 128k;
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    add_header Strict-Transport-Security "max-age=31536000" always;

    access_log /var/log/nginx/vpnfree.access.log;
    error_log  /var/log/nginx/vpnfree.error.log;

    location / {
        proxy_pass http://127.0.0.1:8099;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Connection "";
        proxy_set_header X-Real-IP $kyt_client_ip;
        proxy_set_header X-Forwarded-For $kyt_client_ip;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header CF-Connecting-IP "";
        proxy_connect_timeout 10s;
        proxy_send_timeout 200s;
        proxy_read_timeout 200s;
        proxy_buffering off;
    }
}
