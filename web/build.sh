#!/bin/bash
# Build web.zip dari folder src/. Jalankan setelah mengedit src/.
set -e
cd "$(dirname "$0")"
find src -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find src -type f -name '*.pyc' -delete 2>/dev/null || true
rm -f web.zip
( cd src && zip -rq ../web.zip . -x '*.pyc' '__pycache__/*' )
echo "web.zip dibuat: $(stat -c%s web.zip) bytes"
echo "SHA256: $(sha256sum web.zip | cut -d' ' -f1)"
