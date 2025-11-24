#!/bin/bash
###############################################################################
# 모든 백업 및 해킹 파일 완전 삭제
###############################################################################

echo "╔═══════════════════════════════════════════════╗"
echo "║   모든 백업 파일 및 해킹 파일 삭제           ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Root 권한 확인
if [ "$EUID" -ne 0 ]; then
    echo "❌ Root 권한이 필요합니다. sudo를 사용하세요."
    exit 1
fi

echo "[*] 백업 파일 삭제 중..."
rm -f /tmp/index_ORIGINAL.php
rm -f /tmp/index_HACKED.php
echo "✅ 백업 파일 삭제 완료"

echo "[*] 악성 파일 삭제 중..."
rm -f /var/www/html/public/security_report.pdf
rm -f /var/www/html/www/security_report.pdf
rm -f /var/www/html/public/network_diagram.jpg
rm -f /var/www/html/www/network_diagram.jpg
echo "✅ 악성 파일 삭제 완료"

echo "[*] .htaccess 삭제 중..."
rm -f /var/www/html/public/.htaccess
rm -f /var/www/html/www/.htaccess
echo "✅ .htaccess 삭제 완료"

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║   ✅ 모든 파일 삭제 완료!                   ║"
echo "║                                              ║"
echo "║   이제 MODERN_DEFACEMENT_FIXED.sh를 실행하면 ║"
echo "║   깨끗하게 처음부터 시작합니다.              ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""
