#!/bin/bash
###############################################################################
# Laravel 원본 index.php 복구
###############################################################################

echo "╔═══════════════════════════════════════════════╗"
echo "║   Laravel 원본 index.php 복구                ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Root 권한 확인
if [ "$EUID" -ne 0 ]; then
    echo "❌ Root 권한이 필요합니다. sudo를 사용하세요."
    exit 1
fi

echo "[*] Laravel 원본 index.php 생성 중..."

# Laravel 기본 index.php
cat > /var/www/html/public/index.php << 'EOFLARAVEL'
<?php

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Request;

define('LARAVEL_START', microtime(true));

/*
|--------------------------------------------------------------------------
| Check If Application Is Under Maintenance
|--------------------------------------------------------------------------
*/

if (file_exists(__DIR__.'/../storage/framework/maintenance.php')) {
    require __DIR__.'/../storage/framework/maintenance.php';
}

/*
|--------------------------------------------------------------------------
| Register The Auto Loader
|--------------------------------------------------------------------------
*/

require __DIR__.'/../vendor/autoload.php';

/*
|--------------------------------------------------------------------------
| Run The Application
|--------------------------------------------------------------------------
*/

$app = require_once __DIR__.'/../bootstrap/app.php';

$kernel = $app->make(Kernel::class);

$response = $kernel->handle(
    $request = Request::capture()
)->send();

$kernel->terminate($request, $response);
EOFLARAVEL

chmod 644 /var/www/html/public/index.php
chown apache:apache /var/www/html/public/index.php

# www 폴더에도 복사
if [ -d "/var/www/html/www" ]; then
    cp /var/www/html/public/index.php /var/www/html/www/index.php
    chmod 644 /var/www/html/www/index.php
    chown apache:apache /var/www/html/www/index.php
fi

# 모든 백업 삭제
rm -f /tmp/index_ORIGINAL.php
rm -f /tmp/index_HACKED.php

# 악성 파일 삭제
rm -f /var/www/html/public/security_report.pdf
rm -f /var/www/html/www/security_report.pdf
rm -f /var/www/html/public/network_diagram.jpg
rm -f /var/www/html/www/network_diagram.jpg

# .htaccess 삭제
rm -f /var/www/html/public/.htaccess
rm -f /var/www/html/www/.htaccess

# Apache 재시작
systemctl restart httpd 2>/dev/null

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║   ✅ Laravel 원본 복구 완료!                 ║"
echo "║                                              ║"
echo "║   이제 정상적인 Laravel 페이지가 표시됩니다. ║"
echo "║                                              ║"
echo "║   해킹 페이지 배포:                          ║"
echo "║   sudo bash MODERN_DEFACEMENT_FIXED.sh       ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""
