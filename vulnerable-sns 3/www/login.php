<?php
// login.php - 로그인 (SQL Injection 취약)
// 취약점: 중급 난이도 - 일부 필터링 있지만 우회 가능

include 'config.php';

// 이미 로그인된 경우
if (isLoggedIn()) {
    header('Location: index.php');
    exit();
}

$error = '';
$debug = isset($_GET['debug']) ? true : false;

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // 중급 보안: 기본 필터링 (우회 가능)
    $username = trim($username);
    $password = trim($password);

    // 블랙리스트 필터링 (불완전)
    $blacklist = ['union', 'select', 'insert', 'update', 'delete', 'drop'];
    $blocked = false;

    foreach ($blacklist as $word) {
        // 취약점: 대소문자만 체크, 주석이나 인코딩 우회 가능
        if (stripos($username, $word) !== false) {
            $blocked = true;
            break;
        }
    }

    if ($blocked) {
        $error = "⚠️ 입력에 허용되지 않은 문자가 포함되어 있습니다.";
    } else {
        $conn = getConnection();

        // 취약점: Prepared Statement 미사용
        $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

        if ($debug) {
            $error .= "<br><code style='font-size: 11px;'>DEBUG: $query</code>";
        }

        $result = $conn->query($query);

        if ($result && $result->num_rows > 0) {
            $user = $result->fetch_assoc();
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];

            header('Location: index.php');
            exit();
        } else {
            $error = "❌ 로그인 실패! 사용자명 또는 비밀번호가 올바르지 않습니다.";
            if ($debug) {
                $error .= "<br><small style='color: #666;'>실행된 쿼리: $query</small>";
            }
        }

        $conn->close();
    }
}
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>로그인 - Vulnerable SNS</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 450px;
            width: 100%;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo i {
            font-size: 60px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .logo h1 {
            font-size: 28px;
            color: #333;
            margin-top: 10px;
        }
        .logo p {
            color: #999;
            font-size: 14px;
            margin-top: 5px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
            font-size: 14px;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 14px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 15px;
            transition: all 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        .error {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 10px;
            margin-bottom: 20px;
            border-left: 4px solid #c33;
            font-size: 14px;
        }
        .info-box {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            margin-top: 20px;
        }
        .info-box h3 {
            font-size: 14px;
            color: #667eea;
            margin-bottom: 10px;
        }
        .info-box ul {
            list-style: none;
            font-size: 13px;
            color: #555;
        }
        .info-box li {
            padding: 5px 0;
        }
        .info-box code {
            background: #fff;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        .register-link {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 14px;
        }
        .register-link a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        .register-link a:hover {
            text-decoration: underline;
        }
        .warning {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 12px;
            border-radius: 8px;
            margin-top: 15px;
            font-size: 12px;
            color: #856404;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <i class="fas fa-shield-alt"></i>
            <h1>Vulnerable SNS</h1>
            <p>보안 취약점 학습 플랫폼</p>
        </div>

        <?php if ($error): ?>
            <div class="error"><?php echo $error; ?></div>
        <?php endif; ?>

        <form method="POST">
            <div class="form-group">
                <label><i class="fas fa-user"></i> 사용자명</label>
                <input type="text" name="username" required autofocus placeholder="username">
            </div>

            <div class="form-group">
                <label><i class="fas fa-lock"></i> 비밀번호</label>
                <input type="password" name="password" required placeholder="password">
            </div>

            <button type="submit" class="btn">
                <i class="fas fa-sign-in-alt"></i> 로그인
            </button>
        </form>

        <div class="register-link">
            계정이 없으신가요? <a href="register.php">회원가입</a>
        </div>

        <div class="info-box">
            <h3><i class="fas fa-info-circle"></i> 테스트 계정</h3>
            <ul>
                <li><strong>관리자:</strong> admin / admin123</li>
                <li><strong>일반유저:</strong> alice / alice2024</li>
                <li><strong>일반유저:</strong> bob / bobby123</li>
            </ul>
        </div>

        <div class="warning">
            <strong>⚠️ 보안 경고:</strong> 이 애플리케이션은 교육 목적으로 의도적으로 취약하게 제작되었습니다.<br>
            <strong>💡 힌트:</strong> SQL Injection 공격 가능 (중급 난이도)<br>
            <strong>🔍 디버그:</strong> <code>?debug=1</code> 추가하여 쿼리 확인
        </div>
    </div>
</body>
</html>
