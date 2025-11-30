<?php
// register.php - 회원가입
include 'config.php';

if (isLoggedIn()) {
    header('Location: index.php');
    exit();
}

$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);
    $email = trim($_POST['email']);
    $full_name = trim($_POST['full_name']);

    // 기본 검증
    if (empty($username) || empty($password) || empty($email) || empty($full_name)) {
        $error = "모든 필드를 입력해주세요.";
    } elseif (strlen($username) < 3) {
        $error = "사용자명은 최소 3자 이상이어야 합니다.";
    } else {
        $conn = getConnection();

        // 취약점: SQL Injection 가능 (Prepared Statement 미사용)
        $query = "INSERT INTO users (username, password, email, full_name, points)
                  VALUES ('$username', '$password', '$email', '$full_name', 100)";

        if ($conn->query($query) === TRUE) {
            $success = "✅ 회원가입 성공! 100 포인트가 지급되었습니다.";
            $success .= "<br><a href='login.php'>로그인 페이지로 이동 →</a>";
        } else {
            $error = "❌ 회원가입 실패: " . $conn->error;
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
    <title>회원가입 - Vulnerable SNS</title>
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
        .register-container {
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 500px;
            width: 100%;
        }
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
        }
        h1 i {
            color: #667eea;
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
        input[type="password"],
        input[type="email"] {
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
        .success {
            background: #d4edda;
            color: #155724;
            padding: 12px;
            border-radius: 10px;
            margin-bottom: 20px;
            border-left: 4px solid #28a745;
        }
        .success a {
            color: #155724;
            font-weight: 600;
        }
        .error {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 10px;
            margin-bottom: 20px;
            border-left: 4px solid #c33;
        }
        .login-link {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 14px;
        }
        .login-link a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="register-container">
        <h1><i class="fas fa-user-plus"></i> 회원가입</h1>

        <?php if ($success): ?>
            <div class="success"><?php echo $success; ?></div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="error"><?php echo $error; ?></div>
        <?php endif; ?>

        <form method="POST">
            <div class="form-group">
                <label><i class="fas fa-user"></i> 사용자명</label>
                <input type="text" name="username" required placeholder="3자 이상">
            </div>

            <div class="form-group">
                <label><i class="fas fa-lock"></i> 비밀번호</label>
                <input type="password" name="password" required>
            </div>

            <div class="form-group">
                <label><i class="fas fa-envelope"></i> 이메일</label>
                <input type="email" name="email" required>
            </div>

            <div class="form-group">
                <label><i class="fas fa-id-card"></i> 이름</label>
                <input type="text" name="full_name" required>
            </div>

            <button type="submit" class="btn">
                <i class="fas fa-check"></i> 가입하기
            </button>
        </form>

        <div class="login-link">
            이미 계정이 있으신가요? <a href="login.php">로그인</a>
        </div>
    </div>
</body>
</html>
