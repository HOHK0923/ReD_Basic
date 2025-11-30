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

    // =============================================================================
    // 중급 보안 필터링: 블랙리스트 기반 필터링 (교육용으로 의도적으로 우회 가능)
    // =============================================================================

    // 1. 기본 공백 제거 (앞뒤 공백만 제거, 중간 공백은 유지)
    $username = trim($username);
    $password = trim($password);

    // 2. 블랙리스트 필터링 (의도적으로 불완전하게 구현)
    //
    // 왜 이렇게 구현했나?
    // - 실제 환경에서 초보 개발자가 만들 수 있는 불완전한 보안을 재현
    // - 블랙리스트 방식의 한계를 학습하기 위한 교육용 설계
    //
    // 현재 구현의 취약점:
    // 1) 작은따옴표(')는 차단하지만 주석(--, #)은 허용 → 우회 가능
    // 2) 대소문자 혼용 우회 가능 (예: UnIoN, SeLeCt)
    // 3) 공백 대신 주석이나 특수문자 삽입 우회 가능 (예: UNION/**/SELECT)
    // 4) 인코딩 우회 가능 (예: URL 인코딩, Hex 인코딩)
    // 5) 키워드 중첩 우회 가능 (예: SELSELECTECT)
    //
    // 올바른 방어 방법:
    // - Prepared Statement (매개변수화된 쿼리) 사용
    // - 입력값 화이트리스트 검증
    // - ORM 사용
    $blacklist = [
        'union',    // UNION 기반 SQLi 방어 시도
        'select',   // SELECT 쿼리 주입 방어 시도
        'insert',   // INSERT 쿼리 주입 방어 시도
        'update',   // UPDATE 쿼리 주입 방어 시도
        'delete',   // DELETE 쿼리 주입 방어 시도
        'drop',     // DROP 쿼리 주입 방어 시도
        '\'',       // ⭐ 새로 추가: 작은따옴표 차단 (하지만 우회 가능)
        '"',        // 큰따옴표 차단
        '\\',       // 백슬래시 차단
        ';',        // 세미콜론 차단 (다중 쿼리 실행 방지)
    ];
    $blocked = false;

    foreach ($blacklist as $word) {
        // stripos: 대소문자 구분 없이 문자열 검색
        // 취약점: 주석(--, #)이나 인코딩을 통한 우회 가능
        //
        // 우회 예시:
        // - 대소문자 혼용: "UniOn" → 차단됨 (stripos 사용)
        // - 주석 우회: "admin'--" → ' 때문에 차단, 하지만 admin" or 1=1-- 가능
        // - 공백 우회: "admin'/**/--" → ' 때문에 차단됨
        // - 인코딩: URL 인코딩으로 우회 가능
        if (stripos($username, $word) !== false) {
            $blocked = true;
            break;
        }
    }

    if ($blocked) {
        $error = "⚠️ 입력에 허용되지 않은 문자가 포함되어 있습니다.";
    } else {
        $conn = getConnection();

        // =============================================================================
        // ⚠️ 핵심 취약점: SQL Injection 취약점
        // =============================================================================
        //
        // 문제점:
        // - Prepared Statement를 사용하지 않고 사용자 입력을 직접 쿼리에 삽입
        // - 블랙리스트 필터링만으로는 모든 공격을 막을 수 없음
        //
        // 취약한 쿼리 예시:
        // SELECT * FROM users WHERE username = 'admin' AND password = 'test'
        //
        // 공격 예시:
        // 입력값: username = "admin" OR "1"="1" --, password = "anything"
        // 실행되는 쿼리:
        // SELECT * FROM users WHERE username = "admin" OR "1"="1" --' AND password = 'anything'
        // → 주석(--)으로 인해 password 조건이 무시됨
        // → OR "1"="1"이 항상 참이므로 로그인 성공
        //
        // 올바른 방어 방법:
        // $stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
        // $stmt->bind_param("ss", $username, $password);
        // $stmt->execute();
        $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

        if ($debug) {
            // 디버그 모드: 실행된 쿼리를 화면에 표시
            // 실제 환경에서는 절대 하면 안 되는 행동 (정보 노출 취약점)
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
