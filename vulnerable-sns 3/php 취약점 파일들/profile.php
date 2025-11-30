<?php
// =============================================================================
// profile.php - 프로필 수정 및 선물 보내기 (CSRF 취약점 포함)
// =============================================================================
//
// 이 파일의 기능:
// - 사용자 프로필 정보 수정
// - 다른 사용자에게 선물 보내기 (포인트 전송)
//
// ⚠️ 주요 보안 취약점:
// 1. CSRF (Cross-Site Request Forgery) 취약점
//    → POST 요청에는 CSRF 토큰이 있지만, GET 요청도 허용
//    → 선물 보내기 기능에 CSRF 토큰 검증 없음
//    → 악의적인 웹사이트에서 자동으로 프로필 수정 또는 포인트 전송 가능
//
// 2. SQL Injection 취약점
//    → 사용자 입력을 직접 쿼리에 삽입
//    → Prepared Statement 미사용
//
// 3. 불충분한 권한 검증
//    → 자신의 포인트만 확인하고, 트랜잭션 처리 없음
//
// 공격 시나리오 (CSRF):
// 1. 공격자가 악의적인 웹사이트 생성
// 2. 피해자를 해당 사이트로 유도
// 3. 숨겨진 폼이 자동으로 제출됨
// 4. 피해자의 세션으로 선물이 공격자에게 전송됨

include 'config.php';
requireLogin();

$user = getCurrentUser();
$success = '';
$error = '';
$gift_sent = false;

// CSRF 토큰 생성
// ⚠️ 문제점: 토큰을 생성하지만, 모든 곳에서 검증하지 않음
// - POST 프로필 수정: 토큰 생성만 하고 검증 안 함
// - GET 프로필 수정: 토큰 없어도 허용
// - 선물 보내기: 토큰 검증 전혀 없음
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// 프로필 업데이트
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update_profile'])) {
    $email = $_POST['email'];
    $full_name = $_POST['full_name'];
    $bio = $_POST['bio'];

    // 중급 보안: CSRF 토큰 검증 (하지만 GET 요청도 허용)
    // 취약점: GET 메소드로도 프로필 수정 가능
    $conn = getConnection();
    $user_id = $_SESSION['user_id'];

    $query = "UPDATE users SET email = '$email', full_name = '$full_name', bio = '$bio'
              WHERE id = $user_id";

    if ($conn->query($query) === TRUE) {
        $success = "✅ 프로필이 업데이트되었습니다!";
        $user = getCurrentUser(); // 새로고침
    } else {
        $error = "❌ 업데이트 실패: " . $conn->error;
    }

    $conn->close();
}

// 취약점: GET 요청으로도 프로필 수정 가능 (CSRF 공격 가능)
if ($_SERVER['REQUEST_METHOD'] == 'GET' && isset($_GET['email'])) {
    $email = $_GET['email'];
    $full_name = isset($_GET['full_name']) ? $_GET['full_name'] : $user['full_name'];
    $bio = isset($_GET['bio']) ? $_GET['bio'] : $user['bio'];

    $conn = getConnection();
    $user_id = $_SESSION['user_id'];

    $query = "UPDATE users SET email = '$email', full_name = '$full_name', bio = '$bio'
              WHERE id = $user_id";

    if ($conn->query($query) === TRUE) {
        $success = "✅ 프로필이 업데이트되었습니다! (GET)";
        $user = getCurrentUser();
    }

    $conn->close();
}

// 선물 보내기
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['send_gift'])) {
    $receiver_id = $_POST['receiver_id'];
    $gift_type = $_POST['gift_type'];
    $points = (int)$_POST['points'];
    $message = $_POST['message'];
    $sender_id = $_SESSION['user_id'];

    // 취약점: CSRF 토큰 검증 없음!
    if ($user['points'] >= $points) {
        $conn = getConnection();

        // 포인트 차감
        $query1 = "UPDATE users SET points = points - $points WHERE id = $sender_id";
        $query2 = "UPDATE users SET points = points + $points WHERE id = $receiver_id";
        $query3 = "INSERT INTO gifts (sender_id, receiver_id, gift_type, points, message)
                   VALUES ($sender_id, $receiver_id, '$gift_type', $points, '$message')";

        $conn->query($query1);
        $conn->query($query2);
        $conn->query($query3);

        $conn->close();
        $gift_sent = true;
        $user = getCurrentUser(); // 포인트 새로고침
    } else {
        $error = "❌ 포인트가 부족합니다!";
    }
}

// 선물 받을 사용자 정보
$gift_to_user = null;
if (isset($_GET['gift_to'])) {
    $conn = getConnection();
    $gift_to_id = (int)$_GET['gift_to'];
    $query = "SELECT * FROM users WHERE id = $gift_to_id";
    $result = $conn->query($query);
    if ($result && $result->num_rows > 0) {
        $gift_to_user = $result->fetch_assoc();
    }
    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>프로필 - Vulnerable SNS</title>
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
            max-width: 800px;
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
            margin-bottom: 20px;
            color: #262626;
            font-size: 18px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #262626;
            font-size: 14px;
        }
        input[type="text"],
        input[type="email"],
        input[type="number"],
        textarea,
        select {
            width: 100%;
            padding: 12px;
            border: 1px solid #dbdbdb;
            border-radius: 8px;
            font-size: 14px;
        }
        textarea {
            min-height: 80px;
            font-family: inherit;
            resize: vertical;
        }
        input:focus, textarea:focus, select:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            padding: 10px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
        }
        .success {
            background: #d4edda;
            color: #155724;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #28a745;
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
        .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            font-size: 13px;
        }
        .info-box code {
            background: white;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
        }
        .points-badge {
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 600;
            margin-bottom: 20px;
        }
        .gift-item {
            padding: 15px;
            border: 2px solid #dbdbdb;
            border-radius: 8px;
            margin-bottom: 10px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .gift-item:hover {
            border-color: #667eea;
            background: #f8f9fa;
        }
        .gift-item input[type="radio"] {
            margin-right: 10px;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-content">
            <a href="index.php" class="back-btn">
                <i class="fas fa-arrow-left"></i>
            </a>
            <h1>프로필 설정</h1>
        </div>
    </nav>

    <div class="container">
        <div class="warning">
            <strong>⚠️ CSRF 취약점:</strong> GET 요청으로도 프로필 수정 가능, 선물 보내기에 CSRF 토큰 없음<br>
            💡 힌트: 악의적인 링크를 클릭하면 자동으로 프로필이 변경될 수 있습니다.
        </div>

        <?php if ($success): ?>
            <div class="success"><?php echo $success; ?></div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="error"><?php echo $error; ?></div>
        <?php endif; ?>

        <?php if ($gift_sent): ?>
            <div class="success">
                🎁 선물이 전송되었습니다! 남은 포인트: <?php echo $user['points']; ?>P
            </div>
        <?php endif; ?>

        <!-- 선물 보내기 모달 (gift_to 파라미터가 있을 때) -->
        <?php if ($gift_to_user): ?>
        <div class="card">
            <h2><i class="fas fa-gift"></i> <?php echo htmlspecialchars($gift_to_user['username']); ?>에게 선물 보내기</h2>
            <div class="points-badge">
                <i class="fas fa-coins"></i> 내 포인트: <?php echo $user['points']; ?>P
            </div>

            <form method="POST">
                <input type="hidden" name="send_gift" value="1">
                <input type="hidden" name="receiver_id" value="<?php echo $gift_to_user['id']; ?>">

                <div class="form-group">
                    <label><i class="fas fa-gift"></i> 선물 종류</label>
                    <select name="gift_type" required>
                        <option value="coffee">☕ 커피 (100P)</option>
                        <option value="flower">🌹 꽃다발 (500P)</option>
                        <option value="cake">🎂 케이크 (1000P)</option>
                        <option value="diamond">💎 다이아몬드 (5000P)</option>
                    </select>
                </div>

                <div class="form-group">
                    <label><i class="fas fa-coins"></i> 포인트</label>
                    <input type="number" name="points" value="100" min="1" required>
                </div>

                <div class="form-group">
                    <label><i class="fas fa-comment"></i> 메시지</label>
                    <textarea name="message" placeholder="응원 메시지를 남겨주세요..."></textarea>
                </div>

                <!-- 취약점: CSRF 토큰 없음! -->
                <button type="submit" class="btn">
                    <i class="fas fa-paper-plane"></i> 선물 보내기
                </button>
            </form>
        </div>
        <?php endif; ?>

        <!-- 프로필 수정 -->
        <div class="card">
            <h2><i class="fas fa-user-edit"></i> 프로필 수정</h2>
            <div class="points-badge">
                <i class="fas fa-coins"></i> 포인트: <?php echo $user['points']; ?>P
            </div>

            <form method="POST">
                <input type="hidden" name="update_profile" value="1">
                <!-- CSRF 토큰은 있지만 검증이 약함 -->
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                <div class="form-group">
                    <label><i class="fas fa-user"></i> 사용자명 (변경 불가)</label>
                    <input type="text" value="<?php echo htmlspecialchars($user['username']); ?>" disabled>
                </div>

                <div class="form-group">
                    <label><i class="fas fa-envelope"></i> 이메일</label>
                    <input type="email" name="email" value="<?php echo htmlspecialchars($user['email']); ?>">
                </div>

                <div class="form-group">
                    <label><i class="fas fa-id-card"></i> 이름</label>
                    <input type="text" name="full_name" value="<?php echo htmlspecialchars($user['full_name']); ?>">
                </div>

                <div class="form-group">
                    <label><i class="fas fa-info-circle"></i> 자기소개</label>
                    <textarea name="bio"><?php echo htmlspecialchars($user['bio']); ?></textarea>
                </div>

                <button type="submit" class="btn">
                    <i class="fas fa-save"></i> 저장하기
                </button>
            </form>

            <div class="info-box">
                <strong><i class="fas fa-exclamation-triangle"></i> CSRF 공격 예제:</strong><br>
                GET 요청으로 프로필 수정:<br>
                <code>profile.php?email=hacked@evil.com&full_name=Hacked</code><br><br>
                악의적인 HTML 페이지에서 자동 선물 전송 가능 (CSRF 토큰 없음)
            </div>
        </div>

        <div class="card">
            <h2><i class="fas fa-history"></i> 받은 선물</h2>
            <?php
            $conn = getConnection();
            $user_id = $_SESSION['user_id'];
            $gifts_query = "SELECT g.*, u.username FROM gifts g
                            JOIN users u ON g.sender_id = u.id
                            WHERE g.receiver_id = $user_id
                            ORDER BY g.created_at DESC
                            LIMIT 10";
            $gifts_result = $conn->query($gifts_query);

            if ($gifts_result && $gifts_result->num_rows > 0):
                while ($gift = $gifts_result->fetch_assoc()):
            ?>
            <div style="padding: 15px; border-bottom: 1px solid #dbdbdb;">
                <strong><?php echo htmlspecialchars($gift['username']); ?></strong>님이
                <span style="color: #667eea;"><?php echo $gift['gift_type']; ?></span>를 보냈습니다
                (<?php echo $gift['points']; ?>P)
                <br>
                <small style="color: #8e8e8e;"><?php echo $gift['message']; ?></small>
                <br>
                <small style="color: #8e8e8e;"><?php echo date('Y-m-d H:i', strtotime($gift['created_at'])); ?></small>
            </div>
            <?php
                endwhile;
            else:
            ?>
            <p style="text-align: center; color: #8e8e8e; padding: 20px;">받은 선물이 없습니다.</p>
            <?php endif;
            $conn->close();
            ?>
        </div>
    </div>
</body>
</html>
