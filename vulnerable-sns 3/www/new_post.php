<?php
// new_post.php - 새 게시물 작성 (XSS 취약)
include 'config.php';
requireLogin();

$user = getCurrentUser();
$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $content = $_POST['content'];
    $user_id = $_SESSION['user_id'];

    // 중급 보안: 일부 태그만 필터링 (불완전)
    $dangerous_tags = ['<script', '<iframe', '<object', '<embed'];
    $is_blocked = false;

    foreach ($dangerous_tags as $tag) {
        // 취약점: 대소문자 혼합, 인코딩으로 우회 가능
        if (stripos($content, $tag) !== false) {
            $is_blocked = true;
            break;
        }
    }

    if ($is_blocked) {
        $error = "⚠️ 허용되지 않은 태그가 포함되어 있습니다.";
    } else {
        $conn = getConnection();

        // 취약점: SQL Injection도 가능
        $query = "INSERT INTO posts (user_id, content) VALUES ($user_id, '$content')";

        if ($conn->query($query) === TRUE) {
            header('Location: index.php');
            exit();
        } else {
            $error = "❌ 게시물 작성 실패: " . $conn->error;
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
    <title>새 게시물 - Vulnerable SNS</title>
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
            justify-content: space-between;
            align-items: center;
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
            max-width: 600px;
            margin: 40px auto;
            padding: 0 20px;
        }
        .card {
            background: white;
            border: 1px solid #dbdbdb;
            border-radius: 8px;
            padding: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 10px;
            font-weight: 600;
            color: #262626;
        }
        textarea {
            width: 100%;
            min-height: 200px;
            padding: 15px;
            border: 1px solid #dbdbdb;
            border-radius: 8px;
            font-size: 15px;
            font-family: inherit;
            resize: vertical;
        }
        textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
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
        .examples {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-top: 15px;
            font-size: 13px;
        }
        .examples h3 {
            font-size: 14px;
            margin-bottom: 10px;
            color: #667eea;
        }
        .examples code {
            display: block;
            background: white;
            padding: 8px;
            border-radius: 4px;
            margin: 5px 0;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-content">
            <a href="index.php" class="back-btn">
                <i class="fas fa-arrow-left"></i>
            </a>
            <h1>새 게시물</h1>
            <div style="width: 24px;"></div>
        </div>
    </nav>

    <div class="container">
        <div class="card">
            <div class="warning">
                <strong>⚠️ XSS 취약점 테스트 영역</strong><br>
                일부 위험한 태그는 차단되지만 우회 가능합니다.
            </div>

            <?php if ($error): ?>
                <div class="error"><?php echo $error; ?></div>
            <?php endif; ?>

            <form method="POST">
                <div class="form-group">
                    <label><i class="fas fa-pen"></i> 게시물 내용</label>
                    <textarea name="content" required placeholder="무슨 생각을 하고 계신가요?"></textarea>
                </div>

                <button type="submit" class="btn">
                    <i class="fas fa-paper-plane"></i> 게시하기
                </button>
            </form>

            <div class="examples">
                <h3><i class="fas fa-flask"></i> XSS 테스트 예제</h3>
                <p><strong>차단되는 태그:</strong></p>
                <code>&lt;script&gt;alert('XSS')&lt;/script&gt; ❌</code>
                <code>&lt;iframe src="..."&gt;&lt;/iframe&gt; ❌</code>

                <p style="margin-top: 10px;"><strong>우회 가능한 방법:</strong></p>
                <code>&lt;img src=x onerror=alert('XSS')&gt; ✅</code>
                <code>&lt;svg onload=alert(1)&gt; ✅</code>
                <code>&lt;body onload=alert(document.cookie)&gt; ✅</code>
                <code>&lt;input onfocus=alert(1) autofocus&gt; ✅</code>
            </div>
        </div>
    </div>
</body>
</html>
