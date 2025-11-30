<?php
// =============================================================================
// config.php - 데이터베이스 연결 설정
// =============================================================================
//
// 이 파일의 목적:
// - 데이터베이스 연결 정보 중앙 관리
// - 공통 함수 제공 (로그인 체크, 사용자 정보 조회 등)
//
// ⚠️ 주요 보안 취약점:
// 1. 하드코딩된 자격증명 (DB_USER, DB_PASS)
//    → LFI 취약점을 통해 이 파일이 노출되면 DB 접근 가능
//    → 실제 환경에서는 환경 변수(.env)나 설정 파일로 분리해야 함
//
// 2. 상세한 에러 메시지 노출
//    → 공격자에게 DB 구조, 버전 정보 등을 알려줌
//
// 3. root 계정 사용
//    → 최소 권한 원칙 위반
//    → 실제로는 제한된 권한을 가진 별도 계정을 사용해야 함

// 데이터베이스 접속 정보 (⚠️ 하드코딩 - 보안 취약점)
define('DB_HOST', 'localhost');
define('DB_USER', 'root');           // ⚠️ root 계정 사용 (권장하지 않음)
define('DB_PASS', 'vulnerable123');  // ⚠️ 약한 비밀번호
define('DB_NAME', 'vulnerable_sns');

// 업로드 디렉토리
define('UPLOAD_DIR', __DIR__ . '/uploads/');
define('UPLOAD_URL', '/uploads/');

// 데이터베이스 연결
function getConnection() {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

    // 취약점: 상세한 에러 메시지 노출
    if ($conn->connect_error) {
        die("❌ 데이터베이스 연결 실패: " . $conn->connect_error);
    }

    $conn->set_charset("utf8mb4");
    return $conn;
}

// 세션 시작
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// 로그인 확인 함수
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

// 로그인 체크 (리다이렉트)
function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: login.php');
        exit();
    }
}

// 현재 사용자 정보 가져오기
function getCurrentUser() {
    if (!isLoggedIn()) {
        return null;
    }

    $conn = getConnection();
    $user_id = $_SESSION['user_id'];

    // 취약점: SQL Injection 가능
    $query = "SELECT * FROM users WHERE id = $user_id";
    $result = $conn->query($query);

    if ($result && $result->num_rows > 0) {
        $user = $result->fetch_assoc();
        $conn->close();
        return $user;
    }

    $conn->close();
    return null;
}
?>
