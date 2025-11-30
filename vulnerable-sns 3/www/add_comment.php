<?php
// add_comment.php - 댓글 추가 (XSS 취약)
include 'config.php';
requireLogin();

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $post_id = $_POST['post_id'];
    $content = $_POST['content'];
    $user_id = $_SESSION['user_id'];

    $conn = getConnection();

    // 취약점: 필터링 없이 그대로 저장
    $query = "INSERT INTO comments (post_id, user_id, content)
              VALUES ($post_id, $user_id, '$content')";

    $conn->query($query);
    $conn->close();
}

header('Location: index.php');
exit();
?>
