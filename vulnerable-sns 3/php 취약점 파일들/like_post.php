<?php
// like_post.php - 좋아요 기능
include 'config.php';
requireLogin();

if (isset($_GET['id'])) {
    $post_id = $_GET['id'];
    $conn = getConnection();

    $query = "UPDATE posts SET likes = likes + 1 WHERE id = $post_id";
    $conn->query($query);
    $conn->close();
}

header('Location: index.php');
exit();
?>
