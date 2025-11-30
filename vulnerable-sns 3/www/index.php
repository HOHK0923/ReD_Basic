<?php
// index.php - 메인 피드 (XSS 취약)
include 'config.php';
requireLogin();

$user = getCurrentUser();
$conn = getConnection();

// 게시물 조회
$posts_query = "SELECT p.*, u.username, u.full_name, u.profile_image
                FROM posts p
                JOIN users u ON p.user_id = u.id
                ORDER BY p.created_at DESC
                LIMIT 50";
$posts_result = $conn->query($posts_query);

$conn->close();
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>홈 - Vulnerable SNS</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #fafafa;
        }
        .navbar {
            background: white;
            border-bottom: 1px solid #dbdbdb;
            padding: 15px 0;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .nav-content {
            max-width: 975px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0 20px;
        }
        .logo {
            font-size: 24px;
            font-weight: 700;
            color: #262626;
        }
        .logo i {
            color: #667eea;
            margin-right: 8px;
        }
        .nav-links {
            display: flex;
            gap: 20px;
            align-items: center;
        }
        .nav-links a {
            color: #262626;
            text-decoration: none;
            font-size: 24px;
            transition: color 0.2s;
        }
        .nav-links a:hover {
            color: #667eea;
        }
        .user-info {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .user-info span {
            font-weight: 600;
            color: #262626;
        }
        .container {
            max-width: 600px;
            margin: 40px auto;
            padding: 0 20px;
        }
        .post-card {
            background: white;
            border: 1px solid #dbdbdb;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .post-header {
            padding: 15px;
            display: flex;
            align-items: center;
            gap: 12px;
            border-bottom: 1px solid #efefef;
        }
        .post-avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 700;
            font-size: 18px;
        }
        .post-info {
            flex: 1;
        }
        .post-author {
            font-weight: 600;
            color: #262626;
        }
        .post-time {
            font-size: 12px;
            color: #8e8e8e;
        }
        .post-content {
            padding: 15px;
            color: #262626;
            line-height: 1.6;
        }
        .post-image {
            width: 100%;
            max-height: 600px;
            object-fit: cover;
        }
        .post-actions {
            padding: 12px 15px;
            display: flex;
            gap: 15px;
            border-top: 1px solid #efefef;
        }
        .post-actions button {
            background: none;
            border: none;
            color: #262626;
            font-size: 20px;
            cursor: pointer;
            transition: color 0.2s;
        }
        .post-actions button:hover {
            color: #667eea;
        }
        .post-likes {
            padding: 0 15px 10px;
            font-weight: 600;
            color: #262626;
            font-size: 14px;
        }
        .post-comments {
            padding: 15px;
            border-top: 1px solid #efefef;
        }
        .comment {
            margin-bottom: 10px;
            font-size: 14px;
        }
        .comment-author {
            font-weight: 600;
            color: #262626;
            margin-right: 8px;
        }
        .comment-content {
            color: #262626;
        }
        .comment-form {
            display: flex;
            gap: 10px;
            margin-top: 10px;
        }
        .comment-form input {
            flex: 1;
            border: none;
            outline: none;
            font-size: 14px;
            padding: 8px;
        }
        .comment-form button {
            background: none;
            border: none;
            color: #667eea;
            font-weight: 600;
            cursor: pointer;
        }
        .new-post-btn {
            position: fixed;
            bottom: 30px;
            right: 30px;
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            font-size: 24px;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
            transition: transform 0.2s;
        }
        .new-post-btn:hover {
            transform: scale(1.1);
        }
        .warning-banner {
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            color: #856404;
        }
        .warning-banner strong {
            color: #d63031;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-content">
            <div class="logo">
                <i class="fas fa-shield-alt"></i>
                VulnerableSNS
            </div>
            <div class="nav-links">
                <a href="index.php" title="홈"><i class="fas fa-home"></i></a>
                <a href="upload.php" title="업로드"><i class="fas fa-cloud-upload-alt"></i></a>
                <a href="profile.php" title="프로필"><i class="fas fa-user"></i></a>
                <a href="logout.php" title="로그아웃"><i class="fas fa-sign-out-alt"></i></a>
            </div>
            <div class="user-info">
                <span><?php echo htmlspecialchars($user['username']); ?></span>
                <span style="color: #667eea;">| <?php echo $user['points']; ?> P</span>
            </div>
        </div>
    </nav>

    <div class="container">
        <div class="warning-banner">
            <strong>⚠️ XSS 취약점:</strong> 게시물과 댓글에 스크립트 삽입 가능 (중급 난이도)<br>
            💡 힌트: 일부 태그는 필터링되지만 우회 가능합니다.
        </div>

        <?php while ($post = $posts_result->fetch_assoc()): ?>
        <div class="post-card">
            <div class="post-header">
                <div class="post-avatar">
                    <?php echo strtoupper(substr($post['username'], 0, 1)); ?>
                </div>
                <div class="post-info">
                    <div class="post-author"><?php echo htmlspecialchars($post['username']); ?></div>
                    <div class="post-time"><?php echo date('Y-m-d H:i', strtotime($post['created_at'])); ?></div>
                </div>
            </div>

            <?php if ($post['image']): ?>
            <img src="<?php echo htmlspecialchars($post['image']); ?>" class="post-image" alt="Post image">
            <?php endif; ?>

            <div class="post-content">
                <!-- 취약점: XSS - htmlspecialchars 미사용 -->
                <?php echo $post['content']; ?>
            </div>

            <div class="post-likes">
                <i class="fas fa-heart" style="color: #ed4956;"></i>
                <?php echo $post['likes']; ?>명이 좋아합니다
            </div>

            <div class="post-actions">
                <button onclick="likePost(<?php echo $post['id']; ?>)">
                    <i class="far fa-heart"></i>
                </button>
                <button onclick="toggleComments(<?php echo $post['id']; ?>)">
                    <i class="far fa-comment"></i>
                </button>
                <a href="profile.php?gift_to=<?php echo $post['user_id']; ?>" style="text-decoration: none;">
                    <button>
                        <i class="fas fa-gift"></i>
                    </button>
                </a>
            </div>

            <div class="post-comments" id="comments-<?php echo $post['id']; ?>" style="display: none;">
                <?php
                $conn2 = getConnection();
                $post_id = $post['id'];
                $comments_query = "SELECT c.*, u.username FROM comments c
                                   JOIN users u ON c.user_id = u.id
                                   WHERE c.post_id = $post_id
                                   ORDER BY c.created_at ASC";
                $comments_result = $conn2->query($comments_query);

                while ($comment = $comments_result->fetch_assoc()):
                ?>
                <div class="comment">
                    <span class="comment-author"><?php echo htmlspecialchars($comment['username']); ?></span>
                    <!-- 취약점: XSS - 댓글에도 필터링 없음 -->
                    <span class="comment-content"><?php echo $comment['content']; ?></span>
                </div>
                <?php endwhile;
                $conn2->close();
                ?>

                <form method="POST" action="add_comment.php" class="comment-form">
                    <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                    <input type="text" name="content" placeholder="댓글 달기..." required>
                    <button type="submit">게시</button>
                </form>
            </div>
        </div>
        <?php endwhile; ?>
    </div>

    <a href="new_post.php">
        <button class="new-post-btn">
            <i class="fas fa-plus"></i>
        </button>
    </a>

    <script>
        function likePost(postId) {
            fetch('like_post.php?id=' + postId)
                .then(() => location.reload());
        }

        function toggleComments(postId) {
            const comments = document.getElementById('comments-' + postId);
            comments.style.display = comments.style.display === 'none' ? 'block' : 'none';
        }
    </script>
</body>
</html>
