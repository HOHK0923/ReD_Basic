<?php
// setup.php - 데이터베이스 초기화
// AWS EC2에서 처음 실행 시 한 번만 실행

$host = 'localhost';
$user = 'root';
$pass = 'vulnerable123';

echo "<h1>🔧 Vulnerable SNS 데이터베이스 설정</h1>";
echo "<hr>";

// 데이터베이스 연결
$conn = new mysqli($host, $user, $pass);

if ($conn->connect_error) {
    die("연결 실패: " . $conn->connect_error);
}

// 데이터베이스 생성
$sql = "CREATE DATABASE IF NOT EXISTS vulnerable_sns CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci";
if ($conn->query($sql) === TRUE) {
    echo "✅ 데이터베이스 'vulnerable_sns' 생성 완료<br>";
} else {
    echo "❌ 오류: " . $conn->error . "<br>";
}

$conn->select_db('vulnerable_sns');

// 사용자 테이블
$sql = "CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    full_name VARCHAR(100),
    bio TEXT,
    profile_image VARCHAR(255),
    points INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

if ($conn->query($sql) === TRUE) {
    echo "✅ 사용자 테이블 생성 완료<br>";
} else {
    echo "❌ 오류: " . $conn->error . "<br>";
}

// 게시물 테이블
$sql = "CREATE TABLE IF NOT EXISTS posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    image VARCHAR(255),
    likes INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_created (created_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

if ($conn->query($sql) === TRUE) {
    echo "✅ 게시물 테이블 생성 완료<br>";
} else {
    echo "❌ 오류: " . $conn->error . "<br>";
}

// 댓글 테이블
$sql = "CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_post (post_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

if ($conn->query($sql) === TRUE) {
    echo "✅ 댓글 테이블 생성 완료<br>";
} else {
    echo "❌ 오류: " . $conn->error . "<br>";
}

// 선물 테이블
$sql = "CREATE TABLE IF NOT EXISTS gifts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    gift_type VARCHAR(50) NOT NULL,
    points INT NOT NULL,
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

if ($conn->query($sql) === TRUE) {
    echo "✅ 선물 테이블 생성 완료<br>";
} else {
    echo "❌ 오류: " . $conn->error . "<br>";
}

// 테스트 데이터 삽입
$sql = "INSERT IGNORE INTO users (id, username, password, email, full_name, bio, points) VALUES
    (1, 'admin', 'admin123', 'admin@sns.com', '관리자', '시스템 관리자입니다.', 10000),
    (2, 'alice', 'alice2024', 'alice@email.com', '앨리스', '여행을 좋아하는 앨리스입니다 ✈️', 500),
    (3, 'bob', 'bobby123', 'bob@email.com', '밥', '개발자 밥입니다 💻', 300),
    (4, 'charlie', 'charlie99', 'charlie@email.com', '찰리', '사진 찍는 것을 좋아합니다 📸', 150),
    (5, 'david', 'david456', 'david@email.com', '데이빗', '음악이 좋아요 🎵', 200)";

if ($conn->query($sql) === TRUE) {
    echo "✅ 사용자 데이터 삽입 완료<br>";
} else {
    echo "❌ 오류: " . $conn->error . "<br>";
}

$sql = "INSERT IGNORE INTO posts (user_id, content, likes) VALUES
    (2, '안녕하세요! 오늘 날씨가 정말 좋네요 🌞', 15),
    (3, '새로운 프로젝트를 시작했어요. 응원해주세요! 💪', 23),
    (4, '제주도 여행 다녀왔어요. 사진 공유합니다!', 42),
    (2, '맛있는 카페 발견! 다들 가보세요 ☕', 18),
    (5, '오늘 들은 노래가 너무 좋아서 공유해요 🎶', 31)";

if ($conn->query($sql) === TRUE) {
    echo "✅ 게시물 데이터 삽입 완료<br>";
} else {
    echo "❌ 오류: " . $conn->error . "<br>";
}

$sql = "INSERT IGNORE INTO comments (post_id, user_id, content) VALUES
    (1, 3, '정말 좋은 날씨네요!'),
    (1, 4, '저도 산책 다녀왔어요 😊'),
    (2, 2, '응원합니다! 화이팅!'),
    (3, 5, '사진 예쁘네요!'),
    (4, 3, '저도 가고 싶어요!')";

if ($conn->query($sql) === TRUE) {
    echo "✅ 댓글 데이터 삽입 완료<br>";
} else {
    echo "❌ 오류: " . $conn->error . "<br>";
}

echo "<br><h2>✨ 설정 완료!</h2>";
echo "<p><strong>테스트 계정:</strong></p>";
echo "<ul>";
echo "<li>admin / admin123 (관리자, 10000 포인트)</li>";
echo "<li>alice / alice2024 (500 포인트)</li>";
echo "<li>bob / bobby123 (300 포인트)</li>";
echo "<li>charlie / charlie99 (150 포인트)</li>";
echo "</ul>";
echo "<br><a href='login.php' style='background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>→ 로그인 페이지로 이동</a>";

$conn->close();
?>
