<?php
// 최소 DB 연결 테스트
$mysqli = new mysqli("localhost", "root", "vulnerable123", "vulnerable_sns");

if ($mysqli->connect_error) {
    die("DB 연결 실패: " . $mysqli->connect_error);
}

echo "DB 연결 성공!";
$mysqli->close();
?>

