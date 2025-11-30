<?php
// download.php - 파일 다운로드 (취약점)
include 'config.php';
requireLogin();

if (isset($_GET['file'])) {
    $filename = $_GET['file'];

    // 취약점: 경로 검증 없음
    $file_path = UPLOAD_DIR . $filename;

    // 취약점: ../ 를 사용하여 다른 파일도 다운로드 가능
    // 예: download.php?file=../../config.php

    if (file_exists($file_path)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($filename) . '"');
        header('Content-Length: ' . filesize($file_path));
        readfile($file_path);
        exit;
    } else {
        die("파일을 찾을 수 없습니다.");
    }
}

header('Location: upload.php');
exit();
?>
