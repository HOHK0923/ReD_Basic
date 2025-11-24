# RedChain - Integrated Penetration Testing Framework

**교육 및 연구 목적 전용 / Educational & Research Purpose Only**

---

## 📋 개요

RedChain은 기존의 개별 공격 스크립트들을 하나의 통합 CLI 인터페이스로 제공하는 침투 테스트 프레임워크입니다.

**특징:**
- 🎯 **대화형 CLI** - pwndbg 스타일의 직관적인 명령어 인터페이스
- 🔧 **설정 관리** - 타겟 서버, SSH 정보, Tor 설정 등을 저장/관리
- 🚀 **자동화** - 전체 공격 체인을 자동으로 실행
- 🔐 **Tor 지원** - 옵션으로 Tor를 통한 익명 스캔 지원 (기존 코드 기능 유지)
- 📊 **통합 인터페이스** - 포트스캔, 엔드포인트 탐색, AWS 공격, 웹변조 등 모든 기능을 하나의 도구에서

---

## 🚀 설치

### 1. 의존성 설치

```bash
# Kali Linux / Ubuntu / Debian
sudo apt update
sudo apt install -y python3 python3-pip nmap ffuf tor proxychains4

# Python 패키지
pip3 install requests
```

### 2. Tor 설정 (선택사항)

Tor를 사용하려면 Tor 서비스를 시작해야 합니다:

```bash
# Tor 서비스 시작
sudo systemctl start tor

# Tor 상태 확인
sudo systemctl status tor

# proxychains 설정 확인 (/etc/proxychains4.conf)
# 마지막 줄에 다음이 있어야 함:
# socks5 127.0.0.1 9050
```

### 3. RedChain 설치

```bash
# 실행 권한 부여
cd /Users/hwangjunha/Desktop/Red_basic_local/H/CLEAN_PROJECT/06_Integrated_Tool
chmod +x redchain.py

# 심볼릭 링크 생성 (선택사항)
sudo ln -s $(pwd)/redchain.py /usr/local/bin/redchain
```

---

## 📖 사용법

### 기본 실행

```bash
# 직접 실행
./redchain.py

# 또는 (심볼릭 링크 생성한 경우)
redchain
```

### 초기 설정

RedChain을 처음 실행하면 다음과 같이 설정합니다:

```
redchain> set target 52.79.240.83          # 타겟 서버 IP 또는 도메인
redchain> set ssh_user sysadmin             # SSH 사용자명
redchain> set ssh_key ~/.ssh/my-key.pem     # SSH 키 경로 (선택사항)
redchain> set tor on                        # Tor 사용 (선택사항)
redchain> show                              # 설정 확인
```

**설정은 자동으로 `~/.redchain_config.json`에 저장됩니다.**

---

## 🎯 주요 명령어

### 설정 명령어

| 명령어 | 설명 | 예제 |
|--------|------|------|
| `set target <IP/도메인>` | 타겟 서버 설정 | `set target 52.79.240.83` |
| `set ssh_user <사용자>` | SSH 사용자 설정 | `set ssh_user ec2-user` |
| `set ssh_key <경로>` | SSH 키 경로 설정 | `set ssh_key ~/.ssh/key.pem` |
| `set tor on/off` | Tor 사용 설정 | `set tor on` |
| `show` | 현재 설정 표시 | `show` |

### 정찰 명령어

| 명령어 | 설명 | 예제 |
|--------|------|------|
| `scan` | 포트 스캔 (기본) | `scan` |
| `scan full` | 전체 포트 스캔 | `scan full` |
| `scan <포트>` | 특정 포트 스캔 | `scan 80,443,8080` |
| `enum` | 엔드포인트 탐색 | `enum` |
| `enum api` | API 엔드포인트 탐색 | `enum api` |
| `enum admin` | 관리자 페이지 탐색 | `enum admin` |

### 공격 명령어

| 명령어 | 설명 | 실행되는 스크립트 |
|--------|------|-------------------|
| `imds` | AWS IMDS 공격 | `120_aws_imds_exploit.py` |
| `escalate` | AWS 권한 상승 | `121_aws_privilege_escalation.py` |
| `deface` | 웹사이트 변조 (랜섬웨어) | `SILENT_DOWNLOAD.sh` |
| `deface modern` | 모던 해킹 페이지 | `MODERN_DEFACEMENT.sh` |
| `deface restore` | 원본 복구 | `TOGGLE_SITE.sh` |

### SSH 명령어

| 명령어 | 설명 | 예제 |
|--------|------|------|
| `ssh` | 대화형 SSH 연결 | `ssh` |
| `ssh <명령어>` | 원격 명령 실행 | `ssh whoami` |
| `scp <로컬> <원격>` | 파일 업로드 | `scp /tmp/file.txt /home/` |
| `scp -d <원격> <로컬>` | 파일 다운로드 | `scp -d /var/log/access.log ./` |

### 자동화 명령어

| 명령어 | 설명 |
|--------|------|
| `auto recon` | 정찰만 (포트스캔 + 엔드포인트) |
| `auto exploit` | 공격만 (IMDS → 권한상승 → 변조) |
| `auto full` | 정찰 + 공격 전체 |

### 유틸리티

| 명령어 | 설명 |
|--------|------|
| `help` | 명령어 목록 |
| `help <명령어>` | 특정 명령어 도움말 |
| `clear` | 화면 지우기 |
| `exit` 또는 `quit` | 종료 |

---

## 📝 사용 예제

### 시나리오 1: 정찰만 수행

```bash
./redchain.py

redchain> set target example.com
redchain> set tor on              # 익명 스캔 (선택사항)
redchain> scan                    # 포트 스캔
redchain> enum api                # API 엔드포인트 탐색
redchain> exit
```

### 시나리오 2: 전체 공격 체인 수행

```bash
./redchain.py

redchain> set target 52.79.240.83
redchain> set ssh_user sysadmin
redchain> set ssh_key ~/.ssh/my-key.pem
redchain> auto full               # 정찰 + 공격 전체 자동 실행
```

### 시나리오 3: 수동으로 각 단계 실행

```bash
./redchain.py

redchain> set target 52.79.240.83
redchain> set ssh_user ec2-user

# 1. 정찰
redchain> scan
redchain> enum

# 2. AWS IMDS 공격
redchain> imds

# 3. AWS 권한 확인
redchain> escalate

# 4. 웹사이트 변조
redchain> deface

# 5. 원격 명령 실행
redchain> ssh whoami
redchain> ssh 'ls -la /var/www/html'

# 6. 복구
redchain> deface restore
```

### 시나리오 4: IP가 자주 바뀌는 서버 관리

**설정 파일을 사용하면 IP만 업데이트하면 됩니다:**

```bash
# 오늘 IP: 52.79.240.83
redchain> set target 52.79.240.83
redchain> ssh                     # SSH 연결

# 내일 IP가 바뀌면
redchain> set target 52.79.240.100
redchain> ssh                     # 새 IP로 자동 연결
```

**또는 도메인 사용:**

```bash
# IP 대신 도메인 설정 (IP가 바뀌어도 도메인은 동일)
redchain> set target myserver.example.com
redchain> ssh                     # 도메인으로 자동 연결
```

---

## 🔍 공격 체인 흐름

RedChain이 자동으로 실행하는 공격 체인:

```
1. 정찰 (Reconnaissance)
   ├─ 포트 스캔 (nmap)
   └─ 엔드포인트 탐색 (ffuf)

2. 초기 침투 (Initial Access)
   └─ /api/health.php SSRF 발견 및 악용

3. 자격 증명 탈취 (Credential Access)
   ├─ IMDS 접근
   ├─ IAM Role 이름 획득
   └─ IAM Credentials 탈취

4. 권한 상승 (Privilege Escalation)
   ├─ AWS 리소스 열거 (EC2, S3, RDS)
   ├─ Secrets Manager 탈취
   └─ SSM 원격 명령 실행

5. 지속성 확보 (Persistence)
   ├─ 웹사이트 변조
   ├─ 백도어 설치
   └─ 악성코드 배포
```

---

## ⚙️ 고급 설정

### 1. Tor 사용

```bash
# Tor 활성화
redchain> set tor on

# Tor를 통한 포트 스캔 (느림)
redchain> scan

# Tor를 통한 엔드포인트 탐색
redchain> enum api
```

**주의**: Tor를 통한 스캔은 매우 느립니다. 정찰 단계에서만 사용하는 것을 권장합니다.

### 2. SSH 키 없이 비밀번호 인증

```bash
# SSH 키 설정하지 않으면 비밀번호를 물어봅니다
redchain> set ssh_user sysadmin
# ssh_key는 설정하지 않음

redchain> ssh
# 비밀번호 입력 프롬프트 표시됨
```

### 3. 여러 타겟 관리

```bash
# 타겟 1
redchain> set target server1.example.com
redchain> scan
redchain> imds

# 타겟 2로 전환
redchain> set target server2.example.com
redchain> scan
redchain> imds
```

설정은 자동으로 저장되므로, 마지막으로 설정한 타겟이 다음 실행 시 기본값이 됩니다.

---

## 🛠️ 문제 해결

### 1. "nmap: command not found"

```bash
sudo apt install nmap
```

### 2. "ffuf: command not found"

```bash
# ffuf 설치
sudo apt install ffuf

# 또는 Go로 설치
go install github.com/ffuf/ffuf@latest
```

### 3. Tor 연결 실패

```bash
# Tor 서비스 시작
sudo systemctl start tor

# Tor 포트 확인 (9050이 열려있어야 함)
netstat -tlnp | grep 9050
```

### 4. SSH 키 권한 오류

```bash
# SSH 키 권한 수정
chmod 600 ~/.ssh/my-key.pem
```

### 5. Python import 오류

```bash
# requests 패키지 설치
pip3 install requests

# 또는
sudo apt install python3-requests
```

---

## ⚠️ 법적 고지

**이 도구는 교육 및 연구 목적으로만 사용되어야 합니다.**

- ✅ **허가된 환경**에서만 사용 (자신의 서버, CTF, 테스트 환경)
- ❌ **실제 운영 시스템**에 절대 사용 금지
- ❌ **승인되지 않은 시스템**에 사용 시 법적 책임

**관련 법률:**
- 정보통신망법 위반 시 최대 5년 이하 징역
- 전자금융거래법 위반 시 최대 10년 이하 징역
- 형법 제347조의2 (컴퓨터등 사용사기)

**무단 사용으로 인한 모든 법적 책임은 사용자에게 있습니다.**

---

## 📚 참고 자료

- [프로젝트 README](../README.md) - 전체 프로젝트 개요
- [공격 체인 상세 분석](../03_Documentation/COMPLETE_ATTACK_ANALYSIS.md)
- [AWS IMDS 공격 스크립트](../01_AWS_IMDS_Attack/)
- [웹사이트 변조 스크립트](../02_Site_Defacement/)

---

## 🎓 학습 목적

이 도구는 다음을 학습하기 위해 만들어졌습니다:

1. **SSRF (Server-Side Request Forgery)** - 서버 측 요청 위조 취약점
2. **AWS IMDS 공격** - IMDSv1 취약점 악용
3. **권한 상승** - IAM Credentials를 통한 AWS 인프라 접근
4. **웹 공격** - ModSecurity WAF 우회 기법
5. **자동화** - 침투 테스트 도구 개발 및 자동화

**완벽한 보안 시스템도 작은 설정 실수 하나로 무너질 수 있다는 것을 보여줍니다.**

---

**멘티**: 황준하
**희망분야**: AWS 클라우드 보안
**프로젝트 기간**: 2025년 11월
**멘토링**: 보안 전문가 현직자 멘토링 프로그램
