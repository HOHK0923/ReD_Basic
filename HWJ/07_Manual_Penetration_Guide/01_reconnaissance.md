# Phase 1: 정찰 (Reconnaissance)

## 개요
정찰은 침투 테스트의 첫 번째 단계로, 대상 시스템에 대한 최대한 많은 정보를 수집하는 과정입니다. 포트 스캔, 서비스 식별, 디렉토리 탐색 등을 통해 공격 표면을 파악합니다.

## 필수 도구
- Nmap
- Nikto
- Gobuster
- Dirb
- Masscan
- Whatweb

---

## 1. 포트 스캔 (Port Scanning)

### 1.1 Nmap 기본 스캔
```bash
# 기본 SYN 스캔
nmap -sS 13.125.80.75

# 서비스 버전 탐지
nmap -sV 13.125.80.75

# OS 탐지
nmap -O 13.125.80.75

# 공격적인 스캔 (OS, 버전, 스크립트, traceroute)
nmap -A 13.125.80.75

# 전체 포트 스캔 (1-65535)
nmap -p- 13.125.80.75

# 빠른 스캔 (상위 100개 포트)
nmap -F 13.125.80.75

# UDP 스캔
nmap -sU 13.125.80.75
```

### 1.2 Nmap 고급 옵션
```bash
# 특정 포트 스캔
nmap -p 22,80,443,3306,8080 13.125.80.75

# 타이밍 템플릿 (0=느림, 5=빠름)
nmap -T4 13.125.80.75

# 방화벽 우회 (Fragmentation)
nmap -f 13.125.80.75

# Decoy 스캔 (다른 IP로 위장)
nmap -D RND:10 13.125.80.75

# 스크립트 스캔
nmap --script vuln 13.125.80.75
nmap --script http-enum 13.125.80.75
nmap --script ssl-cert 13.125.80.75

# 출력 저장
nmap -oN scan_results.txt 13.125.80.75
nmap -oX scan_results.xml 13.125.80.75
nmap -oA scan_all_formats 13.125.80.75
```

### 1.3 Masscan (대규모 고속 스캔)
```bash
# 매우 빠른 전체 포트 스캔
masscan 13.125.80.75 -p1-65535 --rate=1000

# 특정 포트 범위
masscan 13.125.80.75 -p80,443,8000-9000 --rate=10000

# 결과 저장
masscan 13.125.80.75 -p1-65535 -oL masscan_results.txt
```

---

## 2. 웹 서버 스캔

### 2.1 Nikto 웹 취약점 스캔
```bash
# 기본 스캔
nikto -h http://13.125.80.75

# HTTPS 스캔
nikto -h https://13.125.80.75

# 특정 포트 스캔
nikto -h http://13.125.80.75:8080

# 상세 출력
nikto -h http://13.125.80.75 -Display V

# 결과 저장
nikto -h http://13.125.80.75 -o nikto_results.html -Format html

# 특정 플러그인만 실행
nikto -h http://13.125.80.75 -Plugins "headers,cookies"

# Tuning (특정 유형 테스트)
nikto -h http://13.125.80.75 -Tuning x  # x=모든 테스트
```

### 2.2 Whatweb (웹 기술 탐지)
```bash
# 기본 스캔
whatweb http://13.125.80.75

# 상세 출력
whatweb -v http://13.125.80.75

# 공격적인 스캔
whatweb -a 3 http://13.125.80.75

# URL 리스트 스캔
whatweb -i urls.txt

# 결과 저장
whatweb http://13.125.80.75 -l whatweb_results.txt
```

---

## 3. 디렉토리 및 파일 탐색

### 3.1 Gobuster
```bash
# 기본 디렉토리 브루트포스
gobuster dir -u http://13.125.80.75 -w /usr/share/wordlists/dirb/common.txt

# 파일 확장자 지정
gobuster dir -u http://13.125.80.75 -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak

# 상태 코드 필터링
gobuster dir -u http://13.125.80.75 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 404,403

# 쿠키 사용
gobuster dir -u http://13.125.80.75 -w /usr/share/wordlists/dirb/common.txt -c "session=abc123"

# User-Agent 설정
gobuster dir -u http://13.125.80.75 -w /usr/share/wordlists/dirb/common.txt -a "Mozilla/5.0"

# 재귀 스캔 (하위 디렉토리)
gobuster dir -u http://13.125.80.75 -w /usr/share/wordlists/dirb/common.txt -r

# DNS 서브도메인 브루트포스
gobuster dns -d example.com -w /usr/share/wordlists/dnsmap.txt

# Vhost 브루트포스
gobuster vhost -u http://13.125.80.75 -w /usr/share/wordlists/subdomains.txt

# 결과 저장
gobuster dir -u http://13.125.80.75 -w /usr/share/wordlists/dirb/common.txt -o gobuster_results.txt
```

### 3.2 Dirb
```bash
# 기본 스캔
dirb http://13.125.80.75

# 커스텀 워드리스트
dirb http://13.125.80.75 /usr/share/wordlists/dirb/big.txt

# 파일 확장자 지정
dirb http://13.125.80.75 -X .php,.html,.txt

# 쿠키 설정
dirb http://13.125.80.75 -c "PHPSESSID=abc123"

# User-Agent 설정
dirb http://13.125.80.75 -a "Mozilla/5.0"

# 재귀 비활성화
dirb http://13.125.80.75 -r

# 결과 저장
dirb http://13.125.80.75 -o dirb_results.txt
```

### 3.3 Ffuf (빠른 파일/디렉토리 퍼징)
```bash
# 디렉토리 브루트포스
ffuf -u http://13.125.80.75/FUZZ -w /usr/share/wordlists/dirb/common.txt

# 파일 확장자 브루트포스
ffuf -u http://13.125.80.75/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.html,.txt

# 상태 코드 필터링
ffuf -u http://13.125.80.75/FUZZ -w /usr/share/wordlists/dirb/common.txt -fc 404

# 크기 필터링 (특정 크기 제외)
ffuf -u http://13.125.80.75/FUZZ -w /usr/share/wordlists/dirb/common.txt -fs 4242

# POST 데이터 퍼징
ffuf -u http://13.125.80.75/login.php -w /usr/share/wordlists/rockyou.txt -X POST -d "username=admin&password=FUZZ"

# 헤더 퍼징
ffuf -u http://13.125.80.75 -w /usr/share/wordlists/dirb/common.txt -H "X-Custom-Header: FUZZ"
```

---

## 4. 백업 파일 및 민감 파일 검색

### 4.1 일반적인 백업 파일 패턴
```bash
# Curl로 백업 파일 확인
curl -I http://13.125.80.75/config.php.bak
curl -I http://13.125.80.75/index.php.old
curl -I http://13.125.80.75/backup.sql
curl -I http://13.125.80.75/.git/config
curl -I http://13.125.80.75/.env

# 백업 파일 브루트포스 (Gobuster)
gobuster dir -u http://13.125.80.75 -w /usr/share/wordlists/dirb/common.txt -x bak,old,backup,swp,~,sql,zip,tar.gz

# Git 디렉토리 스캔
curl http://13.125.80.75/.git/HEAD
curl http://13.125.80.75/.git/config

# SVN 디렉토리
curl http://13.125.80.75/.svn/entries
```

### 4.2 민감 파일 리스트
```bash
# 일반적으로 확인해야 할 파일들
http://13.125.80.75/robots.txt
http://13.125.80.75/sitemap.xml
http://13.125.80.75/.htaccess
http://13.125.80.75/web.config
http://13.125.80.75/phpinfo.php
http://13.125.80.75/info.php
http://13.125.80.75/test.php
http://13.125.80.75/.env
http://13.125.80.75/composer.json
http://13.125.80.75/package.json
http://13.125.80.75/README.md
http://13.125.80.75/CHANGELOG.md
http://13.125.80.75/LICENSE
```

---

## 5. SSL/TLS 분석

### 5.1 SSLScan
```bash
# SSL/TLS 스캔
sslscan 13.125.80.75:443

# 상세 출력
sslscan --verbose 13.125.80.75:443

# 특정 프로토콜만 테스트
sslscan --tlsall 13.125.80.75:443
```

### 5.2 Nmap SSL 스크립트
```bash
# SSL 인증서 정보
nmap --script ssl-cert -p 443 13.125.80.75

# SSL 취약점 스캔
nmap --script ssl-enum-ciphers -p 443 13.125.80.75

# Heartbleed 취약점
nmap --script ssl-heartbleed -p 443 13.125.80.75

# SSL 프로토콜 버전
nmap --script ssl-known-key -p 443 13.125.80.75
```

### 5.3 OpenSSL 수동 테스트
```bash
# 인증서 정보 확인
openssl s_client -connect 13.125.80.75:443 -showcerts

# 특정 프로토콜 테스트
openssl s_client -connect 13.125.80.75:443 -tls1_2
openssl s_client -connect 13.125.80.75:443 -ssl3

# 암호화 스위트 확인
openssl s_client -connect 13.125.80.75:443 -cipher 'ECDHE-RSA-AES256-GCM-SHA384'
```

---

## 6. 정보 수집 자동화

### 6.1 자동화 스크립트 (Bash)
```bash
#!/bin/bash
# recon_auto.sh - 자동 정찰 스크립트

TARGET=$1
OUTPUT_DIR="recon_${TARGET}_$(date +%Y%m%d_%H%M%S)"

mkdir -p $OUTPUT_DIR
cd $OUTPUT_DIR

echo "[*] Starting reconnaissance on $TARGET"

# 1. Nmap 스캔
echo "[*] Running Nmap scan..."
nmap -sS -sV -O -p- -T4 $TARGET -oA nmap_full_scan

# 2. Nikto 스캔
echo "[*] Running Nikto scan..."
nikto -h http://$TARGET -o nikto_scan.html -Format html

# 3. Gobuster 디렉토리 스캔
echo "[*] Running Gobuster..."
gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak -o gobuster_scan.txt

# 4. 백업 파일 검색
echo "[*] Searching for backup files..."
for ext in bak old backup swp sql zip tar.gz; do
    curl -I http://$TARGET/config.php.$ext >> backup_files.txt 2>&1
    curl -I http://$TARGET/index.php.$ext >> backup_files.txt 2>&1
done

# 5. SSL 스캔 (443 포트 열려있으면)
if nmap -p 443 $TARGET | grep -q "open"; then
    echo "[*] Running SSL scan..."
    sslscan $TARGET:443 > sslscan_results.txt
fi

echo "[+] Reconnaissance complete! Results saved in $OUTPUT_DIR"
```

### 6.2 Python 자동화 스크립트
```python
#!/usr/bin/env python3
# recon_auto.py

import subprocess
import sys
import os
from datetime import datetime

def run_command(command, output_file=None):
    """명령 실행 및 결과 저장"""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(result.stdout)
        return result.stdout
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

def main(target):
    # 출력 디렉토리 생성
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = f"recon_{target}_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    os.chdir(output_dir)

    print(f"[*] Starting reconnaissance on {target}")

    # Nmap 스캔
    print("[*] Running Nmap scan...")
    run_command(f"nmap -sS -sV -p- -T4 {target}", "nmap_scan.txt")

    # Nikto 스캔
    print("[*] Running Nikto scan...")
    run_command(f"nikto -h http://{target}", "nikto_scan.txt")

    # Gobuster
    print("[*] Running Gobuster...")
    run_command(f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt", "gobuster_scan.txt")

    print(f"[+] Reconnaissance complete! Results in {output_dir}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 recon_auto.py <target_ip>")
        sys.exit(1)

    main(sys.argv[1])
```

---

## 7. 결과 분석

### 7.1 열린 포트 우선순위
```
높음 (즉시 조사):
- 21 (FTP) - 익명 로그인 확인
- 22 (SSH) - 버전 확인, 브루트포스 가능성
- 23 (Telnet) - 평문 프로토콜
- 80/443 (HTTP/HTTPS) - 웹 애플리케이션 테스트
- 3306 (MySQL) - 원격 접근 가능 여부
- 3389 (RDP) - 브루트포스 공격 가능
- 5432 (PostgreSQL)
- 6379 (Redis) - 인증 없는 접근
- 27017 (MongoDB)

중간:
- 25 (SMTP) - 메일 릴레이
- 110/995 (POP3)
- 143/993 (IMAP)
- 445 (SMB) - 파일 공유, EternalBlue
- 1433 (MSSQL)
- 8080/8443 (대체 HTTP/HTTPS)

낮음:
- 53 (DNS)
- 111 (RPCbind)
- 135 (MSRPC)
```

### 7.2 발견사항 정리
```bash
# Nmap 결과에서 열린 포트만 추출
cat nmap_scan.txt | grep "open" > open_ports.txt

# 웹 서버 응답 코드 정리
cat gobuster_scan.txt | grep "Status: 200" > interesting_paths.txt

# 백업 파일 확인
cat backup_files.txt | grep "200 OK" > found_backups.txt
```

---

## 핵심 정리

1. **포트 스캔 먼저** - Nmap으로 열린 포트와 서비스 파악
2. **웹 서비스 집중** - 대부분의 취약점은 웹 애플리케이션에서 발견
3. **백업 파일 필수 확인** - .bak, .old 파일에서 소스 코드 노출 가능
4. **SSL/TLS 확인** - 약한 암호화는 중간자 공격 가능
5. **결과 저장** - 모든 스캔 결과를 파일로 저장하여 나중에 분석

## 다음 단계
Phase 2: SQL Injection으로 진행하여 발견된 웹 애플리케이션 공격
