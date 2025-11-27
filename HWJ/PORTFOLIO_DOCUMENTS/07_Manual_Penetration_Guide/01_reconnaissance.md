# Phase 1: Reconnaissance (정찰)

정찰은 침투 테스트의 첫 단계로, 대상 시스템에 대한 최대한 많은 정보를 수집하는 과정입니다.

## 📋 목차

1. [포트 스캔](#포트-스캔)
2. [웹 취약점 스캔](#웹-취약점-스캔)
3. [디렉토리 브루트포스](#디렉토리-브루트포스)
4. [백업 파일 탐색](#백업-파일-탐색)
5. [서비스 핑거프린팅](#서비스-핑거프린팅)

---

## 포트 스캔

### Nmap - 기본 스캔

```bash
# 기본 스캔
nmap 3.35.218.180

# 서비스 버전 탐지
nmap -sV 3.35.218.180

# OS 탐지
nmap -O 3.35.218.180

# 모든 포트 스캔
nmap -p- 3.35.218.180

# 공격적인 스캔 (서비스, OS, 스크립트)
nmap -A 3.35.218.180

# 스크립트 스캔
nmap -sC 3.35.218.180

# 결과를 파일로 저장
nmap -sV -sC -p- 3.35.218.180 -oN nmap_scan.txt -oX nmap_scan.xml
```

### Nmap - 고급 옵션

```bash
# UDP 스캔
nmap -sU 3.35.218.180

# 스텔스 스캔 (SYN scan)
nmap -sS 3.35.218.180

# 방화벽 우회
nmap -f 3.35.218.180  # 패킷 단편화
nmap -D RND:10 3.35.218.180  # Decoy 스캔

# 타이밍 조절 (느리게 → 탐지 회피)
nmap -T0 3.35.218.180  # Paranoid (매우 느림)
nmap -T1 3.35.218.180  # Sneaky
nmap -T2 3.35.218.180  # Polite
nmap -T3 3.35.218.180  # Normal (기본값)
nmap -T4 3.35.218.180  # Aggressive (빠름)
nmap -T5 3.35.218.180  # Insane (매우 빠름)

# 특정 포트 스캔
nmap -p 22,80,443,3306,8080 3.35.218.180
nmap -p 1-1000 3.35.218.180
```

### Nmap - 유용한 NSE 스크립트

```bash
# HTTP 관련 정보 수집
nmap --script=http-enum 3.35.218.180
nmap --script=http-headers 3.35.218.180
nmap --script=http-methods 3.35.218.180
nmap --script=http-title 3.35.218.180

# 취약점 스캔
nmap --script=vuln 3.35.218.180

# SQL Injection 테스트
nmap --script=http-sql-injection 3.35.218.180

# 기본 인증 우회
nmap --script=http-auth-finder 3.35.218.180

# SSL/TLS 정보
nmap --script=ssl-enum-ciphers -p 443 3.35.218.180
```

---

## 웹 취약점 스캔

### Nikto

```bash
# 기본 스캔
nikto -h http://3.35.218.180

# 특정 포트 스캔
nikto -h http://3.35.218.180:8080

# SSL 사이트 스캔
nikto -h https://3.35.218.180

# 결과를 파일로 저장
nikto -h http://3.35.218.180 -o nikto_result.txt

# 모든 플러그인 실행
nikto -h http://3.35.218.180 -Plugins all

# 특정 플러그인만 실행
nikto -h http://3.35.218.180 -Plugins 'apache_expect_xss'

# User-Agent 변경
nikto -h http://3.35.218.180 -useragent "Mozilla/5.0"

# 프록시 사용 (Burp Suite 연동)
nikto -h http://3.35.218.180 -useproxy http://127.0.0.1:8080
```

### WhatWeb

```bash
# 기본 스캔
whatweb http://3.35.218.180

# 상세 정보
whatweb -v http://3.35.218.180

# 공격적인 스캔
whatweb --aggression 3 http://3.35.218.180

# 특정 플러그인
whatweb -p Apache,PHP http://3.35.218.180
```

---

## 디렉토리 브루트포스

### Gobuster

```bash
# 기본 디렉토리 스캔
gobuster dir -u http://3.35.218.180 \
  -w /usr/share/wordlists/dirb/common.txt

# 특정 확장자 포함
gobuster dir -u http://3.35.218.180 \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,html,js,zip,bak

# 상태 코드 필터링 (404 제외)
gobuster dir -u http://3.35.218.180 \
  -w /usr/share/wordlists/dirb/common.txt \
  --exclude-length 0

# 쓰레드 증가 (빠른 스캔)
gobuster dir -u http://3.35.218.180 \
  -w /usr/share/wordlists/dirb/big.txt \
  -t 50

# 쿠키 사용
gobuster dir -u http://3.35.218.180 \
  -w /usr/share/wordlists/dirb/common.txt \
  -c "PHPSESSID=abc123"

# User-Agent 변경
gobuster dir -u http://3.35.218.180 \
  -w /usr/share/wordlists/dirb/common.txt \
  -a "Mozilla/5.0"

# 결과 저장
gobuster dir -u http://3.35.218.180 \
  -w /usr/share/wordlists/dirb/common.txt \
  -o gobuster_results.txt
```

### Dirb

```bash
# 기본 스캔
dirb http://3.35.218.180

# 커스텀 워드리스트
dirb http://3.35.218.180 /usr/share/wordlists/dirb/big.txt

# 확장자 지정
dirb http://3.35.218.180 -X .php,.txt,.bak

# 인증 사용
dirb http://3.35.218.180 -u username:password

# 재귀 깊이 제한
dirb http://3.35.218.180 -r

# 결과 저장
dirb http://3.35.218.180 -o dirb_results.txt
```

### Wfuzz

```bash
# 디렉토리 퍼징
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt \
  --hc 404 http://3.35.218.180/FUZZ

# 파일 퍼징
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt \
  --hc 404 http://3.35.218.180/FUZZ.php

# 파라미터 퍼징
wfuzz -c -z file,/usr/share/wordlists/wfuzz/general/common.txt \
  --hc 404 "http://3.35.218.180/page.php?FUZZ=test"

# POST 데이터 퍼징
wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt \
  -d "username=FUZZ&password=test" \
  --hc 200 http://3.35.218.180/login.php

# 여러 위치 동시 퍼징
wfuzz -c -z file,users.txt -z file,pass.txt \
  -d "username=FUZZ&password=FUZ2Z" \
  http://3.35.218.180/login.php
```

---

## 백업 파일 탐색

### 백업 파일 패턴

```bash
# Gobuster로 백업 파일 찾기
gobuster dir -u http://3.35.218.180 \
  -w /usr/share/wordlists/dirb/common.txt \
  -x bak,old,backup,orig,save,~,swp,tmp

# 특정 파일의 백업 찾기
# index.php의 백업들
curl http://3.35.218.180/index.php.bak
curl http://3.35.218.180/index.php.old
curl http://3.35.218.180/index.php.backup
curl http://3.35.218.180/index.php~
curl http://3.35.218.180/index.php.save
curl http://3.35.218.180/.index.php.swp

# API 파일 백업
curl http://3.35.218.180/api/health.php.bak
curl http://3.35.218.180/api/health.php.old

# 설정 파일 백업
curl http://3.35.218.180/config.php.bak
curl http://3.35.218.180/config.php.old
curl http://3.35.218.180/.config.php.swp
```

### 자동화 스크립트

```bash
#!/bin/bash
# backup_finder.sh

TARGET="http://3.35.218.180"
FILES=("index" "login" "admin" "config" "database" "db" "upload" "api/health")
EXTENSIONS=("php" "asp" "aspx" "jsp")
BACKUP_SUFFIXES=(".bak" ".old" ".backup" ".orig" ".save" "~" ".swp" ".tmp")

for file in "${FILES[@]}"; do
    for ext in "${EXTENSIONS[@]}"; do
        for suffix in "${BACKUP_SUFFIXES[@]}"; do
            URL="${TARGET}/${file}.${ext}${suffix}"
            echo "[*] Testing: $URL"

            STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL")

            if [ "$STATUS" == "200" ]; then
                echo "[+] FOUND: $URL"
                curl -s "$URL" > "found_$(basename $URL)"
            fi
        done
    done
done
```

---

## 서비스 핑거프린팅

### 웹 서버 식별

```bash
# curl로 헤더 확인
curl -I http://3.35.218.180

# 특정 헤더 추출
curl -I http://3.35.218.180 | grep Server
curl -I http://3.35.218.180 | grep X-Powered-By

# 모든 응답 헤더 보기
curl -v http://3.35.218.180 2>&1 | grep "^< "

# OPTIONS 메소드로 지원 메소드 확인
curl -X OPTIONS -i http://3.35.218.180
```

### 기술 스택 식별

```bash
# Wappalyzer CLI
npm install -g wappalyzer
wappalyzer http://3.35.218.180

# WhatWeb
whatweb -v http://3.35.218.180

# BuiltWith
# https://builtwith.com/3.35.218.180
```

### 숨겨진 헤더 찾기

```bash
# 다양한 HTTP 메소드 시도
for method in GET POST PUT DELETE OPTIONS TRACE CONNECT PATCH; do
    echo "[*] Testing $method"
    curl -X $method -v http://3.35.218.180 2>&1 | grep "^< "
    echo "---"
done

# 다양한 User-Agent로 테스트
curl -A "Mozilla/5.0" -I http://3.35.218.180
curl -A "Googlebot" -I http://3.35.218.180
curl -A "curl/7.68.0" -I http://3.35.218.180
```

---

## robots.txt & sitemap.xml

```bash
# robots.txt 확인
curl http://3.35.218.180/robots.txt

# sitemap.xml 확인
curl http://3.35.218.180/sitemap.xml

# sitemap 여러 형식
curl http://3.35.218.180/sitemap.xml
curl http://3.35.218.180/sitemap_index.xml
curl http://3.35.218.180/sitemap.xml.gz
```

---

## SSL/TLS 분석

```bash
# SSLScan
sslscan 3.35.218.180

# TestSSL
testssl.sh https://3.35.218.180

# Nmap SSL scripts
nmap --script ssl-enum-ciphers -p 443 3.35.218.180
nmap --script ssl-cert -p 443 3.35.218.180
nmap --script ssl-heartbleed -p 443 3.35.218.180
```

---

## DNS 정보 수집

```bash
# DNS 조회
dig 3.35.218.180
nslookup 3.35.218.180

# 역방향 DNS
dig -x 3.35.218.180

# 모든 DNS 레코드
dig any 3.35.218.180

# DNS 브루트포스
dnsrecon -d 3.35.218.180 -t brt
fierce --domain 3.35.218.180
```

---

## 종합 정찰 스크립트

```bash
#!/bin/bash
# recon_all.sh - 종합 정찰 스크립트

TARGET="3.35.218.180"
OUTPUT_DIR="recon_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

echo "[*] Starting comprehensive reconnaissance on $TARGET"

# 1. Nmap 스캔
echo "[*] Running Nmap..."
nmap -sV -sC -p- "$TARGET" -oN nmap_full.txt -oX nmap_full.xml &

# 2. Nikto 스캔
echo "[*] Running Nikto..."
nikto -h "http://$TARGET" -o nikto.txt &

# 3. Gobuster
echo "[*] Running Gobuster..."
gobuster dir -u "http://$TARGET" \
  -w /usr/share/wordlists/dirb/big.txt \
  -x php,txt,html,bak,old \
  -o gobuster.txt &

# 4. WhatWeb
echo "[*] Running WhatWeb..."
whatweb -v "http://$TARGET" > whatweb.txt &

# 5. SSL 스캔 (HTTPS인 경우)
echo "[*] Running SSLScan..."
sslscan "$TARGET" > sslscan.txt 2>&1 &

# 모든 백그라운드 작업 완료 대기
wait

echo "[+] Reconnaissance complete! Results in $OUTPUT_DIR"
ls -lh
```

---

## 정찰 체크리스트

- [ ] Nmap 전체 포트 스캔 완료
- [ ] 서비스 버전 식별
- [ ] OS 식별
- [ ] Nikto 웹 취약점 스캔
- [ ] 디렉토리 브루트포스 (common.txt)
- [ ] 디렉토리 브루트포스 (big.txt)
- [ ] 백업 파일 탐색
- [ ] robots.txt 확인
- [ ] sitemap.xml 확인
- [ ] HTTP 헤더 분석
- [ ] SSL/TLS 설정 확인
- [ ] DNS 정보 수집
- [ ] 기술 스택 식별

---

## 다음 단계

정찰 단계에서 수집한 정보를 바탕으로:
1. 발견된 취약점 우선순위 결정
2. SQL Injection 테스트 (Phase 2)
3. SSRF 테스트 (Phase 3)
4. 파일 업로드 테스트

[→ Phase 2: SQL Injection으로 이동](02_sql_injection.md)
