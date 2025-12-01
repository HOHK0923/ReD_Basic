# ReD_Basic

웹 보안 취약점 분석 및 침투 테스트 프로젝트 (2024.11 - 2025.12)

## Overview

OWASP Top 10 취약점 실습 및 AWS 클라우드 보안 연구 프로젝트.
취약한 SNS 웹앱을 구축하고, 공격/방어 자동화 도구를 직접 개발했습니다.

핵심 목표:
- SSRF → AWS IMDS → IAM 탈취 → 클라우드 인프라 장악 자동화
- ModSecurity WAF 우회 기법 연구
- 실무 환경에서 자동화 도구의 한계 분석

## Project Structure

```
ReD_Basic/
├── HWJ/                              # 황준하 - AWS 보안 & 침투 자동화
│   ├── 01_AWS_IMDS_Attack/
│   │   ├── 120_aws_imds_exploit.py   # AWS IMDS 자동 탈취 도구
│   │   └── 121_aws_privilege_escalation.py
│   ├── 02_Site_Defacement/           # 웹 사이트 변조
│   ├── 03_Persistence/               # 백도어 설치
│   │   ├── webshell_backdoor.py
│   │   ├── ssm_backdoor.py
│   │   └── php_only_backdoor.py
│   ├── 04_Privilege_Escalation/
│   │   └── privesc_enum.py
│   ├── 05_Defense_Bypass/
│   │   └── blueteam_bypass.py        # WAF + Fail2Ban 우회
│   ├── 06_Integrated_Tool/
│   │   ├── redchain.py               # 통합 CLI 도구 (2,000+ lines)
│   │   ├── auto_redteam.py
│   │   ├── auto_redteam_ultimate.py  # 완전 자동화 (실패)
│   │   ├── auto_redteam_blueteam_bypass.py  # 방어 우회 자동화
│   │   └── real_penetration.py       # EC2 User-data 백도어
│   ├── 07_Manual_Penetration_Guide/  # 침투 테스트 가이드 (12개 문서)
│   │   ├── 01_reconnaissance.md
│   │   ├── 02_sql_injection.md
│   │   ├── 03_ssrf_and_imds.md
│   │   ├── 04_reverse_shell.md
│   │   ├── 05_privilege_escalation.md
│   │   ├── 06_persistence.md
│   │   ├── 07_data_exfiltration.md
│   │   ├── 08_covering_tracks.md
│   │   ├── 09_advanced_techniques.md
│   │   ├── 10_full_automation_script.py
│   │   ├── 11_real_world_attacks.md  # 피싱, 내부자 공격 등
│   │   ├── 12_low_privilege_escalation_scenario.md
│   │   └── 13_low_priv_to_root.py
│   ├── PORTFOLIO_DOCUMENTS/
│   │   └── AUTOMATED_TOOL_FAILURE_REPORT.md  # 자동화 실패 분석
│   ├── security_alert_tester.py      # 보안 알림 시스템 테스트
│   ├── restore_health_php.sh         # 취약점 복구
│   ├── penetration_test_report_final.md
│   └── README.md
│
├── HYE/                              # 혜 - CSRF 자동화
│   ├── 1124_CSRF_Auto.py             # 자동 CSRF 공격 (CVSS 7.8)
│   ├── 1124_CSRF_Dashboard.py        # 대시보드 공격
│   ├── 1124_CSRF_Post.py             # 게시물 조작
│   ├── 1124_Auto_Report/             # 공격 보고서 자동 생성
│   └── 1124_Post_Report/
│
├── YOUNG/                            # 조영운 - XSS & 피싱
│   ├── xss_tool3_edit.py             # XSS 자동화 v3 (12가지 모듈)
│   ├── monitor.py                    # 크리덴셜 수집 모니터링
│   ├── bf2025.php                    # 블랙프라이데이 피싱
│   ├── bftest.php
│   ├── secure_login.php              # 보안 경고 피싱
│   ├── blackfriday.txt
│   ├── security.txt
│   ├── phishing 설명.txt
│   ├── xss_tool3_edit 설명.txt
│   └── 보고서_자료정리_조영운.txt
│
└── vulnerable-sns 3/                 # 취약한 SNS 웹앱
    ├── login.php
    ├── register.php
    ├── index.php
    ├── new_post.php
    ├── file.php                      # SSRF 취약점
    ├── download.php
    ├── like_post.php
    └── config.php
```

## Team Contributions

### HWJ - AWS Security & Red Team Automation

**핵심 성과:**
- AWS IMDS v1 취약점 자동 익스플로잇 개발
- EC2 User-data 백도어를 통한 영구 지속성 확보 연구
- ModSecurity WAF에 대한 450+ 공격 시도 및 우회 기법 개발
- RedChain CLI 통합 도구 개발 (2,000+ lines)
- 침투 테스트 가이드 12개 작성 (15,000+ lines)

**개발 도구:**
1. `auto_redteam_ultimate.py` (450 lines) - SSRF → IMDS → AWS 장악 자동화 (실패 분석)
2. `real_penetration.py` (280 lines) - EC2 User-data 수정 백도어
3. `auto_redteam_blueteam_bypass.py` - Fail2Ban + ModSecurity 우회
4. `redchain.py` - 통합 CLI 침투 도구
5. `security_alert_tester.py` - 침입 탐지 시스템 테스트

**주요 발견:**
- WAF 차단율: 247/247 알려진 페이로드 완벽 차단 (100%)
- 느린 요청 (3초 delay) + 우회 패턴으로 40% 성공률 달성
- EC2 User-data 수정 시 인스턴스 재부팅 필요 (탐지 위험)
- SSRF 엔드포인트가 삭제되면 자동화 도구 무용지물

**상세 문서:**
- [HWJ/README.md](./HWJ/README.md) - 전체 연구 요약
- [AUTOMATED_TOOL_FAILURE_REPORT.md](./HWJ/PORTFOLIO_DOCUMENTS/AUTOMATED_TOOL_FAILURE_REPORT.md) - 자동화 실패 원인 분석
- [Manual Penetration Guide](./HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/) - 12개 침투 가이드

### HYE - CSRF Automation

**핵심 성과:**
- CSRF 자동 탐지 및 익스플로잇 도구 개발
- 포인트 전송 자동화 공격 (CVSS 7.8)
- 공격 결과 자동 리포트 생성

**개발 도구:**
1. `1124_CSRF_Auto.py` - 자동 포인트 전송 공격
   - CVE-2021-44228, CVE-2020-35489 참조
   - Session hijacking 기반
   - Rate limiting 우회
2. `1124_CSRF_Dashboard.py` - 대시보드 공격
3. `1124_CSRF_Post.py` - 게시물 조작

**공격 메커니즘:**
```
1. 피해자 계정 정보 획득 (bob/bobby123)
2. 자동 로그인
3. 다양한 HTTP 메서드로 포인트 전송
4. 서버 응답 분석
5. 공격자 계정으로 포인트 이체
```

**방어 권고:**
- CSRF 토큰 구현
- Rate limiting
- 2FA 도입
- 트랜잭션 한도 설정

### YOUNG - XSS & Credential Harvesting

**핵심 성과:**
- XSS 자동화 도구 v3 개발 (12가지 공격 모듈)
- 피싱 사이트 구축 및 크리덴셜 수집 자동화
- WAF 우회 인코딩 기법 연구

**개발 도구:**
1. `xss_tool3_edit.py` - XSS 자동화
   - 인터랙티브 메뉴 시스템
   - Reflected, Stored, DOM-based, Blind XSS
   - 인코딩 우회: HTML Entity, URL, Unicode, Base64, Hex
   - 프록시 로테이션
   - 스텔스 모드 (WAF 회피)

2. 피싱 시스템:
   - `bf2025.php` - 블랙프라이데이 피싱 (긴급성 강조)
   - `secure_login.php` - 보안 경고 피싱 (2FA UI 모방)
   - `monitor.py` - 실시간 크리덴셜 수집 모니터링

**테스트 결과 (대상: healthmash.net):**

| 인코딩 방식 | 성공 | 차단율 |
|------------|------|--------|
| HTML Entity | 0 | 100% |
| URL Encode | 0 | 100% |
| Unicode | 0 | 100% |
| Base64 | 0 | 100% |
| Hex | 0 | 100% |

**실패 원인:**
- WAF가 모든 XSS 키워드 차단 (`<script`, `onerror=`, `onload=`)
- 스크립트 패턴 감지 기준이 매우 엄격
- 공격 감지 시 즉시 IP 차단

**수집 데이터:**
- Username/Password
- IP 주소
- User-Agent
- 접속 시간
- Referer

## Key Research Findings

### 1. Automation Limits (HWJ 연구)

**테스트 환경:**
- Target: AWS EC2 (3.35.218.180)
- Defense: ModSecurity WAF + Fail2Ban + PHP disable_functions
- Period: 2024.11.26

**공격 시도 통계:**

| Attack Type | Attempts | Success | Rate | Notes |
|------------|----------|---------|------|-------|
| SQL Injection | 200+ | 0 | 0% | WAF 차단 |
| SSRF (normal) | 50+ | 0 | 0% | 엔드포인트 삭제됨 |
| SSRF (bypass) | 20+ | 8 | 40% | 느린 요청 |
| File Upload | 30+ | 0 | 0% | 확장자 검증 |
| CSRF | 20+ | 15 | 75% | 토큰 미구현 |
| XSS (basic) | 100+ | 0 | 0% | WAF 차단 |
| XSS (encoded) | 100+ | 40 | 40% | 일부 우회 |
| Webshell Upload | 30+ | 0 | 0% | 확장자 + disable_functions |

**총 공격 시도: 450+**
**ModSecurity 차단: 247건 (100% 차단률)**

### 2. WAF Bypass Techniques

**실패한 자동화:**
```python
# auto_redteam_ultimate.py - 450 lines
# 예상: 5분 안에 AWS 전체 장악
# 실제: 100% 차단
```

**성공한 우회:**
```python
# auto_redteam_blueteam_bypass.py
def bypass_waf():
    time.sleep(3)  # 느린 요청으로 rate limiting 회피
    headers = {
        'User-Agent': 'Mozilla/5.0...'  # 정상 브라우저 위장
    }
    # Content-Type 변조
    # 대소문자, 공백, 인코딩 우회
```

**성공률:**
- 일반 자동화: 0%
- 방어 우회 최적화: 40%
- 수동 침투 + 도구 조합: 90%

### 3. Defense Analysis

**ModSecurity WAF:**
- 알려진 페이로드 100% 차단
- 10년 이상의 공격 패턴 학습
- Signature 기반 탐지
- **약점:** Custom pattern 탐지 불가, 느린 공격 탐지 어려움

**Fail2Ban:**
- 5회 실패 시 IP 자동 차단
- **우회:** 3초 delay로 threshold 회피

**PHP disable_functions:**
- `system`, `exec`, `shell_exec`, `passthru` 등 차단
- RCE 완전 방어
- **우회 불가**

**CSRF 방어:**
- 토큰 미구현 (취약)
- **성공률: 75%**

## Tools & Usage

### redchain.py - Main Penetration Testing CLI

```bash
cd HWJ/06_Integrated_Tool
./redchain.py

# Commands:
set target http://target.com
auto bypass      # WAF bypass automation
auto redteam     # Full automation
auto recon       # Recon only
show vulns       # List vulnerabilities
```

**Features:**
- SSRF → AWS IMDS → IAM 탈취 자동화
- ModSecurity + Fail2Ban 우회
- 병렬 취약점 스캔
- 자동 보고서 생성

### auto_redteam_blueteam_bypass.py

```bash
python3 auto_redteam_blueteam_bypass.py http://target.com
```

**Bypass Techniques:**
- 3초 delay (Fail2Ban 우회)
- User-Agent rotation
- Pattern obfuscation (대소문자, 공백, 인코딩)
- Content-Type 변조

### security_alert_tester.py

```bash
python3 security_alert_tester.py
```

**Tests:**
- Webshell upload simulation
- URI diversity detection
- XSS/SQLi pattern injection
- Login functionality test

### CSRF Automation (HYE)

```bash
python3 HYE/1124_CSRF_Auto.py
```

### XSS Automation (YOUNG)

```bash
python3 YOUNG/xss_tool3_edit.py
```

**Modules:**
1. Basic XSS
2. Reflected XSS
3. Stored XSS
4. DOM-based XSS
5. Blind XSS
6. HTML Entity encoding
7. URL encoding
8. Unicode encoding
9. Base64 encoding
10. Hex encoding
11. Polyglot payloads
12. WAF bypass patterns

## Setup

```bash
git clone https://github.com/HOHK0923/ReD_Basic.git
cd ReD_Basic

# Python dependencies
pip install requests boto3 paramiko colorama beautifulsoup4

# Kali tools (optional)
apt install nmap nikto gobuster sqlmap metasploit-framework
```

## Key Lessons Learned

### 1. Automation Fails Against Modern WAF

ModSecurity는 10년 이상의 공격 패턴을 학습했기 때문에 알려진 페이로드는 100% 차단합니다.
자동화 도구는 "알려진 것"만 시도하므로 WAF에 무력합니다.

**해결책:**
- 하이브리드 접근 (자동화 + 수동)
- Custom pattern 개발
- Slow attack (rate limiting 우회)

### 2. Single Vulnerability = Full Compromise

SSRF 취약점 하나로 AWS 전체 인프라를 장악할 수 있습니다.

**공격 체인:**
```
SSRF (file.php?url=)
  → AWS IMDS (169.254.169.254)
    → IAM credentials
      → S3 bucket access
        → Sensitive data exfiltration
          → EC2 control via SSM
            → Root access
```

### 3. Human Factor is the Weakest Link

**기술 공격 vs 피싱:**
- 기술 공격 성공률: < 1% (WAF가 막음)
- 피싱 성공률: 30-40% (사람이 클릭)
- CSRF 성공률: 75% (토큰 미구현)

최신 WAF도 피싱 이메일 한 통은 못 막습니다.

### 4. Defense Requires Perfection, Attack Needs One Flaw

블루팀은 모든 취약점을 막아야 하지만,
레드팀은 하나의 취약점만 찾으면 됩니다.

**방어의 어려움:**
- 모든 엔드포인트 보안 필요
- Zero-day 공격 방어 불가능
- 내부자 위협 대응 어려움
- 설정 실수 (777 권한, CSRF 토큰 누락) 흔함

## Documentation

### HWJ Documentation
- [HWJ/README.md](./HWJ/README.md) - 전체 AWS 보안 연구
- [AUTOMATED_TOOL_FAILURE_REPORT.md](./HWJ/PORTFOLIO_DOCUMENTS/AUTOMATED_TOOL_FAILURE_REPORT.md) - 자동화 실패 원인 분석
- [penetration_test_report_final.md](./HWJ/penetration_test_report_final.md) - 최종 침투 테스트 보고서

### Manual Penetration Guides (12개)
1. [01_reconnaissance.md](./HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/01_reconnaissance.md)
2. [02_sql_injection.md](./HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/02_sql_injection.md)
3. [03_ssrf_and_imds.md](./HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/03_ssrf_and_imds.md)
4. [04_reverse_shell.md](./HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/04_reverse_shell.md)
5. [05_privilege_escalation.md](./HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/05_privilege_escalation.md)
6. [06_persistence.md](./HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/06_persistence.md)
7. [07_data_exfiltration.md](./HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/07_data_exfiltration.md)
8. [08_covering_tracks.md](./HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/08_covering_tracks.md)
9. [09_advanced_techniques.md](./HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/09_advanced_techniques.md)
10. [10_full_automation_script.py](./HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/10_full_automation_script.py)
11. [11_real_world_attacks.md](./HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/11_real_world_attacks.md) - 피싱, 내부자 공격
12. [12_low_privilege_escalation_scenario.md](./HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/12_low_privilege_escalation_scenario.md)

### YOUNG Documentation
- [보고서_자료정리_조영운.txt](./YOUNG/보고서_자료정리_조영운.txt) - XSS & 피싱 연구
- [xss_tool3_edit 설명.txt](./YOUNG/xss_tool3_edit 설명.txt)
- [phishing 설명.txt](./YOUNG/phishing 설명.txt)

## Tech Stack

**Languages:**
- Python 3.8+ (boto3, requests, paramiko, asyncio, BeautifulSoup)
- PHP 7.4+
- Bash

**Cloud:**
- AWS (EC2, S3, IAM, IMDS, SSM)

**Security Tools:**
- ModSecurity WAF
- Fail2Ban
- Kali Linux (nmap, sqlmap, Metasploit, Burp Suite)

**Web:**
- Apache/Nginx
- MySQL/MariaDB

## Real-World Attack Scenarios

### Scenario 1: SSRF → AWS Compromise (from HWJ research)

```
1. Recon: nmap 발견 file.php?url= 파라미터
2. SSRF: url=http://169.254.169.254/latest/meta-data/
3. IMDS: IAM role credentials 탈취
4. AWS CLI: 탈취한 credentials로 S3 접근
5. Data Exfil: 민감 데이터 다운로드
6. Persistence: EC2 User-data 백도어 설치
7. Privilege Escalation: SSM으로 root 명령 실행
```

### Scenario 2: Phishing → Account Takeover (from YOUNG research)

```
1. Phishing: bf2025.php (블랙프라이데이 긴급 할인)
2. Credential Harvesting: monitor.py로 실시간 수집
3. Account Login: 수집한 ID/PW로 로그인
4. Data Theft: 개인정보 (이름, 이메일, 전화번호) 탈취
5. Credential Stuffing: 타 서비스에서 동일 계정 시도
```

### Scenario 3: Low Privilege → Root (from HWJ Guide 12)

```
1. 낮은 권한 계정 탈취 (dev-junior)
2. Cron job 발견 (777 권한 스크립트)
3. SUID rootbash 생성
4. Root 쉘 획득
5. 백도어 설치
```

## Legal

**For educational purposes only.**

무단으로 타인의 시스템에 침투하는 것은 불법입니다.

**한국 법률:**
- 정보통신망법: 무단 침입 시 5년 이하 징역 또는 5천만원 이하 벌금
- 개인정보보호법: 데이터 유출 시 가중 처벌

**허용:**
- 본인 소유 시스템 테스트
- 사전 계약된 침투 테스트
- CTF 대회
- 보안 연구

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- Capital One Breach (2019) - SSRF to IMDS attack
- CVE-2021-44228 (Session Management)
- CVE-2020-35489 (Automated Point Transfer)

## License

MIT License (educational use only)

## Contact

황준하 (HWJ) - hwangpongpong10@gmail.com

---

Last updated: 2025-12-01
