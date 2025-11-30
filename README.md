# ReD_Basic - 웹 애플리케이션 보안 연구 프로젝트

![Version](https://img.shields.io/badge/version-3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-brightgreen.svg)
![PHP](https://img.shields.io/badge/php-7.4+-purple.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**팀 프로젝트**: 웹 애플리케이션 보안 취약점 연구 및 자동화 도구 개발
**작성 기간**: 2024년 11월 ~ 2025년 12월
**목적**: 웹 보안 취약점 분석, 침투 테스트 자동화, 방어 기법 연구

---

## 프로젝트 개요

ReD_Basic은 웹 애플리케이션의 보안 취약점을 연구하고, 이를 탐지/방어/우회하는 자동화 도구를 개발하는 팀 프로젝트입니다.

취약한 SNS 웹 애플리케이션을 대상으로 OWASP Top 10 취약점을 분석하고, AWS 클라우드 환경까지 확장하여 실무에서 발생할 수 있는 보안 사고를 재현하고 연구했습니다.

### 핵심 연구 주제

```
[레드팀] SSRF → AWS IMDS → IAM 자격증명 탈취 → 클라우드 인프라 장악
[블루팀] WAF 설정 → 침입 탐지 → 보안 알림 자동화
[연구] 자동화 도구의 한계 분석 및 실전 방어 우회 기법
```

**핵심 발견**:
- 완벽한 WAF(ModSecurity)도 예외 설정 하나로 무력화 가능
- 자동화 도구는 알려진 패턴만 탐지 (창의적 공격에 취약)
- 실무 환경에서는 "기술"보다 "사람"이 가장 큰 취약점
- 블루팀 방어를 우회하려면 느린 요청과 우회 패턴 필요

---

## 프로젝트 구조

```
ReD_Basic/
├── HWJ/                          # 황준하 - AWS 클라우드 보안 & 자동화
│   ├── 01_AWS_IMDS_Attack/       # AWS IMDS 공격 연구
│   ├── 02_Site_Defacement/       # 웹 사이트 변조 기법
│   ├── 03_Persistence/           # 백도어 및 지속성 확보
│   ├── 04_Privilege_Escalation/  # 권한 상승 기법
│   ├── 05_Code_Analysis/         # 소스코드 분석
│   ├── 05_Defense_Bypass/        # 블루팀 방어 우회
│   ├── 06_Integrated_Tool/       # RedChain CLI 통합 도구
│   │   ├── redchain.py           # CLI 메인 도구
│   │   ├── auto_redteam.py       # 자동 침투 테스트
│   │   ├── auto_redteam_blueteam_bypass.py  # 방어 우회 자동화
│   │   └── real_penetration.py   # User-data 백도어
│   ├── 07_Manual_Penetration_Guide/  # 수동 침투 가이드
│   ├── PORTFOLIO_DOCUMENTS/      # 핵심 연구 문서
│   ├── security_alert_tester.py  # 보안 알림 테스트 도구
│   ├── restore_health_php.sh     # 취약점 복구 스크립트
│   └── README.md                 # HWJ 상세 문서
│
├── HYE/                          # 혜 - CSRF 공격 자동화 연구
│   ├── 1124_CSRF_Auto.py         # CSRF 자동 공격 도구
│   ├── 1124_CSRF_Dashboard.py    # CSRF 대시보드 공격
│   ├── 1124_CSRF_Post.py         # CSRF 게시물 공격
│   ├── 1124_Auto_Report/         # 자동 보고서 생성
│   └── 1124_Post_Report/         # 게시물 리포트
│
├── YOUNG/                        # 조영운 - XSS 공격 & 피싱
│   ├── xss_tool3_edit.py         # XSS 자동 공격 도구 v3
│   ├── monitor.py                # 웹 모니터링 도구
│   ├── bf2025.php                # 블랙프라이데이 피싱 페이지
│   ├── bftest.php                # 피싱 테스트 페이지
│   ├── secure_login.php          # 보안 로그인 (방어)
│   └── 보고서_자료정리_조영운.txt # 연구 보고서
│
├── vulnerable-sns 3/             # 취약한 SNS 웹 애플리케이션
│   ├── www/                      # 웹 루트
│   ├── login.php                 # 로그인
│   ├── register.php              # 회원가입
│   ├── index.php                 # 메인 페이지
│   ├── new_post.php              # 게시물 작성
│   ├── file.php                  # 파일 업로드 (SSRF 취약점)
│   ├── download.php              # 파일 다운로드
│   ├── like_post.php             # 좋아요 기능
│   └── config.php                # DB 설정
│
├── .gitignore                    # Git 제외 파일 목록
├── LICENSE                       # MIT 라이선스
└── README.md                     # 이 파일 (프로젝트 전체 개요)
```

---

## 팀원별 연구 분야

### 황준하 (HWJ) - AWS 클라우드 보안 & 레드팀 자동화

**주요 성과**:
- AWS IMDS v1 취약점 공격 자동화 도구 개발
- ModSecurity WAF 우회 기법 연구 (450+ 공격 시도)
- 블루팀 방어(Fail2Ban + ModSecurity) 우회 자동화
- RedChain CLI 통합 침투 테스트 도구 개발 (2,000+ 줄)
- 수동 침투 테스트 가이드 12개 작성 (15,000+ 줄)

**핵심 기술**:
- Python (boto3, requests, paramiko, asyncio)
- AWS (EC2, S3, IAM, IMDS)
- Bash 자동화 스크립팅
- Kali Linux (nmap, sqlmap, Metasploit)

**핵심 도구**:
- `redchain.py`: CLI 통합 침투 테스트 도구
- `auto_redteam_blueteam_bypass.py`: 블루팀 방어 우회 자동화
- `security_alert_tester.py`: 보안 알림 시스템 테스트
- `13_low_priv_to_root.py`: 권한 상승 시나리오

**상세 문서**: [HWJ/README.md](./HWJ/README.md)

### 혜 (HYE) - CSRF 공격 자동화

**주요 성과**:
- CSRF 취약점 자동 탐지 및 공격 도구 개발
- 대시보드 기능에 대한 CSRF 공격 시나리오
- 게시물 작성/삭제 CSRF 자동화
- 공격 결과 자동 리포트 생성 시스템

**핵심 기술**:
- Python (웹 자동화)
- HTML/CSS (공격 페이로드 생성)
- HTTP 세션 관리

**핵심 도구**:
- `1124_CSRF_Auto.py`: 자동 CSRF 공격
- `1124_CSRF_Dashboard.py`: 대시보드 공격
- `1124_CSRF_Post.py`: 게시물 공격

### 조영운 (YOUNG) - XSS 공격 & 소셜 엔지니어링

**주요 성과**:
- XSS 자동 공격 도구 v3 개발
- 블랙프라이데이 피싱 페이지 제작
- 웹 모니터링 도구 개발
- 보안 로그인 시스템 구현 (방어)

**핵심 기술**:
- Python (웹 스크래핑, 자동화)
- PHP (피싱 페이지 개발)
- HTML/CSS/JavaScript (XSS 페이로드)

**핵심 도구**:
- `xss_tool3_edit.py`: XSS 자동 공격 도구
- `bf2025.php`: 블랙프라이데이 피싱
- `monitor.py`: 웹 모니터링

---

## 주요 연구 성과

### 1. 레드팀 연구 (공격)

✅ **자동화 도구 개발**
- SSRF → AWS IMDS → IAM 탈취 자동화
- CSRF 자동 공격 및 리포트 생성
- XSS 페이로드 자동 주입 및 탐지
- 총 코드량: 약 5,000줄

✅ **AWS 클라우드 공격**
- EC2 인스턴스 User-data 수정 백도어
- S3 버킷 권한 탈취 및 데이터 유출
- IAM 자격증명 탈취 후 권한 상승

✅ **웹 애플리케이션 공격**
- SQL Injection (200+ 페이로드)
- File Upload (웹쉘 업로드)
- SSRF (AWS IMDS 공격)
- CSRF (자동화)
- XSS (Reflected, Stored)

### 2. 블루팀 연구 (방어)

✅ **보안 시스템 구축**
- ModSecurity WAF 설정 및 룰셋 적용
- Fail2Ban 침입 차단 시스템
- 보안 알림 자동화 (침입 탐지 시 Slack 알림)
- 파일 무결성 모니터링

✅ **방어 효과 분석**
- ModSecurity 차단율: 100% (247/247 공격 차단)
- Fail2Ban IP 차단: 5회 실패 시 자동 차단
- PHP disable_functions: RCE 방어
- 업로드 파일 확장자 검증

### 3. 방어 우회 연구

✅ **WAF 우회 기법**
- 느린 요청으로 rate limiting 회피
- User-Agent 변경 (정상 브라우저 위장)
- Content-Type 변조 (이미지로 위장)
- 우회 패턴 (대소문자, 공백, 인코딩)

✅ **Fail2Ban 우회**
- 긴 대기 시간 (3초) 삽입
- IP 로테이션 시뮬레이션
- 정상 요청과 공격 요청 섞기

✅ **성공률**
- 일반 자동화 도구: 0% 성공
- 방어 우회 최적화: 30-40% 성공
- 수동 침투 테스트: 90% 성공

---

## 핵심 교훈

### 1. 자동화의 한계

> "자동화는 빠르지만 경직적이다. 창의성은 사람만의 것이다."

**발견한 사실**:
- 자동화 도구 = 알려진 패턴만 탐지/공격
- WAF = 10년 이상의 공격 패턴 학습
- 결과 = 자동화 도구 100% 차단
- 해결책 = 하이브리드 (자동 + 수동)

### 2. 방어의 중요성

> "공격보다 방어가 훨씬 어렵다"

**블루팀의 어려움**:
- 모든 취약점을 다 막아야 함 (하나라도 뚫리면 침투)
- 레드팀은 하나의 취약점만 찾으면 됨
- Zero-Day 공격은 방어 불가능
- 내부자 공격은 기술로 막기 어려움

### 3. 실무의 복잡성

> "영화처럼 5분 해킹? 현실은 6개월 장기전이다."

**현실적 공격 시나리오**:
```
Day 1-7: 정찰 (GitHub, LinkedIn, OSINT)
Day 8-14: 피싱 캠페인 (직원 10명에게 발송)
Day 15: 한 명 클릭 → 개발자 계정 탈취
Day 16-30: 내부 네트워크 침투 및 권한 확인
Day 31-90: 권한 상승, 백도어 설치, 증거 은폐
```

### 4. 사람이 가장 큰 취약점

> "최신 WAF도 피싱 이메일 한 통은 못 막는다"

**통계**:
- 기술 공격 성공률: < 1% (WAF가 막음)
- 피싱 공격 성공률: 30-40% (사람이 클릭)
- 내부자 공격: 방어 거의 불가능
- 설정 실수 (777 권한): 매우 흔함

---

## 설치 및 사용법

### 1. 환경 설정

```bash
# 저장소 클론
git clone https://github.com/your-repo/ReD_Basic.git
cd ReD_Basic

# Python 패키지 설치
pip install requests boto3 paramiko colorama

# Kali Linux 도구 (선택)
apt install nmap nikto gobuster sqlmap metasploit-framework
```

### 2. 취약한 웹 애플리케이션 실행

```bash
# Docker로 실행
cd vulnerable-sns\ 3
docker-compose up -d

# 또는 PHP 내장 서버
php -S 0.0.0.0:8080
```

### 3. RedChain 통합 도구 사용

```bash
cd HWJ/06_Integrated_Tool

# RedChain CLI 실행
./redchain.py

# 타겟 설정
set target http://3.35.218.180

# 자동 공격
auto redteam          # 완전 자동 레드팀 침투
auto bypass           # 블루팀 방어 우회 침투
auto recon            # 정찰만 실행
```

### 4. 개별 도구 실행

```bash
# AWS IMDS 공격
python3 HWJ/01_AWS_IMDS_Attack/120_aws_imds_exploit.py

# CSRF 자동 공격
python3 HYE/1124_CSRF_Auto.py

# XSS 자동 공격
python3 YOUNG/xss_tool3_edit.py

# 보안 알림 테스트
python3 HWJ/security_alert_tester.py
```

---

## 필독 문서

### 가장 중요한 문서들

1. **[HWJ/README.md](./HWJ/README.md)**
   - AWS 클라우드 보안 연구 전체 개요
   - 자동화 도구 개발 및 실패 분석
   - 블루팀 방어 우회 기법

2. **[HWJ/PORTFOLIO_DOCUMENTS/AUTOMATED_TOOL_FAILURE_REPORT.md](./HWJ/PORTFOLIO_DOCUMENTS/AUTOMATED_TOOL_FAILURE_REPORT.md)**
   - 자동화 도구 실패 분석 (450+ 공격 시도)
   - WAF 차단율 100% 분석
   - 실패에서 배운 교훈

3. **[HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/11_real_world_attacks.md](./HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/11_real_world_attacks.md)**
   - 실제 해커들이 사용하는 방법
   - 피싱, 내부자, 장기전 전략
   - 자동화 실패 시 대안

---

## 기술 스택

### 백엔드
- **PHP 7.4+**: 취약한 웹 애플리케이션
- **MySQL/MariaDB**: 데이터베이스
- **Apache/Nginx**: 웹 서버

### 공격 도구
- **Python 3.8+**: 자동화 스크립트
  - requests, boto3, paramiko, asyncio
- **Bash**: 자동화 스크립팅
- **Kali Linux**: nmap, sqlmap, Metasploit

### 방어 시스템
- **ModSecurity**: Web Application Firewall
- **Fail2Ban**: 침입 차단 시스템
- **AIDE**: 파일 무결성 모니터링

### 클라우드
- **AWS EC2**: 웹 서버 호스팅
- **AWS S3**: 데이터 저장
- **AWS IAM**: 권한 관리
- **AWS IMDS**: 메타데이터 서비스 (공격 대상)

---

## 보안 연구 결과 요약

### 공격 통계

| 공격 유형 | 시도 횟수 | 성공 횟수 | 성공률 |
|----------|---------|---------|--------|
| SQL Injection | 200+ | 0 | 0% (WAF 차단) |
| SSRF | 50+ | 0 | 0% (엔드포인트 삭제) |
| File Upload | 30+ | 0 | 0% (확장자 검증) |
| CSRF | 20+ | 15 | 75% (토큰 미검증) |
| XSS | 100+ | 40 | 40% (필터링 불완전) |
| 방어 우회 SSRF | 20+ | 8 | 40% (느린 요청) |
| 피싱 | 10 | 4 | 40% (사람 실수) |

### 방어 시스템 효과

| 방어 시스템 | 차단 성공률 | 비고 |
|-----------|-----------|------|
| ModSecurity WAF | 100% | 알려진 패턴은 완벽 차단 |
| Fail2Ban | 95% | IP 기반 차단 (우회 가능) |
| PHP disable_functions | 100% | RCE 완전 차단 |
| 파일 확장자 검증 | 90% | 확장자 변조로 우회 가능 |
| CSRF 토큰 | 0% | 미구현 (취약) |
| XSS 필터링 | 60% | 우회 패턴 존재 |

---

## 향후 계획

### 단기 (1개월)
- [ ] AI 기반 페이로드 생성기 (GPT-4 활용)
- [ ] Bug Bounty 플랫폼 참여
- [ ] OWASP ZAP 플러그인 개발

### 중기 (3개월)
- [ ] AWS Security Specialty 인증 취득
- [ ] 하이브리드 침투 도구 개발 (자동 + 수동)
- [ ] 실제 침투 테스트 프로젝트 참여

### 장기 (6개월+)
- [ ] 보안 컨설팅 회사 입사
- [ ] 보안 컨퍼런스 발표 (CodeEngn, DEFCON)
- [ ] 오픈소스 보안 도구 공개

---

## 법적 고지사항

⚠️ **매우 중요**

본 프로젝트는 **교육 및 연구 목적**으로만 사용해야 합니다.

### 절대 금지
- ❌ 무단으로 타인의 시스템 침투
- ❌ 허가 없는 보안 테스트
- ❌ 악의적 목적 사용
- ❌ 데이터 유출 및 파괴

### 허용
- ✅ 본인 소유 시스템 테스트
- ✅ 사전 승인된 침투 테스트 (계약서 필수)
- ✅ 보안 연구 및 학습
- ✅ CTF 대회 참여
- ✅ 교육 목적 데모

### 법적 책임
- **정보통신망법**: 무단 침입 시 **5년 이하 징역 또는 5천만원 이하 벌금**
- **개인정보보호법**: 데이터 유출 시 **가중 처벌**
- **형법**: 업무방해죄, 재산범죄 등 추가 처벌 가능
- **모든 법적 책임은 사용자에게 있습니다**

---

## 참고 자료

### 도서
- "The Web Application Hacker's Handbook" - Dafydd Stuttard
- "Real-World Bug Hunting" - Peter Yaworski
- "Social Engineering: The Art of Human Hacking" - Kevin Mitnick
- "AWS Security" - Dylan Shields

### 온라인 자료
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

### 실제 사례
- **Capital One Breach (2019)**: SSRF → AWS IMDS → 1억 개 계정 유출
- **Uber Breach (2022)**: 소셜 엔지니어링 → MFA 피로 공격
- **SolarWinds (2020)**: 공급망 공격 → 18,000개 조직 침투
- **Equifax Breach (2017)**: Apache Struts 취약점 → 1억 4,700만 개 계정 유출

---

## 팀원 연락처

### 황준하 (HWJ)
- **Email**: hwangpongpong10@gmail.com
- **GitHub**: [GitHub Profile]
- **역할**: AWS 클라우드 보안, 레드팀 자동화 연구

### 혜 (HYE)
- **역할**: CSRF 공격 자동화 연구

### 조영운 (YOUNG)
- **역할**: XSS 공격 & 소셜 엔지니어링 연구

---

## 라이선스

MIT License (교육 목적 한정)

```
추가 제한사항:
- 상업적 사용 금지
- 악의적 목적 사용 금지
- 무단 침투 테스트 금지
- 데이터 유출 및 파괴 금지
```

본 프로젝트의 모든 코드와 문서는 교육 목적으로만 사용되어야 하며, 불법적인 활동에 사용될 경우 법적 책임은 전적으로 사용자에게 있습니다.

---

## 프로젝트 타임라인

- **2024-11-25**: 프로젝트 시작, 취약한 SNS 애플리케이션 개발
- **2024-11-26**: AWS IMDS 공격 연구 및 자동화 도구 개발
- **2024-11-27**: CSRF, XSS 자동화 도구 개발
- **2024-11-28**: ModSecurity WAF 설정 및 450+ 공격 테스트
- **2024-11-29**: 자동화 실패 분석 및 대안 연구
- **2024-11-30**: 블루팀 방어 우회 자동화 개발
- **2025-12-01**: 프로젝트 문서화 및 정리

---

## 감사의 말

이 프로젝트를 통해 웹 보안의 복잡성과 자동화의 한계를 깊이 이해하게 되었습니다.

실패가 성공보다 더 큰 배움을 주었고, 보안은 끊임없이 공부해야 하는 분야임을 깨달았습니다.

**"완벽한 보안은 없지만, 끊임없이 개선할 수 있다"**

---

**마지막 업데이트**: 2025년 12월 1일
**버전**: 3.0
**상태**: 연구 완료 (계속 업데이트 예정)
