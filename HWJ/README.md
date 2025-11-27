# RedChain - AWS 클라우드 보안 침투 테스트 연구 프로젝트

![Version](https://img.shields.io/badge/version-2.6-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**작성자**: 황준하
**작성 기간**: 2025년 11월
**목적**: AWS 클라우드 보안 연구 및 자동화 도구 개발

---

## 프로젝트 개요

RedChain은 AWS 클라우드 환경의 보안 취약점을 연구하고, 침투 테스트를 자동화하기 위해 개발한 프로젝트입니다.

실제 보안 사고(Capital One 2019 SSRF)를 참고하여, 작은 설정 실수가 어떻게 전체 인프라를 무너뜨리는지 재현하고, 이를 방어하는 방법을 연구했습니다.

### 핵심 연구 주제

```
SSRF 취약점 → AWS IMDS 접근 → IAM 자격증명 탈취 → 클라우드 인프라 장악
```

**발견한 핵심**:
- 완벽한 WAF(ModSecurity)도 예외 설정 하나로 무력화됨
- 자동화 도구의 한계와 사람의 창의성 필요성
- 실무에서는 기술보다 "사람"이 가장 큰 취약점

---

## 프로젝트 구조

```
HWJ/
├── 01_AWS_IMDS_Attack/          # AWS IMDS 공격 연구
│   ├── 119_setup_aws_vuln.sh    # 취약한 환경 구성
│   └── 120_aws_imds_exploit.py  # IMDS 자동 공격 도구
│
├── 06_Integrated_Tool/          # 자동화 도구 개발
│   ├── redchain.py              # CLI 통합 도구
│   ├── auto_redteam_ultimate.py # 완전 자동화 시도
│   └── real_penetration.py      # User-data 백도어
│
├── PORTFOLIO_DOCUMENTS/         # 포트폴리오 문서 (필독!)
│   ├── AUTOMATED_TOOL_FAILURE_REPORT.md  # 자동화 실패 분석
│   └── 07_Manual_Penetration_Guide/      # 수동 침투 테스트 연구
│       ├── 01~09_*.md               # 단계별 가이드
│       ├── 10_full_automation_script.py
│       ├── 11_real_world_attacks.md # 실제 해커 방법론
│       ├── 12_low_privilege_escalation_scenario.md
│       └── 13_low_priv_to_root.py
│
└── README.md                    # 이 파일
```

---

## 연구 과정 및 발견

### 1단계: 자동화 도구 개발 (1주차)

#### 개발한 도구

**auto_redteam_ultimate.py**
- SSRF → IMDS → AWS 장악까지 완전 자동화
- 총 개발 시간: 40시간
- 코드량: 약 450줄

**real_penetration.py**
- EC2 User-data 수정을 통한 영구 백도어
- AWS API 활용한 자동화
- 코드량: 약 280줄

#### 기대했던 것
> "자동화하면 모든 걸 5분 안에 해킹할 수 있을 거야"

### 2단계: 실전 테스트 (2주차)

#### 테스트 환경
- **대상**: AWS EC2 (3.35.218.180)
- **보안**: ModSecurity WAF, PHP disable_functions
- **목표**: 완전 자동화로 서버 장악

#### 충격적인 결과

```
총 시도: 450+ 공격
성공: 0건
ModSecurity 차단: 247건 (100%)

SQL Injection: 200+ 페이로드 테스트 → 전부 차단
SSRF: 엔드포인트 삭제로 접근 불가
Reverse Shell: RCE 경로 없음

최종 성공률: 0%
```

#### 깨달음
> "자동화 도구는 강화된 서버에 거의 무력하다"

### 3단계: 원인 분석 및 대안 연구 (3주차)

#### 왜 실패했는가?

**1. WAF의 강력함**
```
ModSecurity = 10년 이상의 공격 패턴 학습
자동화 도구 페이로드 = 모두 "알려진 것"
결과 = 100% 차단
```

**2. 도구의 근본적 한계**
```python
# 도구는 이렇게 동작
if attack_failed:
    print("Failed")
    exit()

# 사람은 이렇게 생각
if attack_failed:
    try_phishing()
    try_social_engineering()
    wait_6_months()
    buy_zero_day()
    # 무한한 창의성
```

**3. 환경 변화 대응 불가**
```
예상: health.php 엔드포인트 존재
현실: 엔드포인트 삭제됨
도구: 멈춤
사람: 백업 파일(.bak) 찾아서 소스코드 분석
```

#### 대안 연구

**실제 해커들의 방법**:
1. 기술 공격 실패 → 피싱으로 직원 계정 탈취
2. 외부 방어 강함 → 내부자 매수 또는 활용
3. 지금 안 됨 → 6개월 대기 (인내심)
4. 직접 못 함 → Zero-Day 구매 (돈)

**가장 현실적인 시나리오**:
```
낮은 권한 개발자 계정 (dev-junior)
→ Cron Job 777 권한 발견
→ SUID rootbash 생성
→ Root 쉘 획득
→ 백도어 설치

성공률: 매우 높음 (실수가 흔함)
```

---

## 주요 성과

### 기술적 성과

✅ **자동화 도구 개발**
- Python 기반 침투 도구 3개
- CLI 통합 도구 (redchain.py)
- 총 코드량: 약 2,000줄

✅ **연구 문서 작성**
- 침투 테스트 가이드 12개 (15,000줄)
- 실패 분석 보고서
- 실전 시나리오 및 스크립트

✅ **실전 경험**
- 450+ 공격 시도 및 분석
- WAF 우회 실패 경험
- 대안 시나리오 개발

### 학습 성과

**보안 지식 심화**:
- AWS 클라우드 보안 아키텍처
- ModSecurity WAF 동작 원리
- OWASP Top 10 심층 이해

**도구 숙련도**:
- Kali Linux 전문 도구 활용
- sqlmap, Metasploit, Burp Suite
- nmap, nikto, gobuster

**프로그래밍 실력**:
- Python 고급 패턴 (asyncio, paramiko)
- AWS boto3 SDK 마스터
- Bash 자동화 스크립트

---

## 핵심 교훈

### 1. 자동화의 한계

> "자동화는 반복 작업만 가능하다. 창의성은 사람만의 것이다."

**발견한 사실**:
- 자동화 도구 = 빠르지만 경직됨
- 실제 침투 = 느리지만 유연함
- 최선 = 하이브리드 (도구 + 사람)

### 2. 실제 보안의 복잡성

> "영화처럼 5분 해킹? 현실은 6개월 장기전이다."

**현실적 공격 흐름**:
```
Day 1-7: 정찰 (GitHub, LinkedIn)
Day 8-14: 피싱 캠페인 (10명에게 발송)
Day 15: 한 명 클릭 → 개발자 계정 탈취
Day 16-30: 내부 네트워크 침투
Day 31-90: 권한 상승 및 백도어 설치
```

### 3. 사람이 가장 큰 취약점

> "최신 WAF도 피싱 이메일 한 통은 못 막는다."

**통계**:
- 기술 공격 성공률: < 1%
- 피싱 공격 성공률: 30-40%
- 내부자 공격: 방어 거의 불가능

---

## 사용법

### 1. 환경 설정

```bash
# 저장소 클론
git clone [this_repository]
cd HWJ

# Python 패키지
pip install requests boto3 paramiko

# Kali Linux 도구
apt install nmap nikto gobuster sqlmap metasploit-framework
```

### 2. 자동화 도구 실행

```bash
# RedChain CLI (통합 도구)
cd 06_Integrated_Tool
./redchain.py

# 개별 도구
python3 01_AWS_IMDS_Attack/120_aws_imds_exploit.py
python3 PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/13_low_priv_to_root.py
```

### 3. 수동 침투 테스트

```bash
# 가이드 문서
cd PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide
cat README.md

# 각 Phase 학습
cat 01_reconnaissance.md
cat 11_real_world_attacks.md
```

---

## 필독 문서

### 🌟 가장 중요한 문서들

1. **[AUTOMATED_TOOL_FAILURE_REPORT.md](./PORTFOLIO_DOCUMENTS/AUTOMATED_TOOL_FAILURE_REPORT.md)**
   - 자동화 도구 개발 및 실패 전 과정
   - 솔직한 경험과 배운 점
   - **포트폴리오의 핵심**

2. **[11_real_world_attacks.md](./PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/11_real_world_attacks.md)**
   - 자동화가 실패했을 때의 대안
   - 실제 해커들이 사용하는 방법
   - 피싱, 내부자, 장기전 전략

3. **[12_low_privilege_escalation_scenario.md](./PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/12_low_privilege_escalation_scenario.md)**
   - 가장 현실적인 공격 시나리오
   - 낮은 권한 → Root 권한 상승
   - 실무에서 자주 발생하는 실수 활용

---

## 배운 점 요약

### 기술적 교훈

1. ✅ WAF 우회는 매우 어렵다 (성공률 < 1%)
2. ✅ IMDS v1은 위험하다 → v2 필수
3. ✅ 자동화는 알려진 패턴만 찾는다
4. ✅ 새로운 공격은 사람만 개발 가능

### 실무적 교훈

1. ✅ 기술보다 사람이 더 취약하다
2. ✅ 피싱이 가장 효과적이다
3. ✅ 내부 설정 실수(777 권한)가 흔하다
4. ✅ 장기전 인내심이 필요하다

### 개인적 성장

1. ✅ 실패에서 더 많이 배운다
2. ✅ 이론과 실전은 완전히 다르다
3. ✅ 문제 해결 능력이 핵심이다
4. ✅ 겸손함이 중요하다 (처음 목표: 5분 해킹 → 현실: 0% 성공)

---

## 향후 계획

### 단기 (1개월)
- [ ] AI 기반 페이로드 생성기 (GPT-4)
- [ ] Bug Bounty 플랫폼 참여
- [ ] 오픈소스 기여 시작

### 중기 (3개월)
- [ ] AWS Security Specialty 인증
- [ ] 하이브리드 도구 개발 (자동 + 수동)
- [ ] 실제 침투 테스트 프로젝트 참여

### 장기 (6개월+)
- [ ] 보안 컨설팅 회사 입사
- [ ] 컨퍼런스 발표 (CodeEngn, DEFCON)
- [ ] 보안 연구 논문 작성

---

## 법적 고지사항

⚠️ **매우 중요**

본 프로젝트는 **교육 및 연구 목적**으로만 사용해야 합니다.

**절대 금지**:
- 무단으로 타인의 시스템 침투
- 허가 없는 보안 테스트
- 악의적 목적 사용

**허용**:
- 본인 소유 시스템 테스트
- 사전 승인된 침투 테스트 (계약서 필수)
- 보안 연구 및 학습
- CTF 대회 참여

**법적 책임**:
- 정보통신망법: 무단 침입 시 5년 이하 징역
- 개인정보보호법: 데이터 유출 시 가중 처벌
- 모든 책임은 사용자에게 있습니다

---

## 참고 자료

### 도서
- "The Web Application Hacker's Handbook" - Dafydd Stuttard
- "Social Engineering: The Art of Human Hacking" - Kevin Mitnick
- "AWS Security" - Dylan Shields

### 웹 자료
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

### 실제 사례
- Capital One Breach (2019) - SSRF to IMDS
- Uber Breach (2022) - Social Engineering
- SolarWinds (2020) - Supply Chain Attack

---

## 연락처

**작성자**: 황준하
**이메일**: hwangpongpong10@gmail.com
**GitHub**: [이 저장소]
**작성일**: 2025년 11월 26일

---

## 라이선스

MIT License (교육 목적 한정)

```
추가 제한사항:
- 상업적 사용 금지
- 악의적 목적 사용 금지
- 무단 침투 테스트 금지
```

---

**마지막 업데이트**: 2025년 11월 26일
**버전**: 2.6
**상태**: 연구 완료 (계속 업데이트 예정)

---

## 감사의 말

이 프로젝트를 통해 보안의 복잡성과 자동화의 한계를 깊이 이해하게 되었습니다.

실패가 성공보다 더 큰 배움을 주었고, 겸손함의 중요성을 깨달았습니다.

**"완벽한 보안은 없지만, 끊임없이 개선할 수 있다"**