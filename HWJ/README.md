# RedChain - AWS 클라우드 보안 침투 테스트 자동화

![Version](https://img.shields.io/badge/version-2.5-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**작성자**: 황준하
**목적**: AWS 클라우드 보안 엔지니어 포트폴리오

---

## 프로젝트 소개

AWS EC2 인스턴스의 IMDS(Instance Metadata Service) 취약점을 이용한 공격 체인을 자동화한 프로젝트입니다.

실제 보안 사고 사례(Capital One 2019)를 참고하여 작은 설정 실수가 어떻게 전체 인프라를 무너뜨리는지 재현했습니다.

### 공격 시나리오

```
WAF 우회 (health check 예외)
    → SSRF 취약점 발견
    → AWS IMDS 공격
    → IAM Credentials 탈취
    → 클라우드 리소스 접근
```

**핵심 포인트**: ModSecurity WAF가 있지만 `/api/health.php`만 예외 처리되어 있어서 전체 방어가 무력화됨

---

## 주요 기능

- **자동화 CLI 도구** (pwndbg 스타일)
- AWS Credentials 자동 수집 및 재사용
- SSH 비밀번호 자동 입력 (sshpass)
- Tor 프록시 지원
- **Persistence 백도어** (레드팀 시뮬레이션)
  - 백도어 사용자 생성
  - SSH 키 백도어
  - Cron/Systemd 자동 재연결
  - 웹쉘

---

## 설치

```bash
git clone https://github.com/your-username/RedChain.git
cd RedChain/CLEAN_PROJECT/06_Integrated_Tool
sudo ./install.sh
./redchain.py
```

---

## 사용법

```bash
# 타겟 설정
redchain> set target 15.164.94.241
redchain> set ssh_user admin
redchain> set ssh_pass MyPassword123

# 공격 실행
redchain> imds          # Credentials 탈취
redchain> escalate      # AWS 리소스 확인
redchain> deface        # 웹사이트 변조
redchain> persist install  # 백도어 설치 (레드팀 시뮬레이션)

# 시뮬레이션 종료 후 정리
redchain> persist cleanup  # 모든 백도어 제거
```

---

## 프로젝트 구조

```
├── 01_AWS_IMDS_Attack/         # IMDS 공격 스크립트
├── 02_Site_Defacement/         # 웹 변조 스크립트
├── 03_Persistence/             # 백도어 및 Persistence 모듈
├── 05_Code_Analysis/           # 코드 분석 문서
└── 06_Integrated_Tool/         # CLI 도구
```

자세한 내용은 [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) 참고

---

## 기술 스택

- **Python 3.8+**: cmd, requests, boto3
- **Bash**: 자동화 스크립트
- **도구**: nmap, ffuf, sshpass, tor

---

## 배운 점

1. **WAF 우회**: 예외 설정 하나로 전체 방어 무력화
2. **IMDSv1 위험성**: IMDSv2로 업그레이드 필수
3. **자동화**: 반복 작업을 CLI로 통합하면 효율적

---

## 방어 방법

```bash
# IMDSv2 강제
aws ec2 modify-instance-metadata-options \
    --instance-id i-xxxxx \
    --http-tokens required

# WAF 예외 제거
# ModSecurity 설정에서 health check 예외 삭제

# SSRF 차단
# 내부 IP(169.254.x.x) 요청 차단
```

---

## 법적 고지

**교육 목적으로만 사용**

자신이 소유하거나 허가받은 시스템에서만 테스트하세요.
무단 침입 시 정보통신망법 위반으로 5년 이하 징역에 처해질 수 있습니다.

---

## 라이선스

MIT License - 자유롭게 사용 가능 (교육 목적)

---

**Contact**: hwangpongpong10@gmail.com
