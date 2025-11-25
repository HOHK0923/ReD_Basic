# 프로젝트 구조

## 디렉토리 구성

```
CLEAN_PROJECT/
├── README.md
├── LICENSE
├── PROJECT_STRUCTURE.md
│
├── 01_AWS_IMDS_Attack/
│   └── 120_aws_imds_exploit.py       # SSRF → IAM Credentials 탈취
│
├── 02_Site_Defacement/
│   ├── MODERN_DEFACEMENT_FIXED.sh    # 랜섬웨어 페이지 배포
│   ├── TOGGLE_MODERN_FIXED.sh        # 원본/해킹 토글
│   ├── RESET_ALL.sh                  # 백업 삭제
│   └── RESTORE_LARAVEL.sh            # Laravel 복구
│
├── 03_Persistence/
│   ├── README.md                     # Persistence 모듈 문서
│   ├── backdoor_setup.sh             # 백도어 설치 (사용자, SSH, Cron, Systemd, 웹쉘)
│   └── cleanup_backdoor.sh           # 백도어 제거 및 정리
│
├── 05_Code_Analysis/
│   ├── REDCHAIN_CODE_ANALYSIS.md     # redchain.py 분석
│   └── 02_COMMAND_IMPLEMENTATION.md  # 명령어 구현 분석
│
└── 06_Integrated_Tool/
    ├── redchain.py                   # CLI 메인
    ├── install.sh                    # 자동 설치
    ├── package.sh                    # 패키징
    └── README.md                     # 사용법
```

## 파일 설명

### 01_AWS_IMDS_Attack/

**120_aws_imds_exploit.py** (415 라인)
- Health check API 탐지
- SSRF 취약점 확인
- IAM Role 이름 획득
- Credentials JSON 저장

실행:
```bash
python3 120_aws_imds_exploit.py http://target-ip
```

### 02_Site_Defacement/

**MODERN_DEFACEMENT_FIXED.sh** (313 라인)
- BLACKLOCK 랜섬웨어 페이지
- network_diagram.jpg 자동 다운로드
- .htaccess PHP 리다이렉트

**TOGGLE_MODERN_FIXED.sh** (368 라인)
- 원본 ↔ 해킹 페이지 전환
- 자동 백업 관리

**RESET_ALL.sh** (41 라인)
- /tmp/ 백업 파일 삭제
- 악성 파일 제거

**RESTORE_LARAVEL.sh** (99 라인)
- Laravel index.php 복구
- 모든 변조 파일 정리

### 03_Persistence/

**backdoor_setup.sh** (200+ 라인)
- 백도어 사용자 생성 (sysupdate)
- SSH 키 백도어 설치
- Cron 작업 추가 (매 시간 리버스 쉘)
- Systemd 서비스 백도어
- 웹쉘 설치 (/.system/health.php)

**cleanup_backdoor.sh** (100+ 라인)
- 모든 백도어 제거
- 시스템 복구
- 로그 정리

실행:
```bash
# 백도어 설치
redchain> persist install

# 백도어 제거
redchain> persist cleanup
```

### 05_Code_Analysis/

포트폴리오용 코드 분석 문서

**REDCHAIN_CODE_ANALYSIS.md**
- Python 모듈 분석
- 클래스 구조 설명
- 코드 패턴 설명

**02_COMMAND_IMPLEMENTATION.md**
- 명령어 구현 상세
- 문자열 처리 기법
- 에러 핸들링

### 06_Integrated_Tool/

**redchain.py** (667 라인)
- cmd.Cmd 기반 CLI
- AWS Credentials 자동 관리
- SSH/SCP 자동화

주요 클래스:
```python
class RedChainCLI(cmd.Cmd):
    def do_set()       # 설정
    def do_imds()      # IMDS 공격
    def do_escalate()  # 권한 상승
    def do_deface()    # 웹 변조
    def do_persist()   # Persistence 백도어
```

**install.sh** (200 라인)
- Python 확인
- 패키지 설치 (nmap, ffuf, sshpass)
- pip 의존성 설치

**package.sh** (252 라인)
- tar.gz 생성
- 버전 관리

## 기술 스택

| 언어 | 용도 |
|------|------|
| Python 3.8+ | CLI, AWS SDK |
| Bash | 자동화 스크립트 |
| PHP | 타겟 서버 |
| JavaScript | 악성코드 다운로드 |

## 총 라인 수

- Python: ~1,200
- Bash: ~1,300
- Markdown: ~4,000
- **합계**: ~6,500 라인

---

**작성**: 2025-11-25
**버전**: 2.5
