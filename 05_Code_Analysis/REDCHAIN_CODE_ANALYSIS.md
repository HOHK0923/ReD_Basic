# RedChain 자동화 툴 - 완전 코드 분석

**작성자**: 황준하
**프로젝트**: AWS 클라우드 보안 침투 테스트 자동화
**목적**: 포트폴리오 및 취업 준비용 상세 기술 분석

---

## 📋 목차

1. [프로젝트 구조 및 아키텍처](#1-프로젝트-구조-및-아키텍처)
2. [핵심 모듈 분석](#2-핵심-모듈-분석)
3. [라인별 코드 분석](#3-라인별-코드-분석)
4. [주요 기능 흐름도](#4-주요-기능-흐름도)
5. [보안 메커니즘](#5-보안-메커니즘)

---

## 1. 프로젝트 구조 및 아키텍처

### 1.1 전체 디렉토리 구조

```
RedChain/
│
├── 06_Integrated_Tool/              # CLI 통합 도구 (핵심)
│   ├── redchain.py                  # 메인 CLI 프로그램
│   ├── install.sh                   # 의존성 설치 스크립트
│   └── package.sh                   # 배포 패키징 스크립트
│
├── 01_AWS_IMDS_Attack/              # AWS IMDS 공격 모듈
│   ├── 120_aws_imds_exploit.py      # SSRF → IAM Credentials 탈취
│   └── 121_aws_privilege_escalation.py  # AWS 리소스 열거
│
├── 02_Site_Defacement/              # 웹사이트 변조 모듈
│   ├── MODERN_DEFACEMENT_FIXED.sh   # 해킹 페이지 배포
│   ├── TOGGLE_MODERN_FIXED.sh       # 원본/해킹 토글
│   ├── RESET_ALL.sh                 # 백업 파일 삭제
│   └── RESTORE_LARAVEL.sh           # Laravel 원본 복구
│
└── 05_Code_Analysis/                # 코드 분석 문서 (이 파일)
```

### 1.2 아키텍처 다이어그램

```
┌─────────────────────────────────────────────────────────────┐
│                      RedChain CLI (redchain.py)             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  cmd.Cmd 클래스 상속 (대화형 CLI 프레임워크)         │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
           │                    │                    │
           ▼                    ▼                    ▼
    ┌─────────────┐      ┌─────────────┐    ┌──────────────┐
    │  AWS IMDS   │      │  SSH/SCP    │    │  Config      │
    │  Attack     │      │  Operations │    │  Management  │
    └─────────────┘      └─────────────┘    └──────────────┘
           │                    │                    │
           ▼                    ▼                    ▼
    ┌─────────────┐      ┌─────────────┐    ┌──────────────┐
    │ Python      │      │ subprocess  │    │ JSON         │
    │ subprocess  │      │ + sshpass   │    │ ~/.redchain  │
    └─────────────┘      └─────────────┘    └──────────────┘
```

---

## 2. 핵심 모듈 분석

### 2.1 사용된 Python 표준 라이브러리

#### `cmd` 모듈
```python
import cmd
```
- **용도**: 대화형 명령줄 인터프리터 생성
- **핵심 클래스**: `cmd.Cmd`
- **주요 메서드**:
  - `do_<command>()`: 명령어 구현
  - `help_<command>()`: 도움말 제공
  - `cmdloop()`: 대화형 루프 실행
- **왜 사용했나?**: pwndbg, gdb 같은 대화형 디버거 스타일 CLI 구현

**문법 예제**:
```python
class MyCLI(cmd.Cmd):
    prompt = 'mycli> '

    def do_hello(self, arg):
        """Say hello"""
        print(f"Hello {arg}!")

    def do_exit(self, arg):
        """Exit the program"""
        return True  # cmdloop() 종료

if __name__ == '__main__':
    MyCLI().cmdloop()
```

#### `subprocess` 모듈
```python
import subprocess
```
- **용도**: 외부 프로세스 실행 및 제어
- **주요 함수**:
  - `subprocess.run()`: 명령 실행 및 결과 반환
  - `subprocess.Popen()`: 백그라운드 프로세스 생성
- **보안 고려사항**: `shell=True` 사용 시 명령 주입 취약점 주의

**문법 예제**:
```python
# 기본 사용법
result = subprocess.run(['ls', '-la'], capture_output=True, text=True)
print(result.stdout)

# shell=True 사용 (주의!)
result = subprocess.run('ls -la | grep py', shell=True, capture_output=True)

# 환경 변수 전달
env = os.environ.copy()
env['MY_VAR'] = 'value'
subprocess.run(['python3', 'script.py'], env=env)
```

#### `pathlib.Path` 모듈
```python
from pathlib import Path
```
- **용도**: 객체 지향적 파일 시스템 경로 처리
- **왜 사용했나?**: `os.path`보다 직관적이고 플랫폼 독립적
- **주요 메서드**:
  - `Path.home()`: 홈 디렉토리
  - `Path.exists()`: 파일 존재 확인
  - `Path / 'subdir'`: 경로 결합

**문법 예제**:
```python
# 홈 디렉토리의 설정 파일
config_file = Path.home() / '.myconfig' / 'settings.json'

# 파일 존재 확인
if config_file.exists():
    data = config_file.read_text()

# 프로젝트 루트 찾기
project_root = Path(__file__).parent.parent
```

#### `json` 모듈
```python
import json
```
- **용도**: JSON 데이터 직렬화/역직렬화
- **주요 함수**:
  - `json.load()`: 파일에서 JSON 읽기
  - `json.dump()`: 파일에 JSON 쓰기
  - `json.loads()`: 문자열에서 JSON 파싱
  - `json.dumps()`: Python 객체를 JSON 문자열로 변환

**문법 예제**:
```python
# 파일 읽기
with open('config.json', 'r') as f:
    config = json.load(f)

# 파일 쓰기
with open('config.json', 'w') as f:
    json.dump(config, f, indent=2)

# 문자열 파싱
data = json.loads('{"name": "value"}')
```

### 2.2 사용된 외부 라이브러리

#### `requests` 모듈
```python
import requests
```
- **용도**: HTTP 요청 전송 (SSRF 공격에 사용)
- **주요 기능**:
  - GET/POST 요청
  - 프록시 지원 (Tor)
  - 타임아웃 설정

**문법 예제**:
```python
# 기본 GET 요청
response = requests.get('http://example.com')
print(response.text)

# Tor 프록시 사용
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}
response = requests.get('http://example.com', proxies=proxies, timeout=10)

# SSRF 공격 예제
response = requests.get('http://169.254.169.254/latest/meta-data/')
```

#### `boto3` 모듈
```python
import boto3
```
- **용도**: AWS SDK for Python
- **주요 클래스**:
  - `boto3.client()`: 저수준 AWS API 클라이언트
  - `boto3.resource()`: 고수준 AWS 리소스 인터페이스
- **인증**: 환경 변수 또는 credentials 파일 사용

**문법 예제**:
```python
# 환경 변수로 인증
import os
os.environ['AWS_ACCESS_KEY_ID'] = 'ASIA...'
os.environ['AWS_SECRET_ACCESS_KEY'] = '...'
os.environ['AWS_SESSION_TOKEN'] = '...'

# EC2 클라이언트 생성
ec2 = boto3.client('ec2', region_name='ap-northeast-2')

# 인스턴스 목록
response = ec2.describe_instances()
for reservation in response['Reservations']:
    for instance in reservation['Instances']:
        print(instance['InstanceId'])
```

---

## 3. 라인별 코드 분석

### 3.1 셰뱅(Shebang) 및 독스트링 (Line 0-4)

```python
#!/usr/bin/env python3
"""
RedChain - Integrated Penetration Testing Framework
교육 및 연구 목적 전용 / Educational & Research Purpose Only
"""
```

**분석**:
- `#!/usr/bin/env python3`:
  - **셰뱅(Shebang)**: Unix/Linux에서 스크립트 실행 시 사용할 인터프리터 지정
  - `/usr/bin/env python3`: 시스템 PATH에서 python3 찾음 (절대 경로보다 유연)
  - 이 라인 덕분에 `./redchain.py` 직접 실행 가능

- **독스트링(Docstring)**:
  - 모듈 레벨 문서화
  - `help(redchain)` 실행 시 표시됨
  - 법적 면책조항 포함 (교육 목적임을 명시)

**실행 흐름**:
```bash
# 셰뱅 덕분에 가능:
./redchain.py

# 셰뱅 없으면:
python3 redchain.py
```

---

### 3.2 모듈 임포트 (Line 6-14)

```python
import cmd
import sys
import os
import json
import subprocess
import readline
from pathlib import Path
from datetime import datetime
import requests
```

**각 모듈의 역할**:

| 모듈 | 용도 | 사용 예시 |
|------|------|-----------|
| `cmd` | CLI 프레임워크 | `class RedChainCLI(cmd.Cmd)` |
| `sys` | 시스템 파라미터 | `sys.exit(1)` |
| `os` | 운영체제 인터페이스 | `os.system()`, `os.environ` |
| `json` | JSON 처리 | 설정 파일 읽기/쓰기 |
| `subprocess` | 외부 명령 실행 | SSH, SCP, 스크립트 실행 |
| `readline` | 명령줄 편집 | 화살표 키, 히스토리 |
| `pathlib.Path` | 경로 처리 | 플랫폼 독립적 경로 조작 |
| `datetime` | 날짜/시간 | 타임스탬프 생성 |
| `requests` | HTTP 요청 | SSRF 공격, API 호출 |

**임포트 방식 차이**:
```python
import os           # os.system() 사용
from pathlib import Path  # Path() 직접 사용 (Path.Path() 아님)
```

---

### 3.3 색상 클래스 정의 (Line 16-26)

```python
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
```

**ANSI 이스케이프 코드 분석**:

#### ANSI 색상 코드 구조
```
\033[<코드>m
  │   │   └─ 'm'으로 끝남 (필수)
  │   └─ 속성 코드 (숫자)
  └─ ESC 문자 (8진수 033 = 10진수 27)
```

#### 색상 코드 표

| 코드 | 색상 | 용도 |
|------|------|------|
| `\033[91m` | 빨강 | 에러, 위험 |
| `\033[92m` | 초록 | 성공 |
| `\033[93m` | 노랑 | 경고 |
| `\033[94m` | 파랑 | 정보 |
| `\033[95m` | 마젠타 | 헤더 |
| `\033[96m` | 시안 | 강조 |
| `\033[0m` | 리셋 | 색상 초기화 |
| `\033[1m` | 굵게 | 강조 |
| `\033[4m` | 밑줄 | 강조 |

**사용 예제**:
```python
# 초록색으로 성공 메시지
print(f"{Colors.OKGREEN}[+] 성공!{Colors.ENDC}")

# 빨간색 + 굵게
print(f"{Colors.BOLD}{Colors.FAIL}[!] 에러{Colors.ENDC}")

# 여러 색상 조합
print(f"{Colors.OKCYAN}[*] 진행 중...{Colors.ENDC}")
```

**왜 클래스로 정의?**:
- 상수 그룹화 (네임스페이스)
- `Colors.OKGREEN` 같이 직관적 사용
- 타이핑 자동완성 지원

---

### 3.4 RedChainCLI 클래스 정의 및 초기화 (Line 28-60)

```python
class RedChainCLI(cmd.Cmd):
    intro = f"""
{Colors.BOLD}{Colors.FAIL}╔═══════════════════════════════════════════════════════════════╗
║                        RedChain v1.0                          ║
║              Integrated Penetration Testing Framework        ║
║                                                               ║
║  {Colors.WARNING}⚠  교육 및 연구 목적 전용 / Educational Purpose Only{Colors.FAIL}  ║
╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}

타입: {Colors.OKCYAN}help{Colors.ENDC} 또는 {Colors.OKCYAN}?{Colors.ENDC} - 사용 가능한 명령어 확인
타입: {Colors.OKCYAN}help <command>{Colors.ENDC} - 특정 명령어 도움말
타입: {Colors.OKCYAN}exit{Colors.ENDC} 또는 {Colors.OKCYAN}quit{Colors.ENDC} - 종료

"""
    prompt = f'{Colors.BOLD}{Colors.FAIL}redchain>{Colors.ENDC} '

    def __init__(self):
        super().__init__()
        self.config_file = Path.home() / '.redchain_config.json'
        self.config = self.load_config()
        self.target = self.config.get('target', None)
        self.use_tor = self.config.get('use_tor', False)
        self.ssh_user = self.config.get('ssh_user', 'ec2-user')
        self.ssh_key = self.config.get('ssh_key', None)
        self.ssh_pass = self.config.get('ssh_pass', None)
        self.project_root = Path(__file__).parent.parent
        self.aws_credentials = None
```

#### `cmd.Cmd` 클래스 상속 상세 분석

**cmd.Cmd의 특수 속성**:

| 속성 | 타입 | 설명 |
|------|------|------|
| `intro` | str | 프로그램 시작 시 출력되는 환영 메시지 |
| `prompt` | str | 명령 프롬프트 문자열 |
| `cmdloop()` | method | 대화형 루프 시작 |
| `do_*()` | method | 명령어 구현 패턴 |
| `help_*()` | method | 도움말 구현 패턴 |
| `emptyline()` | method | 빈 줄 입력 시 동작 |
| `default()` | method | 알 수 없는 명령어 처리 |

**작동 원리**:
```python
# cmd.Cmd 내부 동작 (의사 코드)
class Cmd:
    def cmdloop(self):
        print(self.intro)  # 환영 메시지
        while True:
            line = input(self.prompt)  # 명령 입력 받기
            if line == 'exit':
                break

            # 'hello world' 입력 시
            cmd, args = line.split(' ', 1)  # 'hello', 'world'
            method = getattr(self, f'do_{cmd}', None)
            if method:
                result = method(args)  # do_hello('world') 호출
                if result:  # True 반환 시 종료
                    break
            else:
                self.default(line)  # 알 수 없는 명령어
```

#### `__init__()` 메서드 분석

```python
def __init__(self):
    super().__init__()  # 부모 클래스(cmd.Cmd) 초기화
```

**`super().__init__()`의 역할**:
- 부모 클래스의 `__init__()` 호출
- cmd.Cmd의 내부 상태 초기화
- 명령 히스토리, readline 설정 등

```python
self.config_file = Path.home() / '.redchain_config.json'
```

**경로 구성 분석**:
- `Path.home()`: 사용자 홈 디렉토리
  - Linux/Mac: `/home/username`
  - Windows: `C:\Users\username`
- `/` 연산자: 경로 결합 (pathlib의 특징)
- 결과: `/home/username/.redchain_config.json`

**왜 홈 디렉토리?**:
- 사용자별 독립적 설정
- 어디서 실행해도 동일한 설정 사용
- 설정 파일 유실 방지

```python
self.config = self.load_config()
```

**메서드 호출 순서**:
1. `__init__()` 실행 중
2. `self.load_config()` 호출
3. 설정 파일 읽기 또는 기본값 생성
4. 딕셔너리 반환 후 `self.config`에 저장

```python
self.target = self.config.get('target', None)
```

**`dict.get()` 메서드**:
- 문법: `dict.get(key, default)`
- 키가 없으면 `default` 반환 (KeyError 발생 안 함)
- `self.config['target']`보다 안전

**비교**:
```python
# KeyError 발생 가능
target = config['target']  # 키 없으면 에러

# None 반환 (안전)
target = config.get('target', None)

# 기본값 지정
user = config.get('ssh_user', 'ec2-user')
```

```python
self.project_root = Path(__file__).parent.parent
```

**`__file__` 변수**:
- 현재 파일의 절대 경로
- 예: `/home/user/RedChain/06_Integrated_Tool/redchain.py`

**경로 탐색**:
```python
Path(__file__)                # /home/user/RedChain/06_Integrated_Tool/redchain.py
Path(__file__).parent         # /home/user/RedChain/06_Integrated_Tool
Path(__file__).parent.parent  # /home/user/RedChain (프로젝트 루트)
```

**왜 필요?**:
- 프로젝트 내 다른 스크립트 찾기
- 예: `self.project_root / '01_AWS_IMDS_Attack' / 'exploit.py'`

```python
self.aws_credentials = None
```

**초기값 None**:
- IMDS 공격 성공 시 여기에 credentials 저장
- 나중에 `escalate` 명령어에서 재사용
- 메모리 캐싱 (매번 파일 읽기 방지)

---

### 3.5 설정 파일 관리 (load_config, save_config)

```python
def load_config(self):
    """설정 파일 로드"""
    if self.config_file.exists():
        with open(self.config_file, 'r') as f:
            return json.load(f)
    else:
        return {
            'target': None,
            'use_tor': False,
            'ssh_user': 'ec2-user',
            'ssh_key': None,
            'ssh_pass': None
        }
```

#### 파일 존재 확인

```python
if self.config_file.exists():
```

**`Path.exists()` 메서드**:
- 파일 또는 디렉토리 존재 여부 확인
- 반환값: `True` 또는 `False`
- 심볼릭 링크 추적함

**대안 메서드들**:
```python
path.exists()      # 파일 또는 디렉토리
path.is_file()     # 파일만
path.is_dir()      # 디렉토리만
path.is_symlink()  # 심볼릭 링크
```

#### Context Manager (`with` 문)

```python
with open(self.config_file, 'r') as f:
    return json.load(f)
```

**`with` 문법 분석**:
```python
# with 문 사용 (권장)
with open('file.txt', 'r') as f:
    data = f.read()
# 자동으로 f.close() 호출

# with 없이 (비권장)
f = open('file.txt', 'r')
try:
    data = f.read()
finally:
    f.close()  # 수동으로 닫아야 함
```

**왜 `with` 사용?**:
- 파일 자동 닫기 (리소스 누수 방지)
- 예외 발생해도 안전하게 정리
- 코드 간결성

**`open()` 모드**:
| 모드 | 의미 | 용도 |
|------|------|------|
| `'r'` | Read | 읽기 전용 |
| `'w'` | Write | 쓰기 (덮어쓰기) |
| `'a'` | Append | 추가 쓰기 |
| `'r+'` | Read+Write | 읽기/쓰기 |
| `'rb'` | Read Binary | 바이너리 읽기 |

#### JSON 파싱

```python
json.load(f)
```

**`json.load()` vs `json.loads()`**:
```python
# load(): 파일 객체에서 읽기
with open('config.json', 'r') as f:
    data = json.load(f)

# loads(): 문자열에서 읽기
json_string = '{"key": "value"}'
data = json.loads(json_string)
```

**JSON 구조 예제**:
```json
{
  "target": "15.164.94.241",
  "use_tor": false,
  "ssh_user": "sysadmin",
  "ssh_key": null,
  "ssh_pass": "Adm1n!2024#Secure"
}
```

#### 기본 설정 반환

```python
else:
    return {
        'target': None,
        'use_tor': False,
        'ssh_user': 'ec2-user',
        'ssh_key': None,
        'ssh_pass': None
    }
```

**딕셔너리 리터럴**:
```python
# 빈 딕셔너리
config = {}

# 초기값 있는 딕셔너리
config = {
    'key1': 'value1',
    'key2': 123,
    'key3': None,
    'key4': ['list', 'values']
}
```

**None의 의미**:
- "설정되지 않음"을 명시적으로 표현
- `if self.target:` 같은 조건문에서 False로 평가
- JSON에서 `null`로 직렬화됨

---

### 3.6 설정 저장 메서드

```python
def save_config(self):
    """설정 파일 저장"""
    self.config['target'] = self.target
    self.config['use_tor'] = self.use_tor
    self.config['ssh_user'] = self.ssh_user
    self.config['ssh_key'] = self.ssh_key
    self.config['ssh_pass'] = self.ssh_pass

    with open(self.config_file, 'w') as f:
        json.dump(self.config, f, indent=2)
```

#### 딕셔너리 업데이트

```python
self.config['target'] = self.target
```

**동작 원리**:
1. 인스턴스 변수 → 딕셔너리로 복사
2. 메모리 상태와 파일 동기화 준비

**왜 이렇게?**:
- `self.target`: 프로그램 실행 중 사용 (빠름)
- `self.config`: 파일 저장용 (영구 보관)

#### JSON 직렬화

```python
json.dump(self.config, f, indent=2)
```

**`json.dump()` 파라미터**:
| 파라미터 | 설명 | 예제 |
|----------|------|------|
| `obj` | 직렬화할 Python 객체 | `self.config` |
| `fp` | 파일 객체 | `f` |
| `indent` | 들여쓰기 공백 수 | `2` |
| `ensure_ascii` | ASCII만 사용 | `False` (한글 지원) |
| `sort_keys` | 키 정렬 | `True` |

**`indent=2` 효과**:
```json
// indent=2 (가독성 좋음)
{
  "target": "15.164.94.241",
  "use_tor": false
}

// indent=None (압축됨)
{"target":"15.164.94.241","use_tor":false}
```

---

## 계속 작성 중...

이 문서는 redchain.py의 모든 코드를 한 줄씩 분석합니다. 다음 섹션에서는:
- `do_set()` 명령어 분석
- `do_imds()` AWS 공격 흐름
- `do_escalate()` 권한 상승
- `do_deface()` 웹사이트 변조
- SSH/SCP 자동화
- 에러 처리 및 예외 상황

등을 다룰 예정입니다.
