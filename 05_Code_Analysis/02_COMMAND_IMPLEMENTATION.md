# RedChain 명령어 구현 상세 분석

**파일**: `redchain.py`
**섹션**: 명령어 구현 (do_* 메서드)

---

## 1. `do_set()` - 설정 명령어

### 1.1 전체 코드

```python
def do_set(self, arg):
    """설정 변경

사용법:
    set target <IP 또는 도메인>   - 타겟 서버 설정
    set ssh_user <사용자명>       - SSH 사용자 설정
    set ssh_key <경로>            - SSH 키 경로 설정
    set ssh_pass <비밀번호>       - SSH 비밀번호 설정
    set tor on|off                - Tor 사용 설정
"""
    args = arg.split(maxsplit=1)
    if len(args) < 2:
        print(f"{Colors.FAIL}[-] 사용법: set <옵션> <값>{Colors.ENDC}")
        return

    option = args[0].lower()
    value = args[1]
```

### 1.2 문자열 분할 (split)

```python
args = arg.split(maxsplit=1)
```

**`str.split()` 메서드 상세**:

| 파라미터 | 기본값 | 설명 |
|----------|--------|------|
| `sep` | None (공백) | 구분자 |
| `maxsplit` | -1 (무제한) | 최대 분할 횟수 |

**`maxsplit=1`의 중요성**:
```python
# 사용자 입력: "set ssh_pass My Pass 123"

# maxsplit=1 (올바름)
args = "ssh_pass My Pass 123".split(maxsplit=1)
# 결과: ['ssh_pass', 'My Pass 123']

# maxsplit 없음 (문제!)
args = "ssh_pass My Pass 123".split()
# 결과: ['ssh_pass', 'My', 'Pass', '123']
```

**왜 maxsplit=1?**:
- 비밀번호에 공백이 있을 수 있음
- 첫 번째 공백까지만 분할
- 나머지는 하나의 문자열로 유지

### 1.3 입력 검증

```python
if len(args) < 2:
    print(f"{Colors.FAIL}[-] 사용법: set <옵션> <값>{Colors.ENDC}")
    return
```

**방어적 프로그래밍**:
```python
# 잘못된 입력 예시:
>>> set target        # 값 없음
>>> set               # 옵션도 값도 없음

# len(args) < 2 체크로 모두 방지
```

**`return` 문**:
- 함수 즉시 종료
- `cmd.Cmd`에서는 `None` 반환 = 계속 실행
- `True` 반환 = cmdloop() 종료

### 1.4 target 설정 (URL 정리)

```python
if option == 'target':
    clean_target = value
    clean_target = clean_target.replace('http://', '').replace('https://', '')
    clean_target = clean_target.rstrip('/')

    self.target = clean_target
```

**URL 정리 과정**:

```python
# 입력: "https://example.com/api/"
value = "https://example.com/api/"

# 1단계: http:// 제거
clean_target = value.replace('http://', '')
# 결과: "https://example.com/api/"

# 2단계: https:// 제거
clean_target = clean_target.replace('https://', '')
# 결과: "example.com/api/"

# 3단계: 뒤의 / 제거
clean_target = clean_target.rstrip('/')
# 결과: "example.com/api"
```

**`str.rstrip()` 메서드**:
```python
'hello   '.rstrip()      # 'hello' (공백 제거)
'hello///'.rstrip('/')   # 'hello' (/ 제거)
'hello\n\n'.rstrip('\n') # 'hello' (개행 제거)
```

**왜 URL 정리?**:
- SSH 접속 시 `ssh user@example.com` 형태 필요
- HTTP 요청 시 `http://example.com` 자동 추가
- 일관된 형식 유지

### 1.5 ssh_key 설정 (경로 확장)

```python
elif option == 'ssh_key':
    self.ssh_key = os.path.expanduser(value)
    print(f"{Colors.OKGREEN}[+] SSH 키 설정됨: {self.ssh_key}{Colors.ENDC}")
```

**`os.path.expanduser()` 함수**:

```python
# ~ (틸드) 확장
os.path.expanduser('~/.ssh/id_rsa')
# Linux: /home/username/.ssh/id_rsa
# Mac: /Users/username/.ssh/id_rsa
# Windows: C:\Users\username\.ssh\id_rsa

# ~user 확장 (다른 사용자)
os.path.expanduser('~john/.ssh/id_rsa')
# /home/john/.ssh/id_rsa
```

**왜 필요?**:
- 사용자가 `~/.ssh/key.pem` 입력 가능
- 셸이 자동 확장 안 함 (Python 문자열이므로)
- 절대 경로로 변환 필요

### 1.6 ssh_pass 설정 (비밀번호 마스킹)

```python
elif option == 'ssh_pass':
    self.ssh_pass = value
    print(f"{Colors.OKGREEN}[+] SSH 비밀번호 설정됨: {'*' * len(value)}{Colors.ENDC}")
```

**비밀번호 마스킹**:
```python
value = "MyP@ssw0rd"
masked = '*' * len(value)
# 결과: "**********"

# 문자열 곱셈 연산
'a' * 3      # 'aaa'
'=' * 10     # '=========='
'*' * 5      # '*****'
```

**보안 고려사항**:
- 터미널 히스토리에 평문 비밀번호 남음 (위험)
- 출력 시에만 마스킹 (저장은 평문)
- 더 나은 방법: `getpass.getpass()` 사용

**getpass 예제** (개선 가능):
```python
import getpass

# 입력 숨김 (화면에 안 보임)
password = getpass.getpass("Password: ")
```

### 1.7 Tor 설정 (Boolean 변환)

```python
elif option == 'tor':
    if value.lower() in ['on', 'true', '1']:
        self.use_tor = True
        print(f"{Colors.WARNING}[+] Tor 활성화됨{Colors.ENDC}")
    else:
        self.use_tor = False
        print(f"{Colors.OKGREEN}[+] Tor 비활성화됨{Colors.ENDC}")
```

**Boolean 값 처리**:

```python
# 다양한 입력 허용
'on'.lower()    # 'on'    → True
'ON'.lower()    # 'on'    → True
'On'.lower()    # 'on'    → True
'true'.lower()  # 'true'  → True
'1'.lower()     # '1'     → True

# False로 처리
'off'.lower()   # 'off'   → False
'false'.lower() # 'false' → False
'0'.lower()     # '0'     → False
```

**`in` 연산자**:
```python
# 리스트에서 검색
'on' in ['on', 'true', '1']  # True
'yes' in ['on', 'true', '1'] # False

# 문자열에서 검색
'on' in 'python'  # False
'th' in 'python'  # True
```

### 1.8 설정 저장 및 프롬프트 업데이트

```python
self.save_config()
self.update_prompt()
```

**메서드 체이닝**:
1. `save_config()`: 설정을 JSON 파일에 저장
2. `update_prompt()`: 프롬프트 문자열 업데이트

**update_prompt() 구현**:
```python
def update_prompt(self):
    """프롬프트 업데이트"""
    if self.target:
        target_display = f"{Colors.OKGREEN}{self.target}{Colors.ENDC}"
    else:
        target_display = f"{Colors.FAIL}no-target{Colors.ENDC}"

    tor_display = f"{Colors.WARNING}[TOR]{Colors.ENDC}" if self.use_tor else ""

    self.prompt = f'{Colors.BOLD}{Colors.FAIL}redchain{Colors.ENDC}({target_display}){tor_display}> '
```

**프롬프트 변화**:
```bash
# 초기 상태
redchain>

# target 설정 후
redchain(15.164.94.241)>

# tor 활성화 후
redchain(15.164.94.241)[TOR]>
```

**삼항 연산자 (Ternary Operator)**:
```python
# 문법: value_if_true if condition else value_if_false
tor_display = "[TOR]" if self.use_tor else ""

# 동일한 코드 (if-else 문)
if self.use_tor:
    tor_display = "[TOR]"
else:
    tor_display = ""
```

---

## 2. `do_show()` - 설정 확인 명령어

### 2.1 전체 코드

```python
def do_show(self, arg):
    """현재 설정 확인

사용법:
    show       - 모든 설정 표시
"""
    print(f"\n{Colors.BOLD}현재 설정:{Colors.ENDC}")
    print(f"  Target:    {self.target or Colors.FAIL + 'Not Set' + Colors.ENDC}")
    print(f"  SSH User:  {self.ssh_user}")
    print(f"  SSH Key:   {self.ssh_key or Colors.FAIL + 'Not Set' + Colors.ENDC}")
    print(f"  SSH Pass:  {'*' * len(self.ssh_pass) if self.ssh_pass else Colors.FAIL + 'Not Set' + Colors.ENDC}")
    print(f"  Use Tor:   {Colors.WARNING if self.use_tor else Colors.OKGREEN}{'ON' if self.use_tor else 'OFF'}{Colors.ENDC}")
    print()
```

### 2.2 `or` 연산자 활용

```python
self.target or Colors.FAIL + 'Not Set' + Colors.ENDC
```

**Python의 `or` 단축 평가 (Short-circuit Evaluation)**:

```python
# A or B
# A가 True면 A 반환, False면 B 반환

None or 'default'           # 'default'
'' or 'default'             # 'default'
0 or 'default'              # 'default'
'value' or 'default'        # 'value'
15.164.94.241 or 'default'  # '15.164.94.241'
```

**Falsy 값 (False로 평가)**:
```python
None      # 없음
False     # 불린 False
0         # 숫자 0
0.0       # 실수 0.0
''        # 빈 문자열
[]        # 빈 리스트
{}        # 빈 딕셔너리
()        # 빈 튜플
```

**실제 동작**:
```python
# target이 None일 때
self.target or 'Not Set'
# None or 'Not Set' → 'Not Set'

# target이 설정되었을 때
self.target or 'Not Set'
# '15.164.94.241' or 'Not Set' → '15.164.94.241'
```

### 2.3 조건부 색상 적용

```python
Colors.WARNING if self.use_tor else Colors.OKGREEN
```

**색상 선택 로직**:
```python
# Tor 활성화 시
self.use_tor = True
color = Colors.WARNING if self.use_tor else Colors.OKGREEN
# 결과: Colors.WARNING (노란색)

# Tor 비활성화 시
self.use_tor = False
color = Colors.WARNING if self.use_tor else Colors.OKGREEN
# 결과: Colors.OKGREEN (초록색)
```

**출력 예제**:
```
현재 설정:
  Target:    15.164.94.241
  SSH User:  sysadmin
  SSH Key:   Not Set
  SSH Pass:  ********************
  Use Tor:   OFF
```

---

## 3. `check_dependencies()` - 의존성 검사

### 3.1 전체 코드

```python
def check_dependencies(self):
    """boto3, botocore 패키지 확인 및 자동 설치"""
    missing = []

    try:
        import boto3
    except ImportError:
        missing.append('boto3')

    try:
        import botocore
    except ImportError:
        missing.append('botocore')

    if missing:
        print(f"{Colors.WARNING}[!] 필수 패키지가 설치되어 있지 않습니다: {', '.join(missing)}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] 자동 설치를 시도합니다...{Colors.ENDC}\n")

        # apt로 먼저 시도 (Kali Linux)
        for pkg in missing:
            if pkg == 'boto3':
                apt_pkg = 'python3-boto3'
            elif pkg == 'botocore':
                apt_pkg = 'python3-botocore'

            result = os.system(f"sudo apt install -y {apt_pkg} 2>/dev/null")
            if result != 0:
                # apt 실패 시 pip3로
                os.system(f"pip3 install {pkg}")

        print(f"\n{Colors.OKGREEN}[+] 패키지 설치 완료{Colors.ENDC}\n")
        return True

    return True
```

### 3.2 동적 Import와 예외 처리

```python
try:
    import boto3
except ImportError:
    missing.append('boto3')
```

**동적 Import 설명**:

```python
# 정적 Import (파일 상단)
import boto3  # 파일 로드 시 바로 실행, 없으면 프로그램 종료

# 동적 Import (함수 내부)
def check():
    try:
        import boto3  # 필요할 때만 Import
    except ImportError:
        print("boto3 없음")
        # 프로그램 계속 실행 가능
```

**ImportError 예외**:
- 모듈을 찾을 수 없을 때 발생
- `try-except`로 잡아서 처리
- 우아한 에러 핸들링 가능

### 3.3 리스트 메서드 - append()

```python
missing = []
missing.append('boto3')
missing.append('botocore')
```

**`list.append()` 메서드**:
```python
# 빈 리스트
lst = []

# 요소 추가
lst.append('item1')  # ['item1']
lst.append('item2')  # ['item1', 'item2']
lst.append('item3')  # ['item1', 'item2', 'item3']

# 리스트 추가 (중첩됨)
lst.append(['a', 'b'])  # ['item1', 'item2', 'item3', ['a', 'b']]
```

**`append` vs `extend`**:
```python
lst = [1, 2, 3]

# append: 요소 하나 추가
lst.append(4)
# [1, 2, 3, 4]

# extend: 여러 요소 추가
lst.extend([5, 6, 7])
# [1, 2, 3, 4, 5, 6, 7]
```

### 3.4 문자열 결합 - join()

```python
', '.join(missing)
```

**`str.join()` 메서드**:

```python
# 리스트를 문자열로 결합
items = ['boto3', 'botocore', 'awscli']

# 쉼표로 결합
result = ', '.join(items)
# 결과: 'boto3, botocore, awscli'

# 공백으로 결합
result = ' '.join(items)
# 결과: 'boto3 botocore awscli'

# 개행으로 결합
result = '\n'.join(items)
# 결과: 'boto3\nbotocore\nawscli'
```

**왜 `','.join(list)`가 아니라 `str.join(list)`?**:
- Python의 설계 철학
- 문자열 메서드로 일관성 유지
- 다른 언어들은 `list.join(',')` 형태

### 3.5 os.system() - 외부 명령 실행

```python
result = os.system(f"sudo apt install -y {apt_pkg} 2>/dev/null")
if result != 0:
    os.system(f"pip3 install {pkg}")
```

**`os.system()` 함수**:

```python
# 반환값: 종료 코드 (exit code)
result = os.system('ls -la')
# 0: 성공
# 1~255: 실패 (명령어마다 다름)

# 출력 캡처 안 됨 (화면에만 표시)
os.system('echo hello')  # hello (화면 출력)
```

**종료 코드 (Exit Code)**:
```bash
# 성공
$ ls /
$ echo $?
0

# 실패
$ ls /nonexistent
$ echo $?
2
```

**stderr 리다이렉션**:
```bash
# 2>/dev/null
#  │  └─ /dev/null (블랙홀, 버리기)
#  └─ 2 (stderr 파일 디스크립터)

# 에러 메시지 숨기기
sudo apt install -y python3-boto3 2>/dev/null

# 표준 출력, 에러 모두 숨기기
command > /dev/null 2>&1
```

### 3.6 fallback 패턴

```python
result = os.system(f"sudo apt install -y {apt_pkg} 2>/dev/null")
if result != 0:
    # apt 실패 시 pip3로
    os.system(f"pip3 install {pkg}")
```

**Fallback 패턴**:
1. 먼저 `apt` 시도 (Kali Linux에 최적화)
2. 실패하면 `pip3` 시도 (범용)
3. 사용자 경험 향상 (자동 복구)

**실전 예제**:
```python
# 설정 파일 읽기 with fallback
def load_config():
    try:
        return json.load(open('config.json'))
    except FileNotFoundError:
        return {'default': 'values'}

# API 호출 with fallback
def get_data():
    try:
        return api.fetch_from_primary()
    except ConnectionError:
        return api.fetch_from_backup()
```

---

## 계속...

다음 섹션에서는:
- `do_imds()` - AWS IMDS 공격 구현
- `load_latest_credentials()` - 자동 credentials 로드
- `do_escalate()` - 환경 변수로 credentials 전달
- `do_deface()` - SSH/SCP 자동화

를 분석하겠습니다.
