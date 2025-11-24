# RedChain 빠른 시작 가이드

## 🚀 5분 안에 시작하기

### 1단계: 설치 (1분)

```bash
cd /Users/hwangjunha/Desktop/Red_basic_local/H/CLEAN_PROJECT/06_Integrated_Tool
./install.sh
```

**질문에 'y' 입력:**
- 필수 도구 설치? → **y**
- Tor 설치? → **y** (익명 스캔용, 선택사항)
- 전역 명령어 사용? → **y** (중요! 이렇게 해야 `redchain` 명령어로 실행됨)

### 2단계: 실행 (10초)

```bash
redchain
```

**또는**

```bash
./redchain.py
```

### 3단계: 타겟 설정 (30초)

```
redchain> set target 52.79.240.83
redchain> set ssh_user sysadmin
redchain> show
```

### 4단계: 공격 시작! (3분)

```
redchain> auto full
```

---

## 💡 주요 명령어 (gdb 스타일)

### 설정
```
set target 52.79.240.83      # 타겟 설정 (필수!)
set ssh_user sysadmin         # SSH 사용자 (필수!)
set ssh_key ~/.ssh/key.pem    # SSH 키 (선택)
set tor on                    # Tor 사용 (선택)
show                          # 설정 확인
```

### 스캔
```
scan                # 포트 스캔
enum                # 엔드포인트 탐색
```

### 공격
```
imds                # AWS IMDS 공격
escalate            # AWS 권한 상승
deface              # 웹사이트 변조
```

### SSH
```
ssh                 # SSH 연결
ssh whoami          # 원격 명령 실행
```

### 자동화
```
auto recon          # 정찰만
auto exploit        # 공격만
auto full           # 전체
```

### 기타
```
help                # 도움말
clear               # 화면 지우기
exit                # 종료
```

---

## 🎯 예제 시나리오

### 시나리오 1: IP 바뀌는 서버 연결

```bash
# 터미널에서 바로 실행
redchain

# 새 IP로 업데이트
redchain> set target 52.79.240.100
redchain> ssh
```

### 시나리오 2: 전체 공격 자동화

```bash
redchain

redchain> set target example.com
redchain> set ssh_user ec2-user
redchain> auto full
# 나머지는 자동!
```

### 시나리오 3: 정찰만

```bash
redchain

redchain> set target example.com
redchain> set tor on
redchain> auto recon
```

---

## ⚡ 문제 해결

### "redchain: command not found"

```bash
# 설치 스크립트 다시 실행
cd /Users/hwangjunha/Desktop/Red_basic_local/H/CLEAN_PROJECT/06_Integrated_Tool
./install.sh

# 또는 직접 실행
./redchain.py
```

### "타겟이 설정되지 않았습니다"

```
redchain> set target <IP 또는 도메인>
```

---

## 🔥 Tips

1. **설정은 자동 저장됨** - 다음 실행 시 타겟이 기억됨
2. **Tab 자동완성** - 명령어를 Tab으로 자동완성
3. **Ctrl+D** - 빠른 종료
4. **help <명령어>** - 각 명령어 상세 설명

---

**이제 `redchain` 한 번만 치면 됩니다!** 🚀
