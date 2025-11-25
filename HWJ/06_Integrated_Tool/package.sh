#!/bin/bash
###############################################################################
# RedChain 패키징 스크립트
# Kali Linux 및 다른 시스템으로 이식 가능한 압축 파일 생성
###############################################################################

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║               RedChain 패키징 스크립트                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# 색상 정의
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 현재 디렉토리
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 패키지 정보
PACKAGE_NAME="redchain"
VERSION="2.6"
DATE=$(date +%Y%m%d)
OUTPUT_NAME="${PACKAGE_NAME}_v${VERSION}_${DATE}"

echo -e "${BLUE}[*] 프로젝트 루트: $PROJECT_ROOT${NC}"
echo -e "${BLUE}[*] 패키지 이름: $OUTPUT_NAME${NC}"
echo ""

# 임시 디렉토리 생성
TMP_DIR="/tmp/${OUTPUT_NAME}"
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

echo -e "${BLUE}[*] 파일 복사 중...${NC}"

# 1. RedChain 도구 복사
echo -e "${YELLOW}  - 06_Integrated_Tool${NC}"
cp -r "$SCRIPT_DIR" "$TMP_DIR/redchain"

# 2. AWS IMDS 공격 스크립트 복사
echo -e "${YELLOW}  - 01_AWS_IMDS_Attack${NC}"
cp -r "$PROJECT_ROOT/01_AWS_IMDS_Attack" "$TMP_DIR/redchain/"

# 3. Site Defacement 스크립트 복사
echo -e "${YELLOW}  - 02_Site_Defacement${NC}"
cp -r "$PROJECT_ROOT/02_Site_Defacement" "$TMP_DIR/redchain/"

# 4. Persistence 모듈 복사
echo -e "${YELLOW}  - 03_Persistence${NC}"
cp -r "$PROJECT_ROOT/03_Persistence" "$TMP_DIR/redchain/"

# 4.5. Privilege Escalation 모듈 복사
echo -e "${YELLOW}  - 04_Privilege_Escalation${NC}"
cp -r "$PROJECT_ROOT/04_Privilege_Escalation" "$TMP_DIR/redchain/" 2>/dev/null || true

# 5. 문서 복사
echo -e "${YELLOW}  - Documentation${NC}"
cp -r "$PROJECT_ROOT/03_Documentation" "$TMP_DIR/redchain/" 2>/dev/null || true

# 6. 메인 README 복사
echo -e "${YELLOW}  - README.md${NC}"
cp "$PROJECT_ROOT/README.md" "$TMP_DIR/redchain/PROJECT_README.md" 2>/dev/null || true

# 7. 불필요한 파일 제거
echo -e "${BLUE}[*] 정리 중...${NC}"
find "$TMP_DIR" -name ".DS_Store" -delete
find "$TMP_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$TMP_DIR" -name "*.pyc" -delete
find "$TMP_DIR" -name ".git" -type d -exec rm -rf {} + 2>/dev/null || true

# 8. 실행 권한 부여
echo -e "${BLUE}[*] 실행 권한 설정 중...${NC}"
chmod +x "$TMP_DIR/redchain/redchain.py"
chmod +x "$TMP_DIR/redchain/install.sh"
chmod +x "$TMP_DIR/redchain/package.sh"
find "$TMP_DIR/redchain/01_AWS_IMDS_Attack" -name "*.py" -exec chmod +x {} \;
find "$TMP_DIR/redchain/01_AWS_IMDS_Attack" -name "*.sh" -exec chmod +x {} \;
find "$TMP_DIR/redchain/02_Site_Defacement" -name "*.sh" -exec chmod +x {} \;
find "$TMP_DIR/redchain/03_Persistence" -name "*.sh" -exec chmod +x {} \;
find "$TMP_DIR/redchain/04_Privilege_Escalation" -name "*.py" -exec chmod +x {} \; 2>/dev/null || true

# 9. Kali Linux용 설치 가이드 생성
echo -e "${BLUE}[*] Kali Linux 설치 가이드 생성 중...${NC}"
cat > "$TMP_DIR/redchain/INSTALL_KALI.md" << 'EOF'
# RedChain - Kali Linux 설치 가이드

## 🐉 Kali Linux에서 5분 만에 설치하기

### 1단계: 압축 해제

```bash
# 다운로드한 위치로 이동
cd ~/Downloads

# 압축 해제
tar -xzf redchain_v1.0_*.tar.gz
cd redchain
```

### 2단계: 설치 스크립트 실행

```bash
chmod +x install.sh
./install.sh
```

**설치 과정에서 질문:**
- 필수 도구 설치? → **y** (nmap, ffuf 등)
- Tor 설치? → **y** (익명 스캔용, 이미 설치되어 있을 수 있음)
- 전역 명령어 사용? → **y** (중요!)

### 3단계: 실행

```bash
redchain
```

**또는**

```bash
./redchain.py
```

---

## 🎯 빠른 시작

```bash
redchain

redchain> set target <타겟 IP>
redchain> set ssh_user <사용자명>
redchain> auto full
```

---

## ⚡ Kali Linux 전용 팁

### 1. Tor가 이미 설치되어 있는 경우

```bash
# Tor 서비스 시작
sudo systemctl start tor

# 자동 시작 설정
sudo systemctl enable tor
```

### 2. nmap을 proxychains와 함께 사용

```bash
redchain> set tor on
redchain> scan
```

### 3. 여러 타겟 관리

```bash
# 타겟 1
redchain> set target 192.168.1.100
redchain> scan

# 타겟 2로 전환
redchain> set target 192.168.1.101
redchain> scan
```

---

## 🔧 의존성

Kali Linux에는 대부분의 도구가 이미 설치되어 있습니다:

- ✅ Python 3
- ✅ nmap
- ✅ Tor
- ✅ proxychains4
- ⚠️ ffuf (설치 필요할 수 있음)

### ffuf 수동 설치

```bash
# 방법 1: apt
sudo apt install ffuf

# 방법 2: Go
go install github.com/ffuf/ffuf@latest
```

---

## 📁 디렉토리 구조

```
redchain/
├── redchain.py              # 메인 CLI 도구
├── install.sh               # 설치 스크립트
├── README.md                # 문서
├── QUICKSTART.md            # 빠른 시작
├── INSTALL_KALI.md          # 이 파일
├── 01_AWS_IMDS_Attack/      # AWS 공격 스크립트
├── 02_Site_Defacement/      # 웹 변조 스크립트
└── 03_Documentation/        # 상세 문서
```

---

## ⚠️ 법적 고지

이 도구는 교육 및 연구 목적으로만 사용하세요.
승인되지 않은 시스템에 사용 시 법적 책임을 질 수 있습니다.

---

**Kali Linux에 최적화되었습니다!** 🐉
EOF

# 10. 압축 파일 생성
echo ""
echo -e "${BLUE}[*] 압축 파일 생성 중...${NC}"

# tar.gz 생성
OUTPUT_DIR="$PROJECT_ROOT"
OUTPUT_FILE="$OUTPUT_DIR/${OUTPUT_NAME}.tar.gz"

cd /tmp
tar -czf "$OUTPUT_FILE" "$OUTPUT_NAME"

# 11. 정리
rm -rf "$TMP_DIR"

# 12. 완료
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    ✅ 패키징 완료!                            ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}출력 파일:${NC}"
echo -e "  ${BLUE}$OUTPUT_FILE${NC}"
echo ""

# 파일 크기 표시
FILE_SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
echo -e "${GREEN}파일 크기:${NC} ${BLUE}$FILE_SIZE${NC}"
echo ""

echo -e "${YELLOW}Kali Linux에서 사용하기:${NC}"
echo -e "  1. ${BLUE}scp ${OUTPUT_NAME}.tar.gz kali@<KALI-IP>:~/Downloads/${NC}"
echo -e "  2. Kali에서: ${BLUE}cd ~/Downloads${NC}"
echo -e "  3. Kali에서: ${BLUE}tar -xzf ${OUTPUT_NAME}.tar.gz${NC}"
echo -e "  4. Kali에서: ${BLUE}cd redchain${NC}"
echo -e "  5. Kali에서: ${BLUE}./install.sh${NC}"
echo -e "  6. Kali에서: ${BLUE}redchain${NC}"
echo ""

echo -e "${GREEN}또는 직접 복사:${NC}"
echo -e "  ${BLUE}cp $OUTPUT_FILE /path/to/usb/${NC}"
echo ""
