#!/bin/bash
###############################################################################
# RedChain 설치 스크립트
# Educational & Research Purpose Only
###############################################################################

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║               RedChain 설치 스크립트                          ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 1. Python 확인
echo -e "${BLUE}[*] Python 버전 확인...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[-] Python3가 설치되어 있지 않습니다.${NC}"
    echo -e "${YELLOW}[!] sudo apt install python3 python3-pip${NC}"
    exit 1
fi
PYTHON_VERSION=$(python3 --version)
echo -e "${GREEN}[+] $PYTHON_VERSION${NC}"
echo ""

# 2. 필수 패키지 확인
echo -e "${BLUE}[*] 필수 도구 확인 중...${NC}"
MISSING_TOOLS=()

if ! command -v nmap &> /dev/null; then
    MISSING_TOOLS+=("nmap")
fi

if ! command -v ffuf &> /dev/null; then
    MISSING_TOOLS+=("ffuf")
fi

if ! command -v sshpass &> /dev/null; then
    MISSING_TOOLS+=("sshpass")
fi

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo -e "${YELLOW}[!] 다음 도구가 설치되어 있지 않습니다: ${MISSING_TOOLS[*]}${NC}"
    echo -e "${BLUE}[*] 설치하시겠습니까? (y/n)${NC}"
    read -r install_choice

    if [[ "$install_choice" =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}[*] 도구 설치 중...${NC}"
        sudo apt update
        sudo apt install -y "${MISSING_TOOLS[@]}"
    else
        echo -e "${YELLOW}[!] 일부 기능이 작동하지 않을 수 있습니다.${NC}"
    fi
else
    echo -e "${GREEN}[+] 모든 필수 도구가 설치되어 있습니다.${NC}"
fi
echo ""

# 3. Python 패키지 설치
echo -e "${BLUE}[*] Python 패키지 확인 중...${NC}"
MISSING_PACKAGES=()

python3 -c "import requests" 2>/dev/null
if [ $? -ne 0 ]; then
    MISSING_PACKAGES+=("requests")
fi

python3 -c "import boto3" 2>/dev/null
if [ $? -ne 0 ]; then
    MISSING_PACKAGES+=("boto3")
fi

python3 -c "import botocore" 2>/dev/null
if [ $? -ne 0 ]; then
    MISSING_PACKAGES+=("botocore")
fi

if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
    echo -e "${YELLOW}[!] 다음 Python 패키지를 설치합니다: ${MISSING_PACKAGES[*]}${NC}"

    # apt로 설치 시도 (Kali/Debian/Ubuntu)
    if command -v apt &> /dev/null; then
        echo -e "${BLUE}[*] apt를 통해 설치 중...${NC}"
        for pkg in "${MISSING_PACKAGES[@]}"; do
            if [ "$pkg" == "boto3" ]; then
                sudo apt install -y python3-boto3 2>/dev/null || pip3 install boto3
            elif [ "$pkg" == "botocore" ]; then
                sudo apt install -y python3-botocore 2>/dev/null || pip3 install botocore
            else
                pip3 install "$pkg"
            fi
        done
    else
        # pip로 설치
        echo -e "${BLUE}[*] pip3를 통해 설치 중...${NC}"
        pip3 install "${MISSING_PACKAGES[@]}"
    fi

    echo -e "${GREEN}[+] Python 패키지 설치 완료${NC}"
else
    echo -e "${GREEN}[+] 모든 Python 패키지가 이미 설치되어 있습니다.${NC}"
fi

# AWS CLI 설치 확인
if ! command -v aws &> /dev/null; then
    echo -e "${YELLOW}[!] AWS CLI가 설치되어 있지 않습니다.${NC}"
    echo -e "${BLUE}[*] AWS CLI를 설치하시겠습니까? (권한 테스트용, 선택사항) (y/n)${NC}"
    read -r aws_choice

    if [[ "$aws_choice" =~ ^[Yy]$ ]]; then
        sudo apt install -y awscli
        echo -e "${GREEN}[+] AWS CLI 설치 완료${NC}"
    fi
else
    echo -e "${GREEN}[+] AWS CLI가 이미 설치되어 있습니다.${NC}"
fi
echo ""

# 4. Tor 설치 확인 (선택사항)
echo -e "${BLUE}[*] Tor 설치 확인 중...${NC}"
if ! command -v tor &> /dev/null; then
    echo -e "${YELLOW}[!] Tor가 설치되어 있지 않습니다.${NC}"
    echo -e "${BLUE}[*] Tor를 설치하시겠습니까? (익명 스캔용, 선택사항) (y/n)${NC}"
    read -r tor_choice

    if [[ "$tor_choice" =~ ^[Yy]$ ]]; then
        sudo apt install -y tor proxychains4
        sudo systemctl enable tor
        sudo systemctl start tor
        echo -e "${GREEN}[+] Tor 설치 완료${NC}"
    else
        echo -e "${YELLOW}[!] Tor 없이 계속 진행합니다.${NC}"
    fi
else
    echo -e "${GREEN}[+] Tor가 이미 설치되어 있습니다.${NC}"

    # Tor 서비스 확인
    if systemctl is-active --quiet tor; then
        echo -e "${GREEN}[+] Tor 서비스가 실행 중입니다.${NC}"
    else
        echo -e "${YELLOW}[!] Tor 서비스를 시작하시겠습니까? (y/n)${NC}"
        read -r start_tor
        if [[ "$start_tor" =~ ^[Yy]$ ]]; then
            sudo systemctl start tor
            echo -e "${GREEN}[+] Tor 서비스 시작됨${NC}"
        fi
    fi
fi
echo ""

# 5. 실행 권한 부여
echo -e "${BLUE}[*] 실행 권한 부여 중...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SCRIPT_DIR/redchain.py"
echo -e "${GREEN}[+] 실행 권한 부여 완료${NC}"
echo ""

# 6. 심볼릭 링크 생성 (선택사항)
echo -e "${BLUE}[*] 전역 명령어로 사용하시겠습니까? (y/n)${NC}"
echo -e "${YELLOW}    (심볼릭 링크를 /usr/local/bin/redchain에 생성)${NC}"
read -r symlink_choice

if [[ "$symlink_choice" =~ ^[Yy]$ ]]; then
    if [ -L /usr/local/bin/redchain ]; then
        sudo rm /usr/local/bin/redchain
    fi
    sudo ln -s "$SCRIPT_DIR/redchain.py" /usr/local/bin/redchain
    echo -e "${GREEN}[+] 심볼릭 링크 생성됨: /usr/local/bin/redchain${NC}"
    echo -e "${GREEN}[+] 이제 어디서든 'redchain' 명령어로 실행 가능합니다.${NC}"
else
    echo -e "${YELLOW}[!] '$SCRIPT_DIR/redchain.py'로 직접 실행하세요.${NC}"
fi
echo ""

# 7. 완료
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    ✅ 설치 완료!                              ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}실행 방법:${NC}"
if [[ "$symlink_choice" =~ ^[Yy]$ ]]; then
    echo -e "  ${BLUE}redchain${NC}"
else
    echo -e "  ${BLUE}$SCRIPT_DIR/redchain.py${NC}"
fi
echo ""
echo -e "${YELLOW}시작하기:${NC}"
echo -e "  1. ${BLUE}set target <IP 또는 도메인>${NC}  - 타겟 설정"
echo -e "  2. ${BLUE}set ssh_user <사용자명>${NC}      - SSH 사용자 설정"
echo -e "  3. ${BLUE}scan${NC}                        - 포트 스캔"
echo -e "  4. ${BLUE}help${NC}                        - 명령어 목록"
echo ""
echo -e "${RED}⚠  법적 고지:${NC}"
echo -e "  이 도구는 교육 및 연구 목적으로만 사용하세요."
echo -e "  승인되지 않은 시스템에 사용 시 법적 책임을 질 수 있습니다."
echo ""
