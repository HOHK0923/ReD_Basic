#!/bin/bash
# 칼리 리눅스 침투 테스트 도구 설치 스크립트
# Kali Linux Penetration Testing Tools Setup Script

echo "========================================"
echo "침투 테스트 도구 자동 설치"
echo "Automated Penetration Testing Tools Setup"
echo "========================================"
echo ""

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Root 권한 확인
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root${NC}"
   echo "Usage: sudo bash 00_setup_tools.sh"
   exit 1
fi

echo -e "${GREEN}[+] Starting tool installation...${NC}"
echo ""

# 1. 시스템 업데이트
echo -e "${YELLOW}[*] Updating system...${NC}"
apt update -y
apt upgrade -y

# 2. 기본 도구 설치
echo -e "${YELLOW}[*] Installing basic penetration testing tools...${NC}"
apt install -y \
    nmap \
    nikto \
    gobuster \
    dirb \
    dirbuster \
    sqlmap \
    netcat \
    ncat \
    socat \
    netcat-traditional \
    metasploit-framework \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    wget \
    git \
    vim \
    nano \
    tmux \
    screen \
    jq \
    hydra \
    john \
    hashcat \
    aircrack-ng \
    steghide \
    binwalk \
    foremost \
    exiftool \
    masscan \
    whatweb \
    sslscan \
    enum4linux \
    nbtscan \
    onesixtyone \
    smbclient \
    snmp \
    ftp \
    telnet \
    openssh-client \
    proxychains4 \
    tor \
    rlwrap

echo -e "${GREEN}[+] Basic tools installed${NC}"

# 3. Python 라이브러리 설치
echo -e "${YELLOW}[*] Installing Python libraries...${NC}"
pip3 install --upgrade pip
pip3 install \
    requests \
    paramiko \
    pwntools \
    python-nmap \
    scapy \
    impacket \
    beautifulsoup4 \
    lxml \
    pycryptodome \
    colorama \
    tqdm

echo -e "${GREEN}[+] Python libraries installed${NC}"

# 4. 도구 디렉토리 생성
TOOLS_DIR="/opt/pentest-tools"
mkdir -p $TOOLS_DIR
cd $TOOLS_DIR

echo -e "${YELLOW}[*] Downloading additional tools to $TOOLS_DIR...${NC}"

# 5. LinPEAS (Linux Privilege Escalation Awesome Script)
echo -e "${YELLOW}[*] Downloading LinPEAS...${NC}"
wget -q https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O linpeas.sh
chmod +x linpeas.sh
echo -e "${GREEN}[+] LinPEAS downloaded${NC}"

# 6. LinEnum
echo -e "${YELLOW}[*] Downloading LinEnum...${NC}"
wget -q https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O linenum.sh
chmod +x linenum.sh
echo -e "${GREEN}[+] LinEnum downloaded${NC}"

# 7. Linux Exploit Suggester
echo -e "${YELLOW}[*] Downloading Linux Exploit Suggester...${NC}"
wget -q https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
echo -e "${GREEN}[+] Linux Exploit Suggester downloaded${NC}"

# 8. pspy (프로세스 모니터링)
echo -e "${YELLOW}[*] Downloading pspy...${NC}"
wget -q https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 -O pspy64
chmod +x pspy64
wget -q https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32 -O pspy32
chmod +x pspy32
echo -e "${GREEN}[+] pspy downloaded${NC}"

# 9. Chisel (터널링)
echo -e "${YELLOW}[*] Downloading Chisel...${NC}"
CHISEL_VERSION="v1.9.1"
wget -q https://github.com/jpillora/chisel/releases/download/${CHISEL_VERSION}/chisel_${CHISEL_VERSION#v}_linux_amd64.gz -O chisel.gz
gunzip -f chisel.gz
chmod +x chisel
echo -e "${GREEN}[+] Chisel downloaded${NC}"

# 10. SecLists (워드리스트 모음)
echo -e "${YELLOW}[*] Cloning SecLists...${NC}"
if [ ! -d "SecLists" ]; then
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git
    echo -e "${GREEN}[+] SecLists cloned${NC}"
else
    echo -e "${YELLOW}[!] SecLists already exists, skipping${NC}"
fi

# 11. PayloadsAllTheThings
echo -e "${YELLOW}[*] Cloning PayloadsAllTheThings...${NC}"
if [ ! -d "PayloadsAllTheThings" ]; then
    git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git
    echo -e "${GREEN}[+] PayloadsAllTheThings cloned${NC}"
else
    echo -e "${YELLOW}[!] PayloadsAllTheThings already exists, skipping${NC}"
fi

# 12. Impacket (Python 네트워크 프로토콜 도구)
echo -e "${YELLOW}[*] Installing Impacket...${NC}"
if [ ! -d "impacket" ]; then
    git clone https://github.com/fortra/impacket.git
    cd impacket
    pip3 install .
    cd ..
    echo -e "${GREEN}[+] Impacket installed${NC}"
else
    echo -e "${YELLOW}[!] Impacket already exists, skipping${NC}"
fi

# 13. Exploit-DB
echo -e "${YELLOW}[*] Updating Exploit-DB...${NC}"
searchsploit -u
echo -e "${GREEN}[+] Exploit-DB updated${NC}"

# 14. Metasploit 업데이트
echo -e "${YELLOW}[*] Updating Metasploit...${NC}"
msfupdate
echo -e "${GREEN}[+] Metasploit updated${NC}"

# 15. Wordlists 압축 해제
echo -e "${YELLOW}[*] Extracting wordlists...${NC}"
if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null
    echo -e "${GREEN}[+] rockyou.txt extracted${NC}"
fi

# 16. AWS CLI 설치
echo -e "${YELLOW}[*] Installing AWS CLI...${NC}"
if ! command -v aws &> /dev/null; then
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q awscliv2.zip
    ./aws/install
    rm -rf aws awscliv2.zip
    echo -e "${GREEN}[+] AWS CLI installed${NC}"
else
    echo -e "${YELLOW}[!] AWS CLI already installed${NC}"
fi

# 17. Docker 설치 (컨테이너 탈출 테스트용)
echo -e "${YELLOW}[*] Installing Docker...${NC}"
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    systemctl enable docker
    systemctl start docker
    echo -e "${GREEN}[+] Docker installed${NC}"
else
    echo -e "${YELLOW}[!] Docker already installed${NC}"
fi

# 18. Go 설치 (일부 도구 컴파일용)
echo -e "${YELLOW}[*] Installing Go...${NC}"
if ! command -v go &> /dev/null; then
    GO_VERSION="1.21.5"
    wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
    rm go${GO_VERSION}.linux-amd64.tar.gz

    # PATH 설정
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.bashrc
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/kali/.bashrc
    export PATH=$PATH:/usr/local/go/bin

    echo -e "${GREEN}[+] Go installed${NC}"
else
    echo -e "${YELLOW}[!] Go already installed${NC}"
fi

# 19. Nuclei (취약점 스캐너)
echo -e "${YELLOW}[*] Installing Nuclei...${NC}"
if command -v go &> /dev/null; then
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    cp ~/go/bin/nuclei /usr/local/bin/ 2>/dev/null || cp /root/go/bin/nuclei /usr/local/bin/
    echo -e "${GREEN}[+] Nuclei installed${NC}"
fi

# 20. Subfinder (서브도메인 탐색)
echo -e "${YELLOW}[*] Installing Subfinder...${NC}"
if command -v go &> /dev/null; then
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    cp ~/go/bin/subfinder /usr/local/bin/ 2>/dev/null || cp /root/go/bin/subfinder /usr/local/bin/
    echo -e "${GREEN}[+] Subfinder installed${NC}"
fi

# 21. ffuf (Fuzz Faster U Fool)
echo -e "${YELLOW}[*] Installing ffuf...${NC}"
if command -v go &> /dev/null; then
    go install github.com/ffuf/ffuf/v2@latest
    cp ~/go/bin/ffuf /usr/local/bin/ 2>/dev/null || cp /root/go/bin/ffuf /usr/local/bin/
    echo -e "${GREEN}[+] ffuf installed${NC}"
fi

# 22. 심볼릭 링크 생성
echo -e "${YELLOW}[*] Creating symbolic links...${NC}"
ln -sf $TOOLS_DIR/linpeas.sh /usr/local/bin/linpeas
ln -sf $TOOLS_DIR/pspy64 /usr/local/bin/pspy
ln -sf $TOOLS_DIR/chisel /usr/local/bin/chisel

# 23. 권한 설정
echo -e "${YELLOW}[*] Setting permissions...${NC}"
chmod -R 755 $TOOLS_DIR
chown -R root:root $TOOLS_DIR

# 24. 설치 확인
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}설치 완료! (Installation Complete!)${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

echo -e "${YELLOW}[*] Installed tools location: $TOOLS_DIR${NC}"
echo ""

echo -e "${YELLOW}[*] Verifying installations:${NC}"
echo -n "  - nmap: "
command -v nmap &> /dev/null && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAILED${NC}"

echo -n "  - sqlmap: "
command -v sqlmap &> /dev/null && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAILED${NC}"

echo -n "  - gobuster: "
command -v gobuster &> /dev/null && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAILED${NC}"

echo -n "  - metasploit: "
command -v msfconsole &> /dev/null && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAILED${NC}"

echo -n "  - python3: "
command -v python3 &> /dev/null && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAILED${NC}"

echo -n "  - aws-cli: "
command -v aws &> /dev/null && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAILED${NC}"

echo -n "  - docker: "
command -v docker &> /dev/null && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAILED${NC}"

echo -n "  - LinPEAS: "
[ -f "$TOOLS_DIR/linpeas.sh" ] && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAILED${NC}"

echo -n "  - pspy: "
[ -f "$TOOLS_DIR/pspy64" ] && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAILED${NC}"

echo -n "  - chisel: "
[ -f "$TOOLS_DIR/chisel" ] && echo -e "${GREEN}OK${NC}" || echo -e "${RED}FAILED${NC}"

echo ""
echo -e "${GREEN}[+] All tools installed successfully!${NC}"
echo -e "${YELLOW}[*] Tools directory: $TOOLS_DIR${NC}"
echo -e "${YELLOW}[*] You can now run the penetration testing scripts${NC}"
echo ""
echo -e "${YELLOW}Example usage:${NC}"
echo "  python3 10_full_penetration_automation.py -t TARGET_IP -p YOUR_IP"
echo ""
echo -e "${GREEN}Happy Hacking!${NC}"
