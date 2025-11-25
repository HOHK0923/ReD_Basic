#!/bin/bash
###############################################################################
# RedChain Persistence Cleanup - 시뮬레이션 종료 후 정리
# 모든 백도어 제거 및 시스템 복구
###############################################################################

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         RedChain Persistence Cleanup - 백도어 제거           ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 권한 확인
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-] 이 스크립트는 root 권한이 필요합니다${NC}"
    exit 1
fi

BACKDOOR_USER="sysupdate"
BACKDOOR_HOME="/var/opt/.sysupdate"
SERVICE_NAME="system-update-check"
WEBSHELL_PATH="/var/www/html/.system/health.php"

echo -e "${YELLOW}[!] 백도어 제거를 시작합니다...${NC}"
echo ""

# 1. Systemd 서비스 제거
echo -e "${BLUE}[1] Systemd 서비스 제거 중...${NC}"
if systemctl list-unit-files | grep -q "$SERVICE_NAME"; then
    systemctl stop "$SERVICE_NAME" 2>/dev/null
    systemctl disable "$SERVICE_NAME" 2>/dev/null
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    echo -e "${GREEN}[+] Systemd 서비스 제거 완료${NC}"
else
    echo -e "${YELLOW}[!] Systemd 서비스 없음 - 건너뜀${NC}"
fi

# 2. Cron 작업 제거
echo ""
echo -e "${BLUE}[2] Cron 작업 제거 중...${NC}"
if id "$BACKDOOR_USER" &>/dev/null; then
    crontab -u "$BACKDOOR_USER" -r 2>/dev/null
    echo -e "${GREEN}[+] Cron 작업 제거 완료${NC}"
else
    echo -e "${YELLOW}[!] 사용자 없음 - Cron 건너뜀${NC}"
fi

# 3. 웹쉘 제거
echo ""
echo -e "${BLUE}[3] 웹쉘 제거 중...${NC}"
if [ -f "$WEBSHELL_PATH" ]; then
    rm -f "$WEBSHELL_PATH"
    rmdir "$(dirname "$WEBSHELL_PATH")" 2>/dev/null
    echo -e "${GREEN}[+] 웹쉘 제거 완료${NC}"
else
    echo -e "${YELLOW}[!] 웹쉘 없음 - 건너뜀${NC}"
fi

# 4. 백도어 사용자 제거
echo ""
echo -e "${BLUE}[4] 백도어 사용자 제거 중...${NC}"
if id "$BACKDOOR_USER" &>/dev/null; then
    # 프로세스 종료
    pkill -u "$BACKDOOR_USER" 2>/dev/null

    # 사용자 삭제
    userdel -r "$BACKDOOR_USER" 2>/dev/null

    # 홈 디렉토리 강제 삭제
    rm -rf "$BACKDOOR_HOME"

    # sudoers 파일 제거
    rm -f "/etc/sudoers.d/sysupdate"

    echo -e "${GREEN}[+] 백도어 사용자 제거 완료${NC}"
else
    echo -e "${YELLOW}[!] 백도어 사용자 없음 - 건너뜀${NC}"
fi

# 5. 로그 파일 제거
echo ""
echo -e "${BLUE}[5] 로그 파일 제거 중...${NC}"
rm -f /var/log/redteam_persistence.log
echo -e "${GREEN}[+] 로그 파일 제거 완료${NC}"

# 완료
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    정리 완료!                                 ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}[+] 모든 백도어가 제거되었습니다${NC}"
echo -e "${BLUE}[*] 시스템이 정리되었습니다${NC}"
echo ""
