#!/usr/bin/env python3
"""
보안 알림 시스템 테스트 도구
Security Alert System Testing Tool

이 도구는 구축된 보안 알림 시스템이 정상적으로 작동하는지 테스트합니다.
각 탐지 규칙을 의도적으로 트리거하여 알림이 발생하는지 확인합니다.

사용법:
    python3 security_alert_tester.py -t TARGET_URL -a ALL
    python3 security_alert_tester.py -t http://13.125.80.75 -a webshell
"""

import argparse
import requests
import time
import random
import string
from datetime import datetime
from urllib.parse import urljoin

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class SecurityAlertTester:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.test_results = []

    def log(self, message, level='INFO'):
        timestamp = datetime.now().strftime('%H:%M:%S')
        if level == 'SUCCESS':
            print(f"{Colors.OKGREEN}[+][{timestamp}]{Colors.ENDC} {message}")
        elif level == 'ERROR':
            print(f"{Colors.FAIL}[-][{timestamp}]{Colors.ENDC} {message}")
        elif level == 'WARNING':
            print(f"{Colors.WARNING}[!][{timestamp}]{Colors.ENDC} {message}")
        elif level == 'TEST':
            print(f"{Colors.OKCYAN}[TEST][{timestamp}]{Colors.ENDC} {message}")
        else:
            print(f"{Colors.OKBLUE}[*][{timestamp}]{Colors.ENDC} {message}")

    def wait_between_tests(self, seconds=2):
        """테스트 간 대기"""
        time.sleep(seconds)

    def login(self, username='alice', password='alice2024'):
        """로그인 수행"""
        try:
            login_url = urljoin(self.target_url, '/login.php')
            data = {
                'username': username,
                'password': password
            }
            self.log(f"로그인 시도: {username} / {password}")
            response = self.session.post(login_url, data=data, timeout=10, allow_redirects=True)

            if 'logout' in response.text.lower() or 'dashboard' in response.url.lower() or response.status_code == 200:
                self.log(f"로그인 성공: {username}", 'SUCCESS')
                return True
            else:
                self.log(f"로그인 실패: {username}", 'ERROR')
                return False
        except Exception as e:
            self.log(f"로그인 오류: {e}", 'ERROR')
            return False

    # ========== 테스트 1: Webshell 이후 URI 다변화 의심 탐지 ==========
    def test_webshell_uri_diversity(self):
        """
        규칙: 웹쉘(file.php) 호출 이후 URI 다양성 증가
        - 단일 IP에서 5분 내 3개 이상의 고유 URI 접근
        """
        self.log("=" * 60, 'TEST')
        self.log("TEST 1: Webshell 이후 URI 다변화 의심 탐지", 'TEST')
        self.log("=" * 60, 'TEST')

        # 1단계: 웹쉘 업로드/접근 시뮬레이션
        webshell_paths = [
            '/uploads/shell.php',
            '/uploads/test.php',
            '/public/file.php',
            '/temp/backdoor.php'
        ]

        self.log("1단계: 웹쉘 파일 접근 시뮬레이션...")
        for path in webshell_paths:
            try:
                url = urljoin(self.target_url, path)
                self.log(f"접근: {url}")
                response = self.session.get(url, timeout=5)
                self.wait_between_tests(0.5)
            except Exception as e:
                pass

        # 2단계: 다양한 URI 접근 (정찰 활동 시뮬레이션)
        self.log("2단계: 다양한 URI 접근 (URI 다변화 트리거)...")
        diverse_uris = [
            '/admin/config.php',
            '/api/users',
            '/backup/database.sql',
            '/includes/settings.php',
            '/.env',
            '/phpinfo.php',
            '/test.php',
            '/info.php'
        ]

        for uri in diverse_uris:
            try:
                url = urljoin(self.target_url, uri)
                self.log(f"접근: {url}")
                response = self.session.get(url, timeout=5)
                self.wait_between_tests(0.3)
            except Exception as e:
                pass

        self.log("웹쉘 이후 URI 다변화 테스트 완료!", 'SUCCESS')
        self.log("예상: '222.105.110.121'에서 URI 다변화 알림 발생", 'WARNING')
        self.test_results.append({
            'test': 'webshell_uri_diversity',
            'status': 'executed',
            'expected_alert': 'Abnormal Increase in URI Diversity'
        })

    # ========== 테스트 2: HTTP 클라이언트-요청-의심 ==========
    def test_http_client_request_suspicious(self):
        """
        규칙: 의심스러운 HTTP 클라이언트 요청
        - curl, wget, python-requests 등 비정상 User-Agent
        """
        self.log("=" * 60, 'TEST')
        self.log("TEST 2: HTTP 클라이언트 요청 의심 탐지", 'TEST')
        self.log("=" * 60, 'TEST')

        suspicious_user_agents = [
            'curl/7.68.0',
            'Wget/1.20.3',
            'python-requests/2.28.0',
            'Python-urllib/3.9',
            'Go-http-client/1.1',
            'Ruby',
            'Nikto/2.1.6',
            'sqlmap/1.6',
            'Nmap Scripting Engine',
            'Metasploit'
        ]

        self.log("의심스러운 User-Agent로 요청 전송 중...")

        for user_agent in suspicious_user_agents:
            try:
                headers = {'User-Agent': user_agent}
                self.log(f"User-Agent: {user_agent}")
                response = self.session.get(self.target_url, headers=headers, timeout=5)
                self.wait_between_tests(0.5)
            except Exception as e:
                pass

        self.log("의심스러운 HTTP 클라이언트 요청 테스트 완료!", 'SUCCESS')
        self.log("예상: '의심스러운 HTTP 클라이언트 요청' 알림 발생", 'WARNING')
        self.test_results.append({
            'test': 'http_client_suspicious',
            'status': 'executed',
            'expected_alert': 'Suspicious HTTP Client Request'
        })

    # ========== 테스트 3: 비정상적인 URI 다양성 증가 ==========
    def test_abnormal_uri_diversity(self):
        """
        규칙: 단일 IP에서 짧은 시간 내 많은 고유 URI 접근
        - 5분 내 10개 이상 고유 URI
        """
        self.log("=" * 60, 'TEST')
        self.log("TEST 3: 비정상적인 URI 다양성 증가 탐지", 'TEST')
        self.log("=" * 60, 'TEST')

        self.log("다양한 URI 대량 접근 중 (디렉토리 스캔 시뮬레이션)...")

        # 다양한 URI 생성
        common_paths = [
            '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
            '/backup', '/backups', '/old', '/test', '/temp',
            '/config', '/conf', '/cfg', '/settings',
            '/api', '/rest', '/v1', '/v2',
            '/upload', '/uploads', '/files', '/documents',
            '/private', '/secret', '/hidden', '/confidential',
            '/db', '/database', '/sql', '/dump',
            '/.git', '/.svn', '/.env', '/.htaccess'
        ]

        extensions = ['.php', '.bak', '.old', '.txt', '.sql', '']

        for path in common_paths:
            for ext in random.sample(extensions, 2):
                try:
                    uri = f"{path}{ext}"
                    url = urljoin(self.target_url, uri)
                    self.log(f"접근: {url}")
                    response = self.session.get(url, timeout=5)
                    self.wait_between_tests(0.2)
                except Exception as e:
                    pass

        self.log("비정상적인 URI 다양성 증가 테스트 완료!", 'SUCCESS')
        self.log("예상: 'URI 다양성 비정상 증가' 알림 발생", 'WARNING')
        self.test_results.append({
            'test': 'abnormal_uri_diversity',
            'status': 'executed',
            'expected_alert': 'Abnormal Increase in URI Diversity'
        })

    # ========== 테스트 4: 웹쉘 업로드 실행 탐지 ==========
    def test_webshell_upload_execution(self):
        """
        규칙: 웹쉘 파일 업로드 후 실행
        - .php, .jsp 등 실행 가능 파일 업로드
        """
        self.log("=" * 60, 'TEST')
        self.log("TEST 4: 웹쉘 업로드 및 실행 탐지", 'TEST')
        self.log("=" * 60, 'TEST')

        # 로그인 필요
        if not self.login():
            self.log("로그인 실패로 웹쉘 업로드 테스트 건너뛰기", 'WARNING')
            return

        # 웹쉘 파일 업로드 시뮬레이션
        webshell_content = "<?php system($_GET['cmd']); ?>"
        webshell_filenames = [
            'shell.php',
            'backdoor.php',
            'test.php5',
            'cmd.phtml',
            'shell.php.jpg'  # 이중 확장자
        ]

        self.log("웹쉘 파일 업로드 시뮬레이션...")

        upload_endpoint = urljoin(self.target_url, '/upload.php')

        for filename in webshell_filenames:
            try:
                files = {
                    'file': (filename, webshell_content, 'application/x-php')
                }
                self.log(f"업로드 시도: {filename}")
                response = self.session.post(upload_endpoint, files=files, timeout=5)
                self.wait_between_tests(0.5)
            except Exception as e:
                pass

        # 업로드된 파일 실행 시뮬레이션
        self.log("업로드된 웹쉘 실행 시도...")

        for filename in webshell_filenames:
            try:
                webshell_url = urljoin(self.target_url, f'/uploads/{filename}')
                params = {'cmd': 'whoami'}
                self.log(f"실행 시도: {webshell_url}?cmd=whoami")
                response = self.session.get(webshell_url, params=params, timeout=5)
                self.wait_between_tests(0.5)
            except Exception as e:
                pass

        self.log("웹쉘 업로드 및 실행 테스트 완료!", 'SUCCESS')
        self.log("예상: '웹쉘 업로드 및 실행 탐지' 알림 발생", 'WARNING')
        self.test_results.append({
            'test': 'webshell_upload_execution',
            'status': 'executed',
            'expected_alert': 'Webshell Upload and Execution Detected'
        })

    # ========== 테스트 5: SQL Injection 시도 탐지 ==========
    def test_sql_injection_attempts(self):
        """
        규칙: SQL Injection 공격 페이로드 탐지
        """
        self.log("=" * 60, 'TEST')
        self.log("TEST 5: SQL Injection 시도 탐지", 'TEST')
        self.log("=" * 60, 'TEST')

        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1-- -",
            "admin' OR '1'='1",
            "' UNION SELECT NULL-- -",
            "' AND SLEEP(5)-- -",
            "1' AND '1'='1",
            "' OR 'a'='a",
            "admin'-- -",
            "' UNION SELECT version()-- -"
        ]

        test_endpoints = [
            '/login.php',
            '/page.php?id=1',
            '/search.php?q=test',
            '/api/users?id=1'
        ]

        self.log("SQL Injection 페이로드 전송 중...")

        for endpoint in test_endpoints:
            for payload in sql_payloads:
                try:
                    url = urljoin(self.target_url, endpoint)
                    if '?' in endpoint:
                        url = f"{url}&sqli={payload}"
                    else:
                        url = f"{url}?param={payload}"

                    self.log(f"전송: {payload[:30]}...")
                    response = self.session.get(url, timeout=5)
                    self.wait_between_tests(0.3)
                except Exception as e:
                    pass

        self.log("SQL Injection 시도 테스트 완료!", 'SUCCESS')
        self.log("예상: 'SQL Injection 시도' 알림 발생", 'WARNING')
        self.test_results.append({
            'test': 'sql_injection',
            'status': 'executed',
            'expected_alert': 'SQL Injection Attempt Detected'
        })

    # ========== 테스트 6: Path Traversal 시도 탐지 ==========
    def test_path_traversal_attempts(self):
        """
        규칙: Path Traversal 공격 탐지
        """
        self.log("=" * 60, 'TEST')
        self.log("TEST 6: Path Traversal 시도 탐지", 'TEST')
        self.log("=" * 60, 'TEST')

        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '....//....//etc/passwd',
            '..%2f..%2f..%2fetc%2fpasswd',
            '..%252f..%252fetc%252fpasswd',
            '/var/www/../../etc/passwd',
            'file:///etc/passwd'
        ]

        test_endpoints = [
            '/download.php?file=',
            '/view.php?page=',
            '/include.php?path='
        ]

        self.log("Path Traversal 페이로드 전송 중...")

        for endpoint in test_endpoints:
            for payload in traversal_payloads:
                try:
                    url = urljoin(self.target_url, f"{endpoint}{payload}")
                    self.log(f"전송: {payload[:40]}...")
                    response = self.session.get(url, timeout=5)
                    self.wait_between_tests(0.3)
                except Exception as e:
                    pass

        self.log("Path Traversal 시도 테스트 완료!", 'SUCCESS')
        self.log("예상: 'Path Traversal 시도' 알림 발생", 'WARNING')
        self.test_results.append({
            'test': 'path_traversal',
            'status': 'executed',
            'expected_alert': 'Path Traversal Attempt Detected'
        })

    # ========== 테스트 7: 브루트포스 공격 탐지 ==========
    def test_brute_force_attack(self):
        """
        규칙: 단일 IP에서 다수의 로그인 시도
        """
        self.log("=" * 60, 'TEST')
        self.log("TEST 7: 브루트포스 공격 탐지", 'TEST')
        self.log("=" * 60, 'TEST')

        common_passwords = [
            'admin', 'password', '123456', 'admin123',
            'root', 'password123', 'qwerty', 'letmein',
            '12345678', 'welcome', 'monkey', '1234'
        ]

        login_endpoint = urljoin(self.target_url, '/login.php')

        self.log("브루트포스 공격 시뮬레이션 (다수의 로그인 시도)...")

        for password in common_passwords:
            try:
                data = {
                    'username': 'admin',
                    'password': password
                }
                self.log(f"로그인 시도: admin / {password}")
                response = self.session.post(login_endpoint, data=data, timeout=5)
                self.wait_between_tests(0.5)
            except Exception as e:
                pass

        self.log("브루트포스 공격 테스트 완료!", 'SUCCESS')
        self.log("예상: '브루트포스 공격 탐지' 알림 발생", 'WARNING')
        self.test_results.append({
            'test': 'brute_force',
            'status': 'executed',
            'expected_alert': 'Brute Force Attack Detected'
        })

    # ========== 테스트 8: XSS 시도 탐지 ==========
    def test_xss_attempts(self):
        """
        규칙: XSS 공격 페이로드 탐지
        """
        self.log("=" * 60, 'TEST')
        self.log("TEST 8: XSS 시도 탐지", 'TEST')
        self.log("=" * 60, 'TEST')

        # 로그인 필요
        if not self.login():
            self.log("로그인 실패, GET 기반 XSS만 테스트", 'WARNING')

        xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            'javascript:alert(1)',
            '<iframe src=javascript:alert(1)>',
            '<body onload=alert(1)>',
            '<script>document.cookie</script>'
        ]

        # new_post.php에 XSS 페이로드 게시 (로그인 필요)
        self.log("new_post.php에 XSS 페이로드 게시 시도...")
        new_post_url = urljoin(self.target_url, '/new_post.php')
        for payload in xss_payloads[:3]:  # 처음 3개만
            try:
                data = {'content': payload}
                self.log(f"게시물 작성: {payload[:40]}...")
                response = self.session.post(new_post_url, data=data, timeout=5)
                self.wait_between_tests(0.5)
            except Exception as e:
                pass

        # GET 기반 XSS 테스트
        test_endpoints = [
            '/search.php?q=',
            '/comment.php?text=',
            '/profile.php?name='
        ]

        self.log("GET 파라미터 XSS 페이로드 전송 중...")

        for endpoint in test_endpoints:
            for payload in xss_payloads:
                try:
                    url = urljoin(self.target_url, f"{endpoint}{payload}")
                    self.log(f"전송: {payload[:40]}...")
                    response = self.session.get(url, timeout=5)
                    self.wait_between_tests(0.3)
                except Exception as e:
                    pass

        self.log("XSS 시도 테스트 완료!", 'SUCCESS')
        self.log("예상: 'XSS 시도' 알림 발생", 'WARNING')
        self.test_results.append({
            'test': 'xss',
            'status': 'executed',
            'expected_alert': 'XSS Attempt Detected'
        })

    # ========== 테스트 9: 대량 404 에러 (스캔 탐지) ==========
    def test_mass_404_scanning(self):
        """
        규칙: 단일 IP에서 짧은 시간 내 다수의 404 에러
        """
        self.log("=" * 60, 'TEST')
        self.log("TEST 9: 대량 404 에러 (스캔 활동) 탐지", 'TEST')
        self.log("=" * 60, 'TEST')

        random_paths = [
            ''.join(random.choices(string.ascii_lowercase, k=8))
            for _ in range(20)
        ]

        self.log("존재하지 않는 경로 대량 접근 (스캔 시뮬레이션)...")

        for path in random_paths:
            try:
                url = urljoin(self.target_url, f'/{path}.php')
                self.log(f"접근: {url}")
                response = self.session.get(url, timeout=5)
                self.wait_between_tests(0.2)
            except Exception as e:
                pass

        self.log("대량 404 에러 테스트 완료!", 'SUCCESS')
        self.log("예상: '스캔 활동 탐지 (대량 404)' 알림 발생", 'WARNING')
        self.test_results.append({
            'test': 'mass_404',
            'status': 'executed',
            'expected_alert': 'Scanning Activity Detected (Mass 404 Errors)'
        })

    # ========== 테스트 10: SSRF 시도 탐지 ==========
    def test_ssrf_attempts(self):
        """
        규칙: SSRF 공격 페이로드 탐지
        """
        self.log("=" * 60, 'TEST')
        self.log("TEST 10: SSRF 시도 탐지", 'TEST')
        self.log("=" * 60, 'TEST')

        ssrf_payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost',
            'http://127.0.0.1',
            'http://0.0.0.0',
            'http://[::1]',
            'http://metadata.google.internal',
            'file:///etc/passwd',
            'dict://localhost:11211/stats'
        ]

        test_endpoints = [
            '/api/health.php?url=',
            '/fetch.php?url=',
            '/proxy.php?target='
        ]

        self.log("SSRF 페이로드 전송 중...")

        for endpoint in test_endpoints:
            for payload in ssrf_payloads:
                try:
                    url = urljoin(self.target_url, f"{endpoint}{payload}")
                    self.log(f"전송: {payload[:50]}...")
                    response = self.session.get(url, timeout=5)
                    self.wait_between_tests(0.3)
                except Exception as e:
                    pass

        self.log("SSRF 시도 테스트 완료!", 'SUCCESS')
        self.log("예상: 'SSRF 시도' 알림 발생", 'WARNING')
        self.test_results.append({
            'test': 'ssrf',
            'status': 'executed',
            'expected_alert': 'SSRF Attempt Detected'
        })

    # ========== 모든 테스트 실행 ==========
    def run_all_tests(self):
        """모든 보안 알림 테스트 실행"""
        self.log("\n" + "=" * 60)
        self.log(f"{Colors.HEADER}보안 알림 시스템 전체 테스트 시작{Colors.ENDC}")
        self.log(f"대상: {self.target_url}")
        self.log("=" * 60 + "\n")

        tests = [
            self.test_webshell_uri_diversity,
            self.test_http_client_request_suspicious,
            self.test_abnormal_uri_diversity,
            self.test_webshell_upload_execution,
            self.test_sql_injection_attempts,
            self.test_path_traversal_attempts,
            self.test_brute_force_attack,
            self.test_xss_attempts,
            self.test_mass_404_scanning,
            self.test_ssrf_attempts
        ]

        for i, test in enumerate(tests, 1):
            self.log(f"\n진행: {i}/{len(tests)} 테스트", 'INFO')
            test()
            self.log(f"대기 중... (다음 테스트까지 3초)", 'INFO')
            time.sleep(3)

        self.print_summary()

    def run_specific_test(self, test_name):
        """특정 테스트만 실행"""
        tests = {
            'webshell': self.test_webshell_uri_diversity,
            'http_client': self.test_http_client_request_suspicious,
            'uri_diversity': self.test_abnormal_uri_diversity,
            'upload': self.test_webshell_upload_execution,
            'sqli': self.test_sql_injection_attempts,
            'path_traversal': self.test_path_traversal_attempts,
            'brute_force': self.test_brute_force_attack,
            'xss': self.test_xss_attempts,
            'scan': self.test_mass_404_scanning,
            'ssrf': self.test_ssrf_attempts
        }

        if test_name.lower() in tests:
            self.log(f"\n{Colors.HEADER}특정 테스트 실행: {test_name}{Colors.ENDC}")
            tests[test_name.lower()]()
            self.print_summary()
        else:
            self.log(f"알 수 없는 테스트: {test_name}", 'ERROR')
            self.log(f"사용 가능한 테스트: {', '.join(tests.keys())}", 'INFO')

    def print_summary(self):
        """테스트 결과 요약 출력"""
        self.log("\n" + "=" * 60)
        self.log(f"{Colors.HEADER}테스트 완료 요약{Colors.ENDC}")
        self.log("=" * 60)

        self.log(f"\n총 실행된 테스트: {len(self.test_results)}개\n")

        for i, result in enumerate(self.test_results, 1):
            self.log(f"{i}. {result['test']}")
            self.log(f"   상태: {result['status']}")
            self.log(f"   예상 알림: {result['expected_alert']}\n")

        self.log("=" * 60)
        self.log(f"{Colors.WARNING}⚠️  보안 알림 시스템을 확인하여 알림이 발생했는지 검증하세요!{Colors.ENDC}")
        self.log("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description='보안 알림 시스템 테스트 도구',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  # 모든 테스트 실행
  %(prog)s -t http://13.125.80.75 -a ALL

  # 특정 테스트만 실행
  %(prog)s -t http://13.125.80.75 -a webshell
  %(prog)s -t http://13.125.80.75 -a sqli
  %(prog)s -t http://13.125.80.75 -a xss

사용 가능한 테스트:
  webshell      - 웹쉘 이후 URI 다변화
  http_client   - 의심스러운 HTTP 클라이언트
  uri_diversity - 비정상적 URI 다양성
  upload        - 웹쉘 업로드 및 실행
  sqli          - SQL Injection 시도
  path_traversal- Path Traversal 시도
  brute_force   - 브루트포스 공격
  xss           - XSS 시도
  scan          - 스캔 활동 (404 대량)
  ssrf          - SSRF 시도
  ALL           - 모든 테스트 실행
        """
    )

    parser.add_argument('-t', '--target', required=True, help='대상 URL (예: http://13.125.80.75)')
    parser.add_argument('-a', '--attack', required=True, help='공격 유형 (ALL 또는 특정 테스트명)')

    args = parser.parse_args()

    tester = SecurityAlertTester(args.target)

    if args.attack.upper() == 'ALL':
        tester.run_all_tests()
    else:
        tester.run_specific_test(args.attack)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}[!] 사용자에 의해 중단됨{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.FAIL}[-] 에러 발생: {e}{Colors.ENDC}")
