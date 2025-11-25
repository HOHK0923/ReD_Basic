from flask import Flask, render_template, jsonify
from datetime import datetime, timedelta
import requests
import threading
import time
import re
from bs4 import BeautifulSoup

app = Flask(__name__)

# 모니터링 설정
MONITOR_CONFIG = {
    'target_server': 'http://3.35.218.180',
    'hacker_id': 13,
    'hacker_username': 'hacker',
    'hacker_password': 'hacker123',
    'monitoring_interval': 10,
}

# 실시간 데이터 저장소
dashboard_data = {
    'hacker_current_points': 0,
    'previous_points': 0,
    'victims': [],  # 피해자 목록
    'gift_records': [],
    'total_stolen_all': 0,
    'last_check': None,
    'connection_status': 'disconnected',
    'login_status': False,
    'success_rate': 100
}

# 세션 생성
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
})
session.timeout = 15


def login_to_target_server():
    """타겟 서버에 hacker로 로그인"""
    # 재시도 제한
    if hasattr(login_to_target_server, 'last_attempt'):
        time_since_last = time.time() - login_to_target_server.last_attempt
        if time_since_last < 30:
            return False

    login_to_target_server.last_attempt = time.time()
    print("[LOGIN] hacker 계정으로 로그인 시도...")

    try:
        login_url = f"{MONITOR_CONFIG['target_server']}/login.php"
        response = session.get(login_url, timeout=10)

        if response.status_code != 200:
            dashboard_data['login_status'] = False
            return False

        login_data = {
            'username': MONITOR_CONFIG['hacker_username'],
            'password': MONITOR_CONFIG['hacker_password']
        }

        login_response = session.post(login_url, data=login_data, timeout=10)

        if any(keyword in login_response.text.lower() for keyword in ['logout', 'profile', '포인트']):
            print("[+] ✅ hacker 로그인 성공!")
            dashboard_data['login_status'] = True
            dashboard_data['connection_status'] = 'connected'
            return True
        else:
            dashboard_data['login_status'] = False
            dashboard_data['connection_status'] = 'login_failed'
            return False

    except Exception as e:
        print(f"[-] 로그인 오류: {e}")
        dashboard_data['login_status'] = False
        return False


def get_hacker_profile_data():
    """hacker 프로필에서 포인트와 선물 기록 추출"""
    try:
        if not dashboard_data['login_status']:
            if not login_to_target_server():
                return None, []

        profile_url = f"{MONITOR_CONFIG['target_server']}/profile.php?id={MONITOR_CONFIG['hacker_id']}"
        response = session.get(profile_url, timeout=15)

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            current_points = extract_current_points(soup)
            gift_records = extract_gift_records(soup)
            return current_points, gift_records
        else:
            dashboard_data['login_status'] = False
            return None, []

    except Exception as e:
        print(f"[ERROR] 프로필 데이터 추출 오류: {e}")
        return None, []


def extract_current_points(soup):
    """HTML에서 현재 포인트 추출"""
    try:
        points_badge = soup.find('div', class_='points-badge')
        if points_badge:
            points_text = points_badge.get_text()
            points_match = re.search(r'포인트:\s*(\d+)P?', points_text, re.IGNORECASE)
            if points_match:
                points = int(points_match.group(1))
                print(f"[POINTS] hacker 현재 포인트: {points}P")
                return points
        return None
    except Exception as e:
        print(f"[ERROR] 포인트 추출 오류: {e}")
        return None


def extract_gift_records(soup):
    """HTML에서 선물 기록 추출"""
    gift_records = []
    try:
        gift_divs = soup.find_all('div', style=re.compile(r'padding.*15px'))

        for div in gift_divs:
            div_html = str(div)
            div_text = div.get_text()

            sender_match = re.search(r'<strong>([^<]+)</strong>', div_html)
            if not sender_match or sender_match.group(1) == 'hacker':
                continue

            sender = sender_match.group(1)

            gift_type_match = re.search(r'<span[^>]*color:\s*#667eea[^>]*>([^<]+)</span>', div_html)
            gift_type = gift_type_match.group(1) if gift_type_match else 'unknown'

            points_match = re.search(r'보냈습니다\s*\((\d+)[pP]\)', div_text, re.IGNORECASE)
            points = int(points_match.group(1)) if points_match else 0

            message_match = re.search(r'<small[^>]*color:\s*#8e8e8e[^>]*>([^<]+)</small>', div_html)
            message = message_match.group(1) if message_match else ''

            time_match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})', div_text)
            timestamp = time_match.group(1) if time_match else datetime.now().strftime('%Y-%m-%d %H:%M')

            if sender and points > 0:
                gift_record = {
                    'sender': sender,
                    'gift_type': gift_type,
                    'points': points,
                    'message': message,
                    'timestamp': timestamp,
                    'detected_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'unique_id': f"{sender}_{timestamp}_{points}"
                }
                gift_records.append(gift_record)

        return gift_records
    except Exception as e:
        print(f"[ERROR] 선물 기록 추출 오류: {e}")
        return []


def monitor_hacker_account():
    """백그라운드에서 hacker 계정 모니터링"""
    print("🔄 [MONITOR] hacker 계정 모니터링 시작...")

    while True:
        try:
            current_points, current_gifts = get_hacker_profile_data()

            if current_points is not None:
                dashboard_data['hacker_current_points'] = current_points
                dashboard_data['previous_points'] = current_points

                # 새로운 선물 처리
                if current_gifts:
                    existing_gift_ids = set(
                        gift.get('unique_id', '') for gift in dashboard_data.get('gift_records', []))
                    new_gifts = [gift for gift in current_gifts if gift.get('unique_id', '') not in existing_gift_ids]

                    for gift in new_gifts:
                        victim_record = {
                            'victim_name': gift['sender'],
                            'points_stolen': gift['points'],
                            'gift_type': gift['gift_type'],
                            'message': gift['message'],
                            'timestamp': gift['timestamp'],
                            'detected_at': gift['detected_at'],
                            'is_new': True
                        }
                        dashboard_data['victims'].append(victim_record)

                    dashboard_data['gift_records'] = current_gifts

            dashboard_data['last_check'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        except Exception as e:
            print(f"[MONITOR ERROR] {e}")

        time.sleep(MONITOR_CONFIG['monitoring_interval'])


# Flask 라우트들
@app.route('/')
def dashboard():
    """메인 대시보드"""
    return render_template('dashboard.html')


@app.route('/api/hacker/stats')
def get_hacker_stats():
    """hacker 통계 데이터 (대시보드용)"""
    today = datetime.now().date()

    # 오늘 피해자들
    today_victims = [v for v in dashboard_data['victims']
                     if datetime.strptime(v['detected_at'], '%Y-%m-%d %H:%M:%S').date() == today]

    # 24시간 내 데이터
    yesterday = datetime.now() - timedelta(hours=24)
    last_24h_victims = [v for v in dashboard_data['victims']
                        if datetime.strptime(v['detected_at'], '%Y-%m-%d %H:%M:%S') >= yesterday]

    # 실시간으로 누적 탈취 포인트 계산
    total_stolen_points = sum(v['points_stolen'] for v in dashboard_data['victims'])

    # 최대 단일 탈취
    max_single_steal = max([v['points_stolen'] for v in dashboard_data['victims']] + [0])

    # 평균 탈취량
    avg_steal = total_stolen_points // len(dashboard_data['victims']) if dashboard_data['victims'] else 0

    # dashboard_data 업데이트
    dashboard_data['total_stolen_all'] = total_stolen_points

    print(f"[DEBUG] 실시간 계산:")
    print(f"  - 총 피해자: {len(dashboard_data['victims'])}명")
    print(f"  - 누적 포인트: {total_stolen_points}P")
    print(f"  - 최대 단일: {max_single_steal}P")
    print(f"  - 평균: {avg_steal}P")

    return jsonify({
        'current_points': dashboard_data['hacker_current_points'],
        'total_stolen': total_stolen_points,  # 실시간 계산값 사용
        'today_stolen': sum(v['points_stolen'] for v in today_victims),
        'last_24h': sum(v['points_stolen'] for v in last_24h_victims),
        'total_victims': len(dashboard_data['victims']),
        'max_single_steal': max_single_steal,
        'avg_steal': avg_steal,
        'success_rate': dashboard_data['success_rate'],
        'active_targets': len(last_24h_victims),
        'last_update': dashboard_data['last_check'],
        'connection_status': dashboard_data['connection_status'],
        'login_status': dashboard_data['login_status']
    })

@app.route('/api/hacker/victims')
def get_hacker_victims():
    """피해자 목록"""
    victims = sorted(dashboard_data['victims'], key=lambda x: x['detected_at'], reverse=True)

    # 최신순으로 정렬
    victims = sorted(dashboard_data['victims'],
                     key=lambda x: x['detected_at'], reverse=True)

    # 사용자명 → ID 매핑
    def get_user_id_by_username(username):
        user_id_mapping = {
            'admin': 1,
            'bob': 11,
            'alice': 12,
            'hacker': 13
        }
        return user_id_mapping.get(username.lower(), 0)

    # 대시보드 형식에 맞게 변환
    victim_list = []
    for victim in victims[:20]:  # 최근 20명
        victim_data = {
            'username': victim['victim_name'],
            'user_id': get_user_id_by_username(victim['victim_name']),
            'points': victim['points_stolen'],
            'gift_type': victim['gift_type'],
            'message': victim['message'],
            'timestamp': victim['timestamp'],
            'ip': 'monitored_user',
            'user_agent': 'detected_from_profile',
            'is_new': victim.get('is_new', False)
        }
        victim_list.append(victim_data)

    return jsonify(victim_list)

@app.route('/api/test-attack', methods=['POST'])
def test_attack():
    """테스트 피해자 추가"""
    import random

    test_names = ['alice', 'bob', 'charlie', 'testuser']
    gift_types = ['coffee', 'flower', 'cake', 'diamond']
    points_options = [10, 50, 100, 500]

    victim_record = {
        'victim_name': random.choice(test_names),
        'points_stolen': random.choice(points_options),
        'gift_type': random.choice(gift_types),
        'message': 'TEST 피해자',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M'),
        'detected_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'is_new': True
    }

    dashboard_data['victims'].append(victim_record)
    dashboard_data['total_stolen_all'] += victim_record['points_stolen']  # 이 줄이 중요!

    print(f"🧪 [TEST] 테스트 피해자 추가: {victim_record['victim_name']} → {victim_record['points_stolen']}P")

    return jsonify({
        'status': 'success',
        'message': f"테스트 피해자 추가: {victim_record['victim_name']} ({victim_record['points_stolen']}P)"
    })


@app.route('/api/clear', methods=['DELETE'])
def clear_data():
    """데이터 초기화"""
    dashboard_data['victims'] = []
    return jsonify({'status': 'success', 'message': '피해자 데이터 초기화 완료'})


if __name__ == '__main__':
    print("🏴‍☠️ HACKER 모니터링 대시보드")
    print(f"🌐 대시보드: http://localhost:8080")

    # 백그라운드 모니터링 시작
    monitor_thread = threading.Thread(target=monitor_hacker_account, daemon=True)
    monitor_thread.start()

    # Flask 서버 실행
    app.run(host='0.0.0.0', port=8080, debug=True, threaded=True)