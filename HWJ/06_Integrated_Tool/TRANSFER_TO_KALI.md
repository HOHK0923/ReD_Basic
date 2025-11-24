# Kali Linux로 전송하기

## 📦 압축 파일 정보

**파일명**: `redchain_v1.0_20251124.tar.gz`
**위치**: `/Users/hwangjunha/Desktop/Red_basic_local/H/CLEAN_PROJECT/redchain_v1.0_20251124.tar.gz`
**크기**: 61KB

---

## 🚀 Kali Linux로 전송하는 3가지 방법

### 방법 1: SCP로 직접 전송 (추천)

```bash
# Mac에서 실행
cd /Users/hwangjunha/Desktop/Red_basic_local/H/CLEAN_PROJECT
scp redchain_v1.0_20251124.tar.gz kali@<KALI-IP>:~/Downloads/

# 예시
scp redchain_v1.0_20251124.tar.gz kali@192.168.1.100:~/Downloads/
```

**Kali에서 설치:**
```bash
cd ~/Downloads
tar -xzf redchain_v1.0_20251124.tar.gz
cd redchain_v1.0_20251124/redchain
./install.sh
redchain
```

---

### 방법 2: USB 메모리 사용

```bash
# Mac에서 USB 마운트 위치 확인
df -h | grep -i volume

# USB로 복사 (예: /Volumes/USB)
cp redchain_v1.0_20251124.tar.gz /Volumes/USB/

# USB를 Kali에 연결 후
cd /media/usb  # USB 마운트 위치
cp redchain_v1.0_20251124.tar.gz ~/Downloads/
cd ~/Downloads
tar -xzf redchain_v1.0_20251124.tar.gz
cd redchain_v1.0_20251124/redchain
./install.sh
redchain
```

---

### 방법 3: 웹 서버로 전송

**Mac에서 임시 웹 서버 실행:**
```bash
cd /Users/hwangjunha/Desktop/Red_basic_local/H/CLEAN_PROJECT
python3 -m http.server 8000
```

**Kali에서 다운로드:**
```bash
cd ~/Downloads
wget http://<MAC-IP>:8000/redchain_v1.0_20251124.tar.gz
tar -xzf redchain_v1.0_20251124.tar.gz
cd redchain_v1.0_20251124/redchain
./install.sh
redchain
```

---

## 🎯 Kali에서 설치 후 사용

### 1. 설치 (자동)
```bash
cd ~/Downloads/redchain_v1.0_20251124/redchain
./install.sh
# 모든 질문에 'y' 입력
```

### 2. 실행
```bash
redchain
```

### 3. 빠른 시작
```
redchain> set target <타겟 IP>
redchain> set ssh_user <사용자명>
redchain> scan
redchain> enum
redchain> imds
```

---

## 📋 포함된 파일

압축 파일에는 다음이 포함되어 있습니다:

```
redchain/
├── redchain.py                      # 메인 CLI 도구
├── install.sh                       # 자동 설치 스크립트
├── package.sh                       # 재패키징 스크립트
├── README.md                        # 전체 문서
├── QUICKSTART.md                    # 빠른 시작 가이드
├── INSTALL_KALI.md                  # Kali 전용 설치 가이드
├── PROJECT_README.md                # 프로젝트 개요
│
├── 01_AWS_IMDS_Attack/              # AWS 공격 스크립트들
│   ├── 119_setup_aws_vuln.sh
│   ├── 120_aws_imds_exploit.py
│   ├── 121_aws_privilege_escalation.py
│   └── 122_aws_ssm_command.py
│
├── 02_Site_Defacement/              # 웹 변조 스크립트들
│   ├── DEPLOY_HACK.sh
│   ├── SILENT_DOWNLOAD.sh
│   ├── MODERN_DEFACEMENT.sh
│   ├── TOGGLE_SITE.sh
│   └── ...
│
└── 03_Documentation/                # 상세 문서
    └── COMPLETE_ATTACK_ANALYSIS.md
```

---

## ⚡ 문제 해결

### Kali에서 "Permission denied"

```bash
chmod +x redchain.py
chmod +x install.sh
```

### SCP 연결 실패

```bash
# Kali에서 SSH 서비스 확인
sudo systemctl status ssh

# 시작
sudo systemctl start ssh
```

### "redchain: command not found" (설치 후)

```bash
# 직접 실행
./redchain.py

# 또는 재설치
./install.sh
```

---

## 🔥 Kali Linux 전용 기능

### Tor 자동 설정
Kali에는 Tor가 기본 설치되어 있으므로:
```
redchain> set tor on
redchain> scan
```

### Proxychains 통합
```bash
# proxychains 설정 확인
cat /etc/proxychains4.conf

# Tor와 함께 사용
redchain> set tor on
redchain> scan full
```

---

## 📞 지원

문제가 발생하면:
1. `QUICKSTART.md` 확인
2. `README.md` 전체 문서 확인
3. `INSTALL_KALI.md` Kali 전용 가이드 확인

---

**Kali Linux에서 바로 사용 가능합니다!** 🐉
