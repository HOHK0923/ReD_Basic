# ReD_Basic

웹 보안 취약점 분석 및 침투 테스트 자동화 도구

## About

OWASP Top 10 취약점을 실습하고 분석하기 위한 프로젝트입니다. 취약한 SNS 웹앱을 만들고, 여기에 대한 공격/방어 자동화 도구를 개발했습니다.

특히 AWS IMDS를 통한 클라우드 환경 공격과 ModSecurity WAF 우회에 집중했습니다.

## What we found

- ModSecurity는 알려진 페이로드 대부분을 차단함 (450번 시도 중 247번 차단)
- 자동화 도구만으로는 실무 환경 해킹이 거의 불가능
- 느린 요청 + 우회 패턴 조합으로 일부 WAF 우회 가능
- SSRF 취약점 하나로 AWS 전체 인프라 장악 가능

## Structure

```
ReD_Basic/
├── HWJ/                    # AWS cloud security & automation
│   ├── 01_AWS_IMDS_Attack/
│   ├── 05_Defense_Bypass/
│   ├── 06_Integrated_Tool/
│   │   ├── redchain.py     # main CLI tool
│   │   └── auto_redteam_blueteam_bypass.py
│   └── security_alert_tester.py
│
├── HYE/                    # CSRF automation
│   └── 1124_CSRF_*.py
│
├── YOUNG/                  # XSS & phishing
│   ├── xss_tool3_edit.py
│   └── bf2025.php
│
└── vulnerable-sns 3/       # vulnerable web app
    └── *.php
```

## Team

**HWJ** - AWS security & red team automation
- Built AWS IMDS exploit automation
- Tested 450+ attacks against ModSecurity WAF
- Made WAF bypass tool with slow requests
- [Details](./HWJ/README.md)

**HYE** - CSRF automation
- Automated CSRF detection and exploitation
- Dashboard & post manipulation attacks

**YOUNG** - XSS & phishing
- XSS automation tool v3
- Black Friday phishing page

## Key Tools

**redchain.py** - Main CLI for penetration testing
```bash
./redchain.py
set target http://target.com
auto bypass    # WAF bypass automation
auto redteam   # full automation
```

**auto_redteam_blueteam_bypass.py** - Bypasses Fail2Ban + ModSecurity
- Slow requests (3s delay between attacks)
- User-Agent rotation
- Pattern obfuscation

**security_alert_tester.py** - Tests intrusion detection
- Simulates webshell upload attempts
- URI diversity detection
- XSS/SQLi patterns

## Results

### Attack Statistics

| Attack Type | Attempts | Success | Rate |
|------------|----------|---------|------|
| SQL Injection | 200+ | 0 | 0% (WAF blocked) |
| SSRF (normal) | 50+ | 0 | 0% |
| SSRF (bypass) | 20+ | 8 | 40% |
| File Upload | 30+ | 0 | 0% |
| CSRF | 20+ | 15 | 75% |
| XSS | 100+ | 40 | 40% |

### Defense Analysis

ModSecurity blocked 247/247 known payloads. But we found:
- Slow requests can bypass rate limiting
- Custom patterns evade signature detection
- CSRF tokens not implemented (easy target)
- Human factor still the weakest link

## Setup

```bash
git clone https://github.com/HOHK0923/ReD_Basic.git
cd ReD_Basic
pip install requests boto3 paramiko colorama
```

## Usage

```bash
# Main tool
cd HWJ/06_Integrated_Tool
./redchain.py
set target http://target.com
auto bypass

# CSRF test
python3 HYE/1124_CSRF_Auto.py

# XSS test
python3 YOUNG/xss_tool3_edit.py

# Alert testing
python3 HWJ/security_alert_tester.py
```

## Documentation

- [HWJ/README.md](./HWJ/README.md) - Detailed AWS security research
- [AUTOMATED_TOOL_FAILURE_REPORT.md](./HWJ/PORTFOLIO_DOCUMENTS/AUTOMATED_TOOL_FAILURE_REPORT.md) - Why automation failed
- [Manual Penetration Guide](./HWJ/PORTFOLIO_DOCUMENTS/07_Manual_Penetration_Guide/) - Step-by-step guides

## Tech Stack

- Python 3.8+ (boto3, requests, paramiko)
- PHP 7.4+
- AWS (EC2, S3, IAM, IMDS)
- ModSecurity WAF
- Fail2Ban

## Legal

For educational purposes only. Don't attack systems you don't own.

Unauthorized access is illegal (Korean law: up to 5 years imprisonment).

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- Capital One Breach (2019) - SSRF to IMDS case study

## License

MIT License (educational use only)

---

Contact: hwangpongpong10@gmail.com
