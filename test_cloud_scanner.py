import unittest
import boto3
import json
from moto import mock_aws
from cloud_scanner import CloudSecurityScanner

class TestCloudSecurityScanner(unittest.TestCase):
    @mock_aws
    def setUp(self):
        # Setup mock AWS environment
        self.scanner = CloudSecurityScanner()

    # ==========================================
    # S3 BENCHMARKS
    # ==========================================
    @mock_aws
    def test_s3_public_bucket_detected(self):
        """Benchmark: Should detect a bucket without Public Access Block"""
        s3 = boto3.client('s3', region_name='us-east-1')
        s3.create_bucket(Bucket='my-public-bucket')
        
        self.scanner.scan_s3_buckets()
        vulnerabilities = self.scanner.report['S3_Vulnerabilities']
        self.assertTrue(any(v['Resource'] == 'my-public-bucket' for v in vulnerabilities))

    @mock_aws
    def test_s3_secure_bucket_ignored(self):
        """Benchmark: Should ignore a securely configured bucket"""
        s3 = boto3.client('s3', region_name='us-east-1')
        s3.create_bucket(Bucket='my-secure-bucket')
        s3.put_public_access_block(
            Bucket='my-secure-bucket',
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        self.scanner.scan_s3_buckets()
        vulnerabilities = self.scanner.report['S3_Vulnerabilities']
        self.assertFalse(any(v['Resource'] == 'my-secure-bucket' for v in vulnerabilities))

    # ==========================================
    # SECURITY GROUP BENCHMARKS
    # ==========================================
    @mock_aws
    def test_security_group_open_ssh_detected(self):
        """Benchmark: Should detect 0.0.0.0/0 open to the world"""
        ec2 = boto3.client('ec2', region_name='us-east-1')
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        sg = ec2.create_security_group(GroupName='test-sg-open', Description='test', VpcId=vpc['Vpc']['VpcId'])
        
        ec2.authorize_security_group_ingress(
            GroupId=sg['GroupId'],
            IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        )
        
        self.scanner.scan_security_groups()
        vulnerabilities = self.scanner.report['SecurityGroup_Vulnerabilities']
        self.assertTrue(any('test-sg-open' in v['Resource'] for v in vulnerabilities))

    @mock_aws
    def test_security_group_secure_ignored(self):
        """Benchmark: Should ignore properly scoped CIDR blocks"""
        ec2 = boto3.client('ec2', region_name='us-east-1')
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        sg = ec2.create_security_group(GroupName='test-sg-secure', Description='test', VpcId=vpc['Vpc']['VpcId'])
        
        ec2.authorize_security_group_ingress(
            GroupId=sg['GroupId'],
            IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '192.168.1.0/24'}]}]
        )
        
        self.scanner.scan_security_groups()
        vulnerabilities = self.scanner.report['SecurityGroup_Vulnerabilities']
        self.assertFalse(any('test-sg-secure' in v['Resource'] for v in vulnerabilities))

    # ==========================================
    # IAM BENCHMARKS
    # ==========================================
    @mock_aws
    def test_iam_admin_access_detected(self):
        """Benchmark: Should flag AdministratorAccess policies"""
        iam = boto3.client('iam', region_name='us-east-1')
        iam.create_role(RoleName='admin-role', AssumeRolePolicyDocument='{}')
        iam.attach_role_policy(RoleName='admin-role', PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        
        self.scanner.scan_iam_roles()
        vulnerabilities = self.scanner.report['IAM_Vulnerabilities']
        self.assertTrue(any(v['Resource'] == 'admin-role' for v in vulnerabilities))

    @mock_aws
    def test_iam_inline_unrestricted_detected(self):
        """Benchmark: Should flag inline policies with Action * and Resource *"""
        iam = boto3.client('iam', region_name='us-east-1')
        iam.create_role(RoleName='inline-bad-role', AssumeRolePolicyDocument='{}')
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        }
        iam.put_role_policy(RoleName='inline-bad-role', PolicyName='bad-policy', PolicyDocument=json.dumps(policy_doc))
        
        self.scanner.scan_iam_roles()
        vulnerabilities = self.scanner.report['IAM_Vulnerabilities']
        self.assertTrue(any(v['Resource'] == 'inline-bad-role' for v in vulnerabilities))

    # ==========================================
    # CLOUDTRAIL BENCHMARKS
    # ==========================================
    @mock_aws
    def test_cloudtrail_no_trails_detected(self):
        """Benchmark: Should detect when no CloudTrails exist at all"""
        # Because it's a mocked blank environment, no trails exist
        self.scanner.scan_cloudtrail()
        vulnerabilities = self.scanner.report['CloudTrail_Vulnerabilities']
        self.assertTrue(any(v['Issue'] == 'No CloudTrails configured.' for v in vulnerabilities))

if __name__ == '__main__':
    unittest.main()
