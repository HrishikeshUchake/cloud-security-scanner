import unittest
import boto3
from moto import mock_aws
from cloud_scanner import CloudSecurityScanner

class TestCloudSecurityScanner(unittest.TestCase):
    @mock_aws
    def setUp(self):
        # Setup mock AWS environment
        self.scanner = CloudSecurityScanner()

    @mock_aws
    def test_s3_public_bucket(self):
        s3 = boto3.client('s3', region_name='us-east-1')
        s3.create_bucket(Bucket='my-public-bucket')
        # We don't apply a public access block, so it should be flagged.
        
        self.scanner.scan_s3_buckets()
        vulnerabilities = self.scanner.report['S3_Vulnerabilities']
        self.assertTrue(any(v['Resource'] == 'my-public-bucket' for v in vulnerabilities))

    @mock_aws
    def test_security_group_open_ssh(self):
        ec2 = boto3.client('ec2', region_name='us-east-1')
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        sg = ec2.create_security_group(GroupName='test-sg', Description='test', VpcId=vpc['Vpc']['VpcId'])
        
        ec2.authorize_security_group_ingress(
            GroupId=sg['GroupId'],
            IpPermissions=[{'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        )
        
        self.scanner.scan_security_groups()
        vulnerabilities = self.scanner.report['SecurityGroup_Vulnerabilities']
        self.assertTrue(any('test-sg' in v['Resource'] for v in vulnerabilities))

if __name__ == '__main__':
    unittest.main()
