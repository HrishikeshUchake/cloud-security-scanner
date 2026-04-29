import boto3
from moto import mock_aws
from cloud_scanner import CloudSecurityScanner

@mock_aws
def run():
    s3 = boto3.client('s3', region_name='us-east-1')
    s3.create_bucket(Bucket='my-secure-bucket')
    s3.put_public_access_block(Bucket='my-secure-bucket', PublicAccessBlockConfiguration={'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True})
    s3.put_bucket_encryption(Bucket='my-secure-bucket', ServerSideEncryptionConfiguration={'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]})
    scanner = CloudSecurityScanner()
    scanner.scan_s3_buckets()
    print(scanner.report['S3_Vulnerabilities'])

run()
