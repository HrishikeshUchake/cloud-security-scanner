import boto3
import uuid


def deploy_vulnerable_bucket():
    s3_client = boto3.client('s3')

    # Generate a unique bucket name (S3 bucket names must be globally unique)
    bucket_name = f"cloud-scanner-vulnerable-test-{uuid.uuid4().hex[:8]}"

    print(f"Deploying deliberately vulnerable bucket: {bucket_name}")

    try:
        # 1. Create the bucket
        # Note: If your default region isn't us-east-1, you might need a LocationConstraint
        s3_client.create_bucket(Bucket=bucket_name)
        print(" -> Bucket created.")

        # 2. Explicitly remove the Public Access Block (AWS enables this by default now)
        # This action creates the misconfiguration your scanner is looking for!
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': False,
                'IgnorePublicAcls': False,
                'BlockPublicPolicy': False,
                'RestrictPublicBuckets': False
            }
        )
        print(" -> Public Access Block disabled (VULNERABILITY INTRODUCED).")
        print("\nDeployment Complete!")
        print("======================================================")
        print("Run your scanner now: python cloud_scanner.py")
        print("IMPORTANT: Delete this bucket when you are done!")
        print("======================================================")

    except Exception as e:
        print(f"Error deploying test bucket: {e}")


if __name__ == "__main__":
    deploy_vulnerable_bucket()
