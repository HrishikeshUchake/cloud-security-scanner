import boto3
import json
import csv
import urllib.parse
from datetime import datetime, timezone
from botocore.exceptions import ClientError

class CloudSecurityScanner:
    def __init__(self):
        self.s3_client = boto3.client('s3')
        self.ec2_client = boto3.client('ec2')
        self.iam_client = boto3.client('iam')
        self.rds_client = boto3.client('rds')
        self.cloudtrail_client = boto3.client('cloudtrail')
        self.lambda_client = boto3.client('lambda')
        self.apigw_client = boto3.client('apigateway')
        
        self.report = {
            "S3_Vulnerabilities": [],
            "SecurityGroup_Vulnerabilities": [],
            "IAM_Vulnerabilities": [],
            "RDS_Vulnerabilities": [],
            "CloudTrail_Vulnerabilities": [],
            "EBS_Vulnerabilities": [],
            "Lambda_Vulnerabilities": [],
            "APIGateway_Vulnerabilities": []
        }

    def scan_s3_buckets(self):
        print("Scanning S3 Buckets...")
        try:
            buckets = self.s3_client.list_buckets().get('Buckets', [])
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    pab = self.s3_client.get_public_access_block(Bucket=bucket_name)
                    config = pab['PublicAccessBlockConfiguration']
                    if not all([config.get('BlockPublicAcls'), config.get('IgnorePublicAcls'), 
                                config.get('BlockPublicPolicy'), config.get('RestrictPublicBuckets')]):
                        self.report["S3_Vulnerabilities"].append({"Resource": bucket_name, "Issue": "Public access not fully blocked."})
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        self.report["S3_Vulnerabilities"].append({"Resource": bucket_name, "Issue": "No Public Access Block config found."})
                try:
                    self.s3_client.get_bucket_encryption(Bucket=bucket_name)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        self.report["S3_Vulnerabilities"].append({"Resource": bucket_name, "Issue": "Default encryption is not enabled."})
        except Exception as e:
            print(f"Error scanning S3: {e}")

    def scan_security_groups(self):
        print("Scanning Security Groups...")
        try:
            sgs = self.ec2_client.describe_security_groups().get('SecurityGroups', [])
            for sg in sgs:
                for perm in sg.get('IpPermissions', []):
                    for ip_range in perm.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            port = perm.get('FromPort', 'All')
                            self.report["SecurityGroup_Vulnerabilities"].append({
                                "Resource": f"{sg['GroupName']} ({sg['GroupId']})", 
                                "Issue": f"Open to 0.0.0.0/0 on port {port}."
                            })
        except Exception as e:
            print(f"Error scanning Security Groups: {e}")

    def scan_iam_roles(self):
        print("Scanning IAM Roles...")
        try:
            roles = self.iam_client.list_roles().get('Roles', [])
            for role in roles:
                role_name = role['RoleName']
                # Check Attached Policies
                attached = self.iam_client.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
                for policy in attached:
                    if policy['PolicyName'] == 'AdministratorAccess':
                        self.report["IAM_Vulnerabilities"].append({"Resource": role_name, "Issue": "Attached to AdministratorAccess."})
                
                # Check Inline Policies for Action: * and Resource: *
                inline_policies = self.iam_client.list_role_policies(RoleName=role_name).get('PolicyNames', [])
                for policy_name in inline_policies:
                    policy_doc = self.iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name).get('PolicyDocument', {})
                    statements = policy_doc.get('Statement', [])
                    if isinstance(statements, dict): statements = [statements]
                    for stmt in statements:
                        if stmt.get('Effect') == 'Allow':
                            action = stmt.get('Action', [])
                            resource = stmt.get('Resource', [])
                            if (action == '*' or '*' in action) and (resource == '*' or '*' in resource):
                                self.report["IAM_Vulnerabilities"].append({
                                    "Resource": role_name, 
                                    "Issue": f"Inline policy '{policy_name}' allows unrestricted access (*/*)."
                                })
        except Exception as e:
            print(f"Error scanning IAM Roles: {e}")

    def scan_rds_instances(self):
        print("Scanning RDS Instances...")
        try:
            instances = self.rds_client.describe_db_instances().get('DBInstances', [])
            for db in instances:
                if db.get('PubliclyAccessible'):
                    self.report["RDS_Vulnerabilities"].append({
                        "Resource": db['DBInstanceIdentifier'], 
                        "Issue": "Database is publicly accessible."
                    })
        except Exception as e:
            print(f"Error scanning RDS: {e}")

    def scan_cloudtrail(self):
        print("Scanning CloudTrail...")
        try:
            trails = self.cloudtrail_client.describe_trails().get('trailList', [])
            if not trails:
                self.report["CloudTrail_Vulnerabilities"].append({"Resource": "Account", "Issue": "No CloudTrails configured."})
            for trail in trails:
                status = self.cloudtrail_client.get_trail_status(Name=trail['TrailARN'])
                if not status.get('IsLogging'):
                    self.report["CloudTrail_Vulnerabilities"].append({
                        "Resource": trail['Name'], 
                        "Issue": "Trail exists but logging is currently disabled."
                    })
        except Exception as e:
            print(f"Error scanning CloudTrail: {e}")


    def scan_iam_users(self):
        print("Scanning IAM Users...")
        try:
            users = self.iam_client.list_users().get('Users', [])
            for user in users:
                user_name = user['UserName']
                # Check MFA
                mfa = self.iam_client.list_mfa_devices(UserName=user_name).get('MFADevices', [])
                if not mfa:
                    self.report["IAM_Vulnerabilities"].append({
                        "Resource": user_name,
                        "Issue": "No MFA enabled for user."
                    })
                # Check Access Keys
                keys = self.iam_client.list_access_keys(UserName=user_name).get('AccessKeyMetadata', [])
                for key in keys:
                    if key['Status'] == 'Active':
                        age = (datetime.now(timezone.utc) - key['CreateDate']).days
                        if age > 90:
                            self.report["IAM_Vulnerabilities"].append({
                                "Resource": f"{user_name} ({key['AccessKeyId']})",
                                "Issue": f"Active access key is older than 90 days."
                            })
        except Exception as e:
            print(f"Error scanning IAM Users: {e}")

    def scan_ebs_volumes(self):
        print("Scanning EBS Volumes...")
        try:
            volumes = self.ec2_client.describe_volumes().get('Volumes', [])
            for vol in volumes:
                if not vol.get('Encrypted'):
                    self.report["EBS_Vulnerabilities"].append({
                        "Resource": vol['VolumeId'],
                        "Issue": "EBS volume is not encrypted."
                    })
        except Exception as e:
            print(f"Error scanning EBS Volumes: {e}")

    def scan_lambda_functions(self):
        print("Scanning Lambda Functions...")
        try:
            funcs = self.lambda_client.list_functions().get('Functions', [])
            for func in funcs:
                func_name = func['FunctionName']
                if 'Environment' in func and 'Variables' in func['Environment']:
                    if 'KMSKeyArn' not in func:
                        self.report["Lambda_Vulnerabilities"].append({
                            "Resource": func_name,
                            "Issue": "Environment variables lacking KMS encryption."
                        })
                try:
                    policy_str = self.lambda_client.get_policy(FunctionName=func_name).get('Policy', '{}')
                    for stmt in json.loads(policy_str).get('Statement', []):
                        if stmt.get('Effect') == 'Allow' and stmt.get('Principal') == '*':
                            self.report["Lambda_Vulnerabilities"].append({
                                "Resource": func_name,
                                "Issue": "Resource-based policy allows public access."
                            })
                except ClientError as e:
                    if e.response['Error']['Code'] != 'ResourceNotFoundException':
                        pass
        except Exception as e:
            print(f"Error scanning Lambda Functions: {e}")

    def scan_api_gateways(self):
        print("Scanning API Gateways...")
        try:
            apis = self.apigw_client.get_rest_apis().get('items', [])
            for api in apis:
                api_id = api['id']
                stages = self.apigw_client.get_stages(restApiId=api_id).get('item', [])
                for stage in stages:
                    if not stage.get('webAclArn'):
                        self.report["APIGateway_Vulnerabilities"].append({
                            "Resource": f"{api['name']} (Stage: {stage.get('stageName', 'default')})",
                            "Issue": "API stage lacks WAF protection."
                        })
                resources = self.apigw_client.get_resources(restApiId=api_id).get('items', [])
                for res in resources:
                    for method_name in res.get('resourceMethods', {}):
                        if method_name != 'OPTIONS':
                            method_info = self.apigw_client.get_method(restApiId=api_id, resourceId=res['id'], httpMethod=method_name)
                            if method_info.get('authorizationType') == 'NONE':
                                self.report["APIGateway_Vulnerabilities"].append({
                                    "Resource": f"{api['name']} ({res.get('path', '/')} : {method_name})",
                                    "Issue": "API method lacks authorization configuration."
                                })
        except Exception as e:
            print(f"Error scanning API Gateways: {e}")

    def generate_reports(self):
        print("\nGenerating Reports...")
        # JSON
        with open("report.json", "w") as f:
            json.dump(self.report, f, indent=4)
        
        # CSV
        with open("report.csv", "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Category", "Resource", "Issue"])
            for category, vulnerabilities in self.report.items():
                for vuln in vulnerabilities:
                    writer.writerow([category, vuln["Resource"], vuln["Issue"]])
        
        # HTML
        html_content = "<html><head><title>Cloud Security Report</title><style>body{font-family: Arial;} table{border-collapse: collapse; width: 100%;} th, td{border: 1px solid #ddd; padding: 8px;} th{background-color: #f2f2f2;}</style></head><body>"
        html_content += "<h1>AWS Cloud Security Misconfiguration Report</h1><table><tr><th>Category</th><th>Resource</th><th>Issue</th></tr>"
        for category, vulnerabilities in self.report.items():
            for vuln in vulnerabilities:
                html_content += f"<tr><td>{category}</td><td>{vuln['Resource']}</td><td>{vuln['Issue']}</td></tr>"
        html_content += "</table></body></html>"
        
        with open("report.html", "w") as f:
            f.write(html_content)
        
        print("Reports saved: report.json, report.csv, report.html")

if __name__ == "__main__":
    scanner = CloudSecurityScanner()
    scanner.scan_s3_buckets()
    scanner.scan_security_groups()
    scanner.scan_iam_roles()
    scanner.scan_iam_users()
    scanner.scan_ebs_volumes()
    scanner.scan_lambda_functions()
    scanner.scan_api_gateways()
    scanner.scan_rds_instances()
    scanner.scan_cloudtrail()
    scanner.generate_reports()
