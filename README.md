# Cloud Security Misconfiguration Scanner (CSPM)

An automated Cloud Security Posture Management (CSPM) tool designed to programmatically audit AWS environments for common but critical security misconfigurations. Developed in Python, this tool utilizes the AWS SDK (`boto3`) to interface directly with AWS REST APIs, extract resource metadata, and evaluate configurations against established security best practices.

## Technical Architecture

The system is built on a modular, object-oriented architecture (`CloudSecurityScanner` class) that sequentially polls AWS service endpoints. The findings are aggregated in-memory and dynamically serialized into multiple reporting formats.

### 1. Amazon S3 (Simple Storage Service)
The scanner evaluates the security posture of S3 buckets by querying the `GetPublicAccessBlock` API. It specifically checks for the absence or misconfiguration of:
- `BlockPublicAcls`
- `IgnorePublicAcls`
- `BlockPublicPolicy`
- `RestrictPublicBuckets`

Any bucket lacking a comprehensive block across all four parameters is flagged as a potential data exfiltration risk. Additionally, it queries the `GetBucketEncryption` API to ensure default encryption (SSE-S3 or KMS) is explicitly enabled to protect data at rest.

### 2. Amazon EC2 Security Groups (Network Firewalls)
The tool iterates through all Security Groups within the VPCs, inspecting the `IpPermissions` arrays. It parses ingress network ACLs and flags overly permissive CIDR blocks (`0.0.0.0/0` or `::/0`) explicitly tied to sensitive administrative ports (e.g., TCP 22 for SSH, TCP 3389 for RDP, or completely unrestricted traffic).

### 3. AWS IAM (Identity and Access Management)
The scanner performs deep policy parsing on IAM Roles and evaluates IAM Users to enforce the Principle of Least Privilege and strong authentication:
- **Managed Policies:** Scans attached policies to flag overly broad access rights, specifically targeting roles with `AdministratorAccess`.
- **Inline Policies:** Iterates through custom inline JSON policy documents. It parses the `Statement` blocks to identify overly permissive wildcard configurations where both `Action: "*"` and `Resource: "*"` are present simultaneously.
- **IAM Users:** Evaluates individual users to ensure Multi-Factor Authentication (MFA) is enabled and flags any active access keys that are older than 90 days to enforce credential rotation.

### 4. Amazon RDS (Relational Database Service)
Analyzes RDS cluster and instance configurations, specifically evaluating the `PubliclyAccessible` boolean flag to ensure managed databases are not exposed directly to the public internet.

### 5. AWS CloudTrail (Audit & Compliance)
Verifies that API auditing is both present and active across the account. It queries the `DescribeTrails` and `GetTrailStatus` endpoints to ensure trails exist and that the `IsLogging` status is currently set to `True`.

### 6. Amazon EBS (Elastic Block Store)
Analyzes `DescribeVolumes` API to explicitly flag any unencrypted Elastic Block Store (EBS) volumes to protect data at rest.

### 7. AWS Lambda (Serverless Compute)
Evaluates Lambda functions to check for environment variables lacking KMS encryption. It also parses the resource-based policies to flag any functions allowing public access (`Principal: "*"`).

### 8. Amazon API Gateway
Scans REST API stages to detect endpoints lacking Web Application Firewall (WAF) protection. Additionally, it evaluates API methods to flag routes missing authorization configurations (`authorizationType: "NONE"`).

---

## Testing Methodology & Benchmarking

The project implements a rigorous, isolated unit-testing suite using the `moto` framework. This allows for in-memory mocking of the AWS control plane.

The test suite evaluates the scanner against established benchmarks:
- **True Positives:** Verifies the scanner successfully catches deliberately vulnerable configurations (e.g., an S3 bucket explicitly stripped of its Public Access Block, or an IAM role with wildcard inline policies).
- **True Negatives:** Verifies the scanner appropriately ignores securely configured resources, preventing false positives (e.g., Security Groups restricted to internal `192.168.1.0/24` subnets).

## Prerequisites
- Python 3.8+
- AWS CLI configured with valid programmatic credentials (`aws configure`)

## Installation
1. Clone this repository.
2. Install the required dependencies:
   ```bash
   pip install boto3 moto pytest
   ```

## Usage
Execute the scanner from your terminal. It will automatically utilize your local AWS credentials profile.
```bash
python cloud_scanner.py
```

### Reporting Artifacts
Upon execution, the system aggregates findings and outputs them synchronously into the local directory:
1. `report.json`: Machine-readable structured payload for SIEM ingestion or automated parsing.
2. `report.csv`: Flat-file output for quick triage and spreadsheet analysis.
3. `report.html`: A styled, human-readable HTML dashboard for immediate visual review by security analysts.

## Running Tests
Run the mocked unit testing suite to validate scanner logic without modifying real AWS infrastructure:
```bash
python -m unittest test_cloud_scanner.py
```
