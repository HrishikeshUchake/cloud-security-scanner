# Cloud Security Misconfiguration Scanner

A Python-based automated security scanning tool designed to identify common security misconfigurations in AWS cloud environments.

## Architecture
The scanner utilizes the `boto3` SDK to programmatically interface with AWS APIs. It extracts configuration metadata from various services and evaluates them against established security best practices.

**Supported Services & Checks:**
- **Amazon S3**: Detects missing Public Access Block configurations.
- **Amazon EC2 (Security Groups)**: Identifies unrestricted inbound rules (0.0.0.0/0) on sensitive ports like SSH/RDP.
- **AWS IAM**: Flags roles with `AdministratorAccess` or inline policies containing `Action: "*"` and `Resource: "*"`.
- **Amazon RDS**: Detects publicly accessible database instances.
- **AWS CloudTrail**: Ensures trails exist and logging is actively enabled.

## Prerequisites
- Python 3.8+
- AWS CLI configured with valid credentials (`aws configure`)

## Installation
1. Clone this repository.
2. Install the required dependencies:
   ```bash
   pip install boto3 moto pytest
   ```

## Usage
Run the scanner from the terminal. It will utilize your default AWS credentials.
```bash
python cloud_scanner.py
```

### Reporting
The tool automatically generates three files upon completion:
1. `report.json` - Machine-readable format.
2. `report.csv` - Easy to import into Excel or SIEM tools.
3. `report.html` - A visual dashboard for quick human review.

## Testing
We use `moto` to mock AWS services so tests run locally without modifying real AWS infrastructure.
Run the tests using:
```bash
python -m unittest test_cloud_scanner.py
```
