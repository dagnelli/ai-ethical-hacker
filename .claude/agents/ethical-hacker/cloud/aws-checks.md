# AWS Security Checks

> *"Every bucket tells a story. Every IAM policy reveals secrets."*

## S3 Bucket Security

### Public Bucket Detection

```bash
# List all buckets
aws s3 ls

# Check bucket ACL
aws s3api get-bucket-acl --bucket $BUCKET

# Check bucket policy
aws s3api get-bucket-policy --bucket $BUCKET

# Check public access block
aws s3api get-public-access-block --bucket $BUCKET

# Test anonymous access
aws s3 ls s3://$BUCKET --no-sign-request
aws s3 cp s3://$BUCKET/test.txt ./test.txt --no-sign-request
```

### Common Bucket Misconfigurations

```bash
# Check for bucket logging
aws s3api get-bucket-logging --bucket $BUCKET

# Check encryption
aws s3api get-bucket-encryption --bucket $BUCKET

# Check versioning
aws s3api get-bucket-versioning --bucket $BUCKET

# Check MFA delete
aws s3api get-bucket-versioning --bucket $BUCKET | grep MFADelete
```

## IAM Security

### User Enumeration

```bash
# List all users
aws iam list-users

# Get user details
aws iam get-user --user-name $USER

# List user policies
aws iam list-user-policies --user-name $USER
aws iam list-attached-user-policies --user-name $USER

# Get policy document
aws iam get-user-policy --user-name $USER --policy-name $POLICY

# List access keys
aws iam list-access-keys --user-name $USER

# Check last key usage
aws iam get-access-key-last-used --access-key-id $KEY_ID
```

### Role Enumeration

```bash
# List all roles
aws iam list-roles

# Get role details
aws iam get-role --role-name $ROLE

# Get role policies
aws iam list-role-policies --role-name $ROLE
aws iam list-attached-role-policies --role-name $ROLE

# Get trust policy
aws iam get-role --role-name $ROLE --query 'Role.AssumeRolePolicyDocument'

# Assume role (if permitted)
aws sts assume-role --role-arn $ROLE_ARN --role-session-name test
```

### Policy Analysis

```bash
# List all policies
aws iam list-policies --scope Local

# Get policy details
aws iam get-policy --policy-arn $POLICY_ARN

# Get policy document
aws iam get-policy-version --policy-arn $POLICY_ARN --version-id v1

# Simulate policy (test permissions)
aws iam simulate-principal-policy --policy-source-arn $PRINCIPAL_ARN --action-names s3:GetObject
```

### Dangerous Permissions to Look For

```json
// Admin-like permissions
"Action": "*"
"Action": "iam:*"
"Action": "sts:AssumeRole"

// Privilege escalation vectors
"Action": "iam:CreatePolicyVersion"
"Action": "iam:SetDefaultPolicyVersion"
"Action": "iam:AttachUserPolicy"
"Action": "iam:AttachRolePolicy"
"Action": "iam:CreateAccessKey"
"Action": "iam:CreateLoginProfile"
"Action": "iam:UpdateLoginProfile"
"Action": "iam:PutUserPolicy"
"Action": "iam:PutRolePolicy"
"Action": "iam:PassRole" + "lambda:CreateFunction"
"Action": "iam:PassRole" + "ec2:RunInstances"

// Data exfiltration
"Action": "s3:*"
"Action": "dynamodb:*"
"Action": "rds:*"
```

## EC2 Security

### Instance Enumeration

```bash
# List all instances
aws ec2 describe-instances

# Get specific instance
aws ec2 describe-instances --instance-ids $INSTANCE_ID

# Get user data (may contain secrets)
aws ec2 describe-instance-attribute --instance-id $INSTANCE_ID --attribute userData

# List security groups
aws ec2 describe-security-groups

# Check for public instances
aws ec2 describe-instances --filters "Name=ip-address,Values=*"
```

### Security Group Analysis

```bash
# List security groups
aws ec2 describe-security-groups

# Find open to world (0.0.0.0/0)
aws ec2 describe-security-groups --filters "Name=ip-permission.cidr,Values=0.0.0.0/0"

# Check specific ports
aws ec2 describe-security-groups --filters "Name=ip-permission.from-port,Values=22" "Name=ip-permission.cidr,Values=0.0.0.0/0"
```

### IMDSv1 vs IMDSv2

```bash
# Check IMDS version
aws ec2 describe-instances --query "Reservations[].Instances[].MetadataOptions"

# From inside EC2 - IMDSv1 (vulnerable)
curl http://169.254.169.254/latest/meta-data/

# IMDSv2 (requires token)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

## Lambda Security

### Function Enumeration

```bash
# List functions
aws lambda list-functions

# Get function details
aws lambda get-function --function-name $FUNCTION

# Get function policy
aws lambda get-policy --function-name $FUNCTION

# Get environment variables (may contain secrets)
aws lambda get-function-configuration --function-name $FUNCTION --query 'Environment.Variables'

# List layers
aws lambda list-layers
```

## Secrets Manager / SSM

### Secrets Enumeration

```bash
# List secrets
aws secretsmanager list-secrets

# Get secret value
aws secretsmanager get-secret-value --secret-id $SECRET_ID

# List SSM parameters
aws ssm describe-parameters

# Get SSM parameter
aws ssm get-parameter --name $PARAM_NAME --with-decryption
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption
```

## CloudTrail Analysis

```bash
# List trails
aws cloudtrail describe-trails

# Check trail status
aws cloudtrail get-trail-status --name $TRAIL

# Look for gaps in logging
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging
```

## Privilege Escalation Paths

### Via IAM

```bash
# 1. Create new policy version
aws iam create-policy-version --policy-arn $ARN --policy-document file://admin.json --set-as-default

# 2. Attach admin policy to user
aws iam attach-user-policy --user-name $USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 3. Create new access key for another user
aws iam create-access-key --user-name $TARGET_USER

# 4. Update login profile
aws iam update-login-profile --user-name $USER --password NewPassword123!
```

### Via Lambda

```bash
# If have iam:PassRole and lambda:CreateFunction
# Create Lambda with privileged role

# Lambda code to assume role
# Execute Lambda to gain privileges
```

### Via EC2

```bash
# If have iam:PassRole and ec2:RunInstances
# Launch EC2 with privileged instance profile
# Access IMDS for temporary credentials
```

## Quick Security Audit

```bash
# Run Prowler
prowler aws

# Run ScoutSuite
scout aws

# Quick manual checks
aws iam get-account-summary
aws iam generate-credential-report
aws iam get-credential-report
aws s3api list-buckets --query "Buckets[].Name"
aws ec2 describe-security-groups --filters "Name=ip-permission.cidr,Values=0.0.0.0/0"
```
