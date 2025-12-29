# SKYBREAKER Tools Reference

> *"Every cloud has tools. Every tool breaks barriers."*

## Multi-Cloud Tools

### ScoutSuite
**Source**: https://github.com/nccgroup/ScoutSuite

```bash
# AWS
scout aws --profile $PROFILE

# Azure
scout azure --cli

# GCP
scout gcp --project-id $PROJECT_ID

# Output to specific directory
scout aws --profile $PROFILE --report-dir ./report
```

### Prowler
**Source**: https://github.com/prowler-cloud/prowler

```bash
# AWS - Full scan
prowler aws

# AWS - Specific checks
prowler aws --checks s3_bucket_public_access,iam_root_access_key

# Azure
prowler azure

# GCP
prowler gcp

# Generate HTML report
prowler aws -M html
```

### CloudFox
**Source**: https://github.com/BishopFox/cloudfox

```bash
# AWS - All modules
cloudfox aws --profile $PROFILE all-checks

# AWS - Specific modules
cloudfox aws --profile $PROFILE principals
cloudfox aws --profile $PROFILE permissions
cloudfox aws --profile $PROFILE buckets
cloudfox aws --profile $PROFILE secrets

# Azure
cloudfox azure --subscription $SUB_ID all-checks
```

### Trufflehog
**Source**: https://github.com/trufflesecurity/trufflehog

```bash
# Scan Git repo
trufflehog git https://github.com/org/repo

# Scan GitHub org
trufflehog github --org=organization

# Scan filesystem
trufflehog filesystem /path/to/code

# Scan S3 bucket
trufflehog s3 --bucket=bucket-name
```

### Gitleaks
**Source**: https://github.com/gitleaks/gitleaks

```bash
# Scan current directory
gitleaks detect

# Scan specific repo
gitleaks detect --source=/path/to/repo

# Scan with custom config
gitleaks detect -c gitleaks.toml
```

## AWS Tools

### AWS CLI
```bash
# Configure credentials
aws configure --profile $PROFILE

# Get caller identity
aws sts get-caller-identity

# List S3 buckets
aws s3 ls

# List EC2 instances
aws ec2 describe-instances

# List IAM users
aws iam list-users

# List IAM roles
aws iam list-roles

# Get IAM policy
aws iam get-policy --policy-arn $ARN
aws iam get-policy-version --policy-arn $ARN --version-id v1

# List Lambda functions
aws lambda list-functions

# Get secrets
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id $SECRET_ID
```

### Pacu
**Source**: https://github.com/RhinoSecurityLabs/pacu

```bash
# Start Pacu
python3 pacu.py

# Set keys
set_keys

# Run enumeration
run iam__enum_users_roles_policies_groups
run ec2__enum
run s3__enum

# Privilege escalation
run iam__privesc_scan

# Exploitation
run lambda__backdoor_new_roles
```

### enumerate-iam
**Source**: https://github.com/andresriancho/enumerate-iam

```bash
# Enumerate permissions
python enumerate-iam.py --access-key $ACCESS_KEY --secret-key $SECRET_KEY
```

### S3Scanner
**Source**: https://github.com/sa7mon/S3Scanner

```bash
# Scan for S3 buckets
python3 s3scanner.py --bucket-name bucket-name

# Scan from list
python3 s3scanner.py --bucket-file buckets.txt

# Dump bucket contents
python3 s3scanner.py --bucket-name bucket-name --dump
```

### CloudMapper
**Source**: https://github.com/duo-labs/cloudmapper

```bash
# Collect data
python cloudmapper.py collect --account $ACCOUNT_NAME

# Generate report
python cloudmapper.py report --account $ACCOUNT_NAME

# Find public assets
python cloudmapper.py public --account $ACCOUNT_NAME
```

## Azure Tools

### Azure CLI
```bash
# Login
az login

# Get account info
az account show

# List subscriptions
az account list

# List resource groups
az group list

# List VMs
az vm list

# List storage accounts
az storage account list

# List blobs
az storage blob list --account-name $ACCOUNT --container $CONTAINER

# List Azure AD users
az ad user list

# List service principals
az ad sp list

# Get Key Vault secrets
az keyvault secret list --vault-name $VAULT
az keyvault secret show --vault-name $VAULT --name $SECRET
```

### ROADtools
**Source**: https://github.com/dirkjanm/ROADtools

```bash
# Authenticate
roadrecon auth -u user@domain.com

# Gather data
roadrecon gather

# Analyze
roadrecon-gui
```

### AzureHound
**Source**: https://github.com/BloodHoundAD/AzureHound

```bash
# Collect data
azurehound -u user@domain.com list -t $TENANT_ID -o output.json
```

### MicroBurst
**Source**: https://github.com/NetSPI/MicroBurst

```powershell
# Import module
Import-Module MicroBurst.psm1

# Enumerate
Invoke-EnumerateAzureBlobs -Base $COMPANY
Invoke-EnumerateAzureSubDomains -Base $COMPANY

# Get metadata
Get-AzurePasswords
```

## GCP Tools

### gcloud CLI
```bash
# Authenticate
gcloud auth login
gcloud auth application-default login

# Get project info
gcloud config list
gcloud projects list

# List compute instances
gcloud compute instances list

# List storage buckets
gsutil ls

# List bucket contents
gsutil ls gs://bucket-name

# List service accounts
gcloud iam service-accounts list

# List IAM policies
gcloud projects get-iam-policy $PROJECT_ID

# Get secrets
gcloud secrets list
gcloud secrets versions access latest --secret=$SECRET_ID
```

### GCPBucketBrute
**Source**: https://github.com/RhinoSecurityLabs/GCPBucketBrute

```bash
# Enumerate buckets
python3 gcpbucketbrute.py -k keywords.txt
```

## Kubernetes Tools

### kubectl
```bash
# Get cluster info
kubectl cluster-info

# List pods
kubectl get pods --all-namespaces

# List secrets
kubectl get secrets --all-namespaces

# Get secret content
kubectl get secret $SECRET -o yaml

# List service accounts
kubectl get serviceaccounts --all-namespaces

# Check RBAC
kubectl auth can-i --list

# Get pod with high privileges
kubectl get pods -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true)'
```

### kube-hunter
**Source**: https://github.com/aquasecurity/kube-hunter

```bash
# Scan cluster
kube-hunter --remote $CLUSTER_IP

# Active hunting
kube-hunter --remote $CLUSTER_IP --active
```

### kubeaudit
**Source**: https://github.com/Shopify/kubeaudit

```bash
# Full audit
kubeaudit all

# Specific checks
kubeaudit privileged
kubeaudit capabilities
kubeaudit rootfs
```

### Peirates
**Source**: https://github.com/inguardians/peirates

```bash
# Interactive menu
peirates

# From within a pod for lateral movement
```

## Metadata Exploitation

### SSRF to Cloud Metadata

```bash
# AWS
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/user-data/

# Azure (requires header)
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# GCP (requires header)
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

## Quick Reference

```bash
# AWS - Quick enum
aws sts get-caller-identity
aws s3 ls
aws iam list-users
cloudfox aws principals

# Azure - Quick enum
az account show
az group list
az vm list
az storage account list

# GCP - Quick enum
gcloud config list
gcloud projects list
gcloud compute instances list
gsutil ls

# Find secrets in code
trufflehog git https://github.com/org/repo
gitleaks detect --source=/path/to/code
```
