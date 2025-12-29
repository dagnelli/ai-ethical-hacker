# GCP Security Checks

> *"Every project is a frontier. Every service account is a key."*

## IAM Security

### Service Account Enumeration

```bash
# List service accounts
gcloud iam service-accounts list

# Get service account details
gcloud iam service-accounts describe $SA_EMAIL

# List service account keys
gcloud iam service-accounts keys list --iam-account=$SA_EMAIL

# Check for user-managed keys (risky)
gcloud iam service-accounts keys list --iam-account=$SA_EMAIL --managed-by=user
```

### IAM Policy Analysis

```bash
# Get project IAM policy
gcloud projects get-iam-policy $PROJECT_ID

# Get specific resource IAM policy
gcloud compute instances get-iam-policy $INSTANCE --zone=$ZONE

# List roles
gcloud iam roles list

# Get role permissions
gcloud iam roles describe roles/editor
gcloud iam roles describe $CUSTOM_ROLE --project=$PROJECT_ID

# Test permissions
gcloud projects get-iam-policy $PROJECT_ID --flatten="bindings[].members" --format="table(bindings.role)"
```

### Dangerous Permissions

```yaml
# Primitive roles (avoid)
roles/owner
roles/editor
roles/viewer

# Dangerous permissions
iam.serviceAccountKeys.create
iam.serviceAccounts.actAs
iam.serviceAccounts.getAccessToken
iam.serviceAccounts.implicitDelegation
storage.buckets.setIamPolicy
compute.instances.setMetadata
cloudfunctions.functions.create
```

## Cloud Storage Security

### Bucket Enumeration

```bash
# List buckets
gsutil ls

# Get bucket details
gsutil ls -L -b gs://$BUCKET

# Get bucket IAM policy
gsutil iam get gs://$BUCKET

# Check for public access
gsutil iam get gs://$BUCKET | grep allUsers
gsutil iam get gs://$BUCKET | grep allAuthenticatedUsers
```

### Bucket Access Testing

```bash
# List bucket contents (anonymous)
gsutil ls gs://$BUCKET
curl https://storage.googleapis.com/$BUCKET/

# Download object
gsutil cp gs://$BUCKET/$OBJECT ./local_file
curl https://storage.googleapis.com/$BUCKET/$OBJECT -o local_file

# Check uniform bucket-level access
gsutil uniformbucketlevelaccess get gs://$BUCKET
```

## Compute Security

### Instance Enumeration

```bash
# List instances
gcloud compute instances list

# Get instance details
gcloud compute instances describe $INSTANCE --zone=$ZONE

# Get instance metadata (from inside)
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/

# Get service account token (from inside)
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```

### Firewall Rules

```bash
# List firewall rules
gcloud compute firewall-rules list

# Get firewall rule details
gcloud compute firewall-rules describe $RULE

# Find open to internet
gcloud compute firewall-rules list --filter="sourceRanges:0.0.0.0/0"

# Find open SSH
gcloud compute firewall-rules list --filter="allowed[].ports:22 AND sourceRanges:0.0.0.0/0"
```

### Metadata Security

```bash
# Check if project-wide SSH keys enabled
gcloud compute project-info describe --format="value(commonInstanceMetadata.items)"

# Check instance metadata
gcloud compute instances describe $INSTANCE --zone=$ZONE --format="value(metadata.items)"

# Check for startup script (may contain secrets)
gcloud compute instances describe $INSTANCE --zone=$ZONE --format="value(metadata.items[startup-script])"
```

## Cloud Functions Security

### Function Enumeration

```bash
# List functions
gcloud functions list

# Get function details
gcloud functions describe $FUNCTION --region=$REGION

# Get function source
gcloud functions describe $FUNCTION --region=$REGION --format="value(sourceArchiveUrl)"

# Check invoker permissions
gcloud functions get-iam-policy $FUNCTION --region=$REGION
```

### Environment Variables

```bash
# Get environment variables (may contain secrets)
gcloud functions describe $FUNCTION --region=$REGION --format="value(environmentVariables)"
```

## Secret Manager

### Secret Enumeration

```bash
# List secrets
gcloud secrets list

# Get secret metadata
gcloud secrets describe $SECRET

# Access secret version
gcloud secrets versions access latest --secret=$SECRET

# List secret versions
gcloud secrets versions list $SECRET
```

## BigQuery Security

### Dataset Enumeration

```bash
# List datasets
bq ls

# Get dataset info
bq show $DATASET

# Get dataset access
bq show --format=prettyjson $DATASET | jq '.access'

# Check for public datasets
bq show --format=prettyjson $DATASET | jq '.access[] | select(.specialGroup=="allUsers" or .specialGroup=="allAuthenticatedUsers")'
```

## GKE Security

### Cluster Enumeration

```bash
# List clusters
gcloud container clusters list

# Get cluster credentials
gcloud container clusters get-credentials $CLUSTER --zone=$ZONE

# Check cluster config
gcloud container clusters describe $CLUSTER --zone=$ZONE

# Check for legacy ABAC
gcloud container clusters describe $CLUSTER --zone=$ZONE --format="value(legacyAbac)"

# Check private cluster
gcloud container clusters describe $CLUSTER --zone=$ZONE --format="value(privateClusterConfig)"
```

## Privilege Escalation Paths

### Via Service Account Key

```bash
# If can create service account key
gcloud iam service-accounts keys create key.json --iam-account=$SA_EMAIL
gcloud auth activate-service-account --key-file=key.json
```

### Via Impersonation

```bash
# If have iam.serviceAccounts.getAccessToken on target SA
gcloud auth print-access-token --impersonate-service-account=$TARGET_SA
```

### Via Compute Instance

```bash
# If can set metadata on instance with privileged SA
gcloud compute instances add-metadata $INSTANCE --metadata=startup-script='#!/bin/bash
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token > /tmp/token'
```

### Via Cloud Functions

```bash
# If can create/update functions with privileged SA
# Deploy function that returns SA token
```

## Quick Security Audit

```bash
# Run Prowler for GCP
prowler gcp

# Run ScoutSuite
scout gcp --project-id $PROJECT_ID

# Manual checks
gcloud projects get-iam-policy $PROJECT_ID
gsutil ls
gcloud compute firewall-rules list --filter="sourceRanges:0.0.0.0/0"
gcloud iam service-accounts list
```

## Common Misconfigurations

| Issue | Check Command |
|-------|---------------|
| Public Bucket | `gsutil iam get gs://$BUCKET | grep allUsers` |
| Open Firewall | `gcloud compute firewall-rules list --filter="sourceRanges:0.0.0.0/0"` |
| User-managed SA Keys | `gcloud iam service-accounts keys list --managed-by=user` |
| Primitive Roles | `gcloud projects get-iam-policy | grep roles/editor` |
| Public Functions | `gcloud functions get-iam-policy | grep allUsers` |
| Default SA Usage | Check compute instances using default SA |
