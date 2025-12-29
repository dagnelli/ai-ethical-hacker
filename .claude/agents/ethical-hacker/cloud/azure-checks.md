# Azure Security Checks

> *"Every subscription is a kingdom. Every misconfiguration is a door."*

## Azure AD Security

### User Enumeration

```bash
# List all users
az ad user list

# Get specific user
az ad user show --id $USER_ID

# List user group memberships
az ad user get-member-groups --id $USER_ID

# List global admins
az ad directory-role list --query "[?displayName=='Global Administrator'].{id:id}"
az ad directory-role member list --id $ROLE_ID
```

### Service Principal Enumeration

```bash
# List service principals
az ad sp list

# Get service principal details
az ad sp show --id $SP_ID

# List app registrations
az ad app list

# Check for secret expiration
az ad app credential list --id $APP_ID
```

### Role Assignments

```bash
# List role assignments
az role assignment list

# List role assignments for subscription
az role assignment list --subscription $SUB_ID

# List custom roles
az role definition list --custom-role-only

# Get role definition
az role definition list --name "Contributor"
```

## Storage Security

### Storage Account Enumeration

```bash
# List storage accounts
az storage account list

# Get storage account properties
az storage account show --name $ACCOUNT --resource-group $RG

# Check public access
az storage account show --name $ACCOUNT --query "allowBlobPublicAccess"

# List containers
az storage container list --account-name $ACCOUNT

# Check container access level
az storage container show --account-name $ACCOUNT --name $CONTAINER --query "properties.publicAccess"
```

### Blob Access Testing

```bash
# List blobs (if accessible)
az storage blob list --account-name $ACCOUNT --container-name $CONTAINER

# Download blob
az storage blob download --account-name $ACCOUNT --container-name $CONTAINER --name $BLOB --file ./downloaded

# Test anonymous access
curl https://$ACCOUNT.blob.core.windows.net/$CONTAINER/$BLOB
```

## Virtual Machine Security

### VM Enumeration

```bash
# List VMs
az vm list

# Get VM details
az vm show --name $VM --resource-group $RG

# List VM extensions
az vm extension list --vm-name $VM --resource-group $RG

# Get VM instance view
az vm get-instance-view --name $VM --resource-group $RG
```

### Network Security Groups

```bash
# List NSGs
az network nsg list

# Get NSG rules
az network nsg rule list --nsg-name $NSG --resource-group $RG

# Find open to internet
az network nsg rule list --nsg-name $NSG --resource-group $RG --query "[?sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet']"
```

## Key Vault Security

### Key Vault Enumeration

```bash
# List Key Vaults
az keyvault list

# Get Key Vault properties
az keyvault show --name $VAULT

# List secrets
az keyvault secret list --vault-name $VAULT

# Get secret value
az keyvault secret show --vault-name $VAULT --name $SECRET

# List keys
az keyvault key list --vault-name $VAULT

# List certificates
az keyvault certificate list --vault-name $VAULT
```

### Access Policies

```bash
# Get access policies
az keyvault show --name $VAULT --query "properties.accessPolicies"

# Check for overly permissive access
az keyvault show --name $VAULT --query "properties.accessPolicies[?permissions.secrets[?contains(@,'all')]]"
```

## Azure Functions

### Function Enumeration

```bash
# List function apps
az functionapp list

# Get function app settings
az functionapp config appsettings list --name $APP --resource-group $RG

# Get function details
az functionapp function list --name $APP --resource-group $RG
```

## Managed Identity

### Identity Enumeration

```bash
# List user-assigned identities
az identity list

# Check VM managed identity
az vm identity show --name $VM --resource-group $RG

# From inside VM - get token
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### Using Managed Identity Token

```bash
# Get token
TOKEN=$(curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r '.access_token')

# Use token
curl -H "Authorization: Bearer $TOKEN" "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

## Azure Resource Manager

### Resource Enumeration

```bash
# List all resources
az resource list

# List resources by type
az resource list --resource-type Microsoft.Compute/virtualMachines

# Export ARM template
az group export --name $RG
```

### Activity Log

```bash
# List activity logs
az monitor activity-log list --resource-group $RG

# Filter by operation
az monitor activity-log list --resource-group $RG --query "[?operationName.value=='Microsoft.Authorization/roleAssignments/write']"
```

## Privilege Escalation Paths

### Via Azure AD

```powershell
# If Global Admin or Privileged Role Administrator
# Assign yourself to higher roles

# Via Application Administrator
# Create app with high privileges
# Add credentials to existing apps
```

### Via Managed Identity

```bash
# If VM has managed identity with high privileges
# Access from compromised VM
# Use token to access other resources
```

### Via Automation Account

```bash
# If have access to Automation Account RunAs account
# Execute runbooks with elevated privileges
```

## Quick Security Audit

```bash
# Run Prowler for Azure
prowler azure

# Run ScoutSuite
scout azure --cli

# Manual checks
az account show
az role assignment list --all
az storage account list --query "[?allowBlobPublicAccess==true]"
az network nsg list --query "[].securityRules[?sourceAddressPrefix=='*']"
```

## Common Misconfigurations

| Issue | Check Command |
|-------|---------------|
| Public Storage | `az storage account show --query "allowBlobPublicAccess"` |
| Open NSG Rules | `az network nsg rule list` |
| No Key Vault Soft Delete | `az keyvault show --query "properties.enableSoftDelete"` |
| Excessive Role Assignments | `az role assignment list --all` |
| Unrotated Secrets | `az ad app credential list` |
| Unrestricted Management Ports | `az network nsg rule list` |
