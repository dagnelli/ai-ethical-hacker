# SKYBREAKER References

## Research Performed

### Searches Conducted
1. "AWS penetration testing methodology 2025"
2. "Azure AD security assessment"
3. "GCP privilege escalation paths"
4. "cloud IAM exploitation"
5. "container escape techniques 2025"
6. "Kubernetes pentest guide"
7. "SSRF to cloud metadata"
8. "serverless security testing"

## Primary Sources

### Cloud Security Frameworks

#### MITRE ATT&CK Cloud
- **Source**: https://attack.mitre.org/matrices/enterprise/cloud/
- **Description**: Cloud-specific attack techniques

#### CSA Cloud Controls Matrix
- **Source**: https://cloudsecurityalliance.org/research/cloud-controls-matrix/
- **Description**: Cloud security controls framework

### AWS Security

#### AWS Security Best Practices
- **Source**: https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/
- **Description**: AWS security guidance

#### Rhino Security Labs AWS Research
- **Source**: https://rhinosecuritylabs.com/aws/
- **Description**: AWS exploitation techniques

#### Pacu Documentation
- **Source**: https://github.com/RhinoSecurityLabs/pacu/wiki
- **Description**: AWS exploitation framework

### Azure Security

#### Microsoft Security Documentation
- **Source**: https://docs.microsoft.com/en-us/azure/security/
- **Description**: Azure security guidance

#### ROADtools
- **Source**: https://github.com/dirkjanm/ROADtools
- **Description**: Azure AD reconnaissance

#### SpecterOps Azure Research
- **Source**: https://posts.specterops.io/
- **Description**: Azure AD attack research

### GCP Security

#### GCP Security Best Practices
- **Source**: https://cloud.google.com/security/best-practices
- **Description**: GCP security guidance

#### GCP IAM Documentation
- **Source**: https://cloud.google.com/iam/docs
- **Description**: IAM reference

## Tool Documentation

### Multi-Cloud
| Tool | Documentation |
|------|---------------|
| ScoutSuite | https://github.com/nccgroup/ScoutSuite |
| Prowler | https://github.com/prowler-cloud/prowler |
| CloudFox | https://github.com/BishopFox/cloudfox |
| Trufflehog | https://github.com/trufflesecurity/trufflehog |

### AWS
| Tool | Documentation |
|------|---------------|
| AWS CLI | https://docs.aws.amazon.com/cli/ |
| Pacu | https://github.com/RhinoSecurityLabs/pacu |
| enumerate-iam | https://github.com/andresriancho/enumerate-iam |
| S3Scanner | https://github.com/sa7mon/S3Scanner |

### Azure
| Tool | Documentation |
|------|---------------|
| Azure CLI | https://docs.microsoft.com/en-us/cli/azure/ |
| ROADtools | https://github.com/dirkjanm/ROADtools |
| AzureHound | https://github.com/BloodHoundAD/AzureHound |
| MicroBurst | https://github.com/NetSPI/MicroBurst |

### GCP
| Tool | Documentation |
|------|---------------|
| gcloud CLI | https://cloud.google.com/sdk/gcloud |
| GCPBucketBrute | https://github.com/RhinoSecurityLabs/GCPBucketBrute |

### Kubernetes
| Tool | Documentation |
|------|---------------|
| kubectl | https://kubernetes.io/docs/reference/kubectl/ |
| kube-hunter | https://github.com/aquasecurity/kube-hunter |
| kubeaudit | https://github.com/Shopify/kubeaudit |
| Peirates | https://github.com/inguardians/peirates |

## Knowledge Resources

### HackTricks Cloud
- **Source**: https://cloud.hacktricks.xyz/
- **Description**: Cloud pentesting techniques

### Cloud Security Alliance
- **Source**: https://cloudsecurityalliance.org/
- **Description**: Cloud security research

### Hacking the Cloud
- **Source**: https://hackingthe.cloud/
- **Description**: Cloud attack techniques

## Research Papers & Blogs

### AWS
- Rhino Security Labs Blog
- Cloudar Security Blog
- AWS Security Blog

### Azure
- SpecterOps Posts
- NetSPI Blog
- Microsoft Security Response

### GCP
- Google Cloud Security Blog
- Praetorian Blog

## Training Resources

### Practice Labs
| Platform | URL | Focus |
|----------|-----|-------|
| CloudGoat | https://github.com/RhinoSecurityLabs/cloudgoat | AWS |
| AzureGoat | https://github.com/ine-labs/AzureGoat | Azure |
| GCPGoat | https://github.com/ine-labs/GCPGoat | GCP |
| Kubernetes Goat | https://madhuakula.com/kubernetes-goat/ | K8s |

### Certifications
- AWS Security Specialty
- Azure Security Engineer
- GCP Professional Cloud Security Engineer

## Cheat Sheets

| Topic | Source |
|-------|--------|
| AWS Pentest | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources/Cloud%20-%20AWS%20Pentest.md |
| Azure Pentest | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md |
| GCP Pentest | https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Methodology%20and%20Resources/Cloud%20-%20GCP%20Pentest.md |

## Version Information

| Tool | Version | Verified |
|------|---------|----------|
| Prowler | Latest | 2025-01 |
| ScoutSuite | Latest | 2025-01 |
| CloudFox | Latest | 2025-01 |
| Pacu | Latest | 2025-01 |

## Notes

- Cloud security requires understanding of IAM
- Metadata services are high-value targets
- Storage misconfigurations are common
- Service accounts/roles are key attack vectors
- Always verify testing is authorized
- Document all findings and access paths
