# ElastiCache Migration Auditor

Identifies which IAM users/roles will lose access when migrating ElastiCache clusters via DNS switch.

## Problem
When switching DNS from legacy to new ElastiCache cluster, IAM policies with hardcoded cluster ARNs break.

## What It Does
- Scans all IAM policies for hardcoded cluster ARNs
- Identifies high-risk principals (will lose access)
- Shows CloudTrail activity (who accessed clusters)
- Displays active resources (EC2/Lambda using ElastiCache)
- Provides migration recommendations

## Requirements
```bash
pip install boto3
aws configure  # Must have AWS credentials
```

## Usage
```bash
python3 migration_auditor.py
```

## Output
```
📊 CLUSTER CONNECTION METRICS
   - Current and peak connections for both clusters

🖥️  ACTIVE RESOURCES
   - EC2 instances, Lambda functions with ElastiCache access

🔍 IAM POLICY AUDIT
   - ⚠️ HIGH RISK: Principals with hardcoded ARNs
   - ✅ SAFE: Principals using wildcard (*)

📜 CLOUDTRAIL ANALYSIS
   - Who accessed ElastiCache in past 24 hours

🎯 MIGRATION RECOMMENDATIONS
   - Action items or migration readiness confirmation
```

## AWS Permissions Needed
- `iam:ListUsers`, `iam:ListRoles`, `iam:GetPolicy`
- `elasticache:DescribeCacheClusters`
- `cloudtrail:LookupEvents`
- `cloudwatch:GetMetricStatistics`
- `ec2:DescribeInstances`
- `lambda:ListFunctions`

## Configuration
Edit line 23 to change region:
```python
region_name='us-east-1'  # Change to your region
```

Edit lines 27-28 to change cluster names:
```python
for cluster_id in ['legacy-cache', 'new-cache']:  # Your cluster IDs
```

## Notes
- CloudTrail has 5-15 minute delay
- Script is read-only (no changes made)
- Standalone - no other files needed
