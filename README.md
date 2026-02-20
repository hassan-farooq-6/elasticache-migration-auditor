# ElastiCache Migration Auditor

Identifies which IAM users/roles will lose access when migrating ElastiCache clusters via DNS switch.

## Problem
When switching DNS from legacy ElastiCache cluster to a new one, IAM policies with hardcoded cluster ARNs break.

## What It Does
- Scans all IAM policies for hardcoded cluster ARNs
- Identifies high-risk principals (will lose access)
- Shows CloudTrail activity (who accessed clusters)
- Displays active resources (EC2/Lambda/ECS/EventBridge using ElastiCache)
- Detects indirect access (EventBridge triggering ECS/Lambda with Redis access)
- Provides migration recommendations

## Requirements
```bash
pip install boto3
aws configure  # Must have AWS credentials
```

## Configuration

**IMPORTANT:** Edit lines 11, 12 at the top of the script to match your environment:

```python
# ============================================================================
# CONFIGURATION - CHANGE THESE VALUES FOR YOUR ENVIRONMENT
# ============================================================================
AWS_REGION = 'us-east-1'  # Change to your AWS region (e.g., 'us-west-2', 'eu-west-1')
LEGACY_CLUSTER_ID = 'legacy-cache'  # Change to your cluster ID
# ============================================================================
```

**Example:**
```python
AWS_REGION = 'eu-west-1'
LEGACY_CLUSTER_ID = 'prod-redis-old'
```

## Usage

**Basic usage (default: 24 hours):**
```bash
python3 migration_auditor.py
```

**With custom duration (min: 3600s / 1 hour, max: 2592000s / 30 days):**
```bash
# Check last 1 hour (3600 seconds - minimum)
python3 migration_auditor.py --duration 3600

# Check last 12 hours (43200 seconds)
python3 migration_auditor.py --duration 43200

# Check last 7 days (604800 seconds)
python3 migration_auditor.py --duration 604800

# Check last 30 days (2592000 seconds - maximum)
python3 migration_auditor.py --duration 2592000
```

## Output
```
📊 CLUSTER CONNECTION METRICS
   - Current and peak connections for the cluster

🖥️  ACTIVE RESOURCES
   - EC2 instances, Lambda functions, API Gateway, Auto Scaling groups, ECS services
   - EventBridge rules triggering resources with Redis access
   - Detects both direct and indirect Redis access patterns

🔍 IAM POLICY AUDIT
   - ⚠️ HIGH RISK: Principals with hardcoded ARNs
   - ✅ SAFE: Principals using wildcard (*)

📜 CLOUDTRAIL ANALYSIS
   - ElastiCache API calls in the specified time period
   - Shows management operations (DescribeCacheClusters, ModifyCacheCluster, etc.)
   - Note: Data plane operations (GET/SET) are not logged by CloudTrail

🎯 MIGRATION RECOMMENDATIONS
   - Action items or migration readiness confirmation
```

## Detection Capabilities

### Direct Access Detection
- EC2 instances with IAM roles accessing ElastiCache/Secrets Manager
- Lambda functions with VPC access to Redis
- ECS services/tasks with Redis connectivity
- Auto Scaling groups with ElastiCache access

### Indirect Access Detection
- EventBridge rules triggering ECS tasks that access Redis
- EventBridge rules triggering Lambda functions with Redis access
- EventBridge rules triggering Step Functions with Redis access

### Access Pattern Detection
- IAM policies with ElastiCache permissions
- Secrets Manager access to Redis credentials
- VPC connectivity to ElastiCache clusters

## AWS Permissions Needed
- `iam:ListUsers`, `iam:ListRoles`, `iam:GetPolicy`, `iam:GetInstanceProfile`
- `elasticache:DescribeCacheClusters`
- `cloudtrail:LookupEvents`
- `cloudwatch:GetMetricStatistics`
- `ec2:DescribeInstances`
- `lambda:ListFunctions`, `lambda:GetFunction`
- `apigateway:GetRestApis`
- `autoscaling:DescribeAutoScalingGroups`
- `ecs:ListClusters`, `ecs:ListServices`, `ecs:DescribeServices`, `ecs:DescribeTaskDefinition`
- `events:ListRules`, `events:ListTargetsByRule`
- `secretsmanager:ListSecrets`
- `states:DescribeStateMachine` (for Step Functions detection)

## Notes
- CloudTrail has 5-15 minute delay
- CloudTrail only logs management API calls, not Redis data operations (GET/SET/PING)
- Script is read-only (no changes made)
- Standalone - no other files needed
- Detects both direct and indirect (orchestrated) Redis access patterns
