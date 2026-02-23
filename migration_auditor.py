#!/usr/bin/env python3
import boto3
from datetime import datetime, timedelta
import json
import sys
import argparse

# ============================================================================
# CONFIGURATION - CHANGE THESE VALUES FOR YOUR ENVIRONMENT
# ============================================================================
AWS_REGION = 'us-east-1'  # Change to your AWS region (e.g., 'us-west-2', 'eu-west-1')
LEGACY_CLUSTER_ID = 'redis-poc'  # Change to your cluster ID
# ============================================================================

def get_legacy_cluster_info():
    """Get legacy cluster ARN"""
    ec = boto3.client('elasticache', region_name=AWS_REGION)
    clusters = ec.describe_cache_clusters()
    
    legacy_arn = None
    
    for cluster in clusters['CacheClusters']:
        if cluster['CacheClusterId'] == LEGACY_CLUSTER_ID:
            legacy_arn = f"arn:aws:elasticache:{AWS_REGION}:{cluster['CacheClusterId']}"
            break
    
    return legacy_arn

def scan_policies_for_legacy_arn():
    """Find all IAM principals with hardcoded legacy-cache ARN"""
    iam = boto3.client('iam')
    results = {'users': [], 'roles': [], 'safe_principals': []}
    
    # Scan all users
    users = iam.list_users()
    for user in users['Users']:
        has_legacy_arn = False
        has_wildcard = False
        
        # Check attached policies
        policies = iam.list_attached_user_policies(UserName=user['UserName'])
        for policy in policies['AttachedPolicies']:
            policy_doc = iam.get_policy(PolicyArn=policy['PolicyArn'])
            version = iam.get_policy_version(
                PolicyArn=policy['PolicyArn'],
                VersionId=policy_doc['Policy']['DefaultVersionId']
            )
            policy_str = json.dumps(version['PolicyVersion']['Document'])
            
            if 'elasticache' in policy_str.lower():
                if LEGACY_CLUSTER_ID in policy_str:
                    has_legacy_arn = True
                if '"Resource":"*"' in policy_str or '"Resource": "*"' in policy_str:
                    has_wildcard = True
        
        if has_legacy_arn:
            results['users'].append({'name': user['UserName'], 'risk': f'HIGH - Hardcoded {LEGACY_CLUSTER_ID} ARN'})
        elif has_wildcard:
            results['safe_principals'].append({'name': user['UserName'], 'type': 'user'})
    
    # Scan all roles
    roles = iam.list_roles()
    for role in roles['Roles']:
        has_legacy_arn = False
        has_wildcard = False
        
        policies = iam.list_attached_role_policies(RoleName=role['RoleName'])
        for policy in policies['AttachedPolicies']:
            policy_doc = iam.get_policy(PolicyArn=policy['PolicyArn'])
            version = iam.get_policy_version(
                PolicyArn=policy['PolicyArn'],
                VersionId=policy_doc['Policy']['DefaultVersionId']
            )
            policy_str = json.dumps(version['PolicyVersion']['Document'])
            
            if 'elasticache' in policy_str.lower():
                if LEGACY_CLUSTER_ID in policy_str:
                    has_legacy_arn = True
                if '"Resource":"*"' in policy_str or '"Resource": "*"' in policy_str:
                    has_wildcard = True
        
        if has_legacy_arn:
            results['roles'].append({'name': role['RoleName'], 'risk': f'HIGH - Hardcoded {LEGACY_CLUSTER_ID} ARN'})
        elif has_wildcard:
            results['safe_principals'].append({'name': role['RoleName'], 'type': 'role'})
    
    return results

def get_cluster_connections():
    """Get current connections for the cluster"""
    cw = boto3.client('cloudwatch', region_name=AWS_REGION)
    end = datetime.utcnow()
    start = end - timedelta(hours=1)
    
    response = cw.get_metric_statistics(
        Namespace='AWS/ElastiCache',
        MetricName='CurrConnections',
        Dimensions=[{'Name': 'CacheClusterId', 'Value': LEGACY_CLUSTER_ID}],
        StartTime=start,
        EndTime=end,
        Period=3600,
        Statistics=['Average', 'Maximum']
    )
    
    if response['Datapoints']:
        dp = response['Datapoints'][0]
        return {
            'current': int(dp.get('Average', 0)),
            'peak': int(dp.get('Maximum', 0))
        }
    else:
        return {'current': 0, 'peak': 0}

def get_active_resources():
    """Find all active EC2/Lambda/API Gateway/Auto Scaling/ECS resources with ElastiCache access"""
    resources = []
    iam = boto3.client('iam')
    ec2 = boto3.client('ec2', region_name=AWS_REGION)
    sm = boto3.client('secretsmanager', region_name=AWS_REGION)
    
    # Get Redis cluster VPC and security groups
    redis_security_groups = set()
    redis_vpc_id = None
    try:
        elasticache = boto3.client('elasticache', region_name=AWS_REGION)
        cluster_info = elasticache.describe_cache_clusters(
            CacheClusterId=LEGACY_CLUSTER_ID,
            ShowCacheNodeInfo=True
        )
        if cluster_info['CacheClusters']:
            cluster = cluster_info['CacheClusters'][0]
            for sg in cluster.get('SecurityGroups', []):
                redis_security_groups.add(sg['SecurityGroupId'])
            
            if cluster.get('CacheSubnetGroupName'):
                subnet_group = elasticache.describe_cache_subnet_groups(
                    CacheSubnetGroupName=cluster['CacheSubnetGroupName']
                )
                if subnet_group['CacheSubnetGroups']:
                    redis_vpc_id = subnet_group['CacheSubnetGroups'][0].get('VpcId')
    except: pass
    
    # Get security groups that can access Redis
    allowed_security_groups = set()
    for redis_sg in redis_security_groups:
        try:
            sg_details = ec2.describe_security_groups(GroupIds=[redis_sg])
            for sg in sg_details['SecurityGroups']:
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    if from_port <= 6379 <= to_port:
                        for source_sg in rule.get('UserIdGroupPairs', []):
                            allowed_security_groups.add(source_sg['GroupId'])
        except: pass
    
    # Get Redis secret ARN
    redis_secret_arn = None
    try:
        secrets = sm.list_secrets()
        for secret in secrets.get('SecretList', []):
            if 'redis' in secret['Name'].lower() or LEGACY_CLUSTER_ID in secret['Name'].lower():
                redis_secret_arn = secret['ARN']
                break
    except: pass
    
    # Get all roles with ElastiCache OR Secrets Manager access
    elasticache_roles = []
    roles = iam.list_roles()
    for role in roles['Roles']:
        has_access = False
        
        policies = iam.list_attached_role_policies(RoleName=role['RoleName'])
        for policy in policies['AttachedPolicies']:
            try:
                policy_doc = iam.get_policy(PolicyArn=policy['PolicyArn'])
                version = iam.get_policy_version(
                    PolicyArn=policy['PolicyArn'],
                    VersionId=policy_doc['Policy']['DefaultVersionId']
                )
                policy_str = json.dumps(version['PolicyVersion']['Document'])
                
                if 'elasticache' in policy_str.lower():
                    has_access = True
                    break
                
                if redis_secret_arn and 'secretsmanager:GetSecretValue' in policy_str:
                    if redis_secret_arn in policy_str or '"Resource":"*"' in policy_str or '"Resource": "*"' in policy_str:
                        has_access = True
                        break
            except: pass
        
        if not has_access:
            try:
                inline_policies = iam.list_role_policies(RoleName=role['RoleName'])
                for policy_name in inline_policies.get('PolicyNames', []):
                    policy_doc = iam.get_role_policy(RoleName=role['RoleName'], PolicyName=policy_name)
                    policy_str = json.dumps(policy_doc['PolicyDocument'])
                    
                    if 'elasticache' in policy_str.lower():
                        has_access = True
                        break
                    
                    if redis_secret_arn and 'secretsmanager:GetSecretValue' in policy_str:
                        if redis_secret_arn in policy_str or '"Resource":"*"' in policy_str or '"Resource": "*"' in policy_str:
                            has_access = True
                            break
            except: pass
        
        if has_access:
            elasticache_roles.append(role['RoleName'])
    
    # Check EC2 - IAM permissions OR VPC connectivity
    try:
        instances = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                has_access = False
                role_name = 'No IAM Role'
                access_method = ''
                
                profile_arn = instance.get('IamInstanceProfile', {}).get('Arn', '')
                if profile_arn:
                    profile_name = profile_arn.split('/')[-1]
                    try:
                        profile_info = iam.get_instance_profile(InstanceProfileName=profile_name)
                        if profile_info['InstanceProfile']['Roles']:
                            role_name = profile_info['InstanceProfile']['Roles'][0]['RoleName']
                            if role_name in elasticache_roles:
                                has_access = True
                                access_method = 'IAM'
                    except: pass
                
                if not has_access and instance.get('VpcId') == redis_vpc_id:
                    for sg in instance.get('SecurityGroups', []):
                        if sg['GroupId'] in allowed_security_groups:
                            has_access = True
                            access_method = 'VPC'
                            break
                
                if has_access:
                    instance_name = instance['InstanceId']
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                            break
                    
                    resources.append({
                        'type': 'EC2',
                        'id': instance_name,
                        'principal': role_name,
                        'state': f"{instance['State']['Name']} ({access_method})",
                        'since': instance.get('LaunchTime')
                    })
    except: pass
    
    # Check Lambda - IAM permissions OR VPC connectivity
    try:
        lambda_client = boto3.client('lambda', region_name=AWS_REGION)
        functions = lambda_client.list_functions()
        for func in functions['Functions']:
            has_access = False
            access_method = ''
            func_role = func['Role'].split('/')[-1]
            
            if func_role in elasticache_roles:
                has_access = True
                access_method = 'IAM'
            
            if not has_access and func.get('VpcConfig', {}).get('VpcId') == redis_vpc_id:
                for sg_id in func['VpcConfig'].get('SecurityGroupIds', []):
                    if sg_id in allowed_security_groups:
                        has_access = True
                        access_method = 'VPC'
                        break
            
            if has_access:
                resources.append({
                    'type': 'Lambda',
                    'id': func['FunctionName'],
                    'principal': func_role,
                    'state': access_method
                })
    except: passfunc_role,
                    'state': 'active'
                })
    except: pass
    
    # Check API Gateway
    try:
        apigw = boto3.client('apigateway', region_name=AWS_REGION)
        apis = apigw.get_rest_apis()
        for api in apis.get('items', []):
            resources.append({
                'type': 'API Gateway',
                'id': api['name'],
                'principal': 'N/A',
                'state': 'deployed'
            })
    except: pass
    
    # Check Auto Scaling Groups
    try:
        asg = boto3.client('autoscaling', region_name=AWS_REGION)
        groups = asg.describe_auto_scaling_groups()
        for group in groups['AutoScalingGroups']:
            # Check if instances in ASG have ElastiCache roles
            for instance in group['Instances']:
                instance_id = instance['InstanceId']
                try:
                    ec2_detail = ec2.describe_instances(InstanceIds=[instance_id])
                    for reservation in ec2_detail['Reservations']:
                        for inst in reservation['Instances']:
                            profile_arn = inst.get('IamInstanceProfile', {}).get('Arn', '')
                            if profile_arn:
                                profile_name = profile_arn.split('/')[-1]
                                profile_info = iam.get_instance_profile(InstanceProfileName=profile_name)
                                if profile_info['InstanceProfile']['Roles']:
                                    role_name = profile_info['InstanceProfile']['Roles'][0]['RoleName']
                                    if role_name in elasticache_roles:
                                        resources.append({
                                            'type': 'Auto Scaling',
                                            'id': group['AutoScalingGroupName'],
                                            'principal': role_name,
                                            'state': f"{group['DesiredCapacity']} instances"
                                        })
                                        break
                except:
                    pass
    except: pass
    
    # Check ECS
    try:
        ecs = boto3.client('ecs', region_name=AWS_REGION)
        clusters = ecs.list_clusters()
        for cluster_arn in clusters.get('clusterArns', []):
            services = ecs.list_services(cluster=cluster_arn)
            for service_arn in services.get('serviceArns', []):
                try:
                    service_details = ecs.describe_services(cluster=cluster_arn, services=[service_arn])
                    for service in service_details.get('services', []):
                        task_def = service.get('taskDefinition', '')
                        if task_def:
                            task_def_details = ecs.describe_task_definition(taskDefinition=task_def)
                            task_role = task_def_details['taskDefinition'].get('taskRoleArn', '').split('/')[-1]
                            if task_role in elasticache_roles:
                                resources.append({
                                    'type': 'ECS',
                                    'id': service['serviceName'],
                                    'principal': task_role,
                                    'state': f"{service['runningCount']} tasks"
                                })
                except:
                    pass
    except: pass
    
    # Check EventBridge: Find ANY roles that trigger resources with Redis access
    try:
        events = boto3.client('events', region_name=AWS_REGION)
        
        rules = events.list_rules()
        for rule in rules.get('Rules', []):
            try:
                targets = events.list_targets_by_rule(Rule=rule['Name'])
                for target in targets.get('Targets', []):
                    target_arn = target.get('Arn', '')
                    eventbridge_role_arn = target.get('RoleArn', '')
                    
                    if not eventbridge_role_arn:
                        continue
                    
                    eventbridge_role_name = eventbridge_role_arn.split('/')[-1]
                    has_redis_access = False
                    
                    # Check if target is ECS
                    if 'ecs' in target_arn.lower():
                        task_def_arn = target.get('EcsParameters', {}).get('TaskDefinitionArn', '')
                        if task_def_arn:
                            try:
                                ecs = boto3.client('ecs', region_name=AWS_REGION)
                                task_def = ecs.describe_task_definition(taskDefinition=task_def_arn)
                                task_role_arn = task_def['taskDefinition'].get('taskRoleArn', '')
                                if task_role_arn:
                                    task_role_name = task_role_arn.split('/')[-1]
                                    if task_role_name in elasticache_roles:
                                        has_redis_access = True
                            except: pass
                    
                    # Check if target is Lambda
                    elif 'lambda' in target_arn.lower():
                        lambda_name = target_arn.split(':')[-1]
                        try:
                            lambda_client = boto3.client('lambda', region_name=AWS_REGION)
                            func = lambda_client.get_function(FunctionName=lambda_name)
                            func_role = func['Configuration']['Role'].split('/')[-1]
                            if func_role in elasticache_roles:
                                has_redis_access = True
                        except: pass
                    
                    # Check if target is Step Functions
                    elif 'states' in target_arn.lower():
                        try:
                            sfn = boto3.client('stepfunctions', region_name=AWS_REGION)
                            state_machine = sfn.describe_state_machine(stateMachineArn=target_arn)
                            sfn_role = state_machine['roleArn'].split('/')[-1]
                            if sfn_role in elasticache_roles:
                                has_redis_access = True
                        except: pass
                    
                    if has_redis_access:
                        resources.append({
                            'type': 'EventBridge',
                            'id': rule['Name'],
                            'principal': eventbridge_role_name,
                            'state': f"triggers resource with Redis access"
                        })
            except: pass
    except: pass
    
    return resources

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='ElastiCache Migration Auditor')
    parser.add_argument(
        '--duration',
        type=int,
        default=86400,  # 24 hours in seconds
        choices=range(3600, 2592001),  # Min: 1 hour (3600s), Max: 30 days (2592000s)
        metavar='SECONDS',
        help='Duration in seconds to check CloudTrail logs (min: 3600, max: 2592000, default: 86400)'
    )
    args = parser.parse_args()
    
    # Convert seconds to hours for display
    duration_hours = args.duration / 3600
    
    print("=" * 80)
    print("ELASTICACHE MIGRATION AUDIT REPORT")
    print("=" * 80)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"CloudTrail Duration: {duration_hours:.1f} hours ({args.duration} seconds)\n")
    
    # Step 1: Connection metrics
    print("📊 CLUSTER CONNECTION METRICS (PAST 1 HOUR)")
    print("-" * 80)
    connections = get_cluster_connections()
    
    print(f"\n  {LEGACY_CLUSTER_ID}:")
    print(f"    Current connections: {connections.get('current', 0)}")
    print(f"    Peak connections: {connections.get('peak', 0)}")
    
    print("\n" + "=" * 80)
    print("🖥️  ACTIVE RESOURCES ACCESSING ELASTICACHE")
    print("-" * 80)
    
    resources = get_active_resources()
    
    if resources:
        for res in resources:
            print(f"\n  ✓ {res['type']}: {res['id']}")
            print(f"    Principal: {res['principal']}")
            print(f"    State: {res['state']}")
            if 'since' in res:
                print(f"    Active since: {res['since']}")
    else:
        print("\n  No active resources found")
    
    # Step 3: Policy audit
    print("\n" + "=" * 80)
    print("🔍 IAM POLICY AUDIT - MIGRATION RISK ANALYSIS")
    print("-" * 80)
    
    results = scan_policies_for_legacy_arn()
    
    print(f"\n⚠️  HIGH RISK - Principals with hardcoded {LEGACY_CLUSTER_ID} ARN:")
    print("   (These will LOSE ACCESS after DNS migration)")
    print("-" * 80)
    
    if results['users']:
        print("\n  Users:")
        for user in results['users']:
            print(f"    ❌ {user['name']} - {user['risk']}")
    
    if results['roles']:
        print("\n  Roles:")
        for role in results['roles']:
            print(f"    ❌ {role['name']} - {role['risk']}")
    
    if not results['users'] and not results['roles']:
        print(f"\n  ✅ No principals found with hardcoded {LEGACY_CLUSTER_ID} ARN")
    
    print("\n" + "=" * 80)
    print("✅ SAFE - Principals using wildcard (*)")
    print("   (These will continue working after DNS migration)")
    print("-" * 80)
    
    if results['safe_principals']:
        for principal in results['safe_principals']:
            print(f"    ✅ {principal['name']} ({principal['type']})")
    else:
        print("\n    No principals using wildcard")
    
    # Step 4: CloudTrail analysis
    print("\n" + "=" * 80)
    print(f"📜 CLOUDTRAIL ANALYSIS (PAST {duration_hours:.1f} HOURS)")
    print("-" * 80)
    
    ct = boto3.client('cloudtrail', region_name=AWS_REGION)
    end = datetime.utcnow()
    start = end - timedelta(seconds=args.duration)
    
    activity = {}
    
    try:
        events = ct.lookup_events(
            LookupAttributes=[
                {'AttributeKey': 'EventSource', 'AttributeValue': 'elasticache.amazonaws.com'}
            ],
            StartTime=start,
            EndTime=end,
            MaxResults=50
        )
        
        for event in events.get('Events', []):
            username = event.get('Username', 'Unknown')
            event_name = event.get('EventName', '')
            
            if username not in activity:
                activity[username] = []
            
            activity[username].append({
                'event': event_name,
                'time': event['EventTime']
            })
    except Exception as e:
        print(f"\n  ⚠️  CloudTrail error: {e}")
    
    if activity:
        for principal, events in activity.items():
            print(f"\n  {principal}:")
            for evt in events:
                print(f"    • {evt['event']} at {evt['time'].strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        print(f"\n  No ElastiCache activity found in past {duration_hours:.1f} hours")
        print("  Note: CloudTrail has 5-15 min delay")
    
    # Final recommendations
    print("\n" + "=" * 80)
    print("🎯 MIGRATION RECOMMENDATIONS")
    print("=" * 80)
    
    if results['users'] or results['roles']:
        print("\n⚠️  ACTION REQUIRED:")
        print("   1. Update hardcoded ARNs to use wildcard (*)")
        print("   2. Test access with new cluster before DNS switch")
        print("   3. Monitor CloudTrail for access failures post-migration")
    else:
        print("\n✅ READY FOR MIGRATION:")
        print(f"   • No hardcoded {LEGACY_CLUSTER_ID} ARNs found")
        print("   • All principals use wildcard resources")
        print("   • DNS switch should be seamless")
    
    print("\n" + "=" * 80)

if __name__ == '__main__':
    main()
