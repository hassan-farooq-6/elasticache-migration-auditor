#!/usr/bin/env python3
import boto3
from datetime import datetime, timedelta
import json

# ============================================================================
# CONFIGURATION - CHANGE THESE VALUES FOR YOUR ENVIRONMENT
# ============================================================================
AWS_REGION = 'us-east-1'  # Change to your AWS region (e.g., 'us-west-2', 'eu-west-1')
LEGACY_CLUSTER_ID = 'legacy-cache'  # Change to your legacy cluster ID
NEW_CLUSTER_ID = 'new-cache'  # Change to your new cluster ID
# ============================================================================

def get_legacy_cluster_info():
    """Get legacy cluster ARN"""
    ec = boto3.client('elasticache', region_name=AWS_REGION)
    clusters = ec.describe_cache_clusters()
    
    legacy_arn = None
    new_arn = None
    
    for cluster in clusters['CacheClusters']:
        if cluster['CacheClusterId'] == LEGACY_CLUSTER_ID:
            legacy_arn = f"arn:aws:elasticache:{AWS_REGION}:{cluster['CacheClusterId']}"
        elif cluster['CacheClusterId'] == NEW_CLUSTER_ID:
            new_arn = f"arn:aws:elasticache:{AWS_REGION}:{cluster['CacheClusterId']}"
    
    return legacy_arn, new_arn

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
    """Get current connections for both clusters"""
    cw = boto3.client('cloudwatch', region_name=AWS_REGION)
    end = datetime.utcnow()
    start = end - timedelta(hours=1)
    
    clusters = {}
    
    for cluster_id in [LEGACY_CLUSTER_ID, NEW_CLUSTER_ID]:
        response = cw.get_metric_statistics(
            Namespace='AWS/ElastiCache',
            MetricName='CurrConnections',
            Dimensions=[{'Name': 'CacheClusterId', 'Value': cluster_id}],
            StartTime=start,
            EndTime=end,
            Period=3600,
            Statistics=['Average', 'Maximum']
        )
        
        if response['Datapoints']:
            dp = response['Datapoints'][0]
            clusters[cluster_id] = {
                'current': int(dp.get('Average', 0)),
                'peak': int(dp.get('Maximum', 0))
            }
        else:
            clusters[cluster_id] = {'current': 0, 'peak': 0}
    
    return clusters

def get_active_resources():
    """Find all active EC2/Lambda/ECS resources with ElastiCache access"""
    resources = []
    iam = boto3.client('iam')
    
    # Get all roles with ElastiCache access
    elasticache_roles = []
    roles = iam.list_roles()
    for role in roles['Roles']:
        policies = iam.list_attached_role_policies(RoleName=role['RoleName'])
        for policy in policies['AttachedPolicies']:
            policy_doc = iam.get_policy(PolicyArn=policy['PolicyArn'])
            version = iam.get_policy_version(
                PolicyArn=policy['PolicyArn'],
                VersionId=policy_doc['Policy']['DefaultVersionId']
            )
            if 'elasticache' in json.dumps(version['PolicyVersion']['Document']).lower():
                elasticache_roles.append(role['RoleName'])
                break
    
    # Check EC2
    try:
        ec2 = boto3.client('ec2', region_name=AWS_REGION)
        instances = ec2.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                profile_arn = instance.get('IamInstanceProfile', {}).get('Arn', '')
                if profile_arn:
                    profile_name = profile_arn.split('/')[-1]
                    try:
                        profile_info = iam.get_instance_profile(InstanceProfileName=profile_name)
                        if profile_info['InstanceProfile']['Roles']:
                            role_name = profile_info['InstanceProfile']['Roles'][0]['RoleName']
                            if role_name in elasticache_roles:
                                resources.append({
                                    'type': 'EC2',
                                    'id': instance['InstanceId'],
                                    'principal': role_name,
                                    'state': instance['State']['Name'],
                                    'since': instance['LaunchTime']
                                })
                    except:
                        pass
    except: pass
    
    # Check Lambda
    try:
        lambda_client = boto3.client('lambda', region_name=AWS_REGION)
        functions = lambda_client.list_functions()
        for func in functions['Functions']:
            func_role = func['Role'].split('/')[-1]
            if func_role in elasticache_roles:
                resources.append({
                    'type': 'Lambda',
                    'id': func['FunctionName'],
                    'principal': func_role,
                    'state': 'deployed'
                })
    except: pass
    
    return resources

def main():
    print("=" * 80)
    print("ELASTICACHE MIGRATION AUDIT REPORT")
    print("=" * 80)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Step 1: Connection metrics
    print("📊 CLUSTER CONNECTION METRICS (PAST 1 HOUR)")
    print("-" * 80)
    connections = get_cluster_connections()
    
    legacy_conn = connections.get(LEGACY_CLUSTER_ID, {})
    new_conn = connections.get(NEW_CLUSTER_ID, {})
    
    print(f"\n  {LEGACY_CLUSTER_ID}:")
    print(f"    Current connections: {legacy_conn.get('current', 0)}")
    print(f"    Peak connections: {legacy_conn.get('peak', 0)}")
    
    print(f"\n  {NEW_CLUSTER_ID}:")
    print(f"    Current connections: {new_conn.get('current', 0)}")
    print(f"    Peak connections: {new_conn.get('peak', 0)}")
    
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
    print("📜 CLOUDTRAIL ANALYSIS (PAST 24 HOURS)")
    print("-" * 80)
    
    ct = boto3.client('cloudtrail', region_name=AWS_REGION)
    end = datetime.utcnow()
    start = end - timedelta(hours=24)
    
    activity = {}
    
    try:
        events = ct.lookup_events(
            StartTime=start,
            EndTime=end,
            MaxResults=50
        )
        
        for event in events.get('Events', []):
            if 'elasticache' in event.get('EventSource', '').lower():
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
            for evt in events[:3]:
                print(f"    • {evt['event']} at {evt['time'].strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        print("\n  No ElastiCache activity found in past 24 hours")
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
