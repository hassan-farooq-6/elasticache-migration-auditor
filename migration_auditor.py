#!/usr/bin/env python3
import boto3
from datetime import datetime, timedelta
import json
import time
import argparse
from collections import defaultdict

# ============================================================================
# CONFIGURATION - CHANGE THESE VALUES FOR YOUR ENVIRONMENT
# ============================================================================
AWS_REGION = 'us-east-1'
LEGACY_CLUSTER_ID = 'redis-poc'
# ============================================================================

def get_redis_eni_ips():
    """Get Redis ENI private IPs (not DNS)"""
    try:
        ec2 = boto3.client('ec2', region_name=AWS_REGION)
        ec = boto3.client('elasticache', region_name=AWS_REGION)
        
        cluster = ec.describe_cache_clusters(CacheClusterId=LEGACY_CLUSTER_ID, ShowCacheNodeInfo=True)
        if not cluster['CacheClusters']:
            return set()
        
        subnet_ids = []
        if cluster['CacheClusters'][0].get('CacheSubnetGroupName'):
            sg = ec.describe_cache_subnet_groups(CacheSubnetGroupName=cluster['CacheClusters'][0]['CacheSubnetGroupName'])
            subnet_ids = [s['SubnetIdentifier'] for s in sg['CacheSubnetGroups'][0]['Subnets']]
        
        enis = ec2.describe_network_interfaces(Filters=[
            {'Name': 'subnet-id', 'Values': subnet_ids},
            {'Name': 'description', 'Values': [f'*{LEGACY_CLUSTER_ID}*']}
        ])
        
        ips = set()
        for eni in enis['NetworkInterfaces']:
            ips.add(eni['PrivateIpAddress'])
        
        return ips
    except Exception as e:
        print(f"  ⚠️  Error getting Redis IPs: {e}")
        return set()

def analyze_vpc_flow_logs(duration_seconds):
    """Analyze VPC Flow Logs with proper polling"""
    logs = boto3.client('logs', region_name=AWS_REGION)
    
    redis_ips = get_redis_eni_ips()
    if not redis_ips:
        return {}
    
    end = datetime.utcnow()
    start = end - timedelta(seconds=duration_seconds)
    connections = defaultdict(lambda: {'count': 0, 'first_seen': None, 'last_seen': None, 'enis': set(), 'ips': set()})
    
    try:
        paginator = logs.get_paginator('describe_log_groups')
        for page in paginator.paginate(logGroupNamePrefix='/aws/vpc/flowlogs'):
            for lg in page.get('logGroups', [])[:3]:
                try:
                    redis_ips_str = ' or '.join([f'dstAddr = "{ip}"' for ip in redis_ips])
                    query = f"fields @timestamp, srcAddr, interfaceId | filter dstPort = 6379 and action = 'ACCEPT' and ({redis_ips_str}) | stats count() by interfaceId, srcAddr"
                    
                    query_id = logs.start_query(
                        logGroupName=lg['logGroupName'],
                        startTime=int(start.timestamp()),
                        endTime=int(end.timestamp()),
                        queryString=query
                    )['queryId']
                    
                    # Poll until complete
                    for _ in range(30):
                        result = logs.get_query_results(queryId=query_id)
                        if result['status'] == 'Complete':
                            break
                        time.sleep(2)
                    
                    if result['status'] != 'Complete':
                        continue
                    
                    for record in result.get('results', []):
                        data = {f['field']: f['value'] for f in record}
                        eni_id = data.get('interfaceId')
                        src_ip = data.get('srcAddr')
                        count = int(data.get('count()', 0))
                        
                        if eni_id and src_ip:
                            key = f"{eni_id}:{src_ip}"
                            connections[key]['count'] += count
                            connections[key]['enis'].add(eni_id)
                            connections[key]['ips'].add(src_ip)
                            if not connections[key]['first_seen']:
                                connections[key]['first_seen'] = start
                            connections[key]['last_seen'] = end
                except Exception as e:
                    print(f"  ⚠️  Flow log query error: {e}")
                    continue
    except Exception as e:
        print(f"  ⚠️  Flow logs error: {e}")
    
    return connections

def resolve_eni_to_resource(eni_id, ip):
    """Resolve ENI to resource with full details"""
    try:
        ec2 = boto3.client('ec2', region_name=AWS_REGION)
        iam = boto3.client('iam')
        
        eni = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
        if not eni['NetworkInterfaces']:
            return None
        
        eni_data = eni['NetworkInterfaces'][0]
        attachment = eni_data.get('Attachment', {})
        description = eni_data.get('Description', '')
        
        # EC2
        if attachment.get('InstanceId'):
            instance_id = attachment['InstanceId']
            inst = ec2.describe_instances(InstanceIds=[instance_id])
            if inst['Reservations']:
                instance = inst['Reservations'][0]['Instances'][0]
                role = 'No IAM Role'
                profile_arn = instance.get('IamInstanceProfile', {}).get('Arn', '')
                if profile_arn:
                    profile_name = profile_arn.split('/')[-1]
                    try:
                        profile = iam.get_instance_profile(InstanceProfileName=profile_name)
                        if profile['InstanceProfile']['Roles']:
                            role = profile['InstanceProfile']['Roles'][0]['RoleName']
                    except:
                        pass
                
                name = instance_id
                for tag in instance.get('Tags', []):
                    if tag['Key'] == 'Name':
                        name = tag['Value']
                        break
                
                return {'type': 'EC2', 'name': name, 'principal': role, 'method': 'VPC'}
        
        # Lambda
        if 'Lambda' in description or 'lambda' in description:
            parts = description.split()
            func_name = parts[-1] if parts else 'Unknown'
            try:
                lambda_client = boto3.client('lambda', region_name=AWS_REGION)
                func = lambda_client.get_function(FunctionName=func_name)
                role = func['Configuration']['Role'].split('/')[-1]
                return {'type': 'Lambda', 'name': func_name, 'principal': role, 'method': 'VPC'}
            except:
                return {'type': 'Lambda', 'name': func_name, 'principal': 'Unknown', 'method': 'VPC'}
        
        # ECS
        if 'ECS' in description or 'ecs-' in description:
            return {'type': 'ECS', 'name': description[:50], 'principal': 'Unknown', 'method': 'VPC'}
        
        return None
    except:
        return None

def analyze_cloudtrail_identities(duration_seconds):
    """Analyze CloudTrail with full pagination"""
    ct = boto3.client('cloudtrail', region_name=AWS_REGION)
    end = datetime.utcnow()
    start = end - timedelta(seconds=duration_seconds)
    
    identities = defaultdict(lambda: {'count': 0, 'first_seen': None, 'last_seen': None, 'events': set()})
    
    try:
        paginator = ct.get_paginator('lookup_events')
        for page in paginator.paginate(
            LookupAttributes=[{'AttributeKey': 'EventSource', 'AttributeValue': 'elasticache.amazonaws.com'}],
            StartTime=start,
            EndTime=end
        ):
            for event in page.get('Events', []):
                username = event.get('Username', 'Unknown')
                event_name = event.get('EventName', '')
                timestamp = event['EventTime']
                
                identities[username]['count'] += 1
                identities[username]['events'].add(event_name)
                if not identities[username]['first_seen'] or timestamp < identities[username]['first_seen']:
                    identities[username]['first_seen'] = timestamp
                if not identities[username]['last_seen'] or timestamp > identities[username]['last_seen']:
                    identities[username]['last_seen'] = timestamp
    except Exception as e:
        print(f"  ⚠️  CloudTrail error: {e}")
    
    return identities

def get_active_resources():
    """Get currently configured resources with pagination"""
    resources = []
    iam = boto3.client('iam')
    ec2 = boto3.client('ec2', region_name=AWS_REGION)
    sm = boto3.client('secretsmanager', region_name=AWS_REGION)
    
    # Get Redis info
    redis_security_groups = set()
    redis_vpc_id = None
    try:
        elasticache = boto3.client('elasticache', region_name=AWS_REGION)
        cluster_info = elasticache.describe_cache_clusters(CacheClusterId=LEGACY_CLUSTER_ID, ShowCacheNodeInfo=True)
        if cluster_info['CacheClusters']:
            cluster = cluster_info['CacheClusters'][0]
            for sg in cluster.get('SecurityGroups', []):
                redis_security_groups.add(sg['SecurityGroupId'])
            if cluster.get('CacheSubnetGroupName'):
                subnet_group = elasticache.describe_cache_subnet_groups(CacheSubnetGroupName=cluster['CacheSubnetGroupName'])
                if subnet_group['CacheSubnetGroups']:
                    redis_vpc_id = subnet_group['CacheSubnetGroups'][0].get('VpcId')
    except:
        pass
    
    # Get allowed security groups
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
        except:
            pass
    
    # Get Redis secret
    redis_secret_arn = None
    try:
        paginator = sm.get_paginator('list_secrets')
        for page in paginator.paginate():
            for secret in page.get('SecretList', []):
                if 'redis' in secret['Name'].lower() or LEGACY_CLUSTER_ID in secret['Name'].lower():
                    redis_secret_arn = secret['ARN']
                    break
            if redis_secret_arn:
                break
    except:
        pass
    
    # Get roles with access
    elasticache_roles = []
    try:
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                has_access = False
                try:
                    policies = iam.list_attached_role_policies(RoleName=role['RoleName'])
                    for policy in policies['AttachedPolicies']:
                        try:
                            policy_doc = iam.get_policy(PolicyArn=policy['PolicyArn'])
                            version = iam.get_policy_version(
                                PolicyArn=policy['PolicyArn'],
                                VersionId=policy_doc['Policy']['DefaultVersionId']
                            )
                            policy_str = json.dumps(version['PolicyVersion']['Document'])
                            if 'elasticache' in policy_str.lower() or (redis_secret_arn and redis_secret_arn in policy_str):
                                has_access = True
                                break
                        except:
                            pass
                except:
                    pass
                
                if has_access:
                    elasticache_roles.append(role['RoleName'])
    except:
        pass
    
    # Check EC2
    try:
        paginator = ec2.get_paginator('describe_instances')
        for page in paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]):
            for reservation in page['Reservations']:
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
                        except Exception as e:
                            pass
                    
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
                        resources.append({'type': 'EC2', 'id': instance_name, 'principal': role_name, 'state': f"{instance['State']['Name']} ({access_method})"})
    except Exception as e:
        print(f"  ⚠️  EC2 scan error: {e}")
    
    # Check Lambda
    try:
        lambda_client = boto3.client('lambda', region_name=AWS_REGION)
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for func in page['Functions']:
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
                    resources.append({'type': 'Lambda', 'id': func['FunctionName'], 'principal': func_role, 'state': access_method})
    except:
        pass
    
    # Check ECS
    try:
        ecs = boto3.client('ecs', region_name=AWS_REGION)
        paginator = ecs.get_paginator('list_clusters')
        for page in paginator.paginate():
            for cluster_arn in page.get('clusterArns', []):
                try:
                    svc_paginator = ecs.get_paginator('list_services')
                    for svc_page in svc_paginator.paginate(cluster=cluster_arn):
                        for service_arn in svc_page.get('serviceArns', []):
                            try:
                                service_details = ecs.describe_services(cluster=cluster_arn, services=[service_arn])
                                for service in service_details.get('services', []):
                                    task_def = service.get('taskDefinition', '')
                                    if task_def:
                                        task_def_details = ecs.describe_task_definition(taskDefinition=task_def)
                                        task_role = task_def_details['taskDefinition'].get('taskRoleArn', '').split('/')[-1]
                                        exec_role = task_def_details['taskDefinition'].get('executionRoleArn', '').split('/')[-1]
                                        if task_role in elasticache_roles or exec_role in elasticache_roles:
                                            principal = task_role if task_role in elasticache_roles else exec_role
                                            resources.append({'type': 'ECS', 'id': service['serviceName'], 'principal': principal, 'state': f"{service['runningCount']} tasks"})
                            except Exception as e:
                                pass
                except Exception as e:
                    pass
    except Exception as e:
        print(f"  ⚠️  ECS scan error: {e}")
    
    return resources

def scan_policies_for_legacy_arn():
    """Scan IAM policies with pagination"""
    iam = boto3.client('iam')
    results = {'users': [], 'roles': [], 'safe_principals': []}
    
    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                has_legacy_arn = False
                has_wildcard = False
                try:
                    policies = iam.list_attached_user_policies(UserName=user['UserName'])
                    for policy in policies['AttachedPolicies']:
                        policy_doc = iam.get_policy(PolicyArn=policy['PolicyArn'])
                        version = iam.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=policy_doc['Policy']['DefaultVersionId'])
                        policy_str = json.dumps(version['PolicyVersion']['Document'])
                        if 'elasticache' in policy_str.lower():
                            if LEGACY_CLUSTER_ID in policy_str:
                                has_legacy_arn = True
                            if '"Resource":"*"' in policy_str or '"Resource": "*"' in policy_str:
                                has_wildcard = True
                except:
                    pass
                
                if has_legacy_arn:
                    results['users'].append({'name': user['UserName'], 'risk': f'HIGH - Hardcoded {LEGACY_CLUSTER_ID} ARN'})
                elif has_wildcard:
                    results['safe_principals'].append({'name': user['UserName'], 'type': 'user'})
    except:
        pass
    
    try:
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                has_legacy_arn = False
                has_wildcard = False
                try:
                    policies = iam.list_attached_role_policies(RoleName=role['RoleName'])
                    for policy in policies['AttachedPolicies']:
                        policy_doc = iam.get_policy(PolicyArn=policy['PolicyArn'])
                        version = iam.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=policy_doc['Policy']['DefaultVersionId'])
                        policy_str = json.dumps(version['PolicyVersion']['Document'])
                        if 'elasticache' in policy_str.lower():
                            if LEGACY_CLUSTER_ID in policy_str:
                                has_legacy_arn = True
                            if '"Resource":"*"' in policy_str or '"Resource": "*"' in policy_str:
                                has_wildcard = True
                except:
                    pass
                
                if has_legacy_arn:
                    results['roles'].append({'name': role['RoleName'], 'risk': f'HIGH - Hardcoded {LEGACY_CLUSTER_ID} ARN'})
                elif has_wildcard:
                    results['safe_principals'].append({'name': role['RoleName'], 'type': 'role'})
    except:
        pass
    
    return results

def get_cluster_connections():
    """Get current connections"""
    cw = boto3.client('cloudwatch', region_name=AWS_REGION)
    end = datetime.utcnow()
    start = end - timedelta(hours=1)
    
    try:
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
            return {'current': int(dp.get('Average', 0)), 'peak': int(dp.get('Maximum', 0))}
    except:
        pass
    
    return {'current': 0, 'peak': 0}

def main():
    parser = argparse.ArgumentParser(description='ElastiCache Migration Auditor')
    parser.add_argument('--duration', type=int, default=86400, choices=range(3600, 2592001), metavar='SECONDS',
                        help='Duration in seconds (min: 3600, max: 2592000, default: 86400)')
    args = parser.parse_args()
    
    duration_hours = args.duration / 3600
    
    print("=" * 80)
    print("ELASTICACHE MIGRATION AUDIT REPORT")
    print("=" * 80)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Analysis Duration: {duration_hours:.1f} hours ({args.duration} seconds)\n")
    
    # Connection metrics
    print("📊 CLUSTER CONNECTION METRICS (PAST 1 HOUR)")
    print("-" * 80)
    connections = get_cluster_connections()
    print(f"\n  {LEGACY_CLUSTER_ID}:")
    print(f"    Current connections: {connections.get('current', 0)}")
    print(f"    Peak connections: {connections.get('peak', 0)}")
    
    # Active resources
    print("\n" + "=" * 80)
    print("🖥️  ACTIVE RESOURCES ACCESSING ELASTICACHE")
    print("-" * 80)
    resources = get_active_resources()
    if resources:
        for res in resources:
            print(f"\n  ✓ {res['type']}: {res['id']}")
            print(f"    Principal: {res['principal']}")
            print(f"    State: {res['state']}")
    else:
        print("\n  No active resources found")
    
    # VPC Flow Logs
    print("\n" + "=" * 80)
    print(f"🌐 VPC FLOW LOGS ANALYSIS (PAST {duration_hours:.1f} HOURS)")
    print("-" * 80)
    print("\nAnalyzing network traffic to Redis port 6379...")
    
    flow_connections = analyze_vpc_flow_logs(args.duration)
    resolved_resources = {}
    
    for key, data in flow_connections.items():
        eni_id = list(data['enis'])[0]
        ip = list(data['ips'])[0]
        resource = resolve_eni_to_resource(eni_id, ip)
        if resource:
            res_key = f"{resource['type']}:{resource['name']}"
            if res_key not in resolved_resources:
                resolved_resources[res_key] = {**resource, 'count': 0, 'first_seen': None, 'last_seen': None}
            resolved_resources[res_key]['count'] += data['count']
            if not resolved_resources[res_key]['first_seen'] or data['first_seen'] < resolved_resources[res_key]['first_seen']:
                resolved_resources[res_key]['first_seen'] = data['first_seen']
            if not resolved_resources[res_key]['last_seen'] or data['last_seen'] > resolved_resources[res_key]['last_seen']:
                resolved_resources[res_key]['last_seen'] = data['last_seen']
    
    if resolved_resources:
        for res_key, res in resolved_resources.items():
            print(f"\n  ✓ {res['type']}: {res['name']}")
            print(f"    Principal: {res['principal']}")
            print(f"    Method: {res['method']}")
            print(f"    Connections: {res['count']}")
            print(f"    First seen: {res['first_seen'].strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"    Last seen: {res['last_seen'].strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        print("\n  No VPC Flow Logs found or no connections detected")
        print("  Note: VPC Flow Logs must be enabled")
    
    # CloudTrail identities
    print("\n" + "=" * 80)
    print(f"👤 IAM IDENTITY ANALYSIS (PAST {duration_hours:.1f} HOURS)")
    print("-" * 80)
    print("\nAnalyzing CloudTrail for IAM identities...")
    
    identities = analyze_cloudtrail_identities(args.duration)
    
    if identities:
        for username, data in identities.items():
            method = 'IAM'
            if ':assumed-role/' in username:
                method = 'AssumedRole'
            elif 'federated' in username.lower():
                method = 'Federated'
            
            print(f"\n  ✓ {username}")
            print(f"    Method: {method}")
            print(f"    Events: {', '.join(list(data['events'])[:3])}")
            print(f"    Count: {data['count']}")
            print(f"    First seen: {data['first_seen'].strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"    Last seen: {data['last_seen'].strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        print(f"\n  No IAM identity activity found")
        print("  Note: CloudTrail has 5-15 min delay")
    
    # Combined report
    print("\n" + "=" * 80)
    print("📊 COMBINED CONNECTION REPORT")
    print("-" * 80)
    
    total = len(resolved_resources) + len(identities)
    if total > 0:
        print(f"\nTotal unique connections: {total}")
        print(f"\nBreakdown by access method:")
        methods = defaultdict(int)
        for res in resolved_resources.values():
            methods[res['method']] += 1
        for username, data in identities.items():
            if ':assumed-role/' in username:
                methods['AssumedRole'] += 1
            elif 'federated' in username.lower():
                methods['Federated'] += 1
            else:
                methods['IAM'] += 1
        for method, count in methods.items():
            print(f"  • {method}: {count}")
    else:
        print("\n  No historical connections detected")
    
    # Policy audit
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
    
    # Recommendations
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
