import boto3
import json  


ec2_client = boto3.client('ec2')
iam_client = boto3.client('iam')

# --- Network Analysis Functions ---

def check_security_group_exposure(security_groups):
   
    for sg in security_groups:
        try:
            response = ec2_client.describe_security_groups(GroupIds=[sg['GroupId']])
            for group in response['SecurityGroups']:
                for permission in group.get('IpPermissions', []):
                    for ip_range in permission.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            return True
        except Exception as e:
            print(f"Error checking SG {sg['GroupId']}: {e}")
    return False

def check_network_reachability(vpc_id, subnet_id):
   
    try:
        route_tables = ec2_client.describe_route_tables(
            Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}]
        )
        
        if not route_tables['RouteTables']:
            route_tables = ec2_client.describe_route_tables(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]},
                    {'Name': 'association.main', 'Values': ['true']}
                ]
            )

        for rt in route_tables['RouteTables']:
            for route in rt['Routes']:
                if route.get('DestinationCidrBlock') == '0.0.0.0/0':
                    gateway_id = route.get('GatewayId', '')
                    if gateway_id.startswith('igw-'):
                        return True
        return False
    except Exception as e:
        print(f"Error checking network reachability: {e}")
        return False

# --- Identity Analysis Functions ---

def analyze_policy_document(policy_arn):
   
    try:
        policy_info = iam_client.get_policy(PolicyArn=policy_arn)
        version_id = policy_info['Policy']['DefaultVersionId']
        
        policy_version = iam_client.get_policy_version(
            PolicyArn=policy_arn, 
            VersionId=version_id
        )
        document = policy_version['PolicyVersion']['Document']
        
        statements = document.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
            
        for stmt in statements:
            if stmt.get('Effect') == 'Allow':
                actions = stmt.get('Action', [])
                resources = stmt.get('Resource', [])
                
                if isinstance(actions, str): actions = [actions]
                if isinstance(resources, str): resources = [resources]

                if ('*' in actions or '*:*' in actions) and ('*' in resources):
                    return True
        return False
    except Exception as e:
        print(f"Error analyzing policy {policy_arn}: {e}")
        return False

def check_admin_permissions(iam_role_name):
    if not iam_role_name:
        return False  
    try:
        attached_policies = iam_client.list_attached_role_policies(RoleName=iam_role_name)
        for policy in attached_policies['AttachedPolicies']:
            if analyze_policy_document(policy['PolicyArn']):
                return True
        return False
    except Exception as e:
        print(f"Error checking role {iam_role_name}: {e}")
        return False

# --- Main Orchestrator ---

def scan_cloud_environment():
    print("Starting Deep Cloud Context Scan...\n")
    
    instances = ec2_client.describe_instances(
        Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
    )

    all_findings = []
    found_toxic_combo = False

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            vpc_id = instance.get('VpcId')
            subnet_id = instance.get('SubnetId')
            public_ip = instance.get('PublicIpAddress')
            
            print(f"Scanning Instance: {instance_id}...")

            # 1. Network Context
            sg_open = check_security_group_exposure(instance.get('SecurityGroups', []))
            network_reachable = False
            if sg_open and public_ip:
                network_reachable = check_network_reachability(vpc_id, subnet_id)
            
            is_effectively_exposed = sg_open and network_reachable
            
            if is_effectively_exposed:
                print(f"  [Network] Status: CRITICAL (Open SG + Public IP + Route to Internet)")
            elif sg_open and not network_reachable:
                print(f"  [Network] Status: Warning (Open SG but NO Route to Internet)")
            else:
                print(f"  [Network] Status: Secure")

            # 2. Identity Context
            iam_role = instance.get('IamInstanceProfile', {})
            role_name = iam_role.get('Arn', '').split('/')[-1] if iam_role else None
            
            is_admin = False
            if role_name:
                is_admin = check_admin_permissions(role_name)
            
            if is_admin:
                print(f"  [Identity] Status: CRITICAL (Admin Permissions found)")
            else:
                print(f"  [Identity] Status: Low Privileges")

            # 3. Determine Risk Level
            is_toxic = is_effectively_exposed and is_admin
            if is_toxic:
                print(f"\n[!!!] TOXIC COMBINATION DETECTED ON {instance_id} [!!!]\n")
                found_toxic_combo = True

            # --- Data Collection for JSON Export ---
            finding_data = {
                "instance_id": instance_id,
                "vpc_id": vpc_id,
                "public_ip": public_ip,
                "network_analysis": {
                    "security_group_open": sg_open,
                    "route_to_gateway": network_reachable,
                    "effectively_exposed": is_effectively_exposed
                },
                "identity_analysis": {
                    "role_name": role_name,
                    "has_admin_privileges": is_admin
                },
                "risk_assessment": {
                    "is_toxic_combination": is_toxic,
                    "severity": "CRITICAL" if is_toxic else "LOW"
                }
            }
            all_findings.append(finding_data) 

    # --- Export to JSON ---
    output_filename = "scan_results.json"
    try:
        with open(output_filename, 'w') as f:
            json.dump(all_findings, f, indent=4)
        print(f"\nScan complete. Results exported to '{output_filename}'.")
    except Exception as e:
        print(f"Error exporting to JSON: {e}")

    if not found_toxic_combo:
        print("Good job! No toxic combinations found.")

if __name__ == "__main__":
    scan_cloud_environment()