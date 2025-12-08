import boto3

ec2_client = boto3.client('ec2')
iam_client = boto3.client('iam')

def get_instance_public_exposure(security_groups):
    
    for sg in security_groups:
        response = ec2_client.describe_security_groups(GroupIds=[sg['GroupId']])
        for group in response['SecurityGroups']:
            for permission in group['IpPermissions']:
                if 'IpRanges' in permission:
                    for ip_range in permission['IpRanges']:
                        if ip_range['CidrIp'] == '0.0.0.0/0':
                            return True
    return False

def check_admin_privileges(iam_role_name):
    if not iam_role_name:
        return False
    
    attached_policies = iam_client.list_attached_role_policies(RoleName=iam_role_name)
    
    for policy in attached_policies['AttachedPolicies']:
        if policy['PolicyName'] == 'AdministratorAccess':
            return True
    return False

def scan_cloud_environment():
    print("Starting Cloud Context Scan...\n")
    
    instances = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

    found_toxic_combo = False

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            
    
            security_groups = instance.get('SecurityGroups', [])
            is_exposed = get_instance_public_exposure(security_groups)
            
            iam_role = instance.get('IamInstanceProfile', {})
            role_name = iam_role.get('Arn', '').split('/')[-1] if iam_role else None
            is_admin = False
            if role_name:
                try:
                    is_admin = check_admin_privileges(role_name)
                except:
                    pass

            
            print(f"Scanning Instance: {instance_id}")
            print(f"  -> Exposed to Internet? {is_exposed}")
            print(f"  -> Has Admin Privileges? {is_admin}")

            if is_exposed and is_admin:
                print(f"\n[!!!] TOXIC COMBINATION DETECTED ON {instance_id} [!!!]")
                print("      REASON: This server is exposed to the entire internet AND has Admin keys.")
                print("      ACTION: Immediate remediation required.\n")
                found_toxic_combo = True
            else:
                print("  -> Status: Low Risk (No context overlap)\n")

    if not found_toxic_combo:
        print("No toxic combinations found. Good job!")

if __name__ == "__main__":
    scan_cloud_environment()