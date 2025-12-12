import docker
import subprocess
import json
import sys
from datetime import datetime

try:
    client = docker.from_env()
except Exception as e:
    print(f"❌ Error connecting to Docker: {e}")
    sys.exit(1)

def scan_container_config(container):
  
    findings = []
    config = container.attrs
    
    user = config['Config'].get('User', '')
    if user == '' or user == '0' or user == 'root':
        findings.append("Running as ROOT user")

    if config['HostConfig'].get('Privileged'):
        findings.append("Running in PRIVILEGED mode")

    mounts = config.get('Mounts', [])
    for mount in mounts:
        source = mount.get('Source', '')
        if 'docker.sock' in source:
            findings.append("Docker Socket mounted inside container")

    ports = config['NetworkSettings'].get('Ports', {})
    for port in ports:
        if port == '22/tcp':
             findings.append("Port 22 (SSH) is exposed")

    return findings

def scan_vulnerabilities(image_name):
    print(f"   ⏳ Scanning image '{image_name}' with Trivy...")
    try:
        cmd = [
            "trivy", "image",
            "--format", "json",
            "--severity", "CRITICAL,HIGH",
            "--quiet",
            image_name
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            return {"status": "error", "message": "Trivy failed or not found", "counts": {}}

        data = json.loads(result.stdout)
        
       
        critical_count = 0
        high_count = 0
        
        if 'Results' in data:
            for target in data['Results']:
                for vuln in target.get('Vulnerabilities', []):
                    severity = vuln.get('Severity')
                    if severity == 'CRITICAL':
                        critical_count += 1
                    elif severity == 'HIGH':
                        high_count += 1
        
        return {
            "status": "success",
            "message": f"Found {critical_count} Critical, {high_count} High",
            "counts": {"critical": critical_count, "high": high_count}
        }

    except FileNotFoundError:
        return {"status": "error", "message": "Trivy not installed", "counts": {}}
    except json.JSONDecodeError:
        return {"status": "error", "message": "Failed to parse Trivy output", "counts": {}}

def main():
    print("🔍 Starting Advanced CWPP Scan with JSON Export...")
    print("=================================================")

    containers = client.containers.list()
    
    full_report = {
        "scan_time": datetime.now().isoformat(),
        "total_containers_scanned": len(containers),
        "results": []
    }

    if not containers:
        print("No running containers found.")
        return

    for container in containers:
        container_name = container.name
        image_name = container.image.tags[0] if container.image.tags else "Unknown"
        
        print(f"\n📦 Processing: {container_name}")
        
        config_findings = scan_container_config(container)
        vuln_data = scan_vulnerabilities(image_name)

        if config_findings:
            print(f"   ⚠️  Configuration Issues: {len(config_findings)} found")
        else:
            print(f"   ✅ Configuration Secure")
            
        print(f"   🛡️  Vulnerabilities: {vuln_data['message']}")

        container_report = {
            "container_name": container_name,
            "container_id": container.short_id,
            "image": image_name,
            "security_status": "RISK" if (config_findings or vuln_data['counts'].get('critical', 0) > 0) else "SECURE",
            "findings": {
                "configuration": config_findings,
                "vulnerabilities": vuln_data['counts']
            }
        }
        
        full_report['results'].append(container_report)

    print("\n💾 Saving report to 'report.json'...")
    with open('report.json', 'w') as f:
        json.dump(full_report, f, indent=4)
    
    print("✅ Done! You can integrate 'report.json' with your SIEM or Dashboard.")

if __name__ == "__main__":
    main()