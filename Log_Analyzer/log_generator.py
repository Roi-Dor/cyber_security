import random
import datetime

# Configuration
LOG_FILE = "server.log"
NUM_ENTRIES = 25

# 1. Templates for "Normal" Traffic (Safe)
safe_endpoints = [
    "/index.html", "/about", "/contact", "/products?id=", "/images/logo.png",
    "/api/v1/status", "/login"
]

# 2. Templates for "Malicious" Traffic (Attacks)
attacks = [
    # SQL Injection
    ("GET /products?id=' OR 1=1 --", "403"),
    ("POST /login user='admin'--", "403"),
    # Path Traversal
    ("GET /../../etc/passwd", "404"),
    ("GET /images/../../root/.bash_history", "404"),
    # AWS/Cloud Metadata Theft (Specific to Cloud Security!)
    ("GET /latest/meta-data/iam/security-credentials/", "200"),
    # XSS (Cross Site Scripting)
    ("GET /search?q=<script>alert('pwned')</script>", "200")
]

def get_random_ip():
    return f"{random.randint(10, 192)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def get_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

print(f"📝 Generating {NUM_ENTRIES} log entries...")

with open(LOG_FILE, "w") as f:
    for _ in range(NUM_ENTRIES):
        # 90% chance of normal traffic, 10% chance of attack
        if random.random() > 0.1:
            endpoint = random.choice(safe_endpoints)
            if "id=" in endpoint: endpoint += str(random.randint(1, 1000))
            status = "200"
            log = f"{get_timestamp()} INFO GET {endpoint} status={status} ip={get_random_ip()}"
        else:
            attack_endpoint, status = random.choice(attacks)
            log = f"{get_timestamp()} WARN {attack_endpoint} status={status} ip={get_random_ip()}"
        
        f.write(log + "\n")

print(f"✅ Done! Created '{LOG_FILE}' with mixed traffic.")