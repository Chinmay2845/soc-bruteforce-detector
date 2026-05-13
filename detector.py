import re
import json
from collections import defaultdict
from datetime import datetime

LOG_FILE = "logs/auth.log"
REPORT_FILE = "report/incident.json" 

failed_logins = defaultdict(int)

MITRE_ATTACKS = "T1110 - Brute Force"

THRESHOLD = 5

with open(LOG_FILE, "r") as file:
    logs = file.readlines()

for line in logs:

    # match failed login attempts
    failed_match = re.search(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)", line)

    if failed_match:
        ip = failed_match.group(1)
        failed_logins[ip] += 1

incidents = []

print("\n-----------------------SOC Alert-----------------------")

for ip, count in failed_logins.items():

    if count >= THRESHOLD:

        severity = ""

        if count >=10:
            severity = "High"
        elif count >= 7:
            severity = "Medium"
        else:
            severity = "Low"
        
        incident = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": ip,
            "failed_attempts": count,
            "attack_type": "Brute Force",
            "severity": severity,
            "mitre_attack": MITRE_ATTACKS,
            "recommended_action": "Block IP and investigate"
        }
        incidents.append(incident)

        print(f"[{severity} ALERT]")
        print(f"Suspicious IP: {ip}")
        print(f"Failed Attempts: {count}")
        print(f"MITRE Technique: {MITRE_ATTACKS}")
        print("Recommended Action: Block IP")
        print("----------------------------------")

with open(REPORT_FILE, "w") as report:
    json.dump(incidents, report, indent=4)  

print("\nIncident report saved succesfully to", REPORT_FILE)