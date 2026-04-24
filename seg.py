import os
import sys
import json

"""
Segregation Script — Parses DNS Dumpster JSON output into categorized files.

Usage: python3 seg.py <domain>
  Reads from dump/output_<domain>.txt and writes categorized data to enum/
"""

if len(sys.argv) < 2:
    print("Usage: python3 seg.py <domain>")
    sys.exit(1)

domain = sys.argv[1]
input_file = f"dump/output_{domain}.txt"

if not os.path.exists(input_file):
    print(f"[-] Input file not found: {input_file}")
    sys.exit(1)

if not os.path.exists('enum'):
    os.makedirs('enum')

# Parse the JSON output from DnsDumpster
try:
    with open(input_file, 'r') as file:
        data = json.loads(file.read())
except json.JSONDecodeError:
    # Fallback: try line-based parsing for non-JSON output
    with open(input_file, 'r') as file:
        lines = file.readlines()

    subdomains = [line.strip() for line in lines if 'subdomain' in line.lower()]
    ips = [line.strip() for line in lines if 'ip' in line.lower()]
    ns_records = [line.strip() for line in lines if 'ns' in line.lower()]

    with open('enum/subdomains.txt', 'w') as file:
        for subdomain in subdomains:
            file.write(subdomain + '\n')

    with open('enum/ips.txt', 'w') as file:
        for ip in ips:
            file.write(ip + '\n')

    with open('enum/ns_records.txt', 'w') as file:
        for ns in ns_records:
            file.write(ns + '\n')

    print(f"[+] Segregated output written to enum/ (line-based parsing)")
    sys.exit(0)

# JSON-based parsing (DnsDumpster outputs structured JSON)
subdomains = []
ips = []
ns_records = []
mx_records = []
dns_records = []
txt_records = []

for entry in data:
    entry_type = entry.get('type', '')

    if entry_type == 'Host':
        for record in entry.get('records', []):
            server_name = record.get('server_name', '')
            ip_address = record.get('ip_address', '')
            if server_name:
                subdomains.append(server_name)
            if ip_address:
                ips.append(ip_address)

    elif entry_type == 'DNS':
        for record in entry.get('records', []):
            server_name = record.get('server_name', '')
            ip_address = record.get('ip_address', '')
            if server_name:
                ns_records.append(f"{server_name} ({ip_address})")
                dns_records.append(record)

    elif entry_type == 'MX':
        for record in entry.get('records', []):
            server_name = record.get('server_name', '')
            if server_name:
                mx_records.append(server_name)

    elif entry_type == 'TXT':
        for record in entry.get('records', []):
            txt = record.get('record', '')
            if txt:
                txt_records.append(txt)

# Write segregated output files
with open('enum/subdomains.txt', 'w') as file:
    for subdomain in subdomains:
        file.write(subdomain + '\n')

with open('enum/ips.txt', 'w') as file:
    for ip in ips:
        file.write(ip + '\n')

with open('enum/ns_records.txt', 'w') as file:
    for ns in ns_records:
        file.write(ns + '\n')

if mx_records:
    with open('enum/mx_records.txt', 'w') as file:
        for mx in mx_records:
            file.write(mx + '\n')

if txt_records:
    with open('enum/txt_records.txt', 'w') as file:
        for txt in txt_records:
            file.write(txt + '\n')

with open('enum/description.txt', 'w') as file:
    file.write("Host: This is the main domain that was scanned.\n")
    file.write("MX: Mail Exchange (MX) records associated with the domain.\n")
    file.write("NS: Name Server (NS) records associated with the domain. Each record includes the IP address and name of the name server.\n")
    file.write("DNS: DNS server records for the domain.\n")
    file.write("TXT: TXT records associated with the domain (SPF, DKIM, etc.).\n")
    file.write("Subdomains: List of subdomains discovered via DNS enumeration.\n")
    file.write("IPs: IP addresses associated with discovered subdomains.\n")

print(f"[+] Segregated output written to enum/")
print(f"    Subdomains: {len(subdomains)}")
print(f"    IPs: {len(ips)}")
print(f"    NS Records: {len(ns_records)}")
print(f"    MX Records: {len(mx_records)}")
print(f"    TXT Records: {len(txt_records)}")
