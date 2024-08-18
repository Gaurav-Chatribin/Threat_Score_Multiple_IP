import requests
import time
from concurrent.futures import ThreadPoolExecutor

# Replace with your actual API keys
VT_API_KEY = 'Enter your API Key'
ABUSEIPDB_API_KEY = 'Enter your API Key'

# Base URLs for the APIs
VT_API_URL = 'https://www.virustotal.com/api/v3/ip_addresses/'
ABUSEIPDB_API_URL = 'https://api.abuseipdb.com/api/v2/check'

# Input and Output files
INPUT_FILE = 'ip_list.txt'
OUTPUT_FILE = 'ip_threat_scores.txt'

# Function to get VirusTotal report
def get_virustotal_report(ip_or_domain, report_type):
    if report_type == 'ip':
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_or_domain}'
    elif report_type == 'domain':
        url = f'https://www.virustotal.com/api/v3/domains/{ip_or_domain}'
    else:
        return {"error": "Invalid report type"}
    
    headers = {'x-apikey': VT_API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        tags = data.get("data", {}).get("attributes", {}).get("tags", [])
        details = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "tags": tags,
            "details": details
        }
    else:
        return {"error": "API request failed or invalid IP/domain"}

# Function to get AbuseIPDB score
def get_abuseipdb_score(ip_address, max_age_days=90):
    check_url = 'https://api.abuseipdb.com/api/v2/check'
    check_headers = {
        'Key': ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    check_params = {
        'ipAddress': ip_address,
        'maxAgeInDays': max_age_days,
        'verbose': True
    }

    check_response = requests.get(check_url, headers=check_headers, params=check_params)

    if check_response.status_code == 200:
        data = check_response.json().get('data', {})
        return data.get('abuseConfidenceScore', 'N/A')
    else:
        print(f"AbuseIPDB check request failed for {ip_address} with status code {check_response.status_code}")
        return 'N/A'

# Function to process a single IP address
def process_ip(ip):
    print(f"Processing IP: {ip}")
    vt_report = get_virustotal_report(ip, 'ip')
    abuse_score = get_abuseipdb_score(ip)

    if 'error' in vt_report:
        vt_tags = "Error fetching VirusTotal data"
        vt_details = "Error fetching VirusTotal data"
    else:
        vt_tags = ', '.join(vt_report.get("tags", []))
        vt_details = vt_report.get("details", {})

    result = f"IP: {ip}\n"
    result += f"VirusTotal Tags: {vt_tags}\n"
    result += f"VirusTotal Details: {vt_details}\n"
    result += f"AbuseIPDB Score: {abuse_score}\n\n"

    # Rate limiting: Wait for 1 second before the next request
    time.sleep(1)
    
    return result

# Function to update the IP list with scores and save to the output file
def update_ip_list_with_scores(ip_list):
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(process_ip, ip_list))
    
    with open(OUTPUT_FILE, 'w') as file:
        file.writelines(results)

def read_ip_list_from_file():
    with open(INPUT_FILE, 'r') as file:
        ip_list = [line.strip() for line in file.readlines()]
    return ip_list

# Read the IP addresses from the input file
ip_addresses = read_ip_list_from_file()

# Update the IP list with scores and save to the output file
update_ip_list_with_scores(ip_addresses)

print(f"\nIP threat scores have been saved to {OUTPUT_FILE}")
