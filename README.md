# Multiple IP Threat Score

## Description

The Threat Reputation Checker is a Python script designed to assess the reputation of IP addresses by querying the VirusTotal and AbuseIPDB APIs. This script retrieves and evaluates threat data and scores associated with each IP address. It processes multiple IP addresses, providing detailed threat assessments and saving the results to an output file.

The script can:
- **Check Reputation**: Queries both VirusTotal and AbuseIPDB for threat data.
- **Handle Multiple IPs**: Efficiently processes a list of IP addresses from an input file.
- **Save Results**: Outputs the threat data and scores to a specified output file for easy review.

This tool is useful for monitoring and analyzing the security status of multiple IP addresses, helping to identify potential threats based on their reputation.

### Note: Adjust the below the in code based on the ratelimit set by Virustotal & AbuseIPDB. 
    # Rate limiting: Wait for 1 second before the next request
    time.sleep(1)

   To know know check the Rate limit Provided by this vendor based on your plans.
  -  https://virustotal.readme.io/reference/public-vs-premium-api
  -  https://www.abuseipdb.com/pricing
   
   

## Features

- **VirusTotal Integration**: Retrieves tags and detailed analysis statistics for IP addresses.
- **AbuseIPDB Integration**: Checks the abuse confidence score for IP addresses.
- **Multi-IP Processing**: Reads IP addresses from an input file and processes them in parallel.
- **Result Saving**: Saves the threat scores and details to an output file.

## Requirements

- Python 3.6 or higher
- `requests` library
- `concurrent.futures` library
- `whois` library (if used in other versions)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Gaurav-Chatribin/Threat_Score_Multiple_IP.git


2. Install the required libraries:

   ```bash
    pip install requests whois


4. Add the API to the code
   
   ```bash
      VT_API_KEY = 'your_virustotal_api_key'
      ABUSEIPDB_API_KEY = 'your_abuseipdb_api_key'

5. Usage
   
   ```bash
       python threat_reputation_checker.py

6. Example Output:
   
   ```bash
        IP: 1.1.1.1
        VirusTotal Tags: ['suspicious-udp']
        VirusTotal Details: {'malicious': 1, 'suspicious': 1, 'undetected': 27, 'harmless': 64, 'timeout': 0}
        AbuseIPDB Score: 0

7. Troubleshooting:
- Empty Output File: Ensure your API keys are correct and valid. Check for rate limiting or request errors from the APIs.
- API Request Errors: Verify that the IP addresses in your input file are correctly formatted and valid.


Acknowledgments:
Thanks to VirusTotal and AbuseIPDB for providing the APIs.
Contributions and feedback are welcome!
`Gaurav-Chatribin`, `Threat_Score_Multiple_IP`



