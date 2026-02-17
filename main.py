import email
from email import policy
import time
import re
import argparse
import sys
import requests

API_KEY = 'YOUR_API_KEY'


def extr_URLs(email_body):
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    found_urls = re.findall(url_pattern, email_body)

    return list(set(found_urls))


def extr_IPv4(email_header):
    received_headers = email_header.get_all('Received')

    if not received_headers:
        return None

    origin_header = received_headers[-1]

    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    match = re.search(ipv4_pattern, origin_header)

    if match:
        return match.group(0)
    else:
        return None


def check_reputation(ioc, ioc_type="ip"):
    if not API_KEY:
        print(f"   [!] No API Key configured. Skipping real check for {ioc}")
        return 0

    headers = {"x-apikey": API_KEY}
    try:
        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                json_resp = response.json()
                return json_resp['data']['attributes']['last_analysis_stats']['malicious']

    except Exception as e:
        print(f"   [!] API Error: {e}")

    return 0

# def analyze_email(filepath):

# def main():

# if __name__ == "__main__":
#     main()
