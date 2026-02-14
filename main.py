import email
import re
import argparse
import sys
import requests
import beautifulsoup4

API_KEY = 'YOUR_API_KEY'


def extr_URLs(email_body):
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
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

# def check_reputation(ioc):

# def analyze_email(filepath):

# def main():
