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

# def check_reputation(ioc):

# def analyze_email(filepath):


def main():
    raw_email_string = """Subject: Urgent!
From: hacker@bad.com
To: victim@company.com
Received: from mail.google.com (mail.google.com [172.217.0.0]) by my-server.com;
Received: from intermediate.net (relay.net [104.16.132.0]) by google.com;
Received: from evil-laptop.local (bad-guy-pc [45.33.22.11]) by intermediate.net;

Hello,
Please click this link: https://malicious-site.com/login.php?user=target
This email was sent from an internal server.
"""
    msg = email.message_from_string(raw_email_string, policy=policy.default)
    body = msg.get_body(preferencelist=('plain')).get_content()

    ips = extr_IPv4(msg)
    urls = extr_URLs(body)

    print("Analyzer started...")

    time.sleep(5)

    print("Found IPs:", ips)
    print("Found URLs:", urls)


if __name__ == "__main__":
    main()
