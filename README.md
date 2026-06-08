# Phishing Email Analyzer
![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![Email](https://img.shields.io/badge/Lib-Email%20Parsing-orange?style=flat&logo=gmail)
![VirusTotal](https://img.shields.io/badge/API-VirusTotal-394EFF?style=flat&logo=virustotal&logoColor=white)
![Security](https://img.shields.io/badge/Security-Phishing%20Analysis-red)

A Python-based automated sort tool designed to help SOC Analysts quickly detect Indicators of Compromise (IoCs) in suspicious emails.

## Features:
1. Header Forensics: Analyzes email headers to detect Spoofing
2. IoC Extraction: Automatically parses the email body and headers to extract:
    - Source IP 
    - Malicious URLs 
3. Reputation Check: Integrated logic to query VirusTotal API for real-time reputation scoring of discovered IPs.
4. Multipart Parsing: robustly handles complex email formats (HTML + Text) to find hidden links.

## Technologies
1. Python 3
2. Regex (for pattern matching IPs and URLs)
3. Email Library (for parsing MIME standards)
4. Requests (for API communication)


