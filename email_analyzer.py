import email
from email import policy
import re
import os
import requests

FILE_PATH = "./suspicious_mail.eml"

API_KEY = "38cfd996bfbc421b3328da95d40e9746259c430fc3695b73e38e448667c1e64a"


def extr_URLs(email_body):
    url_pattern = r"https?://[^\s<>\"]+|www\.[^\s<>\"]+"
    found_urls = re.findall(url_pattern, email_body)
    return list(set(found_urls))


def extr_IPv4(email_message):
    received_headers = email_message.get_all("Received")
    if not received_headers:
        return None

    origin_header = received_headers[-1]
    ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    match = re.search(ipv4_pattern, origin_header)

    if match:
        return match.group(0)
    return None


def check_reputation(ioc, ioc_type="ip"):
    if not API_KEY:
        print(
            f"   [!] Brak klucza API. Pomijam sprawdzanie w VirusTotal dla: {ioc}")
        return 0

    headers = {"x-apikey": API_KEY}
    try:
        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        elif ioc_type == "url":
            import base64

            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            return 0

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_resp = response.json()
            return json_resp["data"]["attributes"]["last_analysis_stats"][
                "malicious"
            ]
        else:
            print(f"   [!] API zwróciło status: {response.status_code}")

    except Exception as e:
        print(f"   [!] Błąd API: {e}")

    return 0


def analyze_email(filepath):
    print(f"[*] Rozpoczynam analizę pliku: {filepath}")

    if not os.path.exists(filepath):
        print(
            f"[!] Błąd: Plik '{filepath}' nie istnieje w tym katalogu!"
        )
        print(f"[i] Twój obecny katalog roboczy to: {os.getcwd()}")
        return

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            parsed_email = email.message_from_file(f, policy=policy.default)
    except Exception as e:
        print(f"[!] Błąd podczas odczytu pliku: {e}")
        return

    from_address = str(parsed_email.get("From", ""))
    reply_to = str(parsed_email.get("Reply-To", ""))

    print("\n--- Analiza Nagłówków (Headers) ---")
    print(f"From: {from_address}")
    if reply_to:
        print(f"Reply-To: {reply_to}")
        if from_address not in reply_to and reply_to not in from_address:
            print(
                "[!] WYSOKIE RYZYKO: Możliwy spoofing! Adres Reply-To różni się od nadawcy (From)."
            )
    else:
        print("Reply-To: Nie określono (w normie).")

    source_ip = extr_IPv4(parsed_email)
    if source_ip:
        print(f"\n--- Analiza Adresu IP Nadawcy ---")
        print(f"Adres IP źródłowy: {source_ip}")
        ip_score = check_reputation(source_ip, ioc_type="ip")
        if ip_score > 0:
            print(
                f"[!] Ostrzeżenie: Adres IP {source_ip} został oflagowany jako złośliwy przez {ip_score} silników."
            )
        else:
            print("[+] Reputacja IP wygląda na czystą.")

    print("\n--- Analiza Treści (URL Extraction) ---")
    body = ""
    if parsed_email.is_multipart():
        for part in parsed_email.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                body = part.get_payload(decode=True).decode(errors="ignore")
                break
    else:
        body = parsed_email.get_payload(decode=True).decode(errors="ignore")

    urls = extr_URLs(body)
    if urls:
        print(f"Znaleziono {len(urls)} unikalny(ch) link(ów):")
        for url in urls:
            print(f" - {url}")
            url_score = check_reputation(url, ioc_type="url")
            if url_score > 0:
                print(
                    f"   [!] KRYTYCZNE: Znaleziono złośliwy link! Oflagowany przez {url_score} silników."
                )
    else:
        print("Nie znaleziono żadnych linków URL w treści maila.")

    print("\n[*] Analiza zakończona powodzeniem.")


def main():
    analyze_email(FILE_PATH)


if __name__ == "__main__":
    main()
