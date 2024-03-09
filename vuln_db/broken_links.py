from urllib.parse import urljoin, urlparse
from colorama import Fore
import requests
import re
import urllib3
import concurrent.futures

requests.packages.urllib3.disable_warnings()

user_agent_ = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
header = {"User-Agent": user_agent_}

def validate(url):
    check_link = urlparse(url)
    validate = bool(check_link.netloc) and bool(check_link.scheme) and check_link.scheme in ['http', 'https']
    return validate

def check_link(link, s):
    try:
        r = s.get(link, verify=False, headers=header)
        if r.status_code == 404:
            return link
    except (PermissionError, urllib3.exceptions.ReadTimeoutError, requests.exceptions.ReadTimeout, requests.exceptions.InvalidURL):
        pass
    return None

def scan(url: str) -> str:
    try:
        s = requests.Session()
        r = s.get(url, verify=False, headers=header)
        content = r.content
        links = set(re.findall('(?:href=")(.*?)"', content.decode('utf-8')))
        duplicates = set()
        for web_links in links:
            web_links = urljoin(url, web_links)
            duplicates.add(web_links)
        
        socials = ["instagram", "facebook", "github", "twitter"]
        social_links = set()
        not_found = set()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(check_link, link, s) for link in duplicates]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    for social in socials:
                        if social in result:
                            social_links.add(result)
                        else:
                            not_found.add(result)
        
        if social_links:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}- {Fore.WHITE}Broken Social Links: {Fore.GREEN}{', '.join(map(str,social_links))}")
        
        if not_found:
            no_dup = list(not_found)
            with open(f"/Users/c0deninja/tools/Gsec/output/broken_links.txt", "w") as f:
                for nodup in no_dup:
                    f.write(f"{nodup}\n")
    except requests.exceptions.InvalidSchema:
        pass