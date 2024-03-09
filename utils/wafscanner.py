from colorama import Fore
from bs4 import BeautifulSoup
from plugins import agent_list
import requests 

requests.packages.urllib3.disable_warnings()


user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

WAF = ["Cloudflare", "ModSecurity", "Citrix", "Imperva"]
WAF_ = []

banner = """


██     ██  █████  ███████ 
██     ██ ██   ██ ██      
██  █  ██ ███████ █████   
██ ███ ██ ██   ██ ██      
 ███ ███  ██   ██ ██   Detector v1.0    



"""


def waf_headers(domain: str) -> str:
    r = requests.get(f"{domain}", verify=False, headers=header)
    wafheaders = ['x-content-security-policy', 'x-frame-options', 'x-xss-protection', 'x-webkit-csp', 'server: cloudflare']
    if r.status_code == 200:
        for k,v in r.headers.items():
            if k in wafheaders:
                return True


def waf_ssl_tls_config(domain: str) -> str:
    r = requests.get(f"{domain}", verify=False, headers=header)
    if r.status_code == 200:
        for waf_list in WAF:
            if waf_list in r.text or "Let\s Encrypt" in r.text:
                return True
                

def waf_url_structure(domain: str) -> str:
    r = requests.get(f"{domain}", verify=False, headers=header)
    if r.status_code == 200:
        soup = BeautifulSoup(r.text, 'html.parser')
        for link in soup.find_all('a'):
            if "waf" in link.get("href"):
                return True
            
def waf_response_code(domain: str) -> str:
    r = requests.get(f"{domain}", verify=False, headers=header)
    if r.status_code == 406:
        WAF_.append("ModSecurity")
    if r.status_code == 501:
        WAF_.append("ModSecurity")

def waf_text(domain: str) -> str:
    r = requests.get(f"{domain}", verify=False, headers=header)
    for waf_list in WAF:
        if waf_list in r.text:
            WAF_.append(waf_list)

def main(domain: str) -> str:
    headers = waf_headers(domain)
    ssl_tls = waf_ssl_tls_config(domain)
    url_structure = waf_url_structure(domain)
    if WAF_:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} WAF: {Fore.GREEN}{Fore.GREEN}{', '.join(map(str,WAF))}")
    if headers or ssl_tls or url_structure:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} WAF: {Fore.GREEN}{Fore.GREEN}POSSIBLE!")


    






