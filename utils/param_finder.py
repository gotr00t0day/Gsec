from colorama import Fore
from urllib.parse import urljoin
import requests
import re
import sys

requests.packages.urllib3.disable_warnings()


user_agent_ = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
header = {"User-Agent": user_agent_}


with open(f"payloads/ssrf.txt", "r") as f:
    ssrf_list = [x.strip() for x in f.readlines()]

with open(f"payloads/rce.txt", "r") as f:
    rce_list = [x.strip() for x in f.readlines()]

with open(f"payloads/openredirect.txt", "r") as f:
    openredirect_list = [x.strip() for x in f.readlines()]

def get_params(domain: str) -> str:
    try:
        r = requests.get(domain, verify=False, headers=header)
        content = r.content
        links = re.findall('(?:href=")(.*?)"', content.decode('utf-8'))
        duplicatelinks = set(links)
        params_links = []
        for link in links:
            link = urljoin(domain, link)
            if link not in duplicatelinks:
                if "=" in link:
                    params_links.append(link + "\n")
        param_value: list[str] = []
        dic: dict[str, str] = {}
        payloads: list[str] = []
        for params2 in params_links:
            parameters = params2.split("=")[0]
            pos = max(parameters.find("?"), 0)
            value = parameters[pos:].strip()
            param_value.append(f"{value}=")
        for keys in params_links:
            for values in param_value:          
                dic[keys] = values
                param_value.remove(values)
                break
        for item, value in dic.items():
            if value in rce_list:
                payloads.append("RCE")
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Link: {Fore.YELLOW}{item} {Fore.GREEN} Injection Point: {Fore.LIGHTBLUE_EX}{value} {Fore.WHITE} Payload: {Fore.CYAN} RCE")
            if value in ssrf_list:
                payloads.append("SSRF")
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Link: {Fore.YELLOW}{item} {Fore.GREEN} Injection Point: {Fore.LIGHTBLUE_EX}{value} {Fore.WHITE} Payload: {Fore.CYAN} SSRF")
            if value in openredirect_list:
                payloads.append("OPEN REDIRECT")
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Link: {Fore.YELLOW}{item} {Fore.GREEN} Injection Point: {Fore.LIGHTBLUE_EX}{value} {Fore.WHITE} Payload: {Fore.CYAN} OPEN REDIRECT")
            if not payloads:
                print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Link: {Fore.YELLOW}{item} {Fore.GREEN} Injection Point: {Fore.LIGHTBLUE_EX}{value}")
    except requests.exceptions.ConnectionError:
        print (Fore.RED + "Connection Error")
    except requests.exceptions.MissingSchema:
        print (Fore.RED + "Please use: http://site.com")
    except UnicodeDecodeError:
        pass

if __name__ == "__main__":
    print(f"{Fore.WHITE} Searching for vulnerable paramaters for {Fore.CYAN}SSRF, RCE, Open Redirect{Fore.GREEN}\n")
    get_params(sys.argv[1])