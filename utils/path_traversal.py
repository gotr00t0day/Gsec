from colorama import Fore
from urllib.parse import urljoin
import requests
import re
import sys
import os

requests.packages.urllib3.disable_warnings()


user_agent_ = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
header = {"User-Agent": user_agent_}

banner = """


 ██▓███   ▄▄▄     ▄▄▄█████▓ ██░ ██  ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓
▓██░  ██▒▒████▄   ▓  ██▒ ▓▒▓██░ ██▒▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒
▓██░ ██▓▒▒██  ▀█▄ ▒ ▓██░ ▒░▒██▀▀██░▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░
▒██▄█▓▒ ▒░██▄▄▄▄██░ ▓██▓ ░ ░▓█ ░██ ░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ 
▒██▒ ░  ░ ▓█   ▓██▒ ▒██▒ ░ ░▓█▒░██▓░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ 
▒▓▒░ ░  ░ ▒▒   ▓▒█░ ▒ ░░    ▒ ░░▒░▒ ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   
░▒ ░       ▒   ▒▒ ░   ░     ▒ ░▒░ ░ ▒ ░▒░ ░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░    
░░         ░   ▒    ░       ░  ░░ ░ ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░      
               ░  ░         ░  ░  ░ ░  ░  ░   ░              ░   V1.0       
                                                                        
by c0deninja
"""

def path_traversal_scan(domain: str) -> str:
    try:
        s = requests.Session()
        r = s.get(domain, verify=False, headers=header)
        content = r.content
        links = re.findall('(?:href=")(.*?)"', content.decode('utf-8'))
        duplicatelinks = set(links)
        params_links = []
        for link in links:
            link = urljoin(domain, link)
            if link not in duplicatelinks:
                if "=" in link:
                    params_links.append(link + "\n")
        parameters_list: list[str] = []
        vulnerable: list[str] = []
        for params2 in params_links:
            parameters = params2.split("=")[0]
            parameters_list.append(f"{parameters}=")
        cdir = os.getcwd()
        with open(f"{cdir}/payloads/traversal.txt", "r") as f:
            path_traversal_list = [x.strip() for x in f.readlines()]
        for parameterslist in parameters_list:
            for path_list in path_traversal_list:
                r_traversal = requests.get(f"{parameterslist}{path_list}", verify=False, headers=header)
                if r_traversal.status_code == 200 and "root:x:" in r_traversal.text:
                    vulnerable.append(f"{parameterslist}{path_list}")
        if vulnerable:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Path_Traversal: {Fore.GREEN}{', '.join(map(str,vulnerable))}")


    except requests.exceptions.ConnectionError:
        print (Fore.RED + "Connection Error")
    except requests.exceptions.MissingSchema:
        print (Fore.RED + "Please use: http://site.com")


if __name__ == "__main__":
    path_traversal_scan(sys.argv[1])