from colorama import Fore
from plugins import agent_list
import requests

user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

def crossdomain_misconfig(url: str) -> str:
    r = requests.get(f"{url}/crossdomain.xml", verify=False, headers=header)
    if r.status_code == 200:
         print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Crossdomain: {Fore.GREEN}{url}/crossdomain.xml")
         print(f"{Fore.MAGENTA}Permissions: {Fore.WHITE}Checking for permissions in crossdomain.xml file...")
         if "*" in r.text and not "404" in r.text:
            print(f"{Fore.MAGENTA}Permissions: {Fore.WHITE} Allow access from domain *")

