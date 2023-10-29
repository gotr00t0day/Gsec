from colorama import Fore
from plugins import agent_list
import requests

user_a = agent_list.get_useragent()
header = {"User-Agent": user_a}

def securitytxt(domain: str) -> str:
    sec_loc = ["security.txt", ".well-known/security.txt"]
    for sec_locs in sec_loc:
        s = requests.Session()
        r = s.get(f"{domain}/{sec_locs}", verify=False, headers=header)
        if r.status_code == 200:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Security.txt: {Fore.GREEN}{domain}/{sec_locs}")
        else:
            pass