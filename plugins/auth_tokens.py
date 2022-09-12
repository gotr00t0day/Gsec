from colorama import Fore
from plugins import agent_list
import requests

user_agent_ = agent_list.get_useragent()
header = {"User-Agent": user_agent_}

def auth_tokens(domain: str, proxy=None) -> str:
    res = requests.get(domain, verify=False, headers=header)
    for item, key in res.headers.items():
        if item == "Authorization" or item == "authorization":
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Authorization: {Fore.MAGENTA}{key}")

